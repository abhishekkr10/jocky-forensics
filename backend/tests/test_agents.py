from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.auth import create_user, token_hash
from backend.app.db import connection
from backend.app.core import ROOT, EXE
from backend.app import engine, integrity
from backend.app.agent_client import execute
from concurrent.futures import ThreadPoolExecutor
import time
import os
import pytest
PLATFORM="windows" if os.name=="nt" else "ubuntu"

def test_two_authenticated_endpoints_collect_real_system_data():
    with TestClient(app) as client:
        create_user("remote-admin","Test-agent-password-123")
        login=client.post("/api/v1/auth/login",json={"username":"remote-admin","password":"Test-agent-password-123"})
        client.headers["X-CSRF-Token"]=login.json()["csrf"]
        root=ROOT/"fixtures"
        agents=[client.post("/api/v1/agents",json={"hostname":f"endpoint-{i}","platform":PLATFORM,"approved_root":str(root)}).json() for i in range(2)]
        targets=",".join('"'+a["id"]+'"' for a in agents)
        source=f"mode live\ntarget [{targets}]\ncollect system_information as s\nverify evidence"
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(engine.run,source,"remote-test","remote-case")
            deadline=time.monotonic()+15
            while not future.done() and time.monotonic()<deadline:
                for agent in agents:
                    headers={"Authorization":"Bearer "+agent["credential"]}
                    task=client.post("/api/v1/agent/poll",headers=headers).json()["task"]
                    if task:
                        result=execute(task["payload"],EXE,root,integrity.public_key())
                        path=f"/api/v1/agent/tasks/{task['id']}/complete"
                        other=next(a for a in agents if a!=agent)
                        assert client.post(path,json={"result":result},headers={"Authorization":"Bearer "+other["credential"]}).status_code==409
                        assert client.post(path,json={"result":result},headers=headers).status_code==200
                        assert client.post(path,json={"result":result},headers=headers).status_code==409
                time.sleep(.01)
            bundle=future.result(timeout=1)
        assert {r["endpoint_id"] for r in engine.records(bundle)}=={a["id"] for a in agents}
        assert len(engine.records(bundle))==2
        assert integrity.verify(bundle)["integrity"]=="valid"
        assert all(r["provenance_kind"]=="live" for r in engine.records(bundle))

def test_enrollment_heartbeat_and_revocation():
    with TestClient(app) as client:
        create_user("agent-admin","Test-agent-password-123")
        assert client.post("/api/v1/agents",json={"hostname":"lab-host","platform":PLATFORM,"approved_root":str(ROOT/"fixtures")}).status_code==401
        login=client.post("/api/v1/auth/login",json={"username":"agent-admin","password":"Test-agent-password-123"})
        client.headers["X-CSRF-Token"]=login.json()["csrf"]
        enrolled=client.post("/api/v1/agents",json={"hostname":"lab-host","platform":PLATFORM,"approved_root":str(ROOT/"fixtures")})
        assert enrolled.status_code==201
        credential=enrolled.json()["credential"]
        identity=enrolled.json()["id"]
        with connection() as db:
            assert db.execute("SELECT token_hash FROM agents WHERE id=?",(identity,)).fetchone()[0]==token_hash(credential)
        assert client.post("/api/v1/agent/heartbeat").status_code==401
        headers={"Authorization":"Bearer "+credential}
        assert client.post("/api/v1/agent/heartbeat",headers=headers).json()["id"]==identity
        assert "credential" not in client.get("/api/v1/agents").text
        assert client.post(f"/api/v1/agents/{identity}/revoke").status_code==200
        assert client.post("/api/v1/agent/heartbeat",headers=headers).status_code==401

def test_reviewer_cannot_enroll():
    with TestClient(app) as client:
        create_user("agent-reviewer","Test-agent-password-123","reviewer")
        login=client.post("/api/v1/auth/login",json={"username":"agent-reviewer","password":"Test-agent-password-123"})
        client.headers["X-CSRF-Token"]=login.json()["csrf"]
        assert client.post("/api/v1/agents",json={"hostname":"host","platform":PLATFORM,"approved_root":str(ROOT/"fixtures")}).status_code==403

def test_cancelled_dispatch_and_restart_recovery():
    from backend.app.agents import dispatch
    from backend.app.core import native
    from backend.app.db import now
    import json
    with TestClient(app) as client:
        create_user("cancel-agent-admin","Test-agent-password-123")
        login=client.post("/api/v1/auth/login",json={"username":"cancel-agent-admin","password":"Test-agent-password-123"})
        client.headers["X-CSRF-Token"]=login.json()["csrf"]
        agent=client.post("/api/v1/agents",json={"hostname":"host","platform":PLATFORM,"approved_root":str(ROOT/"fixtures")}).json()
        source=f'mode live\ntarget ["{agent["id"]}"]\ncollect system_information as s'
        compiled=native("compile",{"source":source})
        with pytest.raises(RuntimeError,match="cancelled"):
            dispatch(agent["id"],source,compiled,compiled["plan"]["nodes"][0],"cancelled-run",lambda:True)
        with connection() as db:
            assert db.execute("SELECT status FROM agent_tasks WHERE agent_id=?",(agent["id"],)).fetchone()[0]=="cancelled"
            db.execute("INSERT INTO agent_tasks(id,agent_id,payload,status,created_at,expires_at) VALUES(?,?,?,?,?,?)",("restart-task",agent["id"],json.dumps({}),"running",now(),time.time()+45))
    with TestClient(app):
        with connection() as db:
            assert db.execute("SELECT status FROM agent_tasks WHERE id='restart-task'").fetchone()[0]=="interrupted"
