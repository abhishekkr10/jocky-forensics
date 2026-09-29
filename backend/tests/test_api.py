import time
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.auth import create_user
from backend.app.core import ROOT

def test_complete_api_journey():
    with TestClient(app) as c:
        create_user("api-test","Test-only-password-123")
        assert c.get("/api/v1/investigations").status_code==401
        login=c.post("/api/v1/auth/login",json={"username":"api-test","password":"Test-only-password-123"})
        assert login.status_code==200
        csrf=login.json()["csrf"]
        assert c.post("/api/v1/investigations",json={"name":"X","source":""}).status_code==403
        c.headers["X-CSRF-Token"]=csrf
        source=(ROOT/"examples/triage.jky").read_text()
        inv=c.post("/api/v1/investigations",json={"name":"API lab","source":source}).json()
        base=f"/api/v1/investigations/{inv['id']}"
        assert not c.post(base+"/check",json={"source":"collect processesx as p"}).json()["ok"]
        assert c.post(base+"/compile",json={"source":source}).json()["ok"]
        for attempt in range(2):
            job=c.post(base+"/runs",json={"source":source})
            assert job.status_code==202
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                state=c.get("/api/v1/runs/"+job.json()["id"]).json()
                if state["status"] not in {"queued","running"}:break
                time.sleep(.05)
            assert state["status"]=="completed",state
        assert c.get(base+"/evidence").json()["total"]==8
        assert len(c.get(base+"/detections").json())==2
        assert c.post(base+"/verify").json()["integrity"]=="valid"
        assert c.post(base+"/tamper-test").json()["integrity"]=="invalid"
        assert c.post(base+"/verify").json()["integrity"]=="valid"
        report=c.post(base+"/reports",json={"format":"html"}).json()
        assert "INVESTIGATION REPORT" in c.get(report["url"]).text
        assert len(c.get("/api/v1/audit").json())>0
        c.post("/api/v1/auth/logout")
        assert c.get(base).status_code==401

def test_reviewer_cannot_write():
    with TestClient(app) as c:
        create_user("reviewer-test","Test-only-password-123","reviewer")
        r=c.post("/api/v1/auth/login",json={"username":"reviewer-test","password":"Test-only-password-123"})
        c.headers["X-CSRF-Token"]=r.json()["csrf"]
        assert c.post("/api/v1/investigations",json={"name":"Denied","source":""}).status_code==403
