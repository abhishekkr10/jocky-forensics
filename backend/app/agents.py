"""Explicit enrollment and revocable machine credentials, separate from user sessions."""
import secrets
import uuid
import json
import time
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from .auth import administrator, current_user, token_hash
from .db import audit, connection, now
from pathlib import PureWindowsPath, PurePosixPath

router = APIRouter(prefix="/api/v1")

class Enrollment(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(pattern="^(windows|ubuntu)$")
    approved_root: str = Field(min_length=1,max_length=1024)

def machine(request: Request):
    authorization=request.headers.get("authorization","")
    if not authorization.startswith("Bearer "):
        raise HTTPException(401,"Agent credential required")
    with connection() as db:
        row=db.execute("SELECT id,hostname,platform FROM agents WHERE token_hash=? AND revoked=0",(token_hash(authorization[7:]),)).fetchone()
    if not row:
        raise HTTPException(401,"Invalid or revoked agent credential")
    return dict(row)

@router.post("/agents",status_code=201)
def enroll(body: Enrollment, user=Depends(current_user)):
    administrator(user)
    path=PureWindowsPath(body.approved_root) if body.platform=="windows" else PurePosixPath(body.approved_root)
    if not path.is_absolute(): raise HTTPException(422,"An absolute endpoint collection root is required")
    identity=str(uuid.uuid4())
    credential=secrets.token_urlsafe(32)
    with connection() as db:
        db.execute("INSERT INTO agents(id,token_hash,hostname,platform,approved_root,registered_at) VALUES(?,?,?,?,?,?)",(identity,token_hash(credential),body.hostname,body.platform,body.approved_root,now()))
        db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,?)",(identity,body.hostname,body.platform,"remote","not yet observed","[]"))
    audit(user["id"],"agent.enrolled",identity)
    return {"id":identity,"credential":credential,"hostname":body.hostname,"platform":body.platform}

@router.get("/agents")
def list_agents(user=Depends(current_user)):
    administrator(user)
    with connection() as db:
        return [dict(r) for r in db.execute("SELECT id,hostname,platform,registered_at,last_seen,revoked FROM agents ORDER BY registered_at")]

@router.post("/agents/{identity}/revoke")
def revoke(identity: str,user=Depends(current_user)):
    administrator(user)
    with connection() as db:
        if db.execute("UPDATE agents SET revoked=1 WHERE id=?",(identity,)).rowcount!=1:
            raise HTTPException(404,"Agent not found")
        db.execute("UPDATE agent_tasks SET status='cancelled',error='Agent revoked' WHERE agent_id=? AND status IN ('queued','running')",(identity,))
    audit(user["id"],"agent.revoked",identity)
    return {"status":"revoked"}

@router.post("/agent/heartbeat")
def heartbeat(agent=Depends(machine)):
    timestamp=now()
    with connection() as db:
        db.execute("UPDATE agents SET last_seen=? WHERE id=? AND revoked=0",(timestamp,agent["id"]))
        db.execute("UPDATE endpoints SET last_seen=? WHERE id=?",(timestamp,agent["id"]))
    return {"id":agent["id"],"last_seen":timestamp,"status":"registered"}

@router.post("/agent/poll")
def poll(agent=Depends(machine)):
    with connection() as db:
        db.execute("UPDATE agent_tasks SET status='expired' WHERE agent_id=? AND status IN ('queued','running') AND expires_at<?",(agent["id"],time.time()))
        task=db.execute("SELECT id,payload FROM agent_tasks WHERE agent_id=? AND status='queued' ORDER BY created_at LIMIT 1",(agent["id"],)).fetchone()
        if not task: return {"task":None}
        db.execute("UPDATE agent_tasks SET status='running' WHERE id=? AND status='queued'",(task["id"],))
        return {"task":{"id":task["id"],"payload":json.loads(task["payload"])}}

class Completion(BaseModel):
    result: dict | None = None
    error: str | None = Field(default=None,max_length=2000)

@router.post("/agent/tasks/{identity}/complete")
def complete(identity:str,body:Completion,agent=Depends(machine)):
    if (body.result is None)==(body.error is None): raise HTTPException(422,"Provide a result or error")
    if body.result is not None:
        rows=body.result.get("rows")
        if not isinstance(rows,list) or len(rows)>10000 or any(not isinstance(row,dict) for row in rows): raise HTTPException(422,"Invalid collection rows")
        if body.result.get("status") not in {"success","partial"} or not isinstance(body.result.get("warnings"),list): raise HTTPException(422,"Invalid collection status")
    with connection() as db:
        changed=db.execute("UPDATE agent_tasks SET status=?,result=?,error=? WHERE id=? AND agent_id=? AND status='running' AND expires_at>?",("failed" if body.error is not None else "completed",json.dumps(body.result),body.error,identity,agent["id"],time.time())).rowcount
        if not changed: raise HTTPException(409,"Task unavailable, expired or already completed")
    return {"status":"accepted"}

def dispatch(identity,source,compiled,node,run_id,cancelled):
    from .integrity import signed_job
    with connection() as db:
        agent=db.execute("SELECT approved_root FROM agents WHERE id=? AND revoked=0",(identity,)).fetchone()
        if not agent: raise ValueError("Target is not an enrolled active agent")
        root=agent["approved_root"]
        payload={"source":source,"plan":compiled["plan"],"operation_id":node["id"],"approved_root":root,"signed_job":signed_job(compiled["plan_digest"],node["id"],root,run_id)}
        identity_task=str(uuid.uuid4())
        db.execute("INSERT INTO agent_tasks(id,agent_id,payload,status,created_at,expires_at) VALUES(?,?,?,?,?,?)",(identity_task,identity,json.dumps(payload),"queued",now(),time.time()+45))
    try:
        while True:
            if cancelled(): raise RuntimeError("Investigation cancelled")
            with connection() as db:
                task=db.execute("SELECT * FROM agent_tasks WHERE id=?",(identity_task,)).fetchone()
                active=db.execute("SELECT revoked FROM agents WHERE id=?",(identity,)).fetchone()
            if active["revoked"]: raise RuntimeError("Agent credential revoked during execution")
            if task["status"]=="completed": return json.loads(task["result"])
            if task["status"] not in {"queued","running"}: raise RuntimeError(task["error"] or "Remote task unavailable")
            if task["expires_at"]<time.time(): raise RuntimeError("Remote collection timed out")
            time.sleep(.1)
    finally:
        with connection() as db:
            db.execute("UPDATE agent_tasks SET status='cancelled' WHERE id=? AND status IN ('queued','running')",(identity_task,))
