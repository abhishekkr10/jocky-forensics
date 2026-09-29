import copy
import hashlib
import json
import os
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from .core import ROOT, native
from .db import initialize, connection, audit, now
from .auth import bootstrap, current_user, writer, HASHER, token_hash
from . import engine, integrity

POOL = ThreadPoolExecutor(max_workers=2)
@asynccontextmanager
async def lifespan(app):
    initialize(); bootstrap(); integrity.signing_key()
    yield

app = FastAPI(title="JOCKY forensic investigation API",version="0.1.0",lifespan=lifespan)

@app.middleware("http")
async def boundaries(request: Request, call_next):
    if int(request.headers.get("content-length","0")) > 2*1024*1024:
        return Response("Request too large",status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "DENY"
    return response

class Login(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=300)
class Investigation(BaseModel):
    name: str = Field(min_length=1,max_length=120)
    source: str = Field(max_length=65536)
class Source(BaseModel):
    source: str = Field(max_length=65536)
class Report(BaseModel):
    format: str = "html"

LOGIN_FAILURES = {}
@app.post("/api/v1/auth/login")
def login(body: Login, request: Request, response: Response):
    origin=request.headers.get("origin")
    if origin and origin.rstrip("/") != str(request.base_url).rstrip("/"):
        raise HTTPException(403,"Cross-origin login denied")
    key=(request.client.host if request.client else "local", body.username)
    failures=[t for t in LOGIN_FAILURES.get(key,[]) if t>time.time()-60]
    if len(failures)>=10: raise HTTPException(429,"Retry after one minute")
    with connection() as db:
        user=db.execute("SELECT * FROM users WHERE username=?",(body.username,)).fetchone()
        try:
            if not user: raise ValueError()
            HASHER.verify(user["password_hash"],body.password)
        except Exception:
            LOGIN_FAILURES[key]=failures+[time.time()]
            raise HTTPException(401,"Invalid credentials")
        token, csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(24)
        db.execute("INSERT INTO sessions VALUES(?,?,?,?)",(token_hash(token),user["id"],csrf,time.time()+8*3600))
    response.set_cookie("jocky_session",token,httponly=True,samesite="strict",secure=os.environ.get("JOCKY_HTTPS")=="1",max_age=8*3600)
    audit(user["id"],"login")
    return {"username":user["username"],"role":user["role"],"csrf":csrf}

@app.get("/api/v1/auth/me")
def me(user=Depends(current_user)):
    return {k:user[k] for k in ("username","role","csrf")}

@app.post("/api/v1/auth/logout")
def logout(request:Request,response:Response,user=Depends(current_user)):
    with connection() as db: db.execute("DELETE FROM sessions WHERE token_hash=?",(token_hash(request.cookies.get("jocky_session","")),))
    response.delete_cookie("jocky_session"); audit(user["id"],"logout")
    return {"ok":True}

def investigation(id,user):
    with connection() as db: row=db.execute("SELECT * FROM investigations WHERE id=?",(id,)).fetchone()
    if not row: raise HTTPException(404,"Investigation not found")
    if user["role"]=="investigator" and row["owner_id"]!=user["id"]: raise HTTPException(403,"Investigation access denied")
    return dict(row)

def latest_bundle(id,user):
    investigation(id,user)
    with connection() as db: row=db.execute("SELECT bundle FROM jobs WHERE investigation_id=? AND status='completed' ORDER BY created_at DESC LIMIT 1",(id,)).fetchone()
    if not row: raise HTTPException(409,"No completed run")
    return json.loads(row["bundle"])

@app.get("/api/v1/examples")
def examples(user=Depends(current_user)):
    return {"lab":(ROOT/"examples/triage.jky").read_text(),"multi":(ROOT/"examples/multi-endpoint.jky").read_text(),"live":(ROOT/"examples/live.jky").read_text()}

@app.get("/api/v1/endpoints")
def endpoints(user=Depends(current_user)):
    with connection() as db: rows=[dict(r) for r in db.execute("SELECT * FROM endpoints ORDER BY id")]
    for r in rows:
        r["capabilities"]=json.loads(r["capabilities"])
        r["status"]="lab fixture" if r["kind"]=="synthetic" else "last local observation"
    return rows

@app.post("/api/v1/investigations",status_code=201)
def create(body:Investigation,user=Depends(current_user)):
    writer(user); id=str(uuid.uuid4())
    with connection() as db: db.execute("INSERT INTO investigations VALUES(?,?,?,?,?)",(id,body.name,user["id"],body.source,now()))
    audit(user["id"],"investigation.created",id)
    return investigation(id,user)

@app.get("/api/v1/investigations")
def investigations(user=Depends(current_user)):
    with connection() as db:
        return [dict(r) for r in db.execute("SELECT i.*, (SELECT status FROM jobs WHERE investigation_id=i.id ORDER BY created_at DESC LIMIT 1) AS status FROM investigations i WHERE ? != 'investigator' OR owner_id=? ORDER BY created_at DESC",(user["role"],user["id"]))]

@app.get("/api/v1/investigations/{id}")
def get_investigation(id:str,user=Depends(current_user)): return investigation(id,user)

@app.post("/api/v1/investigations/{id}/check")
def check(id:str,body:Source,user=Depends(current_user)):
    writer(user); investigation(id,user)
    return native("check",{"source":body.source})

@app.post("/api/v1/investigations/{id}/compile")
def compile_source(id:str,body:Source,user=Depends(current_user)):
    writer(user); investigation(id,user)
    result=native("compile",{"source":body.source})
    if result["ok"]:
        with connection() as db:
            db.execute("UPDATE investigations SET source=? WHERE id=?",(body.source,id))
            db.execute("INSERT INTO plans VALUES(?,?,?,?,?)",(str(uuid.uuid4()),id,result["plan_digest"],json.dumps(result["plan"]),now()))
        audit(user["id"],"plan.compiled",id)
    return result

def execute_job(job_id, inv, user_id):
    try:
        with connection() as db: db.execute("UPDATE jobs SET status='running' WHERE id=?",(job_id,))
        def cancelled():
            with connection() as db: return bool(db.execute("SELECT cancelled FROM jobs WHERE id=?",(job_id,)).fetchone()[0])
        bundle=engine.run(inv["source"],job_id,inv["id"],cancelled)
        with connection() as db:
            for stream in bundle["streams"]:
                endpoint=stream["entries"][0]["record"]["endpoint_id"] if stream["entries"] else stream["stream_id"].split(":",1)[1]
                kind="synthetic" if bundle["mode"]=="lab" else "live"
                db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,capabilities=excluded.capabilities",(endpoint,endpoint,"lab fixture" if kind=="synthetic" else os.name,kind,now(),json.dumps(bundle["plan"]["required_capabilities"])))
                db.execute("INSERT INTO evidence_streams VALUES(?,?,?,?,?,?)",(stream["stream_id"],job_id,endpoint,stream["record_count"],stream["chain_head"],stream["completeness"]))
                for e in stream["entries"]:
                    r=e["record"]
                    db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?)",(r["evidence_id"],stream["stream_id"],e["sequence"],r["event_time"],r["artifact_type"],json.dumps(e)))
            for d in bundle["detections"]:
                db.execute("INSERT INTO detections VALUES(?,?,?)",(d["id"],job_id,json.dumps(d)))
                for eid in d["evidence_ids"]: db.execute("INSERT INTO detection_evidence VALUES(?,?,?)",(job_id,d["id"],eid))
            db.execute("INSERT INTO checkpoints VALUES(?,?)",(job_id,json.dumps(bundle["checkpoint"])))
            db.execute("UPDATE jobs SET status='completed',completed_at=?,bundle=? WHERE id=?",(now(),json.dumps(bundle),job_id))
            for node in bundle["plan"]["nodes"]:
                if node["opcode"]=="report":
                    fmt=node["parameters"]["format"]
                    content=engine.report_html(bundle) if fmt=="html" else json.dumps(bundle,indent=2)
                    db.execute("INSERT INTO reports VALUES(?,?,?,?,?)",(str(uuid.uuid4()),job_id,fmt,content,now()))
        audit(user_id,"run.completed",job_id)
    except Exception as exc:
        with connection() as db: db.execute("UPDATE jobs SET status=?,completed_at=?,error=? WHERE id=?",("cancelled" if "cancelled" in str(exc).lower() else "failed",now(),str(exc)[:3000],job_id))
        audit(user_id,"run.failed",job_id)

@app.post("/api/v1/investigations/{id}/runs",status_code=202)
def start_run(id:str,body:Source,user=Depends(current_user)):
    writer(user); inv=investigation(id,user)
    result=native("compile",{"source":body.source})
    if not result["ok"]: raise HTTPException(422,result["diagnostics"])
    with connection() as db:
        if db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]>=2: raise HTTPException(429,"Two investigations are already active")
        job_id=str(uuid.uuid4()); db.execute("INSERT INTO jobs(id,investigation_id,status,created_at) VALUES(?,?,?,?)",(job_id,id,"queued",now()))
        db.execute("UPDATE investigations SET source=? WHERE id=?",(body.source,id))
    inv["source"]=body.source
    POOL.submit(execute_job,job_id,inv,user["id"])
    audit(user["id"],"run.started",job_id)
    return {"id":job_id,"status":"queued"}

@app.get("/api/v1/runs/{id}")
def run_status(id:str,user=Depends(current_user)):
    with connection() as db: row=db.execute("SELECT id,investigation_id,status,created_at,completed_at,error FROM jobs WHERE id=?",(id,)).fetchone()
    if not row: raise HTTPException(404,"Run not found")
    investigation(row["investigation_id"],user)
    return dict(row)

@app.post("/api/v1/runs/{id}/cancel")
def cancel(id:str,user=Depends(current_user)):
    writer(user); run_status(id,user)
    with connection() as db: db.execute("UPDATE jobs SET cancelled=1 WHERE id=?",(id,))
    return {"status":"cancellation_requested"}

@app.get("/api/v1/investigations/{id}/workspace")
def workspace(id:str,user=Depends(current_user)):
    b=latest_bundle(id,user)
    return {k:v for k,v in b.items() if k not in {"streams","blobs"}} | {"evidence_count":sum(s["record_count"] for s in b["streams"]),"streams":[{k:v for k,v in s.items() if k!="entries"} for s in b["streams"]]}

@app.get("/api/v1/investigations/{id}/evidence")
def evidence(id:str,offset:int=0,limit:int=200,user=Depends(current_user)):
    rows=engine.records(latest_bundle(id,user));offset=max(0,offset);limit=max(1,min(limit,1000))
    return {"items":rows[offset:offset+limit],"total":len(rows),"offset":offset}

@app.get("/api/v1/investigations/{id}/detections")
def detections(id:str,user=Depends(current_user)): return latest_bundle(id,user)["detections"]
@app.get("/api/v1/investigations/{id}/timeline")
def timeline(id:str,user=Depends(current_user)): return latest_bundle(id,user)["analysis"]["timeline"]
@app.get("/api/v1/investigations/{id}/correlations")
def correlations(id:str,user=Depends(current_user)): return latest_bundle(id,user)["analysis"]["edges"]
@app.get("/api/v1/investigations/{id}/processes")
def processes(id:str,user=Depends(current_user)): return [r for r in engine.records(latest_bundle(id,user)) if r["artifact_type"]=="processes"]
@app.get("/api/v1/investigations/{id}/network")
def network(id:str,user=Depends(current_user)): return [r for r in engine.records(latest_bundle(id,user)) if r["artifact_type"]=="network_connections"]
@app.post("/api/v1/investigations/{id}/verify")
def verify(id:str,user=Depends(current_user)):
    result=integrity.verify(latest_bundle(id,user));audit(user["id"],"integrity.verified",id);return result
@app.post("/api/v1/investigations/{id}/tamper-test")
def tamper(id:str,user=Depends(current_user)):
    writer(user);b=copy.deepcopy(latest_bundle(id,user))
    if b["mode"]!="lab": raise HTTPException(400,"Tamper demonstration is lab-only")
    b["streams"][0]["entries"][0]["record"]["payload"]["summary"]="Modified copy"
    result=integrity.verify(b);audit(user["id"],"lab.tamper_copy_verified",id)
    return result | {"original_unchanged":True}

@app.post("/api/v1/investigations/{id}/reports",status_code=201)
def report(id:str,body:Report,user=Depends(current_user)):
    writer(user);b=latest_bundle(id,user)
    if body.format not in {"html","json"}: raise HTTPException(400,"Expected html or json")
    content=engine.report_html(b) if body.format=="html" else json.dumps(b,indent=2)
    rid=str(uuid.uuid4())
    with connection() as db: db.execute("INSERT INTO reports VALUES(?,?,?,?,?)",(rid,b["run_id"],body.format,content,now()))
    audit(user["id"],"report.generated",rid)
    return {"id":rid,"url":f"/api/v1/reports/{rid}","format":body.format}

@app.get("/api/v1/investigations/{id}/reports")
def list_reports(id:str,user=Depends(current_user)):
    investigation(id,user)
    with connection() as db:
        return [dict(r) for r in db.execute("SELECT r.id,r.format,r.created_at FROM reports r JOIN jobs j ON r.job_id=j.id WHERE j.investigation_id=? ORDER BY r.created_at DESC",(id,))]

@app.get("/api/v1/reports/{id}")
def get_report(id:str,user=Depends(current_user)):
    with connection() as db: row=db.execute("SELECT r.*,j.investigation_id FROM reports r JOIN jobs j ON j.id=r.job_id WHERE r.id=?",(id,)).fetchone()
    if not row: raise HTTPException(404,"Report not found")
    investigation(row["investigation_id"],user)
    return Response(row["content"],media_type="text/html" if row["format"]=="html" else "application/json",headers={"Content-Disposition":f"inline; filename=jocky-{id}.{row['format']}","Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; sandbox"})

@app.get("/api/v1/audit")
def audits(user=Depends(current_user)):
    with connection() as db: return [dict(r) for r in db.execute("SELECT action,subject,created_at FROM audit_logs WHERE ?='administrator' OR user_id=? ORDER BY id DESC LIMIT 100",(user["role"],user["id"]))]
@app.get("/api/v1/rule-packs")
def rules(user=Depends(current_user)):
    return [{"id":name,"engine":eng,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"source":path.read_text()} for name,eng,path in [("triage-v1","Sigma",ROOT/"rules/sigma/encoded_script.yml"),("demo-v1","YARA-X",ROOT/"rules/yara/demo.yar")]]
@app.get("/api/v1/health")
def health(): return {"status":"ok","version":"0.1.0"}

if (ROOT/"frontend/dist").exists():
    app.mount("/",StaticFiles(directory=ROOT/"frontend/dist",html=True),name="frontend")
