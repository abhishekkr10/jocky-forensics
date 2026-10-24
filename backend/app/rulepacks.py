"""Administrator-published, immutable content-addressed rule packs."""
import hashlib
import json
import os
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,Field
from .core import DATA
from .auth import current_user,administrator
from .db import audit

router=APIRouter(prefix="/api/v1")
class Publication(BaseModel):
    engine:str=Field(pattern="^(sigma|yara)$")
    version:str=Field(min_length=1,max_length=50,pattern="^[A-Za-z0-9._-]+$")
    source:str=Field(min_length=1,max_length=65536)

def path_for(pack):
    engine,sep,digest=pack.partition(":")
    if engine not in {"sigma","yara"} or sep!=":" or len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest): raise ValueError("Invalid rule pack identifier")
    return DATA/"rule-packs"/(digest+".json")

def load(pack):
    record=json.loads(path_for(pack).read_text(encoding="utf-8"))
    body={k:record[k] for k in ("engine","version","source")}
    digest=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    if record["id"]!=pack or digest!=pack.split(":",1)[1] or record["digest"]!=digest: raise ValueError("Stored rule pack digest mismatch")
    return record

@router.post("/rule-packs",status_code=201)
def publish(body:Publication,user=Depends(current_user)):
    administrator(user)
    try:
        if body.engine=="sigma":
            from .detection import compile_sigma
            rule,_=compile_sigma(body.source)
            if rule.logsource.product!="windows" or rule.logsource.category!="process_creation": raise ValueError("Custom Sigma packs currently require windows/process_creation telemetry")
        else:
            import yara_x
            yara_x.compile(body.source)
    except Exception as exc: raise HTTPException(422,"Rule validation failed: "+str(exc)[:500])
    digest=hashlib.sha256(json.dumps(body.model_dump(),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    record={"id":body.engine+":"+digest,"engine":body.engine,"version":body.version,"source":body.source,"digest":digest}
    path=path_for(record["id"]);path.parent.mkdir(parents=True,exist_ok=True)
    try:
        with path.open("x",encoding="utf-8") as output:
            json.dump(record,output);output.flush();os.fsync(output.fileno())
    except FileExistsError:
        existing=load(record["id"])
        if existing!=record: raise HTTPException(409,"Content already published with different version metadata")
    audit(user["id"],"rule-pack.published",record["id"])
    return record
