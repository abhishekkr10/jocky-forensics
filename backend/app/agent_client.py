"""Opt-in polling endpoint. Executes only source-bound, signed native collection jobs."""
import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def execute(payload,worker,root,key):
    if payload.get("approved_root")!=str(root):
        raise ValueError("Coordinator root differs from locally approved root")
    env=os.environ.copy()
    env["JOCKY_AGENT_PUBLIC_KEY"]=key
    result=subprocess.run([str(worker),"operation"],input=json.dumps(payload),capture_output=True,text=True,encoding="utf-8",timeout=40,shell=False,env=env)
    if result.returncode!=0: raise ValueError(result.stderr.strip()[:2000] or "Native collection failed")
    return json.loads(result.stdout)

def main():
    parser=argparse.ArgumentParser(description="JOCKY authenticated collection endpoint")
    parser.add_argument("--config",type=Path,required=True)
    parser.add_argument("--once",action="store_true",help="Poll once instead of running continuously")
    args=parser.parse_args()
    config=json.loads(args.config.read_text())
    url=config["coordinator"].rstrip("/")
    parsed=urlparse(url)
    if parsed.scheme!="https" and not (parsed.scheme=="http" and parsed.hostname in {"127.0.0.1","localhost"}):
        parser.error("HTTPS is required except for loopback testing")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        parser.error("Coordinator URL must not contain credentials, query or fragment")
    root=Path(config["approved_root"]).resolve(strict=True)
    worker=Path(config["worker"]).resolve(strict=True)
    key=config["public_key"]
    if len(bytes.fromhex(key))!=32: parser.error("Expected a pinned 32-byte coordinator public key")
    opener=build_opener(NoRedirect())
    def post(path,body):
        data=json.dumps(body).encode()
        if len(data)>2*1024*1024: raise ValueError("Collection exceeds remote upload limit")
        request=Request(url+"/api/v1"+path,data=data,headers={"Authorization":"Bearer "+config["credential"],"Content-Type":"application/json"})
        with opener.open(request,timeout=15) as response:
            raw=response.read(2*1024*1024+1)
            if len(raw)>2*1024*1024: raise ValueError("Coordinator response exceeds limit")
            return json.loads(raw)
    while True:
        try:
            post("/agent/heartbeat",{})
            task=post("/agent/poll",{}).get("task")
            if task:
                try:
                    result=execute(task["payload"],worker,root,key)
                    post(f"/agent/tasks/{task['id']}/complete",{"result":result})
                except Exception as exc:
                    post(f"/agent/tasks/{task['id']}/complete",{"error":str(exc)[:2000]})
        except Exception as exc:
            # Credentials and request payloads must never be logged.
            print("Endpoint request failed:",type(exc).__name__,flush=True)
            if args.once: raise SystemExit(1)
        if args.once: break
        time.sleep(5)

if __name__=="__main__": main()
