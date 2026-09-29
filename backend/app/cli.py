"""Local pipeline commands used by the JOCKY executable."""
import argparse
import json
import sys
import uuid
from pathlib import Path
from .core import ROOT
from .engine import run, report_html
from .integrity import verify

def main():
    parser=argparse.ArgumentParser(description="JOCKY local investigation pipeline")
    parser.add_argument("command",choices=["simulate","run","verify-bundle","report"])
    parser.add_argument("path",type=Path)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--trusted-key",type=Path)
    args=parser.parse_args()
    if args.command in {"simulate","run"}:
        source=args.path.read_text(encoding="utf-8")
        from .core import native
        compiled=native("compile",{"source":source})
        if not compiled["ok"]: raise ValueError(json.dumps(compiled["diagnostics"]))
        if args.command=="simulate" and compiled["plan"]["mode"]!="lab": raise ValueError("simulate requires mode lab")
        id=str(uuid.uuid4()); bundle=run(source,id,id)
        output=args.output or ROOT/"artifacts"/id/"bundle.json"
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(bundle,indent=2),encoding="utf-8")
        output.with_suffix(".checkpoint.json").write_text(json.dumps(bundle["checkpoint"],indent=2),encoding="utf-8")
        output.with_suffix(".public-key.txt").write_text(bundle["checkpoint"]["public_key"],encoding="ascii")
        output.with_suffix(".html").write_text(report_html(bundle),encoding="utf-8")
        print(json.dumps({"bundle":str(output),"evidence":sum(s["record_count"] for s in bundle["streams"]),"detections":len(bundle["detections"]),"verification":bundle["verification"]}))
    else:
        bundle=json.loads(args.path.read_text(encoding="utf-8"))
        trusted=args.trusted_key.read_text().strip() if args.trusted_key else None
        result=verify(bundle,trusted)
        if args.command=="verify-bundle":
            print(json.dumps(result))
            if result["integrity"]!="valid":return 1
        else:
            if result["integrity"]!="valid":raise ValueError("Refusing report generation for invalid bundle")
            output=args.output or args.path.with_suffix(".html")
            output.write_text(report_html(bundle),encoding="utf-8")
            print(json.dumps({"report":str(output)}))
    return 0

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:
        print(str(exc),file=sys.stderr);sys.exit(1)
