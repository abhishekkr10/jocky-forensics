"""Local coordinator: Rust compilation/collection/analysis, isolated detection adapters."""
import copy
import hashlib
import html
import json
from datetime import datetime, timezone, timedelta
from .core import ROOT, native
from . import detection, integrity

BASE = datetime(2026, 9, 30, 10, 31, tzinfo=timezone.utc)
PROCESS_KEY = "lab-boot:4242:2026-09-30T10:31:02Z"

def lab_rows(name):
    common = {"process_key": PROCESS_KEY}
    if name == "system_information":
        return [{"hostname": "WIN-LAB-01", "os": "Windows lab fixture", "summary": "Synthetic endpoint context"}]
    if name == "processes":
        return [{**common, "pid": 4242, "ppid": 4100, "name": "powershell.exe", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "summary": "Synthetic PowerShell process snapshot"}]
    if name == "network_connections":
        return [{**common, "source": "192.0.2.10", "destination": "203.0.113.25", "port": 443, "protocol": "tcp", "summary": "Synthetic outbound TLS connection"}]
    if name == "startup_items":
        return [{"path": "C:\\Lab\\Startup\\example.lnk", "summary": "Synthetic startup artifact; never created or executed"}]
    if name == "event_logs":
        return [{**common, "event_kind": "process_creation", "product": "windows", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -EncodedCommand LAB_NON_EXECUTABLE_PLACEHOLDER", "ParentImage": "C:\\Lab\\document_viewer.exe", "summary": "Synthetic encoded-script process creation"},
                {"event_kind": "process_creation", "product": "windows", "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad.exe", "summary": "Benign synthetic control event"}]
    if name == "files":
        data = (ROOT / "fixtures/lab/demo_files/marker.txt").read_bytes()
        return [{"path": "lab://demo_files/marker.txt", "content_hex": data.hex(), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "summary": "Harmless lab marker file"}]
    raise ValueError("Unknown lab collector")

def run(source, run_id, investigation_id, cancelled=lambda: False):
    compiled = native("compile", {"source": source})
    if not compiled["ok"]:
        raise ValueError(json.dumps(compiled["diagnostics"]))
    plan = compiled["plan"]
    if plan["mode"] == "live" and plan["target_selector"] != ["host"]:
        raise ValueError("Remote dispatch is not implemented. Live target must be host.")
    datasets, evidence, detections, coverage, operations, blobs, exports = {}, [], [], [], [], {}, {}
    for pack,digest in plan["rule_digests"].items():
        path=ROOT/("rules/sigma/encoded_script.yml" if pack=="triage-v1" else "rules/yara/demo.yar")
        if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise ValueError("Rule pack changed since compiler build; rebuild the compiler to pin the new pack")
    analysis = {"timeline": [], "edges": [], "risk": {"score": 0, "label": "NOT CALCULATED", "contributions": []}}
    streams = []
    complete = True
    for endpoint in plan["target_selector"]:
        if endpoint == "host":
            import socket
            endpoint = socket.gethostname()
        datasets = {}
        endpoint_records = []
        for node in plan["nodes"]:
            if cancelled():
                raise RuntimeError("Investigation cancelled")
            op, args, output = node["opcode"], node["parameters"], node["output"]
            result = []
            status, warnings = "success", []
            inputs = [item for name in node["inputs"] for item in datasets[name]]
            if op in {"collect", "simulate", "import"}:
                name = args["name"]
                provenance = "synthetic" if plan["mode"] == "lab" else "live"
                if op == "simulate":
                    rows = [{"event_kind": name, "process_key": PROCESS_KEY, "summary": f"Synthetic {name} telemetry — no technique executed"}]
                elif op == "import":
                    path = (ROOT / "fixtures" / args["path"]).resolve()
                    if not path.is_relative_to((ROOT / "fixtures").resolve()) or path.stat().st_size > 1048576:
                        raise ValueError("Import must be a bounded file within fixtures")
                    rows = json.loads(path.read_text())
                    if not isinstance(rows, list) or len(rows) > 1000 or any(not isinstance(r, dict) for r in rows):
                        raise ValueError("Import expects at most 1000 JSON objects")
                    provenance = "imported"
                elif plan["mode"] == "lab":
                    rows = lab_rows(name)
                else:
                    root=str(ROOT / "fixtures")
                    collected = native("operation", {"source": source, "plan": plan, "operation_id": node["id"], "approved_root": root,
                        "signed_job":integrity.signed_job(compiled["plan_digest"],node["id"],root,run_id)})
                    rows, status, warnings = collected["rows"], collected["status"], collected["warnings"]
                for i, row in enumerate(rows):
                    row = copy.deepcopy(row)
                    content = row.pop("content_hex", None)
                    raw = None
                    if content is not None:
                        digest = hashlib.sha256(bytes.fromhex(content)).hexdigest()
                        blobs[digest] = content
                        raw = {"blob_sha256": digest}
                    index = len(evidence)
                    timestamp = (BASE + timedelta(seconds=index*3)).isoformat().replace("+00:00", "Z") if provenance == "synthetic" else datetime.now(timezone.utc).isoformat()
                    # Imported timestamps are kept verbatim in payload; only explicit UTC event_time is accepted.
                    event_time = timestamp if provenance == "synthetic" and name not in {"system_information", "processes", "startup_items", "files"} else None
                    if provenance in {"imported","live"} and row.get("event_time"):
                        parsed = datetime.fromisoformat(row["event_time"].replace("Z", "+00:00"))
                        if parsed.tzinfo is None:
                            raise ValueError("Imported event_time requires timezone")
                        event_time = parsed.astimezone(timezone.utc).isoformat()
                    rec = {"schema_version": "1.0", "evidence_id": f"{run_id}:{endpoint}:{node['id']}:{i}",
                           "investigation_id": investigation_id, "execution_id": run_id, "endpoint_id": endpoint,
                           "operation_id": node["id"], "collector_id": name, "collector_version": "0.1.0",
                           "source_span": plan["source_map"][node["id"]], "provenance_kind": provenance,
                           "scenario_id": "triage-v1" if provenance == "synthetic" else None,
                           "artifact_type": name, "event_kind": row.get("event_kind", name), "event_time": event_time,
                           "observed_at": timestamp, "collected_at": timestamp, "received_at": timestamp,
                           "time_metadata": {"precision": "seconds" if provenance == "synthetic" else "microseconds", "uncertainty": "fixture" if provenance == "synthetic" else "unmeasured", "timestamp_meaning": "event" if event_time else "observation"},
                           "entities": {"process_key": row.get("process_key")}, "payload": row, "raw_reference": raw,
                           "collection_status": status, "warnings": warnings}
                    result.append(rec)
                    evidence.append(rec)
                    endpoint_records.append(rec)
            elif op == "hunt":
                result, evaluation = detection.sigma(inputs, node["id"])
                for d in result: d["id"] = f"{endpoint}:{d['id']}"
                detections.extend(result); coverage.append(evaluation)
            elif op == "scan":
                result, evaluation = detection.yara(inputs, node["id"], blobs)
                for d in result: d["id"] = f"{endpoint}:{d['id']}"
                detections.extend(result); coverage.append(evaluation)
            elif op in {"filter", "assert"}:
                pred = args["predicate"]
                selected = []
                for record in inputs:
                    current = record["payload"]
                    for part in pred["field"].split("."):
                        current = current.get(part) if isinstance(current, dict) else None
                    matched = current is not None and ((str(current) == pred["value"]) if pred["op"] == "==" else (str(current) != pred["value"]) if pred["op"] == "!=" else pred["value"] in str(current))
                    if matched: selected.append(record)
                if op == "assert" and (not inputs or len(selected) != len(inputs)):
                    raise ValueError("Assertion failed (empty dataset or predicate mismatch)")
                result = selected
            elif op == "compare":
                left, right = (datasets[x] for x in node["inputs"])
                right_digests = {hashlib.sha256(integrity.canonical(r["payload"])).hexdigest() for r in right}
                result = [r for r in left if hashlib.sha256(integrity.canonical(r["payload"])).hexdigest() not in right_digests]
            elif op == "correlate":
                es = [r for r in inputs if "evidence_id" in r]
                ds = [r for r in inputs if "engine" in r]
                analysis = native("analyze", {"evidence": es, "detections": ds})
                # Enforce the requested time window on identity links; rule-input links have no causal time claim.
                by_id = {r["evidence_id"]: r for r in es}
                def in_window(edge):
                    if edge["source"] not in by_id or edge["target"] not in by_id: return True
                    a,b=(by_id[edge[k]] for k in ("source","target"))
                    ta,tb=(datetime.fromisoformat((r["event_time"] or r["observed_at"]).replace("Z","+00:00")) for r in (a,b))
                    return abs((ta-tb).total_seconds()) <= args["window_seconds"]
                analysis["edges"] = [e for e in analysis["edges"] if in_window(e)]
                result = [analysis]
            elif op == "timeline": result = inputs[0]["timeline"]
            elif op == "risk": result = [inputs[0]["risk"]]
            elif op == "export":
                from pathlib import PurePath
                filename=args["path"]
                if PurePath(filename).name!=filename or ":" in filename or "\\" in filename:
                    raise ValueError("Export name must be a simple filename")
                exports[f"{endpoint}/{filename}"]=copy.deepcopy(inputs)
            elif op in {"verify", "report"}:
                # Materialized below after immutable streams have been sealed.
                result = []
            else:
                raise ValueError(f"Unsupported operation {op}")
            if output: datasets[output] = result
            if status != "success": complete = False
            operations.append({"id": node["id"], "opcode": op, "endpoint_id": endpoint, "status": status,
                               "count": len(result), "warnings": warnings, "source_span": plan["source_map"][node["id"]]})
        streams.append(native("seal", {"stream_id": f"{run_id}:{endpoint}", "records": endpoint_records, "complete": complete}))
    bundle = {"version": "1.0", "run_id": run_id, "investigation_id": investigation_id, "mode": plan["mode"],
              "source": source, "plan": plan, "plan_digest": compiled["plan_digest"], "streams": streams, "blobs": blobs,
              "detections": detections, "coverage": coverage, "operations": operations, "analysis": analysis,"exports":exports}
    bundle["checkpoint"] = integrity.checkpoint(streams, compiled["plan_digest"],integrity.analysis_digest(bundle))
    bundle["verification"] = integrity.verify(bundle)
    return bundle

def records(bundle):
    return [dict(e["record"], record_digest=e["record_digest"], sequence=e["sequence"], previous_hash=e["previous_hash"], current_hash=e["current_hash"]) for s in bundle["streams"] for e in s["entries"]]

def report_html(bundle):
    rows = records(bundle)
    esc = lambda v: html.escape(str(v), quote=True)
    risk = bundle["analysis"]["risk"]
    return """<!doctype html><html lang="en"><meta charset="utf-8"><title>JOCKY investigation report</title>
<style>body{font:15px system-ui;color:#192337;max-width:1100px;margin:50px auto;padding:24px}h1{letter-spacing:.08em}table{border-collapse:collapse;width:100%;font-size:12px}td,th{padding:10px;border:1px solid #ddd;text-align:left;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f0f3f8;padding:20px}.badge{color:#254cc8}a{color:#254cc8}</style>
<h1>JOCKY / INVESTIGATION REPORT</h1>""" + f"<p class='badge'>{esc(bundle['mode'].upper())} · {esc(bundle['run_id'])}</p><p>Integrity: {esc(integrity.verify(bundle))}</p><p>{esc(risk['label'])}: {risk['score']} / 100. Triage heuristic, not a compromise probability.</p><h2>Source</h2><pre id='source'>{esc(bundle['source'])}</pre><h2>Detections</h2>" + "".join(f"<p>{esc(d['engine'])}: {esc(d['rule'])} · " + " ".join(f"<a href='#e-{esc(i)}'>Evidence</a>" for i in d['evidence_ids']) + "</p>" for d in bundle['detections']) + "<h2>Evidence</h2><table><tr><th>Kind</th><th>Provenance</th><th>Collector / source</th><th>Record</th></tr>" + "".join(f"<tr id='e-{esc(r['evidence_id'])}'><td>{esc(r['event_kind'])}</td><td>{esc(r['provenance_kind'])}</td><td>{esc(r['collector_id'])} {esc(r['collector_version'])}<br><a href='#source'>line {r['source_span']['line']}</a></td><td>{esc(json.dumps(r['payload']))}</td></tr>" for r in rows) + "</table><h2>Analysis, rule versions and checkpoint</h2><pre>" + esc(json.dumps({k:bundle[k] for k in ["plan_digest","coverage","detections","analysis","checkpoint","operations"]},indent=2)) + "</pre><p>Integrity does not establish endpoint truthfulness. Preserve the checkpoint independently.</p></html>"
