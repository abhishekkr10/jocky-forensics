"""Fixed executable bridge. No shell, arbitrary command or dynamic plugin loading."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get("JOCKY_DATA", ROOT / "data")).resolve()
DATA.mkdir(parents=True, exist_ok=True)
EXE = ROOT / "target" / "debug" / ("jocky.exe" if os.name == "nt" else "jocky")

def native(command, payload):
    if command not in {"compile", "check", "operation", "seal", "verify", "analyze", "predicate"}:
        raise ValueError("Disallowed native operation")
    args = [str(EXE), command] + (["--stdin"] if command in {"compile", "check"} else [])
    env = os.environ.copy()
    if command == "operation":
        from .integrity import public_key
        env["JOCKY_AGENT_PUBLIC_KEY"] = public_key()
    proc = subprocess.run(args, input=json.dumps(payload, ensure_ascii=False), capture_output=True,
                          encoding="utf-8", timeout=45, cwd=ROOT, shell=False, env=env)
    if proc.returncode not in (0, 2):
        raise RuntimeError(proc.stderr.strip()[:2000] or "Native worker failed")
    return json.loads(proc.stdout)
