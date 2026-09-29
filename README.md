# JOCKY

JOCKY is a defensive digital-forensics investigation platform. Investigators write a compact JOCKY script, compile it into a deterministic plan, collect bounded endpoint telemetry, evaluate Sigma and YARA-X rules, correlate evidence, reconstruct a timeline, verify a signed evidence checkpoint and generate a report.

The project is intentionally read-oriented. It does not provide shell execution, persistence, privilege escalation, process injection, credential access, security-control bypass or covert communications. Advanced techniques in the lab scenario are synthetic telemetry only.

## Local setup

Requirements: Rust with the GNU Windows target, Python 3.13+, Node.js 20+, and SQLite. Ubuntu/WSL is optional for cross-platform testing.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.lock
cargo build --workspace
npm.cmd --prefix frontend install
```

Start the local API:

```powershell
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Start the local frontend in another terminal:

```powershell
npm.cmd --prefix frontend run dev
```

Open `http://127.0.0.1:5173`. The local demo login is `investigator` / `test123`; `data/` is ignored and must never be committed.

## CLI

```powershell
cargo run -p jocky-cli -- check examples/triage.jky
cargo run -p jocky-cli -- compile examples/triage.jky --output artifacts/triage.ir.json
cargo run -p jocky-cli -- simulate examples/triage.jky --output artifacts/triage/bundle.json
cargo run -p jocky-cli -- verify artifacts/triage/bundle.json --trusted-key artifacts/triage/bundle.public-key.txt
```

The lab run is deterministic and harmless. It contains eight labelled synthetic observations, a Sigma finding and a YARA-X match for the harmless marker in `fixtures/lab/demo_files/marker.txt`.

`examples/multi-endpoint.jky` demonstrates bounded multi-endpoint case handling with independent evidence streams. Targets are synthetic lab identifiers; live remote transport is intentionally not enabled.

## Tests

```powershell
cargo test --workspace
.venv\Scripts\python.exe -m pytest backend/tests -q
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run test:e2e
```

The browser test covers compilation diagnostics, IR, lab execution, evidence/source tracing, timeline filtering, signed integrity verification, copied-evidence tamper detection and HTML report generation. Browser tests use a separate local port and temporary data directory.

## Architecture

See [architecture.md](architecture.md) for component contracts, data flow and trust boundaries. [CURRENT_STATUS.md](CURRENT_STATUS.md) records the verified implementation state and known limitations.

## Current limitations

Ubuntu execution is not verified on the current Windows development machine. Windows Event Log collection uses the documented native API; Linux collection provides bounded text-log coverage. Remote agent transport, full disk parsing, memory-image processing, packet capture and broad Sigma compatibility are intentionally outside the current local MVP.
