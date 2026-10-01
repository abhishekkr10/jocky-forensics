# JOCKY

JOCKY is a local digital-forensics investigation platform developed against the SIH26148 problem statement. A Rust compiler turns JOCKY scripts into deterministic plans. The backend coordinates bounded collection, Sigma and YARA-X evaluation, correlation, signed evidence verification and portable reports. The React console keeps each finding connected to its source and evidence.

The current implementation supports defensive, read-oriented investigations. Lab techniques generate explicitly synthetic telemetry. The project does not implement antivirus/EDR bypass, process injection, vulnerable-driver exploitation, polymorphic evasion or domain-fronted agent transport.

## Website and investigation console

The [public website](https://jocky-six.vercel.app) contains product documentation and a labelled snapshot of a synthetic lab investigation. Its **Open console** link checks backend connectivity before requesting credentials. A hosted investigation backend is not yet connected to the public deployment.

The complete working console runs locally. Open `http://127.0.0.1:5173/#/app` during development, or `http://127.0.0.1:8000/#/app` after building the frontend. Hash navigation supports the existing backend static-file mount; `/app` is also recognized by frontend servers that provide SPA fallback routing.

## Requirements

- Stable Rust and Cargo. The tested Windows setup uses `x86_64-pc-windows-gnu` and its linker toolchain.
- Python 3.12 or later. Local verification used Python 3.13; CI is configured for Python 3.12 on Ubuntu.
- Node.js 20 or later and npm.
- SQLite is provided by Python's standard library.

## Windows setup

From the repository root:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.lock
cargo build --workspace
npm.cmd --prefix frontend ci
npm.cmd --prefix frontend run build
```

Start the backend:

```powershell
.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

For frontend development, start a second terminal:

```powershell
npm.cmd --prefix frontend run dev
```

The development frontend proxies `/api` to the local backend. The backend also serves the production build from `frontend/dist` when that directory exists.

## Ubuntu setup

Install the Rust toolchain, Python with venv support, Node.js and a C/C++ build toolchain, then run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.lock
cargo build --workspace
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Run `npm --prefix frontend run dev` in another terminal for frontend development. Ubuntu CI is configured; this release's checks were performed on Windows, so local Ubuntu execution is not claimed as newly verified.

## Sign in

On a fresh database, startup creates an `investigator` account with the administrator role and a randomly generated password. Credentials are written to `data/first-login.txt` and that file is removed after the first successful login. Save the credential before signing in. Existing databases retain their accounts and passwords.

The login page does not publish a password. New users created through the administration helper must have passwords of at least 12 characters. Sessions use an HTTP-only cookie and mutating requests require the session's CSRF token. Administrator API documentation is available at `/api/v1/admin/docs` after sign-in; unauthenticated `/docs` and `/openapi.json` are disabled.

## Run the lab investigation

1. Open the console and select **New investigation**.
2. In **JOCKY Editor**, load **Deterministic lab**.
3. Check the script, compile to IR and run the investigation.
4. Inspect the relationship graph, telemetry coverage, evidence, timeline and detections.
5. Open **Integrity** and verify the signed checkpoint. **Tamper Test** verifies a modified copy and leaves the stored evidence unchanged.
6. Export an HTML report or JSON bundle from **Reports**.

The reference lab produces eight labelled synthetic observations, a Sigma finding and a YARA-X match for `fixtures/lab/demo_files/marker.txt`. `examples/multi-endpoint.jky` uses independent synthetic streams and merges their analysis. `examples/live.jky` collects bounded observations from the local host; it does not connect to remote endpoints.

## CLI and Rust builds

```sh
cargo run -p jocky-cli -- check examples/triage.jky
cargo run -p jocky-cli -- compile examples/triage.jky --output artifacts/triage.ir.json
cargo run -p jocky-cli -- simulate examples/triage.jky --output artifacts/triage/bundle.json
cargo run -p jocky-cli -- verify artifacts/triage/bundle.json --trusted-key artifacts/triage/bundle.public-key.txt
cargo build --workspace --release
```

The current Python bridge invokes the debug binary under `target/debug`, so run `cargo build --workspace` before starting the backend even if release binaries have also been built.

## Configuration and evidence storage

| Setting | Purpose | Default |
| --- | --- | --- |
| `JOCKY_DATA` | Database, reports and local runtime data | Repository-relative `data/` |
| `JOCKY_KEY_PATH` | Ed25519 checkpoint signing key | `%APPDATA%/jocky/checkpoint.key` on Windows; `~/.config/jocky/checkpoint.key` on Unix |
| `JOCKY_HTTPS=1` | Mark session cookies secure when serving HTTPS | Disabled for loopback development |

Keep signing keys separate from the database and retain them when moving an installation. Verification fails if the trusted key is missing; it does not silently create a replacement. Fresh startup migrates a legacy `data/checkpoint.key` when the configured external key does not already exist. Conflicting keys require explicit resolution.

Case data, keys, local credentials, caches and build output are ignored by Git. Small intentional synthetic fixtures are version controlled; real machine evidence must remain outside tracked source. The public demo contains only synthetic reference records. Fonts are self-hosted, with their SIL Open Font License files retained under `frontend/src/assets/fonts`.

## Verification

```powershell
cargo test --workspace
cargo build --workspace --release
.venv\Scripts\python.exe -m pytest backend/tests -q
npm.cmd --prefix frontend run build
npm.cmd --prefix frontend run test
npm.cmd --prefix frontend run test:e2e
```

On Unix, use `.venv/bin/python` and `npm` for the equivalent commands. If the Playwright Chromium browser is not installed, run `npm exec --prefix frontend playwright install chromium` before the browser suite.

The browser test covers sign-in, compilation diagnostics, IR, lab execution, source tracing, timeline filtering, checkpoint verification, tamper-copy detection, report generation and mobile layout. Backend and browser tests use isolated databases and signing keys. CI runs Rust, Python and frontend build/unit checks.

## Architecture and current limits

See [architecture.md](architecture.md) for data flow and trust boundaries, [CURRENT_STATUS.md](CURRENT_STATUS.md) for verified implementation state.

Remote agent transport, live vulnerable-driver inventory, full disk parsing, memory-image analysis and packet capture are not implemented. Native event-log and startup collection can be partial. Sigma compatibility is limited to supported predicates. Historical checkpoint manifests without the current analysis digest are rejected; they are not automatically re-signed. Evidence integrity establishes consistency with a trusted checkpoint, not endpoint truthfulness or collection completeness.
