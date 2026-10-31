# JOCKY

JOCKY is a digital-forensics investigation prototype developed for the Smart India Hackathon problem statement SIH26148. A Rust compiler turns JOCKY scripts into deterministic plans. The backend coordinates bounded collection, Sigma and YARA-X evaluation, correlation, signed evidence verification and portable reports. The React console keeps each finding connected to its source and evidence.

The current implementation supports defensive, read-oriented investigations. Lab techniques generate explicitly synthetic telemetry. The project does not implement antivirus/EDR bypass, process injection, vulnerable-driver exploitation, polymorphic evasion or domain-fronted agent transport.

## Website and investigation console

The [public website](https://jocky-six.vercel.app) contains product documentation and a labelled snapshot of a synthetic lab investigation. Its **Check console** link checks backend connectivity before requesting credentials. The investigation workflow runs through the locally hosted backend and console.

The complete working console runs locally. Open `http://127.0.0.1:5173/#/app` during development, or `http://127.0.0.1:8000/#/app` after building the frontend. Hash navigation supports the existing backend static-file mount; `/app` is also recognized by frontend servers that provide SPA fallback routing.

## Requirements

- Stable Rust and Cargo. The tested Windows setup uses `x86_64-pc-windows-gnu` and its linker toolchain.
- Python 3.12 or later. Local verification used Python 3.13; CI is configured for Python 3.12 on Ubuntu.
- Node.js 20 or later and npm.
- SQLite is provided by Python's standard library.
- The backend must be running while using the investigation console. Restart it after shutting down or restarting the host laptop.

## Windows setup

Clone the repository, then run the setup commands from its root:

```sh
git clone https://github.com/abhishekkr10/jocky-forensics.git
cd jocky-forensics
```

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

Run `npm --prefix frontend run dev` in another terminal for frontend development.

## Opening JOCKY on another laptop

`127.0.0.1` and `localhost` always refer to the laptop where the browser is running. Sending someone `http://127.0.0.1:8000/#/app` does not connect them to your laptop. A connection-refused error usually means the backend is not running on that address and port. Start it with the command above, keep the terminal open and reload the page.

For an independent installation, install the requirements, clone this repository and follow the Windows or Ubuntu setup on the second laptop. Start its backend and open `http://127.0.0.1:8000/#/app`. Each installation has its own accounts, signing key and case storage.

### Access over the same Wi-Fi or LAN

To use one running installation from another laptop on a trusted private network:

1. Build the frontend on the host using `npm --prefix frontend run build`.
2. Stop the existing loopback backend with `Ctrl+C` in its terminal, then start it from the repository root with a network-accessible binding:

   ```powershell
   .venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
   ```

   On Ubuntu, use `.venv/bin/python` in place of `.venv\Scripts\python.exe`.

3. Find the host's private IPv4 address using `ipconfig` on Windows or `hostname -I` on Ubuntu. Use the address of the adapter connected to the shared network.
4. Allow inbound TCP port 8000 through the host firewall only for the trusted private network. Guest Wi-Fi or client isolation can prevent devices from connecting.
5. On the second laptop, open `http://<host-private-ip>:8000/#/app`, replacing the placeholder with that address, and sign in using an account on the host installation. Keep the host awake and its backend running.

`0.0.0.0` is a server binding, not a browser destination. This HTTP setup is for a trusted local demonstration; use the [HTTPS deployment configuration](deploy/README.md) when transmitting sensitive evidence or exposing the console beyond that network. Do not forward this HTTP port to the public internet.

Opening the console from another laptop accesses the host's cases. It does not automatically collect evidence from the visiting laptop; collection from that machine requires its own installation or an [enrolled endpoint agent](deploy/agents.md). The Vercel website serves the public preview; the full workflow requires a running backend.

## Sign in

On a fresh database, startup creates an `investigator` account with the administrator role and a randomly generated password. Credentials are written to `data/first-login.txt` and that file is removed after the first successful login. Save the credential before signing in. The file is created exclusively with owner-only permissions on Unix; on Windows, startup uses `whoami` and `icacls` to restrict it to the running account, SYSTEM and Administrators before writing the password. Keep the data directory private on shared machines. Existing databases retain their accounts and passwords.

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

The Python bridge defaults to the debug binary under `target/debug`, so run `cargo build --workspace` before starting the backend. Set `JOCKY_WORKER` to an installed release binary to use a release build.

## Configuration and evidence storage

| Setting | Purpose | Default |
| --- | --- | --- |
| `JOCKY_DATA` | Database, reports and local runtime data | Repository-relative `data/` |
| `JOCKY_KEY_PATH` | Ed25519 checkpoint signing key | `%APPDATA%/jocky/checkpoint.key` on Windows; `~/.config/jocky/checkpoint.key` on Unix |
| `JOCKY_HTTPS=1` | Mark session cookies secure when serving HTTPS | Disabled for loopback development |
| `JOCKY_WORKER` | Native worker executable | Repository-relative `target/debug/jocky` (`jocky.exe` on Windows) |

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

## Architecture

See [architecture.md](architecture.md) for the compiler, runtime, backend, frontend and evidence trust boundaries. [CURRENT_STATUS.md](CURRENT_STATUS.md) records implementation and verification details.

The prototype combines authenticated endpoint polling, bounded native collection, PCAP metadata import and signed evidence. Collection results report coverage and permission restrictions explicitly. Evidence verification establishes consistency with a trusted checkpoint; endpoint truthfulness and collection completeness are separate properties.

## Deployment configuration and endpoint agents

The repository includes a multi-stage Docker build, persistent evidence and signing-key volumes, and a same-origin Caddy HTTPS gateway. See [deployment setup](deploy/README.md) for infrastructure requirements and startup commands, and [endpoint enrollment](deploy/agents.md) for authenticated polling agents. `JOCKY_WORKER` selects an installed native release binary while local development retains its debug default.

## Language, collectors and rule packs

Dataset filters support bounded Boolean expressions and typed comparisons. Reusable dataset functions expand into deterministic plans with isolated bindings; see [examples/functions.jky](examples/functions.jky). Nested calls and recursion are unsupported.

Windows collectors include bounded Run/RunOnce registry inventory and Win32 service state. Ubuntu event-log collection supports bounded journal reads with text-log fallback. Classic Ethernet PCAP imports extract bounded packet metadata; PCAPNG and live capture are unsupported.

Administrators can publish validated Sigma and YARA-X packs from **Rule Packs**. Scripts pin immutable identifiers whose digest binds engine, version and source. Publication does not automatically activate a pack. See [verification and collection limits](deploy/verification.md) for supported syntax, trust requirements and coverage limits.
