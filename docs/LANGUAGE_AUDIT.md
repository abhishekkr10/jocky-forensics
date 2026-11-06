# JOCKY language and claim audit

Audit date: 6 November 2026 (Asia/Kolkata). Baseline: `9070daee9d9ce69853812903fa225b19047e74e6`, default branch `master`. All findings below were established before editing tracked files. Commands ran on Windows, Python 3.13 and Cargo 1.98.1 (GNU target).

## Repository map

| Top-level directory | Contents |
| --- | --- |
| `.github/` | CI: Ubuntu/Windows native, backend and frontend checks; container smoke job |
| `backend/` | Python/FastAPI coordinator, auth, SQLite migrations, integrity and detection adapters; 11 test modules plus isolation setup; locked requirements |
| `crates/` | Nine Rust crates: IR, language, evidence, collectors, detection, analysis, runtime, CLI and agent |
| `deploy/` | Caddy gateway configuration, deployment/agent instructions and verification limits |
| `docs/` | SIH demonstration guide and synthetic dashboard image |
| `examples/` | Four JOCKY scripts: triage, live, multi-endpoint and dataset functions |
| `fixtures/` | Harmless synthetic lab marker; no real evidence required |
| `frontend/` | React/TypeScript console and static showcase, synthetic snapshot, CSS, fonts with third-party licenses, unit and browser tests, Vite/TS config |

Root files include Cargo workspace/lock, Dockerfile, compose.yaml, README, architecture and status documents, ignore rules and a line-ending-only .gitattributes. There is no project-wide LICENSE. .git is repository metadata, not application source; target, .venv, artifacts, node_modules and dist were created only as ignored verification outputs.

## Approximate source size

Tracked source only; nonblank physical lines, including comments. Dense one-line Rust/TS files mean line counts are not complexity measures. Excludes lockfiles, fixtures, font assets, generated/build output and the captured JSON demo. Test implementation is counted separately where possible, not disguised as generated code.

| Language | Approx. nonblank lines | Tracked files |
| --- | ---: | ---: |
| Python | 1,766 | 25 |
| Rust | 682 | 14 |
| TypeScript/JavaScript | 581 | 17 |
| CSS | 286 | 3 |
| YAML | 113 | 3 |
| SQL | 73 | 3 |
| JOCKY | 51 | 4 |
| HTML | 1 | 1 |

Python includes 1,193 application lines and 573 test lines. TypeScript/JS includes about 451 implementation/config lines and 130 test lines. Rust unit tests are inline in the 682 lines. Dockerfile/config prose is not counted as a programming language above.

GitHub Linguist's actual API byte counts at audit time: Python 111,072; TypeScript 96,725; Rust 59,268; CSS 20,984; Dockerfile 1,267; HTML 780; YARA 209. Python remains larger than Rust even if its genuine tests are excluded (77,516 application bytes vs 59,268 Rust bytes). Rust is a smaller, substantial component, not the whole platform. No legitimate generated Python/vendor directory explains the result. Existing .gitattributes only normalizes text/line endings; do not mark actual application or tests as generated to change the card.

## Claim audit

| Claim | Where made | Evidence in code | Status | Fix needed |
| --- | --- | --- | --- | --- |
| Rust compiler/parser | Resume, profile README, repo README | crates/jocky-language/src/lib.rs: lex, parse, compile, lower; functions.rs and predicate.rs | TRUE | Identify the mixed stack |
| Deterministic analysis plans | Resume, repo README/architecture | Ordered maps, sequential node IDs, sorted packs/capabilities; language deterministic and IR canonical_key_order tests | TRUE | Scope to identical source/compiler/built-in rules; not all execution outputs |
| Signed evidence checkpoints verified in Rust | Resume | backend/app/integrity.py checkpoint/verify signs and verifies Ed25519; calls native stream verify | PARTLY TRUE | Attribute signature creation/verification to Python; Rust verifies chains and signed jobs |
| Rust evidence integrity checks | Profile, repo README | jocky-evidence seal/verify binds SHA-256 record digest, stream identity, sequence and chain; valid/tampering tests | TRUE | Distinguish chain consistency from a trusted signature |
| Signed job authorization in Rust | Repo README | jocky-runtime verify_job uses ed25519-dalek and trusted env key; checks signature, expiry/future time, plan/op/root binding | TRUE | Do not call these checkpoint signatures |
| Working local forensics platform | Profile, README | Python engine/native bridge, FastAPI, SQLite, React; pipeline/API/browser suite | TRUE | Keep local scope |
| Labelled synthetic public demo | Resume, profile, README | Showcase.tsx imports lab-preview.json; eight records all provenance_kind synthetic; snapshot/no-execution labels | TRUE | Make static preview scope explicit |
| Eight observations, Sigma finding and YARA-X match | Repo README | Fresh triage CLI: eight records, two detections, valid verification; harmless marker fixture | TRUE | Not a detection-accuracy benchmark |
| Bounded collection | Description, README | Compiler limits; native record caps, file capability root, file bytes/time, event-log bounds; subprocess timeout | TRUE | Per-collector controls; not hard OS CPU/memory quotas; some APIs enumerate before truncation |
| Traceable detections | Description, README | engine source_span, operation_id, evidence IDs; detection rule versions/digests; source links in console/report | TRUE | Keep |
| Checkpoint protects expected streams and derived analysis | README, architecture | Python verifies signer/signature, plan and analysis digests, expected stream count/identity/head/completeness; Rust checks entries; blob checks; tamper tests | TRUE | Trust key must be independently retained; integrity is not endpoint truthfulness |
| Python-free shortest walkthrough | README implication | CLI simulate/run/report and bundle verify call .venv Python; native compile/check are Rust | PARTLY TRUE | Put venv installation before walkthrough |
| Complete online investigation service | Not asserted; README says unavailable | Public site is static; backend/worker are local | NOT SUPPORTED | Do not claim hosted cases or live public verification |
| Linux/clean-machine/production readiness | README limitations and deploy docs | CI configuration exists; current audit is Windows only | PARTLY TRUE | Keep separate-host, TLS, Linux execution and clean-machine validation as unverified here |
| Dataset functions and typed filters | Repo README | language functions/predicate modules, Rust and Python tests | TRUE | Keep recursion/nested-call exclusions |
| PCAP, Windows inventory and published rules | Repo README | pcap.py, windows_inventory.rs, rulepacks.py and corresponding passing tests | TRUE | Keep classic-PCAP/selected-registry/service-state and supported-rule-subset boundaries |
| Session authentication/CSRF/first-login behavior | Repo README | auth.py, main.py; API/security tests | TRUE | Windows key-file ACLs and production HTTPS not separately certified by this audit |

## Commands and observed results

- `cargo build --workspace --locked`: PASS, debug workspace build (1m41s on this checkout).
- `cargo test --workspace --locked`: PASS, 23 unit tests, zero failures; doc-test groups contain no tests.
- `cargo clippy --workspace --all-targets --locked`: PASS with existing warnings. Clippy initially was not installed; installed with `rustup component add clippy`. Not a warnings-as-errors pass; CI does not configure clippy.
- `python -m venv .venv`, then `.venv/Scripts/python.exe -m pip install -r backend/requirements.lock`: PASS, isolated pinned environment.
- `.venv/Scripts/python.exe -m pytest backend/tests -q`: PASS, 52 tests, one FastAPI/Starlette TestClient deprecation warning.
- `npm.cmd --prefix frontend ci`, `npm.cmd --prefix frontend run build`: PASS.
- `npm.cmd --prefix frontend test`: PASS, eight tests in two files.
- `npm.cmd --prefix frontend run test:e2e`: PASS, one full investigation browser test (compile, trace, verify, tamper-copy, report and mobile checks).
- `cargo run -p jocky-cli -- check examples/triage.jky`: PASS.
- `cargo run -p jocky-cli -- compile examples/triage.jky --output C:/portfolio/jocky-audit/triage.ir.json`: PASS.
- `cargo run -p jocky-cli -- simulate examples/triage.jky --output C:/portfolio/jocky-audit/triage/bundle.json`: PASS, eight records, two detections, integrity valid.
- `cargo run -p jocky-cli -- verify C:/portfolio/jocky-audit/triage/bundle.json --trusted-key C:/portfolio/jocky-audit/triage/bundle.public-key.txt`: PASS, integrity valid. Simulation used isolated JOCKY_DATA/JOCKY_KEY_PATH outside source.

## Hygiene, links and limitations

README local paths exist and its public website/badge returned HTTP 200. GitHub description accurately described features but omitted the mixed-language architecture. Topics included python/rust/sigma/yara/digital-forensics/evidence-integrity. No tracked .env/private-key files found. A high-signal scan over 290 historical objects found no private-key PEM blocks, GitHub token formats, AWS access-key IDs or live Stripe key formats. This targeted search can miss arbitrary passwords, encrypted credentials or unrecognized formats; no credential values are printed. Test passwords are fixture values, not published production credentials. Do not interpret this as a full security audit.

The checked synthetic source/snapshot uses fixed lab hostnames, documentation IP addresses and a harmless marker; all eight public snapshot records identify synthetic provenance. Real local collection in tests stays in isolated temporary storage. This does not independently attest the origin of every external image or historical binary.

No build/test failure requires new feature code. Existing determinism tests already cover the stated property; no mirror test added. Clippy style/readability warnings remain. Several source files are highly compressed, making review harder. Missing project license requires the owner's explicit selection; no license is assumed. Linux execution, current remote CI, container deployment, production TLS, independent host agents and clean-machine install are not certified by these local checks. No files deleted and no history rewritten.

## Accurate application wording

Tech Stack: Rust, Python/FastAPI, React/TypeScript, SQLite.

Resume bullet: Compiled investigation scripts into deterministic plans in Rust; combined Rust hash-chain checks with Python Ed25519 checkpoint verification and a synthetic demo.

Profile row: Rust compiler and evidence-chain checks, Python/FastAPI orchestration and Ed25519 checkpoints, and a local React/TypeScript console with a static synthetic demo.
