# JOCKY architecture

Defensive forensic DSL. No shell opcode, evasion, offensive execution or automatic elevation.

## Contracts
Rust language -> spanned AST -> semantic validation -> deterministic JSON IR -> bounded runtime -> immutable evidence -> detections -> indexed correlation -> persisted correlation/timeline records -> timeline/risk -> report.
FastAPI owns authentication, SQLite persistence and jobs. React/TypeScript/Vite + CodeMirror consumes real API results. The public landing page and console share a frontend build. The console is entered through `/#/app` and requests credentials only after a successful same-origin backend health check. The deployed public frontend currently has no hosted investigation backend. Its reference lab demo uses a captured, labelled synthetic result. Synthetic evidence is always labelled and separate from live collection.

## Modules
- jocky-ir: versioned plans, nodes, source spans, canonical hashing.
- jocky-language: lexer, parser, dataset/capability validation, lowering.
- jocky-evidence: immutable records, per-stream chains and verification.
- jocky-collectors: bounded native collection and explicit partial states.
- jocky-detection: predicate evaluation contract; pySigma lowers supported rules.
- jocky-analysis: evidence relationships, timestamp-aware timeline, explainable score.
- jocky-runtime: validated operation execution; lab fixtures never execute techniques.
- jocky-cli / jocky-agent: local CLI and restricted agent entrypoint.
- backend: FastAPI, SQLite migrations, session auth, signed checkpoints, persisted correlation and timeline records.
- frontend: editor, workspace, evidence/detection trace, timeline, integrity, reports.

## Integrity and trust
Canonical JSON uses sorted keys, integer/string values and explicit nulls. SHA-256 chain binds stream identity, sequence and record digest. A signed completion checkpoint binds expected streams/counts/heads and the analysis digest, including run identity, mode and captured blobs. Workspace, evidence, detection, timeline, correlation and report reads use the verified bundle. Normalized timeline and correlation tables are retained for indexing but are not authoritative API results. Independently retained public key/checkpoint is the trust anchor. Integrity and collection completeness are separate. A signature does not establish endpoint truthfulness.

## Deployment
The investigation runtime uses local native Windows/Ubuntu processes, SQLite and filesystem blobs; optional authenticated HTTPS polling endpoints. The optional static public preview can be hosted separately and has no access to case data. The coordinator defaults to a repository-local debug worker; JOCKY_WORKER selects an installed release binary. Release binaries can be built, and polling endpoints can execute signed collection tasks. Platform support is only claimed where tested. Resource and path bounds enforced at execution as well as compilation. Read-oriented collection can affect live host state.

## Scope
CURRENT_STATUS.md records the implemented subset and verification commands. Unsupported constructs fail explicitly rather than behaving as no-ops.

## Initial deployment decisions
YARA-X 1.21 uses the official Python native wheel in the coordinator; pySigma lowers predicates to the Rust evaluator. This avoids Wasmtime/MSVC packaging during the GNU Windows bootstrap. Rust handles compiler, native collectors, hash chain and analysis; Python coordinates stages and renders reports. SQLite uses explicit versioned SQL migrations and parameterized sqlite3 transactions instead of an ORM. A Python polling client dispatches source-bound signed collection payloads to the existing native worker. The coordinator persists task assignment, expiry and results in SQLite; endpoint enrollment uses separate revocable machine credentials. The container deployment uses one coordinator replica and persistent evidence/signing-key volumes.

## Dataset functions and rule publication

Dataset functions are expanded into the existing bounded IR at compile time, with deterministic local bindings and call-site spans. No runtime code loading or recursion is introduced. Built-in rule bytes retain compiler-pinned digests. Published packs use a content address binding engine, version and source; scripts pin that identifier, and the coordinator verifies stored content before evaluation. The native compiler validates custom identifier syntax without loading rule files. Administrator publication is separate from investigation execution.
