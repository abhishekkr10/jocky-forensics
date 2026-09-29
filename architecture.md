# JOCKY architecture

Defensive forensic DSL. No shell opcode, evasion, offensive execution or automatic elevation.

## Contracts
Rust language -> spanned AST -> semantic validation -> deterministic JSON IR -> bounded runtime -> immutable evidence -> detections -> indexed correlation -> timeline/risk -> report.
FastAPI owns authentication, SQLite persistence and jobs. React/TypeScript/Vite + CodeMirror consumes real API results. Synthetic evidence is always labelled and separate from live collection.

## Modules
- jocky-ir: versioned plans, nodes, source spans, canonical hashing.
- jocky-language: lexer, parser, dataset/capability validation, lowering.
- jocky-evidence: immutable records, per-stream chains and verification.
- jocky-collectors: bounded native collection and explicit partial states.
- jocky-detection: predicate evaluation contract; pySigma lowers supported rules.
- jocky-analysis: evidence relationships, timestamp-aware timeline, explainable score.
- jocky-runtime: validated operation execution; lab fixtures never execute techniques.
- jocky-cli / jocky-agent: local CLI and restricted agent entrypoint.
- backend: FastAPI, SQLAlchemy/SQLite, migrations, session auth, signed checkpoints.
- frontend: editor, workspace, evidence/detection trace, timeline, integrity, reports.

## Integrity and trust
Canonical JSON uses sorted keys, integer/string values and explicit nulls. SHA-256 chain binds stream identity, sequence and record digest. A signed completion checkpoint binds expected streams/counts/heads. Independently retained public key/checkpoint is the trust anchor. Integrity and collection completeness are separate. A signature does not establish endpoint truthfulness.

## Deployment
Local native Windows/Ubuntu processes, SQLite and filesystem blobs; no distributed infrastructure. Release binaries on endpoints. Platform support is only claimed where tested. Resource and path bounds enforced at execution as well as compilation. Read-oriented collection can affect live host state.

## Scope
CURRENT_STATUS.md records the implemented subset and verification commands. Unsupported constructs fail explicitly rather than behaving as no-ops.

## Initial deployment decisions
YARA-X 1.21 uses the official Python native wheel in the coordinator; pySigma lowers predicates to the Rust evaluator. This avoids Wasmtime/MSVC packaging during the GNU Windows bootstrap. Rust handles compiler, native collectors, hash chain and analysis; Python coordinates stages and renders reports. SQLite uses explicit versioned SQL migrations and parameterized sqlite3 transactions instead of an ORM. Remote agent transport is not yet claimed. Native agent is a local JSON worker only.
