# Current status

- Phase: integrated local investigation platform; frontend in progress.
- Completed: Rust workspace/compiler/IR/collectors/hash chain/analysis; pySigma predicate lowering; YARA-X adapter; signed checkpoints; FastAPI authentication; SQLite migrations; asynchronous jobs; HTML/JSON reports.
- Working: deterministic lab pipeline produces eight evidence records and two real engine detections; native Windows system/process/network collection.
- Tests passing: 18 Rust unit tests; 20 Python pipeline/API tests; 2 frontend unit tests; 1 Playwright end-to-end test.
- Tests failing: none.
- Limitations: Ubuntu execution unverified; historical native event-log collection skipped explicitly; startup collection covers selected directories; remote transport not implemented; filter/assert supports one comparison.
- Blockers: none for local dashboard integration.
- Next: optional follow-up work is broader Sigma compatibility, richer platform-specific artifact coverage, and remote endpoint transport.
- Verification: `cargo build --workspace`; `cargo test --workspace`; `python -m pytest backend/tests -q`; `npm.cmd --prefix frontend run build`; `npm.cmd --prefix frontend run test`; `npm.cmd --prefix frontend run test:e2e`.
