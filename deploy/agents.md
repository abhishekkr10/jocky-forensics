# Authenticated endpoint collection

Agents poll the coordinator over HTTPS. They do not listen for inbound connections or provide a shell. Enrollment requires an administrator session and CSRF token. Machine credentials are separate from browser sessions and stored as hashes by the coordinator. Revocation cancels outstanding tasks.

1. Build the endpoint's native binary with `cargo build --release --bin jocky` and install Python 3.12 or later.
2. POST `/api/v1/agents` using an administrator session, with `hostname`, `platform` (`windows` or `ubuntu`), and `approved_root` set to the absolute directory explicitly authorized for file collection **on that endpoint**.
3. Save the returned credential securely on the endpoint. It is shown once. Retrieve the coordinator public key from a verified case checkpoint and compare it through an independent trusted channel.
4. Create an untracked, access-controlled JSON configuration file with these fields:

```json
{
  "coordinator": "https://forensics.example.org",
  "credential": "<enrollment credential>",
  "public_key": "<independently verified coordinator public key hex>",
  "approved_root": "/srv/approved-evidence",
  "worker": "/usr/local/bin/jocky"
}
```

Use endpoint-native absolute paths on Windows. Keep this configuration outside the source checkout; never publish credentials. The resolved root must match enrollment exactly.

```sh
python -m backend.app.agent_client --config /etc/jocky/agent.json
```

Run from an installed checkout with the `backend` Python package available. `--once` provides a single heartbeat/poll for diagnostics. The agent retries connectivity every five seconds without logging credentials. Redirects are rejected, TLS certificates are verified, and plaintext HTTP is allowed only on loopback.

Use the enrolled UUIDs as live targets:

```text
mode live
target ["<agent UUID>"]
collect system_information as s
collect processes max_records=200 as p
verify evidence
```

Tasks contain source-bound signed plans. Native workers verify the pinned key, source/plan digest, operation and approved root before collection. Result submission is restricted to the assigned agent, expires after 45 seconds, and is accepted only once. A server restart interrupts outstanding tasks rather than automatically replaying collection. Cancellation stops further dispatch and rejects late results; an already executing native collector may finish within its timeout. Remote uploads are limited to 2 MiB; larger file collections fail explicitly.

Current dispatch processes endpoints in plan order; different investigations can use the coordinator's two worker threads concurrently. The two-identity integration test runs on a single machine. Separate Windows/Ubuntu hosts, production HTTPS, endpoint packaging and automatic service installation remain unverified. Authentication identifies a credential holder, not the truthfulness of endpoint evidence.
