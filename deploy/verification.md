# Verification and collection limits

## Independent checkpoint verification

Generate a JSON report or export a bundle with the CLI. Retain its checkpoint and public key separately through an authenticated channel. A public key bundled with the evidence is not an independent trust anchor.

```sh
python -m backend.app.cli verify-bundle case.json --trusted-key retained-public-key.txt
```

This existing command verifies the signature, signed analysis digest, expected streams, record chains and captured blob digests. It needs the native worker, but not the coordinator's private signing key when a trusted public key is supplied. A valid signature does not prove that an endpoint reported truthfully.

## Compound dataset filters

```text
mode lab
collect processes as p
filter p where pid >= 100 and (name == "powershell.exe" or name == "cmd.exe") as selected
assert selected where not name startswith "cmd"
verify evidence
```

`and` binds more tightly than `or`; parentheses change grouping. Literals can be integers, booleans, null or quoted strings. Numeric ordering requires numeric fields. Missing fields do not match comparisons. String comparisons are case-sensitive; Sigma semantics are evaluated separately. Expressions are bounded to 256 tokens and 16 levels of explicit nesting. Reusable functions accept one dataset argument and return a locally produced dataset. Calls are expanded deterministically with isolated bindings and call-site source spans. Nested calls/recursion, control flow and external code execution are not supported. See `examples/functions.jky`.

## Packet capture import

Place an explicitly authorized capture under the local `fixtures/` directory for the current bounded importer. Keep real captures untracked and access-controlled; the repository-wide evidence hygiene rules still apply.

```text
mode live
target host
import pcap "capture.pcap" as packets
export packets json "packet-metadata.json"
verify evidence
```

Only classic PCAP 2.4 with Ethernet link type is supported, up to 1 MiB and 1000 packets. IPv4/IPv6 addresses and available TCP/UDP ports are extracted. Raw timestamp fractions and their precision are retained; normalized timestamps have microsecond precision. Capture timestamps originate from the capture producer. PCAPNG, deep protocol reconstruction, IPv6 extension-header decoding and packet transmission are not implemented. Unsupported captures fail explicitly.

## Journal collection

Ubuntu collection attempts `journalctl` JSON output, bounded by ten seconds, one MiB and the requested record limit. It currently covers accessible entries from the last 24 hours. The raw journal timestamp and unit/message metadata are preserved. Permission restrictions remain explicit; unavailable journals fall back to bounded text logs. The `since` argument does not currently change the journal window. Native Ubuntu execution requires separate verification; Windows tests cover the journal parser only.

## Build validation

CI now specifies Ubuntu and Windows jobs, Rust release artifacts and application tests. This configuration has not run for the current uncommitted changes. Container build, production TLS, separate-host agents and installation on clean machines require verification before a release claim.

## Windows inventory

`collect registry_startup max_records=20 as r` reads current-user/machine Run and RunOnce keys in the native worker registry view. `collect services max_records=20 as s` enumerates Win32 service state and PID through the service-control manager. Both are read-only and report coverage limits. Commands found in registry values are never executed. Drivers, all user hives, alternate registry views and service configuration remain outside this bounded collection.

## Published rule packs

Administrators can validate and publish packs in the Rule Packs screen or POST `/api/v1/rule-packs` with `engine`, `version`, and `source`. Each identifier is `sigma:<digest>` or `yara:<digest>`, where the digest binds the engine, version and source together. Publication never modifies an existing pack. Investigation source references that exact identifier in `hunt sigma` or `scan yara`; the plan, detection metadata and signed analysis retain it. Storage modification fails validation. Original built-in pack identifiers continue to work.

Custom Sigma packs currently require Windows process-creation telemetry and the supported field-predicate subset. YARA scans preserved file bytes. Publishing a pack does not automatically execute it or activate it across other cases. Remote endpoints validate the same deterministic source/plan; rule evaluation remains in the coordinator.
