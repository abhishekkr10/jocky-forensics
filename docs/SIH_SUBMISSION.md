# SIH submission guide

## Demonstration flow

1. Start the local API and frontend using the commands in `README.md`.
2. Sign in with the local demo credential shown in the login screen.
3. Open **JOCKY Editor** and load **Deterministic lab**.
4. Run the investigation and open **Workspace** after completion.
5. Show the pipeline, evidence graph, telemetry coverage, Sigma/YARA findings and risk explanation.
6. Open **Evidence** to trace a finding to its collector and source line.
7. Open **Integrity** to verify the signed checkpoint and run the lab-only tamper test.
8. Open **Reports** to generate the portable HTML or JSON case bundle.

The **Multi-endpoint lab** example demonstrates independent evidence streams for two synthetic targets. It is safe fixture data and does not contact remote systems.

## Implemented scope

JOCKY includes a deterministic language and intermediate representation, bounded Windows/Linux-oriented collectors, event-log normalization, Sigma and YARA-X evaluation, evidence provenance, per-stream hash chains, signed checkpoints, correlation, timelines, process lineage, reports and an authenticated local console.

The platform also maps defensive indicators for process-injection, API-tampering, vulnerable-driver, suspicious native-tool and persistence telemetry. These are detections over observed or synthetic records; the framework never executes those techniques.

## Scope boundary

The implementation intentionally excludes AV bypass, polymorphic evasion, process injection, reflective loading, privilege escalation, BYOVD exploitation, EDR disabling, covert routing and domain fronting. The lab can represent related indicator names as synthetic evidence so investigators can validate detection and reporting without running an offensive technique.

## Reproducibility

The repository contains the source, fixtures, rule packs, tests, CI workflow and local startup commands needed to reproduce the demonstration. Remote deployment is outside this submission; the supported demonstration runs on loopback.
