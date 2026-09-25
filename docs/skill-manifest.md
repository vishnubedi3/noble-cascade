# Capability inventory — status meanings

`agent-skills/manifest.yaml` (34 entries), `agent-skills/INSTALLATION_MANIFEST.yaml` (34 entries) and `agent-skills/CAPABILITY_MAP.yaml` describe **historical skill references**, not 34 installed upstream projects. No upstream source version, commit, license metadata, or integration was verified just because a wrapper/runbook exists. All historical upstreams are marked `upstream_installed: false`. The old `commit: HEAD`, fabricated `version` claims and blanket `INSTALLED` statuses were removed.

| Status | Count | Meaning |
| --- | ---: | --- |
| `LOCAL_ADAPTER` | 14 | Some intent implemented independently in `noble/`; **not** upstream integration or complete capability |
| `PARTIAL_IMPLEMENTATION` | 3 | A constrained local subset exists (process command boundary, Python SQL-candidate inspection, synthetic reproduction) |
| `REFERENCE_ONLY` | 12 | Runbook/example/wrapper only; no registered executable capability |
| `UNAVAILABLE` | 5 | External SAST, SCA, secret scanner, IaC scanner or Docker backend absent/unintegrated |
| `FULL_IMPLEMENTATION` | **2 runtime tools** | Registered offline built-ins: `static-code-scan`, `fixture-sql-verify`; full only **within their narrow declared coverage**, not broad security testing |

`runtime_registered: false` on all 34 historical entries means a historical script cannot be selected as a tool. `manifest.yaml:runtime_tools` is the only advertised executable tool list. Use `noble tools` and `noble doctor` for actual availability. `integration_wrapper` identifies a file, **not** an upstream installation. If a capability is missing, the runtime returns an explicit refusal rather than silently falling back.

Most important changes from the original prototype: legacy scope wrapper delegates to the anchored scope engine, `--approve` no longer self-approves, scanner wrappers fail nonzero when not available, `validate-findings.cjs` performs real Draft-07 validation, and sample `findings.json` was emptied so it cannot pose as a confirmed report. See the [historical execution baseline](execution-report-89f3ab.md) and [engineering report](engineering-report.md) for before/after evidence.
