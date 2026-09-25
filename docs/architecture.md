# Noble Cascade Architecture — implemented state

The current runtime is a **bounded, offline, local CLI**. The original 7-category / 34-skill architecture is an inventory and inspiration, not an installed upstream stack. `agent-skills/manifest.yaml:runtime_tools` is the concise catalog of what can actually execute (two trusted built-ins). There is no web API, generic scanner orchestrator, Docker runtime, outbound network service, credential broker, or multi-user identity provider.

```
Trusted local OS identity + operator
  │ CLI: noble authorize / scan / validate / inspect / report / audit
  ▼
Typed SecurityRequest + request-ID reservation (SQLite transaction)
  │ untrusted input; bounded JSON-schema tool parameters
  ▼
ScopeEngine → Authorizer → RiskEngine → ApprovalManager
  │ deny unknown + exact target/action/purpose/time grant
  │ high risk requires distinct approver; no high-risk tools registered
  ▼
ToolRegistry → preconditions → persistent rate/concurrency lease
  │ names and argv fixed by trusted code; no direct shell or network tool
  ▼
CommandRunner (python -I, subprocess, rlimit, timeout, capped I/O)
  │ trusted worker code, filesystem/network NOT isolated by OS sandbox
  ▼
AST source analysis OR known synthetic SQLite verifier
  │ target files are read as DATA; never imported or executed
  ▼
OutputValidator (schema + ID/target/tool/version + exact source line)
  │ fixture verifier: hash + independent SQLite reproduction
  ▼
Evidence (redacted/quarantined, hashed, write-once IDs, provenance)
  ▼
Reasoning (false-positive analysis, separate confidence/severity)
  ▼
Finding (candidate or confirmed SYNTHETIC) → Reporter
  ▼
SQLite audit chain (decision records with SHA-256 links)
```

## Trust and failure boundaries

| Boundary | Input → output | Trust | Failure / enforcement |
| --- | --- | --- | --- |
| OS account → CLI | local commands → typed request | Repo-owning OS UID only; `USER`/`LOGNAME` env ignored | Cannot claim multi-user or remote identity assurance; state directory 0700, DB 0600 |
| CLI → scope | raw target/action → canonical target + ALLOW/DENY/UNKNOWN | Operator strings untrusted; YAML policy trusted only if checkout owner trusted | Anchored repository/domain matches; URL query/credentials/escapes denied; CIDR fully contained; realpath blocks outside-root symlinks; UNKNOWN denies |
| Scope → grant | canonical target/action/purpose → authorization | Issuer is trusted local checkout owner; grant ID is not a universal boolean | Missing/expired/wrong-principal/wrong-action/wrong-target/wrong-purpose/wrong-permission deny |
| Risk → approval | action/context → LOW/MEDIUM/HIGH/CRITICAL → bound decision | Target data cannot approve itself | Unknown actions CRITICAL; HIGH requires separate principal and unexpired bound state; revoked/changed/forged deny; no HIGH tool registered |
| Tool selection | registered name/schema → trusted worker invocation | Registry trusted code, request parameters untrusted | Unknown tools/target types/network/side effects/sandbox missing refuse; no arbitrary command path |
| Worker → output | local source text → bounded JSON | Worker trusted code; source/tool output untrusted data | Non-root file/symlink escape, large file, timeout, nonzero exit, oversized output, schema/provenance mismatch fail closed or explicit inconclusive |
| Output → evidence | checked source/test result → hashed evidence | Source evidence TARGET_CONTENT; test result DERIVED_AGENT_DATA | No raw stdout persisted; snippet must equal actual source line; prompt-like text quarantined; sensitive values redacted |
| Evidence → finding | linked evidence → candidate/confirmed | Tool assertions are insufficient by themselves | Candidate for generic AST; confirmed only for exact known fixture after parent independently reproduces it; report checks evidence IDs/hashes |
| Decisions → audit | policy/execution events → chained SQLite rows | State owned by local OS user | Audit write failure before execution prevents tool launch; chain detects accidental/naive alteration, **not** same-user DB rewrite |

## Typed lifecycle and outcomes

`CREATED → VALIDATING → SCOPE_CHECK → AUTHORIZATION_CHECK → RISK_ASSESSMENT → WAITING_FOR_APPROVAL → APPROVED → EXECUTING → COLLECTING_EVIDENCE → VALIDATING_RESULT → COMPLETED` is the happy path. Terminal alternatives: `BLOCKED`, `FAILED`, `TIMED_OUT`, `CANCELLED` (reserved, no cancellation interface yet). Results store the state history and a structured outcome such as `success_no_findings`, `success_with_findings`, `denied_authorization`, `approval_required`, `tool_unavailable`, `sandbox_unavailable`, `invalid_scope`, `invalid_output`, `inconclusive`, `rate_limited`, or `timeout`. A worker returning no observations is not treated as a guarantee the target is secure.

## Files and persistence

- `config/runtime.yaml` — bounded, versioned, validated offline limits; no network mode.
- `agent-skills/governance/scope-enforcement/scope-policy.yaml` — deny-by-default authorized *local* roots plus historical repo/domain entries. Registry target-kind restrictions mean repo/domain scope alone cannot trigger a local tool.
- `noble/` — typed models, policy engines, command boundary, evidence/reasoning/reporting, CLI, and built-ins.
- `tests/fixtures/sql_injection.py` — deliberately vulnerable *inert* source file. The verifier first checks its fixed SHA-256; it never imports this file.
- `.noble/state.db` — ignored local state: grants, approvals, request ID reservations/results, evidence, findings, rate leases, hash-chained audit. File owner mode 0600 in directory 0700. Do not commit.
- `agent-skills/` — historical reference wrappers/runbooks. The `run_sast.py` adapter delegates only to the registered local scanner and requires a grant; other external scanner shims return nonzero UNAVAILABLE.

## Scope of process isolation

`PROCESS_LOCAL` means `python -I` and sanitized environment, fixed `argv` with `shell=False`, wall-time and CPU limits, RAM/file descriptor/file-size limits, bounded stdin and captured output, and new process group terminated on timeout. This is *not* a container, seccomp, filesystem namespace, DNS boundary, or egress firewall. The only reachable worker code is trusted, non-network, read-only built-in logic; third-party scanners are **never** launched from this boundary. `docker-compose.yml` is an untested, network-disabled reference file, not an integrated backend.
