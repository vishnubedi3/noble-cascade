# Execution Report — Commit `89f3ab`

> **Historical baseline, not current behavior.** This report records execution of the *original* prototype before the control-plane implementation. The defects it documented have been addressed or explicitly marked unavailable; consult [README](../README.md), [skill inventory](skill-manifest.md), and [engineering report](engineering-report.md) for current status. In particular, the original `findings.json` contained a placeholder that has since been removed.

**Commit:** `3f181fec1b7a6675fe0bd98b3c92d31287b86c5e` (root commit, message `89f3ab`)
**Contents:** 53 files, 5,069 insertions — the full Noble Cascade agent-skill ecosystem
**Executed:** 2026-09-25 (UTC) in the Arena sandbox, on branch `arena/01a0d89d-noble-cascade`
**Scope of execution:** every runnable entry point introduced by the commit, run through the
governance order the README specifies (scope gate → approval gate → execution → validation → reporting).

---

## 1. Environment preparation

| Item | State before | Action |
|---|---|---|
| Python | 3.11.2 | — |
| PyYAML | **missing** (`ModuleNotFoundError: No module named 'yaml'`) — `enforce_scope.py` and `validate-stack.py` both import it, so the stack could not start | `pip install --user --break-system-packages pyyaml` → **pyyaml 6.0.3** |
| jsonschema | missing | installed (used for the real schema check in §4) |
| Node | v22.22.3 | — |
| Go | **absent** — no `go` binary anywhere on the filesystem, `apt-get -s install golang-go` → `E: Unable to locate package`, `go.dev` TLS handshake blocked, `deb.debian.org` unreachable | see §6 |
| Docker | **absent** | see §6 |
| semgrep / bandit / checkov / gitleaks / osv-scanner | all absent | see §5 |

---

## 2. Governance gates (executed)

| Gate | Invocation | Result |
|---|---|---|
| Scope — allow | `enforce_scope.py vishnubedi3/noble-cascade static-analysis` | `[+] Scope check passed`, rc=0 |
| Scope — forbidden target | `enforce_scope.py unauthorized-target.gov remote-code-execution` | `[!] matches forbidden pattern '*.gov'. BLOCKED.`, rc=1 |
| Scope — forbidden action | `enforce_scope.py vishnubedi3/noble-cascade data-exfiltration` | `[!] Action 'data-exfiltration' is forbidden by policy. BLOCKED.`, rc=1 |
| Approval — LOW | `approval_gate.py static-analysis` | automatic approval, rc=0 |
| Approval — MEDIUM | `approval_gate.py code-patching` | logged and proceeded, rc=0 |
| Approval — HIGH, no override | `approval_gate.py poc-execution` | `HIGH risk action halted`, rc=1 |
| Approval — HIGH, `--approve` | `approval_gate.py poc-execution --approve` | proceeded, rc=0 (operator authorization = the "execute the commit" instruction; recorded in §3) |
| Approval — unknown action | `approval_gate.py some-unknown-action` | defaulted to HIGH and halted, rc=1 |
| Authorization | `authz.py` | `operator`/`scan` allowed, `operator`/`controlled-test` denied — assertions passed, rc=0 |

## 3. Skill execution log (all 20 runnable entry points)

| Skill | Exit | Result |
|---|---|---|
| `governance/scope-enforcement/enforce_scope.py` | 0 | allow + 2 deny paths exercised (see §5.1 for a bypass found) |
| `governance/human-approval/approval_gate.py` | 0 | LOW / MEDIUM / HIGH / unknown tiers all exercised |
| `governance/authorization-policy/authz.py` | 0 | role/capability assertions passed |
| `governance/escalation/escalate.py` | 0 | emitted CRITICAL `PromptInjectionAttempt` payload, `action: HALT_AGENT_EXECUTION` |
| `code/language-detection/detect.py` | 0 | `{"languages": [], "build_systems": []}` — see §5.4 |
| `code/multi-language-analysis/run_sast.py` | 0 | degraded: `No such file or directory: 'semgrep'` — Bandit fallback never reached (§5.2) |
| `code/dependency-analysis/audit_deps.py` | 0 | degraded: no `package.json`/`requirements.txt`/`pyproject.toml` at root; `osv-scanner` absent |
| `security/secrets-analysis/scan_secrets.py` | 0 | degraded: `gitleaks` absent, regex fallback never reached (§5.2) |
| `security/configuration-security/scan_iac.py` | 0 | degraded: `checkov` absent |
| `operations/safe-reconnaissance/recon.py` | 0 | `total_files: 11`, mode `passive-recon` |
| `operations/rate-limiting/ratelimit.py` | 0 | calls 1–5 allowed, call 6 throttled at 5/10s |
| `operations/audit-logging/logger.py` | 0 | wrote `agent-skills/operations/audit-logging/audit.log` (1 JSON event, untracked) |
| `reasoning/confidence-assessment/confidence.py` | 0 | `{confidence_score: 100, confidence_level: HIGH}` |
| `resilience/prompt-injection-defense/sanitize.py` | 0 | neutralized `ignore previous instructions` → `[NEUTRALIZED_INJECTION_ATTEMPT]` |
| `resilience/tool-output-validation/validate_output.py` | 0 | benign sample passed |
| `reporting/vulnerability-reporting/report_generator.py` | 0 | findings.json structure confirmed |
| `reporting/vulnerability-reporting/validate-findings.cjs` | 0 | reported "1 findings" — but does not actually validate (§5.3) |
| `reporting/remediation/remediate.py` | 0 | CWE-89 guidance emitted (function returns dict; `__main__` prints only the header) |
| `reporting/reproduction/poc_builder.py` | 0 | emitted local `assert True` test stub for SQL Injection (post-approval) |
| `tests/validate-stack.py` | **0** | **ALL VALIDATION TESTS PASSED** — 34 skills registered, scope, approval, injection-defense, reporting |

Manifest cross-check (via PyYAML): `manifest.yaml` = **34 skills**, `INSTALLATION_MANIFEST.yaml` =
**34 implementations, all `INSTALLED`**, matching `docs/skill-installation-report.md` lines 14–15.
Category split: governance 5, reasoning 5, code 5, security 7, operations 5, resilience 3, reporting 4.
All 34 `integration_wrapper` paths in `manifest.yaml` exist on disk (0 missing).
`docker-compose.yml` parses cleanly (services `agent-sandbox`, `proxy`).

## 4. Real schema validation of the committed findings

`validate-findings.cjs` never opens `report-schema.json`, so its rc=0 proves nothing. Re-ran the check
properly with `jsonschema` Draft-07 against the committed schema:

```
findings validated: 1
schema errors: NONE
```

The committed `findings.json` (FINDING-001) genuinely conforms to `report-schema.json`.

## 5. Defects observed while executing (all reproduced)

1. **Scope enforcement is not deny-by-default for substring matches.** `enforce_scope.py` allows a target
   when `domain in target` or `prefix in target`, so three out-of-scope targets returned **rc=0 (ALLOWED)**:
   - `evil.com/localhost` → allowed (contains `localhost`)
   - `attacker.example/?repo=vishnubedi3/noble-cascade` → allowed (contains `vishnubedi3`)
   - `notvishnubedi3/noble-cascade` → allowed (contains `vishnubedi3`)
   Matching must be anchored/prefix-exact for the "deny-by-default" claim to hold.
2. **Fallbacks in the scanner wrappers are unreachable.** In `run_sast.py` and `scan_secrets.py` the
   `subprocess.run([tool, "--version"])` probe raises `FileNotFoundError` when the tool is missing, which
   jumps straight to `except`, so the `else` branch (Bandit) and the regex secret scan never execute.
   Confirmed: neither `bandit` nor the "Gitleaks not installed" message ever printed.
3. **`validate-findings.cjs` performs no validation.** It reads `report-schema.json` into `schemaPath`
   and never uses it; it only counts array elements and prints success. It also silently creates
   `findings.json` if absent, so a deleted findings file still "passes".
4. **`detect.py` excludes `agent-skills/` from its own walk** (`if ... or "agent-skills" in dirpath`), so on
   this repository it reports `languages: []` even though 19 Python files and 1 Go file are present.
5. **`audit.log` is written into the tracked tree and is not gitignored** — `.gitignore` (a Dynamics 365 BC
   template) has no entry for it; after this run `git status` shows `?? agent-skills/operations/audit-logging/audit.log`.
6. `logger.py` and `escalate.py` use `datetime.utcnow()`; clean on the 3.11.2 runtime used here, deprecated
   in Python ≥ 3.12 (not exercised in this environment).

## 6. Parts of the commit that could not be executed here

- **`governance/safety-policy/guardrails.go`** — no Go toolchain in the sandbox and no route to obtain one
  (`go` not on the filesystem, `golang-go` not in the apt index, `go.dev` and `deb.debian.org` both
  unreachable). **Unchecked.** Its logic is a plain substring denylist over 6 destructive commands.
- **`operations/sandbox-execution/docker-compose.yml`** — no Docker daemon/binary. **Not executed**; YAML
  parsed and both services verified present.
- Semgrep / Bandit / Checkov / Gitleaks / OSV-Scanner analyses — binaries unavailable, so those four
  skills ran to completion but produced no security coverage.

## 7. Artifacts produced by this run

- `agent-skills/operations/audit-logging/audit.log` (untracked, written by the audit-logging skill)
- `docs/execution-report-89f3ab.md` (this report)

No tracked file was modified by the execution.
