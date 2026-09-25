> **Superseded in part (2026-09-25, Master Prompt IV):** CI is now active —
> `.github/workflows/ci-hardened.yml` was relocated from `docs/` and executes
> the full governance chain. See `docs/ci-activation.md` and
> `docs/repository-governance.md`. Rows below marked historical describe the
> pre-activation state and are kept for audit continuity.

# Noble Cascade — Engineering Report

- **Date:** 2026-09-25
- **Working branch:** `arena/01a0d89d-noble-cascade`
- **Baseline:** main commit `3f181fec1b7a6675fe0bd98b3c92d31287b86c5e` (message `89f3ab`)

## Executive state

The architectural prototype is now a **real, bounded offline control plane** for two local built-in capabilities. Every *registered* execution passes canonical scope, an exact principal/target/action/purpose/time grant, contextual risk, approval checks, registry preconditions, persistent rate/concurrency reservations, an audited fixed-argv worker, schema/source validation, write-once evidence, cautious reasoning, and an evidence-backed report. The working SQL fixture yields a candidate from AST alone and a **confirmed synthetic** finding only after hash-locked, independent in-memory SQLite reproduction. This is **not** a general pen-testing agent, production sandbox, upstream scanner integration, independently authenticated multi-user service, or proof of legal authorization.

The repo contains 34 historical skill references but only **2 runtime-registered tools**. Historical statuses are truthful: 14 `LOCAL_ADAPTER`, 3 `PARTIAL_IMPLEMENTATION`, 12 `REFERENCE_ONLY`, 5 `UNAVAILABLE`; zero upstream projects installed/pinned by this repository. `noble doctor` displays both runtime and unavailable states.

## Baseline → final

| Boundary / behavior | `89f3ab` baseline | Final implementation |
| --- | --- | --- |
| Orchestration | Independent examples, no controlled end-to-end path | `NobleEngine` typed lifecycle and structured outcomes; all registered tools use it |
| Scope | Allowed substring repository/domain matches, including `evil.com/localhost` and `notvishnubedi3/noble-cascade` | Anchored normalized repo/domain rules, exact local paths, excluded targets, full CIDR containment, scoped time windows, ambiguity fails closed |
| Authorization | `AuthorizationManager` returned true from role alone | OS-account-bound exact-target/action/purpose/role/privilege/time grants, SQLite record and issuance audit |
| Approval | `--approve` was a universal HIGH bypass | Bound PENDING/APPROVED/REJECTED/EXPIRED/REVOKED state; separate granted principal, compare-and-swap, no self-approval; no HIGH executable tool |
| Execution | Wrapper subprocesses silently missed dependencies or reported rc=0 without a scan | Two allowlisted offline tools, fixed `python -I` argv, sanitized env, process/CPU/RAM/fd/output/wall bounds, sandbox/network fail-closed |
| Audit / rate | Standalone log stub and per-process demo limiter | Owner-only SQLite chained audit, persistent per-principal/tool/target rate + global concurrency leases, request ID replay reservation |
| Evidence / findings | Example `findings.json` claimed `confirmed` without a vulnerability; JS validator counted entries without schema checks | Real Draft-07 compatibility check; example emptied; new schema/target/line/AST/provenance-validated evidence and separate severity/confidence; no generic result auto-confirmation |
| Package/tool health | No package metadata, lock, CI or real test matrix | `pyproject.toml`, hashed runtime/dev locks, `noble doctor`, CLI, layered tests, lint/type/SAST/audit/secret checks and an **inactive** CI workflow template |

### Repository history established

The initial checkout was **shallow**, so `89f3ab` first appeared to be a root commit; after a read-only fetch of history, its actual parent is `b6a43db`. Historical work on `arena/019fdbb4-noble-cascade` ended at `a3b3a14`; it was merged into main via `463ef89` (PR #1). `git merge-base main a3b3a14` is `a3b3a14`. No working branch was switched or pushed.

## Implemented and integrated

- **Runtime foundation:** `noble/models.py`, `noble/errors.py`, `noble/engine.py` and validated `config/runtime.yaml`; typed requests, targets, grants, approvals, risks, tool invocations, evidence, findings, audit events, results and state histories. Distinct blocked, invalid, unavailable, timeout and inconclusive outcomes.
- **Governance:** `noble/targets.py`, `scope.py`, `authorization.py`, `risk.py`, `approvals.py`, `network.py`; strict canonicalization, default deny, OS UID principal, high-risk binding primitives, no network mode.
- **Tool execution:** `noble/registry.py`, `execution.py`, `builtins/worker.py`, `builtins/scanner.py`, `builtins/fixture_sql.py`. Trusted, read-only Python AST candidate rule; exact source-line re-check; one controlled SQLite fixture reproduction independently repeated in the parent. Worker code never imports the target.
- **Evidence and reasoning:** `evidence.py`, `trust.py`, `reasoning.py`; size/schema/duplicate-key/association validation, trust labels, redaction, prompt-like text quarantine, provenance/hash, false-positive notes and explicit candidate vs synthetic confirmed status.
- **Persistence/reporting:** `store.py`, `audit.py`, `reporting.py`; owner-only SQLite store and audit hash chain; evidence-bound JSON/Markdown reports without placeholder claims.
- **Operator experience:** `noble doctor`, `scope`, `tools`, `authorize`, `scan`, `validate`, `inspect`, `findings`, `report`, `audit`. A local OS identity can issue exact grants; it cannot independently attest third-party permission.
- **Defensive legacy corrections:** `enforce_scope.py` delegates to the anchored engine; `approval_gate.py` rejects `--approve`; unavailable scanners/recon/false-success shims exit nonzero; reporting schema adapter actually validates; fabricated finding removed; language detector includes skill files and `.cjs`; Docker example is network-disabled and reference-only.

## Validation (actual results, not projected CI results)

| Check | Result |
| --- | --- |
| Unit tests | **27 collected/passed** |
| Integration tests (including CLI/evidence/report path) | **7 collected/passed** |
| Security/adversarial tests | **23 collected/passed** |
| Regression tests | **8 collected/passed** |
| Invariant tests | **6 collected/passed** |
| Total pytest | **71 passed** |
| Legacy smoke suite | **PASS** — 34 reference paths, 2 runtime tools, bypass regressions, approval refusal, schema negatives |
| `ruff check noble tests` / `ruff format --check noble tests` | **PASS / PASS** |
| `mypy noble` | **PASS, 27 source files** |
| `python -m compileall -q noble agent-skills` | **PASS** |
| `pip wheel . --no-deps` | **PASS** (wheel metadata builds; source checkout still required for policy/fixture) |
| `bandit -r noble -ll -q` | **PASS**; one narrowly annotated B608 suppression for the intentional in-memory SQL fixture reproduction |
| `pip-audit` runtime + dev hashed locks | **0 known vulnerabilities reported** at audit time; advisory network was reachable |
| `detect-secrets` offline candidate scan | **0 candidates** in repository source/docs/config, with one public fixture SHA-256 allowlisted as a non-secret |
| `noble doctor --self-test` | **PASS** for core + pytest; WARN for unavailable external tools, Docker, Go and network sandbox |
| CI | **Not active on GitHub.** A proposed workflow is available only as [`ci-workflow-template.yml`](ci-workflow-template.yml). |

The full test suite was also run from a newly created virtual environment installed with `--require-hashes -r requirements-dev.lock`, followed by `pip install -e . --no-deps`. The inactive CI template proposes lint, typecheck, tests, legacy smoke, wheel build, Bandit, dependency advisory lookup, offline secret candidate scan, and doctor without production credentials or external-target tests. The GitHub App used for this PR cannot create or update `.github/workflows/ci.yml` (missing `workflows` permission); an authorized maintainer must review and install the template in `.github/workflows/ci.yml` separately. **No GitHub CI run or protection is claimed for this PR.**

## Known security boundaries and refusals

- Outside scope, wrong principal/action/target/purpose/role, missing/expired grant, invalid/forged/self-approved approval, unknown tool, unsupported target kind, unsupported network/side effects/sandbox, unsafe input, excessive rate/concurrency, invalid/oversized output, worker error/timeout all refuse or fail with structured results and audit records.
- Only offline, trusted, read-only **built-ins** are registered. This process boundary has resource limits **but is not a filesystem, syscall or network namespace sandbox**. It does not register external binaries even when found on PATH, and it never offers arbitrary shell execution or high-risk testing.
- A static AST signature is only a **candidate**. A confirmed finding is exclusively about the unmodified **synthetic** SQL fixture; it says nothing about a production system.
- No web/API surface exists; a decorative dashboard was intentionally not built before the security path.

## Remaining limitations and assumptions

1. **Identity/approval:** the checkout owner is the local trusted grant issuer; the CLI cannot independently authenticate a second human. Real-world authorization must be obtained out of band. High-risk approval primitives are tested but high-risk execution is unavailable.
2. **Isolation:** trusted worker code shares the OS UID and filesystem; process limits alone cannot contain compromised code or enforce egress. No Docker execution, seccomp/mount isolation, network proxy, DNS/redirect policy or credential broker is integrated. The reference Go guardrail was **not compiled** (Go unavailable); the reference Docker Compose was **not run** (Docker unavailable). Network tools fail closed.
3. **Detection:** the AST tool only finds Python interpolated SQL passed directly to `.execute()`, not data-flow reachability, broad SAST, dependency CVEs, history-wide secrets, IaC, web, authentication, SSRF or active verification. The synthetic verifier is deliberately restricted to one fixture; other vulnerability families are not confirmed.
4. **Audit integrity:** SQLite chained records are tamper-evident only against naive modification, **not** a malicious same-UID actor replacing the entire DB; logs are not externally anchored. A final audit or persistence failure after execution can leave an incomplete result, though a pre-execution audit failure prevents launch.
5. **Packaging/platform:** supported operation is an editable/source checkout from the repository root on Linux/Python 3.11+. Building a wheel succeeds but installing it alone does not supply the scope YAML, runtime config, or fixture. The legacy Node adapter needs Node.js. These assumptions are checked or documented rather than silently ignored.
6. **Repository data:** `.noble/` is untracked and owner-only; test/CLI state is local to the current sandbox and not a delivered findings dataset. The old `audit.log` was a baseline test artifact, not an operational log.

## Highest-value next work

1. Have a maintainer with `workflows` permission review and activate [the CI template](ci-workflow-template.yml) in `.github/workflows/ci.yml`; this PR does **not** configure CI.
2. Add a separately authenticated operator/approver service and immutable/external audit sink **before** offering high-risk actions or multiple users.
3. Integrate a verified filesystem + network isolation backend and pin rules/binaries **before** registering any external scanner or network tool.
4. Expand locally controlled fixtures and conservative evidence validators to additional vulnerability classes, keeping confirmation contingent on independent reproduction and explicit authorization.
5. If non-editable distribution is needed, package validated policy/config resources and prove installation from a wheel in a clean environment; do not infer deployability from a wheel build.

## Operator commands

From the checkout, follow [Installation](installation.md) and [Operator Guide](operator-guide.md). Minimal example: `noble doctor`, `noble scope ./tests/fixtures/sql_injection.py --action static-analysis`, `noble authorize ./tests/fixtures/sql_injection.py --tool static-code-scan`, then `noble scan ./tests/fixtures/sql_injection.py --grant GRANT_ID`. For the synthetic verification, issue a separate `--tool fixture-sql-verify --role security-auditor` grant and call `noble validate`. Review with `noble findings`, `noble report`, and `noble audit --verify`.
