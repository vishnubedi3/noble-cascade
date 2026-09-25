# Operator Guide — actual local CLI

**Only analyze files you are authorized to inspect.** The checked-in policy is a deny-by-default example for this repository and local paths; it is not evidence of a third party's consent. The CLI does not scan a network.

## Workflow

1. `noble doctor` — check policy, registry, audit chain, local file permissions, optional dependencies. Warnings indicate unavailable external capabilities, not a clean scan.
2. `noble scope TARGET --action static-analysis` — display normalized target and ALLOW/DENY/UNKNOWN (unknown denies). This is a policy inspection, **not** an authorization grant.
3. `noble tools` — show the two registered built-ins and their risk/coverage.
4. `noble authorize ./tests/fixtures/sql_injection.py --tool static-code-scan` — as the checkout-owning OS identity, explicitly issue a time-limited, exact-target/action/capability/purpose grant. Store the printed `grant_id` securely; this local administrator step must be backed by real-world authorization external to the tool.
5. `noble scan ./tests/fixtures/sql_injection.py --grant GRANT_ID` — inspect Python AST without importing/executing the target. Returns a **candidate** finding, not proof of exploitability.
6. `noble authorize ./tests/fixtures/sql_injection.py --tool fixture-sql-verify --role security-auditor`, then `noble validate ./tests/fixtures/sql_injection.py --grant VERIFY_GRANT_ID` — deterministic MEDIUM-risk local fixture reproduction. Refuses modified fixtures and other paths. Never runs a real-target PoC.
7. `noble inspect FINDING_ID` or `noble inspect EVIDENCE_ID`, `noble findings`, `noble report --format markdown|json`, and `noble audit --verify` — inspect bounded, persisted results and audit integrity.

`noble scan --help` and `noble authorize --help` show all accepted flags. Grant expiration defaults to **3600 seconds** (max 86400); omitted, wrong, expired, or differently scoped grants deny. The CLI binds principal to `pwd.getpwuid(os.getuid())`; setting `USER` or `LOGNAME` does not impersonate someone else. State is private to that OS account.

## Approval model

LOW needs no human approval after an authorization grant; MEDIUM (the synthetic verifier) proceeds with audit after grant. HIGH/CRITICAL needs a *different* target-bound approver, explicit pending→approved decision, request fingerprint, risk, scope, and expiry; approvals can be rejected/revoked. **There are no executable HIGH tools in this release.** The CLI `approve` command is present for state-machine inspection only; single-user state cannot provide independent human identity attestation. The old `--approve` argument is rejected even when printed on the command line. Do not treat CLI-level approval as a production control until an external identity service exists.

## Exit status and outcome

`0`: command completed or informational inspection allowed. `2`: policy/authorization/approval/input refused; `1`: attempted tool failed/invalid output/time limit/other CLI error; legacy unavailable scanner shims return `3`. Every `noble scan/validate` prints JSON with `state`, `outcome`, `state_history`, evidence IDs, finding IDs, risk and error. `success_no_findings` is not a declaration that the target is secure; `inconclusive` means coverage was incomplete.

## Operational guardrails

- No browser/API server or remote endpoint exists. Do not add a web route around the CLI policy engine.
- Never use the `tests/fixtures/sql_injection.py` fixture in a real application. It is intentionally vulnerable, and only its hash-locked syntax + an independent in-memory reproduction can be confirmed.
- `.noble/state.db` is local, owner-only and ignored by Git; back it up and protect it under your own data policy. Audit hash chaining detects accidental modification, **not** same-user rewriting.
- If a tool, dependency, sandbox or output validator is unavailable, **stop** and review the structured refusal. Do not use old scripts as an approval or scope bypass. External scanner adapters return nonzero rather than a fake success.
