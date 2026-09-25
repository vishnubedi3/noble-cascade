# Noble Cascade

Noble Cascade is an **offline, single-user, policy-governed research runtime** for authorized local security analysis. It turns a small part of the original 34-skill architectural prototype into a working, evidence-backed execution path. It is **not** a general-purpose penetration tester, a production multi-tenant service, or an integration with the named upstream security projects.

## What actually runs

| Registered tool | Scope | Result |
| --- | --- | --- |
| `static-code-scan` | Explicitly granted local Python file/directory under the checkout | Conservative AST detection of interpolated SQL passed to `.execute()`; **candidate** only, never confirmed by a scanner result alone |
| `fixture-sql-verify` | The **unmodified** `tests/fixtures/sql_injection.py`, SHA-256-checked | Bounded in-memory SQLite contrast of unsafe vs parameterized SQL, independently checked by the parent; **confirmed synthetic** finding, not a production claim |

The CLI and runtime have **no network-capable, write-capable, general PoC, or high-risk tools**. Missing Semgrep, Bandit, Gitleaks, Checkov, OSV-Scanner, Go, or Docker never turns into a successful scan. The 34 `agent-skills/` entries remain a categorized historical inventory; their wrappers and `SKILL.md` files are *not* registered tools. `noble doctor` reports the distinction.

## Install — One-Command Setup (Phase 18)

```bash
make setup            # or:
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements-dev.lock && .venv/bin/pip install -e . --no-deps && .venv/bin/noble doctor
```

Fallback (Linux, Python 3.11+):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/noble doctor
```

The checked-in lock includes hashes of all direct and transitive **runtime** dependencies. Optional development dependencies are in `requirements-dev.lock`. The legacy Node smoke validator additionally needs Node.js; the runtime itself does not.

## Authorized local example

1. Check scope without executing:

   ```bash
   .venv/bin/noble scope ./tests/fixtures/sql_injection.py --action static-analysis
   ```

2. The OS account controlling this checkout explicitly issues a time-limited, **exact-target and exact-action** grant. Inspect and save the printed `grant_id`:

   ```bash
   .venv/bin/noble authorize ./tests/fixtures/sql_injection.py --tool static-code-scan
   .venv/bin/noble scan ./tests/fixtures/sql_injection.py --grant GRANT_ID
   ```

   The resulting finding is a **candidate**; syntax alone cannot prove input reachability or exploitability.

3. To reproduce only the known synthetic fixture (no target code is imported/executed), issue a separate verification grant and run the medium-risk verifier:

   ```bash
   .venv/bin/noble authorize ./tests/fixtures/sql_injection.py --tool fixture-sql-verify --role security-auditor
   .venv/bin/noble validate ./tests/fixtures/sql_injection.py --grant VERIFICATION_GRANT_ID
   .venv/bin/noble findings
   .venv/bin/noble report --format markdown
   .venv/bin/noble audit --verify
   ```

A request is **never authorized merely because it was typed into the CLI**: the target must be in the fixed deny-by-default policy, the tool must be registered, and an explicit unexpired grant for this OS identity, action, target, purpose, and permission must exist. In this local single-user mode, the repo-owning OS identity is the trusted grant issuer; it is *not* an independently attested external authorization. Do not use it for untrusted operators or production systems.

## Execution boundary

```
Local OS operator → CLI → validated SecurityRequest → scope (deny unknown)
→ exact authorization grant → contextual risk → bound approval if required
→ registered offline tool → process/time/CPU/memory/output limits
→ schema + provenance + source verification → quarantined evidence
→ candidate or synthetic confirmed finding → report → chained audit record
```

High-risk approvals use a target/action/scope/risk/expiry-bound state machine and forbid self-approval. **No high-risk tool is registered**, and the single-user CLI cannot independently attest a second human identity. `--approve` on the old wrapper is explicitly rejected. Process limits are **not** an OS filesystem or egress sandbox; the worker is trusted local code that reads untrusted files as data. Any future external/network tool must be isolated independently before registration.

## Validate — One-Command Verification (Phases 5, 16, 18, 19)

```bash
make verify           # ./verify-everything.sh — full offline verification
make certify          # noble certify — CERTIFIED/FAILED
make release          # noble release --create && verify

# Or manually:
.venv/bin/python -m pytest -q
.venv/bin/ruff check noble tests && .venv/bin/ruff format --check noble tests && .venv/bin/mypy noble
.venv/bin/python -m noble certify --json          # governance certification
.venv/bin/python -m noble release --verify        # reproducible release
.venv/bin/python -m noble audit-pack              # independent audit bundle
.venv/bin/python -m noble trust-report --json     # self-assessment
.venv/bin/python -m noble trust-index --json      # machine trust index
./verify-everything.sh                            # fresh-clone verification
```

See `docs/hardening-report.md`, `docs/release-process.md`, `docs/compliance-mapping.md` for phase coverage.

```bash
.venv/bin/bandit -r noble -ll -q
.venv/bin/pip-audit -r requirements.lock --disable-pip
.venv/bin/pip-audit -r requirements-dev.lock --disable-pip
.venv/bin/python agent-skills/tests/validate-stack.py  # legacy compatibility smoke, needs Node.js
```

> The intentional SQL injection in `tests/fixtures/sql_injection.py` and its in-memory reproduction is a test fixture, not a vulnerability in a deployed target. Do **not** deploy or import it.

The proposed [CI workflow template](docs/ci-workflow-template.yml) is **inactive** under `docs/`. This PR cannot modify `.github/workflows/` because the GitHub App lacks `workflows` permission; a maintainer must review and install the template separately before any GitHub Actions checks run.

See [Installation](docs/installation.md), [Operator Guide](docs/operator-guide.md), [Architecture](docs/architecture.md), [Security Model](docs/security-model.md), [Capability Inventory](docs/skill-manifest.md), and the [Engineering Report](docs/engineering-report.md).
