# Installation — local offline runtime

## Prerequisites

- Linux with Python **3.11+**, `venv`, POSIX process groups/rlimits, SQLite support.
- Node.js **22** only for the optional legacy smoke validator. No Go or Docker requirement for the operational runtime.
- An OS account authorized to control the checkout and `.noble/` state. Do not run untrusted target code under this account.
- No actual target/network credentials are required or accepted by registered tools.

## Reproducible install

From repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/noble doctor
```

The hash-locked runtime requirements cover PyYAML, jsonschema and their resolved transitive dependencies. The project file `pyproject.toml` constrains compatible releases; use the lock for reproducibility. **Only source-checkout/editable operation from the repository root is supported**: `config/runtime.yaml`, the scope policy, and the synthetic fixture live in the checkout rather than in a standalone wheel. The inactive [CI template](ci-workflow-template.yml) proposes a wheel metadata build, but no GitHub CI is enabled by this PR; a maintainer with workflow permission must install it separately. A wheel build alone does not mean the runtime works without the source checkout. For development, install **`requirements-dev.lock` instead of `requirements.lock`**, then install the editable project without dependencies:

```bash
.venv/bin/python -m pip install --require-hashes -r requirements-dev.lock
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/python -m pytest -q
```

Regenerate locks on a trusted machine with `pip-compile pyproject.toml --generate-hashes -o requirements.lock` and `pip-compile pyproject.toml --extra dev --generate-hashes -o requirements-dev.lock`; review dependency changes and re-run audit before committing.

## State and permissions

The first `noble doctor` or execution creates `.noble/state.db`; `.noble/` is mode `0700`, database `0600`, and Git ignores it. The local SQLite file contains grants, approvals, request/results, evidence, findings, rate leases and the audit chain. **Never commit it or copy it into a target repository.** Directory symlinks and foreign-owned state are refused.

The old audit-log path is ignored for historical compatibility but is no longer written by the runtime. The original `agent-skills/` scripts are not the installation mechanism for the named upstream projects; see `noble tools` and [capability inventory](skill-manifest.md).

## Check installation

```bash
.venv/bin/noble doctor
.venv/bin/noble tools
.venv/bin/python -m pytest -q
.venv/bin/ruff check noble tests
.venv/bin/mypy noble
```

Doctor warnings for missing Docker, Go, Semgrep, Bandit, Gitleaks, Checkov or OSV-Scanner are **truthful limitations, not passed scans**. Even if installed separately, those projects are not registered runtime tools. `noble doctor --self-test` additionally runs the pytest suite (requires dev dependencies); `noble doctor` exits nonzero for broken core configuration, manifests, audit chain, unsafe state permissions, or a requested self-test failure.

The original `agent-skills/tests/validate-stack.py` now checks legacy references/scope/approval/schema regressions; it requires Node.js for its Draft-07 compatibility adapter. The authoritative runtime suite is `pytest`.
