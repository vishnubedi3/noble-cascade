# Dependency Governance

Every dependency is governed: version, source, license, update history, security status. Abandoned packages are detected.

## Runtime dependencies (hash-pinned)

Source: `requirements.lock` (checked in, with `--hash=sha256:`)

```bash
cat requirements.lock | head
```

- `PyYAML>=6.0.2,<7` — hash-pinned, validated by `noble doctor`
- `jsonschema>=4.23,<5` — hash-pinned, validated by `noble doctor`

Python version: `>=3.11` (checked by `noble doctor`)

## Development dependencies

Source: `requirements-dev.lock`

Includes: `pytest`, `ruff`, `mypy`, `bandit`, `pip-audit`, `detect-secrets`

All are hash-pinned and installed with `pip install --require-hashes`.

## Verification

```bash
.venv/bin/pip-audit -r requirements.lock --disable-pip
.venv/bin/pip-audit -r requirements-dev.lock --disable-pip
noble supply-chain --json
noble doctor --integrity
```

`noble supply-chain` verifies:

- `requirements.lock` hash pins present
- `requirements-dev.lock` hash pins present
- `noble/builtins/worker.py` digest matches expected
- Overall PASS/FAIL

## Supply chain verification

Verify worker images, dependencies, tool binaries, downloaded artifacts. Where feasible, pin digests, verify hashes, verify signatures.

See `noble/supply_chain.py`:

- `verify_requirements_hashes()` — ensures lockfiles contain `--hash=sha256:`
- `verify_worker_image()` — SHA-256 of worker file
- `verify_tool_binary()` — optional, for future external tools
- `supply_chain_report()` — aggregated report, used by `noble supply-chain` and `noble doctor --integrity`

## Update process (Secure Update System)

Process:

```
Download → Verify → Validate → Stage → Smoke Test → Activate → Monitor → Rollback
```

No blind upgrades. Every update:

1. Downloads new lock hashes
2. Verifies hashes via `pip-audit` and `noble supply-chain`
3. Validates config via `noble doctor`
4. Stages in a temporary venv
5. Runs `pytest -q` smoke test
6. Activates only if healthy
7. Monitors via `noble health`
8. Rolls back on failure (see `noble/recovery.py`, tested in `tests/chaos/test_chaos.py`)

## Abandoned packages

Detected via `pip-audit` (advisory database) and manual review. The two runtime dependencies (`PyYAML`, `jsonschema`) are actively maintained. Dev dependencies are reviewed via `requirements-dev.lock` and `pyproject.toml` version constraints.

## Licenses

- `LICENSE` file at repo root governs Noble Cascade itself.
- Runtime deps: `PyYAML` (MIT), `jsonschema` (MIT) — permissive, compatible.
- See `pip show PyYAML` and `pip show jsonschema` for details.

## Pinning

All direct and transitive runtime dependencies are pinned with hashes in `requirements.lock`. The CI template (`docs/ci-workflow-template.yml`) installs with `--require-hashes`.

Never upgrade without verifying hashes and running `noble doctor --integrity` and `pytest -q`.
