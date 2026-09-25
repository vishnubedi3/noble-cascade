# Skill Inventory Correction (2026-09-25)

The August 2026 report in the initial commit claimed "34 successfully installed, integrated and validated" with zero unresolved problems. That conclusion was **incorrect**: the files were chiefly local wrappers and runbooks, not checked-out upstream implementations; several wrappers returned success without scanning; the scope check allowed substring bypasses; `--approve` self-authorized high-risk actions; and the findings validator did not validate. The original commit was executed and inspected in [execution-report-89f3ab.md](execution-report-89f3ab.md).

## Current truth

- **34 historical entries tracked; 0 upstream projects installed or independently pinned/verified.** Source names/URLs are historical attribution, not a supply-chain claim.
- Historical status distribution: `LOCAL_ADAPTER`: 14; `PARTIAL_IMPLEMENTATION`: 3; `REFERENCE_ONLY`: 12; `UNAVAILABLE`: 5. No historical entry is marked `INSTALLED` or registered as a runtime tool.
- **2 independent local tools actually registered:** static Python SQL-sink candidate scanner and a hash-locked synthetic SQLite verifier. Neither is Semgrep, Bandit, Gitleaks, Checkov, OSV-Scanner or an upstream project integration.
- **Runtime dependencies:** PyYAML and jsonschema, constrained in `pyproject.toml` and hash-pinned with transitive dependencies in `requirements.lock`; development dependencies separately hashed in `requirements-dev.lock`.
- **Environment:** Go and Docker are absent in this workspace; the Go reference guardrail was not compiled, and the Docker reference is not an execution backend. External scanners are not registered even when a binary happens to be installed.

## Operational decision

Only `noble tools` / `agent-skills/manifest.yaml:runtime_tools` declare executable capabilities. All available runs must pass the `NobleEngine` request → scope → authorization → risk/approval → registry → process boundary → validated evidence → finding → audit path. Historical `agent-skills/` paths are compatibility checks or references and must not be treated as an authorization/runtime stack.

See [architecture](architecture.md), [operator guide](operator-guide.md), [security model](security-model.md), [manifest guide](skill-manifest.md), and [engineering report](engineering-report.md) for precise coverage, tests and limits.
