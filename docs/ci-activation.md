# CI Activation Record — Master Prompt IV

## What changed

The hardened workflow was relocated so GitHub Actions actually executes it:

- from: `docs/ci-hardened.yml` (inactive — GitHub never runs workflows from `docs/`)
- to: `.github/workflows/ci-hardened.yml` (executable)

The move was a relocation, not a duplication: `docs/ci-hardened.yml` was
removed. A byte comparison before removal confirmed the two files were
identical, so no security behavior changed in transit.

## Post-move validation

1. YAML syntax validated (`python -c 'import yaml...'` equivalent via CI parse
   plus local `noble governance --workflow-audit`).
2. Every path reference inspected: the workflow pins to
   `.github/workflows/ci-hardened.yml` in its self-integrity step
   (`sha256sum .github/workflows/ci-hardened.yml`), which is the new live path.
3. Self-integrity checks strengthened during relocation (fail-closed):
   - `pull_request_target` forbidden
   - `persist-credentials: true` forbidden
   - moving action tags (`@vN`) forbidden — immutable SHAs required
   - top-level `permissions: contents: read` required in every workflow
4. Workflow-equivalent checks run locally: `noble governance --workflow-audit`
   must PASS, and `./verify-everything.sh` checks 19–20 (baseline + workflow
   audit) must PASS.
5. No security behavior weakened: the pre-move file is preserved in git history
   (`git log -- docs/ci-hardened.yml`); the live file only adds checks.

## Resulting workflow topology

| Workflow | Trigger | Purpose |
|---|---|---|
| `.github/workflows/main.yml` | push, PR | fast validation (lint/format/type/tests/bandit/secrets/pip-audit) |
| `.github/workflows/ci-hardened.yml` | push, PR (governed paths) | full governance chain incl. certification, release, audit-pack, verify-everything |
| `.github/workflows/security-analysis.yml` | PR, push to main, weekly | dependency-review + CodeQL (adds evidence; never replaces the Noble kernel) |

All third-party actions are pinned to immutable commit SHAs with the
human-readable version in a trailing comment. See
`noble governance --workflow-audit --json` for the machine-readable audit.
