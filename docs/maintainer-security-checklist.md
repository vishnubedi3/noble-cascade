# Maintainer Security Checklist — Noble Cascade

Every item is marked AUTOMATIC (machinery refuses the violating state) or
MANUAL (a human must do it, and the repo cannot do it for them). Never blur
the two: `noble trust-report` reports the same classification via
`assertion_status`.

## Branch protection for `main` (MANUAL — owner-level GitHub settings)

The GitHub integration available to automation returns 403 for branch
protection APIs, so a repository owner must configure this by hand at
Settings -> Branches -> Add rule for `main`:

- [ ] Require a pull request before merging (no direct unreviewed pushes)
- [ ] Require approvals: >= 1
- [ ] Dismiss stale pull request approvals when new commits are pushed
- [ ] Require status checks to pass before merging (see Required checks below)
- [ ] Require branches to be up to date before merging
- [ ] Require conversation resolution before merging
- [ ] Do not allow bypassing the above settings (include administrators)
- [ ] Restrict who can push to matching branches (owner team only)
- [ ] Block force pushes; do not allow deletions

Verification: `gh api repos/<owner>/<repo>/branches/main/protection` should
return the rule (run by the owner, not by automation).

## Required status checks (MANUAL to configure, AUTOMATIC to enforce)

Configure as required in the branch rule above; each check itself fails closed:

- [ ] `Control-plane validation / validate` (lint, format, type, tests, bandit, secrets, pip-audit)
- [ ] `CI Trust Hardened / validate` (full governance chain + verify-everything.sh)
- [ ] `Security analysis / dependency-review` (PR dependency diff)
- [ ] `Security analysis / codeql` (static analysis findings)

Each maps to a real invariant; see `docs/repository-governance.md` §2.

## Workflow activation (AUTOMATIC — verified in CI)

- [x] `.github/workflows/ci-hardened.yml` is executable (moved from `docs/`)
- [x] Self-integrity step pins to `.github/workflows/ci-hardened.yml`
- [x] `noble governance --workflow-audit` passes (pinned SHAs, minimal permissions)
- [x] `./verify-everything.sh` checks 19–20 pass (baseline + workflow audit)

Re-verify after any workflow edit: `python -m noble governance --workflow-audit`.

## CODEOWNERS (MANUAL teams, AUTOMATIC classification)

- [ ] Owner creates teams: `governance`, `runtime`, `sandbox`, `policy`, `workers`, `ci`, `release`
- [ ] Owner replaces `@noble-cascade/<team>` placeholder slugs if the org name differs
- [x] `.github/CODEOWNERS` covers all security-critical areas
- [x] `.github/security-critical.json` classification is deterministic (`noble governance --pr-analysis`)

## Secrets (AUTOMATIC scanning, MANUAL hygiene)

- [x] No secrets in workflow env (`ci-hardened.yml` asserts this)
- [x] `detect-secrets` scan runs in both fast and hardened workflows
- [ ] Owner enables secret scanning + push protection (Settings -> Security)
- [ ] Owner enables Dependabot alerts (Settings -> Security)
- [ ] No maintainer ever pastes credentials into issues/PRs/discussions

## Releases and signing (AUTOMATIC verification, MANUAL tagging)

- [x] `noble release --verify` binds certified source == tagged source == built source == attested source
- [ ] Release tags (`vX.Y.Z`) are created only from verified `main` (maintainer discipline)
- [ ] Tag creation follows `docs/release-process.md` (candidate -> certification -> tag -> artifacts -> attestation)
- [ ] Release notes link the `verify-everything.sh` output for the tagged commit

## Dependency governance (AUTOMATIC pipeline, MANUAL review)

- [x] Hash-pinned locks (`requirements.lock`, `requirements-dev.lock`)
- [x] Dependabot config routes updates through the same pipeline (`.github/dependabot.yml`)
- [x] `pip-audit` + `dependency-review` run on every PR
- [ ] Maintainer reviews dependency PRs for scope creep (new packages need justification)

## Incident response and rollback (MANUAL with AUTOMATIC evidence)

- [ ] Emergency changes follow `docs/repository-governance.md` §8 (actor, timestamp, reason, files, verification, post-review)
- [ ] Rollback = revert PR through the normal pipeline (never force-push `main`)
- [ ] After rollback, regenerate `release/` + `.github/repo-baseline.json` if governed files changed
- [ ] Newly discovered defects become permanent fixtures in `tests/regression/` (see `tests/regression/README.md`)

## Verification cadence (AUTOMATIC in CI, MANUAL to witness)

- [ ] Before every release: fresh-clone verification from scratch (see `docs/external-auditor.md`)
- [ ] Before every release: offline audit verification with no credentials (`bash audit-pack/verification.sh` with empty env)
- [ ] After any baseline drift: review the drift, then regenerate via `noble governance --baseline-create` in a reviewed PR
