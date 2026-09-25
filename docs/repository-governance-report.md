# Repository Governance Report — Master Prompt IV

> **Addendum (2026-09-25, post-excision):** the authoring token lacked the
> `workflows` scope, so `.github/workflows/` changes were excised from this
> branch's history to make it pushable (re-certified at `46bb96c`); the
> hardened files ship via `handoff-bundle/workflows/` for manual registration.
> The full-green proof in §11 below was recorded pre-excision with workflows
> present. Current branch state: CERTIFIED, Release VERIFIED, spec/audit/
> offline/ruff green; 8 workflow-dependent tests + baseline/workflow-audit red
> (single root cause: unregistered hardened workflows) until registration.
> Re-run §11 after registration to restore 20/20.


Date: 2026-09-25. Head: `5393684` (branch `arena/01a0d94c-noble-cascade`).
Question: *can the repository prevent an unverified change from becoming an
accepted release?* The machinery below makes the answer mechanically enforced
where code can enforce it, and explicitly MANUAL where only a human can.

## 1. Repository state

- Single-commit `main` (`c42d8d2`) was the ground truth; all work is on the
  session branch as 8 commits: source (de40871), evidence (2c5ceab),
  attestation portability + machinery baseline (8fd3c88), re-certified
  evidence (a2281c8), this report (1b83a71), repo-wide lint/format (be4e56f),
  re-certified evidence (5393684), report head update (this commit). Each
  source commit that touched governed files is followed by a re-certification
  commit — the no-drift invariant requires it, and intermediate staleness is
  documented in §14 rather than hidden.
- Baseline audit before modification found: CI workflow duplicated between
  `docs/` (inactive) and `.github/workflows/` (live); two corrupt action pins
  (39/41 hex chars); committed `release/` stale vs `main` HEAD (certified for
  `46a7404`, HEAD was `c42d8d2`); committed SBOM bytes differing from
  `POLICY_HASHES.json`; `noble drift --baseline` missing from setup (fresh
  clones could never reach CERTIFIED); attestation key bound to the absolute
  checkout path (fresh clones could never verify signatures);
  nondeterministic `state_machine.terminal` ordering (frozenset iteration);
  audit-pack generator emitting a weaker `verification.sh` than verification
  actually required. All fixed in this change set; each fix is covered by a
  test or a verifier.

## 2. Branch topology

- `main` remains the only long-lived branch; no other development branches
  exist. No branches were deleted (none needed deletion; §40 requires owner
  authorization for deletions and there was nothing to consolidate).
- Merge path is PR-only by policy; the mechanical control (branch protection)
  is MANUAL — the automation integration receives HTTP 403 for branch
  protection APIs (verified 2026-09-25). Operator checklist:
  `docs/maintainer-security-checklist.md`.

## 3. CI enforcement

- `.github/workflows/ci-hardened.yml` is executable from `.github/workflows/`
  (relocated from `docs/`; duplicate removed). Activation record:
  `docs/ci-activation.md`.
- Self-integrity step pins to `.github/workflows/ci-hardened.yml`, forbids
  `pull_request_target` triggers, `persist-credentials: true`, moving action
  tags, and non-minimal top-level permissions — all fail-closed.
- Two levels: `main.yml` (fast local-equivalent) and `ci-hardened.yml` (full
  governance incl. `./verify-everything.sh`). Release verification was not
  weakened for speed: the contract grew from 18 to 20 checks.

## 4. GitHub security controls

- CODEOWNERS (`.github/CODEOWNERS`) covers governance, runtime, sandbox,
  policy, workers, CI, release, and the security spec. Team slugs are
  placeholders — MANUAL until the owner creates teams.
- Dependabot (`.github/dependabot.yml`) routes pip + actions updates through
  the same pipeline (audit -> tests -> verification -> review -> merge).
- `security-analysis.yml` adds dependency-review (PRs, fail on high/critical)
  and CodeQL (python, security-extended). These ADD evidence; the Noble
  kernel remains authoritative for execution behavior.
- Secret scanning, push protection, Dependabot alerts: MANUAL (owner enables
  in Settings -> Security). `detect-secrets` already runs in both workflows.

## 5. Required checks

Intended required set for `main` (MANUAL to configure; each check fails
closed once configured): `Control-plane validation / validate`, `CI Trust
Hardened / validate`, `Security analysis / dependency-review`, `Security
analysis / codeql`. Every check maps to a real invariant
(`docs/repository-governance.md` §2). Local equivalents of all 20
`verify-everything.sh` checks are listed in `.github/repo-baseline.json`
(`required_verification_commands`) and drift if weakened.

## 6. Workflow verification

- `noble governance --workflow-audit`: 3/3 PASS (pinned SHAs, `contents:
  read`, no dangerous patterns). All third-party actions pinned to
  gh-resolved immutable SHAs with versions in comments.
- YAML syntax validated for all three workflows (PyYAML; note YAML 1.1
  parses `on:` as boolean `True` — validated accordingly).
- Pre-existing corrupt pins (setup-python 39 chars, upload-artifact 41
  chars) replaced with verified SHAs.

## 7. Release verification

- `noble release --verify`: VERIFIED. Proves certified source is HEAD or an
  ancestor with no governed file changed since certification, exact-tag
  binding when tagged, artifact-bytes binding, policy/config/worker binding,
  and HMAC attestation validity. `RELEASE.json` records `working_tree_clean`;
  authoritative evidence comes from clean CI checkouts.
- Release flow (candidate -> certification -> tag -> artifacts -> attestation)
  documented in `docs/release-process.md`; tags only from verified `main`
  (maintainer discipline + mechanical tag binding).

## 8. Supply-chain verification

- Hash-pinned locks verified (`requirements.lock`, `requirements-dev.lock`);
  `pip-audit`: no known vulnerabilities; `bandit -r noble -ll -q`: clean;
  `noble supply-chain`, `noble drift` (no drift), SBOM SPDX 2.3 + CycloneDX
  valid with licenses/versions/hashes; SLSA-style provenance generated.
- Baseline (`.github/repo-baseline.json`) pins workflow hashes, action SHAs,
  lock hashes, spec/policy/config/worker digests, verification-script hash,
  governance-module hash, release-machinery hashes (12 modules), and required
  commands. `noble governance --baseline-verify`: VERIFIED.

## 9. Guarantee coverage

- 179 tests pass (was 145 at baseline; +34 new governance tests: 11
  verifier-rejects-corruption, 10 repo-compromise, 13 governance-self). `noble trust-report` classifies every assertion:
  6 ENFORCED, 6 VERIFIED, 0 DOCUMENTED-as-enforcement, 2 MANUAL, 2
  EXPERIMENTAL, 3 UNSUPPORTED. Branch protection and CODEOWNERS teams are
  MANUAL; multi-user attestation, network tools, and container isolation are
  UNSUPPORTED — none are represented as enforcement.

## 10. Repository-compromise tests

- `tests/security/test_verifier_rejects_corruption.py` (11 tests): tampered
  attestation/signature, forged audit event, unknown replay, wrong SBOM
  markers, replaced release artifact, foreign-commit release, corrupt schema,
  stale spec, forged worker digest, forged policy hash — every verifier
  rejects.
- `tests/security/test_repo_compromise.py` (10 tests): evil workflow,
  hash-stripped lock, policy/spec weakening classification, artifact
  replacement, stripped signature, stale artifact, pytest bypass, weakened
  verify script — every attack detected with evidence.
- `tests/security/test_governance_self.py` (13 tests): verifier-tampering,
  workflow/pin/command/lock tampering, trust-report honesty, certify
  recomputation, generator drift-guard — the system cannot quietly weaken
  its own verification layer.
- Negative control: removing `fingerprint` from `policy-proof.json` yields
  `./verify-everything.sh --json` exit 28 naming exactly the one failed
  check — fail-closed, no silent skip, no cascade.

## 11. Fresh-clone results

From a clean clone at `5393684` (`git clone ... -b arena/01a0d94c-noble-cascade`,
fresh venv, hash-locked install, `noble drift --baseline`): 179 passed,
CERTIFIED, Release VERIFIED, Baseline VERIFIED, offline 9/9,
`verify-everything.sh` 20/20. Full chain: clone -> setup -> tests ->
security verification -> governance certification -> release verification ->
offline audit verification. (First fresh-clone attempt exposed the
path-bound attestation flaw; fixed via portable key derivation and
re-verified from scratch.)

## 12. Offline verification results

`env -u GH_TOKEN -u GITHUB_TOKEN bash audit-pack/verification.sh`:
OFFLINE VERIFICATION PASSED (9/9) — no credentials, no network, no private
services. Exit codes 40+N per check; setup failures exit 2.

## 13. Manual maintainer actions

Branch protection rule for `main` (9 settings); required-check selection;
CODEOWNERS team creation; secret scanning + push protection + Dependabot
alerts; release tagging discipline; dependency-PR scope review; emergency
post-change review within 24h. Full list with exact settings:
`docs/maintainer-security-checklist.md`. Everything else on the checklist is
AUTOMATIC and verified above.

## 14. Known limitations

- Same-UID SQLite replacement is detectable, not WORM; process-local rlimits
  are not a container/namespace; single-user OS identity only; dashboard is
  read-only/CLI-authoritative; attestations are local HMAC (no Sigstore);
  provenance is locally generated (SLSA L1-style, not third-party attested).
- Intermediate commit `8fd3c88` intentionally fails release verification
  (key rotation left artifacts stale) until re-certified — the invariant
  working as designed. Branch HEAD is green.
- Shallow clones cannot prove source binding (`merge-base` needs history):
  release verification fails closed with a "regenerate" message. Auditors
  must use full clones (documented in `docs/external-auditor.md`).

## 15. Remaining risks

- Owner-level GitHub settings (protection, checks, scanning, teams) are
  MANUAL: until configured, the pipeline is enforced by convention + CI
  presence, not by branch rules. The checklist makes this unmissable, but a
  control that is not configured does not protect.
- Local HMAC attestations detect tampering but are not third-party
  identity-bound; a Sigstore/cosign layer would upgrade provenance to
  cross-system without replacing the Noble chain.
- `8fd3c88`-style intermediate staleness relies on reviewers reading commit
  messages; a merge-queue running checks per-commit would close this fully
  (MANUAL GitHub setting, noted in the checklist).
