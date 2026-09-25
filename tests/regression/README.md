# Security Regression Corpus — Noble Cascade

Every discovered security defect becomes a permanent regression fixture.
Fixtures in this directory are **never deleted**; a fix is proven by the
fixture failing before the fix and passing after.

## Entry format

Each regression test documents:

- vulnerability (what was wrong)
- exploit condition (how to trigger it)
- expected rejection (what the fixed code does)
- fixed version (release containing the fix)
- affected guarantee (from `docs/guarantee-matrix.md`)

## Corpus index

| Test | Vulnerability | Fixed in | Guarantee |
|---|---|---|---|
| `test_legacy_regressions.py` | legacy threat fixtures | 0.2.0 | historical coverage |
| `test_threat_replay.py` | historical failure replay | 0.2.0 | threat replay |
| `../security/test_verifier_rejects_corruption.py` | verifiers accepting corrupt evidence (policy hash, audit chain, replay, SBOM, attestation, release hash, spec, worker digest) | 0.2.0 (Master Prompt IV) | tamper-evident verification |
| `../security/test_repo_compromise.py` | repository compromise paths (workflow, dependency, policy, spec, artifact, unsigned release, stale artifact, bypassed test, weakened script) | 0.2.0 (Master Prompt IV) | repository governance |
| `../security/test_governance_self.py` | quiet weakening of the verification layer itself | 0.2.0 (Master Prompt IV) | self-governance |

## Rules

1. New defects get a new test here (or in `tests/security/` with an index row
   above) **before** the fix lands, demonstrating the failure.
2. Fixtures must be deterministic and offline (no network, no credentials).
3. Security history is executable: `python -m pytest tests/regression tests/security -q`.
