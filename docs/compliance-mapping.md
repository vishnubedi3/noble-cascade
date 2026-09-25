# Compliance Technical Mappings (Phase 14)

> Not a legal attestation. These are technical mappings referencing existing reproducible evidence.

## NIST SSDF 1.1

| Practice | Evidence | Verified by |
|----------|----------|-------------|
| PO.1 Define Security Requirements | `docs/security-spec.json` invariants, `docs/security-model.md` | `noble spec --verify` |
| PS.1 Secure Design | `noble/kernel.py` single gate, `noble/contracts.py` | `tests/unit/test_kernel.py` |
| PW.4 Reuse Well-Secured Components | `requirements.lock` hash-pinned | `noble supply-chain --json` |
| PW.7 Use Automated Tools | ruff, mypy, bandit, pip-audit, pytest | `noble doctor` |
| PW.8 Check Included Software | SBOM | `release/SBOM.spdx.json` |
| RV.1 Vulnerability Response | `docs/governance-proof.md`, audit ledger | `noble audit --verify` |

Run: `noble compliance --framework nist --json`

## OWASP SAMM 2.0

| Domain | Practice | Evidence | Level |
|--------|----------|----------|-------|
| Governance | Strategy & Metrics | `noble/metrics.py`, `scorecard.py` | 1 |
| Governance | Policy & Compliance | `scope-policy.yaml` | 2 |
| Design | Threat Assessment | `security-model.md` threat table | 2 |
| Implementation | Secure Build | `release/PROVENANCE.json` SLSA L1 | 1 |
| Verification | Testing | 145 tests, property/fuzz/chaos | 2 |
| Operations | Environment Management | `doctor`, `health` | 1 |

## SLSA 1.0

- **L1** Provenance available: `release/PROVENANCE.json` — implemented
- **L2** Hosted build service: GitHub Actions `ci-hardened.yml` — partial (local reproducible)
- **L3** Hardened build, non-falsifiable provenance: `ATTESTATION.md` HMAC + git pinning — local-simulated (replace with Sigstore for L3)

Verification: `noble compliance --framework slsa --json` or `noble release --verify`

## CIS Controls v8

- **CIS 2** Inventory of Software: SBOM SPDX + CycloneDX (`noble sbom`)
- **CIS 3** Data Protection: evidence hashing, redaction, 0700/0600 perms (`tests/security/test_sensitive_paths.py`)
- **CIS 4** Secure Configuration: `runtime.yaml` schema (`noble/config_schema.py`, `noble doctor --policy`)
- **CIS 8** Audit Log Management: chained `audit_events`, `noble audit --verify`
- **CIS 10** Malware Defenses: allowlist, quarantine, no network tools (`noble supply-chain`)

Run: `noble compliance --framework cis --json` or `noble compliance --json` for all.

All mappings are `noble compliance --framework all --json`.

## Verification

```bash
noble compliance --json | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'nist_ssdf' in d"
ls release/SBOM.*.json release/PROVENANCE.json
cat release/ATTESTATION.md
```
