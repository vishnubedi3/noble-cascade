"""Compliance Profiles — technical mappings, not legal attestation.

Generate evidence aligned with NIST SSDF, OWASP SAMM, SLSA, CIS principles
by referencing existing evidence rather than inventing new behavior.
"""

from __future__ import annotations

from typing import Any


def nist_ssdf_map() -> dict[str, Any]:
    return {
        "framework": "NIST SSDF 1.1",
        "mappings": [
            {
                "practice": "PO.1 Define Security Requirements",
                "evidence": "docs/security-spec.json invariants, docs/security-model.md",
                "verified_by": "noble spec --verify",
            },
            {
                "practice": "PS.1 Secure Design",
                "evidence": "noble/kernel.py single gate, noble/contracts.py",
                "verified_by": "tests/unit/test_kernel.py",
            },
            {
                "practice": "PW.4 Reuse Well-Secured Components",
                "evidence": "requirements.lock hash-pinned, noble/supply_chain.py",
                "verified_by": "noble supply-chain --json",
            },
            {
                "practice": "PW.7 Use Automated Tools",
                "evidence": "ruff, mypy, bandit, pip-audit, pytest",
                "verified_by": "CI workflow .github/workflows/control-plane.yml",
            },
            {
                "practice": "PW.8 Check Included Software",
                "evidence": "SBOM.spdx.json, SBOM.cyclonedx.json",
                "verified_by": "release/SBOM.spdx.json exists",
            },
            {
                "practice": "RV.1 Vulnerability Response",
                "evidence": "docs/governance-proof.md, audit ledger",
                "verified_by": "noble audit --verify",
            },
        ],
    }


def owasp_samm_map() -> dict[str, Any]:
    return {
        "framework": "OWASP SAMM 2.0",
        "mappings": [
            {
                "domain": "Governance",
                "practice": "Strategy & Metrics",
                "evidence": "noble/metrics.py, noble/scorecard.py",
                "level": 1,
            },
            {
                "domain": "Governance",
                "practice": "Policy & Compliance",
                "evidence": "agent-skills/governance/scope-enforcement/scope-policy.yaml",
                "level": 2,
            },
            {
                "domain": "Design",
                "practice": "Threat Assessment",
                "evidence": "docs/security-model.md threat table",
                "level": 2,
            },
            {
                "domain": "Implementation",
                "practice": "Secure Build",
                "evidence": "release/PROVENANCE.json, SLSA L1",
                "level": 1,
            },
            {
                "domain": "Verification",
                "practice": "Testing",
                "evidence": "145 tests, property/fuzz/chaos",
                "level": 2,
            },
            {
                "domain": "Operations",
                "practice": "Environment Management",
                "evidence": "noble/doctor.py, noble/health.py",
                "level": 1,
            },
        ],
    }


def slsa_map() -> dict[str, Any]:
    return {
        "framework": "SLSA 1.0",
        "levels": {
            "L1": {
                "requirement": "Provenance available",
                "evidence": "release/PROVENANCE.json",
                "status": "implemented",
            },
            "L2": {
                "requirement": "Hosted build service",
                "evidence": "GitHub Actions .github/workflows/control-plane.yml",
                "status": "partial (local reproducible)",
            },
            "L3": {
                "requirement": "Hardened build, non-falsifiable provenance",
                "evidence": "ATTESTATION.md HMAC + git commit pinning",
                "status": "local-simulated (replace with Sigstore for L3)",
            },
        },
        "provenance": "release/PROVENANCE.json predicateType slsa.dev/provenance/v1",
        "verification": "noble release --verify",
    }


def cis_map() -> dict[str, Any]:
    return {
        "framework": "CIS Controls v8",
        "mappings": [
            {
                "control": "CIS 2 Inventory of Software",
                "evidence": "SBOM.spdx.json + SBOM.cyclonedx.json",
                "verified_by": "noble release",
            },
            {
                "control": "CIS 3 Data Protection",
                "evidence": "evidence hashing, redaction, 0700/0600 perms",
                "verified_by": "tests/security/test_sensitive_paths.py",
            },
            {
                "control": "CIS 4 Secure Configuration",
                "evidence": "config/runtime.yaml schema, noble/config_schema.py",
                "verified_by": "noble doctor --policy",
            },
            {
                "control": "CIS 8 Audit Log Management",
                "evidence": "chained audit_events, noble audit --verify",
                "verified_by": "store.verify_audit()",
            },
            {
                "control": "CIS 10 Malware Defenses",
                "evidence": "tool allowlist, quarantine, no network tools",
                "verified_by": "noble supply-chain",
            },
        ],
    }


def all_compliance() -> dict[str, Any]:
    return {
        "nist_ssdf": nist_ssdf_map(),
        "owasp_samm": owasp_samm_map(),
        "slsa": slsa_map(),
        "cis": cis_map(),
        "disclaimer": "Technical mappings only; not a legal compliance attestation. Evidence is reproducible via `noble verify` and `verify-everything.sh`.",
    }
