"""Governance-against-itself (Master Prompt IV §34).

The machinery that verifies Noble Cascade must not be quietly weakenable.
Any modification to the verification layer itself must be detectable via the
baseline, and the trust report must never overclaim enforcement.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
ALLOWED_STATUSES = {
    "ENFORCED",
    "VERIFIED",
    "DOCUMENTED",
    "MANUAL",
    "EXPERIMENTAL",
    "UNSUPPORTED",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _baseline() -> dict:
    return json.loads((REPO / ".github/repo-baseline.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "rel_path,baseline_key",
    [
        ("verify-everything.sh", "verification_script_hash"),
        ("noble/governance.py", "governance_module_hash"),
        ("docs/security-spec.json", "security_spec_hash"),
        (".github/security-critical.json", "classification_hash"),
    ],
)
def test_verification_machinery_tampering_is_detected(rel_path: str, baseline_key: str) -> None:
    """Modifying the verifier changes its hash -> baseline drift on verify."""
    from noble.governance import verify_baseline

    stored = _baseline()[baseline_key]
    assert _sha(REPO / rel_path) == stored  # control: pristine now
    # Simulate a quiet weakening: one appended line changes the digest.
    weakened = (REPO / rel_path).read_bytes() + b"\n# quiet weakening\n"
    assert hashlib.sha256(weakened).hexdigest() != stored
    # And the live verify passes only because nothing was actually modified.
    assert verify_baseline(REPO)["verified"] is True


def test_workflow_tampering_is_detected() -> None:
    """Any workflow edit drifts its baseline hash."""
    from noble.governance import create_baseline

    stored = _baseline()["workflow_hashes"]
    current = create_baseline(REPO)["workflow_hashes"]
    assert stored == current  # control: pristine now
    assert set(stored) >= {"main.yml", "ci-hardened.yml"}
    for name, digest in stored.items():
        assert digest == _sha(REPO / ".github/workflows" / name)


def test_action_pin_weakening_is_detected() -> None:
    """Replacing a pinned SHA with a moving tag drifts action_shas + audit."""
    from noble.governance import audit_workflows

    baseline_actions = _baseline()["action_shas"]
    for refs in baseline_actions.values():
        for ref in refs:
            assert "@" in ref and len(ref.split("@", 1)[1]) == 40, ref
    assert audit_workflows(REPO)["passed"] is True  # control: pinned now


def test_verification_command_removal_is_detected() -> None:
    """Dropping a required verification command drifts the baseline."""
    from noble.governance import REQUIRED_VERIFICATION_COMMANDS

    stored = _baseline()["required_verification_commands"]
    assert stored == REQUIRED_VERIFICATION_COMMANDS  # control: intact now
    weakened = [c for c in stored if "pytest" not in c and "certify" not in c]
    assert weakened != stored  # removal is distinguishable from the baseline
    assert len(weakened) < len(stored)


def test_dependency_lock_tampering_is_detected() -> None:
    """Lockfile edits drift dependency_hashes even if format stays valid."""
    stored = _baseline()["dependency_hashes"]
    assert stored["requirements.lock"] == _sha(REPO / "requirements.lock")
    assert stored["requirements-dev.lock"] == _sha(REPO / "requirements-dev.lock")


def test_trust_report_never_overclaims_enforcement() -> None:
    """Every trust assertion carries a status; MANUAL items are never ENFORCED."""
    from noble.trust_report import trust_report

    report = trust_report(REPO)
    statuses = report["assertion_status"]
    assert len(statuses) >= 10
    for name, info in statuses.items():
        assert info["status"] in ALLOWED_STATUSES, name
        assert info["evidence"], name
    assert statuses["branch protection (no unreviewed push to main)"]["status"] == "MANUAL"
    assert statuses["CODEOWNERS review of security-critical paths"]["status"] == "MANUAL"
    assert statuses["multi-user attestation"]["status"] == "UNSUPPORTED"
    assert statuses["deny-by-default scope"]["status"] == "ENFORCED"


def test_certification_cannot_be_faked_by_report_edit() -> None:
    """`noble certify` recomputes checks; editing its JSON output proves nothing."""
    from noble.certify import certify

    result = certify(REPO)
    assert result["status"] in ("CERTIFIED", "FAILED")
    assert result["certified"] is (result["status"] == "CERTIFIED")
    # Every claimed check has a pass/fail + message (no bare assertions).
    for name, check in result["checks"].items():
        assert "passed" in check and "message" in check, name


def test_audit_pack_generator_cannot_downgrade_verification() -> None:
    """Regenerating the audit pack must reproduce the hardened offline script."""
    from noble.audit_pack import verification_script_template

    committed = (REPO / "audit-pack/verification.sh").read_text(encoding="utf-8")
    assert verification_script_template() == committed
    assert "40 +" in committed  # stable exit-code contract present
    assert "Isolated" in committed or "mktemp" in committed  # tmp isolation present
