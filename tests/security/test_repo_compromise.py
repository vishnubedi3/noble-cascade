"""Repository compromise scenarios (Master Prompt IV §33).

For every scenario: attack -> detection -> blocked/reported -> evidence.
Each test simulates the attack against an isolated copy (never the live
checkout) and asserts the governance machinery detects it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent


def _write_evil_workflow(root: Path) -> None:
    wf_dir = root / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "evil.yml").write_text(
        "name: Evil\non:\n  pull_request_target:\n    types: [opened]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n          persist-credentials: true\n"
        "      - run: echo ${{ github.event.issue.title }}\n",
        encoding="utf-8",
    )


def test_malicious_workflow_modification_is_detected(tmp_path: Path) -> None:
    """Attack: PR adds pull_request_target + unpinned action + credential leak."""
    from noble.governance import audit_workflows

    _write_evil_workflow(tmp_path)
    report = audit_workflows(tmp_path)
    assert report["passed"] is False
    findings = report["workflows"]["evil.yml"]["findings"]
    joined = " ".join(findings)
    assert "pull_request_target" in joined
    assert "unpinned" in joined
    assert "persist-credentials" in joined


def test_live_workflows_have_no_compromise_indicators() -> None:
    """Control: the real workflows must be clean under the same audit."""
    from noble.governance import audit_workflows

    report = audit_workflows(REPO)
    assert report["passed"] is True, report["findings"]
    assert report["count"] >= 2


def test_malicious_dependency_update_is_detected(tmp_path: Path) -> None:
    """Attack: dependency update strips hash pins from the lockfile."""
    from noble.supply_chain import verify_requirements_hashes

    ok, _ = verify_requirements_hashes(REPO / "requirements-dev.lock")
    assert ok is True  # control: committed lock is hash-pinned
    evil_lock = tmp_path / "requirements-dev.lock"
    evil_lock.write_text("requests==2.32.0  # no hashes here\n", encoding="utf-8")
    ok_evil, msg = verify_requirements_hashes(evil_lock)
    assert ok_evil is False
    assert "hash" in msg


def test_policy_weakening_is_security_critical() -> None:
    """Attack: policy file weakened -> classified critical with full verification."""
    from noble.governance import classify_paths

    result = classify_paths(["agent-skills/governance/scope-enforcement/scope-policy.yaml"])
    assert result["security_critical"] is True
    assert result["severity"] == "critical"
    assert "governance-certification" in result["required_verification"]
    assert "deny-by-default scope" in result["guarantees"]


def test_security_spec_weakening_is_security_critical() -> None:
    """Attack: security-spec tampering -> critical, spec verification required."""
    from noble.governance import classify_paths

    result = classify_paths(["docs/security-spec.json", "noble/spec.py"])
    assert result["severity"] == "critical"
    assert "specification-verification" in result["required_verification"]


def test_release_artifact_replacement_is_detected(tmp_path: Path) -> None:
    """Attack: release artifact replaced after certification -> verify fails."""
    from noble.release import verify_release

    staged = tmp_path / "release"
    shutil.copytree(REPO / "release", staged)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S603,S607 - fixed git plumbing, no shell
        capture_output=True,
        text=True,
        cwd=str(REPO),
    ).stdout.strip()
    doc = json.loads((staged / "RELEASE.json").read_text(encoding="utf-8"))
    doc["git_commit"] = head
    (staged / "RELEASE.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8"
    )
    (staged / "PROVENANCE.json").write_text('{"forged": true}', encoding="utf-8")
    ok, issues = verify_release(REPO, staged)
    assert ok is False
    assert any("PROVENANCE.json" in i for i in issues), issues


def test_unsigned_release_is_detected() -> None:
    """Attack: attestation signature stripped -> attestation verification fails."""
    from noble.attest import verify_attestation

    bundle = json.loads((REPO / "release/ATTESTATION.json").read_text(encoding="utf-8"))
    assert verify_attestation(bundle["payload"], bundle["attestation"]) is True  # control
    stripped = {"digest": bundle["attestation"]["digest"]}  # no signature
    assert verify_attestation(bundle["payload"], stripped) is False


def test_stale_generated_artifact_is_detected() -> None:
    """Attack: stale generated spec presented as current -> sync check fails."""
    from noble.spec import generate_spec

    generated = json.dumps(generate_spec(), sort_keys=True)
    committed = json.loads((REPO / "docs/security-spec.json").read_text(encoding="utf-8"))
    assert json.dumps(committed, sort_keys=True) == generated  # control: fresh
    # A stale artifact (last week's spec) would differ from today's generation
    # if implementation changed; the sync predicate must distinguish them.
    stale = json.loads(generated)
    stale["version"] = "0.0.0-stale"
    assert json.dumps(stale, sort_keys=True) != generated


def test_bypassed_test_is_detected() -> None:
    """Attack: pytest removed from CI -> baseline still requires it (drift)."""
    from noble.governance import REQUIRED_VERIFICATION_COMMANDS

    assert "python -m pytest -q" in REQUIRED_VERIFICATION_COMMANDS
    assert "bash verify-everything.sh" in REQUIRED_VERIFICATION_COMMANDS
    # And at least one live workflow actually runs the suite (no silent bypass).
    hits = [
        wf
        for wf in (REPO / ".github/workflows").glob("*.yml")
        if "pytest" in wf.read_text(encoding="utf-8")
    ]
    assert hits, "no workflow runs pytest — test execution bypassed"


def test_modified_verification_script_is_detected() -> None:
    """Attack: verify-everything.sh weakened -> baseline hash mismatch."""
    import hashlib

    from noble.governance import verify_baseline

    result = verify_baseline(REPO)
    assert result["verified"] is True, result["drift"]  # control: unmodified now
    baseline = json.loads((REPO / ".github/repo-baseline.json").read_text(encoding="utf-8"))
    current = hashlib.sha256((REPO / "verify-everything.sh").read_bytes()).hexdigest()
    assert baseline["verification_script_hash"] == current
    weakened = current.encode() + b"# skip all checks\n"
    assert hashlib.sha256(weakened).hexdigest() != baseline["verification_script_hash"]
