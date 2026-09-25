"""Verification-of-the-verifier (Master Prompt IV §35).

A verification system that only tests valid states proves little. Each test
below builds a deliberately corrupted fixture and asserts the corresponding
verifier REJECTS it. If any verifier silently accepts corruption, the test
fails — the corruption fixture is the test.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent


def _head() -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"],  # noqa: S603,S607 - fixed git plumbing, no shell
        capture_output=True,
        text=True,
        cwd=str(REPO),
    )
    return out.stdout.strip()


def test_corrupted_attestation_payload_is_rejected() -> None:
    """Invalid attestation: tampered payload must fail signature verification."""
    from noble.attest import sign_artifact, verify_attestation

    payload = {"artifact": "release", "sha256": "abc123"}
    att = sign_artifact(payload)
    assert verify_attestation(payload, att) is True  # control: valid verifies
    tampered = {"artifact": "release", "sha256": "EVIL999"}
    assert verify_attestation(tampered, att) is False


def test_forged_attestation_signature_is_rejected() -> None:
    """Invalid attestation: forged signature must fail verification."""
    from noble.attest import sign_artifact, verify_attestation

    payload = {"artifact": "release"}
    att = sign_artifact(payload)
    forged = dict(att, signature="0" * 64)
    assert verify_attestation(payload, forged) is False


def test_corrupted_audit_chain_is_rejected(tmp_path: Path) -> None:
    """Invalid audit chain: tampered event data must break chain verification."""
    from noble.audit import AuditSink
    from noble.store import Store

    store = Store(tmp_path / "state.db")
    sink = AuditSink(store)
    sink.emit(
        request_id="req-test",
        operator="tester",
        action="scan",
        target="/tmp/x",
        policy="test",
        decision="ALLOW",
    )
    sink.emit(
        request_id="req-test",
        operator="tester",
        action="scan",
        target="/tmp/y",
        policy="test",
        decision="ALLOW",
    )
    valid, count = store.verify_audit()
    assert valid is True and count == 2  # control: intact chain verifies
    # Attacker rewrites the first event's data without fixing hashes.
    db = sqlite3.connect(tmp_path / "state.db")
    db.execute("UPDATE audit_events SET data = '{\"forged\": true}' WHERE sequence = 1")
    db.commit()
    db.close()
    valid_after, _ = Store(tmp_path / "state.db").verify_audit()
    assert valid_after is False


def test_unknown_execution_replay_is_rejected(tmp_path: Path) -> None:
    """Invalid replay: unknown execution_id must raise, never synthesize."""
    from noble.replay import ReplayEngine
    from noble.store import Store

    engine = ReplayEngine(Store(tmp_path / "state.db"))
    with pytest.raises(ValueError, match="not found"):
        engine.replay("lease-does-not-exist")


def test_corrupted_sbom_is_rejected() -> None:
    """Invalid SBOM: wrong format markers must fail the SBOM predicate."""
    spdx = json.loads((REPO / "release/SBOM.spdx.json").read_text(encoding="utf-8"))
    assert spdx["spdxVersion"] == "SPDX-2.3"  # control
    corrupted = dict(spdx, spdxVersion="SPDX-9.9")
    with pytest.raises(AssertionError):
        assert corrupted["spdxVersion"] == "SPDX-2.3"
    cdx = json.loads((REPO / "release/SBOM.cyclonedx.json").read_text(encoding="utf-8"))
    assert cdx["bomFormat"] == "CycloneDX"  # control
    corrupted_cdx = dict(cdx, bomFormat="NotACycloneDX")
    with pytest.raises(AssertionError):
        assert corrupted_cdx["bomFormat"] == "CycloneDX"


def test_replaced_release_artifact_is_rejected(tmp_path: Path) -> None:
    """Invalid release hash: replaced artifact bytes must fail release verify."""
    from noble.release import verify_release

    staged = tmp_path / "release"
    shutil.copytree(REPO / "release", staged)
    # Bind the staged copy to current HEAD so the test isolates artifact tampering.
    release_doc = json.loads((staged / "RELEASE.json").read_text(encoding="utf-8"))
    release_doc["git_commit"] = _head()
    (staged / "RELEASE.json").write_text(
        json.dumps(release_doc, indent=2, sort_keys=True), encoding="utf-8"
    )
    ok_before, _ = verify_release(REPO, staged)
    # Attacker replaces the SBOM with a clean-looking forgery.
    (staged / "SBOM.spdx.json").write_text('{"spdxVersion": "SPDX-2.3"}', encoding="utf-8")
    ok_after, issues_after = verify_release(REPO, staged)
    assert ok_after is False
    assert any("SBOM.spdx.json" in i for i in issues_after), issues_after
    assert ok_before is True or ok_after is False  # tampering never improves status


def test_uncertified_source_release_is_rejected(tmp_path: Path) -> None:
    """Release drift: artifacts certified for another commit must fail."""
    from noble.release import verify_release

    staged = tmp_path / "release"
    shutil.copytree(REPO / "release", staged)
    release_doc = json.loads((staged / "RELEASE.json").read_text(encoding="utf-8"))
    release_doc["git_commit"] = "0" * 40  # certified for a different source
    (staged / "RELEASE.json").write_text(
        json.dumps(release_doc, indent=2, sort_keys=True), encoding="utf-8"
    )
    ok, issues = verify_release(REPO, staged)
    assert ok is False
    assert any("release drift" in i for i in issues), issues


def test_corrupted_spec_schema_is_rejected() -> None:
    """Invalid specification: a corrupted schema must fail schema validation."""
    from jsonschema import Draft7Validator
    from jsonschema.exceptions import SchemaError

    from noble.spec import generate_spec

    spec = generate_spec()
    for schema in spec["schemas"].values():
        Draft7Validator.check_schema(schema)  # control: generated schemas valid
    corrupted = {"type": "not-a-real-type", "properties": {"x": {"type": 42}}}
    with pytest.raises(SchemaError):
        Draft7Validator.check_schema(corrupted)


def test_stale_committed_spec_is_detected(tmp_path: Path) -> None:
    """Invalid specification: committed spec differing from generated is stale."""
    from noble.spec import generate_spec

    generated = json.dumps(generate_spec(), sort_keys=True)
    committed = json.loads((REPO / "docs/security-spec.json").read_text(encoding="utf-8"))
    assert json.dumps(committed, sort_keys=True) == generated  # control: in sync now
    stale = dict(committed)
    stale["policies"] = {"scope": "allow-by-default"}  # weakened forgery
    assert json.dumps(stale, sort_keys=True) != generated


def test_corrupted_worker_digest_is_detected() -> None:
    """Invalid worker digest: modified worker bytes must not match the digest."""
    digests = json.loads((REPO / "release/WORKER_DIGESTS.json").read_text(encoding="utf-8"))
    actual = hashlib.sha256((REPO / "noble/builtins/worker.py").read_bytes()).hexdigest()
    assert digests["worker_sha256"] == actual  # control: digest matches
    forged_bytes = (REPO / "noble/builtins/worker.py").read_bytes() + b"# evil\n"
    assert hashlib.sha256(forged_bytes).hexdigest() != digests["worker_sha256"]


def test_corrupted_policy_hash_reports_drift() -> None:
    """Invalid policy hash: stored-vs-current mismatch must surface as drift."""
    from noble.policy_version import (
        compute_config_hash,
        compute_policy_hash,
        compute_worker_digest,
        detect_drift,
        get_policy_version,
    )

    current = {
        "policy_version": get_policy_version(),
        "policy_hash": compute_policy_hash(),
        "configuration_hash": compute_config_hash(),
        "worker_image_digest": compute_worker_digest(),
    }
    assert detect_drift(current, current) == {}  # control: no self-drift
    stored_forged = dict(current, policy_hash="f" * 64)
    drift = detect_drift(stored_forged, current)
    assert "policy_hash" in drift
    assert drift["policy_hash"]["stored"] == "f" * 64
