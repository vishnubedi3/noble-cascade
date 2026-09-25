import pytest

from noble.signing import hash_evidence, hash_finding, hash_report, sign_finding


@pytest.mark.unit
def test_hashes_deterministic():
    ev = {
        "evidence_id": "ev-abc",
        "content": "hello",
        "content_hash": "abc",
        "target": "t",
        "tool": "static-code-scan",
        "provenance": {"a": 1},
    }
    h1 = hash_evidence(ev)
    h2 = hash_evidence(ev)
    assert h1 == h2
    assert len(h1) == 64
    finding = {
        "finding_id": "finding-abc",
        "title": "t",
        "target": "t",
        "evidence_ids": ["ev-abc"],
        "confidence": {"score": 45},
        "severity": {"tier": "LOW"},
        "provenance": {},
        "state": "candidate",
    }
    fh = hash_finding(finding)
    assert len(fh) == 64
    report = {"findings": ["finding-abc"], "request_id": "req-abc"}
    rh = hash_report(report)
    assert len(rh) == 64


@pytest.mark.unit
def test_sign_finding():
    ev = {
        "evidence_id": "ev-1",
        "content": "x",
        "content_hash": "abc",
        "target": "t",
        "tool": "s",
        "provenance": {},
    }
    finding = {
        "finding_id": "finding-1",
        "title": "t",
        "target": "t",
        "evidence_ids": ["ev-1"],
        "confidence": {},
        "severity": {},
        "provenance": {},
        "state": "candidate",
    }
    signed = sign_finding(finding, [ev])
    assert "finding_hash" in signed
    assert "composite_hash" in signed
