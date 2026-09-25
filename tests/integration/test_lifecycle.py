from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from noble.engine import NobleEngine
from noble.models import ExecutionState, Outcome, SecurityRequest
from noble.reporting import FINDING_SCHEMA, Reporter
from tests.conftest import FIXTURE, make_scan_request


@pytest.mark.integration
def test_full_candidate_path(engine: NobleEngine, grant_scan: str) -> None:
    result = engine.run(make_scan_request(grant_scan))
    assert result.state is ExecutionState.COMPLETED
    assert result.outcome is Outcome.SUCCESS_WITH_FINDINGS
    assert result.error is None
    assert result.state_history == (
        "CREATED",
        "VALIDATING",
        "SCOPE_CHECK",
        "AUTHORIZATION_CHECK",
        "RISK_ASSESSMENT",
        "WAITING_FOR_APPROVAL",
        "APPROVED",
        "EXECUTING",
        "COLLECTING_EVIDENCE",
        "VALIDATING_RESULT",
        "COMPLETED",
    )
    assert len(result.evidence_ids) == 1
    assert len(result.finding_ids) == 1
    finding = engine.store.get_finding(result.finding_ids[0])
    assert finding is not None
    assert finding["state"] == "candidate"
    assert finding["confidence"]["level"] == "LOW"
    assert finding["reproduction"] is None
    assert not list(Draft7Validator(FINDING_SCHEMA).iter_errors(finding))
    evidence = engine.store.get_evidence(result.evidence_ids[0])
    assert evidence and evidence["trust_level"] == "TARGET_CONTENT"
    assert evidence["provenance"]["data_classification"] == "TARGET"
    assert evidence["target"] == str(FIXTURE)
    assert evidence["provenance"]["operator"] == "researcher"
    assert len(engine.store.list_audit()) >= 8
    assert engine.store.verify_audit()[0] is True
    persisted = engine.store.get_result(result.request_id)
    assert persisted and persisted["state"] == "COMPLETED"


@pytest.mark.integration
def test_synthetic_reproduction_end_to_end(engine: NobleEngine, grant_verify: str) -> None:
    request = SecurityRequest(
        action="local-unit-test-verification",
        target=str(FIXTURE),
        requester="researcher",
        tool="fixture-sql-verify",
        authorization_grant=grant_verify,
    )
    result = engine.run(request)
    assert result.succeeded and result.outcome is Outcome.SUCCESS_WITH_FINDINGS
    assert len(result.evidence_ids) == 2
    finding = engine.store.get_finding(result.finding_ids[0])
    assert finding is not None and finding["state"] == "confirmed"
    assert finding["provenance"]["classification"] == "synthetic"
    assert finding["confidence"]["score"] >= 90
    assert finding["severity"]["tier"] == "MEDIUM"  # severity != confidence
    assert finding["reproduction"]["controlled"] is True
    assert all(engine.store.get_evidence(eid) is not None for eid in finding["evidence_ids"])
    report = Reporter(engine.store)
    assert "Synthetic" in report.as_markdown()
    parsed = json.loads(report.as_json())
    assert parsed["findings"][0]["state"] == "confirmed"
    assert parsed["findings"][0]["target"] == str(FIXTURE)
    assert engine.store.verify_audit()[0]


@pytest.mark.integration
def test_no_grant_no_execution(engine: NobleEngine) -> None:
    result = engine.run(make_scan_request(None))
    assert result.state is ExecutionState.BLOCKED
    assert result.outcome is Outcome.DENIED_AUTHORIZATION
    assert result.error and result.error["code"] == "authorization_denied"
    assert "EXECUTING" not in result.state_history
    assert result.finding_ids == ()
    assert engine.store.list_evidence(result.request_id) == []
    assert engine.store.verify_audit()[0]


@pytest.mark.integration
def test_clean_file_is_not_a_finding(engine: NobleEngine) -> None:
    source = Path(engine.config.workspace_root) / "noble/__init__.py"
    from noble.targets import normalize_target

    grant = engine.authorizer.issue(
        issuer="admin",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=normalize_target(str(source)),
        purpose="security-research",
        privileges=("scan",),
    )
    result = engine.run(make_scan_request(grant.grant_id, target=str(source)))
    assert result.outcome is Outcome.SUCCESS_NO_FINDINGS
    assert result.evidence_ids == ()
    assert engine.store.list_findings() == []


@pytest.mark.integration
def test_no_arbitrary_tool_path(engine: NobleEngine, grant_scan: str) -> None:
    malicious = make_scan_request(grant_scan)
    malicious.tool = "bash -c 'cat /etc/passwd'"
    result = engine.run(malicious)
    assert not result.succeeded
    assert result.outcome is Outcome.BLOCKED_POLICY
    assert result.error and result.error["code"] == "tool_unknown"
    assert "EXECUTING" not in result.state_history
