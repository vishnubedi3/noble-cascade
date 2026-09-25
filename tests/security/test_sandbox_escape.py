"""Sandbox escape tests — attack your own sandbox."""

import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from noble.execution import CommandRunner
from noble.models import ApprovalState, ExecutionContext, ToolInvocation, utcnow
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.security
def test_filesystem_escape_blocked(engine, grant_scan):
    # Attempt to reference file outside workspace via .. path
    from noble.models import CommandResult

    class EscapeRunner:
        def run(self, invocation):
            # Try to claim a file outside workspace
            data = {
                "request_id": invocation.context.request_id,
                "target": invocation.context.target.canonical,
                "tool": invocation.definition.name,
                "version": invocation.definition.version,
                "complete": True,
                "warnings": [],
                "provenance": {"scanner": "local-ast-sql-v1"},
                "observations": [
                    {
                        "title": "Escape",
                        "category": "sql-injection",
                        "cwe": "CWE-89",
                        "file": "../../etc/passwd",
                        "line": 1,
                        "snippet": "x",
                        "description": "escape",
                        "impact": "none",
                        "remediation": "none",
                        "verified": False,
                        "reproduction": None,
                    }
                ],
            }
            return CommandResult((sys.executable,), 0, json.dumps(data), "", 0.01, False, False)

    engine.runner = EscapeRunner()  # type: ignore
    result = engine.run(make_scan_request(grant_scan))
    from noble.models import Outcome

    assert result.outcome == Outcome.INVALID_OUTPUT
    assert result.finding_ids == ()


@pytest.mark.security
def test_mount_abuse_not_exposed(tmp_path: Path):
    # Ensure state directory is not symlink
    from noble.errors import ConfigurationInvalid
    from noble.store import Store

    link = tmp_path / "link"
    target_dir = tmp_path / "target"
    target_dir.mkdir()
    link.symlink_to(target_dir)
    with pytest.raises(ConfigurationInvalid):
        Store(link / "state.db")


@pytest.mark.security
def test_process_resource_limits(engine, grant_scan, tmp_path: Path, monkeypatch):
    import noble.execution as exec_mod

    stub = tmp_path / "worker_loop.py"
    stub.write_text("while True: pass\n")
    monkeypatch.setattr(exec_mod, "WORKER_PATH", stub)
    tool = engine.registry.get("static-code-scan")
    tool.timeout_seconds = 0.2
    target = normalize_target(str(FIXTURE), workspace_root=engine.config.workspace_root)
    request = make_scan_request(grant_scan)
    auth = engine.authorizer.check(request, target, ("scan",))
    scope = engine.scope.snapshot(target, request.action)
    ctx = ExecutionContext(
        request_id=request.request_id,
        operator_id="researcher",
        target=target,
        scope=scope,
        authorization=auth,
        approval_state=ApprovalState.NOT_REQUIRED,
        risk=engine.risk.assess(request, target),
        deadline=utcnow() + timedelta(seconds=0.2),
        sandbox_id="test",
        network_policy=(),
        credential_policy="none",
        audit_context="test",
        workspace_root=engine.config.workspace_root,
    )
    inv = ToolInvocation("lease-test", tool, ctx, {})
    from noble.errors import ToolTimeout

    with pytest.raises(ToolTimeout):
        CommandRunner(engine.config).run(inv)


@pytest.mark.security
def test_environment_leakage_blocked(engine, grant_scan):
    # Worker environment should be sanitized
    result = engine.run(make_scan_request(grant_scan))
    # Even if env contains secrets, they should not leak into evidence
    import json

    evidence_list = engine.store.list_evidence(result.request_id)
    for ev in evidence_list:
        assert "SECRET" not in json.dumps(ev) or "[REDACTED" in json.dumps(ev)


@pytest.mark.security
def test_credential_exposure_in_target_rejected(engine):
    raw = str(ROOT / "tests/fixtures/password=supersecret123.py")
    result = engine.run(make_scan_request(None, target=raw))
    assert result.outcome.value in ("invalid_input", "invalid_scope", "denied_authorization")
    # Ensure secret not in audit
    import json

    assert "supersecret123" not in json.dumps(engine.store.list_audit())
