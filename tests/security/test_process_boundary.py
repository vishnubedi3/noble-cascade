"""Attack the actual bounded worker process, not only policy functions."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

import noble.execution as execution_module
from noble.engine import NobleEngine
from noble.errors import InvalidOutput, ToolTimeout
from noble.execution import CommandRunner
from noble.models import ApprovalState, ExecutionContext, Outcome, ToolInvocation, utcnow
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request


def _context(engine: NobleEngine, grant_scan: str) -> ExecutionContext:
    target = normalize_target(str(FIXTURE), workspace_root=engine.config.workspace_root)
    request = make_scan_request(grant_scan)
    auth = engine.authorizer.check(request, target, ("scan",))
    scope = engine.scope.snapshot(target, request.action)
    return ExecutionContext(
        request_id=request.request_id,
        operator_id="researcher",
        target=target,
        scope=scope,
        authorization=auth,
        approval_state=ApprovalState.NOT_REQUIRED,
        risk=engine.risk.assess(request, target),
        deadline=utcnow() + timedelta(seconds=1),
        sandbox_id="process-local-rlimit",
        network_policy=(),
        credential_policy="none",
        audit_context="test",
        workspace_root=engine.config.workspace_root,
        parameters={},
    )


@pytest.mark.security
def test_process_wall_timeout_kills_worker(
    engine: NobleEngine, grant_scan: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = tmp_path / "worker_sleep.py"
    stub.write_text("import time\ntime.sleep(3)\n")
    monkeypatch.setattr(execution_module, "WORKER_PATH", stub)
    tool = engine.registry.get("static-code-scan")
    tool.timeout_seconds = 0.1
    with pytest.raises(ToolTimeout):
        CommandRunner(engine.config).run(
            ToolInvocation("lease-test", tool, _context(engine, grant_scan), {})
        )


@pytest.mark.security
def test_oversized_stdout_is_killed_without_persisting(
    engine: NobleEngine, grant_scan: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stub = tmp_path / "worker_big.py"
    stub.write_text("import sys\nsys.stdout.write('A' * 200000)\n")
    monkeypatch.setattr(execution_module, "WORKER_PATH", stub)
    tool = engine.registry.get("static-code-scan")
    with pytest.raises(InvalidOutput):
        CommandRunner(engine.config).run(
            ToolInvocation("lease-test", tool, _context(engine, grant_scan), {})
        )


@pytest.mark.security
def test_filename_shell_metacharacters_never_reach_shell(engine: NobleEngine) -> None:
    fixtures = Path(engine.config.workspace_root) / "tests/fixtures"
    malicious = fixtures / "source;echo_UNSAFE.py"
    sentinel = fixtures / "echo_UNSAFE.py"
    assert not sentinel.exists()
    try:
        malicious.write_text("# inert source\n", encoding="utf-8")
        target = normalize_target(str(malicious), workspace_root=engine.config.workspace_root)
        grant = engine.authorizer.issue(
            issuer="admin",
            principal="researcher",
            role="operator",
            capability="scan",
            action="static-analysis",
            target=target,
            purpose="security-research",
            privileges=("scan",),
        )
        result = engine.run(make_scan_request(grant.grant_id, target=str(malicious)))
        assert result.outcome is Outcome.SUCCESS_NO_FINDINGS
        assert not sentinel.exists()
    finally:
        malicious.unlink(missing_ok=True)


@pytest.mark.security
def test_audit_failure_prevents_tool_start(engine: NobleEngine, grant_scan: str) -> None:
    class FailingAudit:
        def emit(self, **kwargs):
            raise sqlite3.OperationalError("audit disk is unavailable")

    class SpyRunner:
        called = False

        def run(self, *args, **kwargs):
            self.called = True
            raise AssertionError("runner must not start after audit failure")

    spy = SpyRunner()
    engine.runner = spy  # type: ignore[assignment]
    engine.audit = FailingAudit()  # type: ignore[assignment]
    request = make_scan_request(grant_scan)
    result = engine.run(request)
    assert not spy.called
    assert result.outcome is Outcome.INTERNAL_ERROR
    assert result.error and result.error["code"] == "audit_failure"
    assert "EXECUTING" not in result.state_history
    # Interrupted IDs remain reserved: do not replay a possibly executed action.
    assert engine.store.reserve_request(request.request_id) is False


@pytest.mark.security
def test_lease_cleanup_failure_is_not_reported_as_success(
    engine: NobleEngine, grant_scan: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken_release(lease_id: str) -> None:
        raise sqlite3.OperationalError("simulated database write failure")

    monkeypatch.setattr(engine.store, "release_lease", broken_release)
    result = engine.run(make_scan_request(grant_scan))
    assert result.outcome is Outcome.INTERNAL_ERROR
    assert result.state.value == "FAILED"
    assert result.error and result.error["code"] == "lease_cleanup_failed"
    assert engine.store.verify_audit()[0]
