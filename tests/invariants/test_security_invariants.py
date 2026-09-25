"""Executable security invariants for the only registered tool path."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from noble.engine import NobleEngine
from noble.models import Outcome
from noble.store import Store
from tests.conftest import FIXTURE, make_scan_request


@pytest.mark.invariants
def test_no_tool_execution_without_authorization_or_scope(
    engine: NobleEngine, grant_scan: str
) -> None:
    for grant, target in ((None, str(FIXTURE)), (grant_scan, "/etc/passwd")):
        result = engine.run(make_scan_request(grant, target=target))
        assert "EXECUTING" not in result.state_history
        assert result.finding_ids == ()
        assert result.audit_event_ids


@pytest.mark.invariants
def test_local_actor_is_os_bound_not_env_spoofed(
    engine: NobleEngine, grant_scan: str, monkeypatch
) -> None:
    monkeypatch.setenv("USER", "researcher")
    monkeypatch.setenv("LOGNAME", "researcher")
    # Test engine has a deliberately injected test identity; a real engine
    # ignores USER/LOGNAME and binds to the actual OS UID.
    real = NobleEngine(engine.config, store=engine.store)
    assert real.actor_identity == __import__("pwd").getpwuid(os.getuid()).pw_name
    request = make_scan_request(grant_scan)
    result = real.run(request)
    assert result.outcome is Outcome.DENIED_AUTHORIZATION
    assert "EXECUTING" not in result.state_history


@pytest.mark.invariants
def test_replaying_request_id_cannot_launch_tool_twice(
    engine: NobleEngine, grant_scan: str
) -> None:
    request = make_scan_request(grant_scan)
    first = engine.run(request)
    assert first.succeeded
    second = engine.run(request)
    assert second.outcome is Outcome.INVALID_INPUT
    assert "EXECUTING" not in second.state_history
    assert engine.store.get_result(request.request_id)["outcome"] == first.outcome.value
    assert engine.store.verify_audit()[0]


@pytest.mark.invariants
def test_concurrent_request_reservation_is_single_use(tmp_path: Path) -> None:
    store = Store(tmp_path / "state/state.db")
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(store.reserve_request, ["req-1234567890abcdef"] * 8))
    assert results.count(True) == 1
    assert results.count(False) == 7


@pytest.mark.invariants
def test_no_report_from_unvalidated_output(engine: NobleEngine, grant_scan: str) -> None:
    from noble.models import CommandResult

    class InvalidRunner:
        def run(self, invocation):
            return CommandResult(("trusted-worker",), 0, "not JSON", "", 0.0, False, False)

    engine.runner = InvalidRunner()  # type: ignore[assignment]
    result = engine.run(make_scan_request(grant_scan))
    assert result.outcome is Outcome.INVALID_OUTPUT
    assert engine.store.list_findings() == []
    assert engine.store.verify_audit()[0]


@pytest.mark.invariants
def test_sandbox_and_network_do_not_silently_degrade(engine: NobleEngine, grant_scan: str) -> None:
    from noble.models import SandboxRequirement

    tool = engine.registry.get("static-code-scan")
    tool.sandbox = SandboxRequirement.CONTAINER
    result = engine.run(make_scan_request(grant_scan))
    assert result.outcome is Outcome.SANDBOX_UNAVAILABLE
    assert "EXECUTING" not in result.state_history
    assert result.finding_ids == ()
