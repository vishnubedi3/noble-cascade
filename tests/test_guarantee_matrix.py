"""Guarantee matrix executable evidence — every claim has a test."""

import pathlib
from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.scope import ScopeEngine
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.unit
def test_guarantee_scope_deny_unknown():
    scope = ScopeEngine.from_file(workspace_root=ROOT)
    d = scope.evaluate(normalize_target("/etc/passwd"), "static-analysis")
    assert not d.allowed
    assert d.decision.value in ("DENY", "UNKNOWN")


@pytest.mark.unit
def test_guarantee_authorization_exact():
    import pathlib

    from noble.config import RuntimeConfig

    tmp = pathlib.Path(__import__("tempfile").mkdtemp())
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    target = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
    grant = engine.authorizer.issue(
        issuer="a",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="security-research",
        privileges=("scan",),
    )
    result = engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    assert result.succeeded
    result2 = engine.run(make_scan_request(grant.grant_id, target=str(ROOT / "noble/__init__.py")))
    assert not result2.succeeded


@pytest.mark.unit
def test_guarantee_sandbox_wall_timeout():
    import pathlib

    from noble.execution import CommandRunner

    tmp = pathlib.Path(__import__("tempfile").mkdtemp())
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    stub = tmp / "sleep.py"
    stub.write_text("import time; time.sleep(2)\n")
    import pytest as pt

    import noble.execution as m

    orig = m.WORKER_PATH
    m.WORKER_PATH = stub
    try:
        tool = engine.registry.get("static-code-scan")
        tool.timeout_seconds = 0.1
        from datetime import timedelta

        from noble.models import ApprovalState, ExecutionContext, ToolInvocation, utcnow

        target = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
        req = make_scan_request(
            engine.authorizer.issue(
                issuer="a",
                principal="researcher",
                role="operator",
                capability="scan",
                action="static-analysis",
                target=target,
                purpose="security-research",
                privileges=("scan",),
            ).grant_id
        )
        auth = engine.authorizer.check(req, target, ("scan",))
        scope = engine.scope.snapshot(target, req.action)
        ctx = ExecutionContext(
            request_id=req.request_id,
            operator_id="researcher",
            target=target,
            scope=scope,
            authorization=auth,
            approval_state=ApprovalState.NOT_REQUIRED,
            risk=engine.risk.assess(req, target),
            deadline=utcnow() + timedelta(seconds=0.1),
            sandbox_id="test",
            network_policy=(),
            credential_policy="none",
            audit_context="test",
            workspace_root=str(ROOT),
        )
        inv = ToolInvocation("lease-test", tool, ctx, {})
        from noble.errors import ToolTimeout

        with pt.raises(ToolTimeout):
            CommandRunner(config).run(inv)
    finally:
        m.WORKER_PATH = orig


@pytest.mark.unit
def test_guarantee_worker_verification():
    tmp = pathlib.Path(__import__("tempfile").mkdtemp())
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    target = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
    grant = engine.authorizer.issue(
        issuer="a",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="security-research",
        privileges=("scan",),
    )
    result = engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    assert result.worker_id is not None
    assert result.policy_hash is not None


@pytest.mark.unit
def test_guarantee_ledger_replay():
    tmp = pathlib.Path(__import__("tempfile").mkdtemp())
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    target = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
    grant = engine.authorizer.issue(
        issuer="a",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="security-research",
        privileges=("scan",),
    )
    result = engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    from noble.replay import ReplayEngine

    r = ReplayEngine(store).replay(result.execution_id)
    assert r["request_id"] == result.request_id
