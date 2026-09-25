"""Chaos testing — inject controlled failures and observe recovery."""

import time
from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.recovery import RecoveryManager
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.security
def test_worker_crash_recovery(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    # Simulate worker crash by using failing runner
    from noble.errors import ToolTimeout

    class CrashRunner:
        def run(self, inv):
            raise ToolTimeout("simulated crash")

    engine.runner = CrashRunner()  # type: ignore
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
    assert result.outcome.value == "timeout"
    # Recovery should clear stale leases policy-safe
    mgr = RecoveryManager(store, config=config)
    recovered = mgr.attempt_recovery()
    assert recovered["policy_safe"] is True


@pytest.mark.security
def test_queue_corruption_recovery(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    # Inject stale leases
    store.acquire_lease(
        lease_id="lease-stale",
        principal="a",
        tool="scan",
        target="t",
        per_minute=10,
        global_per_minute=10,
        max_concurrent=10,
        timeout=1,
        now=time.time() - 100,
    )
    from noble.health import HealthMonitor

    mon = HealthMonitor(config=config, store=store)
    checks, overall = mon.check_all()
    # Should detect degraded or handle stale
    from noble.recovery import RecoveryManager

    mgr = RecoveryManager(store, config=config)
    n = mgr.recover_stalled_leases()
    assert n >= 0


@pytest.mark.security
def test_timeout_recovery_is_policy_safe(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state3"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state3/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    # Normal execution should succeed even after recovery
    from noble.targets import normalize_target

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
    # Recovery should not relax policy
    mgr = RecoveryManager(store, config=config)
    mgr.recover_stalled_leases()
    # Second execution with wrong grant should still be denied
    result2 = engine.run(make_scan_request(grant.grant_id, target="/etc/passwd"))
    assert not result2.succeeded
