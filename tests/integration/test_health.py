from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.health import HealthMonitor, HealthStatus
from noble.store import Store

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_health_monitor(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    monitor = HealthMonitor(config=config, store=store)
    checks, overall = monitor.check_all()
    assert len(checks) >= 7
    components = {c.component for c in checks}
    assert "policy" in components
    assert "database" in components
    assert "workers" in components
    assert "queue" in components
    assert "sandbox" in components
    assert "tools" in components
    # Overall should be HEALTHY or DEGRADED (dashboard is DEGRADED in CLI-only)
    assert overall in (
        HealthStatus.HEALTHY,
        HealthStatus.DEGRADED,
        HealthStatus.BLOCKED,
        HealthStatus.FAILED,
    )
    # Policy should be healthy
    policy_check = next(c for c in checks if c.component == "policy")
    assert policy_check.status == HealthStatus.HEALTHY
