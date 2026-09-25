from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.metrics import collect_metrics
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_metrics_collect(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
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
    engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    # also a blocked
    engine.run(make_scan_request(grant.grant_id, target="/etc/passwd"))
    m = collect_metrics(store)
    assert m.total_executions >= 2
    assert m.blocked_actions >= 1
    assert "success_with_findings" in m.outcome_breakdown
