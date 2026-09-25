from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.replay import ReplayEngine
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_replay_reconstructs(tmp_path: Path):
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
    result = engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    assert result.execution_id is not None
    replayer = ReplayEngine(store)
    replayed = replayer.replay(result.execution_id)
    assert replayed["request_id"] == result.request_id
    assert replayed["read_only"] is True
    assert len(replayed["evidence"]) == len(result.evidence_ids)
    assert len(replayed["findings"]) == len(result.finding_ids)
    assert "policy" in replayed
    # Replay by request
    replayed2 = replayer.replay_by_request(result.request_id)
    assert replayed2["execution_id"] == result.execution_id


@pytest.mark.integration
def test_replay_is_read_only(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
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
    replayer = ReplayEngine(store)
    before = len(store.list_findings())
    replayer.replay(result.execution_id)
    after = len(store.list_findings())
    assert before == after
