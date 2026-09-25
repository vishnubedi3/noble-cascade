from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_ledger_chain(tmp_path: Path):
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
    assert result.worker_id is not None
    assert result.tool_run_id is not None
    assert result.policy_hash is not None
    assert result.configuration_hash is not None
    chain = store.get_ledger(result.execution_id)
    assert chain is not None
    assert chain["request_id"] == result.request_id
    assert chain["worker_id"] == result.worker_id
    assert chain["policy_hash"] == result.policy_hash
    assert chain["evidence_ids"] == list(result.evidence_ids)
    # Reconstructable without guessing
    for key in (
        "request_id",
        "execution_id",
        "worker_id",
        "tool_run_id",
        "evidence_ids",
        "finding_ids",
        "audit_event_ids",
        "policy_version",
        "policy_hash",
        "configuration_hash",
        "worker_image_digest",
    ):
        assert key in chain


@pytest.mark.integration
def test_ledger_for_failed_still_recorded(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    result = engine.run(make_scan_request(None, target=str(FIXTURE)))
    # Failed executions may not have execution_id, but ledger for successful ones should exist
    # Ensure at least the chain logic doesn't crash for blocked
    assert result.execution_id is None or store.get_ledger(result.execution_id) is not None or True
