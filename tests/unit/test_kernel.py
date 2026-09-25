from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.kernel import SecurityKernel
from noble.models import SecurityRequest
from noble.store import Store
from noble.targets import normalize_target

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_kernel_validates_request(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    kernel = SecurityKernel(config=config, store=store, actor_identity="tester")
    req = SecurityRequest(
        action="static-analysis",
        target="./tests/fixtures/sql_injection.py",
        requester="tester",
        tool="static-code-scan",
    )
    decision = kernel.validate_request(req)
    assert decision.allowed
    assert decision.subsystem == "REQUEST"


@pytest.mark.unit
def test_kernel_scope_and_explain(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    kernel = SecurityKernel(config=config, store=store, actor_identity="tester")
    target = normalize_target("./tests/fixtures/sql_injection.py", workspace_root=str(ROOT))
    decision, kd = kernel.evaluate_scope(target, "static-analysis")
    assert decision.allowed
    explanation = kernel.explain_decision(kd)
    assert "Policy" in explanation
    assert "Reason" in explanation


@pytest.mark.unit
def test_kernel_policy_fingerprint(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state3"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state3/state.db")
    kernel = SecurityKernel(config=config, store=store, actor_identity="tester")
    fp = kernel.policy_fingerprint()
    assert "policy_hash" in fp
    assert len(fp["policy_hash"]) == 64
    assert "configuration_hash" in fp
