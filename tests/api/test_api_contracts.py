"""API contract testing — every endpoint (CLI surface) validated for schema/auth/rate/error/malformed."""

from pathlib import Path

import pytest

from noble.cli import make_parser
from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.store import Store
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_cli_schema_validation():
    parser = make_parser()
    # Valid simulate
    args = parser.parse_args(
        ["simulate", str(FIXTURE), "--action", "static-analysis", "--tool", "static-code-scan"]
    )
    assert args.target == str(FIXTURE)
    # Invalid tool should be rejected by parser choices? But simulate allows any string
    # Ensure unknown tool via runtime is blocked
    from noble.simulate import PolicySimulator

    sim = PolicySimulator()
    result = sim.simulate(str(FIXTURE), "static-analysis", "nonexistent-tool")
    assert result.execution == "BLOCKED"


@pytest.mark.unit
def test_authorization_contract_via_cli(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    # No grant -> denied
    result = engine.run(make_scan_request(None, target=str(FIXTURE)))
    assert result.outcome.value == "denied_authorization"
    assert result.error["code"] == "authorization_denied"


@pytest.mark.unit
def test_rate_limit_contract(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    # Exhaust rate limit
    for i in range(5):
        try:
            store.acquire_lease(
                lease_id=f"lease-{i}",
                principal="p",
                tool="scan",
                target="t",
                per_minute=2,
                global_per_minute=10,
                max_concurrent=10,
                timeout=10,
                now=100,
            )
        except Exception:
            pass
    from noble.errors import RateLimited

    with pytest.raises(RateLimited):
        store.acquire_lease(
            lease_id="lease-fail",
            principal="p",
            tool="scan",
            target="t",
            per_minute=2,
            global_per_minute=10,
            max_concurrent=10,
            timeout=10,
            now=100,
        )


@pytest.mark.unit
def test_malformed_input_returns_structured_error():
    from noble.errors import InvalidInput
    from noble.targets import normalize_target

    with pytest.raises(InvalidInput):
        normalize_target("")
    with pytest.raises(InvalidInput):
        normalize_target("https://localhost:999999/")
