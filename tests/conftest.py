"""Isolated state per test; only the synthetic committed fixture is scanned."""

from __future__ import annotations

from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.models import SecurityRequest
from noble.store import Store
from noble.targets import normalize_target

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/fixtures/sql_injection.py"


@pytest.fixture
def engine(tmp_path: Path) -> NobleEngine:
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    return NobleEngine(
        config, store=Store(tmp_path / "state/state.db"), actor_identity="researcher"
    )


@pytest.fixture
def grant_scan(engine: NobleEngine) -> str:
    target = normalize_target(str(FIXTURE), workspace_root=engine.config.workspace_root)
    return engine.authorizer.issue(
        issuer="trusted-admin",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="security-research",
        privileges=("scan",),
    ).grant_id


@pytest.fixture
def grant_verify(engine: NobleEngine) -> str:
    target = normalize_target(str(FIXTURE), workspace_root=engine.config.workspace_root)
    return engine.authorizer.issue(
        issuer="trusted-admin",
        principal="researcher",
        role="security-auditor",
        capability="verify",
        action="local-unit-test-verification",
        target=target,
        purpose="security-research",
        privileges=("verify",),
    ).grant_id


def make_scan_request(
    grant_id: str | None, *, target: str = str(FIXTURE), **kwargs: object
) -> SecurityRequest:
    return SecurityRequest(
        action="static-analysis",
        target=target,
        requester="researcher",
        tool="static-code-scan",
        authorization_grant=grant_id,
        **kwargs,
    )
