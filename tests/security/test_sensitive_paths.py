"""Credential-shaped source paths and hostile request fields must not leak into state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from noble.engine import NobleEngine
from noble.errors import InvalidInput
from noble.models import Outcome
from noble.targets import normalize_target
from tests.conftest import make_scan_request


@pytest.mark.security
def test_direct_credential_shaped_target_is_refused_and_redacted(engine: NobleEngine) -> None:
    raw = str(Path(engine.config.workspace_root) / "tests/fixtures/api_key=ABCDEFGHIJKLMNOPQRST.py")
    target = normalize_target(raw)
    with pytest.raises(InvalidInput):
        engine.authorizer.issue(
            issuer="admin",
            principal="researcher",
            role="operator",
            capability="scan",
            action="static-analysis",
            target=target,
            purpose="security-research",
            privileges=("scan",),
        )
    result = engine.run(make_scan_request(None, target=raw))
    assert result.outcome is Outcome.INVALID_INPUT
    assert "ABCDEFGHIJKLMNOPQRST" not in json.dumps(result.to_dict())
    assert "ABCDEFGHIJKLMNOPQRST" not in json.dumps(engine.store.list_audit())


@pytest.mark.security
def test_scanned_credential_shaped_filename_is_redacted_in_evidence(engine: NobleEngine) -> None:
    root = Path(engine.config.workspace_root)
    file = root / "tests/fixtures/api_key=ABCDEFGHIJKLMNOPQRST.py"
    try:
        file.write_text(
            "def example(conn, name):\n"
            "    return conn.execute(f\"SELECT name FROM users WHERE name = '{name}'\")\n"
        )
        target = normalize_target(str(file.parent), workspace_root=engine.config.workspace_root)
        grant = engine.authorizer.issue(
            issuer="admin",
            principal="researcher",
            role="operator",
            capability="scan",
            action="static-analysis",
            target=target,
            purpose="security-research",
            privileges=("scan",),
        )
        result = engine.run(make_scan_request(grant.grant_id, target=str(file.parent)))
        assert result.succeeded
        assert result.finding_ids
        assert "ABCDEFGHIJKLMNOPQRST" not in json.dumps(engine.store.list_findings())
        assert "ABCDEFGHIJKLMNOPQRST" not in json.dumps(
            engine.store.list_evidence(result.request_id)
        )
    finally:
        file.unlink(missing_ok=True)
