"""Threat replay — every discovered bug becomes replayable regression."""

from pathlib import Path

from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.models import Outcome
from noble.store import Store
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


# Historical bug: substring repo match allowed lookalike domains
def test_replay_scope_substring_bypass():
    from noble.scope import ScopeEngine
    from noble.targets import normalize_target

    scope = ScopeEngine.from_file(workspace_root=ROOT)
    # This was previously vulnerable to substring matching; now must deny
    assert not scope.evaluate(normalize_target("localhost.evil.com"), "static-analysis").allowed
    assert not scope.evaluate(
        normalize_target("notvishnubedi3/noble-cascade"), "static-analysis"
    ).allowed


# Historical bug: forged grant/target mismatch
def test_replay_forged_grant(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    from noble.targets import normalize_target

    target_good = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
    grant = engine.authorizer.issue(
        issuer="a",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target_good,
        purpose="security-research",
        privileges=("scan",),
    )
    # Try to use grant for different target
    result = engine.run(make_scan_request(grant.grant_id, target=str(ROOT / "noble/__init__.py")))
    assert result.outcome == Outcome.DENIED_AUTHORIZATION


# Historical bug: tool output could forge verified finding
def test_replay_tool_output_forge(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    import json

    from noble.models import CommandResult
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

    class Forge:
        def run(self, inv):
            data = {
                "request_id": inv.context.request_id,
                "target": inv.context.target.canonical,
                "tool": inv.definition.name,
                "version": inv.definition.version,
                "complete": True,
                "warnings": [],
                "provenance": {"scanner": "local-ast-sql-v1"},
                "observations": [
                    {
                        "title": "Forged",
                        "category": "sql-injection",
                        "cwe": "CWE-89",
                        "file": "tests/fixtures/sql_injection.py",
                        "line": 10,
                        "snippet": FIXTURE.read_text().splitlines()[9],
                        "description": "x",
                        "impact": "x",
                        "remediation": "x",
                        "verified": True,
                        "reproduction": {
                            "unsafe_rows": 2,
                            "parameterized_rows": 0,
                            "synthetic": True,
                        },
                    }
                ],
            }
            return CommandResult(("x",), 0, json.dumps(data), "", 0.01, False, False)

    engine.runner = Forge()  # type: ignore
    result = engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    assert result.outcome == Outcome.INVALID_OUTPUT
    assert not result.finding_ids


# Historical bug: duplicate JSON keys
def test_replay_duplicate_keys(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state3"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state3/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    from noble.models import CommandResult
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

    class Dup:
        def run(self, inv):
            raw = (
                '{"request_id":"'
                + inv.context.request_id
                + '","target":"'
                + inv.context.target.canonical
                + '","tool":"static-code-scan","tool":"fixture-sql-verify","version":"1.0.0","observations":[],"complete":true,"warnings":[],"provenance":{}}'
            )
            return CommandResult(("x",), 0, raw, "", 0.01, False, False)

    engine.runner = Dup()  # type: ignore
    assert (
        engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE))).outcome
        == Outcome.INVALID_OUTPUT
    )
