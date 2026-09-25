from __future__ import annotations

from pathlib import Path

import pytest

from noble.errors import ConfigurationInvalid, InvalidInput
from noble.models import ScopeDecision, TargetKind
from noble.scope import ScopeEngine
from noble.targets import normalize_target

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_exact_repository_wildcard_is_anchored() -> None:
    scope = ScopeEngine.from_file()
    assert scope.evaluate(normalize_target("vishnubedi3/noble-cascade"), "static-analysis").allowed
    for bad in ("notvishnubedi3/noble-cascade", "vishnubedi3.example/bad", "other/noble-cascade"):
        try:
            target = normalize_target(bad)
        except InvalidInput:
            continue
        assert scope.evaluate(target, "static-analysis").decision is not ScopeDecision.ALLOW


@pytest.mark.unit
@pytest.mark.parametrize(
    "raw",
    [
        "evil.com/localhost",
        "attacker.example/?repo=vishnubedi3/noble-cascade",
        "https://attacker.example/?repo=vishnubedi3/noble-cascade",
        "https://localhost@evil.com/",
        "https://localhost/secret?token=abc",
        "https://localhost\\@evil.com/",
        "http://localhost/%2e%2e/secret",
        "repo/ok%252Fbad",
        "localhost\u202e.evil.com",
        "https://localhost:notaport/",
        "",
    ],
)
def test_ambiguous_targets_fail_closed(raw: str) -> None:
    with pytest.raises(InvalidInput):
        normalize_target(raw)


@pytest.mark.unit
def test_domain_wildcard_requires_proper_subdomain() -> None:
    scope = ScopeEngine.from_file()
    good = normalize_target("docs.local")
    assert scope.evaluate(good, "static-analysis").allowed
    for host in ("evil.local.evil.com", "notlocalhost", "target-app.internal.evil.com"):
        assert not scope.evaluate(normalize_target(host), "static-analysis").allowed


@pytest.mark.unit
def test_forbidden_target_and_action_override_allow() -> None:
    policy = {
        "default_action": "deny",
        "scope": {
            "allowed_domains": ["*.gov"],
            "allowed_testing_methods": ["static-analysis", "data-exfiltration"],
            "forbidden_targets": ["*.gov"],
            "forbidden_actions": ["data-exfiltration"],
        },
    }
    scope = ScopeEngine(policy, workspace_root=ROOT)
    assert (
        scope.evaluate(normalize_target("department.gov"), "static-analysis").decision
        is ScopeDecision.DENY
    )
    assert (
        scope.evaluate(normalize_target("localhost"), "data-exfiltration").decision
        is ScopeDecision.DENY
    )


@pytest.mark.unit
def test_directory_scope_resolves_symlinks(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    (work / "linked").symlink_to(tmp_path, target_is_directory=True)
    scope = ScopeEngine(
        {
            "default_action": "deny",
            "scope": {
                "allowed_directories": ["."],
                "allowed_testing_methods": ["static-analysis"],
            },
        },
        workspace_root=work,
    )
    assert scope.evaluate(normalize_target(str(work / "ok.py")), "static-analysis").allowed
    assert (
        scope.evaluate(
            normalize_target(str(work / "linked" / "escaped.py")), "static-analysis"
        ).decision
        is ScopeDecision.UNKNOWN
    )


@pytest.mark.unit
def test_invalid_policy_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationInvalid):
        ScopeEngine({"default_action": "allow", "scope": {}}, workspace_root=tmp_path)
    with pytest.raises(ConfigurationInvalid):
        ScopeEngine(
            {"default_action": "deny", "scope": {"allowed_repositories": ["*"]}},
            workspace_root=tmp_path,
        )


@pytest.mark.unit
def test_normalization_classes_and_ports() -> None:
    assert normalize_target("VishnuBedi3/Noble-Cascade").canonical == "vishnubedi3/noble-cascade"
    url = normalize_target("https://Docs.local:443/guide/../a")
    assert url.kind is TargetKind.URL and url.canonical == "https://docs.local/a"
    assert normalize_target("10.0.0.7").kind is TargetKind.IP
    assert normalize_target("10.0.0.0/24").kind is TargetKind.CIDR


@pytest.mark.unit
def test_only_explicit_actions_are_allowed() -> None:
    scope = ScopeEngine.from_file()
    target = normalize_target("vishnubedi3/noble-cascade")
    assert scope.evaluate(target, "unknown-action").decision is ScopeDecision.DENY
    assert scope.evaluate(target, "local-unit-test-verification").allowed


@pytest.mark.unit
def test_cidr_scope_requires_full_containment() -> None:
    scope = ScopeEngine.from_file()
    assert scope.evaluate(normalize_target("10.0.0.0/8"), "static-analysis").allowed
    assert scope.evaluate(normalize_target("10.0.0.0/9"), "static-analysis").allowed
    # 10.0.0.0/7 covers 11.0.0.0/8, which is NOT authorized.
    assert (
        scope.evaluate(normalize_target("10.0.0.0/7"), "static-analysis").decision
        is ScopeDecision.UNKNOWN
    )


@pytest.mark.unit
def test_scope_time_window_blocks_expired_scope(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    scope = ScopeEngine(
        {
            "default_action": "deny",
            "scope": {
                "allowed_repositories": ["vishnubedi3/*"],
                "allowed_testing_methods": ["static-analysis"],
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2025-01-02T00:00:00Z",
            },
        },
        workspace_root=tmp_path,
    )
    target = normalize_target("vishnubedi3/noble-cascade")
    assert scope.evaluate(
        target, "static-analysis", moment=datetime(2025, 1, 1, 12, tzinfo=timezone.utc)
    ).allowed
    assert (
        scope.evaluate(
            target, "static-analysis", moment=datetime(2025, 1, 3, tzinfo=timezone.utc)
        ).decision
        is ScopeDecision.DENY
    )
    with pytest.raises(ConfigurationInvalid):
        ScopeEngine(
            {"default_action": "deny", "scope": {"valid_until": "2025-01-02"}},
            workspace_root=tmp_path,
        )
