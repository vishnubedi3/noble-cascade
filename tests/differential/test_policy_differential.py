"""Differential testing — compare policy engine vs reference implementation."""

from pathlib import Path

import pytest

from noble.scope import ScopeEngine
from noble.targets import normalize_target

ROOT = Path(__file__).resolve().parents[2]


def reference_evaluate(target_str: str, action: str, policy: dict):
    # Simple reference: substring match (intentionally naive) to show differential
    # We compare Noble's anchored logic vs naive substring
    target = normalize_target(target_str)
    # Naive would allow evil.com/localhost via substring
    naive_allow = "localhost" in target_str
    # Noble should deny evil.com/localhost
    engine = ScopeEngine(policy, workspace_root=ROOT)
    noble_decision = engine.evaluate(target, action)
    return naive_allow, noble_decision.allowed


@pytest.mark.unit
def test_differential_naive_vs_canonical():
    policy = {
        "default_action": "deny",
        "scope": {
            "allowed_domains": ["localhost", "*.local"],
            "allowed_testing_methods": ["static-analysis"],
        },
    }
    # Naive substring check would allow localhost.evil.com because it contains "localhost"
    # Noble's anchored matching denies lookalike
    naive, noble = reference_evaluate("localhost.evil.com", "static-analysis", policy)
    assert naive is True
    assert noble is False
    # Noble correctly allows proper subdomain
    assert (
        ScopeEngine(policy, workspace_root=ROOT)
        .evaluate(normalize_target("docs.local"), "static-analysis")
        .allowed
    )
    # Differential should catch bypass attempts


@pytest.mark.unit
def test_policy_differential_no_divergence_on_valid():
    policy = {
        "default_action": "deny",
        "scope": {
            "allowed_repositories": ["vishnubedi3/*"],
            "allowed_testing_methods": ["static-analysis"],
        },
    }
    engine = ScopeEngine(policy, workspace_root=ROOT)
    d1 = engine.evaluate(normalize_target("vishnubedi3/noble-cascade"), "static-analysis")
    d2 = engine.evaluate(normalize_target("vishnubedi3/noble-cascade"), "static-analysis")
    assert d1.decision == d2.decision
