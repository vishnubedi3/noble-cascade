"""Deterministic contextual risk classification."""

from __future__ import annotations

from .models import RiskAssessment, RiskTier, SecurityRequest, Target

LOW_ACTIONS = frozenset(
    {"static-analysis", "dependency-audit", "secret-scanning", "reconnaissance"}
)
MEDIUM_ACTIONS = frozenset({"local-unit-test-verification", "non-destructive-fuzzing"})
HIGH_ACTIONS = frozenset(
    {"poc-execution", "active-fuzzing", "credential-testing", "exploit-verification"}
)
CRITICAL_ACTIONS = frozenset(
    {
        "production-modification",
        "data-exfiltration",
        "denial-of-service",
        "destructive-database-drop",
    }
)


class RiskEngine:
    def assess(self, request: SecurityRequest, target: Target) -> RiskAssessment:
        action = request.action
        if action in LOW_ACTIONS:
            score = 10
        elif action in MEDIUM_ACTIONS:
            score = 35
        elif action in HIGH_ACTIONS:
            score = 70
        else:
            score = 95  # Unknown actions default to CRITICAL.
        factors: dict[str, str | int | bool] = {"action": action}
        if target.environment in ("production", "internet-facing"):
            score += 35
            factors["environment"] = target.environment
        if request.parameters.get("network") is True:
            score += 25
            factors["network_exposure"] = True
        if request.parameters.get("write") is True:
            score += 20
            factors["side_effects"] = "write"
        if action in CRITICAL_ACTIONS:
            score = 100
            factors["destructive"] = True
        score = min(score, 100)
        tier = (
            RiskTier.CRITICAL
            if score >= 90
            else RiskTier.HIGH
            if score >= 60
            else RiskTier.MEDIUM
            if score >= 30
            else RiskTier.LOW
        )
        return RiskAssessment(
            action=action,
            tier=tier,
            score=score,
            factors=factors,
            rationale=f"{tier.value}: action, environment, network and side effects evaluated",
        )
