"""Policy Simulation — answer 'what would happen?' without executing.

    noble simulate TARGET --action static-analysis --tool static-code-scan

Produces:
    Scope: ALLOWED/DENY/UNKNOWN
    Risk: LOW/MEDIUM/HIGH/CRITICAL
    Approval: REQUIRED / NOT_REQUIRED / WOULD_BLOCK
    Execution: ALLOWED / BLOCKED
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import RuntimeConfig
from .models import RiskTier, ScopeDecision
from .scope import ScopeEngine
from .targets import normalize_target


@dataclass(frozen=True, slots=True)
class SimulationResult:
    target: str
    action: str
    tool: str
    scope_decision: str
    scope_rule: str
    scope_reason: str
    risk_tier: str
    risk_score: int
    approval_required: bool
    execution: str
    execution_reason: str
    policy: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "action": self.action,
            "tool": self.tool,
            "scope": self.scope_decision,
            "scope_rule": self.scope_rule,
            "scope_reason": self.scope_reason,
            "risk": self.risk_tier,
            "risk_score": self.risk_score,
            "approval": "REQUIRED" if self.approval_required else "NOT_REQUIRED",
            "execution": self.execution,
            "execution_reason": self.execution_reason,
            "policy": self.policy,
        }

    def explain(self) -> str:
        return (
            f"Simulation for {self.target} [{self.action}/{self.tool}]\n"
            f"  Scope:    {self.scope_decision} (rule: {self.scope_rule}) — {self.scope_reason}\n"
            f"  Policy:   {self.policy}\n"
            f"  Risk:     {self.risk_tier} (score {self.risk_score})\n"
            f"  Approval: {'REQUIRED' if self.approval_required else 'NOT_REQUIRED'}\n"
            f"  Execution:{self.execution} — {self.execution_reason}\n"
        )


class PolicySimulator:
    def __init__(self, config: RuntimeConfig | None = None, scope: ScopeEngine | None = None):

        self.config = config or RuntimeConfig.load()
        self.scope = scope or ScopeEngine.from_file(workspace_root=self.config.workspace_root)

    def simulate(self, raw_target: str, action: str, tool: str | None = None) -> SimulationResult:
        from .models import SecurityRequest
        from .registry import ToolRegistry
        from .risk import RiskEngine

        target = normalize_target(raw_target, workspace_root=self.config.workspace_root)
        decision = self.scope.evaluate(target, action)

        # Risk
        req = SecurityRequest(
            action=action, target=raw_target, requester="simulator", tool=tool or "unknown"
        )
        risk = RiskEngine().assess(req, target)

        # Tool checks
        execution = "BLOCKED"
        reason = decision.reason
        if decision.decision is ScopeDecision.DENY:
            execution = "BLOCKED"
            reason = f"Scope DENY: {decision.reason}"
        elif decision.decision is ScopeDecision.UNKNOWN:
            execution = "BLOCKED"
            reason = f"Scope UNKNOWN (deny-by-default): {decision.reason}"
        else:
            # Check registry
            if tool:
                try:
                    reg = ToolRegistry(self.config)
                    definition = reg.get(tool)
                    if definition.action != action:
                        execution = "BLOCKED"
                        reason = f"Tool {tool} does not implement action {action}"
                    elif target.kind not in definition.allowed_target_kinds:
                        execution = "BLOCKED"
                        reason = f"Tool {tool} does not support target kind {target.kind.value}"
                    elif definition.network_required:
                        execution = "BLOCKED"
                        reason = "Network-capable tools require isolation (unavailable)"
                    elif risk.tier.rank >= RiskTier.HIGH.rank:
                        execution = "BLOCKED"
                        reason = "HIGH risk requires distinct approval (no HIGH tools registered)"
                    else:
                        execution = "ALLOWED"
                        reason = (
                            "All preconditions satisfied (would proceed to authorization check)"
                        )
                except Exception as exc:
                    execution = "BLOCKED"
                    reason = f"Tool check failed: {type(exc).__name__}: {exc}"
            else:
                execution = "ALLOWED" if decision.allowed else "BLOCKED"

        return SimulationResult(
            target=target.canonical,
            action=action,
            tool=tool or "none",
            scope_decision=decision.decision.value,
            scope_rule=decision.rule,
            scope_reason=decision.reason,
            risk_tier=risk.tier.value,
            risk_score=risk.score,
            approval_required=risk.tier.rank >= RiskTier.HIGH.rank,
            execution=execution,
            execution_reason=reason,
            policy=self.scope.name,
        )
