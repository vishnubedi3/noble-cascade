"""Canonical Security Kernel — single authoritative policy enforcement core.

All security-relevant decisions flow through this module. Every entry point
(CLI, Engine, future API/dashboard) must use Kernel; never duplicate policy logic.

Responsibilities:
    Request validation
    Scope evaluation
    Authorization check
    Risk assessment
    Approval enforcement
    Execution state transitions (via StateMachine)
    Evidence handling contracts
    Audit emission

The Kernel is deterministic, has no hidden state, and is fully testable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals import ApprovalManager
from .authorization import Authorizer
from .config import RuntimeConfig
from .errors import InvalidInput
from .models import (
    PolicyDecision,
    RiskAssessment,
    SecurityRequest,
    Target,
)
from .risk import RiskEngine
from .scope import ScopeEngine
from .store import Store

_ID_RE = re.compile(r"^req-[0-9a-f]{32}$")
_PRINCIPAL_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


@dataclass(frozen=True, slots=True)
class KernelDecision:
    """One explainable policy decision produced by the Kernel."""

    subsystem: str
    decision: str
    allowed: bool
    reason: str
    policy: str
    rule: str
    details: dict[str, Any]


class SecurityKernel:
    """Authoritative security core. All policy logic lives here."""

    def __init__(
        self,
        config: RuntimeConfig | None = None,
        *,
        store: Store | None = None,
        scope: ScopeEngine | None = None,
        actor_identity: str | None = None,
    ) -> None:
        import os
        import pwd

        self.actor_identity = actor_identity or pwd.getpwuid(os.getuid()).pw_name
        self.config = config or RuntimeConfig.load()
        self.store = store or Store(Path(self.config.state_directory) / "state.db")
        self.scope = scope or ScopeEngine.from_file(workspace_root=self.config.workspace_root)
        self.authorizer = Authorizer(self.store)
        self.approvals = ApprovalManager(self.store)
        self.risk = RiskEngine()

    # ------------------------------------------------------------------
    # Request validation (deterministic, no I/O beyond store reservation)
    # ------------------------------------------------------------------
    def validate_request(self, request: SecurityRequest) -> KernelDecision:
        if not _ID_RE.fullmatch(request.request_id):
            raise InvalidInput("request ID has an invalid format")
        if not _PRINCIPAL_RE.fullmatch(request.requester):
            raise InvalidInput("requester identity has an invalid format")
        if request.requester != self.actor_identity:
            from .errors import AuthorizationDenied

            raise AuthorizationDenied("requester must match the local OS actor identity")
        if not request.action or not request.tool:
            raise InvalidInput("action and registered tool are required")
        if not isinstance(request.parameters, dict):
            raise InvalidInput("tool parameters must be an object")
        return KernelDecision(
            subsystem="REQUEST",
            decision="VALID",
            allowed=True,
            reason="request structure and principal validated",
            policy="kernel/request-validation",
            rule="request.schema.principal_binding",
            details={"request_id": request.request_id},
        )

    def evaluate_scope(self, target: Target, action: str) -> tuple[PolicyDecision, KernelDecision]:
        decision = self.scope.evaluate(target, action)
        kernel_decision = KernelDecision(
            subsystem="SCOPE",
            decision=decision.decision.value,
            allowed=decision.allowed,
            reason=decision.reason,
            policy=self.scope.name,
            rule=decision.rule,
            details={"target": target.canonical, "action": action, "kind": target.kind.value},
        )
        return decision, kernel_decision

    def check_authorization(
        self, request: SecurityRequest, target: Target, required_permissions: tuple[str, ...]
    ):
        auth = self.authorizer.check(request, target, required_permissions)
        return auth, KernelDecision(
            subsystem="AUTH",
            decision="AUTHORIZED",
            allowed=True,
            reason=f"grant {auth.grant_id} permits the required capability",
            policy="local-os-admin",
            rule="authorization.exact_match",
            details={
                "grant_id": auth.grant_id,
                "principal": auth.principal,
                "capability": auth.capability,
            },
        )

    def assess_risk(
        self, request: SecurityRequest, target: Target
    ) -> tuple[RiskAssessment, KernelDecision]:
        risk = self.risk.assess(request, target)
        return risk, KernelDecision(
            subsystem="RISK",
            decision=risk.tier.value,
            allowed=True,
            reason=risk.rationale,
            policy="risk/classification",
            rule=f"risk.tier.{risk.tier.value.lower()}",
            details={"score": risk.score, "factors": risk.factors},
        )

    def explain_decision(self, decision: KernelDecision) -> str:
        return (
            f"{decision.subsystem}: {decision.decision}\n"
            f"  Allowed: {decision.allowed}\n"
            f"  Reason: {decision.reason}\n"
            f"  Policy: {decision.policy}\n"
            f"  Rule: {decision.rule}\n"
            f"  Details: {json.dumps(decision.details, sort_keys=True)}"
        )

    def policy_fingerprint(self) -> dict[str, str]:
        """Cryptographically verifiable policy fingerprint for an execution."""
        from .policy_version import compute_policy_fingerprint

        return compute_policy_fingerprint(self.config, self.scope)
