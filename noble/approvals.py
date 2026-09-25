"""High-risk approval state machine, bound to request and policy scope.

The agent itself cannot issue or approve high-risk requests. Identity is the
local OS user at the CLI boundary. A separate, trusted identity provider is
needed before this model can be deployed in a multi-user service.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .audit import AuditSink
from .errors import (
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalRequired,
    AuthorizationDenied,
    SelfApprovalDenied,
)
from .models import (
    Approval,
    ApprovalState,
    RiskAssessment,
    Scope,
    SecurityRequest,
    new_id,
    stable_hash,
    utcnow,
)
from .store import Store


def _scope_digest(scope: Scope) -> str:
    return stable_hash(
        "|".join(
            (
                scope.policy_name,
                *scope.allowed_targets,
                *scope.allowed_actions,
                *scope.denied_targets,
                *scope.denied_actions,
                scope.valid_from.isoformat() if scope.valid_from else "",
                scope.valid_until.isoformat() if scope.valid_until else "",
                *scope.network_destinations,
            )
        )
    )


class ApprovalManager:
    def __init__(self, store: Store) -> None:
        self.store = store

    def request(
        self,
        request: SecurityRequest,
        risk: RiskAssessment,
        scope: Scope,
        *,
        valid_for_seconds: int = 1800,
        now: datetime | None = None,
    ) -> Approval:
        if not risk.requires_approval:
            raise ApprovalInvalid("only HIGH and CRITICAL actions require human approval")
        if not 1 <= valid_for_seconds <= 3600:
            raise ApprovalInvalid("approval lifetime must be between 1 and 3600 seconds")
        moment = now or utcnow()
        approval = Approval(
            approval_id=new_id("approval"),
            request_fingerprint=request.fingerprint(),
            action=request.action,
            target=scope.allowed_targets[0],
            risk_tier=risk.tier.value,
            requester=request.requester,
            scope_digest=_scope_digest(scope),
            state=ApprovalState.PENDING,
            requested_at=moment,
            expires_at=moment + timedelta(seconds=valid_for_seconds),
        )
        AuditSink(self.store).emit(
            request_id=request.request_id,
            operator=request.requester,
            action=request.action,
            target=scope.allowed_targets[0],
            policy=scope.policy_name,
            decision="APPROVAL_REQUESTED",
            risk=risk.tier.value,
            approval=approval.approval_id,
            result="pending",
            reason="request-bound high-risk approval created",
        )
        self.store.put_approval(approval)
        return approval

    def decide(
        self,
        approval_id: str,
        *,
        approver: str,
        approver_grant_id: str,
        approve: bool,
        reason: str,
        now: datetime | None = None,
    ) -> Approval:
        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise ApprovalInvalid("unknown approval")
        moment = now or utcnow()
        if approval.state is not ApprovalState.PENDING:
            raise ApprovalInvalid("approval is not pending")
        if moment > approval.expires_at:
            approval.state = ApprovalState.EXPIRED
            self.store.update_approval(approval, expected_state=ApprovalState.PENDING)
            raise ApprovalExpired("approval expired before decision")
        if approver == approval.requester or not approver:
            raise SelfApprovalDenied("requester cannot approve their own action")
        grant = self.store.get_grant(approver_grant_id)
        if (
            grant is None
            or grant.principal != approver
            or grant.role != "approver"
            or grant.capability != "approve"
            or grant.action != approval.action
            or "approve" not in grant.privileges
            or not grant.active_at(moment)
            or grant.target_pattern != approval.target
        ):
            raise AuthorizationDenied("approver lacks an active target-bound approval grant")
        approval.state = ApprovalState.APPROVED if approve else ApprovalState.REJECTED
        approval.approver = approver
        approval.decided_at = moment
        approval.reason = reason[:200]
        AuditSink(self.store).emit(
            request_id=approval.approval_id,
            operator=approver,
            action=approval.action,
            target=approval.target,
            policy="approval-state-machine",
            decision="APPROVAL_DECISION_REQUESTED",
            risk=approval.risk_tier,
            approval=approval.approval_id,
            result="approve" if approve else "reject",
            reason=reason,
        )
        if not self.store.update_approval(approval, expected_state=ApprovalState.PENDING):
            raise ApprovalInvalid("approval changed during decision")
        return approval

    def revoke(self, approval_id: str, *, approver: str, now: datetime | None = None) -> Approval:
        approval = self.store.get_approval(approval_id)
        if approval is None or approval.state is not ApprovalState.APPROVED:
            raise ApprovalInvalid("approval is not currently approved")
        if approval.approver != approver:
            raise AuthorizationDenied("only the original approver can revoke this approval")
        approval.state = ApprovalState.REVOKED
        approval.decided_at = now or utcnow()
        AuditSink(self.store).emit(
            request_id=approval.approval_id,
            operator=approver,
            action=approval.action,
            target=approval.target,
            policy="approval-state-machine",
            decision="APPROVAL_REVOCATION_REQUESTED",
            risk=approval.risk_tier,
            approval=approval.approval_id,
            result="revoke",
            reason="original approver revoked approval",
        )
        if not self.store.update_approval(approval, expected_state=ApprovalState.APPROVED):
            raise ApprovalInvalid("approval changed during revocation")
        return approval

    def ensure(
        self,
        request: SecurityRequest,
        risk: RiskAssessment,
        scope: Scope,
        *,
        now: datetime | None = None,
    ) -> Approval | None:
        if not risk.requires_approval:
            return None
        if not request.approval_token:
            raise ApprovalRequired("explicit human approval required for HIGH/CRITICAL action")
        approval = self.store.get_approval(request.approval_token)
        if approval is None:
            raise ApprovalInvalid("unknown approval ID")
        moment = now or utcnow()
        if moment > approval.expires_at:
            raise ApprovalExpired("approval has expired")
        if (
            approval.state is not ApprovalState.APPROVED
            or approval.approver == request.requester
            or approval.request_fingerprint != request.fingerprint()
            or approval.scope_digest != _scope_digest(scope)
            or approval.risk_tier != risk.tier.value
            or approval.requester != request.requester
        ):
            raise ApprovalInvalid("approval is rejected, revoked, forged or does not match request")
        return approval
