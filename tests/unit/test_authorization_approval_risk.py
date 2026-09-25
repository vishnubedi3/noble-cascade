from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from noble.approvals import ApprovalManager
from noble.authorization import Authorizer
from noble.errors import ApprovalExpired, ApprovalInvalid, AuthorizationDenied, SelfApprovalDenied
from noble.models import ApprovalState, RiskTier, Scope, SecurityRequest, Target, TargetKind, utcnow
from noble.risk import RiskEngine
from noble.store import Store
from noble.targets import normalize_target


@pytest.mark.unit
def test_grant_exact_target_action_principal_purpose_and_time(tmp_path: Path) -> None:
    auth = Authorizer(Store(tmp_path / "state/state.db"))
    target = normalize_target("vishnubedi3/noble-cascade")
    grant = auth.issue(
        issuer="admin",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="research",
        privileges=("scan",),
        valid_for_seconds=60,
    )
    base = SecurityRequest(
        action="static-analysis",
        target=target.canonical,
        requester="researcher",
        purpose="research",
        authorization_grant=grant.grant_id,
    )
    assert auth.check(base, target, ("scan",)).principal == "researcher"
    base.action = "secret-scanning"
    with pytest.raises(AuthorizationDenied):
        auth.check(base, target, ("scan",))
    base.action = "static-analysis"
    base.requester = "other-user"
    with pytest.raises(AuthorizationDenied):
        auth.check(base, target, ("scan",))
    base.requester = "researcher"
    base.purpose = "different-purpose"
    with pytest.raises(AuthorizationDenied):
        auth.check(base, target, ("scan",))
    base.purpose = "research"
    other_target = normalize_target("vishnubedi3/other")
    with pytest.raises(AuthorizationDenied):
        auth.check(base, other_target, ("scan",))
    with pytest.raises(AuthorizationDenied):
        auth.check(base, target, ("verify",))
    with pytest.raises(AuthorizationDenied):
        auth.check(base, target, ("scan",), now=grant.valid_until + timedelta(seconds=1))


@pytest.mark.unit
def test_role_limits_and_grant_expiry_bounds(tmp_path: Path) -> None:
    auth = Authorizer(Store(tmp_path / "state/state.db"))
    target = normalize_target("vishnubedi3/noble-cascade")
    with pytest.raises(AuthorizationDenied):
        auth.issue(
            issuer="admin",
            principal="operator",
            role="operator",
            capability="verify",
            action="static-analysis",
            target=target,
            purpose="research",
            privileges=("verify",),
        )
    with pytest.raises(AuthorizationDenied):
        auth.issue(
            issuer="admin",
            principal="operator",
            role="admin",
            capability="*",
            action="static-analysis",
            target=target,
            purpose="research",
            privileges=("*",),
        )


@pytest.mark.unit
def test_risk_unknown_is_critical_and_context_can_raise_risk() -> None:
    engine = RiskEngine()
    target = Target(raw="fixture", kind=TargetKind.REPOSITORY, canonical="owner/repo")
    assert (
        engine.assess(SecurityRequest("static-analysis", "owner/repo", "x"), target).tier
        is RiskTier.LOW
    )
    assert (
        engine.assess(SecurityRequest("unknown", "owner/repo", "x"), target).tier
        is RiskTier.CRITICAL
    )
    target.environment = "production"
    assert (
        engine.assess(
            SecurityRequest("static-analysis", "owner/repo", "x", parameters={"network": True}),
            target,
        ).tier
        is RiskTier.HIGH
    )
    assert (
        engine.assess(SecurityRequest("data-exfiltration", "owner/repo", "x"), target).tier
        is RiskTier.CRITICAL
    )


@pytest.mark.unit
def test_approval_machine_rejects_self_forged_expired_changed_and_revoked(tmp_path: Path) -> None:
    store = Store(tmp_path / "state/state.db")
    manager = ApprovalManager(store)
    authorizer = Authorizer(store)
    target = normalize_target("vishnubedi3/noble-cascade")
    grant = authorizer.issue(
        issuer="admin",
        principal="auditor",
        role="approver",
        capability="approve",
        action="poc-execution",
        target=target,
        purpose="research",
        privileges=("approve",),
        valid_for_seconds=1800,
    )
    request = SecurityRequest(
        action="poc-execution",
        target=target.canonical,
        requester="researcher",
        tool="synthetic",
        parameters={"fixture": True},
    )
    scope = Scope(
        "synthetic-scope", allowed_targets=(target.canonical,), allowed_actions=(request.action,)
    )
    risk = RiskEngine().assess(request, target)
    assert risk.tier is RiskTier.HIGH
    approval = manager.request(request, risk, scope, valid_for_seconds=120)
    assert approval.state is ApprovalState.PENDING
    with pytest.raises(SelfApprovalDenied):
        manager.decide(
            approval.approval_id,
            approver="researcher",
            approver_grant_id=grant.grant_id,
            approve=True,
            reason="self",
        )
    with pytest.raises(AuthorizationDenied):
        manager.decide(
            approval.approval_id,
            approver="intruder",
            approver_grant_id=grant.grant_id,
            approve=True,
            reason="forged",
        )
    manager.decide(
        approval.approval_id,
        approver="auditor",
        approver_grant_id=grant.grant_id,
        approve=True,
        reason="fixture",
    )
    request.approval_token = approval.approval_id
    assert manager.ensure(request, risk, scope) is not None
    request.parameters["fixture"] = False
    with pytest.raises(ApprovalInvalid):
        manager.ensure(request, risk, scope)
    request.parameters["fixture"] = True
    with pytest.raises(ApprovalInvalid):
        manager.ensure(
            request,
            risk,
            Scope(
                "different-scope",
                allowed_targets=(target.canonical,),
                allowed_actions=(request.action,),
            ),
        )
    with pytest.raises(ApprovalExpired):
        manager.ensure(request, risk, scope, now=utcnow() + timedelta(hours=1))
    manager.revoke(approval.approval_id, approver="auditor")
    with pytest.raises(ApprovalInvalid):
        manager.ensure(request, risk, scope)


@pytest.mark.unit
def test_approval_decision_is_atomic(tmp_path: Path) -> None:
    store = Store(tmp_path / "state/state.db")
    target = normalize_target("vishnubedi3/noble-cascade")
    manager = ApprovalManager(store)
    request = SecurityRequest("poc-execution", target.canonical, "researcher", tool="synthetic")
    scope = Scope("scope", allowed_targets=(target.canonical,), allowed_actions=(request.action,))
    approval = manager.request(request, RiskEngine().assess(request, target), scope)
    approval.state = ApprovalState.APPROVED
    assert store.update_approval(approval, expected_state=ApprovalState.REJECTED) is False
    assert store.get_approval(approval.approval_id).state is ApprovalState.PENDING
