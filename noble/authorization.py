"""Capability grants bound to principal, target, action, purpose and time.

Issuance is *not* an agent tool. The local CLI can create grants only for the
OS identity controlling the state directory; this is a single-user offline
control plane, not a multi-user identity provider.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from .audit import AuditSink
from .errors import AuthorizationDenied, InvalidInput
from .evidence import redact_sensitive
from .models import Authorization, AuthorizationGrant, SecurityRequest, Target, new_id, utcnow
from .store import Store

ROLE_CAPABILITIES: dict[str, frozenset[str]] = {
    "operator": frozenset({"scan", "report"}),
    "security-auditor": frozenset({"scan", "verify", "report"}),
    "approver": frozenset({"approve"}),
}


class Authorizer:
    def __init__(self, store: Store) -> None:
        self.store = store

    def issue(
        self,
        *,
        issuer: str,
        principal: str,
        role: str,
        capability: str,
        action: str,
        target: Target,
        purpose: str,
        privileges: tuple[str, ...],
        valid_for_seconds: int = 3600,
        now: datetime | None = None,
    ) -> AuthorizationGrant:
        """Issue a local grant. Caller must separately authenticate *issuer*.

        The grant is intentionally exact-target (no wildcard delegation). The
        CLI gates this method on the current OS identity and a scope check.
        """
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", issuer) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", principal
        ):
            raise InvalidInput("issuer and principal must be unambiguous local identities")
        if role not in ROLE_CAPABILITIES or capability not in ROLE_CAPABILITIES[role]:
            raise AuthorizationDenied("role cannot grant the requested capability")
        if not privileges or any(p not in ROLE_CAPABILITIES[role] for p in privileges):
            raise AuthorizationDenied("requested privileges exceed role capabilities")
        if capability not in privileges:
            raise AuthorizationDenied("grant privilege list must include its capability")
        if not 1 <= valid_for_seconds <= 86400:
            raise InvalidInput("grant lifetime must be between 1 and 86400 seconds")
        if not purpose or len(purpose) > 200 or not action or len(action) > 100:
            raise InvalidInput("purpose and action must be valid nonempty values")
        if redact_sensitive(target.canonical) != target.canonical:
            raise InvalidInput("target contains a credential-shaped value")
        if redact_sensitive(purpose) != purpose or any(ord(ch) < 32 for ch in purpose):
            raise InvalidInput("purpose cannot contain credentials or control characters")
        moment = now or utcnow()
        grant = AuthorizationGrant(
            grant_id=new_id("grant"),
            principal=principal,
            role=role,
            capability=capability,
            action=action,
            target_pattern=target.canonical,
            purpose=purpose,
            privileges=privileges,
            valid_from=moment,
            valid_until=moment + timedelta(seconds=valid_for_seconds),
            granted_by=issuer,
        )
        # Audit *before* committing a security-sensitive grant. If the audit
        # sink fails, no grant is issued; the prior event also records intent.
        AuditSink(self.store).emit(
            request_id=grant.grant_id,
            operator=issuer,
            action=action,
            target=target.canonical,
            policy="local-os-admin",
            decision="GRANT_ISSUANCE_REQUESTED",
            result="pending",
            reason=f"exact-target {capability} grant for {principal}",
        )
        self.store.put_grant(grant)
        return grant

    def check(
        self,
        request: SecurityRequest,
        target: Target,
        required_permissions: tuple[str, ...],
        *,
        now: datetime | None = None,
    ) -> Authorization:
        """An operator's request by itself never confers authorization."""
        if not request.authorization_grant:
            raise AuthorizationDenied("no authorization grant supplied")
        grant = self.store.get_grant(request.authorization_grant)
        if grant is None:
            raise AuthorizationDenied("authorization grant is unknown")
        moment = now or utcnow()
        if (
            grant.principal != request.requester
            or grant.target_pattern != target.canonical
            or grant.purpose != request.purpose
            or grant.action != request.action
            or not grant.active_at(moment)
            or grant.capability not in ROLE_CAPABILITIES.get(grant.role, frozenset())
            or not set(required_permissions).issubset(set(grant.privileges))
        ):
            raise AuthorizationDenied(
                "grant does not authorize this principal, target, purpose or capability"
            )
        return Authorization(
            grant_id=grant.grant_id,
            principal=grant.principal,
            role=grant.role,
            capability=grant.capability,
            checked_at=moment,
        )
