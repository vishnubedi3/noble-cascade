"""Security Contracts — explicit invariants per subsystem.

Every subsystem receives explicit contracts.

Example Scope Contract:
    Input: target
    Output: allow / deny / unknown
    Invariant: Unknown never becomes allow.

Repeat across every subsystem.
"""

from __future__ import annotations

from typing import Any

from .models import PolicyDecision, ScopeDecision


class ContractViolation(RuntimeError):
    pass


def scope_contract_allows_enforcement(decision: PolicyDecision) -> None:
    """Scope contract: UNKNOWN never becomes ALLOW."""
    # This is enforced by ScopeEngine returning UNKNOWN -> engine denies.
    # Contract test verifies invariant.
    if decision.decision is ScopeDecision.UNKNOWN and decision.allowed:
        raise ContractViolation("Scope contract violated: UNKNOWN became ALLOW")


def authorization_contract(principal: str, grant_principal: str, allowed: bool) -> None:
    """Authorization contract: only exact principal match allows."""
    if allowed and principal != grant_principal:
        raise ContractViolation("Authorization contract violated: principal mismatch but allowed")


def approval_contract(requester: str, approver: str, allowed: bool) -> None:
    """Approval contract: self-approval never becomes allow."""
    if allowed and requester == approver:
        raise ContractViolation("Approval contract violated: self-approval allowed")


def sandbox_contract(sandbox_available: bool, executed: bool) -> None:
    """Sandbox contract: if sandbox unavailable, execution must not happen."""
    if not sandbox_available and executed:
        raise ContractViolation("Sandbox contract violated: execution without sandbox")


def evidence_contract(content_hash: str, expected: str, trusted: bool) -> None:
    """Evidence contract: hash mismatch never becomes trusted."""
    if content_hash != expected and trusted:
        raise ContractViolation("Evidence contract violated: hash mismatch but trusted")


def tool_output_contract(is_valid: bool, became_finding: bool) -> None:
    """Tool output contract: invalid output never becomes finding."""
    if not is_valid and became_finding:
        raise ContractViolation("Tool output contract violated: invalid output became finding")


CONTRACTS = {
    "scope": {
        "description": "Unknown never becomes allow",
        "input": "target",
        "output": ["ALLOW", "DENY", "UNKNOWN"],
        "invariant": "UNKNOWN -> DENY",
        "check": scope_contract_allows_enforcement,
    },
    "authorization": {
        "description": "Only exact principal/target/purpose/time grants allow",
        "input": "request + grant",
        "output": "AUTHORIZED / DENIED",
        "invariant": "mismatch -> DENY",
        "check": authorization_contract,
    },
    "approval": {
        "description": "Self-approval never allows high-risk",
        "input": "requester, approver",
        "output": "APPROVED / DENIED",
        "invariant": "requester == approver -> DENY",
        "check": approval_contract,
    },
    "sandbox": {
        "description": "Unavailable sandbox prevents execution",
        "input": "sandbox_available",
        "output": "EXECUTED / BLOCKED",
        "invariant": "not available -> not executed",
        "check": sandbox_contract,
    },
    "evidence": {
        "description": "Hash mismatch prevents trust",
        "input": "content_hash",
        "output": "TRUSTED / UNTRUSTED",
        "invariant": "mismatch -> UNTRUSTED",
        "check": evidence_contract,
    },
    "tool_output": {
        "description": "Invalid output never becomes finding",
        "input": "tool_output_valid",
        "output": "FINDING / NO_FINDING",
        "invariant": "invalid -> no finding",
        "check": tool_output_contract,
    },
}


def all_contracts() -> dict[str, Any]:
    return CONTRACTS
