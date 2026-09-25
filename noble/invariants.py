"""Formal Security Invariants — each invariant as spec->impl->test->replay->audit.

10 invariants, each with executable proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Invariant:
    id: int
    title: str
    specification: str
    implementation: str
    test: str
    replay_proof: str
    audit_proof: str


INVARIANTS: list[Invariant] = [
    Invariant(
        1,
        "No tool executes outside authorized scope (UNKNOWN->DENY)",
        "ScopeEngine.evaluate must return DENY or UNKNOWN for unauthorized target; UNKNOWN is treated as DENY; see scope-policy.yaml deny-by-default.",
        "noble/scope.py ScopeEngine.evaluate + noble/kernel.py gate() fail-closed",
        "tests/unit/test_scope_and_targets.py, tests/test_guarantee_matrix.py::test_guarantee_scope_deny_unknown, tests/property/test_target_properties.py",
        "noble simulate <outside> --json shows scope DENY and execution BLOCKED; replay of blocked execution shows state=BLOCKED",
        "audit event decision=PASSED/FAILED vs DENY with policy=Authorized Security Research Scope in audit_events table",
    ),
    Invariant(
        2,
        "High-risk actions cannot execute without required approval",
        "RiskEngine tier HIGH/CRITICAL requires Approval; ApprovalManager gates execution; no HIGH tool registered.",
        "noble/risk.py RiskEngine + noble/approvals.py ApprovalManager + noble/engine.py approval check",
        "tests/unit/test_authorization_approval_risk.py, tests/unit/test_kernel.py",
        "replay of simulated HIGH action shows approval REQUIRED and execution BLOCKED",
        "audit APPROVAL_REQUIRED events with risk_tier HIGH",
    ),
    Invariant(
        3,
        "Agent cannot approve its own action",
        "ApprovalManager.decide checks requester != approver; self-approval denied with SelfApprovalDenied.",
        "noble/approvals.py compare-and-swap + self-approval check",
        "tests/unit/test_authorization_approval_risk.py::test_self_approval_denied",
        "replay shows approval state REJECTED with reason self-approval",
        "audit APPROVAL_REJECTED with reason self-approval",
    ),
    Invariant(
        4,
        "Unknown policy decisions fail closed",
        "Any exception in scope/authorization/risk returns DENY/BLOCKED; no silent fallback.",
        "noble/kernel.py + noble/scope.py + noble/engine.py except Exception: deny",
        "tests/security/test_tool_poisoning.py, tests/invariants/test_security_invariants.py",
        "replay of error injection shows BLOCKED",
        "audit OPERATOR_COMMAND_REFUSED or INVALID_INPUT",
    ),
    Invariant(
        5,
        "Target content cannot override system policy (prompt injection quarantined)",
        "Untrusted content is sanitized/quarantined via noble/trust.py; control chars stripped; no target code import.",
        "noble/trust.py quarantine() + evidence sanitization",
        "tests/security/test_prompt_injection.py (12 patterns)",
        "replay evidence provenance quarantined=true",
        "audit SECURITY quarantine detection",
    ),
    Invariant(
        6,
        "Tool output cannot directly become trusted evidence without validation",
        "Output must match jsonschema, ID/target/tool/version/size checks; fixture digest re-check; quarantine.",
        "noble/evidence.py + noble/execution.py OutputValidator",
        "tests/security/test_tool_poisoning.py, tests/security/test_boundaries.py",
        "replay findings state candidate vs confirmed; invalid output yields 0 findings",
        "audit INVALID_OUTPUT events",
    ),
    Invariant(
        7,
        "Credentials are not exposed unnecessarily",
        "URLs with credentials rejected; field-aware redaction; no raw stdout in logs; 0700/0600 perms.",
        "noble/trust.py redact + noble/targets.py credential check",
        "tests/security/test_sensitive_paths.py",
        "replay sanitized target canonical without credentials",
        "audit redacted target field",
    ),
    Invariant(
        8,
        "Every security-sensitive execution is auditable",
        "AuditSink emits chained hash events for every decision; store.verify_audit() validates.",
        "noble/audit.py AuditSink + noble/store.py chained audit_events",
        "tests/invariants/test_security_invariants.py, tests/integration/test_lifecycle.py",
        "replay audit_events list per execution",
        "noble audit --verify VALID",
    ),
    Invariant(
        9,
        "Sandbox failure prevents execution rather than weakening isolation",
        "CommandRunner checks resource limits; if unavailable, tool is refused (SandboxFailure).",
        "noble/execution.py CommandRunner + noble/doctor.py _check_sandbox",
        "tests/security/test_process_boundary.py, tests/security/test_sandbox_escape.py",
        "replay blocked with sandbox_unavailable",
        "audit SANDBOX_FAILURE",
    ),
    Invariant(
        10,
        "Web/API cannot bypass CLI controls",
        "Dashboard is read-only; no HTTP API writes; CLI is authoritative.",
        "dashboard/index.html fetch GET only + noble/health.py",
        "tests/integration/test_browser.py (no POST bypass)",
        "replay via CLI only; dashboard shows read-only",
        "audit CLI-only decisions, health dashboard DEGRADED",
    ),
]


def to_json() -> list[dict[str, Any]]:
    return [
        {
            "id": inv.id,
            "title": inv.title,
            "specification": inv.specification,
            "implementation": inv.implementation,
            "test": inv.test,
            "replay_proof": inv.replay_proof,
            "audit_proof": inv.audit_proof,
        }
        for inv in INVARIANTS
    ]
