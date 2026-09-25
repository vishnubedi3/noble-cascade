"""Strong runtime models.

Typed boundaries everywhere: nothing policy-relevant travels as a bare dict.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    """128-bit random IDs; not bearer credentials, but collision/guess resistant."""
    return f"{prefix}-{uuid.uuid4().hex}"


def stable_hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


class TargetKind(str, Enum):
    REPOSITORY = "repository"
    HOST = "host"
    URL = "url"
    PATH = "path"
    IP = "ip"
    CIDR = "cidr"
    LOCAL_WORKSPACE = "local-workspace"


class ScopeDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


class ApprovalState(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    REQUIRED = "REQUIRED"
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ExecutionState(str, Enum):
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    SCOPE_CHECK = "SCOPE_CHECK"
    AUTHORIZATION_CHECK = "AUTHORIZATION_CHECK"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    WAITING_FOR_APPROVAL = "WAITING_FOR_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    VALIDATING_RESULT = "VALIDATING_RESULT"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


TERMINAL_STATES = frozenset(
    {
        ExecutionState.COMPLETED,
        ExecutionState.BLOCKED,
        ExecutionState.FAILED,
        ExecutionState.TIMED_OUT,
        ExecutionState.CANCELLED,
    }
)


class Outcome(str, Enum):
    """Distinguishes the eleven ways an execution can end."""

    SUCCESS_WITH_FINDINGS = "success_with_findings"
    SUCCESS_NO_FINDINGS = "success_no_findings"
    BLOCKED_POLICY = "blocked_policy"
    DENIED_AUTHORIZATION = "denied_authorization"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_INVALID = "approval_invalid"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_FAILED = "tool_failed"
    TIMEOUT = "timeout"
    INVALID_SCOPE = "invalid_scope"
    INVALID_OUTPUT = "invalid_output"
    INCONCLUSIVE = "inconclusive"
    RATE_LIMITED = "rate_limited"
    INVALID_INPUT = "invalid_input"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    NETWORK_DENIED = "network_denied"
    INTERNAL_ERROR = "internal_error"


class SideEffectClass(str, Enum):
    NONE = "none"
    READ_LOCAL = "read_local"
    WRITE_WORKSPACE = "write_workspace"
    NETWORK = "network"


class SandboxRequirement(str, Enum):
    NONE = "none"
    PROCESS_LOCAL = "process_local"
    CONTAINER = "container"


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    SUSPECTED = "SUSPECTED"
    SUPPORTED = "SUPPORTED"
    VALIDATED = "VALIDATED"
    CONFIRMED = "CONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class FindingState(str, Enum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted-risk"


class CapabilityStatus(str, Enum):
    """Honest manifest status values (directive section 34)."""

    FULL_IMPLEMENTATION = "FULL_IMPLEMENTATION"
    LOCAL_ADAPTER = "LOCAL_ADAPTER"
    PARTIAL_IMPLEMENTATION = "PARTIAL_IMPLEMENTATION"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    UNAVAILABLE = "UNAVAILABLE"
    EXPERIMENTAL = "EXPERIMENTAL"


@dataclass(slots=True)
class Target:
    """A normalized, canonical execution target."""

    raw: str
    kind: TargetKind
    canonical: str
    host: str | None = None
    port: int | None = None
    path: str | None = None
    owner: str | None = None
    name: str | None = None
    environment: str = "unknown"

    @property
    def id(self) -> str:
        return stable_hash(f"{self.kind.value}:{self.canonical}")[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"kind": self.kind.value}


@dataclass(slots=True)
class Scope:
    """The authorized boundary a request is evaluated against."""

    policy_name: str
    allowed_targets: tuple[str, ...] = ()
    denied_targets: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    denied_actions: tuple[str, ...] = ()
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    target_classes: tuple[str, ...] = ()
    network_destinations: tuple[str, ...] = ()

    def covers(self, target: Target) -> bool:
        return target.canonical in self.allowed_targets


@dataclass(slots=True)
class SecurityRequest:
    """An operator request, the only legitimate entry point to the control plane."""

    action: str
    target: str
    requester: str
    tool: str | None = None
    purpose: str = "security-research"
    parameters: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: new_id("req"))
    created_at: datetime = field(default_factory=utcnow)
    approval_token: str | None = None
    authorization_grant: str | None = None

    def fingerprint(self) -> str:
        """Binding material for approvals: any change invalidates an approval."""
        payload = json.dumps(
            {
                "action": self.action,
                "target": self.target,
                "tool": self.tool,
                "parameters": self.parameters,
            },
            sort_keys=True,
            default=str,
        )
        return stable_hash(payload)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuthorizationGrant:
    """WHO may do WHAT against WHICH target, for WHICH purpose, WHEN."""

    grant_id: str
    principal: str
    role: str
    capability: str
    target_pattern: str
    purpose: str
    privileges: tuple[str, ...]
    valid_from: datetime
    valid_until: datetime
    granted_by: str
    action: str = ""  # Older local grants without an action are deliberately invalid.

    def active_at(self, moment: datetime) -> bool:
        return self.valid_from <= moment <= self.valid_until

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["privileges"] = list(self.privileges)
        data["valid_from"] = self.valid_from.isoformat()
        data["valid_until"] = self.valid_until.isoformat()
        return data


@dataclass(slots=True)
class Authorization:
    grant_id: str
    principal: str
    role: str
    capability: str
    checked_at: datetime = field(default_factory=utcnow)


@dataclass(slots=True)
class RiskAssessment:
    action: str
    tier: RiskTier
    score: int
    factors: dict[str, str | int | bool] = field(default_factory=dict)
    rationale: str = ""
    assessed_at: datetime = field(default_factory=utcnow)

    @property
    def requires_approval(self) -> bool:
        return self.tier.rank >= RiskTier.HIGH.rank

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "tier": self.tier.value,
            "score": self.score,
            "factors": self.factors,
            "rationale": self.rationale,
            "assessed_at": self.assessed_at.isoformat(),
        }


@dataclass(slots=True)
class Approval:
    approval_id: str
    request_fingerprint: str
    action: str
    target: str
    risk_tier: str
    requester: str
    scope_digest: str
    state: ApprovalState
    requested_at: datetime
    expires_at: datetime
    approver: str | None = None
    decided_at: datetime | None = None
    reason: str = ""

    def valid_for(self, request: SecurityRequest, moment: datetime) -> bool:
        if self.state is not ApprovalState.APPROVED:
            return False
        if moment > self.expires_at:
            return False
        return self.request_fingerprint == request.fingerprint()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["requested_at"] = self.requested_at.isoformat()
        data["expires_at"] = self.expires_at.isoformat()
        data["decided_at"] = self.decided_at.isoformat() if self.decided_at else None
        return data


@dataclass(slots=True)
class ToolDefinition:
    """A declared capability. Nothing executes that is not declared here."""

    name: str
    version: str
    description: str
    action: str
    risk_tier: RiskTier
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    required_permissions: tuple[str, ...]
    requires_approval: bool
    allowed_target_kinds: tuple[TargetKind, ...]
    network_required: bool
    network_destinations: tuple[str, ...]
    sandbox: SandboxRequirement
    timeout_seconds: float
    rate_limit_per_minute: int
    side_effects: SideEffectClass
    evidence_behavior: str
    status: CapabilityStatus = CapabilityStatus.FULL_IMPLEMENTATION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("risk_tier", "sandbox", "side_effects", "status"):
            data[key] = getattr(self, key).value
        data["allowed_target_kinds"] = [k.value for k in self.allowed_target_kinds]
        data["required_permissions"] = list(self.required_permissions)
        data["network_destinations"] = list(self.network_destinations)
        return data


@dataclass(slots=True)
class ExecutionContext:
    """The only thing a tool receives. Tools cannot escape it."""

    request_id: str
    operator_id: str
    target: Target
    scope: Scope
    authorization: Authorization
    approval_state: ApprovalState
    risk: RiskAssessment
    deadline: datetime
    sandbox_id: str
    network_policy: tuple[str, ...]
    credential_policy: str
    audit_context: str
    workspace_root: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "operator_id": self.operator_id,
            "target": self.target.to_dict(),
            "scope": self.scope.policy_name,
            "authorization": self.authorization.grant_id,
            "approval_state": self.approval_state.value,
            "risk": self.risk.tier.value,
            "deadline": self.deadline.isoformat(),
            "sandbox_id": self.sandbox_id,
            "network_policy": list(self.network_policy),
            "credential_policy": self.credential_policy,
            "audit_context": self.audit_context,
            "workspace_root": self.workspace_root,
        }


@dataclass(slots=True)
class ToolInvocation:
    """A registry-checked tool call bound to its exact execution context."""

    invocation_id: str
    definition: ToolDefinition
    context: ExecutionContext
    parameters: dict[str, Any]
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invocation_id": self.invocation_id,
            "tool": self.definition.name,
            "tool_version": self.definition.version,
            "request_id": self.context.request_id,
            "target": self.context.target.canonical,
            "created_at": self.created_at.isoformat(),
            "parameter_names": sorted(self.parameters),  # Never serialize raw values.
        }


@dataclass(slots=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    truncated: bool
    timed_out: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"argv": list(self.argv)}


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    request_id: str
    execution_id: str
    tool: str
    tool_version: str
    target: str
    category: str
    content: str
    content_hash: str
    trust_level: str
    recorded_at: datetime
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recorded_at"] = self.recorded_at.isoformat()
        return data


@dataclass(slots=True)
class ValidationResult:
    valid: bool
    issues: tuple[str, ...] = ()
    checked_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "issues": list(self.issues)}


@dataclass(slots=True)
class SeverityAssessment:
    vector: str
    tier: RiskTier
    impact: int
    exploitability: int
    exposure: int
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"tier": self.tier.value}


@dataclass(slots=True)
class ConfidenceAssessment:
    score: int
    level: str
    evidence_count: int
    contradictions: int
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FalsePositiveAnalysis:
    claim: str
    supporting: tuple[str, ...]
    missing: tuple[str, ...]
    benign_explanations: tuple[str, ...]
    contradictory: tuple[str, ...]
    validation_steps: tuple[str, ...]
    verdict: EvidenceStatus
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "supporting": list(self.supporting),
            "missing": list(self.missing),
            "benign_explanations": list(self.benign_explanations),
            "contradictory": list(self.contradictory),
            "validation_steps": list(self.validation_steps),
            "verdict": self.verdict.value,
            "notes": self.notes,
        }


@dataclass(slots=True)
class Reproduction:
    steps: tuple[str, ...]
    non_destructive: bool
    controlled: bool
    result: str
    execution_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"steps": list(self.steps)}


@dataclass(slots=True)
class Finding:
    finding_id: str
    title: str
    category: str
    target: str
    description: str
    evidence_ids: tuple[str, ...]
    confidence: ConfidenceAssessment
    severity: SeverityAssessment
    impact: str
    affected_component: str
    reproduction: Reproduction | None
    remediation: str
    references: tuple[str, ...]
    state: FindingState
    status: EvidenceStatus
    provenance: dict[str, Any]
    cwe: str | None = None
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["evidence_ids"] = list(self.evidence_ids)
        data["references"] = list(self.references)
        data["confidence"] = self.confidence.to_dict()
        data["severity"] = self.severity.to_dict()
        data["reproduction"] = self.reproduction.to_dict() if self.reproduction else None
        return data


@dataclass(slots=True)
class AuditEvent:
    event_id: str
    timestamp: datetime
    request_id: str
    operator: str
    action: str
    target: str
    policy: str
    decision: str
    risk: str
    approval: str
    tool: str
    execution: str
    result: str
    reason: str
    data_classification: str = "AGENT_DERIVED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(slots=True)
class PolicyDecision:
    decision: ScopeDecision
    rule: str
    reason: str
    evaluated_at: datetime = field(default_factory=utcnow)

    @property
    def allowed(self) -> bool:
        return self.decision is ScopeDecision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "rule": self.rule,
            "reason": self.reason,
        }


@dataclass(slots=True)
class ExecutionResult:
    request_id: str
    state: ExecutionState
    outcome: Outcome
    target: str
    action: str
    tool: str | None
    execution_id: str | None = None
    evidence_ids: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    audit_event_ids: tuple[str, ...] = ()
    state_history: tuple[str, ...] = (ExecutionState.CREATED.value,)
    error: dict[str, Any] | None = None
    validation: ValidationResult | None = None
    risk: RiskAssessment | None = None
    approval: Approval | None = None
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None

    @property
    def succeeded(self) -> bool:
        return self.state is ExecutionState.COMPLETED and self.outcome in (
            Outcome.SUCCESS_WITH_FINDINGS,
            Outcome.SUCCESS_NO_FINDINGS,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "state": self.state.value,
            "outcome": self.outcome.value,
            "target": self.target,
            "action": self.action,
            "tool": self.tool,
            "execution_id": self.execution_id,
            "evidence_ids": list(self.evidence_ids),
            "finding_ids": list(self.finding_ids),
            "audit_event_ids": list(self.audit_event_ids),
            "state_history": list(self.state_history),
            "error": self.error,
            "validation": self.validation.to_dict() if self.validation else None,
            "risk": self.risk.to_dict() if self.risk else None,
            "approval": self.approval.to_dict() if self.approval else None,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
