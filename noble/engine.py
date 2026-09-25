"""Single entry point for policy-governed local execution.

Validation → scope → authorization → risk → approval → tool selection →
preconditions → rate/concurrency → audited execution → validated evidence →
reasoning → persisted findings → final audit/result.

No public path can call a builtin tool without coming through these checks.
"""

from __future__ import annotations

import os
import pwd
import re
import sqlite3
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft7Validator

from .approvals import ApprovalManager
from .audit import AuditSink
from .authorization import Authorizer
from .config import RuntimeConfig
from .errors import (
    ApprovalExpired,
    ApprovalInvalid,
    ApprovalRequired,
    AuthorizationDenied,
    InvalidInput,
    InvalidOutput,
    NetworkDenied,
    NobleError,
    RateLimited,
    SandboxFailure,
    ScopeDenied,
    ScopeUnknown,
    ToolExecutionFailed,
    ToolTimeout,
    ToolUnavailable,
    ToolUnknown,
)
from .evidence import OutputValidator, build_evidence, redact_sensitive
from .execution import CommandRunner
from .models import (
    ApprovalState,
    ExecutionContext,
    ExecutionResult,
    ExecutionState,
    Outcome,
    RiskTier,
    SandboxRequirement,
    SecurityRequest,
    ToolInvocation,
    new_id,
    utcnow,
)
from .network import NetworkPolicy
from .reasoning import evaluate_observation
from .registry import ToolRegistry
from .risk import RiskEngine
from .scope import ScopeEngine
from .store import Store
from .targets import normalize_target
from .trust import quarantine

_ID_RE = re.compile(r"^req-[0-9a-f]{32}$")
_PRINCIPAL_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")


class NobleEngine:
    """All available capabilities flow through one executable control plane."""

    def __init__(
        self,
        config: RuntimeConfig | None = None,
        *,
        store: Store | None = None,
        scope: ScopeEngine | None = None,
        registry: ToolRegistry | None = None,
        runner: CommandRunner | None = None,
        actor_identity: str | None = None,
    ) -> None:
        self.actor_identity = actor_identity or pwd.getpwuid(os.getuid()).pw_name
        self.config = config or RuntimeConfig.load()
        self.store = store or Store(Path(self.config.state_directory) / "state.db")
        self.scope = scope or ScopeEngine.from_file(workspace_root=self.config.workspace_root)
        self.registry = registry or ToolRegistry(self.config)
        self.runner = runner or CommandRunner(self.config)
        self.authorizer = Authorizer(self.store)
        self.approvals = ApprovalManager(self.store)
        self.audit = AuditSink(self.store)
        self.risk = RiskEngine()
        self.output_validator = OutputValidator(self.config)
        self.network = NetworkPolicy(enabled=self.config.network_enabled)

    def run(self, request: SecurityRequest) -> ExecutionResult:
        result = ExecutionResult(
            request_id=request.request_id,
            state=ExecutionState.CREATED,
            outcome=Outcome.INTERNAL_ERROR,
            action=request.action,
            target=request.target,
            tool=request.tool,
        )
        event_ids: list[str] = []
        states: list[str] = [result.state.value]
        lease_id: str | None = None
        risk_tier = "UNKNOWN"
        approval_state = "NOT_REQUIRED"
        canonical_target = (
            redact_sensitive(request.target[:2048])
            if isinstance(request.target, str)
            else "[INVALID_TARGET]"
        )
        request_reserved = False

        def transition(state: ExecutionState) -> None:
            if result.state in {
                ExecutionState.COMPLETED,
                ExecutionState.BLOCKED,
                ExecutionState.FAILED,
                ExecutionState.TIMED_OUT,
                ExecutionState.CANCELLED,
            }:
                raise RuntimeError("execution cannot transition out of a terminal state")
            result.state = state
            states.append(state.value)

        def audit(decision: str, reason: str, *, outcome: str = "pending") -> None:
            event = self.audit.emit(
                request_id=request.request_id,
                operator=request.requester,
                action=request.action,
                target=canonical_target,
                policy=self.scope.name,
                decision=decision,
                risk=risk_tier,
                approval=approval_state,
                tool=request.tool or "none",
                execution=(
                    f"{result.execution_id}:{result.state.value}"
                    if result.execution_id
                    else result.state.value
                ),
                result=outcome,
                reason=reason,
            )
            event_ids.append(event.event_id)

        try:
            transition(ExecutionState.VALIDATING)
            if not _ID_RE.fullmatch(request.request_id):
                raise InvalidInput("request ID has an invalid format")
            if not _PRINCIPAL_RE.fullmatch(request.requester):
                raise InvalidInput("requester identity has an invalid format")
            if request.requester != self.actor_identity:
                raise AuthorizationDenied("requester must match the local OS actor identity")
            if not self.store.reserve_request(request.request_id):
                raise InvalidInput("duplicate request ID is not accepted")
            request_reserved = True
            if not request.action or not request.tool:
                raise InvalidInput("action and registered tool are required")
            if not isinstance(request.parameters, dict):
                raise InvalidInput("tool parameters must be an object")
            # Metadata lookup is safe; no tool is selected or launched here.
            definition = self.registry.get(request.tool)
            if list(Draft7Validator(definition.input_schema).iter_errors(request.parameters)):
                raise InvalidInput("tool parameters violate declared input schema")
            audit("REQUESTED", "request validated")

            transition(ExecutionState.SCOPE_CHECK)
            target = normalize_target(request.target, workspace_root=self.config.workspace_root)
            canonical_target = redact_sensitive(target.canonical)
            if canonical_target != target.canonical:
                raise InvalidInput(
                    "target contains a credential-shaped value; rename or use a safe directory"
                )
            decision = self.scope.evaluate(target, request.action)
            audit(decision.decision.value, decision.reason)
            if not decision.allowed:
                if decision.decision.value == "UNKNOWN":
                    raise ScopeUnknown("target does not match the authorized scope")
                raise ScopeDenied("action or target was denied by scope policy")
            scoped = self.scope.snapshot(target, request.action)

            transition(ExecutionState.AUTHORIZATION_CHECK)
            auth = self.authorizer.check(request, target, definition.required_permissions)
            audit("AUTHORIZED", f"grant {auth.grant_id} permits the required capability")

            transition(ExecutionState.RISK_ASSESSMENT)
            risk = self.risk.assess(request, target)
            if risk.tier.rank < definition.risk_tier.rank:
                risk.tier = definition.risk_tier
                risk.score = max(risk.score, 70 if risk.tier is RiskTier.HIGH else 35)
                risk.rationale += "; raised to registered tool risk floor"
            result.risk = risk
            risk_tier = risk.tier.value
            audit("CLASSIFIED", f"risk tier {risk_tier}")

            transition(ExecutionState.WAITING_FOR_APPROVAL)
            try:
                approval = self.approvals.ensure(request, risk, scoped)
            except ApprovalRequired:
                # Create a request bound to this exact target/action/scope. The
                # current requester cannot approve it through the tool path.
                result.approval = self.approvals.request(request, risk, scoped)
                approval_state = result.approval.state.value
                audit("APPROVAL_PENDING", "awaiting a distinct authorized approver")
                raise
            result.approval = approval
            approval_state = approval.state.value if approval else ApprovalState.NOT_REQUIRED.value
            audit("APPROVAL_CHECKED", "approval satisfied or not required")

            transition(ExecutionState.APPROVED)
            selected = self.registry.validate_selection(request.tool, request.action, target.kind)
            if selected.network_required or request.parameters.get("network"):
                raise NetworkDenied("network-capable execution is unavailable")
            if selected.side_effects.value != "read_local":
                raise SandboxFailure("only read-only local tools can use the process boundary")
            if selected.sandbox is not SandboxRequirement.PROCESS_LOCAL:
                raise SandboxFailure("required isolation backend is not available")
            if selected.name == "fixture-sql-verify":
                # Only the fixed, source-controlled synthetic fixture is eligible.
                from .builtins.fixture_sql import fixture_is_exact

                try:
                    if not fixture_is_exact(
                        Path(target.canonical), Path(self.config.workspace_root)
                    ):
                        raise InvalidInput(
                            "fixture verifier only accepts the unmodified local fixture"
                        )
                except OSError as exc:
                    raise InvalidInput(
                        "fixture verifier requires an existing local fixture"
                    ) from exc
            if not Path(target.canonical).exists():
                raise InvalidInput("local target does not exist")
            audit("PRECONDITIONS_PASSED", "read-only offline tool selected")

            lease_id = new_id("lease")
            self.store.acquire_lease(
                lease_id=lease_id,
                principal=request.requester,
                tool=selected.name,
                target=target.canonical,
                per_minute=selected.rate_limit_per_minute,
                global_per_minute=self.config.limits.rate_per_minute,
                max_concurrent=self.config.limits.global_concurrency,
                timeout=selected.timeout_seconds,
            )
            result.execution_id = lease_id
            transition(ExecutionState.EXECUTING)
            audit("EXECUTING", "rate/concurrency lease acquired", outcome="started")
            context = ExecutionContext(
                request_id=request.request_id,
                operator_id=request.requester,
                target=target,
                scope=scoped,
                authorization=auth,
                approval_state=ApprovalState.APPROVED if approval else ApprovalState.NOT_REQUIRED,
                risk=risk,
                deadline=utcnow() + timedelta(seconds=selected.timeout_seconds),
                sandbox_id="process-local-rlimit",
                network_policy=(),
                credential_policy="no credentials supplied",
                audit_context=event_ids[-1],
                workspace_root=self.config.workspace_root,
                parameters=request.parameters,
            )
            invocation = ToolInvocation(
                invocation_id=lease_id,
                definition=selected,
                context=context,
                parameters=request.parameters,
            )
            command = self.runner.run(invocation)
            transition(ExecutionState.COLLECTING_EVIDENCE)
            audit(
                "TOOL_FINISHED",
                f"trusted worker exited 0 in {command.duration_seconds:.3f}s",
                outcome="completed",
            )
            transition(ExecutionState.VALIDATING_RESULT)
            checked = self.output_validator.validate(command.stdout, selected, context)
            from .models import ValidationResult

            result.validation = ValidationResult(
                valid=checked.complete,
                issues=tuple(
                    quarantine(redact_sensitive(warning)).sanitized for warning in checked.warnings
                ),
            )
            audit("OUTPUT_VALIDATED", "output schema, provenance, source and reproduction checked")

            evidence_ids: list[str] = []
            finding_ids: list[str] = []
            for observation in checked.observations:
                evidence = build_evidence(
                    observation,
                    context=context,
                    definition=selected,
                    execution_id=lease_id,
                    tool_provenance=checked.provenance,
                )
                for item in evidence:
                    self.store.put_evidence(item)
                    evidence_ids.append(item.evidence_id)
                finding = evaluate_observation(
                    observation,
                    evidence,
                    request_id=request.request_id,
                    target=target.canonical,
                    tool=selected.name,
                    version=selected.version,
                    operator=request.requester,
                    grant_id=auth.grant_id,
                )
                self.store.put_finding(finding, request.request_id)
                finding_ids.append(finding.finding_id)
            result.evidence_ids = tuple(evidence_ids)
            result.finding_ids = tuple(finding_ids)
            transition(ExecutionState.COMPLETED)
            result.outcome = (
                Outcome.INCONCLUSIVE
                if not checked.complete
                else Outcome.SUCCESS_WITH_FINDINGS
                if finding_ids
                else Outcome.SUCCESS_NO_FINDINGS
            )
        except NobleError as exc:
            result.error = exc.to_dict()
            result.outcome = _outcome_for_error(exc)
            transition(
                ExecutionState.TIMED_OUT
                if isinstance(exc, ToolTimeout)
                else ExecutionState.BLOCKED
                if isinstance(
                    exc,
                    (
                        ScopeDenied,
                        AuthorizationDenied,
                        ApprovalRequired,
                        ApprovalExpired,
                        ApprovalInvalid,
                        NetworkDenied,
                        RateLimited,
                        InvalidInput,
                        SandboxFailure,
                        ToolUnknown,
                    ),
                )
                else ExecutionState.FAILED
            )
        except (OSError, sqlite3.Error, RuntimeError, ValueError, TypeError) as exc:
            # Unexpected errors must fail closed and cannot leak input values.
            result.error = {
                "code": "internal_error",
                "message": "internal control-plane failure (details suppressed)",
                "retryable": False,
                "details": {"error_type": type(exc).__name__},
            }
            result.outcome = Outcome.INTERNAL_ERROR
            if result.state not in {
                ExecutionState.COMPLETED,
                ExecutionState.BLOCKED,
                ExecutionState.FAILED,
            }:
                transition(ExecutionState.FAILED)
        finally:
            if lease_id is not None:
                try:
                    self.store.release_lease(lease_id)
                except (OSError, sqlite3.Error):
                    # No caller may mistake a tool run with failed cleanup for
                    # an ordinary successful execution. The stale lease
                    # expires after the runner's bounded timeout + grace.
                    if result.state is not ExecutionState.FAILED:
                        states.append(ExecutionState.FAILED.value)
                    result.state = ExecutionState.FAILED
                    result.outcome = Outcome.INTERNAL_ERROR
                    result.error = {
                        "code": "lease_cleanup_failed",
                        "message": "tool lease could not be released",
                        "retryable": False,
                        "details": {},
                    }
            result.target = canonical_target
            result.state_history = tuple(states)
            result.finished_at = utcnow()
            # Audit write must succeed for this execution to be considered
            # complete. If logging fails, fail closed; never launch if the
            # preceding decision audit could not be written.
            try:
                audit(
                    "FINISHED",
                    result.error["code"] if result.error else "execution complete",
                    outcome=result.outcome.value,
                )
                result.audit_event_ids = tuple(event_ids)
                if request_reserved:
                    self.store.put_result(result)
            except (OSError, sqlite3.Error):
                result.state = ExecutionState.FAILED
                result.outcome = Outcome.INTERNAL_ERROR
                result.error = {
                    "code": "audit_failure",
                    "message": "audit/persistence failed",
                    "retryable": False,
                    "details": {},
                }
        return result


def _outcome_for_error(exc: NobleError) -> Outcome:
    if isinstance(exc, ScopeDenied):
        return Outcome.INVALID_SCOPE
    if isinstance(exc, AuthorizationDenied):
        return Outcome.DENIED_AUTHORIZATION
    if isinstance(exc, ApprovalRequired):
        return Outcome.APPROVAL_REQUIRED
    if isinstance(exc, ApprovalExpired):
        return Outcome.APPROVAL_EXPIRED
    if isinstance(exc, ApprovalInvalid):
        return Outcome.APPROVAL_INVALID
    if isinstance(exc, ToolUnknown):
        return Outcome.BLOCKED_POLICY
    if isinstance(exc, ToolUnavailable):
        return Outcome.TOOL_UNAVAILABLE
    if isinstance(exc, ToolExecutionFailed):
        return Outcome.TOOL_FAILED
    if isinstance(exc, ToolTimeout):
        return Outcome.TIMEOUT
    if isinstance(exc, InvalidOutput):
        return Outcome.INVALID_OUTPUT
    if isinstance(exc, InvalidInput):
        return Outcome.INVALID_INPUT
    if isinstance(exc, SandboxFailure):
        return Outcome.SANDBOX_UNAVAILABLE
    if isinstance(exc, NetworkDenied):
        return Outcome.NETWORK_DENIED
    if isinstance(exc, RateLimited):
        return Outcome.RATE_LIMITED
    return Outcome.BLOCKED_POLICY
