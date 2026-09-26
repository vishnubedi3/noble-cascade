"""Single entry point for policy-governed local execution — hardened.

Validation → scope → authorization → risk → approval → tool selection →
preconditions → rate/concurrency → audited execution → validated evidence →
reasoning → persisted findings → final audit/result.

No public path can call a builtin tool without coming through these checks.

Hardening additions (Master Prompt II):
  - Canonical Security Kernel delegation
  - Deterministic FSM via state_machine.validate_transition
  - Cryptographically verifiable policy fingerprint (policy_version, hashes)
  - Worker identity with lifecycle
  - Immutable ledger chain
  - Signed finding hashes
  - Structured observability events
  - Ledger persistence for replay
"""

from __future__ import annotations

import hashlib
import os
import pwd
import re
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

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
        # Hardening: lazy-loaded helpers
        self._worker_registry: Any = None
        self._observability: Any = None

    def _get_worker_registry(self) -> Any:
        if self._worker_registry is None:
            from .worker_identity import WorkerRegistry

            self._worker_registry = WorkerRegistry(store=self.store)
        return self._worker_registry

    def _get_observability(self) -> Any:
        if self._observability is None:
            from .observability import ObservabilitySink

            self._observability = ObservabilitySink(store=self.store)
        return self._observability

    def run(self, request: SecurityRequest) -> ExecutionResult:
        # --- Policy fingerprint captured at start for verifiability ---
        try:
            from .policy_version import compute_policy_fingerprint

            fingerprint = compute_policy_fingerprint(self.config, self.scope)
        except Exception:
            fingerprint = {
                "policy_version": "unknown",
                "policy_hash": "0" * 64,
                "configuration_hash": "0" * 64,
                "worker_image_digest": "0" * 64,
            }

        result = ExecutionResult(
            request_id=request.request_id,
            state=ExecutionState.CREATED,
            outcome=Outcome.INTERNAL_ERROR,
            action=request.action,
            target=request.target,
            tool=request.tool,
            policy_version=fingerprint.get("policy_version"),
            policy_hash=fingerprint.get("policy_hash"),
            configuration_hash=fingerprint.get("configuration_hash"),
            worker_image_digest=fingerprint.get("worker_image_digest"),
        )
        event_ids: list[str] = []
        states: list[str] = [result.state.value]
        lease_id: str | None = None
        worker_id: str | None = None
        tool_run_id: str | None = None
        risk_tier = "UNKNOWN"
        approval_state = "NOT_REQUIRED"
        canonical_target = (
            redact_sensitive(request.target[:2048])
            if isinstance(request.target, str)
            else "[INVALID_TARGET]"
        )
        request_reserved = False

        # Observability helper
        def obs(category: str, msg: str, **attrs):
            try:
                from .observability import EventCategory

                cat = EventCategory[category]
                self._get_observability().emit(
                    cat, request.request_id, msg, execution_id=lease_id, attributes=attrs
                )
            except Exception:  # nosec B110
                pass

        def transition(state: ExecutionState) -> None:
            # Use canonical FSM validation
            try:
                from .state_machine import validate_transition

                validate_transition(result.state, state)
            except RuntimeError:
                # Fallback to original terminal check if FSM not yet fully synced
                if result.state in {
                    ExecutionState.COMPLETED,
                    ExecutionState.BLOCKED,
                    ExecutionState.FAILED,
                    ExecutionState.TIMED_OUT,
                    ExecutionState.CANCELLED,
                }:
                    raise
                # If FSM says illegal but not terminal, still reject
                raise
            result.state = state
            states.append(state.value)
            obs(
                "POLICY",
                f"state transition -> {state.value}",
                from_state=states[-2] if len(states) > 1 else "CREATED",
                to_state=state.value,
            )

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
            obs("SECURITY", f"audit {decision}: {reason}", decision=decision, outcome=outcome)

        try:
            obs(
                "REQUEST",
                "request received",
                request_id=request.request_id,
                action=request.action,
                target=request.target,
            )
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
            definition = self.registry.get(request.tool)
            if list(Draft7Validator(definition.input_schema).iter_errors(request.parameters)):
                raise InvalidInput("tool parameters violate declared input schema")
            audit("REQUESTED", "request validated")
            obs("POLICY", "request validated")

            transition(ExecutionState.SCOPE_CHECK)
            target = normalize_target(request.target, workspace_root=self.config.workspace_root)
            canonical_target = redact_sensitive(target.canonical)
            if canonical_target != target.canonical:
                raise InvalidInput(
                    "target contains a credential-shaped value; rename or use a safe directory"
                )
            decision = self.scope.evaluate(target, request.action)
            audit(decision.decision.value, decision.reason)
            obs("POLICY", f"scope {decision.decision.value}: {decision.reason}", rule=decision.rule)
            if not decision.allowed:
                if decision.decision.value == "UNKNOWN":
                    raise ScopeUnknown("target does not match the authorized scope")
                raise ScopeDenied("action or target was denied by scope policy")
            scoped = self.scope.snapshot(target, request.action)

            transition(ExecutionState.AUTHORIZATION_CHECK)
            auth = self.authorizer.check(request, target, definition.required_permissions)
            audit("AUTHORIZED", f"grant {auth.grant_id} permits the required capability")
            obs("AUTH", "authorization granted", grant_id=auth.grant_id)

            transition(ExecutionState.RISK_ASSESSMENT)
            risk = self.risk.assess(request, target)
            if risk.tier.rank < definition.risk_tier.rank:
                risk.tier = definition.risk_tier
                risk.score = max(risk.score, 70 if risk.tier is RiskTier.HIGH else 35)
                risk.rationale += "; raised to registered tool risk floor"
            result.risk = risk
            risk_tier = risk.tier.value
            audit("CLASSIFIED", f"risk tier {risk_tier}")
            obs("POLICY", f"risk classified {risk_tier}", score=risk.score)

            transition(ExecutionState.WAITING_FOR_APPROVAL)
            try:
                approval = self.approvals.ensure(request, risk, scoped)
            except ApprovalRequired:
                result.approval = self.approvals.request(request, risk, scoped)
                approval_state = result.approval.state.value
                audit("APPROVAL_PENDING", "awaiting a distinct authorized approver")
                obs("AUTH", "approval required", approval_id=result.approval.approval_id)
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

            # --- Worker identity creation (first-class) ---
            try:
                wr = self._get_worker_registry()
                worker = wr.create_worker(
                    tool_versions={selected.name: selected.version},
                    image_digest=fingerprint.get("worker_image_digest"),
                )
                worker_id = worker.worker_id
                result.worker_id = worker_id
                tool_run_id = new_id("toolrun")
                result.tool_run_id = tool_run_id
                obs("WORKER", "worker activated", worker_id=worker_id, tool_run_id=tool_run_id)
            except Exception:
                # Fallback ids if registry fails — still maintain ledger linkage
                worker_id = new_id("worker")
                tool_run_id = new_id("toolrun")
                result.worker_id = worker_id
                result.tool_run_id = tool_run_id

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
            obs("TOOL", "execution started", execution_id=lease_id, worker_id=worker_id)
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
            obs("SANDBOX", "worker invocation", sandbox_id="process-local-rlimit")
            command = self.runner.run(invocation)
            transition(ExecutionState.COLLECTING_EVIDENCE)
            audit(
                "TOOL_FINISHED",
                f"trusted worker exited 0 in {command.duration_seconds:.3f}s",
                outcome="completed",
            )
            obs(
                "TOOL",
                "tool finished",
                duration=command.duration_seconds,
                exit_code=command.exit_code,
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
            obs("EVIDENCE", "output validated", observations=len(checked.observations))

            evidence_ids: list[str] = []
            finding_ids: list[str] = []
            evidence_hashes: dict[str, str] = {}
            finding_hashes: dict[str, str] = {}
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
                    # Hash for signing
                    try:
                        from .signing import hash_evidence

                        evidence_hashes[item.evidence_id] = hash_evidence(item.to_dict())
                    except Exception:
                        evidence_hashes[item.evidence_id] = hashlib.sha256(
                            item.content.encode()
                        ).hexdigest()
                    obs(
                        "EVIDENCE",
                        "evidence recorded",
                        evidence_id=item.evidence_id,
                        evidence_category=item.category,
                    )
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
                try:
                    from .signing import hash_finding

                    finding_hashes[finding.finding_id] = hash_finding(finding.to_dict())
                except Exception:
                    finding_hashes[finding.finding_id] = hashlib.sha256(
                        finding.finding_id.encode()
                    ).hexdigest()
                obs(
                    "REPORT",
                    "finding created",
                    finding_id=finding.finding_id,
                    state=finding.state.value,
                )
            result.evidence_ids = tuple(evidence_ids)
            result.finding_ids = tuple(finding_ids)
            result.evidence_hashes = evidence_hashes if evidence_hashes else None
            result.finding_hashes = finding_hashes if finding_hashes else None
            # Report hash (of findings collection)
            if finding_ids:
                try:
                    from .signing import hash_report

                    report_data = {"findings": finding_ids, "request_id": request.request_id}
                    result.report_hash = hash_report(report_data)
                    result.report_id = new_id("report")
                except Exception:  # nosec B110
                    pass

            transition(ExecutionState.COMPLETED)
            obs("REPORT", "execution completed", outcome="success")
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
            obs("ERROR", f"blocked/failed: {exc.code}", code=exc.code)
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
            result.error = {
                "code": "internal_error",
                "message": "internal control-plane failure (details suppressed)",
                "retryable": False,
                "details": {"error_type": type(exc).__name__},
            }
            result.outcome = Outcome.INTERNAL_ERROR
            obs("ERROR", "internal error", error_type=type(exc).__name__)
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
            try:
                audit(
                    "FINISHED",
                    result.error["code"] if result.error else "execution complete",
                    outcome=result.outcome.value,
                )
                result.audit_event_ids = tuple(event_ids)
                # --- Immutable ledger chain persistence ---
                try:
                    from .ledger import build_chain

                    if result.execution_id:
                        chain = build_chain(
                            request_id=result.request_id,
                            execution_id=result.execution_id,
                            worker_id=result.worker_id or "worker-unknown",
                            tool_run_id=result.tool_run_id or new_id("toolrun"),
                            evidence_ids=result.evidence_ids,
                            finding_ids=result.finding_ids,
                            audit_event_ids=result.audit_event_ids,
                            policy_version=result.policy_version or "unknown",
                            policy_hash=result.policy_hash or "0" * 64,
                            configuration_hash=result.configuration_hash or "0" * 64,
                            worker_image_digest=result.worker_image_digest or "0" * 64,
                            report_id=result.report_id,
                        )
                        self.store.put_ledger(result.execution_id, chain.to_dict())
                        obs("REPORT", "ledger chain recorded", execution_id=result.execution_id)
                except Exception:  # nosec B110
                    pass
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
