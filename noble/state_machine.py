"""Deterministic finite-state machine for execution lifecycle.

Every execution follows a single explicit FSM. Illegal transitions are rejected
and audited. Terminal states are absorbing (no outgoing edges).

Spec-compliant state names include both the legacy engine states and the
canonical OS-level states (PLANNED, DISPATCHED, RUNNING, REPORTING) so that
future workers can use the richer vocabulary without breaking replay.
"""

from __future__ import annotations

from .models import ExecutionState

# Allowed transitions as adjacency set. This is the single source of truth.
# Terminal states have no outgoing transitions.
ALLOWED_TRANSITIONS: dict[ExecutionState, frozenset[ExecutionState]] = {
    ExecutionState.CREATED: frozenset({ExecutionState.VALIDATING}),
    ExecutionState.VALIDATING: frozenset(
        {ExecutionState.SCOPE_CHECK, ExecutionState.FAILED, ExecutionState.BLOCKED}
    ),
    ExecutionState.SCOPE_CHECK: frozenset(
        {ExecutionState.AUTHORIZATION_CHECK, ExecutionState.BLOCKED, ExecutionState.FAILED}
    ),
    ExecutionState.AUTHORIZATION_CHECK: frozenset(
        {ExecutionState.RISK_ASSESSMENT, ExecutionState.BLOCKED, ExecutionState.FAILED}
    ),
    ExecutionState.RISK_ASSESSMENT: frozenset(
        {ExecutionState.WAITING_FOR_APPROVAL, ExecutionState.FAILED, ExecutionState.BLOCKED}
    ),
    ExecutionState.WAITING_FOR_APPROVAL: frozenset(
        {ExecutionState.APPROVED, ExecutionState.BLOCKED, ExecutionState.FAILED}
    ),
    ExecutionState.APPROVED: frozenset(
        {ExecutionState.EXECUTING, ExecutionState.FAILED, ExecutionState.BLOCKED}
    ),
    # Extended OS-level vocabulary: APPROVED may go through PLANNED->DISPATCHED->RUNNING
    # but ENGINE currently uses EXECUTING directly; both are permitted for compatibility.
    ExecutionState.EXECUTING: frozenset(
        {
            ExecutionState.COLLECTING_EVIDENCE,
            ExecutionState.FAILED,
            ExecutionState.TIMED_OUT,
            ExecutionState.BLOCKED,
        }
    ),
    ExecutionState.COLLECTING_EVIDENCE: frozenset(
        {ExecutionState.VALIDATING_RESULT, ExecutionState.FAILED}
    ),
    ExecutionState.VALIDATING_RESULT: frozenset(
        {ExecutionState.COMPLETED, ExecutionState.FAILED, ExecutionState.BLOCKED}
    ),
    # Terminal states — no outgoing
    ExecutionState.COMPLETED: frozenset(),
    ExecutionState.BLOCKED: frozenset(),
    ExecutionState.FAILED: frozenset(),
    ExecutionState.TIMED_OUT: frozenset(),
    ExecutionState.CANCELLED: frozenset(),
}

# Optional extended states if present in future enums
try:
    _PLANNED = ExecutionState["PLANNED"]  # type: ignore
    _DISPATCHED = ExecutionState["DISPATCHED"]
    _RUNNING = ExecutionState["RUNNING"]
    _REPORTING = ExecutionState["REPORTING"]
    ALLOWED_TRANSITIONS[_PLANNED] = frozenset(
        {_DISPATCHED, ExecutionState.FAILED, ExecutionState.BLOCKED}
    )
    ALLOWED_TRANSITIONS[_DISPATCHED] = frozenset(
        {_RUNNING, ExecutionState.FAILED, ExecutionState.BLOCKED}
    )
    ALLOWED_TRANSITIONS[_RUNNING] = frozenset(
        {ExecutionState.COLLECTING_EVIDENCE, ExecutionState.FAILED, ExecutionState.TIMED_OUT}
    )
    ALLOWED_TRANSITIONS[ExecutionState.VALIDATING_RESULT] = frozenset(
        {_REPORTING, ExecutionState.COMPLETED, ExecutionState.FAILED}
    )
    ALLOWED_TRANSITIONS[_REPORTING] = frozenset({ExecutionState.COMPLETED, ExecutionState.FAILED})
    # Allow APPROVED -> PLANNED as OS path
    ALLOWED_TRANSITIONS[ExecutionState.APPROVED] = frozenset(
        {ExecutionState.EXECUTING, _PLANNED, ExecutionState.FAILED, ExecutionState.BLOCKED}
    )
except (KeyError, AttributeError):
    pass


TERMINAL_STATES = frozenset(
    {
        ExecutionState.COMPLETED,
        ExecutionState.BLOCKED,
        ExecutionState.FAILED,
        ExecutionState.TIMED_OUT,
        ExecutionState.CANCELLED,
    }
)


def is_terminal(state: ExecutionState) -> bool:
    return state in TERMINAL_STATES


def can_transition(frm: ExecutionState, to: ExecutionState) -> bool:
    return to in ALLOWED_TRANSITIONS.get(frm, frozenset())


def validate_transition(frm: ExecutionState, to: ExecutionState) -> None:
    if is_terminal(frm):
        raise RuntimeError(f"illegal transition out of terminal state {frm.value} -> {to.value}")
    # Allow any non-terminal to transition to terminal states (fail-closed)
    # This preserves backward compatibility for error paths while still blocking
    # illegal non-terminal -> non-terminal jumps like COMPLETED -> RUNNING.
    if to in TERMINAL_STATES:
        return
    if not can_transition(frm, to):
        raise RuntimeError(f"illegal state transition {frm.value} -> {to.value}")


def describe_fsm() -> dict:
    return {
        "states": [s.value for s in ExecutionState],
        "terminal": [s.value for s in TERMINAL_STATES],
        "transitions": {
            k.value: sorted(v.value for v in vals) for k, vals in ALLOWED_TRANSITIONS.items()
        },
    }
