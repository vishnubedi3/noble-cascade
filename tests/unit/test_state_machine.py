import pytest

from noble.models import ExecutionState
from noble.state_machine import can_transition, is_terminal, validate_transition


@pytest.mark.unit
def test_happy_path_transitions():
    path = [
        ExecutionState.CREATED,
        ExecutionState.VALIDATING,
        ExecutionState.SCOPE_CHECK,
        ExecutionState.AUTHORIZATION_CHECK,
        ExecutionState.RISK_ASSESSMENT,
        ExecutionState.WAITING_FOR_APPROVAL,
        ExecutionState.APPROVED,
        ExecutionState.EXECUTING,
        ExecutionState.COLLECTING_EVIDENCE,
        ExecutionState.VALIDATING_RESULT,
        ExecutionState.COMPLETED,
    ]
    for frm, to in zip(path, path[1:]):
        validate_transition(frm, to)


@pytest.mark.unit
def test_illegal_transition_rejected():
    with pytest.raises(RuntimeError):
        validate_transition(ExecutionState.COMPLETED, ExecutionState.RUNNING)
    with pytest.raises(RuntimeError):
        validate_transition(ExecutionState.COMPLETED, ExecutionState.EXECUTING)
    with pytest.raises(RuntimeError):
        validate_transition(ExecutionState.BLOCKED, ExecutionState.VALIDATING)


@pytest.mark.unit
def test_terminal_is_absorbing():
    for term in (
        ExecutionState.COMPLETED,
        ExecutionState.BLOCKED,
        ExecutionState.FAILED,
        ExecutionState.TIMED_OUT,
        ExecutionState.CANCELLED,
    ):
        assert is_terminal(term)
        assert not can_transition(term, ExecutionState.VALIDATING)
        with pytest.raises(RuntimeError):
            validate_transition(term, ExecutionState.CREATED)


@pytest.mark.unit
def test_error_transitions_allowed_from_any():
    # Any non-terminal can go to FAILED/BLOCKED/TIMED_OUT for fail-closed
    for state in (ExecutionState.VALIDATING, ExecutionState.SCOPE_CHECK, ExecutionState.EXECUTING):
        validate_transition(state, ExecutionState.FAILED)
        validate_transition(state, ExecutionState.BLOCKED)
        validate_transition(state, ExecutionState.TIMED_OUT)
