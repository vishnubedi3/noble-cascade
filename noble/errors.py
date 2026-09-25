"""Typed failure model.

Every failure the control plane can produce is a distinct type, so callers can
distinguish *refused to act* from *could not act* from *attempted and failed*.
"""

from __future__ import annotations

from dataclasses import dataclass, field


class ErrorCode:
    POLICY_DENIED = "policy_denied"
    SCOPE_DENIED = "scope_denied"
    SCOPE_UNKNOWN = "scope_unknown"
    AUTHORIZATION_DENIED = "authorization_denied"
    APPROVAL_REQUIRED = "approval_required"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_INVALID = "approval_invalid"
    SELF_APPROVAL = "self_approval"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TOOL_UNKNOWN = "tool_unknown"
    TOOL_EXECUTION_FAILED = "tool_execution_failed"
    TOOL_TIMEOUT = "tool_timeout"
    SANDBOX_FAILURE = "sandbox_failure"
    NETWORK_DENIED = "network_denied"
    RATE_LIMITED = "rate_limited"
    INVALID_INPUT = "invalid_input"
    INVALID_OUTPUT = "invalid_output"
    EVIDENCE_VALIDATION_FAILED = "evidence_validation_failed"
    CONFIGURATION_INVALID = "configuration_invalid"
    INTERNAL_ERROR = "internal_error"


@dataclass(slots=True)
class NobleError(Exception):
    """Base class for every control-plane failure."""

    message: str
    code: str = ErrorCode.INTERNAL_ERROR
    retryable: bool = False
    details: dict[str, str | int | bool] = field(default_factory=dict)

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"[{self.code}] {self.message}"


class PolicyDenied(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.POLICY_DENIED, False, details)


class ScopeDenied(PolicyDenied):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        NobleError.__init__(self, message, ErrorCode.SCOPE_DENIED, False, details)


class ScopeUnknown(ScopeDenied):
    """Fail-closed: no rule matched, therefore deny."""

    def __init__(self, message: str, **details: str | int | bool) -> None:
        NobleError.__init__(self, message, ErrorCode.SCOPE_UNKNOWN, False, details)


class AuthorizationDenied(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.AUTHORIZATION_DENIED, False, details)


class ApprovalRequired(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.APPROVAL_REQUIRED, False, details)


class ApprovalExpired(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.APPROVAL_EXPIRED, True, details)


class ApprovalInvalid(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.APPROVAL_INVALID, False, details)


class SelfApprovalDenied(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.SELF_APPROVAL, False, details)


class ToolUnavailable(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.TOOL_UNAVAILABLE, True, details)


class ToolUnknown(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.TOOL_UNKNOWN, False, details)


class ToolExecutionFailed(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.TOOL_EXECUTION_FAILED, False, details)


class ToolTimeout(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.TOOL_TIMEOUT, True, details)


class SandboxFailure(NobleError):
    """Isolation assumptions could not be established: execution must not proceed."""

    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.SANDBOX_FAILURE, False, details)


class NetworkDenied(PolicyDenied):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        NobleError.__init__(self, message, ErrorCode.NETWORK_DENIED, False, details)


class RateLimited(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.RATE_LIMITED, True, details)


class InvalidInput(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.INVALID_INPUT, False, details)


class InvalidOutput(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.INVALID_OUTPUT, False, details)


class EvidenceValidationFailed(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.EVIDENCE_VALIDATION_FAILED, False, details)


class ConfigurationInvalid(NobleError):
    def __init__(self, message: str, **details: str | int | bool) -> None:
        super().__init__(message, ErrorCode.CONFIGURATION_INVALID, False, details)
