"""Fail-closed, field-aware audit events with a verifiable hash chain."""

from __future__ import annotations

from .evidence import redact_sensitive
from .models import AuditEvent, new_id, utcnow
from .store import Store
from .trust import quarantine


class AuditSink:
    def __init__(self, store: Store) -> None:
        self.store = store

    def emit(
        self,
        *,
        request_id: str,
        operator: str,
        action: str,
        target: str,
        policy: str,
        decision: str,
        risk: str = "UNKNOWN",
        approval: str = "NOT_REQUIRED",
        tool: str = "none",
        execution: str = "none",
        result: str = "pending",
        reason: str = "",
    ) -> AuditEvent:
        # A log is not a dumping ground for raw credentials or tool output.
        # Truncate and sanitize *values*, never field names.
        fields = {
            "operator": operator,
            "action": action,
            "target": target,
            "policy": policy,
            "decision": decision,
            "risk": risk,
            "approval": approval,
            "tool": tool,
            "execution": execution,
            "result": result,
            "reason": reason,
        }
        safe = {
            key: quarantine(redact_sensitive(str(value)[:1024]), max_length=1024).sanitized
            for key, value in fields.items()
        }
        event = AuditEvent(
            event_id=new_id("audit"),
            timestamp=utcnow(),
            request_id=request_id,
            **safe,
        )
        self.store.append_audit(event)  # Propagates errors: NEVER execute without audit.
        return event
