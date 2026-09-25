"""Real Observability — structured events with timeline reconstruction.

Categories:
    REQUEST, POLICY, AUTH, WORKER, TOOL, SANDBOX, EVIDENCE, REPORT, ERROR, SECURITY
Support timeline reconstruction.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from .models import new_id, utcnow


class EventCategory(str, Enum):
    REQUEST = "REQUEST"
    POLICY = "POLICY"
    AUTH = "AUTH"
    WORKER = "WORKER"
    TOOL = "TOOL"
    SANDBOX = "SANDBOX"
    EVIDENCE = "EVIDENCE"
    REPORT = "REPORT"
    ERROR = "ERROR"
    SECURITY = "SECURITY"


@dataclass(slots=True)
class ObservabilityEvent:
    event_id: str
    category: EventCategory
    timestamp: datetime
    request_id: str
    execution_id: str | None
    message: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "category": self.category.value,
            "timestamp": self.timestamp.isoformat(),
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "message": self.message,
            "attributes": self.attributes,
        }


class ObservabilitySink:
    """In-memory + persisted observability sink."""

    def __init__(self, store=None) -> None:
        self.store = store
        self._buffer: list[ObservabilityEvent] = []

    def emit(
        self,
        category: EventCategory,
        request_id: str,
        message: str,
        *,
        execution_id: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> ObservabilityEvent:
        evt = ObservabilityEvent(
            event_id=new_id("obs"),
            category=category,
            timestamp=utcnow(),
            request_id=request_id,
            execution_id=execution_id,
            message=message,
            attributes=attributes or {},
        )
        self._buffer.append(evt)
        if self.store is not None:
            with contextlib.suppress(Exception):
                self.store.put_observability(evt.to_dict())
        return evt

    def timeline(self, request_id: str) -> list[dict[str, Any]]:
        # Prefer persisted if available
        if self.store is not None:
            try:
                events = self.store.list_observability(request_id)
                if events:
                    return sorted(events, key=lambda e: e["timestamp"])
            except Exception:
                pass
        return sorted(
            [e.to_dict() for e in self._buffer if e.request_id == request_id],
            key=lambda e: e["timestamp"],
        )

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        if self.store is not None:
            try:
                return self.store.list_observability_all(limit=limit)
            except Exception:
                pass
        return [e.to_dict() for e in self._buffer[-limit:]]
