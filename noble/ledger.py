"""Immutable Execution Ledger — complete reconstructable chain.

Every execution becomes a complete chain:
    Request -> Policy -> Authorization -> Approval -> Worker -> Tool -> Evidence -> Finding -> Report -> Audit

Every link receives a unique ID:
    request_id, execution_id, worker_id, tool_run_id, evidence_id, finding_id, report_id

The chain is reconstructable without guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .models import utcnow


@dataclass(slots=True)
class LedgerChain:
    request_id: str
    execution_id: str
    worker_id: str
    tool_run_id: str
    evidence_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    report_id: str | None
    audit_event_ids: tuple[str, ...]
    policy_version: str
    policy_hash: str
    configuration_hash: str
    worker_image_digest: str
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "execution_id": self.execution_id,
            "worker_id": self.worker_id,
            "tool_run_id": self.tool_run_id,
            "evidence_ids": list(self.evidence_ids),
            "finding_ids": list(self.finding_ids),
            "report_id": self.report_id,
            "audit_event_ids": list(self.audit_event_ids),
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "configuration_hash": self.configuration_hash,
            "worker_image_digest": self.worker_image_digest,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LedgerChain:
        from datetime import datetime

        return cls(
            request_id=data["request_id"],
            execution_id=data["execution_id"],
            worker_id=data["worker_id"],
            tool_run_id=data["tool_run_id"],
            evidence_ids=tuple(data.get("evidence_ids", [])),
            finding_ids=tuple(data.get("finding_ids", [])),
            report_id=data.get("report_id"),
            audit_event_ids=tuple(data.get("audit_event_ids", [])),
            policy_version=data.get("policy_version", "unknown"),
            policy_hash=data.get("policy_hash", ""),
            configuration_hash=data.get("configuration_hash", ""),
            worker_image_digest=data.get("worker_image_digest", ""),
            created_at=datetime.fromisoformat(data["created_at"])
            if "created_at" in data
            else utcnow(),
        )


def build_chain(
    *,
    request_id: str,
    execution_id: str,
    worker_id: str,
    tool_run_id: str,
    evidence_ids: tuple[str, ...],
    finding_ids: tuple[str, ...],
    audit_event_ids: tuple[str, ...],
    policy_version: str,
    policy_hash: str,
    configuration_hash: str,
    worker_image_digest: str,
    report_id: str | None = None,
) -> LedgerChain:
    return LedgerChain(
        request_id=request_id,
        execution_id=execution_id,
        worker_id=worker_id,
        tool_run_id=tool_run_id,
        evidence_ids=evidence_ids,
        finding_ids=finding_ids,
        report_id=report_id,
        audit_event_ids=audit_event_ids,
        policy_version=policy_version,
        policy_hash=policy_hash,
        configuration_hash=configuration_hash,
        worker_image_digest=worker_image_digest,
    )
