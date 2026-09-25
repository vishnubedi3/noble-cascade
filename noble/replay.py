"""Deterministic Replay — reconstruct an execution without re-executing.

Given execution_id, the system reconstructs:
    request, target, policy, worker, tool versions, evidence, findings, report

Replay is READ ONLY — no execution is repeated automatically.
Replay exists to reproduce decisions.
"""

from __future__ import annotations

from typing import Any

from .store import Store


class ReplayEngine:
    def __init__(self, store: Store):
        self.store = store

    def replay(self, execution_id: str) -> dict[str, Any]:
        # Find the execution result that holds this execution_id (lease_id)
        # Search recent results
        for result in self.store.list_results(limit=1000):
            if result.get("execution_id") == execution_id:
                return self._build_replay(result)
        # Also check ledger table if present
        try:
            chain: Any = self.store.get_ledger(execution_id)
            if chain:
                _res = self.store.get_result(chain["request_id"])  # type: ignore[index]
                if _res:
                    return self._build_replay(_res, chain=chain)  # type: ignore[arg-type]
        except Exception:
            pass
        raise ValueError(f"execution_id {execution_id} not found")

    def replay_by_request(self, request_id: str) -> dict[str, Any]:
        result = self.store.get_result(request_id)
        if result is None:
            raise ValueError(f"request_id {request_id} not found")
        return self._build_replay(result)

    def _build_replay(
        self, result: dict[str, Any], chain: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        request_id = result["request_id"]
        evidence = self.store.list_evidence(request_id)
        findings = [self.store.get_finding(fid) for fid in result.get("finding_ids", [])]
        findings = [f for f in findings if f is not None]
        # Reconstruct audit timeline for this request
        all_audit = self.store.list_audit(limit=1000)
        [
            e
            for e in all_audit
            if e.get("request_id") == request_id
            or e.get("request_id") in result.get("audit_event_ids", [])
            or e["request_id"] in result.get("audit_event_ids", [])
        ]
        # Also include audit events whose request_id matches
        # Use broader filter: events with same request_id
        audit_for_request = [e for e in all_audit if e.get("request_id") == request_id]
        # If chain exists, use it for policy hashes
        policy_info = {}
        if chain:
            policy_info = {
                k: chain.get(k)
                for k in (
                    "policy_version",
                    "policy_hash",
                    "configuration_hash",
                    "worker_image_digest",
                    "worker_id",
                    "tool_run_id",
                )
            }
        else:
            # Try to extract from result if present (newer executions)
            for k in (
                "policy_version",
                "policy_hash",
                "configuration_hash",
                "worker_image_digest",
                "worker_id",
                "tool_run_id",
            ):
                if k in result:
                    policy_info[k] = result[k]

        # Determine tool versions from findings provenance
        tool_versions: dict[str, Any] = {}
        for f in findings:  # type: ignore[assignment]
            tool = f.get("provenance", {}).get("tool")  # type: ignore[union-attr]
            ver = f.get("provenance", {}).get("tool_version") or "1.0.0"  # type: ignore[union-attr]
            if tool:
                tool_versions[tool] = ver

        return {
            "request_id": request_id,
            "execution_id": result.get("execution_id"),
            "state": result.get("state"),
            "outcome": result.get("outcome"),
            "target": result.get("target"),
            "action": result.get("action"),
            "tool": result.get("tool"),
            "risk": result.get("risk"),
            "approval": result.get("approval"),
            "state_history": result.get("state_history"),
            "evidence": evidence,
            "findings": findings,
            "audit_events": audit_for_request,
            "policy": policy_info,
            "tool_versions": tool_versions,
            "read_only": True,
            "replay_note": "This replay is read-only; no tool was re-executed. Policy and evidence are reconstructed from persisted state.",
        }
