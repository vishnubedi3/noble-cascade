"""Security Metrics — measurable indicators.

Examples:
    blocked_actions, approval_latency, worker_failures, replay_success,
    sandbox_failures, false_positive_rate, verification_coverage,
    policy_drift_events

Exposed in dashboard and via CLI.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .store import Store


@dataclass(slots=True)
class SecurityMetrics:
    total_executions: int = 0
    blocked_actions: int = 0
    successful_with_findings: int = 0
    successful_no_findings: int = 0
    failed: int = 0
    timed_out: int = 0
    approval_required: int = 0
    invalid_inputs: int = 0
    invalid_outputs: int = 0
    sandbox_unavailable: int = 0
    network_denied: int = 0
    rate_limited: int = 0
    worker_failures: int = 0
    sandbox_failures: int = 0
    policy_drift_events: int = 0
    replay_success: int = 0
    replay_failed: int = 0
    verification_coverage: float = 0.0
    false_positive_rate: float = 0.0
    outcome_breakdown: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_executions": self.total_executions,
            "blocked_actions": self.blocked_actions,
            "successful_with_findings": self.successful_with_findings,
            "successful_no_findings": self.successful_no_findings,
            "failed": self.failed,
            "timed_out": self.timed_out,
            "approval_required": self.approval_required,
            "invalid_inputs": self.invalid_inputs,
            "invalid_outputs": self.invalid_outputs,
            "sandbox_unavailable": self.sandbox_unavailable,
            "network_denied": self.network_denied,
            "rate_limited": self.rate_limited,
            "worker_failures": self.worker_failures,
            "sandbox_failures": self.sandbox_failures,
            "policy_drift_events": self.policy_drift_events,
            "replay_success": self.replay_success,
            "replay_failed": self.replay_failed,
            "verification_coverage": self.verification_coverage,
            "false_positive_rate": self.false_positive_rate,
            "outcome_breakdown": self.outcome_breakdown,
        }


def collect_metrics(store: Store) -> SecurityMetrics:
    results = store.list_results(limit=1000)
    m = SecurityMetrics()
    m.total_executions = len(results)
    outcomes = Counter(r.get("outcome") for r in results)
    m.outcome_breakdown = dict(outcomes)  # type: ignore[arg-type]
    m.blocked_actions = sum(1 for r in results if r.get("state") == "BLOCKED")
    m.successful_with_findings = outcomes.get("success_with_findings", 0)
    m.successful_no_findings = outcomes.get("success_no_findings", 0)
    m.failed = outcomes.get("tool_failed", 0) + sum(
        1 for r in results if r.get("state") == "FAILED"
    )
    m.timed_out = outcomes.get("timeout", 0)
    m.approval_required = outcomes.get("approval_required", 0)
    m.invalid_inputs = outcomes.get("invalid_input", 0)
    m.invalid_outputs = outcomes.get("invalid_output", 0)
    m.sandbox_unavailable = outcomes.get("sandbox_unavailable", 0)
    m.network_denied = outcomes.get("network_denied", 0)
    m.rate_limited = outcomes.get("rate_limited", 0)
    # Verification coverage: confirmed vs candidate
    findings = store.list_findings(limit=1000)
    if findings:
        confirmed = sum(1 for f in findings if f.get("state") == "confirmed")
        m.verification_coverage = confirmed / len(findings)
        # False positive rate approximated as candidate/total
        candidates = sum(1 for f in findings if f.get("state") == "candidate")
        m.false_positive_rate = candidates / len(findings) if findings else 0.0
    # Drift events: count audit events with drift decision
    audit = store.list_audit(limit=1000)
    m.policy_drift_events = sum(1 for e in audit if "drift" in e.get("decision", "").lower())
    return m
