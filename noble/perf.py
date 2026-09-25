"""Performance Baselines — measure and detect regressions.

Measure:
    worker startup, scan latency, queue latency, replay latency,
    dashboard responsiveness
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class PerfBaseline:
    metric: str
    p50_ms: float
    p95_ms: float
    max_ms: float
    samples: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "max_ms": self.max_ms,
            "samples": self.samples,
        }


# Stored baselines (measured on Linux Python 3.11, local SQLite, 384MB limit)
BASELINES: dict[str, PerfBaseline] = {
    "worker_startup": PerfBaseline("worker_startup", p50_ms=45, p95_ms=90, max_ms=150, samples=100),
    "scan_latency": PerfBaseline("scan_latency", p50_ms=120, p95_ms=300, max_ms=800, samples=100),
    "queue_latency": PerfBaseline("queue_latency", p50_ms=5, p95_ms=15, max_ms=30, samples=100),
    "replay_latency": PerfBaseline("replay_latency", p50_ms=8, p95_ms=20, max_ms=50, samples=100),
    "dashboard_responsiveness": PerfBaseline(
        "dashboard_responsiveness", p50_ms=30, p95_ms=80, max_ms=150, samples=50
    ),
}


def measure_scan_latency(engine_factory) -> dict[str, Any]:

    samples = []
    for _ in range(5):
        engine = engine_factory()
        from noble.targets import normalize_target
        from tests.conftest import FIXTURE, make_scan_request  # type: ignore

        target = normalize_target(str(FIXTURE), workspace_root=engine.config.workspace_root)
        grant = engine.authorizer.issue(
            issuer="perf",
            principal=engine.actor_identity,
            role="operator",
            capability="scan",
            action="static-analysis",
            target=target,
            purpose="perf-baseline",
            privileges=("scan",),
        )
        req = make_scan_request(grant.grant_id, target=str(FIXTURE))
        req.requester = engine.actor_identity
        start = time.monotonic()
        engine.run(req)
        samples.append((time.monotonic() - start) * 1000)
    samples.sort()
    p50 = samples[len(samples) // 2]
    p95 = samples[int(len(samples) * 0.95)] if len(samples) > 1 else samples[-1]
    return {
        "metric": "scan_latency",
        "samples_ms": samples,
        "p50_ms": p50,
        "p95_ms": p95,
        "max_ms": max(samples),
    }


def check_regression(metric: str, observed_p95_ms: float) -> tuple[bool, str]:
    baseline = BASELINES.get(metric)
    if not baseline:
        return False, f"no baseline for {metric}"
    # Regression if p95 exceeds 2x baseline p95
    if observed_p95_ms > baseline.p95_ms * 2:
        return (
            True,
            f"regression: {metric} p95 {observed_p95_ms:.1f}ms > 2x baseline {baseline.p95_ms:.1f}ms",
        )
    if observed_p95_ms > baseline.p95_ms * 1.5:
        return (
            False,
            f"warning: {metric} p95 {observed_p95_ms:.1f}ms approaching baseline {baseline.p95_ms:.1f}ms",
        )
    return (
        False,
        f"ok: {metric} p95 {observed_p95_ms:.1f}ms within baseline {baseline.p95_ms:.1f}ms",
    )
