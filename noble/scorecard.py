"""Security Scorecards — verification coverage, not security scoring.

Score verification coverage:
    policy coverage, test coverage, replay coverage, worker verification coverage
These are engineering metrics.
"""

from __future__ import annotations

from typing import Any

from .store import Store


def policy_coverage(store: Store) -> dict[str, Any]:
    # Count distinct policies exercised in recent executions vs total policies
    # In local mode, one policy file; coverage is whether it was exercised and drift-checked
    from .drift import DriftDetector

    detector = DriftDetector()
    detector.current_fingerprint()
    baseline = detector.load_baseline()
    drift_checked = baseline is not None
    results = store.list_results(limit=1000)
    exercised = len(results) > 0
    return {
        "metric": "policy_coverage",
        "exercised": exercised,
        "drift_baseline": drift_checked,
        "score": (1 if exercised else 0) * 0.5 + (1 if drift_checked else 0) * 0.5,
        "detail": f"policy exercised={exercised}, drift baseline present={drift_checked}",
    }


def replay_coverage(store: Store) -> dict[str, Any]:
    results = store.list_results(limit=1000)
    if not results:
        return {"metric": "replay_coverage", "score": 0, "detail": "no executions to replay"}
    # Try replay for each
    from .replay import ReplayEngine

    engine = ReplayEngine(store)
    success = 0
    for r in results[:20]:
        try:
            rep = engine.replay_by_request(r["request_id"])
            if rep and rep.get("read_only"):
                success += 1
        except Exception:
            pass
    score = success / min(len(results), 20) if results else 0
    return {
        "metric": "replay_coverage",
        "score": score,
        "tested": min(len(results), 20),
        "passed": success,
    }


def worker_verification_coverage(store: Store) -> dict[str, Any]:
    # Check that every execution has worker identity linkage
    results = store.list_results(limit=1000)
    if not results:
        return {"metric": "worker_verification", "score": 0, "detail": "no executions"}
    with_worker = sum(1 for r in results if r.get("worker_id") or r.get("execution_id"))
    score = with_worker / len(results)
    return {
        "metric": "worker_verification",
        "score": score,
        "with_worker": with_worker,
        "total": len(results),
    }


def test_coverage_summary() -> dict[str, Any]:
    # Estimate from pytest counts (static; updated by CI)
    # Attempt to run pytest --collect-only if available
    try:
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = proc.stdout.strip().splitlines()
        # Last line like "71 tests collected"
        total = 0
        for line in lines:
            if "test" in line and "collected" in line:
                import re

                m = re.search(r"(\d+)\s+test", line)
                if m:
                    total = int(m.group(1))
        return {
            "metric": "test_coverage",
            "total_tests": total,
            "score": min(total / 80, 1.0),
            "detail": f"{total} tests collected",
        }
    except Exception:
        return {"metric": "test_coverage", "score": 0, "detail": "could not collect"}


def build_scorecard(store: Store) -> dict[str, Any]:
    pc = policy_coverage(store)
    rc = replay_coverage(store)
    wc = worker_verification_coverage(store)
    tc = test_coverage_summary()
    overall = (pc["score"] + rc["score"] + wc["score"] + tc["score"]) / 4
    return {
        "overall": overall,
        "policy_coverage": pc,
        "replay_coverage": rc,
        "worker_verification": wc,
        "test_coverage": tc,
        "interpretation": "Score verification coverage, not security. Higher means more claims have executable evidence.",
    }
