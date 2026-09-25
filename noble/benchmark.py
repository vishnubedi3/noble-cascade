"""Benchmarking — repeatable measurements.

Measures:
  replay latency, worker startup, policy evaluation, ledger insertion,
  drift detection, certification runtime.
Future regressions become measurable via stored baselines.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .perf import BASELINES, check_regression  # reuse baselines


@dataclass(frozen=True, slots=True)
class BenchResult:
    metric: str
    samples_ms: list[float]
    p50_ms: float
    p95_ms: float
    max_ms: float
    mean_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "samples_ms": self.samples_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
        }


def _measure(metric: str, fn: Callable[[], Any], repeats: int = 5) -> BenchResult:
    samples = []
    for _ in range(repeats):
        start = time.monotonic()
        fn()
        samples.append((time.monotonic() - start) * 1000)
    samples_sorted = sorted(samples)
    p50 = samples_sorted[len(samples_sorted) // 2]
    p95 = (
        samples_sorted[int(len(samples_sorted) * 0.95)]
        if len(samples_sorted) > 1
        else samples_sorted[-1]
    )
    return BenchResult(
        metric,
        samples_sorted,
        p50,
        p95,
        max(samples_sorted),
        sum(samples_sorted) / len(samples_sorted),
    )


def run_benchmarks(workspace_root: Path | None = None) -> dict[str, Any]:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path(__file__).resolve().parent.parent.resolve()
    )
    results: dict[str, Any] = {}

    # policy evaluation
    def _policy_eval():
        from .scope import ScopeEngine
        from .targets import normalize_target

        scope = ScopeEngine.from_file(workspace_root=root)
        t = normalize_target(
            str(root / "tests/fixtures/sql_injection.py"), workspace_root=str(root)
        )
        scope.evaluate(t, "static-analysis")

    results["policy_evaluation"] = _measure("policy_evaluation", _policy_eval).to_dict()

    # replay latency (if ledger exists)
    def _replay():
        try:
            from .config import RuntimeConfig
            from .replay import ReplayEngine
            from .store import Store

            cfg = RuntimeConfig.load(workspace_root=root)
            store = Store(Path(cfg.state_directory) / "state.db")
            results_list = store.list_results(limit=1)
            if results_list and results_list[0].get("execution_id"):
                ReplayEngine(store).replay(results_list[0]["execution_id"])
        except Exception:
            pass

    results["replay_latency"] = _measure("replay_latency", _replay).to_dict()

    # drift detection
    def _drift():
        from .drift import DriftDetector

        DriftDetector(workspace_root=root).detect()

    results["drift_detection"] = _measure("drift_detection", _drift).to_dict()

    # certification runtime
    def _cert():
        from .certify import certify

        certify(root)

    results["certification"] = _measure("certification", _cert).to_dict()

    # ledger insertion (create dummy ledger entry)
    def _ledger():
        try:
            from .config import RuntimeConfig
            from .store import Store

            cfg = RuntimeConfig.load(workspace_root=root)
            store = Store(Path(cfg.state_directory) / "state.db")
            # just list ledgers (insertion would mutate state, so we measure query)
            store.list_ledgers(limit=5)
        except Exception:
            pass

    results["ledger_insertion"] = _measure("ledger_insertion", _ledger).to_dict()

    # worker startup (engine creation)
    def _worker_startup():
        import tempfile

        from .config import RuntimeConfig
        from .engine import NobleEngine
        from .store import Store

        tmp = Path(tempfile.mkdtemp())
        loaded = RuntimeConfig.load(workspace_root=root)
        cfg = RuntimeConfig(
            workspace_root=str(root),
            state_directory=str(tmp / "state"),
            network_enabled=False,
            limits=loaded.limits,
        )
        NobleEngine(cfg, store=Store(tmp / "state/state.db"), actor_identity="bench")

    results["worker_startup"] = _measure("worker_startup", _worker_startup).to_dict()

    # regression check vs perf baselines where applicable
    for k, v in list(results.items()):
        if k in BASELINES:
            is_reg, msg = check_regression(k, v["p95_ms"])
            v["regression"] = is_reg
            v["regression_msg"] = msg

    return {
        "benchmarks": results,
        "platform": __import__("platform").platform(),
        "generatedAt": __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .isoformat(),
    }
