"""Continuous Runtime Health — beyond startup verification.

Monitor: worker health, queue health, sandbox health, tool health,
         policy health, database health, dashboard health

Statuses: HEALTHY, DEGRADED, BLOCKED, FAILED
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class HealthCheck:
    component: str
    status: HealthStatus
    message: str
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status.value,
            "message": self.message,
            "details": self.details or {},
        }


class HealthMonitor:
    def __init__(self, config=None, store=None) -> None:
        from .config import RuntimeConfig
        from .store import Store

        self.config = config
        self.store = store

        if self.config is None:
            try:
                self.config = RuntimeConfig.load()
            except Exception:
                self.config = None
        if self.store is None and self.config is not None:
            try:
                self.store = Store(Path(self.config.state_directory) / "state.db")
            except Exception:
                self.store = None

    def check_all(self) -> tuple[list[HealthCheck], HealthStatus]:
        checks: list[HealthCheck] = []
        checks.append(self._check_policy())
        checks.append(self._check_database())
        checks.append(self._check_workers())
        checks.append(self._check_queue())
        checks.append(self._check_sandbox())
        checks.append(self._check_tools())
        checks.append(self._check_dashboard())
        # Overall is worst status
        order = {
            HealthStatus.HEALTHY: 0,
            HealthStatus.DEGRADED: 1,
            HealthStatus.BLOCKED: 2,
            HealthStatus.FAILED: 3,
        }
        worst = max(checks, key=lambda c: order[c.status])
        return checks, worst.status

    def _check_policy(self) -> HealthCheck:
        if self.config is None:
            return HealthCheck("policy", HealthStatus.FAILED, "runtime config unavailable")
        try:
            from .scope import ScopeEngine

            scope = ScopeEngine.from_file(workspace_root=self.config.workspace_root)
            return HealthCheck(
                "policy",
                HealthStatus.HEALTHY,
                f"policy {scope.name} validated",
                {"roots": len(scope.allowed_roots)},
            )
        except Exception as exc:
            return HealthCheck(
                "policy", HealthStatus.FAILED, f"policy invalid: {type(exc).__name__}"
            )

    def _check_database(self) -> HealthCheck:
        if self.store is None:
            return HealthCheck("database", HealthStatus.FAILED, "store unavailable")
        try:
            valid, count = self.store.verify_audit()
            if not valid:
                return HealthCheck(
                    "database", HealthStatus.FAILED, "audit chain invalid", {"events": count}
                )
            # Check permissions
            db_path = Path(self.store.db_path)
            dir_mode = os.stat(db_path.parent).st_mode & 0o777
            db_mode = os.stat(db_path).st_mode & 0o777
            if dir_mode != 0o700 or db_mode != 0o600:
                return HealthCheck(
                    "database",
                    HealthStatus.DEGRADED,
                    f"permissions {dir_mode:o}/{db_mode:o} not 700/600",
                )
            return HealthCheck("database", HealthStatus.HEALTHY, f"{count} audit events verified")
        except Exception as exc:
            return HealthCheck(
                "database", HealthStatus.FAILED, f"database error: {type(exc).__name__}"
            )

    def _check_workers(self) -> HealthCheck:
        if self.config is None:
            return HealthCheck(
                "workers", HealthStatus.DEGRADED, "config unavailable, worker liveness unknown"
            )
        # In local runtime, workers are ephemeral per-execution
        # Check that worker image exists and is readable
        worker_path = Path(self.config.workspace_root) / "noble/builtins/worker.py"
        if not worker_path.is_file():
            return HealthCheck("workers", HealthStatus.FAILED, "worker image missing")
        # Check recent executions for failures
        if self.store is not None:
            try:
                results = self.store.list_results(limit=20)
                failed = sum(1 for r in results if r.get("state") == "FAILED")
                if failed > 5:
                    return HealthCheck(
                        "workers", HealthStatus.DEGRADED, f"{failed}/20 recent executions failed"
                    )
            except Exception:  # nosec B110
                pass
        return HealthCheck(
            "workers", HealthStatus.HEALTHY, "worker image present, no active degradation"
        )

    def _check_queue(self) -> HealthCheck:
        if self.store is None:
            return HealthCheck("queue", HealthStatus.DEGRADED, "store unavailable")
        try:
            with self.store._connection() as db:  # type: ignore
                active = db.execute("SELECT count(*) AS n FROM active_leases").fetchone()["n"]
                rate = db.execute("SELECT count(*) AS n FROM rate_calls").fetchone()["n"]
            if active >= (self.config.limits.global_concurrency if self.config else 2):
                return HealthCheck(
                    "queue", HealthStatus.DEGRADED, f"concurrency saturated: {active} active leases"
                )
            return HealthCheck(
                "queue", HealthStatus.HEALTHY, f"{active} active, {rate} recent calls"
            )
        except Exception as exc:
            return HealthCheck(
                "queue", HealthStatus.FAILED, f"queue check failed: {type(exc).__name__}"
            )

    def _check_sandbox(self) -> HealthCheck:
        # Process-local sandbox is always available if we can set rlimits
        try:
            import resource

            # Try to query limits
            resource.getrlimit(resource.RLIMIT_CPU)
            return HealthCheck("sandbox", HealthStatus.HEALTHY, "process-local rlimits available")
        except Exception:
            return HealthCheck("sandbox", HealthStatus.BLOCKED, "sandbox rlimits unavailable")

    def _check_tools(self) -> HealthCheck:
        if self.config is None:
            return HealthCheck("tools", HealthStatus.FAILED, "config unavailable")
        try:
            from .registry import ToolRegistry

            reg = ToolRegistry(self.config)
            if len(reg.list()) == 0:
                return HealthCheck("tools", HealthStatus.FAILED, "no tools registered")
            return HealthCheck("tools", HealthStatus.HEALTHY, f"{len(reg.list())} tools registered")
        except Exception as exc:
            return HealthCheck(
                "tools", HealthStatus.FAILED, f"tool registry invalid: {type(exc).__name__}"
            )

    def _check_dashboard(self) -> HealthCheck:
        # No browser/API surface in local CLI mode — report as DEGRADED not FAILED
        dashboard_path = Path(self.config.workspace_root) / "dashboard" if self.config else None
        if dashboard_path and dashboard_path.exists():
            return HealthCheck("dashboard", HealthStatus.HEALTHY, "dashboard assets present")
        return HealthCheck(
            "dashboard", HealthStatus.DEGRADED, "no dashboard registered (CLI-only mode)"
        )
