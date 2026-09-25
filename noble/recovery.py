"""Autonomous Recovery — self-recover from certain failures, policy-safe.

Examples:
    unhealthy worker, stalled queue, failed heartbeat

Recovery must remain policy-safe (never bypass scope/auth/approval).
"""

from __future__ import annotations

import time
from typing import Any

from .health import HealthMonitor, HealthStatus
from .store import Store


class RecoveryManager:
    def __init__(self, store: Store, config=None):
        self.store = store
        self.config = config
        self.monitor = HealthMonitor(config=config, store=store)

    def recover_stalled_leases(self, timeout_grace: float = 5.0) -> int:
        """Remove expired leases that should have been cleaned up."""
        now = time.time()
        with self.store._connection() as db:  # type: ignore
            before = db.execute("SELECT count(*) AS n FROM active_leases").fetchone()["n"]
            db.execute("DELETE FROM active_leases WHERE expires_at < ?", (now,))
            after = db.execute("SELECT count(*) AS n FROM active_leases").fetchone()["n"]
        return before - after

    def recover_stale_rate_calls(self) -> int:
        now = time.time()
        with self.store._connection() as db:  # type: ignore
            before = db.execute("SELECT count(*) AS n FROM rate_calls").fetchone()["n"]
            db.execute("DELETE FROM rate_calls WHERE called_at < ?", (now - 60.0,))
            after = db.execute("SELECT count(*) AS n FROM rate_calls").fetchone()["n"]
        return before - after

    def attempt_recovery(self) -> dict[str, Any]:
        checks, overall = self.monitor.check_all()
        actions: list[str] = []
        # Policy-safe recoveries only: clean stale DB state, never relax policy
        if any(c.component == "queue" and c.status != HealthStatus.HEALTHY for c in checks):
            n = self.recover_stalled_leases()
            if n:
                actions.append(f"cleared {n} stalled leases")
            n2 = self.recover_stale_rate_calls()
            if n2:
                actions.append(f"cleared {n2} stale rate calls")
        # Re-check
        checks2, overall2 = self.monitor.check_all()
        return {
            "before": overall.value,
            "after": overall2.value,
            "actions": actions,
            "checks_before": [c.to_dict() for c in checks],
            "checks_after": [c.to_dict() for c in checks2],
            "policy_safe": True,
            "note": "Recovery never relaxes scope/auth/approval/sandbox; only clears expired state",
        }
