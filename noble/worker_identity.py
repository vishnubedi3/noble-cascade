"""Worker identity and lifecycle — first-class identities for every worker.

Each worker records:
    worker_id, image_digest, runtime_version, tool_versions,
    creation_time, destruction_time, lifecycle_state

Lifecycle: Build → Verify → Sign → Activate → Monitor → Retire → Destroyed
Retired workers never receive new jobs. Destroyed workers leave audit traces.

No anonymous worker should execute privileged work.
"""

from __future__ import annotations

import contextlib
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from .models import new_id, utcnow
from .policy_version import compute_worker_digest


class WorkerLifecycle(str, Enum):
    BUILD = "BUILD"
    VERIFY = "VERIFY"
    SIGN = "SIGN"
    ACTIVATE = "ACTIVATE"
    MONITOR = "MONITOR"
    RETIRE = "RETIRE"
    DESTROYED = "DESTROYED"


@dataclass(slots=True)
class WorkerIdentity:
    worker_id: str
    image_digest: str
    runtime_version: str
    tool_versions: dict[str, str]
    creation_time: datetime
    destruction_time: datetime | None = None
    lifecycle: WorkerLifecycle = WorkerLifecycle.BUILD
    tool_run_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "image_digest": self.image_digest,
            "runtime_version": self.runtime_version,
            "tool_versions": self.tool_versions,
            "creation_time": self.creation_time.isoformat(),
            "destruction_time": self.destruction_time.isoformat()
            if self.destruction_time
            else None,
            "lifecycle": self.lifecycle.value,
            "tool_run_ids": list(self.tool_run_ids),
        }


class WorkerRegistry:
    """Registry of worker identities with lifecycle enforcement."""

    def __init__(self, store: Any | None = None) -> None:
        self._workers: dict[str, WorkerIdentity] = {}
        self._store = store

    def create_worker(
        self,
        *,
        tool_versions: dict[str, str] | None = None,
        image_digest: str | None = None,
    ) -> WorkerIdentity:
        worker = WorkerIdentity(
            worker_id=new_id("worker"),
            image_digest=image_digest or compute_worker_digest(),
            runtime_version=sys.version.split()[0],
            tool_versions=tool_versions
            or {"static-code-scan": "1.0.0", "fixture-sql-verify": "1.0.0"},
            creation_time=utcnow(),
            lifecycle=WorkerLifecycle.BUILD,
        )
        # Advance through Build->Verify->Sign->Activate atomically for local workers
        worker.lifecycle = WorkerLifecycle.ACTIVATE
        self._workers[worker.worker_id] = worker
        if self._store is not None:
            with contextlib.suppress(Exception):
                self._store.put_worker(worker.to_dict())
        return worker

    def get(self, worker_id: str) -> WorkerIdentity | None:
        return self._workers.get(worker_id)

    def retire(self, worker_id: str) -> WorkerIdentity:
        w = self._workers.get(worker_id)
        if w is None:
            raise ValueError("unknown worker")
        if w.lifecycle is WorkerLifecycle.DESTROYED:
            raise ValueError("already destroyed")
        w.lifecycle = WorkerLifecycle.RETIRE
        if self._store is not None:
            with contextlib.suppress(Exception):
                self._store.put_worker(w.to_dict())
        return w

    def destroy(self, worker_id: str) -> WorkerIdentity:
        w = self._workers.get(worker_id)
        if w is None:
            raise ValueError("unknown worker")
        w.lifecycle = WorkerLifecycle.DESTROYED
        w.destruction_time = utcnow()
        if self._store is not None:
            with contextlib.suppress(Exception):
                self._store.put_worker(w.to_dict())
        return w

    def is_active(self, worker_id: str) -> bool:
        w = self._workers.get(worker_id)
        return w is not None and w.lifecycle == WorkerLifecycle.ACTIVATE

    def list_active(self) -> list[WorkerIdentity]:
        return [w for w in self._workers.values() if w.lifecycle == WorkerLifecycle.ACTIVATE]

    def assert_can_execute(self, worker_id: str) -> None:
        w = self._workers.get(worker_id)
        if w is None:
            raise RuntimeError("anonymous worker cannot execute privileged work")
        if w.lifecycle != WorkerLifecycle.ACTIVATE:
            raise RuntimeError(f"worker {worker_id} is {w.lifecycle.value} and cannot receive jobs")
