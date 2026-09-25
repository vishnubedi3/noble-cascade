"""SQLite-backed local state with write-once evidence and chained audit events.

The state directory is owner-only. Transactions serialize rate-limit and
concurrency decisions across CLI processes. No raw credentials or unrestricted
tool output are persisted. This protects against accidental tampering, not a
malicious process already running as the same OS account.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .errors import ConfigurationInvalid, RateLimited
from .models import (
    Approval,
    ApprovalState,
    AuditEvent,
    AuthorizationGrant,
    Evidence,
    ExecutionResult,
    Finding,
)

SCHEMA_VERSION = 1


def _json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        directory = self.db_path.parent
        if directory.is_symlink():
            raise ConfigurationInvalid("state directory must not be a symlink")
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if directory.is_symlink() or directory.stat().st_uid != os.getuid():
            raise ConfigurationInvalid("state directory is not owned by this user")
        directory.chmod(0o700)
        if self.db_path.is_symlink():
            raise ConfigurationInvalid("state database must not be a symlink")
        if not self.db_path.exists():
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            try:
                fd = os.open(str(self.db_path), flags, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        info = self.db_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise ConfigurationInvalid("state database is not an owner-owned regular file")
        self.db_path.chmod(0o600)
        self._init_schema()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            yield connection
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self._connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    grant_id TEXT PRIMARY KEY, data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY, data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY, data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS request_reservations (
                    request_id TEXT PRIMARY KEY, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL, data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE, data TEXT NOT NULL,
                    prev_hash TEXT NOT NULL, event_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rate_calls (
                    principal TEXT NOT NULL, tool TEXT NOT NULL, target TEXT NOT NULL,
                    called_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_leases (
                    lease_id TEXT PRIMARY KEY, principal TEXT NOT NULL,
                    tool TEXT NOT NULL, target TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS rate_calls_lookup
                    ON rate_calls(principal, tool, target, called_at);
                """
            )
            version = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if version and int(version["value"]) != SCHEMA_VERSION:
                raise ConfigurationInvalid(f"unsupported state schema version {version['value']}")
            if not version:
                db.execute(
                    "INSERT INTO meta(key,value) VALUES ('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )

    def put_grant(self, grant: AuthorizationGrant) -> None:
        with self._connection() as db:
            db.execute(
                "INSERT INTO grants(grant_id,data) VALUES (?,?)",
                (grant.grant_id, _json(grant.to_dict())),
            )

    def get_grant(self, grant_id: str) -> AuthorizationGrant | None:
        with self._connection() as db:
            row = db.execute("SELECT data FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
        if row is None:
            return None
        raw = json.loads(row["data"])
        raw["valid_from"] = _iso(raw["valid_from"])
        raw["valid_until"] = _iso(raw["valid_until"])
        raw["privileges"] = tuple(raw["privileges"])
        return AuthorizationGrant(**raw)

    def list_grants(self, principal: str | None = None) -> list[AuthorizationGrant]:
        with self._connection() as db:
            ids = [row["grant_id"] for row in db.execute("SELECT grant_id FROM grants")]
        grants = [self.get_grant(i) for i in ids]
        return [
            g for g in grants if g is not None and (principal is None or g.principal == principal)
        ]

    def put_approval(self, approval: Approval) -> None:
        with self._connection() as db:
            db.execute(
                "INSERT INTO approvals(approval_id,data) VALUES (?,?)",
                (approval.approval_id, _json(approval.to_dict())),
            )

    def update_approval(self, approval: Approval, *, expected_state: ApprovalState) -> bool:
        """Atomic compare-and-swap prevents racing approvals and revocations."""
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT data FROM approvals WHERE approval_id=?", (approval.approval_id,)
            ).fetchone()
            if row is None or json.loads(row["data"])["state"] != expected_state.value:
                db.execute("ROLLBACK")
                return False
            db.execute(
                "UPDATE approvals SET data=? WHERE approval_id=?",
                (_json(approval.to_dict()), approval.approval_id),
            )
            db.execute("COMMIT")
        return True

    def get_approval(self, approval_id: str) -> Approval | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT data FROM approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
        if row is None:
            return None
        raw = json.loads(row["data"])
        raw["state"] = ApprovalState(raw["state"])
        raw["requested_at"] = _iso(raw["requested_at"])
        raw["expires_at"] = _iso(raw["expires_at"])
        raw["decided_at"] = _iso(raw["decided_at"]) if raw["decided_at"] else None
        return Approval(**raw)

    def reserve_request(self, request_id: str) -> bool:
        """Atomically reject replay, even when two processes start together.

        Reservations intentionally do not auto-expire: an interrupted request
        might already have launched a tool. Recovery requires a NEW request ID.
        """
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            taken = db.execute(
                "SELECT 1 FROM requests WHERE request_id=? UNION ALL "
                "SELECT 1 FROM request_reservations WHERE request_id=?",
                (request_id, request_id),
            ).fetchone()
            if taken is not None:
                db.execute("ROLLBACK")
                return False
            db.execute(
                "INSERT INTO request_reservations(request_id,created_at) VALUES (?,?)",
                (request_id, time.time()),
            )
            db.execute("COMMIT")
        return True

    def put_result(self, result: ExecutionResult) -> None:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO requests(request_id,data) VALUES (?,?)",
                (result.request_id, _json(result.to_dict())),
            )
            db.execute("DELETE FROM request_reservations WHERE request_id=?", (result.request_id,))
            db.execute("COMMIT")

    def get_result(self, request_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT data FROM requests WHERE request_id=?", (request_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_results(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute("SELECT data FROM requests ORDER BY rowid DESC LIMIT ?", (limit,))
            return [json.loads(row["data"]) for row in rows]

    def put_evidence(self, evidence: Evidence) -> None:
        with self._connection() as db:
            db.execute(
                "INSERT INTO evidence(evidence_id,request_id,execution_id,data) VALUES (?,?,?,?)",
                (
                    evidence.evidence_id,
                    evidence.request_id,
                    evidence.execution_id,
                    _json(evidence.to_dict()),
                ),
            )

    def get_evidence(self, evidence_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT data FROM evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_evidence(self, request_id: str) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute("SELECT data FROM evidence WHERE request_id=?", (request_id,))
            return [json.loads(row["data"]) for row in rows]

    def put_finding(self, finding: Finding, request_id: str) -> None:
        with self._connection() as db:
            db.execute(
                "INSERT INTO findings(finding_id,request_id,data) VALUES (?,?,?)",
                (finding.finding_id, request_id, _json(finding.to_dict())),
            )

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._connection() as db:
            row = db.execute(
                "SELECT data FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_findings(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute("SELECT data FROM findings ORDER BY rowid DESC LIMIT ?", (limit,))
            return [json.loads(row["data"]) for row in rows]

    def append_audit(self, event: AuditEvent) -> str:
        """Append an event to a SHA-256 chain, serialized by the SQLite write lock."""
        data = _json(event.to_dict())
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            last = db.execute(
                "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            prev_hash = last["event_hash"] if last else "0" * 64
            digest = hashlib.sha256(f"{prev_hash}\n{data}".encode()).hexdigest()
            db.execute(
                "INSERT INTO audit_events(event_id,data,prev_hash,event_hash) VALUES (?,?,?,?)",
                (event.event_id, data, prev_hash, digest),
            )
            db.execute("COMMIT")
        return digest

    def list_audit(self, limit: int = 30) -> list[dict[str, Any]]:
        with self._connection() as db:
            rows = db.execute(
                "SELECT data FROM audit_events ORDER BY sequence DESC LIMIT ?", (limit,)
            )
            return [json.loads(row["data"]) for row in rows]

    def verify_audit(self) -> tuple[bool, int]:
        count = 0
        prev = "0" * 64
        with self._connection() as db:
            rows = db.execute(
                "SELECT data,prev_hash,event_hash FROM audit_events ORDER BY sequence"
            )
            for row in rows:
                digest = hashlib.sha256(f"{prev}\n{row['data']}".encode()).hexdigest()
                if prev != row["prev_hash"] or digest != row["event_hash"]:
                    return False, count
                prev = digest
                count += 1
        return True, count

    def acquire_lease(
        self,
        *,
        lease_id: str,
        principal: str,
        tool: str,
        target: str,
        per_minute: int,
        global_per_minute: int,
        max_concurrent: int,
        timeout: float,
        now: float | None = None,
    ) -> None:
        """Reserve rate and concurrency atomically across processes.

        Old reservations expire after timeout+grace. For long-running tools the
        configured timeout is always bounded and the runner kills at timeout.
        """
        timestamp = time.time() if now is None else now
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM rate_calls WHERE called_at < ?", (timestamp - 60.0,))
            db.execute("DELETE FROM active_leases WHERE expires_at < ?", (timestamp,))
            local_count = db.execute(
                "SELECT count(*) AS n FROM rate_calls WHERE principal=? AND tool=? AND target=?",
                (principal, tool, target),
            ).fetchone()["n"]
            global_count = db.execute(
                "SELECT count(*) AS n FROM rate_calls WHERE principal=?", (principal,)
            ).fetchone()["n"]
            active = db.execute("SELECT count(*) AS n FROM active_leases").fetchone()["n"]
            if (
                local_count >= per_minute
                or global_count >= global_per_minute
                or active >= max_concurrent
            ):
                db.execute("ROLLBACK")
                raise RateLimited(
                    "rate or concurrency limit exceeded",
                    tool=tool,
                    limit=per_minute,
                    max_concurrent=max_concurrent,
                )
            db.execute(
                "INSERT INTO rate_calls(principal,tool,target,called_at) VALUES (?,?,?,?)",
                (principal, tool, target, timestamp),
            )
            db.execute(
                "INSERT INTO active_leases(lease_id,principal,tool,target,expires_at) VALUES (?,?,?,?,?)",
                (lease_id, principal, tool, target, timestamp + timeout + 5.0),
            )
            db.execute("COMMIT")

    def release_lease(self, lease_id: str) -> None:
        with self._connection() as db:
            db.execute("DELETE FROM active_leases WHERE lease_id=?", (lease_id,))
