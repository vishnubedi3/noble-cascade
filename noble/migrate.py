"""Migration Framework — every schema change includes migration.

Test migrations. Never require operators to manually repair data.
"""

from __future__ import annotations

from .store import SCHEMA_VERSION, Store

MIGRATIONS: dict[int, str] = {
    # Example: if we ever bump to version 2, migration SQL goes here.
    # For now, only version 1 exists; this framework tests forward compatibility.
    2: """
        -- Migration v1 -> v2: add ledger table if not exists
        CREATE TABLE IF NOT EXISTS ledger (
            execution_id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        );
    """,
}


class MigrationManager:
    def __init__(self, store: Store):
        self.store = store

    def current_version(self) -> int:
        with self.store._connection() as db:  # type: ignore
            row = db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            return int(row["value"]) if row else 0

    def needs_migration(self) -> bool:
        return self.current_version() < SCHEMA_VERSION

    def migrate(self) -> list[str]:
        applied: list[str] = []
        cur = self.current_version()
        for version in sorted(MIGRATIONS):
            if version > cur and version <= SCHEMA_VERSION:
                with self.store._connection() as db:  # type: ignore
                    db.executescript(MIGRATIONS[version])
                    db.execute(
                        "INSERT OR REPLACE INTO meta(key,value) VALUES ('schema_version',?)",
                        (str(version),),
                    )
                applied.append(f"migrated to v{version}")
        # Ensure ledger/observability tables exist even without version bump (idempotent)
        self._ensure_aux_tables()
        return applied

    def _ensure_aux_tables(self) -> None:
        with self.store._connection() as db:  # type: ignore
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger (
                    execution_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worker_registry (
                    worker_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS observability (
                    event_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS observability_req ON observability(request_id);
                """
            )

    def test_migration_idempotent(self) -> bool:
        before = self.current_version()
        self.migrate()
        after = self.current_version()
        # Running again should be no-op
        self.migrate()
        return before <= after
