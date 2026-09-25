"""Disaster Recovery — backup and restore for critical state.

Back up:
    findings, reports, audit logs, configuration, policy, worker metadata

Test restoration. Backups that are never restored are assumptions.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from .store import Store


class BackupManager:
    def __init__(self, store: Store, workspace_root: str | Path):
        self.store = store
        self.root = Path(workspace_root).resolve()

    def create_backup(self, dest: str | Path) -> dict[str, Any]:
        dest = Path(dest).resolve()
        dest.mkdir(parents=True, exist_ok=True)
        # Dump findings
        findings = self.store.list_findings(limit=10000)
        audit = self.store.list_audit(limit=10000)
        # Also dump grants, approvals, results via direct DB copy and JSON export
        data: dict[str, Any] = {
            "findings": findings,
            "audit": audit,
            "results": self.store.list_results(limit=10000),
        }
        # Include config and policy
        try:
            data["config"] = (self.root / "config/runtime.yaml").read_text(encoding="utf-8")
        except Exception:
            data["config"] = None
        try:
            data["policy"] = (
                self.root / "agent-skills/governance/scope-enforcement/scope-policy.yaml"
            ).read_text(encoding="utf-8")
        except Exception:
            data["policy"] = None
        # Worker metadata if ledger exists
        try:
            with self.store._connection() as db:  # type: ignore[attr-defined]
                workers = [dict(r) for r in db.execute("SELECT data FROM worker_registry")]
                data["workers"] = [json.loads(r["data"]) for r in workers]
        except Exception:
            data["workers"] = []

        out_file = dest / "noble_backup.json"
        out_file.write_text(
            json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, default=str),
            encoding="utf-8",
        )
        # Also copy raw DB for full restore
        db_copy = dest / "state.db.backup"
        shutil.copy2(self.store.db_path, db_copy)
        # Hash for integrity
        digest = hashlib.sha256(out_file.read_bytes()).hexdigest()
        (dest / "backup.sha256").write_text(digest + "  noble_backup.json\n", encoding="utf-8")
        return {
            "path": str(out_file),
            "sha256": digest,
            "findings": len(findings),
            "audit": len(audit),
        }

    def verify_backup(self, backup_dir: str | Path) -> tuple[bool, str]:
        backup_dir = Path(backup_dir)
        bf = backup_dir / "noble_backup.json"
        hf = backup_dir / "backup.sha256"
        if not bf.is_file() or not hf.is_file():
            return False, "backup files missing"
        expected = hf.read_text(encoding="utf-8").split()[0]
        actual = hashlib.sha256(bf.read_bytes()).hexdigest()
        if expected != actual:
            return False, f"hash mismatch expected {expected[:12]} got {actual[:12]}"
        # Try to parse
        try:
            data = json.loads(bf.read_text(encoding="utf-8"))
            if "findings" not in data or "audit" not in data:
                return False, "backup schema invalid"
        except Exception as exc:
            return False, f"parse failed: {type(exc).__name__}"
        return True, f"verified {len(data['findings'])} findings, {len(data['audit'])} audit events"

    def restore(
        self, backup_dir: str | Path, target_db: str | Path | None = None
    ) -> dict[str, Any]:
        backup_dir = Path(backup_dir)
        valid, msg = self.verify_backup(backup_dir)
        if not valid:
            raise ValueError(f"backup verification failed: {msg}")
        data = json.loads((backup_dir / "noble_backup.json").read_text(encoding="utf-8"))
        # If target_db provided, restore into new store; otherwise overwrite current
        if target_db is not None:
            target = Path(target_db)
            shutil.copy2(backup_dir / "state.db.backup", target)
            Store(target)
            return {
                "restored_db": str(target),
                "findings": len(data["findings"]),
                "audit": len(data["audit"]),
                "verified": True,
            }
        else:
            # Overwrite current DB
            shutil.copy2(backup_dir / "state.db.backup", self.store.db_path)
            return {
                "restored_db": str(self.store.db_path),
                "findings": len(data["findings"]),
                "audit": len(data["audit"]),
                "verified": True,
            }
