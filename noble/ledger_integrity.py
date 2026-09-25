"""Long-Term Ledger Integrity — chained hashes, checkpointing, snapshot verification.

- Chained hashes via audit_events prev_hash/event_hash (already in Store)
- Checkpointing: periodic hash of ledger head + audit head
- Snapshot verification: verify snapshot integrity
- Corruption detection: detect broken chain
- Partial recovery: recover valid prefix up to corruption
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _canonical(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()


def compute_ledger_checkpoint(store) -> dict[str, Any]:
    # head hashes
    with store._connection() as db:
        audit_head = db.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        ledger_head = db.execute("SELECT data FROM ledger ORDER BY rowid DESC LIMIT 1").fetchone()
        audit_count = db.execute("SELECT COUNT(*) as c FROM audit_events").fetchone()["c"]
        ledger_count = db.execute("SELECT COUNT(*) as c FROM ledger").fetchone()["c"]
    audit_hash = audit_head["event_hash"] if audit_head else "0" * 64
    ledger_hash = (
        hashlib.sha256(ledger_head["data"].encode()).hexdigest() if ledger_head else "0" * 64
    )
    checkpoint_hash = hashlib.sha256(f"{audit_hash}:{ledger_hash}".encode()).hexdigest()
    return {
        "audit_head": audit_hash,
        "ledger_head": ledger_hash,
        "audit_count": audit_count,
        "ledger_count": ledger_count,
        "checkpoint_hash": checkpoint_hash,
        "createdAt": datetime.now(timezone.utc).isoformat(),
    }


def write_checkpoint(store, path: Path | str | None = None) -> Path:
    p = Path(path) if path else Path(store.db_path).parent / "checkpoint.json"
    # ensure checkpoint table exists (create if missing)
    with store._connection() as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS ledger_checkpoints (
                checkpoint_hash TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
    cp = compute_ledger_checkpoint(store)
    with store._connection() as db:
        db.execute(
            "INSERT OR REPLACE INTO ledger_checkpoints(checkpoint_hash, data, created_at) VALUES (?,?,?)",
            (cp["checkpoint_hash"], json.dumps(cp, sort_keys=True), cp["createdAt"]),
        )
    if p:
        p.write_text(json.dumps(cp, indent=2, sort_keys=True), encoding="utf-8")
    return p


def verify_checkpoint(store, checkpoint_hash: str | None = None) -> tuple[bool, str]:
    current = compute_ledger_checkpoint(store)
    if checkpoint_hash:
        with store._connection() as db:
            row = db.execute(
                "SELECT data FROM ledger_checkpoints WHERE checkpoint_hash=?", (checkpoint_hash,)
            ).fetchone()
            if not row:
                return False, f"checkpoint {checkpoint_hash[:8]} not found"
            stored = json.loads(row["data"])
            if stored["checkpoint_hash"] != checkpoint_hash:
                return False, "stored checkpoint hash mismatch"
            # compare counts? allow current to have grown beyond checkpoint
            if (
                current["audit_count"] < stored["audit_count"]
                or current["ledger_count"] < stored["ledger_count"]
            ):
                return False, "current counts less than checkpoint (possible truncation)"
            return (
                True,
                f"checkpoint {checkpoint_hash[:8]} verified; current {current['checkpoint_hash'][:8]}",
            )
    # verify without specific hash: just check chain integrity
    valid, count = store.verify_audit()
    if not valid:
        return False, f"audit chain INVALID at {count}"
    return (
        True,
        f"ledger integrity VALID audit={current['audit_count']} ledger={current['ledger_count']} checkpoint={current['checkpoint_hash'][:12]}",
    )


def detect_corruption(store) -> dict[str, Any]:
    valid, count = store.verify_audit()
    if valid:
        return {
            "corrupted": False,
            "valid_prefix": count,
            "message": f"no corruption, {count} events valid",
        }
    # find first broken
    with store._connection() as db:
        rows = list(
            db.execute(
                "SELECT sequence, data, prev_hash, event_hash FROM audit_events ORDER BY sequence"
            )
        )
    prev = "0" * 64
    for idx, row in enumerate(rows):
        expected = hashlib.sha256(f"{prev}\n{row['data']}".encode()).hexdigest()
        if prev != row["prev_hash"] or expected != row["event_hash"]:
            return {
                "corrupted": True,
                "first_corrupted_sequence": row["sequence"],
                "valid_prefix": idx,
                "message": f"corruption at sequence {row['sequence']}",
            }
        prev = expected
    return {"corrupted": True, "valid_prefix": count, "message": "unknown corruption"}


def partial_recovery(store, output_path: Path | str | None = None) -> dict[str, Any]:
    info = detect_corruption(store)
    if not info["corrupted"]:
        return {
            "recovered": False,
            "message": "no corruption, no recovery needed",
            "valid_prefix": info["valid_prefix"],
        }
    # recover valid prefix by exporting it
    valid_prefix = info["valid_prefix"]
    with store._connection() as db:
        rows = list(
            db.execute("SELECT data FROM audit_events ORDER BY sequence LIMIT ?", (valid_prefix,))
        )
        ledgers = list(
            db.execute("SELECT data FROM ledger ORDER BY rowid LIMIT ?", (valid_prefix,))
        )
    recovered = {
        "valid_audit_events": [json.loads(r["data"]) for r in rows],
        "valid_ledgers": [json.loads(r["data"]) for r in ledgers],
        "valid_prefix": valid_prefix,
        "recoveredAt": datetime.now(timezone.utc).isoformat(),
    }
    if output_path:
        p = Path(output_path)
        p.write_text(json.dumps(recovered, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "recovered": True,
        "valid_prefix": valid_prefix,
        "message": f"recovered {valid_prefix} events to {output_path}"
        if output_path
        else f"recovered {valid_prefix} events",
    }
