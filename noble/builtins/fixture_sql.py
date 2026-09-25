"""Controlled SQL-injection verification for the *known synthetic fixture only*.

Does not import the fixture or execute target code. The expected SHA256 prevents
an arbitrary repository file from being treated as a validated reproduction.
"""

from __future__ import annotations

import ast
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

FIXTURE_REL_PATH = "tests/fixtures/sql_injection.py"
EXPECTED_SHA256 = "92d5e1dcf2af2be4450259210a150fd9fbf1c623c0d0c6852be3a4bfdadd18ba"  # pragma: allowlist secret (public fixture file digest, not a credential)


def fixture_is_exact(target: Path, workspace_root: Path) -> bool:
    expected = (workspace_root / FIXTURE_REL_PATH).resolve(strict=True)
    if target.resolve(strict=True) != expected:
        return False
    return hashlib.sha256(target.read_bytes()).hexdigest() == EXPECTED_SHA256


def verify_fixture(target: Path, workspace_root: Path) -> dict[str, Any]:
    """Verify AST shape and contrast unsafe/parameterized queries in memory."""
    if not fixture_is_exact(target, workspace_root):
        raise ValueError("target is not the unmodified synthetic SQL fixture")
    lines = target.read_text(encoding="utf-8").splitlines()
    tree = ast.parse("\n".join(lines), filename="synthetic-fixture")
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and node.args
        and isinstance(node.args[0], ast.JoinedStr)
    ]
    if len(matches) != 1:
        raise ValueError("synthetic fixture no longer contains the expected SQL sink")
    source_line = matches[0].lineno
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE users (name TEXT)")
        conn.executemany("INSERT INTO users (name) VALUES (?)", [("alice",), ("bob",)])
        synthetic_input = "x' OR 1=1 --"
        # Same SQL *shape* as the fixture's AST. Never invoke fixture code.
        # Intentionally vulnerable SQL shape on synthetic in-memory data only.
        unsafe = conn.execute(
            f"SELECT name FROM users WHERE name = '{synthetic_input}'"  # noqa: S608  # nosec B608
        ).fetchall()
        safe = conn.execute("SELECT name FROM users WHERE name = ?", (synthetic_input,)).fetchall()
    if len(unsafe) != 2 or len(safe) != 0:
        raise ValueError("isolated SQL reproduction did not establish the expected contrast")
    return {
        "source_line": source_line,
        "source_excerpt": lines[source_line - 1][:300],
        "fixture_sha256": EXPECTED_SHA256,
        "unsafe_rows": len(unsafe),
        "parameterized_rows": len(safe),
        "synthetic": True,
    }
