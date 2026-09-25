"""Conservative AST-based local code inspection.

This is not Semgrep and does not claim broad SAST coverage. It reads .py files
as *data*, never imports or executes them, and reports candidates only.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any

IGNORED_PARTS = frozenset({".git", ".noble", ".venv", "node_modules", "__pycache__", ".cache"})


def _candidate(path: Path, node: ast.Call, lines: list[str], root: Path) -> dict[str, Any]:
    return {
        "title": "SQL query constructed from an interpolated value",
        "category": "sql-injection",
        "cwe": "CWE-89",
        "file": str(path.relative_to(root)),
        "line": node.lineno,
        "snippet": lines[node.lineno - 1][:300],
        "description": "A SQL execute call receives an interpolated expression; verify data flow manually.",
        "impact": "Input may change query semantics if it reaches this statement.",
        "remediation": "Use parameterized queries rather than string interpolation.",
        "verified": False,
        "reproduction": None,
    }


def _is_interpolated(node: ast.AST) -> bool:
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def scan_python(
    target: Path,
    root: Path,
    *,
    max_files: int,
    max_file_bytes: int,
    max_observations: int,
) -> dict[str, Any]:
    """Inspect a local path, fail inconclusive on skipped/oversized inputs."""
    base = root.resolve(strict=True)
    target = target.resolve(strict=True)
    if os.path.commonpath((str(base), str(target))) != str(base):
        raise ValueError("target escapes authorized workspace")
    if target.is_file():
        paths = [target] if target.suffix == ".py" else []
    elif target.is_dir():
        paths = sorted(target.rglob("*.py"))
    else:
        raise ValueError("target is not a file or directory")
    observations: list[dict[str, Any]] = []
    warnings: list[str] = []
    files_seen = 0
    complete = True
    for path in paths:
        if any(part in IGNORED_PARTS for part in path.relative_to(base).parts):
            continue
        if files_seen >= max_files:
            complete = False
            warnings.append("file limit reached; scan is incomplete")
            break
        files_seen += 1
        if os.path.commonpath((str(base), str(path.resolve()))) != str(base):
            complete = False
            warnings.append("symlink outside authorized root skipped")
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                complete = False
                warnings.append("oversized file skipped")
                continue
            text = path.read_text(encoding="utf-8")
            lines = text.splitlines()
            tree = ast.parse(text, filename=str(path.relative_to(base)))
        except (OSError, UnicodeError, SyntaxError):
            complete = False
            warnings.append("unreadable or unparsable Python file skipped")
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and _is_interpolated(node.args[0])
            ):
                if len(observations) >= max_observations:
                    complete = False
                    warnings.append("observation limit reached; scan is incomplete")
                    break
                observations.append(_candidate(path, node, lines, base))
        if len(observations) >= max_observations:
            break
    return {
        "observations": observations,
        "complete": complete,
        "warnings": warnings[:10],
        "provenance": {"files_inspected": files_seen, "scanner": "local-ast-sql-v1"},
    }
