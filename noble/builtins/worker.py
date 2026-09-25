"""Isolated child process for trusted built-in read-only tools.

Launched with ``python -I`` and a restricted environment. Never imports
untrusted target files, evaluates target text or accepts arbitrary tool names.
This is process containment, NOT a filesystem/network sandbox.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# -I omits the project directory from sys.path. Only the developer-controlled
# package root is inserted, not any directory supplied in the worker payload.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PROJECT_ROOT))

from noble.builtins.fixture_sql import verify_fixture  # noqa: E402
from noble.builtins.scanner import scan_python  # noqa: E402


def _run(payload: dict[str, Any]) -> dict[str, Any]:
    root = Path(payload["workspace_root"]).resolve(strict=True)
    if root != _PROJECT_ROOT or not root.is_dir():
        raise ValueError("workspace root is not the installed Noble Cascade checkout")
    target = Path(payload["target"]).resolve(strict=True)
    if os.path.commonpath((str(root), str(target))) != str(root):
        raise ValueError("target escapes authorized workspace")
    tool = payload["tool"]
    if tool == "static-code-scan":
        data = scan_python(
            target,
            root,
            max_files=int(payload["max_files"]),
            max_file_bytes=int(payload["max_file_bytes"]),
            max_observations=int(payload["max_observations"]),
        )
    elif tool == "fixture-sql-verify":
        verified = verify_fixture(target, root)
        data = {
            "observations": [
                {
                    "title": "Synthetic SQL injection reproduced in isolated in-memory SQLite",
                    "category": "sql-injection",
                    "cwe": "CWE-89",
                    "file": str(target.relative_to(root)),
                    "line": verified["source_line"],
                    "snippet": verified["source_excerpt"],
                    "description": "Known fixture interpolates a value in SQL; isolated SQLite comparison demonstrates differing results.",
                    "impact": "Synthetic input returned both fixture records rather than no records.",
                    "remediation": "Use parameterized queries instead of interpolating SQL values.",
                    "verified": True,
                    "reproduction": {
                        "unsafe_rows": verified["unsafe_rows"],
                        "parameterized_rows": verified["parameterized_rows"],
                        "synthetic": True,
                    },
                }
            ],
            "complete": True,
            "warnings": [],
            "provenance": {
                "fixture_sha256": verified["fixture_sha256"],
                "scanner": "fixture-sql-v1",
            },
        }
    else:
        raise ValueError("unknown or unregistered worker tool")
    return {
        "request_id": payload["request_id"],
        "target": str(target),
        "tool": tool,
        "version": "1.0.0",
        **data,
    }


def main() -> int:
    try:
        # Limit payload before any parsing: no arbitrary stdin stream.
        raw = sys.stdin.buffer.read(16_385)
        if len(raw) > 16_384:
            raise ValueError("worker payload exceeds input limit")
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("worker payload must be a mapping")
        result = _run(payload)
        sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
        return 0
    except (ValueError, TypeError, KeyError, OSError, SyntaxError, json.JSONDecodeError):
        # Deliberately no paths, target strings, stack traces or credentials on stderr.
        sys.stderr.write("builtin worker refused an invalid or unsafe input\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
