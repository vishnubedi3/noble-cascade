#!/usr/bin/env python3
"""Compatibility wrapper around Noble Cascade's *single* scope engine.

This command only inspects policy. It does not confer authorization or launch a
tool. All real execution passes through ``noble.engine.NobleEngine``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from noble.errors import NobleError  # noqa: E402
from noble.scope import ScopeEngine  # noqa: E402


def check_scope(target: str, action: str) -> bool:
    try:
        _, decision = ScopeEngine.from_file(workspace_root=ROOT).normalize_and_evaluate(
            target, action
        )
    except NobleError as exc:
        print(f"[!] Scope check BLOCKED: {exc.code}.")
        return False
    print(
        f"[{'+' if decision.allowed else '!'}] Scope {decision.decision.value}: {decision.reason}."
    )
    return decision.allowed


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: enforce_scope.py TARGET ACTION", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(0 if check_scope(sys.argv[1], sys.argv[2]) else 1)
