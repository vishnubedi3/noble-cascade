#!/usr/bin/env python3
"""Deprecated role-only demo. No role string alone authorizes a security action.

Use ``noble authorize`` to create a principal/action/target/purpose/time-bound
grant and ``NobleEngine.run`` to execute. This module intentionally does not
provide a permissive ``AuthorizationManager`` shim.
"""

from __future__ import annotations

import sys


class AuthorizationManager:
    def authorize(self, role: str, capability: str) -> bool:
        print("DENIED: role/capability alone does not prove target-bound authorization", file=sys.stderr)
        return False


if __name__ == "__main__":
    print("UNAVAILABLE: role-only authorization has been disabled. See 'noble authorize --help'.", file=sys.stderr)
    raise SystemExit(3)
