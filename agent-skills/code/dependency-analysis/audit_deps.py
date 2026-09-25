#!/usr/bin/env python3
"""Dependency vulnerability audit is UNAVAILABLE in the controlled runtime.

The old wrapper ran ``pip list`` then swallowed a missing osv-scanner error and
returned 0. Neither ``pip list`` nor a manifest parse is a CVE audit. No
automated dependency finding is claimed until a versioned advisory source and
isolated, authorized scanner are registered.
"""

from __future__ import annotations

import sys


def audit_dependencies() -> int:
    print(
        "UNAVAILABLE: no authorized OSV/CVE audit tool is registered. See 'noble doctor'.",
        file=sys.stderr,
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(audit_dependencies())
