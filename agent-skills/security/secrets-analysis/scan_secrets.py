#!/usr/bin/env python3
"""History/workspace secret scanning is UNAVAILABLE in the controlled runtime.

The original Gitleaks version check raised before its unimplemented regex
fallback; rc=0 did not mean the repository was scanned. Do not claim a clean
secret scan until an isolated scanner is installed and integrated.
"""

from __future__ import annotations

import sys


def scan_secrets() -> int:
    print(
        "UNAVAILABLE: no authorized history/workspace secret scanner is registered. See 'noble doctor'.",
        file=sys.stderr,
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(scan_secrets())
