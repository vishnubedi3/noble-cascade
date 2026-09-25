#!/usr/bin/env python3
"""IaC misconfiguration scanning is UNAVAILABLE in the controlled runtime.

The original Checkov version probe swallowed a missing dependency and returned
0 without scanning. Network-less, isolated integration is required first.
"""

from __future__ import annotations

import sys


def scan_iac() -> int:
    print(
        "UNAVAILABLE: no authorized Checkov/IaC scanner is registered. See 'noble doctor'.",
        file=sys.stderr,
    )
    return 3


if __name__ == "__main__":
    raise SystemExit(scan_iac())
