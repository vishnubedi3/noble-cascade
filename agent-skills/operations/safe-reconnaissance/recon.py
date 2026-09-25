#!/usr/bin/env python3
"""Legacy file-count recon is disabled; it was never an authorized scan.

The registered ``noble scan`` command performs bounded local AST analysis
only after scope and an exact authorization grant. No network reconnaissance
capability is registered.
"""

from __future__ import annotations

import sys


def run_recon() -> None:
    raise RuntimeError("standalone reconnaissance is not registered; use 'noble scan'")


if __name__ == "__main__":
    print("UNAVAILABLE: no reconnaissance tool is registered. See 'noble tools'.", file=sys.stderr)
    raise SystemExit(3)
