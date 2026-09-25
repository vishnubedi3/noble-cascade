#!/usr/bin/env python3
"""Legacy in-memory demonstration disabled; it was bypassed across processes.

The operational limiter is ``Store.acquire_lease``: SQLite transaction-based
per-principal/tool/target call rate and global concurrent reservations,
consulted by every NobleEngine tool invocation.
"""

from __future__ import annotations

import sys


if __name__ == "__main__":
    print("UNAVAILABLE: use 'noble scan/validate' for integrated rate limits.", file=sys.stderr)
    raise SystemExit(3)
