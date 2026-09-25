#!/usr/bin/env python3
"""Legacy standalone audit emitter disabled: it could forge a success event.

All operational audit records are emitted by the control plane through the
owner-only SQLite hash-chained ``AuditSink``. Use ``noble audit --verify``.
"""

from __future__ import annotations

import sys


def log_event(*args: object, **kwargs: object) -> None:
    raise RuntimeError("standalone audit logging disabled; use NobleEngine.run")


if __name__ == "__main__":
    print("UNAVAILABLE: standalone event creation disabled; use 'noble audit'.", file=sys.stderr)
    raise SystemExit(3)
