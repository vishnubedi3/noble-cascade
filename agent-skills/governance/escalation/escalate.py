#!/usr/bin/env python3
"""Historical alert stub disabled: printing HALT never actually stopped tools.

NobleEngine refuses unsafe actions using typed errors and audit. There is no
external PagerDuty/Slack alert integration; no such capability is claimed.
"""

from __future__ import annotations

import sys


def escalate(incident_type: str, details: dict[str, object]) -> None:
    raise RuntimeError("external escalation is unimplemented; NobleEngine fails closed locally")


if __name__ == "__main__":
    print("UNAVAILABLE: external escalation is not integrated. See 'noble audit'.", file=sys.stderr)
    raise SystemExit(3)
