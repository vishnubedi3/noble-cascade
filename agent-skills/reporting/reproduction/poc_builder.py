#!/usr/bin/env python3
"""No placeholder PoC may claim successful verification.

The only operational reproduction is ``noble validate`` on the immutable
synthetic fixture, subject to scope and a separate verification grant.
"""

from __future__ import annotations

import sys


def build_poc(vulnerability_type: str) -> None:
    raise RuntimeError(
        "unrestricted PoC generation is not implemented; use 'noble validate' on the synthetic fixture"
    )


if __name__ == "__main__":
    print(
        "UNAVAILABLE: no general PoC runner is registered. See 'noble validate --help'.",
        file=sys.stderr,
    )
    raise SystemExit(3)
