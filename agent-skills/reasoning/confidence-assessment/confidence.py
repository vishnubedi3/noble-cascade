#!/usr/bin/env python3
"""Legacy unconditional 100/100 confidence stub disabled.

The real reasoning path in ``noble.reasoning`` ties confidence to validated
source evidence and, for synthetic confirmation, an independent reproduction.
"""

from __future__ import annotations

import sys


def assess_confidence(*args: object, **kwargs: object) -> None:
    raise RuntimeError("standalone confidence score is not evidence-backed; use NobleEngine.run")


if __name__ == "__main__":
    print("UNAVAILABLE: confidence requires validated evidence in NobleEngine.", file=sys.stderr)
    raise SystemExit(3)
