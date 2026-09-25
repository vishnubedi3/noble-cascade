#!/usr/bin/env python3
"""Legacy regex-only output check disabled.

A string scan cannot prove tool-output provenance, schema, request/target match
or evidence integrity. The operational validator is
``noble.evidence.OutputValidator``, invoked only from ``NobleEngine.run``.
"""

from __future__ import annotations

import sys


def validate_output(output_text: str) -> bool:
    raise RuntimeError("standalone output validation is not sufficient; use NobleEngine.run")


if __name__ == "__main__":
    print("UNAVAILABLE: standalone regex validation disabled. Use 'noble validate' for the fixture.", file=sys.stderr)
    raise SystemExit(3)
