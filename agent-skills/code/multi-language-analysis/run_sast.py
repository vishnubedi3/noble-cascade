#!/usr/bin/env python3
"""Legacy command adapter: only the registered offline AST scanner is runnable.

The original Semgrep/Bandit fallback silently succeeded without either tool.
This adapter never claims to run Semgrep or Bandit. A grant is mandatory.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="explicit local directory or file")
    parser.add_argument("--grant", required=True, help="exact-target scan authorization grant")
    args = parser.parse_args(argv)
    result = subprocess.run(
        [sys.executable, "-m", "noble", "scan", args.target, "--grant", args.grant],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
