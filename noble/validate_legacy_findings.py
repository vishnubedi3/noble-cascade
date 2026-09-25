"""Validate legacy findings.json against its Draft-07 schema, without modifying it.

Standalone for the Node compatibility adapter. Legacy data is *not* imported
into the evidence-backed Noble Cascade report store.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator

LEGACY_DIR = (
    Path(__file__).resolve().parent.parent / "agent-skills/reporting/vulnerability-reporting"
)


def validate(path: Path, schema_path: Path = LEGACY_DIR / "report-schema.json") -> int:
    try:
        if not path.is_file() or not schema_path.is_file():
            print(
                "INVALID: schema or findings file is absent; no template will be created",
                file=sys.stderr,
            )
            return 1
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft7Validator.check_schema(schema)
        findings = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(findings, list):
            print("INVALID: findings must be a JSON array", file=sys.stderr)
            return 1
        validator = Draft7Validator(schema)
        errors = [error for finding in findings for error in validator.iter_errors(finding)]
        if errors:
            print(f"INVALID: {len(errors)} schema violations", file=sys.stderr)
            return 1
        print(
            f"Validated {len(findings)} legacy records against Draft-07 schema (not a security scan)"
        )
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(
            f"INVALID: unable to read or parse legacy findings ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(
        validate(Path(sys.argv[1]) if len(sys.argv) > 1 else LEGACY_DIR / "findings.json")
    )
