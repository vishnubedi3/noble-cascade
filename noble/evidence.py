"""Validated tool outputs and immutable, provenance-rich evidence.

Untrusted tool output is schema-checked, target-bound, source-matched, size
limited, and quarantined before it can support any finding. Only the known
synthetic verifier can produce a CONFIRMED result, and the parent independently
rechecks the immutable fixture and reproduction.
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from .builtins.fixture_sql import EXPECTED_SHA256, verify_fixture
from .builtins.scanner import _is_interpolated
from .config import RuntimeConfig
from .errors import InvalidOutput
from .models import Evidence, ExecutionContext, ToolDefinition, new_id, stable_hash, utcnow
from .trust import DataClassification, TrustLevel, quarantine

_SECRET_VALUE = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|secret|access[_-]?token|authorization)\b"
    r"(\s*[=:]\s*)(['\"]?)([^'\"\s,;]+)(['\"]?)"
)
_TOKEN_SHAPES = re.compile(r"(?i)\b(ghp_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{20,})\b")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}")


def redact_sensitive(text: str) -> str:
    """Redact credential *values*, preserving useful field names and context."""
    cleaned = _SECRET_VALUE.sub(r"\1\2[REDACTED]", text)
    cleaned = _TOKEN_SHAPES.sub("[REDACTED_CREDENTIAL]", cleaned)
    return _BEARER.sub("Bearer [REDACTED]", cleaned)


@dataclass(frozen=True, slots=True)
class ValidatedToolOutput:
    observations: tuple[dict[str, Any], ...]
    complete: bool
    warnings: tuple[str, ...]
    provenance: dict[str, Any]


class OutputValidator:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def validate(
        self,
        raw: str,
        definition: ToolDefinition,
        context: ExecutionContext,
    ) -> ValidatedToolOutput:
        if len(raw.encode("utf-8")) > self.config.limits.max_output_bytes:
            raise InvalidOutput("tool output exceeds configured size limit")

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON key")
                result[key] = value
            return result

        try:
            data = json.loads(
                raw,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")),
                object_pairs_hook=reject_duplicates,
            )
        except (ValueError, TypeError) as exc:
            raise InvalidOutput("tool output is not valid JSON") from exc
        errors = list(Draft7Validator(definition.output_schema).iter_errors(data))
        if errors:
            raise InvalidOutput("tool output violates its declared schema")
        if (
            data["request_id"] != context.request_id
            or data["target"] != context.target.canonical
            or data["tool"] != definition.name
            or data["version"] != definition.version
        ):
            raise InvalidOutput("tool output provenance does not match invocation")
        expected_scanner = (
            "local-ast-sql-v1" if definition.name == "static-code-scan" else "fixture-sql-v1"
        )
        if data["provenance"].get("scanner") != expected_scanner:
            raise InvalidOutput("tool output scanner provenance is not trusted")
        observations = data["observations"]
        if len(observations) > self.config.limits.max_observations:
            raise InvalidOutput("too many tool observations")
        root = Path(context.workspace_root).resolve()
        actual_target = Path(context.target.canonical).resolve()
        for obs in observations:
            relative = Path(obs["file"])
            if relative.is_absolute() or ".." in relative.parts or "\\" in obs["file"]:
                raise InvalidOutput("tool output references an unsafe file")
            file = (root / relative).resolve()
            if os.path.commonpath((str(root), str(file))) != str(root):
                raise InvalidOutput("tool output references a file outside workspace")
            if actual_target.is_file():
                if file != actual_target:
                    raise InvalidOutput("tool output references a different target file")
            elif os.path.commonpath((str(actual_target), str(file))) != str(actual_target):
                raise InvalidOutput("tool output references a file outside target directory")
            try:
                if file.stat().st_size > self.config.limits.max_file_bytes:
                    raise InvalidOutput("tool output references an oversized file")
                lines = file.read_text(encoding="utf-8").splitlines()
                expected = lines[obs["line"] - 1][:300]
            except (IndexError, OSError, UnicodeError) as exc:
                raise InvalidOutput("tool output file or line is unreadable") from exc
            if expected != obs["snippet"]:
                raise InvalidOutput("tool output snippet does not match source line")
            if definition.name == "static-code-scan":
                if obs["verified"] or obs["reproduction"] is not None:
                    raise InvalidOutput("a static scan cannot claim a verified reproduction")
                try:
                    tree = ast.parse("\n".join(lines), filename="validated-source")
                except SyntaxError as exc:
                    raise InvalidOutput("candidate source cannot be parsed independently") from exc
                if not any(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "execute"
                    and node.args
                    and _is_interpolated(node.args[0])
                    and node.lineno == obs["line"]
                    for node in ast.walk(tree)
                ):
                    raise InvalidOutput("candidate does not match an independent SQL AST check")
            elif definition.name == "fixture-sql-verify":
                if not obs["verified"] or not data["complete"]:
                    raise InvalidOutput("fixture verification did not complete")
                if data["provenance"].get("fixture_sha256") != EXPECTED_SHA256:
                    raise InvalidOutput("fixture digest does not match known fixture")
                # Second validation, outside the worker, with a separate SQLite
                # connection. Neither source text nor worker assertions suffice.
                try:
                    checked = verify_fixture(file, root)
                except (OSError, ValueError, UnicodeError) as exc:
                    raise InvalidOutput("independent fixture verification failed") from exc
                actual = obs["reproduction"]
                if (
                    actual is None
                    or checked["source_line"] != obs["line"]
                    or actual["unsafe_rows"] != checked["unsafe_rows"]
                    or actual["parameterized_rows"] != checked["parameterized_rows"]
                    or actual["synthetic"] is not True
                ):
                    raise InvalidOutput("fixture reproduction was not independently confirmed")
        if definition.name == "fixture-sql-verify" and len(observations) != 1:
            raise InvalidOutput("fixture verifier must return exactly one observation")
        return ValidatedToolOutput(
            observations=tuple(observations),
            complete=data["complete"],
            warnings=tuple(data["warnings"]),
            provenance=data["provenance"],
        )


def build_evidence(
    observation: dict[str, Any],
    *,
    context: ExecutionContext,
    definition: ToolDefinition,
    execution_id: str,
    tool_provenance: dict[str, Any],
) -> list[Evidence]:
    """Convert a validated observation into write-once evidence records."""
    source = quarantine(redact_sensitive(observation["snippet"]), max_length=300)
    common = {
        "request_id": context.request_id,
        "execution_id": execution_id,
        "tool": definition.name,
        "tool_version": definition.version,
        "target": context.target.canonical,
    }
    source_evidence = Evidence(
        evidence_id=new_id("ev"),
        category="source-code",
        content=source.sanitized,
        content_hash=stable_hash(source.sanitized),
        trust_level=TrustLevel.TARGET_CONTENT.name,
        recorded_at=utcnow(),
        provenance={
            "source": "target-file",
            "file": redact_sensitive(observation["file"]),
            "line": observation["line"],
            "tool": definition.name,
            "operator": context.operator_id,
            "authorization_grant": context.authorization.grant_id,
            "policy": context.scope.policy_name,
            "tool_version": definition.version,
            "source_sha256": stable_hash(observation["snippet"]),
            "quarantined": source.hostile,
            "data_classification": DataClassification.TARGET.name,
            **tool_provenance,
        },
        **common,
    )
    evidence = [source_evidence]
    if observation["verified"]:
        # These counts are independently recomputed by OutputValidator.
        rep = observation["reproduction"]
        content = f"Synthetic in-memory SQLite: interpolated={rep['unsafe_rows']} rows; parameterized={rep['parameterized_rows']} rows"
        evidence.append(
            Evidence(
                evidence_id=new_id("ev"),
                category="test-result",
                content=content,
                content_hash=stable_hash(content),
                trust_level=TrustLevel.DERIVED_AGENT_DATA.name,
                recorded_at=utcnow(),
                provenance={
                    "source": "known-synthetic-fixture-reproduction",
                    "operator": context.operator_id,
                    "authorization_grant": context.authorization.grant_id,
                    "policy": context.scope.policy_name,
                    "tool_version": definition.version,
                    "independent_validation": True,
                    "data_classification": DataClassification.AGENT_DERIVED.name,
                    **tool_provenance,
                },
                **common,
            )
        )
    return evidence
