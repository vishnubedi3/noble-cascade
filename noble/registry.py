"""Allowlisted local tool registry and boundary schemas.

Only the tools declared here are reachable from ``noble run``. The 34
historical skill entries are *not* automatically registered as executable
capabilities; most are reference runbooks or wrappers without upstream tools.
"""

from __future__ import annotations

from typing import Any

from .config import RuntimeConfig
from .errors import InvalidInput, ToolUnknown
from .models import (
    CapabilityStatus,
    RiskTier,
    SandboxRequirement,
    SideEffectClass,
    TargetKind,
    ToolDefinition,
)

OBSERVATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "title",
        "category",
        "cwe",
        "file",
        "line",
        "snippet",
        "description",
        "impact",
        "remediation",
        "verified",
        "reproduction",
    ],
    "properties": {
        "title": {"type": "string", "minLength": 1, "maxLength": 180},
        "category": {"const": "sql-injection"},
        "cwe": {"const": "CWE-89"},
        "file": {"type": "string", "minLength": 1, "maxLength": 300},
        "line": {"type": "integer", "minimum": 1},
        "snippet": {"type": "string", "maxLength": 300},
        "description": {"type": "string", "minLength": 1, "maxLength": 500},
        "impact": {"type": "string", "minLength": 1, "maxLength": 500},
        "remediation": {"type": "string", "minLength": 1, "maxLength": 500},
        "verified": {"type": "boolean"},
        "reproduction": {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "required": ["unsafe_rows", "parameterized_rows", "synthetic"],
                    "properties": {
                        "unsafe_rows": {"type": "integer", "minimum": 0, "maximum": 10},
                        "parameterized_rows": {"type": "integer", "minimum": 0, "maximum": 10},
                        "synthetic": {"const": True},
                    },
                    "additionalProperties": False,
                },
            ]
        },
    },
    "additionalProperties": False,
}

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "request_id",
        "target",
        "tool",
        "version",
        "observations",
        "complete",
        "warnings",
        "provenance",
    ],
    "properties": {
        "request_id": {"type": "string", "pattern": "^req-[0-9a-f]{32}$"},
        "target": {"type": "string", "minLength": 1, "maxLength": 2048},
        "tool": {"enum": ["static-code-scan", "fixture-sql-verify"]},
        "version": {"const": "1.0.0"},
        "observations": {"type": "array", "maxItems": 100, "items": OBSERVATION_SCHEMA},
        "complete": {"type": "boolean"},
        "warnings": {
            "type": "array",
            "maxItems": 10,
            "items": {"type": "string", "maxLength": 100},
        },
        "provenance": {
            "type": "object",
            "properties": {
                "files_inspected": {"type": "integer", "minimum": 0, "maximum": 1000},
                "fixture_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "scanner": {"type": "string", "maxLength": 80},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "max_files": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
    "additionalProperties": False,
}


class ToolRegistry:
    def __init__(self, config: RuntimeConfig) -> None:
        common: dict[str, Any] = {
            "version": "1.0.0",
            "input_schema": INPUT_SCHEMA,
            "output_schema": OUTPUT_SCHEMA,
            "allowed_target_kinds": (TargetKind.PATH, TargetKind.LOCAL_WORKSPACE),
            "network_required": False,
            "network_destinations": (),
            "sandbox": SandboxRequirement.PROCESS_LOCAL,
            "timeout_seconds": float(config.limits.timeout_seconds),
            "rate_limit_per_minute": min(10, config.limits.rate_per_minute),
            "side_effects": SideEffectClass.READ_LOCAL,
            "evidence_behavior": "bounded source snippet + provenance, no unrestricted stdout",
            "status": CapabilityStatus.FULL_IMPLEMENTATION,
        }
        self._tools: dict[str, ToolDefinition] = {
            "static-code-scan": ToolDefinition(
                name="static-code-scan",
                description="Offline bounded Python AST inspection (SQL execute candidates only)",
                action="static-analysis",
                risk_tier=RiskTier.LOW,
                required_permissions=("scan",),
                requires_approval=False,
                **common,
            ),
            "fixture-sql-verify": ToolDefinition(
                name="fixture-sql-verify",
                description="Controlled reproduction for the unmodified synthetic SQL fixture only",
                action="local-unit-test-verification",
                risk_tier=RiskTier.MEDIUM,
                required_permissions=("verify",),
                requires_approval=False,
                **common,
            ),
        }

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolUnknown("tool is not registered") from exc

    def list(self) -> list[ToolDefinition]:
        return sorted(self._tools.values(), key=lambda tool: tool.name)

    def validate_selection(self, name: str, action: str, target_kind: TargetKind) -> ToolDefinition:
        tool = self.get(name)
        if tool.action != action:
            raise InvalidInput("selected tool does not implement the requested action")
        if target_kind not in tool.allowed_target_kinds:
            raise InvalidInput("selected tool does not support this target type")
        return tool
