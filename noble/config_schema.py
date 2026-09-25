"""Configuration Integrity — schema, validation, defaults, migration, compatibility.

Every configuration file should have schema, validation, defaults, migration,
compatibility checks. Invalid configuration must fail before execution begins.
"""

from __future__ import annotations

from typing import Any

from jsonschema import Draft7Validator

RUNTIME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["version", "state_directory", "network_enabled", "limits"],
    "properties": {
        "version": {"const": 1},
        "state_directory": {"const": ".noble"},
        "network_enabled": {"const": False},
        "limits": {
            "type": "object",
            "required": [
                "max_output_bytes",
                "max_input_bytes",
                "max_file_bytes",
                "max_files",
                "max_observations",
                "timeout_seconds",
                "cpu_seconds",
                "memory_mb",
                "global_concurrency",
                "rate_per_minute",
            ],
            "properties": {
                "max_output_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
                "max_input_bytes": {"type": "integer", "minimum": 1, "maximum": 65536},
                "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 1048576},
                "max_files": {"type": "integer", "minimum": 1, "maximum": 1000},
                "max_observations": {"type": "integer", "minimum": 1, "maximum": 100},
                "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
                "cpu_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
                "memory_mb": {"type": "integer", "minimum": 1, "maximum": 1024},
                "global_concurrency": {"type": "integer", "minimum": 1, "maximum": 8},
                "rate_per_minute": {"type": "integer", "minimum": 1, "maximum": 120},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

SCOPE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["policy_name", "version", "default_action", "scope"],
    "properties": {
        "policy_name": {"type": "string", "minLength": 1},
        "version": {"type": "string", "minLength": 1},
        "default_action": {"const": "deny"},
        "scope": {
            "type": "object",
            "properties": {
                "allowed_domains": {"type": "array", "items": {"type": "string"}},
                "allowed_repositories": {"type": "array", "items": {"type": "string"}},
                "allowed_ip_ranges": {"type": "array", "items": {"type": "string"}},
                "allowed_directories": {"type": "array", "items": {"type": "string"}},
                "allowed_testing_methods": {"type": "array", "items": {"type": "string"}},
                "forbidden_targets": {"type": "array", "items": {"type": "string"}},
                "forbidden_actions": {"type": "array", "items": {"type": "string"}},
                "approval_required_actions": {"type": "array", "items": {"type": "string"}},
                "rate_limits": {"type": "object"},
                "valid_from": {"type": "string"},
                "valid_until": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": True,
}


def validate_runtime_config(data: dict[str, Any]) -> list[str]:
    errors = list(Draft7Validator(RUNTIME_SCHEMA).iter_errors(data))
    # Additional cross-field check: cpu <= timeout
    if not errors and data["limits"]["cpu_seconds"] > data["limits"]["timeout_seconds"]:
        errors.append(type("E", (), {"message": "cpu_seconds must be <= timeout_seconds"})())
    return [e.message for e in errors]


def validate_scope_policy(data: dict[str, Any]) -> list[str]:
    errors = list(Draft7Validator(SCOPE_SCHEMA).iter_errors(data))
    return [e.message for e in errors]


def migrate_runtime_config(data: dict[str, Any]) -> dict[str, Any]:
    """Apply defaults and migrations. Currently version 1 only; placeholder for future."""
    if data.get("version") is None:
        data["version"] = 1
    return data


def check_compatibility(stored_version: int, current_version: int) -> tuple[bool, str]:
    if stored_version == current_version:
        return True, "compatible"
    if stored_version < current_version:
        return False, f"stored v{stored_version} requires migration to v{current_version}"
    return (
        False,
        f"stored v{stored_version} is newer than runtime v{current_version} — downgrade not supported",
    )
