"""Validated trusted runtime configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from .errors import ConfigurationInvalid

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config/runtime.yaml"


@dataclass(frozen=True, slots=True)
class Limits:
    max_output_bytes: int
    max_input_bytes: int
    max_file_bytes: int
    max_files: int
    max_observations: int
    timeout_seconds: int
    cpu_seconds: int
    memory_mb: int
    global_concurrency: int
    rate_per_minute: int


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    workspace_root: str
    state_directory: str
    network_enabled: bool
    limits: Limits

    @classmethod
    def load(
        cls,
        path: str | Path = CONFIG_PATH,
        *,
        workspace_root: str | Path | None = None,
    ) -> RuntimeConfig:
        root = os.path.realpath(workspace_root or CONFIG_PATH.parent.parent)
        try:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationInvalid("runtime configuration is unreadable or malformed") from exc
        if not isinstance(data, dict) or data.get("version") != 1:
            raise ConfigurationInvalid("runtime configuration must declare version: 1")
        if data.get("network_enabled") is not False:
            raise ConfigurationInvalid("network execution is not supported by the local runtime")
        directory = data.get("state_directory")
        if directory != ".noble":
            raise ConfigurationInvalid("state_directory must be exactly .noble")
        state_path = os.path.realpath(os.path.join(root, directory))
        if os.path.commonpath((root, state_path)) != root:
            raise ConfigurationInvalid("state_directory escapes workspace root")
        raw = data.get("limits")
        if not isinstance(raw, dict):
            raise ConfigurationInvalid("runtime limits are missing")
        keys = (
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
        )
        if any(type(raw.get(key)) is not int or raw[key] <= 0 for key in keys):
            raise ConfigurationInvalid("all runtime limits must be positive integers")
        limits = Limits(**{key: raw[key] for key in keys})
        if (
            limits.max_output_bytes > 1_048_576
            or limits.max_input_bytes > 65_536
            or limits.max_file_bytes > 1_048_576
            or limits.max_files > 1000
            or limits.max_observations > 100
            or limits.timeout_seconds > 60
            or limits.cpu_seconds > limits.timeout_seconds
            or limits.memory_mb > 1024
            or limits.global_concurrency > 8
            or limits.rate_per_minute > 120
        ):
            raise ConfigurationInvalid("runtime limits exceed security ceilings")
        return cls(root, state_path, False, limits)
