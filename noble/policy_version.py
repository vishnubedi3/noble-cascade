"""Cryptographically verifiable policy & configuration versioning.

Every execution records:
    policy_version, policy_hash, configuration_hash, worker_image_digest

Later investigators can determine: which exact policy governed this execution?
Drift becomes detectable by comparing current hashes to stored execution hashes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .scope import ScopeEngine

WORKER_PATH = Path(__file__).resolve().parent / "builtins/worker.py"
POLICY_PATH = (
    Path(__file__).resolve().parent.parent
    / "agent-skills/governance/scope-enforcement/scope-policy.yaml"
)
CONFIG_PATH = Path(__file__).resolve().parent.parent / "config/runtime.yaml"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_json(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def compute_policy_hash(scope: ScopeEngine | None = None, policy_path: Path = POLICY_PATH) -> str:
    try:
        return _sha256_file(policy_path)
    except OSError:
        # Fallback: hash the scope object dump
        if scope is not None:
            dump = {
                "name": scope.name,
                "allowed_domains": scope.allowed_domains,
                "allowed_repositories": scope.allowed_repositories,
                "allowed_ip_ranges": scope.allowed_ip_ranges,
                "allowed_directories": scope.allowed_directories,
                "allowed_actions": scope.allowed_actions,
                "forbidden_targets": scope.forbidden_targets,
                "forbidden_actions": scope.forbidden_actions,
            }
            return _sha256_json(dump)
        return "0" * 64


def compute_config_hash(
    config: RuntimeConfig | None = None, config_path: Path = CONFIG_PATH
) -> str:
    try:
        return _sha256_file(config_path)
    except OSError:
        if config is not None:
            return _sha256_json(
                {
                    "workspace_root": config.workspace_root,
                    "state_directory": config.state_directory,
                    "network_enabled": config.network_enabled,
                    "limits": config.limits.__dict__,
                }
            )
        return "0" * 64


def compute_worker_digest(worker_path: Path = WORKER_PATH) -> str:
    try:
        return _sha256_file(worker_path)
    except OSError:
        return "0" * 64


def get_policy_version(policy_path: Path = POLICY_PATH) -> str:
    try:
        import yaml

        data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
        return str(data.get("version", "unknown"))
    except Exception:
        return "unknown"


def compute_policy_fingerprint(config: RuntimeConfig, scope: ScopeEngine) -> dict[str, str]:
    return {
        "policy_version": get_policy_version(),
        "policy_hash": compute_policy_hash(scope),
        "configuration_hash": compute_config_hash(config),
        "worker_image_digest": compute_worker_digest(),
    }


def detect_drift(stored: dict[str, str], current: dict[str, str]) -> dict[str, dict[str, str]]:
    drift: dict[str, dict[str, str]] = {}
    for key in ("policy_version", "policy_hash", "configuration_hash", "worker_image_digest"):
        if stored.get(key) != current.get(key):
            drift[key] = {"stored": stored.get(key, ""), "current": current.get(key, "")}
    return drift
