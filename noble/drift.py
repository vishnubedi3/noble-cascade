"""Security Drift Detection — detect unexpected change.

Examples:
    worker image changed
    tool version changed
    policy changed
    dependency changed
    configuration changed

Generates explicit drift reports.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from pathlib import Path
from typing import Any

from .policy_version import (
    compute_config_hash,
    compute_policy_hash,
    compute_worker_digest,
    get_policy_version,
)


class DriftDetector:
    def __init__(self, workspace_root: str | Path | None = None):
        root = Path(workspace_root or Path(__file__).resolve().parent.parent).resolve()
        self.root = root
        self.baseline_path = root / ".noble/drift_baseline.json"

    def current_fingerprint(self) -> dict[str, str]:
        from .config import RuntimeConfig

        config_hash = ""
        policy_hash = ""
        worker_digest = compute_worker_digest()
        policy_version = get_policy_version()
        with contextlib.suppress(Exception):
            config_hash = compute_config_hash()
        with contextlib.suppress(Exception):
            policy_hash = compute_policy_hash()
        # Dependencies hash — hash of requirements.lock
        dep_hash = ""
        try:
            dep_hash = hashlib.sha256((self.root / "requirements.lock").read_bytes()).hexdigest()
        except Exception:
            dep_hash = "unknown"
        # Tool versions
        tool_versions = ""
        try:
            from .config import RuntimeConfig

            cfg = RuntimeConfig.load(workspace_root=self.root)
            from .registry import ToolRegistry

            reg = ToolRegistry(cfg)
            tool_versions = hashlib.sha256(
                json.dumps({t.name: t.version for t in reg.list()}, sort_keys=True).encode()
            ).hexdigest()
        except Exception:
            tool_versions = "unknown"

        return {
            "policy_version": policy_version,
            "policy_hash": policy_hash,
            "configuration_hash": config_hash,
            "worker_image_digest": worker_digest,
            "dependency_hash": dep_hash,
            "tool_versions_hash": tool_versions,
        }

    def save_baseline(self) -> dict[str, str]:
        fp = self.current_fingerprint()
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(fp, indent=2, sort_keys=True), encoding="utf-8")
        with contextlib.suppress(Exception):
            self.baseline_path.chmod(0o600)
        return fp

    def load_baseline(self) -> dict[str, str] | None:
        try:
            return json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def detect(self) -> dict[str, Any]:
        current = self.current_fingerprint()
        baseline = self.load_baseline()
        if baseline is None:
            return {
                "drift_detected": False,
                "reason": "no baseline established; run drift --baseline",
                "current": current,
                "baseline": None,
                "changes": {},
            }
        changes = {}
        for key in current:
            if baseline.get(key) != current.get(key):
                changes[key] = {"baseline": baseline.get(key), "current": current.get(key)}
        return {
            "drift_detected": bool(changes),
            "changes": changes,
            "current": current,
            "baseline": baseline,
        }

    def report(self) -> str:
        result = self.detect()
        if result["baseline"] is None:
            return "DRIFT: no baseline — run `noble drift --baseline` to establish one\n"
        if not result["drift_detected"]:
            return "DRIFT: no changes detected — system matches baseline\n"
        lines = ["DRIFT DETECTED:"]
        for key, diff in result["changes"].items():
            lines.append(f"  {key}:")
            lines.append(
                f"    baseline: {diff['baseline'][:16]}..."
                if diff["baseline"] and len(diff["baseline"]) > 16
                else f"    baseline: {diff['baseline']}"
            )
            lines.append(
                f"    current:  {diff['current'][:16]}..."
                if diff["current"] and len(diff["current"]) > 16
                else f"    current:  {diff['current']}"
            )
        return "\n".join(lines) + "\n"
