"""SLSA-style Provenance — immutable build inputs, reproducible builds.

Every artifact answers: Exactly which source created me?
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(root), text=True
        ).strip()
    except Exception:
        return "unknown"


def _git_dirty(root: Path) -> bool:
    try:
        out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(root), text=True)
        return bool(out.strip())
    except Exception:
        return False


def _file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return "0" * 64


def generate_provenance(workspace_root: Path | None = None) -> dict[str, Any]:
    root = (
        Path(workspace_root).resolve() if workspace_root else Path(__file__).resolve().parent.parent
    )
    now = datetime.now(timezone.utc).isoformat()
    commit = _git_commit(root)
    # Build inputs: critical files hashed
    inputs = {}
    for rel in [
        "pyproject.toml",
        "requirements.lock",
        "requirements-dev.lock",
        "config/runtime.yaml",
        "agent-skills/governance/scope-enforcement/scope-policy.yaml",
        "noble/builtins/worker.py",
        "docs/security-spec.json",
    ]:
        p = root / rel
        inputs[rel] = _file_hash(p) if p.exists() else "missing"
    # Record python and platform for reproducibility
    return {
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "builder": {"id": "local+noble-cascade"},
            "buildType": "https://noble-cascade.local/build/v0.2.0",
            "invocation": {
                "configSource": {
                    "uri": f"git+https://github.com/vishnubedi3/noble-cascade@{commit}",
                    "digest": {"sha1": commit},
                    "entryPoint": "noble release",
                },
                "parameters": {},
            },
            "materials": [
                {
                    "uri": "git+https://github.com/vishnubedi3/noble-cascade",
                    "digest": {"sha1": commit},
                },
                *[{"uri": f"file://{k}", "digest": {"sha256": v}} for k, v in inputs.items()],
            ],
            "buildConfig": {
                "pythonVersion": platform.python_version(),
                "platform": platform.platform(),
                "architecture": platform.machine(),
            },
            "metadata": {
                "buildStartedOn": now,
                "buildFinishedOn": now,
                "completeness": {"parameters": True, "environment": True, "materials": True},
                "reproducible": True,
                "dirty": _git_dirty(root),
            },
        },
        "subject": [
            {
                "name": "release",
                "digest": {
                    "sha256": hashlib.sha256(
                        json.dumps(inputs, sort_keys=True).encode()
                    ).hexdigest()
                },
            }
        ],
        "commit": commit,
        "inputs": inputs,
        "generatedAt": now,
    }


def write_provenance(path: Path | str, workspace_root: Path | None = None) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = generate_provenance(workspace_root)
    p.write_text(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8")
    return p
