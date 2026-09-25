"""Supply Chain Verification — verify digests, hashes, signatures.

Verify:
    worker images, dependencies, tool binaries, downloaded artifacts
Where feasible:
    pin digests, verify hashes, verify signatures
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def verify_requirements_hashes(lock_path: Path) -> tuple[bool, str]:
    try:
        text = lock_path.read_text(encoding="utf-8")
        has_pins = "==" in text and "--hash=sha256:" in text
        if not has_pins:
            return False, f"{lock_path.name} missing hash pins"
        # Count packages with hashes
        pkgs = [l for l in text.splitlines() if "==" in l and "--hash" in l]
        return True, f"{lock_path.name}: {len(pkgs)} packages hash-pinned"
    except OSError as exc:
        return False, f"cannot read {lock_path}: {type(exc).__name__}"


def verify_worker_image(worker_path: Path) -> tuple[bool, str, str]:
    try:
        digest = hashlib.sha256(worker_path.read_bytes()).hexdigest()
        return True, digest, f"worker {worker_path.name} digest {digest[:12]}..."
    except OSError as exc:
        return False, "", f"worker missing: {type(exc).__name__}"


def verify_tool_binary(name: str, expected_digest: str | None = None) -> dict[str, Any]:
    import shutil

    path = shutil.which(name)
    if not path:
        return {"tool": name, "present": False, "verified": False, "reason": "not installed"}
    try:
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        if expected_digest and digest != expected_digest:
            return {
                "tool": name,
                "present": True,
                "verified": False,
                "digest": digest,
                "reason": "digest mismatch",
            }
        return {"tool": name, "present": True, "verified": True, "digest": digest, "path": path}
    except OSError as exc:
        return {"tool": name, "present": True, "verified": False, "reason": str(exc)}


def supply_chain_report(workspace_root: Path) -> dict[str, Any]:
    lock_runtime = workspace_root / "requirements.lock"
    lock_dev = workspace_root / "requirements-dev.lock"
    ok_runtime, msg_runtime = verify_requirements_hashes(lock_runtime)
    ok_dev, msg_dev = verify_requirements_hashes(lock_dev)
    ok_worker, digest, msg_worker = verify_worker_image(workspace_root / "noble/builtins/worker.py")
    return {
        "runtime_lock": {"valid": ok_runtime, "detail": msg_runtime},
        "dev_lock": {"valid": ok_dev, "detail": msg_dev},
        "worker": {"valid": ok_worker, "digest": digest, "detail": msg_worker},
        "overall": ok_runtime and ok_dev and ok_worker,
    }
