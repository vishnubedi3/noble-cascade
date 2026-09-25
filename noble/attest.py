"""Cryptographic Attestations — signed artifacts.

Releases, worker images, security spec, policy bundle, ledger snapshots
are attested via SHA-256 + HMAC-like deterministic signing.
Verification requires only public artifacts (digest pinning).

Note: This is a local deterministic attestation scheme using a
repo-derived key (hash of worker.py). For production, replace with
Sigstore/cosign. Verification is offline without network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _attestation_key(workspace_root: Path) -> bytes:
    # Deterministic key derived from worker.py + repo root; not a secret, just binds attestation to source
    worker = workspace_root / "noble/builtins/worker.py"
    try:
        wb = worker.read_bytes()
    except Exception:
        wb = b"noble-cascade-default-key"
    return hashlib.sha256(wb + str(workspace_root).encode()).digest()


def _canonical(data: Any) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
    ).encode()


def sign_artifact(payload: dict[str, Any], workspace_root: Path | None = None) -> dict[str, str]:
    root = (
        Path(workspace_root).resolve() if workspace_root else Path(__file__).resolve().parent.parent
    )
    key = _attestation_key(root)
    c = _canonical(payload)
    digest = hashlib.sha256(c).hexdigest()
    sig = hmac.new(key, c, hashlib.sha256).hexdigest()
    return {
        "digest": digest,
        "signature": sig,
        "algorithm": "HMAC-SHA256",
        "key_id": hashlib.sha256(key).hexdigest()[:16],
    }


def verify_attestation(
    payload: dict[str, Any], attestation: dict[str, str], workspace_root: Path | None = None
) -> bool:
    root = (
        Path(workspace_root).resolve() if workspace_root else Path(__file__).resolve().parent.parent
    )
    key = _attestation_key(root)
    c = _canonical(payload)
    expected_sig = hmac.new(key, c, hashlib.sha256).hexdigest()
    expected_digest = hashlib.sha256(c).hexdigest()
    return hmac.compare_digest(
        expected_sig, attestation.get("signature", "")
    ) and expected_digest == attestation.get("digest")


def attest_file(path: Path | str, workspace_root: Path | None = None) -> dict[str, Any]:
    p = Path(path)
    data = p.read_bytes()
    # attestation over file hash + metadata
    payload = {"file": p.name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    sig = sign_artifact(payload, workspace_root)
    return {
        "file": p.name,
        "path": str(p),
        "sha256": payload["sha256"],
        "attestation": sig,
        "attestedAt": datetime.now(timezone.utc).isoformat(),
        "statement": "attestation binds file hash to repo key; verify with noble attest --verify",
    }


def attestation_bundle(
    files: list[Path | str], workspace_root: Path | None = None
) -> dict[str, Any]:
    root = (
        Path(workspace_root).resolve() if workspace_root else Path(__file__).resolve().parent.parent
    )
    bundle = []
    for f in files:
        p = Path(f)
        if p.exists():
            bundle.append(attest_file(p, root))
    # bundle signature
    payload = {"files": [{k: v for k, v in b.items() if k != "attestation"} for b in bundle]}
    sig = sign_artifact(payload, root)
    return {
        "bundle": bundle,
        "bundle_attestation": sig,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "key_id": sig["key_id"],
    }
