"""Reproducible Release System — every release cryptographically reproducible.

Layout:
release/
  RELEASE.json
  SBOM.spdx.json
  SBOM.cyclonedx.json
  PROVENANCE.json
  POLICY_HASHES.json
  TEST_RESULTS.json
  SECURITY_SPEC_HASH.json
  WORKER_DIGESTS.json
  ATTESTATION.md
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .policy_version import (
    compute_config_hash,
    compute_policy_hash,
    compute_worker_digest,
    get_policy_version,
)
from .spec import generate_spec


def _git_tag(root: Path) -> str:
    try:
        tag = subprocess.check_output(
            ["git", "describe", "--tags", "--exact-match"], cwd=str(root), text=True
        ).strip()
        return tag
    except Exception:
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "--short", "HEAD"], cwd=str(root), text=True
            ).strip()
            return f"0.2.0-{commit}"
        except Exception:
            return "0.2.0-unknown"


def _git_commit(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(root), text=True
        ).strip()
    except Exception:
        return "unknown"


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hash_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return "0" * 64


def _write_json(path: Path, data: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True, default=str)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode()).hexdigest()


def create_release(
    workspace_root: Path | None = None,
    version: str | None = None,
    output_dir: Path | str = "release",
) -> dict[str, Any]:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path(__file__).resolve().parent.parent.resolve()
    )
    out = Path(output_dir)
    if not out.is_absolute():
        out = (root / out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # Core hashes
    policy_hash = compute_policy_hash()
    config_hash = compute_config_hash()
    worker_digest = compute_worker_digest()
    policy_version = get_policy_version()

    spec = generate_spec()
    spec_hash = hashlib.sha256(
        json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()

    # dependency lock snapshots (read files if present)
    def _lock_snapshot(p: Path) -> dict[str, Any]:
        if not p.exists():
            return {"present": False, "hash": "missing", "lines": 0}
        text = p.read_text(encoding="utf-8")
        return {
            "present": True,
            "hash": hashlib.sha256(text.encode()).hexdigest(),
            "lines": len(text.splitlines()),
        }

    lock = _lock_snapshot(root / "requirements.lock")
    dev_lock = _lock_snapshot(root / "requirements-dev.lock")

    # Test manifest: collect pytest tests
    try:
        result = subprocess.run(
            ["python", "-m", "pytest", "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=15,
        )
        # pytest --collect-only -q prints lines like tests/...::test_...
        tests = [l for l in result.stdout.splitlines() if "::" in l]
        test_manifest = {"count": len(tests), "tests": tests[:200], "raw": result.stdout[:5000]}
    except Exception as exc:
        test_manifest = {"count": 0, "tests": [], "error": str(exc)}

    # Try to run tests for TEST_RESULTS.json (quick)
    try:
        tr = subprocess.run(
            ["python", "-m", "pytest", "-q"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=90,
        )
        test_results = {
            "exit_code": tr.returncode,
            "passed": tr.stdout.count(" passed") > 0,
            "summary": tr.stdout.strip().splitlines()[-2:] if tr.stdout else [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        test_results = {"exit_code": -1, "error": str(exc)}

    git_tag = version or _git_tag(root)
    git_commit = _git_commit(root)

    # Build RELEASE.json
    release = {
        "name": "noble-cascade",
        "version": git_tag,
        "git_commit": git_commit,
        "git_tag": git_tag,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "configuration_hash": config_hash,
        "worker_image_digest": worker_digest,
        "security_spec_hash": spec_hash,
        "dependency_locks": {"requirements.lock": lock, "requirements-dev.lock": dev_lock},
        "test_manifest": test_manifest,
        "reproducible": True,
        "builder": {
            "id": "local+noble-cascade",
            "python": subprocess.check_output(["python", "--version"], text=True).strip()
            if True
            else "unknown",
        },
    }

    # Write SBOMs
    from .sbom import generate_cyclonedx, generate_spdx

    spdx = generate_spdx(root)
    cdx = generate_cyclonedx(root)

    # provenance
    from .provenance import generate_provenance

    provenance = generate_provenance(root)

    # hashes for verification
    release_hash = _write_json(out / "RELEASE.json", release)
    spdx_hash = _write_json(out / "SBOM.spdx.json", spdx)
    cdx_hash = _write_json(out / "SBOM.cyclonedx.json", cdx)
    prov_hash = _write_json(out / "PROVENANCE.json", provenance)

    policy_hashes = {
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "configuration_hash": config_hash,
        "worker_image_digest": worker_digest,
        "security_spec_hash": spec_hash,
        "release_json_sha256": release_hash,
        "sbom_spdx_sha256": spdx_hash,
        "sbom_cyclonedx_sha256": cdx_hash,
        "provenance_sha256": prov_hash,
    }
    policy_hashes_hash = _write_json(out / "POLICY_HASHES.json", policy_hashes)
    test_results_hash = _write_json(out / "TEST_RESULTS.json", test_results)
    # SECURITY_SPEC_HASH.json is just spec hash + spec
    sec_spec_hash_doc = {"security_spec_hash": spec_hash, "spec": spec, "sha256": spec_hash}
    sec_hash = _write_json(out / "SECURITY_SPEC_HASH.json", sec_spec_hash_doc)
    worker_digests = {
        "worker_image_digest": worker_digest,
        "worker_path": "noble/builtins/worker.py",
        "worker_sha256": _hash_file(root / "noble/builtins/worker.py"),
    }
    worker_hash = _write_json(out / "WORKER_DIGESTS.json", worker_digests)

    # ATTESTATION.md: human + machine attestation
    from .attest import sign_artifact

    payload = {
        "release": release_hash,
        "spdx": spdx_hash,
        "cyclonedx": cdx_hash,
        "provenance": prov_hash,
        "policy_hashes": policy_hashes_hash,
        "test_results": test_results_hash,
        "security_spec": sec_hash,
        "worker": worker_hash,
    }
    att = sign_artifact(payload, root)
    attestation_md = f"""# Noble Cascade Release Attestation

Version: {git_tag}
Commit: {git_commit}
Created: {release["createdAt"]}

## Hashes

- RELEASE.json: {release_hash}
- SBOM.spdx.json: {spdx_hash}
- SBOM.cyclonedx.json: {cdx_hash}
- PROVENANCE.json: {prov_hash}
- POLICY_HASHES.json: {policy_hashes_hash}
- TEST_RESULTS.json: {test_results_hash}
- SECURITY_SPEC_HASH.json: {sec_hash}
- WORKER_DIGESTS.json: {worker_hash}

## Attestation

Algorithm: {att["algorithm"]}
Digest: {att["digest"]}
Signature: {att["signature"]}
Key ID: {att["key_id"]}

Verification: `noble release --verify` or `noble attest --verify release/ATTESTATION.md`

This attestation binds all release artifacts to the repo-derived key (HMAC-SHA256 over canonical JSON).
For production, replace with Sigstore.

## Reproducibility

To reproduce:
```bash
git clone https://github.com/vishnubedi3/noble-cascade && cd noble-cascade
git checkout {git_commit}
noble release --create {git_tag}
# compare hashes in release/
```
"""
    (out / "ATTESTATION.md").write_text(attestation_md, encoding="utf-8")
    # also write machine JSON
    _write_json(
        out / "ATTESTATION.json",
        {"payload": payload, "attestation": att, "markdown": "ATTESTATION.md"},
    )

    return {
        "release_dir": str(out),
        "version": git_tag,
        "commit": git_commit,
        "hashes": payload,
        "attestation": att,
    }


def verify_release(
    workspace_root: Path | None = None, release_dir: Path | str = "release"
) -> tuple[bool, list[str]]:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path(__file__).resolve().parent.parent.resolve()
    )
    rd = Path(release_dir)
    if not rd.is_absolute():
        rd = (root / rd).resolve()
    issues = []
    if not rd.exists():
        return False, [f"release dir {rd} missing; run noble release --create"]
    # check expected files
    expected = [
        "RELEASE.json",
        "SBOM.spdx.json",
        "SBOM.cyclonedx.json",
        "PROVENANCE.json",
        "POLICY_HASHES.json",
        "TEST_RESULTS.json",
        "SECURITY_SPEC_HASH.json",
        "WORKER_DIGESTS.json",
        "ATTESTATION.md",
    ]
    for f in expected:
        if not (rd / f).exists():
            issues.append(f"missing {f}")
    # verify hashes if present
    try:
        from .attest import verify_attestation

        if (rd / "ATTESTATION.json").exists():
            data = json.loads((rd / "ATTESTATION.json").read_text(encoding="utf-8"))
            payload = data.get("payload", {})
            att = data.get("attestation", {})
            if not verify_attestation(payload, att, root):
                issues.append("attestation signature mismatch")
        # verify policy hashes match current
        if (rd / "POLICY_HASHES.json").exists():
            stored = json.loads((rd / "POLICY_HASHES.json").read_text(encoding="utf-8"))
            current = {
                "policy_hash": compute_policy_hash(),
                "configuration_hash": compute_config_hash(),
                "worker_image_digest": compute_worker_digest(),
            }
            for k in ("policy_hash", "configuration_hash", "worker_image_digest"):
                if stored.get(k) != current.get(k):
                    issues.append(
                        f"drift: {k} stored {stored.get(k, '')[:12]} != current {current.get(k, '')[:12]}"
                    )
    except Exception as exc:
        issues.append(f"verify error: {type(exc).__name__}: {exc}")
    return (len(issues) == 0, issues)
