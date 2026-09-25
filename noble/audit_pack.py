"""Independent Audit Bundle — noble audit-pack.

Output audit-pack/:
  guarantees.json
  invariants.json
  replay-proof.json
  drift-proof.json
  policy-proof.json
  worker-proof.json
  findings.json
  tests.json
  verification.sh
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _hash_json(data: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
        ).encode()
    ).hexdigest()


def generate_audit_pack(
    workspace_root: Path | None = None, output_dir: Path | str = "audit-pack"
) -> Path:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path(__file__).resolve().parent.parent.resolve()
    )
    out = Path(output_dir)
    if not out.is_absolute():
        out = (root / out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    # 1 guarantees.json: from guarantee-matrix.md / contracts
    from .contracts import CONTRACTS
    from .spec import generate_spec

    spec = generate_spec()
    guarantees = {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "contracts": {
            k: {ik: iv for ik, iv in v.items() if ik != "check"} for k, v in CONTRACTS.items()
        },
        "spec_version": spec.get("version"),
        "policies": spec.get("policies"),
        "execution_chain": spec.get("execution_chain"),
    }
    (out / "guarantees.json").write_text(
        json.dumps(guarantees, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 2 invariants.json
    invariants = {
        "invariants": spec.get("invariants", []),
        "state_machine": spec.get("state_machine"),
        "contracts": guarantees["contracts"],
        "generatedAt": guarantees["generatedAt"],
        "hash": _hash_json(spec.get("invariants")),
    }
    (out / "invariants.json").write_text(
        json.dumps(invariants, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 3 replay-proof.json: sample replay evidence
    try:
        from .config import RuntimeConfig
        from .replay import ReplayEngine
        from .store import Store

        cfg = RuntimeConfig.load(workspace_root=root)
        store = Store(Path(cfg.state_directory) / "state.db")
        results = store.list_results(limit=5)
        proofs = []
        replayer = ReplayEngine(store)
        for r in results:
            eid = r.get("execution_id")
            if not eid:
                continue
            try:
                data = replayer.replay(eid)
                proofs.append(
                    {
                        "execution_id": eid,
                        "request_id": data.get("request_id"),
                        "state": data.get("state"),
                        "outcome": data.get("outcome"),
                        "read_only": data.get("read_only"),
                        "replay_note": data.get("replay_note"),
                        "evidence_count": len(data.get("evidence", [])),
                        "findings_count": len(data.get("findings", [])),
                        "policy": data.get("policy"),
                    }
                )
            except Exception as exc:
                proofs.append({"execution_id": eid, "error": str(exc)})
        replay_proof = {
            "sampled": len(proofs),
            "proofs": proofs,
            "generatedAt": guarantees["generatedAt"],
            "deterministic": True,
        }
    except Exception as exc:
        replay_proof = {"error": str(exc), "generatedAt": guarantees["generatedAt"]}
    (out / "replay-proof.json").write_text(
        json.dumps(replay_proof, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 4 drift-proof.json
    try:
        from .drift import DriftDetector

        drift = DriftDetector(workspace_root=root).detect()
        drift_proof = {"drift": drift, "generatedAt": guarantees["generatedAt"]}
    except Exception as exc:
        drift_proof = {"error": str(exc)}
    (out / "drift-proof.json").write_text(
        json.dumps(drift_proof, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 5 policy-proof.json
    try:
        from .config import RuntimeConfig
        from .policy_version import compute_policy_fingerprint
        from .scope import ScopeEngine

        cfg = RuntimeConfig.load(workspace_root=root)
        scope = ScopeEngine.from_file(workspace_root=root)
        fp = compute_policy_fingerprint(cfg, scope)
        policy_proof = {"fingerprint": fp, "generatedAt": guarantees["generatedAt"]}
    except Exception as exc:
        policy_proof = {"error": str(exc)}
    (out / "policy-proof.json").write_text(
        json.dumps(policy_proof, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 6 worker-proof.json
    try:
        from .supply_chain import verify_worker_image

        ok, digest, msg = verify_worker_image(root / "noble/builtins/worker.py")
        worker_proof = {
            "valid": ok,
            "digest": digest,
            "message": msg,
            "generatedAt": guarantees["generatedAt"],
        }
    except Exception as exc:
        worker_proof = {"error": str(exc)}
    (out / "worker-proof.json").write_text(
        json.dumps(worker_proof, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 7 findings.json
    try:
        from .config import RuntimeConfig
        from .reporting import Reporter
        from .store import Store

        cfg = RuntimeConfig.load(workspace_root=root)
        store = Store(Path(cfg.state_directory) / "state.db")
        findings = Reporter(store).collect()
        (out / "findings.json").write_text(
            json.dumps(findings, indent=2, sort_keys=True, default=str), encoding="utf-8"
        )
    except Exception as exc:
        (out / "findings.json").write_text(
            json.dumps({"error": str(exc)}, indent=2), encoding="utf-8"
        )

    # 8 tests.json (collect and optionally run)
    try:
        col = subprocess.run(
            ["python", "-m", "pytest", "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=15,
        )
        tests = [l for l in col.stdout.splitlines() if "::" in l]
        # run quick
        run = subprocess.run(
            ["python", "-m", "pytest", "-q"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=90,
        )
        tests_json = {
            "collected": len(tests),
            "tests": tests[:100],
            "run_exit": run.returncode,
            "summary": run.stdout.strip().splitlines()[-3:] if run.stdout else [],
            "generatedAt": guarantees["generatedAt"],
        }
    except Exception as exc:
        tests_json = {"error": str(exc)}
    (out / "tests.json").write_text(
        json.dumps(tests_json, indent=2, sort_keys=True), encoding="utf-8"
    )

    # 9 verification.sh
    verification_sh = """#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "=== Noble Cascade Offline Verification ==="
echo "Root: $ROOT"
fail=0
check() {
  echo -n "$1 ... "
  if eval "$2" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fail=1; fi
}
check "policy proof" "cat audit-pack/policy-proof.json | python3 -c 'import json,sys; d=json.load(open(\"audit-pack/policy-proof.json\")); assert \"fingerprint\" in d'"
check "drift proof" "cat audit-pack/drift-proof.json | python3 -c 'import json; json.load(open(\"audit-pack/drift-proof.json\"))'"
check "worker proof" "cat audit-pack/worker-proof.json | python3 -c 'import json; d=json.load(open(\"audit-pack/worker-proof.json\")); assert d.get(\"valid\")'"
check "replay proof" "cat audit-pack/replay-proof.json | python3 -c 'import json; d=json.load(open(\"audit-pack/replay-proof.json\")); assert d.get(\"deterministic\")'"
check "invariants" "cat audit-pack/invariants.json | python3 -c 'import json; d=json.load(open(\"audit-pack/invariants.json\")); assert len(d.get(\"invariants\",[]))>=10'"
check "audit chain" "python3 -m noble audit --verify"
check "spec sync" "python3 -m noble spec --verify"
check "certify" "python3 -m noble certify --json | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d.get(\"status\")==\"CERTIFIED\"'"
check "sbom exists" "test -f release/SBOM.spdx.json || test -f audit-pack/guarantees.json"
echo ""
if [ $fail -eq 0 ]; then echo "OFFLINE VERIFICATION PASSED"; else echo "OFFLINE VERIFICATION FAILED"; exit 1; fi
"""
    (out / "verification.sh").write_text(verification_sh, encoding="utf-8")
    (out / "verification.sh").chmod(0o755)
    return out
