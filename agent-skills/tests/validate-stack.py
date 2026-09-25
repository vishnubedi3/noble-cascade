#!/usr/bin/env python3
"""Compatibility smoke suite for legacy skill references and the new runtime.

The full test matrix lives in ``python3 -m pytest``. This script no longer
confuses a wrapper file with a working upstream integration, and never treats
``--approve`` as human approval.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from noble.config import RuntimeConfig  # noqa: E402
from noble.registry import ToolRegistry  # noqa: E402


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([*args], cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)


def test_manifest() -> None:
    data = yaml.safe_load((ROOT / "agent-skills/manifest.yaml").read_text(encoding="utf-8"))
    skills = data["skills"]
    assert len(skills) == 34, "expected 34 historical skill references"
    assert all((ROOT / item["integration_wrapper"]).exists() for item in skills)
    assert len(ToolRegistry(RuntimeConfig.load()).list()) == 2, "only 2 local tools are actually registered"
    assert all(item.get("status") != "INSTALLED" for item in skills), "stale status claim"
    print("[+] 34 historical references; 2 registered offline tools; no false INSTALLED claims")


def test_scope() -> None:
    program = "agent-skills/governance/scope-enforcement/enforce_scope.py"
    assert _run(sys.executable, program, "vishnubedi3/noble-cascade", "static-analysis").returncode == 0
    for target in ("unauthorized-target.gov", "evil.com/localhost", "notvishnubedi3/noble-cascade", "attacker.example/?repo=vishnubedi3/noble-cascade"):
        assert _run(sys.executable, program, target, "static-analysis").returncode != 0, target
    print("[+] Exact repository allow; forbidden and three substring-bypass regressions blocked")


def test_approval() -> None:
    program = "agent-skills/governance/human-approval/approval_gate.py"
    assert _run(sys.executable, program, "static-analysis").returncode == 0
    assert _run(sys.executable, program, "poc-execution").returncode != 0
    assert _run(sys.executable, program, "poc-execution", "--approve").returncode != 0
    assert _run(sys.executable, program, "unknown-action").returncode != 0
    print("[+] LOW tier informational; HIGH/unknown actions and forged --approve denied")


def test_injection() -> None:
    sample = _run(sys.executable, "agent-skills/resilience/prompt-injection-defense/sanitize.py")
    assert sample.returncode == 0 and "[QUARANTINED_INSTRUCTION]" in sample.stdout
    print("[+] Untrusted instructions quarantined as data")


def test_reporting() -> None:
    program = "agent-skills/reporting/vulnerability-reporting/validate-findings.cjs"
    assert _run("node", program).returncode == 0
    with tempfile.TemporaryDirectory() as temp:
        missing = Path(temp) / "not-found.json"
        assert _run("node", program, str(missing)).returncode != 0
        invalid = Path(temp) / "invalid.json"
        invalid.write_text(json.dumps([{"id": "example"}]))
        assert _run("node", program, str(invalid)).returncode != 0
        assert not missing.exists(), "validator must not create a fake finding"
    print("[+] Real Draft-07 schema check; missing/invalid data denied without template creation")


if __name__ == "__main__":
    print("=== Noble Cascade legacy-reference smoke suite ===")
    try:
        test_manifest()
        test_scope()
        test_approval()
        test_injection()
        test_reporting()
    except (AssertionError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"[!] Validation FAILED: {exc}")
        raise SystemExit(1) from exc
    print("=== ALL VALIDATION TESTS PASSED SUCCESSFULLY ===")
