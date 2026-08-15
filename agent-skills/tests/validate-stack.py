#!/usr/bin/env python3
"""
Stack Validation Test Harness
Tests skill discovery, loading, scope enforcement, deny-by-default behavior, approval gates, and reporting.
"""

import sys
import os
import subprocess
import yaml
import json

def test_manifest():
    print("[*] Testing skill manifest loading...")
    manifest_path = "agent-skills/manifest.yaml"
    assert os.path.exists(manifest_path), "manifest.yaml missing"
    with open(manifest_path, "r") as f:
        data = yaml.safe_load(f)
    assert len(data.get("skills", [])) >= 30, "Expected at least 30 registered skills"
    print(f"[+] Manifest test passed: {len(data['skills'])} skills registered.")

def test_scope_enforcement():
    print("[*] Testing scope enforcement & deny-by-default...")
    res = subprocess.run([sys.executable, "agent-skills/governance/scope-enforcement/enforce_scope.py", "vishnubedi3/noble-cascade", "static-analysis"], capture_output=True, text=True)
    assert res.returncode == 0, f"Allowed scope failed: {res.stderr}"
    
    res_denied = subprocess.run([sys.executable, "agent-skills/governance/scope-enforcement/enforce_scope.py", "unauthorized-target.gov", "remote-code-execution"], capture_output=True, text=True)
    assert res_denied.returncode != 0, "Forbidden target should have been blocked"
    print("[+] Scope enforcement and deny-by-default tests passed.")

def test_human_approval():
    print("[*] Testing human approval risk tiers...")
    res_low = subprocess.run([sys.executable, "agent-skills/governance/human-approval/approval_gate.py", "static-analysis"], capture_output=True, text=True)
    assert res_low.returncode == 0, "Low risk action should pass automatically"

    res_high = subprocess.run([sys.executable, "agent-skills/governance/human-approval/approval_gate.py", "poc-execution"], capture_output=True, text=True)
    assert res_high.returncode != 0, "High risk action should halt without approval override"

    res_override = subprocess.run([sys.executable, "agent-skills/governance/human-approval/approval_gate.py", "poc-execution", "--approve"], capture_output=True, text=True)
    assert res_override.returncode == 0, "High risk action with --approve should succeed"
    print("[+] Human approval gate tests passed.")

def test_prompt_injection():
    print("[*] Testing prompt injection defense...")
    res = subprocess.run([sys.executable, "agent-skills/resilience/prompt-injection-defense/sanitize.py"], capture_output=True, text=True)
    assert res.returncode == 0
    print("[+] Prompt injection defense test passed.")

def test_reporting():
    print("[*] Testing vulnerability reporting schema validation...")
    res = subprocess.run(["node", "agent-skills/reporting/vulnerability-reporting/validate-findings.cjs"], capture_output=True, text=True)
    assert res.returncode == 0, f"Findings validation failed: {res.stderr}"
    print("[+] Vulnerability reporting schema test passed.")

if __name__ == "__main__":
    print("=== Starting Authorized Agent Stack Validation ===")
    try:
        test_manifest()
        test_scope_enforcement()
        test_human_approval()
        test_prompt_injection()
        test_reporting()
        print("=== ALL VALIDATION TESTS PASSED SUCCESSFULLY ===")
        sys.exit(0)
    except AssertionError as e:
        print(f"[!] Validation FAILED: {e}")
        sys.exit(1)
    except Exception as ex:
        print(f"[!] Unexpected error during validation: {ex}")
        sys.exit(1)
