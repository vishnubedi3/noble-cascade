#!/usr/bin/env python3
"""
Human Approval Gate (Agent Guardrails Template pattern)
Classifies operations into LOW, MEDIUM, HIGH risk tiers and enforces human sign-off for HIGH risk.
"""

import sys

RISK_TIERS = {
    "LOW": ["static-analysis", "dependency-audit", "secret-scanning", "reconnaissance"],
    "MEDIUM": ["code-patching", "non-destructive-testing"],
    "HIGH": ["active-fuzzing", "poc-execution", "production-modification", "exploit-verification"]
}

def evaluate_risk(action: str) -> str:
    for tier, actions in RISK_TIERS.items():
        if action in actions:
            return tier
    return "HIGH" # Default deny-by-default to HIGH risk for unknown actions

def require_approval(action: str, override_approval: bool = False) -> bool:
    tier = evaluate_risk(action)
    print(f"[*] Action '{action}' evaluated as risk tier: {tier}")
    
    if tier == "LOW":
        print("[+] LOW risk tier: automatic approval granted.")
        return True
    elif tier == "MEDIUM":
        print("[*] MEDIUM risk tier: logging action and proceeding with audit trail.")
        return True
    else:
        print(f"[!] HIGH risk tier detected for action '{action}'.")
        if override_approval:
            print("[+] Human approval override provided. Proceeding.")
            return True
        else:
            print("[!] HIGH risk action halted. Explicit human approval required. Agent cannot self-approve.")
            return False

if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "static-analysis"
    override = "--approve" in sys.argv
    success = require_approval(action, override)
    sys.exit(0 if success else 1)
