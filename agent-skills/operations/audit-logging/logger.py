#!/usr/bin/env python3
"""
Structured Audit Logging Engine (TheArchitectit Agent Guardrails Template pattern)
Records meaningful agent actions, policy decisions, and results while redacting secrets.
"""

import os
import json
from datetime import datetime

LOG_FILE = "agent-skills/operations/audit-logging/audit.log"

def log_event(action: str, target: str, tool: str, policy_decision: str, approval_status: str, result: str):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "target": target,
        "tool": tool,
        "policy_decision": policy_decision,
        "approval_status": approval_status,
        "result": result
    }
    
    # Redact potential secrets or tokens
    event_str = json.dumps(event)
    for sensitive in ["password", "token", "secret", "authorization"]:
        if sensitive in event_str.lower():
            event_str = event_str.replace(sensitive, "[REDACTED]")

    with open(LOG_FILE, "a") as f:
        f.write(event_str + "\n")
    print(f"[*] Audit Logged: {action} -> {policy_decision}")

if __name__ == "__main__":
    log_event("scan", "target-app", "semgrep", "ALLOWED", "NOT_REQUIRED", "success")
