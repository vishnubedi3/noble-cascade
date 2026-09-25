#!/usr/bin/env python3
"""Risk-classification compatibility wrapper (NOT an approval bypass).

There is no universal ``--approve`` flag: high-risk requests need a
request-bound approval from a *different* authorized principal, checked by
``noble.approvals.ApprovalManager`` inside the control plane. This script does
not execute tools or issue an approval.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from noble.models import SecurityRequest  # noqa: E402
from noble.risk import RiskEngine  # noqa: E402
from noble.targets import normalize_target  # noqa: E402


def evaluate_risk(action: str) -> str:
    target = normalize_target(str(ROOT), workspace_root=str(ROOT))
    request = SecurityRequest(action=action, target=target.canonical, requester="local-operator")
    return RiskEngine().assess(request, target).tier.value


def require_approval(action: str, override_approval: bool = False) -> bool:
    tier = evaluate_risk(action)
    print(f"[*] Action '{action}' evaluated as risk tier: {tier}")
    if override_approval:
        print("[!] --approve is not a valid human approval; request-bound approval is required.")
        return False
    if tier in ("HIGH", "CRITICAL"):
        print("[!] Approval required; no high-risk tool is registered in the local runtime.")
        return False
    print("[*] Risk classification only; execution still requires scope and an explicit grant.")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: approval_gate.py ACTION [--approve (always refused)]", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(0 if require_approval(sys.argv[1], "--approve" in sys.argv[2:]) else 1)
