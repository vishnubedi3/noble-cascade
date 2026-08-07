#!/usr/bin/env python3
"""
Authorization Policy Wrapper (Microsoft Agent Governance Toolkit pattern)
Manages role-based access and capability token verification across agent actions.
"""

class AuthorizationManager:
    def __init__(self):
        self.roles = {
            "operator": ["read", "scan", "analyze", "report"],
            "security-auditor": ["read", "scan", "analyze", "report", "controlled-test"],
            "admin": ["*"]
        }

    def authorize(self, role: str, capability: str) -> bool:
        if role not in self.roles:
            print(f"[!] Role '{role}' unknown. Access denied.")
            return False
        perms = self.roles[role]
        if "*" in perms or capability in perms:
            print(f"[+] Role '{role}' authorized for capability '{capability}'.")
            return True
        print(f"[!] Role '{role}' lacks capability '{capability}'. Access denied.")
        return False

if __name__ == "__main__":
    am = AuthorizationManager()
    assert am.authorize("operator", "scan") == True
    assert am.authorize("operator", "controlled-test") == False
    print("[+] Authorization policy wrapper test passed.")
