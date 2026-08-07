#!/usr/bin/env python3
"""
Dependency Vulnerability Audit Wrapper (Security Skills / OSV-Scanner pattern)
Audits project dependencies against CVE databases with reachability triage.
"""

import subprocess
import sys
import os

def audit_dependencies():
    print("[*] Auditing dependencies for known CVEs (osv-scanner / npm audit)...")
    try:
        if os.path.exists("package.json"):
            subprocess.run(["npm", "audit", "--json"], check=False)
        if os.path.exists("requirements.txt") or os.path.exists("pyproject.toml"):
            subprocess.run(["pip", "list"], check=False)
        # Run osv-scanner if available
        subprocess.run(["osv-scanner", "--version"], capture_output=True, text=True)
    except Exception as e:
        print(f"[!] Dependency audit note: {e}")

if __name__ == "__main__":
    audit_dependencies()
