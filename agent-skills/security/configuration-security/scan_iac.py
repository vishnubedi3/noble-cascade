#!/usr/bin/env python3
"""
Configuration Security & IaC Scanner (SecOpsAgentKit / Checkov pattern)
Scans infrastructure as code and configuration files for security misconfigurations.
"""

import subprocess
import sys
import os

def scan_iac():
    print("[*] Scanning Infrastructure as Code (Checkov)...")
    try:
        subprocess.run(["checkov", "--version"], capture_output=True, text=True)
        subprocess.run(["checkov", "-d", ".", "--quiet"], check=False)
    except Exception as e:
        print(f"[!] IaC scan note: {e}")

if __name__ == "__main__":
    scan_iac()
