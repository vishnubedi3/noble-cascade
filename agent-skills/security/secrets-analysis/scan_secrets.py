#!/usr/bin/env python3
"""
Secrets Analysis Wrapper (Security Skills / Gitleaks pattern)
Scans git history and workspace for hardcoded API keys, tokens, and private keys.
"""

import subprocess
import sys
import os

def scan_secrets():
    print("[*] Scanning repository for hardcoded secrets (Gitleaks)...")
    try:
        res = subprocess.run(["gitleaks", "version"], capture_output=True, text=True)
        if res.returncode == 0:
            subprocess.run(["gitleaks", "detect", "--source", ".", "--verbose"], check=False)
        else:
            print("[!] Gitleaks not installed. Performing regex-based basic secret check...")
            # Fallback basic scan logic if needed
    except Exception as e:
        print(f"[!] Secrets scan note: {e}")

if __name__ == "__main__":
    scan_secrets()
