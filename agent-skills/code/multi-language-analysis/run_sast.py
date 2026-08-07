#!/usr/bin/env python3
"""
Multi-Language SAST Wrapper (SecOpsAgentKit / Semgrep / Bandit pattern)
Executes static security analyzers on the repository workspace.
"""

import subprocess
import sys
import os

def run_sast():
    print("[*] Running SAST analysis (Semgrep / Bandit)...")
    try:
        # Check if semgrep is installed
        res = subprocess.run(["semgrep", "--version"], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] Semgrep detected. Running security rules...")
            subprocess.run(["semgrep", "--config", "auto", "--quiet"], check=False)
        else:
            print("[!] Semgrep not found. Falling back to Bandit for Python analysis...")
            subprocess.run(["bandit", "-r", ".", "-ll"], check=False)
    except Exception as e:
        print(f"[!] SAST execution note: {e}")

if __name__ == "__main__":
    run_sast()
