#!/usr/bin/env python3
"""
Safe Reconnaissance Runner (Cloudflare Security Audit Skill pattern)
Performs non-destructive mapping of application structure and entry points.
"""

import os
import json

def run_recon():
    print("[*] Performing safe reconnaissance of workspace...")
    file_list = []
    for root, dirs, files in os.walk("."):
        if ".git" in root or "agent-skills" in root or "node_modules" in root:
            continue
        for f in files:
            file_list.append(os.path.join(root, f))
    
    report = {
        "total_files": len(file_list),
        "status": "completed",
        "mode": "passive-recon"
    }
    print(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    run_recon()
