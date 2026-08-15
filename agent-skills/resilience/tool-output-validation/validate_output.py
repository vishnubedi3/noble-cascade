#!/usr/bin/env python3
"""
Tool Output Validation Skill (NVIDIA SkillSpector pattern)
Scans tool execution outputs for malicious patterns, webshell indicators, or data exfiltration.
"""

import sys
import re

MALICIOUS_PATTERNS = [
    r"eval\(",
    r"exec\(",
    r"subprocess\.Popen",
    r"os\.system",
    r"base64\.b64decode",
    r"http://.*exfil"
]

def validate_output(output_text: str) -> bool:
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, output_text):
            print(f"[!] Warning: Suspicious pattern detected in tool output ('{pattern}').")
            return False
    print("[+] Tool output validation passed.")
    return True

if __name__ == "__main__":
    validate_output("print('hello world')")
