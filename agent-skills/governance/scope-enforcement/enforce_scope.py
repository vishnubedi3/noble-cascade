#!/usr/bin/env python3
"""
Scope Enforcement Engine
Enforces deny-by-default rules against target URLs, IPs, repositories, and actions.
"""

import sys
import os
import yaml

def load_policy():
    policy_path = os.path.join(os.path.dirname(__file__), 'scope-policy.yaml')
    if not os.path.exists(policy_path):
        return {"default_action": "deny"}
    with open(policy_path, 'r') as f:
        return yaml.safe_load(f)

def check_scope(target: str, action: str) -> bool:
    policy = load_policy()
    
    # Check forbidden targets
    for forbidden in policy.get('scope', {}).get('forbidden_targets', []):
        if forbidden.startswith('*') and target.endswith(forbidden[1:]):
            print(f"[!] Target '{target}' matches forbidden pattern '{forbidden}'. BLOCKED.")
            return False
        elif target == forbidden:
            print(f"[!] Target '{target}' is explicitly forbidden. BLOCKED.")
            return False

    # Check forbidden actions
    if action in policy.get('scope', {}).get('forbidden_actions', []):
        print(f"[!] Action '{action}' is forbidden by policy. BLOCKED.")
        return False

    # Check allowed repositories / domains
    allowed = False
    for repo_pattern in policy.get('scope', {}).get('allowed_repositories', []):
        if repo_pattern.endswith('/*'):
            prefix = repo_pattern[:-2]
            if target.startswith(prefix) or prefix in target:
                allowed = True
                break
        elif target == repo_pattern:
            allowed = True
            break

    for domain in policy.get('scope', {}).get('allowed_domains', []):
        if domain.startswith('*') and target.endswith(domain[1:]):
            allowed = True
            break
        elif domain in target:
            allowed = True
            break

    if not allowed:
        print(f"[!] Target '{target}' and Action '{action}' not found in allowed scope. Deny-by-default applied. BLOCKED.")
        return False

    print(f"[+] Scope check passed for target '{target}' and action '{action}'.")
    return True

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "local-workspace"
    action = sys.argv[2] if len(sys.argv) > 2 else "static-analysis"
    success = check_scope(target, action)
    sys.exit(0 if success else 1)
