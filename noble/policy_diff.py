"""Policy Regression Framework — noble policy-diff.

Answers: what changed, why, affected rules/guarantees/tests/replay impact.
Policy is version-controlled behavior.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


def _git_show(commit: str, rel_path: str, root: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "show", f"{commit}:{rel_path}"], cwd=str(root), text=True
        )
    except Exception:
        return None


def _parse_scope_rules(text: str) -> dict[str, Any]:
    try:
        import yaml

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {"raw": text[:2000]}


def policy_diff(
    from_commit: str | None = None,
    to_commit: str | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    root = (
        Path(workspace_root).resolve()
        if workspace_root
        else Path(__file__).resolve().parent.parent.resolve()
    )
    rel = "agent-skills/governance/scope-enforcement/scope-policy.yaml"
    # determine commits
    if not from_commit:
        try:
            from_commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD~1"], cwd=str(root), text=True
            ).strip()
        except Exception:
            from_commit = "HEAD"
    if not to_commit:
        try:
            to_commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=str(root), text=True
            ).strip()
        except Exception:
            to_commit = "HEAD"
    old_text = _git_show(from_commit, rel, root)
    new_text = _git_show(to_commit, rel, root)
    old_rules = _parse_scope_rules(old_text) if old_text else {}
    new_rules = _parse_scope_rules(new_text) if new_text else {}
    # diff keys
    old_keys = set(old_rules.keys()) if isinstance(old_rules, dict) else set()
    new_keys = set(new_rules.keys()) if isinstance(new_rules, dict) else set()
    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = []
    for k in old_keys & new_keys:
        if old_rules.get(k) != new_rules.get(k):
            changed.append(k)
    # affected guarantees: map policy keys to invariants
    guarantee_map = {
        "allowed_directories": [1],
        "allowed_domains": [1],
        "allowed_ip_ranges": [1],
        "allowed_actions": [1, 2],
        "forbidden_targets": [1],
        "forbidden_actions": [1],
        "version": [1],
    }
    affected_guarantees = set()
    for k in added + removed + changed:
        affected_guarantees.update(guarantee_map.get(k, []))
    # affected tests: heuristic
    affected_tests = []
    if added or removed or changed:
        affected_tests = [
            "tests/unit/test_scope_and_targets.py",
            "tests/test_guarantee_matrix.py",
            "tests/property/test_target_properties.py",
        ]
    # why: try to get commit message
    why = ""
    try:
        why = (
            subprocess.check_output(
                ["git", "log", "--format=%B", "-n", "1", to_commit], cwd=str(root), text=True
            )
            .strip()
            .splitlines()[0][:200]
        )
    except Exception:
        why = "policy diff"
    # replay impact
    replay_impact = "Re-run `noble replay` on recent executions; if policy hash changed, replay shows new policy hash and prior executions remain valid under old hash."
    if changed or added or removed:
        replay_impact = "Policy hash drift detected; replay of old executions will show stored policy_hash != current; use `noble drift` to verify."

    return {
        "from": from_commit,
        "to": to_commit,
        "file": rel,
        "what_changed": {"added": added, "removed": removed, "changed": changed},
        "why": why,
        "affected_rules": sorted(set(added + removed + changed)),
        "affected_guarantees": sorted(affected_guarantees),
        "affected_tests": affected_tests,
        "replay_impact": replay_impact,
        "old_version": old_rules.get("version") if isinstance(old_rules, dict) else None,
        "new_version": new_rules.get("version") if isinstance(new_rules, dict) else None,
    }
