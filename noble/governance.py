"""Repository governance kernel — Master Prompt IV.

Makes the repository itself enforce the trust model Noble Cascade claims:
- security baseline creation/verification (drift from the baseline is detectable)
- workflow audit (permissions, pinned actions, dangerous patterns)
- pull-request security analysis (files -> surface -> tests -> guarantees)
- guarantee impact analysis (code change -> affected guarantees)

Every function is pure over the checkout (no network, no credentials) so CI,
fresh clones, and offline auditors all observe the same result.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

BASELINE_PATH = Path(".github/repo-baseline.json")
CLASSIFICATION_PATH = Path(".github/security-critical.json")
WORKFLOWS_DIR = Path(".github/workflows")

REQUIRED_VERIFICATION_COMMANDS = [
    "ruff check noble tests",
    "ruff format --check noble tests",
    "mypy noble",
    "python -m pytest -q",
    "bandit -r noble -ll -q",
    "pip-audit -r requirements-dev.lock --disable-pip",
    "python -m noble doctor --json",
    "python -m noble health --json",
    "python -m noble drift --json",
    "python -m noble ledger --verify --json",
    "python -m noble audit --verify",
    "python -m noble spec --verify",
    "python -m noble certify --json",
    "python -m noble trust-index --json",
    "python -m noble trust-report",
    "python -m noble release --verify",
    "bash verify-everything.sh",
    "bash audit-pack/verification.sh",
    "python -m noble governance --baseline-verify",
    "python -m noble governance --workflow-audit",
]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"uses:\s*([^\s#]+)")
_UNTRUSTED_INPUT_RE = re.compile(
    r"\$\{\{\s*github\.event\.(?:issue|comment|pull_request|head_commit|commits|review)"
)


def _root(workspace_root: Path | None) -> Path:
    if workspace_root is not None:
        return Path(workspace_root).resolve()
    return Path(__file__).resolve().parent.parent.resolve()


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _run_git(root: Path, args: list[str]) -> str:
    try:
        out = subprocess.run(
            ["git", *args], capture_output=True, text=True, cwd=str(root), timeout=30
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except Exception:
        return ""


def _action_shas(root: Path) -> dict[str, list[str]]:
    """Map workflow file -> sorted list of pinned action references (name@sha)."""
    result: dict[str, list[str]] = {}
    for wf in sorted((root / WORKFLOWS_DIR).glob("*.yml")):
        refs: list[str] = []
        for line in wf.read_text(encoding="utf-8").splitlines():
            if "grep " in line:  # self-check patterns mention uses: syntactically
                continue
            for match in _USES_RE.finditer(line):
                ref = match.group(1).strip().strip("'\"")
                refs.append(ref)
        result[wf.name] = sorted(refs)
    return result


def _workflow_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for wf in sorted((root / WORKFLOWS_DIR).glob("*.yml")):
        digest = _sha256_file(wf)
        if digest:
            hashes[wf.name] = digest
    return hashes


def create_baseline(workspace_root: Path | None = None) -> dict[str, Any]:
    """Build the machine-readable repository security baseline."""
    root = _root(workspace_root)
    try:
        from .policy_version import (
            compute_config_hash,
            compute_policy_hash,
            compute_worker_digest,
        )

        policy_hash = compute_policy_hash()
        config_hash = compute_config_hash()
        worker_digest = compute_worker_digest()
    except Exception:
        policy_hash = config_hash = worker_digest = "0" * 64
    spec_hash = _sha256_file(root / "docs/security-spec.json") or "missing"
    baseline: dict[str, Any] = {
        "version": 1,
        "description": (
            "Repository security baseline. Drift from this baseline is "
            "detectable via `noble governance --baseline-verify`. Regenerate "
            "only through a reviewed PR; the regeneration itself is evidence."
        ),
        "commit": _run_git(root, ["rev-parse", "HEAD"]) or "unknown",
        "branch_expectations": {
            "default_branch": "main",
            "protected_branches": ["main"],
            "direct_push": "prohibited (requires owner-level branch protection)",
            "required_pull_request": True,
            "force_push": "prohibited",
            "branch_deletion": "prohibited",
        },
        "workflow_hashes": _workflow_hashes(root),
        "action_shas": _action_shas(root),
        "dependency_hashes": {
            "requirements.lock": _sha256_file(root / "requirements.lock") or "missing",
            "requirements-dev.lock": _sha256_file(root / "requirements-dev.lock") or "missing",
        },
        "security_spec_hash": spec_hash,
        "policy_hash": policy_hash,
        "config_hash": config_hash,
        "worker_digest": worker_digest,
        "verification_script_hash": _sha256_file(root / "verify-everything.sh") or "missing",
        "governance_module_hash": _sha256_file(root / "noble/governance.py") or "missing",
        "classification_hash": _sha256_file(root / CLASSIFICATION_PATH) or "missing",
        "release_configuration": {
            "release_dir": "release/",
            "audit_pack_dir": "audit-pack/",
            "tag_binding": "RELEASE.json commit must equal tagged commit",
        },
        "required_verification_commands": REQUIRED_VERIFICATION_COMMANDS,
    }
    return baseline


def write_baseline(workspace_root: Path | None = None) -> Path:
    root = _root(workspace_root)
    out = root / BASELINE_PATH
    out.write_text(
        json.dumps(create_baseline(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return out


def verify_baseline(workspace_root: Path | None = None) -> dict[str, Any]:
    """Compare the checkout against the committed baseline; fail on drift."""
    root = _root(workspace_root)
    baseline_file = root / BASELINE_PATH
    if not baseline_file.exists():
        return {
            "verified": False,
            "drift": ["baseline file .github/repo-baseline.json missing"],
            "baseline_commit": "unknown",
            "current_commit": _run_git(root, ["rev-parse", "HEAD"]) or "unknown",
        }
    try:
        stored = json.loads(baseline_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "verified": False,
            "drift": [f"baseline file unreadable: {exc}"],
            "baseline_commit": "unknown",
            "current_commit": _run_git(root, ["rev-parse", "HEAD"]) or "unknown",
        }
    current = create_baseline(root)
    drift: list[str] = []
    for key in (
        "workflow_hashes",
        "action_shas",
        "dependency_hashes",
        "security_spec_hash",
        "policy_hash",
        "config_hash",
        "worker_digest",
        "verification_script_hash",
        "governance_module_hash",
        "classification_hash",
    ):
        if stored.get(key) != current.get(key):
            drift.append(f"{key} drifted from baseline (review + regenerate baseline)")
    if stored.get("required_verification_commands") != current.get(
        "required_verification_commands"
    ):
        drift.append("required_verification_commands drifted from baseline")
    return {
        "verified": len(drift) == 0,
        "drift": drift,
        "baseline_commit": stored.get("commit", "unknown"),
        "current_commit": current["commit"],
    }


def audit_workflows(workspace_root: Path | None = None) -> dict[str, Any]:
    """Audit every workflow: permissions, pinning, secrets, trust boundaries."""
    root = _root(workspace_root)
    workflows: dict[str, Any] = {}
    for wf in sorted((root / WORKFLOWS_DIR).glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        top, _, _jobs = text.partition("jobs:")
        uses: list[str] = []
        for line in text.splitlines():
            if "grep " in line:  # self-check patterns mention uses: syntactically
                continue
            for m in _USES_RE.finditer(line):
                uses.append(m.group(1).strip().strip("'\""))
        unpinned = [u for u in uses if "@" not in u or not _SHA_RE.match(u.split("@", 1)[1])]
        local_refs = [u for u in unpinned if u.startswith(("./", "docker://"))]
        third_party_unpinned = [u for u in unpinned if u not in local_refs]
        findings: list[str] = []
        if "permissions:" not in top or "contents: read" not in top:
            findings.append("top-level permissions must grant only 'contents: read'")
        if re.search(r"permissions:\s*write-all", text):
            findings.append("write-all permissions are forbidden")
        # pull_request_target is dangerous only as a workflow trigger; mentions in
        # comments or self-check grep patterns are not trigger usage.
        if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE):
            findings.append("pull_request_target trigger requires explicit security review")
        # persist-credentials: true is dangerous as YAML config, not inside the
        # self-check grep that forbids it. Skip comments and grep -v guarded lines.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "grep " in line:
                continue
            if re.search(r"persist-credentials:\s*true", line):
                findings.append("persist-credentials must be false")
                break
        if third_party_unpinned:
            findings.append(f"unpinned third-party actions: {third_party_unpinned}")
        if _UNTRUSTED_INPUT_RE.search(text):
            findings.append("attacker-controlled github.event input interpolated into run:")
        if re.search(r"\$\{\{\s*secrets\.", text):
            findings.append("secret interpolation present — verify minimal exposure")
        if re.search(r"actions/upload-artifact@", text) and "retention-days" not in text:
            findings.append("artifact upload should set retention-days")
        workflows[wf.name] = {
            "sha256": _sha256_file(wf),
            "actions": uses,
            "permissions_minimal": "contents: read" in top,
            "pinned": len(third_party_unpinned) == 0,
            "findings": findings,
            "passed": len(findings) == 0,
        }
    all_findings = [f for w in workflows.values() for f in w["findings"]]
    return {
        "workflows": workflows,
        "count": len(workflows),
        "passed": len(all_findings) == 0,
        "findings": all_findings,
    }


def load_classification(workspace_root: Path | None = None) -> dict[str, Any]:
    root = _root(workspace_root)
    path = root / CLASSIFICATION_PATH
    if not path.exists():
        return {"rules": [], "default": {"severity": "standard"}}
    return json.loads(path.read_text(encoding="utf-8"))


def classify_paths(paths: list[str], workspace_root: Path | None = None) -> dict[str, Any]:
    """Map changed paths -> security rules, guarantees, required verification."""
    classification = load_classification(workspace_root)
    matched_rules: dict[str, Any] = {}
    unmatched: list[str] = []
    for path in paths:
        hit = False
        for rule in classification.get("rules", []):
            for prefix in rule.get("paths", []):
                if path == prefix or path.startswith(prefix):
                    matched_rules[rule["id"]] = rule
                    hit = True
                    break
        if not hit:
            unmatched.append(path)
    guarantees: list[str] = []
    verification: list[str] = []
    for rule in matched_rules.values():
        guarantees.extend(rule.get("guarantees", []))
        verification.extend(rule.get("required_verification", []))
    severities = [r.get("severity", "standard") for r in matched_rules.values()]
    rank = {"standard": 0, "high": 1, "critical": 2}
    overall = "standard"
    for sev in severities:
        if rank.get(sev, 0) > rank[overall]:
            overall = sev
    return {
        "matched_rules": sorted(matched_rules),
        "domains": sorted({r.get("domain", "") for r in matched_rules.values()}),
        "severity": overall,
        "security_critical": overall in ("high", "critical"),
        "guarantees": sorted(set(guarantees)),
        "required_verification": sorted(set(verification)),
        "unmatched_paths": unmatched,
    }


def changed_files(
    from_commit: str | None = None,
    to_commit: str | None = None,
    workspace_root: Path | None = None,
) -> list[str]:
    root = _root(workspace_root)
    base = from_commit or "HEAD~1"
    head = to_commit or "HEAD"
    out = _run_git(root, ["diff", "--name-only", f"{base}...{head}"])
    if not out and base == "HEAD~1":
        # Single-commit history or no upstream range: fall back to working tree.
        out = _run_git(root, ["diff", "--name-only", "HEAD"])
    if not out:
        porcelain = _run_git(root, ["status", "--porcelain"])
        files: set[str] = set()
        for line in porcelain.splitlines():
            entry = line[3:].strip().strip('"')
            if " -> " in entry:  # rename: take the new path
                entry = entry.split(" -> ", 1)[1]
            if entry:
                files.add(entry)
        return sorted(files)
    return sorted({line.strip() for line in out.splitlines() if line.strip()})


def pr_analysis(
    from_commit: str | None = None,
    to_commit: str | None = None,
    workspace_root: Path | None = None,
) -> dict[str, Any]:
    """PR security analysis: files -> surface -> tests -> guarantees -> verification."""
    root = _root(workspace_root)
    files = changed_files(from_commit, to_commit, root)
    classification = classify_paths(files, root)
    tests_affected = [
        f
        for f in files
        if f.startswith("tests/") or f.startswith("noble/") or f == "pyproject.toml"
    ]
    return {
        "from": from_commit or "HEAD~1",
        "to": to_commit or "HEAD",
        "files_changed": files,
        "files_count": len(files),
        "security_surface": classification["matched_rules"],
        "domains": classification["domains"],
        "severity": classification["severity"],
        "security_critical": classification["security_critical"],
        "tests_affected": tests_affected,
        "guarantees_affected": classification["guarantees"],
        "verification_required": classification["required_verification"],
        "unmatched_paths": classification["unmatched_paths"],
    }


def guarantee_impact(paths: list[str], workspace_root: Path | None = None) -> dict[str, Any]:
    """Connect a code change to the guarantees it can affect (spec-rooted)."""
    root = _root(workspace_root)
    classification = classify_paths(paths, root)
    spec_path = root / "docs/security-spec.json"
    spec_guarantees: list[str] = []
    if spec_path.exists():
        try:
            spec = json.loads(spec_path.read_text(encoding="utf-8"))
            spec_guarantees = sorted(spec.get("guarantees", spec.get("contracts", {}).keys()))
        except (OSError, json.JSONDecodeError):
            spec_guarantees = []
    return {
        "paths": paths,
        "guarantees_affected": classification["guarantees"],
        "spec_guarantee_index": spec_guarantees,
        "severity": classification["severity"],
        "required_verification": classification["required_verification"],
    }
