"""Bugs found while executing commit 89f3ab — now permanent regressions."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=15, check=False)  # noqa: S603 - fixed local test scripts only


@pytest.mark.regression
def test_substring_scope_bypass_is_closed() -> None:
    program = "agent-skills/governance/scope-enforcement/enforce_scope.py"
    for raw in (
        "evil.com/localhost",
        "attacker.example/?repo=vishnubedi3/noble-cascade",
        "notvishnubedi3/noble-cascade",
    ):
        assert _run(sys.executable, program, raw, "static-analysis").returncode != 0


@pytest.mark.regression
def test_boolean_approval_flag_cannot_self_approve() -> None:
    program = "agent-skills/governance/human-approval/approval_gate.py"
    forged = _run(sys.executable, program, "poc-execution", "--approve")
    assert forged.returncode != 0
    assert "not a valid human approval" in forged.stdout


@pytest.mark.regression
def test_unavailable_scanners_never_exit_clean() -> None:
    for program in (
        "agent-skills/code/dependency-analysis/audit_deps.py",
        "agent-skills/security/secrets-analysis/scan_secrets.py",
        "agent-skills/security/configuration-security/scan_iac.py",
    ):
        result = _run(sys.executable, program)
        assert result.returncode == 3
        assert "UNAVAILABLE" in result.stderr
    result = _run(sys.executable, "agent-skills/code/multi-language-analysis/run_sast.py")
    assert result.returncode != 0  # cannot scan without an explicit grant + target


@pytest.mark.regression
def test_language_detection_no_longer_omits_skill_sources() -> None:
    result = _run(sys.executable, "agent-skills/code/language-detection/detect.py")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "Python" in data["languages"]
    assert "Go" in data["languages"]
    assert "JavaScript" in data["languages"]
    assert "Python / setuptools" in data["build_systems"]


@pytest.mark.regression
def test_legacy_validator_checks_real_schema_without_creating_files(tmp_path: Path) -> None:
    node = "agent-skills/reporting/vulnerability-reporting/validate-findings.cjs"
    missing = tmp_path / "missing.json"
    assert _run("node", node, str(missing)).returncode == 1
    assert not missing.exists()
    invalid = tmp_path / "malformed.json"
    invalid.write_text(json.dumps([{"id": "1", "status": "confirmed"}]))
    assert _run("node", node, str(invalid)).returncode == 1
    valid = tmp_path / "valid.json"
    valid.write_text(
        json.dumps(
            [
                {
                    "id": "synthetic",
                    "title": "test only",
                    "severity": "LOW",
                    "cwe": "CWE-89",
                    "file": "synthetic.py",
                    "line": 1,
                    "description": "test",
                    "reproduction_steps": "test",
                    "remediation": "test",
                    "status": "inconclusive",
                }
            ]
        )
    )
    assert _run("node", node, str(valid)).returncode == 0


@pytest.mark.regression
def test_no_fabricated_legacy_finding_or_unrestricted_poc() -> None:
    legacy = json.loads(
        (ROOT / "agent-skills/reporting/vulnerability-reporting/findings.json").read_text()
    )
    assert legacy == []
    poc = _run(sys.executable, "agent-skills/reporting/reproduction/poc_builder.py")
    assert poc.returncode == 3 and "UNAVAILABLE" in poc.stderr
    logger = _run(sys.executable, "agent-skills/operations/audit-logging/logger.py")
    assert logger.returncode == 3
    for old_stub in (
        "agent-skills/operations/safe-reconnaissance/recon.py",
        "agent-skills/operations/rate-limiting/ratelimit.py",
        "agent-skills/governance/escalation/escalate.py",
        "agent-skills/reasoning/confidence-assessment/confidence.py",
        "agent-skills/resilience/tool-output-validation/validate_output.py",
    ):
        refused = _run(sys.executable, old_stub)
        assert refused.returncode == 3
        assert "UNAVAILABLE" in refused.stderr


@pytest.mark.regression
def test_docker_reference_has_no_proxy_egress_or_net_admin() -> None:
    data = yaml.safe_load(
        (ROOT / "agent-skills/operations/sandbox-execution/docker-compose.yml").read_text()
    )
    services = data["services"]
    assert set(services) == {"agent-sandbox"}
    assert services["agent-sandbox"]["network_mode"] == "none"
    assert "NET_ADMIN" not in services["agent-sandbox"]["cap_drop"]
    assert "cap_add" not in services["agent-sandbox"]
    assert services["agent-sandbox"]["read_only"] is True


@pytest.mark.regression
def test_manifests_are_truthful_about_upstream() -> None:
    manifest = yaml.safe_load((ROOT / "agent-skills/manifest.yaml").read_text())
    installed = yaml.safe_load((ROOT / "agent-skills/INSTALLATION_MANIFEST.yaml").read_text())
    assert len(manifest["skills"]) == len(installed["implementations"]) == 34
    assert len(manifest["runtime_tools"]) == 2
    assert all(not x["upstream_installed"] for x in manifest["skills"])
    assert all(
        not x["installed"] and x["status"] != "INSTALLED" for x in installed["implementations"]
    )
    assert manifest["default_action"] == "deny"
