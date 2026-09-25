from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

from tests.conftest import FIXTURE, ROOT


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed CLI executable, no shell
        [sys.executable, "-m", "noble", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=os.environ.copy(),
    )


@pytest.mark.integration
def test_operator_cli_full_synthetic_path() -> None:
    assert _cli("doctor").returncode == 0
    assert _cli("scope", str(FIXTURE), "--action", "local-unit-test-verification").returncode == 0
    grant_result = _cli(
        "authorize", str(FIXTURE), "--tool", "fixture-sql-verify", "--role", "security-auditor"
    )
    assert grant_result.returncode == 0, grant_result.stderr
    grant = json.loads(grant_result.stdout)["grant_id"]
    run = _cli("validate", str(FIXTURE), "--grant", grant)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["outcome"] == "success_with_findings"
    assert result["risk"]["tier"] == "MEDIUM"
    assert result["finding_ids"]
    inspected = _cli("inspect", result["finding_ids"][0])
    assert inspected.returncode == 0
    assert json.loads(inspected.stdout)["state"] == "confirmed"
    assert _cli("audit", "--verify").returncode == 0
    assert _cli("report", "--format", "json").returncode == 0


@pytest.mark.integration
def test_cli_denies_missing_grant_and_unknown_capability() -> None:
    result = _cli("scan", str(FIXTURE), "--grant", "grant-nonexistent")
    assert result.returncode == 2
    parsed = json.loads(result.stdout)
    assert parsed["state"] == "BLOCKED"
    assert parsed["error"]["code"] == "authorization_denied"
    unsafe = _cli("scope", "https://evil.example/localhost", "--action", "static-analysis")
    assert unsafe.returncode != 0
    assert (
        _cli(
            "authorize", str(FIXTURE), "--tool", "fixture-sql-verify", "--role", "operator"
        ).returncode
        == 2
    )
