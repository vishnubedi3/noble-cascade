from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from noble import doctor


@pytest.mark.unit
def test_doctor_reports_missing_dependency_without_crashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda module: None if module == "yaml" else original(module),
    )
    diagnostics, healthy = doctor.run_doctor()
    assert not healthy
    assert any(d.component == "PyYAML" and d.status == "FAIL" for d in diagnostics)
    assert "requirements.lock" in diagnostics[0].message


@pytest.mark.unit
def test_doctor_checks_core_and_audit_with_isolated_root(tmp_path: Path) -> None:
    # Doctor reads the trusted repo policy/config, but allows the test to prove
    # a missing local manifest produces a structured diagnostic.
    diagnostics, healthy = doctor.run_doctor(root=tmp_path)
    assert not healthy
    assert any(d.status == "FAIL" for d in diagnostics)
