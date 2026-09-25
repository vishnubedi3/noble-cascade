from pathlib import Path

import pytest
import yaml

from noble.config_schema import (
    check_compatibility,
    migrate_runtime_config,
    validate_runtime_config,
    validate_scope_policy,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_runtime_schema():
    data = yaml.safe_load((ROOT / "config/runtime.yaml").read_text())
    errors = validate_runtime_config(data)
    assert errors == []
    # Invalid: missing version
    bad = {"state_directory": ".noble", "network_enabled": False, "limits": {}}
    assert len(validate_runtime_config(bad)) > 0


@pytest.mark.unit
def test_scope_schema():
    data = yaml.safe_load(
        (ROOT / "agent-skills/governance/scope-enforcement/scope-policy.yaml").read_text()
    )
    assert validate_scope_policy(data) == []


@pytest.mark.unit
def test_migration_and_compatibility():
    assert migrate_runtime_config({"version": 1})["version"] == 1
    assert check_compatibility(1, 1)[0] is True
    assert check_compatibility(1, 2)[0] is False
