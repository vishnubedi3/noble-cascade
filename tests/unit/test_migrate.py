from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.migrate import MigrationManager
from noble.store import Store

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_migration_idempotent(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    mgr = MigrationManager(store)
    assert mgr.test_migration_idempotent()
    assert mgr.current_version() >= 1
    # Apply again
    applied = mgr.migrate()
    # Second time should be empty or not fail
    assert isinstance(applied, list)
