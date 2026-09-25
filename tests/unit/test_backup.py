from pathlib import Path

import pytest

from noble.backup import BackupManager
from noble.config import RuntimeConfig
from noble.engine import NobleEngine
from noble.store import Store
from noble.targets import normalize_target
from tests.conftest import FIXTURE, make_scan_request

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_backup_and_restore(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    engine = NobleEngine(config, store=store, actor_identity="researcher")
    target = normalize_target(str(FIXTURE), workspace_root=str(ROOT))
    grant = engine.authorizer.issue(
        issuer="a",
        principal="researcher",
        role="operator",
        capability="scan",
        action="static-analysis",
        target=target,
        purpose="security-research",
        privileges=("scan",),
    )
    engine.run(make_scan_request(grant.grant_id, target=str(FIXTURE)))
    mgr = BackupManager(store, workspace_root=ROOT)
    dest = tmp_path / "backup"
    info = mgr.create_backup(dest)
    assert info["findings"] >= 1
    ok, msg = mgr.verify_backup(dest)
    assert ok
    # Restore to new db
    new_db = tmp_path / "restored/state.db"
    new_db.parent.mkdir(parents=True)
    mgr.restore(dest, target_db=new_db)
    restored = Store(new_db)
    assert len(restored.list_findings()) >= 1
    assert restored.verify_audit()[0]
