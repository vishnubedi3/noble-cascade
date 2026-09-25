from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.policy_version import (
    compute_config_hash,
    compute_policy_fingerprint,
    compute_policy_hash,
    compute_worker_digest,
    detect_drift,
)
from noble.scope import ScopeEngine

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_policy_hashes():
    cfg = RuntimeConfig.load(workspace_root=ROOT)
    scope = ScopeEngine.from_file(workspace_root=ROOT)
    ph = compute_policy_hash(scope)
    ch = compute_config_hash(cfg)
    wd = compute_worker_digest()
    assert len(ph) == 64
    assert len(ch) == 64
    assert len(wd) == 64


@pytest.mark.unit
def test_fingerprint_and_drift(tmp_path: Path):
    cfg = RuntimeConfig.load(workspace_root=ROOT)
    scope = ScopeEngine.from_file(workspace_root=ROOT)
    fp = compute_policy_fingerprint(cfg, scope)
    assert "policy_version" in fp
    # No drift when comparing to itself
    assert detect_drift(fp, fp) == {}
    # Detect change
    modified = fp.copy()
    modified["policy_hash"] = "0" * 64
    drift = detect_drift(fp, modified)
    assert "policy_hash" in drift
