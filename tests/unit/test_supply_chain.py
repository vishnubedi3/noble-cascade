from pathlib import Path

import pytest

from noble.supply_chain import supply_chain_report, verify_requirements_hashes, verify_worker_image

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_supply_chain():
    ok, msg = verify_requirements_hashes(ROOT / "requirements.lock")
    assert ok
    ok2, digest, msg2 = verify_worker_image(ROOT / "noble/builtins/worker.py")
    assert ok2 and len(digest) == 64
    report = supply_chain_report(ROOT)
    assert "overall" in report
