from pathlib import Path

import pytest

from noble.drift import DriftDetector

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_drift_detection(tmp_path: Path):
    detector = DriftDetector(workspace_root=ROOT)
    # Ensure we can save baseline to temp location
    detector.baseline_path = tmp_path / "drift.json"
    fp = detector.save_baseline()
    assert "policy_hash" in fp
    result = detector.detect()
    assert result["drift_detected"] is False
    # Simulate drift
    modified = fp.copy()
    modified["policy_hash"] = "0" * 64
    # Manually write modified baseline and check detection
    import json

    (tmp_path / "drift2.json").write_text(json.dumps(modified))
    detector2 = DriftDetector(workspace_root=ROOT)
    detector2.baseline_path = tmp_path / "drift2.json"
    # Now current vs baseline where baseline is tampered, should show drift if we compare current to modified baseline
    # Instead, test detect_drift logic directly
    from noble.policy_version import detect_drift

    drift = detect_drift(modified, fp)
    assert "policy_hash" in drift
