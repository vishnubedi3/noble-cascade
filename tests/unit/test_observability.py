from pathlib import Path

import pytest

from noble.config import RuntimeConfig
from noble.observability import EventCategory, ObservabilitySink
from noble.store import Store

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.unit
def test_observability_categories(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state/state.db")
    sink = ObservabilitySink(store=store)
    for cat in EventCategory:
        evt = sink.emit(cat, "req-test", f"test {cat.value}")
        assert evt.category == cat
    timeline = sink.timeline("req-test")
    assert len(timeline) == len(EventCategory)


@pytest.mark.unit
def test_timeline_reconstruction(tmp_path: Path):
    loaded = RuntimeConfig.load(workspace_root=ROOT)
    config = RuntimeConfig(
        workspace_root=str(ROOT),
        state_directory=str(tmp_path / "state2"),
        network_enabled=False,
        limits=loaded.limits,
    )
    store = Store(tmp_path / "state2/state.db")
    sink = ObservabilitySink(store=store)
    sink.emit(EventCategory.REQUEST, "req-abc", "request")
    sink.emit(EventCategory.POLICY, "req-abc", "policy")
    sink.emit(EventCategory.TOOL, "req-abc", "tool")
    tl = sink.timeline("req-abc")
    assert [e["category"] for e in tl] == ["REQUEST", "POLICY", "TOOL"]
