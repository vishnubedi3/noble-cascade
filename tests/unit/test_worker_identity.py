import pytest

from noble.worker_identity import WorkerLifecycle, WorkerRegistry


@pytest.mark.unit
def test_worker_lifecycle():
    reg = WorkerRegistry()
    w = reg.create_worker()
    assert w.lifecycle == WorkerLifecycle.ACTIVATE
    assert w.worker_id.startswith("worker-")
    assert reg.is_active(w.worker_id)
    reg.retire(w.worker_id)
    assert not reg.is_active(w.worker_id)
    assert reg.get(w.worker_id).lifecycle == WorkerLifecycle.RETIRE
    reg.destroy(w.worker_id)
    assert reg.get(w.worker_id).lifecycle == WorkerLifecycle.DESTROYED
    assert reg.get(w.worker_id).destruction_time is not None


@pytest.mark.unit
def test_no_anonymous_worker():
    reg = WorkerRegistry()
    with pytest.raises(RuntimeError):
        reg.assert_can_execute("worker-unknown")
    w = reg.create_worker()
    reg.assert_can_execute(w.worker_id)
    reg.retire(w.worker_id)
    with pytest.raises(RuntimeError):
        reg.assert_can_execute(w.worker_id)
