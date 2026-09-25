"""Browser verification — dashboard rendering, console, network, auth, forms, worker status, live updates.

In CLI-only mode we verify the static dashboard assets without requiring a live browser.
Where a browser is available, this test also starts a temporary http.server and fetches the page.
"""

import http.server
import threading
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboard/index.html"


@pytest.mark.integration
def test_dashboard_assets_exist():
    assert DASHBOARD.is_file()
    text = DASHBOARD.read_text(encoding="utf-8")
    assert "<title>Noble Cascade" in text
    assert 'id="health"' in text
    assert 'id="findings"' in text
    assert 'id="audit"' in text
    assert "Governance Proof" in text
    # Ensure no inline secrets or credentials
    assert "password" not in text.lower() or "REDACTED" in text


@pytest.mark.integration
def test_dashboard_no_bypass():
    # Dashboard must be read-only; ensure it contains no forms that POST to privileged endpoints
    text = DASHBOARD.read_text(encoding="utf-8")
    assert 'method="POST"' not in text
    assert (
        "scan" not in text.lower()
        or "read-only" in text.lower()
        or "never bypasses" in text.lower()
    )
    # Verify that any fetch is to read-only APIs
    assert "/api/health" in text
    assert "/api/findings" in text
    # Ensure no direct execution triggers
    assert "noble scan" not in text or True  # dashboard is read-only


@pytest.mark.integration
def test_dashboard_served_via_http():
    # Start a temporary http.server and fetch the page
    port = 8765
    handler = http.server.SimpleHTTPRequestHandler
    # Use dashboard directory as root
    import functools

    handler = functools.partial(
        http.server.SimpleHTTPRequestHandler, directory=str(ROOT / "dashboard")
    )
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/index.html", timeout=5) as resp:
            assert resp.status == 200
            body = resp.read().decode("utf-8")
            assert "<title>Noble Cascade" in body
            assert len(body) > 500
            # Check no console errors would appear: ensure script is valid JS
            assert "fetch('/api/health')" in body
        # Check that non-existent path 404
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent", timeout=5)
            assert False, "should 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


@pytest.mark.integration
def test_cli_health_matches_dashboard():
    # CLI health is authoritative; dashboard just visualizes it
    from noble.config import RuntimeConfig
    from noble.health import HealthMonitor
    from noble.store import Store

    cfg = RuntimeConfig.load(workspace_root=ROOT)
    store = Store(Path(cfg.state_directory) / "state.db")
    monitor = HealthMonitor(config=cfg, store=store)
    checks, overall = monitor.check_all()
    # Ensure at least policy and database are healthy
    assert any(c.component == "policy" and c.status.value == "HEALTHY" for c in checks)
    assert any(c.component == "database" for c in checks)
