# Dashboard

This is a **read-only** operator dashboard for Noble Cascade. It never bypasses the CLI policy engine.

- Health, findings, audit, metrics are fetched via `/api/*` which are read-only projections of the SQLite state.
- No mutation is performed via the browser.
- All security decisions remain in `noble/kernel.py` and `noble/engine.py`; the dashboard simply visualizes `noble health`, `noble findings`, and `noble audit` data.

To serve locally for verification:

```bash
python -m http.server 8000 --directory dashboard
# or
noble health --json | python -m json.tool
```

Browser verification is part of CI: see `tests/integration/test_browser.py` (uses `http.server` and checks rendering, console, network, auth, forms, worker status, live updates).

No web endpoint bypasses the CLI controls — verified by contract tests in `tests/api/test_api_contracts.py`.
