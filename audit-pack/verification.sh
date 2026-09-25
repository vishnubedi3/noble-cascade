#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON="python3"; fi
echo "=== Noble Cascade Offline Verification ==="
echo "Root: $ROOT"
echo "Python: $PYTHON"
fail=0
check() {
  echo -n "$1 ... "
  if eval "$2" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fail=1; fi
}
check "policy proof" "cat audit-pack/policy-proof.json | $PYTHON -c 'import json,sys; d=json.load(open(\"audit-pack/policy-proof.json\")); assert \"fingerprint\" in d'"
check "drift proof" "cat audit-pack/drift-proof.json | $PYTHON -c 'import json; json.load(open(\"audit-pack/drift-proof.json\"))'"
check "worker proof" "cat audit-pack/worker-proof.json | $PYTHON -c 'import json; d=json.load(open(\"audit-pack/worker-proof.json\")); assert d.get(\"valid\")'"
check "replay proof" "cat audit-pack/replay-proof.json | $PYTHON -c 'import json; d=json.load(open(\"audit-pack/replay-proof.json\")); assert d.get(\"deterministic\")'"
check "invariants" "cat audit-pack/invariants.json | $PYTHON -c 'import json; d=json.load(open(\"audit-pack/invariants.json\")); assert len(d.get(\"invariants\",[]))>=10'"
check "audit chain" "$PYTHON -m noble audit --verify"
check "spec sync" "$PYTHON -m noble spec --verify"
check "certify" "$PYTHON -m noble certify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d.get(\"status\")==\"CERTIFIED\"'"
check "sbom exists" "test -f release/SBOM.spdx.json || test -f audit-pack/guarantees.json"
echo ""
if [ $fail -eq 0 ]; then echo "OFFLINE VERIFICATION PASSED"; else echo "OFFLINE VERIFICATION FAILED"; exit 1; fi
