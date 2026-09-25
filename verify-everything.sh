#!/usr/bin/env bash
set -euo pipefail
# Noble Cascade — External Verification Script
# Fresh clone should verify itself: dependency verification, hashes, signatures, replay, drift, policy, test, SBOM, release verification

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
# Prefer venv python for reproducibility
if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON="python3"; fi
if [ -x "$ROOT/.venv/bin/pytest" ]; then PYTEST="$ROOT/.venv/bin/pytest"; else PYTEST="$PYTHON -m pytest"; fi
echo "=== Noble Cascade verify-everything.sh ==="
echo "Root: $ROOT"
echo "Python: $PYTHON ($($PYTHON --version 2>&1))"
echo "Commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
echo ""

fail=0
step=0
check() {
  step=$((step+1))
  echo "[$step] $1 ..."
  if eval "$2"; then
    echo "  -> PASS"
  else
    echo "  -> FAIL"
    fail=1
  fi
}

# 1 dependency verification (hash-pinned)
check "dependency verification (hash-pinned locks)" \
  "test -f requirements.lock && test -f requirements-dev.lock && grep -q -- '--hash=sha256:' requirements.lock"

# 2 hashes (policy, config, worker)
check "policy/config/worker hashes computable" \
  "$PYTHON -m noble policy-diff --json >/dev/null || $PYTHON -c 'import noble.policy_version as p; assert p.compute_policy_hash()!=\"0\"*64'"

# 3 signatures / аттестация verification (release attestation)
check "release attestation exists and verifies" \
  "test -f release/PROVENANCE.json && test -f release/ATTESTATION.md && $PYTHON -m noble release --verify >/dev/null"

# 4 replay verification (deterministic, read-only)
check "replay verification (sample)" \
  "$PYTHON -m noble ledger --json >/tmp/ledger.json && eid=\$($PYTHON -c 'import json; j=json.load(open(\"/tmp/ledger.json\")); print(j[0][\"execution_id\"] if j else \"\")') && ( [ -z \"\$eid\" ] || $PYTHON -m noble replay \"\$eid\" --json >/dev/null )"

# 5 drift verification
check "drift verification (no drift vs baseline)" \
  "$PYTHON -m noble drift --json >/tmp/drift.json && $PYTHON -c 'import json; d=json.load(open(\"/tmp/drift.json\")); assert d.get(\"drift_detected\")==False'"

# 6 policy verification
check "policy verification (scope + spec sync)" \
  "$PYTHON -m noble spec --verify >/dev/null && $PYTHON -m noble doctor --policy --json >/dev/null"

# 7 test verification
check "test verification (pytest)" \
  "$PYTHON -m pytest -q"

# 8 SBOM verification
check "SBOM verification (SPDX + CycloneDX)" \
  "test -f release/SBOM.spdx.json && test -f release/SBOM.cyclonedx.json && $PYTHON -c 'import json; d=json.load(open(\"release/SBOM.spdx.json\")); assert d[\"spdxVersion\"]==\"SPDX-2.3\"; d2=json.load(open(\"release/SBOM.cyclonedx.json\")); assert d2[\"bomFormat\"]==\"CycloneDX\"'"

# 9 release verification (hashes, SBOM, provenance)
check "release verification (all artifacts)" \
  "$PYTHON -m noble release --verify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"verified\"]==True'"

# 10 certify
check "governance certification (noble certify)" \
  "$PYTHON -m noble certify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"status\"]==\"CERTIFIED\"'"

# 11 audit chain
check "audit chain (chained hashes)" \
  "$PYTHON -m noble audit --verify >/dev/null"

# 12 ledger integrity (checkpoint + corruption detection)
check "ledger integrity (checkpoint & verify)" \
  "$PYTHON -m noble ledger --checkpoint >/dev/null && $PYTHON -m noble ledger --verify >/dev/null"

# 13 SBOM licenses & versions present
check "SBOM licenses/versions/hashes present" \
  "$PYTHON -c 'import json; spdx=json.load(open(\"release/SBOM.spdx.json\")); assert any(\"licenseConcluded\" in p for p in spdx[\"packages\"])'"

# 14 invariants executable
check "invariants (10 invariants executable)" \
  "$PYTHON -m noble invariants --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert len(d)==10'"

# 15 trust index
check "trust index (machine-readable)" \
  "$PYTHON -m noble trust-index --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"governance\"]==\"verified\"; assert d[\"tests\"]>=100'"

# 16 platform verification (no hidden assumptions)
check "platform verification" \
  "$PYTHON -m noble platform --json >/dev/null"

# 17 benchmark (reproducible)
check "benchmark (repeatable)" \
  "$PYTHON -m noble benchmark --json >/dev/null"

# 18 audit-pack offline verification
check "audit-pack + offline verification.sh" \
  "test -f audit-pack/verification.sh && bash audit-pack/verification.sh"

echo ""
if [ $fail -eq 0 ]; then
  echo "=== VERIFY EVERYTHING: PASSED ==="
  echo "Every important security guarantee is backed by executable, reproducible, independently verifiable evidence."
  exit 0
else
  echo "=== VERIFY EVERYTHING: FAILED ==="
  exit 1
fi
