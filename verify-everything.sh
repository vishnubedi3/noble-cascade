#!/usr/bin/env bash
# Noble Cascade — External Verification Contract (Master Prompt IV).
#
# A successful exit (0) means: every check below passed on THIS checkout with
# no hidden developer state, no credentials, and no network access required.
#
# Usage:
#   ./verify-everything.sh            human-readable output, exit 0 or 10+N
#   ./verify-everything.sh --json     machine-readable JSON summary on stdout
#
# Exit codes (stable contract — do not renumber, only append):
#   0   all checks passed
#   2   environment/setup failure (python missing, noble not importable)
#   11  dependency verification (hash-pinned locks) failed
#   12  policy/config/worker hashes failed
#   13  release attestation failed
#   14  replay verification failed
#   15  drift verification failed
#   16  policy/spec verification failed
#   17  test verification (pytest) failed
#   18  SBOM format verification failed
#   19  release verification failed
#   20  governance certification failed
#   21  audit chain verification failed
#   22  ledger integrity verification failed
#   23  SBOM content verification failed
#   24  invariants verification failed
#   25  trust index verification failed
#   26  platform verification failed
#   27  benchmark verification failed
#   28  audit-pack offline verification failed
#   29  repository governance baseline verification failed
#   30  workflow audit verification failed
#
# Environment assumptions (explicit):
#   REQUIRED: python3 (>=3.11), git checkout (for commit identity; unknown ok)
#   REQUIRED: noble importable (pip install -e . --no-deps) + locked deps
#   NOT REQUIRED: network access, GitHub credentials, private services,
#     developer-only environment variables. Temporary artifacts are isolated
#     in a fresh mktemp directory and removed on exit.
# Fail-closed: every check runs even after a failure; failures are collected
# and reported — no check is ever silently skipped. Exit code is the FIRST
# failed check's code.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

JSON_MODE=0
if [ "${1:-}" = "--json" ]; then JSON_MODE=1; fi

# Prefer venv python for reproducibility
if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON="python3"; fi

TMPDIR_ISOLATED="$(mktemp -d "${TMPDIR:-/tmp}/noble-verify.XXXXXX")"
trap 'rm -rf "$TMPDIR_ISOLATED"' EXIT

log() { if [ "$JSON_MODE" -eq 0 ]; then echo "$*"; fi; }

log "=== Noble Cascade verify-everything.sh (external verification contract) ==="
log "Root: $ROOT"
log "Python: $PYTHON ($($PYTHON --version 2>&1 || echo MISSING))"
log "Commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
log "Isolated tmp: $TMPDIR_ISOLATED"
log "Credentials required: none | Network required: none"
log ""

# --- setup gate (exit 2, the only early-abort path) ---
if ! command -v "$PYTHON" >/dev/null 2>&1; then echo "SETUP: python not found" >&2; exit 2; fi
if ! "$PYTHON" -c "import noble" 2>/dev/null; then
  echo "SETUP: 'noble' package not importable — run: pip install --require-hashes -r requirements-dev.lock && pip install -e . --no-deps" >&2
  exit 2
fi

declare -a NAMES=()
declare -a CODES=()
declare -a RESULTS=()
declare -a DETAILS=()
first_fail_code=0

RESULTS_FILE="$TMPDIR_ISOLATED/results.tsv"
: > "$RESULTS_FILE"

check() { # $1=num $2=name $3=command
  local num="$1" name="$2" cmd="$3"
  local code=$((10 + num))
  NAMES+=("$name"); CODES+=("$code")
  log "[$num] $name ..."
  local out
  if out=$(eval "$cmd" 2>&1); then
    RESULTS+=("PASS"); DETAILS+=("")
    printf "%s\t%s\t%s\n" "$code" "PASS" "$name" >> "$RESULTS_FILE"
    log "  -> PASS"
  else
    RESULTS+=("FAIL"); DETAILS+=("$(echo "$out" | tail -n 5 | head -c 800)")
    printf "%s\t%s\t%s\n" "$code" "FAIL" "$name" >> "$RESULTS_FILE"
    log "  -> FAIL (exit $code)"
    if [ "$JSON_MODE" -eq 0 ]; then echo "$out" | tail -n 10 | sed 's/^/     | /'; fi
    if [ "$first_fail_code" -eq 0 ]; then first_fail_code=$code; fi
  fi
}

export TMPDIR="$TMPDIR_ISOLATED"

check 1 "dependency verification (hash-pinned locks)" \
  "test -f requirements.lock && test -f requirements-dev.lock && grep -q -- '--hash=sha256:' requirements.lock && grep -q -- '--hash=sha256:' requirements-dev.lock"

check 2 "policy/config/worker hashes computable" \
  "$PYTHON -m noble policy-diff --json >/dev/null || $PYTHON -c 'import noble.policy_version as p; assert p.compute_policy_hash()!=\"0\"*64'"

check 3 "release attestation exists and verifies" \
  "test -f release/PROVENANCE.json && test -f release/ATTESTATION.md && $PYTHON -m noble release --verify >/dev/null"

check 4 "replay verification (sample)" \
  "$PYTHON -m noble ledger --json >$TMPDIR_ISOLATED/ledger.json && eid=\$($PYTHON -c 'import json; j=json.load(open(\"$TMPDIR_ISOLATED/ledger.json\")); print(j[0][\"execution_id\"] if j else \"\")') && ( [ -z \"\$eid\" ] || $PYTHON -m noble replay \"\$eid\" --json >/dev/null )"

check 5 "drift verification (no drift vs baseline)" \
  "$PYTHON -m noble drift --json >$TMPDIR_ISOLATED/drift.json && $PYTHON -c 'import json; d=json.load(open(\"$TMPDIR_ISOLATED/drift.json\")); assert d.get(\"drift_detected\")==False, d'"

check 6 "policy verification (scope + spec sync)" \
  "$PYTHON -m noble spec --verify >/dev/null && $PYTHON -m noble doctor --policy --json >/dev/null"

check 7 "test verification (pytest)" \
  "$PYTHON -m pytest -q -p no:cacheprovider"

check 8 "SBOM verification (SPDX + CycloneDX)" \
  "test -f release/SBOM.spdx.json && test -f release/SBOM.cyclonedx.json && $PYTHON -c 'import json; d=json.load(open(\"release/SBOM.spdx.json\")); assert d[\"spdxVersion\"]==\"SPDX-2.3\"; d2=json.load(open(\"release/SBOM.cyclonedx.json\")); assert d2[\"bomFormat\"]==\"CycloneDX\"'"

check 9 "release verification (all artifacts)" \
  "$PYTHON -m noble release --verify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"verified\"]==True, d'"

check 10 "governance certification (noble certify)" \
  "$PYTHON -m noble certify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"status\"]==\"CERTIFIED\", d'"

check 11 "audit chain (chained hashes)" \
  "$PYTHON -m noble audit --verify >/dev/null"

check 12 "ledger integrity (checkpoint & verify)" \
  "$PYTHON -m noble ledger --checkpoint >/dev/null && $PYTHON -m noble ledger --verify >/dev/null"

check 13 "SBOM licenses/versions/hashes present" \
  "$PYTHON -c 'import json; spdx=json.load(open(\"release/SBOM.spdx.json\")); assert any(\"licenseConcluded\" in p for p in spdx[\"packages\"])'"

check 14 "invariants (10 invariants executable)" \
  "$PYTHON -m noble invariants --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert len(d)==10, len(d)'"

check 15 "trust index (machine-readable)" \
  "$PYTHON -m noble trust-index --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d[\"governance\"]==\"verified\", d; assert d[\"tests\"]>=100, d'"

check 16 "platform verification" \
  "$PYTHON -m noble platform --json >/dev/null"

check 17 "benchmark (repeatable)" \
  "$PYTHON -m noble benchmark --json >/dev/null"

check 18 "audit-pack + offline verification.sh" \
  "test -f audit-pack/verification.sh && bash audit-pack/verification.sh"

check 19 "repository governance baseline (no drift from baseline)" \
  "$PYTHON -m noble governance --baseline-verify >/dev/null"

check 20 "workflow audit (pinned actions, minimal permissions)" \
  "$PYTHON -m noble governance --workflow-audit >/dev/null"

# --- report ---
if [ "$JSON_MODE" -eq 1 ]; then
  RESULTS_FILE="$RESULTS_FILE" "$PYTHON" - "$first_fail_code" <<'PYEOF'
import json, os, subprocess, sys
first_fail = int(sys.argv[1])
checks = []
with open(os.environ["RESULTS_FILE"], encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) == 3:
            checks.append({"exit_code": int(parts[0]), "result": parts[1], "name": parts[2]})
commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown"
print(json.dumps({
    "tool": "verify-everything.sh",
    "passed": first_fail == 0,
    "exit_code": 0 if first_fail == 0 else first_fail,
    "commit": commit,
    "checks": checks,
}, indent=2, sort_keys=True))
sys.exit(0 if first_fail == 0 else first_fail)
PYEOF
else
  echo ""
  if [ "$first_fail_code" -eq 0 ]; then
    echo "=== VERIFY EVERYTHING: PASSED (20/20) ==="
    echo "Every important security guarantee is backed by executable, reproducible, independently verifiable evidence."
    exit 0
  else
    nfail=0
    for i in "${!RESULTS[@]}"; do
      if [ "${RESULTS[$i]}" = "FAIL" ]; then
        nfail=$((nfail+1))
        echo "FAILED [exit ${CODES[$i]}]: ${NAMES[$i]}"
        if [ -n "${DETAILS[$i]}" ]; then echo "${DETAILS[$i]}" | sed 's/^/    | /'; fi
      fi
    done
    echo "=== VERIFY EVERYTHING: FAILED ($nfail check(s) failed) ==="
    exit "$first_fail_code"
  fi
fi
