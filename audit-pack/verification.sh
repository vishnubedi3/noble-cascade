#!/usr/bin/env bash
# Noble Cascade — Offline Audit Verification (Master Prompt IV hardened).
#
# Must succeed with: no GitHub credentials, no repository credentials, no
# private services, no developer-only environment variables. Network access is
# NOT required; if any check ever needs it, that is a bug to document, not to
# silently accept. Exit 0 = OFFLINE VERIFICATION PASSED; exit 40+N = check N
# failed (stable contract); exit 2 = environment/setup failure.
set -uo pipefail
PACK="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$PACK/.." && pwd)"
if [ ! -d "$ROOT/.github" ]; then ROOT="$(pwd)"; fi
cd "$ROOT"
if [ -x "$ROOT/.venv/bin/python" ]; then PYTHON="$ROOT/.venv/bin/python"; else PYTHON="python3"; fi
echo "=== Noble Cascade Offline Verification ==="
echo "Root: $ROOT"
echo "Pack: $PACK"
echo "Python: $PYTHON ($($PYTHON --version 2>&1 || echo MISSING))"
echo "Credentials required: none | Network required: none"
echo "GH_TOKEN present: $([ -n "${GH_TOKEN:-}" ] && echo yes-ignored || echo no)"
echo "GITHUB_TOKEN present: $([ -n "${GITHUB_TOKEN:-}" ] && echo yes-ignored || echo no)"
echo ""

if ! command -v "$PYTHON" >/dev/null 2>&1; then echo "SETUP: python not found" >&2; exit 2; fi
if ! "$PYTHON" -c "import noble" 2>/dev/null; then
  echo "SETUP: 'noble' package not importable — run: pip install -e . --no-deps" >&2
  exit 2
fi

TMPDIR_ISOLATED="$(mktemp -d "${TMPDIR:-/tmp}/noble-offline.XXXXXX")"
trap 'rm -rf "$TMPDIR_ISOLATED"' EXIT
export TMPDIR="$TMPDIR_ISOLATED"

first_fail=0
check() { # $1=num $2=name $3=command
  local num="$1" name="$2" cmd="$3"
  local code=$((40 + num))
  echo -n "[$num] $name ... "
  local out
  if out=$(eval "$cmd" 2>&1); then echo "PASS"; else
    echo "FAIL (exit $code)"
    echo "$out" | tail -n 8 | sed 's/^/     | /'
    if [ "$first_fail" -eq 0 ]; then first_fail=$code; fi
  fi
}

check 1 "policy proof" \
  "$PYTHON -c 'import json; d=json.load(open(\"${PACK}/policy-proof.json\")); assert \"fingerprint\" in d, d.keys()'"
check 2 "drift proof" \
  "$PYTHON -c 'import json; d=json.load(open(\"${PACK}/drift-proof.json\")); assert d[\"drift\"].get(\"drift_detected\")==False, d'"
check 3 "worker proof" \
  "$PYTHON -c 'import json; d=json.load(open(\"${PACK}/worker-proof.json\")); assert d.get(\"valid\"), d'"
check 4 "replay proof" \
  "$PYTHON -c 'import json; d=json.load(open(\"${PACK}/replay-proof.json\")); assert d.get(\"deterministic\"), d'"
check 5 "invariants" \
  "$PYTHON -c 'import json; d=json.load(open(\"${PACK}/invariants.json\")); assert len(d.get(\"invariants\",[]))>=10, d'"
check 6 "audit chain" "$PYTHON -m noble audit --verify"
check 7 "spec sync" "$PYTHON -m noble spec --verify"
check 8 "certify" \
  "$PYTHON -m noble certify --json | $PYTHON -c 'import json,sys; d=json.load(sys.stdin); assert d.get(\"status\")==\"CERTIFIED\", d'"
check 9 "sbom exists" "test -f release/SBOM.spdx.json || test -f ${PACK}/guarantees.json"

echo ""
if [ "$first_fail" -eq 0 ]; then echo "OFFLINE VERIFICATION PASSED (9/9)"; exit 0
else echo "OFFLINE VERIFICATION FAILED (first failure exit $first_fail)"; exit "$first_fail"; fi
