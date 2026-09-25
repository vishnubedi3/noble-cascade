# External Auditor Workflow — Noble Cascade

An independent reviewer needs no privileged repository access for basic
assurance: no credentials, no private services, no maintainer action. All
commands run offline after dependency installation.

```
Clone -> Setup -> Verify -> Certify -> Inspect specification
  -> Inspect guarantees -> Replay execution -> Verify audit -> Verify release
```

## 1. Clone

```bash
git clone <repository-url> noble-cascade   # full clone: source binding needs history
cd noble-cascade
git rev-parse HEAD   # record the exact commit under audit
```

## 2. Setup

```bash
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.lock
.venv/bin/pip install -e . --no-deps
.venv/bin/noble doctor
.venv/bin/noble drift --baseline
```

Expected: core runtime ready; WARN lines for uninstalled optional scanners are
normal (the runtime claims no fallback scan).

## 3. Verify (external contract)

```bash
./verify-everything.sh
echo "exit: $?"   # 0 = all 20 checks passed; 10+N = check N failed
./verify-everything.sh --json   # machine-readable summary
```

## 4. Certify

```bash
.venv/bin/noble certify --json   # status must be CERTIFIED
.venv/bin/noble trust-report     # every assertion carries ENFORCED/VERIFIED/... status
```

## 5. Inspect specification and guarantees

```bash
.venv/bin/noble spec --verify    # generated spec matches implementation
.venv/bin/noble invariants --json | head -c 2000
# read: docs/security-spec.json, docs/guarantee-matrix.md, docs/governance-proof.md
```

## 6. Replay an execution (deterministic, read-only)

```bash
.venv/bin/noble ledger --json > /tmp/ledger.json
# pick an execution_id, then:
.venv/bin/noble replay <execution_id> --json | head -c 2000
```

Replay must set `read_only: true` and never re-launch a tool.

## 7. Verify audit (offline, no credentials)

```bash
env -u GH_TOKEN -u GITHUB_TOKEN bash audit-pack/verification.sh
.venv/bin/noble audit --verify
.venv/bin/noble ledger --verify
```

## 8. Verify release (no drift)

```bash
.venv/bin/noble release --verify --json   # verified must be true
.venv/bin/noble governance --baseline-verify --json
.venv/bin/noble governance --workflow-audit --json
```

`release --verify` proves certified source == tagged source == built source ==
attested source; any mismatch fails with a named reason.

## What the auditor cannot check (and must not assume)

- Branch protection, required checks, secret scanning, and CODEOWNERS teams are
  owner-level GitHub settings (MANUAL). The checklist for them is
  `docs/maintainer-security-checklist.md`; automation cannot attest them.
- `noble trust-report` marks each assertion; anything MANUAL/EXPERIMENTAL/
  UNSUPPORTED is explicitly not claimed as enforcement.
