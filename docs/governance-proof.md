# Governance Proof — Evidence, Not Trust

> Did Noble Cascade remain inside policy?

An external reviewer can answer using evidence alone, without trusting the operator's word.

## How to verify a single execution

1. **Find the execution**

```bash
noble ledger --json | jq '.[] | select(.execution_id=="lease-...")'
# or
noble audit --json | jq '.events[] | select(.request_id=="req-...")'
```

Each execution records:

```
request_id, execution_id, worker_id, tool_run_id,
evidence_id, finding_id, report_id, audit_event_ids,
policy_version, policy_hash, configuration_hash, worker_image_digest
```

2. **Check policy that governed it**

```bash
noble drift --json
# Compare stored policy_hash vs current policy_hash
# If they differ, drift is explicit — the execution's policy is still known via its hash
sha256sum agent-skills/governance/scope-enforcement/scope-policy.yaml
sha256sum config/runtime.yaml
# Compare to ledger's policy_hash / configuration_hash
```

Every `ExecutionResult` includes `policy_version`, `policy_hash`, `configuration_hash`, `worker_image_digest` — see `noble inspect req-...` .

3. **Replay the decision without re-executing**

```bash
noble replay lease-... --json
# or
noble replay req-... --json
```

Replay is **read-only**: it reconstructs request, target, policy, worker, tool versions, evidence, findings, report from persisted state. No tool is re-launched.

Example replay output:

```json
{
  "request_id": "req-abc",
  "execution_id": "lease-xyz",
  "state": "COMPLETED",
  "outcome": "success_with_findings",
  "target": "/path",
  "action": "static-analysis",
  "tool": "static-code-scan",
  "risk": {"tier": "LOW"},
  "evidence": [...],
  "findings": [...],
  "policy": {"policy_hash": "...", "worker_image_digest": "..."},
  "read_only": true
}
```

4. **Verify evidence and findings**

```bash
noble inspect finding-... --json | jq '.provenance'
# Check evidence_ids -> noble inspect ev-... --json
# Verify hashes:
python - <<'PY'
import hashlib, json
ev = json.load(open("/tmp/ev.json"))
assert hashlib.sha256(json.dumps(ev, sort_keys=True).encode()).hexdigest() == ev["content_hash"]
PY
```

Signed findings: `finding_hash`, `evidence_hash`, `report_hash` are SHA-256 over canonical JSON (`noble/signing.py`). Tampering is detectable.

5. **Verify audit chain**

```bash
noble audit --verify
# Returns VALID and count, or indicates tampering
# Audit is a SHA-256 hash chain (prev_hash -> event_hash) stored in SQLite
# Manual check:
sqlite3 .noble/state.db "SELECT prev_hash, event_hash, data FROM audit_events ORDER BY sequence"
```

6. **Check worker identity**

```bash
noble ledger --json | jq '.[].worker_id'
# Each worker has a unique worker_id, image_digest, runtime_version, tool_versions, creation/destruction time
# No anonymous worker can execute privileged work (see WorkerRegistry.assert_can_execute)
# Retired workers never receive jobs: `noble/doctor --workers`
```

7. **Check policy explanations**

```bash
noble simulate ./tests/fixtures/sql_injection.py --action static-analysis --tool static-code-scan
# Output:
# Scope: ALLOW (rule: directory) — path is under root
# Policy: Authorized Security Research Scope Rule: directory Reason: ...
# Risk: LOW Approval: NOT_REQUIRED Execution: ALLOWED
```

Every denial explains: `Denied. Reason: Target outside scope. Policy: scope-policy.yaml Rule: denied.external.production`

Machines enforce; humans investigate.

## Full timeline reconstruction

```bash
noble replay req-... --json | jq '.audit_events'
# Or observability timeline:
python - <<'PY'
from noble.store import Store
from pathlib import Path
from noble.config import RuntimeConfig
cfg = RuntimeConfig.load()
store = Store(Path(cfg.state_directory)/"state.db")
print(store.list_audit(limit=100))
PY
```

Observability categories: `REQUEST, POLICY, AUTH, WORKER, TOOL, SANDBOX, EVIDENCE, REPORT, ERROR, SECURITY` — see `noble/observability.py`.

## What an auditor can conclude

If:

- `noble audit --verify` is VALID,
- `noble replay` reconstructs the chain without gaps,
- `policy_hash` in the ledger matches the policy file at that version (or drift is explicitly reported via `noble drift`),
- `worker_image_digest` matches the worker file,
- `finding_hash` matches recomputed hash,
- `scope` decision was `ALLOW` via an anchored rule (not substring),
- `authorization` grant was exact principal/target/action/purpose/time,

Then the platform's claim — *every security action remained inside policy* — is mechanically verified.

If any check fails, the system fails closed and records the failure as `BLOCKED`, `FAILED`, or `INVALID_*` with an audit event. No silent fallback.

## Evidence locations

- State DB: `.noble/state.db` (owner-only 0600, directory 0700)
- Backups: `noble backup --create DIR` creates hash-verified `noble_backup.json` + `state.db.backup` + `backup.sha256`
- Ledger: `ledger` table in SQLite, also via `noble ledger`
- Spec: `docs/security-spec.json` (machine-readable, synchronized via `noble spec --verify`)
- Guarantee matrix: `docs/guarantee-matrix.md` with executable evidence per subsystem
- Health: `noble health` and `noble doctor --runtime --workers --sandbox --policy --network --security --integrity --replay`

No undocumented assumptions. No inferred guarantees.
