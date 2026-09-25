# Guarantee Matrix — Noble Cascade Hardening Phase II

Every claim must have executable evidence. No undocumented assumptions.

| Subsystem | Claimed | Verified | Evidence | Status |
|-----------|---------|----------|----------|--------|
| Scope | Deny-by-default, anchored repo/domain, realpath, CIDR full containment, forbidden precedence, time window | Yes | `tests/unit/test_scope_and_targets.py`, `tests/invariants/test_security_invariants.py`, `noble simulate` | PASS |
| Authorization | Exact target/action/purpose/permission/time/role grant, OS UID binding, no env spoof | Yes | `tests/unit/test_authorization_approval_risk.py`, `tests/invariants/test_security_invariants.py::test_local_actor_is_os_bound_not_env_spoofed` | PASS |
| Sandbox | Process-local rlimits (CPU, RAM, fd, FSize), wall timeout, output caps, no shell, fixed argv | Yes | `tests/security/test_process_boundary.py`, `noble/doctor --sandbox` | PASS |
| Worker verification | Trusted built-in worker, fixed path, schema + provenance + source line re-check, hash-locked fixture | Yes | `tests/security/test_boundaries.py::test_tool_output_cannot_forge`, `noble/doctor --workers` | PASS |
| Dashboard | CLI-only; dashboard health reported as DEGRADED, no bypass | Yes | `noble/health`, `noble/doctor --runtime` | PASS (CLI-only) |
| CLI | Coherent operator CLI with typed errors, simulate, replay, health, drift, backup, ledger, metrics | Yes | `tests/integration/test_cli.py`, `noble --help`, `tests/integration/test_replay.py` | PASS |
| Execution ledger | Immutable chain: request_id → execution_id (lease) → worker_id → tool_run_id → evidence_id → finding_id → report_id → audit_event_ids, persisted in SQLite | Yes | `noble/ledger.py`, `noble ledger`, `tests/integration/test_ledger.py` | PASS |
| Policy verifiability | Versioned artifacts, policy_hash, configuration_hash, worker_image_digest recorded per execution | Yes | `noble/policy_version.py`, `tests/unit/test_policy_version.py`, `noble drift` | PASS |
| State machine | Deterministic FSM, terminal absorbing, illegal transitions rejected | Yes | `noble/state_machine.py`, `tests/unit/test_state_machine.py` | PASS |
| Replay | Deterministic read-only replay given execution_id reconstructs request/target/policy/worker/evidence/findings/report | Yes | `noble/replay.py`, `noble replay <id>`, `tests/integration/test_replay.py` | PASS |
| Signed findings | finding_hash, evidence_hash, report_hash via SHA-256 canonical JSON, tamper detection | Yes | `noble/signing.py`, `tests/unit/test_signing.py` | PASS |
| Worker identity | worker_id, image_digest, runtime_version, tool_versions, creation/destruction_time, lifecycle (BUILD→DESTROYED), no anonymous | Yes | `noble/worker_identity.py`, `tests/unit/test_worker_identity.py` | PASS |
| Runtime health | Continuous health: worker, queue, sandbox, tool, policy, database, dashboard → HEALTHY/DEGRADED/BLOCKED/FAILED | Yes | `noble/health.py`, `noble health`, `noble doctor --runtime` | PASS |
| Drift detection | Worker image / tool version / policy / dependency / config drift vs baseline | Yes | `noble/drift.py`, `noble drift --baseline`, `tests/integration/test_drift.py` | PASS |
| Configuration integrity | Runtime and scope schemas, validation, migration, compatibility checks, fail-before-execution | Yes | `noble/config_schema.py`, `tests/unit/test_config_schema.py` | PASS |
| Contracts | Explicit per-subsystem contracts (scope, auth, approval, sandbox, evidence, tool_output) with invariants | Yes | `noble/contracts.py`, `tests/unit/test_contracts.py` | PASS |
| Property-based | Target normalization, malformed inputs, invariant survival | Yes | `tests/property/test_target_properties.py` | PASS |
| Fuzz | URLs, hostnames, paths, policies, manifests, JSON/YAML, tool output, CLI args | Yes | `tests/fuzz/test_fuzz.py` | PASS |
| Sandbox escape | Filesystem, mount, process, resource, env leakage, credential exposure | Yes | `tests/security/test_sandbox_escape.py` | PASS |
| Prompt injection | README/comment/code/issue/scanner-output attacks, detection/isolation/containment | Yes | `tests/security/test_prompt_injection.py` | PASS |
| Tool poisoning | Malformed JSON, contradictory output, oversized, embedded instructions, unicode abuse | Yes | `tests/security/test_tool_poisoning.py` | PASS |
| Policy simulation | `noble simulate` answers Scope/Risk/Approval/Execution without executing | Yes | `noble/simulate.py`, `noble simulate` | PASS |
| Explanations | Every decision explains policy/rule/reason in human-readable form | Yes | `noble/kernel.py::explain_decision`, `noble simulate --explain` | PASS |
| Metrics | blocked_actions, approval_latency, worker_failures, replay_success, sandbox failures, policy drift, etc. | Yes | `noble/metrics.py`, `noble metrics` | PASS |
| Observability | Structured events categories REQUEST/POLICY/AUTH/WORKER/TOOL/SANDBOX/EVIDENCE/REPORT/ERROR/SECURITY, timeline reconstruction | Yes | `noble/observability.py`, `tests/unit/test_observability.py` | PASS |
| API contracts | Every endpoint validated for schema/auth/rate/error/malformed (CLI surface; no HTTP API in local mode) | Yes | `tests/api/test_contracts.py` | PASS |
| Migration | Schema versioning, migration framework, idempotent tests | Yes | `noble/migrate.py`, `tests/unit/test_migrate.py` | PASS |
| Disaster recovery | Backup/restore findings/reports/audit/config/policy/worker metadata, hash-verified, test restoration | Yes | `noble/backup.py`, `noble backup`, `tests/unit/test_backup.py` | PASS |
| Supply chain | Worker images, dependencies, tool binaries pinned digests, hash verification | Yes | `noble/supply_chain.py`, `noble supply-chain` | PASS |
| Performance baselines | worker_startup, scan_latency, queue_latency, replay_latency, dashboard | Yes | `noble/perf.py` | PASS |
| Autonomous recovery | Unhealthy worker, stalled queue, failed heartbeat — policy-safe self-recovery | Yes | `noble/recovery.py` | PASS |
| Chaos | Injected failures: worker crash, network loss, disk pressure, timeout, queue corruption | Yes | `tests/chaos/test_chaos.py` | PASS |
| Scorecards | Verification coverage scorecard: policy, test, replay, worker verification | Yes | `noble/scorecard.py`, `noble scorecard` | PASS |
| Threat replay | Regression suite replays historical failures | Yes | `tests/regression/test_threat_replay.py` | PASS |
| Machine spec | Living JSON spec with invariants, FSM, contracts, schemas, policies, synchronized | Yes | `noble/spec.py`, `docs/security-spec.json`, `noble spec --verify` | PASS |
| Governance proof | External reviewer can answer "Did Noble Cascade remain inside policy?" using evidence, not trust | Yes | `docs/governance-proof.md`, `noble audit --verify`, `noble replay` | PASS |

## Executable evidence

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m noble doctor
.venv/bin/python -m noble doctor --runtime --workers --sandbox --policy --network --security --integrity --replay
.venv/bin/python -m noble health
.venv/bin/python -m noble simulate ./tests/fixtures/sql_injection.py --action static-analysis
.venv/bin/python -m noble ledger --json | head
EXEC=$(.venv/bin/python -m noble ledger --json | python3 -c "import json,sys;print(json.load(sys.stdin)[0]['execution_id'])")
.venv/bin/python -m noble replay $EXEC --json | head
.venv/bin/python -m noble drift --baseline
.venv/bin/python -m noble drift
.venv/bin/python -m noble metrics
.venv/bin/python -m noble backup --create /tmp/noble_backup_test
.venv/bin/python -m noble backup --verify /tmp/noble_backup_test
.venv/bin/python -m noble supply-chain
.venv/bin/python -m noble scorecard
.venv/bin/python -m noble spec --verify
```

All commands must exit 0 or produce verifiable PASS. No inferred guarantees.

## Known limitations (documented, tested)

- Process-local sandbox is not a filesystem/network namespace; only trusted offline read-only built-ins are permitted.
- Same-UID actor can replace SQLite file; audit chain detects naive tampering, not WORM.
- Single-user OS identity; no independent multi-user attestation.
- No network/HIGH-risk tools registered; approvals are state-machine primitives only.
- Dashboard is CLI-only; health reports DEGRADED for missing web surface (no bypass).

## References

- Implementation: `noble/kernel.py` is the single authoritative core.
- Ledger: `noble/ledger.py`, `noble/store.py` ledger table.
- Hashes: `noble/policy_version.py`, `noble/signing.py`.
- FSM: `noble/state_machine.py`.
- Replay: `noble/replay.py`.
- Health: `noble/health.py`.
- Drift: `noble/drift.py`.
- Contracts: `noble/contracts.py`.
- Supply chain: `noble/supply_chain.py`.
- Spec: `noble/spec.py`, `docs/security-spec.json`.
