"""Machine-Readable Security Specification — living specification.

Include invariants, state machine, contracts, schemas, policies.
Implementation remains synchronized via code generation and verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config_schema import RUNTIME_SCHEMA, SCOPE_SCHEMA
from .contracts import CONTRACTS
from .models import ExecutionState
from .registry import INPUT_SCHEMA, OBSERVATION_SCHEMA, OUTPUT_SCHEMA
from .reporting import FINDING_SCHEMA
from .state_machine import describe_fsm


def generate_spec() -> dict[str, Any]:
    # Make contracts JSON-serializable (strip function values)
    serializable_contracts = {
        k: {ik: iv for ik, iv in v.items() if ik != "check"} for k, v in CONTRACTS.items()
    }
    return {
        "name": "Noble Cascade Security Specification",
        "version": "0.2.0",
        "invariants": [
            "No tool executes outside authorized scope (UNKNOWN -> DENY)",
            "High-risk actions cannot execute without required approval",
            "Agent cannot approve its own action",
            "Unknown policy decisions fail closed",
            "Target content cannot override system policy",
            "Tool output cannot directly become trusted evidence without validation",
            "Credentials are not exposed unnecessarily",
            "Every security-sensitive execution is auditable",
            "Sandbox failure prevents execution rather than silently weakening isolation",
            "Web/API cannot bypass CLI controls",
        ],
        "state_machine": describe_fsm(),
        "contracts": serializable_contracts,
        "schemas": {
            "runtime_config": RUNTIME_SCHEMA,
            "scope_policy": SCOPE_SCHEMA,
            "tool_input": INPUT_SCHEMA,
            "tool_output": OUTPUT_SCHEMA,
            "observation": OBSERVATION_SCHEMA,
            "finding": FINDING_SCHEMA,
        },
        "policies": {
            "scope": "deny-by-default, anchored matches, forbidden precedence, CIDR full containment",
            "authorization": "exact principal/target/action/purpose/time/permissions",
            "approval": "PENDING->APPROVED/REJECTED/EXPIRED/REVOKED, compare-and-swap, no self-approval",
            "network": "hard deny — no network-capable tool registered",
            "sandbox": "process-local rlimits, bounded I/O, no filesystem/network namespace",
        },
        "execution_chain": [
            "Request",
            "Policy",
            "Authorization",
            "Approval",
            "Worker",
            "Tool",
            "Evidence",
            "Finding",
            "Report",
            "Audit",
        ],
        "identifiers": [
            "request_id",
            "execution_id",
            "worker_id",
            "tool_run_id",
            "evidence_id",
            "finding_id",
            "report_id",
            "audit_event_id",
        ],
    }


def write_spec(path: str | Path = "docs/security-spec.json") -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(generate_spec(), indent=2, sort_keys=True, ensure_ascii=True), encoding="utf-8"
    )
    return p


def verify_sync() -> tuple[bool, list[str]]:
    """Check that spec is synchronized with implementation.

    Master Prompt IV: the committed docs/security-spec.json must equal the
    generated spec. Generated security specifications must never silently
    diverge from implementation — regenerate via `noble spec` in a reviewed PR.
    """
    issues: list[str] = []
    spec = generate_spec()
    try:
        committed_path = Path(__file__).resolve().parent.parent / "docs/security-spec.json"
        committed = json.loads(committed_path.read_text(encoding="utf-8"))
        if json.dumps(committed, sort_keys=True) != json.dumps(spec, sort_keys=True):
            issues.append(
                "docs/security-spec.json is stale vs generate_spec(); "
                "regenerate with `noble spec` (reviewed change)"
            )
    except FileNotFoundError:
        issues.append("docs/security-spec.json missing; regenerate with `noble spec`")
    except json.JSONDecodeError as exc:
        issues.append(f"docs/security-spec.json is not valid JSON: {exc}")
    # Verify state machine states match ExecutionState enum
    fsm_states = set(spec["state_machine"]["states"])
    enum_states = {s.value for s in ExecutionState}
    if fsm_states != enum_states:
        issues.append(f"FSM states {fsm_states} != enum {enum_states}")
    # Verify schemas are valid Draft-07
    try:
        from jsonschema import Draft7Validator

        for _name, schema in spec["schemas"].items():
            Draft7Validator.check_schema(schema)
    except Exception as exc:
        issues.append(f"schema invalid: {type(exc).__name__}: {exc}")
    return (len(issues) == 0, issues)
