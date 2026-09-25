"""Local operator CLI. Every execution command invokes :class:`NobleEngine`."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import sqlite3
import sys
from typing import Any

from .doctor import run_doctor


def _json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=True, default=str))


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noble",
        description="Deny-by-default offline security research control plane (local single-user mode)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("doctor", help="check configuration, audit, optional tools and isolation")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--self-test", action="store_true", help="also run pytest (needs dev dependencies)"
    )
    p.add_argument("--runtime", action="store_true", help="continuous runtime health")
    p.add_argument("--workers", action="store_true", help="worker identity and lifecycle")
    p.add_argument("--sandbox", action="store_true", help="sandbox health")
    p.add_argument("--policy", action="store_true", help="policy and drift")
    p.add_argument("--network", action="store_true", help="network policy")
    p.add_argument("--security", action="store_true", help="security boundaries")
    p.add_argument("--integrity", action="store_true", help="supply chain and audit integrity")
    p.add_argument("--replay", action="store_true", help="replay coverage")
    p = sub.add_parser(
        "scope", help="inspect policy for one target and action (does not authorize execution)"
    )
    p.add_argument("target")
    p.add_argument("--action", default="static-analysis")
    p = sub.add_parser("tools", help="show the two registered offline tools")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("authorize", help="issue a time-limited grant from this OS account")
    p.add_argument("target")
    p.add_argument("--tool", choices=("static-code-scan", "fixture-sql-verify"), required=True)
    p.add_argument("--role", choices=("operator", "security-auditor"), default="operator")
    p.add_argument("--purpose", default="security-research")
    p.add_argument("--valid-for", type=int, default=3600, metavar="SECONDS")
    for command, tool, help_text in (
        (
            "scan",
            "static-code-scan",
            "scan authorized local Python as data; findings remain candidates",
        ),
        ("validate", "fixture-sql-verify", "verify the unmodified synthetic SQL fixture in SQLite"),
    ):
        p = sub.add_parser(command, help=help_text)
        p.add_argument("target")
        p.add_argument("--grant", required=True, help="an exact-target authorization grant ID")
        if command == "scan":
            p.add_argument("--max-files", type=int, default=None)
        p.set_defaults(tool=tool)
    p = sub.add_parser("inspect", help="inspect a persisted request, evidence ID or finding ID")
    p.add_argument("identifier")
    p = sub.add_parser("findings", help="list persisted findings (never legacy example findings)")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("report", help="render findings from persisted evidence")
    p.add_argument("--format", choices=("json", "markdown"), default="markdown")
    p = sub.add_parser("audit", help="inspect verifiable audit chain")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser(
        "approve", help="decide a pending approval (requires a distinct OS approver and grant)"
    )
    p.add_argument("approval_id")
    p.add_argument("--grant", required=True, help="separate approver capability grant")
    p.add_argument("--reject", action="store_true", help="reject instead of approving")
    p.add_argument("--reason", required=True)

    # --- Hardening extensions ---
    p = sub.add_parser("simulate", help="policy simulation: what would happen without executing")
    p.add_argument("target")
    p.add_argument("--action", default="static-analysis")
    p.add_argument("--tool", default="static-code-scan")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("replay", help="deterministic replay of an execution (read-only)")
    p.add_argument("identifier", help="execution_id (lease-...) or request_id (req-...)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser(
        "health",
        help="continuous runtime health: workers, queue, sandbox, tools, policy, db, dashboard",
    )
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("drift", help="detect security drift vs baseline")
    p.add_argument("--baseline", action="store_true", help="establish new baseline")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("metrics", help="security metrics: blocked actions, approval latency, etc.")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("ledger", help="inspect immutable execution ledger chain")
    p.add_argument("execution_id", nargs="?", help="execution_id to inspect (omit to list recent)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("backup", help="disaster recovery: backup/restore findings and audit")
    p.add_argument("--create", metavar="DIR", help="create backup in DIR")
    p.add_argument("--verify", metavar="DIR", help="verify backup in DIR")
    p.add_argument("--restore", metavar="DIR", help="restore from backup DIR")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("supply-chain", help="verify supply chain: hashes, digests, dependencies")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("scorecard", help="verification coverage scorecard")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("spec", help="machine-readable security specification")
    p.add_argument("--verify", action="store_true", help="verify spec sync with implementation")
    p.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command == "doctor":
        # Handle extended doctor flags
        extended = any(
            [
                args.runtime,
                args.workers,
                args.sandbox,
                args.policy,
                args.network,
                args.security,
                args.integrity,
                args.replay,
            ]
        )
        if extended:
            from pathlib import Path as _Path

            root = _Path(__file__).resolve().parent.parent.resolve()
            all_checks: list = []
            if args.runtime:
                from .doctor import _check_runtime_health

                all_checks.extend(_check_runtime_health(root))
            if args.workers:
                from .doctor import _check_workers

                all_checks.extend(_check_workers(root))
            if args.sandbox:
                from .doctor import _check_sandbox

                all_checks.extend(_check_sandbox(root))
            if args.policy:
                from .doctor import _check_policy

                all_checks.extend(_check_policy(root))
            if args.network:
                from .doctor import _check_network

                all_checks.extend(_check_network(root))
            if args.security:
                from .doctor import _check_security

                all_checks.extend(_check_security(root))
            if args.integrity:
                from .doctor import _check_integrity

                all_checks.extend(_check_integrity(root))
            if args.replay:
                from .doctor import _check_replay

                all_checks.extend(_check_replay(root))
            healthy = not any(c.status == "FAIL" for c in all_checks)
            if args.json:
                _json({"core_healthy": healthy, "diagnostics": [c.to_dict() for c in all_checks]})
            else:
                for check in all_checks:
                    print(f"{check.status:4} {check.component:23} {check.message}")
            print(f"Extended checks: {'healthy' if healthy else 'issues found'}")
            return 0 if healthy else 1
        checks, healthy = run_doctor(self_test=args.self_test)
        if args.json:
            _json({"core_healthy": healthy, "diagnostics": [x.to_dict() for x in checks]})
        else:
            for check in checks:
                print(f"{check.status:4} {check.component:23} {check.message}")
            print(f"Core runtime: {'ready' if healthy else 'unavailable'}; WARN is not PASS")
        return 0 if healthy else 1
    try:
        from .engine import NobleEngine
        from .errors import NobleError
        from .models import ScopeDecision, SecurityRequest
        from .reporting import Reporter
        from .targets import normalize_target
    except ImportError as exc:
        print(
            f"Unavailable runtime dependency: {type(exc).__name__}; run 'noble doctor'",
            file=sys.stderr,
        )
        return 1
    try:
        engine = NobleEngine()
        current_user = pwd.getpwuid(os.getuid()).pw_name
        if args.command == "scope":
            from .errors import InvalidInput
            from .evidence import redact_sensitive
            from .models import new_id

            target = normalize_target(args.target, workspace_root=engine.config.workspace_root)
            if redact_sensitive(target.canonical) != target.canonical:
                raise InvalidInput("target contains a credential-shaped value")
            decision = engine.scope.evaluate(target, args.action)
            engine.audit.emit(
                request_id=new_id("inspect"),
                operator=current_user,
                action=args.action,
                target=target.canonical,
                policy=engine.scope.name,
                decision=decision.decision.value,
                result="scope_inspection",
                reason=decision.reason,
            )
            _json({"target": target.to_dict(), "policy": engine.scope.name, **decision.to_dict()})
            return 0 if decision.decision is ScopeDecision.ALLOW else 2
        if args.command == "tools":
            tools = [tool.to_dict() for tool in engine.registry.list()]
            if args.json:
                _json(tools)
            else:
                for tool in tools:
                    print(
                        f"{tool['name']:22} {tool['action']:30} {tool['risk_tier']:6} {tool['description']}"
                    )
            return 0
        if args.command == "authorize":
            definition = engine.registry.get(args.tool)
            target = normalize_target(args.target, workspace_root=engine.config.workspace_root)
            decision = engine.scope.evaluate(target, definition.action)
            if not decision.allowed or target.kind not in definition.allowed_target_kinds:
                from .models import new_id

                engine.audit.emit(
                    request_id=new_id("grant-refused"),
                    operator=current_user,
                    action=definition.action,
                    target=target.canonical,
                    policy=engine.scope.name,
                    decision="GRANT_REFUSED",
                    tool=definition.name,
                    result="blocked",
                    reason=decision.reason if not decision.allowed else "target kind unsupported",
                )
                print(
                    "Refused: target/action/tool is outside the authorized local scope",
                    file=sys.stderr,
                )
                return 2
            if not engine.config.network_enabled and definition.network_required:
                print("Refused: network sandbox unavailable", file=sys.stderr)
                return 2
            if args.role == "operator" and "verify" in definition.required_permissions:
                from .models import new_id

                engine.audit.emit(
                    request_id=new_id("grant-refused"),
                    operator=current_user,
                    action=definition.action,
                    target=target.canonical,
                    policy=engine.scope.name,
                    decision="GRANT_REFUSED",
                    tool=definition.name,
                    result="blocked",
                    reason="role lacks verify capability",
                )
                print("Refused: verification requires the security-auditor role", file=sys.stderr)
                return 2
            grant = engine.authorizer.issue(
                issuer=current_user,
                principal=current_user,
                role=args.role,
                capability=definition.required_permissions[0],
                action=definition.action,
                target=target,
                purpose=args.purpose,
                privileges=definition.required_permissions,
                valid_for_seconds=args.valid_for,
            )
            engine.audit.emit(
                request_id=grant.grant_id,
                operator=current_user,
                action=definition.action,
                target=target.canonical,
                policy=engine.scope.name,
                decision="GRANT_ISSUED",
                tool=definition.name,
                result="authorized",
                reason=f"grant {grant.grant_id} expires {grant.valid_until.isoformat()}",
            )
            _json(grant.to_dict())
            return 0
        if args.command in ("scan", "validate"):
            definition = engine.registry.get(args.tool)
            params = {}
            if args.command == "scan" and args.max_files is not None:
                params["max_files"] = args.max_files
            request = SecurityRequest(
                action=definition.action,
                target=args.target,
                requester=current_user,
                tool=definition.name,
                authorization_grant=args.grant,
                parameters=params,
            )
            result = engine.run(request)
            _json(result.to_dict())
            return 0 if result.succeeded else 2 if result.state.value == "BLOCKED" else 1
        if args.command == "inspect":
            identifier = args.identifier
            if identifier.startswith("req-"):
                entry = engine.store.get_result(identifier)
            elif identifier.startswith("ev-"):
                entry = engine.store.get_evidence(identifier)
            elif identifier.startswith("finding-"):
                entry = engine.store.get_finding(identifier)
            else:
                entry = None
            if entry is None:
                print("Not found", file=sys.stderr)
                return 1
            _json(entry)
            return 0
        if args.command == "findings":
            findings = Reporter(engine.store).collect()
            if args.json:
                _json(findings)
            else:
                for item in findings:
                    print(
                        f"{item['finding_id']} {item['state']:12} {item['confidence']['score']:3}% {item['title']}"
                    )
                print(f"{len(findings)} persisted findings")
            return 0
        if args.command == "report":
            reporter = Reporter(engine.store)
            print(reporter.as_json() if args.format == "json" else reporter.as_markdown(), end="")
            return 0
        if args.command == "audit":
            valid, count = engine.store.verify_audit()
            if args.json:
                _json({"valid": valid, "count": count, "events": engine.store.list_audit()})
            else:
                print(f"Audit chain: {'VALID' if valid else 'INVALID'} ({count} checked events)")
                if not args.verify:
                    for event in engine.store.list_audit():
                        print(
                            f"{event['timestamp']} {event['decision']:23} {event['request_id']} {event['result']}"
                        )
            return 0 if valid else 1
        if args.command == "approve":
            approval = engine.approvals.decide(
                args.approval_id,
                approver=current_user,
                approver_grant_id=args.grant,
                approve=not args.reject,
                reason=args.reason,
            )
            engine.audit.emit(
                request_id=approval.approval_id,
                operator=current_user,
                action=approval.action,
                target=approval.target,
                policy=engine.scope.name,
                decision=approval.state.value,
                risk=approval.risk_tier,
                approval=approval.approval_id,
                result=approval.state.value,
                reason="decision by a distinct granted approver",
            )
            _json(approval.to_dict())
            return 0
        if args.command == "simulate":
            from .simulate import PolicySimulator

            sim = PolicySimulator(config=engine.config, scope=engine.scope)
            # Use explicit error handling to provide policy explanation
            try:
                sim_result = sim.simulate(args.target, args.action, args.tool)
                if args.json:
                    _json(sim_result.to_dict())
                else:
                    print(sim_result.explain())
                    # Explain decision in required format
                    print(
                        f"Policy: {sim_result.policy} Rule: {sim_result.scope_rule} Reason: {sim_result.scope_reason}"
                    )
                return 0 if sim_result.execution == "ALLOWED" else 2
            except Exception as exc:
                _json({"error": {"code": "invalid_input", "message": str(exc)}})
                return 2
        if args.command == "replay":
            from .replay import ReplayEngine

            replayer = ReplayEngine(engine.store)
            ident = args.identifier
            try:
                if ident.startswith("lease-") or ident.startswith("exec-"):
                    data = replayer.replay(ident)
                elif ident.startswith("req-"):
                    data = replayer.replay_by_request(ident)
                else:
                    # Try both
                    try:
                        data = replayer.replay(ident)
                    except Exception:
                        data = replayer.replay_by_request(ident)
                if args.json:
                    _json(data)
                else:
                    print(f"Replay {ident} (READ ONLY):")
                    print(
                        f"  Request: {data.get('request_id')} -> {data.get('target')} [{data.get('action')}]"
                    )
                    print(f"  State: {data.get('state')} Outcome: {data.get('outcome')}")
                    print(f"  Policy: {data.get('policy')}")
                    print(f"  Tool versions: {data.get('tool_versions')}")
                    print(
                        f"  Evidence: {len(data.get('evidence', []))} Findings: {len(data.get('findings', []))}"
                    )
                    print(f"  Note: {data.get('replay_note')}")
                return 0
            except Exception as exc:
                _json({"error": {"code": "not_found", "message": str(exc)}})
                return 1
        if args.command == "health":
            from .health import HealthMonitor

            monitor = HealthMonitor(config=engine.config, store=engine.store)
            hchecks, hoverall = monitor.check_all()  # type: ignore[assignment]
            if args.json:
                _json({"overall": hoverall.value, "checks": [c.to_dict() for c in hchecks]})
            else:
                for c in hchecks:
                    print(f"{c.status.value:9} {c.component:18} {c.message}")
                print(f"Overall: {hoverall.value}")
            return 0 if hoverall.value == "HEALTHY" else 1 if hoverall.value == "DEGRADED" else 2
        if args.command == "drift":
            from .drift import DriftDetector

            detector = DriftDetector(workspace_root=engine.config.workspace_root)
            if args.baseline:
                fp = detector.save_baseline()
                _json({"baseline_saved": fp} if args.json else fp)
                if not args.json:
                    print(f"Baseline saved at {detector.baseline_path}")
                    _json(fp)
                return 0
            drift_result = detector.detect()  # type: ignore[assignment]
            if args.json:
                _json(drift_result)
            else:
                print(detector.report())
                if drift_result["drift_detected"]:
                    print("Drift details:", json.dumps(drift_result["changes"], indent=2))
            return 0 if not drift_result["drift_detected"] else 2
        if args.command == "metrics":
            from .metrics import collect_metrics

            metrics = collect_metrics(engine.store)
            if args.json:
                _json(metrics.to_dict())
            else:
                for k, v in metrics.to_dict().items():
                    print(f"{k:25} {v}")
            return 0
        if args.command == "ledger":
            if args.execution_id:
                chain = engine.store.get_ledger(args.execution_id)
                if not chain:
                    print("Not found", file=sys.stderr)
                    return 1
                _json(chain) if args.json else _json(chain)
            else:
                chains = engine.store.list_ledgers(limit=20)
                if args.json:
                    _json(chains)
                else:
                    for _entry in chains:  # type: ignore[assignment]
                        print(
                            f"{_entry['execution_id']} req={_entry['request_id']} worker={_entry['worker_id']} findings={len(_entry['finding_ids'])}"
                        )
                    print(f"{len(chains)} ledger entries")
            return 0
        if args.command == "backup":
            from .backup import BackupManager

            mgr = BackupManager(engine.store, workspace_root=engine.config.workspace_root)
            if args.create:
                info = mgr.create_backup(args.create)
                _json(info) if args.json else print(
                    f"Backup created at {info['path']} sha256={info['sha256'][:12]}..."
                )
                return 0
            if args.verify:
                ok, msg = mgr.verify_backup(args.verify)
                _json({"valid": ok, "message": msg}) if args.json else print(
                    f"Verify: {'OK' if ok else 'FAIL'} {msg}"
                )
                return 0 if ok else 1
            if args.restore:
                info = mgr.restore(args.restore)
                _json(info) if args.json else print(f"Restored {info['findings']} findings")
                return 0
            print("Specify --create DIR or --verify DIR or --restore DIR", file=sys.stderr)
            return 2
        if args.command == "supply-chain":
            from pathlib import Path as _P

            from .supply_chain import supply_chain_report

            report = supply_chain_report(_P(engine.config.workspace_root))
            if args.json:
                _json(report)
            else:
                for k, v in report.items():
                    if k != "overall":
                        print(f"{k:15} {'PASS' if v['valid'] else 'FAIL'} {v['detail']}")
                print(f"Overall: {'PASS' if report['overall'] else 'FAIL'}")
            return 0 if report["overall"] else 1
        if args.command == "scorecard":
            from .scorecard import build_scorecard

            card = build_scorecard(engine.store)
            if args.json:
                _json(card)
            else:
                print(f"Overall verification coverage: {card['overall']:.2f}")
                for key in (
                    "policy_coverage",
                    "replay_coverage",
                    "worker_verification",
                    "test_coverage",
                ):
                    entry = card[key]
                    print(f"  {key:20} score={entry['score']:.2f} {entry.get('detail', '')}")
                print(card["interpretation"])
            return 0
        if args.command == "spec":
            from .spec import generate_spec, verify_sync, write_spec

            if args.verify:
                ok, issues = verify_sync()
                if args.json:
                    _json({"synchronized": ok, "issues": issues, "spec": generate_spec()})
                else:
                    print("Spec sync: PASS" if ok else "FAIL")
                    for iss in issues:
                        print(f"  - {iss}")
                return 0 if ok else 1
            spec = generate_spec()
            if args.json:
                _json(spec)
            else:
                path = write_spec()
                print(f"Specification written to {path}")
                print(
                    f"States: {len(spec['state_machine']['states'])} Invariants: {len(spec['invariants'])}"
                )
            return 0
        return 1
    except NobleError as exc:
        if "engine" in locals() and args.command in ("scope", "authorize", "approve"):
            from .evidence import redact_sensitive
            from .models import new_id

            try:
                engine.audit.emit(
                    request_id=new_id("refused"),
                    operator=current_user,
                    action=getattr(args, "action", args.command),
                    target=redact_sensitive(str(getattr(args, "target", "[unknown]"))),
                    policy=engine.scope.name,
                    decision="OPERATOR_COMMAND_REFUSED",
                    result="blocked",
                    reason=exc.code,
                )
            except (OSError, sqlite3.Error):
                _json(
                    {"error": {"code": "audit_failure", "message": "refusal could not be audited"}}
                )
                return 1
        _json({"error": exc.to_dict()})
        return 2
    except (OSError, sqlite3.Error):
        _json({"error": {"code": "state_failure", "message": "local state is unavailable"}})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
