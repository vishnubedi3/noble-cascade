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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.command == "doctor":
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
