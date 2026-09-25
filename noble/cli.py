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
    p.add_argument(
        "--commit", help="historical commit to verify replay against (time-travel)", default=None
    )

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
    p.add_argument("--checkpoint", action="store_true", help="create ledger checkpoint")
    p.add_argument("--verify", action="store_true", help="verify ledger integrity")
    p.add_argument("--detect-corruption", action="store_true", help="detect ledger corruption")

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

    # --- Master Prompt III: Assurance & Reproducible Releases ---
    p = sub.add_parser("certify", help="governance certification: verify all trust pillars")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("audit-pack", help="generate independent audit bundle")
    p.add_argument("--output", default="audit-pack", help="output directory")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("policy-diff", help="policy regression: what changed between commits")
    p.add_argument("--from", dest="from_commit", default=None, help="from commit (default HEAD~1)")
    p.add_argument("--to", dest="to_commit", default=None, help="to commit (default HEAD)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("trust-report", help="repository self-assessment")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("trust-index", help="machine-readable trust report")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("release", help="reproducible release: create and verify")
    p.add_argument("--create", nargs="?", const="auto", help="create release (optional version)")
    p.add_argument("--verify", action="store_true", help="verify release artifacts")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("sbom", help="generate SBOM (SPDX and CycloneDX)")
    p.add_argument("--format", choices=("spdx", "cyclonedx", "both"), default="both")
    p.add_argument("--output", default="release", help="output directory")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("attest", help="cryptographic attestations")
    p.add_argument("--file", help="file to attest")
    p.add_argument("--verify", action="store_true", help="verify attestation")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("provenance", help="generate SLSA provenance")
    p.add_argument("--output", default="release/PROVENANCE.json")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("compliance", help="compliance profile mappings")
    p.add_argument("--framework", choices=("nist", "owasp", "slsa", "cis", "all"), default="all")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("platform", help="multi-platform verification")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("benchmark", help="repeatable performance benchmarks")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("verify", help="external verification (alias for certify + sbom checks)")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("invariants", help="formal security invariants")
    p.add_argument("--json", action="store_true")

    # --- Master Prompt IV: repository governance ---
    p = sub.add_parser(
        "governance", help="repository governance: baseline, workflow audit, PR analysis"
    )
    p.add_argument(
        "--baseline-create", action="store_true", help="write .github/repo-baseline.json"
    )
    p.add_argument(
        "--baseline-verify", action="store_true", help="verify checkout against baseline"
    )
    p.add_argument("--workflow-audit", action="store_true", help="audit .github/workflows/*")
    p.add_argument("--pr-analysis", action="store_true", help="analyze changed files vs guarantees")
    p.add_argument("--from", dest="from_commit", default=None, help="from commit (default HEAD~1)")
    p.add_argument("--to", dest="to_commit", default=None, help="to commit (default HEAD)")
    p.add_argument("--paths", nargs="*", default=None, help="explicit paths for guarantee impact")
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
    # Handle non-engine commands first (certify, release etc that may not need engine)
    if args.command == "certify":
        from .certify import certify

        result = certify()
        if args.json:
            _json(result)
        else:
            print(result["status"])
            for k, v in result["checks"].items():
                print(f"  {k:15} {'PASS' if v['passed'] else 'FAIL'} {v['message']}")
            if result["certified"]:
                print("CERTIFIED")
            else:
                print("FAILED")
        return 0 if result["certified"] else 1
    if args.command == "audit-pack":
        from .audit_pack import generate_audit_pack

        out = generate_audit_pack(output_dir=args.output)
        if args.json:
            _json({"audit_pack": str(out), "files": [str(p) for p in out.iterdir()]})
        else:
            print(f"Audit pack created at {out}")
            for p in sorted(out.iterdir()):
                print(f"  {p.name}")
        return 0
    if args.command == "policy-diff":
        from .policy_diff import policy_diff

        diff = policy_diff(from_commit=args.from_commit, to_commit=args.to_commit)
        if args.json:
            _json(diff)
        else:
            print(f"Policy diff {diff['from'][:8]} -> {diff['to'][:8]}")
            print(f"  file: {diff['file']}")
            print(f"  added: {diff['what_changed']['added']}")
            print(f"  removed: {diff['what_changed']['removed']}")
            print(f"  changed: {diff['what_changed']['changed']}")
            print(f"  affected guarantees: {diff['affected_guarantees']}")
            print(f"  affected tests: {diff['affected_tests']}")
            print(f"  why: {diff['why']}")
            print(f"  replay impact: {diff['replay_impact']}")
        return 0
    if args.command == "trust-report":
        from .trust_report import trust_report

        report = trust_report()
        if args.json:
            _json(report)
        else:
            print("=== Noble Cascade Trust Report ===")
            print(f"Version: {report['version']}")
            print(
                "Assertions (status: ENFORCED > VERIFIED > DOCUMENTED > MANUAL > EXPERIMENTAL > UNSUPPORTED):"
            )
            for name, info in report.get("assertion_status", {}).items():
                print(f"  [{info['status']:12}] {name}")
            print("Limitations:")
            for l in report["limitations"]:
                print(f"  - {l}")
            print(f"Verification: {report['verification_status']}")
            print(f"Reproducibility: {report['reproducibility_status']}")
        return 0
    if args.command == "trust-index":
        from .trust_index import generate_trust_index

        idx = generate_trust_index()
        if args.json:
            _json(idx)
        else:
            print(json.dumps(idx, indent=2, sort_keys=True))
        return 0
    if args.command == "release":
        from .release import create_release, verify_release

        if args.create is not None:
            version = None if args.create == "auto" else args.create
            info = create_release(version=version)
            if args.json:
                _json(info)
            else:
                print(f"Release {info['version']} created at {info['release_dir']}")
                print(f"  commit {info['commit']}")
                for k, v in info["hashes"].items():
                    print(f"  {k}: {v[:12]}...")
        if args.verify:
            ok, issues = verify_release()
            if args.json:
                _json({"verified": ok, "issues": issues})
            else:
                print("Release VERIFIED" if ok else "Release FAILED")
                for iss in issues:
                    print(f"  - {iss}")
            return 0 if ok else 1
        if args.create is None and not args.verify:
            # default verify
            ok, issues = verify_release()
            if args.json:
                _json({"verified": ok, "issues": issues})
            else:
                print("Release VERIFIED" if ok else "Release FAILED")
                for iss in issues:
                    print(f"  - {iss}")
            return 0 if ok else 1
        return 0
    if args.command == "sbom":
        from pathlib import Path as _P

        from .sbom import generate_cyclonedx, generate_spdx, write_cyclonedx, write_spdx

        out_dir = _P(args.output)
        if args.format in ("spdx", "both"):
            p = write_spdx(out_dir / "SBOM.spdx.json")
            if not args.json:
                print(f"SPDX SBOM written to {p}")
        if args.format in ("cyclonedx", "both"):
            p2 = write_cyclonedx(out_dir / "SBOM.cyclonedx.json")
            if not args.json:
                print(f"CycloneDX SBOM written to {p2}")
        if args.json:
            _json(
                {
                    "spdx": generate_spdx() if args.format in ("spdx", "both") else None,
                    "cyclonedx": generate_cyclonedx()
                    if args.format in ("cyclonedx", "both")
                    else None,
                }
            )
        return 0
    if args.command == "attest":
        from pathlib import Path as _P

        from .attest import attest_file

        if args.file:
            p = _P(args.file)
            if not p.exists():
                print(f"File not found: {p}", file=sys.stderr)
                return 1
            att = attest_file(p)
            if args.json:
                _json(att)
            else:
                print(f"Attestation for {p}:")
                print(f"  sha256: {att['sha256']}")
                print(f"  signature: {att['attestation']['signature'][:16]}...")
                print(f"  algorithm: {att['attestation']['algorithm']}")
            return 0
        # attest bundle verification: check release attestation
        from .release import verify_release

        ok, issues = verify_release()
        if args.json:
            _json({"verified": ok, "issues": issues})
        else:
            print("Attestation VERIFIED" if ok else "Attestation FAILED")
            for iss in issues:
                print(f"  - {iss}")
        return 0 if ok else 1
    if args.command == "provenance":
        from .provenance import generate_provenance, write_provenance

        if args.json:
            _json(generate_provenance())
        else:
            p = write_provenance(args.output)
            print(f"Provenance written to {p}")
        return 0
    if args.command == "compliance":
        from .compliance import all_compliance, cis_map, nist_ssdf_map, owasp_samm_map, slsa_map

        mapping = {
            "nist": nist_ssdf_map(),
            "owasp": owasp_samm_map(),
            "slsa": slsa_map(),
            "cis": cis_map(),
            "all": all_compliance(),
        }
        data = mapping[args.framework]
        if args.json:
            _json(data)
        else:
            print(json.dumps(data, indent=2, sort_keys=True))
        return 0
    if args.command == "platform":
        from .platform_check import verify_platform

        info = verify_platform()
        if args.json:
            _json(info)
        else:
            print(f"Platform: {info['platform']['system']} {info['platform']['machine']}")
            print(f"Support: {info['supported_level']}")
            for w in info["warnings"]:
                print(f"WARN: {w}")
            for iss in info["issues"]:
                print(f"ISSUE: {iss}")
            print(f"Differences: {info['differences']}")
        return 0 if not info["issues"] else 1
    if args.command == "benchmark":
        from .benchmark import run_benchmarks

        data = run_benchmarks()
        if args.json:
            _json(data)
        else:
            print("Benchmarks:")
            for k, v in data["benchmarks"].items():
                print(
                    f"  {k:20} p50 {v['p50_ms']:.1f}ms p95 {v['p95_ms']:.1f}ms max {v['max_ms']:.1f}ms"
                )
        return 0
    if args.command == "invariants":
        from .invariants import INVARIANTS, to_json

        if args.json:
            _json(to_json())
        else:
            for inv in INVARIANTS:
                print(f"Invariant {inv.id}: {inv.title}")
                print(f"  Spec: {inv.specification}")
                print(f"  Impl: {inv.implementation}")
                print(f"  Test: {inv.test}")
        return 0
    if args.command == "governance":
        from .governance import (
            audit_workflows,
            guarantee_impact,
            pr_analysis,
            verify_baseline,
            write_baseline,
        )

        if args.baseline_create:
            out = write_baseline()
            if args.json:
                _json({"baseline": str(out)})
            else:
                print(f"Baseline written to {out}")
            return 0
        if args.baseline_verify:
            result = verify_baseline()
            if args.json:
                _json(result)
            else:
                print("Baseline VERIFIED" if result["verified"] else "Baseline DRIFTED")
                for item in result["drift"]:
                    print(f"  - {item}")
                print(f"  baseline commit: {result['baseline_commit'][:12]}")
                print(f"  current commit:  {result['current_commit'][:12]}")
            return 0 if result["verified"] else 1
        if args.workflow_audit:
            report = audit_workflows()
            if args.json:
                _json(report)
            else:
                print(f"Workflows audited: {report['count']}")
                for name, wf in report["workflows"].items():
                    print(f"  {name}: {'PASS' if wf['passed'] else 'FAIL'}")
                    for finding in wf["findings"]:
                        print(f"    - {finding}")
            return 0 if report["passed"] else 1
        if args.paths:
            result = guarantee_impact(args.paths)
        else:
            result = pr_analysis(args.from_commit, args.to_commit)
        if args.json:
            _json(result)
        else:
            files = result.get("files_changed", result.get("paths", []))
            print(f"Files changed: {result.get('files_count', len(files))}")
            for f in files[:30]:
                print(f"  - {f}")
            print(f"Severity: {result['severity']}")
            critical = result.get("security_critical", result["severity"] != "standard")
            print(f"Security-critical: {critical}")
            print(f"Surface: {result.get('security_surface', result.get('guarantees_affected'))}")
            print(f"Guarantees affected: {result['guarantees_affected']}")
            print(f"Verification required: {result['required_verification']}")
        return 0
    if args.command == "verify":
        from .certify import certify

        result = certify()
        # also check release and sbom
        from pathlib import Path as _P

        release_ok = (_P("release/RELEASE.json").exists(),)
        if args.json:
            _json({"certify": result, "release_exists": release_ok[0]})
        else:
            print(result["status"])
            for k, v in result["checks"].items():
                print(f"  {k:15} {'PASS' if v['passed'] else 'FAIL'} {v['message']}")
            print(f"Release exists: {release_ok[0]}")
        return 0 if result["certified"] else 1
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
            exec_result = engine.run(request)  # type: ignore[assignment]
            _json(exec_result.to_dict())
            return 0 if exec_result.succeeded else 2 if exec_result.state.value == "BLOCKED" else 1
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
            # Time-travel: if --commit, verify that commit's policy matches execution's policy
            if args.commit:
                import hashlib
                import subprocess
                from pathlib import Path as _P

                try:
                    commit_hash = args.commit
                    # resolve commit
                    full = subprocess.check_output(
                        ["git", "rev-parse", commit_hash],
                        cwd=str(_P(engine.config.workspace_root)),
                        text=True,
                    ).strip()
                    # try to get policy file at that commit
                    policy_at_commit = subprocess.check_output(
                        [
                            "git",
                            "show",
                            f"{full}:agent-skills/governance/scope-enforcement/scope-policy.yaml",
                        ],
                        cwd=str(_P(engine.config.workspace_root)),
                        text=True,
                    )
                    policy_hash_at_commit = hashlib.sha256(policy_at_commit.encode()).hexdigest()
                    # do replay first
                    if ident.startswith("lease-") or ident.startswith("exec-"):
                        data = replayer.replay(ident)
                    elif ident.startswith("req-"):
                        data = replayer.replay_by_request(ident)
                    else:
                        try:
                            data = replayer.replay(ident)
                        except Exception:
                            data = replayer.replay_by_request(ident)
                    # compare
                    stored_hash = (
                        data.get("policy", {}).get("policy_hash") or data.get("policy_hash") or ""
                    )
                    data["time_travel"] = {
                        "requested_commit": full,
                        "policy_hash_at_commit": policy_hash_at_commit,
                        "execution_policy_hash": stored_hash,
                        "match": policy_hash_at_commit == stored_hash,
                        "note": "Time-travel verification: execution's policy hash is compared to git history without re-executing",
                    }
                except Exception as exc:
                    _json({"error": {"code": "time_travel_failed", "message": str(exc)}})
                    return 1
                if args.json:
                    _json(data)
                else:
                    print(f"Replay {ident} @ {args.commit} (READ ONLY, time-travel):")
                    print(f"  Match: {data['time_travel']['match']}")
                    print(
                        f"  Execution policy: {data['time_travel']['execution_policy_hash'][:12]}"
                    )
                    print(
                        f"  Commit policy:    {data['time_travel']['policy_hash_at_commit'][:12]}"
                    )
                return 0 if data["time_travel"]["match"] else 2
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
            # checkpoint / verify extensions
            if args.checkpoint:
                from .ledger_integrity import write_checkpoint

                p = write_checkpoint(engine.store)
                if args.json:
                    _json({"checkpoint": str(p)})
                else:
                    print(f"Checkpoint written to {p}")
                return 0
            if args.verify:
                from .ledger_integrity import verify_checkpoint

                ok, msg = verify_checkpoint(engine.store)
                if args.json:
                    _json({"verified": ok, "message": msg})
                else:
                    print(f"Ledger integrity: {'VALID' if ok else 'INVALID'} {msg}")
                return 0 if ok else 1
            if args.detect_corruption:
                from .ledger_integrity import detect_corruption

                info = detect_corruption(engine.store)
                if args.json:
                    _json(info)
                else:
                    print(json.dumps(info, indent=2))
                return 0 if not info["corrupted"] else 1
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
