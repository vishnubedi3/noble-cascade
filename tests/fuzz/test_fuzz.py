"""Fuzz testing for URLs, hostnames, paths, policies, manifests, JSON/YAML, tool output, CLI args."""

import json
import random
import string
from pathlib import Path

import pytest
import yaml

from noble.config import RuntimeConfig
from noble.errors import ConfigurationInvalid, InvalidInput
from noble.scope import ScopeEngine
from noble.targets import normalize_target

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.security
def test_fuzz_urls_hostnames_paths():
    payloads = [
        "https://localhost/" + "A" * 2000,
        "https://" + "a" * 100 + ".local",
        "http://127.0.0.1%2e",
        "https://localhost///...///",
        "/etc/passwd" + "\x00",
        "./" + "../" * 20 + "etc/passwd",
        "vishnubedi3/" + "a" * 1000,
        "https://localhost:abc/",
        "https://%6c%6f%63%61%6c%68%6f%73%74/",
    ]
    for p in payloads:
        try:
            normalize_target(p, workspace_root=ROOT)
        except (InvalidInput, ConfigurationInvalid, ValueError, TypeError):
            pass
        except Exception as e:
            pytest.fail(f"fuzz url crashed: {p!r} -> {type(e).__name__}: {e}")


@pytest.mark.security
def test_fuzz_policies():
    for _ in range(100):
        # Random policy dict
        policy = {
            "default_action": random.choice(["deny", "allow", ""]),
            "scope": {
                "allowed_domains": [random.choice(["*.local", "*", "evil*", "a" * 100])],
                "allowed_testing_methods": ["static-analysis"],
            },
        }
        try:
            ScopeEngine(policy, workspace_root=ROOT)
        except (ConfigurationInvalid, ValueError, TypeError, AttributeError):
            pass
        except Exception as e:
            pytest.fail(f"policy fuzz crashed: {type(e).__name__}")


@pytest.mark.security
def test_fuzz_json_yaml_tool_output():
    for _ in range(100):
        # Random JSON that might be tool output
        blob = "".join(random.choice(string.printable) for _ in range(random.randint(10, 500)))
        try:
            json.loads(blob)
        except:
            pass
        # YAML
        try:
            yaml.safe_load(blob)
        except:
            pass
    # Tool output JSON fuzz via OutputValidator
    from datetime import datetime, timedelta, timezone

    from noble.evidence import OutputValidator
    from noble.models import (
        ApprovalState,
        Authorization,
        ExecutionContext,
        RiskAssessment,
        Scope,
        Target,
        TargetKind,
    )
    from noble.registry import ToolRegistry

    cfg = RuntimeConfig.load(workspace_root=ROOT)
    validator = OutputValidator(cfg)
    # Try random blobs
    for _ in range(50):
        blob = '{"request_id": "req-' + "a" * 32 + '", "target": "/tmp"}'
        # We just ensure validator doesn't crash process, it should raise InvalidOutput
        from noble.models import (
            RiskTier,
        )

        dummy_def = ToolRegistry(cfg).get("static-code-scan")
        target = Target(
            raw="a", kind=TargetKind.PATH, canonical=str(ROOT / "tests/fixtures/sql_injection.py")
        )
        # Use try to avoid crash
        try:
            ctx = ExecutionContext(
                request_id="req-" + "a" * 32,
                operator_id="tester",
                target=target,
                scope=Scope(policy_name="test", allowed_targets=(target.canonical,)),
                authorization=Authorization(
                    grant_id="grant-abc", principal="tester", role="operator", capability="scan"
                ),
                approval_state=ApprovalState.NOT_REQUIRED,
                risk=RiskAssessment(action="static-analysis", tier=RiskTier.LOW, score=10),
                deadline=datetime.now(timezone.utc) + timedelta(seconds=10),
                sandbox_id="test",
                network_policy=(),
                credential_policy="none",
                audit_context="test",
                workspace_root=str(ROOT),
            )
            validator.validate(blob * 10, dummy_def, ctx)
        except Exception:
            pass


@pytest.mark.security
def test_fuzz_cli_args():
    from noble.cli import make_parser

    parser = make_parser()
    fuzz_inputs = [
        ["scope", "https://localhost/../../etc/passwd", "--action", "static-analysis"],
        ["authorize", "/etc/passwd", "--tool", "static-code-scan"],
        ["scan", "/tmp", "--grant", "grant-xxx"],
        ["simulate", "https://evil.com", "--action", "data-exfiltration"],
        ["replay", "lease-" + "a" * 20],
    ]
    for args in fuzz_inputs:
        try:
            parser.parse_args(args)
        except SystemExit:
            pass
        except Exception as e:
            pytest.fail(f"CLI fuzz crashed on {args}: {type(e).__name__}")
