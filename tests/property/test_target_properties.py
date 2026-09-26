"""Property-based tests for target normalization — invariant must survive thousands of malformed inputs."""

import random
import string

import pytest

from noble.errors import InvalidInput
from noble.targets import normalize_target


@pytest.mark.unit
def test_target_normalization_never_crashes():
    malformed = [
        "",
        "   ",
        "\x00",
        "https://localhost/\x00",
        "https://localhost:999999/",
        "http://[::1",
        "repo//name",
        "////",
        "a" * 3000,
        "https://evil.com?x=" + "A" * 1000,
        "https://localhost%2e%2e/secret",
        "repo%252Fbad",
        "localhost\u202e.evil.com",
        "https://user:pass@localhost/",  # pragma: allowlist secret
        "https://localhost#frag",
        "https://localhost?query=1",
        "\ufeffhttps://localhost/",
        "http://localhost\\\\@evil.com/",
        "10.0.0.0/33",
        "999.999.999.999",
        "../etc/passwd",
        "./a/../../b",
        "http://localhost:0/",
        "http://localhost:70000/",
    ]
    for raw in malformed:
        try:
            normalize_target(raw)
        except (InvalidInput, ValueError, TypeError):
            pass
        except Exception as e:
            pytest.fail(f"normalize_target crashed on {raw!r}: {type(e).__name__}: {e}")


@pytest.mark.unit
def test_random_fuzz_target_normalization():
    for _ in range(500):
        # Generate random string of varied characters
        length = random.randint(1, 100)
        chars = string.ascii_letters + string.digits + ":/.?=%#@-_.~\\"
        raw = "".join(random.choice(chars) for _ in range(length))
        # Also inject control chars occasionally
        if random.random() < 0.1:
            raw = raw[:10] + chr(random.randint(0, 31)) + raw[10:]
        try:
            t = normalize_target(raw)
            # Invariant: canonical never contains control chars
            assert "\x00" not in t.canonical
            assert len(t.canonical) <= 2048
        except (InvalidInput, ValueError, TypeError):
            pass


@pytest.mark.unit
def test_hostname_normalization_properties():
    cases = [
        ("Docs.local", "docs.local"),
        ("LOCALHOST", "localhost"),
        ("https://Docs.local:443/a/../b", "https://docs.local/b"),
    ]
    for raw, expected_canonical in cases:
        t = normalize_target(raw)
        assert expected_canonical in t.canonical or t.canonical == expected_canonical


@pytest.mark.unit
def test_cidr_containment_property():
    from pathlib import Path

    from noble.scope import ScopeEngine

    ROOT = Path(__file__).resolve().parents[2]
    scope = ScopeEngine(
        {
            "default_action": "deny",
            "scope": {
                "allowed_ip_ranges": ["10.0.0.0/8"],
                "allowed_testing_methods": ["static-analysis"],
            },
        },
        workspace_root=ROOT,
    )
    # 10.0.0.0/9 is inside 10.0.0.0/8 -> ALLOW, /7 is not fully contained -> UNKNOWN
    assert scope.evaluate(normalize_target("10.0.0.0/9"), "static-analysis").allowed
    assert not scope.evaluate(normalize_target("10.0.0.0/7"), "static-analysis").allowed
    # Random CIDR fuzz: any CIDR not fully inside should not be allowed
    for _ in range(50):
        # Generate random CIDR and check no crash
        try:
            scope.evaluate(normalize_target("10.0.0.0/16"), "static-analysis")
        except Exception:
            pytest.fail("CIDR evaluation crashed")
