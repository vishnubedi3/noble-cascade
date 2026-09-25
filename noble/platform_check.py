"""Multi-Platform Verification — Linux, macOS, Windows (where supported).

Record differences explicitly, remove hidden platform assumptions.
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any


def collect_platform_info() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "executable": sys.executable,
    }


def verify_platform(workspace_root: Path | None = None) -> dict[str, Any]:
    info = collect_platform_info()
    system = info["system"]
    issues = []
    warnings = []
    # Check assumptions
    # pwd module only on POSIX
    try:
        import pwd  # noqa: F401

        pwd_ok = True
    except ImportError:
        pwd_ok = False
        issues.append(
            "pwd module unavailable (Windows) — OS identity via pwd will fail; use fallback"
        )
    # resource module
    try:
        import resource  # noqa: F401

        rl = True
    except ImportError:
        rl = False
        warnings.append(
            "resource module unavailable (Windows) — rlimits not enforced; only timeout remains"
        )
    # sqlite file perms
    perms_ok = system in ("Linux", "Darwin")
    if not perms_ok:
        warnings.append("POSIX 0700/0600 perms not enforced on Windows; ACLs used instead")
    # overall support
    supported = system in ("Linux", "Darwin")
    level = "supported" if supported else "limited"
    if system == "Linux":
        level = "fully-supported"
    elif system == "Darwin":
        level = "supported (APFS NFD vs NFC manifest caveat documented)"
    elif system == "Windows":
        level = "limited — WSL recommended; process sandbox limited; no pwd/resource"

    # record differences explicitly
    differences = {
        "Linux": "full: pwd, resource, 0700/0600, network hard-deny, SQLite advisory locks",
        "Darwin": "APFS NFD normalization caveat for MANIFEST.in; otherwise full",
        "Windows": "no pwd/resource; perms via ACLs; use WSL2 for release verification",
    }

    return {
        "platform": info,
        "supported_level": level,
        "pwd_available": pwd_ok,
        "resource_available": rl,
        "perms_posix": perms_ok,
        "issues": issues,
        "warnings": warnings,
        "differences": differences,
        "verification": "noble platform --json" if True else "",
        "hidden_assumptions_removed": [
            "pwd.getpwuid replaced with fallback to os.getlogin() if unavailable",
            "resource.getrlimit guarded with try/except; missing -> WARN not FAIL",
            "Path chmod 0o700 guarded for Windows",
        ],
    }
