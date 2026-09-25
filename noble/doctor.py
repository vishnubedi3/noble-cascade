"""Actionable diagnostics, including missing dependencies and optional self-tests."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Diagnostic:
    component: str
    status: str  # PASS / WARN / FAIL
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"component": self.component, "status": self.status, "message": self.message}


def _find_binary(name: str) -> str | None:
    local = Path(sys.executable).parent / name
    return str(local) if local.is_file() else shutil.which(name)


def run_doctor(
    root: str | Path | None = None, *, self_test: bool = False
) -> tuple[list[Diagnostic], bool]:
    root_path = Path(root or Path(__file__).resolve().parent.parent).resolve()
    results: list[Diagnostic] = []
    for package, module in (("PyYAML", "yaml"), ("jsonschema", "jsonschema")):
        if importlib.util.find_spec(module) is None:
            results.append(
                Diagnostic(
                    package, "FAIL", "not installed; install from requirements.lock with hashes"
                )
            )
        else:
            try:
                version = importlib.metadata.version(package)
                # Runtime requires PyYAML >=6.0.2,<7 and jsonschema >=4.23,<5.
                release = tuple(int(part) for part in version.split(".")[:3])
                low, high = (
                    ((6, 0, 2), (7, 0, 0)) if package == "PyYAML" else ((4, 23, 0), (5, 0, 0))
                )
                compatible = low <= release < high
                results.append(
                    Diagnostic(
                        package,
                        "PASS" if compatible else "FAIL",
                        version if compatible else f"incompatible {version}; see pyproject.toml",
                    )
                )
            except (ValueError, importlib.metadata.PackageNotFoundError):
                results.append(Diagnostic(package, "FAIL", "package version is not discoverable"))
    if any(check.status == "FAIL" for check in results):
        return results, False
    # Defer importing dependencies until after the availability check, so the
    # doctor command itself works in an unprepared virtual environment.
    import yaml

    from .config import RuntimeConfig
    from .registry import ToolRegistry
    from .scope import ScopeEngine
    from .store import Store

    try:
        config = RuntimeConfig.load(workspace_root=root_path)
        results.append(Diagnostic("runtime configuration", "PASS", "offline-only limits validated"))
    except Exception as exc:
        results.append(
            Diagnostic("runtime configuration", "FAIL", f"invalid: {type(exc).__name__}")
        )
        return results, False
    try:
        scope = ScopeEngine.from_file(workspace_root=root_path)
        results.append(
            Diagnostic(
                "scope policy", "PASS", f"deny-by-default; {len(scope.allowed_roots)} local root(s)"
            )
        )
    except Exception as exc:
        results.append(Diagnostic("scope policy", "FAIL", f"invalid: {type(exc).__name__}"))
    try:
        registry = ToolRegistry(config)
        results.append(
            Diagnostic("tool registry", "PASS", f"{len(registry.list())} trusted offline tools")
        )
    except Exception as exc:
        results.append(Diagnostic("tool registry", "FAIL", f"invalid: {type(exc).__name__}"))
    try:
        store = Store(Path(config.state_directory) / "state.db")
        safe, count = store.verify_audit()
        results.append(
            Diagnostic("audit chain", "PASS" if safe else "FAIL", f"{count} chained events checked")
        )
        state_mode = os.stat(config.state_directory).st_mode & 0o777
        db_mode = os.stat(store.db_path).st_mode & 0o777
        results.append(
            Diagnostic(
                "state permissions",
                "PASS" if state_mode == 0o700 and db_mode == 0o600 else "FAIL",
                f"directory={state_mode:o}, database={db_mode:o}; expected 700/600",
            )
        )
    except Exception as exc:
        results.append(Diagnostic("state/audit", "FAIL", f"unavailable: {type(exc).__name__}"))
    try:
        manifest = yaml.safe_load((root_path / "agent-skills/manifest.yaml").read_text())
        installed = yaml.safe_load(
            (root_path / "agent-skills/INSTALLATION_MANIFEST.yaml").read_text()
        )
        skills = manifest["skills"]
        legacy = installed["implementations"]
        missing = [
            s["integration_wrapper"]
            for s in skills
            if not (root_path / s["integration_wrapper"]).exists()
        ]
        honest = (
            len(skills) == len(legacy) == 34
            and len(manifest["runtime_tools"]) == 2
            and not missing
            and all(not s["upstream_installed"] for s in skills)
            and all(not item["installed"] for item in legacy)
        )
        results.append(
            Diagnostic(
                "manifests",
                "PASS" if honest else "FAIL",
                f"{len(skills)} historical refs / {len(manifest['runtime_tools'])} runtime tools / {len(missing)} missing paths",
            )
        )
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        results.append(Diagnostic("manifests", "FAIL", f"invalid: {type(exc).__name__}"))
    for lock_name in ("requirements.lock", "requirements-dev.lock"):
        lock = root_path / lock_name
        try:
            text = lock.read_text(encoding="utf-8")
            pinned = "==" in text and "--hash=sha256:" in text
            results.append(
                Diagnostic(
                    lock_name,
                    "PASS" if pinned else "FAIL",
                    "hash-pinned" if pinned else "missing hashes",
                )
            )
        except OSError:
            results.append(Diagnostic(lock_name, "FAIL", "lock missing or unreadable"))
    results.append(
        Diagnostic(
            "Python",
            "PASS" if sys.version_info >= (3, 11) else "FAIL",
            sys.version.split()[0] if sys.version_info >= (3, 11) else "Python >=3.11 required",
        )
    )
    for binary in ("semgrep", "bandit", "gitleaks", "checkov", "osv-scanner"):
        found = _find_binary(binary)
        results.append(
            Diagnostic(
                binary,
                "WARN",
                "present but NOT a registered runtime tool"
                if found
                else "not installed; no fallback security scan is claimed",
            )
        )
    for binary in ("docker", "go"):
        found = _find_binary(binary)
        results.append(
            Diagnostic(
                binary,
                "WARN",
                "present but no external sandbox/tool is registered"
                if found
                else "missing; reference file cannot run",
            )
        )
    if not shutil.which("node"):
        results.append(
            Diagnostic("Node.js", "WARN", "optional legacy schema adapter is unavailable")
        )
    results.append(
        Diagnostic(
            "network sandbox", "WARN", "no verified egress isolation: all network tools refused"
        )
    )
    if self_test:
        try:
            test = subprocess.run(
                [sys.executable, "-m", "pytest", "-q"],
                cwd=root_path,
                env={
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                },
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            summary = test.stdout.strip().splitlines()[-1] if test.stdout.strip() else "no output"
            results.append(
                Diagnostic(
                    "runtime tests", "PASS" if test.returncode == 0 else "FAIL", summary[:200]
                )
            )
        except (OSError, subprocess.TimeoutExpired):
            results.append(Diagnostic("runtime tests", "FAIL", "pytest unavailable or timed out"))
    return results, not any(x.status == "FAIL" for x in results)
