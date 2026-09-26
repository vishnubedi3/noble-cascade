"""Bounded subprocess boundary for *registered trusted workers only*.

No shell, no caller-controlled argv, no arbitrary plugin command. CPU, virtual
memory, file size, fd count, wall time, stdin and stdout are bounded. This is
NOT a filesystem or egress sandbox: only offline, built-in read-only tools are
allowed. External tools must fail closed until a real isolation backend exists.
"""

from __future__ import annotations

import json
import os
import resource
import selectors
import signal
import subprocess  # nosec B404
import sys
import time
from contextlib import suppress
from pathlib import Path

from jsonschema import Draft7Validator

from .config import RuntimeConfig
from .errors import (
    InvalidInput,
    InvalidOutput,
    SandboxFailure,
    ToolExecutionFailed,
    ToolTimeout,
    ToolUnavailable,
)
from .models import CommandResult, SandboxRequirement, ToolInvocation, utcnow

WORKER_PATH = Path(__file__).resolve().parent / "builtins/worker.py"


class CommandRunner:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def _limit_child(self) -> None:
        limits = self.config.limits
        resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1))
        ram_bytes = limits.memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (ram_bytes, ram_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1_048_576, 1_048_576))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    @staticmethod
    def _kill_group(proc: subprocess.Popen[bytes]) -> None:
        # Do not call poll() before killpg: reaping a fast-exiting parent
        # could leave live children with inherited pipes and a reusable PGID.
        if proc.returncode is not None:
            return
        with suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise ToolTimeout("trusted worker could not be terminated") from exc

    def run(self, invocation: ToolInvocation) -> CommandResult:
        definition = invocation.definition
        context = invocation.context
        parameters = invocation.parameters
        if (
            not context.scope.covers(context.target)
            or context.authorization.principal != context.operator_id
        ):
            raise SandboxFailure("worker context has no bound scope or principal")
        if definition.action != context.risk.action:
            raise SandboxFailure("worker tool/action binding changed")
        if context.deadline <= utcnow():
            raise ToolTimeout("worker deadline has already passed")
        if list(Draft7Validator(definition.input_schema).iter_errors(parameters)):
            raise InvalidInput("worker parameters are not registered and schema-valid")
        if definition.sandbox is not SandboxRequirement.PROCESS_LOCAL:
            raise SandboxFailure("required sandbox is unavailable; tool refused")
        if definition.network_required or context.network_policy:
            raise SandboxFailure("network-capable tools require independently verified isolation")
        if definition.name not in {"static-code-scan", "fixture-sql-verify"}:
            raise ToolUnavailable("no trusted built-in worker for selected tool")
        if not WORKER_PATH.is_file() or not os.path.samefile(
            context.workspace_root, self.config.workspace_root
        ):
            raise SandboxFailure("trusted worker or workspace is unavailable")
        payload = {
            "request_id": context.request_id,
            "tool": definition.name,
            "target": context.target.canonical,
            "workspace_root": self.config.workspace_root,
            "max_files": min(
                int(parameters.get("max_files", self.config.limits.max_files)),
                self.config.limits.max_files,
            ),
            "max_file_bytes": self.config.limits.max_file_bytes,
            "max_observations": self.config.limits.max_observations,
        }
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        if len(data) > self.config.limits.max_input_bytes:
            raise InvalidInput("worker payload exceeds input limit")
        argv = (sys.executable, "-I", str(WORKER_PATH.resolve(strict=True)))
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LC_ALL": "C.UTF-8",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
        }
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                argv,
                cwd=self.config.workspace_root,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,  # nosec B603
                close_fds=True,
                start_new_session=True,
                preexec_fn=self._limit_child,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ToolUnavailable("trusted worker process could not start") from exc
        stdout = bytearray()
        stderr = bytearray()
        timed_out = False
        truncated = False
        try:
            if proc.stdin is None or proc.stdout is None or proc.stderr is None:
                raise ToolExecutionFailed("trusted worker pipes are unavailable")
            try:
                proc.stdin.write(data)
                proc.stdin.close()
            except BrokenPipeError as exc:
                with suppress(OSError):
                    proc.stdin.close()
                raise ToolExecutionFailed(
                    "trusted worker exited before accepting its input"
                ) from exc
            with selectors.DefaultSelector() as sel:
                for stream, dest in ((proc.stdout, stdout), (proc.stderr, stderr)):
                    os.set_blocking(stream.fileno(), False)
                    sel.register(stream, selectors.EVENT_READ, dest)
                while sel.get_map():
                    remaining = definition.timeout_seconds - (time.monotonic() - start)
                    if remaining <= 0:
                        timed_out = True
                        self._kill_group(proc)
                        break
                    for key, _ in sel.select(timeout=min(remaining, 0.25)):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            sel.unregister(key.fileobj)
                            continue
                        dest = key.data
                        dest.extend(chunk)
                        if len(stdout) + len(stderr) > self.config.limits.max_output_bytes:
                            truncated = True
                            self._kill_group(proc)
                            break
                    if truncated:
                        break
            if not timed_out and not truncated:
                remaining = definition.timeout_seconds - (time.monotonic() - start)
                try:
                    proc.wait(timeout=max(remaining, 0.001))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    self._kill_group(proc)
        finally:
            self._kill_group(proc)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
        duration = time.monotonic() - start
        if timed_out:
            raise ToolTimeout("trusted tool exceeded wall-time limit", tool=definition.name)
        if truncated:
            raise InvalidOutput("trusted tool exceeded output size limit", tool=definition.name)
        if proc.returncode != 0:
            raise ToolExecutionFailed(
                "trusted built-in tool refused input or failed",
                tool=definition.name,
                exit_code=proc.returncode or -1,
            )
        try:
            out = stdout.decode("utf-8", errors="strict")
            err = stderr.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise InvalidOutput("tool output encoding is not UTF-8") from exc
        return CommandResult(
            argv=argv,
            exit_code=proc.returncode,
            stdout=out,
            stderr=err[:2048],
            duration_seconds=duration,
            truncated=False,
            timed_out=False,
        )
