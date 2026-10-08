"""Fenced subprocess supervision for scheduler actors."""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .evidence import redact_text
from .isolation import IsolationLayout
from .runner import terminate_process_group


LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")


class ProcessExecutionError(RuntimeError):
    """A child timed out, lost its lease, or could not be supervised safely."""


@dataclass(frozen=True)
class ProcessResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    elapsed_seconds: float
    stdout_path: Path
    stderr_path: Path

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class FencedProcessExecutor:
    """Run one child while periodically proving its scheduler lease is current."""

    def __init__(
        self,
        layout: IsolationLayout,
        agent_id: str,
        role: str,
        *,
        command_prefix: Sequence[str] = (),
        heartbeat: Callable[[], None] | None = None,
        assert_current: Callable[[], None] | None = None,
        heartbeat_seconds: float = 10.0,
        secret_environment: Mapping[str, str] | None = None,
        known_secrets: Sequence[str] = (),
    ) -> None:
        if role not in {"coder", "tester", "reviewer", "integrator"}:
            raise ValueError(f"invalid process role: {role}")
        if heartbeat_seconds <= 0:
            raise ValueError("heartbeat_seconds must be positive")
        self.paths = layout.agent_paths(agent_id)
        self.agent_id = agent_id
        self.role = role
        self.command_prefix = tuple(command_prefix)
        self.heartbeat = heartbeat or (lambda: None)
        self.assert_current = assert_current or (lambda: None)
        self.heartbeat_seconds = heartbeat_seconds
        self.secret_environment = dict(secret_environment or {})
        self.known_secrets = tuple(secret for secret in known_secrets if secret)

    def run(
        self,
        command: Sequence[str],
        cwd: Path,
        *,
        label: str,
        timeout_seconds: float,
        input_text: str | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> ProcessResult:
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("command must contain non-empty arguments")
        if not LABEL_RE.fullmatch(label):
            raise ValueError("invalid process label")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        working_directory = cwd.resolve()
        if not working_directory.is_dir():
            raise ValueError(f"working directory does not exist: {working_directory}")

        stdout_path = self.paths.logs / f"{label}.stdout.log"
        stderr_path = self.paths.logs / f"{label}.stderr.log"
        stdout_raw = self.paths.logs / f".{label}.{os.getpid()}.stdout.raw"
        stderr_raw = self.paths.logs / f".{label}.{os.getpid()}.stderr.raw"
        child_environment = self._environment(environment or {})
        started = time.monotonic()
        timed_out = False
        process: subprocess.Popen[str] | None = None
        try:
            with stdout_raw.open("w", encoding="utf-8") as stdout_handle, stderr_raw.open(
                "w", encoding="utf-8"
            ) as stderr_handle:
                os.chmod(stdout_raw, 0o600)
                os.chmod(stderr_raw, 0o600)
                self.assert_current()
                process = subprocess.Popen(
                    [*self.command_prefix, *command],
                    cwd=working_directory,
                    env=child_environment,
                    stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    text=True,
                    start_new_session=True,
                )
                if input_text is not None and process.stdin is not None:
                    process.stdin.write(input_text)
                    process.stdin.close()
                next_heartbeat = started + self.heartbeat_seconds
                deadline = started + timeout_seconds
                while process.poll() is None:
                    now = time.monotonic()
                    if now >= deadline:
                        timed_out = True
                        self._terminate_group(process)
                        break
                    if now >= next_heartbeat:
                        try:
                            self.assert_current()
                            self.heartbeat()
                        except Exception as exc:
                            self._terminate_group(process)
                            raise ProcessExecutionError(
                                f"{self.role} process lost its current lease"
                            ) from exc
                        next_heartbeat = now + self.heartbeat_seconds
                    time.sleep(min(0.1, max(0.01, deadline - now)))
                returncode = process.wait()
            stdout = stdout_raw.read_text(encoding="utf-8", errors="replace")
            stderr = stderr_raw.read_text(encoding="utf-8", errors="replace")
            stdout = redact_text(stdout, self.known_secrets)
            stderr = redact_text(stderr, self.known_secrets)
            self._replace_log(stdout_path, stdout)
            self._replace_log(stderr_path, stderr)
            return ProcessResult(
                tuple(command),
                returncode,
                stdout,
                stderr,
                timed_out,
                time.monotonic() - started,
                stdout_path,
                stderr_path,
            )
        finally:
            if process is not None and process.poll() is None:
                self._terminate_group(process)
            stdout_raw.unlink(missing_ok=True)
            stderr_raw.unlink(missing_ok=True)

    def _environment(self, additions: Mapping[str, str]) -> dict[str, str]:
        inherited = {
            name: os.environ[name]
            for name in ("PATH", "LANG", "LC_ALL", "NO_PROXY", "no_proxy")
            if os.environ.get(name)
        }
        environment = {
            **inherited,
            **self.secret_environment,
            **dict(additions),
            "HOME": str(self.paths.home),
            "XDG_CACHE_HOME": str(self.paths.cache),
            "PYTHONPYCACHEPREFIX": str(self.paths.cache / "python"),
            "USER": f"coding-{self.role}",
            "LOGNAME": f"coding-{self.role}",
            "GIT_OPTIONAL_LOCKS": "0",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
        }
        return environment

    @staticmethod
    def _replace_log(path: Path, value: str) -> None:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(value, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    @staticmethod
    def _terminate_group(process: subprocess.Popen[str]) -> None:
        if not terminate_process_group(process):
            raise ProcessExecutionError(
                "process did not terminate within the bounded shutdown grace"
            )
