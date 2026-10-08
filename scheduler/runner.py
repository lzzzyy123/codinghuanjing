"""Bounded subprocess execution and kernel-enforced Reviewer access probes."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


IDENTITY_COMPONENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


class RunnerError(RuntimeError):
    pass


class RunnerTimeout(RunnerError):
    pass


def run_bounded(
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: float,
    text: bool = True,
) -> subprocess.CompletedProcess:
    """Run without a shell and terminate the whole process group on timeout."""
    if not arguments:
        raise ValueError("command must be non-empty")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    try:
        process = subprocess.Popen(
            list(arguments),
            cwd=cwd,
            env=dict(env),
            text=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise RunnerError(f"could not start {arguments[0]!r}: {exc}") from exc
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        terminated = terminate_process_group(process)
        # A descendant can create a new session and keep the inherited pipe
        # descriptors open after the original process group is gone. Never use
        # an unbounded communicate() here: closing our pipe endpoints makes the
        # timeout itself the final bound even for such an escaped descendant.
        _close_process_pipes(process)
        if not terminated:
            raise RunnerTimeout(
                f"command {arguments[0]!r} timed out after {timeout_seconds:g}s "
                "and did not terminate within the bounded shutdown grace"
            ) from exc
        raise RunnerTimeout(
            f"command {arguments[0]!r} timed out after {timeout_seconds:g}s"
        ) from exc
    return subprocess.CompletedProcess(arguments, process.returncode, stdout, stderr)


def terminate_process_group(
    process: subprocess.Popen, *, grace_seconds: float = 2.0
) -> bool:
    """Best-effort process-group shutdown with a strict total wait bound."""
    if grace_seconds <= 0:
        raise ValueError("grace_seconds must be positive")

    # Signal the original group even when the leader has already exited. Its
    # descendants may still be alive and holding resources or inherited FDs.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass

    # The group leader may exit on SIGTERM while a child ignores it, so always
    # address the original group again. Also kill the leader directly in case
    # it changed its own process group after launch.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None


def _close_process_pipes(process: subprocess.Popen) -> None:
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except OSError:
                pass


@dataclass(frozen=True)
class UnixIdentity:
    user: str
    group: str

    def __post_init__(self) -> None:
        if not IDENTITY_COMPONENT_RE.fullmatch(self.user):
            raise ValueError("invalid Unix user")
        if not IDENTITY_COMPONENT_RE.fullmatch(self.group):
            raise ValueError("invalid Unix group")

    def chpst_prefix(self) -> tuple[str, ...]:
        executable = shutil.which("chpst")
        if executable is None:
            raise RunnerError("chpst is unavailable; Unix identity isolation cannot be verified")
        return (executable, "-u", f"{self.user}:{self.group}")


_READ_ONLY_PROBE = r"""
import errno
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
forbidden_roots = [pathlib.Path(value) for value in sys.argv[2:]]
failures = []
for current, directories, files in os.walk(root, followlinks=False):
    current_path = pathlib.Path(current)
    paths = [current_path]
    paths.extend(current_path / name for name in directories)
    paths.extend(current_path / name for name in files)
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_dir():
            if not os.access(path, os.R_OK | os.X_OK):
                failures.append(f"unreadable directory: {path}")
            if os.access(path, os.W_OK):
                failures.append(f"writable directory: {path}")
            continue
        if not os.access(path, os.R_OK):
            failures.append(f"unreadable file: {path}")
        try:
            descriptor = os.open(path, os.O_WRONLY | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                failures.append(f"unexpected write probe error for {path}: {exc}")
        else:
            os.close(descriptor)
            failures.append(f"writable file: {path}")
for forbidden in forbidden_roots:
    probe = forbidden / f".coding-reviewer-write-probe-{os.getpid()}"
    try:
        descriptor = os.open(
            probe,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
            failures.append(f"unexpected forbidden-root probe error for {forbidden}: {exc}")
    else:
        os.close(descriptor)
        probe.unlink(missing_ok=True)
        failures.append(f"writable forbidden root: {forbidden}")
if failures:
    sys.stderr.write("\n".join(failures[:20]))
    raise SystemExit(2)
"""


class ReviewerReadOnlyProbe:
    """Verify snapshot permissions as the same Unix identity used by Reviewer."""

    def __init__(
        self,
        *,
        command_prefix: Sequence[str] = (),
        python_executable: str = sys.executable,
        timeout_seconds: float = 15,
    ) -> None:
        if not python_executable:
            raise ValueError("python_executable must be non-empty")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.command_prefix = tuple(command_prefix)
        self.python_executable = python_executable
        self.timeout_seconds = timeout_seconds

    @classmethod
    def for_identity(
        cls,
        identity: UnixIdentity,
        *,
        python_executable: str = sys.executable,
        timeout_seconds: float = 15,
    ) -> "ReviewerReadOnlyProbe":
        return cls(
            command_prefix=identity.chpst_prefix(),
            python_executable=python_executable,
            timeout_seconds=timeout_seconds,
        )

    def verify(
        self, root: Path, forbidden_write_roots: Sequence[Path] = ()
    ) -> None:
        root = root.resolve()
        if not root.is_dir():
            raise RunnerError(f"Reviewer snapshot is missing: {root}")
        result = run_bounded(
            [
                *self.command_prefix,
                self.python_executable,
                "-c",
                _READ_ONLY_PROBE,
                str(root),
                *(str(path.resolve()) for path in forbidden_write_roots),
            ],
            cwd=root,
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            },
            timeout_seconds=self.timeout_seconds,
        )
        if result.returncode != 0:
            detail = str(result.stderr).strip()[-4000:]
            raise RunnerError(
                "Reviewer identity can modify or cannot read the snapshot"
                + (f": {detail}" if detail else "")
            )
