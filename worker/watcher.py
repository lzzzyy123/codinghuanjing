#!/usr/bin/env python3
"""Single-process RFC coding worker.

The queue is intentionally filesystem based. A global flock prevents multiple
workers, and an atomic rename from inbox to working claims each task.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import time
import traceback
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

import yaml


BASE = Path(os.environ.get("CODING_WORKER_HOME", "/opt/coding-worker")).resolve()
PERSISTENT_ROOT = Path("/openbayes/home").resolve()
TODO = BASE / "todo"
INBOX = TODO / "inbox"
WORKING = TODO / "working"
DONE = TODO / "done"
FAILED = TODO / "failed"
REPORTS = BASE / "reports"
WORKTREES = BASE / "worktrees"
RUNTIME = BASE / "runtime"
PROMPTS = BASE / "worker" / "prompts"

PROJECT_ROOT_VALUE = os.environ.get("PROJECT_ROOT", "").strip()
PROJECT_ROOT = Path(PROJECT_ROOT_VALUE).resolve() if PROJECT_ROOT_VALUE else None
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main").strip()
GIT_REMOTE = os.environ.get("GIT_REMOTE", "origin").strip()
MODEL = os.environ.get("MODEL", "xiaosuan-8")
AGENT_CLI = os.environ.get("AGENT_CLI", "/openbayes/home/.local/bin/claude")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "5"))
AGENT_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", "1800"))
TEST_TIMEOUT = int(os.environ.get("TEST_TIMEOUT", "1200"))
GIT_TIMEOUT = int(os.environ.get("GIT_TIMEOUT", "180"))
FULL_REGRESSION_COMMAND = os.environ.get("FULL_REGRESSION_COMMAND", "").strip()
PYTHON_BASELINE_ROOT = os.environ.get("PYTHON_BASELINE_ROOT", "").strip()
PYTHON_BASELINE_COMMIT = os.environ.get("PYTHON_BASELINE_COMMIT", "").strip()
MAX_REVIEW_CYCLES = int(os.environ.get("MAX_REVIEW_CYCLES", "3"))
MAX_CODER_CYCLES = int(os.environ.get("MAX_CODER_CYCLES", "5"))
MAX_CODER_CONTINUATIONS = int(os.environ.get("MAX_CODER_CONTINUATIONS", "16"))
MAX_CODER_PROTOCOL_RETRIES = int(os.environ.get("MAX_CODER_PROTOCOL_RETRIES", "2"))
MAX_CODER_PROTOCOL_FAILURES_TOTAL = int(
    os.environ.get("MAX_CODER_PROTOCOL_FAILURES_TOTAL", "8")
)
MAX_CODER_CONTINUATIONS_TOTAL = int(os.environ.get("MAX_CODER_CONTINUATIONS_TOTAL", "48"))
MAX_CODER_LIFECYCLE_ACTIONS = int(os.environ.get("MAX_CODER_LIFECYCLE_ACTIONS", "64"))
MAX_CONSECUTIVE_ERRORS = int(os.environ.get("MAX_CONSECUTIVE_ERRORS", "3"))
MAX_REVIEW_FORMAT_REPAIRS = int(os.environ.get("MAX_REVIEW_FORMAT_REPAIRS", "2"))
MAX_CONCURRENT_TASKS = int(os.environ.get("MAX_CONCURRENT_TASKS", "1"))
KEEP_SUCCESS_WORKTREES = os.environ.get("KEEP_SUCCESS_WORKTREES", "false").lower() == "true"

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
BRANCH_RE = re.compile(r"^agent/[A-Za-z0-9][A-Za-z0-9._/-]{0,180}$")
GIT_RUNNER = ["chpst", "-u", "codingworker:codingproject", str(BASE / "bin" / "git-exec")]
AGENT_RUNNER = ["chpst", "-u", "codingagent:codingproject", str(BASE / "bin" / "agent-exec")]
WORKER_HOME = "/openbayes/home/coding-worker-home"
AGENT_HOME = "/openbayes/home/coding-agent-home"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stdout,
)
LOG = logging.getLogger("coding-worker")


class TaskFailure(RuntimeError):
    pass


class AgentFailure(TaskFailure):
    pass


class ReviewFormatError(AgentFailure):
    pass


class ReviewInfrastructureFailure(TaskFailure):
    pass


class CoderInfrastructureFailure(TaskFailure):
    pass


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


@dataclass(frozen=True)
class CoderOutputAssessment:
    classification: str
    normalized: str
    errors: tuple[str, ...] = ()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def append_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(text)
        if text and not text.endswith("\n"):
            handle.write("\n")


def task_log(report_dir: Path, message: str, level: int = logging.INFO) -> None:
    LOG.log(level, "%s: %s", report_dir.name, message)
    append_text(report_dir / "worker.log", f"{utc_now()} {logging.getLevelName(level)} {message}\n")


def safe_tail(value: str, limit: int = 12000) -> str:
    return value if len(value) <= limit else "[truncated]\n" + value[-limit:]


SENSITIVE_ENV_NAMES = (
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "LITELLM_API_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
)


def redact_sensitive_text(value: str) -> str:
    """Remove known credentials and common inline secret assignments from evidence."""
    sensitive_keys = {
        "apikey",
        "api_key",
        "access_token",
        "authorization",
        "auth_token",
        "client_secret",
        "password",
        "refresh_token",
    }

    def redact_inline_text(text: str) -> str:
        for name in SENSITIVE_ENV_NAMES:
            secret = os.environ.get(name, "")
            if len(secret) >= 4:
                text = text.replace(secret, "[REDACTED]")
        quoted_assignment = re.compile(
            r"(?i)(\b(?:api[_-]?key|access[_-]?token|authorization|auth[_-]?token|"
            r"client[_-]?secret|password|refresh[_-]?token)\b\s*[:=]\s*)"
            r"([\"'])([^\r\n]*?)(\2)"
        )
        text = quoted_assignment.sub(
            lambda match: f'{match.group(1)}{match.group(2)}[REDACTED]{match.group(2)}',
            text,
        )
        text = re.sub(
            r"(?i)(\bauthorization\b\s*[:=]\s*)(?:(?:bearer|basic)\s+)?"
            r"[^\s,}\]]+",
            r"\1[REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)((?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
            r"password|refresh[_-]?token)\s*[:=]\s*)([^\s,}\]]+)",
            r"\1[REDACTED]",
            text,
        )
        return re.sub(
            r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
            "Bearer [REDACTED]",
            text,
        )

    def redact_json(item: Any, key: str = "") -> Any:
        normalized_key = key.lower().replace("-", "_")
        if normalized_key in sensitive_keys:
            return "[REDACTED]"
        if isinstance(item, dict):
            return {str(name): redact_json(child, str(name)) for name, child in item.items()}
        if isinstance(item, list):
            return [redact_json(child) for child in item]
        if isinstance(item, str):
            return redact_inline_text(item)
        return item

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
    if parsed is not None:
        return json.dumps(redact_json(parsed), ensure_ascii=False, separators=(",", ":"))

    return redact_inline_text(value)


def write_redacted(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact_sensitive_text(value), encoding="utf-8")


@contextmanager
def rfc_lock(base: Path, task_id: str, *, blocking: bool) -> Iterator[None]:
    """Fence all control-plane and Worker mutations for one RFC."""
    if not TASK_ID_RE.fullmatch(task_id):
        raise TaskFailure("invalid RFC ID for lock")
    lock_dir = base / "runtime" / "rfc-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{task_id}.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    operation = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(handle, operation)
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        yield
    finally:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        finally:
            handle.close()


def terminate_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def execute(
    args: list[str],
    cwd: Path,
    timeout: int,
    *,
    input_text: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> CommandResult:
    display = shlex.join(args)
    process = subprocess.Popen(
        args,
        cwd=str(cwd),
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        return CommandResult(display, process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        stdout, stderr = process.communicate()
        return CommandResult(display, 124, stdout, stderr, timed_out=True)


def validate_worktree_pointer(cwd: Path) -> None:
    if PROJECT_ROOT is None or cwd == PROJECT_ROOT:
        return
    try:
        cwd.relative_to(WORKTREES)
    except ValueError:
        return
    pointer = cwd / ".git"
    if not pointer.is_file() or pointer.is_symlink():
        raise TaskFailure(f"Task worktree has an invalid .git pointer: {pointer}")
    match = re.fullmatch(r"gitdir: (.+)\n?", pointer.read_text(encoding="utf-8"))
    if not match:
        raise TaskFailure(f"Task worktree .git pointer has invalid content: {pointer}")
    target = Path(match.group(1)).resolve()
    expected_parent = (PROJECT_ROOT / ".git" / "worktrees").resolve()
    if expected_parent not in target.parents or not target.is_dir():
        raise TaskFailure("Task worktree .git pointer escaped the bound repository")
    target_stat = target.stat()
    pointer_stat = pointer.stat()
    if target_stat.st_uid != 22022 or stat.S_IMODE(target_stat.st_mode) & 0o022:
        raise TaskFailure("Task worktree Git metadata has unsafe ownership or permissions")
    if pointer_stat.st_uid != 22022 or stat.S_IMODE(pointer_stat.st_mode) & 0o022:
        raise TaskFailure("Task worktree .git pointer has unsafe ownership or permissions")


def git(cwd: Path, *args: str, check: bool = True) -> CommandResult:
    validate_worktree_pointer(cwd)
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": WORKER_HOME,
        "USER": "codingworker",
        "LOGNAME": "codingworker",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    result = execute([*GIT_RUNNER, "git", *args], cwd, GIT_TIMEOUT, env=env)
    if check and not result.ok:
        raise TaskFailure(
            f"Git command failed: {result.command}\n"
            f"stdout:\n{safe_tail(result.stdout)}\nstderr:\n{safe_tail(result.stderr)}"
        )
    return result


def protect_git_metadata(repo: Path, worktree: Path) -> None:
    """Protect configuration and this worktree's metadata from Agent writes."""
    git_dir = repo / ".git"
    targets = [git_dir / "config", git_dir / "hooks"]
    worktree_git_dir = Path(git(worktree, "rev-parse", "--git-dir").stdout.strip()).resolve()
    if worktree_git_dir != git_dir and git_dir in worktree_git_dir.parents:
        targets.append(worktree_git_dir)
    for target in targets:
        if not target.exists() or target.is_symlink():
            continue
        paths = [target]
        if target.is_dir():
            paths.extend(path for path in target.rglob("*") if not path.is_symlink())
        for path in paths:
            os.chown(path, 22022, 22024)
            os.chmod(path, 0o750 if path.is_dir() else 0o640)
    pointer = worktree / ".git"
    if pointer.is_file():
        os.chown(pointer, 22022, 22024)
        os.chmod(pointer, 0o640)


def prepare_agent_worktree(worktree: Path) -> None:
    """Give codingagent write access to code without exposing Git metadata."""
    paths = [worktree]
    paths.extend(path for path in worktree.rglob("*") if not path.is_symlink())
    for path in paths:
        if path == worktree / ".git":
            continue
        os.chown(path, -1, 22024)
        mode = stat.S_IMODE(path.stat().st_mode)
        if path.is_dir():
            os.chmod(path, mode | 0o2770)
        else:
            os.chmod(path, mode | 0o660)


def parse_rfc(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise TaskFailure("RFC must start with YAML front matter delimited by ---")
    try:
        closing = next(index for index, line in enumerate(lines[1:], start=1) if line.strip() == "---")
    except StopIteration as exc:
        raise TaskFailure("RFC YAML front matter has no closing ---") from exc
    try:
        metadata = yaml.safe_load("\n".join(lines[1:closing])) or {}
    except yaml.YAMLError as exc:
        raise TaskFailure(f"Invalid RFC YAML front matter: {exc}") from exc
    if not isinstance(metadata, dict):
        raise TaskFailure("RFC YAML front matter must be a mapping")
    obsolete = sorted(
        set(metadata)
        & {"project", "repository", "base_branch", "working_directory", "branch"}
    )
    if obsolete:
        raise TaskFailure(
            "Single-project RFCs must not set project location fields: " + ", ".join(obsolete)
        )
    for command_key in ("test_command", "lint_command", "build_command"):
        if metadata.get(command_key) is not None and not isinstance(metadata[command_key], str):
            raise TaskFailure(f"{command_key} must be a string or null")
    return metadata, text


def prepare_worktree(
    task_id: str, report_dir: Path, allow_existing: bool
) -> tuple[Path, Path, str, str, str]:
    if PROJECT_ROOT is None:
        raise TaskFailure("Worker is not bound to a project; set PROJECT_ROOT and restart")
    repo = PROJECT_ROOT
    branch = f"agent/{task_id}"
    base_branch = BASE_BRANCH
    if not BRANCH_RE.fullmatch(branch):
        raise TaskFailure("branch must start with agent/ and be a valid task branch")
    if branch in {"main", "master", base_branch}:
        raise TaskFailure("task branch must differ from main/master/base_branch")
    git(repo, "check-ref-format", "--branch", branch)
    task_log(report_dir, f"Fetching latest {GIT_REMOTE}/{base_branch}")
    git(
        repo,
        "fetch",
        "--prune",
        GIT_REMOTE,
        f"+refs/heads/{base_branch}:refs/remotes/{GIT_REMOTE}/{base_branch}",
    )
    base_ref = f"refs/remotes/{GIT_REMOTE}/{base_branch}"
    git(repo, "rev-parse", "--verify", base_ref)

    worktree = (WORKTREES / task_id).resolve()
    if worktree.exists():
        if not allow_existing:
            raise TaskFailure(f"Worktree already exists for new RFC ID {task_id}")
        git(worktree, "rev-parse", "--is-inside-work-tree")
        active_branch = git(worktree, "branch", "--show-current").stdout.strip()
        if active_branch != branch:
            raise TaskFailure(f"existing worktree uses {active_branch}, expected {branch}")
    else:
        branch_exists = git(repo, "show-ref", "--verify", f"refs/heads/{branch}", check=False).ok
        if not branch_exists:
            remote_branch = git(
                repo, "ls-remote", "--exit-code", "--heads", GIT_REMOTE, branch, check=False
            )
            if remote_branch.ok:
                git(
                    repo,
                    "fetch",
                    GIT_REMOTE,
                    f"refs/heads/{branch}:refs/heads/{branch}",
                )
                branch_exists = True
        if branch_exists and not allow_existing:
            raise TaskFailure(f"Task branch already exists for new RFC ID {task_id}")
        args = ["worktree", "add", str(worktree), branch]
        if not branch_exists:
            args = ["worktree", "add", "-b", branch, str(worktree), base_ref]
        git(repo, *args)
        task_log(report_dir, f"Created worktree {worktree} on {branch}")

    prepare_agent_worktree(worktree)
    protect_git_metadata(repo, worktree)
    base_commit = git(worktree, "merge-base", "HEAD", base_ref).stdout.strip()
    return repo, worktree, base_branch, branch, base_commit


def load_prompt(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


def run_agent_once(role: str, prompt: str, cwd: Path, report_dir: Path, label: str) -> str:
    command = [
        *AGENT_RUNNER,
        AGENT_CLI,
        "-p",
        "--model",
        MODEL,
        "--output-format",
        "json",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": AGENT_HOME,
        "USER": "codingagent",
        "LOGNAME": "codingagent",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "ANTHROPIC_BASE_URL": os.environ.get("ANTHROPIC_BASE_URL", ""),
        "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
        "ANTHROPIC_AUTH_TOKEN": os.environ.get("ANTHROPIC_AUTH_TOKEN", ""),
        "NO_PROXY": os.environ.get("NO_PROXY", ""),
        "no_proxy": os.environ.get("no_proxy", ""),
        "GIT_OPTIONAL_LOCKS": "0",
        "PYTHONPYCACHEPREFIX": f"{AGENT_HOME}/.cache/coding-worker/{report_dir.name}",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
    }
    if PYTHON_BASELINE_ROOT:
        env["HERMES_PYTHON_BASELINE_ROOT"] = PYTHON_BASELINE_ROOT
    if PYTHON_BASELINE_COMMIT:
        env["HERMES_PYTHON_BASELINE_COMMIT"] = PYTHON_BASELINE_COMMIT
    task_log(report_dir, f"Starting independent {role} process ({label})")
    result = execute(command, cwd, AGENT_TIMEOUT, input_text=prompt, env=env)
    raw_path = report_dir / "raw" / f"{label}.json"
    write_redacted(raw_path, result.stdout)
    if result.stderr:
        write_redacted(report_dir / "raw" / f"{label}.stderr.log", result.stderr)
    if not result.ok:
        reason = "timed out" if result.timed_out else f"exited {result.returncode}"
        detail = redact_sensitive_text(safe_tail(result.stderr or result.stdout))
        raise AgentFailure(f"{role} {reason}: {detail}")
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AgentFailure(f"{role} returned invalid CLI JSON: {exc}") from exc
    if envelope.get("is_error") or envelope.get("subtype") != "success":
        detail = redact_sensitive_text(safe_tail(result.stdout))
        raise AgentFailure(f"{role} returned an error envelope: {detail}")
    answer = envelope.get("result")
    if not isinstance(answer, str) or not answer.strip():
        raise AgentFailure(f"{role} returned no final result")
    return redact_sensitive_text(answer.strip())


def run_agent(role: str, prompt: str, cwd: Path, report_dir: Path, label: str) -> str:
    last_error: Optional[Exception] = None
    for attempt in range(1, MAX_CONSECUTIVE_ERRORS + 1):
        attempt_label = label if attempt == 1 else f"{label}-retry-{attempt}"
        try:
            return run_agent_once(role, prompt, cwd, report_dir, attempt_label)
        except AgentFailure as exc:
            last_error = exc
            task_log(report_dir, f"{role} infrastructure error {attempt}/{MAX_CONSECUTIVE_ERRORS}: {exc}", logging.ERROR)
            if attempt < MAX_CONSECUTIVE_ERRORS:
                time.sleep(min(30, attempt * 5))
    raise AgentFailure(str(last_error))


def combined_diff(worktree: Path, base_branch: str) -> str:
    tracked = git(worktree, "diff", "--binary", base_branch, "--").stdout
    untracked_raw = git(worktree, "ls-files", "--others", "--exclude-standard", "-z").stdout
    pieces = [tracked]
    for relative in filter(None, untracked_raw.split("\0")):
        result = git(worktree, "diff", "--no-index", "--binary", "--", "/dev/null", relative, check=False)
        if result.returncode not in (0, 1):
            raise TaskFailure(f"Could not generate diff for untracked file {relative}: {result.stderr}")
        pieces.append(result.stdout)
    return "".join(pieces)


def workspace_fingerprint(worktree: Path, base_branch: str) -> str:
    status = git(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout
    content = status + "\0" + combined_diff(worktree, base_branch)
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def changed_paths(worktree: Path, base_ref: str) -> list[str]:
    tracked = git(worktree, "diff", "--name-only", "-z", base_ref, "--").stdout
    untracked = git(worktree, "ls-files", "--others", "--exclude-standard", "-z").stdout
    return sorted(set(filter(None, (tracked + untracked).split("\0"))))


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_coder_input_binding(
    rfc_text: str,
    metadata: dict[str, Any],
    task_id: str,
    worktree: Path,
) -> dict[str, Any]:
    """Bind a checkpoint to every mutable input that can change Coder behavior."""
    dependency_path = worktree / "coordination" / "requests" / task_id / "dependencies.json"
    dependency_present = dependency_path.exists()
    if dependency_present:
        try:
            dependency_path.resolve().relative_to(worktree.resolve())
        except ValueError as exc:
            raise TaskFailure("Coder dependency manifest escaped its worktree") from exc
        if dependency_path.is_symlink() or not dependency_path.is_file():
            raise TaskFailure("Coder dependency manifest must be a regular file")
    dependency = {
        "path": str(dependency_path.relative_to(worktree)),
        "present": dependency_present,
        "sha256": (
            hashlib.sha256(dependency_path.read_bytes()).hexdigest()
            if dependency_present
            else None
        ),
    }
    binding: dict[str, Any] = {
        "schema_version": 1,
        "task_id": task_id,
        "effective_rfc_sha256": hashlib.sha256(rfc_text.encode("utf-8")).hexdigest(),
        "commands": {
            key: {
                "present": key in metadata,
                "value_sha256": canonical_digest(metadata.get(key)) if key in metadata else None,
            }
            for key in ("lint_command", "build_command", "test_command")
        },
        "dependency_manifest": dependency,
    }
    binding["digest"] = canonical_digest(binding)
    return binding


def validate_input_binding(binding: dict[str, Any]) -> None:
    digest = str(binding.get("digest", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise TaskFailure("Coder input binding digest is missing or invalid")
    payload = {key: item for key, item in binding.items() if key != "digest"}
    if canonical_digest(payload) != digest:
        raise TaskFailure("Coder input binding digest is invalid")


def checkpoint_digest(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "checkpoint_digest"}
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def persist_coder_checkpoint(
    report_dir: Path,
    label: str,
    task_id: str,
    branch: str,
    base_commit: str,
    worktree: Path,
    base_ref: str,
    before_fingerprint: str,
    classification: str,
    *,
    input_binding: dict[str, Any],
    raw_path: Optional[Path] = None,
    diagnostics: tuple[str, ...] = (),
) -> dict[str, Any]:
    validate_input_binding(input_binding)
    checkpoints = report_dir / "coder-checkpoints"
    checkpoints.mkdir(parents=True, exist_ok=True)
    raw_diff = combined_diff(worktree, base_ref)
    patch = redact_sensitive_text(raw_diff)
    patch_path = checkpoints / f"{label}.patch"
    patch_path.write_text(patch, encoding="utf-8")
    raw_sha256 = None
    raw_relative = None
    if raw_path is not None and raw_path.is_file():
        raw_relative = str(raw_path.relative_to(report_dir))
        raw_sha256 = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at": utc_now(),
        "rfc": task_id,
        "branch": branch,
        "base_commit": base_commit,
        "head_commit": git(worktree, "rev-parse", "HEAD").stdout.strip(),
        "label": label,
        "classification": classification,
        "diagnostics": list(diagnostics),
        "before_fingerprint": before_fingerprint,
        "after_fingerprint": workspace_fingerprint(worktree, base_ref),
        "changed_paths": changed_paths(worktree, base_ref),
        "patch": str(patch_path.relative_to(report_dir)),
        "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        "workspace_patch_sha256": hashlib.sha256(raw_diff.encode("utf-8")).hexdigest(),
        "raw_envelope": raw_relative,
        "raw_envelope_sha256": raw_sha256,
        "input_binding": input_binding,
        "input_binding_digest": input_binding.get("digest"),
    }
    manifest["checkpoint_digest"] = checkpoint_digest(manifest)
    manifest_path = checkpoints / f"{label}.json"
    atomic_json(manifest_path, manifest)
    manifest["manifest"] = str(manifest_path.relative_to(report_dir))
    return manifest


def validate_coder_checkpoint(
    report_dir: Path,
    checkpoint: dict[str, Any],
    task_id: str,
    branch: str,
    base_commit: str,
    worktree: Path,
    base_ref: str,
    expected_input_binding: dict[str, Any],
) -> dict[str, Any]:
    manifest_relative = str(checkpoint.get("manifest", ""))
    manifest_path = (report_dir / manifest_relative).resolve()
    try:
        manifest_path.relative_to(report_dir.resolve())
    except ValueError as exc:
        raise TaskFailure("Coder checkpoint manifest escaped its report directory") from exc
    if not manifest_path.is_file():
        raise TaskFailure("Coder checkpoint manifest is missing")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TaskFailure(f"Coder checkpoint manifest is invalid JSON: {exc}") from exc
    expected_digest = str(checkpoint.get("checkpoint_digest", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise TaskFailure("Coder checkpoint digest is missing or invalid")
    if manifest.get("checkpoint_digest") != expected_digest:
        raise TaskFailure("Coder checkpoint status and manifest digests differ")
    if checkpoint_digest(manifest) != expected_digest:
        raise TaskFailure("Coder checkpoint manifest digest is invalid")
    expected_identity = {
        "rfc": task_id,
        "branch": branch,
        "base_commit": base_commit,
    }
    for key, expected in expected_identity.items():
        if manifest.get(key) != expected:
            raise TaskFailure(f"Coder checkpoint {key} does not match the retry target")
    recorded_binding = manifest.get("input_binding")
    if not isinstance(recorded_binding, dict):
        raise TaskFailure("Coder checkpoint input binding is missing")
    validate_input_binding(recorded_binding)
    validate_input_binding(expected_input_binding)
    if manifest.get("input_binding_digest") != recorded_binding.get("digest"):
        raise TaskFailure("Coder checkpoint input binding digest does not match its manifest")
    if recorded_binding != expected_input_binding:
        raise TaskFailure("Coder checkpoint inputs changed after the checkpoint was recorded")
    patch_relative = str(manifest.get("patch", ""))
    patch_path = (report_dir / patch_relative).resolve()
    try:
        patch_path.relative_to(report_dir.resolve())
    except ValueError as exc:
        raise TaskFailure("Coder checkpoint patch escaped its report directory") from exc
    if not patch_path.is_file():
        raise TaskFailure("Coder checkpoint patch is missing")
    patch = patch_path.read_text(encoding="utf-8")
    if hashlib.sha256(patch.encode("utf-8")).hexdigest() != manifest.get("patch_sha256"):
        raise TaskFailure("Coder checkpoint patch digest is invalid")
    raw_relative = manifest.get("raw_envelope")
    if raw_relative:
        raw_path = (report_dir / str(raw_relative)).resolve()
        try:
            raw_path.relative_to(report_dir.resolve())
        except ValueError as exc:
            raise TaskFailure("Coder raw envelope escaped its report directory") from exc
        if not raw_path.is_file():
            raise TaskFailure("Coder raw envelope is missing")
        if hashlib.sha256(raw_path.read_bytes()).hexdigest() != manifest.get(
            "raw_envelope_sha256"
        ):
            raise TaskFailure("Coder raw envelope digest is invalid")
    head_commit = git(worktree, "rev-parse", "HEAD").stdout.strip()
    if head_commit != manifest.get("head_commit"):
        raise TaskFailure("Coder worktree HEAD changed after the checkpoint was recorded")
    current_patch = combined_diff(worktree, base_ref)
    if hashlib.sha256(current_patch.encode("utf-8")).hexdigest() != manifest.get(
        "workspace_patch_sha256"
    ):
        raise TaskFailure("Coder worktree changed after the checkpoint was recorded")
    if workspace_fingerprint(worktree, base_ref) != manifest.get("after_fingerprint"):
        raise TaskFailure("Coder worktree fingerprint changed after the checkpoint was recorded")
    if changed_paths(worktree, base_ref) != manifest.get("changed_paths"):
        raise TaskFailure("Coder changed paths differ from the checkpoint")
    return manifest


def run_test_command(name: str, command: str, cwd: Path, report_dir: Path) -> CommandResult:
    task_log(report_dir, f"Running {name}: {command}")
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": AGENT_HOME,
        "USER": "codingagent",
        "LOGNAME": "codingagent",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONPYCACHEPREFIX": f"{AGENT_HOME}/.cache/coding-worker/{report_dir.name}",
    }
    if PYTHON_BASELINE_ROOT:
        env["HERMES_PYTHON_BASELINE_ROOT"] = PYTHON_BASELINE_ROOT
    if PYTHON_BASELINE_COMMIT:
        env["HERMES_PYTHON_BASELINE_COMMIT"] = PYTHON_BASELINE_COMMIT
    result = execute(
        [*AGENT_RUNNER, "bash", "-lc", command], cwd, TEST_TIMEOUT, env=env
    )
    header = (
        f"\n===== {utc_now()} {name} =====\n"
        f"COMMAND: {command}\nEXIT_CODE: {result.returncode}\nTIMED_OUT: {str(result.timed_out).lower()}\n"
        f"--- STDOUT ---\n{result.stdout}\n--- STDERR ---\n{result.stderr}\n"
    )
    append_text(report_dir / "tests.log", header)
    return result


def run_tests(metadata: dict[str, Any], cwd: Path, report_dir: Path) -> tuple[bool, str]:
    configured = [
        ("lint", metadata.get("lint_command", "")),
        ("build", metadata.get("build_command", "")),
        ("test", metadata.get("test_command", "")),
    ]
    if not any(command and command.strip() for _, command in configured):
        raise TaskFailure("RFC must configure at least one lint, build, or test command")
    summaries: list[str] = []
    all_passed = True
    for name, command in configured:
        if not command or not command.strip():
            continue
        result = run_test_command(name, command.strip(), cwd, report_dir)
        summaries.append(
            f"{name}: exit={result.returncode}, timed_out={result.timed_out}\n"
            f"stdout:\n{safe_tail(result.stdout, 5000)}\n"
            f"stderr:\n{safe_tail(result.stderr, 5000)}"
        )
        if not result.ok:
            all_passed = False
    return all_passed, "\n\n".join(summaries)


def run_full_regression(
    metadata: dict[str, Any], cwd: Path, report_dir: Path
) -> tuple[bool, str, str]:
    """Run the root-controlled final gate after independent review passes."""
    if not FULL_REGRESSION_COMMAND:
        return True, "full regression: not configured (legacy command set)", "SKIPPED"
    module_command = str(metadata.get("test_command", "")).strip()
    if module_command == FULL_REGRESSION_COMMAND:
        return True, "full regression: reused identical passing RFC test command", "REUSED"
    result = run_test_command(
        "full-regression", FULL_REGRESSION_COMMAND, cwd, report_dir
    )
    summary = (
        f"full-regression: exit={result.returncode}, timed_out={result.timed_out}\n"
        f"stdout:\n{safe_tail(result.stdout, 5000)}\n"
        f"stderr:\n{safe_tail(result.stderr, 5000)}"
    )
    return result.ok, summary, "PASS" if result.ok else "FAIL"


def json_object_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for start, character in enumerate(text):
        if character != "{":
            continue
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            current = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == '"':
                    in_string = False
                continue
            if current == '"':
                in_string = True
            elif current == "{":
                depth += 1
            elif current == "}":
                depth -= 1
                if depth == 0:
                    candidates.append(text[start : index + 1])
                    break
                if depth < 0:
                    break
    return candidates


def escape_invalid_json_string_escapes(candidate: str) -> str:
    """Repair only invalid JSON string escapes, preserving all other bytes."""
    output: list[str] = []
    in_string = False
    index = 0
    while index < len(candidate):
        character = candidate[index]
        if character == '"':
            in_string = not in_string
            output.append(character)
            index += 1
            continue
        if in_string and character == "\\" and index + 1 < len(candidate):
            escaped = candidate[index + 1]
            if escaped in '"\\/bfnrt':
                output.extend((character, escaped))
                index += 2
                continue
            if escaped == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", candidate[index + 2 : index + 6]):
                output.append(candidate[index : index + 6])
                index += 6
                continue
            output.extend(("\\", "\\", escaped))
            index += 2
            continue
        output.append(character)
        index += 1
    return "".join(output)


def decode_review_object(text: str, *, tolerate_invalid_escapes: bool = False) -> dict[str, Any]:
    errors: list[str] = []
    for candidate in json_object_candidates(text):
        value_text = (
            escape_invalid_json_string_escapes(candidate)
            if tolerate_invalid_escapes
            else candidate
        )
        try:
            value = json.loads(value_text)
        except json.JSONDecodeError as exc:
            errors.append(f"line {exc.lineno} column {exc.colno}: {exc.msg}")
            continue
        if isinstance(value, dict) and "verdict" in value:
            return value
    detail = errors[-1] if errors else "no balanced JSON object containing verdict"
    raise ReviewFormatError(f"Reviewer JSON could not be decoded: {detail}")


def extract_json_object(text: str) -> dict[str, Any]:
    return decode_review_object(text)


def validate_review(text: str) -> dict[str, Any]:
    review = extract_json_object(text)
    verdict = review.get("verdict")
    if verdict not in {"PASS", "REQUEST_CHANGES"}:
        raise ReviewFormatError("Reviewer verdict must be PASS or REQUEST_CHANGES")
    issues = review.get("required_changes", review.get("issues"))
    if not isinstance(issues, list) or not all(isinstance(issue, str) for issue in issues):
        raise ReviewFormatError("Reviewer required_changes must be an array of strings")
    if verdict == "REQUEST_CHANGES" and not issues:
        raise ReviewFormatError("REQUEST_CHANGES must include at least one issue")
    if verdict == "PASS" and issues:
        raise ReviewFormatError("PASS must use an empty required_changes array")
    if verdict == "REQUEST_CHANGES":
        required_markers = ("Issue:", "Location:", "Reproduction:", "Acceptance:")
        for issue in issues:
            missing = [marker for marker in required_markers if marker.casefold() not in issue.casefold()]
            if missing:
                raise ReviewFormatError(
                    "Each required change must include Issue, Location, Reproduction, and Acceptance markers"
                )
    review["required_changes"] = issues
    for key in (
        "summary",
        "test_review",
        "architecture_scope_review",
        "security_review",
    ):
        if not isinstance(review.get(key), str) or not review[key].strip():
            raise ReviewFormatError(f"Reviewer {key} must be a non-empty string")
    for key in ("acceptance_criteria", "code_review_findings", "regression_risks"):
        if not isinstance(review.get(key), list) or not all(
            isinstance(item, str) for item in review[key]
        ):
            raise ReviewFormatError(f"Reviewer {key} must be an array of strings")
    return review


def normalize_review_text(value: str) -> str:
    controls = {"\b": r"\b", "\f": r"\f", "\n": r"\n", "\r": r"\r", "\t": r"\t"}
    normalized = "".join(controls.get(character, character) for character in value)
    return " ".join(normalized.split()).casefold()


def review_invariants(text: str) -> dict[str, Any]:
    review = decode_review_object(text, tolerate_invalid_escapes=True)
    verdict = review.get("verdict")
    issues = review.get("required_changes", review.get("issues"))
    if verdict not in {"PASS", "REQUEST_CHANGES"}:
        raise ReviewFormatError("Cannot safely repair review without a valid original verdict")
    if not isinstance(issues, list) or not all(isinstance(issue, str) for issue in issues):
        raise ReviewFormatError("Cannot safely repair review without its original required changes")
    if verdict == "PASS" and issues:
        raise ReviewFormatError("Original PASS review contains required changes")
    if verdict == "REQUEST_CHANGES" and not issues:
        raise ReviewFormatError("Original REQUEST_CHANGES review contains no issue")
    review["required_changes"] = issues
    return review


def review_preserves_invariants(original: dict[str, Any], repaired: dict[str, Any]) -> bool:
    if repaired.get("verdict") != original.get("verdict"):
        return False
    original_issues = original.get("required_changes", [])
    repaired_issues = repaired.get("required_changes", [])
    if len(original_issues) != len(repaired_issues):
        return False
    for source, destination in zip(original_issues, repaired_issues):
        if normalize_review_text(source) not in normalize_review_text(destination):
            return False
    for key in ("acceptance_criteria", "code_review_findings", "regression_risks"):
        source_items = original.get(key)
        destination_items = repaired.get(key)
        if not isinstance(source_items, list) or not all(isinstance(item, str) for item in source_items):
            continue
        if not isinstance(destination_items, list) or len(source_items) > len(destination_items):
            return False
        normalized_destination = [normalize_review_text(item) for item in destination_items]
        if any(
            not any(normalize_review_text(item) in candidate for candidate in normalized_destination)
            for item in source_items
        ):
            return False
    for key in ("summary", "test_review", "architecture_scope_review", "security_review"):
        source = original.get(key)
        destination = repaired.get(key)
        if isinstance(source, str) and (
            not isinstance(destination, str)
            or normalize_review_text(source) != normalize_review_text(destination)
        ):
            return False
    return True


def review_format_repair_prompt(
    original: dict[str, Any], parse_error: str, repair_attempt: int
) -> str:
    canonical = json.dumps(original, ensure_ascii=True, indent=2)
    return f"""# Role: Reviewer Output Formatter

You are formatting an already completed independent review. Do not inspect or modify code.
Do not change the verdict, summary, findings, acceptance assessments, risks, or issue count.
Do not remove, combine, soften, or invent required changes. Never turn REQUEST_CHANGES into PASS.

The previous serialization error was: {parse_error}
Format repair attempt: {repair_attempt}/{MAX_REVIEW_FORMAT_REPAIRS}

Return exactly one JSON object with the Reviewer schema and no Markdown fence or preamble.
For every REQUEST_CHANGES item, preserve the original issue text verbatim inside `Issue:` and append
`Location:`, `Reproduction:`, and `Acceptance:` fields grounded only in that same original issue.

Canonical original review object:
{canonical}
"""


def validate_review_with_repairs(
    review_text: str,
    report_dir: Path,
    artifact_stem: str,
    repair: Callable[[str, int], str],
) -> tuple[dict[str, Any], int]:
    current = redact_sensitive_text(review_text)
    write_redacted(report_dir / f"review-raw-{artifact_stem}-format-0.txt", current)
    diagnostics: list[dict[str, Any]] = []
    try:
        original = review_invariants(current)
    except ReviewFormatError as exc:
        diagnostics.append({"format_attempt": 0, "error": str(exc), "repair_safe": False})
        atomic_json(report_dir / f"review-format-diagnostics-{artifact_stem}.json", {"attempts": diagnostics})
        raise ReviewInfrastructureFailure(
            "REVIEW_INFRA_FAILED: original verdict/issues could not be recovered without invention"
        ) from exc

    last_error = "unknown review format error"
    for format_attempt in range(0, MAX_REVIEW_FORMAT_REPAIRS + 1):
        try:
            review = validate_review(current)
            if not review_preserves_invariants(original, review):
                raise ReviewFormatError(
                    "Formatted review changed the original verdict, findings, or required changes"
                )
            diagnostics.append(
                {
                    "format_attempt": format_attempt,
                    "result": "PASS",
                    "sha256": hashlib.sha256(current.encode("utf-8")).hexdigest(),
                }
            )
            atomic_json(
                report_dir / f"review-format-diagnostics-{artifact_stem}.json",
                {"attempts": diagnostics},
            )
            return review, format_attempt
        except ReviewFormatError as exc:
            last_error = str(exc)
            diagnostics.append(
                {
                    "format_attempt": format_attempt,
                    "result": "INVALID",
                    "error": last_error,
                    "sha256": hashlib.sha256(current.encode("utf-8")).hexdigest(),
                }
            )
        if format_attempt >= MAX_REVIEW_FORMAT_REPAIRS:
            break
        current = redact_sensitive_text(
            repair(review_format_repair_prompt(original, last_error, format_attempt + 1), format_attempt + 1)
        )
        write_redacted(
            report_dir / f"review-raw-{artifact_stem}-format-{format_attempt + 1}.txt",
            current,
        )

    atomic_json(
        report_dir / f"review-format-diagnostics-{artifact_stem}.json",
        {"attempts": diagnostics},
    )
    raise ReviewInfrastructureFailure(
        f"REVIEW_INFRA_FAILED: no schema-valid, invariant-preserving review after "
        f"{MAX_REVIEW_FORMAT_REPAIRS} format repairs: {last_error}"
    )


CODER_REPORT_HEADINGS = (
    "# Coding Report",
    "## Summary",
    "## Files Changed",
    "## Implementation Details",
    "## Technical Decisions",
    "## RFC Deviations",
    "## Tests",
    "## Known Limitations",
    "## Risks",
    "## Follow-up Suggestions",
)

CODER_COMPLETION_RE = re.compile(r"(?m)^Completion Status: (CONTINUE|READY_FOR_TESTS)$")
CODER_TOOL_CALL_OPEN_RE = re.compile(
    r"(?is)(?:<(?:\|DSML\||｜DSML｜)tool_calls\s*>|<tool_calls\s*>)"
)
CODER_TOOL_INVOKE_RE = re.compile(
    r"(?is)(?:<(?:\|DSML\||｜DSML｜)invoke\b|<invoke\b|<tool_call\b)"
)
CODER_TOOL_BODY_RE = re.compile(
    r"(?is)(?:<(?:\|DSML\||｜DSML｜)parameter\b|<parameter\b|"
    r"[\"'](?:tool|arguments|parameters)[\"']\s*:)"
)


def coder_report_errors(text: str) -> list[str]:
    return [heading for heading in CODER_REPORT_HEADINGS if heading not in text]


def normalize_coder_report(text: str) -> str:
    marker = text.find("# Coding Report")
    return text[marker:].strip() if marker >= 0 else text.strip()


def contains_structural_tool_call_markup(text: str) -> bool:
    """Reject serialized tool calls, without treating prose marker mentions as evidence."""
    opening = CODER_TOOL_CALL_OPEN_RE.search(text)
    if opening is None:
        return False
    remainder = text[opening.end() :]
    invoke = CODER_TOOL_INVOKE_RE.search(remainder)
    if invoke is None:
        return False
    return CODER_TOOL_BODY_RE.search(remainder[invoke.start() :]) is not None


def assess_coder_output(text: str) -> CoderOutputAssessment:
    redacted = redact_sensitive_text(text.strip())
    if contains_structural_tool_call_markup(redacted):
        return CoderOutputAssessment(
            "CODER_PROTOCOL_OUTPUT_INVALID",
            redacted,
            ("literal tool-protocol markup appeared in the final result",),
        )
    completions = CODER_COMPLETION_RE.findall(redacted)
    if not completions:
        return CoderOutputAssessment(
            "CODER_REPORT_INVALID",
            normalize_coder_report(redacted),
            ("missing Completion Status: READY_FOR_TESTS",),
        )
    if len(completions) > 1:
        return CoderOutputAssessment(
            "CODER_REPORT_INVALID", redacted, ("multiple completion statuses",)
        )
    completion = completions[0]
    if completion == "CONTINUE":
        return CoderOutputAssessment("CONTINUE", redacted)
    normalized = normalize_coder_report(redacted)
    missing = tuple(coder_report_errors(normalized))
    if missing:
        return CoderOutputAssessment("CODER_REPORT_INVALID", normalized, missing)
    if completion != "READY_FOR_TESTS":
        return CoderOutputAssessment(
            "CODER_REPORT_INVALID", normalized, ("invalid completion status",)
        )
    return CoderOutputAssessment("READY_FOR_TESTS", normalized)


def latest_agent_raw_path(report_dir: Path, label: str) -> Optional[Path]:
    candidates = list((report_dir / "raw").glob(f"{label}*.json"))
    return max(candidates, key=lambda path: path.stat().st_mtime) if candidates else None


def markdown_list(items: list[str], empty: str = "None.") -> str:
    return "\n".join(f"- {item}" for item in items) if items else empty


def render_review_report(review: dict[str, Any], task_id: str, attempt: int, cycle: int) -> str:
    return f"""# Review Report - {task_id}

Attempt {attempt}, review cycle {cycle}.

## Verdict

{review['verdict']}

## Acceptance Criteria Review

{markdown_list(review['acceptance_criteria'])}

## Code Review Findings

{markdown_list(review['code_review_findings'])}

## Test Review

{review['test_review']}

## Architecture / Scope Review

{review['architecture_scope_review']}

## Security Review

{review['security_review']}

## Regression Risks

{markdown_list(review['regression_risks'])}

## Required Changes

{markdown_list(review['required_changes'])}
"""


def markdown_section(text: str, heading: str) -> str:
    pattern = re.compile(
        rf"^## {re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)", re.MULTILINE | re.DOTALL
    )
    match = pattern.search(text)
    return match.group(1).strip() if match else "Not stated."


def github_repository_url(remote_url: str) -> Optional[str]:
    match = re.fullmatch(r"git@github\.com:([^/]+)/(.+?)(?:\.git)?", remote_url)
    if not match:
        return None
    return f"https://github.com/{match.group(1)}/{match.group(2)}"


def create_pr_description(
    task_id: str,
    rfc_text: str,
    metadata: dict[str, Any],
    coder_report: str,
    review: dict[str, Any],
    commit_sha: str,
    report_dir: Path,
) -> str:
    acceptance = markdown_section(rfc_text, "Acceptance Criteria").replace("- [ ]", "- [x]")
    commands = [
        str(metadata.get(key, "")).strip()
        for key in ("lint_command", "build_command", "test_command")
        if str(metadata.get(key, "")).strip()
    ]
    if FULL_REGRESSION_COMMAND and FULL_REGRESSION_COMMAND not in commands:
        commands.append(FULL_REGRESSION_COMMAND)
    test_lines = "\n".join(f"- PASS: `{command}`" for command in commands)
    description = f"""## RFC

{task_id}

## Goal

{markdown_section(rfc_text, 'Goal')}

## Acceptance Criteria

{acceptance}

## Implementation

{markdown_section(coder_report, 'Summary')}

## Key Decisions

{markdown_section(coder_report, 'Technical Decisions')}

## Tests

{test_lines}
- Full evidence: `reports/{task_id}/tests.log` in the bound container

## Reviewer

{review['verdict']}: {review['summary']}

## Commit

`{commit_sha}`

## Reports

Container report: `reports/{task_id}/`
"""
    (report_dir / "pr-description.md").write_text(description, encoding="utf-8")
    return description


def update_status(report_dir: Path, state: dict[str, Any], **changes: Any) -> None:
    sequence = int(state.get("event_sequence", 0) or 0) + 1
    state.update(changes)
    state["updated_at"] = utc_now()
    state["event_sequence"] = sequence
    atomic_json(report_dir / "status.json", state)
    event = {
        "sequence": sequence,
        "occurred_at": state["updated_at"],
        "status": state.get("status"),
        "phase": state.get("phase"),
        "tests_status": state.get("tests_status"),
        "module_tests_status": state.get("module_tests_status"),
        "full_regression_status": state.get("full_regression_status"),
        "review": state.get("review"),
        "push": state.get("push"),
        "changes": sorted(changes),
    }
    append_text(
        report_dir / "events.jsonl",
        json.dumps(event, ensure_ascii=False, separators=(",", ":")),
    )


def configured_commands(metadata: dict[str, Any]) -> dict[str, str]:
    commands = {
        key: str(metadata.get(key, "")).strip()
        for key in ("lint_command", "build_command", "test_command")
    }
    commands["full_regression_command"] = FULL_REGRESSION_COMMAND
    return commands


def build_review_candidate(
    rfc_text: str,
    metadata: dict[str, Any],
    base_commit: str,
    worktree: Path,
    base_ref: str,
    coder_report: str,
) -> dict[str, Any]:
    return {
        "rfc_sha256": hashlib.sha256(rfc_text.encode("utf-8")).hexdigest(),
        "commands": configured_commands(metadata),
        "base_commit": base_commit,
        "workspace_fingerprint": workspace_fingerprint(worktree, base_ref),
        "coder_report_sha256": hashlib.sha256(coder_report.encode("utf-8")).hexdigest(),
    }


def review_candidate_is_reusable(
    previous_status: dict[str, Any],
    candidate: dict[str, Any],
    coder_report: str,
) -> bool:
    if previous_status.get("status") != "review_infra_failed":
        return False
    if previous_status.get("tests_status") != "PASS" or not previous_status.get("tests_passed"):
        return False
    if coder_report_errors(coder_report):
        return False
    previous_candidate = previous_status.get("validated_candidate")
    return isinstance(previous_candidate, dict) and previous_candidate == candidate


def coder_prompt(
    rfc_text: str,
    task_id: str,
    worktree: Path,
    branch: str,
    feedback: str,
    cycle: int,
) -> str:
    correction = (
        f"\n# Required Corrections From Previous Attempt\n{feedback}\n"
        if feedback and feedback not in rfc_text
        else ""
    )
    return (
        load_prompt("coder.md")
        + f"\n\n# Runtime Context\n"
        + f"RFC ID: {task_id}\nProject root: {PROJECT_ROOT}\nWorktree: {worktree}\nBranch: {branch}\n"
        + f"Working directory: {worktree}\nCoder cycle: {cycle}/{MAX_CODER_CYCLES}\n"
        + "The existing worktree is the authoritative checkpoint. Continue from it; do not "
        + "discard or broadly rewrite prior work without a demonstrated correctness reason. "
        + "Never print tool-call protocol markup as text. If more implementation work remains, "
        + "return the required Coder Progress Checkpoint with Completion Status: CONTINUE. "
        + "Return Completion Status: READY_FOR_TESTS only after the implementation and its "
        + "required tests are ready for the independent Worker gates.\n"
        + f"\n# RFC\n{rfc_text}\n"
        + correction
    )


def record_coder_lifecycle_action(
    report_dir: Path,
    status: dict[str, Any],
    classification: str,
) -> None:
    lifecycle_total = int(status.get("total_coder_lifecycle_actions", 0) or 0) + 1
    changes: dict[str, Any] = {"total_coder_lifecycle_actions": lifecycle_total}
    exceeded = lifecycle_total > MAX_CODER_LIFECYCLE_ACTIONS
    if classification == "CODER_PROTOCOL_OUTPUT_INVALID":
        protocol_total = int(status.get("total_coder_protocol_failures", 0) or 0) + 1
        changes["total_coder_protocol_failures"] = protocol_total
        exceeded = exceeded or protocol_total >= MAX_CODER_PROTOCOL_FAILURES_TOTAL
    elif classification == "CONTINUE":
        continuation_total = int(status.get("total_coder_continuations", 0) or 0) + 1
        changes["total_coder_continuations"] = continuation_total
        exceeded = exceeded or continuation_total >= MAX_CODER_CONTINUATIONS_TOTAL
    update_status(report_dir, status, **changes)
    if exceeded:
        raise CoderInfrastructureFailure(
            "CODER_LIFECYCLE_LIMIT_EXCEEDED: persistent Coder recovery limits were exceeded"
        )


def require_coder_lifecycle_capacity(status: dict[str, Any]) -> None:
    if int(status.get("total_coder_lifecycle_actions", 0) or 0) >= MAX_CODER_LIFECYCLE_ACTIONS:
        raise CoderInfrastructureFailure(
            "CODER_LIFECYCLE_LIMIT_EXCEEDED: no Coder lifecycle actions remain"
        )


def run_coder_until_gate(
    rfc_text: str,
    metadata: dict[str, Any],
    task_id: str,
    worktree: Path,
    branch: str,
    base_commit: str,
    base_ref: str,
    report_dir: Path,
    status: dict[str, Any],
    attempt: int,
    cycle: int,
    feedback: str,
) -> tuple[CoderOutputAssessment, dict[str, Any]]:
    continuations = 0
    protocol_retry = 0
    current_feedback = feedback
    while True:
        require_coder_lifecycle_capacity(status)
        base_label = f"attempt-{attempt}-coder-{cycle}"
        label = (
            base_label
            if continuations == 0 and protocol_retry == 0
            else f"{base_label}-continuation-{continuations}-protocol-{protocol_retry}"
        )
        input_binding = build_coder_input_binding(rfc_text, metadata, task_id, worktree)
        before = workspace_fingerprint(worktree, base_ref)
        answer = run_agent(
            "Coder",
            coder_prompt(rfc_text, task_id, worktree, branch, current_feedback, cycle),
            worktree,
            report_dir,
            label,
        )
        assessment = assess_coder_output(answer)
        output_path = report_dir / "coder-outputs" / f"{label}.md"
        write_redacted(output_path, assessment.normalized + "\n")
        raw_path = latest_agent_raw_path(report_dir, label)
        if raw_path is None:
            raise CoderInfrastructureFailure(
                "CODER_CHECKPOINT_FAILED: redacted raw Coder envelope is missing"
            )
        if build_coder_input_binding(rfc_text, metadata, task_id, worktree) != input_binding:
            raise CoderInfrastructureFailure(
                "CODER_INPUT_CHANGED: RFC commands or dependency manifest changed during Coder execution"
            )
        checkpoint = persist_coder_checkpoint(
            report_dir,
            label,
            task_id,
            branch,
            base_commit,
            worktree,
            base_ref,
            before,
            assessment.classification,
            input_binding=input_binding,
            raw_path=raw_path,
            diagnostics=assessment.errors,
        )
        update_status(
            report_dir,
            status,
            coder_checkpoint=checkpoint,
            coder_output_classification=assessment.classification,
            coder_continuations=continuations,
            coder_protocol_retries=protocol_retry,
        )
        record_coder_lifecycle_action(report_dir, status, assessment.classification)
        if assessment.classification == "CODER_PROTOCOL_OUTPUT_INVALID":
            task_log(
                report_dir,
                f"Coder protocol output invalid at {label}; checkpoint preserved",
                logging.ERROR,
            )
            if protocol_retry >= MAX_CODER_PROTOCOL_RETRIES:
                raise CoderInfrastructureFailure(
                    "CODER_PROTOCOL_OUTPUT_INVALID: literal tool protocol output persisted after "
                    f"{MAX_CODER_PROTOCOL_RETRIES} controlled retries"
                )
            protocol_retry += 1
            current_feedback = (
                "The previous final result contained literal tool-call protocol markup. The Worker "
                "did not execute that markup. Resume from the actual current worktree. Do not repeat "
                "or quote the markup. Use native tools only during execution, then return exactly one "
                "Coder Progress Checkpoint or Coding Report with the required Completion Status."
            )
            continue
        protocol_retry = 0
        if assessment.classification == "CONTINUE":
            continuations += 1
            update_status(
                report_dir,
                status,
                phase="coding_checkpoint",
                coder_continuations=continuations,
            )
            task_log(
                report_dir,
                f"Coder checkpoint {continuations}/{MAX_CODER_CONTINUATIONS} preserved; continuing",
            )
            if continuations >= MAX_CODER_CONTINUATIONS:
                raise CoderInfrastructureFailure(
                    "CODER_CONTINUATION_LIMIT_EXCEEDED: implementation did not reach "
                    f"READY_FOR_TESTS after {MAX_CODER_CONTINUATIONS} checkpoints"
                )
            current_feedback = (
                "Your prior progress checkpoint was preserved. Continue the remaining RFC work from "
                "the current worktree, focusing on the stated Next Focus. Do not restart completed "
                "work. Return CONTINUE while work remains or READY_FOR_TESTS with the complete Coding "
                "Report only when all required implementation and test artifacts are ready.\n\n"
                + safe_tail(assessment.normalized, 6000)
            )
            update_status(report_dir, status, phase="coding")
            continue
        return assessment, checkpoint


def reviewer_prompt(
    rfc_text: str,
    task_id: str,
    worktree: Path,
    base_branch: str,
    branch: str,
    report_dir: Path,
    cycle: int,
) -> str:
    return (
        load_prompt("reviewer.md")
        + f"\n\n# Runtime Context\nRFC ID: {task_id}\nWorktree: {worktree}\n"
        + f"Project root: {PROJECT_ROOT}\nBase branch: {base_branch}\nTask branch: {branch}\n"
        + f"Review cycle: {cycle}/{MAX_REVIEW_CYCLES}\n"
        + f"Complete worker-generated diff: {report_dir / 'diff.patch'}\n"
        + f"Coder report: {report_dir / 'coder-report.md'}\n"
        + f"Independent test log: {report_dir / 'tests.log'}\n"
        + f"\n# RFC\n{rfc_text}\n"
    )


def perform_review(
    rfc_text: str,
    task_id: str,
    worktree: Path,
    base_ref: str,
    branch: str,
    report_dir: Path,
    attempt: int,
    cycle: int,
) -> tuple[dict[str, Any], int]:
    before = workspace_fingerprint(worktree, base_ref)
    review_text = run_agent(
        "Reviewer",
        reviewer_prompt(rfc_text, task_id, worktree, base_ref, branch, report_dir, cycle),
        worktree,
        report_dir,
        f"attempt-{attempt}-reviewer-{cycle}",
    )

    def repair(prompt: str, format_attempt: int) -> str:
        return run_agent(
            "ReviewerFormatter",
            prompt,
            worktree,
            report_dir,
            f"attempt-{attempt}-reviewer-{cycle}-format-{format_attempt}",
        )

    artifact_stem = f"attempt-{attempt}-cycle-{cycle}"
    review, repairs = validate_review_with_repairs(
        review_text, report_dir, artifact_stem, repair
    )
    after = workspace_fingerprint(worktree, base_ref)
    if before != after:
        raise TaskFailure("Reviewer or format repair modified the task worktree; review aborted")
    human_review = render_review_report(review, task_id, attempt, cycle)
    (report_dir / f"review-attempt-{attempt}-cycle-{cycle}.md").write_text(
        human_review, encoding="utf-8"
    )
    (report_dir / "review-report.md").write_text(human_review, encoding="utf-8")
    atomic_json(report_dir / f"review-attempt-{attempt}-cycle-{cycle}.json", review)
    atomic_json(report_dir / "review-latest.json", review)
    return review, repairs


def commit_result(task_id: str, title: str, worktree: Path, base_ref: str, report_dir: Path) -> str:
    git(worktree, "add", "-A")
    if git(worktree, "diff", "--cached", "--quiet", check=False).returncode == 0:
        head = git(worktree, "rev-parse", "HEAD").stdout.strip()
        base = git(worktree, "rev-parse", base_ref).stdout.strip()
        if head == base:
            raise TaskFailure("Coder produced no committable changes")
        # A prior worker may have committed and crashed before final status was
        # persisted. Reusing that task-branch commit makes recovery idempotent.
        final_diff = git(worktree, "diff", "--binary", f"{base_ref}...HEAD", "--").stdout
        (report_dir / "diff.patch").write_text(final_diff, encoding="utf-8")
        return head
    message = f"{task_id}: {title}" if title else task_id
    git(
        worktree,
        "-c",
        "user.name=Coding Worker",
        "-c",
        "user.email=coding-worker@localhost",
        "commit",
        "--no-verify",
        "-m",
        message,
        "-m",
        f"RFC: {task_id}\nTests: PASS\nReview: PASS",
    )
    commit_sha = git(worktree, "rev-parse", "HEAD").stdout.strip()
    final_diff = git(worktree, "diff", "--binary", f"{base_ref}...HEAD", "--").stdout
    (report_dir / "diff.patch").write_text(final_diff, encoding="utf-8")
    return commit_sha


def push_result(
    repo: Path, task_id: str, branch: str, commit_sha: str
) -> tuple[str, Optional[str]]:
    if branch != f"agent/{task_id}" or not BRANCH_RE.fullmatch(branch):
        raise TaskFailure(f"Refusing to push unsafe task branch: {branch}")
    if branch in {BASE_BRANCH, "main", "master"}:
        raise TaskFailure("Refusing to push a protected base branch")
    git(repo, "push", GIT_REMOTE, f"refs/heads/{branch}:refs/heads/{branch}")
    remote_line = git(repo, "ls-remote", "--heads", GIT_REMOTE, branch).stdout.strip()
    if not remote_line or remote_line.split()[0] != commit_sha:
        raise TaskFailure("Remote task branch does not resolve to the accepted commit after push")
    remote_url = git(repo, "remote", "get-url", GIT_REMOTE).stdout.strip()
    repository_url = github_repository_url(remote_url)
    compare_url = None
    if repository_url:
        compare_url = (
            f"{repository_url}/compare/{urllib.parse.quote(BASE_BRANCH, safe='')}..."
            f"{urllib.parse.quote(branch, safe='')}?expand=1"
        )
    return remote_url, compare_url


def review_feedback(review: dict[str, Any]) -> str:
    return "Independent review requested these changes:\n" + "\n".join(
        f"{index}. {issue}"
        for index, issue in enumerate(review["required_changes"], start=1)
    )


def complete_task(
    task_id: str,
    metadata: dict[str, Any],
    rfc_text: str,
    answer: str,
    review: dict[str, Any],
    repo: Path,
    worktree: Path,
    base_ref: str,
    branch: str,
    report_dir: Path,
    status: dict[str, Any],
) -> None:
    update_status(report_dir, status, phase="committing")
    commit_sha = commit_result(
        task_id, str(metadata.get("title", "")).strip(), worktree, base_ref, report_dir
    )
    update_status(report_dir, status, phase="pushing", commit_sha=commit_sha)
    remote_url, compare_url = push_result(repo, task_id, branch, commit_sha)
    create_pr_description(task_id, rfc_text, metadata, answer, review, commit_sha, report_dir)
    prior_pr_url = status.get("pr_url")
    prior_pr_status = status.get("pr_status")
    status.pop("pending_amendment", None)
    update_status(
        report_dir,
        status,
        status="done",
        phase="complete",
        commit_sha=commit_sha,
        tests_passed=True,
        tests_status="PASS",
        review="PASS",
        push="PASS",
        remote_url=remote_url,
        compare_url=compare_url,
        pr_status=prior_pr_status if prior_pr_url else "not_created",
        pr_url=prior_pr_url,
        completed_at=utc_now(),
    )
    task_log(report_dir, f"Completed and pushed {branch} at {commit_sha}")
    if not KEEP_SUCCESS_WORKTREES:
        # Build tools can leave owner-only ignored directories. Restore the
        # shared-group permissions before codingworker removes the worktree.
        prepare_agent_worktree(worktree)
        git(repo, "worktree", "remove", "--force", str(worktree))
        git(repo, "worktree", "prune")
        update_status(report_dir, status, worktree_removed=True)


def process_task(rfc_path: Path) -> None:
    task_id = rfc_path.stem
    report_dir = REPORTS / task_id
    report_dir.mkdir(parents=True, exist_ok=True)
    if not TASK_ID_RE.fullmatch(task_id):
        raise TaskFailure(f"Invalid RFC filename stem: {task_id}")

    status_path = report_dir / "status.json"
    had_status = status_path.exists()
    if had_status:
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            status = {}
    else:
        status = {}
    previous_status = dict(status)
    previous_total_reviews = int(status.get("total_review_cycles", status.get("review_cycles", 0)) or 0)
    previous_total_coder = int(status.get("total_coder_cycles", status.get("coder_cycles", 0)) or 0)
    attempt = int(status.get("attempts", 0) or 0) + 1
    if status.get("failure"):
        history = status.get("failure_history", [])
        if not isinstance(history, list):
            history = []
        history.append(
            {
                "attempt": max(1, attempt - 1),
                "failed_at": status.get("failed_at"),
                "failure": status["failure"],
            }
        )
        status["failure_history"] = history
    status.pop("failure", None)
    status.pop("failed_at", None)
    status.pop("failure_kind", None)
    status.update(
        {
            "rfc": task_id,
            "status": "working",
            "phase": "initializing",
            "model": MODEL,
            "tests_passed": False,
            "tests_status": "PENDING",
            "module_tests_status": "PENDING",
            "full_regression_status": "PENDING" if FULL_REGRESSION_COMMAND else "SKIPPED",
            "review": None,
            "review_cycles": 0,
            "coder_cycles": 0,
            "total_review_cycles": previous_total_reviews,
            "total_coder_cycles": previous_total_coder,
            "total_coder_protocol_failures": int(
                status.get("total_coder_protocol_failures", 0) or 0
            ),
            "total_coder_continuations": int(status.get("total_coder_continuations", 0) or 0),
            "total_coder_lifecycle_actions": int(
                status.get("total_coder_lifecycle_actions", 0) or 0
            ),
            "attempts": attempt,
            "started_at": status.get("started_at", utc_now()),
        }
    )
    update_status(report_dir, status)
    task_log(report_dir, f"Processing {rfc_path}")

    metadata, rfc_text = parse_rfc(rfc_path)
    amendment = previous_status.get("pending_amendment")
    amendment_text = ""
    if isinstance(amendment, dict):
        amendment_path = report_dir / "amendments" / str(amendment.get("file", ""))
        try:
            amendment_path.resolve().relative_to((report_dir / "amendments").resolve())
        except ValueError as exc:
            raise TaskFailure("Pending amendment path escaped its report directory") from exc
        if not amendment_path.is_file():
            raise TaskFailure("Pending amendment report is missing")
        amendment_text = amendment_path.read_text(encoding="utf-8")
    effective_rfc_text = rfc_text
    if amendment_text:
        effective_rfc_text += "\n\n" + amendment_text
    repo, worktree, base_branch, branch, base_commit = prepare_worktree(
        task_id, report_dir, had_status
    )
    base_ref = base_commit
    status.update(
        {
            "title": str(metadata.get("title", "")).strip(),
            "project_root": str(repo),
            "worktree": str(worktree),
            "branch": branch,
            "base_branch": base_branch,
            "base_commit": base_commit,
            "git_remote": GIT_REMOTE,
            "pr_status": previous_status.get("pr_status", "not_created"),
            "pr_url": previous_status.get("pr_url"),
        }
    )
    if previous_status.get("status") == "coder_retry_queued":
        recorded_base = str(previous_status.get("base_commit", ""))
        checkpoint = previous_status.get("coder_checkpoint")
        if recorded_base != base_commit or not isinstance(checkpoint, dict):
            raise TaskFailure("Queued Coder retry lost its recorded base or checkpoint")
        validate_coder_checkpoint(
            report_dir,
            checkpoint,
            task_id,
            branch,
            base_commit,
            worktree,
            base_ref,
            build_coder_input_binding(effective_rfc_text, metadata, task_id, worktree),
        )
        task_log(report_dir, "Revalidated Coder checkpoint after queue claim")
    update_status(report_dir, status, phase="coding")

    feedback = amendment_text
    review_cycles = 0
    coder_report_path = report_dir / "coder-report.md"
    if coder_report_path.is_file():
        prior_answer = coder_report_path.read_text(encoding="utf-8").strip()
        current_candidate = build_review_candidate(
            effective_rfc_text,
            metadata,
            base_commit,
            worktree,
            base_ref,
            prior_answer,
        )
        if review_candidate_is_reusable(previous_status, current_candidate, prior_answer):
            review_cycles = 1
            update_status(
                report_dir,
                status,
                phase="reviewing_resume",
                tests_passed=True,
                tests_status="PASS",
                module_tests_status="PASS",
                validated_candidate=current_candidate,
                review_cycles=review_cycles,
                total_review_cycles=previous_total_reviews + review_cycles,
                reviewer_resume=True,
            )
            task_log(report_dir, "Reusing unchanged tested candidate; resuming independent Reviewer")
            review, repairs = perform_review(
                effective_rfc_text,
                task_id,
                worktree,
                base_ref,
                branch,
                report_dir,
                attempt,
                review_cycles,
            )
            update_status(
                report_dir,
                status,
                review=review["verdict"],
                review_format_repairs=repairs,
            )
            if review["verdict"] == "PASS":
                update_status(
                    report_dir,
                    status,
                    phase="full_regression",
                    full_regression_status="RUNNING",
                )
                regression_passed, regression_summary, regression_status = run_full_regression(
                    metadata, worktree, report_dir
                )
                update_status(
                    report_dir,
                    status,
                    tests_passed=regression_passed,
                    tests_status="PASS" if regression_passed else "FAIL",
                    full_regression_status=regression_status,
                )
                if regression_passed:
                    complete_task(
                        task_id,
                        metadata,
                        rfc_text,
                        prior_answer,
                        review,
                        repo,
                        worktree,
                        base_ref,
                        branch,
                        report_dir,
                        status,
                    )
                    return
                feedback = (
                    "The root-controlled full regression failed after review PASS. Fix only "
                    "the demonstrated implementation defect, then rerun the necessary module "
                    "tests and independent review.\n\n" + regression_summary
                )
                task_log(
                    report_dir,
                    "Full regression failed after resumed review",
                    logging.WARNING,
                )
            else:
                feedback = review_feedback(review)
                task_log(
                    report_dir,
                    f"Reviewer requested changes in resumed cycle {review_cycles}",
                    logging.WARNING,
                )
        elif previous_status.get("status") == "review_infra_failed":
            task_log(
                report_dir,
                "Stored review candidate changed; Coder and tests must run again",
                logging.WARNING,
            )

    for coder_cycle in range(1, MAX_CODER_CYCLES + 1):
        update_status(
            report_dir,
            status,
            phase="coding",
            coder_cycles=coder_cycle,
            review_cycles=review_cycles,
            total_coder_cycles=previous_total_coder + coder_cycle,
        )
        assessment, checkpoint = run_coder_until_gate(
            effective_rfc_text,
            metadata,
            task_id,
            worktree,
            branch,
            base_commit,
            base_ref,
            report_dir,
            status,
            attempt,
            coder_cycle,
            feedback,
        )
        answer = assessment.normalized
        (report_dir / f"coder-attempt-{attempt}-cycle-{coder_cycle}.md").write_text(
            answer + "\n", encoding="utf-8"
        )
        if assessment.classification != "READY_FOR_TESTS":
            feedback = (
                "Your Coding Report did not follow the mandatory format. Inspect the existing "
                "implementation, make any needed corrections, and return a complete report containing: "
                + ", ".join(assessment.errors)
            )
            task_log(
                report_dir,
                f"Coder report format invalid after cycle {coder_cycle}: "
                + ", ".join(assessment.errors),
                logging.WARNING,
            )
            continue
        (report_dir / "coder-report.md").write_text(answer + "\n", encoding="utf-8")
        diff = combined_diff(worktree, base_ref)
        (report_dir / "diff.patch").write_text(diff, encoding="utf-8")

        update_status(report_dir, status, phase="testing", tests_status="RUNNING")
        tests_passed, test_summary = run_tests(metadata, worktree, report_dir)
        update_status(
            report_dir,
            status,
            tests_passed=tests_passed,
            tests_status="PASS" if tests_passed else "FAIL",
            module_tests_status="PASS" if tests_passed else "FAIL",
        )
        if not tests_passed:
            feedback = (
                "The independent worker tests failed. Fix the implementation and rerun relevant tests.\n\n"
                + test_summary
            )
            task_log(report_dir, f"Tests failed after coder cycle {coder_cycle}", logging.WARNING)
            continue

        candidate = build_review_candidate(
            effective_rfc_text,
            metadata,
            base_commit,
            worktree,
            base_ref,
            answer,
        )
        update_status(report_dir, status, validated_candidate=candidate)

        if review_cycles >= MAX_REVIEW_CYCLES:
            raise TaskFailure(f"Exceeded maximum review cycles ({MAX_REVIEW_CYCLES})")
        review_cycles += 1
        update_status(
            report_dir,
            status,
            phase="reviewing",
            review_cycles=review_cycles,
            total_review_cycles=previous_total_reviews + review_cycles,
        )
        review, repairs = perform_review(
            effective_rfc_text,
            task_id,
            worktree,
            base_ref,
            branch,
            report_dir,
            attempt,
            review_cycles,
        )
        update_status(
            report_dir,
            status,
            review=review["verdict"],
            review_format_repairs=repairs,
        )

        if review["verdict"] == "PASS":
            update_status(
                report_dir,
                status,
                phase="full_regression",
                full_regression_status="RUNNING",
            )
            regression_passed, regression_summary, regression_status = run_full_regression(
                metadata, worktree, report_dir
            )
            update_status(
                report_dir,
                status,
                tests_passed=regression_passed,
                tests_status="PASS" if regression_passed else "FAIL",
                full_regression_status=regression_status,
            )
            if regression_passed:
                complete_task(
                    task_id,
                    metadata,
                    rfc_text,
                    answer,
                    review,
                    repo,
                    worktree,
                    base_ref,
                    branch,
                    report_dir,
                    status,
                )
                return
            feedback = (
                "The root-controlled full regression failed after review PASS. Fix only the "
                "demonstrated implementation defect, then rerun the necessary module tests "
                "and independent review.\n\n" + regression_summary
            )
            task_log(report_dir, "Full regression failed after review PASS", logging.WARNING)
            continue

        feedback = review_feedback(review)
        task_log(report_dir, f"Reviewer requested changes in cycle {review_cycles}", logging.WARNING)

    raise TaskFailure(f"Exceeded maximum coder cycles ({MAX_CODER_CYCLES})")


def final_destination(directory: Path, source: Path) -> Path:
    target = directory / source.name
    if not target.exists():
        return target
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return directory / f"{source.stem}.retry-{timestamp}{source.suffix}"


def handle_claimed(rfc_path: Path) -> None:
    task_id = rfc_path.stem
    report_dir = REPORTS / task_id
    try:
        process_task(rfc_path)
    except CoderInfrastructureFailure as exc:
        report_dir.mkdir(parents=True, exist_ok=True)
        reason = str(exc)
        failure_kind = reason.split(":", 1)[0]
        task_log(report_dir, reason, logging.ERROR)
        append_text(
            report_dir / "failure-report.md",
            f"# Coder Infrastructure Failure\n\n{utc_now()}\n\n{reason}\n",
        )
        status_path = report_dir / "status.json"
        try:
            status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
        except (json.JSONDecodeError, OSError):
            status = {}
        status.update(
            {
                "rfc": task_id,
                "status": "coder_infra_failed",
                "phase": "coder_infra_failed",
                "failure_kind": failure_kind,
                "failure": reason,
            }
        )
        update_status(report_dir, status, failed_at=utc_now())
        LOG.debug("Task traceback:\n%s", traceback.format_exc())
        if rfc_path.exists():
            os.replace(rfc_path, final_destination(FAILED, rfc_path))
        return
    except ReviewInfrastructureFailure as exc:
        report_dir.mkdir(parents=True, exist_ok=True)
        reason = str(exc)
        task_log(report_dir, reason, logging.ERROR)
        append_text(
            report_dir / "failure-report.md",
            f"# Review Infrastructure Failure\n\n{utc_now()}\n\n{reason}\n",
        )
        status_path = report_dir / "status.json"
        try:
            status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
        except (json.JSONDecodeError, OSError):
            status = {}
        status.update(
            {
                "rfc": task_id,
                "status": "review_infra_failed",
                "phase": "review_infra_failed",
                "failure_kind": "REVIEW_INFRA_FAILED",
                "failure": reason,
            }
        )
        update_status(report_dir, status, failed_at=utc_now())
        LOG.debug("Task traceback:\n%s", traceback.format_exc())
        if rfc_path.exists():
            os.replace(rfc_path, final_destination(FAILED, rfc_path))
        return
    except Exception as exc:
        report_dir.mkdir(parents=True, exist_ok=True)
        reason = f"{type(exc).__name__}: {exc}"
        task_log(report_dir, reason, logging.ERROR)
        append_text(report_dir / "failure-report.md", f"# Failure\n\n{utc_now()}\n\n{reason}\n")
        status_path = report_dir / "status.json"
        try:
            status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.exists() else {}
        except (json.JSONDecodeError, OSError):
            status = {}
        status.update({"rfc": task_id, "status": "failed", "phase": "failed", "failure": reason})
        update_status(report_dir, status, failed_at=utc_now())
        LOG.debug("Task traceback:\n%s", traceback.format_exc())
        if rfc_path.exists():
            os.replace(rfc_path, final_destination(FAILED, rfc_path))
        return
    if rfc_path.exists():
        os.replace(rfc_path, final_destination(DONE, rfc_path))


def report_is_done(task_id: str) -> bool:
    status_path = REPORTS / task_id / "status.json"
    if not status_path.exists():
        return False
    try:
        return json.loads(status_path.read_text(encoding="utf-8")).get("status") == "done"
    except (json.JSONDecodeError, OSError):
        return False


def recover_working() -> None:
    for rfc_path in sorted(WORKING.glob("*.md")):
        LOG.warning("Recovering RFC left in working: %s", rfc_path.name)
        with rfc_lock(BASE, rfc_path.stem, blocking=True):
            handle_claimed(rfc_path)


def normalize_completed_statuses() -> None:
    """Move stale retry errors into history for older completed statuses."""
    for status_path in REPORTS.glob("*/status.json"):
        with rfc_lock(BASE, status_path.parent.name, blocking=True):
            try:
                state = json.loads(status_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if state.get("status") != "done" or not state.get("failure"):
                continue
            history = state.get("failure_history", [])
            if not isinstance(history, list):
                history = []
            history.append(
                {
                    "attempt": None,
                    "failed_at": state.get("failed_at"),
                    "failure": state["failure"],
                }
            )
            state["failure_history"] = history
            state.pop("failure", None)
            state.pop("failed_at", None)
            state["updated_at"] = utc_now()
            atomic_json(status_path, state)


def recover_coder_retry_enqueues() -> None:
    """Reconcile durable retry enqueue intents after control-process failure."""
    for status_path in REPORTS.glob("*/status.json"):
        task_id = status_path.parent.name
        if not TASK_ID_RE.fullmatch(task_id):
            continue
        try:
            with rfc_lock(BASE, task_id, blocking=False):
                try:
                    state = json.loads(status_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                retry = state.get("coder_retry")
                if state.get("status") != "coder_retry_queued" or not isinstance(retry, dict):
                    continue
                destination = INBOX / f"{task_id}.md"
                if destination.exists() or (WORKING / destination.name).exists():
                    continue
                operation_id = str(retry.get("enqueue_operation_id", ""))
                staged_name = str(retry.get("staged_name", ""))
                transaction_relative = str(retry.get("transaction_manifest", ""))
                expected_digest = str(retry.get("transaction_digest", ""))
                valid_names = (
                    re.fullmatch(r"[0-9a-f]{32}", operation_id)
                    and re.fullmatch(
                        rf"\.control-{re.escape(task_id)}-[0-9]+-[0-9a-f]{{32}}",
                        staged_name,
                    )
                    and transaction_relative == f"enqueue-transactions/{operation_id}.json"
                    and re.fullmatch(r"[0-9a-f]{64}", expected_digest)
                )
                if not valid_names:
                    raise TaskFailure("Coder retry enqueue intent is incomplete or invalid")
                staged = INBOX / staged_name
                transaction_path = (status_path.parent / transaction_relative).resolve()
                try:
                    transaction_path.relative_to(status_path.parent.resolve())
                except ValueError as exc:
                    raise TaskFailure("Coder retry transaction escaped its report directory") from exc
                try:
                    transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    raise TaskFailure(f"Coder retry transaction is unavailable: {exc}") from exc
                transaction_payload = {
                    key: item for key, item in transaction.items() if key != "digest"
                }
                if (
                    transaction.get("digest") != expected_digest
                    or canonical_digest(transaction_payload) != expected_digest
                    or transaction.get("rfc") != task_id
                    or transaction.get("operation_id") != operation_id
                    or transaction.get("staged_name") != staged_name
                    or transaction.get("destination_name") != destination.name
                ):
                    raise TaskFailure("Coder retry transaction digest or identity is invalid")
                if staged.is_file():
                    os.replace(staged, destination)
                    update_status(
                        status_path.parent,
                        state,
                        coder_retry_recovery={
                            "operation_id": operation_id,
                            "action": "published_staged_enqueue",
                            "recovered_at": utc_now(),
                        },
                    )
                    task_log(status_path.parent, "Recovered staged Coder retry enqueue")
                    continue
                rollback_source = transaction.get("rollback_state")
                if not isinstance(rollback_source, dict):
                    raise TaskFailure("Coder retry transaction has no rollback state")
                rollback = json.loads(json.dumps(rollback_source))
                rollback["event_sequence"] = int(state.get("event_sequence", 0) or 0)
                rollback["total_coder_lifecycle_actions"] = int(
                    state.get("total_coder_lifecycle_actions", 0) or 0
                )
                failures = rollback.get("enqueue_failures", [])
                if not isinstance(failures, list):
                    failures = []
                failures.append(
                    {
                        "operation_id": operation_id,
                        "failed_at": utc_now(),
                        "error": "Recovered missing staged retry enqueue after control-process failure",
                    }
                )
                rollback["enqueue_failures"] = failures
                update_status(status_path.parent, rollback)
                task_log(status_path.parent, "Rolled back missing staged Coder retry enqueue")
        except BlockingIOError:
            continue
        except Exception as exc:
            with rfc_lock(BASE, task_id, blocking=True):
                try:
                    state = json.loads(status_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    state = {"rfc": task_id}
                destination = INBOX / f"{task_id}.md"
                if (
                    state.get("status") != "coder_retry_queued"
                    or destination.exists()
                    or (WORKING / destination.name).exists()
                ):
                    continue
                state.update(
                    {
                        "status": "coder_infra_failed",
                        "phase": "coder_enqueue_recovery_failed",
                        "failure_kind": "CODER_ENQUEUE_RECOVERY_FAILED",
                        "failure": f"CODER_ENQUEUE_RECOVERY_FAILED: {exc}",
                    }
                )
                update_status(status_path.parent, state, failed_at=utc_now())
                task_log(status_path.parent, str(state["failure"]), logging.ERROR)


def scan_inbox() -> None:
    if PROJECT_ROOT is None:
        return
    for source in sorted(INBOX.glob("*.md")):
        task_id = source.stem
        try:
            with rfc_lock(BASE, task_id, blocking=False):
                if not source.exists():
                    continue
                if report_is_done(task_id):
                    duplicate = final_destination(
                        FAILED, source.with_name(f"{source.stem}.duplicate{source.suffix}")
                    )
                    os.replace(source, duplicate)
                    LOG.error(
                        "Rejected duplicate completed RFC %s; moved to %s",
                        source.name,
                        duplicate.name,
                    )
                    continue
                claimed = WORKING / source.name
                if claimed.exists():
                    LOG.warning(
                        "RFC %s is already in working; leaving inbox copy untouched", source.name
                    )
                    continue
                os.replace(source, claimed)
                LOG.info("Claimed RFC %s", source.name)
                handle_claimed(claimed)
        except BlockingIOError:
            LOG.info("RFC %s is fenced by a control-plane operation", source.name)


def validate_runtime() -> None:
    if MAX_CONCURRENT_TASKS != 1:
        raise RuntimeError("This worker version requires MAX_CONCURRENT_TASKS=1")
    if (
        MAX_REVIEW_CYCLES < 1
        or MAX_CODER_CYCLES < 1
        or MAX_CODER_CONTINUATIONS < 1
        or MAX_CODER_CONTINUATIONS > 64
        or MAX_CONSECUTIVE_ERRORS < 1
    ):
        raise RuntimeError("Cycle and error limits are outside their supported bounds")
    if MAX_CODER_PROTOCOL_RETRIES < 0 or MAX_CODER_PROTOCOL_RETRIES > 2:
        raise RuntimeError("MAX_CODER_PROTOCOL_RETRIES must be between 0 and 2")
    if (
        MAX_CODER_PROTOCOL_FAILURES_TOTAL < 1
        or MAX_CODER_PROTOCOL_FAILURES_TOTAL > 32
        or MAX_CODER_CONTINUATIONS_TOTAL < 1
        or MAX_CODER_CONTINUATIONS_TOTAL > 256
        or MAX_CODER_LIFECYCLE_ACTIONS < 1
        or MAX_CODER_LIFECYCLE_ACTIONS > 512
    ):
        raise RuntimeError("Persistent Coder lifecycle limits are outside supported bounds")
    if MAX_REVIEW_FORMAT_REPAIRS < 0 or MAX_REVIEW_FORMAT_REPAIRS > 2:
        raise RuntimeError("MAX_REVIEW_FORMAT_REPAIRS must be between 0 and 2")
    if os.geteuid() != 0:
        raise RuntimeError("Worker orchestrator must run as root and drop privileges for every child")
    if not Path(AGENT_CLI).is_file():
        raise RuntimeError(f"Agent CLI does not exist: {AGENT_CLI}")
    if not BASE_BRANCH:
        raise RuntimeError("BASE_BRANCH must not be empty")
    if not GIT_REMOTE or not re.fullmatch(r"[A-Za-z0-9._-]+", GIT_REMOTE):
        raise RuntimeError("GIT_REMOTE must be a simple non-empty remote name")
    if PROJECT_ROOT is not None:
        if not Path(PROJECT_ROOT_VALUE).is_absolute():
            raise RuntimeError("PROJECT_ROOT must be an absolute path")
        if not PROJECT_ROOT.is_dir():
            raise RuntimeError(f"PROJECT_ROOT does not exist: {PROJECT_ROOT}")
        try:
            PROJECT_ROOT.relative_to(PERSISTENT_ROOT)
        except ValueError:
            raise RuntimeError("PROJECT_ROOT must be below persistent /openbayes/home")
        if PROJECT_ROOT == BASE or BASE in PROJECT_ROOT.parents:
            raise RuntimeError("PROJECT_ROOT must not be the Coding Worker source tree or a child of it")
        git(PROJECT_ROOT, "rev-parse", "--git-dir")
        git(PROJECT_ROOT, "remote", "get-url", GIT_REMOTE)
    for directory in (INBOX, WORKING, DONE, FAILED, REPORTS, WORKTREES, RUNTIME):
        directory.mkdir(parents=True, exist_ok=True)


def main() -> int:
    validate_runtime()
    lock_path = RUNTIME / "worker.lock"
    lock_handle = lock_path.open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        LOG.error("Another coding worker holds %s", lock_path)
        return 2
    lock_handle.seek(0)
    lock_handle.truncate()
    lock_handle.write(str(os.getpid()))
    lock_handle.flush()
    if PROJECT_ROOT is None:
        LOG.warning(
            "Coding worker started unbound: base=%s model=%s; inbox will remain paused until PROJECT_ROOT is configured",
            BASE,
            MODEL,
        )
    else:
        LOG.info(
            "Coding worker started: base=%s project=%s remote=%s base_branch=%s model=%s poll=%ss",
            BASE,
            PROJECT_ROOT,
            GIT_REMOTE,
            BASE_BRANCH,
            MODEL,
            POLL_INTERVAL,
        )
    normalize_completed_statuses()
    if PROJECT_ROOT is not None:
        recover_working()
    while True:
        recover_coder_retry_enqueues()
        scan_inbox()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        LOG.info("Coding worker stopped")
