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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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
MAX_REVIEW_CYCLES = int(os.environ.get("MAX_REVIEW_CYCLES", "3"))
MAX_CODER_CYCLES = int(os.environ.get("MAX_CODER_CYCLES", "5"))
MAX_CONSECUTIVE_ERRORS = int(os.environ.get("MAX_CONSECUTIVE_ERRORS", "3"))
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
    task_log(report_dir, f"Starting independent {role} process ({label})")
    result = execute(command, cwd, AGENT_TIMEOUT, input_text=prompt, env=env)
    raw_path = report_dir / "raw" / f"{label}.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(result.stdout, encoding="utf-8")
    if result.stderr:
        (report_dir / "raw" / f"{label}.stderr.log").write_text(result.stderr, encoding="utf-8")
    if not result.ok:
        reason = "timed out" if result.timed_out else f"exited {result.returncode}"
        raise AgentFailure(f"{role} {reason}: {safe_tail(result.stderr or result.stdout)}")
    try:
        envelope = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AgentFailure(f"{role} returned invalid CLI JSON: {exc}") from exc
    if envelope.get("is_error") or envelope.get("subtype") != "success":
        raise AgentFailure(f"{role} returned an error envelope: {safe_tail(result.stdout)}")
    answer = envelope.get("result")
    if not isinstance(answer, str) or not answer.strip():
        raise AgentFailure(f"{role} returned no final result")
    return answer.strip()


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


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and "verdict" in value:
            return value
    raise AgentFailure("Reviewer result did not contain a JSON object with verdict")


def validate_review(text: str) -> dict[str, Any]:
    review = extract_json_object(text)
    verdict = review.get("verdict")
    if verdict not in {"PASS", "REQUEST_CHANGES"}:
        raise AgentFailure("Reviewer verdict must be PASS or REQUEST_CHANGES")
    issues = review.get("required_changes", review.get("issues"))
    if not isinstance(issues, list) or not all(isinstance(issue, str) for issue in issues):
        raise AgentFailure("Reviewer required_changes must be an array of strings")
    if verdict == "REQUEST_CHANGES" and not issues:
        raise AgentFailure("REQUEST_CHANGES must include at least one issue")
    if verdict == "PASS" and issues:
        raise AgentFailure("PASS must use an empty required_changes array")
    review["required_changes"] = issues
    for key in (
        "summary",
        "test_review",
        "architecture_scope_review",
        "security_review",
    ):
        if not isinstance(review.get(key), str) or not review[key].strip():
            raise AgentFailure(f"Reviewer {key} must be a non-empty string")
    for key in ("acceptance_criteria", "code_review_findings", "regression_risks"):
        if not isinstance(review.get(key), list) or not all(
            isinstance(item, str) for item in review[key]
        ):
            raise AgentFailure(f"Reviewer {key} must be an array of strings")
    return review


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


def coder_report_errors(text: str) -> list[str]:
    return [heading for heading in CODER_REPORT_HEADINGS if heading not in text]


def normalize_coder_report(text: str) -> str:
    marker = text.find("# Coding Report")
    return text[marker:].strip() if marker >= 0 else text.strip()


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
    state.update(changes)
    state["updated_at"] = utc_now()
    atomic_json(report_dir / "status.json", state)


def coder_prompt(
    rfc_text: str,
    task_id: str,
    worktree: Path,
    branch: str,
    feedback: str,
    cycle: int,
) -> str:
    return (
        load_prompt("coder.md")
        + f"\n\n# Runtime Context\n"
        + f"RFC ID: {task_id}\nProject root: {PROJECT_ROOT}\nWorktree: {worktree}\nBranch: {branch}\n"
        + f"Working directory: {worktree}\nCoder cycle: {cycle}/{MAX_CODER_CYCLES}\n"
        + f"\n# RFC\n{rfc_text}\n"
        + (f"\n# Required Corrections From Previous Attempt\n{feedback}\n" if feedback else "")
    )


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
    status.update(
        {
            "rfc": task_id,
            "status": "working",
            "phase": "initializing",
            "model": MODEL,
            "tests_passed": False,
            "tests_status": "PENDING",
            "review": None,
            "review_cycles": 0,
            "coder_cycles": 0,
            "total_review_cycles": previous_total_reviews,
            "total_coder_cycles": previous_total_coder,
            "attempts": attempt,
            "started_at": status.get("started_at", utc_now()),
        }
    )
    update_status(report_dir, status)
    task_log(report_dir, f"Processing {rfc_path}")

    metadata, rfc_text = parse_rfc(rfc_path)
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
            "pr_status": "not_created",
            "pr_url": None,
        }
    )
    update_status(report_dir, status, phase="coding")

    feedback = ""
    review_cycles = 0
    for coder_cycle in range(1, MAX_CODER_CYCLES + 1):
        update_status(
            report_dir,
            status,
            phase="coding",
            coder_cycles=coder_cycle,
            review_cycles=review_cycles,
            total_coder_cycles=previous_total_coder + coder_cycle,
        )
        answer = run_agent(
            "Coder",
            coder_prompt(rfc_text, task_id, worktree, branch, feedback, coder_cycle),
            worktree,
            report_dir,
            f"attempt-{attempt}-coder-{coder_cycle}",
        )
        answer = normalize_coder_report(answer)
        (report_dir / f"coder-attempt-{attempt}-cycle-{coder_cycle}.md").write_text(
            answer + "\n", encoding="utf-8"
        )
        (report_dir / "coder-report.md").write_text(answer + "\n", encoding="utf-8")
        missing_headings = coder_report_errors(answer)
        if missing_headings:
            feedback = (
                "Your Coding Report did not follow the mandatory format. Inspect the existing "
                "implementation, make any needed corrections, and return a complete report containing: "
                + ", ".join(missing_headings)
            )
            task_log(
                report_dir,
                f"Coder report format invalid after cycle {coder_cycle}: {', '.join(missing_headings)}",
                logging.WARNING,
            )
            continue
        diff = combined_diff(worktree, base_ref)
        (report_dir / "diff.patch").write_text(diff, encoding="utf-8")

        update_status(report_dir, status, phase="testing", tests_status="RUNNING")
        tests_passed, test_summary = run_tests(metadata, worktree, report_dir)
        update_status(
            report_dir,
            status,
            tests_passed=tests_passed,
            tests_status="PASS" if tests_passed else "FAIL",
        )
        if not tests_passed:
            feedback = (
                "The independent worker tests failed. Fix the implementation and rerun relevant tests.\n\n"
                + test_summary
            )
            task_log(report_dir, f"Tests failed after coder cycle {coder_cycle}", logging.WARNING)
            continue

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
        before = workspace_fingerprint(worktree, base_ref)
        review_text = run_agent(
            "Reviewer",
            reviewer_prompt(
                rfc_text, task_id, worktree, base_ref, branch, report_dir, review_cycles
            ),
            worktree,
            report_dir,
            f"attempt-{attempt}-reviewer-{review_cycles}",
        )
        after = workspace_fingerprint(worktree, base_ref)
        if before != after:
            raise TaskFailure("Reviewer modified the task worktree; review aborted")
        review = validate_review(review_text)
        human_review = render_review_report(review, task_id, attempt, review_cycles)
        (report_dir / f"review-attempt-{attempt}-cycle-{review_cycles}.md").write_text(
            human_review, encoding="utf-8"
        )
        (report_dir / "review-report.md").write_text(human_review, encoding="utf-8")
        atomic_json(report_dir / f"review-attempt-{attempt}-cycle-{review_cycles}.json", review)
        atomic_json(report_dir / "review-latest.json", review)
        update_status(report_dir, status, review=review["verdict"])

        if review["verdict"] == "PASS":
            update_status(report_dir, status, phase="committing")
            commit_sha = commit_result(
                task_id, str(metadata.get("title", "")).strip(), worktree, base_ref, report_dir
            )
            update_status(report_dir, status, phase="pushing", commit_sha=commit_sha)
            remote_url, compare_url = push_result(repo, task_id, branch, commit_sha)
            create_pr_description(
                task_id, rfc_text, metadata, answer, review, commit_sha, report_dir
            )
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
                pr_status="not_created",
                pr_url=None,
                completed_at=utc_now(),
            )
            task_log(report_dir, f"Completed and pushed {branch} at {commit_sha}")
            if not KEEP_SUCCESS_WORKTREES:
                git(repo, "worktree", "remove", "--force", str(worktree))
                git(repo, "worktree", "prune")
                update_status(report_dir, status, worktree_removed=True)
            return

        feedback = "Independent review requested these changes:\n" + "\n".join(
            f"{index}. {issue}"
            for index, issue in enumerate(review["required_changes"], start=1)
        )
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
        handle_claimed(rfc_path)


def normalize_completed_statuses() -> None:
    """Move stale retry errors into history for older completed statuses."""
    for status_path in REPORTS.glob("*/status.json"):
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


def scan_inbox() -> None:
    if PROJECT_ROOT is None:
        return
    for source in sorted(INBOX.glob("*.md")):
        task_id = source.stem
        if report_is_done(task_id):
            duplicate = final_destination(FAILED, source.with_name(f"{source.stem}.duplicate{source.suffix}"))
            os.replace(source, duplicate)
            LOG.error("Rejected duplicate completed RFC %s; moved to %s", source.name, duplicate.name)
            continue
        claimed = WORKING / source.name
        if claimed.exists():
            LOG.warning("RFC %s is already in working; leaving inbox copy untouched", source.name)
            continue
        os.replace(source, claimed)
        LOG.info("Claimed RFC %s", source.name)
        handle_claimed(claimed)


def validate_runtime() -> None:
    if MAX_CONCURRENT_TASKS != 1:
        raise RuntimeError("This worker version requires MAX_CONCURRENT_TASKS=1")
    if MAX_REVIEW_CYCLES < 1 or MAX_CODER_CYCLES < 1 or MAX_CONSECUTIVE_ERRORS < 1:
        raise RuntimeError("Cycle and error limits must be positive")
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
        scan_inbox()
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        LOG.info("Coding worker stopped")
