#!/usr/bin/env python3
"""Non-destructive installation, gateway, service, and repository diagnostics."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path


BASE = Path(os.environ.get("CODING_WORKER_HOME", "/openbayes/home/coding-worker"))
PROJECT_VALUE = os.environ.get("PROJECT_ROOT", "").strip()
PROJECT = Path(PROJECT_VALUE) if PROJECT_VALUE else None
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main").strip()
GIT_REMOTE = os.environ.get("GIT_REMOTE", "origin").strip()
MODEL = os.environ.get("MODEL", "xiaosuan-8").strip()
AGENT_CLI = os.environ.get("AGENT_CLI", "/openbayes/home/.local/bin/claude")
LITELLM_BASE_URL = os.environ.get("LITELLM_BASE_URL", "").rstrip("/")
LITELLM_API_KEY = os.environ.get("LITELLM_API_KEY", "")
PRIVATE_KEY = BASE / "secrets" / "github_deploy_key"
PYTHON_BASELINE_ROOT_VALUE = os.environ.get("PYTHON_BASELINE_ROOT", "").strip()
PYTHON_BASELINE_COMMIT = os.environ.get("PYTHON_BASELINE_COMMIT", "").strip()

failures = 0


def report(name: str, status_value: str, detail: str) -> None:
    global failures
    print(f"[{status_value}] {name}: {detail}")
    if status_value == "FAIL":
        failures += 1


def command(args: list[str], *, cwd: Path = BASE, timeout: int = 90, env=None, text=None):
    try:
        return subprocess.run(
            args,
            cwd=cwd,
            env=env,
            input=text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return exc


def git(*args: str, timeout: int = 90):
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/openbayes/home/coding-worker-home",
        "USER": "codingworker",
        "LOGNAME": "codingworker",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    return command(
        [
            "chpst",
            "-u",
            "codingworker:codingproject",
            str(BASE / "bin" / "git-exec"),
            "git",
            "-C",
            str(PROJECT),
            *args,
        ],
        env=env,
        timeout=timeout,
    )


def command_check(name: str, result, detail: str = "ok") -> bool:
    if isinstance(result, Exception):
        report(name, "FAIL", str(result))
        return False
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip().splitlines()
        report(name, "FAIL", message[-1] if message else f"exit {result.returncode}")
        return False
    report(name, "PASS", detail)
    return True


for directory in (BASE / "todo" / "inbox", BASE / "reports", BASE / "runtime"):
    if directory.is_dir() and os.access(directory, os.R_OK | os.W_OK | os.X_OK):
        report(f"permissions {directory}", "PASS", "root orchestrator can access")
    else:
        report(f"permissions {directory}", "FAIL", "missing or inaccessible")

service = command(["sv", "status", "coding-worker"], env={**os.environ, "SVDIR": "/etc/service"})
command_check("Worker service", service, service.stdout.strip() if not isinstance(service, Exception) else "")

if not LITELLM_BASE_URL or not LITELLM_API_KEY or LITELLM_API_KEY == "replace-me":
    report("LiteLLM configuration", "FAIL", "URL or API key is not configured")
else:
    try:
        request = urllib.request.Request(
            f"{LITELLM_BASE_URL}/v1/models",
            headers={"Authorization": f"Bearer {LITELLM_API_KEY}"},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=30) as response:
            payload = json.load(response)
        ids = {item.get("id") for item in payload.get("data", []) if isinstance(item, dict)}
        if MODEL in ids:
            report("LiteLLM model", "PASS", f"exact model ID '{MODEL}' is available")
        else:
            report("LiteLLM model", "FAIL", f"exact model ID '{MODEL}' is unavailable")
    except Exception as exc:
        report("LiteLLM gateway", "FAIL", f"{type(exc).__name__}: {exc}")

gateway_host = LITELLM_BASE_URL.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
agent_env = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": "/openbayes/home/coding-agent-home",
    "USER": "codingagent",
    "LOGNAME": "codingagent",
    "ANTHROPIC_BASE_URL": LITELLM_BASE_URL,
    "ANTHROPIC_API_KEY": LITELLM_API_KEY,
    "ANTHROPIC_AUTH_TOKEN": LITELLM_API_KEY,
    "NO_PROXY": f"localhost,127.0.0.1,{gateway_host}",
    "no_proxy": f"localhost,127.0.0.1,{gateway_host}",
    "GIT_OPTIONAL_LOCKS": "0",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
}
agent = command(
    [
        "chpst",
        "-u",
        "codingagent:codingproject",
        str(BASE / "bin" / "agent-exec"),
        AGENT_CLI,
        "-p",
        "--model",
        MODEL,
        "--output-format",
        "json",
        "--no-session-persistence",
        "--dangerously-skip-permissions",
    ],
    cwd=Path("/openbayes/home/coding-agent-home"),
    timeout=120,
    env=agent_env,
    text="Reply with exactly: CODING_WORKER_DOCTOR_OK",
)
if not isinstance(agent, Exception) and agent.returncode == 0:
    try:
        envelope = json.loads(agent.stdout)
        healthy = envelope.get("subtype") == "success" and not envelope.get("is_error")
    except json.JSONDecodeError:
        healthy = False
    report("Claude Code + LiteLLM", "PASS" if healthy else "FAIL", "real Agent CLI call completed" if healthy else "invalid Agent CLI result")
else:
    command_check("Claude Code + LiteLLM", agent)

if PRIVATE_KEY.exists():
    key_stat = PRIVATE_KEY.stat()
    mode = stat.S_IMODE(key_stat.st_mode)
    if mode == 0o600 and key_stat.st_uid == 22022:
        report("Deploy private key", "PASS", "owned by codingworker with mode 0600")
    else:
        report("Deploy private key", "FAIL", f"unexpected owner/mode uid={key_stat.st_uid} mode={mode:o}")
    unreadable = command(
        ["chpst", "-u", "codingagent:codingproject", "test", "!", "-r", str(PRIVATE_KEY)]
    )
    command_check("Agent credential isolation", unreadable, "codingagent cannot read Deploy Key")
else:
    report("Deploy private key", "SKIP", "not generated while project is unbound")

if not PYTHON_BASELINE_ROOT_VALUE and not PYTHON_BASELINE_COMMIT:
    report("Python differential baseline", "SKIP", "not configured")
elif not PYTHON_BASELINE_ROOT_VALUE or not re.fullmatch(r"[0-9a-f]{40}", PYTHON_BASELINE_COMMIT):
    report("Python differential baseline", "FAIL", "root and exact 40-character commit are required")
else:
    python_baseline = Path(PYTHON_BASELINE_ROOT_VALUE)
    required_baseline_file = python_baseline / "agent" / "message_content.py"
    if not python_baseline.is_absolute() or not required_baseline_file.is_file():
        report("Python differential baseline", "FAIL", "configured read-only source snapshot is missing")
    else:
        readable = command(
            ["chpst", "-u", "codingagent:codingproject", "test", "-r", str(required_baseline_file)]
        )
        read_only = command(
            ["chpst", "-u", "codingagent:codingproject", "test", "!", "-w", str(required_baseline_file)]
        )
        if command_check(
            "Python differential baseline read access",
            readable,
            f"codingagent can read pinned {PYTHON_BASELINE_COMMIT[:12]}",
        ):
            command_check(
                "Python differential baseline immutability",
                read_only,
                "codingagent cannot modify reference source",
            )

if PROJECT is None:
    report("Project binding", "SKIP", "Status: unbound; inbox processing is paused")
else:
    if not PROJECT.is_dir():
        report("PROJECT_ROOT", "FAIL", f"does not exist: {PROJECT}")
    elif not (PROJECT / ".git").exists():
        report("PROJECT_ROOT", "FAIL", f"not a Git repository: {PROJECT}")
    else:
        report("PROJECT_ROOT", "PASS", str(PROJECT))
        metadata_path = PROJECT / "baseline" / "metadata.json"
        try:
            project_baseline = json.loads(metadata_path.read_text(encoding="utf-8"))
            project_commit = project_baseline["baseline"]["commit"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError):
            project_commit = None
        if PYTHON_BASELINE_COMMIT:
            report(
                "Project/reference baseline identity",
                "PASS" if project_commit == PYTHON_BASELINE_COMMIT else "FAIL",
                "exact commit matches" if project_commit == PYTHON_BASELINE_COMMIT else "commit mismatch",
            )
        metadata_check = command(
            [
                "chpst",
                "-u",
                "codingagent:codingproject",
                "test",
                "!",
                "-w",
                str(PROJECT / ".git" / "config"),
            ]
        )
        command_check(
            "Agent Git metadata isolation",
            metadata_check,
            "codingagent cannot modify project Git config",
        )
        root_result = git("rev-parse", "--show-toplevel")
        if command_check("Git repository", root_result, root_result.stdout.strip() if not isinstance(root_result, Exception) else ""):
            remote_result = git("remote", "get-url", GIT_REMOTE)
            if command_check("Git remote", remote_result, remote_result.stdout.strip() if not isinstance(remote_result, Exception) else ""):
                remote_url = remote_result.stdout.strip()
                if re.fullmatch(r"git@github\.com:[^/]+/.+\.git", remote_url):
                    report("GitHub repository binding", "PASS", remote_url)
                else:
                    report("GitHub repository binding", "FAIL", "origin is not a GitHub SSH URL")

            status_result = git("status", "--porcelain=v1")
            if not isinstance(status_result, Exception) and status_result.returncode == 0:
                clean = not status_result.stdout.strip()
                report("Project working tree", "PASS" if clean else "FAIL", "clean" if clean else "has local changes")
            else:
                command_check("Project working tree", status_result)

            branch_result = git("branch", "--show-current")
            command_check("Project branch", branch_result, branch_result.stdout.strip() if not isinstance(branch_result, Exception) else "")
            fetch_result = git(
                "fetch",
                "--prune",
                GIT_REMOTE,
                f"+refs/heads/{BASE_BRANCH}:refs/remotes/{GIT_REMOTE}/{BASE_BRANCH}",
                timeout=180,
            )
            if command_check("Git fetch", fetch_result, f"{GIT_REMOTE}/{BASE_BRANCH}"):
                base_result = git("rev-parse", "--verify", f"refs/remotes/{GIT_REMOTE}/{BASE_BRANCH}")
                if command_check("Base branch", base_result, BASE_BRANCH):
                    auth_result = git("ls-remote", "--exit-code", "--heads", GIT_REMOTE, BASE_BRANCH)
                    if command_check("GitHub authentication", auth_result, "read access confirmed"):
                        diagnostic = f"__coding-worker-doctor-{os.getpid()}"
                        push_result = git(
                            "push",
                            "--dry-run",
                            GIT_REMOTE,
                            f"refs/remotes/{GIT_REMOTE}/{BASE_BRANCH}:refs/heads/{diagnostic}",
                            timeout=180,
                        )
                        command_check(
                            "GitHub push permission",
                            push_result,
                            "non-destructive --dry-run write check passed; no branch was created",
                        )

print(f"Doctor result: {'FAIL' if failures else 'PASS'} ({failures} failure(s))")
raise SystemExit(1 if failures else 0)
