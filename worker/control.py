#!/usr/bin/env python3
"""Small administrative operations used by coding-workerctl and Mac tools."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from watcher import TASK_ID_RE, parse_rfc


BASE = Path(os.environ.get("CODING_WORKER_HOME", "/openbayes/home/coding-worker")).resolve()
PROJECT_VALUE = os.environ.get("PROJECT_ROOT", "").strip()
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main").strip()
GIT_REMOTE = os.environ.get("GIT_REMOTE", "origin").strip()


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def git(project: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/openbayes/home/coding-worker-home",
        "USER": "codingworker",
        "LOGNAME": "codingworker",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    return subprocess.run(
        [
            "chpst",
            "-u",
            "codingworker:codingproject",
            str(BASE / "bin" / "git-exec"),
            "git",
            "-C",
            str(project),
            *args,
        ],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def project_status() -> None:
    print(f"Project root: {PROJECT_VALUE or '(not configured)'}")
    print(f"Base branch: {BASE_BRANCH}")
    print(f"Remote: {GIT_REMOTE}")
    if not PROJECT_VALUE:
        print("Repository: (none)")
        print("Status: unbound")
        return
    project = Path(PROJECT_VALUE)
    if not project.is_dir() or not (project / ".git").exists():
        print("Repository: (invalid PROJECT_ROOT)")
        print("Status: unbound")
        return
    remote = git(project, "remote", "get-url", GIT_REMOTE)
    if remote.returncode != 0:
        print("Repository: (configured remote is missing)")
        print("Status: unbound")
        return
    branch = git(project, "branch", "--show-current")
    porcelain = git(project, "status", "--short")
    print(f"Repository: {remote.stdout.strip()}")
    print(f"Current branch: {branch.stdout.strip() or '(detached)'}")
    print(f"Working tree: {'clean' if not porcelain.stdout.strip() else 'has changes'}")
    print("Status: bound")


def rfc_status(task_id: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    status_path = BASE / "reports" / task_id / "status.json"
    state = {}
    if status_path.exists():
        try:
            state = json.loads(status_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"invalid status.json: {exc}")
    queue_state = None
    for name in ("inbox", "working", "done", "failed"):
        if any((BASE / "todo" / name).glob(f"{task_id}*.md")):
            queue_state = "queued" if name == "inbox" else name
            break
    current = state.get("status") or queue_state or "not_found"
    if state.get("phase") == "reviewing":
        current = "reviewing"
    print(f"RFC: {task_id}")
    print(f"Title: {state.get('title') or '-'}")
    print(f"Status: {current}")
    print(f"Phase: {state.get('phase') or '-'}")
    print(f"Branch: {state.get('branch') or f'agent/{task_id}'}")
    print(f"Commit: {state.get('commit_sha') or '-'}")
    tests_status = state.get("tests_status")
    if not tests_status:
        tests_status = "PASS" if state.get("tests_passed") else ("FAIL" if state.get("phase") in {"reviewing", "committing", "pushing", "complete", "failed"} else "PENDING")
    print(f"Tests: {tests_status}")
    print(f"Review: {state.get('review') or '-'}")
    print(f"Push: {state.get('push') or '-'}")
    print(f"PR: {state.get('pr_url') or 'not created'}")
    if state.get("compare_url"):
        print(f"Compare: {state['compare_url']}")
    if state.get("failure"):
        print(f"Failure: {state['failure']}")


def record_pr(task_id: str, url: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    if not re.fullmatch(r"https://github\.com/[^/]+/[^/]+/pull/[0-9]+", url):
        fail("PR URL must be a GitHub pull request URL")
    status_path = BASE / "reports" / task_id / "status.json"
    if not status_path.exists():
        fail("RFC status does not exist")
    state = json.loads(status_path.read_text(encoding="utf-8"))
    if state.get("status") != "done" or state.get("push") != "PASS":
        fail("PR can only be recorded after a successful push")
    state.update(
        {
            "pr_status": "created",
            "pr_url": url,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    atomic_json(status_path, state)
    print(f"Recorded PR for {task_id}: {url}")


def enqueue_upload(upload_name: str, final_name: str) -> None:
    if "/" in upload_name or "/" in final_name:
        fail("filenames must not contain paths")
    if not re.fullmatch(r"\.upload-[A-Za-z0-9._-]+", upload_name):
        fail("invalid upload filename")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md", final_name):
        fail("invalid RFC filename")
    task_id = Path(final_name).stem
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    source = BASE / "todo" / "inbox" / upload_name
    destination = BASE / "todo" / "inbox" / final_name
    if not source.is_file():
        fail("upload is missing")
    if destination.exists() or any((BASE / "todo" / name / final_name).exists() for name in ("working", "done", "failed")):
        fail("RFC filename already exists in the queue")
    if (BASE / "reports" / task_id / "status.json").exists():
        fail("RFC ID already has a report; use a new RFC ID")
    try:
        parse_rfc(source)
    except Exception as exc:
        fail(f"RFC validation failed: {exc}")
    os.rename(source, destination)
    print(f"Queued {task_id}")


def main() -> None:
    if len(sys.argv) < 2:
        fail("missing control command")
    operation = sys.argv[1]
    if operation == "project" and len(sys.argv) == 2:
        project_status()
    elif operation == "rfc-status" and len(sys.argv) == 3:
        rfc_status(sys.argv[2])
    elif operation == "record-pr" and len(sys.argv) == 4:
        record_pr(sys.argv[2], sys.argv[3])
    elif operation == "enqueue-upload" and len(sys.argv) == 4:
        enqueue_upload(sys.argv[2], sys.argv[3])
    else:
        fail("invalid arguments")


if __name__ == "__main__":
    main()
