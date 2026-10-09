#!/usr/bin/env python3
"""Small administrative operations used by coding-workerctl and Mac tools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from watcher import (
    TASK_ID_RE,
    atomic_json,
    build_coder_input_binding,
    build_review_candidate,
    canonical_digest,
    coder_report_errors,
    contains_structural_tool_call_markup,
    parse_rfc,
    persist_coder_checkpoint,
    rfc_lock,
    update_status,
    validate_coder_checkpoint,
    validate_coder_dependency_manifest,
    workspace_fingerprint,
)


BASE = Path(os.environ.get("CODING_WORKER_HOME", "/openbayes/home/coding-worker")).resolve()
PROJECT_VALUE = os.environ.get("PROJECT_ROOT", "").strip()
BASE_BRANCH = os.environ.get("BASE_BRANCH", "main").strip()
GIT_REMOTE = os.environ.get("GIT_REMOTE", "origin").strip()
MAX_CODER_RECOVERY_ATTEMPTS = int(os.environ.get("MAX_CODER_RECOVERY_ATTEMPTS", "3"))
MAX_CODER_LIFECYCLE_ACTIONS = int(os.environ.get("MAX_CODER_LIFECYCLE_ACTIONS", "64"))


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_status(task_id: str) -> tuple[Path, dict]:
    status_path = BASE / "reports" / task_id / "status.json"
    if not status_path.is_file():
        fail("RFC status does not exist")
    try:
        state = json.loads(status_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid status.json: {exc}")
    return status_path, state


def status_content_digest(status_path: Path) -> str:
    return hashlib.sha256(status_path.read_bytes()).hexdigest()


def effective_rfc(
    rfc_source: Path,
    report_dir: Path,
    state: dict,
) -> tuple[dict, str]:
    metadata, rfc_text = parse_rfc(rfc_source)
    amendment = state.get("pending_amendment")
    if not isinstance(amendment, dict):
        return metadata, rfc_text
    amendment_path = report_dir / "amendments" / str(amendment.get("file", ""))
    try:
        amendment_path.resolve().relative_to((report_dir / "amendments").resolve())
    except ValueError:
        fail("Pending amendment path escaped its report directory")
    if not amendment_path.is_file():
        fail("Pending amendment report is missing")
    return metadata, rfc_text + "\n\n" + amendment_path.read_text(encoding="utf-8")


def task_is_queued_or_working(task_id: str) -> bool:
    return any(
        (BASE / "todo" / name / f"{task_id}.md").exists()
        for name in ("inbox", "working")
    )


def find_task_rfc(directory: str, task_id: str) -> Path:
    root = BASE / "todo" / directory
    exact = root / f"{task_id}.md"
    if exact.is_file():
        return exact
    candidates = sorted(root.glob(f"{task_id}.retry-*.md"), key=lambda path: path.stat().st_mtime)
    if not candidates:
        fail(f"RFC source is missing from todo/{directory}")
    return candidates[-1]


def atomic_enqueue_from(source: Path, task_id: str) -> None:
    destination = BASE / "todo" / "inbox" / f"{task_id}.md"
    if destination.exists() or (BASE / "todo" / "working" / destination.name).exists():
        fail("RFC is already queued or working")
    temporary = destination.with_name(f".control-{task_id}-{os.getpid()}")
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)


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
    if state.get("module_tests_status"):
        print(f"Module tests: {state['module_tests_status']}")
    if state.get("full_regression_status"):
        print(f"Full regression: {state['full_regression_status']}")
    print(f"Review: {state.get('review') or '-'}")
    print(f"Push: {state.get('push') or '-'}")
    print(f"PR: {state.get('pr_url') or 'not created'}")
    if state.get("compare_url"):
        print(f"Compare: {state['compare_url']}")
    if state.get("failure"):
        print(f"Failure: {state['failure']}")


TERMINAL_STATUSES = {"done", "failed", "review_infra_failed", "coder_infra_failed"}


def wait_rfc(task_id: str, timeout_text: str) -> None:
    """Wait for a terminal RFC state without emitting repetitive status output."""
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        timeout = int(timeout_text)
    except ValueError:
        fail("wait timeout must be an integer number of seconds")
    if timeout < 1 or timeout > 86400:
        fail("wait timeout must be between 1 and 86400 seconds")

    deadline = time.monotonic() + timeout
    while True:
        status_path = BASE / "reports" / task_id / "status.json"
        if status_path.is_file():
            try:
                state = json.loads(status_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                fail(f"invalid status.json: {exc}")
            if state.get("status") in TERMINAL_STATUSES:
                rfc_status(task_id)
                if state.get("status") != "done":
                    raise SystemExit(2)
                return
        if time.monotonic() >= deadline:
            rfc_status(task_id)
            raise SystemExit(124)
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))


def _record_pr_locked(task_id: str, url: str) -> None:
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
    update_status(status_path.parent, state)
    print(f"Recorded PR for {task_id}: {url}")


def record_pr(task_id: str, url: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        with rfc_lock(BASE, task_id, blocking=False):
            _record_pr_locked(task_id, url)
    except BlockingIOError:
        fail("RFC is locked by the Worker or another control operation")


def _retry_review_locked(task_id: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    if task_is_queued_or_working(task_id):
        fail("RFC is already queued or working")
    status_path, state = load_status(task_id)
    legacy_format_failure = "Reviewer result did not contain a JSON object with verdict" in str(
        state.get("failure", "")
    )
    if state.get("status") != "review_infra_failed" and not legacy_format_failure:
        fail("RFC is not eligible for a Reviewer-only infrastructure retry")
    if state.get("tests_status") != "PASS" or not state.get("tests_passed"):
        fail("Reviewer-only retry requires previously passing Worker tests")
    worktree = Path(str(state.get("worktree", ""))).resolve()
    expected_worktree = (BASE / "worktrees" / task_id).resolve()
    if worktree != expected_worktree or not worktree.is_dir():
        fail("RFC worktree is missing or outside the task worktree root")
    base_commit = str(state.get("base_commit", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", base_commit):
        fail("RFC base commit is missing or invalid")
    coder_report_path = BASE / "reports" / task_id / "coder-report.md"
    if not coder_report_path.is_file():
        fail("Coder report is missing")
    coder_report = coder_report_path.read_text(encoding="utf-8").strip()
    missing = coder_report_errors(coder_report)
    if missing:
        fail("Coder report is not reusable: " + ", ".join(missing))
    rfc_source = find_task_rfc("failed", task_id)
    metadata, rfc_text = parse_rfc(rfc_source)
    candidate = build_review_candidate(
        rfc_text,
        metadata,
        base_commit,
        worktree,
        base_commit,
        coder_report,
    )
    history = state.get("failure_history", [])
    if not isinstance(history, list):
        history = []
    if state.get("failure"):
        history.append(
            {
                "attempt": state.get("attempts"),
                "failed_at": state.get("failed_at"),
                "failure": state["failure"],
            }
        )
    state.update(
        {
            "status": "review_infra_failed",
            "phase": "review_retry_queued",
            "failure_kind": "REVIEW_INFRA_FAILED",
            "failure": "REVIEW_INFRA_FAILED: Reviewer-only retry queued after candidate validation",
            "validated_candidate": candidate,
            "failure_history": history,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    update_status(status_path.parent, state)
    atomic_enqueue_from(rfc_source, task_id)
    print(f"Queued Reviewer-only retry for {task_id}; Coder/tests will be reused only if unchanged")


def retry_review(task_id: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        with rfc_lock(BASE, task_id, blocking=False):
            _retry_review_locked(task_id)
    except BlockingIOError:
        fail("RFC is locked by the Worker or another control operation")


def _retry_coder_locked(task_id: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    if task_is_queued_or_working(task_id):
        fail("RFC is already queued or working")
    status_path, state = load_status(task_id)
    loaded_status_digest = status_content_digest(status_path)
    failure_kind = str(state.get("failure_kind", ""))
    legacy_protocol_failure = (
        task_id == "RFC-20261008-057"
        and state.get("status") == "failed"
        and "Exceeded maximum coder cycles" in str(state.get("failure", ""))
        and state.get("tests_status") in {None, "PENDING"}
        and not state.get("tests_passed")
    )
    if state.get("status") != "coder_infra_failed" and not legacy_protocol_failure:
        fail("RFC is not eligible for a Coder infrastructure retry")
    if not legacy_protocol_failure and failure_kind not in {
        "CODER_PROTOCOL_OUTPUT_INVALID",
        "CODER_CONTINUATION_LIMIT_EXCEEDED",
        "CODER_INPUT_CHANGED",
    }:
        fail("RFC failure is not a recoverable Coder infrastructure condition")
    if MAX_CODER_RECOVERY_ATTEMPTS < 1 or MAX_CODER_RECOVERY_ATTEMPTS > 10:
        fail("MAX_CODER_RECOVERY_ATTEMPTS must be between 1 and 10")
    retry_count = int(state.get("coder_retry_count", 0) or 0)
    if retry_count >= MAX_CODER_RECOVERY_ATTEMPTS:
        fail(f"Coder retry limit reached ({MAX_CODER_RECOVERY_ATTEMPTS})")
    lifecycle_total = int(state.get("total_coder_lifecycle_actions", 0) or 0)
    if lifecycle_total + 1 >= MAX_CODER_LIFECYCLE_ACTIONS:
        fail(f"Coder lifecycle limit reached ({MAX_CODER_LIFECYCLE_ACTIONS})")
    worktree = Path(str(state.get("worktree", ""))).resolve()
    expected_worktree = (BASE / "worktrees" / task_id).resolve()
    if worktree != expected_worktree or not worktree.is_dir():
        fail("RFC worktree is missing or outside the task worktree root")
    branch = str(state.get("branch", ""))
    expected_branch = f"agent/{task_id}"
    if branch != expected_branch:
        fail("RFC branch does not match its task identity")
    base_commit = str(state.get("base_commit", ""))
    if not re.fullmatch(r"[0-9a-f]{40}", base_commit):
        fail("RFC base commit is missing or invalid")
    active_branch = git(worktree, "branch", "--show-current")
    if active_branch.returncode != 0 or active_branch.stdout.strip() != branch:
        fail("RFC worktree is not on its recorded task branch")
    head = git(worktree, "rev-parse", "HEAD")
    if head.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", head.stdout.strip()):
        fail("RFC worktree HEAD is unavailable")
    merge_base = git(worktree, "merge-base", "HEAD", base_commit)
    if merge_base.returncode != 0 or merge_base.stdout.strip() != base_commit:
        fail("RFC worktree no longer descends from its recorded base")
    rfc_source = find_task_rfc("failed", task_id)
    metadata, effective_rfc_text = effective_rfc(rfc_source, status_path.parent, state)
    input_binding = build_coder_input_binding(
        effective_rfc_text, metadata, task_id, worktree
    )
    checkpoint = state.get("coder_checkpoint")
    if failure_kind == "CODER_INPUT_CHANGED" and not isinstance(checkpoint, dict):
        try:
            validate_coder_dependency_manifest(worktree, task_id)
        except Exception as exc:
            fail(f"Coder input-change recovery manifest is invalid: {exc}")
        raw_outputs = sorted(
            (status_path.parent / "raw").glob("attempt-*-coder-*.json"),
            key=lambda path: path.stat().st_mtime,
        )
        if not raw_outputs:
            fail("Coder input-change failure has no preserved raw envelope")
        recovered_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            current_fingerprint = workspace_fingerprint(worktree, base_commit)
            checkpoint = persist_coder_checkpoint(
                status_path.parent,
                f"input-change-recovery-{recovered_at}",
                task_id,
                branch,
                base_commit,
                worktree,
                base_commit,
                current_fingerprint,
                "CODER_INPUT_CHANGED",
                input_binding=input_binding,
                raw_path=raw_outputs[-1],
                diagnostics=(
                    "Recovered only the stable worktree; Coder, tests, and review must rerun",
                ),
            )
        except Exception as exc:
            fail(f"Could not preserve input-change recovery checkpoint: {exc}")
        state["coder_checkpoint"] = checkpoint
    if legacy_protocol_failure and not isinstance(checkpoint, dict):
        outputs = sorted(
            status_path.parent.glob("coder-attempt-*-cycle-*.md"),
            key=lambda path: path.stat().st_mtime,
        )
        if not outputs:
            fail("Legacy Coder failure has no preserved output")
        latest_output = outputs[-1].read_text(encoding="utf-8")
        if not contains_structural_tool_call_markup(latest_output):
            fail("Legacy Coder failure is not proven to be a tool protocol failure")
        output_match = re.fullmatch(r"coder-attempt-([0-9]+)-cycle-([0-9]+)\.md", outputs[-1].name)
        if output_match is None:
            fail("Legacy Coder output filename is invalid")
        raw_prefix = f"attempt-{output_match.group(1)}-coder-{output_match.group(2)}"
        raw_outputs = sorted(
            (status_path.parent / "raw").glob(f"{raw_prefix}*.json"),
            key=lambda path: path.stat().st_mtime,
        )
        if not raw_outputs:
            fail("Legacy Coder failure has no matching redacted raw envelope")
        matching_raw = None
        for raw_path in reversed(raw_outputs):
            try:
                raw_envelope = json.loads(raw_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            raw_result = raw_envelope.get("result") if isinstance(raw_envelope, dict) else None
            if (
                isinstance(raw_result, str)
                and contains_structural_tool_call_markup(raw_result)
                and raw_result.strip() == latest_output.strip()
            ):
                matching_raw = raw_path
                break
        if matching_raw is None:
            fail("Legacy raw envelope does not prove a tool protocol failure")
        imported_at = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        try:
            before = workspace_fingerprint(worktree, base_commit)
            checkpoint = persist_coder_checkpoint(
                status_path.parent,
                f"legacy-import-{imported_at}",
                task_id,
                branch,
                base_commit,
                worktree,
                base_commit,
                before,
                "CODER_PROTOCOL_OUTPUT_INVALID",
                input_binding=input_binding,
                raw_path=matching_raw,
                diagnostics=("imported from legacy exhausted Coder cycles",),
            )
        except Exception as exc:
            fail(f"Could not import legacy Coder checkpoint: {exc}")
        state["coder_checkpoint"] = checkpoint
        state["failure_kind"] = "CODER_PROTOCOL_OUTPUT_INVALID"
        failure_kind = "CODER_PROTOCOL_OUTPUT_INVALID"
    if not isinstance(checkpoint, dict):
        fail("RFC has no reusable Coder checkpoint")
    try:
        validate_coder_checkpoint(
            status_path.parent,
            checkpoint,
            task_id,
            branch,
            base_commit,
            worktree,
            base_commit,
            input_binding,
        )
    except Exception as exc:
        fail(f"Coder checkpoint validation failed: {exc}")
    if status_content_digest(status_path) != loaded_status_digest:
        fail("RFC status changed during retry validation")
    original_state = deepcopy(state)
    history = state.get("failure_history", [])
    if not isinstance(history, list):
        history = []
    if state.get("failure"):
        history.append(
            {
                "attempt": state.get("attempts"),
                "failed_at": state.get("failed_at"),
                "failure": state["failure"],
                "checkpoint_digest": checkpoint.get("checkpoint_digest"),
            }
        )
    queued_at = datetime.now(timezone.utc).isoformat()
    operation_id = uuid.uuid4().hex
    state.pop("failure", None)
    state.pop("failed_at", None)
    state.update(
        {
            "status": "coder_retry_queued",
            "phase": "coder_retry_queued",
            "coder_retry_count": retry_count + 1,
            "total_coder_lifecycle_actions": lifecycle_total + 1,
            "coder_retry": {
                "queued_at": queued_at,
                "failure_kind": failure_kind,
                "checkpoint_digest": checkpoint.get("checkpoint_digest"),
                "enqueue_operation_id": operation_id,
            },
            "failure_history": history,
            "updated_at": queued_at,
        }
    )
    destination = BASE / "todo" / "inbox" / f"{task_id}.md"
    if destination.exists() or (BASE / "todo" / "working" / destination.name).exists():
        fail("RFC is already queued or working")
    staged = destination.with_name(f".control-{task_id}-{os.getpid()}-{uuid.uuid4().hex}")
    try:
        shutil.copyfile(rfc_source, staged)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    transaction_dir = status_path.parent / "enqueue-transactions"
    transaction_path = transaction_dir / f"{operation_id}.json"
    transaction: dict = {
        "schema_version": 1,
        "rfc": task_id,
        "operation_id": operation_id,
        "created_at": queued_at,
        "staged_name": staged.name,
        "destination_name": destination.name,
        "rollback_state": original_state,
    }
    transaction["digest"] = canonical_digest(transaction)
    try:
        atomic_json(transaction_path, transaction)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    state["coder_retry"].update(
        {
            "staged_name": staged.name,
            "transaction_manifest": str(transaction_path.relative_to(status_path.parent)),
            "transaction_digest": transaction["digest"],
        }
    )
    try:
        if status_content_digest(status_path) != loaded_status_digest:
            fail("RFC status changed before retry transition")
        update_status(status_path.parent, state)
        if destination.exists() or (BASE / "todo" / "working" / destination.name).exists():
            fail("RFC became queued or working during retry publication")
        os.replace(staged, destination)
    except BaseException as exc:
        staged.unlink(missing_ok=True)
        try:
            current = json.loads(status_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            current = {}
        current_retry = current.get("coder_retry")
        if isinstance(current_retry, dict) and current_retry.get("enqueue_operation_id") == operation_id:
            rollback = deepcopy(original_state)
            rollback["event_sequence"] = int(current.get("event_sequence", 0) or 0)
            rollback["total_coder_lifecycle_actions"] = lifecycle_total + 1
            failures = rollback.get("enqueue_failures", [])
            if not isinstance(failures, list):
                failures = []
            failures.append(
                {
                    "operation_id": operation_id,
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            rollback["enqueue_failures"] = failures
            update_status(status_path.parent, rollback)
        raise
    print(
        f"Queued Coder retry {retry_count + 1}/{MAX_CODER_RECOVERY_ATTEMPTS} for {task_id}; "
        "validated worktree checkpoint preserved"
    )


def retry_coder(task_id: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        with rfc_lock(BASE, task_id, blocking=False):
            _retry_coder_locked(task_id)
    except BlockingIOError:
        fail("RFC is locked by the Worker or another control operation")


AMENDMENT_HEADINGS = (
    "# Project Lead Amendment",
    "## Summary",
    "## Required Changes",
    "## Reproduction",
    "## Acceptance Conditions",
)


def _enqueue_amendment_locked(task_id: str, upload_name: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    if not re.fullmatch(r"\.amend-upload-[A-Za-z0-9._-]+", upload_name):
        fail("invalid amendment upload filename")
    if task_is_queued_or_working(task_id):
        fail("RFC is already queued or working")
    status_path, state = load_status(task_id)
    if state.get("status") != "done" or state.get("push") != "PASS":
        fail("Amendment requires a completed, pushed RFC branch")
    if state.get("pr_status") == "merged":
        fail("A merged RFC cannot be amended")
    upload = BASE / "todo" / "inbox" / upload_name
    if not upload.is_file():
        fail("amendment upload is missing")
    if upload.stat().st_size > 256 * 1024:
        fail("amendment report exceeds 256 KiB")
    try:
        feedback = upload.read_text(encoding="utf-8").strip()
    except UnicodeDecodeError:
        fail("amendment report must be UTF-8")
    missing = [heading for heading in AMENDMENT_HEADINGS if heading not in feedback]
    if missing:
        fail("amendment report is missing headings: " + ", ".join(missing))
    source_rfc = find_task_rfc("done", task_id)
    amendments_dir = BASE / "reports" / task_id / "amendments"
    amendments_dir.mkdir(parents=True, exist_ok=True)
    existing = sorted(amendments_dir.glob("amendment-*.md"))
    number = len(existing) + 1
    amendment_name = f"amendment-{number}.md"
    amendment_path = amendments_dir / amendment_name
    os.replace(upload, amendment_path)
    requested_at = datetime.now(timezone.utc).isoformat()
    history = state.get("amendment_history", [])
    if not isinstance(history, list):
        history = []
    history.append({"number": number, "file": amendment_name, "requested_at": requested_at})
    state.update(
        {
            "status": "amendment_queued",
            "phase": "amendment_queued",
            "review": None,
            "pending_amendment": {
                "number": number,
                "file": amendment_name,
                "requested_at": requested_at,
            },
            "amendment_history": history,
            "updated_at": requested_at,
        }
    )
    update_status(status_path.parent, state)
    atomic_enqueue_from(source_rfc, task_id)
    print(f"Queued amendment {number} for {task_id} on its existing branch")


def enqueue_amendment(task_id: str, upload_name: str) -> None:
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        with rfc_lock(BASE, task_id, blocking=False):
            _enqueue_amendment_locked(task_id, upload_name)
    except BlockingIOError:
        fail("RFC is locked by the Worker or another control operation")


def _enqueue_upload_locked(upload_name: str, final_name: str) -> None:
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


def enqueue_upload(upload_name: str, final_name: str) -> None:
    task_id = Path(final_name).stem
    if not TASK_ID_RE.fullmatch(task_id):
        fail("invalid RFC ID")
    try:
        with rfc_lock(BASE, task_id, blocking=False):
            _enqueue_upload_locked(upload_name, final_name)
    except BlockingIOError:
        fail("RFC is locked by the Worker or another control operation")


def main() -> None:
    if len(sys.argv) < 2:
        fail("missing control command")
    operation = sys.argv[1]
    if operation == "project" and len(sys.argv) == 2:
        project_status()
    elif operation == "rfc-status" and len(sys.argv) == 3:
        rfc_status(sys.argv[2])
    elif operation == "wait-rfc" and len(sys.argv) == 4:
        wait_rfc(sys.argv[2], sys.argv[3])
    elif operation == "record-pr" and len(sys.argv) == 4:
        record_pr(sys.argv[2], sys.argv[3])
    elif operation == "retry-review" and len(sys.argv) == 3:
        retry_review(sys.argv[2])
    elif operation == "retry-coder" and len(sys.argv) == 3:
        retry_coder(sys.argv[2])
    elif operation == "enqueue-amendment" and len(sys.argv) == 4:
        enqueue_amendment(sys.argv[2], sys.argv[3])
    elif operation == "enqueue-upload" and len(sys.argv) == 4:
        enqueue_upload(sys.argv[2], sys.argv[3])
    else:
        fail("invalid arguments")


if __name__ == "__main__":
    main()
