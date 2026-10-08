"""Single-writer Git operations for fenced scheduler candidates."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .isolation import IsolationLayout
from .leases import JobLease
from .runner import ReviewerReadOnlyProbe, RunnerError, RunnerTimeout, run_bounded


RFC_ID_RE = re.compile(r"^RFC-[0-9]{8}-[0-9]{3}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
ZERO_COMMIT = "0" * 40


class GitBrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    rfc_id: str
    revision_digest: str
    branch: str
    base_commit: str
    commit_sha: str
    tree_sha: str
    diff_digest: str
    candidate_digest: str


class GitBroker:
    def __init__(
        self,
        repository: Path,
        layout: IsolationLayout,
        lock_path: Path,
        validate_lease: Callable[[JobLease], None],
        *,
        command_prefix: Sequence[str] = (),
        git_timeout_seconds: float = 120,
        reviewer_read_only_probe: ReviewerReadOnlyProbe | None = None,
    ) -> None:
        self.repository = repository.resolve()
        self.layout = layout
        self.lock_path = lock_path
        self.validate_lease = validate_lease
        self.command_prefix = tuple(command_prefix)
        if git_timeout_seconds <= 0:
            raise ValueError("git_timeout_seconds must be positive")
        self.git_timeout_seconds = git_timeout_seconds
        self.reviewer_read_only_probe = reviewer_read_only_probe
        if not (self.repository / ".git").exists():
            raise ValueError("repository must be a non-bare Git checkout")
        lock_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def git(
        self, cwd: Path, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = self._run_git(cwd, arguments, text=True)
        if check and result.returncode != 0:
            raise self._git_failure(arguments, result.returncode, result.stderr)
        return result

    def git_bytes(
        self, cwd: Path, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        result = self._run_git(cwd, arguments, text=False)
        if check and result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace")
            raise self._git_failure(arguments, result.returncode, detail)
        return result

    def _run_git(self, cwd: Path, arguments: Sequence[str], *, text: bool):
        try:
            return run_bounded(
                [*self.command_prefix, "git", "-C", str(cwd), *arguments],
                cwd=cwd,
                text=text,
                timeout_seconds=self.git_timeout_seconds,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                },
            )
        except RunnerTimeout as exc:
            raise GitBrokerError(
                f"git {' '.join(arguments)} timed out after "
                f"{self.git_timeout_seconds:g}s"
            ) from exc
        except RunnerError as exc:
            raise GitBrokerError(f"git {' '.join(arguments)} could not run: {exc}") from exc

    @staticmethod
    def _git_failure(
        arguments: Sequence[str], returncode: int, stderr: str
    ) -> GitBrokerError:
        return GitBrokerError(
            f"git {' '.join(arguments)} failed ({returncode}): {stderr[-4000:]}"
        )

    def prepare_worktree(self, lease: JobLease, base_commit: str) -> Path:
        self._validate_identity(lease.rfc_id, base_commit)
        self._validate_revision(lease.revision_digest)
        self.validate_lease(lease)
        worktree = self.layout.task_worktree(lease.rfc_id, lease.fencing_token)
        branch = f"agent/{lease.rfc_id}"
        with self.locked():
            self.validate_lease(lease)
            self._require_commit(base_commit)
            if worktree.exists():
                self._validate_generation_worktree(worktree, base_commit)
                return worktree
            worktree.parent.mkdir(parents=True, exist_ok=True)
            self.git(self.repository, "worktree", "prune")
            branch_tip = self._branch_tip(branch)
            start_commit = branch_tip or base_commit
            self._require_ancestor(base_commit, start_commit)
            self.git(
                self.repository,
                "worktree",
                "add",
                "--detach",
                str(worktree),
                start_commit,
            )
            return worktree

    def freeze_candidate(
        self, lease: JobLease, base_commit: str, title: str
    ) -> Candidate:
        self._validate_identity(lease.rfc_id, base_commit)
        self._validate_revision(lease.revision_digest)
        if not title.strip() or "\n" in title:
            raise ValueError("candidate title must be one non-empty line")
        self.validate_lease(lease)
        worktree = self.layout.task_worktree(lease.rfc_id, lease.fencing_token)
        branch = f"agent/{lease.rfc_id}"
        with self.locked():
            self.validate_lease(lease)
            self._validate_generation_worktree(worktree, base_commit)
            starting_head = self.git(worktree, "rev-parse", "HEAD").stdout.strip()
            branch_tip = self._branch_tip(branch)
            if branch_tip not in (None, starting_head):
                raise GitBrokerError("RFC branch advanced after this worktree generation started")
            if branch_tip is None and starting_head != base_commit:
                raise GitBrokerError("new RFC branch does not start at its declared base")

            self.git(worktree, "add", "-A")
            staged = self.git_bytes(
                worktree,
                "diff",
                "--cached",
                "--binary",
                "--full-index",
                "--no-ext-diff",
                "--no-renames",
                "--",
            ).stdout
            if not staged:
                if self._is_same_lease_commit(worktree, lease):
                    commit_sha = starting_head
                    parent = self._single_parent(commit_sha)
                    previous = self._publish_branch(branch, commit_sha, parent)
                    self._validate_after_branch_publication(
                        lease, branch, commit_sha, previous
                    )
                    return self._candidate_for_commit(
                        lease, branch, base_commit, commit_sha
                    )
                raise GitBrokerError("candidate has no staged changes")

            self.git(
                worktree,
                "-c",
                "user.name=Coding Worker Git Broker",
                "-c",
                "user.email=coding-worker@localhost",
                "commit",
                "-m",
                f"{lease.rfc_id}: {title}",
                "-m",
                (
                    f"RFC: {lease.rfc_id}\nRevision: {lease.revision_digest}\n"
                    f"Lease: {lease.lease_id}\nFence: {lease.fencing_token}"
                ),
            )
            commit_sha = self.git(worktree, "rev-parse", "HEAD").stdout.strip()
            if not COMMIT_RE.fullmatch(commit_sha):
                raise GitBrokerError("Git did not return a full candidate commit SHA")
            self.validate_lease(lease)
            previous = self._publish_branch(branch, commit_sha, starting_head)
            self._validate_after_branch_publication(
                lease, branch, commit_sha, previous
            )
            return self._candidate_for_commit(
                lease, branch, base_commit, commit_sha
            )

    def create_reviewer_snapshot(self, lease: JobLease, candidate: Candidate) -> Path:
        snapshot = self.layout.reviewer_snapshot(candidate.rfc_id, candidate.commit_sha)
        with self.locked():
            self.validate_lease(lease)
            self._validate_candidate_locked(lease, candidate)
            if snapshot.exists():
                self._validate_snapshot(snapshot, candidate.commit_sha)
                self._make_read_only(snapshot)
                self._probe_snapshot(snapshot)
                return snapshot
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            self.git(self.repository, "worktree", "prune")
            try:
                self.git(
                    self.repository,
                    "worktree",
                    "add",
                    "--detach",
                    str(snapshot),
                    candidate.commit_sha,
                )
                self._make_read_only(snapshot)
                self._probe_snapshot(snapshot)
            except Exception:
                self._cleanup_snapshot_unlocked(snapshot)
                raise
            return snapshot

    def cleanup_reviewer_snapshot(
        self, lease: JobLease, candidate: Candidate
    ) -> None:
        snapshot = self.layout.reviewer_snapshot(candidate.rfc_id, candidate.commit_sha)
        with self.locked():
            self.validate_lease(lease)
            self._validate_candidate_identity(lease, candidate)
            self._cleanup_snapshot_unlocked(snapshot)

    def cleanup_worktree(self, lease: JobLease) -> None:
        worktree = self.layout.task_worktree(lease.rfc_id, lease.fencing_token)
        with self.locked():
            self.validate_lease(lease)
            self._remove_worktree_unlocked(worktree)

    def push_candidate(
        self, lease: JobLease, candidate: Candidate, remote: str = "origin"
    ) -> None:
        if not REMOTE_RE.fullmatch(remote):
            raise ValueError("invalid Git remote")
        with self.locked():
            self.validate_lease(lease)
            self._validate_candidate_locked(lease, candidate)
            self.git(
                self.repository,
                "push",
                remote,
                f"{candidate.commit_sha}:refs/heads/{candidate.branch}",
            )

    def _validate_candidate_locked(
        self, lease: JobLease, candidate: Candidate
    ) -> None:
        self._validate_candidate_identity(lease, candidate)
        self._require_commit(candidate.base_commit)
        self._require_commit(candidate.commit_sha)
        self._require_ancestor(candidate.base_commit, candidate.commit_sha)
        branch_tip = self._branch_tip(candidate.branch)
        if branch_tip != candidate.commit_sha:
            raise GitBrokerError("RFC branch no longer identifies the reviewed candidate")
        actual = self._candidate_for_commit(
            lease,
            candidate.branch,
            candidate.base_commit,
            candidate.commit_sha,
        )
        if actual != candidate:
            raise GitBrokerError("candidate evidence does not match repository content")

    def _validate_candidate_identity(
        self, lease: JobLease, candidate: Candidate
    ) -> None:
        if candidate.rfc_id != lease.rfc_id or candidate.branch != f"agent/{lease.rfc_id}":
            raise GitBrokerError("candidate identity does not match lease")
        if candidate.revision_digest != lease.revision_digest:
            raise GitBrokerError("candidate RFC revision does not match lease")
        if lease.candidate_digest and lease.candidate_digest != candidate.candidate_digest:
            raise GitBrokerError("leased candidate digest does not match supplied candidate")
        self._validate_identity(candidate.rfc_id, candidate.base_commit)
        self._validate_revision(candidate.revision_digest)
        for value, label in (
            (candidate.commit_sha, "candidate commit"),
            (candidate.tree_sha, "candidate tree"),
        ):
            if not COMMIT_RE.fullmatch(value):
                raise GitBrokerError(f"{label} is invalid")
        for value, label in (
            (candidate.diff_digest, "candidate diff digest"),
            (candidate.candidate_digest, "candidate digest"),
        ):
            if not DIGEST_RE.fullmatch(value):
                raise GitBrokerError(f"{label} is invalid")

    def _candidate_for_commit(
        self, lease: JobLease, branch: str, base_commit: str, commit_sha: str
    ) -> Candidate:
        self._require_ancestor(base_commit, commit_sha)
        tree_sha = self.git(
            self.repository, "rev-parse", f"{commit_sha}^{{tree}}"
        ).stdout.strip()
        if not COMMIT_RE.fullmatch(tree_sha):
            raise GitBrokerError("Git did not return a full candidate tree SHA")
        full_diff = self.git_bytes(
            self.repository,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-renames",
            base_commit,
            commit_sha,
            "--",
        ).stdout
        diff_digest = "sha256:" + hashlib.sha256(full_diff).hexdigest()
        evidence = {
            "base_commit": base_commit,
            "branch": branch,
            "commit_sha": commit_sha,
            "diff_digest": diff_digest,
            "revision_digest": lease.revision_digest,
            "rfc_id": lease.rfc_id,
            "tree_sha": tree_sha,
        }
        candidate_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ).hexdigest()
        return Candidate(
            rfc_id=lease.rfc_id,
            revision_digest=lease.revision_digest,
            branch=branch,
            base_commit=base_commit,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            diff_digest=diff_digest,
            candidate_digest=candidate_digest,
        )

    def _publish_branch(
        self, branch: str, commit_sha: str, expected_parent: str
    ) -> str | None:
        branch_tip = self._branch_tip(branch)
        if branch_tip == commit_sha:
            return commit_sha
        if branch_tip is None:
            if expected_parent != self._single_parent(commit_sha):
                raise GitBrokerError("candidate parent changed before branch publication")
            expected_ref = ZERO_COMMIT
        else:
            if branch_tip != expected_parent:
                raise GitBrokerError("RFC branch advanced before candidate publication")
            expected_ref = expected_parent
        self.git(
            self.repository,
            "update-ref",
            f"refs/heads/{branch}",
            commit_sha,
            expected_ref,
        )
        return branch_tip

    def _validate_after_branch_publication(
        self,
        lease: JobLease,
        branch: str,
        commit_sha: str,
        previous: str | None,
    ) -> None:
        try:
            self.validate_lease(lease)
        except Exception:
            if previous != commit_sha:
                if previous is None:
                    self.git(
                        self.repository,
                        "update-ref",
                        "-d",
                        f"refs/heads/{branch}",
                        commit_sha,
                    )
                else:
                    self.git(
                        self.repository,
                        "update-ref",
                        f"refs/heads/{branch}",
                        previous,
                        commit_sha,
                    )
            raise

    def _branch_tip(self, branch: str) -> str | None:
        result = self.git(
            self.repository,
            "rev-parse",
            "--verify",
            "--quiet",
            f"refs/heads/{branch}^{{commit}}",
            check=False,
        )
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise self._git_failure(
                (
                    "rev-parse",
                    "--verify",
                    "--quiet",
                    f"refs/heads/{branch}^{{commit}}",
                ),
                result.returncode,
                result.stderr,
            )
        value = result.stdout.strip()
        if not COMMIT_RE.fullmatch(value):
            raise GitBrokerError("RFC branch did not resolve to a full commit SHA")
        return value

    def _validate_generation_worktree(
        self, worktree: Path, base_commit: str
    ) -> None:
        if not worktree.is_dir():
            raise GitBrokerError("fenced worktree is missing or is not a directory")
        self._validate_managed_worktree(worktree)
        head = self.git(worktree, "rev-parse", "HEAD").stdout.strip()
        if not COMMIT_RE.fullmatch(head):
            raise GitBrokerError("fenced worktree has an invalid HEAD")
        self._require_ancestor(base_commit, head)

    def _validate_snapshot(self, snapshot: Path, commit_sha: str) -> None:
        self._validate_managed_worktree(snapshot)
        actual = self.git(snapshot, "rev-parse", "HEAD").stdout.strip()
        if actual != commit_sha:
            raise GitBrokerError("existing Reviewer snapshot has the wrong commit")
        dirty = self.git(snapshot, "status", "--porcelain=v1", "--untracked-files=all")
        if dirty.stdout:
            raise GitBrokerError("existing Reviewer snapshot is not immutable and clean")

    def _probe_snapshot(self, snapshot: Path) -> None:
        if self.reviewer_read_only_probe is None:
            raise GitBrokerError(
                "Reviewer Unix identity read-only probe is not configured"
            )
        try:
            self.reviewer_read_only_probe.verify(snapshot)
        except RunnerError as exc:
            raise GitBrokerError(f"Reviewer read-only identity check failed: {exc}") from exc

    def _cleanup_snapshot_unlocked(self, snapshot: Path) -> None:
        self._remove_worktree_unlocked(snapshot)
        parent = snapshot.parent
        if parent.is_dir() and not any(parent.iterdir()):
            parent.rmdir()

    def _remove_worktree_unlocked(self, worktree: Path) -> None:
        if worktree.exists():
            if worktree.is_symlink():
                raise GitBrokerError("managed worktree path was replaced by a symbolic link")
            self._make_writable(worktree)
            result = self.git(
                self.repository,
                "worktree",
                "remove",
                "--force",
                str(worktree),
                check=False,
            )
            if result.returncode != 0 and worktree.exists():
                shutil.rmtree(worktree)
        self.git(self.repository, "worktree", "prune")
        if worktree.exists():
            raise GitBrokerError(f"could not remove managed worktree: {worktree}")

    def _validate_managed_worktree(self, worktree: Path) -> None:
        if worktree.is_symlink():
            raise GitBrokerError("managed worktree path was replaced by a symbolic link")
        top_level = Path(
            self.git(worktree, "rev-parse", "--show-toplevel").stdout.strip()
        ).resolve()
        if top_level != worktree.resolve():
            raise GitBrokerError("managed worktree has an unexpected top-level path")
        common_value = self.git(worktree, "rev-parse", "--git-common-dir").stdout.strip()
        common_dir = Path(common_value)
        if not common_dir.is_absolute():
            common_dir = worktree / common_dir
        if common_dir.resolve() != (self.repository / ".git").resolve():
            raise GitBrokerError("managed worktree escaped the bound repository")
        symbolic = self.git(worktree, "symbolic-ref", "-q", "HEAD", check=False)
        if symbolic.returncode == 0:
            raise GitBrokerError("fenced worktrees must remain detached")
        if symbolic.returncode != 1:
            raise self._git_failure(
                ("symbolic-ref", "-q", "HEAD"),
                symbolic.returncode,
                symbolic.stderr,
            )

    def _require_commit(self, commit_sha: str) -> None:
        actual = self.git(
            self.repository, "rev-parse", "--verify", f"{commit_sha}^{{commit}}"
        ).stdout.strip()
        if actual != commit_sha:
            raise GitBrokerError("declared commit does not resolve exactly")

    def _require_ancestor(self, base_commit: str, commit_sha: str) -> None:
        result = self.git(
            self.repository,
            "merge-base",
            "--is-ancestor",
            base_commit,
            commit_sha,
            check=False,
        )
        if result.returncode == 1:
            raise GitBrokerError("candidate is not descended from its declared base")
        if result.returncode != 0:
            raise self._git_failure(
                ("merge-base", "--is-ancestor", base_commit, commit_sha),
                result.returncode,
                result.stderr,
            )

    def _single_parent(self, commit_sha: str) -> str:
        parents = self.git(
            self.repository, "show", "-s", "--format=%P", commit_sha
        ).stdout.strip().split()
        if len(parents) != 1 or not COMMIT_RE.fullmatch(parents[0]):
            raise GitBrokerError("candidate commit must have exactly one parent")
        return parents[0]

    def _is_same_lease_commit(self, worktree: Path, lease: JobLease) -> bool:
        message = self.git(worktree, "show", "-s", "--format=%B", "HEAD").stdout
        required = (
            f"RFC: {lease.rfc_id}",
            f"Revision: {lease.revision_digest}",
            f"Lease: {lease.lease_id}",
            f"Fence: {lease.fencing_token}",
        )
        lines = {line.strip() for line in message.splitlines()}
        return all(value in lines for value in required)

    @staticmethod
    def _validate_identity(rfc_id: str, commit_sha: str) -> None:
        if not RFC_ID_RE.fullmatch(rfc_id):
            raise ValueError("invalid RFC ID")
        if not COMMIT_RE.fullmatch(commit_sha):
            raise ValueError("base commit must be a full Git SHA")

    @staticmethod
    def _validate_revision(revision_digest: str) -> None:
        if not DIGEST_RE.fullmatch(revision_digest):
            raise ValueError("revision digest must be sha256")

    @staticmethod
    def _make_read_only(root: Path) -> None:
        if root.is_symlink():
            raise GitBrokerError("Reviewer snapshot path is a symbolic link")
        for current_root, directories, files in os.walk(root, followlinks=False):
            for name in files:
                path = Path(current_root) / name
                if path.is_symlink():
                    continue
                mode = stat.S_IMODE(path.lstat().st_mode)
                os.chmod(path, mode & ~0o222)
            for name in directories:
                path = Path(current_root) / name
                if path.is_symlink():
                    continue
                mode = stat.S_IMODE(path.lstat().st_mode)
                os.chmod(path, mode & ~0o222)
        mode = stat.S_IMODE(root.lstat().st_mode)
        os.chmod(root, mode & ~0o222)

    @staticmethod
    def _make_writable(root: Path) -> None:
        if root.is_symlink():
            raise GitBrokerError("managed worktree path is a symbolic link")
        for current_root, directories, files in os.walk(root, followlinks=False):
            for name in (*directories, *files):
                path = Path(current_root) / name
                if path.is_symlink():
                    continue
                mode = stat.S_IMODE(path.lstat().st_mode)
                os.chmod(path, mode | stat.S_IWUSR)
        mode = stat.S_IMODE(root.lstat().st_mode)
        os.chmod(root, mode | stat.S_IWUSR)
