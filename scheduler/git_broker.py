"""Single-writer Git operations for fenced scheduler candidates."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .isolation import IsolationLayout
from .leases import JobLease


RFC_ID_RE = re.compile(r"^RFC-[0-9]{8}-[0-9]{3}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class GitBrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class Candidate:
    rfc_id: str
    branch: str
    base_commit: str
    commit_sha: str
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
    ) -> None:
        self.repository = repository.resolve()
        self.layout = layout
        self.lock_path = lock_path
        self.validate_lease = validate_lease
        self.command_prefix = tuple(command_prefix)
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

    def git(self, cwd: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [*self.command_prefix, "git", "-C", str(cwd), *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={
                "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                "HOME": os.environ.get("HOME", "/nonexistent"),
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            },
        )
        if check and result.returncode != 0:
            raise GitBrokerError(
                f"git {' '.join(arguments)} failed ({result.returncode}): "
                f"{result.stderr[-4000:]}"
            )
        return result

    def prepare_worktree(self, lease: JobLease, base_commit: str) -> Path:
        self._validate_identity(lease.rfc_id, base_commit)
        self.validate_lease(lease)
        worktree = self.layout.task_worktree(lease.rfc_id)
        branch = f"agent/{lease.rfc_id}"
        with self.locked():
            self.validate_lease(lease)
            if worktree.exists():
                actual = self.git(worktree, "branch", "--show-current").stdout.strip()
                if actual != branch:
                    raise GitBrokerError(
                        f"existing worktree branch {actual!r} does not match {branch}"
                    )
                return worktree
            worktree.parent.mkdir(parents=True, exist_ok=True)
            existing = self.git(
                self.repository, "show-ref", "--verify", f"refs/heads/{branch}", check=False
            )
            if existing.returncode == 0:
                self.git(self.repository, "worktree", "add", str(worktree), branch)
            else:
                self.git(
                    self.repository,
                    "worktree",
                    "add",
                    "-b",
                    branch,
                    str(worktree),
                    base_commit,
                )
            return worktree

    def freeze_candidate(
        self, lease: JobLease, base_commit: str, title: str
    ) -> Candidate:
        self._validate_identity(lease.rfc_id, base_commit)
        if not title.strip() or "\n" in title:
            raise ValueError("candidate title must be one non-empty line")
        self.validate_lease(lease)
        worktree = self.layout.task_worktree(lease.rfc_id)
        branch = f"agent/{lease.rfc_id}"
        with self.locked():
            self.validate_lease(lease)
            actual = self.git(worktree, "branch", "--show-current").stdout.strip()
            if actual != branch:
                raise GitBrokerError("candidate worktree is not on its fixed RFC branch")
            self.git(worktree, "add", "-A")
            staged = self.git(worktree, "diff", "--cached", "--binary", "--full-index").stdout
            if not staged:
                raise GitBrokerError("candidate has no staged changes")
            candidate_digest = "sha256:" + hashlib.sha256(
                (base_commit + "\0" + staged).encode("utf-8", errors="replace")
            ).hexdigest()
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
                f"RFC: {lease.rfc_id}\nCandidate: {candidate_digest}",
            )
            commit_sha = self.git(worktree, "rev-parse", "HEAD").stdout.strip()
            if not COMMIT_RE.fullmatch(commit_sha):
                raise GitBrokerError("Git did not return a full candidate commit SHA")
            return Candidate(
                lease.rfc_id, branch, base_commit, commit_sha, candidate_digest
            )

    def create_reviewer_snapshot(self, lease: JobLease, candidate: Candidate) -> Path:
        self._validate_candidate(lease, candidate)
        snapshot = self.layout.reviewer_snapshot(candidate.rfc_id, candidate.commit_sha)
        with self.locked():
            self.validate_lease(lease)
            if snapshot.exists():
                actual = self.git(snapshot, "rev-parse", "HEAD").stdout.strip()
                if actual != candidate.commit_sha:
                    raise GitBrokerError("existing Reviewer snapshot has the wrong commit")
                return snapshot
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            self.git(
                self.repository,
                "worktree",
                "add",
                "--detach",
                str(snapshot),
                candidate.commit_sha,
            )
            self._make_read_only(snapshot)
            return snapshot

    def push_candidate(
        self, lease: JobLease, candidate: Candidate, remote: str = "origin"
    ) -> None:
        self._validate_candidate(lease, candidate)
        worktree = self.layout.task_worktree(candidate.rfc_id)
        with self.locked():
            self.validate_lease(lease)
            head = self.git(worktree, "rev-parse", "HEAD").stdout.strip()
            if head != candidate.commit_sha:
                raise GitBrokerError("worktree HEAD no longer matches reviewed candidate")
            self.git(
                worktree,
                "push",
                remote,
                f"refs/heads/{candidate.branch}:refs/heads/{candidate.branch}",
            )

    def _validate_candidate(self, lease: JobLease, candidate: Candidate) -> None:
        self.validate_lease(lease)
        if candidate.rfc_id != lease.rfc_id or candidate.branch != f"agent/{lease.rfc_id}":
            raise GitBrokerError("candidate identity does not match lease")
        if not COMMIT_RE.fullmatch(candidate.commit_sha):
            raise GitBrokerError("candidate commit is invalid")

    @staticmethod
    def _validate_identity(rfc_id: str, commit_sha: str) -> None:
        if not RFC_ID_RE.fullmatch(rfc_id):
            raise ValueError("invalid RFC ID")
        if not COMMIT_RE.fullmatch(commit_sha):
            raise ValueError("base commit must be a full Git SHA")

    @staticmethod
    def _make_read_only(root: Path) -> None:
        for current_root, directories, files in os.walk(root):
            for name in files:
                path = Path(current_root) / name
                mode = stat.S_IMODE(path.stat().st_mode)
                os.chmod(path, mode & ~0o222)
            for name in directories:
                path = Path(current_root) / name
                mode = stat.S_IMODE(path.stat().st_mode)
                os.chmod(path, mode & ~0o222)
        mode = stat.S_IMODE(root.stat().st_mode)
        os.chmod(root, mode & ~0o222)
