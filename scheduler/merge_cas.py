"""Explicit, fenced remote merge CAS primitive; never wired to production automatically."""

from __future__ import annotations

import fcntl
import os
import re
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

from .git_verifier import RepositoryGitVerifier
from .runner import RunnerError, RunnerTimeout, run_bounded


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REF_RE = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class MergeCasError(RuntimeError):
    pass


class AtomicMergeCas(Protocol):
    repository_identity: str
    maximum_duration_seconds: float

    def compare_and_swap(
        self,
        *,
        reservation_id: str,
        fencing_token: int,
        expected_main_commit: str,
        main_ref: str,
        expected_candidate_commit: str,
        candidate_ref: str,
        merge_target_commit: str,
    ) -> None:
        """Atomically validate both remote refs and update main or raise."""


class AtomicGitMergeCas:
    """Use one atomic Git transaction with exact leases for main and candidate."""

    def __init__(
        self,
        repository: Path,
        trusted_remote_url: str,
        lock_path: Path,
        *,
        timeout_seconds: float = 30,
    ) -> None:
        self.repository = repository.resolve()
        self.trusted_remote_url = trusted_remote_url
        self.lock_path = lock_path
        if timeout_seconds <= 0:
            raise ValueError("merge CAS timeout must be positive")
        self.maximum_duration_seconds = float(timeout_seconds)
        verifier = RepositoryGitVerifier(self.repository)
        self.repository_identity = verifier.normalize_remote_identity(trusted_remote_url)
        lock_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def compare_and_swap(
        self,
        *,
        reservation_id: str,
        fencing_token: int,
        expected_main_commit: str,
        main_ref: str,
        expected_candidate_commit: str,
        candidate_ref: str,
        merge_target_commit: str,
    ) -> None:
        if not reservation_id or fencing_token <= 0:
            raise ValueError("merge CAS requires a reservation and positive fence")
        for commit in (
            expected_main_commit,
            expected_candidate_commit,
            merge_target_commit,
        ):
            if not COMMIT_RE.fullmatch(commit):
                raise ValueError("merge CAS commits must be full Git SHAs")
        for ref_name in (main_ref, candidate_ref):
            if not REF_RE.fullmatch(ref_name) or ".." in ref_name:
                raise ValueError("merge CAS refs must be qualified branch refs")
        if main_ref == candidate_ref:
            raise ValueError("main and candidate refs must be distinct")

        arguments = [
            "git",
            "-C",
            str(self.repository),
            "push",
            "--atomic",
            f"--force-with-lease={main_ref}:{expected_main_commit}",
            f"--force-with-lease={candidate_ref}:{expected_candidate_commit}",
            self.trusted_remote_url,
            f"{expected_candidate_commit}:{candidate_ref}",
            f"{merge_target_commit}:{main_ref}",
        ]
        environment = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/nonexistent"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
        with self._locked():
            try:
                result = run_bounded(
                    arguments,
                    cwd=self.repository,
                    env=environment,
                    timeout_seconds=self.maximum_duration_seconds,
                )
            except (RunnerError, RunnerTimeout) as exc:
                raise MergeCasError("atomic merge CAS could not run") from exc
        if result.returncode != 0:
            # The explicit URL or remote diagnostic can contain credentials.
            raise MergeCasError(f"atomic merge CAS was rejected ({result.returncode})")
