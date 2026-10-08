"""Read-only Git verification for scheduler admission and merge evidence."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from .runner import RunnerError, RunnerTimeout, run_bounded


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class GitVerificationError(RuntimeError):
    pass


class RepositoryGitVerifier:
    def __init__(
        self,
        repository: Path,
        *,
        trusted_main_ref: str = "refs/remotes/origin/main",
        timeout_seconds: float = 30,
    ) -> None:
        self.repository = repository.resolve()
        if not (self.repository / ".git").exists():
            raise ValueError("repository must be a non-bare Git checkout")
        if not REF_RE.fullmatch(trusted_main_ref) or ".." in trusted_main_ref:
            raise ValueError("invalid trusted main ref")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.trusted_main_ref = trusted_main_ref
        self.timeout_seconds = timeout_seconds

    def resolve_trusted_main(self) -> str:
        return self._resolve(self.trusted_main_ref)

    def resolve_ref(self, ref_name: str) -> str:
        """Resolve one fully-qualified local ref without changing repository state."""
        if (
            not ref_name.startswith("refs/")
            or not REF_RE.fullmatch(ref_name)
            or ".." in ref_name
        ):
            raise ValueError("invalid fully-qualified Git ref")
        return self._resolve(ref_name)

    def require_exact_ref(self, ref_name: str, expected_commit: str) -> None:
        self.require_commit(expected_commit)
        if self.resolve_ref(ref_name) != expected_commit:
            raise GitVerificationError(
                f"{ref_name} does not identify the reviewed candidate {expected_commit}"
            )

    def candidate_tree(self, commit: str) -> str:
        self.require_commit(commit)
        return self._resolve(f"{commit}^{{tree}}")

    def candidate_diff_digest(self, base_commit: str, commit: str) -> str:
        self.require_ancestor(base_commit, commit)
        result = self._git_bytes(
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-renames",
            base_commit,
            commit,
            "--",
        )
        return "sha256:" + hashlib.sha256(result.stdout).hexdigest()

    def changed_paths(self, base_commit: str, commit: str) -> tuple[str, ...]:
        self.require_ancestor(base_commit, commit)
        result = self._git_bytes(
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            base_commit,
            commit,
            "--",
        )
        try:
            paths = tuple(
                sorted(part.decode("utf-8") for part in result.stdout.split(b"\0") if part)
            )
        except UnicodeDecodeError as exc:
            raise GitVerificationError("candidate contains a non-UTF-8 path") from exc
        if any(
            path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in Path(path).parts)
            for path in paths
        ):
            raise GitVerificationError("candidate contains an invalid repository path")
        return paths

    def refresh_trusted_main(self, remote: str = "origin", branch: str = "main") -> str:
        """Fetch a remote branch into the dedicated trusted ref and return its SHA."""
        if not REMOTE_RE.fullmatch(remote):
            raise ValueError("invalid Git remote name")
        if not REF_RE.fullmatch(branch) or ".." in branch or branch.startswith("-"):
            raise ValueError("invalid Git branch name")
        destination = self.trusted_main_ref
        if not destination.startswith("refs/"):
            raise GitVerificationError("refusing to fetch into a non-qualified trusted ref")
        self._git(
            "fetch",
            "--no-tags",
            "--force",
            remote,
            f"+refs/heads/{branch}:{destination}",
        )
        return self.resolve_trusted_main()

    def require_commit(self, commit: str) -> None:
        if not COMMIT_RE.fullmatch(commit):
            raise GitVerificationError("commit must be a full Git SHA")
        if self._resolve(f"{commit}^{{commit}}") != commit:
            raise GitVerificationError(f"Git object does not resolve exactly: {commit}")

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        self.require_commit(ancestor)
        self.require_commit(descendant)
        result = self._git("merge-base", "--is-ancestor", ancestor, descendant, check=False)
        if result.returncode == 1:
            raise GitVerificationError(f"{ancestor} is not an ancestor of {descendant}")
        if result.returncode != 0:
            raise GitVerificationError(
                f"git merge-base failed ({result.returncode}): {str(result.stderr)[-2000:]}"
            )

    def require_on_trusted_main(self, commit: str) -> str:
        main = self.resolve_trusted_main()
        self.require_ancestor(commit, main)
        return main

    def _resolve(self, value: str) -> str:
        result = self._git("rev-parse", "--verify", value)
        resolved = str(result.stdout).strip()
        if not COMMIT_RE.fullmatch(resolved):
            raise GitVerificationError(f"Git did not resolve a full commit for {value}")
        return resolved

    def _git(self, *arguments: str, check: bool = True):
        try:
            result = run_bounded(
                ["git", "-C", str(self.repository), *arguments],
                cwd=self.repository,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                },
                timeout_seconds=self.timeout_seconds,
            )
        except (RunnerError, RunnerTimeout) as exc:
            raise GitVerificationError(f"Git verification could not run: {exc}") from exc
        if check and result.returncode != 0:
            raise GitVerificationError(
                f"git {' '.join(arguments)} failed ({result.returncode}): "
                f"{str(result.stderr)[-2000:]}"
            )
        return result

    def _git_bytes(self, *arguments: str):
        try:
            result = run_bounded(
                ["git", "-C", str(self.repository), *arguments],
                cwd=self.repository,
                text=False,
                env={
                    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
                    "HOME": os.environ.get("HOME", "/nonexistent"),
                    "GIT_TERMINAL_PROMPT": "0",
                    "GIT_OPTIONAL_LOCKS": "0",
                    "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull,
                    "LANG": os.environ.get("LANG", "C.UTF-8"),
                },
                timeout_seconds=self.timeout_seconds,
            )
        except (RunnerError, RunnerTimeout) as exc:
            raise GitVerificationError(f"Git verification could not run: {exc}") from exc
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace")
            raise GitVerificationError(
                f"git {' '.join(arguments)} failed ({result.returncode}): {detail[-2000:]}"
            )
        return result
