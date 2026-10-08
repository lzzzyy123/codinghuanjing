from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from scheduler.git_broker import GitBroker, GitBrokerError
from scheduler.isolation import IsolationLayout
from scheduler.leases import JobLease


RFC = "RFC-20261008-056"


def run(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


class GitBrokerTests(unittest.TestCase):
    def test_worktree_candidate_and_read_only_reviewer_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "README.md").write_text("base\n")
            run(repo, "add", "README.md")
            run(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "base",
            )
            base = run(repo, "rev-parse", "HEAD")
            lease = JobLease(
                "lease-1", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )
            valid = {lease.lease_id: lease.fencing_token}

            def validate(value: JobLease) -> None:
                if valid.get(value.lease_id) != value.fencing_token:
                    raise GitBrokerError("stale lease")

            layout = IsolationLayout(root / "runtime")
            broker = GitBroker(repo, layout, root / "runtime" / "git.lock", validate)
            worktree = broker.prepare_worktree(lease, base)
            (worktree / "src.ts").write_text("export const ready = true;\n")
            candidate = broker.freeze_candidate(lease, base, "Agent core")
            self.assertTrue(candidate.candidate_digest.startswith("sha256:"))
            snapshot = broker.create_reviewer_snapshot(lease, candidate)
            self.assertEqual((snapshot / "src.ts").read_text(), "export const ready = true;\n")
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode) & 0o222, 0)
            self.assertEqual(stat.S_IMODE((snapshot / "src.ts").stat().st_mode) & 0o222, 0)
            self.assertNotEqual(worktree, snapshot)

    def test_distinct_agent_homes_and_stale_fence_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = IsolationLayout(root)
            first = layout.agent_paths("coder-1")
            second = layout.agent_paths("reviewer-1")
            self.assertNotEqual(first.home, second.home)
            self.assertEqual(stat.S_IMODE(first.home.stat().st_mode), 0o700)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "a").write_text("a")
            run(repo, "add", "a")
            run(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "base",
            )
            base = run(repo, "rev-parse", "HEAD")
            lease = JobLease(
                "lease-1", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )

            def reject(_lease: JobLease) -> None:
                raise GitBrokerError("stale lease")

            broker = GitBroker(repo, layout, root / "git.lock", reject)
            with self.assertRaisesRegex(GitBrokerError, "stale lease"):
                broker.prepare_worktree(lease, base)
            self.assertFalse(layout.task_worktree(RFC).exists())


if __name__ == "__main__":
    unittest.main()
