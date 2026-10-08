from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scheduler.git_broker import GitBroker, GitBrokerError
from scheduler.isolation import IsolationLayout
from scheduler.leases import JobLease
from scheduler.runner import RunnerError


RFC = "RFC-20261008-056"


class AcceptingProbe:
    """Test double; real kernel permission checks live in test_scheduler_runner."""

    def verify(self, _root: Path) -> None:
        return


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
            broker = GitBroker(
                repo,
                layout,
                root / "runtime" / "git.lock",
                validate,
                reviewer_read_only_probe=AcceptingProbe(),  # type: ignore[arg-type]
            )
            worktree = broker.prepare_worktree(lease, base)
            (worktree / "src.ts").write_text("export const ready = true;\n")
            candidate = broker.freeze_candidate(lease, base, "Agent core")
            self.assertTrue(candidate.candidate_digest.startswith("sha256:"))
            self.assertTrue(candidate.diff_digest.startswith("sha256:"))
            self.assertEqual(candidate.revision_digest, lease.revision_digest)
            self.assertEqual(candidate.commit_sha, run(repo, "rev-parse", candidate.branch))
            self.assertEqual(
                candidate.tree_sha,
                run(repo, "rev-parse", f"{candidate.commit_sha}^{{tree}}"),
            )
            full_diff = subprocess.run(
                [
                    "git", "-C", str(repo), "diff", "--binary", "--full-index",
                    "--no-ext-diff", "--no-renames", base, candidate.commit_sha, "--",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ).stdout
            self.assertEqual(
                candidate.diff_digest,
                "sha256:" + hashlib.sha256(full_diff).hexdigest(),
            )
            self.assertEqual(candidate, broker.freeze_candidate(lease, base, "Agent core"))
            unverified = GitBroker(
                repo, layout, root / "runtime" / "git-unverified.lock", validate
            )
            with self.assertRaisesRegex(GitBrokerError, "identity read-only probe"):
                unverified.create_reviewer_snapshot(lease, candidate)
            snapshot = broker.create_reviewer_snapshot(lease, candidate)
            self.assertEqual((snapshot / "src.ts").read_text(), "export const ready = true;\n")
            self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode) & 0o222, 0)
            self.assertEqual(stat.S_IMODE((snapshot / "src.ts").stat().st_mode) & 0o222, 0)
            self.assertNotEqual(worktree, snapshot)
            self.assertEqual(snapshot, broker.create_reviewer_snapshot(lease, candidate))
            broker.cleanup_reviewer_snapshot(lease, candidate)
            broker.cleanup_reviewer_snapshot(lease, candidate)
            self.assertFalse(snapshot.exists())
            broker.cleanup_worktree(lease)
            broker.cleanup_worktree(lease)
            self.assertFalse(worktree.exists())

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
            self.assertFalse(layout.task_worktree(RFC, lease.fencing_token).exists())

    def test_replacement_lease_gets_a_distinct_worktree_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "base").write_text("base\n")
            run(repo, "add", "base")
            run(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "base")
            base = run(repo, "rev-parse", "HEAD")
            old = JobLease(
                "lease-old", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )
            replacement = replace(
                old,
                lease_id="lease-new",
                job_id=2,
                holder_agent_id="coder-2",
                fencing_token=2,
                attempt=2,
            )
            valid = {old.lease_id: old.fencing_token}

            def validate(value: JobLease) -> None:
                if valid.get(value.lease_id) != value.fencing_token:
                    raise GitBrokerError("stale lease")

            layout = IsolationLayout(root / "runtime")
            broker = GitBroker(repo, layout, root / "git.lock", validate)
            old_worktree = broker.prepare_worktree(old, base)
            (old_worktree / "stale.ts").write_text("stale\n")
            valid.clear()
            valid[replacement.lease_id] = replacement.fencing_token
            new_worktree = broker.prepare_worktree(replacement, base)

            self.assertNotEqual(old_worktree, new_worktree)
            self.assertTrue(old_worktree.exists())
            self.assertFalse((new_worktree / "stale.ts").exists())
            with self.assertRaisesRegex(GitBrokerError, "stale lease"):
                broker.freeze_candidate(old, base, "stale")

    def test_candidate_evidence_is_recomputed_before_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "base").write_text("base\n")
            run(repo, "add", "base")
            run(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "base")
            base = run(repo, "rev-parse", "HEAD")
            lease = JobLease(
                "lease-1", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )
            broker = GitBroker(
                repo,
                IsolationLayout(root / "runtime"),
                root / "git.lock",
                lambda _lease: None,
            )
            worktree = broker.prepare_worktree(lease, base)
            (worktree / "change").write_text("candidate\n")
            candidate = broker.freeze_candidate(lease, base, "candidate")

            for field, value in (
                ("tree_sha", "f" * 40),
                ("diff_digest", "sha256:" + "f" * 64),
                ("candidate_digest", "sha256:" + "f" * 64),
                ("base_commit", candidate.commit_sha),
            ):
                with self.subTest(field=field):
                    with self.assertRaises(GitBrokerError):
                        broker.create_reviewer_snapshot(
                            lease, replace(candidate, **{field: value})
                        )

            run(repo, "update-ref", f"refs/heads/{candidate.branch}", base)
            with self.assertRaisesRegex(GitBrokerError, "branch no longer identifies"):
                broker.create_reviewer_snapshot(lease, candidate)

    def test_git_command_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            sleeper = root / "sleep-prefix"
            sleeper.write_text("#!/bin/sh\nsleep 10\n")
            sleeper.chmod(0o700)
            broker = GitBroker(
                repo,
                IsolationLayout(root / "runtime"),
                root / "git.lock",
                lambda _lease: None,
                command_prefix=(str(sleeper),),
                git_timeout_seconds=0.05,
            )
            with self.assertRaisesRegex(GitBrokerError, "timed out"):
                broker.git(repo, "status")

    def test_lease_loss_after_branch_update_rolls_back_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "base").write_text("base\n")
            run(repo, "add", "base")
            run(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "base")
            base = run(repo, "rev-parse", "HEAD")
            lease = JobLease(
                "lease-1", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )
            branch_ref = f"refs/heads/agent/{RFC}"

            def validate(_lease: JobLease) -> None:
                published = subprocess.run(
                    ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", branch_ref],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if published.returncode == 0:
                    raise GitBrokerError("lease expired during publication")

            broker = GitBroker(
                repo,
                IsolationLayout(root / "runtime"),
                root / "git.lock",
                validate,
            )
            worktree = broker.prepare_worktree(lease, base)
            (worktree / "change").write_text("candidate\n")
            with self.assertRaisesRegex(GitBrokerError, "expired during publication"):
                broker.freeze_candidate(lease, base, "candidate")
            missing = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", branch_ref],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertNotEqual(missing.returncode, 0)

    def test_failed_read_only_probe_cleans_snapshot_and_git_metadata(self) -> None:
        class RejectingProbe:
            def verify(self, _root: Path) -> None:
                raise RunnerError("identity can write")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            run(repo, "init", "-b", "main")
            (repo / "base").write_text("base\n")
            run(repo, "add", "base")
            run(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "base")
            base = run(repo, "rev-parse", "HEAD")
            lease = JobLease(
                "lease-1", 1, RFC, "sha256:" + "a" * 64, "coding", "coder",
                "coder-1", 1, 9999999999, None, 1
            )
            layout = IsolationLayout(root / "runtime")
            broker = GitBroker(
                repo,
                layout,
                root / "git.lock",
                lambda _lease: None,
                reviewer_read_only_probe=RejectingProbe(),  # type: ignore[arg-type]
            )
            worktree = broker.prepare_worktree(lease, base)
            (worktree / "change").write_text("candidate\n")
            candidate = broker.freeze_candidate(lease, base, "candidate")
            snapshot = layout.reviewer_snapshot(RFC, candidate.commit_sha)

            with self.assertRaisesRegex(GitBrokerError, "read-only identity check"):
                broker.create_reviewer_snapshot(lease, candidate)
            self.assertFalse(snapshot.exists())
            self.assertNotIn(str(snapshot), run(repo, "worktree", "list", "--porcelain"))


if __name__ == "__main__":
    unittest.main()
