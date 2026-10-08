from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scheduler.git_verifier import GitVerificationError, RepositoryGitVerifier


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def init_main(repo: Path) -> None:
    git(repo, "init")
    git(repo, "checkout", "-b", "main")


class GitVerifierTests(unittest.TestCase):
    def test_candidate_verification_is_exact_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            init_main(repo)
            (repo / "a").write_text("base\n")
            git(repo, "add", "a")
            git(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=t@invalid",
                "commit",
                "-m",
                "base",
            )
            base = git(repo, "rev-parse", "HEAD")
            git(repo, "checkout", "-b", "agent/RFC-20261008-056")
            (repo / "src").mkdir()
            (repo / "src" / "provider.ts").write_text("export {};\n")
            git(repo, "add", "src/provider.ts")
            git(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=t@invalid",
                "commit",
                "-m",
                "candidate",
            )
            candidate = git(repo, "rev-parse", "HEAD")
            verifier = RepositoryGitVerifier(repo)
            ref_name = "refs/heads/agent/RFC-20261008-056"

            self.assertEqual(verifier.resolve_ref(ref_name), candidate)
            verifier.require_exact_ref(ref_name, candidate)
            self.assertEqual(
                verifier.candidate_tree(candidate), git(repo, "rev-parse", "HEAD^{tree}")
            )
            self.assertRegex(verifier.candidate_diff_digest(base, candidate), r"^sha256:")
            self.assertEqual(verifier.changed_paths(base, candidate), ("src/provider.ts",))
            self.assertEqual(git(repo, "rev-parse", ref_name), candidate)

            with self.assertRaisesRegex(GitVerificationError, "does not identify"):
                verifier.require_exact_ref(ref_name, base)
            with self.assertRaises(ValueError):
                verifier.resolve_ref("main")

    def test_refresh_trusted_main_fetches_remote_branch_into_dedicated_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            repo = root / "repo"
            git(root, "init", "--bare", str(remote))
            repo.mkdir()
            init_main(repo)
            git(repo, "remote", "add", "origin", str(remote))
            (repo / "a").write_text("a")
            git(repo, "add", "a")
            git(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "a")
            first = git(repo, "rev-parse", "HEAD")
            git(repo, "push", "origin", "main")

            verifier = RepositoryGitVerifier(
                repo, trusted_main_ref="refs/coding-scheduler/trusted-main"
            )
            self.assertEqual(verifier.refresh_trusted_main(), first)
            self.assertEqual(
                git(repo, "rev-parse", "refs/coding-scheduler/trusted-main"), first
            )

            (repo / "a").write_text("b")
            git(repo, "add", "a")
            git(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "b")
            second = git(repo, "rev-parse", "HEAD")
            git(repo, "push", "origin", "main")
            self.assertEqual(verifier.refresh_trusted_main(), second)

    def test_trusted_main_requires_real_commit_and_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            init_main(repo)
            (repo / "a").write_text("a")
            git(repo, "add", "a")
            git(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "a")
            first = git(repo, "rev-parse", "HEAD")
            git(repo, "update-ref", "refs/remotes/origin/main", first)
            verifier = RepositoryGitVerifier(repo)
            self.assertEqual(verifier.require_on_trusted_main(first), first)

            git(repo, "checkout", "--orphan", "other")
            (repo / "a").unlink()
            (repo / "b").write_text("b")
            git(repo, "add", "-A")
            git(repo, "-c", "user.name=Test", "-c", "user.email=t@invalid", "commit", "-m", "b")
            unrelated = git(repo, "rev-parse", "HEAD")
            with self.assertRaisesRegex(GitVerificationError, "not an ancestor"):
                verifier.require_on_trusted_main(unrelated)
            with self.assertRaises(GitVerificationError):
                verifier.require_commit("f" * 40)


if __name__ == "__main__":
    unittest.main()
