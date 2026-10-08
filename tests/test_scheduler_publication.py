from __future__ import annotations

import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scheduler.git_broker import CandidateScope, GitBroker, GitBrokerError
from scheduler.isolation import IsolationLayout
from scheduler.leases import JobLease
from scheduler.publication import PublicationJournal
from scheduler.state_store import StateConflict, StateStore


RFC = "RFC-20261008-056"
REVISION = "sha256:" + "a" * 64


def run(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def fixture(root: Path):
    remote = root / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    repo = root / "repo"
    repo.mkdir()
    run(repo, "init")
    run(repo, "checkout", "-b", "main")
    (repo / "base").write_text("base\n")
    run(repo, "add", "base")
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
    run(repo, "remote", "add", "origin", str(remote))
    run(repo, "push", "origin", "main")
    lease = JobLease(
        "lease-1",
        1,
        RFC,
        REVISION,
        "coding",
        "coder",
        "coder-1",
        1,
        9999999999,
        None,
        1,
        base,
    )
    store = StateStore(root / "state.sqlite3")
    journal = PublicationJournal(store)
    broker = GitBroker(
        repo,
        IsolationLayout(root / "runtime"),
        root / "git.lock",
        lambda _lease: None,
        candidate_scope=lambda _lease: CandidateScope(frozenset({"change"})),
        publication_journal=journal,
    )
    worktree = broker.prepare_worktree(lease, base)
    (worktree / "change").write_text("candidate\n")
    candidate = broker.freeze_candidate(lease, base, "candidate")
    return repo, remote, lease, journal, broker, candidate


class PublicationTests(unittest.TestCase):
    def test_stale_fence_cannot_mutate_or_downgrade_an_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _repo, _remote, lease, journal, _broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id="lease-2",
                fencing_token=2,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            with self.assertRaisesRegex(StateConflict, "stale lease fence"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id=lease.lease_id,
                    fencing_token=lease.fencing_token,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=None,
                    target_commit=candidate.commit_sha,
                )
            with self.assertRaisesRegex(StateConflict, "stale lease fence"):
                journal.mark_published(
                    publication_id,
                    candidate.commit_sha,
                    lease_id=lease.lease_id,
                    fencing_token=lease.fencing_token,
                )
            record = journal.get(publication_id)
            self.assertEqual(record.lease_id, "lease-2")
            self.assertEqual(record.fencing_token, 2)
            self.assertEqual(record.state, "prepared")

    def test_published_observation_is_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _repo, _remote, lease, journal, _broker, candidate = fixture(Path(directory))
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=f"refs/heads/{candidate.branch}",
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            journal.mark_published(
                publication_id,
                candidate.commit_sha,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
            )
            self.assertEqual(journal.reconcile(publication_id, None), "published")
            record = journal.get(publication_id)
            self.assertEqual(record.state, "published")
            self.assertRegex(record.last_error or "", "diverged")

    def test_changed_precondition_and_parallel_ref_intent_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _repo, _remote, lease, journal, _broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            with self.assertRaisesRegex(StateConflict, "changed while publication"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id="lease-2",
                    fencing_token=2,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=lease.base_commit,
                    target_commit=candidate.commit_sha,
                )
            self.assertEqual(journal.get(publication_id).state, "blocked")
            with self.assertRaisesRegex(StateConflict, "unresolved publication intent"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest="sha256:" + "b" * 64,
                    lease_id="lease-3",
                    fencing_token=3,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=None,
                    target_commit="b" * 40,
                )

    def test_reopened_intent_cannot_bypass_active_ref_arbitration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _repo, _remote, lease, journal, _broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            first = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            self.assertEqual(journal.reconcile(first, None), "not_published")
            second = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest="sha256:" + "b" * 64,
                lease_id="lease-2",
                fencing_token=2,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit="b" * 40,
            ).publication_id

            with self.assertRaisesRegex(StateConflict, "unresolved publication intent"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id="lease-3",
                    fencing_token=3,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=None,
                    target_commit=candidate.commit_sha,
                )
            self.assertEqual([row.publication_id for row in journal.pending()], [second])

    def test_published_prepare_divergence_preserves_publication_fact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _repo, _remote, lease, journal, _broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            journal.mark_published(
                publication_id,
                candidate.commit_sha,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
            )
            with self.assertRaisesRegex(StateConflict, "published remote ref diverged"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id="lease-2",
                    fencing_token=2,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=lease.base_commit,
                    target_commit=candidate.commit_sha,
                )
            record = journal.get(publication_id)
            self.assertEqual(record.state, "published")
            self.assertRegex(record.last_error or "", "diverged")
            self.assertEqual(record.lease_id, "lease-2")
            self.assertEqual(record.fencing_token, 2)
            with self.assertRaisesRegex(StateConflict, "stale lease fence"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id=lease.lease_id,
                    fencing_token=lease.fencing_token,
                    remote="origin",
                    ref_name=ref,
                    previous_commit=lease.base_commit,
                    target_commit=candidate.commit_sha,
                )

    def test_push_is_journaled_and_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, remote, lease, journal, broker, candidate = fixture(Path(directory))
            broker.push_candidate(lease, candidate)
            remote_tip = run(
                remote, "rev-parse", f"refs/heads/{candidate.branch}"
            )
            self.assertEqual(remote_tip, candidate.commit_sha)
            with journal.store.connect() as connection:
                row = connection.execute(
                    "SELECT * FROM publication_records"
                ).fetchone()
            self.assertEqual(row["state"], "confirmed")
            self.assertEqual(row["target_commit"], candidate.commit_sha)

            retry = replace(
                lease,
                lease_id="lease-2",
                job_id=2,
                holder_agent_id="coder-2",
                fencing_token=2,
                attempt=2,
            )
            broker.push_candidate(retry, candidate)
            with journal.store.connect() as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM publication_records"
                ).fetchone()[0]
            self.assertEqual(count, 1)
            self.assertEqual(journal.get(int(row["publication_id"])).state, "confirmed")

            run(remote, "update-ref", f"refs/heads/{candidate.branch}", lease.base_commit)
            with self.assertRaisesRegex(StateConflict, "confirmed remote ref diverged"):
                broker.push_candidate(retry, candidate)
            self.assertEqual(
                run(remote, "rev-parse", f"refs/heads/{candidate.branch}"),
                lease.base_commit,
            )
            confirmed = journal.get(int(row["publication_id"]))
            self.assertEqual(confirmed.state, "confirmed")
            self.assertRegex(confirmed.last_error or "", "diverged")
            self.assertEqual(confirmed.lease_id, retry.lease_id)
            self.assertEqual(confirmed.fencing_token, retry.fencing_token)
            with self.assertRaisesRegex(StateConflict, "stale lease fence"):
                journal.prepare(
                    rfc_id=candidate.rfc_id,
                    revision_digest=candidate.revision_digest,
                    candidate_digest=candidate.candidate_digest,
                    lease_id=lease.lease_id,
                    fencing_token=lease.fencing_token,
                    remote="origin",
                    ref_name=f"refs/heads/{candidate.branch}",
                    previous_commit=lease.base_commit,
                    target_commit=candidate.commit_sha,
                )

    def test_crash_after_push_is_reconciled_and_retry_confirms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _remote, lease, journal, broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            run(repo, "push", "origin", f"{candidate.commit_sha}:{ref}")

            self.assertEqual(
                broker.reconcile_publications(),
                {"published": 1, "not_published": 0, "blocked": 0},
            )
            self.assertEqual(journal.get(publication_id).state, "published")

            broker.push_candidate(lease, candidate)
            self.assertEqual(journal.get(publication_id).state, "confirmed")

    def test_reconciler_blocks_an_unexpected_remote_tip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo, _remote, lease, journal, broker, candidate = fixture(Path(directory))
            ref = f"refs/heads/{candidate.branch}"
            publication_id = journal.prepare(
                rfc_id=candidate.rfc_id,
                revision_digest=candidate.revision_digest,
                candidate_digest=candidate.candidate_digest,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                remote="origin",
                ref_name=ref,
                previous_commit=None,
                target_commit=candidate.commit_sha,
            ).publication_id
            run(repo, "checkout", "main")
            (repo / "other").write_text("other\n")
            run(repo, "add", "other")
            run(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "other",
            )
            other = run(repo, "rev-parse", "HEAD")
            run(repo, "push", "origin", f"{other}:{ref}")

            self.assertEqual(
                broker.reconcile_publications(),
                {"published": 0, "not_published": 0, "blocked": 1},
            )
            self.assertEqual(journal.get(publication_id).state, "blocked")
            with self.assertRaisesRegex(GitBrokerError, "durable journal"):
                GitBroker(
                    repo,
                    IsolationLayout(Path(directory) / "nojournal"),
                    Path(directory) / "nojournal.lock",
                    lambda _lease: None,
                    candidate_scope=lambda _lease: CandidateScope(
                        frozenset({"change"})
                    ),
                ).push_candidate(lease, candidate)


if __name__ == "__main__":
    unittest.main()
