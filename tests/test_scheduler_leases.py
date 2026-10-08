from __future__ import annotations

import concurrent.futures
import json
import tempfile
import unittest
from pathlib import Path

from scheduler.leases import LeaseError, QueueStore
from scheduler.models import TaskState
from scheduler.registry import load_registry, with_revision_digest
from scheduler.state_store import StateStore


def setup(root: Path) -> tuple[StateStore, QueueStore]:
    rfc = with_revision_digest(
        {
            "id": "RFC-20261008-056",
            "title": "Agent core",
            "capability_group": "agent",
            "revision": 1,
            "python_sources": ["hermes/agent.py"],
            "target_files": ["src/agent.ts"],
            "source_targets": {"hermes/agent.py": "src/agent.ts"},
            "lock_keys": ["shared-registry"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}, "definitions": {}},
            "tests": {"level1": ["bun run typecheck"], "level2": ["bun test"]},
            "integration_batch": "agent",
            "acceptance_criteria": ["Equivalent."],
        }
    )
    path = root / "dag.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "commit": "a" * 40,
                    "classification_sha256": "sha256:" + "b" * 64,
                    "in_scope_count": 806,
                },
                "rfcs": [rfc],
            }
        )
    )
    store = StateStore(root / "state.sqlite3")
    store.import_registry(load_registry(path))
    store.transition(
        rfc["id"], TaskState.DRAFT, TaskState.VALIDATED, "validator"
    )
    store.transition(
        rfc["id"], TaskState.VALIDATED, TaskState.READY, "scheduler"
    )
    return store, QueueStore(store)


class LeaseTests(unittest.TestCase):
    def test_concurrent_claim_has_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, queue = setup(Path(directory))
            for index in range(2):
                queue.register_agent(f"coder-{index}", "coder", "xiaosuan-8", f"pid:{index}")
            queue.enqueue(
                "RFC-20261008-056", "coding", "coding:056:1", available_at=0
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                leases = list(
                    executor.map(
                        lambda agent: queue.claim(agent, now=100, lease_seconds=30),
                        ("coder-0", "coder-1"),
                    )
                )
            winners = [lease for lease in leases if lease is not None]
            self.assertEqual(len(winners), 1)
            self.assertEqual(store.task("RFC-20261008-056")["state"], "Leased")

    def test_expired_lease_is_recovered_and_old_writer_is_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, queue = setup(Path(directory))
            queue.register_agent("coder-a", "coder", "xiaosuan-8", "pid:1", now=0)
            queue.register_agent("coder-b", "coder", "xiaosuan-8", "pid:2", now=0)
            queue.enqueue("RFC-20261008-056", "coding", "coding:056:1", available_at=0)
            old = queue.claim("coder-a", now=0, lease_seconds=10)
            self.assertIsNotNone(old)
            queue.start(old, now=1)
            self.assertEqual(queue.recover_expired(now=11), [old.job_id])
            fresh = queue.claim("coder-b", now=11, lease_seconds=10)
            self.assertGreater(fresh.fencing_token, old.fencing_token)
            with self.assertRaisesRegex(LeaseError, "does not exist"):
                queue.finish(old, "passed", {}, now=11)

    def test_expired_integration_lease_returns_to_claimable_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, queue = setup(Path(directory))
            rfc_id = "RFC-20261008-056"
            for expected, target in (
                (TaskState.READY, TaskState.LEASED),
                (TaskState.LEASED, TaskState.CODING),
                (TaskState.CODING, TaskState.TESTING),
                (TaskState.TESTING, TaskState.REVIEWING),
                (TaskState.REVIEWING, TaskState.LEAD_REVIEW),
                (TaskState.LEAD_REVIEW, TaskState.INTEGRATION_READY),
            ):
                store.transition(rfc_id, expected, target, "fixture")
            candidate = "sha256:" + "c" * 64
            queue.enqueue(
                rfc_id,
                "integration",
                "integration:1",
                candidate_digest=candidate,
                available_at=0,
            )
            queue.register_agent("integrator-a", "integrator", "local", "pid:1", now=0)
            queue.register_agent("integrator-b", "integrator", "local", "pid:2", now=0)
            old = queue.claim("integrator-a", now=0, lease_seconds=10)
            queue.start(old, now=1)
            self.assertEqual(store.task(rfc_id)["state"], "Integrating")
            self.assertEqual(queue.recover_expired(now=11), [old.job_id])
            self.assertEqual(store.task(rfc_id)["state"], "IntegrationReady")
            replacement = queue.claim("integrator-b", now=11, lease_seconds=10)
            self.assertIsNotNone(replacement)
            self.assertGreater(replacement.fencing_token, old.fencing_token)

    def test_expired_job_at_attempt_limit_is_explicitly_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, queue = setup(Path(directory))
            queue.register_agent("coder-a", "coder", "xiaosuan-8", "pid:1", now=0)
            queue.enqueue(
                "RFC-20261008-056",
                "coding",
                "coding:bounded",
                max_attempts=1,
                available_at=0,
            )
            lease = queue.claim("coder-a", now=0, lease_seconds=10)
            queue.start(lease, now=1)
            self.assertEqual(queue.recover_expired(now=11), [lease.job_id])
            self.assertEqual(store.task(lease.rfc_id)["state"], "Blocked")
            job = queue.jobs()[0]
            self.assertEqual(job["state"], "failed")
            self.assertEqual(job["result"]["failure_kind"], "ATTEMPTS_EXHAUSTED")

    def test_heartbeat_extends_lease_and_finish_is_idempotency_fenced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _store, queue = setup(Path(directory))
            queue.register_agent("coder-a", "coder", "xiaosuan-8", "pid:1", now=0)
            queue.enqueue("RFC-20261008-056", "coding", "coding:056:1", available_at=0)
            lease = queue.claim("coder-a", now=0, lease_seconds=10)
            renewed = queue.heartbeat(lease, now=5, lease_seconds=10)
            self.assertEqual(renewed.expires_at, 15)
            queue.start(renewed, now=6)
            queue.finish(renewed, "passed", {"candidate": "abc"}, now=7)
            with self.assertRaises(LeaseError):
                queue.finish(renewed, "passed", {}, now=8)
            self.assertEqual(queue.jobs()[0]["result"], {"candidate": "abc"})

    def test_idempotency_key_cannot_change_job_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _store, queue = setup(Path(directory))
            first = queue.enqueue("RFC-20261008-056", "coding", "same")
            second = queue.enqueue("RFC-20261008-056", "coding", "same")
            self.assertEqual(first, second)
            with self.assertRaisesRegex(Exception, "idempotency key reused"):
                queue.enqueue(
                    "RFC-20261008-056", "coding", "same", candidate_digest="changed"
                )

    def test_shared_lock_key_prevents_uncoordinated_parallel_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store, queue = setup(root)
            with store.connect() as connection:
                first = json.loads(
                    connection.execute(
                        "SELECT payload_json FROM rfc_revisions WHERE rfc_id = ?",
                        ("RFC-20261008-056",),
                    ).fetchone()["payload_json"]
                )
            second = with_revision_digest(
                {
                    **{key: value for key, value in first.items() if key != "revision_digest"},
                    "id": "RFC-20261008-057",
                    "title": "Second",
                    "python_sources": ["hermes/second.py"],
                    "target_files": ["src/second.ts"],
                    "source_targets": {"hermes/second.py": "src/second.ts"},
                }
            )
            dag = root / "dag-two.json"
            dag.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "baseline": {
                            "commit": "a" * 40,
                            "classification_sha256": "sha256:" + "b" * 64,
                            "in_scope_count": 806,
                        },
                        "rfcs": [first, second],
                    }
                )
            )
            store.import_registry(load_registry(dag))
            store.transition(second["id"], TaskState.DRAFT, TaskState.VALIDATED, "validator")
            store.transition(second["id"], TaskState.VALIDATED, TaskState.READY, "scheduler")
            queue.register_agent("coder-a", "coder", "xiaosuan-8", "pid:1", now=0)
            queue.register_agent("coder-b", "coder", "xiaosuan-8", "pid:2", now=0)
            queue.enqueue("RFC-20261008-056", "coding", "coding:one", available_at=0)
            queue.enqueue("RFC-20261008-057", "coding", "coding:two", available_at=0)
            first_lease = queue.claim("coder-a", now=0, lease_seconds=100)
            self.assertEqual(first_lease.rfc_id, "RFC-20261008-056")
            self.assertIsNone(queue.claim("coder-b", now=1, lease_seconds=100))
            queue.finish(first_lease, "passed", {}, now=2)
            second_lease = queue.claim("coder-b", now=3, lease_seconds=100)
            self.assertEqual(second_lease.rfc_id, "RFC-20261008-057")


if __name__ == "__main__":
    unittest.main()
