from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scheduler.models import TaskState
from scheduler.leases import QueueStore
from scheduler.registry import load_registry, with_revision_digest
from scheduler.state_store import StateConflict, StateStore


def registry_file(root: Path, revision: int = 1, title: str = "Task") -> Path:
    value = {
            "id": "RFC-20261008-056",
            "title": title,
            "capability_group": "agent",
            "revision": revision,
            "python_sources": ["hermes/a.py"],
            "target_files": ["src/a.ts"],
            "source_targets": {"hermes/a.py": "src/a.ts"},
            "lock_keys": ["fixture"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}, "definitions": {}},
            "tests": {"level1": ["bun run typecheck"], "level2": ["bun test"]},
            "integration_batch": "core",
            "acceptance_criteria": ["Equivalent."],
        }
    if revision > 1:
        predecessor = with_revision_digest({**value, "revision": revision - 1, "title": "Task"})
        value["supersedes"] = {
            "revision": revision - 1,
            "revision_digest": predecessor["revision_digest"],
        }
    rfc = with_revision_digest(value)
    document = {
        "schema_version": 1,
        "baseline": {
            "commit": "a" * 40,
            "classification_sha256": "sha256:" + "b" * 64,
            "in_scope_count": 806,
            "config_data_count": 0,
        },
        "rfcs": [rfc],
    }
    path = root / f"dag-{revision}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class StateStoreTests(unittest.TestCase):
    def test_connection_context_releases_database_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "scheduler.sqlite3")
            connection = store.connect()
            with connection:
                connection.execute("SELECT 1").fetchone()
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def test_import_transition_and_evidence_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3", root / "evidence")
            store.import_registry(load_registry(registry_file(root)))
            event = store.transition(
                "RFC-20261008-056",
                TaskState.DRAFT,
                TaskState.VALIDATED,
                "registry-validator",
                metadata={"check": "ok"},
            )
            self.assertEqual(event["sequence"], 1)
            self.assertEqual(store.task("RFC-20261008-056")["state"], "Validated")
            self.assertEqual(store.transitions("RFC-20261008-056")[0]["metadata"], {"check": "ok"})
            evidence = root / "evidence" / "RFC-20261008-056" / "scheduler-events.jsonl"
            self.assertEqual(json.loads(evidence.read_text())["to_state"], "Validated")

    def test_compare_and_swap_rejects_stale_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3")
            store.import_registry(load_registry(registry_file(root)))
            store.transition(
                "RFC-20261008-056", TaskState.DRAFT, TaskState.VALIDATED, "validator"
            )
            with self.assertRaisesRegex(StateConflict, "expected Draft"):
                store.transition(
                    "RFC-20261008-056", TaskState.DRAFT, TaskState.BLOCKED, "stale"
                )

    def test_active_task_cannot_change_pinned_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3")
            store.import_registry(load_registry(registry_file(root)))
            store.transition(
                "RFC-20261008-056", TaskState.DRAFT, TaskState.VALIDATED, "validator"
            )
            store.transition(
                "RFC-20261008-056", TaskState.VALIDATED, TaskState.READY, "scheduler"
            )
            store.transition(
                "RFC-20261008-056", TaskState.READY, TaskState.LEASED, "scheduler"
            )
            with self.assertRaisesRegex(StateConflict, "cannot replace pinned revision"):
                store.import_registry(load_registry(registry_file(root, 2, "Revised")))

    def test_same_revision_number_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3")
            store.import_registry(load_registry(registry_file(root, 1, "Original")))
            with self.assertRaisesRegex(StateConflict, "immutable revision conflict"):
                store.import_registry(load_registry(registry_file(root, 1, "Changed")))

    def test_revision_switch_cancels_old_nonterminal_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3")
            original = load_registry(registry_file(root))
            store.import_registry(original)
            queue = QueueStore(store)
            queue.enqueue("RFC-20261008-056", "coding", "old-revision", base_commit="a" * 40, available_at=0)

            revised = load_registry(registry_file(root, 2, "Revised"))
            store.import_registry(revised)

            task = store.task("RFC-20261008-056")
            self.assertEqual(task["revision_digest"], revised.rfcs[task["rfc_id"]].revision_digest)
            self.assertEqual(task["state"], "Draft")
            job = queue.jobs()[0]
            self.assertEqual(job["state"], "cancelled")
            self.assertEqual(job["result"]["failure_kind"], "REVISION_SUPERSEDED")

    def test_migration_cancels_queued_unpinned_job_and_frees_idempotency_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "scheduler.sqlite3"
            store = StateStore(database)
            store.import_registry(load_registry(registry_file(root)))
            with store.connect() as connection:
                connection.execute(
                    "INSERT INTO jobs "
                    "(idempotency_key, rfc_id, revision_digest, kind, role, state, "
                    "priority, base_commit, candidate_digest, max_attempts, available_at, "
                    "created_at, updated_at) SELECT 'legacy-coding', rfc_id, "
                    "revision_digest, 'coding', 'coder', 'queued', 0, NULL, NULL, 3, 0, "
                    "'fixture', 'fixture' FROM tasks"
                )

            migrated = StateStore(database)
            jobs = QueueStore(migrated).jobs()
            self.assertEqual(jobs[0]["state"], "cancelled")
            self.assertEqual(
                jobs[0]["result"]["failure_kind"], "BASE_COMMIT_MIGRATION_REQUIRED"
            )
            replacement = QueueStore(migrated).enqueue(
                "RFC-20261008-056",
                "coding",
                "legacy-coding",
                base_commit="a" * 40,
            )
            self.assertNotEqual(replacement, jobs[0]["job_id"])

    def test_migration_retains_active_unpinned_lease_and_blocks_cutover(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "scheduler.sqlite3"
            store = StateStore(database)
            store.import_registry(load_registry(registry_file(root)))
            store.transition(
                "RFC-20261008-056", TaskState.DRAFT, TaskState.VALIDATED, "fixture"
            )
            store.transition(
                "RFC-20261008-056", TaskState.VALIDATED, TaskState.READY, "fixture"
            )
            QueueStore(store).register_agent(
                "legacy-coder", "coder", "xiaosuan-8", "pid:legacy", now=0
            )
            with store.connect() as connection:
                revision = connection.execute(
                    "SELECT revision_digest FROM tasks WHERE rfc_id = 'RFC-20261008-056'"
                ).fetchone()[0]
                cursor = connection.execute(
                    "INSERT INTO jobs "
                    "(idempotency_key, rfc_id, revision_digest, kind, role, state, "
                    "priority, base_commit, candidate_digest, max_attempts, available_at, "
                    "created_at, updated_at) VALUES ('legacy-active', ?, ?, 'coding', "
                    "'coder', 'running', 0, NULL, NULL, 3, 0, 'fixture', 'fixture')",
                    ("RFC-20261008-056", revision),
                )
                job_id = int(cursor.lastrowid)
                connection.execute(
                    "INSERT INTO leases VALUES "
                    "('legacy-lease', 'rfc', ?, ?, 'legacy-coder', 1, 0, 0, 999999)",
                    ("RFC-20261008-056", job_id),
                )
                connection.execute(
                    "INSERT INTO lease_locks VALUES ('fixture', 'legacy-lease', 1)"
                )
                connection.execute(
                    "UPDATE tasks SET state = ? WHERE rfc_id = 'RFC-20261008-056'",
                    (TaskState.CODING.value,),
                )

            migrated = StateStore(database)
            with migrated.connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM lease_locks").fetchone()[0], 1)
                blocker = connection.execute(
                    "SELECT kind, resolved_at FROM migration_blockers"
                ).fetchone()
                self.assertEqual(blocker["kind"], "UNPINNED_ACTIVE_JOB")
                self.assertIsNone(blocker["resolved_at"])
            self.assertEqual(migrated.task("RFC-20261008-056")["state"], "Blocked")

    def test_event_replace_failure_leaves_pending_outbox_and_retry_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3", root / "evidence")
            store.import_registry(load_registry(registry_file(root)))
            real_replace = __import__("os").replace
            failed = False

            def fail_first_replace(source: object, target: object) -> None:
                nonlocal failed
                if not failed and str(target).endswith("00000001.json"):
                    failed = True
                    raise OSError("injected event replace failure")
                real_replace(source, target)

            with mock.patch("scheduler.state_store.os.replace", side_effect=fail_first_replace):
                store.transition(
                    "RFC-20261008-056",
                    TaskState.DRAFT,
                    TaskState.VALIDATED,
                    "validator",
                )

            with store.connect() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM transition_outbox WHERE materialized = 0"
                    ).fetchone()[0],
                    1,
                )
            self.assertEqual(store.materialize_transition_evidence(), 1)
            projection = root / "evidence/RFC-20261008-056/scheduler-events.jsonl"
            self.assertTrue(projection.exists())
            self.assertEqual(list(projection.parent.rglob("*.tmp")), [])

    def test_projection_replace_failure_is_not_acknowledged_and_retry_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3", root / "evidence")
            store.import_registry(load_registry(registry_file(root)))
            real_replace = __import__("os").replace
            failed = False

            def fail_projection_replace(source: object, target: object) -> None:
                nonlocal failed
                if not failed and str(target).endswith("scheduler-events.jsonl"):
                    failed = True
                    raise OSError("injected projection replace failure")
                real_replace(source, target)

            with mock.patch(
                "scheduler.state_store.os.replace", side_effect=fail_projection_replace
            ):
                store.transition(
                    "RFC-20261008-056",
                    TaskState.DRAFT,
                    TaskState.VALIDATED,
                    "validator",
                )

            projection = root / "evidence/RFC-20261008-056/scheduler-events.jsonl"
            self.assertFalse(projection.exists())
            with store.connect() as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM transition_outbox WHERE materialized = 0"
                    ).fetchone()[0],
                    1,
                )
            self.assertEqual(store.materialize_transition_evidence(), 1)
            self.assertTrue(projection.exists())

    def test_materializer_repairs_missing_projection_without_pending_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = StateStore(root / "scheduler.sqlite3", root / "evidence")
            store.import_registry(load_registry(registry_file(root)))
            store.transition(
                "RFC-20261008-056",
                TaskState.DRAFT,
                TaskState.VALIDATED,
                "validator",
            )
            projection = root / "evidence/RFC-20261008-056/scheduler-events.jsonl"
            projection.unlink()

            self.assertEqual(store.materialize_transition_evidence(), 0)
            self.assertTrue(projection.exists())


if __name__ == "__main__":
    unittest.main()
