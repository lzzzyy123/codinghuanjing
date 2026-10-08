from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scheduler.models import TaskState
from scheduler.leases import QueueStore
from scheduler.registry import load_registry, with_revision_digest
from scheduler.state_store import StateConflict, StateStore


def registry_file(root: Path, revision: int = 1, title: str = "Task") -> Path:
    rfc = with_revision_digest(
        {
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
    )
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
            queue.enqueue("RFC-20261008-056", "coding", "old-revision", available_at=0)

            revised = load_registry(registry_file(root, 2, "Revised"))
            store.import_registry(revised)

            task = store.task("RFC-20261008-056")
            self.assertEqual(task["revision_digest"], revised.rfcs[task["rfc_id"]].revision_digest)
            self.assertEqual(task["state"], "Draft")
            job = queue.jobs()[0]
            self.assertEqual(job["state"], "cancelled")
            self.assertEqual(job["result"]["failure_kind"], "REVISION_SUPERSEDED")


if __name__ == "__main__":
    unittest.main()
