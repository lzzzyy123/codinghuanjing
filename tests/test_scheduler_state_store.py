from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scheduler.models import TaskState
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
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}},
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
        },
        "rfcs": [rfc],
    }
    path = root / f"dag-{revision}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


class StateStoreTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
