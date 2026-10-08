from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scheduler.models import TaskState
from scheduler.registry import load_registry, with_revision_digest
from scheduler.scheduler import DagScheduler
from scheduler.state_store import StateConflict, StateStore


CONTRACT = "sha256:" + "c" * 64


def item(rfc_id: str, number: int, **changes: object) -> dict:
    value = {
        "id": rfc_id,
        "title": rfc_id,
        "capability_group": "agent",
        "revision": 1,
        "python_sources": [f"hermes/{number}.py"],
        "target_files": [f"src/{number}.ts"],
        "depends_on": [],
        "contracts": {"provides": {}, "requires": {}},
        "tests": {"level1": ["bun run typecheck"], "level2": ["bun test"]},
        "integration_batch": "agent",
        "acceptance_criteria": ["Equivalent."],
    }
    value.update(changes)
    return with_revision_digest(value)


class ReadinessTests(unittest.TestCase):
    def test_dependency_requires_explicit_matching_merge_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = item(
                "RFC-20261008-056",
                1,
                contracts={"provides": {"agent.core": CONTRACT}, "requires": {}},
            )
            second = item(
                "RFC-20261008-057",
                2,
                depends_on=[first["id"]],
                contracts={"provides": {}, "requires": {"agent.core": CONTRACT}},
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
                        "rfcs": [first, second],
                    }
                )
            )
            registry = load_registry(path)
            store = StateStore(root / "state.sqlite3")
            store.import_registry(registry)
            scheduler = DagScheduler(registry, store)
            scheduler.validate_tasks()
            result = scheduler.refresh_ready()
            self.assertEqual(result["ready"], [first["id"]])
            self.assertRegex(result["blocked"][0], "not merged")
            for expected, target in (
                (TaskState.READY, TaskState.LEASED),
                (TaskState.LEASED, TaskState.CODING),
                (TaskState.CODING, TaskState.TESTING),
                (TaskState.TESTING, TaskState.REVIEWING),
                (TaskState.REVIEWING, TaskState.LEAD_REVIEW),
                (TaskState.LEAD_REVIEW, TaskState.INTEGRATION_READY),
                (TaskState.INTEGRATION_READY, TaskState.INTEGRATING),
                (TaskState.INTEGRATING, TaskState.DONE),
            ):
                store.transition(first["id"], expected, target, "test")
            with self.assertRaisesRegex(StateConflict, "contract evidence"):
                scheduler.record_merge(first["id"], "d" * 40, {}, "lead")
            scheduler.record_merge(
                first["id"], "d" * 40, {"agent.core": CONTRACT}, "lead"
            )
            result = scheduler.refresh_ready()
            self.assertEqual(result["ready"], [second["id"]])

    def test_external_base_delivery_blocks_roots_until_ancestry_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = item("RFC-20261008-056", 1)
            path = root / "dag.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "baseline": {
                            "commit": "a" * 40,
                            "classification_sha256": "sha256:" + "b" * 64,
                            "in_scope_count": 1,
                        },
                        "base_delivery": {
                            "rfc": "RFC-20261008-055",
                            "commit": "c" * 40,
                            "required_merge_state": "merged",
                        },
                        "rfcs": [first],
                    }
                )
            )
            registry = load_registry(path)
            store = StateStore(root / "state.sqlite3")
            store.import_registry(registry)
            scheduler = DagScheduler(registry, store)
            scheduler.validate_tasks()
            result = scheduler.refresh_ready()
            self.assertEqual(result["ready"], [])
            self.assertRegex(result["blocked"][0], "not merged")
            with self.assertRaisesRegex(StateConflict, "verified Git ancestry"):
                scheduler.record_base_delivery("d" * 40, "lead", ancestor_verified=False)
            scheduler.record_base_delivery("d" * 40, "lead", ancestor_verified=True)
            self.assertEqual(scheduler.refresh_ready()["ready"], [first["id"]])


if __name__ == "__main__":
    unittest.main()
