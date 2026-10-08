from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scheduler.models import TaskState
from scheduler.registry import content_digest, load_registry, with_revision_digest
from scheduler.scheduler import DagScheduler
from scheduler.state_store import StateConflict, StateStore


CONTRACT_DEFINITION = {"schema": "agent-core-v1"}
CONTRACT = content_digest(CONTRACT_DEFINITION)


class FakeGitVerifier:
    def __init__(self, main_commits: set[str], ancestors: set[tuple[str, str]] = set()):
        self.main_commits = main_commits
        self.ancestors = ancestors

    def require_on_trusted_main(self, commit: str) -> str:
        if commit not in self.main_commits:
            raise StateConflict("commit is not on trusted main")
        return "f" * 40

    def require_ancestor(self, ancestor: str, descendant: str) -> None:
        if (ancestor, descendant) not in self.ancestors:
            raise StateConflict("required commit is not an ancestor")


def item(rfc_id: str, number: int, **changes: object) -> dict:
    value = {
        "id": rfc_id,
        "title": rfc_id,
        "capability_group": "agent",
        "revision": 1,
        "python_sources": [f"hermes/{number}.py"],
        "target_files": [f"src/{number}.ts"],
        "source_targets": {f"hermes/{number}.py": f"src/{number}.ts"},
        "lock_keys": [f"fixture:{number}"],
        "depends_on": [],
        "contracts": {"provides": {}, "requires": {}, "definitions": {}},
        "tests": {"level1": ["bun run typecheck"], "level2": ["bun test"]},
        "integration_batch": "agent",
        "acceptance_criteria": ["Equivalent."],
    }
    value.update(changes)
    return with_revision_digest(value)


class ReadinessTests(unittest.TestCase):
    def test_legacy_base_delivery_without_trusted_main_proof_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE base_delivery_records (required_rfc_id TEXT PRIMARY KEY, "
                "required_commit TEXT NOT NULL, merged_base_commit TEXT NOT NULL, "
                "ancestor_verified INTEGER NOT NULL, recorded_by TEXT NOT NULL, "
                "recorded_at TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO base_delivery_records VALUES (?, ?, ?, 1, 'legacy', 'fixture')",
                ("RFC-20261008-055", "c" * 40, "d" * 40),
            )
            connection.commit()
            connection.close()
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
                            "config_data_count": 0,
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
            store = StateStore(database)
            store.import_registry(registry)
            scheduler = DagScheduler(registry, store)
            scheduler.validate_tasks()
            result = scheduler.refresh_ready()
            self.assertEqual(result["ready"], [])
            self.assertRegex(result["blocked"][0], "not merged")
            scheduler = DagScheduler(
                registry,
                store,
                FakeGitVerifier({"d" * 40}, {("c" * 40, "d" * 40)}),
            )
            scheduler.record_base_delivery("d" * 40, "lead")
            self.assertEqual(scheduler.refresh_ready()["ready"], [first["id"]])
            with store.connect() as connection:
                upgraded = connection.execute(
                    "SELECT trusted_main_commit FROM base_delivery_records"
                ).fetchone()
            self.assertEqual(upgraded["trusted_main_commit"], "f" * 40)

    def test_dependency_requires_explicit_matching_merge_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = item(
                "RFC-20261008-056",
                1,
                contracts={
                    "provides": {"agent.core": CONTRACT},
                    "requires": {},
                    "definitions": {"agent.core": CONTRACT_DEFINITION},
                },
            )
            second = item(
                "RFC-20261008-057",
                2,
                depends_on=[first["id"]],
                contracts={
                    "provides": {},
                    "requires": {"agent.core": CONTRACT},
                    "definitions": {},
                },
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
                            "config_data_count": 0,
                        },
                        "rfcs": [first, second],
                    }
                )
            )
            registry = load_registry(path)
            store = StateStore(root / "state.sqlite3")
            store.import_registry(registry)
            candidate_digest = "sha256:" + "c" * 64
            candidate_commit = "c" * 40
            scheduler = DagScheduler(
                registry,
                store,
                FakeGitVerifier(
                    {"d" * 40}, {(candidate_commit, "d" * 40)}
                ),
            )
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
            with store.transaction() as connection:
                connection.execute(
                    "INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    ("coder", "coder", "xiaosuan-8", "uid:1001", "idle", 1, 0, "{}"),
                )
                connection.execute(
                    "INSERT INTO candidate_records "
                    "(rfc_id, revision_digest, candidate_digest, base_commit, branch, "
                    "commit_sha, tree_sha, diff_digest, author_agent_id, "
                    "author_process_identity, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        first["id"], first["revision_digest"], candidate_digest,
                        "a" * 40, f"agent/{first['id']}", candidate_commit, "b" * 40,
                        "sha256:" + "d" * 64, "coder", "uid:1001", "fixture",
                    ),
                )
                connection.execute(
                    "INSERT INTO jobs "
                    "(idempotency_key, rfc_id, revision_digest, kind, role, state, "
                    "priority, base_commit, candidate_digest, max_attempts, available_at, "
                    "created_at, updated_at) VALUES (?, ?, ?, 'integration', 'integrator', "
                    "'passed', 0, ?, ?, 1, 0, 'fixture', 'fixture')",
                    (
                        "integration:fixture", first["id"], first["revision_digest"],
                        "a" * 40, candidate_digest,
                    ),
                )
                for index, kind in enumerate(("review", "test"), start=1):
                    connection.execute(
                        "INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            "sha256:" + str(index) * 64,
                            kind,
                            f"{kind}.txt",
                            1,
                            1,
                            "fixture",
                        ),
                    )
                connection.execute(
                    "INSERT INTO review_runs "
                    "(rfc_id, revision_digest, candidate_digest, reviewer_agent_id, "
                    "verdict, infrastructure_status, schema_valid, independent, "
                    "evidence_digest, created_at) VALUES (?, ?, ?, ?, 'PASS', 'PASS', "
                    "1, 1, ?, 'fixture')",
                    (
                        first["id"], first["revision_digest"], candidate_digest,
                        "coder", "sha256:" + "1" * 64,
                    ),
                )
                connection.execute(
                    "INSERT INTO test_runs "
                    "(rfc_id, revision_digest, candidate_digest, level, command_digest, "
                    "environment_digest, baseline_commit, status, evidence_digest, "
                    "started_at, completed_at) VALUES (?, ?, ?, 3, ?, ?, ?, 'PASS', ?, "
                    "'fixture', 'fixture')",
                    (
                        first["id"], first["revision_digest"], candidate_digest,
                        "sha256:" + "3" * 64, "sha256:" + "4" * 64,
                        "a" * 40, "sha256:" + "2" * 64,
                    ),
                )
            with self.assertRaisesRegex(StateConflict, "contract evidence"):
                scheduler.record_merge(
                    first["id"], candidate_digest, "d" * 40, {}, "lead"
                )
            scheduler.record_merge(
                first["id"],
                candidate_digest,
                "d" * 40,
                {"agent.core": CONTRACT},
                "lead",
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
                            "config_data_count": 0,
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
            with self.assertRaisesRegex(StateConflict, "bound Git verifier"):
                scheduler.record_base_delivery("d" * 40, "lead")
            scheduler = DagScheduler(
                registry,
                store,
                FakeGitVerifier({"d" * 40}, {("c" * 40, "d" * 40)}),
            )
            scheduler.record_base_delivery("d" * 40, "lead")
            self.assertEqual(scheduler.refresh_ready()["ready"], [first["id"]])


if __name__ == "__main__":
    unittest.main()
