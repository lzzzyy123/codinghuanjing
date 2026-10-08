from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scheduler.evidence import ArtifactStore
from scheduler.registry import load_registry, with_revision_digest
from scheduler.state_store import StateStore
from scheduler.testing import TestEvidenceStore


def store(root: Path) -> tuple[StateStore, dict]:
    rfc = with_revision_digest(
        {
            "id": "RFC-20261008-056",
            "title": "Test",
            "capability_group": "test",
            "revision": 1,
            "python_sources": ["a.py"],
            "target_files": ["a.ts"],
            "source_targets": {"a.py": "a.ts"},
            "lock_keys": ["fixture"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}, "definitions": {}},
            "tests": {"level1": ["bun test a"], "level2": ["bun test"]},
            "integration_batch": "core",
            "acceptance_criteria": ["Equivalent."],
        }
    )
    dag = root / "dag.json"
    dag.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "commit": "a" * 40,
                    "classification_sha256": "sha256:" + "b" * 64,
                    "in_scope_count": 806,
                    "config_data_count": 0,
                },
                "rfcs": [rfc],
            }
        )
    )
    state = StateStore(root / "state.sqlite3")
    state.import_registry(load_registry(dag))
    return state, rfc


class TestingEvidenceTests(unittest.TestCase):
    def test_reuse_requires_exact_candidate_command_environment_and_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, rfc = store(root)
            artifacts = ArtifactStore(state, root / "artifacts")
            evidence = artifacts.put_text(
                "test-log", "Authorization: Bearer secret-value\nPASS"
            )
            self.assertNotIn("secret-value", artifacts.read_text(evidence))
            tests = TestEvidenceStore(state)
            identity = tests.identity(
                rfc["id"],
                rfc["revision_digest"],
                "sha256:" + "c" * 64,
                2,
                ["bun test"],
                {"BUN_VERSION": "1.3.10"},
                "a" * 40,
            )
            tests.record(identity, "PASS", evidence)
            self.assertEqual(tests.reusable_pass(identity), evidence)
            changed = tests.identity(
                rfc["id"],
                rfc["revision_digest"],
                "sha256:" + "c" * 64,
                2,
                ["bun test --rerun"],
                {"BUN_VERSION": "1.3.10"},
                "a" * 40,
            )
            self.assertIsNone(tests.reusable_pass(changed))

    def test_level_two_requires_python_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, rfc = store(Path(directory))
            tests = TestEvidenceStore(state)
            with self.assertRaisesRegex(ValueError, "requires a full Python baseline"):
                tests.identity(
                    rfc["id"],
                    rfc["revision_digest"],
                    "sha256:" + "c" * 64,
                    2,
                    ["bun test"],
                    {},
                )


if __name__ == "__main__":
    unittest.main()
