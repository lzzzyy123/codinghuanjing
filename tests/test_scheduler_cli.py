from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scheduler.cli import main
from scheduler.registry import with_revision_digest
from scheduler.state_store import StateStore


def write_fixture(root: Path, *, count: int = 1) -> tuple[Path, Path]:
    classification = root / "classification.json"
    entries = [
        {"path": f"source-{index}.py", "disposition": "in_scope", "capability": "test"}
        for index in range(count)
    ]
    content = json.dumps(entries, separators=(",", ":")).encode()
    classification.write_bytes(content)
    rfc = with_revision_digest(
        {
            "id": "RFC-20261008-056",
            "title": "Fixture",
            "capability_group": "test",
            "revision": 1,
            "python_sources": [entry["path"] for entry in entries],
            "target_files": ["src/fixture.ts"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}},
            "tests": {"level1": ["true"], "level2": ["true"]},
            "integration_batch": "test",
            "acceptance_criteria": ["Valid fixture."],
        }
    )
    dag = root / "dag.json"
    dag.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "commit": "a" * 40,
                    "classification_sha256": "sha256:"
                    + hashlib.sha256(content).hexdigest(),
                    "in_scope_count": count,
                },
                "rfcs": [rfc],
            }
        ),
        encoding="utf-8",
    )
    return dag, classification


class SchedulerCliTests(unittest.TestCase):
    def invoke(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                main(arguments)
        except SystemExit as exc:
            return int(exc.code), stdout.getvalue(), stderr.getvalue()
        return 0, stdout.getvalue(), stderr.getvalue()

    def test_validate_requires_classification_in_production_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, _classification = write_fixture(Path(directory))
            code, _stdout, stderr = self.invoke(["validate", str(dag)])
        self.assertEqual(code, 2)
        self.assertIn("requires CLASSIFICATION in production mode", stderr)

    def test_init_requires_classification_before_creating_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dag, _classification = write_fixture(root)
            database = root / "state.sqlite3"
            code, _stdout, stderr = self.invoke(["init", str(dag), str(database)])
            self.assertFalse(database.exists())
        self.assertEqual(code, 2)
        self.assertIn("requires CLASSIFICATION in production mode", stderr)

    def test_production_mode_rejects_a_valid_non_806_partition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, classification = write_fixture(Path(directory))
            code, _stdout, stderr = self.invoke(
                ["validate", str(dag), str(classification)]
            )
        self.assertEqual(code, 2)
        self.assertIn("requires the production 806-path partition", stderr)

    def test_production_mode_accepts_an_exact_806_partition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, classification = write_fixture(Path(directory), count=806)
            code, stdout, stderr = self.invoke(
                ["validate", str(dag), str(classification)]
            )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(json.loads(stdout)["valid"])

    def test_test_mode_explicitly_allows_a_synthetic_partition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, classification = write_fixture(Path(directory))
            code, stdout, stderr = self.invoke(
                ["validate", str(dag), str(classification), "--test-mode"]
            )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(json.loads(stdout)["valid"])

    def test_test_mode_explicitly_allows_missing_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, _classification = write_fixture(Path(directory))
            code, stdout, stderr = self.invoke(["validate", str(dag), "--test-mode"])
        self.assertEqual(code, 0, stderr)
        self.assertTrue(json.loads(stdout)["valid"])

    def test_init_checks_exact_partition_before_writing_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dag, classification = write_fixture(root)
            classification.write_text("[]", encoding="utf-8")
            database = root / "state.sqlite3"
            code, _stdout, stderr = self.invoke(
                ["init", str(dag), str(database), str(classification)]
            )
            self.assertFalse(database.exists())
        self.assertEqual(code, 2)
        self.assertIn("classification digest mismatch", stderr)

    def test_test_mode_init_materializes_fixture_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dag, classification = write_fixture(root)
            database = root / "state.sqlite3"
            code, stdout, stderr = self.invoke(
                ["init", str(dag), str(database), str(classification), "--test-mode"]
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["ready"], ["RFC-20261008-056"])
            with StateStore(database).connect() as connection:
                count = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            self.assertEqual(count, 1)

    def test_workerctl_refuses_validate_without_classification(self) -> None:
        result = subprocess.run(
            ["sh", "bin/coding-workerctl", "scheduler-validate", "dag.json"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires DAG and CLASSIFICATION", result.stderr)

    def test_workerctl_refuses_init_without_classification(self) -> None:
        result = subprocess.run(
            [
                "sh",
                "bin/coding-workerctl",
                "scheduler-init",
                "dag.json",
                "state.sqlite3",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires DAG, DATABASE, and CLASSIFICATION", result.stderr)


if __name__ == "__main__":
    unittest.main()
