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


def git(cwd: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def init_main(repo: Path) -> None:
    git(repo, "init")
    git(repo, "checkout", "-b", "main")


def write_fixture(
    root: Path, *, count: int = 1, config_count: int = 0
) -> tuple[Path, Path]:
    classification = root / "classification.json"
    entries = [
        {"path": f"source-{index}.py", "disposition": "in_scope", "capability": "test"}
        for index in range(count)
    ]
    config_entries = [
        {
            "path": f"config-{index}.json",
            "disposition": "config_data",
            "capability": "test",
        }
        for index in range(config_count)
    ]
    entries.extend(config_entries)
    content = json.dumps(entries, separators=(",", ":")).encode()
    classification.write_bytes(content)
    rfc = with_revision_digest(
        {
            "id": "RFC-20261008-056",
            "title": "Fixture",
            "capability_group": "test",
            "revision": 1,
            "python_sources": [entry["path"] for entry in entries if entry["disposition"] == "in_scope"],
            "config_sources": [entry["path"] for entry in config_entries],
            "target_files": [
                "src/fixture.ts",
                "config/fixture.json",
                "coordination/requests/RFC-20261008-056/dependencies.json",
            ],
            "shared_change_requests": {
                "dependency-manifest": "coordination/requests/RFC-20261008-056/dependencies.json"
            },
            "source_targets": {
                entry["path"]: "src/fixture.ts"
                for entry in entries
                if entry["disposition"] == "in_scope"
            },
            "config_targets": {
                entry["path"]: "config/fixture.json" for entry in config_entries
            },
            "lock_keys": ["fixture"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}, "definitions": {}},
            "tests": {"level1": ["true"], "level2": ["true"], "level3": ["true"]},
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
                    "config_data_count": config_count,
                },
                "shared_resources": {
                    "dependency-manifest": {
                        "files": ["package.json", "bun.lock"],
                        "writer": "integration-git-broker",
                        "request_template": "coordination/requests/{rfc_id}/dependencies.json",
                        "request_owner": "coder",
                        "application_stage": "before-level1",
                    }
                },
                "frozen_control_paths": ["tsconfig.json"],
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
            dag, classification = write_fixture(
                Path(directory), count=806, config_count=188
            )
            code, stdout, stderr = self.invoke(
                ["validate", str(dag), str(classification)]
            )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(json.loads(stdout)["valid"])

    def test_production_mode_rejects_missing_config_data_partition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            dag, classification = write_fixture(Path(directory), count=806)
            code, _stdout, stderr = self.invoke(
                ["validate", str(dag), str(classification)]
            )
        self.assertEqual(code, 2)
        self.assertIn("production 188-path config-data partition", stderr)

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

    def test_record_base_delivery_fetches_and_persists_trusted_main(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = root / "remote.git"
            repository = root / "repo"
            git(root, "init", "--bare", str(remote))
            repository.mkdir()
            init_main(repository)
            git(repository, "remote", "add", "origin", str(remote))
            (repository / "base").write_text("base")
            git(repository, "add", "base")
            git(
                repository,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=t@invalid",
                "commit",
                "-m",
                "base",
            )
            base_commit = git(repository, "rev-parse", "HEAD")
            (repository / "merged").write_text("merged")
            git(repository, "add", "merged")
            git(
                repository,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=t@invalid",
                "commit",
                "-m",
                "merged",
            )
            merged_commit = git(repository, "rev-parse", "HEAD")
            git(repository, "push", "origin", "main")

            dag, classification = write_fixture(root)
            document = json.loads(dag.read_text())
            document["base_delivery"] = {
                "rfc": "RFC-20261008-055",
                "commit": base_commit,
                "required_merge_state": "merged",
            }
            dag.write_text(json.dumps(document))
            database = root / "state.sqlite3"
            code, stdout, stderr = self.invoke(
                ["init", str(dag), str(database), str(classification), "--test-mode"]
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(json.loads(stdout)["ready"], [])
            code, stdout, stderr = self.invoke(
                [
                    "record-base-delivery",
                    str(dag),
                    str(database),
                    str(classification),
                    str(repository),
                    merged_commit,
                    "--recorded-by",
                    "project-lead",
                    "--test-mode",
                ]
            )
            self.assertEqual(code, 0, stderr)
            result = json.loads(stdout)
            self.assertEqual(result["trusted_main_commit"], merged_commit)
            self.assertEqual(result["ready"], ["RFC-20261008-056"])
            with StateStore(database).connect() as connection:
                record = connection.execute(
                    "SELECT * FROM base_delivery_records"
                ).fetchone()
            self.assertEqual(record["trusted_main_commit"], merged_commit)

    def test_status_includes_evidence_counts_and_elapsed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dag, classification = write_fixture(root)
            database = root / "state.sqlite3"
            code, _stdout, stderr = self.invoke(
                ["init", str(dag), str(database), str(classification), "--test-mode"]
            )
            self.assertEqual(code, 0, stderr)
            code, stdout, stderr = self.invoke(
                ["status", str(dag), str(database), "--json"]
            )
            self.assertEqual(code, 0, stderr)
            snapshot = json.loads(stdout)
            self.assertEqual(
                snapshot["evidence_counts"],
                {
                    "candidates": 0,
                    "test_runs": 0,
                    "review_runs": 0,
                    "publications": 0,
                    "merges": 0,
                },
            )
            self.assertEqual(snapshot["publication_pending"], [])
            self.assertEqual(snapshot["publication_blockers"], [])
            self.assertIn("elapsed_seconds", snapshot["tasks"][0])
            self.assertIn("evidence", snapshot["tasks"][0])

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
