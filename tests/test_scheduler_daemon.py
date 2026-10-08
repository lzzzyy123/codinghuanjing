from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scheduler.daemon import DaemonConfig, SchedulerDaemon
from scheduler.state_store import StateStore


class DaemonTests(unittest.TestCase):
    def test_shadow_reconcile_validates_without_claiming_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classification = root / "classification.json"
            content = json.dumps(
                [{"path": "a.py", "disposition": "in_scope", "capability": "test"}]
            ).encode()
            classification.write_bytes(content)
            rfc = {
                "id": "RFC-20261008-056",
                "title": "Shadow",
                "capability_group": "test",
                "revision": 1,
                "python_sources": ["a.py"],
                "target_files": ["a.ts"],
                "depends_on": [],
                "contracts": {"provides": {}, "requires": {}},
                "tests": {"level1": ["true"], "level2": ["true"]},
                "integration_batch": "test",
                "acceptance_criteria": ["Valid."],
            }
            from scheduler.registry import with_revision_digest

            dag = root / "dag.json"
            dag.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "baseline": {
                            "commit": "a" * 40,
                            "classification_sha256": "sha256:"
                            + hashlib.sha256(content).hexdigest(),
                            "in_scope_count": 1,
                        },
                        "rfcs": [with_revision_digest(rfc)],
                    }
                )
            )
            database = root / "state.sqlite3"
            daemon = SchedulerDaemon(
                DaemonConfig(dag, classification, database, root / "evidence")
            )
            result = daemon.reconcile()
            self.assertEqual(result["ready"], ["RFC-20261008-056"])
            with StateStore(database).connect() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)

    def test_non_shadow_mode_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "production cutover"):
            DaemonConfig(Path("a"), Path("b"), Path("c"), Path("d"), mode="active").validate()


if __name__ == "__main__":
    unittest.main()
