from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scheduler.registry import (
    RegistryError,
    content_digest,
    load_registry,
    with_revision_digest,
)


CONTRACT_DEFINITION = {"schema": "request"}
CONTRACT = content_digest(CONTRACT_DEFINITION)


def rfc(rfc_id: str, source: str, target: str, **changes: object) -> dict:
    value = {
        "id": rfc_id,
        "title": rfc_id,
        "capability_group": "test",
        "revision": 1,
        "python_sources": [source],
        "target_files": [target],
        "source_targets": {source: target},
        "lock_keys": [f"rfc:{rfc_id}"],
        "depends_on": [],
        "contracts": {"provides": {}, "requires": {}, "definitions": {}},
        "tests": {"level1": ["bun run typecheck"], "level2": ["bun test"]},
        "integration_batch": "batch-1",
        "acceptance_criteria": ["Mapped behavior is equivalent."],
    }
    value.update(changes)
    return with_revision_digest(value)


def document(rfcs: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "baseline": {
            "commit": "a" * 40,
            "classification_sha256": "sha256:" + "b" * 64,
            "in_scope_count": 806,
        },
        "rfcs": rfcs,
    }


def load(value: dict):
    temporary = tempfile.TemporaryDirectory()
    try:
        path = Path(temporary.name) / "dag.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return load_registry(path)
    finally:
        temporary.cleanup()


class RegistryTests(unittest.TestCase):
    def test_loads_content_addressed_dag_and_contract(self) -> None:
        first = rfc(
            "RFC-20261008-056",
            "hermes/agent/a.py",
            "src/agent/a.ts",
            contracts={
                "provides": {"agent.request": CONTRACT},
                "requires": {},
                "definitions": {"agent.request": CONTRACT_DEFINITION},
            },
        )
        second = rfc(
            "RFC-20261008-057",
            "hermes/agent/b.py",
            "src/agent/b.ts",
            depends_on=[first["id"]],
            contracts={
                "provides": {},
                "requires": {"agent.request": CONTRACT},
                "definitions": {},
            },
        )
        registry = load(document([second, first]))
        self.assertEqual(registry.topological_order, (first["id"], second["id"]))
        self.assertEqual(registry.ancestors(second["id"]), {first["id"]})

    def test_rejects_digest_mutation(self) -> None:
        value = rfc("RFC-20261008-056", "a.py", "a.ts")
        value["title"] = "mutated"
        with self.assertRaisesRegex(RegistryError, "revision_digest mismatch"):
            load(document([value]))

    def test_rejects_cycles(self) -> None:
        first = rfc(
            "RFC-20261008-056", "a.py", "a.ts", depends_on=["RFC-20261008-057"]
        )
        second = rfc(
            "RFC-20261008-057", "b.py", "b.ts", depends_on=["RFC-20261008-056"]
        )
        with self.assertRaisesRegex(RegistryError, "dependency cycle"):
            load(document([first, second]))

    def test_rejects_source_and_target_ownership_collisions(self) -> None:
        first = rfc("RFC-20261008-056", "same.py", "a.ts")
        second = rfc("RFC-20261008-057", "same.py", "b.ts")
        with self.assertRaisesRegex(RegistryError, "ownership collision"):
            load(document([first, second]))

    def test_rejects_contract_hash_mismatch(self) -> None:
        first = rfc(
            "RFC-20261008-056",
            "a.py",
            "a.ts",
            contracts={
                "provides": {"contract": CONTRACT},
                "requires": {},
                "definitions": {"contract": CONTRACT_DEFINITION},
            },
        )
        second = rfc(
            "RFC-20261008-057",
            "b.py",
            "b.ts",
            depends_on=[first["id"]],
            contracts={
                "provides": {},
                "requires": {"contract": "sha256:" + "2" * 64},
                "definitions": {},
            },
        )
        with self.assertRaisesRegex(RegistryError, "provider has"):
            load(document([first, second]))

    def test_exact_classification_partition_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classification = root / "classification.json"
            content = json.dumps(
                [
                    {
                        "path": "a.py",
                        "disposition": "in_scope",
                        "capability": "test",
                    }
                ]
            ).encode()
            classification.write_bytes(content)
            value = document([rfc("RFC-20261008-056", "a.py", "a.ts")])
            value["baseline"]["in_scope_count"] = 1
            value["baseline"]["classification_sha256"] = (
                "sha256:" + hashlib.sha256(content).hexdigest()
            )
            path = root / "dag.json"
            path.write_text(json.dumps(value))
            registry = load_registry(path, classification)
            self.assertEqual(registry.in_scope_count, 1)
            value["rfcs"][0]["python_sources"] = ["missing.py"]
            value["rfcs"][0]["source_targets"] = {"missing.py": "a.ts"}
            value["rfcs"][0] = with_revision_digest(value["rfcs"][0])
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(RegistryError, "source partition mismatch"):
                load_registry(path, classification)

    def test_rejects_incomplete_source_to_target_mapping(self) -> None:
        value = rfc("RFC-20261008-056", "a.py", "a.ts")
        value["source_targets"] = {}
        value = with_revision_digest(value)
        with self.assertRaisesRegex(RegistryError, "map every owned source"):
            load(document([value]))

    def test_rejects_contract_definition_that_does_not_match_hash(self) -> None:
        value = rfc(
            "RFC-20261008-056",
            "a.py",
            "a.ts",
            contracts={
                "provides": {"contract": CONTRACT},
                "requires": {},
                "definitions": {"contract": {"schema": "changed"}},
            },
        )
        with self.assertRaisesRegex(RegistryError, "does not match its hash"):
            load(document([value]))


if __name__ == "__main__":
    unittest.main()
