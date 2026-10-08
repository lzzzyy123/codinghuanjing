from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scheduler.evidence import ArtifactStore
from scheduler.leases import QueueStore
from scheduler.models import TaskState
from scheduler.pipeline import Pipeline, ReviewResult
from scheduler.registry import load_registry, with_revision_digest
from scheduler.state_store import StateStore
from scheduler.testing import TestEvidenceStore


CANDIDATE = "sha256:" + "c" * 64


def setup(root: Path):
    rfc = with_revision_digest(
        {
            "id": "RFC-20261008-056",
            "title": "Agent",
            "capability_group": "agent",
            "revision": 1,
            "python_sources": ["a.py"],
            "target_files": ["a.ts"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}},
            "tests": {"level1": ["bun test a"], "level2": ["bun test"]},
            "integration_batch": "agent",
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
                },
                "rfcs": [rfc],
            }
        )
    )
    state = StateStore(root / "state.sqlite3")
    state.import_registry(load_registry(dag))
    state.transition(rfc["id"], TaskState.DRAFT, TaskState.VALIDATED, "validator")
    state.transition(rfc["id"], TaskState.VALIDATED, TaskState.READY, "scheduler")
    queue = QueueStore(state)
    tests = TestEvidenceStore(state)
    pipeline = Pipeline(state, queue, tests)
    artifacts = ArtifactStore(state, root / "artifacts")
    return state, queue, tests, pipeline, artifacts, rfc


class PipelineTests(unittest.TestCase):
    def test_coder_test_reviewer_pass_flow_stops_at_lead_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, queue, tests, pipeline, artifacts, rfc = setup(Path(directory))
            queue.register_agent("coder-1", "coder", "xiaosuan-8", "pid:1", now=0)
            queue.register_agent("tester-1", "tester", "local", "pid:2", now=0)
            queue.register_agent("reviewer-1", "reviewer", "xiaosuan-8", "pid:3", now=0)
            queue.enqueue(rfc["id"], "coding", "coding:1", available_at=0)
            coder = queue.claim("coder-1", now=0, lease_seconds=100)
            queue.start(coder, now=1)
            level1_log = artifacts.put_text("test-log", "L1 PASS")
            level1 = tests.identity(
                rfc["id"], rfc["revision_digest"], CANDIDATE, 1, ["bun test a"], {}
            )
            tests.record(level1, "PASS", level1_log)
            pipeline.complete_coding(coder, CANDIDATE, level1, now=2)
            tester = queue.claim("tester-1", now=3, lease_seconds=100)
            queue.start(tester, now=4)
            level2_log = artifacts.put_text("test-log", "L2 and differential PASS")
            level2 = tests.identity(
                rfc["id"],
                rfc["revision_digest"],
                CANDIDATE,
                2,
                ["bun test"],
                {},
                "a" * 40,
            )
            pipeline.complete_level2(tester, level2, "PASS", level2_log, now=5)
            reviewer = queue.claim("reviewer-1", now=6, lease_seconds=100)
            queue.start(reviewer, now=7)
            review_log = artifacts.put_text("review", '{"verdict":"PASS"}')
            pipeline.complete_review(
                reviewer, ReviewResult("PASS", "PASS", review_log), now=8
            )
            self.assertEqual(state.task(rfc["id"])["state"], "LeadReview")
            integration_job = pipeline.approve_for_integration(
                rfc["id"], CANDIDATE, "project-lead", available_at=8
            )
            self.assertIsInstance(integration_job, int)
            queue.register_agent("integrator-1", "integrator", "local", "pid:4", now=8)
            integration = queue.claim("integrator-1", now=9, lease_seconds=100)
            queue.start(integration, now=10)
            level3_log = artifacts.put_text("test-log", "L3 full regression PASS")
            level3 = tests.identity(
                rfc["id"],
                rfc["revision_digest"],
                CANDIDATE,
                3,
                ["bun test", "bun run differential:all"],
                {},
                "a" * 40,
            )
            pipeline.complete_integration(integration, level3, level3_log, now=11)
            self.assertEqual(state.task(rfc["id"])["state"], "Done")

    def test_review_infra_failure_reuses_candidate_and_request_changes_amends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, queue, _tests, pipeline, artifacts, rfc = setup(Path(directory))
            state.transition(rfc["id"], TaskState.READY, TaskState.LEASED, "fixture")
            state.transition(rfc["id"], TaskState.LEASED, TaskState.CODING, "fixture")
            state.transition(rfc["id"], TaskState.CODING, TaskState.TESTING, "fixture")
            state.transition(rfc["id"], TaskState.TESTING, TaskState.REVIEWING, "fixture")
            queue.register_agent("reviewer-1", "reviewer", "xiaosuan-8", "pid:1", now=0)
            queue.enqueue(
                rfc["id"], "review", "review:1", candidate_digest=CANDIDATE, available_at=0
            )
            first = queue.claim("reviewer-1", now=0, lease_seconds=100)
            queue.start(first, now=1)
            evidence = artifacts.put_text("review-infra", "invalid JSON")
            pipeline.complete_review(
                first, ReviewResult(None, "FAILED", evidence), now=2
            )
            self.assertEqual(state.task(rfc["id"])["state"], "ReviewInfraFailed")
            retry = queue.claim("reviewer-1", now=3, lease_seconds=100)
            self.assertEqual(retry.candidate_digest, CANDIDATE)
            queue.start(retry, now=4)
            changes = artifacts.put_text("review", "REQUEST_CHANGES")
            pipeline.complete_review(
                retry,
                ReviewResult(
                    "REQUEST_CHANGES", "PASS", changes, ("Fix src/a.ts:1 and rerun L2.",)
                ),
                now=5,
            )
            self.assertEqual(state.task(rfc["id"])["state"], "Amendment")
            coding_jobs = [job for job in queue.jobs() if job["kind"] == "coding"]
            self.assertEqual(len(coding_jobs), 1)


if __name__ == "__main__":
    unittest.main()
