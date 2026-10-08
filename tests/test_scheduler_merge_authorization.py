from __future__ import annotations

import json
import sqlite3
import subprocess
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from scheduler.evidence import ArtifactStore
from scheduler.git_broker import Candidate
from scheduler.git_verifier import RepositoryGitVerifier
from scheduler.leases import QueueStore
from scheduler.merge_authorization import (
    AUTO_MERGE_ELIGIBLE,
    BLOCKED,
    NEEDS_HUMAN_APPROVAL,
    MergeAuthorizationGate,
)
from scheduler.models import TaskState
from scheduler.pipeline import Pipeline, ReviewResult
from scheduler.registry import content_digest, load_registry, with_revision_digest
from scheduler.state_store import StateStore, utc_now
from scheduler.testing import TestEvidenceStore, digest_json


RFC = "RFC-20261008-056"
DEPENDENCY = "RFC-20261008-056"
DEPENDENT = "RFC-20261008-057"
BASELINE = "a" * 40


def git(cwd: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def rfc_payload(
    rfc_id: str,
    target: str,
    *,
    title: str = "Provider transport",
    capability_group: str = "provider",
    depends_on: list[str] | None = None,
    provides: dict[str, str] | None = None,
    definitions: dict[str, object] | None = None,
    requires: dict[str, str] | None = None,
) -> dict:
    return with_revision_digest(
        {
            "id": rfc_id,
            "title": title,
            "capability_group": capability_group,
            "revision": 1,
            "python_sources": [f"hermes/{rfc_id}.py"],
            "target_files": [target],
            "source_targets": {f"hermes/{rfc_id}.py": target},
            "lock_keys": [rfc_id],
            "depends_on": depends_on or [],
            "contracts": {
                "provides": provides or {},
                "requires": requires or {},
                "definitions": definitions or {},
            },
            "tests": {
                "level1": [f"bun test {rfc_id}:smoke"],
                "level2": [f"bun test {rfc_id}:module"],
                "level3": [f"bun test {rfc_id}:integration"],
            },
            "integration_batch": "provider",
            "acceptance_criteria": ["Python and Bun behavior is equivalent."],
        }
    )


@dataclass
class Fixture:
    root: Path
    repo: Path
    state: StateStore
    registry: object
    rfc_id: str
    rfc: object
    candidate: Candidate
    gate: MergeAuthorizationGate
    evidence_digest: str


def complete_fixture(
    root: Path,
    *,
    target: str = "src/provider.ts",
    title: str = "Provider transport",
    capability_group: str = "provider",
    with_dependency: bool = False,
) -> Fixture:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "checkout", "-b", "main")
    (repo / "README.md").write_text("base\n")
    git(repo, "add", "README.md")
    git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "base",
    )
    base = git(repo, "rev-parse", "HEAD")

    definitions: dict[str, object] = {"provider.contract": {"version": 1}}
    contracts = {
        name: content_digest(definition) for name, definition in definitions.items()
    }
    if with_dependency:
        dependency = rfc_payload(
            DEPENDENCY,
            "src/dependency.ts",
            title="Provider dependency",
            provides=contracts,
            definitions=definitions,
        )
        active_id = DEPENDENT
        active = rfc_payload(
            active_id,
            target,
            depends_on=[DEPENDENCY],
            requires=contracts,
        )
        rfcs = [dependency, active]
    else:
        active_id = RFC
        active = rfc_payload(
            active_id,
            target,
            title=title,
            capability_group=capability_group,
        )
        rfcs = [active]

    dag = root / "dag.json"
    dag.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "commit": BASELINE,
                    "classification_sha256": "sha256:" + "b" * 64,
                    "in_scope_count": 806,
                    "config_data_count": 0,
                },
                "rfcs": rfcs,
            }
        )
    )
    registry = load_registry(dag)
    rfc = registry.rfcs[active_id]

    branch = f"agent/{active_id}"
    git(repo, "checkout", "-b", branch)
    destination = repo / target
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("export const migrated = true;\n")
    git(repo, "add", target)
    git(
        repo,
        "-c",
        "user.name=Coder",
        "-c",
        "user.email=coder@example.invalid",
        "commit",
        "-m",
        "candidate",
    )
    commit = git(repo, "rev-parse", "HEAD")
    verifier = RepositoryGitVerifier(repo)
    tree = verifier.candidate_tree(commit)
    diff = verifier.candidate_diff_digest(base, commit)
    candidate_payload = {
        "base_commit": base,
        "branch": branch,
        "commit_sha": commit,
        "diff_digest": diff,
        "revision_digest": rfc.revision_digest,
        "rfc_id": active_id,
        "tree_sha": tree,
    }
    candidate_digest = MergeAuthorizationGate._digest(candidate_payload)
    candidate = Candidate(
        active_id,
        rfc.revision_digest,
        branch,
        base,
        commit,
        tree,
        diff,
        candidate_digest,
    )

    state = StateStore(root / "state.sqlite3")
    state.import_registry(registry)
    state.transition(active_id, TaskState.DRAFT, TaskState.VALIDATED, "validator")
    state.transition(active_id, TaskState.VALIDATED, TaskState.READY, "scheduler")
    queue = QueueStore(state)
    tests = TestEvidenceStore(state)
    pipeline = Pipeline(state, queue, tests)
    artifacts = ArtifactStore(state, root / "artifacts")
    queue.register_agent("coder-1", "coder", "xiaosuan-8", "pid:coder", now=0)
    queue.register_agent("tester-1", "tester", "local", "pid:tester", now=0)
    queue.register_agent(
        "reviewer-1", "reviewer", "xiaosuan-8", "pid:reviewer", now=0
    )
    queue.register_agent(
        "integrator-1", "integrator", "local", "pid:integrator", now=0
    )

    queue.enqueue(active_id, "coding", "coding:fixture", base_commit=base, available_at=0)
    coding = queue.claim("coder-1", now=0, lease_seconds=100)
    assert coding is not None
    queue.start(coding, now=1)
    level1_evidence = artifacts.put_text("test-log", "Level 1 PASS")
    level1 = tests.identity(
        active_id,
        rfc.revision_digest,
        candidate_digest,
        1,
        list(rfc.level1_tests),
        {},
    )
    pipeline.complete_coding(coding, candidate, level1, level1_evidence, now=2)

    testing = queue.claim("tester-1", now=3, lease_seconds=100)
    assert testing is not None
    queue.start(testing, now=4)
    level2_evidence = artifacts.put_text("test-log", "Level 2 differential PASS")
    level2 = tests.identity(
        active_id,
        rfc.revision_digest,
        candidate_digest,
        2,
        list(rfc.level2_tests),
        {},
        BASELINE,
    )
    pipeline.complete_level2(testing, level2, "PASS", level2_evidence, now=5)

    reviewing = queue.claim("reviewer-1", now=6, lease_seconds=100)
    assert reviewing is not None
    queue.start(reviewing, now=7)
    review_evidence = artifacts.put_text("review", '{"verdict":"PASS"}')
    pipeline.complete_review(
        reviewing,
        ReviewResult("PASS", "PASS", review_evidence),
        now=8,
    )
    pipeline.approve_for_integration(
        active_id, candidate_digest, "project-lead", available_at=9
    )

    integration = queue.claim("integrator-1", now=9, lease_seconds=100)
    assert integration is not None
    queue.start(integration, now=10)
    level3_evidence = artifacts.put_text("test-log", "Level 3 PASS")
    level3 = tests.identity(
        active_id,
        rfc.revision_digest,
        candidate_digest,
        3,
        list(rfc.level3_tests),
        {},
        BASELINE,
    )
    pipeline.complete_integration(integration, level3, level3_evidence, now=11)

    with state.transaction() as connection:
        connection.execute(
            "INSERT INTO publication_records "
            "(rfc_id, revision_digest, candidate_digest, lease_id, fencing_token, "
            "remote, ref_name, previous_commit, target_commit, state, observed_commit, "
            "last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "'confirmed', ?, NULL, ?, ?)",
            (
                active_id,
                rfc.revision_digest,
                candidate_digest,
                "publication-lease",
                1,
                "origin",
                f"refs/heads/{branch}",
                None,
                commit,
                commit,
                utc_now(),
                utc_now(),
            ),
        )

    return Fixture(
        root,
        repo,
        state,
        registry,
        active_id,
        rfc,
        candidate,
        MergeAuthorizationGate(registry, state, verifier),
        review_evidence,
    )


def insert_dependency_merge(fixture: Fixture, *, stale_contract: bool) -> None:
    dependency = fixture.registry.rfcs[DEPENDENCY]
    candidate_digest = "sha256:" + "d" * 64
    with fixture.state.transaction() as connection:
        if not stale_contract:
            review = connection.execute(
                "SELECT review_run_id FROM review_runs WHERE rfc_id = ?",
                (fixture.rfc_id,),
            ).fetchone()
            level3 = connection.execute(
                "SELECT test_run_id FROM test_runs WHERE rfc_id = ? AND level = 3",
                (fixture.rfc_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO merge_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    DEPENDENCY,
                    dependency.revision_digest,
                    candidate_digest,
                    "",
                    int(review["review_run_id"]),
                    int(level3["test_run_id"]),
                    fixture.candidate.base_commit,
                    fixture.candidate.base_commit,
                    "{}",
                    "fixture",
                    utc_now(),
                ),
            )
            return

        connection.execute(
            "INSERT INTO candidate_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                DEPENDENCY,
                dependency.revision_digest,
                candidate_digest,
                fixture.candidate.base_commit,
                f"agent/{DEPENDENCY}",
                fixture.candidate.base_commit,
                fixture.candidate.tree_sha,
                fixture.candidate.diff_digest,
                "coder-1",
                "pid:coder",
                utc_now(),
            ),
        )
        review_id = connection.execute(
            "INSERT INTO review_runs "
            "(rfc_id, revision_digest, candidate_digest, reviewer_agent_id, verdict, "
            "infrastructure_status, schema_valid, independent, evidence_digest, created_at) "
            "VALUES (?, ?, ?, 'reviewer-1', 'PASS', 'PASS', 1, 1, ?, ?)",
            (
                DEPENDENCY,
                dependency.revision_digest,
                candidate_digest,
                fixture.evidence_digest,
                utc_now(),
            ),
        ).lastrowid
        level3_id = connection.execute(
            "INSERT INTO test_runs "
            "(rfc_id, revision_digest, candidate_digest, level, command_digest, "
            "environment_digest, baseline_commit, status, evidence_digest, started_at, "
            "completed_at) VALUES (?, ?, ?, 3, ?, ?, ?, 'PASS', ?, ?, ?)",
            (
                DEPENDENCY,
                dependency.revision_digest,
                candidate_digest,
                digest_json(list(dependency.level3_tests)),
                digest_json({}),
                BASELINE,
                fixture.evidence_digest,
                utc_now(),
                utc_now(),
            ),
        ).lastrowid
        connection.execute(
            "INSERT INTO merge_records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                DEPENDENCY,
                dependency.revision_digest,
                candidate_digest,
                fixture.candidate.base_commit,
                review_id,
                level3_id,
                fixture.candidate.base_commit,
                fixture.candidate.base_commit,
                "{}",
                "fixture",
                utc_now(),
            ),
        )


class MergeAuthorizationTests(unittest.TestCase):
    def test_complete_ordinary_module_is_eligible_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            first = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            second = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            self.assertEqual(first.disposition, AUTO_MERGE_ELIGIBLE)
            self.assertEqual(first.blockers, ())
            self.assertEqual(first.decision_id, second.decision_id)
            self.assertEqual(first.decision_digest, second.decision_digest)
            with fixture.state.connect() as connection:
                count = connection.execute(
                    "SELECT COUNT(*) FROM merge_authorization_decisions"
                ).fetchone()[0]
            self.assertEqual(count, 1)

    def test_sensitive_scope_requires_human_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(
                Path(directory),
                target="scheduler/security_policy.ts",
                title="Credential authorization policy",
                capability_group="security",
            )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            self.assertEqual(decision.disposition, NEEDS_HUMAN_APPROVAL)
            self.assertFalse(decision.blockers)
            self.assertTrue(decision.risk_reasons)

    def test_missing_required_evidence_blocks(self) -> None:
        cases = {
            "level2": (
                "DELETE FROM test_runs WHERE rfc_id = ? AND level = 2",
                "module and Python differential PASS evidence is missing",
            ),
            "level3": (
                "DELETE FROM test_runs WHERE rfc_id = ? AND level = 3",
                "Level 3 PASS evidence is missing",
            ),
            "review": (
                "DELETE FROM review_runs WHERE rfc_id = ?",
                "Project Lead approval is not bound to an independent Reviewer PASS",
            ),
            "lead": (
                "UPDATE transitions SET metadata_json = '{}' WHERE rfc_id = ? "
                "AND from_state = 'LeadReview' AND to_state = 'IntegrationReady'",
                "Project Lead approval is missing",
            ),
            "publication": (
                "DELETE FROM publication_records WHERE rfc_id = ?",
                "confirmed remote publication is missing",
            ),
        }
        for name, (statement, expected) in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                fixture = complete_fixture(Path(directory))
                with fixture.state.transaction() as connection:
                    connection.execute(statement, (fixture.rfc_id,))
                decision = fixture.gate.evaluate(
                    fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
                )
                self.assertEqual(decision.disposition, BLOCKED)
                self.assertTrue(any(expected in item for item in decision.blockers))

    def test_candidate_tampering_and_branch_drift_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            with fixture.state.transaction() as connection:
                connection.execute(
                    "UPDATE candidate_records SET tree_sha = ? WHERE rfc_id = ?",
                    ("f" * 40, fixture.rfc_id),
                )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("canonical" in item for item in decision.blockers))
            self.assertTrue(any("tree" in item for item in decision.blockers))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            path = fixture.repo / fixture.rfc.target_files[0]
            path.write_text("export const migrated = false;\n")
            git(fixture.repo, "add", str(fixture.rfc.target_files[0]))
            git(
                fixture.repo,
                "-c",
                "user.name=Drift",
                "-c",
                "user.email=drift@example.invalid",
                "commit",
                "-m",
                "drift",
            )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("exact" in item or "identify" in item for item in decision.blockers))

    def test_active_lease_and_migration_blocker_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            with fixture.state.transaction() as connection:
                coding_job = connection.execute(
                    "SELECT job_id FROM jobs WHERE rfc_id = ? AND kind = 'coding'",
                    (fixture.rfc_id,),
                ).fetchone()
                connection.execute(
                    "INSERT INTO leases VALUES (?, 'rfc', ?, ?, 'coder-1', 99, 0, 0, 999999)",
                    ("stale-active-lease", fixture.rfc_id, coding_job["job_id"]),
                )
                connection.execute(
                    "INSERT INTO migration_blockers VALUES (?, ?, '{}', ?, NULL)",
                    ("fixture-blocker", "FIXTURE", utc_now()),
                )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertIn("RFC still has an active executor lease", decision.blockers)
            self.assertTrue(any("fixture-blocker" in item for item in decision.blockers))

    def test_dependency_evidence_and_contracts_fail_closed(self) -> None:
        for name, setup_dependency, expected in (
            ("missing", None, "has not been merged"),
            ("legacy", False, "incomplete or legacy merge evidence"),
            ("contract", True, "interface contract evidence is stale"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                fixture = complete_fixture(Path(directory), with_dependency=True)
                if setup_dependency is not None:
                    insert_dependency_merge(fixture, stale_contract=setup_dependency)
                decision = fixture.gate.evaluate(
                    fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
                )
                self.assertEqual(decision.disposition, BLOCKED)
                self.assertTrue(any(expected in item for item in decision.blockers))

    def test_authorization_audit_rows_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "project-lead"
            )
            with fixture.state.connect() as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE merge_authorization_decisions SET disposition = 'BLOCKED' "
                        "WHERE decision_id = ?",
                        (decision.decision_id,),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "DELETE FROM merge_authorization_decisions WHERE decision_id = ?",
                        (decision.decision_id,),
                    )


if __name__ == "__main__":
    unittest.main()
