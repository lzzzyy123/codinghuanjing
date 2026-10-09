from __future__ import annotations

import json
import inspect
import sqlite3
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier, Thread
from unittest.mock import patch

from scheduler.evidence import ArtifactStore
from scheduler.git_broker import Candidate
from scheduler.git_verifier import RepositoryGitVerifier
from scheduler.leases import QueueStore
from scheduler.merge_cas import AtomicGitMergeCas, MergeCasError
from scheduler.merge_authorization import (
    AUTO_MERGE_ELIGIBLE,
    BLOCKED,
    NEEDS_HUMAN_APPROVAL,
    MergeAuthorizationGate,
    TrustedApprovalPrincipal,
    sign_project_lead_attestation,
)
from scheduler.models import TaskState
from scheduler.pipeline import Pipeline, ReviewResult
from scheduler.registry import content_digest, load_registry, with_revision_digest
from scheduler.state_store import StateConflict, StateStore, utc_now
from scheduler.testing import TestEvidenceStore, digest_json


RFC = "RFC-20261008-056"
DEPENDENCY = "RFC-20261008-056"
DEPENDENT = "RFC-20261008-057"
BASELINE = "a" * 40
LEAD_ACTOR = "project-lead:mac-owner"
LEAD_CHANNEL = "mac-codex:local"
LEAD_KEY = b"fixture-project-lead-attestation-key"


@dataclass
class MutableClock:
    value: float

    def __call__(self) -> float:
        return self.value


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
    clock=None,
) -> Fixture:
    remote = root / "remote.git"
    git(root, "init", "--bare", str(remote))
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init")
    git(repo, "checkout", "-b", "main")
    git(repo, "remote", "add", "origin", str(remote))
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
    git(repo, "push", "-u", "origin", "main")

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
    git(repo, "push", "origin", f"{branch}:{branch}")
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
    approval_evidence = artifacts.put_text(
        "project-lead-approval", "Project Lead accepted exact candidate"
    )
    with state.connect() as connection:
        review_run_id = int(
            connection.execute(
                "SELECT review_run_id FROM review_runs WHERE rfc_id = ? "
                "ORDER BY review_run_id DESC LIMIT 1",
                (active_id,),
            ).fetchone()["review_run_id"]
        )
    approval_attestation = sign_project_lead_attestation(
        LEAD_KEY,
        rfc_id=active_id,
        revision_digest=rfc.revision_digest,
        candidate_digest=candidate_digest,
        review_run_id=review_run_id,
        actor=LEAD_ACTOR,
        channel=LEAD_CHANNEL,
        evidence_digest=approval_evidence,
    )
    pipeline.approve_for_integration(
        active_id,
        candidate_digest,
        LEAD_ACTOR,
        approval_channel=LEAD_CHANNEL,
        approval_evidence_digest=approval_evidence,
        approval_attestation=approval_attestation,
        available_at=9,
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
        base,
        tree,
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
        MergeAuthorizationGate(
            registry,
            state,
            verifier,
            project_lead_principals=frozenset(
                {TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL)}
            ),
            project_lead_attestation_keys={
                TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL): LEAD_KEY
            },
            trusted_remote_url=str(remote),
            approved_baseline_commit=BASELINE,
            clock=clock or time.time,
        ),
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
            "environment_digest, baseline_commit, trusted_main_commit, "
            "candidate_merge_tree, status, evidence_digest, started_at, completed_at) "
            "VALUES (?, ?, ?, 3, ?, ?, ?, ?, ?, 'PASS', ?, ?, ?)",
            (
                DEPENDENCY,
                dependency.revision_digest,
                candidate_digest,
                digest_json(list(dependency.level3_tests)),
                digest_json({}),
                BASELINE,
                fixture.candidate.base_commit,
                fixture.candidate.tree_sha,
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
            fixture = complete_fixture(Path(directory), clock=MutableClock(100))
            first = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            second = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, NEEDS_HUMAN_APPROVAL)
            self.assertFalse(decision.blockers)
            self.assertTrue(decision.risk_reasons)

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(
                Path(directory),
                target="CODEOWNERS",
                title="Repository ownership map",
                capability_group="repository",
            )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, NEEDS_HUMAN_APPROVAL)
            self.assertTrue(any("CODEOWNERS" in item for item in decision.risk_reasons))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            gate = MergeAuthorizationGate(
                fixture.registry,
                fixture.state,
                RepositoryGitVerifier(fixture.repo),
                project_lead_principals=frozenset(
                    {TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL)}
                ),
                project_lead_attestation_keys={
                    TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL): LEAD_KEY
                },
                trusted_remote_url=str(fixture.root / "remote.git"),
                approved_baseline_commit="b" * 40,
            )
            decision = gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, NEEDS_HUMAN_APPROVAL)
            self.assertTrue(any("baseline" in item for item in decision.risk_reasons))

    def test_sensitive_control_names_and_gate_semantics_are_detected_anywhere(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            cases = (
                "docs/CODEOWNERS",
                "src/generated/.gitattributes",
                "src/compat/parity/report.ts",
                "src/oracles/differential-runner.ts",
                "src/release/gates/check.ts",
                "src/state/baselines/catalog.ts",
                "src/compat/paritySnapshot.ts",
                "src/release/integrationGate.ts",
            )
            for path in cases:
                with self.subTest(path=path):
                    self.assertTrue(fixture.gate._risk_reasons(fixture.rfc, (path,)))

    def test_credential_paths_fail_closed_but_module_differential_tests_do_not(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            credential_paths = (
                ".env.production",
                "packages/provider/.npmrc",
                "home/service/.ssh/config",
                "etc/ssh/sshd_config",
                "deploy/id_ed25519",
                "config/api-tokens.json",
                "runtime/credential-store.json",
                "certificates/client.pem",
            )
            for path in credential_paths:
                with self.subTest(path=path):
                    reasons = fixture.gate._risk_reasons(fixture.rfc, (path,))
                    self.assertTrue(any("credential" in reason for reason in reasons))

            ordinary = fixture.gate._risk_reasons(
                fixture.rfc, ("tests/differential/provider_retry.test.ts",)
            )
            self.assertFalse(ordinary)
            for path in (
                "tests/differential/oracles/provider.json",
                "tests/differential/fixtures/provider.json",
                "tests/differential/framework/runner.ts",
                "tools/differential-runner.ts",
            ):
                with self.subTest(path=path):
                    self.assertTrue(fixture.gate._risk_reasons(fixture.rfc, (path,)))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(
                Path(directory),
                target="tests/differential/provider_retry.test.ts",
            )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, AUTO_MERGE_ELIGIBLE)
            self.assertFalse(decision.risk_reasons)

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(
                Path(directory),
                target="tests/differential/oracles/provider.json",
            )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, NEEDS_HUMAN_APPROVAL)
            self.assertTrue(decision.risk_reasons)

    def test_project_lead_principal_and_channel_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            verifier = RepositoryGitVerifier(fixture.repo)
            for actor in ("scheduler", "tester", "reviewer-1"):
                with self.subTest(actor=actor), self.assertRaisesRegex(
                    ValueError, "Project Lead principal"
                ):
                    MergeAuthorizationGate(
                        fixture.registry,
                        fixture.state,
                        verifier,
                        project_lead_principals=frozenset(
                            {TrustedApprovalPrincipal(actor, LEAD_CHANNEL)}
                        ),
                        trusted_remote_url=str(fixture.root / "remote.git"),
                        approved_baseline_commit=BASELINE,
                    )

            wrong_channel = MergeAuthorizationGate(
                fixture.registry,
                fixture.state,
                verifier,
                project_lead_principals=frozenset(
                    {TrustedApprovalPrincipal(LEAD_ACTOR, "github:other-channel")}
                ),
                project_lead_attestation_keys={
                    TrustedApprovalPrincipal(
                        LEAD_ACTOR, "github:other-channel"
                    ): LEAD_KEY
                },
                trusted_remote_url=str(fixture.root / "remote.git"),
                approved_baseline_commit=BASELINE,
            )
            decision = wrong_channel.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("Project Lead approval" in item for item in decision.blockers))

    def test_project_lead_approval_is_exactly_bound_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            with fixture.state.connect() as connection:
                approval = connection.execute(
                    "SELECT approval_id FROM project_lead_approvals WHERE rfc_id = ?",
                    (fixture.rfc_id,),
                ).fetchone()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE project_lead_approvals SET channel = 'github:forged' "
                        "WHERE approval_id = ?",
                        (approval["approval_id"],),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "DELETE FROM project_lead_approvals WHERE approval_id = ?",
                        (approval["approval_id"],),
                    )

            with fixture.state.transaction() as connection:
                transition = connection.execute(
                    "SELECT id, metadata_json FROM transitions WHERE rfc_id = ? "
                    "AND from_state = 'LeadReview' AND to_state = 'IntegrationReady'",
                    (fixture.rfc_id,),
                ).fetchone()
                metadata = json.loads(transition["metadata_json"])
                metadata["approval_id"] += 1000
                connection.execute(
                    "UPDATE transitions SET metadata_json = ? WHERE id = ?",
                    (json.dumps(metadata, sort_keys=True), transition["id"]),
                )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("Project Lead approval" in item for item in decision.blockers))

    def test_project_lead_attestation_cannot_be_forged_by_approval_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            principal = TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL)
            gate = MergeAuthorizationGate(
                fixture.registry,
                fixture.state,
                RepositoryGitVerifier(fixture.repo),
                project_lead_principals=frozenset({principal}),
                project_lead_attestation_keys={principal: b"different-trusted-key-material-123"},
                trusted_remote_url=str(fixture.root / "remote.git"),
                approved_baseline_commit=BASELINE,
            )
            decision = gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("Project Lead approval" in item for item in decision.blockers))

    def test_remote_identity_is_pinned_normalized_and_credential_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            verifier = RepositoryGitVerifier(fixture.repo)
            identities = {
                verifier.normalize_remote_identity(value)
                for value in (
                    "git@github.com:lzzzyy123/zhuanxie.git",
                    "ssh://git@github.com/lzzzyy123/zhuanxie.git",
                    "https://github.com/lzzzyy123/zhuanxie.git",
                )
            }
            self.assertEqual(
                identities, {"secure:host:github.com/lzzzyy123/zhuanxie"}
            )
            secure = identities.pop()
            self.assertNotEqual(
                secure,
                verifier.normalize_remote_identity(
                    "http://github.com/lzzzyy123/zhuanxie.git"
                ),
            )
            self.assertNotEqual(
                secure,
                verifier.normalize_remote_identity(
                    "git://github.com/lzzzyy123/zhuanxie.git"
                ),
            )
            self.assertNotEqual(
                secure,
                verifier.normalize_remote_identity(str(fixture.root / "remote.git")),
            )

            secret = "not-for-evidence"
            credential_url = (
                f"https://project-lead:{secret}@github.com/lzzzyy123/zhuanxie.git"
            )
            gate = MergeAuthorizationGate(
                fixture.registry,
                fixture.state,
                verifier,
                project_lead_principals=frozenset(
                    {TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL)}
                ),
                project_lead_attestation_keys={
                    TrustedApprovalPrincipal(LEAD_ACTOR, LEAD_CHANNEL): LEAD_KEY
                },
                trusted_remote_url=credential_url,
                approved_baseline_commit=BASELINE,
            )
            normalized = verifier.normalize_remote_identity(credential_url)

            def remote_head(_remote: str, _identity: str, ref_name: str) -> str:
                if ref_name == "refs/heads/main":
                    return fixture.candidate.base_commit
                return fixture.candidate.commit_sha

            with patch.object(
                verifier, "remote_identity", return_value=normalized
            ), patch.object(
                verifier, "resolve_pinned_remote_head", side_effect=remote_head
            ):
                decision = gate.evaluate(
                    fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
                )
            serialized = json.dumps(decision.evidence, sort_keys=True)
            self.assertNotIn(secret, serialized)
            self.assertNotIn("project-lead@", serialized)

            replacement = fixture.root / "other-remote.git"
            git(fixture.root, "init", "--bare", str(replacement))
            git(fixture.repo, "remote", "set-url", "origin", str(replacement))
            retargeted = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(retargeted.disposition, BLOCKED)
            self.assertTrue(any("pinned repository" in item for item in retargeted.blockers))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            replacement = fixture.root / "other-remote.git"
            git(fixture.root, "init", "--bare", str(replacement))
            git(
                fixture.repo,
                "remote",
                "set-url",
                "--add",
                "--push",
                "origin",
                str(replacement),
            )
            split_remote = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(split_remote.disposition, BLOCKED)
            self.assertTrue(
                any("different repositories" in item for item in split_remote.blockers)
            )

    def test_level3_main_binding_and_project_lead_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            with fixture.state.transaction() as connection:
                connection.execute(
                    "UPDATE test_runs SET trusted_main_commit = NULL WHERE rfc_id = ? "
                    "AND level = 3",
                    (fixture.rfc_id,),
                )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("Level 3 PASS" in item for item in decision.blockers))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            with fixture.state.transaction() as connection:
                connection.execute(
                    "UPDATE transitions SET actor = 'scheduler' WHERE rfc_id = ? "
                    "AND from_state = 'LeadReview' AND to_state = 'IntegrationReady'",
                    (fixture.rfc_id,),
                )
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, "scheduler"
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("Project Lead approval" in item for item in decision.blockers))

    def test_publication_requires_trusted_remote_and_live_exact_head(self) -> None:
        for update, expected in (
            ("remote = 'backup'", "confirmed remote publication"),
            ("observed_commit = NULL", "confirmed remote publication"),
        ):
            with self.subTest(update=update), tempfile.TemporaryDirectory() as directory:
                fixture = complete_fixture(Path(directory))
                with fixture.state.transaction() as connection:
                    connection.execute(
                        f"UPDATE publication_records SET {update} WHERE rfc_id = ?",
                        (fixture.rfc_id,),
                    )
                decision = fixture.gate.evaluate(
                    fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
                )
                self.assertEqual(decision.disposition, BLOCKED)
                self.assertTrue(any(expected in item for item in decision.blockers))

        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            git(fixture.repo, "checkout", "-b", "remote-drift", "main")
            (fixture.repo / "README.md").write_text("remote drift\n")
            git(fixture.repo, "add", "README.md")
            git(
                fixture.repo,
                "-c",
                "user.name=Drift",
                "-c",
                "user.email=drift@example.invalid",
                "commit",
                "-m",
                "remote drift",
            )
            git(
                fixture.repo,
                "push",
                "origin",
                f"+remote-drift:refs/heads/{fixture.candidate.branch}",
            )
            git(fixture.repo, "checkout", fixture.candidate.branch)
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(decision.disposition, BLOCKED)
            self.assertTrue(any("trusted remote ref" in item for item in decision.blockers))

    def test_stale_eligibility_must_be_revalidated_before_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            eligible = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            self.assertEqual(eligible.disposition, AUTO_MERGE_ELIGIBLE)

            git(fixture.repo, "checkout", "main")
            (fixture.repo / "README.md").write_text("new main\n")
            git(fixture.repo, "add", "README.md")
            git(
                fixture.repo,
                "-c",
                "user.name=Main",
                "-c",
                "user.email=main@example.invalid",
                "commit",
                "-m",
                "advance main",
            )
            git(fixture.repo, "push", "origin", "main")
            git(fixture.repo, "checkout", fixture.candidate.branch)

            with self.assertRaisesRegex(StateConflict, "stale"):
                fixture.gate.reserve_current_eligibility(
                    eligible.decision_digest,
                    "stale-attempt",
                    "merge-broker:fixture",
                    str(eligible.evidence["trusted_main_commit"]),
                )

    def test_authorization_reservation_is_idempotent_fenced_and_single_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            eligible = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(eligible.evidence["trusted_main_commit"])
            refs_before = git(fixture.repo, "show-ref")
            fixture.gate.merge_cas = AtomicGitMergeCas(
                fixture.repo,
                str(fixture.root / "remote.git"),
                fixture.root / "merge-cas.lock",
                timeout_seconds=5,
            )
            reservation = fixture.gate.reserve_current_eligibility(
                eligible.decision_digest,
                "merge-attempt-1",
                "merge-broker:fixture",
                main,
                lease_seconds=30,
            )
            clock.value = 101
            repeated = fixture.gate.reserve_current_eligibility(
                eligible.decision_digest,
                "merge-attempt-1",
                "merge-broker:fixture",
                main,
                lease_seconds=30,
            )
            self.assertEqual(repeated.reservation_id, reservation.reservation_id)
            with self.assertRaisesRegex(StateConflict, "already reserved"):
                fixture.gate.reserve_current_eligibility(
                    eligible.decision_digest,
                    "merge-attempt-2",
                    "merge-broker:fixture",
                    main,
                )
            with self.assertRaisesRegex(StateConflict, "stale"):
                fixture.gate.consume_reserved_eligibility(
                    reservation.reservation_id,
                    "merge-broker:other",
                    reservation.fencing_token,
                    main,
                    fixture.candidate.commit_sha,
                )
            with self.assertRaisesRegex(StateConflict, "fencing"):
                fixture.gate.consume_reserved_eligibility(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token + 1,
                    main,
                    fixture.candidate.commit_sha,
                )
            with self.assertRaisesRegex(StateConflict, "CAS"):
                fixture.gate.consume_reserved_eligibility(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                    "b" * 40,
                    fixture.candidate.commit_sha,
                )
            clock.value = 102
            consumed = fixture.gate.consume_reserved_eligibility(
                reservation.reservation_id,
                "merge-broker:fixture",
                reservation.fencing_token,
                main,
                fixture.candidate.commit_sha,
            )
            self.assertEqual(consumed.state, "consumed")
            replay = fixture.gate.consume_reserved_eligibility(
                reservation.reservation_id,
                "merge-broker:fixture",
                reservation.fencing_token,
                main,
                fixture.candidate.commit_sha,
            )
            self.assertEqual(replay, consumed)
            with self.assertRaisesRegex(StateConflict, "stale"):
                fixture.gate.reserve_current_eligibility(
                    eligible.decision_digest,
                    "merge-attempt-3",
                    "merge-broker:fixture",
                    main,
                )
            self.assertEqual(git(fixture.repo, "show-ref"), refs_before)
            self.assertEqual(
                git(fixture.repo, "ls-remote", "origin", "refs/heads/main").split()[0],
                fixture.candidate.commit_sha,
            )
            with fixture.state.connect() as connection:
                events = connection.execute(
                    "SELECT event_type FROM merge_authorization_events "
                    "WHERE reservation_id = ? ORDER BY event_id",
                    (reservation.reservation_id,),
                ).fetchall()
            self.assertEqual(
                [row["event_type"] for row in events],
                ["RESERVED", "MERGE_PREPARED", "MERGED"],
            )

    def test_authorization_subject_is_single_use_across_requesters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory), clock=MutableClock(100))
            first = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            second = fixture.gate.evaluate(
                fixture.rfc_id,
                fixture.candidate.candidate_digest,
                "merge-broker:alternate-requester",
            )
            self.assertNotEqual(first.decision_digest, second.decision_digest)
            main = str(first.evidence["trusted_main_commit"])
            reserved = fixture.gate.reserve_current_eligibility(
                first.decision_digest,
                "requester-one",
                "merge-broker:fixture",
                main,
            )
            with self.assertRaisesRegex(StateConflict, "already reserved"):
                fixture.gate.reserve_current_eligibility(
                    second.decision_digest,
                    "requester-two",
                    "merge-broker:fixture",
                    main,
                )
            self.assertEqual(
                reserved.authorization_subject_digest,
                fixture.gate._authorization_subject_digest(second),
            )

    def test_reservation_uses_injected_trusted_clock_after_slow_revalidation(self) -> None:
        for method in (
            MergeAuthorizationGate.reserve_current_eligibility,
            MergeAuthorizationGate.renew_reservation,
            MergeAuthorizationGate.consume_reserved_eligibility,
        ):
            self.assertNotIn("now", inspect.signature(method).parameters)

        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(decision.evidence["trusted_main_commit"])
            reservation = fixture.gate.reserve_current_eligibility(
                decision.decision_digest,
                "slow-revalidation",
                "merge-broker:fixture",
                main,
                lease_seconds=10,
            )
            class UncalledCas:
                repository_identity = fixture.gate.trusted_repository_identity
                maximum_duration_seconds = 5.0

                def compare_and_swap(self, **_arguments) -> None:
                    raise AssertionError("expired reservation must not reach Git CAS")

            fixture.gate.merge_cas = UncalledCas()
            original = fixture.gate._require_current_eligibility

            def slow_revalidation(*arguments):
                result = original(*arguments)
                clock.value = 111
                return result

            with patch.object(
                fixture.gate,
                "_require_current_eligibility",
                side_effect=slow_revalidation,
            ), self.assertRaisesRegex(StateConflict, "cannot cover"):
                fixture.gate.consume_reserved_eligibility(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                    main,
                    fixture.candidate.commit_sha,
                )

    def test_atomic_merge_cas_consumes_only_after_remote_refs_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(decision.evidence["trusted_main_commit"])
            reservation = fixture.gate.reserve_current_eligibility(
                decision.decision_digest,
                "atomic-merge-success",
                "merge-broker:fixture",
                main,
                lease_seconds=30,
            )
            merge_cas = AtomicGitMergeCas(
                fixture.repo,
                str(fixture.root / "remote.git"),
                fixture.root / "merge-cas.lock",
                timeout_seconds=5,
            )
            fixture.gate.merge_cas = merge_cas
            consumed = fixture.gate.execute_reserved_merge(
                reservation.reservation_id,
                "merge-broker:fixture",
                reservation.fencing_token,
                fixture.candidate.commit_sha,
            )
            self.assertEqual(consumed.state, "consumed")
            self.assertEqual(
                git(fixture.repo, "ls-remote", "origin", "refs/heads/main").split()[0],
                fixture.candidate.commit_sha,
            )
            with fixture.state.connect() as connection:
                attempt = connection.execute(
                    "SELECT state, observed_main_commit, observed_candidate_commit "
                    "FROM merge_execution_attempts WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                ).fetchone()
            self.assertEqual(attempt["state"], "applied")
            self.assertEqual(attempt["observed_main_commit"], fixture.candidate.commit_sha)
            self.assertEqual(
                attempt["observed_candidate_commit"], fixture.candidate.commit_sha
            )

    def test_atomic_merge_cas_candidate_race_never_writes_main(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(decision.evidence["trusted_main_commit"])
            reservation = fixture.gate.reserve_current_eligibility(
                decision.decision_digest,
                "atomic-merge-race",
                "merge-broker:fixture",
                main,
                lease_seconds=30,
            )
            delegate = AtomicGitMergeCas(
                fixture.repo,
                str(fixture.root / "remote.git"),
                fixture.root / "merge-cas.lock",
                timeout_seconds=5,
            )

            class CandidateRaceCas:
                repository_identity = delegate.repository_identity
                maximum_duration_seconds = delegate.maximum_duration_seconds

                def compare_and_swap(self, **arguments) -> None:
                    git(fixture.repo, "checkout", "-b", "candidate-race", "main")
                    (fixture.repo / "race.txt").write_text("race\n")
                    git(fixture.repo, "add", "race.txt")
                    git(
                        fixture.repo,
                        "-c",
                        "user.name=Race",
                        "-c",
                        "user.email=race@example.invalid",
                        "commit",
                        "-m",
                        "candidate race",
                    )
                    git(
                        fixture.repo,
                        "push",
                        "origin",
                        f"+candidate-race:refs/heads/{fixture.candidate.branch}",
                    )
                    delegate.compare_and_swap(**arguments)

            fixture.gate.merge_cas = CandidateRaceCas()
            with self.assertRaises(MergeCasError):
                fixture.gate.execute_reserved_merge(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                    fixture.candidate.commit_sha,
                )
            fixture.gate.merge_cas = delegate
            self.assertEqual(
                git(fixture.repo, "ls-remote", "origin", "refs/heads/main").split()[0],
                main,
            )
            with self.assertRaisesRegex(StateConflict, "manual recovery"):
                fixture.gate.reconcile_reserved_merge(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                )
            with fixture.state.connect() as connection:
                state = connection.execute(
                    "SELECT state FROM merge_authorization_reservations "
                    "WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                ).fetchone()["state"]
                attempt = connection.execute(
                    "SELECT state, error_code FROM merge_execution_attempts "
                    "WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                ).fetchone()
            self.assertEqual(state, "reserved")
            self.assertEqual((attempt["state"], attempt["error_code"]), (
                "blocked", "REMOTE_REF_DIVERGED"
            ))

    def test_atomic_merge_cas_unchanged_failure_can_retry_same_intent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(decision.evidence["trusted_main_commit"])
            reservation = fixture.gate.reserve_current_eligibility(
                decision.decision_digest,
                "atomic-merge-retry",
                "merge-broker:fixture",
                main,
                lease_seconds=30,
            )
            delegate = AtomicGitMergeCas(
                fixture.repo,
                str(fixture.root / "remote.git"),
                fixture.root / "merge-cas.lock",
                timeout_seconds=5,
            )

            class TransientFailureCas:
                repository_identity = delegate.repository_identity
                maximum_duration_seconds = delegate.maximum_duration_seconds

                def compare_and_swap(self, **_arguments) -> None:
                    raise MergeCasError("transient fixture failure")

            fixture.gate.merge_cas = TransientFailureCas()
            with self.assertRaises(MergeCasError):
                fixture.gate.execute_reserved_merge(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                    fixture.candidate.commit_sha,
                )
            fixture.gate.merge_cas = delegate
            with self.assertRaisesRegex(StateConflict, "not applied"):
                fixture.gate.reconcile_reserved_merge(
                    reservation.reservation_id,
                    "merge-broker:fixture",
                    reservation.fencing_token,
                )
            consumed = fixture.gate.execute_reserved_merge(
                reservation.reservation_id,
                "merge-broker:fixture",
                reservation.fencing_token,
                fixture.candidate.commit_sha,
            )
            self.assertEqual(consumed.state, "consumed")
            with fixture.state.connect() as connection:
                attempts = connection.execute(
                    "SELECT COUNT(*) FROM merge_execution_attempts "
                    "WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                ).fetchone()[0]
                events = [
                    row["event_type"]
                    for row in connection.execute(
                        "SELECT event_type FROM merge_authorization_events "
                        "WHERE reservation_id = ? ORDER BY event_id",
                        (reservation.reservation_id,),
                    ).fetchall()
                ]
            self.assertEqual(attempts, 1)
            self.assertIn("MERGE_RETRY", events)
            self.assertEqual(events[-1], "MERGED")

    def test_expired_reservation_requires_explicit_abort_and_advances_fence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = MutableClock(100)
            fixture = complete_fixture(Path(directory), clock=clock)
            eligible = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(eligible.evidence["trusted_main_commit"])
            expired = fixture.gate.reserve_current_eligibility(
                eligible.decision_digest,
                "expiring-attempt",
                "merge-broker:fixture",
                main,
                lease_seconds=10,
            )
            fixture.gate.merge_cas = AtomicGitMergeCas(
                fixture.repo,
                str(fixture.root / "remote.git"),
                fixture.root / "merge-cas.lock",
                timeout_seconds=5,
            )
            clock.value = 111
            with self.assertRaisesRegex(StateConflict, "live"):
                fixture.gate.renew_reservation(
                    expired.reservation_id,
                    "merge-broker:fixture",
                    expired.fencing_token,
                )
            with self.assertRaisesRegex(StateConflict, "cannot cover"):
                fixture.gate.consume_reserved_eligibility(
                    expired.reservation_id,
                    "merge-broker:fixture",
                    expired.fencing_token,
                    main,
                    fixture.candidate.commit_sha,
                )
            with self.assertRaisesRegex(StateConflict, "expired pending explicit abort"):
                fixture.gate.reserve_current_eligibility(
                    eligible.decision_digest,
                    "replacement-before-abort",
                    "merge-broker:fixture",
                    main,
                )
            aborted = fixture.gate.abort_reservation(
                expired.reservation_id,
                "merge-broker:fixture",
                expired.fencing_token,
                "operator reconciled expired broker process",
            )
            self.assertEqual(aborted.state, "aborted")
            clock.value = 112
            replacement = fixture.gate.reserve_current_eligibility(
                eligible.decision_digest,
                "replacement-after-abort",
                "merge-broker:fixture",
                main,
            )
            self.assertGreater(replacement.fencing_token, expired.fencing_token)
            clock.value = 113
            renewed = fixture.gate.renew_reservation(
                replacement.reservation_id,
                "merge-broker:fixture",
                replacement.fencing_token,
                lease_seconds=20,
            )
            self.assertEqual(renewed.expires_at, 133)

    def test_concurrent_authorization_reservation_has_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory), clock=MutableClock(100))
            eligible = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            main = str(eligible.evidence["trusted_main_commit"])
            barrier = Barrier(2)
            reservations = []
            failures = []

            def reserve(key: str) -> None:
                barrier.wait()
                try:
                    reservations.append(
                        fixture.gate.reserve_current_eligibility(
                            eligible.decision_digest,
                            key,
                            "merge-broker:fixture",
                            main,
                        )
                    )
                except StateConflict as exc:
                    failures.append(str(exc))

            threads = [
                Thread(target=reserve, args=(f"concurrent-{index}",))
                for index in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(reservations), 1)
            self.assertEqual(len(failures), 1)
            self.assertIn("already reserved", failures[0])

    def test_revision_gate_and_contract_changes_require_human_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            predecessor = dict(fixture.rfc.raw)
            predecessor_digest = "sha256:" + "9" * 64
            with fixture.state.transaction() as connection:
                connection.execute(
                    "INSERT INTO rfc_revisions VALUES (?, 0, ?, ?, ?, ?)",
                    (
                        fixture.rfc_id,
                        predecessor_digest,
                        fixture.registry.digest,
                        json.dumps(predecessor, sort_keys=True),
                        utc_now(),
                    ),
                )
                current_raw = dict(fixture.rfc.raw)
                current_raw["supersedes"] = {
                    "revision": 1,
                    "revision_digest": predecessor_digest,
                }
                current_raw["tests"] = {
                    **current_raw["tests"],
                    "level3": ["different gate"],
                }
                current_raw["contracts"] = {
                    "provides": {"shared.api": "sha256:" + "7" * 64},
                    "requires": {"dependency.api": "sha256:" + "8" * 64},
                    "definitions": {},
                }
                current = replace(fixture.rfc, revision=2, raw=current_raw)
                blockers: list[str] = []
                reasons = fixture.gate._revision_risk_reasons(
                    connection, current, blockers.append
                )
            self.assertFalse(blockers)
            self.assertTrue(any("test gate" in item for item in reasons))
            self.assertTrue(any("interface contract" in item for item in reasons))
            self.assertTrue(any("required shared interface" in item for item in reasons))

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
                "UPDATE review_runs SET independent = 0 WHERE rfc_id = ?",
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
                    fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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
                    fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
                )
                self.assertEqual(decision.disposition, BLOCKED)
                self.assertTrue(any(expected in item for item in decision.blockers))

    def test_authorization_audit_rows_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
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

    def test_reservation_events_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = complete_fixture(Path(directory))
            decision = fixture.gate.evaluate(
                fixture.rfc_id, fixture.candidate.candidate_digest, LEAD_ACTOR
            )
            reservation = fixture.gate.reserve_current_eligibility(
                decision.decision_digest,
                "immutable-event-attempt",
                "merge-broker:fixture",
                str(decision.evidence["trusted_main_commit"]),
            )
            with fixture.state.connect() as connection:
                event = connection.execute(
                    "SELECT event_id FROM merge_authorization_events "
                    "WHERE reservation_id = ?",
                    (reservation.reservation_id,),
                ).fetchone()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE merge_authorization_events SET event_type = 'CONSUMED' "
                        "WHERE event_id = ?",
                        (event["event_id"],),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "DELETE FROM merge_authorization_events WHERE event_id = ?",
                        (event["event_id"],),
                    )


if __name__ == "__main__":
    unittest.main()
