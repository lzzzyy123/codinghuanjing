"""Fail-closed, audit-only merge authorization decisions.

This module never invokes a forge API, moves a Git ref, or merges a branch.  It
only records whether an exact candidate is technically eligible for a later
operator-controlled merge step.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .git_verifier import GitVerificationError, RepositoryGitVerifier
from .models import TaskState
from .registry import Registry, RfcRevision
from .state_store import StateConflict, StateStore, utc_now
from .testing import digest_json


POLICY_VERSION = "merge-authorization/v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")

AUTO_MERGE_ELIGIBLE = "AUTO_MERGE_ELIGIBLE"
NEEDS_HUMAN_APPROVAL = "NEEDS_HUMAN_APPROVAL"
BLOCKED = "BLOCKED"

SENSITIVE_EXACT_PATHS = frozenset(
    {
        ".env",
        ".gitattributes",
        ".gitignore",
        ".gitmodules",
        ".npmrc",
        "CODEOWNERS",
        "Dockerfile",
        "PARITY.md",
        "bun.lock",
        "bunfig.toml",
        "package.json",
        "pyproject.toml",
        "pytest.ini",
        "requirements.txt",
        "tsconfig.json",
    }
)
SENSITIVE_PREFIXES = (
    ".github/",
    ".gitlab/",
    "baseline/",
    "coordination/",
    "scheduler/",
    "service/",
    "templates/",
    "tests/final/",
    "tests/differential/",
    "tests/integration/",
    "tests/parity/",
    "tests/regression/",
    "tools/",
    "worker/",
)
SENSITIVE_COMPONENTS = frozenset(
    {
        "approval",
        "approvals",
        "auth",
        "authentication",
        "authorization",
        "credential",
        "credentials",
        "permission",
        "permissions",
        "policy",
        "secret",
        "secrets",
        "security",
    }
)


@dataclass(frozen=True)
class MergeAuthorizationDecision:
    decision_id: int
    decision_digest: str
    rfc_id: str
    revision_digest: str
    candidate_digest: str
    candidate_commit: str | None
    head_ref: str | None
    disposition: str
    policy_version: str
    risk_reasons: tuple[str, ...]
    blockers: tuple[str, ...]
    evidence: dict[str, Any]
    requested_by: str
    created_at: str


class MergeAuthorizationGate:
    """Evaluate and durably record an exact, non-executing merge decision."""

    def __init__(
        self,
        registry: Registry,
        store: StateStore,
        git_verifier: RepositoryGitVerifier,
        *,
        project_lead_actors: frozenset[str] = frozenset(),
        trusted_publication_remote: str = "origin",
        trusted_main_branch: str = "main",
        approved_baseline_commit: str | None = None,
    ) -> None:
        if not project_lead_actors or any(
            not actor.strip() for actor in project_lead_actors
        ):
            raise ValueError("at least one trusted Project Lead actor is required")
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", trusted_publication_remote
        ):
            raise ValueError("invalid trusted publication remote")
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", trusted_main_branch)
            or ".." in trusted_main_branch
            or trusted_main_branch.startswith("-")
        ):
            raise ValueError("invalid trusted main branch")
        if approved_baseline_commit is None or not COMMIT_RE.fullmatch(
            approved_baseline_commit
        ):
            raise ValueError("an approved full Python baseline commit is required")
        self.registry = registry
        self.store = store
        self.git_verifier = git_verifier
        self.project_lead_actors = frozenset(project_lead_actors)
        self.trusted_publication_remote = trusted_publication_remote
        self.trusted_main_branch = trusted_main_branch
        self.approved_baseline_commit = approved_baseline_commit

    def evaluate(
        self, rfc_id: str, candidate_digest: str, requested_by: str
    ) -> MergeAuthorizationDecision:
        if rfc_id not in self.registry.rfcs:
            raise ValueError(f"unknown RFC: {rfc_id}")
        if not DIGEST_RE.fullmatch(candidate_digest):
            raise ValueError("candidate_digest must be a sha256 digest")
        if not requested_by.strip():
            raise ValueError("requested_by must be non-empty")

        rfc = self.registry.rfcs[rfc_id]
        blockers: list[str] = []
        risk_reasons: set[str] = set()
        if self.registry.baseline_commit != self.approved_baseline_commit:
            risk_reasons.add("Python baseline differs from the approved migration baseline")
        evidence: dict[str, Any] = {
            "registry_digest": self.registry.digest,
            "baseline_commit": self.registry.baseline_commit,
            "required_contracts": dict(sorted(rfc.requires.items())),
            "provided_contracts": dict(sorted(rfc.provides.items())),
        }

        def block(reason: str) -> None:
            if reason not in blockers:
                blockers.append(reason)

        trusted_main_commit: str | None = None
        try:
            trusted_main_commit = self.git_verifier.resolve_trusted_main()
            evidence["trusted_main_commit"] = trusted_main_commit
            live_main_commit = self.git_verifier.resolve_remote_head(
                self.trusted_publication_remote,
                f"refs/heads/{self.trusted_main_branch}",
            )
            evidence["trusted_remote_main_commit"] = live_main_commit
            if live_main_commit != trusted_main_commit:
                block("trusted local main ref is stale relative to the remote main branch")
        except (GitVerificationError, ValueError) as exc:
            block(f"trusted main verification failed: {exc}")

        with self.store.transaction() as connection:
            task = connection.execute(
                "SELECT * FROM tasks WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            if task is None:
                block("scheduler task is missing")
            else:
                evidence["task_state"] = str(task["state"])
                if task["revision_digest"] != rfc.revision_digest:
                    block("active task revision does not match the registry")
                if task["state"] != TaskState.DONE.value:
                    block("task has not completed the Level 3 integration gate")

            revision = connection.execute(
                "SELECT registry_digest, payload_json FROM rfc_revisions "
                "WHERE rfc_id = ? AND revision_digest = ?",
                (rfc_id, rfc.revision_digest),
            ).fetchone()
            if revision is None:
                block("active RFC revision evidence is missing")
            else:
                try:
                    payload = json.loads(revision["payload_json"])
                except (TypeError, json.JSONDecodeError):
                    payload = None
                if revision["registry_digest"] != self.registry.digest or payload != rfc.raw:
                    block("persisted RFC revision or interface contract is stale")

            candidate = connection.execute(
                "SELECT * FROM candidate_records WHERE rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ?",
                (rfc_id, rfc.revision_digest, candidate_digest),
            ).fetchone()
            candidate_commit: str | None = None
            head_ref: str | None = None
            changed_paths: tuple[str, ...] = ()
            expected_merge_tree: str | None = None
            if candidate is None:
                block("exact persisted Coder candidate is missing")
            else:
                candidate_commit = str(candidate["commit_sha"])
                branch = str(candidate["branch"])
                head_ref = f"refs/heads/{branch}"
                evidence.update(
                    {
                        "candidate_commit": candidate_commit,
                        "candidate_tree": str(candidate["tree_sha"]),
                        "candidate_diff_digest": str(candidate["diff_digest"]),
                        "candidate_base_commit": str(candidate["base_commit"]),
                        "candidate_author_agent": str(candidate["author_agent_id"]),
                        "head_ref": head_ref,
                    }
                )
                canonical = self._canonical_candidate_digest(candidate)
                evidence["canonical_candidate_digest"] = canonical
                if canonical != candidate_digest:
                    block("candidate digest is not canonical for its persisted Git evidence")
                if branch != f"agent/{rfc_id}":
                    block("candidate branch does not match the RFC identity")
                try:
                    self.git_verifier.require_exact_ref(head_ref, candidate_commit)
                    self.git_verifier.require_ancestor(
                        str(candidate["base_commit"]), candidate_commit
                    )
                    actual_tree = self.git_verifier.candidate_tree(candidate_commit)
                    actual_diff = self.git_verifier.candidate_diff_digest(
                        str(candidate["base_commit"]), candidate_commit
                    )
                    changed_paths = self.git_verifier.changed_paths(
                        str(candidate["base_commit"]), candidate_commit
                    )
                    if trusted_main_commit is not None:
                        expected_merge_tree = self.git_verifier.candidate_merge_tree(
                            str(candidate["base_commit"]),
                            trusted_main_commit,
                            candidate_commit,
                        )
                        evidence["candidate_merge_tree"] = expected_merge_tree
                    evidence["changed_paths"] = list(changed_paths)
                    if actual_tree != candidate["tree_sha"]:
                        block("candidate tree does not match the reviewed commit")
                    if actual_diff != candidate["diff_digest"]:
                        block("candidate diff does not match the reviewed commit")
                except (GitVerificationError, ValueError) as exc:
                    block(f"Git candidate verification failed: {exc}")

                for path in changed_paths:
                    if not self._owned_by(rfc, path):
                        block(f"candidate changes unowned path: {path}")
                    if self._captured_by(path, self.registry.frozen_control_paths):
                        block(f"candidate changes frozen control path: {path}")

            risk_reasons.update(self._risk_reasons(rfc, changed_paths))
            risk_reasons.update(self._revision_risk_reasons(connection, rfc, block))

            coder = self._passed_job(
                connection, rfc_id, rfc.revision_digest, candidate_digest, "coding"
            )
            coder_result: dict[str, Any] = {}
            if coder is None:
                block("Coder completion evidence is missing for the exact candidate")
            else:
                evidence["coding_job_id"] = int(coder["job_id"])
                coder_result = self._result(coder)
                if candidate is None or any(
                    coder_result.get(key) != candidate[column]
                    for key, column in (
                        ("commit_sha", "commit_sha"),
                        ("tree_sha", "tree_sha"),
                        ("diff_digest", "diff_digest"),
                    )
                ):
                    block("Coder result does not identify the persisted candidate")

            level_runs: dict[int, sqlite3.Row | None] = {}
            for level, commands in (
                (1, rfc.level1_tests),
                (2, rfc.level2_tests),
                (3, rfc.level3_tests),
            ):
                if not commands:
                    block(f"RFC has no Level {level} gate")
                    level_runs[level] = None
                    continue
                baseline = None if level == 1 else self.registry.baseline_commit
                level3_tree = (
                    expected_merge_tree
                    if level == 3 and candidate is not None and trusted_main_commit is not None
                    else None
                )
                level3_clause = (
                    "AND trusted_main_commit = ? AND candidate_merge_tree = ? "
                    if level == 3
                    else ""
                )
                parameters: tuple[Any, ...] = (
                    rfc_id,
                    rfc.revision_digest,
                    candidate_digest,
                    level,
                    digest_json(list(commands)),
                    baseline,
                )
                if level == 3:
                    parameters += (trusted_main_commit, level3_tree)
                query = (
                    "SELECT * FROM test_runs WHERE rfc_id = ? AND revision_digest = ? "
                    "AND candidate_digest = ? AND level = ? AND command_digest = ? "
                    "AND baseline_commit IS ? AND status = 'PASS' "
                    + level3_clause
                    + "ORDER BY test_run_id DESC LIMIT 1"
                )
                run = connection.execute(query, parameters).fetchone()
                level_runs[level] = run
                if run is None:
                    label = "module and Python differential" if level == 2 else f"Level {level}"
                    block(f"{label} PASS evidence is missing for the exact candidate")
                else:
                    evidence[f"level{level}_test_run_id"] = int(run["test_run_id"])
                    evidence[f"level{level}_evidence_digest"] = str(
                        run["evidence_digest"]
                    )

            level1 = level_runs.get(1)
            if coder is not None and (
                level1 is None
                or coder_result.get("level1_evidence") != level1["evidence_digest"]
            ):
                block("Coder result is not bound to the Level 1 evidence")

            level2_job = self._passed_job(
                connection, rfc_id, rfc.revision_digest, candidate_digest, "test_l2"
            )
            if level2_job is None:
                block("module and Python differential job did not pass")
            else:
                evidence["level2_job_id"] = int(level2_job["job_id"])
                level2 = level_runs.get(2)
                if level2 is None or self._result(level2_job).get("evidence") != level2[
                    "evidence_digest"
                ]:
                    block("Level 2 job result is not bound to its test evidence")

            integration = self._passed_job(
                connection, rfc_id, rfc.revision_digest, candidate_digest, "integration"
            )
            if integration is None:
                block("integration job did not pass for the exact candidate")
            else:
                evidence["integration_job_id"] = int(integration["job_id"])
                level3 = level_runs.get(3)
                if level3 is None or self._result(integration).get(
                    "level3_evidence"
                ) != level3["evidence_digest"]:
                    block("integration job result is not bound to the Level 3 evidence")

            approval = self._project_lead_approval(
                connection,
                rfc_id,
                rfc.revision_digest,
                candidate_digest,
                self.project_lead_actors,
            )
            review = None
            if approval is None:
                block("Project Lead approval is missing for the exact candidate")
            else:
                review_id, actor, sequence = approval
                evidence.update(
                    {
                        "project_lead_actor": actor,
                        "project_lead_transition_sequence": sequence,
                        "review_run_id": review_id,
                    }
                )
                review = connection.execute(
                    "SELECT * FROM review_runs WHERE review_run_id = ? AND rfc_id = ? "
                    "AND revision_digest = ? AND candidate_digest = ? AND verdict = 'PASS' "
                    "AND infrastructure_status = 'PASS' AND schema_valid = 1 "
                    "AND independent = 1",
                    (review_id, rfc_id, rfc.revision_digest, candidate_digest),
                ).fetchone()
                if review is None:
                    block("Project Lead approval is not bound to an independent Reviewer PASS")
            if review is not None:
                evidence["review_evidence_digest"] = str(review["evidence_digest"])
                review_job = self._passed_job(
                    connection, rfc_id, rfc.revision_digest, candidate_digest, "review"
                )
                if review_job is None:
                    block("Reviewer job PASS evidence is missing for the exact candidate")
                else:
                    evidence["review_job_id"] = int(review_job["job_id"])
                    review_result = self._result(review_job)
                    if (
                        review_result.get("evidence") != review["evidence_digest"]
                        or review_result.get("verdict") != "PASS"
                        or review_result.get("infrastructure_status") != "PASS"
                    ):
                        block("Reviewer job result is not bound to the approved review")

            if candidate is not None:
                ref_name = f"refs/heads/{candidate['branch']}"
                publication = connection.execute(
                    "SELECT publication_id FROM publication_records WHERE rfc_id = ? "
                    "AND revision_digest = ? AND candidate_digest = ? AND ref_name = ? "
                    "AND target_commit = ? AND remote = ? AND state = 'confirmed' "
                    "AND observed_commit = target_commit AND last_error IS NULL "
                    "ORDER BY publication_id DESC LIMIT 1",
                    (
                        rfc_id,
                        rfc.revision_digest,
                        candidate_digest,
                        ref_name,
                        candidate["commit_sha"],
                        self.trusted_publication_remote,
                    ),
                ).fetchone()
                if publication is None:
                    block("confirmed remote publication is missing for the exact candidate")
                else:
                    evidence["publication_id"] = int(publication["publication_id"])
                    evidence["publication_remote"] = self.trusted_publication_remote
                    try:
                        remote_commit = self.git_verifier.resolve_remote_head(
                            self.trusted_publication_remote, ref_name
                        )
                        evidence["publication_remote_commit"] = remote_commit
                        if remote_commit != candidate["commit_sha"]:
                            block("trusted remote ref does not identify the reviewed candidate")
                    except (GitVerificationError, ValueError) as exc:
                        block(f"trusted remote publication verification failed: {exc}")
                unresolved = connection.execute(
                    "SELECT state FROM publication_records WHERE ref_name = ? "
                    "AND state IN ('prepared', 'published', 'blocked') LIMIT 1",
                    (ref_name,),
                ).fetchone()
                if unresolved is not None:
                    block(
                        "candidate ref has unresolved publication state: "
                        f"{unresolved['state']}"
                    )

            active_lease = connection.execute(
                "SELECT leases.lease_id FROM leases JOIN jobs USING(job_id) "
                "WHERE jobs.rfc_id = ? LIMIT 1",
                (rfc_id,),
            ).fetchone()
            if active_lease is not None:
                block("RFC still has an active executor lease")
            migration_blocker = connection.execute(
                "SELECT blocker_key FROM migration_blockers WHERE resolved_at IS NULL "
                "ORDER BY blocker_key LIMIT 1"
            ).fetchone()
            if migration_blocker is not None:
                block(
                    "scheduler migration blocker is unresolved: "
                    f"{migration_blocker['blocker_key']}"
                )
            existing_merge = connection.execute(
                "SELECT rfc_id FROM merge_records WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            if existing_merge is not None:
                block("RFC already has merge evidence; authorization will not be replayed")

            if candidate is not None:
                self._check_base_delivery(connection, candidate, evidence, block)
                self._check_dependencies(connection, rfc, candidate, evidence, block)

            blockers.sort()
            risks = sorted(risk_reasons)
            if blockers:
                disposition = BLOCKED
            elif risks:
                disposition = NEEDS_HUMAN_APPROVAL
            else:
                disposition = AUTO_MERGE_ELIGIBLE

            decision_payload = {
                "rfc_id": rfc_id,
                "revision_digest": rfc.revision_digest,
                "candidate_digest": candidate_digest,
                "candidate_commit": candidate_commit,
                "head_ref": head_ref,
                "disposition": disposition,
                "policy_version": POLICY_VERSION,
                "risk_reasons": risks,
                "blockers": blockers,
                "evidence": evidence,
                "requested_by": requested_by,
            }
            decision_digest = self._digest(decision_payload)
            existing = connection.execute(
                "SELECT * FROM merge_authorization_decisions WHERE decision_digest = ?",
                (decision_digest,),
            ).fetchone()
            if existing is None:
                created_at = utc_now()
                cursor = connection.execute(
                    "INSERT INTO merge_authorization_decisions "
                    "(decision_digest, rfc_id, revision_digest, candidate_digest, "
                    "candidate_commit, head_ref, disposition, policy_version, risk_json, "
                    "blockers_json, evidence_json, requested_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        decision_digest,
                        rfc_id,
                        rfc.revision_digest,
                        candidate_digest,
                        candidate_commit,
                        head_ref,
                        disposition,
                        POLICY_VERSION,
                        json.dumps(risks, sort_keys=True),
                        json.dumps(blockers, sort_keys=True),
                        json.dumps(evidence, sort_keys=True),
                        requested_by,
                        created_at,
                    ),
                )
                decision_id = int(cursor.lastrowid)
            else:
                decision_id = int(existing["decision_id"])
                created_at = str(existing["created_at"])

        return MergeAuthorizationDecision(
            decision_id=decision_id,
            decision_digest=decision_digest,
            rfc_id=rfc_id,
            revision_digest=rfc.revision_digest,
            candidate_digest=candidate_digest,
            candidate_commit=candidate_commit,
            head_ref=head_ref,
            disposition=disposition,
            policy_version=POLICY_VERSION,
            risk_reasons=tuple(risks),
            blockers=tuple(blockers),
            evidence=evidence,
            requested_by=requested_by,
            created_at=created_at,
        )

    def require_current_eligibility(
        self, decision_digest: str
    ) -> MergeAuthorizationDecision:
        """Re-evaluate an immutable decision immediately before any later executor uses it."""
        if not DIGEST_RE.fullmatch(decision_digest):
            raise ValueError("decision_digest must be a sha256 digest")
        with self.store.connect() as connection:
            row = connection.execute(
                "SELECT * FROM merge_authorization_decisions WHERE decision_digest = ?",
                (decision_digest,),
            ).fetchone()
        if row is None:
            raise StateConflict("merge authorization decision does not exist")
        prior = self._decision(row)
        if prior.disposition != AUTO_MERGE_ELIGIBLE:
            raise StateConflict("merge authorization decision is not auto-merge eligible")
        current = self.evaluate(
            prior.rfc_id, prior.candidate_digest, prior.requested_by
        )
        if (
            current.decision_digest != decision_digest
            or current.disposition != AUTO_MERGE_ELIGIBLE
        ):
            raise StateConflict("merge authorization decision is stale; current evidence differs")
        return current

    def history(self, rfc_id: str) -> tuple[MergeAuthorizationDecision, ...]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM merge_authorization_decisions WHERE rfc_id = ? "
                "ORDER BY decision_id",
                (rfc_id,),
            ).fetchall()
        return tuple(self._decision(row) for row in rows)

    def _check_base_delivery(
        self, connection, candidate, evidence: dict[str, Any], block
    ) -> None:
        if self.registry.base_delivery_rfc is None:
            return
        row = connection.execute(
            "SELECT * FROM base_delivery_records WHERE required_rfc_id = ?",
            (self.registry.base_delivery_rfc,),
        ).fetchone()
        if (
            row is None
            or row["required_commit"] != self.registry.base_delivery_commit
            or not row["ancestor_verified"]
            or not isinstance(row["trusted_main_commit"], str)
            or not COMMIT_RE.fullmatch(row["trusted_main_commit"])
        ):
            block("external base delivery evidence is missing or stale")
            return
        try:
            self.git_verifier.require_ancestor(
                str(row["merged_base_commit"]), str(candidate["base_commit"])
            )
        except (GitVerificationError, ValueError) as exc:
            block(f"candidate base does not contain the approved external base: {exc}")
            return
        evidence["base_delivery_commit"] = str(row["merged_base_commit"])

    def _check_dependencies(
        self,
        connection,
        rfc: RfcRevision,
        candidate,
        evidence: dict[str, Any],
        block,
    ) -> None:
        available: dict[str, str] = {}
        dependency_evidence: dict[str, Any] = {}
        for dependency in rfc.depends_on:
            expected = self.registry.rfcs[dependency]
            merge = connection.execute(
                "SELECT * FROM merge_records WHERE rfc_id = ?", (dependency,)
            ).fetchone()
            if merge is None:
                block(f"dependency {dependency} has not been merged")
                continue
            required_fields = (
                "candidate_digest",
                "candidate_commit",
                "review_run_id",
                "level3_test_run_id",
                "merge_commit",
                "trusted_main_commit",
            )
            if merge["revision_digest"] != expected.revision_digest or any(
                not merge[field] for field in required_fields
            ):
                block(f"dependency {dependency} has incomplete or legacy merge evidence")
                continue
            dep_candidate = connection.execute(
                "SELECT 1 FROM candidate_records WHERE rfc_id = ? AND revision_digest = ? "
                "AND candidate_digest = ? AND commit_sha = ?",
                (
                    dependency,
                    expected.revision_digest,
                    merge["candidate_digest"],
                    merge["candidate_commit"],
                ),
            ).fetchone()
            dep_review = connection.execute(
                "SELECT 1 FROM review_runs WHERE review_run_id = ? AND rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND verdict = 'PASS' "
                "AND infrastructure_status = 'PASS' AND schema_valid = 1 "
                "AND independent = 1",
                (
                    merge["review_run_id"],
                    dependency,
                    expected.revision_digest,
                    merge["candidate_digest"],
                ),
            ).fetchone()
            dep_level3 = connection.execute(
                "SELECT 1 FROM test_runs WHERE test_run_id = ? AND rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND level = 3 "
                "AND status = 'PASS'",
                (
                    merge["level3_test_run_id"],
                    dependency,
                    expected.revision_digest,
                    merge["candidate_digest"],
                ),
            ).fetchone()
            if dep_candidate is None or dep_review is None or dep_level3 is None:
                block(f"dependency {dependency} merge evidence is not candidate-pinned")
                continue
            try:
                contracts = json.loads(merge["contracts_json"])
            except (TypeError, json.JSONDecodeError):
                contracts = None
            if contracts != expected.provides:
                block(f"dependency {dependency} interface contract evidence is stale")
                continue
            try:
                self.git_verifier.require_ancestor(
                    str(merge["merge_commit"]), str(candidate["base_commit"])
                )
            except (GitVerificationError, ValueError) as exc:
                block(f"candidate base omits dependency {dependency}: {exc}")
                continue
            available.update(contracts)
            dependency_evidence[dependency] = {
                "revision_digest": str(merge["revision_digest"]),
                "merge_commit": str(merge["merge_commit"]),
                "review_run_id": int(merge["review_run_id"]),
                "level3_test_run_id": int(merge["level3_test_run_id"]),
            }
        for name, digest in rfc.requires.items():
            if available.get(name) != digest:
                block(f"required interface contract {name} is not available at {digest}")
        evidence["dependencies"] = dependency_evidence

    def _risk_reasons(
        self, rfc: RfcRevision, changed_paths: tuple[str, ...]
    ) -> set[str]:
        reasons: set[str] = set()
        shared_files = {
            path for resource in self.registry.shared_resources.values() for path in resource.files
        }
        descriptor = f"{rfc.capability_group} {rfc.title}".lower()
        if any(token in descriptor for token in SENSITIVE_COMPONENTS):
            reasons.add("security, permission, credential, or approval policy capability")
        for path in changed_paths:
            lowered = path.lower()
            components = set(re.split(r"[^a-z0-9]+", lowered))
            if path in shared_files:
                reasons.add(f"broker-managed shared resource: {path}")
            if path in SENSITIVE_EXACT_PATHS or lowered.startswith(SENSITIVE_PREFIXES):
                reasons.add(f"protected control or gate path: {path}")
            if components.intersection(SENSITIVE_COMPONENTS):
                reasons.add(f"security, permission, or credential path: {path}")
        return reasons

    def _revision_risk_reasons(self, connection, rfc: RfcRevision, block) -> set[str]:
        if rfc.revision == 1:
            return set()
        supersedes = rfc.raw.get("supersedes")
        predecessor_digest = (
            supersedes.get("revision_digest") if isinstance(supersedes, dict) else None
        )
        row = connection.execute(
            "SELECT payload_json FROM rfc_revisions WHERE rfc_id = ? "
            "AND revision_digest = ?",
            (rfc.rfc_id, predecessor_digest),
        ).fetchone()
        if row is None:
            block("superseded RFC revision is unavailable for risk comparison")
            return set()
        try:
            previous = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            block("superseded RFC revision is malformed")
            return set()
        reasons: set[str] = set()
        if previous.get("tests") != rfc.raw.get("tests"):
            reasons.add("test gate definition changed from the superseded RFC revision")
        previous_contracts = previous.get("contracts", {})
        current_contracts = rfc.raw.get("contracts", {})
        if previous_contracts.get("provides", {}) != current_contracts.get("provides", {}):
            reasons.add("provided shared interface contract changed from the superseded revision")
        return reasons

    @staticmethod
    def _owned_by(rfc: RfcRevision, path: str) -> bool:
        return path in rfc.target_files or any(
            path.startswith(prefix + "/") for prefix in rfc.target_prefixes
        )

    @staticmethod
    def _captured_by(path: str, prefixes: tuple[str, ...]) -> bool:
        return any(path == prefix or path.startswith(prefix + "/") for prefix in prefixes)

    @staticmethod
    def _passed_job(connection, rfc_id, revision_digest, candidate_digest, kind):
        candidate_clause = (
            "AND (candidate_digest = ? OR candidate_digest IS NULL) "
            if kind == "coding"
            else "AND candidate_digest = ? "
        )
        rows = connection.execute(
            "SELECT * FROM jobs WHERE rfc_id = ? AND revision_digest = ? "
            + candidate_clause
            + "AND kind = ? AND state = 'passed' "
            "ORDER BY job_id DESC",
            (rfc_id, revision_digest, candidate_digest, kind),
        ).fetchall()
        for row in rows:
            result = MergeAuthorizationGate._result(row)
            if result.get("candidate_digest") == candidate_digest:
                return row
        return None

    @staticmethod
    def _result(row) -> dict[str, Any]:
        try:
            result = json.loads(row["result_json"])
        except (TypeError, json.JSONDecodeError):
            return {}
        return result if isinstance(result, dict) else {}

    @staticmethod
    def _project_lead_approval(
        connection,
        rfc_id,
        revision_digest,
        candidate_digest,
        trusted_actors: frozenset[str],
    ):
        rows = connection.execute(
            "SELECT sequence, actor, metadata_json FROM transitions WHERE rfc_id = ? "
            "AND revision_digest = ? AND from_state = ? AND to_state = ? "
            "ORDER BY sequence DESC",
            (
                rfc_id,
                revision_digest,
                TaskState.LEAD_REVIEW.value,
                TaskState.INTEGRATION_READY.value,
            ),
        ).fetchall()
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"])
                review_id = metadata.get("review_run_id")
            except (TypeError, json.JSONDecodeError, AttributeError):
                continue
            actor = str(row["actor"])
            if (
                metadata.get("candidate_digest") == candidate_digest
                and isinstance(review_id, int)
                and actor in trusted_actors
            ):
                return review_id, actor, int(row["sequence"])
        return None

    @staticmethod
    def _canonical_candidate_digest(candidate) -> str:
        evidence = {
            "base_commit": str(candidate["base_commit"]),
            "branch": str(candidate["branch"]),
            "commit_sha": str(candidate["commit_sha"]),
            "diff_digest": str(candidate["diff_digest"]),
            "revision_digest": str(candidate["revision_digest"]),
            "rfc_id": str(candidate["rfc_id"]),
            "tree_sha": str(candidate["tree_sha"]),
        }
        return MergeAuthorizationGate._digest(evidence)

    @staticmethod
    def _digest(value: Any) -> str:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _decision(row) -> MergeAuthorizationDecision:
        return MergeAuthorizationDecision(
            decision_id=int(row["decision_id"]),
            decision_digest=str(row["decision_digest"]),
            rfc_id=str(row["rfc_id"]),
            revision_digest=str(row["revision_digest"]),
            candidate_digest=str(row["candidate_digest"]),
            candidate_commit=row["candidate_commit"],
            head_ref=row["head_ref"],
            disposition=str(row["disposition"]),
            policy_version=str(row["policy_version"]),
            risk_reasons=tuple(json.loads(row["risk_json"])),
            blockers=tuple(json.loads(row["blockers_json"])),
            evidence=json.loads(row["evidence_json"]),
            requested_by=str(row["requested_by"]),
            created_at=str(row["created_at"]),
        )
