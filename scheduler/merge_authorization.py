"""Fail-closed, audit-only merge authorization decisions.

This module never invokes a forge API, moves a Git ref, or merges a branch.  It
only records whether an exact candidate is technically eligible for a later
operator-controlled merge step.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .git_verifier import GitVerificationError, RepositoryGitVerifier
from .merge_cas import AtomicMergeCas
from .models import TaskState
from .registry import Registry, RfcRevision
from .state_store import StateConflict, StateStore, utc_now
from .testing import digest_json


POLICY_VERSION = "merge-authorization/v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
APPROVAL_ACTOR_RE = re.compile(r"^project-lead:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
APPROVAL_CHANNEL_RE = re.compile(
    r"^(?:mac-codex|github):[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"
)
MERGE_BROKER_RE = re.compile(r"^merge-broker:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
RESERVATION_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
ATTESTATION_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")

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
        "token",
        "tokens",
        "secret",
        "secrets",
        "security",
    }
)
SENSITIVE_GATE_COMPONENTS = frozenset(
    {"baseline", "baselines", "differential", "gate", "gates", "parity"}
)
DIFFERENTIAL_INFRA_COMPONENTS = frozenset(
    {
        "fixture",
        "fixtures",
        "framework",
        "golden",
        "goldens",
        "harness",
        "infrastructure",
        "oracle",
        "oracles",
    }
)
CREDENTIAL_BASENAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        "authorized_keys",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
        "secrets.json",
        "ssh_config",
        "token",
        "tokens.json",
    }
)
MAX_RESERVATION_LEASE_SECONDS = 3600


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


@dataclass(frozen=True)
class TrustedApprovalPrincipal:
    actor: str
    channel: str


def sign_project_lead_attestation(
    key: bytes,
    *,
    rfc_id: str,
    revision_digest: str,
    candidate_digest: str,
    review_run_id: int,
    actor: str,
    channel: str,
    evidence_digest: str,
) -> str:
    """Sign an exact Project Lead approval without persisting its secret key."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("Project Lead attestation key must contain at least 32 bytes")
    payload = {
        "actor": actor,
        "candidate_digest": candidate_digest,
        "channel": channel,
        "evidence_digest": evidence_digest,
        "review_run_id": review_run_id,
        "revision_digest": revision_digest,
        "rfc_id": rfc_id,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "hmac-sha256:" + hmac.new(key, encoded, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class MergeAuthorizationReservation:
    reservation_id: str
    reservation_key: str
    decision_digest: str
    authorization_subject_digest: str
    rfc_id: str
    candidate_digest: str
    holder_identity: str
    expected_trusted_main_commit: str
    fencing_token: int
    state: str
    expires_at: float
    created_at: str
    updated_at: str


class MergeAuthorizationGate:
    """Evaluate and durably record an exact, non-executing merge decision."""

    def __init__(
        self,
        registry: Registry,
        store: StateStore,
        git_verifier: RepositoryGitVerifier,
        *,
        project_lead_principals: frozenset[TrustedApprovalPrincipal] = frozenset(),
        project_lead_attestation_keys: Mapping[TrustedApprovalPrincipal, bytes]
        | None = None,
        trusted_publication_remote: str = "origin",
        trusted_remote_url: str | None = None,
        trusted_main_branch: str = "main",
        approved_baseline_commit: str | None = None,
        clock: Callable[[], float] = time.time,
        merge_cas: AtomicMergeCas | None = None,
    ) -> None:
        if not project_lead_principals:
            raise ValueError("at least one trusted Project Lead principal is required")
        for principal in project_lead_principals:
            if (
                not isinstance(principal, TrustedApprovalPrincipal)
                or not APPROVAL_ACTOR_RE.fullmatch(principal.actor)
                or not APPROVAL_CHANNEL_RE.fullmatch(principal.channel)
            ):
                raise ValueError("invalid trusted Project Lead principal")
        attestation_keys = dict(project_lead_attestation_keys or {})
        if set(attestation_keys) != set(project_lead_principals):
            raise ValueError(
                "every trusted Project Lead principal requires exactly one attestation key"
            )
        if any(
            not isinstance(key, bytes) or len(key) < 32
            for key in attestation_keys.values()
        ):
            raise ValueError("Project Lead attestation keys must contain at least 32 bytes")
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
        if trusted_remote_url is None:
            raise ValueError("a pinned trusted remote URL is required")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self.registry = registry
        self.store = store
        self.git_verifier = git_verifier
        self.project_lead_principals = frozenset(project_lead_principals)
        self.project_lead_attestation_keys = attestation_keys
        self.trusted_publication_remote = trusted_publication_remote
        self.trusted_repository_identity = git_verifier.normalize_remote_identity(
            trusted_remote_url
        )
        self.trusted_main_branch = trusted_main_branch
        self.approved_baseline_commit = approved_baseline_commit
        self.clock = clock
        if (
            merge_cas is not None
            and merge_cas.repository_identity != self.trusted_repository_identity
        ):
            raise ValueError("merge CAS repository identity does not match trusted remote")
        self.merge_cas = merge_cas

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
            "trusted_repository_identity": self.trusted_repository_identity,
        }

        def block(reason: str) -> None:
            if reason not in blockers:
                blockers.append(reason)

        trusted_main_commit: str | None = None
        try:
            actual_remote_identity = self.git_verifier.remote_identity(
                self.trusted_publication_remote
            )
            evidence["observed_repository_identity"] = actual_remote_identity
            if actual_remote_identity != self.trusted_repository_identity:
                block("Git remote does not match the pinned repository identity")
            trusted_main_commit = self.git_verifier.resolve_trusted_main()
            evidence["trusted_main_commit"] = trusted_main_commit
            live_main_commit = self.git_verifier.resolve_pinned_remote_head(
                self.trusted_publication_remote,
                self.trusted_repository_identity,
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
                self.project_lead_principals,
                self.project_lead_attestation_keys,
            )
            review = None
            if approval is None:
                block("Project Lead approval is missing for the exact candidate")
            else:
                (
                    review_id,
                    actor,
                    channel,
                    approval_evidence,
                    approval_attestation,
                    sequence,
                ) = approval
                evidence.update(
                    {
                        "project_lead_actor": actor,
                        "project_lead_channel": channel,
                        "project_lead_approval_evidence": approval_evidence,
                        "project_lead_approval_attestation": approval_attestation,
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
                        remote_commit = self.git_verifier.resolve_pinned_remote_head(
                            self.trusted_publication_remote,
                            self.trusted_repository_identity,
                            ref_name,
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

    def _require_current_eligibility(
        self, decision_digest: str, expected_trusted_main_commit: str
    ) -> MergeAuthorizationDecision:
        """Re-evaluate an immutable decision for reservation/consumption only."""
        if not DIGEST_RE.fullmatch(decision_digest):
            raise ValueError("decision_digest must be a sha256 digest")
        if not COMMIT_RE.fullmatch(expected_trusted_main_commit):
            raise ValueError("expected trusted-main commit must be a full Git SHA")
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
            or current.evidence.get("trusted_main_commit")
            != expected_trusted_main_commit
            or current.evidence.get("trusted_remote_main_commit")
            != expected_trusted_main_commit
        ):
            raise StateConflict("merge authorization decision is stale; current evidence differs")
        return current

    def reserve_current_eligibility(
        self,
        decision_digest: str,
        reservation_key: str,
        holder_identity: str,
        expected_trusted_main_commit: str,
        *,
        lease_seconds: float = 300,
    ) -> MergeAuthorizationReservation:
        """Reserve one decision for a single fenced future merge attempt."""
        self._validate_reservation_identity(reservation_key, holder_identity, lease_seconds)
        current = self._require_current_eligibility(
            decision_digest, expected_trusted_main_commit
        )
        subject_digest = self._authorization_subject_digest(current)
        timestamp = self._clock_now()
        now_text = utc_now()
        with self.store.transaction() as connection:
            existing_key = connection.execute(
                "SELECT * FROM merge_authorization_reservations WHERE reservation_key = ?",
                (reservation_key,),
            ).fetchone()
            if existing_key is not None:
                if (
                    existing_key["decision_digest"] == decision_digest
                    and existing_key["authorization_subject_digest"] == subject_digest
                    and existing_key["holder_identity"] == holder_identity
                    and existing_key["expected_trusted_main_commit"]
                    == expected_trusted_main_commit
                    and existing_key["state"] == "reserved"
                    and float(existing_key["expires_at"]) > timestamp
                ):
                    return self._reservation(existing_key)
                raise StateConflict("reservation key was already used with different state")

            active = connection.execute(
                "SELECT state, expires_at FROM merge_authorization_reservations "
                "WHERE authorization_subject_digest = ? "
                "AND state IN ('reserved', 'consumed')",
                (subject_digest,),
            ).fetchone()
            if active is not None:
                suffix = (
                    " and is expired pending explicit abort"
                    if active["state"] == "reserved"
                    and float(active["expires_at"]) <= timestamp
                    else ""
                )
                raise StateConflict(
                    f"merge authorization is already {active['state']}{suffix}"
                )

            connection.execute(
                "INSERT INTO merge_authorization_subject_fences VALUES (?, 1) "
                "ON CONFLICT(authorization_subject_digest) DO UPDATE "
                "SET last_token = last_token + 1",
                (subject_digest,),
            )
            fencing_token = int(
                connection.execute(
                    "SELECT last_token FROM merge_authorization_subject_fences "
                    "WHERE authorization_subject_digest = ?",
                    (subject_digest,),
                ).fetchone()["last_token"]
            )
            reservation_id = str(uuid.uuid4())
            expires_at = timestamp + lease_seconds
            try:
                connection.execute(
                    "INSERT INTO merge_authorization_reservations "
                    "(reservation_id, reservation_key, decision_digest, "
                    "authorization_subject_digest, rfc_id, "
                    "candidate_digest, holder_identity, expected_trusted_main_commit, "
                    "fencing_token, state, expires_at, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?)",
                    (
                        reservation_id,
                        reservation_key,
                        decision_digest,
                        subject_digest,
                        current.rfc_id,
                        current.candidate_digest,
                        holder_identity,
                        expected_trusted_main_commit,
                        fencing_token,
                        expires_at,
                        now_text,
                        now_text,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StateConflict("merge authorization reservation raced") from exc
            self._append_reservation_event(
                connection,
                reservation_id,
                "RESERVED",
                fencing_token,
                holder_identity,
                {
                    "decision_digest": decision_digest,
                    "expected_trusted_main_commit": expected_trusted_main_commit,
                    "expires_at": expires_at,
                },
            )
            row = connection.execute(
                "SELECT * FROM merge_authorization_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        return self._reservation(row)

    def renew_reservation(
        self,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
        *,
        lease_seconds: float = 300,
    ) -> MergeAuthorizationReservation:
        self._validate_reservation_identity("renewal", holder_identity, lease_seconds)
        timestamp = self._clock_now()
        with self.store.transaction() as connection:
            row = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
            if row["state"] != "reserved" or float(row["expires_at"]) <= timestamp:
                raise StateConflict("only a live reservation can be renewed")
            expires_at = timestamp + lease_seconds
            updated = connection.execute(
                "UPDATE merge_authorization_reservations SET expires_at = ?, updated_at = ? "
                "WHERE reservation_id = ? AND holder_identity = ? AND fencing_token = ? "
                "AND state = 'reserved' AND expires_at > ?",
                (
                    expires_at,
                    utc_now(),
                    reservation_id,
                    holder_identity,
                    fencing_token,
                    timestamp,
                ),
            )
            if updated.rowcount != 1:
                raise StateConflict("reservation changed during renewal")
            self._append_reservation_event(
                connection,
                reservation_id,
                "RENEWED",
                fencing_token,
                holder_identity,
                {"expires_at": expires_at},
            )
            renewed = connection.execute(
                "SELECT * FROM merge_authorization_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        return self._reservation(renewed)

    def consume_reserved_eligibility(
        self,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
        expected_trusted_main_commit: str,
        merge_target_commit: str,
    ) -> MergeAuthorizationReservation:
        """Consume only as the outcome of the configured atomic remote merge CAS."""
        with self.store.connect() as connection:
            initial = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
        if initial["expected_trusted_main_commit"] != expected_trusted_main_commit:
            raise StateConflict("reservation trusted-main CAS input does not match")
        return self.execute_reserved_merge(
            reservation_id,
            holder_identity,
            fencing_token,
            merge_target_commit,
        )

    def execute_reserved_merge(
        self,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
        merge_target_commit: str,
    ) -> MergeAuthorizationReservation:
        """Execute one recoverable atomic remote CAS; production wiring is absent."""
        if not COMMIT_RE.fullmatch(merge_target_commit):
            raise ValueError("merge target must be a full Git SHA")
        if self.merge_cas is None:
            raise StateConflict("merge CAS executor is not configured")
        merge_cas = self.merge_cas
        with self.store.connect() as connection:
            initial = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
            existing_attempt = connection.execute(
                "SELECT attempt_id, state FROM merge_execution_attempts "
                "WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        if existing_attempt is not None and existing_attempt["state"] != "failed":
            return self.reconcile_reserved_merge(
                reservation_id, holder_identity, fencing_token
            )
        if initial["state"] != "reserved":
            raise StateConflict("only a reserved authorization can execute a merge CAS")
        expected_main = str(initial["expected_trusted_main_commit"])
        decision = self._require_current_eligibility(
            str(initial["decision_digest"]), expected_main
        )
        if decision.candidate_commit is None or decision.head_ref is None:
            raise StateConflict("authorization decision has no candidate Git binding")
        if merge_cas.repository_identity != self.trusted_repository_identity:
            raise StateConflict("merge CAS repository identity does not match authorization")
        if float(initial["expires_at"]) - self._clock_now() <= float(
            merge_cas.maximum_duration_seconds
        ):
            raise StateConflict("reservation lease cannot cover the bounded merge CAS")
        try:
            self.git_verifier.require_ancestor(
                expected_main, merge_target_commit
            )
            self.git_verifier.require_ancestor(
                decision.candidate_commit, merge_target_commit
            )
            target_tree = self.git_verifier.candidate_tree(merge_target_commit)
        except (GitVerificationError, ValueError) as exc:
            raise StateConflict(f"merge target is not candidate-bound: {exc}") from exc
        if target_tree != decision.evidence.get("candidate_merge_tree"):
            raise StateConflict("merge target tree differs from Level 3 reviewed tree")

        main_ref = f"refs/heads/{self.trusted_main_branch}"
        attempt_id = self._prepare_merge_attempt(
            initial,
            merge_cas.repository_identity,
            main_ref,
            decision.head_ref,
            decision.candidate_commit,
            merge_target_commit,
        )
        # Git ancestry checks and intent persistence can be slow. Re-read the
        # trusted clock at the last boundary before the bounded remote CAS.
        if float(initial["expires_at"]) - self._clock_now() <= float(
            merge_cas.maximum_duration_seconds
        ):
            self._record_merge_attempt_error(attempt_id, "LEASE_WINDOW_EXHAUSTED")
            raise StateConflict("reservation lease cannot cover the bounded merge CAS")
        try:
            merge_cas.compare_and_swap(
                reservation_id=reservation_id,
                fencing_token=fencing_token,
                expected_main_commit=expected_main,
                main_ref=main_ref,
                expected_candidate_commit=decision.candidate_commit,
                candidate_ref=decision.head_ref,
                merge_target_commit=merge_target_commit,
            )
        except Exception:
            self._record_merge_attempt_error(attempt_id, "CAS_CALL_FAILED")
            raise
        return self.reconcile_reserved_merge(
            reservation_id,
            holder_identity,
            fencing_token,
        )

    def reconcile_reserved_merge(
        self,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
    ) -> MergeAuthorizationReservation:
        """Recover after CAS success/failure by trusting remote refs, not process outcome."""
        if self.merge_cas is None:
            raise StateConflict("merge CAS executor is not configured")
        merge_cas = self.merge_cas
        with self.store.connect() as connection:
            reservation = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
            attempt = connection.execute(
                "SELECT * FROM merge_execution_attempts WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        if attempt is None:
            raise StateConflict("merge execution attempt does not exist")
        if attempt["repository_identity"] != merge_cas.repository_identity:
            raise StateConflict("merge CAS repository identity changed during recovery")
        observed_main = self.git_verifier.resolve_pinned_remote_head(
            self.trusted_publication_remote,
            self.trusted_repository_identity,
            str(attempt["main_ref"]),
        )
        observed_candidate = self.git_verifier.resolve_pinned_remote_head(
            self.trusted_publication_remote,
            self.trusted_repository_identity,
            str(attempt["candidate_ref"]),
        )
        if (
            observed_main == attempt["merge_target_commit"]
            and observed_candidate == attempt["expected_candidate_commit"]
        ):
            with self.store.transaction() as connection:
                current = self._locked_reservation(
                    connection, reservation_id, holder_identity, fencing_token
                )
                if current["state"] == "consumed":
                    return self._reservation(current)
                if current["state"] != "reserved":
                    raise StateConflict("merge CAS succeeded for a non-reserved authorization")
                updated = connection.execute(
                    "UPDATE merge_authorization_reservations SET state = 'consumed', "
                    "updated_at = ? WHERE reservation_id = ? AND holder_identity = ? "
                    "AND fencing_token = ? AND state = 'reserved'",
                    (utc_now(), reservation_id, holder_identity, fencing_token),
                )
                if updated.rowcount != 1:
                    raise StateConflict("reservation changed during merge CAS reconciliation")
                connection.execute(
                    "UPDATE merge_execution_attempts SET state = 'applied', "
                    "observed_main_commit = ?, observed_candidate_commit = ?, "
                    "error_code = NULL, updated_at = ? WHERE attempt_id = ?",
                    (observed_main, observed_candidate, utc_now(), attempt["attempt_id"]),
                )
                self._append_reservation_event(
                    connection,
                    reservation_id,
                    "MERGED",
                    fencing_token,
                    holder_identity,
                    {
                        "attempt_id": int(attempt["attempt_id"]),
                        "merge_target_commit": str(attempt["merge_target_commit"]),
                    },
                )
                row = connection.execute(
                    "SELECT * FROM merge_authorization_reservations "
                    "WHERE reservation_id = ?",
                    (reservation_id,),
                ).fetchone()
            return self._reservation(row)

        unchanged = (
            observed_main == attempt["expected_main_commit"]
            and observed_candidate == attempt["expected_candidate_commit"]
        )
        with self.store.transaction() as connection:
            connection.execute(
                "UPDATE merge_execution_attempts SET state = ?, observed_main_commit = ?, "
                "observed_candidate_commit = ?, error_code = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (
                    "failed" if unchanged else "blocked",
                    observed_main,
                    observed_candidate,
                    "CAS_NOT_APPLIED" if unchanged else "REMOTE_REF_DIVERGED",
                    utc_now(),
                    attempt["attempt_id"],
                ),
            )
            current = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
            self._append_reservation_event(
                connection,
                reservation_id,
                "MERGE_FAILED" if unchanged else "MERGE_BLOCKED",
                fencing_token,
                holder_identity,
                {
                    "attempt_id": int(attempt["attempt_id"]),
                    "observed_candidate_commit": observed_candidate,
                    "observed_main_commit": observed_main,
                },
            )
        raise StateConflict(
            "atomic merge CAS was not applied"
            if unchanged
            else "remote refs diverged during merge CAS; manual recovery is required"
        )

    def _prepare_merge_attempt(
        self,
        reservation,
        repository_identity: str,
        main_ref: str,
        candidate_ref: str,
        expected_candidate_commit: str,
        merge_target_commit: str,
    ) -> int:
        values = (
            int(reservation["fencing_token"]),
            repository_identity,
            main_ref,
            candidate_ref,
            str(reservation["expected_trusted_main_commit"]),
            expected_candidate_commit,
            merge_target_commit,
        )
        with self.store.transaction() as connection:
            current = self._locked_reservation(
                connection,
                str(reservation["reservation_id"]),
                str(reservation["holder_identity"]),
                int(reservation["fencing_token"]),
            )
            if current["state"] != "reserved":
                raise StateConflict("merge execution requires a reserved authorization")
            existing = connection.execute(
                "SELECT * FROM merge_execution_attempts WHERE reservation_id = ?",
                (reservation["reservation_id"],),
            ).fetchone()
            if existing is not None:
                existing_values = tuple(
                    existing[name]
                    for name in (
                        "fencing_token",
                        "repository_identity",
                        "main_ref",
                        "candidate_ref",
                        "expected_main_commit",
                        "expected_candidate_commit",
                        "merge_target_commit",
                    )
                )
                if existing_values != values:
                    raise StateConflict("merge execution attempt identity cannot change")
                if existing["state"] == "failed":
                    connection.execute(
                        "UPDATE merge_execution_attempts SET state = 'prepared', "
                        "error_code = NULL, updated_at = ? WHERE attempt_id = ?",
                        (utc_now(), existing["attempt_id"]),
                    )
                    self._append_reservation_event(
                        connection,
                        str(reservation["reservation_id"]),
                        "MERGE_RETRY",
                        int(reservation["fencing_token"]),
                        str(reservation["holder_identity"]),
                        {"attempt_id": int(existing["attempt_id"])},
                    )
                return int(existing["attempt_id"])
            now_text = utc_now()
            attempt_id = connection.execute(
                "INSERT INTO merge_execution_attempts "
                "(reservation_id, fencing_token, repository_identity, main_ref, "
                "candidate_ref, expected_main_commit, expected_candidate_commit, "
                "merge_target_commit, state, observed_main_commit, "
                "observed_candidate_commit, error_code, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, NULL, NULL, ?, ?)",
                (reservation["reservation_id"], *values, now_text, now_text),
            ).lastrowid
            self._append_reservation_event(
                connection,
                str(reservation["reservation_id"]),
                "MERGE_PREPARED",
                int(reservation["fencing_token"]),
                str(reservation["holder_identity"]),
                {
                    "attempt_id": int(attempt_id),
                    "expected_candidate_commit": expected_candidate_commit,
                    "expected_main_commit": str(
                        reservation["expected_trusted_main_commit"]
                    ),
                    "merge_target_commit": merge_target_commit,
                },
            )
        return int(attempt_id)

    def _record_merge_attempt_error(self, attempt_id: int, error_code: str) -> None:
        with self.store.transaction() as connection:
            updated = connection.execute(
                "UPDATE merge_execution_attempts SET error_code = ?, updated_at = ? "
                "WHERE attempt_id = ? AND state IN ('prepared', 'failed')",
                (error_code, utc_now(), attempt_id),
            )
            if updated.rowcount == 1:
                attempt = connection.execute(
                    "SELECT reservation_id, fencing_token FROM merge_execution_attempts "
                    "WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                reservation = connection.execute(
                    "SELECT holder_identity FROM merge_authorization_reservations "
                    "WHERE reservation_id = ?",
                    (attempt["reservation_id"],),
                ).fetchone()
                self._append_reservation_event(
                    connection,
                    str(attempt["reservation_id"]),
                    "MERGE_ERROR",
                    int(attempt["fencing_token"]),
                    str(reservation["holder_identity"]),
                    {"attempt_id": attempt_id, "error_code": error_code},
                )

    def abort_reservation(
        self,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
        reason: str,
    ) -> MergeAuthorizationReservation:
        if not reason.strip():
            raise ValueError("abort reason must be non-empty")
        with self.store.transaction() as connection:
            row = self._locked_reservation(
                connection, reservation_id, holder_identity, fencing_token
            )
            if row["state"] != "reserved":
                raise StateConflict("only a reserved authorization can be aborted")
            attempt = connection.execute(
                "SELECT state FROM merge_execution_attempts WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if attempt is not None and attempt["state"] != "failed":
                raise StateConflict(
                    "merge attempt must be reconciled as unchanged before abort"
                )
            updated = connection.execute(
                "UPDATE merge_authorization_reservations SET state = 'aborted', "
                "updated_at = ? WHERE reservation_id = ? AND holder_identity = ? "
                "AND fencing_token = ? AND state = 'reserved'",
                (utc_now(), reservation_id, holder_identity, fencing_token),
            )
            if updated.rowcount != 1:
                raise StateConflict("reservation changed during abort")
            self._append_reservation_event(
                connection,
                reservation_id,
                "ABORTED",
                fencing_token,
                holder_identity,
                {"reason": reason.strip()},
            )
            aborted = connection.execute(
                "SELECT * FROM merge_authorization_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
        return self._reservation(aborted)

    @staticmethod
    def _validate_reservation_identity(
        reservation_key: str, holder_identity: str, lease_seconds: float
    ) -> None:
        if not RESERVATION_KEY_RE.fullmatch(reservation_key):
            raise ValueError("invalid merge authorization reservation key")
        if not MERGE_BROKER_RE.fullmatch(holder_identity):
            raise ValueError("invalid merge broker identity")
        if (
            isinstance(lease_seconds, bool)
            or not isinstance(lease_seconds, (int, float))
            or not math.isfinite(float(lease_seconds))
            or lease_seconds <= 0
            or lease_seconds > MAX_RESERVATION_LEASE_SECONDS
        ):
            raise ValueError(
                "merge authorization lease must be positive and at most "
                f"{MAX_RESERVATION_LEASE_SECONDS} seconds"
            )

    @staticmethod
    def _locked_reservation(
        connection: sqlite3.Connection,
        reservation_id: str,
        holder_identity: str,
        fencing_token: int,
    ) -> sqlite3.Row:
        try:
            parsed_id = uuid.UUID(reservation_id)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ValueError("invalid merge authorization reservation ID") from exc
        if str(parsed_id) != reservation_id:
            raise ValueError("invalid merge authorization reservation ID")
        if not MERGE_BROKER_RE.fullmatch(holder_identity):
            raise ValueError("invalid merge broker identity")
        if (
            isinstance(fencing_token, bool)
            or not isinstance(fencing_token, int)
            or fencing_token <= 0
        ):
            raise ValueError("invalid merge authorization fencing token")
        row = connection.execute(
            "SELECT * FROM merge_authorization_reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()
        if row is None:
            raise StateConflict("merge authorization reservation does not exist")
        if (
            row["holder_identity"] != holder_identity
            or int(row["fencing_token"]) != fencing_token
        ):
            raise StateConflict("stale merge authorization holder or fencing token")
        return row

    @staticmethod
    def _append_reservation_event(
        connection: sqlite3.Connection,
        reservation_id: str,
        event_type: str,
        fencing_token: int,
        actor: str,
        payload: dict[str, Any],
    ) -> None:
        if event_type not in {
            "RESERVED",
            "RENEWED",
            "CONSUMED",
            "ABORTED",
            "MERGE_PREPARED",
            "MERGE_ERROR",
            "MERGE_FAILED",
            "MERGE_BLOCKED",
            "MERGE_RETRY",
            "MERGED",
        }:
            raise ValueError("invalid merge authorization event type")
        connection.execute(
            "INSERT INTO merge_authorization_events "
            "(reservation_id, event_type, fencing_token, actor, payload_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                reservation_id,
                event_type,
                fencing_token,
                actor,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                utc_now(),
            ),
        )

    @staticmethod
    def _reservation(row: sqlite3.Row) -> MergeAuthorizationReservation:
        if row is None:
            raise StateConflict("merge authorization reservation was not persisted")
        return MergeAuthorizationReservation(
            reservation_id=str(row["reservation_id"]),
            reservation_key=str(row["reservation_key"]),
            decision_digest=str(row["decision_digest"]),
            authorization_subject_digest=str(row["authorization_subject_digest"]),
            rfc_id=str(row["rfc_id"]),
            candidate_digest=str(row["candidate_digest"]),
            holder_identity=str(row["holder_identity"]),
            expected_trusted_main_commit=str(row["expected_trusted_main_commit"]),
            fencing_token=int(row["fencing_token"]),
            state=str(row["state"]),
            expires_at=float(row["expires_at"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def _clock_now(self) -> float:
        value = self.clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise StateConflict("trusted merge authorization clock returned invalid time")
        return float(value)

    @classmethod
    def _authorization_subject_digest(
        cls, decision: MergeAuthorizationDecision
    ) -> str:
        evidence = decision.evidence
        subject = {
            "candidate_commit": decision.candidate_commit,
            "candidate_digest": decision.candidate_digest,
            "revision_digest": decision.revision_digest,
            "rfc_id": decision.rfc_id,
            "trusted_main_commit": evidence.get("trusted_main_commit"),
            "trusted_remote_main_commit": evidence.get("trusted_remote_main_commit"),
            "trusted_repository_identity": evidence.get("trusted_repository_identity"),
        }
        if (
            not COMMIT_RE.fullmatch(str(subject["candidate_commit"]))
            or not COMMIT_RE.fullmatch(str(subject["trusted_main_commit"]))
            or subject["trusted_remote_main_commit"] != subject["trusted_main_commit"]
            or not isinstance(subject["trusted_repository_identity"], str)
            or not subject["trusted_repository_identity"]
        ):
            raise StateConflict("authorization decision has an incomplete subject binding")
        return cls._digest(subject)

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
            basename = lowered.rsplit("/", 1)[-1]
            if path in shared_files:
                reasons.add(f"broker-managed shared resource: {path}")
            if (
                path in SENSITIVE_EXACT_PATHS
                or basename in {"codeowners", ".gitattributes"}
                or lowered.startswith(SENSITIVE_PREFIXES)
            ):
                reasons.add(f"protected control or gate path: {path}")
            if components.intersection(SENSITIVE_COMPONENTS):
                reasons.add(f"security, permission, or credential path: {path}")
            if self._credential_bearing_path(lowered, components, basename):
                reasons.add(f"credential-bearing path: {path}")
            gate_semantics = components.intersection(SENSITIVE_GATE_COMPONENTS) or {
                token for token in SENSITIVE_GATE_COMPONENTS if token in lowered
            }
            ordinary_differential_test = (
                lowered.startswith("tests/differential/")
                and gate_semantics <= {"differential"}
                and not components.intersection(DIFFERENTIAL_INFRA_COMPONENTS)
            )
            if gate_semantics and not ordinary_differential_test:
                reasons.add(f"parity, differential, baseline, or test gate path: {path}")
        return reasons

    @staticmethod
    def _credential_bearing_path(
        lowered: str, components: set[str], basename: str
    ) -> bool:
        path_parts = set(lowered.split("/"))
        return (
            basename in CREDENTIAL_BASENAMES
            or basename.startswith(".env.")
            or basename.endswith((".key", ".pem", ".p12", ".pfx"))
            or ".ssh" in path_parts
            or "ssh" in components
            or "sshd" in components
            or ".aws" in path_parts
            or ".kube" in path_parts
            or ".docker" in path_parts
            or bool(
                components.intersection(
                    {"credential", "credentials", "secret", "secrets", "token", "tokens"}
                )
            )
        )

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
        if previous_contracts.get("requires", {}) != current_contracts.get("requires", {}):
            reasons.add("required shared interface contract changed from the superseded revision")
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
        trusted_principals: frozenset[TrustedApprovalPrincipal],
        attestation_keys: Mapping[TrustedApprovalPrincipal, bytes],
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
                channel = metadata.get("approval_channel")
                approval_evidence = metadata.get("approval_evidence_digest")
                approval_attestation = metadata.get("approval_attestation")
                approval_id = metadata.get("approval_id")
            except (TypeError, json.JSONDecodeError, AttributeError):
                continue
            actor = str(row["actor"])
            if (
                not isinstance(review_id, int)
                or isinstance(review_id, bool)
                or not isinstance(approval_id, int)
                or isinstance(approval_id, bool)
                or not isinstance(channel, str)
                or not isinstance(approval_evidence, str)
                or not isinstance(approval_attestation, str)
                or not ATTESTATION_RE.fullmatch(approval_attestation)
            ):
                continue
            approval_record = connection.execute(
                "SELECT 1 FROM project_lead_approvals JOIN artifacts "
                "ON artifacts.digest = project_lead_approvals.evidence_digest "
                "WHERE approval_id = ? AND rfc_id = ? AND revision_digest = ? "
                "AND candidate_digest = ? AND review_run_id = ? AND actor = ? "
                "AND channel = ? AND evidence_digest = ? AND attestation = ? "
                "AND artifacts.kind = 'project-lead-approval'",
                (
                    approval_id,
                    rfc_id,
                    revision_digest,
                    candidate_digest,
                    review_id,
                    actor,
                    channel,
                    approval_evidence,
                    approval_attestation,
                ),
            ).fetchone()
            principal = TrustedApprovalPrincipal(actor, channel)
            key = attestation_keys.get(principal)
            expected_attestation = (
                sign_project_lead_attestation(
                    key,
                    rfc_id=rfc_id,
                    revision_digest=revision_digest,
                    candidate_digest=candidate_digest,
                    review_run_id=review_id,
                    actor=actor,
                    channel=channel,
                    evidence_digest=approval_evidence,
                )
                if key is not None
                else None
            )
            if (
                metadata.get("candidate_digest") == candidate_digest
                and principal in trusted_principals
                and approval_record is not None
                and expected_attestation is not None
                and hmac.compare_digest(approval_attestation, expected_attestation)
            ):
                return (
                    review_id,
                    actor,
                    channel,
                    approval_evidence,
                    approval_attestation,
                    int(row["sequence"]),
                )
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
