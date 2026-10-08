"""Transactional multi-process job queue with leases and fencing tokens."""

from __future__ import annotations

import json
import hashlib
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .models import TaskState
from .state_store import StateConflict, StateStore, utc_now
from .testing import TestEvidenceStore, TestIdentity


AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ROLES = {"coder", "tester", "reviewer", "integrator"}
KINDS_BY_ROLE = {
    "coder": {"coding"},
    "tester": {"test_l1", "test_l2", "test_l3"},
    "reviewer": {"review"},
    "integrator": {"integration"},
}
CLAIMABLE_TASK_STATES = {
    "coding": {TaskState.READY.value, TaskState.AMENDMENT.value},
    "test_l1": {TaskState.TESTING.value},
    "test_l2": {TaskState.TESTING.value},
    "test_l3": {TaskState.INTEGRATING.value},
    "review": {TaskState.REVIEWING.value, TaskState.REVIEW_INFRA_FAILED.value},
    "integration": {TaskState.INTEGRATION_READY.value},
}


@dataclass(frozen=True)
class JobLease:
    lease_id: str
    job_id: int
    rfc_id: str
    revision_digest: str
    kind: str
    role: str
    holder_agent_id: str
    fencing_token: int
    expires_at: float
    candidate_digest: str | None
    attempt: int
    base_commit: str | None = None


class LeaseError(StateConflict):
    """A lease is missing, expired, stale, or owned by another agent."""


class QueueStore:
    def __init__(self, store: StateStore):
        self.store = store

    def register_agent(
        self,
        agent_id: str,
        role: str,
        model: str,
        process_identity: str,
        *,
        capacity: int = 1,
        now: float | None = None,
    ) -> None:
        if not AGENT_ID_RE.fullmatch(agent_id):
            raise ValueError("invalid agent_id")
        if role not in ROLES:
            raise ValueError(f"invalid role: {role}")
        if not model.strip() or not process_identity.strip():
            raise ValueError("model and process_identity must be non-empty")
        if capacity < 1:
            raise ValueError("capacity must be positive")
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT role, model, process_identity FROM agents WHERE agent_id = ?",
                (agent_id,),
            ).fetchone()
            if existing is not None and (
                existing["role"] != role
                or existing["model"] != model
                or existing["process_identity"] != process_identity
            ):
                raise StateConflict(
                    "agent role, model, and process identity are immutable; register a new agent_id"
                )
            connection.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, 'idle', ?, ?, '{}') "
                "ON CONFLICT(agent_id) DO UPDATE SET "
                "capacity=excluded.capacity, heartbeat_at=excluded.heartbeat_at",
                (agent_id, role, model, process_identity, capacity, timestamp),
            )

    def heartbeat_agent(
        self, agent_id: str, metrics: dict[str, Any], *, now: float | None = None
    ) -> None:
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            updated = connection.execute(
                "UPDATE agents SET heartbeat_at = ?, metrics_json = ? WHERE agent_id = ?",
                (timestamp, json.dumps(metrics, sort_keys=True), agent_id),
            )
            if updated.rowcount != 1:
                raise KeyError(agent_id)

    def enqueue(
        self,
        rfc_id: str,
        kind: str,
        idempotency_key: str,
        *,
        candidate_digest: str | None = None,
        base_commit: str | None = None,
        priority: int = 0,
        max_attempts: int = 3,
        available_at: float | None = None,
    ) -> int:
        role = next((name for name, kinds in KINDS_BY_ROLE.items() if kind in kinds), None)
        if role is None:
            raise ValueError(f"invalid job kind: {kind}")
        if not idempotency_key.strip():
            raise ValueError("idempotency_key must be non-empty")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if kind in {"coding", "integration"} and (
            base_commit is None or not re.fullmatch(r"[0-9a-f]{40}", base_commit)
        ):
            raise ValueError(f"{kind} jobs require a pinned base commit")
        now_text = utc_now()
        ready_at = time.time() if available_at is None else available_at
        with self.store.transaction() as connection:
            return self._enqueue_in_transaction(
                connection,
                rfc_id,
                kind,
                role,
                idempotency_key,
                candidate_digest,
                base_commit,
                priority,
                max_attempts,
                ready_at,
                now_text,
            )

    def claim(
        self,
        agent_id: str,
        *,
        lease_seconds: float = 300,
        now: float | None = None,
        kinds: Iterable[str] | None = None,
    ) -> JobLease | None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        timestamp = time.time() if now is None else now
        requested_kinds = tuple(kinds or ())
        with self.store.transaction() as connection:
            agent = connection.execute(
                "SELECT * FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if agent is None:
                raise KeyError(agent_id)
            role = str(agent["role"])
            allowed_kinds = KINDS_BY_ROLE[role]
            if requested_kinds:
                if not set(requested_kinds).issubset(allowed_kinds):
                    raise ValueError("requested job kind is incompatible with agent role")
                allowed_kinds = set(requested_kinds)
            active = connection.execute(
                "SELECT COUNT(*) AS count FROM leases WHERE holder_agent_id = ? AND expires_at > ?",
                (agent_id, timestamp),
            ).fetchone()["count"]
            if int(active) >= int(agent["capacity"]):
                return None
            placeholders = ",".join("?" for _ in allowed_kinds)
            rows = connection.execute(
                "SELECT jobs.*, tasks.state AS task_state FROM jobs "
                "JOIN tasks ON tasks.rfc_id = jobs.rfc_id "
                f"WHERE jobs.role = ? AND jobs.kind IN ({placeholders}) "
                "AND jobs.state = 'queued' AND jobs.available_at <= ? "
                "AND jobs.revision_digest = tasks.revision_digest "
                "AND (jobs.kind NOT IN ('coding', 'integration') OR jobs.base_commit IS NOT NULL) "
                "AND jobs.attempt < jobs.max_attempts "
                "ORDER BY jobs.priority DESC, jobs.job_id",
                (role, *sorted(allowed_kinds), timestamp),
            ).fetchall()
            # Locks remain held even after lease expiry until recovery has
            # fenced/stopped the old executor and deletes the lease. This
            # prevents another RFC from overlapping an expired-but-running
            # process on a shared resource.
            active_locks = {
                str(row["lock_key"])
                for row in connection.execute("SELECT lock_key FROM lease_locks")
            }
            job = next(
                (
                    row
                    for row in rows
                    if row["task_state"] in CLAIMABLE_TASK_STATES[str(row["kind"])]
                    and not self._revision_lock_keys(connection, row["revision_digest"])
                    .intersection(active_locks)
                ),
                None,
            )
            if job is None:
                return None
            resource_type = "rfc"
            resource_id = str(job["rfc_id"])
            connection.execute(
                "INSERT INTO resource_fences VALUES (?, ?, 1) "
                "ON CONFLICT(resource_type, resource_id) DO UPDATE "
                "SET last_token = last_token + 1",
                (resource_type, resource_id),
            )
            token = int(
                connection.execute(
                    "SELECT last_token FROM resource_fences "
                    "WHERE resource_type = ? AND resource_id = ?",
                    (resource_type, resource_id),
                ).fetchone()["last_token"]
            )
            lease_id = str(uuid.uuid4())
            expires_at = timestamp + lease_seconds
            try:
                connection.execute(
                    "INSERT INTO leases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        lease_id,
                        resource_type,
                        resource_id,
                        job["job_id"],
                        agent_id,
                        token,
                        timestamp,
                        timestamp,
                        expires_at,
                    ),
                )
                for lock_key in sorted(
                    self._revision_lock_keys(connection, str(job["revision_digest"]))
                ):
                    connection.execute(
                        "INSERT INTO resource_fences VALUES ('lock', ?, 1) "
                        "ON CONFLICT(resource_type, resource_id) DO UPDATE "
                        "SET last_token = last_token + 1",
                        (lock_key,),
                    )
                    lock_token = int(
                        connection.execute(
                            "SELECT last_token FROM resource_fences "
                            "WHERE resource_type = 'lock' AND resource_id = ?",
                            (lock_key,),
                        ).fetchone()["last_token"]
                    )
                    connection.execute(
                        "INSERT INTO lease_locks VALUES (?, ?, ?)",
                        (lock_key, lease_id, lock_token),
                    )
            except Exception as exc:
                raise LeaseError(
                    f"RFC or shared resource is already leased: {resource_id}"
                ) from exc
            changed = connection.execute(
                "UPDATE jobs SET state = 'leased', attempt = attempt + 1, updated_at = ? "
                "WHERE job_id = ? AND state = 'queued'",
                (utc_now(), job["job_id"]),
            )
            if changed.rowcount != 1:
                raise LeaseError(f"job was claimed concurrently: {job['job_id']}")
            if job["kind"] == "coding":
                self._transition_in_transaction(
                    connection,
                    str(job["rfc_id"]),
                    TaskState(str(job["task_state"])),
                    TaskState.LEASED,
                    f"agent:{agent_id}",
                    "coding job leased",
                    {"job_id": job["job_id"], "fencing_token": token},
                )
            connection.execute(
                "UPDATE agents SET status = 'busy', heartbeat_at = ? WHERE agent_id = ?",
                (timestamp, agent_id),
            )
            return JobLease(
                lease_id=lease_id,
                job_id=int(job["job_id"]),
                rfc_id=str(job["rfc_id"]),
                revision_digest=str(job["revision_digest"]),
                kind=str(job["kind"]),
                role=role,
                holder_agent_id=agent_id,
                fencing_token=token,
                expires_at=expires_at,
                candidate_digest=job["candidate_digest"],
                attempt=int(job["attempt"]) + 1,
                base_commit=job["base_commit"],
            )

    def start(self, lease: JobLease, *, now: float | None = None) -> None:
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            job = self._validated_lease(connection, lease, timestamp)
            if job["state"] != "leased":
                raise LeaseError(f"job {lease.job_id} is not leased")
            connection.execute(
                "UPDATE jobs SET state = 'running', updated_at = ? WHERE job_id = ?",
                (utc_now(), lease.job_id),
            )
            if lease.kind == "coding":
                self._transition_in_transaction(
                    connection,
                    lease.rfc_id,
                    TaskState.LEASED,
                    TaskState.CODING,
                    f"agent:{lease.holder_agent_id}",
                    "coding process started",
                    {"job_id": lease.job_id, "fencing_token": lease.fencing_token},
                )
            elif lease.kind == "review":
                task = connection.execute(
                    "SELECT state FROM tasks WHERE rfc_id = ?", (lease.rfc_id,)
                ).fetchone()
                if task["state"] == TaskState.REVIEW_INFRA_FAILED.value:
                    self._transition_in_transaction(
                        connection,
                        lease.rfc_id,
                        TaskState.REVIEW_INFRA_FAILED,
                        TaskState.REVIEWING,
                        f"agent:{lease.holder_agent_id}",
                        "review infrastructure retry started",
                        {"job_id": lease.job_id, "fencing_token": lease.fencing_token},
                    )
            elif lease.kind == "integration":
                self._transition_in_transaction(
                    connection,
                    lease.rfc_id,
                    TaskState.INTEGRATION_READY,
                    TaskState.INTEGRATING,
                    f"agent:{lease.holder_agent_id}",
                    "integration job started",
                    {"job_id": lease.job_id, "fencing_token": lease.fencing_token},
                )

    def heartbeat(
        self, lease: JobLease, *, lease_seconds: float = 300, now: float | None = None
    ) -> JobLease:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            self._validated_lease(connection, lease, timestamp)
            expires_at = timestamp + lease_seconds
            connection.execute(
                "UPDATE leases SET heartbeat_at = ?, expires_at = ? WHERE lease_id = ?",
                (timestamp, expires_at, lease.lease_id),
            )
            connection.execute(
                "UPDATE agents SET heartbeat_at = ? WHERE agent_id = ?",
                (timestamp, lease.holder_agent_id),
            )
        return JobLease(**{**lease.__dict__, "expires_at": expires_at})

    def finish(
        self,
        lease: JobLease,
        outcome: str,
        result: dict[str, Any],
        *,
        now: float | None = None,
    ) -> None:
        if outcome not in {"passed", "failed", "cancelled"}:
            raise ValueError("invalid job outcome")
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            self._validated_lease(connection, lease, timestamp)
            connection.execute(
                "UPDATE jobs SET state = ?, result_json = ?, updated_at = ? WHERE job_id = ?",
                (outcome, json.dumps(result, sort_keys=True), utc_now(), lease.job_id),
            )
            connection.execute("DELETE FROM leases WHERE lease_id = ?", (lease.lease_id,))
            active = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM leases WHERE holder_agent_id = ?",
                    (lease.holder_agent_id,),
                ).fetchone()["count"]
            )
            connection.execute(
                "UPDATE agents SET status = ? WHERE agent_id = ?",
                ("busy" if active else "idle", lease.holder_agent_id),
            )

    def finish_and_transition(
        self,
        lease: JobLease,
        outcome: str,
        result: dict[str, Any],
        expected: TaskState,
        target: TaskState,
        *,
        reason: str,
        next_kind: str | None = None,
        next_idempotency_key: str | None = None,
        next_candidate_digest: str | None = None,
        next_priority: int = 0,
        next_max_attempts: int = 3,
        review_record: dict[str, Any] | None = None,
        test_record: tuple[TestIdentity, str, str] | None = None,
        now: float | None = None,
    ) -> int | None:
        """Atomically publish a fenced result, transition, and enqueue its successor."""
        if outcome not in {"passed", "failed", "cancelled"}:
            raise ValueError("invalid job outcome")
        if (next_kind is None) != (next_idempotency_key is None):
            raise ValueError("next kind and idempotency key must be supplied together")
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            job = self._validated_lease(connection, lease, timestamp)
            if job["state"] != "running":
                raise LeaseError(f"job {lease.job_id} is not running")
            task = connection.execute(
                "SELECT state FROM tasks WHERE rfc_id = ?", (lease.rfc_id,)
            ).fetchone()
            if task is None or task["state"] != expected.value:
                found = None if task is None else task["state"]
                raise StateConflict(f"{lease.rfc_id} expected {expected.value}, found {found}")
            if lease.kind == "coding":
                candidate_digest = str(result.get("candidate_digest", ""))
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", candidate_digest):
                    raise StateConflict("coding result requires a candidate digest")
                candidate_fields = {
                    "branch": str(result.get("branch", "")),
                    "commit_sha": str(result.get("commit_sha", "")),
                    "tree_sha": str(result.get("tree_sha", "")),
                    "diff_digest": str(result.get("diff_digest", "")),
                }
                if candidate_fields["branch"] != f"agent/{lease.rfc_id}":
                    raise StateConflict("coding result requires the RFC candidate branch")
                if not re.fullmatch(r"[0-9a-f]{40}", candidate_fields["commit_sha"]):
                    raise StateConflict("coding result requires a candidate commit")
                if not re.fullmatch(r"[0-9a-f]{40}", candidate_fields["tree_sha"]):
                    raise StateConflict("coding result requires a candidate tree")
                if not re.fullmatch(
                    r"sha256:[0-9a-f]{64}", candidate_fields["diff_digest"]
                ):
                    raise StateConflict("coding result requires a candidate diff digest")
                if lease.base_commit is None:
                    raise StateConflict("coding result requires the pinned base commit")
                candidate_evidence = {
                    "base_commit": lease.base_commit,
                    "branch": candidate_fields["branch"],
                    "commit_sha": candidate_fields["commit_sha"],
                    "diff_digest": candidate_fields["diff_digest"],
                    "revision_digest": lease.revision_digest,
                    "rfc_id": lease.rfc_id,
                    "tree_sha": candidate_fields["tree_sha"],
                }
                expected_candidate_digest = "sha256:" + hashlib.sha256(
                    json.dumps(
                        candidate_evidence,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                    ).encode("ascii")
                ).hexdigest()
                if candidate_digest != expected_candidate_digest:
                    raise StateConflict("candidate digest is not canonical for its Git evidence")
                agent = connection.execute(
                    "SELECT process_identity FROM agents WHERE agent_id = ?",
                    (lease.holder_agent_id,),
                ).fetchone()
                if agent is None:
                    raise StateConflict("candidate author agent is missing")
                existing_candidate = connection.execute(
                    "SELECT base_commit, branch, commit_sha, tree_sha, diff_digest, "
                    "author_agent_id, author_process_identity "
                    "FROM candidate_records "
                    "WHERE rfc_id = ? AND revision_digest = ? AND candidate_digest = ?",
                    (lease.rfc_id, lease.revision_digest, candidate_digest),
                ).fetchone()
                identity = (lease.holder_agent_id, str(agent["process_identity"]))
                if existing_candidate is not None and (
                    existing_candidate["base_commit"] != lease.base_commit
                    or existing_candidate["branch"] != candidate_fields["branch"]
                    or existing_candidate["commit_sha"] != candidate_fields["commit_sha"]
                    or existing_candidate["tree_sha"] != candidate_fields["tree_sha"]
                    or existing_candidate["diff_digest"] != candidate_fields["diff_digest"]
                    or (
                        existing_candidate["author_agent_id"],
                        existing_candidate["author_process_identity"],
                    )
                    != identity
                ):
                    raise StateConflict("candidate digest already has a different author")
                connection.execute(
                    "INSERT OR IGNORE INTO candidate_records "
                    "(rfc_id, revision_digest, candidate_digest, base_commit, branch, "
                    "commit_sha, tree_sha, diff_digest, author_agent_id, "
                    "author_process_identity, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        lease.rfc_id,
                        lease.revision_digest,
                        candidate_digest,
                        str(lease.base_commit),
                        candidate_fields["branch"],
                        candidate_fields["commit_sha"],
                        candidate_fields["tree_sha"],
                        candidate_fields["diff_digest"],
                        identity[0],
                        identity[1],
                        utc_now(),
                    ),
                )
            if test_record is not None:
                identity, test_status, evidence_digest = test_record
                TestEvidenceStore.record_in_transaction(
                    connection,
                    identity,
                    test_status,
                    evidence_digest,
                    expected_rfc_id=lease.rfc_id,
                    expected_revision_digest=lease.revision_digest,
                    expected_candidate_digest=(
                        lease.candidate_digest or str(result.get("candidate_digest", ""))
                    ),
                )
            connection.execute(
                "UPDATE jobs SET state = ?, result_json = ?, updated_at = ? WHERE job_id = ?",
                (outcome, json.dumps(result, sort_keys=True), utc_now(), lease.job_id),
            )
            if review_record is not None:
                if lease.kind != "review" or lease.role != "reviewer":
                    raise StateConflict("review evidence requires an independent Reviewer lease")
                if review_record["candidate_digest"] != lease.candidate_digest:
                    raise StateConflict("review candidate does not match the leased job")
                self._assert_independent_reviewer(connection, lease)
                connection.execute(
                    "INSERT INTO review_runs "
                    "(rfc_id, revision_digest, candidate_digest, reviewer_agent_id, verdict, "
                    "infrastructure_status, schema_valid, independent, evidence_digest, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        lease.rfc_id,
                        lease.revision_digest,
                        review_record["candidate_digest"],
                        lease.holder_agent_id,
                        review_record.get("verdict"),
                        review_record["infrastructure_status"],
                        1 if review_record.get("schema_valid") else 0,
                        1,
                        review_record["evidence_digest"],
                        utc_now(),
                    ),
                )
            self._transition_in_transaction(
                connection,
                lease.rfc_id,
                expected,
                target,
                f"agent:{lease.holder_agent_id}",
                reason,
                {"job_id": lease.job_id, "fencing_token": lease.fencing_token},
            )
            next_job_id = None
            if next_kind is not None and next_idempotency_key is not None:
                next_role = next(
                    (name for name, kinds in KINDS_BY_ROLE.items() if next_kind in kinds), None
                )
                if next_role is None:
                    raise ValueError(f"invalid next job kind: {next_kind}")
                next_job_id = self._enqueue_in_transaction(
                    connection,
                    lease.rfc_id,
                    next_kind,
                    next_role,
                    next_idempotency_key,
                    next_candidate_digest,
                    lease.base_commit,
                    next_priority,
                    next_max_attempts,
                    timestamp,
                    utc_now(),
                )
            connection.execute("DELETE FROM leases WHERE lease_id = ?", (lease.lease_id,))
            active = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM leases WHERE holder_agent_id = ?",
                    (lease.holder_agent_id,),
                ).fetchone()["count"]
            )
            connection.execute(
                "UPDATE agents SET status = ? WHERE agent_id = ?",
                ("busy" if active else "idle", lease.holder_agent_id),
            )
            return next_job_id

    def retry_review_infrastructure(
        self,
        lease: JobLease,
        result: dict[str, Any],
        review_record: dict[str, Any],
        *,
        now: float | None = None,
    ) -> int | None:
        """Requeue one unchanged Reviewer job or block it at its attempt limit."""
        timestamp = time.time() if now is None else now
        with self.store.transaction() as connection:
            job = self._validated_lease(connection, lease, timestamp)
            if job["state"] != "running" or lease.kind != "review" or lease.role != "reviewer":
                raise LeaseError("Reviewer infrastructure retry requires a running Reviewer job")
            if review_record["candidate_digest"] != lease.candidate_digest:
                raise StateConflict("review candidate does not match the leased job")
            self._assert_independent_reviewer(connection, lease)
            task = connection.execute(
                "SELECT state FROM tasks WHERE rfc_id = ?", (lease.rfc_id,)
            ).fetchone()
            if task is None or task["state"] != TaskState.REVIEWING.value:
                found = None if task is None else task["state"]
                raise StateConflict(
                    f"{lease.rfc_id} expected {TaskState.REVIEWING.value}, found {found}"
                )
            connection.execute(
                "INSERT INTO review_runs "
                "(rfc_id, revision_digest, candidate_digest, reviewer_agent_id, verdict, "
                "infrastructure_status, schema_valid, independent, evidence_digest, created_at) "
                "VALUES (?, ?, ?, ?, NULL, ?, 0, 1, ?, ?)",
                (
                    lease.rfc_id,
                    lease.revision_digest,
                    review_record["candidate_digest"],
                    lease.holder_agent_id,
                    review_record["infrastructure_status"],
                    review_record["evidence_digest"],
                    utc_now(),
                ),
            )
            exhausted = int(job["attempt"]) >= int(job["max_attempts"])
            if exhausted:
                target = TaskState.BLOCKED
                job_state = "failed"
                result = {
                    **result,
                    "failure_kind": "REVIEW_INFRA_ATTEMPTS_EXHAUSTED",
                    "attempts": int(job["attempt"]),
                }
                reason = (
                    f"Reviewer infrastructure failed {job['attempt']} times; "
                    "manual recovery is required"
                )
            else:
                target = TaskState.REVIEW_INFRA_FAILED
                job_state = "queued"
                reason = "Reviewer infrastructure failed; unchanged candidate queued for retry"
            connection.execute(
                "UPDATE jobs SET state = ?, result_json = ?, available_at = ?, updated_at = ? "
                "WHERE job_id = ?",
                (
                    job_state,
                    json.dumps(result, sort_keys=True),
                    timestamp,
                    utc_now(),
                    lease.job_id,
                ),
            )
            self._transition_in_transaction(
                connection,
                lease.rfc_id,
                TaskState.REVIEWING,
                target,
                f"agent:{lease.holder_agent_id}",
                reason,
                {"job_id": lease.job_id, "fencing_token": lease.fencing_token},
            )
            connection.execute("DELETE FROM leases WHERE lease_id = ?", (lease.lease_id,))
            active = int(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM leases WHERE holder_agent_id = ?",
                    (lease.holder_agent_id,),
                ).fetchone()["count"]
            )
            connection.execute(
                "UPDATE agents SET status = ? WHERE agent_id = ?",
                ("busy" if active else "idle", lease.holder_agent_id),
            )
            return None if exhausted else lease.job_id

    @staticmethod
    def _assert_independent_reviewer(connection, lease: JobLease) -> None:
        candidate = connection.execute(
            "SELECT author_agent_id, author_process_identity FROM candidate_records "
            "WHERE rfc_id = ? AND revision_digest = ? AND candidate_digest = ?",
            (lease.rfc_id, lease.revision_digest, lease.candidate_digest),
        ).fetchone()
        reviewer = connection.execute(
            "SELECT process_identity FROM agents WHERE agent_id = ? AND role = 'reviewer'",
            (lease.holder_agent_id,),
        ).fetchone()
        if candidate is None:
            raise StateConflict("review requires a persisted candidate author identity")
        if reviewer is None:
            raise StateConflict("reviewer identity is missing")
        if (
            candidate["author_agent_id"] == lease.holder_agent_id
            or candidate["author_process_identity"] == reviewer["process_identity"]
        ):
            raise StateConflict("Reviewer must be independent from the candidate author")

    def approve_reviewed_candidate(
        self,
        rfc_id: str,
        candidate_digest: str,
        actor: str,
        idempotency_key: str,
        *,
        available_at: float | None = None,
        max_attempts: int = 3,
    ) -> int:
        """Atomically verify independent PASS evidence and enqueue integration."""
        timestamp = time.time() if available_at is None else available_at
        with self.store.transaction() as connection:
            task = connection.execute(
                "SELECT revision_digest, state FROM tasks WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            if task is None or task["state"] != TaskState.LEAD_REVIEW.value:
                found = None if task is None else task["state"]
                raise StateConflict(
                    f"{rfc_id} expected {TaskState.LEAD_REVIEW.value}, found {found}"
                )
            review = connection.execute(
                "SELECT review_runs.review_run_id, candidate_records.base_commit "
                "FROM review_runs JOIN candidate_records USING "
                "(rfc_id, revision_digest, candidate_digest) WHERE review_runs.rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND verdict = 'PASS' "
                "AND infrastructure_status = 'PASS' AND schema_valid = 1 "
                "AND independent = 1 AND candidate_records.branch IS NOT NULL "
                "AND candidate_records.commit_sha IS NOT NULL "
                "AND candidate_records.tree_sha IS NOT NULL "
                "AND candidate_records.diff_digest IS NOT NULL "
                "ORDER BY review_run_id DESC LIMIT 1",
                (rfc_id, task["revision_digest"], candidate_digest),
            ).fetchone()
            if review is None:
                raise StateConflict(
                    "integration requires schema-valid independent PASS evidence for this candidate"
                )
            self._transition_in_transaction(
                connection,
                rfc_id,
                TaskState.LEAD_REVIEW,
                TaskState.INTEGRATION_READY,
                actor,
                "Project Lead accepted reviewed candidate for integration",
                {
                    "candidate_digest": candidate_digest,
                    "review_run_id": int(review["review_run_id"]),
                },
            )
            return self._enqueue_in_transaction(
                connection,
                rfc_id,
                "integration",
                "integrator",
                idempotency_key,
                candidate_digest,
                str(review["base_commit"]),
                0,
                max_attempts,
                timestamp,
                utc_now(),
            )

    def transition_and_enqueue(
        self,
        rfc_id: str,
        expected: TaskState,
        target: TaskState,
        actor: str,
        reason: str,
        kind: str,
        idempotency_key: str,
        *,
        candidate_digest: str | None = None,
        base_commit: str | None = None,
        priority: int = 0,
        max_attempts: int = 3,
        available_at: float | None = None,
    ) -> int:
        role = next((name for name, kinds in KINDS_BY_ROLE.items() if kind in kinds), None)
        if role is None:
            raise ValueError(f"invalid job kind: {kind}")
        timestamp = time.time() if available_at is None else available_at
        with self.store.transaction() as connection:
            self._transition_in_transaction(
                connection,
                rfc_id,
                expected,
                target,
                actor,
                reason,
                {"candidate_digest": candidate_digest},
            )
            return self._enqueue_in_transaction(
                connection,
                rfc_id,
                kind,
                role,
                idempotency_key,
                candidate_digest,
                base_commit,
                priority,
                max_attempts,
                timestamp,
                utc_now(),
            )

    def recover_expired(
        self,
        *,
        confirmed_quiescent_lease_ids: set[str],
        now: float | None = None,
    ) -> list[int]:
        """Recover expired work only after a supervisor proved each executor stopped."""
        timestamp = time.time() if now is None else now
        recovered: list[int] = []
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT leases.*, jobs.kind, jobs.rfc_id, jobs.state AS job_state, "
                "jobs.attempt, jobs.max_attempts "
                "FROM leases JOIN jobs ON jobs.job_id = leases.job_id "
                "WHERE leases.expires_at <= ? ORDER BY leases.job_id",
                (timestamp,),
            ).fetchall()
            unconfirmed = sorted(
                str(row["lease_id"])
                for row in rows
                if str(row["lease_id"]) not in confirmed_quiescent_lease_ids
            )
            if unconfirmed:
                raise LeaseError(
                    "expired leases require supervisor quiescence proof before recovery: "
                    + ", ".join(unconfirmed)
                )
            for row in rows:
                task = connection.execute(
                    "SELECT state FROM tasks WHERE rfc_id = ?", (row["rfc_id"],)
                ).fetchone()
                state = TaskState(task["state"])
                exhausted = int(row["attempt"]) >= int(row["max_attempts"])
                if exhausted:
                    result = json.dumps(
                        {
                            "failure_kind": "ATTEMPTS_EXHAUSTED",
                            "attempts": int(row["attempt"]),
                            "expired_fencing_token": int(row["fencing_token"]),
                        },
                        sort_keys=True,
                    )
                    connection.execute(
                        "UPDATE jobs SET state = 'failed', result_json = ?, updated_at = ? "
                        "WHERE job_id = ? AND state IN ('leased', 'running')",
                        (result, utc_now(), row["job_id"]),
                    )
                    if state not in {TaskState.BLOCKED, TaskState.DONE}:
                        self._transition_in_transaction(
                            connection,
                            str(row["rfc_id"]),
                            state,
                            TaskState.BLOCKED,
                            "scheduler:lease-recovery",
                            f"{row['kind']} exhausted {row['max_attempts']} attempts",
                            {
                                "job_id": row["job_id"],
                                "expired_fencing_token": row["fencing_token"],
                                "failure_kind": "ATTEMPTS_EXHAUSTED",
                            },
                        )
                else:
                    connection.execute(
                        "UPDATE jobs SET state = 'queued', available_at = ?, updated_at = ? "
                        "WHERE job_id = ? AND state IN ('leased', 'running')",
                        (timestamp, utc_now(), row["job_id"]),
                    )
                    if row["kind"] == "coding" and state in {
                        TaskState.LEASED,
                        TaskState.CODING,
                    }:
                        self._transition_in_transaction(
                            connection,
                            str(row["rfc_id"]),
                            state,
                            TaskState.READY,
                            "scheduler:lease-recovery",
                            "expired coding lease recovered",
                            {
                                "job_id": row["job_id"],
                                "expired_fencing_token": row["fencing_token"],
                            },
                        )
                    elif row["kind"] in {"integration", "test_l3"} and state == TaskState.INTEGRATING:
                        self._transition_in_transaction(
                            connection,
                            str(row["rfc_id"]),
                            state,
                            TaskState.INTEGRATION_READY,
                            "scheduler:lease-recovery",
                            "expired integration lease recovered",
                            {
                                "job_id": row["job_id"],
                                "expired_fencing_token": row["fencing_token"],
                            },
                        )
                connection.execute("DELETE FROM leases WHERE lease_id = ?", (row["lease_id"],))
                recovered.append(int(row["job_id"]))
            connection.execute(
                "UPDATE agents SET status = 'idle' WHERE status = 'busy' AND NOT EXISTS "
                "(SELECT 1 FROM leases WHERE leases.holder_agent_id = agents.agent_id)"
            )
        return recovered

    def jobs(self) -> list[dict[str, Any]]:
        with self.store.connect() as connection:
            rows = connection.execute("SELECT * FROM jobs ORDER BY job_id").fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["result"] = json.loads(value.pop("result_json"))
            result.append(value)
        return result

    def _validated_lease(self, connection, lease: JobLease, now: float):
        row = connection.execute(
            "SELECT leases.*, jobs.state, jobs.revision_digest, jobs.kind, jobs.role, "
            "jobs.attempt, jobs.max_attempts, jobs.base_commit, jobs.candidate_digest FROM leases "
            "JOIN jobs ON jobs.job_id = leases.job_id WHERE leases.lease_id = ?",
            (lease.lease_id,),
        ).fetchone()
        if row is None:
            raise LeaseError("lease does not exist")
        if (
            int(row["job_id"]) != lease.job_id
            or row["holder_agent_id"] != lease.holder_agent_id
            or int(row["fencing_token"]) != lease.fencing_token
            or row["revision_digest"] != lease.revision_digest
            or row["kind"] != lease.kind
            or row["role"] != lease.role
            or row["candidate_digest"] != lease.candidate_digest
            or row["base_commit"] != lease.base_commit
        ):
            raise LeaseError("lease fencing validation failed")
        if float(row["expires_at"]) <= now:
            raise LeaseError("lease has expired")
        return row

    @staticmethod
    def _revision_lock_keys(connection, revision_digest: str) -> set[str]:
        row = connection.execute(
            "SELECT payload_json FROM rfc_revisions WHERE revision_digest = ?",
            (revision_digest,),
        ).fetchone()
        if row is None:
            raise StateConflict(f"missing RFC revision {revision_digest}")
        payload = json.loads(row["payload_json"])
        return {str(item) for item in payload.get("lock_keys", [])}

    @staticmethod
    def _enqueue_in_transaction(
        connection,
        rfc_id: str,
        kind: str,
        role: str,
        idempotency_key: str,
        candidate_digest: str | None,
        base_commit: str | None,
        priority: int,
        max_attempts: int,
        available_at: float,
        now_text: str,
    ) -> int:
        if kind in {"coding", "integration"} and (
            base_commit is None or not re.fullmatch(r"[0-9a-f]{40}", base_commit)
        ):
            raise ValueError(f"{kind} jobs require a pinned base commit")
        task = connection.execute(
            "SELECT revision_digest FROM tasks WHERE rfc_id = ?", (rfc_id,)
        ).fetchone()
        if task is None:
            raise KeyError(rfc_id)
        connection.execute(
            "INSERT OR IGNORE INTO jobs "
            "(idempotency_key, rfc_id, revision_digest, kind, role, state, priority, "
            "base_commit, candidate_digest, max_attempts, available_at, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)",
            (
                idempotency_key,
                rfc_id,
                task["revision_digest"],
                kind,
                role,
                priority,
                base_commit,
                candidate_digest,
                max_attempts,
                available_at,
                now_text,
                now_text,
            ),
        )
        row = connection.execute(
            "SELECT job_id, rfc_id, revision_digest, kind, base_commit, candidate_digest "
            "FROM jobs WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if (
            row["rfc_id"] != rfc_id
            or row["revision_digest"] != task["revision_digest"]
            or row["kind"] != kind
            or row["candidate_digest"] != candidate_digest
            or row["base_commit"] != base_commit
        ):
            raise StateConflict(f"idempotency key reused with different job: {idempotency_key}")
        return int(row["job_id"])

    @staticmethod
    def _transition_in_transaction(
        connection,
        rfc_id: str,
        expected: TaskState,
        target: TaskState,
        actor: str,
        reason: str,
        metadata: dict[str, Any],
    ) -> None:
        task = connection.execute(
            "SELECT * FROM tasks WHERE rfc_id = ?", (rfc_id,)
        ).fetchone()
        if task is None or task["state"] != expected.value:
            found = None if task is None else task["state"]
            raise StateConflict(f"{rfc_id} expected {expected.value}, found {found}")
        sequence = int(task["event_sequence"]) + 1
        occurred_at = utc_now()
        connection.execute(
            "UPDATE tasks SET state = ?, reason = ?, event_sequence = ?, updated_at = ? "
            "WHERE rfc_id = ?",
            (target.value, reason, sequence, occurred_at, rfc_id),
        )
        connection.execute(
            "INSERT INTO transitions "
            "(rfc_id, sequence, from_state, to_state, reason, actor, revision_digest, "
            "occurred_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rfc_id,
                sequence,
                expected.value,
                target.value,
                reason,
                actor,
                task["revision_digest"],
                occurred_at,
                json.dumps(metadata, sort_keys=True),
            ),
        )
