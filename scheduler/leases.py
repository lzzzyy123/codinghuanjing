"""Transactional multi-process job queue with leases and fencing tokens."""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable

from .models import TaskState
from .state_store import StateConflict, StateStore, utc_now


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
            connection.execute(
                "INSERT INTO agents VALUES (?, ?, ?, ?, 'idle', ?, ?, '{}') "
                "ON CONFLICT(agent_id) DO UPDATE SET role=excluded.role, "
                "model=excluded.model, process_identity=excluded.process_identity, "
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
        now_text = utc_now()
        ready_at = time.time() if available_at is None else available_at
        with self.store.transaction() as connection:
            task = connection.execute(
                "SELECT revision_digest FROM tasks WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            if task is None:
                raise KeyError(rfc_id)
            connection.execute(
                "INSERT OR IGNORE INTO jobs "
                "(idempotency_key, rfc_id, revision_digest, kind, role, state, priority, "
                "candidate_digest, max_attempts, available_at, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)",
                (
                    idempotency_key,
                    rfc_id,
                    task["revision_digest"],
                    kind,
                    role,
                    priority,
                    candidate_digest,
                    max_attempts,
                    ready_at,
                    now_text,
                    now_text,
                ),
            )
            row = connection.execute(
                "SELECT job_id, rfc_id, revision_digest, kind, candidate_digest "
                "FROM jobs WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if (
                row["rfc_id"] != rfc_id
                or row["revision_digest"] != task["revision_digest"]
                or row["kind"] != kind
                or row["candidate_digest"] != candidate_digest
            ):
                raise StateConflict(f"idempotency key reused with different job: {idempotency_key}")
            return int(row["job_id"])

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
                "AND jobs.attempt < jobs.max_attempts "
                "ORDER BY jobs.priority DESC, jobs.job_id",
                (role, *sorted(allowed_kinds), timestamp),
            ).fetchall()
            job = next(
                (
                    row
                    for row in rows
                    if row["task_state"] in CLAIMABLE_TASK_STATES[str(row["kind"])]
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
            except Exception as exc:
                raise LeaseError(f"resource already leased: {resource_id}") from exc
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

    def recover_expired(self, *, now: float | None = None) -> list[int]:
        timestamp = time.time() if now is None else now
        recovered: list[int] = []
        with self.store.transaction() as connection:
            rows = connection.execute(
                "SELECT leases.*, jobs.kind, jobs.rfc_id, jobs.state AS job_state "
                "FROM leases JOIN jobs ON jobs.job_id = leases.job_id "
                "WHERE leases.expires_at <= ? ORDER BY leases.job_id",
                (timestamp,),
            ).fetchall()
            for row in rows:
                connection.execute(
                    "UPDATE jobs SET state = 'queued', available_at = ?, updated_at = ? "
                    "WHERE job_id = ? AND state IN ('leased', 'running')",
                    (timestamp, utc_now(), row["job_id"]),
                )
                if row["kind"] == "coding":
                    task = connection.execute(
                        "SELECT state FROM tasks WHERE rfc_id = ?", (row["rfc_id"],)
                    ).fetchone()
                    state = TaskState(task["state"])
                    if state in {TaskState.LEASED, TaskState.CODING}:
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
            "SELECT leases.*, jobs.state, jobs.revision_digest FROM leases "
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
        ):
            raise LeaseError("lease fencing validation failed")
        if float(row["expires_at"]) <= now:
            raise LeaseError("lease has expired")
        return row

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
