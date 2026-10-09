"""SQLite-backed durable scheduler state and transition evidence."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import ALLOWED_TRANSITIONS, TaskState
from .registry import Registry


class StateConflict(RuntimeError):
    """A state mutation raced or violated the lifecycle."""


class ClosingConnection(sqlite3.Connection):
    """A sqlite connection whose context manager also releases its descriptor."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS registries (
    digest TEXT PRIMARY KEY,
    baseline_commit TEXT NOT NULL,
    classification_sha256 TEXT NOT NULL,
    in_scope_count INTEGER NOT NULL,
    config_data_count INTEGER NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rfc_revisions (
    rfc_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    revision_digest TEXT PRIMARY KEY,
    registry_digest TEXT NOT NULL REFERENCES registries(digest),
    payload_json TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    UNIQUE(rfc_id, revision)
);
CREATE TABLE IF NOT EXISTS tasks (
    rfc_id TEXT PRIMARY KEY,
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    state TEXT NOT NULL,
    reason TEXT,
    event_sequence INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_id TEXT NOT NULL REFERENCES tasks(rfc_id),
    sequence INTEGER NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT,
    actor TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    UNIQUE(rfc_id, sequence)
);
CREATE TABLE IF NOT EXISTS transition_outbox (
    rfc_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    materialized INTEGER NOT NULL DEFAULT 0,
    materialized_at TEXT,
    PRIMARY KEY(rfc_id, sequence),
    FOREIGN KEY(rfc_id, sequence) REFERENCES transitions(rfc_id, sequence)
);
CREATE TRIGGER IF NOT EXISTS transitions_to_outbox
AFTER INSERT ON transitions
BEGIN
    INSERT OR IGNORE INTO transition_outbox(rfc_id, sequence)
    VALUES (NEW.rfc_id, NEW.sequence);
END;
CREATE TABLE IF NOT EXISTS merge_records (
    rfc_id TEXT PRIMARY KEY REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    candidate_digest TEXT NOT NULL,
    candidate_commit TEXT NOT NULL,
    review_run_id INTEGER NOT NULL REFERENCES review_runs(review_run_id),
    level3_test_run_id INTEGER NOT NULL REFERENCES test_runs(test_run_id),
    merge_commit TEXT NOT NULL,
    trusted_main_commit TEXT NOT NULL,
    contracts_json TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS base_delivery_records (
    required_rfc_id TEXT PRIMARY KEY,
    required_commit TEXT NOT NULL,
    merged_base_commit TEXT NOT NULL,
    trusted_main_commit TEXT NOT NULL,
    ancestor_verified INTEGER NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    model TEXT NOT NULL,
    process_identity TEXT NOT NULL,
    status TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    heartbeat_at REAL NOT NULL,
    metrics_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    idempotency_key TEXT NOT NULL UNIQUE,
    rfc_id TEXT NOT NULL REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    kind TEXT NOT NULL,
    role TEXT NOT NULL,
    state TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    base_commit TEXT,
    candidate_digest TEXT,
    attempt INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    available_at REAL NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS jobs_claim_idx
    ON jobs(role, state, available_at, priority DESC, job_id);
CREATE TABLE IF NOT EXISTS resource_fences (
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    last_token INTEGER NOT NULL,
    PRIMARY KEY(resource_type, resource_id)
);
CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    job_id INTEGER NOT NULL UNIQUE REFERENCES jobs(job_id),
    holder_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    fencing_token INTEGER NOT NULL,
    acquired_at REAL NOT NULL,
    heartbeat_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    UNIQUE(resource_type, resource_id)
);
CREATE TABLE IF NOT EXISTS lease_locks (
    lock_key TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL REFERENCES leases(lease_id) ON DELETE CASCADE,
    fencing_token INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    digest TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    redacted INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS test_runs (
    test_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_id TEXT NOT NULL REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    candidate_digest TEXT NOT NULL,
    level INTEGER NOT NULL,
    command_digest TEXT NOT NULL,
    environment_digest TEXT NOT NULL,
    baseline_commit TEXT,
    trusted_main_commit TEXT,
    candidate_merge_tree TEXT,
    status TEXT NOT NULL,
    evidence_digest TEXT NOT NULL REFERENCES artifacts(digest),
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    UNIQUE(rfc_id, revision_digest, candidate_digest, level, command_digest,
           environment_digest, baseline_commit)
);
CREATE TABLE IF NOT EXISTS review_runs (
    review_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_id TEXT NOT NULL REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    candidate_digest TEXT NOT NULL,
    reviewer_agent_id TEXT NOT NULL,
    verdict TEXT,
    infrastructure_status TEXT NOT NULL,
    schema_valid INTEGER NOT NULL DEFAULT 0,
    independent INTEGER NOT NULL DEFAULT 0,
    evidence_digest TEXT NOT NULL REFERENCES artifacts(digest),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_records (
    rfc_id TEXT NOT NULL REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    candidate_digest TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    tree_sha TEXT NOT NULL,
    diff_digest TEXT NOT NULL,
    author_agent_id TEXT NOT NULL REFERENCES agents(agent_id),
    author_process_identity TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(rfc_id, revision_digest, candidate_digest)
);
CREATE TABLE IF NOT EXISTS publication_records (
    publication_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_id TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    remote TEXT NOT NULL,
    ref_name TEXT NOT NULL,
    previous_commit TEXT,
    target_commit TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_commit TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(rfc_id, revision_digest, candidate_digest, remote, ref_name, target_commit)
);
CREATE INDEX IF NOT EXISTS publication_records_state_idx
    ON publication_records(state, publication_id);
CREATE UNIQUE INDEX IF NOT EXISTS publication_records_active_ref_idx
    ON publication_records(remote, ref_name)
    WHERE state IN ('prepared', 'published', 'blocked');
CREATE TABLE IF NOT EXISTS merge_authorization_decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_digest TEXT NOT NULL UNIQUE,
    rfc_id TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    candidate_commit TEXT,
    head_ref TEXT,
    disposition TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    risk_json TEXT NOT NULL,
    blockers_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS merge_authorization_rfc_idx
    ON merge_authorization_decisions(rfc_id, decision_id);
CREATE TRIGGER IF NOT EXISTS merge_authorization_decisions_no_update
BEFORE UPDATE ON merge_authorization_decisions
BEGIN
    SELECT RAISE(ABORT, 'merge authorization audit records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS merge_authorization_decisions_no_delete
BEFORE DELETE ON merge_authorization_decisions
BEGIN
    SELECT RAISE(ABORT, 'merge authorization audit records are immutable');
END;
CREATE TABLE IF NOT EXISTS merge_authorization_fences (
    decision_digest TEXT PRIMARY KEY
        REFERENCES merge_authorization_decisions(decision_digest),
    last_token INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS merge_authorization_reservations (
    reservation_id TEXT PRIMARY KEY,
    reservation_key TEXT NOT NULL UNIQUE,
    decision_digest TEXT NOT NULL
        REFERENCES merge_authorization_decisions(decision_digest),
    rfc_id TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    holder_identity TEXT NOT NULL,
    expected_trusted_main_commit TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved', 'consumed', 'aborted')),
    expires_at REAL NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(decision_digest, fencing_token)
);
CREATE UNIQUE INDEX IF NOT EXISTS merge_authorization_single_use_idx
    ON merge_authorization_reservations(decision_digest)
    WHERE state IN ('reserved', 'consumed');
CREATE TABLE IF NOT EXISTS merge_authorization_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL
        REFERENCES merge_authorization_reservations(reservation_id),
    event_type TEXT NOT NULL,
    fencing_token INTEGER NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS merge_authorization_events_reservation_idx
    ON merge_authorization_events(reservation_id, event_id);
CREATE TRIGGER IF NOT EXISTS merge_authorization_events_no_update
BEFORE UPDATE ON merge_authorization_events
BEGIN
    SELECT RAISE(ABORT, 'merge authorization events are immutable');
END;
CREATE TRIGGER IF NOT EXISTS merge_authorization_events_no_delete
BEFORE DELETE ON merge_authorization_events
BEGIN
    SELECT RAISE(ABORT, 'merge authorization events are immutable');
END;
CREATE TABLE IF NOT EXISTS project_lead_approvals (
    approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rfc_id TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    review_run_id INTEGER NOT NULL REFERENCES review_runs(review_run_id),
    actor TEXT NOT NULL,
    channel TEXT NOT NULL,
    evidence_digest TEXT NOT NULL REFERENCES artifacts(digest),
    created_at TEXT NOT NULL,
    UNIQUE(rfc_id, revision_digest, candidate_digest, review_run_id)
);
CREATE TRIGGER IF NOT EXISTS project_lead_approvals_no_update
BEFORE UPDATE ON project_lead_approvals
BEGIN
    SELECT RAISE(ABORT, 'Project Lead approval records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS project_lead_approvals_no_delete
BEFORE DELETE ON project_lead_approvals
BEGIN
    SELECT RAISE(ABORT, 'Project Lead approval records are immutable');
END;
CREATE TABLE IF NOT EXISTS migration_blockers (
    blocker_key TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved_at TEXT
);
"""


class StateStore:
    def __init__(self, path: Path, evidence_root: Path | None = None):
        self.path = path
        self.evidence_root = evidence_root
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            self._migrate(connection)
            connection.execute("PRAGMA journal_mode = WAL")

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=30,
            isolation_level=None,
            factory=ClosingConnection,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _migrate(connection: sqlite3.Connection) -> None:
        registry_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(registries)")
        }
        if "config_data_count" not in registry_columns:
            connection.execute(
                "ALTER TABLE registries ADD COLUMN config_data_count INTEGER NOT NULL DEFAULT 0"
            )
        review_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(review_runs)")
        }
        if "schema_valid" not in review_columns:
            connection.execute(
                "ALTER TABLE review_runs ADD COLUMN schema_valid INTEGER NOT NULL DEFAULT 0"
            )
        if "independent" not in review_columns:
            connection.execute(
                "ALTER TABLE review_runs ADD COLUMN independent INTEGER NOT NULL DEFAULT 0"
            )
        test_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(test_runs)")
        }
        if "trusted_main_commit" not in test_columns:
            connection.execute("ALTER TABLE test_runs ADD COLUMN trusted_main_commit TEXT")
        if "candidate_merge_tree" not in test_columns:
            connection.execute("ALTER TABLE test_runs ADD COLUMN candidate_merge_tree TEXT")
        job_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)")
        }
        if "base_commit" not in job_columns:
            connection.execute("ALTER TABLE jobs ADD COLUMN base_commit TEXT")
        candidate_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(candidate_records)")
        }
        for name in ("branch", "commit_sha", "tree_sha", "diff_digest"):
            if name not in candidate_columns:
                connection.execute(f"ALTER TABLE candidate_records ADD COLUMN {name} TEXT")
        merge_columns = {
            str(row[1]) for row in connection.execute("PRAGMA table_info(merge_records)")
        }
        for name in (
            "candidate_digest",
            "candidate_commit",
            "review_run_id",
            "level3_test_run_id",
        ):
            if name not in merge_columns:
                column_type = "INTEGER" if name.endswith("_run_id") else "TEXT"
                connection.execute(
                    f"ALTER TABLE merge_records ADD COLUMN {name} {column_type}"
                )
        if "trusted_main_commit" not in merge_columns:
            connection.execute(
                "ALTER TABLE merge_records ADD COLUMN trusted_main_commit TEXT"
            )
        base_delivery_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(base_delivery_records)")
        }
        if "trusted_main_commit" not in base_delivery_columns:
            connection.execute(
                "ALTER TABLE base_delivery_records ADD COLUMN trusted_main_commit TEXT"
            )

        # Pre-pin scheduler databases may contain coding/integration jobs whose
        # checkout base is unknowable. They must never become claimable after an
        # upgrade. Preserve them as cancelled evidence while freeing the original
        # idempotency key so the scheduler can create a correctly pinned job.
        invalid_jobs = connection.execute(
            "SELECT job_id, rfc_id, state FROM jobs WHERE kind IN ('coding', 'integration') "
            "AND base_commit IS NULL AND state IN ('queued', 'leased', 'running')"
        ).fetchall()
        for job in invalid_jobs:
            if job["state"] == "queued":
                connection.execute(
                    "UPDATE jobs SET state = 'cancelled', "
                    "idempotency_key = idempotency_key || ':invalid-unpinned:' || job_id, "
                    "result_json = ?, updated_at = ? WHERE job_id = ?",
                    (
                        json.dumps(
                            {"failure_kind": "BASE_COMMIT_MIGRATION_REQUIRED"},
                            sort_keys=True,
                        ),
                        utc_now(),
                        job["job_id"],
                    ),
                )
            else:
                # Never release an active legacy lease here: the old executor may
                # still be writing. Cutover remains blocked until an external
                # supervisor confirms termination and resolves this record.
                connection.execute(
                    "INSERT OR IGNORE INTO migration_blockers VALUES (?, ?, ?, ?, NULL)",
                    (
                        f"unpinned-active-job:{job['job_id']}",
                        "UNPINNED_ACTIVE_JOB",
                        json.dumps(
                            {
                                "job_id": int(job["job_id"]),
                                "rfc_id": str(job["rfc_id"]),
                                "state": str(job["state"]),
                            },
                            sort_keys=True,
                        ),
                        utc_now(),
                    ),
                )
                task = connection.execute(
                    "SELECT state, event_sequence, revision_digest FROM tasks WHERE rfc_id = ?",
                    (job["rfc_id"],),
                ).fetchone()
                if task is not None and task["state"] not in {
                    TaskState.BLOCKED.value,
                    TaskState.DONE.value,
                }:
                    sequence = int(task["event_sequence"]) + 1
                    occurred_at = utc_now()
                    connection.execute(
                        "UPDATE tasks SET state = ?, reason = ?, event_sequence = ?, "
                        "updated_at = ? WHERE rfc_id = ?",
                        (
                            TaskState.BLOCKED.value,
                            "legacy active job had no pinned base commit",
                            sequence,
                            occurred_at,
                            job["rfc_id"],
                        ),
                    )
                    connection.execute(
                        "INSERT INTO transitions "
                        "(rfc_id, sequence, from_state, to_state, reason, actor, "
                        "revision_digest, occurred_at, metadata_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            job["rfc_id"],
                            sequence,
                            task["state"],
                            TaskState.BLOCKED.value,
                            "legacy active job had no pinned base commit",
                            "schema-migration",
                            task["revision_digest"],
                            occurred_at,
                            json.dumps(
                                {
                                    "failure_kind": "BASE_COMMIT_MIGRATION_REQUIRED",
                                    "job_id": int(job["job_id"]),
                                },
                                sort_keys=True,
                            ),
                        ),
                    )
        connection.execute(
            "INSERT OR IGNORE INTO transition_outbox(rfc_id, sequence) "
            "SELECT rfc_id, sequence FROM transitions"
        )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        committed = False
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
            committed = True
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        if committed:
            try:
                self.materialize_transition_evidence()
            except OSError:
                # The committed outbox row is the durable source of truth. The
                # daemon retries projection after transient filesystem errors.
                pass

    def import_registry(self, registry: Registry) -> None:
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO registries "
                "(digest, baseline_commit, classification_sha256, in_scope_count, "
                "config_data_count, imported_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    registry.digest,
                    registry.baseline_commit,
                    registry.classification_sha256,
                    registry.in_scope_count,
                    registry.config_data_count,
                    now,
                ),
            )
            for rfc_id in registry.topological_order:
                rfc = registry.rfcs[rfc_id]
                payload = json.dumps(rfc.raw, ensure_ascii=False, sort_keys=True)
                supersedes = rfc.raw.get("supersedes")
                if rfc.revision > 1:
                    predecessor = connection.execute(
                        "SELECT revision_digest FROM rfc_revisions "
                        "WHERE rfc_id = ? AND revision = ?",
                        (rfc_id, rfc.revision - 1),
                    ).fetchone()
                    if predecessor is not None and (
                        not isinstance(supersedes, dict)
                        or predecessor["revision_digest"]
                        != supersedes.get("revision_digest")
                    ):
                        raise StateConflict(
                            f"revision lineage conflict for {rfc_id} revision {rfc.revision}"
                        )
                existing = connection.execute(
                    "SELECT revision_digest, payload_json FROM rfc_revisions "
                    "WHERE rfc_id = ? AND revision = ?",
                    (rfc_id, rfc.revision),
                ).fetchone()
                if existing and (
                    existing["revision_digest"] != rfc.revision_digest
                    or existing["payload_json"] != payload
                ):
                    raise StateConflict(
                        f"immutable revision conflict for {rfc_id} revision {rfc.revision}"
                    )
                connection.execute(
                    "INSERT OR IGNORE INTO rfc_revisions VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        rfc_id,
                        rfc.revision,
                        rfc.revision_digest,
                        registry.digest,
                        payload,
                        now,
                    ),
                )
                task = connection.execute(
                    "SELECT revision_digest, state FROM tasks WHERE rfc_id = ?", (rfc_id,)
                ).fetchone()
                if task is None:
                    connection.execute(
                        "INSERT INTO tasks VALUES (?, ?, ?, NULL, 0, ?, ?)",
                        (rfc_id, rfc.revision_digest, TaskState.DRAFT.value, now, now),
                    )
                elif task["revision_digest"] != rfc.revision_digest:
                    state = TaskState(task["state"])
                    if state not in {TaskState.DRAFT, TaskState.VALIDATED, TaskState.BLOCKED}:
                        raise StateConflict(
                            f"cannot replace pinned revision for active task {rfc_id} in {state.value}"
                        )
                    active_lease = connection.execute(
                        "SELECT leases.lease_id FROM leases "
                        "JOIN jobs ON jobs.job_id = leases.job_id "
                        "WHERE jobs.rfc_id = ? AND jobs.revision_digest = ? LIMIT 1",
                        (rfc_id, task["revision_digest"]),
                    ).fetchone()
                    if active_lease is not None:
                        raise StateConflict(
                            f"cannot replace pinned revision for {rfc_id} while a lease exists"
                        )
                    cancellation = json.dumps(
                        {
                            "failure_kind": "REVISION_SUPERSEDED",
                            "superseded_by": rfc.revision_digest,
                        },
                        sort_keys=True,
                    )
                    connection.execute(
                        "UPDATE jobs SET state = 'cancelled', result_json = ?, updated_at = ? "
                        "WHERE rfc_id = ? AND revision_digest = ? "
                        "AND state IN ('queued', 'leased', 'running')",
                        (cancellation, now, rfc_id, task["revision_digest"]),
                    )
                    connection.execute(
                        "UPDATE tasks SET revision_digest = ?, state = ?, reason = NULL, "
                        "updated_at = ? WHERE rfc_id = ?",
                        (rfc.revision_digest, TaskState.DRAFT.value, now, rfc_id),
                    )

    def task(self, rfc_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
        if row is None:
            raise KeyError(rfc_id)
        return dict(row)

    def list_tasks(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM tasks ORDER BY rfc_id").fetchall()
        return [dict(row) for row in rows]

    def transition(
        self,
        rfc_id: str,
        expected: TaskState,
        target: TaskState,
        actor: str,
        *,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if target not in ALLOWED_TRANSITIONS[expected]:
            raise StateConflict(f"invalid transition {expected.value} -> {target.value}")
        if not actor.strip():
            raise ValueError("actor must be non-empty")
        occurred_at = utc_now()
        details = metadata or {}
        with self.transaction() as connection:
            current = connection.execute(
                "SELECT * FROM tasks WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            if current is None:
                raise KeyError(rfc_id)
            if current["state"] != expected.value:
                raise StateConflict(
                    f"{rfc_id} expected {expected.value}, found {current['state']}"
                )
            sequence = int(current["event_sequence"]) + 1
            updated = connection.execute(
                "UPDATE tasks SET state = ?, reason = ?, event_sequence = ?, updated_at = ? "
                "WHERE rfc_id = ? AND state = ? AND event_sequence = ?",
                (
                    target.value,
                    reason,
                    sequence,
                    occurred_at,
                    rfc_id,
                    expected.value,
                    current["event_sequence"],
                ),
            )
            if updated.rowcount != 1:
                raise StateConflict(f"concurrent transition for {rfc_id}")
            connection.execute(
                "INSERT INTO transitions "
                "(rfc_id, sequence, from_state, to_state, reason, actor, "
                "revision_digest, occurred_at, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rfc_id,
                    sequence,
                    expected.value,
                    target.value,
                    reason,
                    actor,
                    current["revision_digest"],
                    occurred_at,
                    json.dumps(details, ensure_ascii=False, sort_keys=True),
                ),
            )
        return {
            "rfc_id": rfc_id,
            "sequence": sequence,
            "from_state": expected.value,
            "to_state": target.value,
            "reason": reason,
            "actor": actor,
            "revision_digest": current["revision_digest"],
            "occurred_at": occurred_at,
            "metadata": details,
        }

    def transitions(self, rfc_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM transitions WHERE rfc_id = ? ORDER BY sequence", (rfc_id,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json"))
            result.append(value)
        return result

    def materialize_transition_evidence(self) -> int:
        if self.evidence_root is None:
            return 0
        connection = self.connect()
        try:
            # Serialize database transitions with their filesystem projection. This
            # prevents two materializers from acknowledging projections built from
            # different transition snapshots.
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT transitions.*, transition_outbox.materialized "
                "FROM transitions JOIN transition_outbox USING(rfc_id, sequence) "
                "ORDER BY transitions.rfc_id, transitions.sequence"
            ).fetchall()
            grouped: dict[str, list[tuple[int, bytes, bool]]] = {}
            for row in rows:
                event = {
                    "rfc_id": row["rfc_id"],
                    "sequence": int(row["sequence"]),
                    "from_state": row["from_state"],
                    "to_state": row["to_state"],
                    "reason": row["reason"],
                    "actor": row["actor"],
                    "revision_digest": row["revision_digest"],
                    "occurred_at": row["occurred_at"],
                    "metadata": json.loads(row["metadata_json"]),
                }
                content = (
                    json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
                ).encode("utf-8")
                grouped.setdefault(str(row["rfc_id"]), []).append(
                    (int(row["sequence"]), content, bool(row["materialized"]))
                )

            materialized = 0
            for rfc_id, events in grouped.items():
                directory = self.evidence_root / rfc_id
                event_directory = directory / "scheduler-events"
                event_directory.mkdir(parents=True, exist_ok=True)
                for sequence, content, _ in events:
                    path = event_directory / f"{sequence:08d}.json"
                    if path.exists():
                        if path.read_bytes() != content:
                            raise StateConflict(
                                f"immutable transition evidence differs: {path}"
                            )
                    else:
                        self._atomic_write(path, content)

                # The outbox is acknowledged only after both immutable events and
                # the complete JSONL projection have reached their final paths.
                projection = directory / "scheduler-events.jsonl"
                projection_content = b"".join(content for _, content, _ in events)
                if not projection.exists() or projection.read_bytes() != projection_content:
                    self._atomic_write(projection, projection_content)
                pending_sequences = [
                    sequence for sequence, _, already_materialized in events
                    if not already_materialized
                ]
                if pending_sequences:
                    placeholders = ",".join("?" for _ in pending_sequences)
                    connection.execute(
                        "UPDATE transition_outbox SET materialized = 1, materialized_at = ? "
                        f"WHERE rfc_id = ? AND sequence IN ({placeholders}) "
                        "AND materialized = 0",
                        (utc_now(), rfc_id, *pending_sequences),
                    )
                    materialized += len(pending_sequences)
            connection.commit()
            return materialized
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o640)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            descriptor = -1
            os.replace(temporary, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
