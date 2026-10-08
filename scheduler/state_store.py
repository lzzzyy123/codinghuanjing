"""SQLite-backed durable scheduler state and transition evidence."""

from __future__ import annotations

import json
import os
import sqlite3
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
CREATE TABLE IF NOT EXISTS merge_records (
    rfc_id TEXT PRIMARY KEY REFERENCES tasks(rfc_id),
    revision_digest TEXT NOT NULL REFERENCES rfc_revisions(revision_digest),
    merge_commit TEXT NOT NULL,
    contracts_json TEXT NOT NULL,
    recorded_by TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS base_delivery_records (
    required_rfc_id TEXT PRIMARY KEY,
    required_commit TEXT NOT NULL,
    merged_base_commit TEXT NOT NULL,
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

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

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
        event = {
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
        self._append_evidence(rfc_id, event)
        return event

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

    def _append_evidence(self, rfc_id: str, event: dict[str, Any]) -> None:
        if self.evidence_root is None:
            return
        directory = self.evidence_root / rfc_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "scheduler-events.jsonl"
        line = json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(descriptor, line.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
