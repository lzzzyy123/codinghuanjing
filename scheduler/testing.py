"""Three-level test evidence and exact-input cache policy."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .state_store import StateConflict, StateStore, utc_now


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def digest_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TestIdentity:
    rfc_id: str
    revision_digest: str
    candidate_digest: str
    level: int
    command_digest: str
    environment_digest: str
    baseline_commit: str | None


class TestEvidenceStore:
    def __init__(self, state: StateStore):
        self.state = state

    @staticmethod
    def identity(
        rfc_id: str,
        revision_digest: str,
        candidate_digest: str,
        level: int,
        commands: list[str],
        environment: dict[str, str],
        baseline_commit: str | None = None,
    ) -> TestIdentity:
        if level not in {1, 2, 3}:
            raise ValueError("test level must be 1, 2, or 3")
        for value in (revision_digest, candidate_digest):
            if not DIGEST_RE.fullmatch(value):
                raise ValueError("revision and candidate must be sha256 digests")
        if level >= 2 and (baseline_commit is None or not COMMIT_RE.fullmatch(baseline_commit)):
            raise ValueError("Level 2/3 requires a full Python baseline commit")
        return TestIdentity(
            rfc_id=rfc_id,
            revision_digest=revision_digest,
            candidate_digest=candidate_digest,
            level=level,
            command_digest=digest_json(commands),
            environment_digest=digest_json(environment),
            baseline_commit=baseline_commit,
        )

    def record(
        self,
        identity: TestIdentity,
        status: str,
        evidence_digest: str,
        *,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        with self.state.transaction() as connection:
            self.record_in_transaction(
                connection,
                identity,
                status,
                evidence_digest,
                started_at=started_at,
                completed_at=completed_at,
            )

    @staticmethod
    def record_in_transaction(
        connection: sqlite3.Connection,
        identity: TestIdentity,
        status: str,
        evidence_digest: str,
        *,
        expected_rfc_id: str | None = None,
        expected_revision_digest: str | None = None,
        expected_candidate_digest: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> None:
        if status not in {"PASS", "FAIL", "INFRA_FAILED"}:
            raise ValueError("invalid test status")
        if not DIGEST_RE.fullmatch(evidence_digest):
            raise ValueError("evidence must be a sha256 digest")
        if identity.level not in {1, 2, 3}:
            raise ValueError("test level must be 1, 2, or 3")
        for value in (identity.revision_digest, identity.candidate_digest):
            if not DIGEST_RE.fullmatch(value):
                raise ValueError("revision and candidate must be sha256 digests")
        if identity.level >= 2 and (
            identity.baseline_commit is None
            or not COMMIT_RE.fullmatch(identity.baseline_commit)
        ):
            raise ValueError("Level 2/3 requires a full Python baseline commit")
        expected = (
            ("RFC", expected_rfc_id, identity.rfc_id),
            ("revision", expected_revision_digest, identity.revision_digest),
            ("candidate", expected_candidate_digest, identity.candidate_digest),
        )
        for label, required, actual in expected:
            if required is not None and required != actual:
                raise StateConflict(f"test {label} does not match the leased job")
        revision = connection.execute(
            "SELECT rfc_id FROM rfc_revisions WHERE revision_digest = ?",
            (identity.revision_digest,),
        ).fetchone()
        if revision is None or revision["rfc_id"] != identity.rfc_id:
            raise StateConflict("test revision does not belong to its RFC")
        task = connection.execute(
            "SELECT revision_digest FROM tasks WHERE rfc_id = ?", (identity.rfc_id,)
        ).fetchone()
        if task is None or task["revision_digest"] != identity.revision_digest:
            raise StateConflict("test revision is not the RFC's active revision")
        start = started_at or utc_now()
        complete = completed_at or utc_now()
        values = (
            identity.rfc_id,
            identity.revision_digest,
            identity.candidate_digest,
            identity.level,
            identity.command_digest,
            identity.environment_digest,
            identity.baseline_commit,
            status,
            evidence_digest,
            start,
            complete,
        )
        existing = connection.execute(
            "SELECT status, evidence_digest FROM test_runs WHERE rfc_id = ? "
            "AND revision_digest = ? AND candidate_digest = ? AND level = ? "
            "AND command_digest = ? AND environment_digest = ? "
            "AND baseline_commit IS ?",
            (
                identity.rfc_id,
                identity.revision_digest,
                identity.candidate_digest,
                identity.level,
                identity.command_digest,
                identity.environment_digest,
                identity.baseline_commit,
            ),
        ).fetchone()
        if existing:
            if existing["status"] != status or existing["evidence_digest"] != evidence_digest:
                raise StateConflict("test identity already has different immutable evidence")
            return
        connection.execute(
            "INSERT INTO test_runs "
            "(rfc_id, revision_digest, candidate_digest, level, command_digest, "
            "environment_digest, baseline_commit, status, evidence_digest, started_at, "
            "completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            values,
        )

    def reusable_pass(self, identity: TestIdentity) -> str | None:
        with self.state.connect() as connection:
            row = connection.execute(
                "SELECT evidence_digest FROM test_runs WHERE rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND level = ? "
                "AND command_digest = ? AND environment_digest = ? "
                "AND baseline_commit IS ? AND status = 'PASS'",
                (
                    identity.rfc_id,
                    identity.revision_digest,
                    identity.candidate_digest,
                    identity.level,
                    identity.command_digest,
                    identity.environment_digest,
                    identity.baseline_commit,
                ),
            ).fetchone()
        return None if row is None else str(row["evidence_digest"])
