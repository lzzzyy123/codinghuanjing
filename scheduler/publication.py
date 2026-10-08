"""Durable intent and recovery records for remote Git publication."""

from __future__ import annotations

from dataclasses import dataclass

from .state_store import StateConflict, StateStore, utc_now


TERMINAL_STATES = frozenset({"confirmed", "not_published", "blocked"})


@dataclass(frozen=True)
class PublicationRecord:
    publication_id: int
    rfc_id: str
    revision_digest: str
    candidate_digest: str
    lease_id: str
    fencing_token: int
    remote: str
    ref_name: str
    previous_commit: str | None
    target_commit: str
    state: str
    observed_commit: str | None
    last_error: str | None


@dataclass(frozen=True)
class PublicationPreparation:
    publication_id: int
    state: str


class PublicationJournal:
    """Records external push intent before Git can change a remote ref."""

    def __init__(self, store: StateStore) -> None:
        self.store = store

    def prepare(
        self,
        *,
        rfc_id: str,
        revision_digest: str,
        candidate_digest: str,
        lease_id: str,
        fencing_token: int,
        remote: str,
        ref_name: str,
        previous_commit: str | None,
        target_commit: str,
    ) -> PublicationPreparation:
        now = utc_now()
        identity = (
            rfc_id,
            revision_digest,
            candidate_digest,
            remote,
            ref_name,
            target_commit,
        )
        conflict: str | None = None
        publication_id: int | None = None
        prepared_state: str | None = None
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM publication_records WHERE rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND remote = ? "
                "AND ref_name = ? AND target_commit = ?",
                identity,
            ).fetchone()
            if existing is not None:
                publication_id = int(existing["publication_id"])
                if existing["state"] == "blocked":
                    raise StateConflict(
                        "remote publication is blocked by an unresolved ref conflict"
                    )
                current_token = int(existing["fencing_token"])
                current_lease = str(existing["lease_id"])
                if fencing_token < current_token or (
                    fencing_token == current_token and current_lease != lease_id
                ):
                    raise StateConflict("publication prepare has a stale lease fence")
                if existing["state"] == "confirmed":
                    if previous_commit != target_commit:
                        conflict = "confirmed remote ref diverged from its target"
                    else:
                        cursor = connection.execute(
                            "UPDATE publication_records SET lease_id = ?, "
                            "fencing_token = ?, updated_at = ? WHERE publication_id = ? "
                            "AND lease_id = ? AND fencing_token = ? AND state = 'confirmed'",
                            (
                                lease_id,
                                fencing_token,
                                now,
                                publication_id,
                                current_lease,
                                current_token,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise StateConflict(
                                "publication fence changed during confirmed retry"
                            )
                        prepared_state = "confirmed"
                else:
                    state = str(existing["state"])
                    if (
                        state == "prepared"
                        and existing["previous_commit"] != previous_commit
                    ):
                        conflict = "remote ref changed while publication intent was unresolved"
                    elif state == "published" and previous_commit != target_commit:
                        conflict = "published remote ref diverged before confirmation"
                    if state == "not_published":
                        active = connection.execute(
                            "SELECT publication_id FROM publication_records "
                            "WHERE remote = ? AND ref_name = ? AND publication_id != ? "
                            "AND state IN ('prepared', 'published', 'blocked') "
                            "ORDER BY publication_id LIMIT 1",
                            (remote, ref_name, publication_id),
                        ).fetchone()
                        if active is not None:
                            raise StateConflict(
                                "remote ref has an unresolved publication intent"
                            )
                if conflict is not None and existing["state"] == "prepared":
                    cursor = connection.execute(
                        "UPDATE publication_records SET lease_id = ?, fencing_token = ?, "
                        "state = 'blocked', observed_commit = ?, last_error = ?, "
                        "updated_at = ? WHERE publication_id = ? AND lease_id = ? "
                        "AND fencing_token = ? AND state = 'prepared'",
                        (
                            lease_id,
                            fencing_token,
                            previous_commit,
                            conflict,
                            now,
                            publication_id,
                            current_lease,
                            current_token,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StateConflict(
                            "publication fence changed while blocking an intent"
                        )
                elif conflict is not None:
                    cursor = connection.execute(
                        "UPDATE publication_records SET lease_id = ?, fencing_token = ?, "
                        "observed_commit = ?, last_error = ?, updated_at = ? "
                        "WHERE publication_id = ? AND lease_id = ? AND fencing_token = ?",
                        (
                            lease_id,
                            fencing_token,
                            previous_commit,
                            conflict,
                            now,
                            publication_id,
                            current_lease,
                            current_token,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StateConflict(
                            "publication fence changed while recording divergence"
                        )
                elif prepared_state != "confirmed":
                    next_state = "published" if state == "published" else "prepared"
                    next_previous = (
                        previous_commit
                        if state == "not_published"
                        else existing["previous_commit"]
                    )
                    cursor = connection.execute(
                        "UPDATE publication_records SET lease_id = ?, fencing_token = ?, "
                        "previous_commit = ?, state = ?, observed_commit = NULL, "
                        "last_error = NULL, updated_at = ? WHERE publication_id = ? "
                        "AND lease_id = ? AND fencing_token = ?",
                        (
                            lease_id,
                            fencing_token,
                            next_previous,
                            next_state,
                            now,
                            publication_id,
                            current_lease,
                            current_token,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise StateConflict(
                            "publication fence changed during prepare"
                        )
                    prepared_state = next_state
            else:
                active = connection.execute(
                    "SELECT publication_id FROM publication_records WHERE remote = ? "
                    "AND ref_name = ? AND state IN ('prepared', 'published', 'blocked') "
                    "ORDER BY publication_id LIMIT 1",
                    (remote, ref_name),
                ).fetchone()
                if active is not None:
                    raise StateConflict(
                        "remote ref has an unresolved publication intent"
                    )
                cursor = connection.execute(
                    "INSERT INTO publication_records "
                    "(rfc_id, revision_digest, candidate_digest, lease_id, fencing_token, "
                    "remote, ref_name, previous_commit, target_commit, state, observed_commit, "
                    "last_error, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', NULL, NULL, ?, ?)",
                    (
                        rfc_id,
                        revision_digest,
                        candidate_digest,
                        lease_id,
                        fencing_token,
                        remote,
                        ref_name,
                        previous_commit,
                        target_commit,
                        now,
                        now,
                    ),
                )
                publication_id = int(cursor.lastrowid)
                prepared_state = "prepared"
        if conflict is not None:
            raise StateConflict(conflict)
        if publication_id is None or prepared_state is None:
            raise StateConflict("publication intent was not persisted")
        return PublicationPreparation(publication_id, prepared_state)

    def mark_published(
        self,
        publication_id: int,
        observed_commit: str,
        *,
        lease_id: str,
        fencing_token: int,
    ) -> None:
        with self.store.transaction() as connection:
            record = self._required(connection, publication_id)
            if observed_commit != record["target_commit"]:
                raise StateConflict("published ref does not match the journal target")
            if record["state"] == "blocked":
                raise StateConflict("blocked publication cannot be marked published")
            if record["state"] == "confirmed":
                return
            self._require_current_fence(record, lease_id, fencing_token)
            if record["state"] not in {"prepared", "published"}:
                raise StateConflict(
                    "publication cannot be marked published from its current state"
                )
            cursor = connection.execute(
                "UPDATE publication_records SET state = 'published', observed_commit = ?, "
                "last_error = NULL, updated_at = ? WHERE publication_id = ? "
                "AND lease_id = ? AND fencing_token = ? "
                "AND state IN ('prepared', 'published')",
                (
                    observed_commit,
                    utc_now(),
                    publication_id,
                    lease_id,
                    fencing_token,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflict("publication fence changed during mark_published")

    def confirm(
        self, publication_id: int, *, lease_id: str, fencing_token: int
    ) -> None:
        with self.store.transaction() as connection:
            record = self._required(connection, publication_id)
            if record["state"] == "confirmed":
                return
            self._require_current_fence(record, lease_id, fencing_token)
            if record["state"] != "published":
                raise StateConflict("only an observed publication can be confirmed")
            cursor = connection.execute(
                "UPDATE publication_records SET state = 'confirmed', updated_at = ? "
                "WHERE publication_id = ? AND lease_id = ? AND fencing_token = ? "
                "AND state = 'published'",
                (utc_now(), publication_id, lease_id, fencing_token),
            )
            if cursor.rowcount != 1:
                raise StateConflict("publication fence changed during confirmation")

    def note_error(
        self,
        publication_id: int,
        error: str,
        *,
        lease_id: str,
        fencing_token: int,
    ) -> None:
        with self.store.transaction() as connection:
            record = self._required(connection, publication_id)
            if record["state"] in TERMINAL_STATES:
                return
            self._require_current_fence(record, lease_id, fencing_token)
            cursor = connection.execute(
                "UPDATE publication_records SET last_error = ?, updated_at = ? "
                "WHERE publication_id = ? AND lease_id = ? AND fencing_token = ? "
                "AND state IN ('prepared', 'published')",
                (
                    error[-2000:],
                    utc_now(),
                    publication_id,
                    lease_id,
                    fencing_token,
                ),
            )
            if cursor.rowcount != 1:
                raise StateConflict("publication fence changed while recording failure")

    def pending(self) -> tuple[PublicationRecord, ...]:
        with self.store.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM publication_records WHERE state IN ('prepared', 'published') "
                "ORDER BY publication_id"
            ).fetchall()
        return tuple(self._record(row) for row in rows)

    def reconcile(
        self, publication_id: int, observed_commit: str | None
    ) -> str:
        with self.store.transaction() as connection:
            record = self._required(connection, publication_id)
            if record["state"] in TERMINAL_STATES:
                return str(record["state"])
            if record["state"] == "published":
                state = "published"
                error = (
                    None
                    if observed_commit == record["target_commit"]
                    else "remote ref diverged after target publication was observed"
                )
            elif observed_commit == record["target_commit"]:
                state = "published"
                error = None
            elif observed_commit == record["previous_commit"]:
                state = "not_published"
                error = None
            else:
                state = "blocked"
                error = "remote ref differs from both previous and target commits"
            connection.execute(
                "UPDATE publication_records SET state = ?, observed_commit = ?, "
                "last_error = ?, updated_at = ? WHERE publication_id = ?",
                (state, observed_commit, error, utc_now(), publication_id),
            )
            return state

    @staticmethod
    def _require_current_fence(record, lease_id: str, fencing_token: int) -> None:
        if (
            record["lease_id"] != lease_id
            or int(record["fencing_token"]) != fencing_token
        ):
            raise StateConflict("publication mutation has a stale lease fence")

    def get(self, publication_id: int) -> PublicationRecord:
        with self.store.connect() as connection:
            row = self._required(connection, publication_id)
        return self._record(row)

    @staticmethod
    def _required(connection, publication_id: int):
        row = connection.execute(
            "SELECT * FROM publication_records WHERE publication_id = ?",
            (publication_id,),
        ).fetchone()
        if row is None:
            raise StateConflict("publication record does not exist")
        return row

    @staticmethod
    def _record(row) -> PublicationRecord:
        return PublicationRecord(
            publication_id=int(row["publication_id"]),
            rfc_id=str(row["rfc_id"]),
            revision_digest=str(row["revision_digest"]),
            candidate_digest=str(row["candidate_digest"]),
            lease_id=str(row["lease_id"]),
            fencing_token=int(row["fencing_token"]),
            remote=str(row["remote"]),
            ref_name=str(row["ref_name"]),
            previous_commit=row["previous_commit"],
            target_commit=str(row["target_commit"]),
            state=str(row["state"]),
            observed_commit=row["observed_commit"],
            last_error=row["last_error"],
        )
