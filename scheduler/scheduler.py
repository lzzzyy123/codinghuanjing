"""Dependency admission and merge evidence for the shadow scheduler."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import TaskState
from .registry import Registry
from .state_store import StateConflict, StateStore, utc_now
from .leases import QueueStore


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DagScheduler:
    def __init__(self, registry: Registry, store: StateStore):
        self.registry = registry
        self.store = store

    def validate_tasks(self, actor: str = "registry-validator") -> list[str]:
        changed: list[str] = []
        for rfc_id in self.registry.topological_order:
            task = self.store.task(rfc_id)
            if task["revision_digest"] != self.registry.rfcs[rfc_id].revision_digest:
                raise StateConflict(f"{rfc_id} active revision does not match registry")
            if task["state"] == TaskState.DRAFT.value:
                self.store.transition(
                    rfc_id,
                    TaskState.DRAFT,
                    TaskState.VALIDATED,
                    actor,
                    reason="registry, ownership, DAG, and contract validation passed",
                )
                changed.append(rfc_id)
        return changed

    def record_merge(
        self,
        rfc_id: str,
        merge_commit: str,
        contracts: dict[str, str],
        recorded_by: str,
    ) -> None:
        if not COMMIT_RE.fullmatch(merge_commit):
            raise ValueError("merge_commit must be a full Git SHA")
        expected = self.registry.rfcs[rfc_id].provides
        if contracts != expected:
            raise StateConflict(f"merged contract evidence does not match {rfc_id} revision")
        task = self.store.task(rfc_id)
        if task["state"] != TaskState.DONE.value:
            raise StateConflict(f"cannot record merge for {rfc_id} before integration is Done")
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM merge_records WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            values = (
                rfc_id,
                task["revision_digest"],
                merge_commit,
                json.dumps(contracts, sort_keys=True),
                recorded_by,
                utc_now(),
            )
            if existing:
                if (
                    existing["revision_digest"] != task["revision_digest"]
                    or existing["merge_commit"] != merge_commit
                    or json.loads(existing["contracts_json"]) != contracts
                ):
                    raise StateConflict(f"conflicting merge evidence for {rfc_id}")
                return
            connection.execute("INSERT INTO merge_records VALUES (?, ?, ?, ?, ?, ?)", values)

    def record_base_delivery(
        self,
        merged_base_commit: str,
        recorded_by: str,
        *,
        ancestor_verified: bool,
    ) -> None:
        required_rfc = self.registry.base_delivery_rfc
        required_commit = self.registry.base_delivery_commit
        if required_rfc is None or required_commit is None:
            raise StateConflict("registry has no external base delivery gate")
        if not COMMIT_RE.fullmatch(merged_base_commit):
            raise ValueError("merged_base_commit must be a full Git SHA")
        if not ancestor_verified:
            raise StateConflict("base delivery requires verified Git ancestry")
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM base_delivery_records WHERE required_rfc_id = ?",
                (required_rfc,),
            ).fetchone()
            values = (
                required_rfc,
                required_commit,
                merged_base_commit,
                1,
                recorded_by,
                utc_now(),
            )
            if existing:
                if (
                    existing["required_commit"] != required_commit
                    or existing["merged_base_commit"] != merged_base_commit
                    or not existing["ancestor_verified"]
                ):
                    raise StateConflict("conflicting external base delivery evidence")
                return
            connection.execute(
                "INSERT INTO base_delivery_records VALUES (?, ?, ?, ?, ?, ?)", values
            )

    def refresh_ready(self, actor: str = "dag-scheduler") -> dict[str, list[str]]:
        ready: list[str] = []
        blocked: list[str] = []
        with self.store.connect() as connection:
            merges = {
                row["rfc_id"]: dict(row)
                for row in connection.execute("SELECT * FROM merge_records").fetchall()
            }
            base_ready = True
            if self.registry.base_delivery_rfc:
                base = connection.execute(
                    "SELECT * FROM base_delivery_records WHERE required_rfc_id = ?",
                    (self.registry.base_delivery_rfc,),
                ).fetchone()
                base_ready = bool(
                    base
                    and base["required_commit"] == self.registry.base_delivery_commit
                    and base["ancestor_verified"]
                )
        for rfc_id in self.registry.topological_order:
            task = self.store.task(rfc_id)
            if task["state"] != TaskState.VALIDATED.value:
                continue
            rfc = self.registry.rfcs[rfc_id]
            if not base_ready:
                blocked.append(
                    f"{rfc_id}: external base {self.registry.base_delivery_rfc} is not merged and ancestry-verified"
                )
                continue
            reason = self._dependency_blocker(rfc.depends_on, rfc.requires, merges)
            if reason is None:
                self.store.transition(
                    rfc_id,
                    TaskState.VALIDATED,
                    TaskState.READY,
                    actor,
                    reason="all dependency merge and contract gates passed",
                )
                ready.append(rfc_id)
            else:
                blocked.append(f"{rfc_id}: {reason}")
        return {"ready": ready, "blocked": blocked}

    def enqueue_ready(self, queue: QueueStore | None = None) -> list[int]:
        """Materialize one idempotent initial Coder job for every Ready revision."""
        queue = queue or QueueStore(self.store)
        job_ids: list[int] = []
        for task in self.store.list_tasks():
            if task["state"] != TaskState.READY.value:
                continue
            revision = str(task["revision_digest"])
            job_ids.append(
                queue.enqueue(
                    str(task["rfc_id"]),
                    "coding",
                    f"coding:{task['rfc_id']}:{revision}",
                )
            )
        return job_ids

    def readiness_blockers(self) -> list[str]:
        with self.store.connect() as connection:
            merges = {
                row["rfc_id"]: dict(row)
                for row in connection.execute("SELECT * FROM merge_records").fetchall()
            }
            base_ready = True
            if self.registry.base_delivery_rfc:
                base = connection.execute(
                    "SELECT * FROM base_delivery_records WHERE required_rfc_id = ?",
                    (self.registry.base_delivery_rfc,),
                ).fetchone()
                base_ready = bool(
                    base
                    and base["required_commit"] == self.registry.base_delivery_commit
                    and base["ancestor_verified"]
                )
        blockers: list[str] = []
        for rfc_id in self.registry.topological_order:
            task = self.store.task(rfc_id)
            if task["state"] != TaskState.VALIDATED.value:
                continue
            if not base_ready:
                blockers.append(
                    f"{rfc_id}: external base {self.registry.base_delivery_rfc} is not merged and ancestry-verified"
                )
                continue
            rfc = self.registry.rfcs[rfc_id]
            reason = self._dependency_blocker(rfc.depends_on, rfc.requires, merges)
            if reason:
                blockers.append(f"{rfc_id}: {reason}")
        return blockers

    def _dependency_blocker(
        self,
        dependencies: tuple[str, ...],
        required_contracts: dict[str, str],
        merges: dict[str, dict[str, Any]],
    ) -> str | None:
        for dependency in dependencies:
            evidence = merges.get(dependency)
            if evidence is None:
                return f"dependency {dependency} is not merged"
            expected_revision = self.registry.rfcs[dependency].revision_digest
            if evidence["revision_digest"] != expected_revision:
                return f"dependency {dependency} merge pins a stale revision"
        available: dict[str, str] = {}
        for dependency in dependencies:
            evidence = merges[dependency]
            available.update(json.loads(evidence["contracts_json"]))
        for name, digest in required_contracts.items():
            if available.get(name) != digest:
                return f"required contract {name} is not present at {digest}"
        return None
