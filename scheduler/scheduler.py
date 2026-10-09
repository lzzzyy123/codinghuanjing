"""Dependency admission and merge evidence for the shadow scheduler."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import TaskState
from .registry import Registry
from .state_store import StateConflict, StateStore, utc_now
from .leases import QueueStore
from .git_verifier import RepositoryGitVerifier


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class DagScheduler:
    def __init__(
        self,
        registry: Registry,
        store: StateStore,
        git_verifier: RepositoryGitVerifier | None = None,
    ):
        self.registry = registry
        self.store = store
        self.git_verifier = git_verifier

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
        candidate_digest: str,
        merge_commit: str,
        contracts: dict[str, str],
        recorded_by: str,
    ) -> None:
        if not COMMIT_RE.fullmatch(merge_commit):
            raise ValueError("merge_commit must be a full Git SHA")
        if self.git_verifier is None:
            raise StateConflict("merge evidence requires the bound Git verifier")
        trusted_main_commit = self.git_verifier.require_on_trusted_main(merge_commit)
        expected = self.registry.rfcs[rfc_id].provides
        if contracts != expected:
            raise StateConflict(f"merged contract evidence does not match {rfc_id} revision")
        task = self.store.task(rfc_id)
        if task["state"] != TaskState.DONE.value:
            raise StateConflict(f"cannot record merge for {rfc_id} before integration is Done")
        with self.store.transaction() as connection:
            candidate = connection.execute(
                "SELECT candidate_digest, commit_sha FROM candidate_records "
                "WHERE rfc_id = ? AND revision_digest = ? AND candidate_digest = ?",
                (rfc_id, task["revision_digest"], candidate_digest),
            ).fetchone()
            if candidate is None or not candidate["commit_sha"]:
                raise StateConflict("merge evidence requires the exact persisted candidate")
            integration = connection.execute(
                "SELECT 1 FROM jobs WHERE rfc_id = ? AND revision_digest = ? "
                "AND kind = 'integration' AND state = 'passed' AND candidate_digest = ?",
                (rfc_id, task["revision_digest"], candidate_digest),
            ).fetchone()
            if integration is None:
                raise StateConflict("merge evidence requires passed integration for the candidate")
            review = connection.execute(
                "SELECT review_run_id FROM review_runs WHERE rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND verdict = 'PASS' "
                "AND infrastructure_status = 'PASS' AND schema_valid = 1 "
                "AND independent = 1 ORDER BY review_run_id DESC LIMIT 1",
                (rfc_id, task["revision_digest"], candidate_digest),
            ).fetchone()
            if review is None:
                raise StateConflict("merge evidence requires independent PASS for the candidate")
            level3 = connection.execute(
                "SELECT test_run_id, trusted_main_commit, candidate_merge_tree "
                "FROM test_runs WHERE rfc_id = ? "
                "AND revision_digest = ? AND candidate_digest = ? AND level = 3 "
                "AND status = 'PASS' AND trusted_main_commit IS NOT NULL "
                "AND candidate_merge_tree IS NOT NULL "
                "ORDER BY test_run_id DESC LIMIT 1",
                (rfc_id, task["revision_digest"], candidate_digest),
            ).fetchone()
            if level3 is None:
                raise StateConflict("merge evidence requires Level 3 PASS for the candidate")
            self.git_verifier.require_ancestor(
                str(level3["trusted_main_commit"]), merge_commit
            )
            if self.git_verifier.candidate_tree(merge_commit) != level3["candidate_merge_tree"]:
                raise StateConflict("merge commit tree does not match the Level 3 candidate tree")
            self.git_verifier.require_ancestor(str(candidate["commit_sha"]), merge_commit)
            existing = connection.execute(
                "SELECT * FROM merge_records WHERE rfc_id = ?", (rfc_id,)
            ).fetchone()
            values = (
                rfc_id,
                task["revision_digest"],
                candidate_digest,
                str(candidate["commit_sha"]),
                int(review["review_run_id"]),
                int(level3["test_run_id"]),
                merge_commit,
                trusted_main_commit,
                json.dumps(contracts, sort_keys=True),
                recorded_by,
                utc_now(),
            )
            if existing:
                if (
                    existing["revision_digest"] != task["revision_digest"]
                    or existing["candidate_digest"] != candidate_digest
                    or existing["candidate_commit"] != candidate["commit_sha"]
                    or existing["review_run_id"] != review["review_run_id"]
                    or existing["level3_test_run_id"] != level3["test_run_id"]
                    or existing["merge_commit"] != merge_commit
                    or json.loads(existing["contracts_json"]) != contracts
                ):
                    raise StateConflict(f"conflicting merge evidence for {rfc_id}")
                if existing["trusted_main_commit"] is None:
                    connection.execute(
                        "UPDATE merge_records SET trusted_main_commit = ?, recorded_by = ?, "
                        "recorded_at = ? WHERE rfc_id = ? AND trusted_main_commit IS NULL",
                        (trusted_main_commit, recorded_by, utc_now(), rfc_id),
                    )
                elif existing["trusted_main_commit"] != trusted_main_commit:
                    raise StateConflict(f"conflicting merge evidence for {rfc_id}")
                return
            connection.execute(
                "INSERT INTO merge_records "
                "(rfc_id, revision_digest, candidate_digest, candidate_commit, "
                "review_run_id, level3_test_run_id, merge_commit, trusted_main_commit, "
                "contracts_json, recorded_by, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                values,
            )

    def record_base_delivery(
        self,
        merged_base_commit: str,
        recorded_by: str,
    ) -> None:
        required_rfc = self.registry.base_delivery_rfc
        required_commit = self.registry.base_delivery_commit
        if required_rfc is None or required_commit is None:
            raise StateConflict("registry has no external base delivery gate")
        if not COMMIT_RE.fullmatch(merged_base_commit):
            raise ValueError("merged_base_commit must be a full Git SHA")
        if self.git_verifier is None:
            raise StateConflict("base delivery requires the bound Git verifier")
        trusted_main_commit = self.git_verifier.require_on_trusted_main(
            merged_base_commit
        )
        self.git_verifier.require_ancestor(required_commit, merged_base_commit)
        with self.store.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM base_delivery_records WHERE required_rfc_id = ?",
                (required_rfc,),
            ).fetchone()
            values = (
                required_rfc,
                required_commit,
                merged_base_commit,
                trusted_main_commit,
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
                if existing["trusted_main_commit"] is None:
                    connection.execute(
                        "UPDATE base_delivery_records SET trusted_main_commit = ?, "
                        "recorded_by = ?, recorded_at = ? WHERE required_rfc_id = ? "
                        "AND trusted_main_commit IS NULL",
                        (trusted_main_commit, recorded_by, utc_now(), required_rfc),
                    )
                elif existing["trusted_main_commit"] != trusted_main_commit:
                    raise StateConflict("conflicting external base delivery evidence")
                return
            connection.execute(
                "INSERT INTO base_delivery_records "
                "(required_rfc_id, required_commit, merged_base_commit, "
                "trusted_main_commit, ancestor_verified, recorded_by, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                values,
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
                    and isinstance(base["trusted_main_commit"], str)
                    and COMMIT_RE.fullmatch(base["trusted_main_commit"])
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

    def enqueue_ready(
        self, queue: QueueStore | None = None, *, base_commit: str | None = None
    ) -> list[int]:
        """Materialize one idempotent initial Coder job for every Ready revision."""
        queue = queue or QueueStore(self.store)
        if base_commit is None:
            if self.git_verifier is None:
                raise StateConflict("Ready job enqueue requires the bound Git verifier")
            base_commit = self.git_verifier.resolve_trusted_main()
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
                    base_commit=base_commit,
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
                    and isinstance(base["trusted_main_commit"], str)
                    and COMMIT_RE.fullmatch(base["trusted_main_commit"])
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
            if not all(
                evidence.get(field)
                for field in (
                    "candidate_digest",
                    "candidate_commit",
                    "review_run_id",
                    "level3_test_run_id",
                    "trusted_main_commit",
                )
            ):
                return f"dependency {dependency} has incomplete legacy merge evidence"
        available: dict[str, str] = {}
        for dependency in dependencies:
            evidence = merges[dependency]
            available.update(json.loads(evidence["contracts_json"]))
        for name, digest in required_contracts.items():
            if available.get(name) != digest:
                return f"required contract {name} is not present at {digest}"
        return None
