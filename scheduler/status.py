"""Consistent scheduler snapshots for Mac and container operators."""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from datetime import datetime
from typing import Any

from .models import TaskState
from .registry import Registry
from .scheduler import DagScheduler
from .state_store import StateStore


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def critical_path(registry: Registry, completed: set[str]) -> list[str]:
    best: dict[str, list[str]] = {}
    for rfc_id in registry.topological_order:
        if rfc_id in completed:
            best[rfc_id] = []
            continue
        candidates = [best[dependency] for dependency in registry.rfcs[rfc_id].depends_on]
        prefix = max(candidates, key=len, default=[])
        best[rfc_id] = [*prefix, rfc_id]
    return max(best.values(), key=len, default=[])


def status_snapshot(registry: Registry, store: StateStore) -> dict[str, Any]:
    now = time.time()
    with store.connect() as connection:
        tasks = [dict(row) for row in connection.execute("SELECT * FROM tasks ORDER BY rfc_id")]
        jobs = [dict(row) for row in connection.execute("SELECT * FROM jobs ORDER BY job_id")]
        agents = [dict(row) for row in connection.execute("SELECT * FROM agents ORDER BY agent_id")]
        leases = [dict(row) for row in connection.execute("SELECT * FROM leases ORDER BY job_id")]
        candidates = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM candidate_records ORDER BY rfc_id, created_at"
            )
        ]
        tests = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM test_runs ORDER BY rfc_id, test_run_id"
            )
        ]
        reviews = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM review_runs ORDER BY rfc_id, review_run_id"
            )
        ]
        publications = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM publication_records ORDER BY publication_id"
            )
        ]
        merge_rows = [
            dict(row)
            for row in connection.execute("SELECT * FROM merge_records ORDER BY rfc_id")
        ]
        base_deliveries = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM base_delivery_records ORDER BY required_rfc_id"
            )
        ]
        migration_blockers = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM migration_blockers WHERE resolved_at IS NULL "
                "ORDER BY blocker_key"
            )
        ]
        merged = {
            row["rfc_id"]
            for row in merge_rows
            if all(
                row.get(field)
                for field in (
                    "candidate_digest",
                    "candidate_commit",
                    "review_run_id",
                    "level3_test_run_id",
                )
            )
            and isinstance(row.get("trusted_main_commit"), str)
            and COMMIT_RE.fullmatch(row["trusted_main_commit"])
        }
    evidence = _evidence_by_rfc(candidates, tests, reviews, publications, merge_rows)
    active_by_agent = {
        lease["holder_agent_id"]: lease for lease in leases
    }
    for task in tasks:
        task["state_age_seconds"] = _age_seconds(task["updated_at"], now)
        task["elapsed_seconds"] = _elapsed_seconds(
            task["created_at"], task["updated_at"] if task["state"] == "Done" else None, now
        )
        task["evidence"] = evidence.get(task["rfc_id"], _empty_evidence())
    for job in jobs:
        job["elapsed_seconds"] = _elapsed_seconds(
            job["created_at"],
            job["updated_at"] if job["state"] in {"passed", "failed", "cancelled"} else None,
            now,
        )
    state_counts = dict(sorted(Counter(task["state"] for task in tasks).items()))
    capability: dict[str, Counter[str]] = {}
    for task in tasks:
        group = registry.rfcs[task["rfc_id"]].capability_group
        capability.setdefault(group, Counter())[task["state"]] += 1
    blockers = [
        {"rfc_id": task["rfc_id"], "reason": task["reason"]}
        for task in tasks
        if task["state"] == TaskState.BLOCKED.value
    ]
    return {
        "registry_digest": registry.digest,
        "baseline_commit": registry.baseline_commit,
        "source_coverage": {
            "in_scope": registry.in_scope_count,
            "config_data": registry.config_data_count,
        },
        "task_counts": state_counts,
        "capabilities": {
            group: dict(sorted(counts.items())) for group, counts in sorted(capability.items())
        },
        "tasks": tasks,
        "jobs": jobs,
        "agents": [
            _agent_status(agent, active_by_agent.get(agent["agent_id"]), now)
            for agent in agents
        ],
        "leases": leases,
        "evidence_counts": {
            "candidates": len(candidates),
            "test_runs": len(tests),
            "review_runs": len(reviews),
            "publications": len(publications),
            "merges": len(merge_rows),
        },
        "publication_pending": [
            row for row in publications if row["state"] in {"prepared", "published"}
        ],
        "publication_blockers": [
            row for row in publications if row["state"] == "blocked"
        ],
        "base_deliveries": base_deliveries,
        "migration_blockers": migration_blockers,
        "critical_path": critical_path(registry, merged),
        "blockers": blockers,
        "admission_blockers": DagScheduler(registry, store).readiness_blockers(),
        "merged": sorted(merged),
    }


def _agent_status(
    agent: dict[str, Any], lease: dict[str, Any] | None, now: float
) -> dict[str, Any]:
    result = dict(agent)
    result["metrics"] = json.loads(result.pop("metrics_json"))
    result["heartbeat_age_seconds"] = max(0.0, round(now - float(result["heartbeat_at"]), 3))
    result["assignment"] = None
    if lease is not None:
        result["assignment"] = {
            "job_id": lease["job_id"],
            "lease_id": lease["lease_id"],
            "running_seconds": max(0.0, round(now - float(lease["acquired_at"]), 3)),
            "expires_at": lease["expires_at"],
        }
    return result


def _empty_evidence() -> dict[str, Any]:
    return {
        "candidate": None,
        "tests": {},
        "review": None,
        "publication": None,
        "merge": None,
    }


def _evidence_by_rfc(
    candidates: list[dict[str, Any]],
    tests: list[dict[str, Any]],
    reviews: list[dict[str, Any]],
    publications: list[dict[str, Any]],
    merges: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        item = result.setdefault(candidate["rfc_id"], _empty_evidence())
        item["candidate"] = candidate
    for test in tests:
        item = result.setdefault(test["rfc_id"], _empty_evidence())
        item["tests"][str(test["level"])] = test
    for review in reviews:
        item = result.setdefault(review["rfc_id"], _empty_evidence())
        item["review"] = review
    for publication in publications:
        item = result.setdefault(publication["rfc_id"], _empty_evidence())
        item["publication"] = publication
    for merge in merges:
        item = result.setdefault(merge["rfc_id"], _empty_evidence())
        item["merge"] = merge
    return result


def _timestamp(value: str) -> float | None:
    try:
        return datetime.fromisoformat(value).timestamp()
    except (TypeError, ValueError):
        return None


def _age_seconds(value: str, now: float) -> float | None:
    timestamp = _timestamp(value)
    return None if timestamp is None else max(0.0, round(now - timestamp, 3))


def _elapsed_seconds(start: str, end: str | None, now: float) -> float | None:
    start_timestamp = _timestamp(start)
    end_timestamp = now if end is None else _timestamp(end)
    if start_timestamp is None or end_timestamp is None:
        return None
    return max(0.0, round(end_timestamp - start_timestamp, 3))
