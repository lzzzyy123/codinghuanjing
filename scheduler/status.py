"""Consistent scheduler snapshots for Mac and container operators."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .models import TaskState
from .registry import Registry
from .scheduler import DagScheduler
from .state_store import StateStore


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
    with store.connect() as connection:
        tasks = [dict(row) for row in connection.execute("SELECT * FROM tasks ORDER BY rfc_id")]
        jobs = [dict(row) for row in connection.execute("SELECT * FROM jobs ORDER BY job_id")]
        agents = [dict(row) for row in connection.execute("SELECT * FROM agents ORDER BY agent_id")]
        leases = [dict(row) for row in connection.execute("SELECT * FROM leases ORDER BY job_id")]
        merged = {
            row["rfc_id"] for row in connection.execute("SELECT rfc_id FROM merge_records")
        }
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
        "agents": [_agent_status(agent) for agent in agents],
        "leases": leases,
        "critical_path": critical_path(registry, merged),
        "blockers": blockers,
        "admission_blockers": DagScheduler(registry, store).readiness_blockers(),
        "merged": sorted(merged),
    }


def _agent_status(agent: dict[str, Any]) -> dict[str, Any]:
    result = dict(agent)
    result["metrics"] = json.loads(result.pop("metrics_json"))
    return result
