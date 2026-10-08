"""Runtime ownership conflict checks for concurrently leased RFCs."""

from __future__ import annotations

from collections.abc import Iterable

from .registry import Registry


def ownership_conflicts(
    registry: Registry, candidate_id: str, active_ids: Iterable[str]
) -> list[str]:
    candidate = registry.rfcs[candidate_id]
    candidate_sources = set(candidate.python_sources)
    candidate_targets = set(candidate.target_files)
    conflicts: list[str] = []
    for active_id in active_ids:
        if active_id == candidate_id:
            conflicts.append(f"{candidate_id} is already active")
            continue
        active = registry.rfcs[active_id]
        source_overlap = sorted(candidate_sources.intersection(active.python_sources))
        target_overlap = sorted(candidate_targets.intersection(active.target_files))
        if source_overlap or target_overlap:
            details = source_overlap + target_overlap
            conflicts.append(f"{active_id}: " + ", ".join(details))
    return conflicts
