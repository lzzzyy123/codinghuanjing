"""Read-only replay and validation of legacy Worker report histories."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class ReplayResult:
    tasks: int
    statuses: dict[str, int]
    events: int
    anomalies: tuple[str, ...]
    durations_seconds: tuple[float, ...]

    def as_dict(self) -> dict:
        ordered = sorted(self.durations_seconds)
        median = 0.0
        if ordered:
            middle = len(ordered) // 2
            median = (
                ordered[middle]
                if len(ordered) % 2
                else (ordered[middle - 1] + ordered[middle]) / 2
            )
        return {
            "tasks": self.tasks,
            "statuses": self.statuses,
            "events": self.events,
            "anomalies": list(self.anomalies),
            "terminal_duration_median_seconds": median,
        }


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def replay_legacy_reports(root: Path) -> ReplayResult:
    statuses: Counter[str] = Counter()
    anomalies: list[str] = []
    durations: list[float] = []
    events_count = 0
    status_paths = sorted(root.glob("*/status.json"))
    for status_path in status_paths:
        task_id = status_path.parent.name
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            anomalies.append(f"{task_id}: invalid status.json: {exc}")
            continue
        statuses[str(status.get("status", "unknown"))] += 1
        started = _parse_time(status.get("started_at"))
        ended = _parse_time(status.get("completed_at") or status.get("failed_at"))
        if started and ended and ended >= started:
            durations.append((ended - started).total_seconds())
        events_path = status_path.parent / "events.jsonl"
        if not events_path.is_file():
            anomalies.append(f"{task_id}: events.jsonl missing")
            continue
        previous = 0
        for line_number, line in enumerate(
            events_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                anomalies.append(f"{task_id}: event line {line_number} invalid: {exc}")
                continue
            events_count += 1
            sequence = event.get("sequence")
            if not isinstance(sequence, int) or sequence != previous + 1:
                anomalies.append(
                    f"{task_id}: event sequence {sequence!r} after {previous}"
                )
                if isinstance(sequence, int):
                    previous = sequence
            else:
                previous = sequence
        status_sequence = status.get("event_sequence")
        if isinstance(status_sequence, int) and status_sequence != previous:
            anomalies.append(
                f"{task_id}: status event_sequence {status_sequence} != events {previous}"
            )
    return ReplayResult(
        tasks=len(status_paths),
        statuses=dict(sorted(statuses.items())),
        events=events_count,
        anomalies=tuple(anomalies),
        durations_seconds=tuple(durations),
    )
