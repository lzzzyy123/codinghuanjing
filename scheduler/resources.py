"""Technical admission guards for model and test process concurrency."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ResourcePolicy:
    max_expensive_processes: int = 2
    min_memory_headroom_bytes: int = 1024 * 1024 * 1024
    min_disk_free_bytes: int = 5 * 1024 * 1024 * 1024
    max_load_per_cpu: float = 1.5


@dataclass(frozen=True)
class ResourceSnapshot:
    cpu_count: int
    load_1m: float
    memory_limit_bytes: int
    memory_working_set_bytes: int
    disk_free_bytes: int
    expensive_processes: int
    oom_kills: int


@dataclass(frozen=True)
class Admission:
    allowed: bool
    blockers: tuple[str, ...]


def admit(snapshot: ResourceSnapshot, policy: ResourcePolicy) -> Admission:
    blockers: list[str] = []
    if snapshot.expensive_processes >= policy.max_expensive_processes:
        blockers.append("expensive process concurrency limit reached")
    headroom = snapshot.memory_limit_bytes - snapshot.memory_working_set_bytes
    if headroom < policy.min_memory_headroom_bytes:
        blockers.append(f"memory headroom {headroom} below reserve")
    if snapshot.disk_free_bytes < policy.min_disk_free_bytes:
        blockers.append("disk free space below reserve")
    if snapshot.cpu_count < 1 or snapshot.load_1m / snapshot.cpu_count > policy.max_load_per_cpu:
        blockers.append("CPU load admission threshold exceeded")
    if snapshot.oom_kills > 0:
        blockers.append("OOM kill evidence requires operator acknowledgement")
    return Admission(not blockers, tuple(blockers))


def _read_key_values(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        pieces = line.split()
        if len(pieces) == 2 and pieces[1].isdigit():
            values[pieces[0]] = int(pieces[1])
    return values


def capture_snapshot(
    persistent_root: Path,
    expensive_processes: int,
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> ResourceSnapshot:
    memory_limit_text = (cgroup_root / "memory.max").read_text(encoding="utf-8").strip()
    memory_limit = (
        int(memory_limit_text)
        if memory_limit_text != "max"
        else int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    )
    memory_current = int((cgroup_root / "memory.current").read_text().strip())
    memory_stat = _read_key_values(cgroup_root / "memory.stat")
    inactive_file = memory_stat.get("inactive_file", 0)
    working_set = max(0, memory_current - inactive_file)
    memory_events = _read_key_values(cgroup_root / "memory.events")
    return ResourceSnapshot(
        cpu_count=os.cpu_count() or 1,
        load_1m=os.getloadavg()[0],
        memory_limit_bytes=memory_limit,
        memory_working_set_bytes=working_set,
        disk_free_bytes=shutil.disk_usage(persistent_root).free,
        expensive_processes=expensive_processes,
        oom_kills=memory_events.get("oom_kill", 0),
    )
