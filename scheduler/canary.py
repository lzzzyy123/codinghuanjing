"""Synthetic multi-process queue and crash-recovery canary."""

from __future__ import annotations

import json
import multiprocessing
import tempfile
import time
from pathlib import Path

from .leases import QueueStore
from .models import TaskState
from .registry import load_registry, with_revision_digest
from .state_store import StateStore


def _rfc(number: int) -> dict:
    rfc_id = f"RFC-20261008-{number:03d}"
    return with_revision_digest(
        {
            "id": rfc_id,
            "title": f"Canary {number}",
            "capability_group": "canary",
            "revision": 1,
            "python_sources": [f"canary/{number}.py"],
            "target_files": [f"src/canary/{number}.ts"],
            "lock_keys": [f"canary:{number}"],
            "depends_on": [],
            "contracts": {"provides": {}, "requires": {}},
            "tests": {"level1": ["true"], "level2": ["true"]},
            "integration_batch": "canary",
            "acceptance_criteria": ["Synthetic job finishes exactly once."],
        }
    )


def _worker(database: str, agent_id: str, role: str, start_at: float) -> None:
    store = StateStore(Path(database))
    queue = QueueStore(store)
    queue.register_agent(agent_id, role, "synthetic", f"pid:{multiprocessing.current_process().pid}", now=start_at)
    lease = queue.claim(agent_id, now=start_at, lease_seconds=30)
    if lease is None:
        raise RuntimeError(f"{agent_id} could not claim a synthetic job")
    queue.start(lease, now=start_at + 0.1)
    time.sleep(0.05)
    queue.finish(lease, "passed", {"agent_id": agent_id}, now=start_at + 1)


def _crashing_worker(database: str, agent_id: str, start_at: float) -> None:
    store = StateStore(Path(database))
    queue = QueueStore(store)
    queue.register_agent(agent_id, "coder", "synthetic", f"pid:{multiprocessing.current_process().pid}", now=start_at)
    lease = queue.claim(agent_id, now=start_at, lease_seconds=1)
    if lease is None:
        raise RuntimeError("crash canary could not claim")
    queue.start(lease, now=start_at + 0.1)


def run_canary(root: Path) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    rfcs = [_rfc(number) for number in range(56, 63)]
    dag = root / "canary-dag.json"
    dag.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "baseline": {
                    "commit": "a" * 40,
                    "classification_sha256": "sha256:" + "b" * 64,
                    "in_scope_count": 7,
                },
                "rfcs": rfcs,
            }
        ),
        encoding="utf-8",
    )
    database = root / "canary.sqlite3"
    store = StateStore(database)
    store.import_registry(load_registry(dag))
    for index, rfc in enumerate(rfcs):
        rfc_id = rfc["id"]
        store.transition(rfc_id, TaskState.DRAFT, TaskState.VALIDATED, "canary")
        store.transition(rfc_id, TaskState.VALIDATED, TaskState.READY, "canary")
        if index >= 4 and index < 6:
            store.transition(rfc_id, TaskState.READY, TaskState.LEASED, "canary")
            store.transition(rfc_id, TaskState.LEASED, TaskState.CODING, "canary")
            store.transition(rfc_id, TaskState.CODING, TaskState.TESTING, "canary")
            store.transition(rfc_id, TaskState.TESTING, TaskState.REVIEWING, "canary")
    queue = QueueStore(store)
    for rfc in rfcs[:4]:
        queue.enqueue(rfc["id"], "coding", f"coding:{rfc['id']}", available_at=0)
    for rfc in rfcs[4:6]:
        queue.enqueue(
            rfc["id"],
            "review",
            f"review:{rfc['id']}",
            candidate_digest="sha256:" + "c" * 64,
            available_at=0,
        )
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_worker, args=(str(database), f"coder-{index}", "coder", 100.0))
        for index in range(4)
    ] + [
        context.Process(target=_worker, args=(str(database), f"reviewer-{index}", "reviewer", 100.0))
        for index in range(2)
    ]
    started = time.monotonic()
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
    elapsed = time.monotonic() - started
    exit_codes = [process.exitcode for process in processes]
    if exit_codes != [0] * 6:
        raise RuntimeError(f"synthetic 4C+2R canary failed: {exit_codes}")

    crash_rfc = rfcs[6]["id"]
    queue.enqueue(crash_rfc, "coding", f"coding:{crash_rfc}", available_at=0)
    crashing = context.Process(
        target=_crashing_worker, args=(str(database), "coder-crash", 200.0)
    )
    crashing.start()
    crashing.join(20)
    if crashing.exitcode != 0:
        raise RuntimeError(f"crash injection process failed unexpectedly: {crashing.exitcode}")
    recovered = queue.recover_expired(now=202.0)
    queue.register_agent("coder-recovery", "coder", "synthetic", "pid:recovery", now=202.0)
    replacement = queue.claim("coder-recovery", now=202.0, lease_seconds=30)
    if replacement is None or replacement.rfc_id != crash_rfc:
        raise RuntimeError("recovered job was not reclaimable")
    queue.start(replacement, now=202.1)
    queue.finish(replacement, "passed", {"recovered": True}, now=203.0)

    jobs = queue.jobs()
    passed = [job for job in jobs if job["state"] == "passed"]
    if len(passed) != 7:
        raise RuntimeError(f"expected 7 passed jobs, found {len(passed)}")
    return {
        "configuration": "4C+2R synthetic",
        "process_exit_codes": exit_codes,
        "jobs_passed": len(passed),
        "unique_job_ids": len({job["job_id"] for job in jobs}),
        "recovered_jobs": recovered,
        "crash_replacement_fencing_token": replacement.fencing_token,
        "elapsed_seconds": round(elapsed, 3),
    }


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="coding-scheduler-canary-") as directory:
        print(json.dumps(run_canary(Path(directory)), indent=2))


if __name__ == "__main__":
    main()
