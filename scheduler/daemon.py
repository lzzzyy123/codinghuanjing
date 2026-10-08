"""Persistent shadow scheduler daemon.

Shadow mode validates and materializes the DAG but never starts Agents or
claims the legacy filesystem queue. Active cutover is intentionally refused
by this module until a separate runner service and operator approval token are
configured.
"""

from __future__ import annotations

import argparse
import logging
import signal
import threading
from dataclasses import dataclass
from pathlib import Path

from .registry import load_registry
from .scheduler import DagScheduler
from .state_store import StateStore


LOG = logging.getLogger("coding-schedulerd")


@dataclass(frozen=True)
class DaemonConfig:
    dag: Path
    classification: Path
    database: Path
    evidence_root: Path
    mode: str = "shadow"
    reconcile_seconds: float = 5.0

    def validate(self) -> None:
        if self.mode != "shadow":
            raise ValueError(
                "this deployment supports shadow mode only; production cutover requires "
                "separately approved runner activation"
            )
        if self.reconcile_seconds <= 0 or self.reconcile_seconds > 60:
            raise ValueError("reconcile interval must be in (0, 60] seconds")


class SchedulerDaemon:
    def __init__(self, config: DaemonConfig):
        config.validate()
        self.config = config
        self.stop_event = threading.Event()

    def reconcile(self) -> dict[str, object]:
        registry = load_registry(self.config.dag, self.config.classification)
        if not registry.shared_resources:
            raise ValueError("production DAG requires broker-managed shared_resources policy")
        if not registry.frozen_control_paths:
            raise ValueError("production DAG requires frozen_control_paths policy")
        if any(not rfc.level3_tests for rfc in registry.rfcs.values()):
            raise ValueError("production DAG requires Level 3 gates for every RFC")
        if any(
            not rfc.raw.get("interface_artifact")
            or not rfc.raw.get("interface_artifact_sha256")
            for rfc in registry.rfcs.values()
        ):
            raise ValueError("production DAG requires versioned interface artifacts")
        store = StateStore(self.config.database, self.config.evidence_root)
        store.import_registry(registry)
        scheduler = DagScheduler(registry, store)
        validated = scheduler.validate_tasks()
        readiness = scheduler.refresh_ready()
        repaired_evidence = store.materialize_transition_evidence()
        # Shadow mode validates persistence/readiness without creating runnable
        # jobs against an unverified repository base.
        enqueued: list[int] = []
        return {
            "registry": registry.digest,
            "validated": validated,
            # Shadow mode has no process supervisor and therefore cannot prove
            # that an expired executor is quiescent. It never releases leases.
            "recovered_jobs": [],
            "enqueued_jobs": enqueued,
            "repaired_evidence": repaired_evidence,
            **readiness,
        }

    def run(self, *, once: bool = False) -> None:
        while not self.stop_event.is_set():
            result = self.reconcile()
            LOG.info(
                "shadow reconcile registry=%s validated=%d ready=%d blocked=%d recovered=%d enqueued=%d",
                result["registry"],
                len(result["validated"]),
                len(result["ready"]),
                len(result["blocked"]),
                len(result["recovered_jobs"]),
                len(result["enqueued_jobs"]),
            )
            if once:
                return
            self.stop_event.wait(self.config.reconcile_seconds)

    def stop(self, *_args: object) -> None:
        self.stop_event.set()


def main() -> None:
    parser = argparse.ArgumentParser(prog="coding-schedulerd")
    parser.add_argument("--dag", type=Path, required=True)
    parser.add_argument("--classification", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--mode", default="shadow")
    parser.add_argument("--reconcile-seconds", type=float, default=5.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    daemon = SchedulerDaemon(
        DaemonConfig(
            dag=args.dag,
            classification=args.classification,
            database=args.database,
            evidence_root=args.evidence_root,
            mode=args.mode,
            reconcile_seconds=args.reconcile_seconds,
        )
    )
    signal.signal(signal.SIGTERM, daemon.stop)
    signal.signal(signal.SIGINT, daemon.stop)
    daemon.run(once=args.once)


if __name__ == "__main__":
    main()
