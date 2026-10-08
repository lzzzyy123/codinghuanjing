"""Operator CLI for the shadow DAG scheduler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .leases import QueueStore
from .registry import load_registry
from .replay import replay_legacy_reports
from .scheduler import DagScheduler
from .state_store import StateStore
from .status import status_snapshot


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="coding-scheduler")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("dag", type=Path)
    validate.add_argument("classification", type=Path, nargs="?")
    initialize = commands.add_parser("init")
    initialize.add_argument("dag", type=Path)
    initialize.add_argument("database", type=Path)
    initialize.add_argument("classification", type=Path, nargs="?")
    status = commands.add_parser("status")
    status.add_argument("dag", type=Path)
    status.add_argument("database", type=Path)
    status.add_argument("--json", action="store_true")
    history = commands.add_parser("history")
    history.add_argument("database", type=Path)
    history.add_argument("rfc_id")
    replay = commands.add_parser("replay")
    replay.add_argument("reports", type=Path)
    recover = commands.add_parser("recover")
    recover.add_argument("database", type=Path)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    if args.command == "validate":
        registry = load_registry(args.dag, args.classification)
        print(json.dumps({"valid": True, "digest": registry.digest, "rfcs": len(registry.rfcs)}))
    elif args.command == "init":
        registry = load_registry(args.dag, args.classification)
        store = StateStore(args.database, args.database.parent / "evidence")
        store.import_registry(registry)
        scheduler = DagScheduler(registry, store)
        scheduler.validate_tasks()
        result = scheduler.refresh_ready()
        print(json.dumps({"database": str(args.database), **result}, indent=2))
    elif args.command == "status":
        snapshot = status_snapshot(load_registry(args.dag), StateStore(args.database))
        if args.json:
            print(json.dumps(snapshot, indent=2))
        else:
            print("States: " + ", ".join(f"{key}={value}" for key, value in snapshot["task_counts"].items()))
            print("Critical path: " + " -> ".join(snapshot["critical_path"]))
            print(f"Agents: {len(snapshot['agents'])}; leases: {len(snapshot['leases'])}")
    elif args.command == "history":
        transitions = StateStore(args.database).transitions(args.rfc_id)
        print(json.dumps(transitions, indent=2))
    elif args.command == "replay":
        print(json.dumps(replay_legacy_reports(args.reports).as_dict(), indent=2))
    elif args.command == "recover":
        recovered = QueueStore(StateStore(args.database)).recover_expired()
        print(json.dumps({"recovered_jobs": recovered}))


if __name__ == "__main__":
    main()
