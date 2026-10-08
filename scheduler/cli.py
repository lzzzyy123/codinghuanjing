"""Operator CLI for the shadow DAG scheduler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .leases import QueueStore
from .registry import Registry, RegistryError, load_registry
from .replay import replay_legacy_reports
from .scheduler import DagScheduler
from .state_store import StateStore
from .status import status_snapshot


PRODUCTION_IN_SCOPE_COUNT = 806


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="coding-scheduler")
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("dag", type=Path)
    validate.add_argument("classification", type=Path, nargs="?")
    validate.add_argument(
        "--test-mode",
        action="store_true",
        help="TEST FIXTURES ONLY: allow validation without the production classification/count gate",
    )
    initialize = commands.add_parser("init")
    initialize.add_argument("dag", type=Path)
    initialize.add_argument("database", type=Path)
    initialize.add_argument("classification", type=Path, nargs="?")
    initialize.add_argument(
        "--test-mode",
        action="store_true",
        help="TEST FIXTURES ONLY: allow initialization without the production classification/count gate",
    )
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


def _load_validated_registry(
    root: argparse.ArgumentParser, args: argparse.Namespace
) -> Registry:
    if args.classification is None and not args.test_mode:
        root.error(
            f"{args.command} requires CLASSIFICATION in production mode; "
            "--test-mode is only for synthetic test fixtures"
        )
    try:
        registry = load_registry(args.dag, args.classification)
    except RegistryError as exc:
        root.error(f"{args.command} registry validation failed: {exc}")
    if not args.test_mode and registry.in_scope_count != PRODUCTION_IN_SCOPE_COUNT:
        root.error(
            f"{args.command} requires the production {PRODUCTION_IN_SCOPE_COUNT}-path "
            f"partition, registry declares {registry.in_scope_count}"
        )
    return registry


def main(argv: list[str] | None = None) -> None:
    root = parser()
    args = root.parse_args(argv)
    if args.command == "validate":
        registry = _load_validated_registry(root, args)
        print(json.dumps({"valid": True, "digest": registry.digest, "rfcs": len(registry.rfcs)}))
    elif args.command == "init":
        registry = _load_validated_registry(root, args)
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
