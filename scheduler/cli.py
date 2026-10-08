"""Operator CLI for the shadow DAG scheduler."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .git_verifier import GitVerificationError, RepositoryGitVerifier
from .registry import Registry, RegistryError, load_registry
from .replay import replay_legacy_reports
from .scheduler import DagScheduler
from .state_store import StateConflict, StateStore
from .status import status_snapshot


PRODUCTION_IN_SCOPE_COUNT = 806
PRODUCTION_CONFIG_DATA_COUNT = 188


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
    for name in ("record-base-delivery", "record-merge"):
        control = commands.add_parser(name)
        control.add_argument("dag", type=Path)
        control.add_argument("database", type=Path)
        control.add_argument("classification", type=Path)
        control.add_argument("repository", type=Path)
        control.add_argument("--remote", default="origin")
        control.add_argument("--branch", default="main")
        control.add_argument("--recorded-by", required=True)
        control.add_argument(
            "--test-mode",
            action="store_true",
            help="TEST FIXTURES ONLY: allow a non-production registry partition",
        )
    base_delivery = commands.choices["record-base-delivery"]
    base_delivery.add_argument("merged_base_commit")
    merge = commands.choices["record-merge"]
    merge.add_argument("rfc_id")
    merge.add_argument("candidate_digest")
    merge.add_argument("merge_commit")
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
    if not args.test_mode and registry.config_data_count != PRODUCTION_CONFIG_DATA_COUNT:
        root.error(
            f"{args.command} requires the production {PRODUCTION_CONFIG_DATA_COUNT}-path "
            f"config-data partition, registry declares {registry.config_data_count}"
        )
    if not args.test_mode and not registry.shared_resources:
        root.error(f"{args.command} requires broker-managed shared_resources policy")
    if not args.test_mode and not registry.frozen_control_paths:
        root.error(f"{args.command} requires a frozen_control_paths policy")
    if not args.test_mode:
        missing_level3 = sorted(
            rfc.rfc_id for rfc in registry.rfcs.values() if not rfc.level3_tests
        )
        if missing_level3:
            root.error(
                f"{args.command} requires Level 3 gates for every RFC; "
                f"missing={missing_level3[:10]}"
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
        root.error(
            "scheduler-recover is disabled: an active supervisor must first prove "
            "the expired executor and its descendants are quiescent"
        )
    elif args.command in {"record-base-delivery", "record-merge"}:
        registry = _load_validated_registry(root, args)
        if not args.database.is_file():
            root.error("scheduler database does not exist; run scheduler-init first")
        store = StateStore(args.database, args.database.parent / "evidence")
        with store.connect() as connection:
            imported = connection.execute(
                "SELECT 1 FROM registries WHERE digest = ?", (registry.digest,)
            ).fetchone()
        if imported is None:
            root.error("scheduler database is not initialized for this registry digest")
        try:
            verifier = RepositoryGitVerifier(
                args.repository,
                trusted_main_ref="refs/coding-scheduler/trusted-main",
            )
            scheduler = DagScheduler(registry, store, verifier)
            trusted_main = verifier.refresh_trusted_main(args.remote, args.branch)
            if args.command == "record-base-delivery":
                scheduler.record_base_delivery(args.merged_base_commit, args.recorded_by)
            else:
                if args.rfc_id not in registry.rfcs:
                    raise StateConflict(f"unknown RFC: {args.rfc_id}")
                scheduler.record_merge(
                    args.rfc_id,
                    args.candidate_digest,
                    args.merge_commit,
                    registry.rfcs[args.rfc_id].provides,
                    args.recorded_by,
                )
            readiness = scheduler.refresh_ready(actor=f"operator:{args.recorded_by}")
        except (GitVerificationError, StateConflict, ValueError) as exc:
            root.error(f"{args.command} refused: {exc}")
        print(
            json.dumps(
                {"trusted_main_commit": trusted_main, **readiness},
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
