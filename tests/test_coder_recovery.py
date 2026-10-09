from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import control  # noqa: E402
import watcher  # noqa: E402


RFC_ID = "RFC-20261008-057"
BASE_COMMIT = "a" * 40
BRANCH = f"agent/{RFC_ID}"
RFC_TEXT = """---
title: Recovery test
test_command: "true"
---

# RFC
"""


def coding_report() -> str:
    sections = [watcher.CODER_REPORT_HEADINGS[0], "Completion Status: READY_FOR_TESTS"]
    sections.extend(watcher.CODER_REPORT_HEADINGS[1:])
    return "\n\n".join(sections)


def command_result(stdout: str = "") -> watcher.CommandResult:
    return watcher.CommandResult("git", 0, stdout, "")


class CoderOutputTests(unittest.TestCase):
    def test_literal_dsml_is_a_protocol_failure_not_a_report_format_failure(self) -> None:
        result = watcher.assess_coder_output(
            'planning\n<｜DSML｜tool_calls><｜DSML｜invoke name="Write">'
        )
        self.assertEqual(result.classification, "CODER_PROTOCOL_OUTPUT_INVALID")
        self.assertIn("tool-protocol", result.errors[0])

    def test_continue_and_ready_are_distinct(self) -> None:
        progress = watcher.assess_coder_output(
            "# Coder Progress Checkpoint - RFC\n\nCompletion Status: CONTINUE\n"
        )
        ready = watcher.assess_coder_output(coding_report())
        self.assertEqual(progress.classification, "CONTINUE")
        self.assertEqual(ready.classification, "READY_FOR_TESTS")

    def test_legacy_complete_report_remains_ready(self) -> None:
        legacy = "\n".join(watcher.CODER_REPORT_HEADINGS)
        self.assertEqual(watcher.assess_coder_output(legacy).classification, "READY_FOR_TESTS")

    def test_conflicting_completion_statuses_are_rejected(self) -> None:
        result = watcher.assess_coder_output(
            coding_report() + "\nCompletion Status: CONTINUE\n"
        )
        self.assertEqual(result.classification, "CODER_REPORT_INVALID")
        self.assertEqual(result.errors, ("multiple completion statuses",))

    def test_coder_infrastructure_failure_has_distinct_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            failed = root / "failed"
            reports.mkdir()
            failed.mkdir()
            rfc = root / f"{RFC_ID}.md"
            rfc.write_text(RFC_TEXT)
            with (
                mock.patch.object(watcher, "REPORTS", reports),
                mock.patch.object(watcher, "FAILED", failed),
                mock.patch.object(
                    watcher,
                    "process_task",
                    side_effect=watcher.CoderInfrastructureFailure(
                        "CODER_PROTOCOL_OUTPUT_INVALID: bad tool output"
                    ),
                ),
            ):
                watcher.handle_claimed(rfc)
            state = json.loads((reports / RFC_ID / "status.json").read_text())
            self.assertEqual(state["status"], "coder_infra_failed")
            self.assertEqual(state["failure_kind"], "CODER_PROTOCOL_OUTPUT_INVALID")


class CoderCheckpointTests(unittest.TestCase):
    def test_checkpoint_binds_redacted_raw_diff_and_workspace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktrees" / RFC_ID
            raw_path = report_dir / "raw" / "attempt-1-coder-1.json"
            worktree.mkdir(parents=True)
            raw_path.parent.mkdir(parents=True)
            raw_path.write_text('{"result":"already redacted"}')
            raw_diff = "diff --git a/file b/file\n+api_key=secret-value\n"
            with (
                mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "secret-value"}),
                mock.patch.object(watcher, "combined_diff", return_value=raw_diff),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fingerprint"),
                mock.patch.object(watcher, "changed_paths", return_value=["file"]),
                mock.patch.object(watcher, "git", return_value=command_result(BASE_COMMIT + "\n")),
            ):
                checkpoint = watcher.persist_coder_checkpoint(
                    report_dir,
                    "attempt-1-coder-1",
                    RFC_ID,
                    BRANCH,
                    BASE_COMMIT,
                    worktree,
                    BASE_COMMIT,
                    "before",
                    "CODER_PROTOCOL_OUTPUT_INVALID",
                    raw_path=raw_path,
                    diagnostics=("literal protocol",),
                )
                manifest = watcher.validate_coder_checkpoint(
                    report_dir,
                    checkpoint,
                    RFC_ID,
                    BRANCH,
                    BASE_COMMIT,
                    worktree,
                    BASE_COMMIT,
                )

            patch = (report_dir / manifest["patch"]).read_text()
            self.assertNotIn("secret-value", patch)
            self.assertIn("[REDACTED]", patch)
            self.assertEqual(manifest["before_fingerprint"], "before")
            self.assertEqual(manifest["after_fingerprint"], "fingerprint")
            self.assertEqual(manifest["changed_paths"], ["file"])
            self.assertEqual(manifest["diagnostics"], ["literal protocol"])
            self.assertEqual(manifest["raw_envelope_sha256"], hashlib.sha256(raw_path.read_bytes()).hexdigest())

    def test_checkpoint_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktrees" / RFC_ID
            worktree.mkdir(parents=True)
            with (
                mock.patch.object(watcher, "combined_diff", return_value="diff"),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fingerprint"),
                mock.patch.object(watcher, "changed_paths", return_value=["file"]),
                mock.patch.object(watcher, "git", return_value=command_result(BASE_COMMIT + "\n")),
            ):
                checkpoint = watcher.persist_coder_checkpoint(
                    report_dir,
                    "attempt-1-coder-1",
                    RFC_ID,
                    BRANCH,
                    BASE_COMMIT,
                    worktree,
                    BASE_COMMIT,
                    "before",
                    "CONTINUE",
                )
                manifest_path = report_dir / checkpoint["manifest"]
                manifest = json.loads(manifest_path.read_text())
                manifest["changed_paths"] = ["tampered"]
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(watcher.TaskFailure, "digest"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        BRANCH,
                        BASE_COMMIT,
                        worktree,
                        BASE_COMMIT,
                    )


class CoderContinuationTests(unittest.TestCase):
    def checkpoint(self, classification: str) -> dict[str, object]:
        return {
            "classification": classification,
            "checkpoint_digest": "d" * 64,
            "manifest": "coder-checkpoints/test.json",
        }

    def test_continue_reuses_worktree_then_ready_enters_gate(self) -> None:
        progress = "# Coder Progress Checkpoint - RFC\nCompletion Status: CONTINUE"
        status: dict[str, object] = {"rfc": RFC_ID, "status": "working"}
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            prompts: list[str] = []

            def run_agent(_role: str, prompt: str, *_args: object) -> str:
                prompts.append(prompt)
                return [progress, coding_report()][len(prompts) - 1]

            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "run_agent", side_effect=run_agent),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher,
                    "persist_coder_checkpoint",
                    side_effect=[self.checkpoint("CONTINUE"), self.checkpoint("READY_FOR_TESTS")],
                ),
            ):
                assessment, _checkpoint = watcher.run_coder_until_gate(
                    RFC_TEXT,
                    RFC_ID,
                    worktree,
                    BRANCH,
                    BASE_COMMIT,
                    BASE_COMMIT,
                    report_dir,
                    status,
                    1,
                    1,
                    "",
                )

            self.assertEqual(assessment.classification, "READY_FOR_TESTS")
            self.assertEqual(len(prompts), 2)
            self.assertIn("prior progress checkpoint was preserved", prompts[1])
            self.assertEqual(status["coder_continuations"], 1)

    def test_protocol_retries_are_bounded(self) -> None:
        invalid = '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
        status: dict[str, object] = {"rfc": RFC_ID, "status": "working"}
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "MAX_CODER_PROTOCOL_RETRIES", 1),
                mock.patch.object(watcher, "run_agent", return_value=invalid) as run,
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher,
                    "persist_coder_checkpoint",
                    return_value=self.checkpoint("CODER_PROTOCOL_OUTPUT_INVALID"),
                ),
                self.assertRaisesRegex(
                    watcher.CoderInfrastructureFailure, "CODER_PROTOCOL_OUTPUT_INVALID"
                ),
            ):
                watcher.run_coder_until_gate(
                    RFC_TEXT,
                    RFC_ID,
                    worktree,
                    BRANCH,
                    BASE_COMMIT,
                    BASE_COMMIT,
                    report_dir,
                    status,
                    1,
                    1,
                    "",
                )
            self.assertEqual(run.call_count, 2)

    def test_invalid_output_never_overwrites_canonical_coder_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            report_dir = reports / RFC_ID
            worktree = root / "worktree"
            repo = root / "project"
            rfc_path = root / "working" / f"{RFC_ID}.md"
            for path in (report_dir, worktree, repo, rfc_path.parent):
                path.mkdir(parents=True, exist_ok=True)
            rfc_path.write_text(RFC_TEXT)
            canonical = coding_report()
            (report_dir / "coder-report.md").write_text(canonical)
            (report_dir / "status.json").write_text(
                json.dumps({"rfc": RFC_ID, "status": "failed", "attempts": 1})
            )
            assessment = watcher.CoderOutputAssessment(
                "CODER_REPORT_INVALID", "unfinished narration", ("# Coding Report",)
            )
            with (
                mock.patch.object(watcher, "REPORTS", reports),
                mock.patch.object(watcher, "PROJECT_ROOT", repo),
                mock.patch.object(watcher, "MAX_CODER_CYCLES", 1),
                mock.patch.object(
                    watcher,
                    "prepare_worktree",
                    return_value=(repo, worktree, "main", BRANCH, BASE_COMMIT),
                ),
                mock.patch.object(watcher, "build_review_candidate", return_value={}),
                mock.patch.object(
                    watcher,
                    "run_coder_until_gate",
                    return_value=(assessment, self.checkpoint("CODER_REPORT_INVALID")),
                ),
                self.assertRaisesRegex(watcher.TaskFailure, "maximum coder cycles"),
            ):
                watcher.process_task(rfc_path)
            self.assertEqual((report_dir / "coder-report.md").read_text(), canonical)

    def test_queued_retry_revalidates_checkpoint_before_coder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            report_dir = reports / RFC_ID
            worktree = root / "worktree"
            repo = root / "project"
            rfc_path = root / "working" / f"{RFC_ID}.md"
            for path in (report_dir, worktree, repo, rfc_path.parent):
                path.mkdir(parents=True, exist_ok=True)
            rfc_path.write_text(RFC_TEXT)
            checkpoint = self.checkpoint("CODER_PROTOCOL_OUTPUT_INVALID")
            (report_dir / "status.json").write_text(
                json.dumps(
                    {
                        "rfc": RFC_ID,
                        "status": "coder_retry_queued",
                        "attempts": 1,
                        "branch": BRANCH,
                        "base_commit": BASE_COMMIT,
                        "coder_checkpoint": checkpoint,
                    }
                )
            )
            ready = watcher.assess_coder_output(coding_report())
            review = {
                "verdict": "PASS",
                "summary": "pass",
                "acceptance_criteria": ["pass"],
                "code_review_findings": ["none"],
                "test_review": "pass",
                "architecture_scope_review": "pass",
                "security_review": "pass",
                "regression_risks": [],
                "required_changes": [],
            }
            with (
                mock.patch.object(watcher, "REPORTS", reports),
                mock.patch.object(watcher, "PROJECT_ROOT", repo),
                mock.patch.object(
                    watcher,
                    "prepare_worktree",
                    return_value=(repo, worktree, "main", BRANCH, BASE_COMMIT),
                ),
                mock.patch.object(watcher, "validate_coder_checkpoint") as validate,
                mock.patch.object(
                    watcher,
                    "run_coder_until_gate",
                    return_value=(ready, self.checkpoint("READY_FOR_TESTS")),
                ) as coder,
                mock.patch.object(watcher, "combined_diff", return_value="diff"),
                mock.patch.object(watcher, "run_tests", return_value=(True, "pass")),
                mock.patch.object(watcher, "build_review_candidate", return_value={}),
                mock.patch.object(watcher, "perform_review", return_value=(review, 0)),
                mock.patch.object(
                    watcher, "run_full_regression", return_value=(True, "pass", "PASS")
                ),
                mock.patch.object(watcher, "complete_task"),
            ):
                watcher.process_task(rfc_path)
            validate.assert_called_once()
            coder.assert_called_once()


class RetryCoderControlTests(unittest.TestCase):
    def make_layout(self, root: Path) -> tuple[Path, Path]:
        report_dir = root / "reports" / RFC_ID
        worktree = root / "worktrees" / RFC_ID
        for path in (
            report_dir,
            worktree,
            root / "todo" / "inbox",
            root / "todo" / "working",
            root / "todo" / "done",
            root / "todo" / "failed",
        ):
            path.mkdir(parents=True, exist_ok=True)
        state = {
            "rfc": RFC_ID,
            "status": "coder_infra_failed",
            "phase": "coder_infra_failed",
            "failure_kind": "CODER_PROTOCOL_OUTPUT_INVALID",
            "failure": "CODER_PROTOCOL_OUTPUT_INVALID: bad protocol",
            "attempts": 2,
            "branch": BRANCH,
            "base_commit": BASE_COMMIT,
            "worktree": str(worktree.resolve()),
            "coder_checkpoint": {
                "checkpoint_digest": "d" * 64,
                "manifest": "coder-checkpoints/test.json",
            },
        }
        (report_dir / "status.json").write_text(json.dumps(state))
        (root / "todo" / "failed" / f"{RFC_ID}.md").write_text(RFC_TEXT)
        return report_dir, worktree

    def git_result(self, _project: Path, *args: str) -> object:
        if args[:2] == ("branch", "--show-current"):
            return command_result(BRANCH + "\n")
        if args[:2] == ("rev-parse", "HEAD"):
            return command_result(BASE_COMMIT + "\n")
        if args and args[0] == "merge-base":
            return command_result(BASE_COMMIT + "\n")
        return command_result()

    def test_retry_coder_preserves_identity_and_enqueues_same_rfc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(control, "validate_coder_checkpoint") as validate,
            ):
                control.retry_coder(RFC_ID)
            state = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(state["status"], "coder_retry_queued")
            self.assertEqual(state["branch"], BRANCH)
            self.assertEqual(state["base_commit"], BASE_COMMIT)
            self.assertEqual(state["coder_retry_count"], 1)
            self.assertEqual(
                state["failure_history"][-1]["checkpoint_digest"], "d" * 64
            )
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())
            validate.assert_called_once()

    def test_legacy_rfc057_protocol_failure_imports_a_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state.update(
                {
                    "status": "failed",
                    "phase": "failed",
                    "failure_kind": None,
                    "failure": "TaskFailure: Exceeded maximum coder cycles (5)",
                    "tests_status": "PENDING",
                    "tests_passed": False,
                }
            )
            state.pop("coder_checkpoint")
            (report_dir / "status.json").write_text(json.dumps(state))
            (report_dir / "coder-attempt-2-cycle-5.md").write_text(
                '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
            )
            (report_dir / "raw").mkdir()
            (report_dir / "raw" / "attempt-2-coder-5.json").write_text(
                json.dumps(
                    {
                        "subtype": "success",
                        "result": '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">',
                    }
                )
            )
            imported = {
                "classification": "CODER_PROTOCOL_OUTPUT_INVALID",
                "checkpoint_digest": "e" * 64,
                "manifest": "coder-checkpoints/legacy.json",
            }
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(control, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(
                    control, "persist_coder_checkpoint", return_value=imported
                ) as persist,
                mock.patch.object(control, "validate_coder_checkpoint"),
            ):
                control.retry_coder(RFC_ID)
            updated = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(updated["status"], "coder_retry_queued")
            self.assertEqual(updated["failure_kind"], "CODER_PROTOCOL_OUTPUT_INVALID")
            self.assertEqual(updated["coder_checkpoint"], imported)
            persist.assert_called_once()

    def test_legacy_cycle_exhaustion_without_protocol_evidence_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state.update(
                {
                    "status": "failed",
                    "failure_kind": None,
                    "failure": "TaskFailure: Exceeded maximum coder cycles (5)",
                    "tests_status": "PENDING",
                    "tests_passed": False,
                }
            )
            state.pop("coder_checkpoint")
            (report_dir / "status.json").write_text(json.dumps(state))
            (report_dir / "coder-attempt-2-cycle-5.md").write_text("ordinary unfinished report")
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)
            self.assertFalse((root / "todo" / "inbox" / f"{RFC_ID}.md").exists())

    def test_retry_coder_rejects_an_active_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            (root / "todo" / "working" / f"{RFC_ID}.md").write_text(RFC_TEXT)
            with (
                mock.patch.object(control, "BASE", root),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)

    def test_retry_coder_fails_closed_on_checkpoint_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(
                    control,
                    "validate_coder_checkpoint",
                    side_effect=watcher.TaskFailure("digest mismatch"),
                ),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)
            self.assertFalse((root / "todo" / "inbox" / f"{RFC_ID}.md").exists())

    def test_retry_coder_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state["coder_retry_count"] = 3
            (report_dir / "status.json").write_text(json.dumps(state))
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "MAX_CODER_RECOVERY_ATTEMPTS", 3),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)


if __name__ == "__main__":
    unittest.main()
