from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import subprocess
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


def concurrent_retry_coder(root_text: str, start: object, results: object) -> None:
    root = Path(root_text)

    def fake_git(_project: Path, *args: str) -> object:
        if args[:2] == ("branch", "--show-current"):
            return command_result(BRANCH + "\n")
        if args[:2] == ("rev-parse", "HEAD"):
            return command_result(BASE_COMMIT + "\n")
        if args and args[0] == "merge-base":
            return command_result(BASE_COMMIT + "\n")
        return command_result()

    start.wait()
    try:
        with (
            mock.patch.object(control, "BASE", root),
            mock.patch.object(control, "git", side_effect=fake_git),
            mock.patch.object(control, "validate_coder_checkpoint"),
        ):
            control.retry_coder(RFC_ID)
    except SystemExit:
        results.put("rejected")
    else:
        results.put("queued")


def hold_rfc_lock(root_text: str, acquired: object, release: object) -> None:
    with watcher.rfc_lock(Path(root_text), RFC_ID, blocking=True):
        acquired.set()
        release.wait(10)


class CoderOutputTests(unittest.TestCase):
    def test_literal_dsml_is_a_protocol_failure_not_a_report_format_failure(self) -> None:
        result = watcher.assess_coder_output(
            'planning\n<｜DSML｜tool_calls><｜DSML｜invoke name="Write">'
            '<｜DSML｜parameter name="path">'
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

    def test_fresh_complete_report_requires_explicit_status(self) -> None:
        legacy = "\n".join(watcher.CODER_REPORT_HEADINGS)
        result = watcher.assess_coder_output(legacy)
        self.assertEqual(result.classification, "CODER_REPORT_INVALID")
        self.assertEqual(result.errors, ("missing Completion Status: READY_FOR_TESTS",))

    def test_prose_mentioning_dsml_marker_is_not_a_protocol_failure(self) -> None:
        text = coding_report() + "\nThe string <｜DSML｜tool_calls> was documented as an example."
        self.assertEqual(watcher.assess_coder_output(text).classification, "READY_FOR_TESTS")

    def test_conflicting_completion_statuses_are_rejected(self) -> None:
        result = watcher.assess_coder_output(
            coding_report() + "\nCompletion Status: CONTINUE\n"
        )
        self.assertEqual(result.classification, "CODER_REPORT_INVALID")
        self.assertEqual(result.errors, ("multiple completion statuses",))

    def test_completion_status_is_case_and_whitespace_exact(self) -> None:
        for marker in (
            "completion status: READY_FOR_TESTS",
            "Completion Status:  READY_FOR_TESTS",
            "Completion Status: READY_FOR_TESTS ",
        ):
            with self.subTest(marker=marker):
                result = watcher.assess_coder_output(
                    coding_report().replace(
                        "Completion Status: READY_FOR_TESTS", marker
                    )
                )
                self.assertEqual(result.classification, "CODER_REPORT_INVALID")

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


class CredentialRedactionTests(unittest.TestCase):
    def test_quoted_json_credentials_remain_valid_and_do_not_leak(self) -> None:
        secrets = {
            "api_key": "api-secret",
            "password": "password-secret",
            "Authorization": "Bearer bearer-secret",
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "client_secret": "client-secret",
        }
        redacted = watcher.redact_sensitive_text(json.dumps(secrets))
        parsed = json.loads(redacted)
        self.assertEqual(set(parsed.values()), {"[REDACTED]"})
        for secret in secrets.values():
            self.assertNotIn(secret, redacted)

    def test_standalone_bearer_and_checkpoint_artifacts_do_not_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktree"
            raw_path = report_dir / "raw" / "attempt.json"
            worktree.mkdir()
            watcher.write_redacted(
                raw_path,
                '{"result":"Authorization: Bearer bearer-secret",'
                '"api_key":"api-secret"}',
            )
            binding = watcher.build_coder_input_binding(
                RFC_TEXT, {"test_command": "true"}, RFC_ID, worktree
            )
            with (
                mock.patch.object(
                    watcher,
                    "combined_diff",
                    return_value="+password='password-secret'\n+Bearer standalone-secret\n",
                ),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fingerprint"),
                mock.patch.object(watcher, "changed_paths", return_value=["file"]),
                mock.patch.object(watcher, "git", return_value=command_result(BASE_COMMIT + "\n")),
            ):
                watcher.persist_coder_checkpoint(
                    report_dir,
                    "redaction",
                    RFC_ID,
                    BRANCH,
                    BASE_COMMIT,
                    worktree,
                    BASE_COMMIT,
                    "before",
                    "CONTINUE",
                    input_binding=binding,
                    raw_path=raw_path,
                )
            evidence = "\n".join(
                path.read_text(encoding="utf-8")
                for path in report_dir.rglob("*")
                if path.is_file()
            )
            for secret in (
                "api-secret",
                "bearer-secret",
                "password-secret",
                "standalone-secret",
            ):
                self.assertNotIn(secret, evidence)
            self.assertIn("[REDACTED]", evidence)

    def test_json_string_leaves_and_agent_errors_are_redacted(self) -> None:
        envelope = json.dumps(
            {
                "result": "api_key=hidden-one; password: hidden-two",
                "message": "Authorization: Basic hidden-three",
            }
        )
        redacted = watcher.redact_sensitive_text(envelope)
        json.loads(redacted)
        for secret in ("hidden-one", "hidden-two", "hidden-three"):
            self.assertNotIn(secret, redacted)

        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            failure = watcher.CommandResult(
                "agent",
                1,
                '{"result":"api_key=stdout-secret"}',
                "password: stderr-secret",
            )
            with (
                mock.patch.object(watcher, "execute", return_value=failure),
                self.assertRaises(watcher.AgentFailure) as raised,
            ):
                watcher.run_agent_once(
                    "Coder", "prompt", Path(directory), report_dir, "failure"
                )
            evidence = str(raised.exception) + "\n" + "\n".join(
                path.read_text(encoding="utf-8")
                for path in report_dir.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("stdout-secret", evidence)
            self.assertNotIn("stderr-secret", evidence)

    def test_error_envelope_exception_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            envelope = json.dumps(
                {
                    "subtype": "error",
                    "is_error": True,
                    "result": "access_token=error-secret",
                }
            )
            result = watcher.CommandResult("agent", 0, envelope, "")
            with (
                mock.patch.object(watcher, "execute", return_value=result),
                self.assertRaises(watcher.AgentFailure) as raised,
            ):
                watcher.run_agent_once(
                    "Reviewer",
                    "prompt",
                    Path(directory),
                    Path(directory) / "reports" / RFC_ID,
                    "error-envelope",
                )
            self.assertNotIn("error-secret", str(raised.exception))


class CoderCheckpointTests(unittest.TestCase):
    def assert_binding_change_rejected(
        self,
        worktree: Path,
        report_dir: Path,
        recorded: dict[str, object],
        current: dict[str, object],
        label: str,
    ) -> None:
        with (
            mock.patch.object(watcher, "combined_diff", return_value="diff"),
            mock.patch.object(watcher, "workspace_fingerprint", return_value="fingerprint"),
            mock.patch.object(watcher, "changed_paths", return_value=["file"]),
            mock.patch.object(watcher, "git", return_value=command_result(BASE_COMMIT + "\n")),
        ):
            checkpoint = watcher.persist_coder_checkpoint(
                report_dir,
                label,
                RFC_ID,
                BRANCH,
                BASE_COMMIT,
                worktree,
                BASE_COMMIT,
                "before",
                "CONTINUE",
                input_binding=recorded,
            )
            with self.assertRaisesRegex(watcher.TaskFailure, "inputs changed"):
                watcher.validate_coder_checkpoint(
                    report_dir,
                    checkpoint,
                    RFC_ID,
                    BRANCH,
                    BASE_COMMIT,
                    worktree,
                    BASE_COMMIT,
                    current,
                )

    def test_checkpoint_binds_redacted_raw_diff_and_workspace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktrees" / RFC_ID
            raw_path = report_dir / "raw" / "attempt-1-coder-1.json"
            worktree.mkdir(parents=True)
            raw_path.parent.mkdir(parents=True)
            raw_path.write_text('{"result":"already redacted"}')
            input_binding = watcher.build_coder_input_binding(
                RFC_TEXT, {"title": "Recovery test", "test_command": "true"}, RFC_ID, worktree
            )
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
                    input_binding=input_binding,
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
                    input_binding,
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
            input_binding = watcher.build_coder_input_binding(
                RFC_TEXT, {"title": "Recovery test", "test_command": "true"}, RFC_ID, worktree
            )
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
                    input_binding=input_binding,
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
                        input_binding,
                    )

    def test_rfc_or_frontmatter_command_change_rejects_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktree"
            worktree.mkdir()
            metadata = {
                "test_command": "true",
                "lint_command": "lint",
                "build_command": "build",
            }
            recorded = watcher.build_coder_input_binding(
                RFC_TEXT, metadata, RFC_ID, worktree
            )
            changed_rfc = watcher.build_coder_input_binding(
                RFC_TEXT + "\nchanged\n", metadata, RFC_ID, worktree
            )
            self.assert_binding_change_rejected(
                worktree, report_dir, recorded, changed_rfc, "rfc-change"
            )
            for command in ("lint_command", "build_command", "test_command"):
                with self.subTest(command=command):
                    changed_metadata = dict(metadata)
                    changed_metadata[command] += "-changed"
                    changed_command = watcher.build_coder_input_binding(
                        RFC_TEXT, changed_metadata, RFC_ID, worktree
                    )
                    self.assert_binding_change_rejected(
                        worktree,
                        report_dir,
                        recorded,
                        changed_command,
                        f"command-change-{command}",
                    )

    def test_dependency_manifest_creation_change_and_removal_reject_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktree"
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )
            dependency.parent.mkdir(parents=True)
            metadata = {"test_command": "true"}

            absent = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            dependency.write_text('{"add":["one"]}')
            created = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            self.assert_binding_change_rejected(
                worktree, report_dir, absent, created, "dependency-created"
            )

            recorded = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            dependency.write_text('{"add":["two"]}')
            changed = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            self.assert_binding_change_rejected(
                worktree, report_dir, recorded, changed, "dependency-changed"
            )

            recorded = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            dependency.unlink()
            removed = watcher.build_coder_input_binding(RFC_TEXT, metadata, RFC_ID, worktree)
            self.assert_binding_change_rejected(
                worktree, report_dir, recorded, removed, "dependency-removed"
            )

    def test_real_git_worktree_checkpoint_validates_and_rejects_head_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            worktree = root / "task-worktree"
            report_dir = root / "reports" / RFC_ID
            repository.mkdir()

            def real_git(*args: str, cwd: Path = repository) -> str:
                result = subprocess.run(
                    ["git", *args],
                    cwd=cwd,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                )
                return result.stdout.strip()

            real_git("init")
            real_git("config", "user.email", "test@example.invalid")
            real_git("config", "user.name", "Recovery Test")
            (repository / "module.ts").write_text("export const value = 1;\n")
            real_git("add", "module.ts")
            real_git("commit", "-m", "base")
            base_commit = real_git("rev-parse", "HEAD")
            real_git("worktree", "add", "-b", BRANCH, str(worktree), base_commit)
            (worktree / "module.ts").write_text("export const value = 2;\n")
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )
            dependency.parent.mkdir(parents=True)
            dependency.write_text('{"add":[]}')
            binding = watcher.build_coder_input_binding(
                RFC_TEXT, {"test_command": "true"}, RFC_ID, worktree
            )

            with (
                mock.patch.object(watcher, "GIT_RUNNER", []),
                mock.patch.object(watcher, "PROJECT_ROOT", repository),
                mock.patch.object(watcher, "WORKTREES", root / "managed-worktrees"),
            ):
                checkpoint = watcher.persist_coder_checkpoint(
                    report_dir,
                    "real-git",
                    RFC_ID,
                    BRANCH,
                    base_commit,
                    worktree,
                    base_commit,
                    watcher.workspace_fingerprint(worktree, base_commit),
                    "CONTINUE",
                    input_binding=binding,
                )
                manifest = watcher.validate_coder_checkpoint(
                    report_dir,
                    checkpoint,
                    RFC_ID,
                    BRANCH,
                    base_commit,
                    worktree,
                    base_commit,
                    binding,
                )
                self.assertEqual(real_git("branch", "--show-current", cwd=worktree), BRANCH)
                self.assertEqual(manifest["base_commit"], base_commit)
                self.assertIn("module.ts", manifest["changed_paths"])
                self.assertIn("coordination/requests", (report_dir / manifest["patch"]).read_text())

                with self.assertRaisesRegex(watcher.TaskFailure, "base_commit"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        BRANCH,
                        "f" * 40,
                        worktree,
                        base_commit,
                        binding,
                    )
                with self.assertRaisesRegex(watcher.TaskFailure, "branch"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        "agent/other",
                        base_commit,
                        worktree,
                        base_commit,
                        binding,
                    )
                changed_binding = watcher.build_coder_input_binding(
                    RFC_TEXT + "changed", {"test_command": "true"}, RFC_ID, worktree
                )
                with self.assertRaisesRegex(watcher.TaskFailure, "inputs changed"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        BRANCH,
                        base_commit,
                        worktree,
                        base_commit,
                        changed_binding,
                    )
                (worktree / "module.ts").write_text("export const value = 3;\n")
                with self.assertRaisesRegex(watcher.TaskFailure, "worktree changed"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        BRANCH,
                        base_commit,
                        worktree,
                        base_commit,
                        binding,
                    )

                real_git("add", ".", cwd=worktree)
                real_git("commit", "-m", "advance", cwd=worktree)
                with self.assertRaisesRegex(watcher.TaskFailure, "HEAD changed"):
                    watcher.validate_coder_checkpoint(
                        report_dir,
                        checkpoint,
                        RFC_ID,
                        BRANCH,
                        base_commit,
                        worktree,
                        base_commit,
                        binding,
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
                    {"test_command": "true"},
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
        invalid = (
            '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
            '<｜DSML｜parameter name="path">'
        )
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
                    {"test_command": "true"},
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

    def test_persistent_totals_continue_across_cycles_and_attempts(self) -> None:
        progress = "# Coder Progress Checkpoint\nCompletion Status: CONTINUE"
        status: dict[str, object] = {
            "rfc": RFC_ID,
            "status": "working",
            "total_coder_continuations": 3,
            "total_coder_lifecycle_actions": 7,
        }
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            answers = [progress, coding_report(), progress, coding_report()]
            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "run_agent", side_effect=answers),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher,
                    "persist_coder_checkpoint",
                    return_value=self.checkpoint("CONTINUE"),
                ),
            ):
                for cycle in (1, 2):
                    watcher.run_coder_until_gate(
                        RFC_TEXT,
                        {"test_command": "true"},
                        RFC_ID,
                        worktree,
                        BRANCH,
                        BASE_COMMIT,
                        BASE_COMMIT,
                        report_dir,
                        status,
                        1,
                        cycle,
                        "",
                    )
            self.assertEqual(status["total_coder_continuations"], 5)
            self.assertEqual(status["total_coder_lifecycle_actions"], 11)

    def test_lifecycle_cap_is_durable_and_not_retryable(self) -> None:
        invalid = (
            '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
            '<｜DSML｜parameter name="path">'
        )
        status: dict[str, object] = {
            "rfc": RFC_ID,
            "status": "working",
            "total_coder_protocol_failures": 0,
            "total_coder_lifecycle_actions": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "MAX_CODER_PROTOCOL_FAILURES_TOTAL", 1),
                mock.patch.object(watcher, "MAX_CODER_LIFECYCLE_ACTIONS", 10),
                mock.patch.object(watcher, "run_agent", return_value=invalid) as run,
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher,
                    "persist_coder_checkpoint",
                    return_value=self.checkpoint("CODER_PROTOCOL_OUTPUT_INVALID"),
                ),
                self.assertRaisesRegex(
                    watcher.CoderInfrastructureFailure, "CODER_LIFECYCLE_LIMIT_EXCEEDED"
                ),
            ):
                watcher.run_coder_until_gate(
                    RFC_TEXT,
                    {"test_command": "true"},
                    RFC_ID,
                    worktree,
                    BRANCH,
                    BASE_COMMIT,
                    BASE_COMMIT,
                    report_dir,
                    status,
                    2,
                    1,
                    "",
                )
            self.assertEqual(status["total_coder_protocol_failures"], 1)
            self.assertEqual(status["total_coder_lifecycle_actions"], 1)
            self.assertEqual(run.call_count, 1)

    def test_continuation_total_cap_stops_before_a_second_invocation(self) -> None:
        progress = "# Coder Progress Checkpoint\nCompletion Status: CONTINUE"
        status: dict[str, object] = {"rfc": RFC_ID, "status": "working"}
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / "reports" / RFC_ID
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "MAX_CODER_CONTINUATIONS_TOTAL", 1),
                mock.patch.object(watcher, "run_agent", return_value=progress) as run,
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher,
                    "persist_coder_checkpoint",
                    return_value=self.checkpoint("CONTINUE"),
                ),
                self.assertRaisesRegex(
                    watcher.CoderInfrastructureFailure, "CODER_LIFECYCLE_LIMIT_EXCEEDED"
                ),
            ):
                watcher.run_coder_until_gate(
                    RFC_TEXT,
                    {"test_command": "true"},
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
            self.assertEqual(run.call_count, 1)
            self.assertEqual(status["total_coder_continuations"], 1)

    def test_lifecycle_cap_prevents_an_extra_agent_invocation(self) -> None:
        status: dict[str, object] = {
            "rfc": RFC_ID,
            "status": "working",
            "total_coder_lifecycle_actions": 4,
        }
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "worktree"
            worktree.mkdir()
            with (
                mock.patch.object(watcher, "MAX_CODER_LIFECYCLE_ACTIONS", 4),
                mock.patch.object(watcher, "run_agent") as run,
                self.assertRaisesRegex(
                    watcher.CoderInfrastructureFailure, "CODER_LIFECYCLE_LIMIT_EXCEEDED"
                ),
            ):
                watcher.run_coder_until_gate(
                    RFC_TEXT,
                    {"test_command": "true"},
                    RFC_ID,
                    worktree,
                    BRANCH,
                    BASE_COMMIT,
                    BASE_COMMIT,
                    Path(directory) / "reports" / RFC_ID,
                    status,
                    2,
                    1,
                    "",
                )
            run.assert_not_called()

    def test_dependency_input_change_during_agent_call_fails_closed(self) -> None:
        status: dict[str, object] = {"rfc": RFC_ID, "status": "working"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktree"
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )
            dependency.parent.mkdir(parents=True)
            dependency.write_text('{"value":1}')

            def mutate_dependency(*_args: object) -> str:
                dependency.write_text('{"value":2}')
                return coding_report()

            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "run_agent", side_effect=mutate_dependency),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(watcher, "persist_coder_checkpoint") as persist,
                self.assertRaisesRegex(
                    watcher.CoderInfrastructureFailure, "CODER_INPUT_CHANGED"
                ),
            ):
                watcher.run_coder_until_gate(
                    RFC_TEXT,
                    {"test_command": "true"},
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
            persist.assert_not_called()

    def test_dependency_manifest_may_be_created_once_and_is_bound_to_checkpoint(self) -> None:
        status: dict[str, object] = {"rfc": RFC_ID, "status": "working"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir = root / "reports" / RFC_ID
            worktree = root / "worktree"
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )

            def create_dependency(*_args: object) -> str:
                dependency.parent.mkdir(parents=True)
                dependency.write_text(
                    json.dumps(
                        {
                            "spec": "dependency-manifest/v1",
                            "rfc_id": RFC_ID,
                            "requested_package_changes": [],
                            "requested_lockfile_changes": [],
                            "notes": [],
                        }
                    )
                )
                return coding_report()

            checkpoint = {"checkpoint_digest": "d" * 64}
            with (
                mock.patch.object(watcher, "PROJECT_ROOT", Path("/project")),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(watcher, "run_agent", side_effect=create_dependency),
                mock.patch.object(watcher, "workspace_fingerprint", return_value="fp"),
                mock.patch.object(watcher, "latest_agent_raw_path", return_value=Path("/raw.json")),
                mock.patch.object(
                    watcher, "persist_coder_checkpoint", return_value=checkpoint
                ) as persist,
                mock.patch.object(watcher, "update_status"),
                mock.patch.object(watcher, "record_coder_lifecycle_action"),
            ):
                assessment, result = watcher.run_coder_until_gate(
                    RFC_TEXT,
                    {"test_command": "true"},
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
            self.assertEqual(result, checkpoint)
            bound_dependency = persist.call_args.kwargs["input_binding"]["dependency_manifest"]
            self.assertTrue(bound_dependency["present"])

    def test_created_dependency_manifest_is_validated_before_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            worktree = Path(directory) / "worktree"
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )
            dependency.parent.mkdir(parents=True)
            before = watcher.build_coder_input_binding(
                RFC_TEXT, {"test_command": "true"}, RFC_ID, worktree
            )
            dependency.write_text('{"spec":"dependency-manifest/v1","rfc_id":"wrong"}')
            after = watcher.build_coder_input_binding(
                RFC_TEXT, {"test_command": "true"}, RFC_ID, worktree
            )
            with self.assertRaisesRegex(
                watcher.CoderInfrastructureFailure, "RFC identity mismatch"
            ):
                watcher.reconcile_coder_input_binding(before, after, worktree, RFC_ID)

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
            amendment_text = "# Project Lead Amendment\n\nRequire the recovery fix.\n"
            (report_dir / "amendments").mkdir()
            (report_dir / "amendments" / "amendment-1.md").write_text(amendment_text)
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
                        "pending_amendment": {"file": "amendment-1.md"},
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
            expected_binding = validate.call_args.args[-1]
            self.assertEqual(
                expected_binding["effective_rfc_sha256"],
                hashlib.sha256(
                    (RFC_TEXT + "\n\n" + amendment_text).encode("utf-8")
                ).hexdigest(),
            )
            coder.assert_called_once()


class RetryCoderControlTests(unittest.TestCase):
    def make_layout(self, root: Path, task_id: str = RFC_ID) -> tuple[Path, Path]:
        branch = f"agent/{task_id}"
        report_dir = root / "reports" / task_id
        worktree = root / "worktrees" / task_id
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
            "rfc": task_id,
            "status": "coder_infra_failed",
            "phase": "coder_infra_failed",
            "failure_kind": "CODER_PROTOCOL_OUTPUT_INVALID",
            "failure": "CODER_PROTOCOL_OUTPUT_INVALID: bad protocol",
            "attempts": 2,
            "branch": branch,
            "base_commit": BASE_COMMIT,
            "worktree": str(worktree.resolve()),
            "coder_checkpoint": {
                "checkpoint_digest": "d" * 64,
                "manifest": "coder-checkpoints/test.json",
            },
        }
        (report_dir / "status.json").write_text(json.dumps(state))
        (root / "todo" / "failed" / f"{task_id}.md").write_text(RFC_TEXT)
        return report_dir, worktree

    def git_result(self, _project: Path, *args: str) -> object:
        if args[:2] == ("branch", "--show-current"):
            return command_result(BRANCH + "\n")
        if args[:2] == ("rev-parse", "HEAD"):
            return command_result(BASE_COMMIT + "\n")
        if args and args[0] == "merge-base":
            return command_result(BASE_COMMIT + "\n")
        return command_result()

    def install_pending_enqueue_transaction(
        self, root: Path, *, with_stage: bool
    ) -> tuple[Path, Path]:
        report_dir = root / "reports" / RFC_ID
        status_path = report_dir / "status.json"
        original = json.loads(status_path.read_text())
        operation_id = "a" * 32
        staged_name = f".control-{RFC_ID}-123-{'b' * 32}"
        destination_name = f"{RFC_ID}.md"
        transaction = {
            "schema_version": 1,
            "rfc": RFC_ID,
            "operation_id": operation_id,
            "created_at": "2026-10-09T00:00:00+00:00",
            "staged_name": staged_name,
            "destination_name": destination_name,
            "rollback_state": original,
        }
        transaction["digest"] = watcher.canonical_digest(transaction)
        transaction_path = report_dir / "enqueue-transactions" / f"{operation_id}.json"
        watcher.atomic_json(transaction_path, transaction)
        queued = json.loads(json.dumps(original))
        queued.pop("failure", None)
        queued.update(
            {
                "status": "coder_retry_queued",
                "phase": "coder_retry_queued",
                "event_sequence": 1,
                "total_coder_lifecycle_actions": 1,
                "coder_retry": {
                    "enqueue_operation_id": operation_id,
                    "staged_name": staged_name,
                    "transaction_manifest": f"enqueue-transactions/{operation_id}.json",
                    "transaction_digest": transaction["digest"],
                },
            }
        )
        watcher.atomic_json(status_path, queued)
        staged = root / "todo" / "inbox" / staged_name
        if with_stage:
            staged.write_text(RFC_TEXT)
        return status_path, root / "todo" / "inbox" / destination_name

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
            self.assertEqual(state["total_coder_lifecycle_actions"], 1)
            self.assertEqual(
                state["failure_history"][-1]["checkpoint_digest"], "d" * 64
            )
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())
            validate.assert_called_once()

    def test_exhausted_coder_cycles_can_retry_only_from_a_valid_checkpoint(self) -> None:
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
                    "tests_status": "FAIL",
                    "tests_passed": False,
                }
            )
            (report_dir / "status.json").write_text(json.dumps(state))
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(control, "validate_coder_checkpoint") as validate,
            ):
                control.retry_coder(RFC_ID)
            updated = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(updated["status"], "coder_retry_queued")
            self.assertEqual(
                updated["coder_retry"]["failure_kind"], "CODER_CYCLES_EXHAUSTED"
            )
            validate.assert_called_once()

    def test_exhausted_coder_cycles_without_checkpoint_are_not_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state.update(
                {
                    "status": "failed",
                    "failure_kind": None,
                    "failure": "TaskFailure: Exceeded maximum coder cycles (5)",
                    "tests_status": "FAIL",
                    "tests_passed": False,
                }
            )
            state.pop("coder_checkpoint")
            (report_dir / "status.json").write_text(json.dumps(state))
            with (
                mock.patch.object(control, "BASE", root),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)
            self.assertFalse((root / "todo" / "inbox" / f"{RFC_ID}.md").exists())

    def test_input_change_retry_preserves_worktree_and_reruns_coder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state["failure_kind"] = "CODER_INPUT_CHANGED"
            state["failure"] = "CODER_INPUT_CHANGED: manifest created"
            state.pop("coder_checkpoint")
            (report_dir / "status.json").write_text(json.dumps(state))
            dependency = (
                worktree / "coordination" / "requests" / RFC_ID / "dependencies.json"
            )
            dependency.parent.mkdir(parents=True)
            dependency.write_text(
                json.dumps(
                    {
                        "spec": "dependency-manifest/v1",
                        "rfc_id": RFC_ID,
                        "requested_package_changes": [],
                        "requested_lockfile_changes": [],
                        "notes": [],
                    }
                )
            )
            raw = report_dir / "raw" / "attempt-1-coder-1.json"
            raw.parent.mkdir()
            raw.write_text('{"subtype":"success"}')
            imported = {
                "classification": "CODER_INPUT_CHANGED",
                "checkpoint_digest": "e" * 64,
                "manifest": "coder-checkpoints/input-change.json",
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
            self.assertEqual(updated["coder_checkpoint"], imported)
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())
            self.assertEqual(
                persist.call_args.args[8], "CODER_INPUT_CHANGED"
            )

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
                '<｜DSML｜parameter name="path">'
            )
            (report_dir / "raw").mkdir()
            (report_dir / "raw" / "attempt-2-coder-5.json").write_text(
                json.dumps(
                    {
                        "subtype": "success",
                        "result": '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
                        '<｜DSML｜parameter name="path">',
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

    def test_legacy_import_is_restricted_to_rfc057(self) -> None:
        other_id = "RFC-20261008-058"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root, other_id)
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
            with (
                mock.patch.object(control, "BASE", root),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(other_id)
            self.assertFalse((root / "todo" / "inbox" / f"{other_id}.md").exists())

    def test_legacy_import_rejects_mismatched_raw_and_markdown(self) -> None:
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
            markdown = (
                '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
                '<｜DSML｜parameter name="path">one'
            )
            raw = (
                '<｜DSML｜tool_calls><｜DSML｜invoke name="Read">'
                '<｜DSML｜parameter name="path">two'
            )
            (report_dir / "coder-attempt-2-cycle-5.md").write_text(markdown)
            (report_dir / "raw").mkdir()
            (report_dir / "raw" / "attempt-2-coder-5.json").write_text(
                json.dumps({"subtype": "success", "result": raw})
            )
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

    def test_lifecycle_limit_stops_administrative_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            state = json.loads((report_dir / "status.json").read_text())
            state["total_coder_lifecycle_actions"] = 4
            (report_dir / "status.json").write_text(json.dumps(state))
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "MAX_CODER_LIFECYCLE_ACTIONS", 4),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)

    def test_enqueue_publication_failure_rolls_back_with_monotonic_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            original_replace = os.replace
            destination = root / "todo" / "inbox" / f"{RFC_ID}.md"

            def fail_publication(source: object, target: object) -> None:
                if Path(target) == destination:
                    raise OSError("simulated publication failure")
                original_replace(source, target)

            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(control, "validate_coder_checkpoint"),
                mock.patch.object(control.os, "replace", side_effect=fail_publication),
                self.assertRaisesRegex(OSError, "publication failure"),
            ):
                control.retry_coder(RFC_ID)
            state = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(state["status"], "coder_infra_failed")
            self.assertEqual(state["event_sequence"], 2)
            self.assertEqual(state["total_coder_lifecycle_actions"], 1)
            self.assertEqual(len(state["enqueue_failures"]), 1)
            self.assertFalse(destination.exists())
            sequences = [
                json.loads(line)["sequence"]
                for line in (report_dir / "events.jsonl").read_text().splitlines()
            ]
            self.assertEqual(sequences, [1, 2])

    def test_status_cas_rejects_mutation_before_transition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_dir, _worktree = self.make_layout(root)
            real_digest = control.status_content_digest(report_dir / "status.json")
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "git", side_effect=self.git_result),
                mock.patch.object(control, "validate_coder_checkpoint"),
                mock.patch.object(
                    control,
                    "status_content_digest",
                    side_effect=[real_digest, "f" * 64],
                ),
                self.assertRaises(SystemExit),
            ):
                control.retry_coder(RFC_ID)
            state = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(state["status"], "coder_infra_failed")
            self.assertFalse((root / "todo" / "inbox" / f"{RFC_ID}.md").exists())

    def test_crash_recovery_publishes_a_durable_staged_enqueue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            status_path, destination = self.install_pending_enqueue_transaction(
                root, with_stage=True
            )
            with (
                mock.patch.object(watcher, "BASE", root),
                mock.patch.object(watcher, "REPORTS", root / "reports"),
                mock.patch.object(watcher, "INBOX", root / "todo" / "inbox"),
                mock.patch.object(watcher, "WORKING", root / "todo" / "working"),
            ):
                watcher.recover_coder_retry_enqueues()
            self.assertTrue(destination.is_file())
            state = json.loads(status_path.read_text())
            self.assertEqual(state["status"], "coder_retry_queued")
            self.assertEqual(
                state["coder_retry_recovery"]["action"], "published_staged_enqueue"
            )
            self.assertEqual(state["event_sequence"], 2)

    def test_crash_recovery_rolls_back_when_staged_enqueue_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            status_path, destination = self.install_pending_enqueue_transaction(
                root, with_stage=False
            )
            with (
                mock.patch.object(watcher, "BASE", root),
                mock.patch.object(watcher, "REPORTS", root / "reports"),
                mock.patch.object(watcher, "INBOX", root / "todo" / "inbox"),
                mock.patch.object(watcher, "WORKING", root / "todo" / "working"),
            ):
                watcher.recover_coder_retry_enqueues()
            self.assertFalse(destination.exists())
            state = json.loads(status_path.read_text())
            self.assertEqual(state["status"], "coder_infra_failed")
            self.assertEqual(state["event_sequence"], 2)
            self.assertEqual(state["total_coder_lifecycle_actions"], 1)
            self.assertIn("missing staged", state["enqueue_failures"][-1]["error"])

    def test_two_concurrent_retries_have_exactly_one_enqueue_winner(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("requires multiprocessing fork")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            context = multiprocessing.get_context("fork")
            start = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=concurrent_retry_coder,
                    args=(str(root), start, results),
                )
                for _ in range(2)
            ]
            for process in processes:
                process.start()
            start.set()
            for process in processes:
                process.join(10)
                self.assertFalse(process.is_alive())
                self.assertEqual(process.exitcode, 0)
            outcomes = sorted(results.get(timeout=2) for _ in processes)
            self.assertEqual(outcomes, ["queued", "rejected"])
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())
            state = json.loads((root / "reports" / RFC_ID / "status.json").read_text())
            self.assertEqual(state["coder_retry_count"], 1)

    def test_worker_lock_fences_control_plane_retry(self) -> None:
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("requires multiprocessing fork")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            context = multiprocessing.get_context("fork")
            acquired = context.Event()
            release = context.Event()
            holder = context.Process(
                target=hold_rfc_lock,
                args=(str(root), acquired, release),
            )
            holder.start()
            self.assertTrue(acquired.wait(5))
            try:
                with (
                    mock.patch.object(control, "BASE", root),
                    self.assertRaises(SystemExit),
                ):
                    control.retry_coder(RFC_ID)
            finally:
                release.set()
                holder.join(10)
            self.assertEqual(holder.exitcode, 0)
            self.assertFalse((root / "todo" / "inbox" / f"{RFC_ID}.md").exists())


if __name__ == "__main__":
    unittest.main()
