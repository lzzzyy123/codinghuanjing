from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import control  # noqa: E402
import watcher  # noqa: E402


RFC_ID = "RFC-20261008-054"
RFC_TEXT = """---
title: Test
test_command: "true"
---

# RFC
"""


def coder_report() -> str:
    return "\n".join(watcher.CODER_REPORT_HEADINGS)


class ControlTests(unittest.TestCase):
    def make_layout(self, root: Path) -> None:
        for path in (
            root / "reports" / RFC_ID,
            root / "worktrees" / RFC_ID,
            root / "todo" / "inbox",
            root / "todo" / "working",
            root / "todo" / "done",
            root / "todo" / "failed",
        ):
            path.mkdir(parents=True, exist_ok=True)

    def test_legacy_review_failure_can_queue_reviewer_only_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            report_dir = root / "reports" / RFC_ID
            state = {
                "rfc": RFC_ID,
                "status": "failed",
                "tests_status": "PASS",
                "tests_passed": True,
                "failure": "Reviewer result did not contain a JSON object with verdict",
                "attempts": 1,
                "base_commit": "a" * 40,
                "worktree": str((root / "worktrees" / RFC_ID).resolve()),
            }
            (report_dir / "status.json").write_text(json.dumps(state))
            (report_dir / "coder-report.md").write_text(coder_report())
            (root / "todo" / "failed" / f"{RFC_ID}.md").write_text(RFC_TEXT)
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "build_review_candidate", return_value={"hash": "ok"}),
            ):
                control.retry_review(RFC_ID)
            updated = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(updated["status"], "review_infra_failed")
            self.assertEqual(updated["validated_candidate"], {"hash": "ok"})
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())

    def test_project_lead_amendment_reuses_rfc_and_branch_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            report_dir = root / "reports" / RFC_ID
            state = {
                "rfc": RFC_ID,
                "status": "done",
                "push": "PASS",
                "branch": f"agent/{RFC_ID}",
                "pr_status": "created",
                "pr_url": "https://github.com/o/r/pull/1",
            }
            (report_dir / "status.json").write_text(json.dumps(state))
            (root / "todo" / "done" / f"{RFC_ID}.md").write_text(RFC_TEXT)
            upload_name = f".amend-upload-{RFC_ID}-test"
            feedback = """# Project Lead Amendment

## Summary
Defect found.
## Required Changes
- Fix it.
## Reproduction
- bun test
## Acceptance Conditions
- Test passes.
"""
            (root / "todo" / "inbox" / upload_name).write_text(feedback)
            with mock.patch.object(control, "BASE", root):
                control.enqueue_amendment(RFC_ID, upload_name)
            updated = json.loads((report_dir / "status.json").read_text())
            self.assertEqual(updated["status"], "amendment_queued")
            self.assertEqual(updated["branch"], f"agent/{RFC_ID}")
            self.assertEqual(updated["pr_url"], "https://github.com/o/r/pull/1")
            self.assertTrue((report_dir / "amendments" / "amendment-1.md").is_file())
            self.assertTrue((root / "todo" / "inbox" / f"{RFC_ID}.md").is_file())

    def test_status_updates_append_durable_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory) / RFC_ID
            state = {"rfc": RFC_ID, "status": "working", "phase": "coding"}
            watcher.update_status(report_dir, state, phase="testing", tests_status="RUNNING")
            watcher.update_status(report_dir, state, tests_status="PASS")

            status = json.loads((report_dir / "status.json").read_text())
            events = [
                json.loads(line)
                for line in (report_dir / "events.jsonl").read_text().splitlines()
            ]
            self.assertEqual(status["event_sequence"], 2)
            self.assertEqual([event["sequence"] for event in events], [1, 2])
            self.assertEqual(events[0]["changes"], ["phase", "tests_status"])
            self.assertEqual(events[1]["tests_status"], "PASS")

    def test_wait_rfc_returns_immediately_for_completed_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            report_dir = root / "reports" / RFC_ID
            (report_dir / "status.json").write_text(
                json.dumps({"rfc": RFC_ID, "status": "done", "phase": "complete"})
            )
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "rfc_status") as show_status,
            ):
                control.wait_rfc(RFC_ID, "10")
            show_status.assert_called_once_with(RFC_ID)

    def test_wait_rfc_times_out_with_current_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_layout(root)
            report_dir = root / "reports" / RFC_ID
            (report_dir / "status.json").write_text(
                json.dumps({"rfc": RFC_ID, "status": "working", "phase": "coding"})
            )
            with (
                mock.patch.object(control, "BASE", root),
                mock.patch.object(control, "rfc_status") as show_status,
                mock.patch.object(control.time, "monotonic", side_effect=[0.0, 1.0]),
                mock.patch.object(control.time, "sleep"),
                self.assertRaises(SystemExit) as raised,
            ):
                control.wait_rfc(RFC_ID, "1")
            self.assertEqual(raised.exception.code, 124)
            show_status.assert_called_once_with(RFC_ID)


if __name__ == "__main__":
    unittest.main()
