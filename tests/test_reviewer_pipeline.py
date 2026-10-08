from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import watcher  # noqa: E402


def review_object(verdict: str = "REQUEST_CHANGES", issue: str = "Fix the defect") -> dict:
    return {
        "verdict": verdict,
        "summary": "Independent summary",
        "acceptance_criteria": ["AC-1: FAIL - reproduced"],
        "code_review_findings": ["Finding preserved"],
        "test_review": "Tests do not cover the defect.",
        "architecture_scope_review": "Scope is otherwise correct.",
        "security_review": "No credential exposure observed.",
        "regression_risks": ["Risk preserved"],
        "required_changes": [] if verdict == "PASS" else [issue],
    }


def actionable_review(original_issue: str = "Fix the defect") -> str:
    value = review_object(issue=original_issue)
    value["required_changes"] = [
        f"Issue: {original_issue} | Location: src/example.ts:10 | "
        "Reproduction: bun test tests/example.test.ts | Acceptance: the test passes"
    ]
    return json.dumps(value)


class ReviewerPipelineTests(unittest.TestCase):
    def test_tolerant_invariants_recover_invalid_regex_escapes(self) -> None:
        raw = json.dumps(review_object(issue="Regex must preserve marker"))
        raw = raw.replace("Regex must preserve marker", r"Regex /\s+\d+/ must preserve marker")
        parsed = watcher.review_invariants("preamble\n```json\n" + raw + "\n```")
        self.assertEqual(parsed["verdict"], "REQUEST_CHANGES")
        self.assertIn("Regex", parsed["required_changes"][0])

    def test_request_changes_requires_actionable_markers(self) -> None:
        with self.assertRaises(watcher.ReviewFormatError):
            watcher.validate_review(json.dumps(review_object()))

    def test_controlled_repair_preserves_verdict_and_issue(self) -> None:
        source_issue = "Fix the defect"
        raw = json.dumps(review_object(issue=source_issue))
        calls: list[int] = []
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)

            def repair(_prompt: str, attempt: int) -> str:
                calls.append(attempt)
                return actionable_review(source_issue)

            review, repairs = watcher.validate_review_with_repairs(
                raw, report_dir, "attempt-1-cycle-1", repair
            )
            self.assertEqual(review["verdict"], "REQUEST_CHANGES")
            self.assertEqual(repairs, 1)
            self.assertEqual(calls, [1])
            diagnostic = json.loads(
                (report_dir / "review-format-diagnostics-attempt-1-cycle-1.json").read_text()
            )
            self.assertEqual(diagnostic["attempts"][-1]["result"], "PASS")

    def test_repair_cannot_change_verdict_or_remove_issue(self) -> None:
        raw = json.dumps(review_object(issue="Original issue"))
        changed = json.dumps(review_object(verdict="PASS"))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(watcher.ReviewInfrastructureFailure):
                watcher.validate_review_with_repairs(
                    raw,
                    Path(directory),
                    "attempt-1-cycle-1",
                    lambda _prompt, _attempt: changed,
                )

    def test_unrecoverable_output_never_invokes_formatter(self) -> None:
        calls = 0

        def repair(_prompt: str, _attempt: int) -> str:
            nonlocal calls
            calls += 1
            return "{}"

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(watcher.ReviewInfrastructureFailure):
                watcher.validate_review_with_repairs(
                    "review stopped before any verdict",
                    Path(directory),
                    "attempt-1-cycle-1",
                    repair,
                )
        self.assertEqual(calls, 0)

    def test_sensitive_values_are_redacted_from_evidence(self) -> None:
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "secret-value"}):
            value = watcher.redact_sensitive_text(
                "secret-value authorization: Bearer second-secret password=third-secret"
            )
        self.assertNotIn("secret-value", value)
        self.assertNotIn("second-secret", value)
        self.assertNotIn("third-secret", value)

    def test_reviewer_candidate_reuse_requires_exact_record(self) -> None:
        candidate = {"workspace_fingerprint": "abc"}
        state = {
            "status": "review_infra_failed",
            "tests_status": "PASS",
            "tests_passed": True,
            "validated_candidate": candidate,
        }
        report = "\n".join(watcher.CODER_REPORT_HEADINGS)
        self.assertTrue(watcher.review_candidate_is_reusable(state, candidate, report))
        self.assertFalse(
            watcher.review_candidate_is_reusable(
                state, {"workspace_fingerprint": "changed"}, report
            )
        )

    def test_review_infrastructure_failure_has_distinct_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            failed = root / "failed"
            reports.mkdir()
            failed.mkdir()
            rfc = root / "RFC-TEST.md"
            rfc.write_text("test")
            with (
                mock.patch.object(watcher, "REPORTS", reports),
                mock.patch.object(watcher, "FAILED", failed),
                mock.patch.object(
                    watcher,
                    "process_task",
                    side_effect=watcher.ReviewInfrastructureFailure("REVIEW_INFRA_FAILED: bad JSON"),
                ),
            ):
                watcher.handle_claimed(rfc)
            state = json.loads((reports / "RFC-TEST" / "status.json").read_text())
            self.assertEqual(state["status"], "review_infra_failed")
            self.assertEqual(state["failure_kind"], "REVIEW_INFRA_FAILED")


if __name__ == "__main__":
    unittest.main()
