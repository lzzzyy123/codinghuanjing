from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import watcher  # noqa: E402


RFC_ID = "RFC-20261008-054"
RFC_TEXT = """---
title: Amendment integration test
test_command: "bun test tests/module.test.ts"
lint_command: "bun run lint"
build_command: "bun run build"
---

# RFC-20261008-054

## Acceptance Criteria

- [ ] Original behavior passes.
"""

AMENDMENT = """# Project Lead Amendment

## Summary

A post-review defect must be corrected on the original task branch.

## Required Changes

- Fix the demonstrated defect locally.

## Reproduction

- `bun test tests/module.test.ts`

## Acceptance Conditions

- The regression is fixed without changing RFC identity.
"""


def coder_report() -> str:
    return "\n\n".join(f"{heading}\nEvidence." for heading in watcher.CODER_REPORT_HEADINGS)


def passing_review() -> dict:
    return {
        "verdict": "PASS",
        "summary": "The amendment is satisfied.",
        "acceptance_criteria": ["Original behavior passes: PASS - evidence"],
        "code_review_findings": ["Scoped correction verified."],
        "test_review": "Module tests pass.",
        "architecture_scope_review": "No boundary change.",
        "security_review": "No new exposure.",
        "regression_risks": ["None identified."],
        "required_changes": [],
    }


class AmendmentFlowTests(unittest.TestCase):
    def test_amendment_runs_coder_tests_and_reviewer_on_same_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            report_dir = reports / RFC_ID
            worktree = root / "worktrees" / RFC_ID
            repo = root / "project"
            rfc_path = root / "working" / f"{RFC_ID}.md"
            for path in (report_dir / "amendments", worktree, repo, rfc_path.parent):
                path.mkdir(parents=True, exist_ok=True)
            rfc_path.write_text(RFC_TEXT)
            (report_dir / "amendments" / "amendment-1.md").write_text(AMENDMENT)
            (report_dir / "status.json").write_text(
                json.dumps(
                    {
                        "rfc": RFC_ID,
                        "status": "amendment_queued",
                        "phase": "amendment_queued",
                        "branch": f"agent/{RFC_ID}",
                        "pr_status": "created",
                        "pr_url": "https://github.com/o/r/pull/54",
                        "attempts": 1,
                        "total_coder_cycles": 1,
                        "total_review_cycles": 1,
                        "pending_amendment": {"number": 1, "file": "amendment-1.md"},
                        "amendment_history": [{"number": 1, "file": "amendment-1.md"}],
                    }
                )
            )

            coder_prompts: list[str] = []

            def run_agent(role: str, prompt: str, *_args: object) -> str:
                self.assertEqual(role, "Coder")
                coder_prompts.append(prompt)
                return coder_report()

            with (
                mock.patch.object(watcher, "REPORTS", reports),
                mock.patch.object(watcher, "PROJECT_ROOT", repo),
                mock.patch.object(watcher, "PROMPTS", ROOT / "worker" / "prompts"),
                mock.patch.object(
                    watcher,
                    "prepare_worktree",
                    return_value=(repo, worktree, "main", f"agent/{RFC_ID}", "a" * 40),
                ) as prepare,
                mock.patch.object(watcher, "run_agent", side_effect=run_agent),
                mock.patch.object(watcher, "combined_diff", return_value="diff"),
                mock.patch.object(watcher, "run_tests", return_value=(True, "module PASS")) as tests,
                mock.patch.object(
                    watcher, "build_review_candidate", return_value={"fingerprint": "candidate"}
                ),
                mock.patch.object(
                    watcher, "perform_review", return_value=(passing_review(), 0)
                ) as review,
                mock.patch.object(
                    watcher, "run_full_regression", return_value=(True, "full PASS", "PASS")
                ) as regression,
                mock.patch.object(watcher, "complete_task") as complete,
            ):
                watcher.process_task(rfc_path)

            prepare.assert_called_once_with(RFC_ID, report_dir, True)
            self.assertEqual(len(coder_prompts), 1)
            self.assertIn(AMENDMENT, coder_prompts[0])
            self.assertEqual(coder_prompts[0].count("# Project Lead Amendment"), 1)
            self.assertIn(f"Branch: agent/{RFC_ID}", coder_prompts[0])
            tests.assert_called_once()
            review.assert_called_once()
            regression.assert_called_once()
            complete.assert_called_once()
            completion_status = complete.call_args.args[-1]
            self.assertEqual(completion_status["rfc"], RFC_ID)
            self.assertEqual(completion_status["branch"], f"agent/{RFC_ID}")
            self.assertEqual(completion_status["pr_url"], "https://github.com/o/r/pull/54")
            self.assertEqual(completion_status["total_coder_cycles"], 2)
            self.assertEqual(completion_status["total_review_cycles"], 2)


if __name__ == "__main__":
    unittest.main()
