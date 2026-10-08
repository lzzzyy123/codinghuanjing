from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scheduler.isolation import IsolationLayout
from scheduler.processes import FencedProcessExecutor, ProcessExecutionError


class ProcessExecutorTests(unittest.TestCase):
    def test_separate_home_cache_logs_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            layout = IsolationLayout(root / "runtime")
            secret = "canary-secret-value"
            executor = FencedProcessExecutor(
                layout,
                "coder-1",
                "coder",
                secret_environment={"ANTHROPIC_API_KEY": secret},
                known_secrets=(secret,),
                heartbeat_seconds=0.01,
            )
            result = executor.run(
                [
                    "/bin/sh",
                    "-c",
                    'printf "%s\\n%s\\n%s\\n" "$HOME" "$XDG_CACHE_HOME" "$ANTHROPIC_API_KEY"',
                ],
                root,
                label="job-1-token-1",
                timeout_seconds=2,
            )
            paths = layout.agent_paths("coder-1")
            self.assertTrue(result.ok)
            self.assertIn(str(paths.home), result.stdout)
            self.assertIn(str(paths.cache), result.stdout)
            self.assertNotIn(secret, result.stdout)
            self.assertIn("[REDACTED]", result.stdout)
            self.assertEqual(os.stat(result.stdout_path).st_mode & 0o777, 0o600)

    def test_lease_loss_terminates_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            calls = 0

            def current() -> None:
                nonlocal calls
                calls += 1
                if calls > 1:
                    raise RuntimeError("stale")

            executor = FencedProcessExecutor(
                IsolationLayout(Path(directory) / "runtime"),
                "reviewer-1",
                "reviewer",
                assert_current=current,
                heartbeat_seconds=0.01,
            )
            with self.assertRaisesRegex(ProcessExecutionError, "lost its current lease"):
                executor.run(
                    ["/bin/sh", "-c", "sleep 5"],
                    Path(directory),
                    label="review-1",
                    timeout_seconds=2,
                )

    def test_timeout_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executor = FencedProcessExecutor(
                IsolationLayout(Path(directory) / "runtime"),
                "tester-1",
                "tester",
            )
            result = executor.run(
                ["/bin/sh", "-c", "sleep 5"],
                Path(directory),
                label="test-1",
                timeout_seconds=0.05,
            )
            self.assertTrue(result.timed_out)
            self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
