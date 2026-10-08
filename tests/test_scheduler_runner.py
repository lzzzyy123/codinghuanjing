from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scheduler.runner import (
    ReviewerReadOnlyProbe,
    RunnerError,
    RunnerTimeout,
    UnixIdentity,
    run_bounded,
)


class RunnerTests(unittest.TestCase):
    def test_bounded_runner_returns_output_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run_bounded(
                [sys.executable, "-c", "print('ok')"],
                cwd=Path(directory),
                env={"PATH": os.environ.get("PATH", "")},
                timeout_seconds=2,
            )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ok\n")

    def test_bounded_runner_times_out_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RunnerTimeout):
                run_bounded(
                    [sys.executable, "-c", "import time; time.sleep(10)"],
                    cwd=Path(directory),
                    env={"PATH": os.environ.get("PATH", "")},
                    timeout_seconds=0.05,
                )

    def test_timeout_does_not_wait_for_escaped_descendant_pipe(self) -> None:
        escaped = (
            "import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(1.5)'],"
            "start_new_session=True);"
            "time.sleep(10)"
        )
        with tempfile.TemporaryDirectory() as directory:
            started = time.monotonic()
            with self.assertRaises(RunnerTimeout):
                run_bounded(
                    [sys.executable, "-c", escaped],
                    cwd=Path(directory),
                    env={"PATH": os.environ.get("PATH", "")},
                    timeout_seconds=0.2,
                )
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.0)

    @unittest.skipIf(os.geteuid() == 0, "root bypasses Unix mode write checks")
    def test_read_only_probe_uses_real_kernel_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "snapshot"
            root.mkdir()
            content = root / "content"
            content.write_text("review me\n")
            probe = ReviewerReadOnlyProbe()
            with self.assertRaisesRegex(RunnerError, "can modify"):
                probe.verify(root)
            content.chmod(0o400)
            root.chmod(0o500)
            probe.verify(root)
            forbidden = Path(directory) / "git-common"
            forbidden.mkdir()
            with self.assertRaisesRegex(RunnerError, "forbidden root"):
                probe.verify(root, (forbidden,))
            forbidden.chmod(0o500)
            probe.verify(root, (forbidden,))

    def test_unix_identity_rejects_command_injection(self) -> None:
        with self.assertRaises(ValueError):
            UnixIdentity("reviewer;id", "codingproject")


if __name__ == "__main__":
    unittest.main()
