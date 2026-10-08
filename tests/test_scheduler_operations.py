from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scheduler.replay import replay_legacy_reports
from scheduler.resources import ResourcePolicy, ResourceSnapshot, admit


class OperationsTests(unittest.TestCase):
    def test_replays_legacy_events_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            task = reports / "RFC-TEST"
            task.mkdir()
            (task / "status.json").write_text(
                json.dumps(
                    {
                        "status": "done",
                        "event_sequence": 2,
                        "started_at": "2026-10-08T00:00:00+00:00",
                        "completed_at": "2026-10-08T00:10:00+00:00",
                    }
                )
            )
            (task / "events.jsonl").write_text(
                json.dumps({"sequence": 1}) + "\n" + json.dumps({"sequence": 2}) + "\n"
            )
            result = replay_legacy_reports(reports)
            self.assertEqual(result.tasks, 1)
            self.assertEqual(result.events, 2)
            self.assertEqual(result.legacy_status_only, 0)
            self.assertEqual(result.anomalies, ())
            self.assertEqual(result.as_dict()["terminal_duration_median_seconds"], 600)

    def test_resource_policy_has_technical_not_cost_guards(self) -> None:
        policy = ResourcePolicy(
            max_expensive_processes=2,
            min_memory_headroom_bytes=1_000,
            min_disk_free_bytes=1_000,
        )
        healthy = ResourceSnapshot(6, 1.0, 6_000, 3_000, 10_000, 1, 0)
        self.assertTrue(admit(healthy, policy).allowed)
        saturated = ResourceSnapshot(6, 1.0, 6_000, 5_900, 10_000, 2, 0)
        result = admit(saturated, policy)
        self.assertFalse(result.allowed)
        self.assertTrue(any("concurrency" in item for item in result.blockers))
        self.assertFalse(any("token" in item or "cost" in item for item in result.blockers))


if __name__ == "__main__":
    unittest.main()
