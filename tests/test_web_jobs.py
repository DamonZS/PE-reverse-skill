from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import time
import unittest

from reverse_analyzer.web_jobs import CONFIRMATION_PHRASE, WebJobManager


class WebJobManagerTests(unittest.TestCase):
    def _wait_for_status(self, manager: WebJobManager, experiment_id: str, expected: str) -> dict:
        deadline = time.time() + 5
        while time.time() < deadline:
            record = manager.store.get(experiment_id)
            if record["status"] == expected:
                return record
            time.sleep(0.05)
        self.fail(f"experiment did not reach {expected}")

    def test_execute_requires_explicit_confirmation(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ")
            manager = WebJobManager(root)
            record = manager.store.create(sample)

            with self.assertRaises(PermissionError):
                manager.execute(record["id"])

            self.assertEqual(manager.store.get(record["id"])["status"], "queued")

    def test_execute_records_completion_and_events(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ")
            manager = WebJobManager(root)
            record = manager.store.create(sample)
            manager.store.build_analysis_command = lambda experiment_id, python_executable=None: [
                sys.executable,
                "-c",
                "print('analysis ok')",
            ]

            result = manager.execute(record["id"], confirmation=CONFIRMATION_PHRASE)

            self.assertTrue(result["running"])
            completed = self._wait_for_status(manager, record["id"], "completed")
            self.assertEqual(completed["summary"]["return_code"], 0)
            messages = [item["message"] for item in manager.event_log.list_events(record["id"])]
            self.assertIn("analysis ok", messages)

    def test_cancel_queued_experiment(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ")
            manager = WebJobManager(root)
            record = manager.store.create(sample)

            cancelled = manager.cancel(record["id"])

            self.assertEqual(cancelled["experiment"]["status"], "cancelled")

    def test_retry_creates_new_queued_record(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ")
            manager = WebJobManager(root)
            record = manager.store.create(sample)
            manager.store.set_status(record["id"], "planned")
            manager.store.set_status(record["id"], "running")
            manager.store.record_result(record["id"], status="failed", error="boom")

            retry = manager.retry(record["id"])

            self.assertEqual(retry["experiment"]["status"], "queued")
            self.assertEqual(retry["experiment"]["metadata"]["retry_of"], record["id"])


if __name__ == "__main__":
    unittest.main()
