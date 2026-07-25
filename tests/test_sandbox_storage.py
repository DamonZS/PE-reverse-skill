import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from reverse_analyzer.sandbox import SandboxWorker, SandboxLimits
from reverse_analyzer.storage import storage_status


class SandboxStorageTests(unittest.TestCase):
    def test_sandbox_is_plan_only_and_restricted(self):
        with TemporaryDirectory() as tmp:
            payload = SandboxWorker(runtime="docker", image="python:3.12-slim", workspace=tmp, limits=SandboxLimits(network=False)).plan(["python", "-c", "print(1)"])
        self.assertTrue(payload["dry_run"])
        self.assertIn("--read-only", payload["argv"])
        self.assertIn("--network", payload["argv"])
        self.assertIn("plan only", payload["execution_boundary"])

    def test_default_storage_is_local(self):
        with TemporaryDirectory() as tmp:
            payload = storage_status(Path(tmp))
        self.assertEqual(payload["backend"], "json")


if __name__ == "__main__":
    unittest.main()
