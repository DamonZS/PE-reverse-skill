from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.sandbox import (
    SANDBOX_CONFIRMATION_PHRASE,
    SandboxLimits,
    SandboxWorker,
    detect_container_runtimes,
)


class SandboxWorkerTests(unittest.TestCase):
    def test_plan_has_defensive_defaults_and_never_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with patch("reverse_analyzer.sandbox.worker.shutil.which", return_value="/bin/docker"):
                with patch("reverse_analyzer.sandbox.worker.subprocess.run") as run:
                    result = SandboxWorker(
                        runtime="docker",
                        image="worker:test",
                        workspace=temporary,
                    ).run(["python", "--version"])

        run.assert_not_called()
        self.assertTrue(result["dry_run"])
        self.assertIn("--read-only", result["argv"])
        self.assertIn("ALL", result["argv"])
        self.assertIn("no-new-privileges", result["argv"])
        self.assertEqual(result["argv"][result["argv"].index("--network") + 1], "none")
        self.assertIn("readonly", result["argv"][result["argv"].index("--mount") + 1])

    def test_execute_requires_exact_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            worker = SandboxWorker(runtime="docker", image="worker:test", workspace=temporary)
            with self.assertRaises(PermissionError):
                worker.run(["true"], execute=True, confirmation="yes")

    def test_confirmed_execution_is_bounded_subprocess(self) -> None:
        completed = subprocess.CompletedProcess(["docker"], 0, stdout=b"ok", stderr=b"")
        with tempfile.TemporaryDirectory() as temporary:
            with patch("reverse_analyzer.sandbox.worker.shutil.which", return_value="/bin/docker"):
                with patch("reverse_analyzer.sandbox.worker.subprocess.run", return_value=completed) as run:
                    result = SandboxWorker(
                        runtime="docker",
                        image="worker:test",
                        workspace=temporary,
                        limits=SandboxLimits(timeout_seconds=7),
                    ).run(
                        ["analyze", "sample.bin"],
                        execute=True,
                        confirmation=SANDBOX_CONFIRMATION_PHRASE,
                    )

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["executed"])
        self.assertEqual(run.call_args.kwargs["timeout"], 7)
        self.assertFalse(run.call_args.kwargs["check"])

    def test_runtime_detection_does_not_probe_when_disabled(self) -> None:
        with patch("reverse_analyzer.sandbox.worker.shutil.which", return_value="/bin/runtime"):
            with patch("reverse_analyzer.sandbox.worker.subprocess.run") as run:
                result = detect_container_runtimes(probe=False)

        run.assert_not_called()
        self.assertTrue(result["available"])
        self.assertFalse(result["verified"])


if __name__ == "__main__":
    unittest.main()
