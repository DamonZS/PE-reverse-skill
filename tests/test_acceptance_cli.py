from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.cli import main


class AcceptanceCliTests(unittest.TestCase):
    def test_list_reports_registered_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["environment", "accept", "list", "--workspace", temporary])

        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(any(item["id"] == "p1-memory-runtime-live" for item in payload["fixtures"]))
        self.assertEqual(payload["records"], [])

    def test_run_requires_explicit_execute_and_rejects_unknown_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "environment",
                        "accept",
                        "run",
                        "--fixture",
                        "p0-environment-contract",
                        "--workspace",
                        temporary,
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("explicit", stderr.getvalue())

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                code = main(
                    [
                        "environment",
                        "accept",
                        "run",
                        "--fixture",
                        "arbitrary-command",
                        "--workspace",
                        temporary,
                        "--execute",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertIn("unknown acceptance fixture", stderr.getvalue())

    def test_repository_fixture_run_and_verify_are_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "environment",
                        "accept",
                        "run",
                        "--fixture",
                        "p0-environment-contract",
                        "--workspace",
                        temporary,
                        "--execute",
                        "--timeout",
                        "60",
                    ]
                )
            record = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(record["outcome"], "passed")
            self.assertFalse(record["live_verified"])
            self.assertTrue(Path(record["record_path"]).is_file())

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "environment",
                        "accept",
                        "verify",
                        "--record",
                        record["record_path"],
                    ]
                )
            verification = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(verification["status"], "ok")

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(
                    [
                        "environment",
                        "validate",
                        "--json",
                        "--acceptance-workspace",
                        temporary,
                    ]
                )
            report = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(report["summary"]["acceptance_record_total"], 1)


if __name__ == "__main__":
    unittest.main()
