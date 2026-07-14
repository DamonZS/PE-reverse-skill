from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from reverse_analyzer.source.runtime_validation import validate_source_runtime


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class SourceRuntimeValidationTests(unittest.TestCase):
    def test_real_python_build_and_behavior_smoke_records_observed_evidence(self) -> None:
        worker = """\
import json
from pathlib import Path
import sys

mode = sys.argv[1]
if mode == "build":
    Path("build.marker").write_bytes(b"local-build-ok")
    print("build-ok")
elif mode == "behavior":
    payload = {"answer": 42, "ok": True}
    Path("result.bin").write_bytes(b"verified-output")
    Path("result.json").write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    print(json.dumps(payload, sort_keys=True))
else:
    raise SystemExit(7)
"""
        expected_json = b'{"answer": 42, "ok": true}'
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(project / "worker.py", worker)

            result = validate_source_runtime(
                project,
                {
                    "steps": [
                        {
                            "name": "build",
                            "kind": "build",
                            "argv": [sys.executable, "worker.py", "build"],
                            "expect": {
                                "exit_code": 0,
                                "stdout": "build-ok\n",
                                "stderr": "",
                                "output_files": {
                                    "build.marker": _sha256(b"local-build-ok"),
                                },
                            },
                        },
                        {
                            "name": "behavior",
                            "kind": "behavior",
                            "argv": [sys.executable, "worker.py", "behavior"],
                            "expect": {
                                "exit_code": 0,
                                "stdout": expected_json.decode("ascii") + "\n",
                                "stderr": "",
                                "output_files": {
                                    "result.bin": _sha256(b"verified-output"),
                                    "result.json": _sha256(expected_json),
                                },
                                "json_assertions": [
                                    {
                                        "source": "stdout",
                                        "path": "/ok",
                                        "equals": True,
                                    },
                                    {
                                        "file": "result.json",
                                        "path": ["answer"],
                                        "equals": 42,
                                        "type": "integer",
                                    },
                                ],
                            },
                        },
                    ]
                },
                default_timeout=10,
            )

            self.assertEqual(result["status"], "passed", result["diagnostics"])
            self.assertFalse(result["behavior_equivalent"])
            self.assertEqual(result["summary"]["executed_step_count"], 2)
            self.assertEqual(result["summary"]["failed_assertion_count"], 0)
            self.assertTrue(result["project"]["changed"])
            self.assertNotEqual(
                result["project"]["sha256_before"],
                result["project"]["sha256_after"],
            )
            self.assertEqual(
                result["provenance"]["project"]["sha256_after"],
                result["project"]["sha256_after"],
            )
            self.assertTrue(result["provenance"]["tools"][0]["available"])
            self.assertTrue(result["provenance"]["tools"][0]["sha256"])
            self.assertIs(result["provenance"]["validator"]["shell"], False)
            self.assertEqual(result["steps"][0]["stdout_text"], "build-ok\n")
            self.assertIs(result["steps"][0]["shell"], False)
            self.assertTrue(
                all(
                    assertion["passed"]
                    for step in result["steps"]
                    for assertion in step["assertions"]
                )
            )
            self.assertEqual(result["artifact"]["status"], "passed")
            self.assertEqual(result["artifact"]["role"], "validation_evidence")
            self.assertFalse(result["artifact"]["behavior_equivalent"])
            json.dumps(result, sort_keys=True, allow_nan=False)

    def test_parent_cwd_and_output_paths_are_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir()
            self._write(
                project / "worker.py",
                "from pathlib import Path\nPath('executed.marker').write_text('ran')\n",
            )
            escape_hash = _sha256(b"outside")

            cwd_escape = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "worker.py"],
                        "cwd": "..",
                    }
                },
            )
            output_escape = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "worker.py"],
                        "expected_output_files": {"../outside.bin": escape_hash},
                    }
                },
            )

            for result in (cwd_escape, output_escape):
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["summary"]["executed_step_count"], 0)
                self.assertTrue(any("invalid validation spec" in item for item in result["diagnostics"]))
            self.assertFalse((project / "executed.marker").exists())
            self.assertFalse((root / "outside.bin").exists())

    def test_real_python_timeout_is_failed_and_process_is_terminated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(
                project / "slow.py",
                "import time\nprint('started', flush=True)\ntime.sleep(10)\n",
            )
            started = time.monotonic()

            result = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "slow.py"],
                        "timeout_seconds": 0.15,
                        "expected_stdout": "started\n",
                    }
                },
            )

            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["steps"][0]["timed_out"])
            self.assertIsNone(result["steps"][0]["exit_code"])
            self.assertEqual(result["steps"][0]["stdout_text"], "started\n")
            self.assertTrue(any("timed out after 0.15 seconds" in item for item in result["diagnostics"]))
            self.assertFalse(result["behavior_equivalent"])

    def test_missing_allowlisted_tool_is_unavailable_without_running_steps(self) -> None:
        missing = "source-runtime-validation-tool-not-installed"
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(project / "input.txt", "unchanged\n")

            result = validate_source_runtime(
                project,
                {"behavior": {"argv": [missing, "--version"]}},
                allowed_tools={missing},
            )

            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["summary"]["planned_step_count"], 1)
            self.assertEqual(result["summary"]["executed_step_count"], 0)
            self.assertEqual(
                result["project"]["sha256_before"],
                result["project"]["sha256_after"],
            )
            self.assertFalse(result["provenance"]["tools"][0]["available"])
            self.assertTrue(any("was not found" in item for item in result["diagnostics"]))
            self.assertFalse(result["artifact"]["behavior_equivalent"])

    def test_wrong_output_hash_is_failed_with_actual_hash_evidence(self) -> None:
        content = b"runtime artifact bytes"
        wrong_hash = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(
                project / "produce.py",
                "from pathlib import Path\nPath('artifact.bin').write_bytes(b'runtime artifact bytes')\n",
            )

            result = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "produce.py"],
                        "expected_output_files": {"artifact.bin": wrong_hash},
                    }
                },
            )

            self.assertEqual(result["status"], "failed")
            output = result["steps"][0]["outputs"][0]
            self.assertEqual(output["expected_sha256"], wrong_hash)
            self.assertEqual(output["sha256"], _sha256(content))
            self.assertFalse(output["matched"])
            hash_assertion = next(
                item
                for item in result["steps"][0]["assertions"]
                if item["kind"] == "output_file_sha256"
            )
            self.assertFalse(hash_assertion["passed"])
            self.assertFalse(result["behavior_equivalent"])

    def test_json_assertions_do_not_coerce_booleans_to_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(
                project / "json_result.py",
                "import json\nprint(json.dumps({'value': True, 'items': [0]}))\n",
            )

            result = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "json_result.py"],
                        "json_assertions": [
                            {"source": "stdout", "path": "/value", "equals": 1},
                            {"source": "stdout", "path": "/items", "contains": False},
                        ],
                    }
                },
            )

            self.assertEqual(result["status"], "failed")
            json_assertions = [
                item for item in result["steps"][0]["assertions"] if item["kind"] == "json"
            ]
            self.assertEqual(len(json_assertions), 2)
            self.assertTrue(all(item["passed"] is False for item in json_assertions))
            self.assertFalse(result["behavior_equivalent"])

    def test_stdout_and_stderr_are_bounded_while_streams_are_drained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write(
                project / "noisy.py",
                "import sys\nsys.stdout.write('o' * 20000)\nsys.stderr.write('e' * 24000)\n",
            )

            result = validate_source_runtime(
                project,
                {
                    "behavior": {
                        "argv": [sys.executable, "noisy.py"],
                        "stdout_limit": 97,
                        "stderr_limit": 113,
                    }
                },
            )

            self.assertEqual(result["status"], "passed", result["diagnostics"])
            stdout = result["steps"][0]["stdout"]
            stderr = result["steps"][0]["stderr"]
            self.assertEqual(stdout["captured_bytes"], 97)
            self.assertEqual(stdout["total_bytes"], 20000)
            self.assertTrue(stdout["truncated"])
            self.assertEqual(stderr["captured_bytes"], 113)
            self.assertEqual(stderr["total_bytes"], 24000)
            self.assertTrue(stderr["truncated"])

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
