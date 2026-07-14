from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from reverse_analyzer.source.behavior_validation import validate_source_behavior


class SourceBehaviorValidationTests(unittest.TestCase):
    def test_real_python_processes_match_normalized_streams_and_declared_outputs(self) -> None:
        original_program = """\
from pathlib import Path
import sys

Path("artifact.bin").write_bytes(b"same-artifact")
Path("result.json").write_text('{"answer":42,"ok":true}', encoding="utf-8")
sys.stdout.buffer.write(b"line\\r\\n" * 64)
sys.stderr.buffer.write(b"note\\r")
raise SystemExit(7)
"""
        reconstructed_program = """\
from pathlib import Path
import sys

Path("artifact.bin").write_bytes(b"same-artifact")
Path("result.json").write_text('{ "ok": true, "answer": 42 }', encoding="utf-8")
sys.stdout.buffer.write(b"line\\n" * 64)
sys.stderr.buffer.write(b"note\\n")
raise SystemExit(7)
"""
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", original_program)
            self._write(reconstructed / "program.py", reconstructed_program)

            result = validate_source_behavior(
                original,
                reconstructed,
                {
                    "target_identity": {"id": "real-python-fixture", "kind": "local_process"},
                    "original": {
                        "argv": [sys.executable, "program.py"],
                        "stdout_limit": 31,
                        "stderr_limit": 3,
                    },
                    "reconstructed": {
                        "argv": [sys.executable, "program.py"],
                        "stdout_limit": 31,
                        "stderr_limit": 3,
                    },
                    "outputs": [
                        {"name": "artifact", "kind": "sha256", "path": "artifact.bin"},
                        {"name": "result", "kind": "json", "path": "result.json"},
                    ],
                },
            )

            self.assertEqual(result["status"], "passed", result["diagnostics"])
            self.assertIs(result["behavior_equivalent"], True)
            self.assertEqual(result["summary"]["comparison_count"], 5)
            self.assertEqual(result["summary"]["mismatched_comparison_count"], 0)
            self.assertEqual(result["runs"]["original"]["exit_code"], 7)
            self.assertEqual(result["runs"]["reconstructed"]["exit_code"], 7)
            self.assertTrue(result["runs"]["original"]["stdout"]["truncated"])
            self.assertTrue(result["runs"]["reconstructed"]["stdout"]["truncated"])
            self.assertTrue(result["runs"]["original"]["stderr"]["truncated"])
            self.assertTrue(result["runs"]["reconstructed"]["stderr"]["truncated"])
            self.assertEqual(
                result["runs"]["original"]["stdout"]["normalized_sha256"],
                result["runs"]["reconstructed"]["stdout"]["normalized_sha256"],
            )
            self.assertNotEqual(
                result["runs"]["original"]["stdout"]["total_bytes"],
                result["runs"]["reconstructed"]["stdout"]["total_bytes"],
            )
            self.assertTrue(
                all(item["matched"] for item in result["comparisons"]),
                result["comparisons"],
            )
            self.assertTrue(
                all(item["produced"] for item in result["runs"]["original"]["outputs"])
            )
            self.assertEqual(result["target_identity"]["original"]["path"], "program.py")
            self.assertTrue(result["target_identity"]["original"]["sha256"])
            self.assertIs(result["target_identity"]["original"]["unchanged"], True)
            self.assertIs(result["commands"]["original"]["shell"], False)
            self.assertEqual(result["commands"]["original"]["argv"][0], sys.executable)
            self.assertIs(result["provenance"]["validator"]["real_subprocess"], True)
            self.assertIs(result["provenance"]["validator"]["runner_injected"], False)
            self.assertIs(result["provenance"]["validator"]["shell"], False)
            self.assertTrue(result["provenance"]["dependencies"]["original"]["sha256"])
            self.assertEqual(
                result["artifact"]["payload"]["target_identity"],
                result["target_identity"],
            )
            self.assertIs(result["artifact"]["behavior_equivalent"], True)
            self.assertTrue(result["artifact"]["evidence_sha256"])
            json.dumps(result, sort_keys=True, allow_nan=False)

    def test_exit_and_stdout_difference_fail_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", "print('original')\nraise SystemExit(2)\n")
            self._write(
                reconstructed / "program.py",
                "print('reconstructed')\nraise SystemExit(3)\n",
            )

            result = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {"argv": [sys.executable, "program.py"]},
                    "reconstructed": {"argv": [sys.executable, "program.py"]},
                },
            )

            self.assertEqual(result["status"], "failed")
            self.assertIs(result["behavior_equivalent"], False)
            comparisons = {item["name"]: item for item in result["comparisons"]}
            self.assertIs(comparisons["exit_code"]["matched"], False)
            self.assertIs(comparisons["stdout"]["matched"], False)
            self.assertIs(comparisons["stderr"]["matched"], True)
            self.assertTrue(any("exit_code" in item for item in result["diagnostics"]))

    def test_output_hash_and_json_value_differences_are_reported(self) -> None:
        program = """\
from pathlib import Path
import json

Path("artifact.bin").write_bytes(ARTIFACT)
Path("result.json").write_text(json.dumps({"value": VALUE}), encoding="utf-8")
"""
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(
                original / "program.py",
                "ARTIFACT = b'left'\nVALUE = True\n" + program,
            )
            self._write(
                reconstructed / "program.py",
                "ARTIFACT = b'right'\nVALUE = 1\n" + program,
            )

            result = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {"argv": [sys.executable, "program.py"]},
                    "reconstructed": {"argv": [sys.executable, "program.py"]},
                    "outputs": [
                        {"name": "artifact", "path": "artifact.bin"},
                        {
                            "name": "value",
                            "kind": "json",
                            "path": "result.json",
                            "json_path": "/value",
                        },
                    ],
                },
            )

            self.assertEqual(result["status"], "failed")
            self.assertIs(result["behavior_equivalent"], False)
            comparisons = {item["name"]: item for item in result["comparisons"]}
            self.assertEqual(comparisons["artifact"]["kind"], "output_file_sha256")
            self.assertIs(comparisons["artifact"]["matched"], False)
            self.assertNotEqual(
                comparisons["artifact"]["original"]["sha256"],
                comparisons["artifact"]["reconstructed"]["sha256"],
            )
            self.assertEqual(comparisons["value"]["kind"], "output_json_value")
            self.assertIs(comparisons["value"]["original"]["value"], True)
            self.assertEqual(comparisons["value"]["reconstructed"]["value"], 1)
            self.assertIs(comparisons["value"]["matched"], False)

    def test_real_python_timeout_is_failed_and_terminated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(
                original / "program.py",
                "import time\nprint('started', flush=True)\ntime.sleep(10)\n",
            )
            self._write(reconstructed / "program.py", "print('started')\n")
            started_at = time.monotonic()

            result = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {
                        "argv": [sys.executable, "program.py"],
                        "timeout_seconds": 0.15,
                    },
                    "reconstructed": {
                        "argv": [sys.executable, "program.py"],
                        "timeout_seconds": 0.15,
                    },
                },
            )

            self.assertLess(time.monotonic() - started_at, 5)
            self.assertEqual(result["status"], "failed")
            self.assertIs(result["behavior_equivalent"], False)
            self.assertIs(result["runs"]["original"]["timed_out"], True)
            self.assertIsNone(result["runs"]["original"]["exit_code"])
            self.assertEqual(result["runs"]["original"]["stdout_text"], "started\n")
            self.assertIs(result["runs"]["reconstructed"]["timed_out"], False)
            self.assertTrue(any("timed out after 0.15" in item for item in result["diagnostics"]))

    def test_cwd_and_declared_output_path_escape_are_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            original, reconstructed = self._roots(base)
            marker_program = "from pathlib import Path\nPath('executed.marker').write_text('ran')\n"
            self._write(original / "program.py", marker_program)
            self._write(reconstructed / "program.py", marker_program)

            cwd_escape = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {"argv": [sys.executable, "program.py"], "cwd": ".."},
                    "reconstructed": {"argv": [sys.executable, "program.py"]},
                },
            )
            output_escape = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {"argv": [sys.executable, "program.py"]},
                    "reconstructed": {"argv": [sys.executable, "program.py"]},
                    "outputs": [{"name": "escape", "path": "../outside.bin"}],
                },
            )

            for result in (cwd_escape, output_escape):
                self.assertEqual(result["status"], "failed")
                self.assertIs(result["behavior_equivalent"], False)
                self.assertEqual(result["summary"]["executed_command_count"], 0)
                self.assertTrue(
                    any("invalid behavior validation spec" in item for item in result["diagnostics"])
                )
            self.assertFalse((original / "executed.marker").exists())
            self.assertFalse((reconstructed / "executed.marker").exists())
            self.assertFalse((base / "outside.bin").exists())

    def test_missing_dependency_is_unavailable_and_mock_identity_cannot_pass(self) -> None:
        missing_tool = "source-behavior-validator-missing-tool"
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            original, reconstructed = self._roots(base)

            unavailable = validate_source_behavior(
                original,
                reconstructed,
                {
                    "original": {"argv": [missing_tool, "--version"]},
                    "reconstructed": {"argv": [missing_tool, "--version"]},
                },
                allowed_tools={missing_tool},
                tool_resolver=lambda _value: None,
            )

            self.assertEqual(unavailable["status"], "unavailable")
            self.assertIs(unavailable["behavior_equivalent"], False)
            self.assertEqual(unavailable["summary"]["executed_command_count"], 0)
            self.assertIs(unavailable["provenance"]["dependencies"]["original"]["available"], False)

            marker_program = "from pathlib import Path\nPath('executed.marker').write_text('ran')\n"
            self._write(original / "program.py", marker_program)
            self._write(reconstructed / "program.py", marker_program)
            mocked = validate_source_behavior(
                original,
                reconstructed,
                {
                    "target_identity": {"kind": "mock"},
                    "original": {"argv": [sys.executable, "program.py"]},
                    "reconstructed": {"argv": [sys.executable, "program.py"]},
                },
            )

            self.assertEqual(mocked["status"], "failed")
            self.assertIs(mocked["behavior_equivalent"], False)
            self.assertEqual(mocked["summary"]["executed_command_count"], 0)
            self.assertTrue(any("non-real execution evidence" in item for item in mocked["diagnostics"]))
            self.assertFalse((original / "executed.marker").exists())
            self.assertFalse((reconstructed / "executed.marker").exists())

    @staticmethod
    def _roots(base: Path) -> tuple[Path, Path]:
        original = base / "original"
        reconstructed = base / "reconstructed"
        original.mkdir()
        reconstructed.mkdir()
        return original, reconstructed

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
