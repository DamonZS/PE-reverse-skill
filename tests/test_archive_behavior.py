from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from reverse_analyzer.source.archive_behavior import validate_archive_behavior


class ArchiveBehaviorValidationTests(unittest.TestCase):
    def test_real_python_fixture_passes_and_persists_validator_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", "print('same')\n")
            self._write(reconstructed / "program.py", "print('same')\n")

            result = validate_archive_behavior(
                original,
                reconstructed,
                self._python_spec(),
                isolated=True,
            )

            self.assertEqual(result["status"], "passed", result.get("diagnostics"))
            self.assertIs(result["behavior_equivalent"], True)
            self.assertIs(result["archive_validation"]["isolated"], True)
            validator = result["provenance"]["validator"]
            self.assertIs(validator["real_subprocess"], True)
            self.assertIs(validator["runner_injected"], False)
            self.assertIs(validator["shell"], False)
            artifact = reconstructed / "docs" / "behavior-validation.json"
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8")), result)

    def test_real_python_difference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", "print('original')\n")
            self._write(reconstructed / "program.py", "print('changed')\n")

            result = validate_archive_behavior(
                original,
                reconstructed,
                self._python_spec(),
                isolated=True,
            )

            self.assertEqual(result["status"], "failed")
            self.assertIs(result["behavior_equivalent"], False)
            self.assertEqual(result["blocking_reasons"], ["behavior_comparison_mismatch"])
            self.assertTrue((reconstructed / "docs" / "behavior-validation.json").is_file())

    def test_non_comparison_failures_have_stable_blocking_reasons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            cases = (
                ("unavailable", "behavior_validation_dependency_unavailable"),
                ("failed", "behavior_validation_failed"),
            )
            for status, expected_reason in cases:
                with self.subTest(status=status):
                    validator_result = {
                        "status": status,
                        "behavior_equivalent": False,
                        "diagnostics": ["runtime detail"],
                        "summary": {"comparison_count": 0, "mismatched_comparison_count": 0},
                        "provenance": {"validator": {"real_subprocess": True, "runner_injected": False, "shell": False}},
                    }
                    with patch(
                        "reverse_analyzer.source.archive_behavior.validate_source_behavior",
                        return_value=validator_result,
                    ):
                        result = validate_archive_behavior(original, reconstructed, self._python_spec(), isolated=True)

                    self.assertEqual(result["blocking_reasons"], [expected_reason])

    def test_original_relative_json_spec_executes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", "print('from-json')\n")
            self._write(reconstructed / "program.py", "print('from-json')\n")
            (original / "validation").mkdir()
            (original / "validation" / "behavior.json").write_text(
                json.dumps(self._python_spec()),
                encoding="utf-8",
            )

            result = validate_archive_behavior(
                original,
                reconstructed,
                "validation/behavior.json",
                isolated=True,
            )

            self.assertEqual(result["status"], "passed", result.get("diagnostics"))
            self.assertEqual(
                result["archive_validation"]["spec_source"],
                {"kind": "original_relative_json", "path": "validation/behavior.json"},
            )

    def test_missing_spec_and_non_isolated_host_are_dependency_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, reconstructed = self._roots(Path(temporary))
            self._write(original / "program.py", "print('same')\n")
            self._write(reconstructed / "program.py", "print('same')\n")

            missing = validate_archive_behavior(original, reconstructed, isolated=True)
            host = validate_archive_behavior(
                original,
                reconstructed,
                self._python_spec(),
                isolated=False,
            )

            self.assertEqual(missing["status"], "dependency-gated")
            self.assertIn("behavior_validation_spec_required", missing["blocking_reasons"])
            self.assertEqual(host["status"], "dependency-gated")
            self.assertIn("isolated_behavior_environment_required", host["blocking_reasons"])
            self.assertIs(host["behavior_equivalent"], False)
            self.assertEqual(host["summary"]["executed_command_count"], 0)

    def test_spec_path_must_stay_inside_original_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            original, reconstructed = self._roots(base)
            outside = base / "outside.json"
            outside.write_text(json.dumps(self._python_spec()), encoding="utf-8")

            result = validate_archive_behavior(
                original,
                reconstructed,
                "../outside.json",
                isolated=True,
            )

            self.assertEqual(result["status"], "failed")
            self.assertIs(result["behavior_equivalent"], False)
            self.assertIn("behavior_validation_spec_path_escape", result["blocking_reasons"])
            self.assertEqual(result["summary"]["executed_command_count"], 0)

            missing_escape = validate_archive_behavior(
                original,
                reconstructed,
                "../missing.json",
                isolated=True,
            )
            self.assertIn(
                "behavior_validation_spec_path_escape",
                missing_escape["blocking_reasons"],
            )

    @staticmethod
    def _python_spec() -> dict[str, object]:
        return {
            "original": {"argv": [sys.executable, "program.py"]},
            "reconstructed": {"argv": [sys.executable, "program.py"]},
        }

    @staticmethod
    def _roots(base: Path) -> tuple[Path, Path]:
        original = base / "original"
        reconstructed = base / "reconstructed"
        original.mkdir()
        reconstructed.mkdir()
        return original, reconstructed

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
