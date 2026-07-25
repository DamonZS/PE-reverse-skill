from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from reverse_analyzer.source.build_repair import run_build_repair_loop


def _failed(log: str = "docs/build-logs/build.log") -> dict[str, object]:
    return {
        "status": "failed",
        "build_passed": False,
        "failed_stage": "build",
        "stages": [{"name": "build", "status": "failed", "log": log, "error": None}],
    }


def _passed() -> dict[str, object]:
    return {"status": "passed", "build_passed": True, "stages": []}


class BuildRepairLoopTests(unittest.TestCase):
    def _project(self, temporary: str, diagnostic: str = "main.cpp:9: error: missing symbol") -> Path:
        project = Path(temporary)
        log = project / "docs" / "build-logs" / "build.log"
        log.parent.mkdir(parents=True)
        log.write_text(diagnostic, encoding="utf-8")
        return project

    def test_failed_build_is_repaired_and_rebuilt_to_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(temporary)
            repairs: list[dict[str, object]] = []

            def repair(**context: object) -> dict[str, object]:
                repairs.append(context)
                return {
                    "applied_changes": [{"path": "src/main.cpp", "summary": "declare symbol"}],
                    "provider": "fixture",
                    "model": "fixture-model",
                    "usage": {"input_tokens": 12, "output_tokens": 5, "total_tokens": 17},
                }

            result = run_build_repair_loop(project, _failed(), lambda root: _passed(), repair)

            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["passed"])
            self.assertEqual(result["iterations_completed"], 1)
            self.assertEqual(result["usage"]["total_tokens"], 17)
            self.assertIn("missing symbol", repairs[0]["diagnostics"])
            iteration = project / "docs" / "build-repair" / "iteration-01"
            self.assertTrue((iteration / "build-before.json").is_file())
            self.assertTrue((iteration / "build-after.json").is_file())
            self.assertTrue((iteration / "repair.json").is_file())
            self.assertTrue((iteration / "logs-before" / "01-build.log").is_file())
            self.assertEqual(result["iterations"][0]["logs_before"], ["docs/build-repair/iteration-01/logs-before/01-build.log"])
            persisted = json.loads((project / "docs" / "build-repair-loop.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted, result)

    def test_repeated_failure_exhausts_iteration_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(temporary)
            builds: list[Path] = []

            def build(root: Path) -> dict[str, object]:
                builds.append(root)
                return _failed()

            result = run_build_repair_loop(
                project,
                _failed(),
                build,
                lambda **_: {"changes": [{"path": "src/main.cpp"}]},
                max_iterations=2,
            )

            self.assertEqual(result["status"], "exhausted")
            self.assertFalse(result["passed"])
            self.assertEqual(result["iterations_completed"], 2)
            self.assertEqual(len(builds), 2)
            self.assertIn("repair_iteration_budget_exhausted", result["blocking_reasons"])

    def test_missing_diagnostics_is_dependency_gated_without_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            called: list[str] = []
            result = run_build_repair_loop(
                temporary,
                {"status": "failed", "build_passed": False, "stages": []},
                lambda _: called.append("build") or _passed(),
                lambda **_: called.append("repair") or {"changes": [{}]},
            )

            self.assertEqual(result["status"], "dependency-gated")
            self.assertEqual(called, [])
            self.assertIn("usable_build_diagnostics_required", result["blocking_reasons"])

    def test_repair_exception_is_archived_and_never_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(temporary)

            def fail_repair(**_: object) -> dict[str, object]:
                raise RuntimeError("provider unavailable")

            result = run_build_repair_loop(project, _failed(), lambda _: _passed(), fail_repair)

            self.assertEqual(result["status"], "exhausted")
            self.assertFalse(result["passed"])
            self.assertIn("repair_callback_failed", result["blocking_reasons"])
            self.assertIn("provider unavailable", result["iterations"][0]["error"])
            self.assertIsNone(result["iterations"][0]["build_after"])

    def test_diagnostics_are_bounded_and_path_traversal_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = self._project(temporary, "x" * 1000)
            observed: list[str] = []
            initial = _failed("../../outside.log")
            initial["stderr"] = "compiler diagnostic " + ("y" * 1000)
            result = run_build_repair_loop(
                project,
                initial,
                lambda _: _passed(),
                lambda **context: observed.append(str(context["diagnostics"])) or {"changes": [{"path": "x"}]},
                max_diagnostic_bytes=80,
            )

            self.assertEqual(result["status"], "passed")
            self.assertLessEqual(result["diagnostic_bytes_consumed"], 80)
            self.assertIn("diagnostics truncated", observed[0])


if __name__ == "__main__":
    unittest.main()
