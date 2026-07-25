from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from reverse_analyzer.source.project_builder import build_project


class _Runner:
    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(command), dict(options)))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[return-value]


class ProjectBuilderTests(unittest.TestCase):
    def test_success_runs_configure_and_build_and_hashes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\nproject(fixture)\n",
                encoding="utf-8",
            )

            class SuccessRunner(_Runner):
                def __call__(self, command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
                    completed = super().__call__(command, **options)
                    if "--build" in command:
                        output = project / ".reconstruction-build" / "fixture.exe"
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_bytes(b"fixture-binary")
                    return completed

            runner = SuccessRunner(
                [
                    subprocess.CompletedProcess([], 0, "configure output\n", "configure warning\n"),
                    subprocess.CompletedProcess([], 0, "build output\n", ""),
                ]
            )
            result = build_project(
                project,
                {"build_ready": True},
                {"status": "executed", "call_count": 1},
                runner=runner,
            )

            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["build_passed"])
            self.assertTrue(result["isolated"])
            self.assertEqual([stage["name"] for stage in result["stages"]], ["configure", "build"])
            self.assertEqual([stage["return_code"] for stage in result["stages"]], [0, 0])
            self.assertEqual(len(runner.calls), 2)
            self.assertEqual(runner.calls[0][0][0:2], ["cmake", "-S"])
            self.assertEqual(runner.calls[1][0][0:2], ["cmake", "--build"])
            self.assertFalse(runner.calls[0][1]["shell"])
            self.assertTrue(result["artifacts"])
            self.assertEqual(result["artifact_count"], 1)
            self.assertEqual(result["artifacts"][0]["path"], ".reconstruction-build/fixture.exe")
            self.assertEqual(len(result["artifacts"][0]["sha256"]), 64)
            self.assertIn("configure output", (project / "docs" / "build-logs" / "configure.log").read_text())
            self.assertIn("configure warning", (project / "docs" / "build-logs" / "configure.log").read_text())
            self.assertIn("build output", (project / "docs" / "build-logs" / "build.log").read_text())
            persisted = json.loads((project / "docs" / "build-result.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted, result)

    def test_compile_failure_is_archived_and_does_not_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            runner = _Runner(
                [
                    subprocess.CompletedProcess([], 0, "configured", ""),
                    subprocess.CompletedProcess([], 2, "", "compiler error"),
                ]
            )
            result = build_project(
                project,
                {"build_ready": True},
                {"status": "executed", "call_count": 1},
                runner=runner,
            )

            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["build_passed"])
            self.assertEqual(result["failed_stage"], "build")
            self.assertIn("build exited with code 2", result["error"])
            self.assertEqual(result["stages"][1]["return_code"], 2)
            self.assertIn("compiler error", (project / "docs" / "build-logs" / "build.log").read_text())
            self.assertTrue((project / "docs" / "build-result.json").is_file())

    def test_mixed_project_builds_cmake_and_apktool_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            decoded = project / "targets" / "mobile" / "source" / "apktool"
            decoded.mkdir(parents=True)
            (decoded / "apktool.yml").write_text("version: 2.9.3\n", encoding="utf-8")
            (project / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\nproject(mixed)\n", encoding="utf-8")
            runner = _Runner([
                subprocess.CompletedProcess([], 0, "configured", ""),
                subprocess.CompletedProcess([], 0, "native built", ""),
                subprocess.CompletedProcess([], 0, "apk built", ""),
            ])

            result = build_project(project, {"build_ready": True}, {"status": "failed", "call_count": 3}, runner=runner)

            self.assertEqual(result["status"], "passed")
            self.assertEqual([stage["name"] for stage in result["stages"]], ["configure", "build", "apktool-mobile"])
            build_environment = runner.calls[2][1]["env"]
            self.assertEqual(build_environment["HOME"], str(project / ".reconstruction-build" / ".runtime-home"))
            self.assertEqual(build_environment["XDG_DATA_HOME"], str(project / ".reconstruction-build" / ".runtime-home" / ".local" / "share"))
            self.assertEqual(runner.calls[2][0][:2], ["apktool", "build"])
            self.assertIn("--frame-path", runner.calls[2][0])
            self.assertEqual(Path(runner.calls[2][0][runner.calls[2][0].index("--frame-path") + 1]), project / ".reconstruction-build" / "android" / "framework")
            self.assertIn(str(decoded), runner.calls[2][0])

    def test_readiness_and_model_gates_prevent_execution(self) -> None:
        for readiness, model_state, reason in (
            ({"build_ready": False}, {"status": "executed", "call_count": 1}, "readiness_not_build_ready"),
            ({"build_ready": True}, {"status": "failed"}, "model_reconstruction_not_executed"),
        ):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as temporary:
                runner = _Runner([])
                project = Path(temporary)
                result = build_project(project, readiness, model_state, runner=runner)

                self.assertEqual(result["status"], "dependency-gated")
                self.assertIn(reason, result["blocking_reasons"])
                self.assertIn(reason, result["error"])
                self.assertEqual(runner.calls, [])
                self.assertEqual(result["stages"], [])
                self.assertTrue((project / "docs" / "build-result.json").is_file())

    def test_host_execution_without_injected_runner_is_dependency_gated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = build_project(
                temporary,
                {"build_ready": True},
                {"status": "executed", "call_count": 1},
                _environment={},
                _container_marker=Path(temporary) / "missing-dockerenv",
            )

            self.assertEqual(result["status"], "dependency-gated")
            self.assertIn("isolated_build_environment_required", result["blocking_reasons"])

    def test_timeout_and_runner_exception_are_archived(self) -> None:
        cases = (
            (
                subprocess.TimeoutExpired(["cmake"], 120, output="partial stdout", stderr="partial stderr"),
                "timed_out",
                "partial stderr",
            ),
            (OSError("cmake unavailable"), "error", "cmake unavailable"),
        )
        for outcome, expected_status, expected_log in cases:
            with self.subTest(status=expected_status), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary)
                result = build_project(
                    project,
                    {"build_ready": True},
                    {"status": "executed", "call_count": 1},
                    runner=_Runner([outcome]),
                )

                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["failed_stage"], "configure")
                self.assertFalse(result["build_passed"])
                self.assertIn(expected_log, (project / "docs" / "build-logs" / "configure.log").read_text())
                self.assertTrue((project / "docs" / "build-result.json").is_file())


if __name__ == "__main__":
    unittest.main()
