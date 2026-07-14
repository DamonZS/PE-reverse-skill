from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from reverse_analyzer.dashboard import build_dashboard
from reverse_analyzer.source.validation import (
    validate_and_write_source_project,
    validate_source_project,
    write_source_validation,
)
from reverse_analyzer.source_reconstruction import (
    reconstruct_source_project,
    summarize_source_reconstruction,
)


class _FixtureRunner:
    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        timeout: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timeout = timeout
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    def __call__(self, command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        self.calls.append((list(command), dict(options)))
        if self.timeout:
            raise subprocess.TimeoutExpired(command, options.get("timeout"), output=self.stdout, stderr=self.stderr)
        return subprocess.CompletedProcess(command, self.returncode, self.stdout, self.stderr)


class SourceValidationTests(unittest.TestCase):
    def test_fixture_runner_receives_bounded_non_shell_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            source = project / "src" / "semi;colon.py"
            self._write_text(source, "# TODO: recovered behavior\nvalue = 1\n")
            runner = _FixtureRunner()

            result = validate_source_project(
                project,
                project_metadata={"stack": "pyinstaller-python"},
                timeout=3,
                runner=runner,
                tool_resolver=lambda name: f"C:/fixture/{name}.exe" if name == "python" else None,
            )

            self.assertEqual(
                set(result),
                {
                    "schema_version",
                    "status",
                    "level",
                    "toolchain",
                    "command",
                    "exit_code",
                    "diagnostics",
                    "validated_files",
                    "placeholder_count",
                    "behavior_equivalent",
                    "provenance",
                },
            )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["level"], "syntax")
            self.assertEqual(result["toolchain"], "python")
            self.assertEqual(result["validated_files"], ["src/semi;colon.py"])
            self.assertEqual(result["placeholder_count"], 1)
            self.assertFalse(result["behavior_equivalent"])
            self.assertEqual(len(runner.calls), 1)
            argv, options = runner.calls[0]
            self.assertIn("./src/semi;colon.py", argv)
            self.assertEqual(argv.count("./src/semi;colon.py"), 1)
            self.assertIs(options["shell"], False)
            self.assertEqual(options["timeout"], 3.0)
            self.assertEqual(options["cwd"], str(project.resolve()))
            self.assertEqual(options["env"]["CI"], "1")

    def test_missing_toolchain_is_unavailable_and_does_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write_text(project / "main.js", "const value = 1;\n")
            runner = _FixtureRunner()

            result = validate_source_project(
                project,
                project_metadata={"stack": "electron"},
                runner=runner,
                tool_resolver=lambda _name: None,
            )

            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["level"], "syntax")
            self.assertIsNone(result["toolchain"])
            self.assertIsNone(result["exit_code"])
            self.assertEqual(result["validated_files"], [])
            self.assertEqual(runner.calls, [])
            self.assertTrue(any("Node.js" in item for item in result["diagnostics"]))

    def test_failed_timeout_and_output_truncation_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write_text(project / "app.py", "value = 1\n")
            resolver = lambda name: "fixture-python" if name == "python" else None

            failed = validate_source_project(
                project,
                project_metadata={"stack": "pyinstaller-python"},
                output_limit=80,
                runner=_FixtureRunner(returncode=7, stderr=f"{project.resolve()} " + "x" * 300),
                tool_resolver=resolver,
            )
            timed_out = validate_source_project(
                project,
                project_metadata={"stack": "pyinstaller-python"},
                timeout=0.25,
                output_limit=80,
                runner=_FixtureRunner(timeout=True, stdout="partial output"),
                tool_resolver=resolver,
            )

            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["exit_code"], 7)
            self.assertTrue(any("[truncated]" in item for item in failed["diagnostics"]))
            self.assertNotIn(str(project.resolve()), "\n".join(failed["diagnostics"]))
            self.assertEqual(timed_out["status"], "failed")
            self.assertIsNone(timed_out["exit_code"])
            self.assertTrue(any("timed out after 0.25 seconds" in item for item in timed_out["diagnostics"]))

    def test_diagnostics_redact_random_validation_temporary_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write_text(project / "app.py", "value = 1\n")

            def runner(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
                environment = options["env"]
                self.assertIsInstance(environment, dict)
                temporary_path = Path(str(environment["GRADLE_USER_HOME"])).parent
                return subprocess.CompletedProcess(
                    command,
                    1,
                    "",
                    f"compiler output: {temporary_path / 'generated-output'}",
                )

            result = validate_source_project(
                project,
                project_metadata={"stack": "pyinstaller-python"},
                runner=runner,
                tool_resolver=lambda name: "fixture-python" if name == "python" else None,
            )

            diagnostics = "\n".join(result["diagnostics"])
            self.assertEqual(result["status"], "failed")
            self.assertIn("<validation-temp>", diagnostics)
            self.assertNotIn("reverse-analyzer-validation-", diagnostics)

    def test_python_compile_runs_real_interpreter_for_valid_and_invalid_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_project = root / "valid"
            invalid_project = root / "invalid"
            self._write_text(valid_project / "app.py", "def recovered():\n    return 1\n")
            self._write_text(invalid_project / "app.py", "def broken(:\n    pass\n")

            valid = validate_source_project(
                valid_project,
                project_metadata={"stack": "pyinstaller-python"},
                timeout=10,
            )
            invalid = validate_source_project(
                invalid_project,
                project_metadata={"stack": "pyinstaller-python"},
                timeout=10,
            )

            self.assertEqual(valid["status"], "passed")
            self.assertEqual(valid["exit_code"], 0)
            self.assertEqual(invalid["status"], "failed")
            self.assertNotEqual(invalid["exit_code"], 0)
            self.assertTrue(any("SyntaxError" in item for item in invalid["diagnostics"]))

    def test_toolchain_plans_use_offline_or_nonexecuting_validation_modes(self) -> None:
        cases = (
            (
                "electron",
                {"main.js": "const recovered = true;\n"},
                {"node"},
                "node",
                "syntax",
                "--no-warnings",
            ),
            (
                "c",
                {"src/main.c": "int main(void) { return 0; }\n"},
                {"cc"},
                "cc",
                "syntax",
                "-fsyntax-only",
            ),
            (
                "csharp",
                {
                    "Recovered.csproj": '<Project Sdk="Microsoft.NET.Sdk"></Project>\n',
                    "src/Program.cs": "internal static class Program { static void Main() {} }\n",
                },
                {"dotnet"},
                "dotnet",
                "build",
                "--no-restore",
            ),
            (
                "csharp",
                {"src/Recovered.cs": "public static class Recovered {}\n"},
                {"csc"},
                "csc",
                "build",
                "/target:library",
            ),
            (
                "android-java",
                {
                    "build.gradle": "plugins {}\n",
                    "app/src/main/java/example/Main.java": "package example; final class Main {}\n",
                },
                {"gradle"},
                "gradle",
                "build",
                "--offline",
            ),
            (
                "android-java",
                {"src/example/Main.java": "package example; final class Main {}\n"},
                {"javac"},
                "javac",
                "build",
                "-proc:none",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (stack, files, tools, expected_tool, level, required_argument) in enumerate(cases):
                with self.subTest(stack=stack, tool=expected_tool):
                    project = root / str(index)
                    for relative_path, content in files.items():
                        self._write_text(project / relative_path, content)
                    runner = _FixtureRunner()
                    result = validate_source_project(
                        project,
                        project_metadata={"stack": stack},
                        runner=runner,
                        tool_resolver=lambda name, available=tools: (
                            f"C:/fixture/{name}.exe" if name in available else None
                        ),
                    )

                    self.assertEqual(result["status"], "passed")
                    self.assertEqual(result["toolchain"], expected_tool)
                    self.assertEqual(result["level"], level)
                    self.assertIn(required_argument, result["command"])
                    self.assertIs(runner.calls[0][1]["shell"], False)

    def test_write_api_is_canonical_deterministic_and_path_constrained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._write_text(project / "app.py", "value = 1\n")
            runner = _FixtureRunner()
            options = {
                "project_metadata": {"stack": "pyinstaller-python", "placeholder_count": 2},
                "runner": runner,
                "tool_resolver": lambda name: "fixture-python" if name == "python" else None,
            }

            result = validate_and_write_source_project(project, **options)
            report_path = project / "source" / "validation.json"
            first_bytes = report_path.read_bytes()
            self.assertEqual(json.loads(first_bytes), result)
            self.assertFalse(result["behavior_equivalent"])

            write_source_validation(project, {**result, "behavior_equivalent": True})
            self.assertEqual(report_path.read_bytes(), first_bytes)
            self.assertFalse(json.loads(first_bytes)["behavior_equivalent"])
            with self.assertRaises(ValueError):
                write_source_validation(project, result, relative_path="../validation.json")
            with self.assertRaises(ValueError):
                write_source_validation(project, result, relative_path="C:/outside.json")

    def test_unsafe_metadata_and_symbolic_link_sources_cannot_pass_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            self._write_text(project / "app.py", "value = 1\n")
            runner = _FixtureRunner()
            result = validate_source_project(
                project,
                project_metadata={
                    "stack": "pyinstaller-python",
                    "entrypoints": ["../outside.py"],
                },
                runner=runner,
                tool_resolver=lambda name: "fixture-python" if name == "python" else None,
            )

            self.assertEqual(result["status"], "failed")
            self.assertTrue(any("unsafe metadata path" in item for item in result["diagnostics"]))
            self.assertNotIn("../outside.py", runner.calls[0][0])

            outside = root / "outside.py"
            outside.write_text("value = 2\n", encoding="utf-8")
            linked_project = root / "linked"
            linked_project.mkdir()
            link = linked_project / "linked.py"
            try:
                link.symlink_to(outside)
            except OSError:
                return
            linked = validate_source_project(
                linked_project,
                project_metadata={"stack": "pyinstaller-python"},
                runner=_FixtureRunner(),
                tool_resolver=lambda name: "fixture-python" if name == "python" else None,
            )
            self.assertEqual(linked["status"], "failed")
            self.assertTrue(any("symbolic-link source" in item for item in linked["diagnostics"]))

    def test_summary_aggregates_validation_reports_without_equivalence_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            passed_project = workspace / "reconstructed_passed"
            unavailable_project = workspace / "nested" / "reconstructed_unavailable"
            legacy_project = workspace / "reconstructed_legacy"
            self._write_text(passed_project / "src" / "main.c", "int main(void) { return 0; }\n")
            self._write_text(unavailable_project / "src" / "main.c", "int main(void) { return 0; }\n")
            self._write_text(legacy_project / "src" / "main.c", "int main(void) { return 0; }\n")
            self._write_json(
                passed_project / "source" / "validation.json",
                self._validation_report("passed", ["src/main.c"], placeholder_count=3),
            )
            self._write_json(
                unavailable_project / "source" / "validation.json",
                self._validation_report("unavailable", [], placeholder_count=2),
            )

            result = summarize_source_reconstruction(workspace)

            summary = result["summary"]
            self.assertEqual(summary["project_total"], 3)
            self.assertEqual(summary["validation_project_total"], 2)
            self.assertEqual(summary["validation_passed_total"], 1)
            self.assertEqual(summary["validation_failed_total"], 0)
            self.assertEqual(summary["validation_unavailable_total"], 1)
            self.assertEqual(summary["validated_file_total"], 1)
            self.assertEqual(summary["placeholder_total"], 5)
            self.assertEqual(
                summary["validation_status_counts"],
                {"failed": 0, "passed": 1, "unavailable": 1},
            )
            projects = {item["name"]: item for item in result["projects"]}
            passed = projects["reconstructed_passed"]
            self.assertEqual(passed["validation_status"], "passed")
            self.assertEqual(passed["validation_level"], "syntax")
            self.assertEqual(passed["validated_file_count"], 1)
            self.assertFalse(passed["behavior_equivalent"])
            self.assertFalse(passed["validation"]["behavior_equivalent"])
            self.assertIsNone(projects["reconstructed_legacy"]["validation"])

    def test_opt_in_reconstruction_validation_attaches_failed_fixture_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "fixture.bin"
            sample.write_bytes(b"MZ fixture")
            runner = _FixtureRunner(returncode=9, stderr="fixture compiler failure")

            result = reconstruct_source_project(
                sample,
                root / "analysis",
                strategy="c",
                validate=True,
                validation_options={
                    "runner": runner,
                    "tool_resolver": lambda name: "fixture-cc" if name == "cc" else None,
                },
            )

            project_dir = Path(result["project_dir"])
            validation_path = project_dir / "source" / "validation.json"
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["validation_status"], "failed")
            self.assertEqual(result["validation"]["exit_code"], 9)
            self.assertFalse(result["behavior_equivalent"])
            self.assertEqual(json.loads(validation_path.read_text(encoding="utf-8")), result["validation"])
            self.assertIn(str(validation_path), result["generated_files"])

            validation_artifact = next(
                item for item in result["artifacts"] if item.get("name") == "source/validation.json"
            )
            self.assertEqual(validation_artifact["status"], "failed")
            self.assertFalse(validation_artifact["behavior_equivalent"])
            self.assertTrue(
                any(
                    item.get("path") == str(validation_path)
                    and item.get("role") == "validation_evidence"
                    for item in result["evidence_manifest_entries"]
                )
            )

            summary = summarize_source_reconstruction(root)
            self.assertEqual(summary["summary"]["validation_failed_total"], 1)
            self.assertEqual(summary["projects"][0]["validation_status"], "failed")

    def test_cli_reconstruction_writes_unavailable_validation_into_all_production_views(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_bytes(b"MZ production validation")
            environment = os.environ.copy()
            environment["PATH"] = ""

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "reverse_analyzer",
                    "analyze",
                    str(sample),
                    "--out",
                    str(out_dir),
                    "--max-iterations",
                    "1",
                    "--reconstruct",
                ],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=120,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            reconstruction = report["reconstruction"]
            project_dir = Path(reconstruction["project_dir"])
            validation_path = project_dir / "source" / "validation.json"
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
            self.assertEqual(validation["status"], "unavailable")
            self.assertFalse(validation["behavior_equivalent"])

            reconstruction_artifact = next(
                item
                for item in reconstruction["artifacts"]
                if item.get("name") == "source/validation.json"
            )
            self.assertEqual(reconstruction_artifact["status"], "unavailable")
            self.assertFalse(reconstruction_artifact["behavior_equivalent"])
            report_artifact = next(
                item
                for item in report["artifacts"]
                if item.get("name") == "source/validation.json"
            )
            self.assertEqual(report_artifact["data"]["status"], "unavailable")

            manifest = json.loads(
                (out_dir / "evidence-manifest.json").read_text(encoding="utf-8")
            )
            manifest_entry = next(
                item
                for item in manifest["artifacts"]
                if str(item.get("path") or "").replace("\\", "/").endswith(
                    "/source/validation.json"
                )
            )
            self.assertEqual(manifest_entry["role"], "validation_evidence")
            self.assertEqual(manifest_entry["status"], "unavailable")

            source_summary = summarize_source_reconstruction(out_dir)
            self.assertEqual(source_summary["summary"]["validation_unavailable_total"], 1)
            project_summary = next(
                item for item in source_summary["projects"] if item["name"] == project_dir.name
            )
            self.assertEqual(project_summary["validation_status"], "unavailable")
            self.assertFalse(project_summary["behavior_equivalent"])

            dashboard = build_dashboard(out_dir, out_dir=root / "dashboard")
            dashboard_source = dashboard["source_reconstruction"]
            self.assertEqual(
                dashboard_source["summary"]["validation_unavailable_total"],
                1,
            )
            self.assertEqual(dashboard_source["projects"][0]["validation_status"], "unavailable")
            self.assertTrue(
                any(
                    str(item.get("path") or "").replace("\\", "/").endswith(
                        "/source/validation.json"
                    )
                    for item in dashboard["artifact_navigation"]["items"]
                )
            )

    @staticmethod
    def _validation_report(
        status: str,
        validated_files: list[str],
        *,
        placeholder_count: int,
    ) -> dict[str, object]:
        return {
            "schema_version": 1,
            "status": status,
            "level": "syntax",
            "toolchain": "fixture" if status != "unavailable" else None,
            "command": ["fixture", "--check"] if status != "unavailable" else [],
            "exit_code": 0 if status == "passed" else None,
            "diagnostics": [],
            "validated_files": validated_files,
            "placeholder_count": placeholder_count,
            "behavior_equivalent": True,
            "provenance": {"validator": {"name": "fixture"}},
        }

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
