from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Mapping
import unittest

from reverse_analyzer.source.runtime_validation import DEFAULT_RUNTIME_VALIDATION_PATH
from reverse_analyzer.source_reconstruction import (
    attach_source_runtime_validation,
    reconstruct_source_project,
)


_EXPECTED_APP_STDOUT = (
    "Reconstructed PyInstaller/Python placeholder; see analysis metadata.\n"
)


class SourceRuntimeIntegrationTests(unittest.TestCase):
    def test_real_local_build_and_behavior_validation_is_attached_from_json_spec(self) -> None:
        spec = {
            "steps": [
                {
                    "name": "compile-generated-python",
                    "kind": "build",
                    "argv": [
                        sys.executable,
                        "-m",
                        "py_compile",
                        "app.py",
                        "reconstructed.py",
                    ],
                    "expect": {"exit_code": 0, "stdout": "", "stderr": ""},
                },
                {
                    "name": "run-generated-entrypoint",
                    "kind": "behavior",
                    "argv": [sys.executable, "app.py"],
                    "expect": {
                        "exit_code": 0,
                        "stdout": _EXPECTED_APP_STDOUT,
                        "stderr": "",
                    },
                },
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = root / "runtime-validation-spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")

            result = self._reconstruct(root, runtime_validation_spec=spec_path)

            runtime = self._assert_runtime_attachment(result, "passed")
            self.assertEqual(runtime["summary"]["executed_step_count"], 2)
            self.assertEqual(
                [step["kind"] for step in runtime["steps"]],
                ["build", "behavior"],
            )
            self.assertTrue(all(step["status"] == "passed" for step in runtime["steps"]))

            # A repeated attachment replaces the prior declarations instead of
            # accumulating duplicate artifacts or generated-file paths.
            for collection_name in ("artifacts", "evidence_manifest_entries"):
                declaration = next(
                    item
                    for item in result[collection_name]
                    if isinstance(item, dict)
                    and item.get("name") == DEFAULT_RUNTIME_VALIDATION_PATH
                )
                declaration.pop("name")
                declaration["path"] = DEFAULT_RUNTIME_VALIDATION_PATH
            result["generated_files"].append(DEFAULT_RUNTIME_VALIDATION_PATH)
            attach_source_runtime_validation(result, spec)
            repeated = self._assert_runtime_attachment(result, "passed")
            self.assertEqual(repeated["summary"]["executed_step_count"], 2)

    def test_missing_local_tool_is_unavailable_without_changing_generation_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing_python = root / "missing-tool" / "python.exe"
            spec = {
                "behavior": {
                    "argv": [str(missing_python), "--version"],
                    "expected_exit_code": 0,
                }
            }

            result = self._reconstruct(root, runtime_validation_spec=spec)

            runtime = self._assert_runtime_attachment(result, "unavailable")
            self.assertEqual(runtime["summary"]["planned_step_count"], 1)
            self.assertEqual(runtime["summary"]["executed_step_count"], 0)
            self.assertEqual(runtime["steps"], [])
            self.assertFalse(runtime["provenance"]["tools"][0]["available"])
            self.assertTrue(any("was not found" in item for item in runtime["diagnostics"]))

    def test_real_local_process_with_wrong_stdout_expectation_is_failed(self) -> None:
        spec = {
            "behavior": {
                "argv": [sys.executable, "app.py"],
                "expect": {
                    "exit_code": 0,
                    "stdout": "unexpected reconstructed output\n",
                    "stderr": "",
                },
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            result = self._reconstruct(root, runtime_validation_spec=spec)

            runtime = self._assert_runtime_attachment(result, "failed")
            self.assertEqual(runtime["summary"]["executed_step_count"], 1)
            step = runtime["steps"][0]
            self.assertEqual(step["status"], "failed")
            self.assertEqual(step["exit_code"], 0)
            self.assertEqual(step["stdout_text"], _EXPECTED_APP_STDOUT)
            self.assertTrue(runtime["provenance"]["tools"][0]["available"])
            stdout_assertion = next(
                assertion
                for assertion in step["assertions"]
                if assertion["kind"] == "stdout"
            )
            self.assertFalse(stdout_assertion["passed"])

    def _reconstruct(
        self,
        root: Path,
        *,
        runtime_validation_spec: Mapping[str, Any] | str | Path,
    ) -> dict[str, Any]:
        sample = root / "sample.exe"
        sample.write_bytes(b"source runtime integration sample")
        return reconstruct_source_project(
            sample,
            root / "out",
            strategy="pyinstaller-python",
            runtime_validation_spec=runtime_validation_spec,
        )

    def _assert_runtime_attachment(
        self,
        result: dict[str, Any],
        expected_status: str,
    ) -> dict[str, Any]:
        self.assertEqual(result["status"], "ok")
        self.assertIs(result["behavior_equivalent"], False)

        runtime = result["runtime_validation"]
        self.assertIsInstance(runtime, dict)
        assert isinstance(runtime, dict)
        self.assertEqual(runtime["status"], expected_status)
        self.assertEqual(result["runtime_validation_status"], expected_status)
        self.assertIs(runtime["behavior_equivalent"], False)

        project_dir = Path(str(result["project_dir"])).resolve()
        expected_report = project_dir / Path(DEFAULT_RUNTIME_VALIDATION_PATH)
        report_path = Path(str(result["runtime_validation_artifact"]))
        self.assertTrue(report_path.is_absolute())
        self.assertEqual(report_path.resolve(), expected_report.resolve())
        report_content = report_path.read_bytes()
        self.assertEqual(json.loads(report_content), runtime)
        report_sha256 = hashlib.sha256(report_content).hexdigest()

        artifacts = [
            item
            for item in result["artifacts"]
            if isinstance(item, dict) and item.get("name") == DEFAULT_RUNTIME_VALIDATION_PATH
        ]
        manifest_entries = [
            item
            for item in result["evidence_manifest_entries"]
            if isinstance(item, dict) and item.get("name") == DEFAULT_RUNTIME_VALIDATION_PATH
        ]
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(len(manifest_entries), 1)
        artifact = artifacts[0]
        manifest = manifest_entries[0]
        runtime_artifact = runtime["artifact"]
        self.assertIsInstance(runtime_artifact, dict)
        assert isinstance(runtime_artifact, dict)

        expected_provenance = runtime["provenance"]
        self.assertEqual(result["runtime_validation_provenance"], expected_provenance)
        generated_provenance = json.loads(
            (project_dir / "analysis" / "provenance.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result["provenance"], generated_provenance)

        for declaration in (runtime_artifact, artifact, manifest):
            self.assertEqual(declaration["kind"], "source_runtime_validation")
            self.assertEqual(declaration["role"], "validation_evidence")
            self.assertEqual(declaration["media_type"], "application/json")
            self.assertEqual(declaration["status"], expected_status)
            self.assertEqual(declaration["confidence"], runtime["confidence"]["score"])
            self.assertEqual(declaration["provenance"], expected_provenance)
            self.assertIs(declaration["behavior_equivalent"], False)

        for declaration in (artifact, manifest):
            self.assertEqual(declaration["name"], DEFAULT_RUNTIME_VALIDATION_PATH)
            self.assertEqual(declaration["path"], str(report_path))
            self.assertEqual(declaration["sha256"], report_sha256)
            self.assertEqual(
                declaration["evidence_sha256"],
                runtime_artifact["evidence_sha256"],
            )

        generated_report_paths = [
            Path(item)
            for item in result["generated_files"]
            if isinstance(item, str)
            and (project_dir / item if not Path(item).is_absolute() else Path(item)).resolve()
            == report_path.resolve()
        ]
        self.assertEqual(len(generated_report_paths), 1)
        return runtime


if __name__ == "__main__":
    unittest.main()
