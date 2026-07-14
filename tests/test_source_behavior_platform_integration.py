from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from typing import Any

from reverse_analyzer.dashboard import build_dashboard
from reverse_analyzer.report.builder import ReportBuilder
from reverse_analyzer.source.behavior_validation import DEFAULT_BEHAVIOR_VALIDATION_PATH
from reverse_analyzer.source_reconstruction import reconstruct_source_project
from reverse_analyzer.tools.executor import ToolResult


_EXPECTED_STDOUT = "Reconstructed PyInstaller/Python placeholder; see analysis metadata.\n"


class SourceBehaviorPlatformIntegrationTests(unittest.TestCase):
    def test_real_generated_project_flows_through_artifacts_report_and_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            original_dir = workspace / "original"
            original_dir.mkdir()
            sample = original_dir / "sample.exe"
            sample.write_bytes(b"source behavior platform integration sample")
            (original_dir / "program.py").write_text(
                f"print({_EXPECTED_STDOUT.rstrip()!r})\n",
                encoding="utf-8",
            )
            spec_path = workspace / "behavior-validation.json"
            spec_path.write_text(
                json.dumps(
                    {
                        "target_identity": {
                            "id": "source-behavior-platform-fixture",
                            "kind": "local-process",
                        },
                        "original": {"argv": [sys.executable, "program.py"]},
                        "reconstructed": {"argv": [sys.executable, "app.py"]},
                    }
                ),
                encoding="utf-8",
            )

            result = reconstruct_source_project(
                sample,
                workspace / "output",
                strategy="pyinstaller-python",
                behavior_validation_spec=spec_path,
                behavior_original_dir=original_dir,
            )

            behavior = result["behavior_validation"]
            self.assertEqual(behavior["status"], "passed", behavior["diagnostics"])
            self.assertIs(result["behavior_equivalent"], True)
            self.assertEqual(behavior["summary"]["comparison_count"], 3)
            self.assertEqual(behavior["summary"]["matched_comparison_count"], 3)
            self.assertEqual(behavior["summary"]["mismatched_comparison_count"], 0)

            project_dir = Path(result["project_dir"])
            artifact_path = project_dir / Path(DEFAULT_BEHAVIOR_VALIDATION_PATH)
            artifact_bytes = artifact_path.read_bytes()
            artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
            self.assertEqual(json.loads(artifact_bytes), behavior)
            self._assert_evidence_declarations(result, artifact_path, artifact_sha256)

            builder = _report_builder(result)
            report = builder.build()
            source = report["source_reconstruction"]
            self.assertEqual(source["behavior_validation_status"], "passed")
            self.assertEqual(source["behavior_validation_summary"]["comparison_count"], 3)
            self.assertEqual(source["behavior_validation_artifact"], str(artifact_path))
            self.assertIs(source["behavior_equivalent"], True)

            markdown = builder.to_markdown()
            self.assertIn("- **Behavior Validation Status:** passed", markdown)
            self.assertIn("- **Behavior Comparisons:** 3", markdown)
            self.assertIn("- **Behavior Matches:** 3", markdown)
            self.assertIn("- **Behavior Mismatches:** 0", markdown)
            self.assertIn("- **Behavior Equivalent:** yes", markdown)

            report_path = workspace / "output" / "report.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            dashboard = build_dashboard(workspace, out_dir=workspace / "dashboard")
            metrics = {
                item["label"]: item["value"]
                for item in dashboard["analysis_views"]["source"]["metrics"]
            }
            self.assertEqual(metrics["Behavior validation"], "passed")
            self.assertEqual(metrics["Behavior comparisons"], 3)
            self.assertEqual(metrics["Behavior matches"], 3)
            self.assertEqual(metrics["Behavior mismatches"], 0)
            self.assertEqual(metrics["Behavior artifact"], str(artifact_path))
            self.assertIs(metrics["Behavior equivalent"], True)

    def test_spoofed_behavior_equivalent_is_rejected_by_report_and_dashboard(self) -> None:
        spoofed = {
            "status": "ok",
            "project_dir": "reconstructed-spoof",
            "behavior_validation": {
                "status": "passed",
                "behavior_equivalent": True,
                "summary": {
                    "comparison_count": 1,
                    "matched_comparison_count": 1,
                    "mismatched_comparison_count": 0,
                },
                "provenance": {"validator": {"name": "fake-runner"}},
            },
            "behavior_validation_status": "passed",
            "behavior_validation_provenance": {"validator": {"name": "fake-runner"}},
            "behavior_equivalent": True,
            "artifacts": [],
        }
        source = _report_builder(spoofed).build()["source_reconstruction"]
        self.assertIs(source["behavior_equivalent"], False)

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            report_path = workspace / "output" / "report.json"
            report_path.parent.mkdir(parents=True)
            report_path.write_text(
                json.dumps({"source_reconstruction": spoofed}),
                encoding="utf-8",
            )
            dashboard = build_dashboard(workspace, out_dir=workspace / "dashboard")
            metrics = {
                item["label"]: item["value"]
                for item in dashboard["analysis_views"]["source"]["metrics"]
            }
            self.assertIs(metrics["Behavior equivalent"], False)

    def _assert_evidence_declarations(
        self,
        result: dict[str, Any],
        artifact_path: Path,
        artifact_sha256: str,
    ) -> None:
        for collection_name in ("artifacts", "evidence_manifest_entries"):
            declarations = [
                item
                for item in result[collection_name]
                if isinstance(item, dict)
                and item.get("name") == DEFAULT_BEHAVIOR_VALIDATION_PATH
            ]
            self.assertEqual(len(declarations), 1)
            declaration = declarations[0]
            self.assertEqual(declaration["path"], str(artifact_path))
            self.assertEqual(declaration["sha256"], artifact_sha256)
            self.assertEqual(declaration["kind"], "source_behavior_validation")
            self.assertEqual(declaration["status"], "passed")
            self.assertIs(declaration["behavior_equivalent"], True)
            self.assertIs(
                declaration["provenance"]["validator"]["real_subprocess"],
                True,
            )


def _report_builder(reconstruction_payload: dict[str, Any]) -> ReportBuilder:
    session = SimpleNamespace(
        session_id="source-behavior-platform-fixture",
        target="fixture.bin",
        status="succeeded",
        artifacts=[],
    )
    tool_results = [
        {
            "tool_name": "reconstruct_project",
            "status": "ok",
            "result": ToolResult(
                tool="reconstruct_project",
                status="ok",
                data=reconstruction_payload,
            ).to_dict(),
        }
    ]
    return ReportBuilder(session, tool_results)


if __name__ == "__main__":
    unittest.main()
