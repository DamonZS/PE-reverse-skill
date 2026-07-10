from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reverse_analyzer.source_reconstruction import summarize_source_reconstruction


class SourceReconstructionSummaryTests(unittest.TestCase):
    def test_discovers_c_project_and_reports_only_workspace_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "reports" / "sample" / "reconstructed_sample"
            self._write(project / "analysis" / "summary.json", {"function_count": 4, "dynamic_evidence_count": 2})
            self._write(project / "analysis" / "module_map.json", {"modules": {"network": [], "core": []}})
            self._write(project / "analysis" / "reconstruction_plan.json", {"tasks": [{"name": "dynamic_correlation"}]})
            self._write(project / "analysis" / "dynamic_evidence.json", [{"api": "connect"}])
            self._write(
                project / "analysis" / "semantic_ir.json",
                {"summary": {"entity_count": 4, "relation_count": 3, "capability_count": 2}},
            )
            self._write(
                project / "analysis" / "reconstruction_verification.json",
                {"status": "ok", "score": 0.91, "coverage": {"semantic_coverage": 1.0, "module_coverage": 1.0}},
            )
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (project / "src" / "network.c").write_text("void network(void) {}\n", encoding="utf-8")
            (project / "assets").mkdir(parents=True, exist_ok=True)
            (project / "assets" / "logo.png").write_bytes(b"PNG")
            (project / "CMakeLists.txt").write_text("project(sample)\n", encoding="utf-8")
            (project / "README.md").write_text("# Sample\n", encoding="utf-8")

            result = summarize_source_reconstruction(workspace)

            self.assertEqual(result["summary"]["project_total"], 1)
            self.assertEqual(result["summary"]["source_file_total"], 2)
            self.assertEqual(result["summary"]["resource_file_total"], 1)
            self.assertEqual(result["summary"]["function_total"], 4)
            self.assertEqual(result["summary"]["dynamic_evidence_total"], 1)
            project_data = result["projects"][0]
            self.assertEqual(project_data["relative_path"], "reports/sample/reconstructed_sample")
            self.assertEqual(project_data["language"], "c")
            self.assertEqual(project_data["module_count"], 2)
            self.assertEqual(project_data["next_task"], "dynamic_correlation")
            self.assertEqual(project_data["semantic_entity_count"], 4)
            self.assertEqual(project_data["semantic_capability_count"], 2)
            self.assertEqual(project_data["verification_score"], 0.91)
            self.assertEqual(result["summary"]["semantic_entity_total"], 4)
            self.assertEqual(result["summary"]["verified_project_total"], 1)
            self.assertEqual(project_data["entrypoints"], ["CMakeLists.txt", "src/main.c"])
            self.assertIn("int main", project_data["source_files"][0]["preview"])
            self.assertFalse(any(str(workspace) in item["path"] for item in project_data["source_files"]))

    def test_gui_project_and_malformed_optional_metadata_are_graceful(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "experiments" / "run-1" / "analysis" / "reconstructed_gui"
            self._write(project / "analysis" / "gui_strategy.json", {"output_stack": "wpf", "status": "ok", "stub_only": True})
            (project / "analysis" / "gui_analysis.json").parent.mkdir(parents=True, exist_ok=True)
            (project / "analysis" / "gui_analysis.json").write_text("{not-json", encoding="utf-8")
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "MainWindow.xaml").write_text("<Window />\n", encoding="utf-8")

            result = summarize_source_reconstruction(workspace)

            self.assertEqual(result["summary"]["project_total"], 1)
            project_data = result["projects"][0]
            self.assertEqual(project_data["output_stack"], "wpf")
            self.assertEqual(project_data["language"], "xaml")
            self.assertEqual(project_data["status"], "ok")
            self.assertTrue(project_data["stub_only"])
            self.assertEqual(result["diagnostics"]["malformed_metadata"], 1)

    def test_missing_workspace_returns_empty_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"

            result = summarize_source_reconstruction(missing)

            self.assertEqual(result["summary"]["project_total"], 0)
            self.assertEqual(result["projects"], [])
            self.assertEqual(result["diagnostics"]["workspace_unavailable"], str(missing))

    def test_source_directories_are_prioritized_before_large_resource_trees(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            project = workspace / "reports" / "sample" / "reconstructed_sample"
            (project / "assets").mkdir(parents=True, exist_ok=True)
            (project / "assets" / "one.bin").write_bytes(b"1")
            (project / "assets" / "two.bin").write_bytes(b"2")
            (project / "src").mkdir(parents=True, exist_ok=True)
            (project / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

            with patch("reverse_analyzer.source_reconstruction._MAX_FILES_PER_PROJECT", 2):
                result = summarize_source_reconstruction(workspace)

            project_data = result["projects"][0]
            self.assertEqual(project_data["source_file_count"], 1)
            self.assertEqual(project_data["source_files"][0]["path"], "src/main.c")
            self.assertTrue(project_data["source_files_truncated"])
            self.assertEqual(result["diagnostics"]["truncated_file_lists"], 1)

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
