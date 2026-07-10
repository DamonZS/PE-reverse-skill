import json
import os
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.reconstruction_verify import verify_reconstruction


class ReconstructionVerifyTests(unittest.TestCase):
    def test_c_project_maps_supplied_semantic_entities_and_covers_modules(self):
        semantic_ir = {
            "status": "ok",
            "schema_version": 1,
            "entities": [
                {"id": "function:entry", "kind": "function", "name": "entry"},
                {"id": "api:winhttp", "kind": "api", "name": "WinHttpOpen"},
                {"id": "api:file", "kind": "api", "name": "CreateFileW"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "reconstruction"
            source_dir = project / "src"
            analysis_dir = project / "analysis"
            source_dir.mkdir(parents=True)
            analysis_dir.mkdir()
            (project / "README.md").write_text("# Reconstruction\n", encoding="utf-8")
            (project / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\nproject(reconstruction C)\n",
                encoding="utf-8",
            )
            (source_dir / "main.c").write_text("int entry(void) { return 0; }\n", encoding="utf-8")
            (source_dir / "network.c").write_text(
                "void network(void) { WinHttpOpen(0, 0, 0, 0, 0); CreateFileW(0, 0, 0, 0, 0, 0, 0); }\n",
                encoding="utf-8",
            )
            (analysis_dir / "semantic_ir.json").write_text(
                json.dumps({"entities": [{"id": "local", "kind": "api", "name": "NotPresent"}]}),
                encoding="utf-8",
            )
            (analysis_dir / "reconstruction_plan.json").write_text(
                json.dumps(
                    {
                        "tasks": [
                            {"name": "reconstruct_core", "metadata": {"module": "core", "module_file": "src/main.c"}},
                            {"name": "reconstruct_network", "metadata": {"module": "network", "module_file": "src/network.c"}},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = verify_reconstruction(project, semantic_ir=semantic_ir)

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["schema_version"], 1)
            self.assertGreaterEqual(result["score"], 0.9)
            self.assertEqual(result["coverage"]["source_file_count"], 2)
            self.assertEqual(result["coverage"]["build_manifest_count"], 1)
            self.assertEqual(result["coverage"]["semantic_entity_count"], 3)
            self.assertEqual(result["coverage"]["mapped_entity_count"], 3)
            self.assertEqual(result["coverage"]["semantic_coverage"], 1.0)
            self.assertEqual(result["coverage"]["planned_module_count"], 2)
            self.assertEqual(result["coverage"]["covered_module_count"], 2)
            self.assertEqual(result["coverage"]["module_coverage"], 1.0)
            self.assertTrue((analysis_dir / "reconstruction_verification.json").is_file())
            self.assertTrue(any(check["name"] == "build_entry" and check["status"] == "pass" for check in result["checks"]))

    def test_gui_project_uses_local_ir_and_static_xaml_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "gui-reconstruction"
            analysis_dir = project / "analysis"
            analysis_dir.mkdir(parents=True)
            (project / "README.md").write_text("# GUI reconstruction\n", encoding="utf-8")
            (project / "GuiReconstruction.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0-windows</TargetFramework></PropertyGroup></Project>',
                encoding="utf-8",
            )
            (project / "MainWindow.xaml").write_text(
                '<Window><Button x:Name="ConnectButton" Click="Connect_Click">Connect</Button></Window>',
                encoding="utf-8",
            )
            (project / "MainWindow.xaml.cs").write_text(
                "partial class MainWindow { void Connect_Click() {} }\n",
                encoding="utf-8",
            )
            (analysis_dir / "semantic_ir.json").write_text(
                json.dumps(
                    {
                        "entities": [
                            {"id": "ui:button", "kind": "ui_control", "name": "ConnectButton"},
                            {"id": "ui:handler", "kind": "ui_handler", "name": "Connect_Click"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (analysis_dir / "reconstruction_plan.json").write_text(
                json.dumps({"tasks": [{"name": "reconstruct_gui", "metadata": {"module": "gui", "module_file": "MainWindow.xaml"}}]}),
                encoding="utf-8",
            )

            result = verify_reconstruction(project)

            self.assertEqual(result["status"], "ok")
            self.assertGreaterEqual(result["coverage"]["source_file_count"], 2)
            self.assertEqual(result["coverage"]["build_manifest_count"], 1)
            self.assertEqual(result["coverage"]["semantic_entity_count"], 2)
            self.assertEqual(result["coverage"]["mapped_entity_count"], 2)
            self.assertEqual(result["coverage"]["module_coverage"], 1.0)

    def test_missing_project_is_unavailable_without_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            result = verify_reconstruction(missing)

            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["score"], 0.0)
            self.assertEqual(result["coverage"]["source_file_count"], 0)
            self.assertEqual(result["artifacts"], [])
            self.assertEqual(result["project_dir"], str(missing.resolve()))

    def test_missing_or_corrupt_metadata_is_graceful_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "partial"
            source_dir = project / "src"
            analysis_dir = project / "analysis"
            source_dir.mkdir(parents=True)
            analysis_dir.mkdir()
            (project / "README.md").write_text("# Partial reconstruction\n", encoding="utf-8")
            (project / "CMakeLists.txt").write_text("project(partial C)\n", encoding="utf-8")
            (source_dir / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (source_dir / "ignored.c").write_bytes(os.urandom(64))
            (analysis_dir / "semantic_ir.json").write_text("{not json", encoding="utf-8")
            (analysis_dir / "reconstruction_plan.json").write_text("[broken", encoding="utf-8")

            first = verify_reconstruction(project)
            second = verify_reconstruction(project)

            self.assertEqual(first, second)
            self.assertEqual(first["status"], "partial")
            self.assertEqual(first["coverage"]["semantic_entity_count"], 0)
            self.assertEqual(first["coverage"]["planned_module_count"], 0)
            self.assertTrue(any(check["name"] == "semantic_ir" and check["status"] == "unavailable" for check in first["checks"]))
            self.assertTrue(any(check["name"] == "reconstruction_plan" and check["status"] == "unavailable" for check in first["checks"]))
            self.assertEqual(first["recommendations"], sorted(first["recommendations"]))
            self.assertTrue((analysis_dir / "reconstruction_verification.json").is_file())


if __name__ == "__main__":
    unittest.main()
