import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.gui import (
    gui_fingerprint,
    gui_resource_extract,
    gui_runtime_probe,
    gui_strategy_select,
    gui_visual_parse,
    gui_visual_regression,
    reconstruct_gui_project,
)


class GuiToolTests(unittest.TestCase):
    def test_desktop_framework_fingerprints_are_ranked(self) -> None:
        signals = {
            "wpf.exe": ("PresentationFramework.dll InitializeComponent .baml", "wpf"),
            "qt.exe": ("Qt6Widgets.dll QWidget QMainWindow", "qt"),
            "electron.exe": ("electron resources/app.asar", "electron"),
            "pyside.exe": ("PyInstaller _internal PySide6", "pyinstaller_pyside"),
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename, (content, expected) in signals.items():
                with self.subTest(filename=filename):
                    sample = root / filename
                    sample.write_text(content, encoding="utf-8")
                    result = gui_fingerprint(sample)
                    self.assertEqual(result["framework"], expected)
                    self.assertGreater(result["confidence"], 0)
                    self.assertTrue(result["evidence"])

    def test_apk_resources_are_fingerprinted_and_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", "<manifest/>")
                archive.writestr("res/layout/activity_main.xml", "<LinearLayout/>")
                archive.writestr("res/drawable/logo.png", b"not-a-real-png")
                archive.writestr("assets/flutter_assets/AssetManifest.json", "{}")
                archive.writestr("lib/arm64-v8a/libflutter.so", b"flutter")

            fingerprint = gui_fingerprint(apk, root / "out")
            resources = gui_resource_extract(apk, root / "out")

            self.assertEqual(fingerprint["platform"], "android-apk")
            self.assertEqual(fingerprint["framework"], "flutter")
            self.assertEqual(resources["counts"]["layouts"], 1)
            self.assertEqual(resources["counts"]["images"], 1)
            self.assertTrue((root / "out" / "gui" / "resources" / "manifest.json").is_file())
            self.assertTrue((root / "out" / "gui" / "resources" / "extracted" / "res" / "layout" / "activity_main.xml").is_file())

    def test_strategy_selection_honors_target_override(self) -> None:
        fingerprint = {"platform": "windows-pe", "framework": "wpf", "confidence": 0.9}
        resources = {"counts": {"layouts": 8, "images": 2}}
        history = {"framework": "wpf", "strategy": "extract_baml_generate_wpf", "success_rate": 1.0}

        auto = gui_strategy_select(fingerprint, resources, historical_strategy=history)
        overridden = gui_strategy_select(fingerprint, resources, historical_strategy=history, target="pyside6")

        self.assertEqual(auto["name"], "extract_baml_generate_wpf")
        self.assertEqual(auto["output_stack"], "wpf")
        self.assertTrue(auto["historical_recommendation_applied"])
        self.assertEqual(overridden["output_stack"], "pyside6")
        self.assertEqual(overridden["requested_target"], "pyside6")

    def test_strategy_selection_reports_evidence_graph_context_without_changing_score_model(self) -> None:
        fingerprint = {"platform": "windows-pe", "framework": "wpf", "confidence": 0.9}
        resources = {"counts": {"layouts": 8, "images": 2}}
        evidence_graph = {
            "confidence": 0.93,
            "nodes": [{"id": "save", "type": "Button"}, {"id": "name", "type": "TextBox"}],
        }

        baseline = gui_strategy_select(fingerprint, resources)
        result = gui_strategy_select(fingerprint, resources, evidence_graph=evidence_graph)

        self.assertEqual(result["evidence_graph_node_count"], 2)
        self.assertEqual(result["evidence_graph_confidence"], 0.93)
        self.assertEqual(result["score"], baseline["score"])

    def test_reconstruction_copies_extracted_assets_and_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_text("electron app.asar", encoding="utf-8")
            extracted = root / "gui" / "resources" / "extracted" / "assets"
            extracted.mkdir(parents=True)
            (extracted / "logo.png").write_bytes(b"asset")
            analysis = {
                "framework": "electron",
                "confidence": 0.9,
                "evidence": ["app.asar"],
                "resources": {"extracted_dir": str(extracted.parents[1])},
                "strategy": {"name": "extract_asar_rebuild_electron", "output_stack": "electron"},
                "runtime_tree": {"window_count": 1, "control_count": 2},
                "visual": {"screenshot_count": 1},
            }

            semantic_ir = {
                "status": "ok",
                "schema_version": 1,
                "entities": [{"id": "ui:electron", "kind": "ui_control", "name": "ElectronShell"}],
                "relations": [],
                "capabilities": [],
            }
            result = reconstruct_gui_project(sample, root / "out", analysis, semantic_ir=semantic_ir)
            project = Path(result["project_dir"])

            self.assertEqual(result["output_stack"], "electron")
            self.assertEqual(result["asset_count"], 1)
            self.assertTrue((project / "package.json").is_file())
            self.assertTrue((project / "assets" / "assets" / "logo.png").is_file())
            self.assertTrue((project / "analysis" / "gui_fingerprint.json").is_file())
            self.assertTrue((project / "analysis" / "ui_tree.json").is_file())
            self.assertTrue((project / "analysis" / "visual_parse.json").is_file())
            self.assertEqual(
                json.loads((project / "analysis" / "semantic_ir.json").read_text(encoding="utf-8")),
                semantic_ir,
            )
            plan = json.loads((project / "analysis" / "reconstruction_plan.json").read_text(encoding="utf-8"))
            self.assertEqual(plan["framework"], "electron")
            self.assertTrue(plan["tasks"])

    def test_wpf_reconstruction_renders_evidence_graph_controls_and_handlers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            analysis = {
                "framework": "wpf",
                "strategy": {"name": "extract_baml_generate_wpf", "output_stack": "wpf"},
                "evidence_graph": {
                    "title": "Evidence UI",
                    "nodes": [
                        {
                            "id": "saveButton",
                            "type": "Button",
                            "text": "Save",
                            "bbox": {"x": 10, "y": 20, "width": 90, "height": 28},
                            "event_handlers": {"Click": "SaveButton_Click"},
                        }
                    ],
                },
            }

            result = reconstruct_gui_project(sample, root / "out", analysis)
            project = Path(result["project_dir"])
            xaml = (project / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
            code_behind = (project / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")

            self.assertFalse(result["stub_only"])
            self.assertEqual(result["renderer"]["control_count"], 1)
            self.assertIn('Content="Save"', xaml)
            self.assertIn('Click="SaveButton_Click"', xaml)
            self.assertIn("void SaveButton_Click(", code_behind)

    def test_runtime_and_visual_tools_degrade_or_compare_safely(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            runtime = gui_runtime_probe(sample, root / "out")
            self.assertIsInstance(runtime, ToolResult)
            self.assertEqual(runtime.status, "unavailable")
            self.assertTrue((root / "out" / "gui" / "runtime_tree.json").is_file())

            screenshots = root / "shots"
            screenshots.mkdir()
            try:
                from PIL import Image
            except ImportError:
                self.skipTest("Pillow is required for successful visual comparison")
            Image.new("RGB", (16, 16), (24, 96, 160)).save(screenshots / "one.png")
            visual = gui_visual_parse(screenshots, root / "out")
            self.assertEqual(visual["status"], "ok")
            self.assertEqual(visual["components"]["image_decode"]["status"], "ok")
            regression = gui_visual_regression(screenshots, screenshots, root / "out")
            self.assertEqual(regression["status"], "ok")
            self.assertEqual(regression["visual_similarity"], 1.0)
            self.assertTrue((root / "out" / "gui" / "regression.json").is_file())


if __name__ == "__main__":
    unittest.main()
