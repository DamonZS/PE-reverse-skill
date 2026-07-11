import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.gui_evidence import build_gui_evidence_graph


class GuiEvidenceGraphTests(unittest.TestCase):
    def test_merges_static_runtime_visual_and_decompiler_evidence(self) -> None:
        fingerprint = {"status": "ok", "platform": "windows-pe", "framework": "wpf", "confidence": 0.94}
        xaml = {
            "status": "ok",
            "title": "Sample UI",
            "nodes": [
                {
                    "id": "save_button",
                    "type": "Button",
                    "text": "Save",
                    "properties": {"Width": "90", "Height": "28"},
                    "event_handlers": {"Click": "SaveButton_Click"},
                    "confidence": 0.95,
                    "source": "xaml",
                }
            ],
        }
        runtime = {
            "status": "ok",
            "windows": [
                {
                    "title": "Sample UI",
                    "controls": [
                        {
                            "class_name": "Button",
                            "title": "Save",
                            "bounds": {"left": 10, "top": 20, "width": 90, "height": 28},
                        }
                    ],
                }
            ],
        }
        visual = {
            "status": "ok",
            "widgets": [{"type": "button", "bbox": {"x": 10, "y": 20, "width": 90, "height": 28}}],
            "text_regions": [{"text": "Save", "bbox": {"x": 18, "y": 25, "width": 35, "height": 16}}],
        }
        decompiler = {"functions": [{"name": "SaveButton_Click"}, {"name": "other"}]}

        graph = build_gui_evidence_graph(
            fingerprint=fingerprint,
            xaml_evidence=xaml,
            runtime_tree=runtime,
            visual=visual,
            decompiler=decompiler,
        )

        self.assertEqual(graph["status"], "ok")
        self.assertEqual(graph["framework"], "wpf")
        self.assertEqual(graph["title"], "Sample UI")
        self.assertEqual(len(graph["nodes"]), 1)
        node = graph["nodes"][0]
        self.assertEqual(node["id"], "save_button")
        self.assertEqual(node["text"], "Save")
        self.assertEqual(node["bbox"]["width"], 90.0)
        self.assertEqual(node["event_handlers"]["Click"], "SaveButton_Click")
        self.assertIn("xaml", {item["source"] for item in node["evidence"]})
        self.assertIn("runtime", {item["source"] for item in node["evidence"]})
        self.assertIn("visual", {item["source"] for item in node["evidence"]})
        self.assertTrue(node["handler_evidence"])

    def test_writes_graph_artifact_and_handles_missing_optional_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            graph = build_gui_evidence_graph(
                fingerprint={"framework": "unknown", "platform": "unknown", "confidence": 0.1},
                resources={"counts": {"layouts": 0}},
                out_dir=tmp,
            )

            self.assertEqual(graph["status"], "ok")
            self.assertEqual(graph["nodes"], [])
            self.assertTrue((Path(tmp) / "gui" / "evidence_graph.json").is_file())
            self.assertEqual(graph["artifacts"][0]["name"], "gui/evidence_graph.json")

    def test_keeps_same_text_controls_from_distinct_xaml_documents_separate(self) -> None:
        xaml = {
            "status": "ok",
            "nodes": [
                {"id": "root", "type": "Grid", "source_path": "first/MainWindow.xaml"},
                {
                    "id": "saveButton",
                    "type": "Button",
                    "text": "Save",
                    "parent_id": "root",
                    "source_path": "first/MainWindow.xaml",
                },
                {"id": "root", "type": "Grid", "source_path": "second/MainWindow.xaml"},
                {
                    "id": "saveButton",
                    "type": "Button",
                    "text": "Save",
                    "parent_id": "root",
                    "source_path": "second/MainWindow.xaml",
                },
            ],
        }

        graph = build_gui_evidence_graph(xaml_evidence=xaml)

        self.assertEqual(len(graph["nodes"]), 4)
        self.assertEqual(len({node["id"] for node in graph["nodes"]}), 4)
        self.assertEqual(len(graph["edges"]), 2)
        self.assertEqual({edge["source"] for edge in graph["edges"]}, {node["id"] for node in graph["nodes"] if node["type"] == "Grid"})


if __name__ == "__main__":
    unittest.main()
