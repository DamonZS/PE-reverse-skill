import json
import unittest
from types import SimpleNamespace

from reverse_analyzer.report import ReportBuilder


def _tool_trace(tool_name: str, data: dict) -> dict:
    return {
        "tool_name": tool_name,
        "result": {
            "tool": tool_name,
            "status": data.get("status", "ok"),
            "data": data,
        },
    }


class ReportBuilderGuiEvidenceTests(unittest.TestCase):
    def test_report_json_and_markdown_expose_gui_evidence_graph_statistics(self) -> None:
        xaml_evidence = {
            "status": "ok",
            "source": "xaml",
            "node_count": 2,
            "nodes": [
                {
                    "id": "saveButton",
                    "type": "Button",
                    "text": "Save",
                    "event_handlers": {"Click": "SaveButton_Click"},
                },
                {
                    "id": "nameBox",
                    "type": "TextBox",
                    "event_handlers": {"TextChanged": "NameChanged"},
                },
            ],
        }
        evidence_graph_nodes = [
            {
                **xaml_evidence["nodes"][0],
                "handler_evidence": [{"handler": "SaveButton_Click", "source": "decompiler", "confidence": 0.8}],
            },
            {
                **xaml_evidence["nodes"][1],
                "handler_evidence": [{"handler": "NameChanged", "source": "decompiler", "confidence": 0.8}],
            },
        ]
        evidence_graph = {
            "status": "ok",
            "version": 1,
            "framework": "wpf",
            "nodes": evidence_graph_nodes,
            "edges": [{"source": "window", "target": "saveButton", "type": "contains"}],
            "source_summary": {"xaml_node_count": 2},
        }
        tool_results = [
            _tool_trace(
                "gui_fingerprint",
                {
                    "status": "ok",
                    "platform": "windows-pe",
                    "framework": "wpf",
                    "confidence": 0.98,
                    "evidence": ["PresentationFramework"],
                },
            ),
            _tool_trace(
                "gui_resource_extract",
                {
                    "status": "ok",
                    "counts": {"layouts": 1},
                    "extracted_files": ["gui/resources/extracted/MainWindow.xaml"],
                    "extracted_dir": "gui/resources/extracted",
                },
            ),
            _tool_trace("gui_xaml_extract", xaml_evidence),
            _tool_trace("gui_evidence_graph", evidence_graph),
            _tool_trace(
                "gui_strategy_select",
                {
                    "status": "ok",
                    "framework": "wpf",
                    "name": "extract_baml_generate_wpf",
                    "output_stack": "wpf",
                    "confidence": 0.98,
                },
            ),
        ]
        session = SimpleNamespace(session_id="gui-report", target="fixture.exe", status="running", artifacts=[])
        builder = ReportBuilder(session, tool_results)

        report = json.loads(builder.to_json())
        gui_analysis = report["gui_analysis"]
        self.assertEqual(gui_analysis["xaml_evidence"]["node_count"], 2)
        self.assertEqual(gui_analysis["xaml_evidence"]["nodes"][0]["id"], "saveButton")
        self.assertEqual(gui_analysis["evidence_graph"]["nodes"], evidence_graph["nodes"])
        self.assertEqual(gui_analysis["evidence_graph"]["edges"], evidence_graph["edges"])

        markdown = builder.to_markdown()
        self.assertIn("- **Evidence Graph Nodes:** 2", markdown)
        self.assertIn("- **Evidence Graph Edges:** 1", markdown)
        self.assertIn("- **Event Handler Links:** 2", markdown)
        self.assertIn("- **XAML Static Nodes:** 2", markdown)


if __name__ == "__main__":
    unittest.main()
