import json
import re
import unittest
from types import SimpleNamespace
from typing import Any

from reverse_analyzer.report import ReportBuilder


def _tool_trace(tool_name: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool_name": tool_name,
        "result": {
            "tool": tool_name,
            "status": data.get("status", "ok"),
            "data": data,
        },
    }


def _markdown_section(markdown: str, heading: str) -> str:
    marker = f"## {heading}\n"
    _, separator, remainder = markdown.partition(marker)
    if not separator:
        return ""
    return remainder.split("\n## ", 1)[0]


class ReportBehaviorGraphTests(unittest.TestCase):
    def test_public_report_api_exposes_behavior_graph_and_gui_state_machine(self) -> None:
        interaction_trace = {
            "status": "ok",
            "version": 1,
            "initial_state": "editing",
            "steps": [
                {
                    "sequence": 1,
                    "event": "Click",
                    "control": {"id": "saveButton", "type": "Button", "text": "Save"},
                    "action": {"id": "SaveButton_Click", "type": "handler"},
                    "from_state": "editing",
                    "to_state": "saved",
                }
            ],
        }
        behavior_graph = {
            "status": "ok",
            "version": 1,
            "nodes": [
                {"id": "control:saveButton", "type": "ui_control", "label": "Save"},
                {"id": "action:SaveButton_Click", "type": "ui_action", "label": "SaveButton_Click"},
                {"id": "state:editing", "type": "ui_state", "label": "editing"},
                {"id": "state:saved", "type": "ui_state", "label": "saved"},
            ],
            "edges": [
                {"source": "control:saveButton", "target": "action:SaveButton_Click", "type": "triggers"},
                {"source": "state:editing", "target": "action:SaveButton_Click", "type": "enables"},
                {"source": "action:SaveButton_Click", "target": "state:saved", "type": "transitions_to"},
            ],
        }
        state_machine = {
            "status": "ok",
            "version": 1,
            "initial_state": "editing",
            "states": [
                {"id": "editing", "initial": True},
                {"id": "saved", "initial": False},
            ],
            "transitions": [
                {
                    "source": "editing",
                    "target": "saved",
                    "control_id": "saveButton",
                    "action": "SaveButton_Click",
                }
            ],
        }
        tool_results = [
            _tool_trace(
                "gui_fingerprint",
                {
                    "status": "ok",
                    "platform": "windows-pe",
                    "framework": "wpf",
                    "confidence": 0.98,
                    "evidence": ["MainWindow.xaml"],
                },
            ),
            _tool_trace("gui_interaction_trace", interaction_trace),
            _tool_trace("gui_behavior_graph", behavior_graph),
            _tool_trace("gui_state_machine", state_machine),
        ]
        session = SimpleNamespace(session_id="behavior-report", target="fixture.exe", status="running", artifacts=[])
        builder = ReportBuilder(session, tool_results)

        built_report = builder.build()
        json_report = json.loads(builder.to_json())
        for report in (built_report, json_report):
            self.assertIn("behavior_graph", report)
            self.assertIn("gui_analysis", report)
            self.assertIn("state_machine", report["gui_analysis"])
            self.assertEqual(report["behavior_graph"]["nodes"], behavior_graph["nodes"])
            self.assertEqual(report["behavior_graph"]["edges"], behavior_graph["edges"])
            self.assertEqual(report["gui_analysis"]["state_machine"]["states"], state_machine["states"])
            self.assertEqual(report["gui_analysis"]["state_machine"]["transitions"], state_machine["transitions"])
            self.assertEqual(report["gui_analysis"]["runtime_tree"]["status"], "unavailable")

        markdown = builder.to_markdown()
        behavior_section = _markdown_section(markdown, "Behavior Evidence Graph")
        state_machine_section = _markdown_section(markdown, "GUI State Machine")
        self.assertTrue(behavior_section, markdown)
        self.assertTrue(state_machine_section, markdown)
        self.assertRegex(behavior_section, re.compile(r"(?im)^- \*\*.*nodes.*\*\*:\s*4\s*$"))
        self.assertRegex(behavior_section, re.compile(r"(?im)^- \*\*.*edges.*\*\*:\s*3\s*$"))
        self.assertRegex(state_machine_section, re.compile(r"(?im)^- \*\*.*states.*\*\*:\s*2\s*$"))
        self.assertRegex(state_machine_section, re.compile(r"(?im)^- \*\*.*transitions.*\*\*:\s*1\s*$"))


if __name__ == "__main__":
    unittest.main()
