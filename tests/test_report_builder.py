import json
import unittest
from types import SimpleNamespace

from reverse_analyzer.report import ReportBuilder


class ReportBuilderTests(unittest.TestCase):
    def test_report_builder_outputs_json_and_markdown_sections(self):
        session = SimpleNamespace(
            session_id="s1",
            target="sample.exe",
            status="succeeded",
            created_at="2026-07-09T00:00:00Z",
            updated_at="2026-07-09T00:01:00Z",
            artifacts=[{"name": "strings.txt", "path": "artifacts/strings.txt"}],
        )
        tool_results = [
            {
                "tool_name": "strings",
                "result": {"findings": [{"title": "Suspicious URL", "severity": "high"}]},
            }
        ]

        builder = ReportBuilder(session, tool_results, {"findings": [{"title": "Packed", "severity": "medium"}]})
        as_json = json.loads(builder.to_json())
        as_markdown = builder.to_markdown()

        self.assertEqual(as_json["sample"]["target"], "sample.exe")
        self.assertEqual(as_json["tool_trace"][0]["tool_name"], "strings")
        self.assertEqual({item["title"] for item in as_json["findings"]}, {"Suspicious URL", "Packed"})
        self.assertIn("# Reverse Analysis Report", as_markdown)
        self.assertIn("## Tool Trace", as_markdown)
        self.assertIn("Suspicious URL", as_markdown)
        self.assertIn("strings.txt", as_markdown)

    def test_report_builder_extracts_nested_toolresult_findings(self):
        session = SimpleNamespace(session_id="s2", target="sample.bin", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "strings_extract",
                "result": {
                    "tool": "strings_extract",
                    "status": "ok",
                    "data": {"strings": ["VirtualAlloc CreateRemoteThread"]},
                },
            },
            {
                "tool_name": "packer_detect",
                "result": {
                    "tool": "packer_detect",
                    "status": "ok",
                    "data": {"packed_likely": True, "score": 50, "indicators": [{"type": "section_name"}]},
                },
            },
        ]

        report = ReportBuilder(session, tool_results).build()

        titles = {item["title"] for item in report["findings"]}
        self.assertIn("Suspicious Windows API strings", titles)
        self.assertIn("Packer indicators detected", titles)


if __name__ == "__main__":
    unittest.main()
