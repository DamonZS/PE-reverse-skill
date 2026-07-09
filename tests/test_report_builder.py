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
        for item in report["findings"]:
            self.assertIn("confidence", item)
            self.assertIn("evidence", item)
            self.assertIn("recommendation", item)

    def test_report_builder_includes_decompiler_unavailable_section(self):
        session = SimpleNamespace(session_id="s3", target="sample.bin", status="running", artifacts=[])
        tool_results = [
            {
                "tool_name": "ghidra_decompile",
                "result": {
                    "tool": "ghidra_decompile",
                    "status": "unavailable",
                    "data": {
                        "status": "unavailable",
                        "setup_hint": "Run: python -m reverse_analyzer --install-guide ghidra",
                        "artifacts": [],
                    },
                },
                "ok": False,
            }
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        self.assertEqual(report["decompiler"]["status"], "unavailable")
        self.assertIn("Ghidra Headless not configured", {item["title"] for item in report["findings"]})
        self.assertIn("## Decompiler", markdown)
        self.assertIn("--install-guide ghidra", markdown)

    def test_report_builder_outputs_pe_yara_and_reconstruction_sections(self):
        session = SimpleNamespace(session_id="s4", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "pe_deep_scan",
                "result": {
                    "tool": "pe_deep_scan",
                    "status": "ok",
                    "data": {
                        "entrypoint": {"section": "UPX0"},
                        "imports": [{"dll": "KERNEL32.dll", "functions": [{"name": "LoadLibraryA"}]}],
                        "exports": {"count": 0, "symbols": []},
                        "resources": {"count": 1, "types": ["ICON"], "entries": []},
                        "tls_callbacks": {"count": 1, "callbacks": [4198400]},
                        "overlay": {"present": True, "size": 32},
                        "rich_header": {"present": True, "entry_count": 2},
                        "section_anomalies": [{"section": "UPX0", "reasons": ["suspicious_name", "high_entropy"]}],
                        "iat_anomalies": [{"dll": "KERNEL32.dll", "type": "null_iat_address"}],
                        "shell_score": 80,
                        "shell_verdict": "likely_packed",
                        "shell_indicators": [{"reason": "suspicious_name"}],
                    },
                },
            },
            {
                "tool_name": "yara_scan",
                "result": {
                    "tool": "yara_scan",
                    "status": "ok",
                    "data": {
                        "rules_path": "rules/yara",
                        "match_count": 1,
                        "matches": [
                            {
                                "rule": "SuspiciousWindowsApiCombo",
                                "namespace": "default.suspicious_apis",
                                "tags": ["suspicious"],
                                "meta": {"severity": "medium", "description": "High-risk API combo"},
                                "strings": {"count": 1, "items": [{"identifier": "$a1", "preview": "CreateRemoteThread"}]},
                            }
                        ],
                    },
                },
            },
            {
                "tool_name": "reconstruct_project",
                "result": {
                    "tool": "reconstruct_project",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "project_dir": "out/reconstructed_sample",
                        "function_count": 2,
                        "import_count": 1,
                        "stub_only": True,
                        "artifacts": [{"name": "src/functions.c", "path": "out/reconstructed_sample/src/functions.c"}],
                    },
                },
            },
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        self.assertEqual(report["pe_analysis"]["shell_score"], 80)
        self.assertEqual(report["yara"]["match_count"], 1)
        self.assertEqual(report["reconstruction"]["status"], "ok")
        self.assertIn("## PE Deep Analysis", markdown)
        self.assertIn("## YARA", markdown)
        self.assertIn("## Reconstruction", markdown)
        self.assertIn("YARA match: SuspiciousWindowsApiCombo", {item["title"] for item in report["findings"]})


if __name__ == "__main__":
    unittest.main()
