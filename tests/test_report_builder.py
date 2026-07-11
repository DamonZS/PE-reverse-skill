import json
import unittest
from types import SimpleNamespace

from reverse_analyzer.core import Flow, ReverseSession, Status, Subtask, Task
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
        session = ReverseSession(session_id="s4", target="sample.exe", status=Status.RUNNING, artifacts=[])
        base = session.add_flow(Flow("binary-analysis", status=Status.SUCCEEDED))
        base.add_task(Task("identify", status=Status.SUCCEEDED))
        base.add_task(Task("analyze", status=Status.SUCCEEDED))
        base.add_task(Task("report", status=Status.SUCCEEDED))
        reconstruction_flow = session.add_flow(Flow("source-reconstruction", status=Status.PENDING))
        reconstruction_task = reconstruction_flow.add_task(Task("reconstruct_loader", status=Status.PENDING))
        reconstruction_task.add_subtask(Subtask("review_loader_xrefs", status=Status.PENDING))
        reconstruction_task.add_subtask(Subtask("recover_entry", status=Status.PENDING))
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
                        "module_count": 2,
                        "module_files": ["src/loader.c", "src/network.c"],
                        "prioritized_modules": [
                            {"module": "loader", "priority_score": 9.5, "function_count": 1, "top_functions": ["entry"]},
                            {"module": "network", "priority_score": 5.25, "function_count": 1, "top_functions": ["worker"]},
                        ],
                        "high_value_functions": [
                            {"name": "entry", "module": "loader", "priority_score": 9.5},
                            {"name": "worker", "module": "network", "priority_score": 5.25},
                        ],
                        "reconstruction_plan": {
                            "status": "planned",
                            "tasks": [
                                {
                                    "name": "reconstruct_loader",
                                    "subtasks": [
                                        {"name": "review_loader_xrefs"},
                                        {"name": "recover_entry"},
                                        {"name": "verify_loader"},
                                    ],
                                },
                                {
                                    "name": "reconstruct_network",
                                    "subtasks": [
                                        {"name": "review_network_xrefs"},
                                        {"name": "recover_worker"},
                                    ],
                                },
                            ],
                        },
                        "task_count": 2,
                        "next_task": "reconstruct_loader",
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
        self.assertEqual(report["reconstruction"]["module_count"], 2)
        self.assertEqual(report["reconstruction"]["prioritized_modules"][0]["module"], "loader")
        self.assertEqual(report["reconstruction"]["task_count"], 2)
        self.assertEqual(report["reconstruction"]["next_task"], "reconstruct_loader")
        self.assertEqual(report["reconstruction"]["flow_status"], "pending")
        self.assertEqual(report["reconstruction"]["completed_task_count"], 0)
        self.assertEqual(report["reconstruction"]["completed_subtask_count"], 0)
        self.assertEqual(report["reconstruction"]["next_subtask"], "review_loader_xrefs")
        self.assertIn("## PE Deep Analysis", markdown)
        self.assertIn("## YARA", markdown)
        self.assertIn("## Reconstruction", markdown)
        self.assertIn("Module Priority", markdown)
        self.assertIn("High-Value Functions", markdown)
        self.assertIn("Plan Tasks", markdown)
        self.assertIn("Flow Status", markdown)
        self.assertIn("Next Subtask", markdown)
        self.assertIn("Reconstruction Plan", markdown)
        self.assertIn("YARA match: SuspiciousWindowsApiCombo", {item["title"] for item in report["findings"]})

    def test_report_builder_exposes_semantic_ir_and_reconstruction_verification(self):
        session = SimpleNamespace(session_id="semantic-1", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "semantic_ir_build",
                "result": {
                    "tool": "semantic_ir_build",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "schema_version": 1,
                        "summary": {
                            "entity_count": 4,
                            "relation_count": 3,
                            "capability_count": 2,
                            "function_count": 1,
                            "api_count": 1,
                            "dynamic_event_count": 1,
                            "ui_control_count": 0,
                            "ui_state_count": 0,
                        },
                        "capabilities": [
                            {"name": "network", "category": "network", "confidence": 0.9, "evidence_count": 2}
                        ],
                    },
                },
            },
            {
                "tool_name": "reconstruction_verify",
                "result": {
                    "tool": "reconstruction_verify",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "schema_version": 1,
                        "score": 0.8,
                        "coverage": {"semantic_coverage": 0.75, "module_coverage": 1.0},
                        "checks": [{"name": "source_files", "status": "ok", "detail": "2 source files", "weight": 0.2}],
                        "recommendations": [],
                    },
                },
            },
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        self.assertEqual(report["semantic_ir"]["summary"]["entity_count"], 4)
        self.assertEqual(report["semantic_ir"]["capabilities"][0]["name"], "network")
        self.assertEqual(report["reconstruction_verification"]["score"], 0.8)
        self.assertIn("## Semantic IR", markdown)
        self.assertIn("## Reconstruction Verification", markdown)

    def test_report_builder_normalizes_malformed_semantic_ir_collections(self):
        session = SimpleNamespace(session_id="semantic-malformed", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "semantic_ir_build",
                "result": {
                    "tool": "semantic_ir_build",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "schema_version": 1,
                        "entities": "entry",
                        "relations": {"source": "entry", "target": "worker"},
                        "capabilities": 7,
                    },
                },
            }
        ]

        report = ReportBuilder(session, tool_results).build()
        markdown = ReportBuilder(session, tool_results).to_markdown()

        self.assertEqual(report["semantic_ir"]["entities"], [])
        self.assertEqual(report["semantic_ir"]["relations"], [])
        self.assertEqual(report["semantic_ir"]["capabilities"], [])
        self.assertIn("- **Entities:** 0", markdown)
        self.assertIn("- **Relations:** 0", markdown)
        self.assertIn("- **Capabilities:** 0", markdown)
        self.assertNotIn("- **Top Capabilities:**", markdown)

    def test_report_builder_extracts_ghidra_capability_findings(self):
        session = SimpleNamespace(session_id="s5", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "ghidra_decompile",
                "result": {
                    "tool": "ghidra_decompile",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "output_dir": "out/decompiled/ghidra",
                        "function_count": 2,
                        "functions": [
                            {
                                "name": "entry",
                                "body_size": 2048,
                                "calls": [{"name": "GetProcAddress"}, {"name": "CreateRemoteThread"}],
                            },
                            {"name": "worker", "body_size": 256, "calls": [{"name": "WinHttpSendRequest"}]},
                        ],
                        "call_graph": {
                            "nodes": [{"name": "entry"}, {"name": "worker"}],
                            "edges": [
                                {"source": "00401000", "target": "00402000"},
                                {"source": "00401000", "target": "00403000"},
                                {"source": "00402000", "target": "00404000"},
                                {"source": "00402000", "target": "00405000"},
                            ],
                        },
                        "strings_xrefs": [
                            {
                                "address": "00405000",
                                "value": "https://c2.example.test/ping",
                                "xref_count": 1,
                                "functions": [{"name": "entry", "entry": "00401000"}],
                            },
                            {
                                "address": "00405020",
                                "value": "User-Agent: reverse-analyzer",
                                "xref_count": 1,
                                "functions": [{"name": "worker", "entry": "00402000"}],
                            },
                            {
                                "address": "00405040",
                                "value": "powershell -enc AAAA",
                                "xref_count": 1,
                                "functions": [{"name": "entry", "entry": "00401000"}],
                            },
                        ],
                        "imports_xrefs": [
                            {"library": "KERNEL32.dll", "label": "LoadLibraryA", "functions": [{"name": "entry", "entry": "00401000"}]},
                            {"library": "KERNEL32.dll", "label": "GetProcAddress", "functions": [{"name": "entry", "entry": "00401000"}]},
                            {"library": "KERNEL32.dll", "label": "VirtualAlloc", "functions": [{"name": "entry", "entry": "00401000"}]},
                            {"library": "KERNEL32.dll", "label": "WriteProcessMemory", "functions": [{"name": "entry", "entry": "00401000"}]},
                            {"library": "KERNEL32.dll", "label": "CreateRemoteThread", "functions": [{"name": "entry", "entry": "00401000"}]},
                            {"library": "WINHTTP.dll", "label": "WinHttpOpen", "functions": [{"name": "worker", "entry": "00402000"}]},
                            {"library": "WINHTTP.dll", "label": "WinHttpSendRequest", "functions": [{"name": "worker", "entry": "00402000"}]},
                            {"library": "URLMON.dll", "label": "URLDownloadToFileA", "functions": [{"name": "worker", "entry": "00402000"}]},
                            {"library": "KERNEL32.dll", "label": "WinExec", "functions": [{"name": "entry", "entry": "00401000"}]},
                        ],
                        "summary": {
                            "program": "sample.exe",
                            "language": "x86:LE:32:default",
                            "compiler": "windows",
                            "image_base": "00400000",
                            "function_count": 2,
                            "string_count": 3,
                            "import_count": 9,
                        },
                    },
                },
            }
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        titles = {item["title"] for item in report["findings"]}
        self.assertIn("Ghidra Headless decompilation completed", titles)
        self.assertIn("Dynamic API resolution indicators", titles)
        self.assertIn("Process injection or in-memory execution indicators", titles)
        self.assertIn("Network communication indicators", titles)
        self.assertIn("Command execution or staging indicators", titles)
        self.assertIn("Large recovered function or dense call graph", titles)

        for title in (
            "Dynamic API resolution indicators",
            "Process injection or in-memory execution indicators",
            "Network communication indicators",
        ):
            finding = next(item for item in report["findings"] if item["title"] == title)
            self.assertIn("confidence", finding)
            self.assertIn("evidence", finding)
            self.assertIn("recommendation", finding)
        dynamic = next(item for item in report["findings"] if item["title"] == "Dynamic API resolution indicators")
        network = next(item for item in report["findings"] if item["title"] == "Network communication indicators")
        self.assertIn("GetProcAddress", dynamic["evidence"]["functions"])
        self.assertTrue(any(item["functions"] for item in network["evidence"]["string_locations"]))

        self.assertEqual(report["decompiler"]["function_count"], 2)
        self.assertEqual(report["decompiler"]["call_graph_edge_count"], 4)
        self.assertEqual(report["decompiler"]["string_count"], 3)
        self.assertEqual(report["decompiler"]["language"], "x86:LE:32:default")
        self.assertIn("Call Graph Edges", markdown)
        self.assertIn("Image Base", markdown)


    def test_report_builder_includes_procmon_dynamic_behavior(self):
        session = SimpleNamespace(session_id="s6", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "procmon_trace",
                "result": {
                    "tool": "procmon_trace",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "backend": "procmon",
                        "event_count": 3,
                        "operation_counts": {"CreateFile": 1, "RegSetValue": 1, "TCP Connect": 1},
                        "category_counts": {"file": 1, "registry": 1, "network": 1},
                        "top_paths": [{"path": "HKCU/Run", "count": 1}],
                        "sample_events": [
                            {"operation": "CreateFile", "category": "file", "path": "C:/tmp/a", "result": "SUCCESS"},
                            {"operation": "RegSetValue", "category": "registry", "path": "HKCU/Run", "result": "SUCCESS"},
                            {"operation": "TCP Connect", "category": "network", "path": "1.2.3.4:443", "result": "SUCCESS"},
                        ],
                        "artifacts": [{"name": "events.csv", "path": "out/dynamic/procmon/events.csv"}],
                    },
                },
            }
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        self.assertEqual(report["dynamic_analysis"]["backend"], "procmon")
        self.assertEqual(report["dynamic_analysis"]["operation_counts"]["CreateFile"], 1)
        titles = {item["title"] for item in report["findings"]}
        self.assertIn("Dynamic network activity observed", titles)
        self.assertIn("Dynamic file or registry access observed", titles)
        self.assertIn("Top OS Operations", markdown)
        self.assertIn("Top Paths", markdown)
    def test_report_builder_includes_frida_hook_profile(self):
        session = SimpleNamespace(session_id="s7", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "frida_trace",
                "result": {
                    "tool": "frida_trace",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "backend": "frida",
                        "mode": "spawn",
                        "hook_profile": "network",
                        "planned_hook_count": 8,
                        "event_count": 1,
                        "api_counts": {"connect": 1},
                        "category_counts": {"network": 1},
                        "events": [{"name": "connect", "category": "network", "params": {"address": "1.2.3.4:443"}}],
                    },
                },
            }
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        self.assertEqual(report["dynamic_analysis"]["hook_profile"], "network")
        self.assertEqual(report["dynamic_analysis"]["planned_hook_count"], 8)
        self.assertIn("Hook Profile", markdown)
        self.assertIn("Planned Hooks", markdown)

    def test_report_builder_merges_gui_pipeline_sections(self):
        session = SimpleNamespace(session_id="gui-1", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "gui_fingerprint",
                "result": {
                    "tool": "gui_fingerprint",
                    "status": "ok",
                    "data": {
                        "platform": "windows-pe",
                        "framework": "wpf",
                        "confidence": 0.94,
                        "evidence": ["PresentationFramework.dll", "BAML resources"],
                    },
                },
            },
            {
                "tool_name": "gui_resource_extract",
                "result": {
                    "tool": "gui_resource_extract",
                    "status": "ok",
                    "data": {"counts": {"icons": 3, "images": 12, "layouts": 8}},
                },
            },
            {
                "tool_name": "gui_runtime_probe",
                "result": {
                    "tool": "gui_runtime_probe",
                    "status": "ok",
                    "data": {"window_count": 2, "control_count": 47},
                },
            },
            {
                "tool_name": "gui_visual_parse",
                "result": {
                    "tool": "gui_visual_parse",
                    "status": "ok",
                    "data": {"screenshot_count": 4, "ocr_text_count": 31, "detected_widget_count": 42},
                },
            },
            {
                "tool_name": "gui_strategy_select",
                "result": {
                    "tool": "gui_strategy_select",
                    "status": "ok",
                    "data": {
                        "name": "extract_baml_generate_wpf",
                        "output_stack": "wpf",
                        "confidence": 0.91,
                        "steps": ["resource_extract", "generate_wpf_project"],
                    },
                },
            },
            {
                "tool_name": "gui_visual_regression",
                "result": {
                    "tool": "gui_visual_regression",
                    "status": "ok",
                    "data": {"pair_count": 4, "visual_similarity": 0.94, "text_match_rate": 0.96, "control_match_rate": 0.88},
                },
            },
        ]

        report = ReportBuilder(session, tool_results).build()
        markdown = ReportBuilder(session, tool_results).to_markdown()

        self.assertEqual(report["gui_analysis"]["framework"], "wpf")
        self.assertEqual(report["gui_analysis"]["resources"]["images"], 12)
        self.assertEqual(report["gui_analysis"]["runtime_tree"]["control_count"], 47)
        self.assertEqual(report["gui_analysis"]["visual"]["ocr_text_count"], 31)
        self.assertEqual(report["gui_analysis"]["strategy"]["name"], "extract_baml_generate_wpf")
        self.assertEqual(report["gui_analysis"]["regression"]["visual_similarity"], 0.94)
        self.assertIn("## GUI Analysis", markdown)
        self.assertIn("## GUI Reconstruction Strategy", markdown)
        self.assertIn("## GUI Visual Regression", markdown)
if __name__ == "__main__":
    unittest.main()
