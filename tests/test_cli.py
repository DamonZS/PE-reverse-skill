import json
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reverse_analyzer.cli import (
    _knowledge_features,
    _knowledge_observations,
    _load_gui_interaction_trace,
    _persist_knowledge,
    _record_dynamic_profile_stats,
    _record_gui_strategy_stats,
    _run_behavior_graph,
)
from reverse_analyzer.config import AnalyzerConfig
from reverse_analyzer.knowledge import KnowledgeBase


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CliTests(unittest.TestCase):
    def test_cli_help_lists_commands(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("analyze", result.stdout)
        self.assertIn("init-knowledge", result.stdout)
        self.assertIn("show-knowledge", result.stdout)
        self.assertIn("list-tools", result.stdout)

        analyze_help = run_cli("analyze", "--help")
        self.assertEqual(analyze_help.returncode, 0, analyze_help.stderr)
        self.assertIn("--dynamic-profile", analyze_help.stdout)
        self.assertIn("auto", analyze_help.stdout)
        self.assertIn("--dynamic-backend", analyze_help.stdout)
        self.assertIn("--gui", analyze_help.stdout)
        self.assertIn("--reconstruct-gui", analyze_help.stdout)

    def test_list_tools_reports_scaffolded_runtime(self) -> None:
        result = run_cli("list-tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pe_deep_scan", result.stdout)
        self.assertIn("yara_scan", result.stdout)
        self.assertIn("reconstruct_project", result.stdout)
        self.assertIn("frida_trace", result.stdout)
        self.assertIn("procmon_trace", result.stdout)
        self.assertIn("gui_fingerprint", result.stdout)
        self.assertIn("gui_strategy_select", result.stdout)
        self.assertIn("reconstruct_gui_project", result.stdout)
        self.assertIn("session-store", result.stdout)
        self.assertIn("AgentLoop", result.stdout)
        self.assertIn("ToolExecutor", result.stdout)
        self.assertIn("ReportBuilder", result.stdout)

    def test_init_and_show_knowledge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run_cli("init-knowledge", "--workspace", tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Knowledge initialized", result.stdout)

            show = run_cli("show-knowledge", "--workspace", tmp)
            self.assertEqual(show.returncode, 0, show.stderr)
            self.assertIn("PentAGI migration knowledge scaffold", show.stdout)

    def test_knowledge_helpers_capture_dynamic_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"MZ")
            report_data = {
                "pe_analysis": {},
                "yara": {},
                "decompiler": {},
                "dynamic_analysis": {
                    "status": "ok",
                    "backend": "all",
                    "backends": ["frida", "procmon"],
                    "event_count": 5,
                    "return_event_count": 2,
                    "api_counts": {"WinHttpSendRequest": 3},
                    "operation_counts": {"TCP Connect": 2},
                    "category_counts": {"network": 5},
                    "top_paths": [{"path": "1.2.3.4:443", "count": 2}],
                },
                "reconstruction": {
                    "status": "ok",
                    "function_count": 0,
                    "import_count": 0,
                    "dynamic_evidence_count": 4,
                    "prioritized_modules": [{"module": "network"}],
                },
                "gui_analysis": {
                    "status": "ok",
                    "framework": "wpf",
                    "xaml_evidence": {"node_count": 3},
                    "evidence_graph": {
                        "status": "ok",
                        "confidence": 0.94,
                        "nodes": [
                            {"id": "save", "handler_evidence": [{"handler": "Save_Click"}]},
                            {"id": "name", "handler_evidence": [{"handler": "NameChanged"}]},
                        ],
                        "edges": [{"source": "window", "target": "save", "type": "contains"}],
                    },
                    "state_machine": {
                        "status": "ok",
                        "states": [{"id": "editing"}, {"id": "saved"}],
                        "actions": [{"id": "save"}],
                        "transitions": [{"source": "editing", "target": "saved"}],
                    },
                },
                "behavior_graph": {
                    "status": "ok",
                    "nodes": [{"id": "state:editing"}, {"id": "action:save"}],
                    "edges": [{"source": "state:editing", "target": "action:save"}],
                    "summary": {
                        "node_count": 2,
                        "edge_count": 1,
                        "linked_handler_count": 1,
                        "dynamic_event_count": 3,
                        "state_count": 2,
                        "transition_count": 1,
                    },
                },
                "findings": [],
            }
            tool_results = [
                {
                    "tool_name": "frida_trace",
                    "result": {
                        "tool": "frida_trace",
                        "status": "ok",
                        "data": {
                            "backend": "frida",
                            "event_count": 3,
                            "api_counts": {"WinHttpSendRequest": 3},
                            "category_counts": {"network": 3},
                            "artifacts": [{"name": "trace.json"}],
                        },
                    },
                }
            ]

            features = _knowledge_features(sample, report_data)
            observations = _knowledge_observations(tool_results, report_data)

            self.assertEqual(features["dynamic"]["backend"], "all")
            self.assertEqual(features["dynamic"]["backends"], ["frida", "procmon"])
            self.assertEqual(features["dynamic"]["event_count"], 5)
            self.assertIsNone(features["dynamic"]["hook_profile"])
            self.assertEqual(features["dynamic"]["top_api_names"], ["WinHttpSendRequest"])
            self.assertEqual(features["dynamic"]["top_operation_names"], ["TCP Connect"])
            self.assertEqual(features["dynamic"]["top_paths"], ["1.2.3.4:443"])
            self.assertEqual(features["reconstruction"]["dynamic_evidence_count"], 4)
            self.assertEqual(features["reconstruction"]["prioritized_modules"], ["network"])
            self.assertEqual(features["gui"]["xaml_node_count"], 3)
            self.assertEqual(features["gui"]["evidence_graph_node_count"], 2)
            self.assertEqual(features["gui"]["evidence_graph_edge_count"], 1)
            self.assertEqual(features["gui"]["event_handler_link_count"], 2)
            self.assertEqual(features["gui"]["state_count"], 2)
            self.assertEqual(features["gui"]["transition_count"], 1)
            self.assertEqual(features["behavior"]["node_count"], 2)
            self.assertEqual(features["behavior"]["transition_count"], 1)
            kinds = [item["kind"] for item in observations]
            self.assertIn("dynamic_behavior", kinds)
            self.assertIn("dynamic_summary", kinds)
            self.assertIn("gui_evidence_graph", kinds)
            self.assertIn("gui_state_machine", kinds)
            self.assertIn("behavior_graph", kinds)

    def test_persist_knowledge_includes_behavior_graph_session_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            config = AnalyzerConfig(
                workspace=root,
                knowledge_dir=root / "knowledge",
                sessions_dir=root / "sessions",
                reports_dir=root / "reports",
            )
            report_data = {
                "sample": {"status": "ok"},
                "pe_analysis": {},
                "yara": {},
                "dynamic_analysis": {},
                "decompiler": {},
                "reconstruction": {},
                "findings": [],
                "gui_analysis": {"status": "ok", "framework": "wpf", "strategy": {}},
                "behavior_graph": {
                    "status": "ok",
                    "nodes": [{"id": "state:editing"}, {"id": "action:save"}],
                    "edges": [{"source": "state:editing", "target": "action:save"}],
                    "summary": {
                        "node_count": 2,
                        "edge_count": 1,
                        "linked_handler_count": 1,
                        "dynamic_event_count": 3,
                        "state_count": 2,
                        "transition_count": 1,
                    },
                },
            }

            _persist_knowledge(
                config,
                sample,
                SimpleNamespace(session_id="session-behavior-graph"),
                root / "out",
                report_data,
                [],
            )

            sessions = KnowledgeBase(config.knowledge_dir).load_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(
                sessions[0]["behavior_graph"],
                {
                    "status": "ok",
                    "node_count": 2,
                    "edge_count": 1,
                    "linked_handler_count": 1,
                    "dynamic_event_count": 3,
                    "state_count": 2,
                    "transition_count": 1,
                },
            )

    def test_persist_knowledge_reports_session_summary_failure_without_losing_sample(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            config = AnalyzerConfig(
                workspace=root,
                knowledge_dir=root / "knowledge",
                sessions_dir=root / "sessions",
                reports_dir=root / "reports",
            )
            report_data = {
                "sample": {"status": "ok"},
                "pe_analysis": {},
                "yara": {},
                "dynamic_analysis": {},
                "decompiler": {},
                "reconstruction": {},
                "findings": [],
                "gui_analysis": {},
                "behavior_graph": {},
            }
            stderr = io.StringIO()

            with patch.object(KnowledgeBase, "append_session_summary", side_effect=OSError("session write blocked")):
                with redirect_stderr(stderr):
                    _persist_knowledge(
                        config,
                        sample,
                        SimpleNamespace(session_id="session-summary-failure"),
                        root / "out",
                        report_data,
                        [],
                    )

            stored = KnowledgeBase(config.knowledge_dir).load_knowledge()
            self.assertIn(str(sample), stored["samples"])
            self.assertIn("knowledge_base.session_summary_failed", stderr.getvalue())

    def test_gui_interaction_trace_loader_handles_invalid_path_types_and_size(self) -> None:
        for invalid_path in ("\0", object()):
            payload = _load_gui_interaction_trace(invalid_path)  # type: ignore[arg-type]
            self.assertEqual(payload["steps"], [])
            self.assertIn("input_error", payload)

        with tempfile.TemporaryDirectory() as tmp:
            trace_path = Path(tmp) / "oversized-trace.json"
            trace_path.write_bytes(b"[" + b" " * (1024 * 1024))

            payload = _load_gui_interaction_trace(trace_path)

        self.assertEqual(payload["steps"], [])
        self.assertIn("exceeds", payload["input_error"])

    def test_behavior_graph_is_not_rerun_after_an_empty_prior_result(self) -> None:
        class NoCallExecutor:
            calls = 0

            def execute(self, *args: object, **kwargs: object) -> dict[str, object]:
                self.calls += 1
                return {}

        executor = NoCallExecutor()
        tool_results = [
            {
                "tool_name": "gui_behavior_graph",
                "result": {},
            }
        ]

        artifacts = _run_behavior_graph(executor, tool_results, None, None, None, Path("."))

        self.assertEqual(artifacts, [])
        self.assertEqual(executor.calls, 0)

    def test_record_dynamic_profile_stats_from_report_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            report_data = {
                "dynamic_analysis": {
                    "status": "ok",
                    "backend": "all",
                    "children": [
                        {
                            "status": "ok",
                            "backend": "frida",
                            "hook_profile": "network",
                            "event_count": 12,
                            "return_event_count": 3,
                            "planned_hook_count": 8,
                            "category_counts": {"network": 12},
                        },
                        {
                            "status": "ok",
                            "backend": "procmon",
                            "event_count": 5,
                            "category_counts": {"file": 5},
                        },
                    ],
                }
            }

            records = _record_dynamic_profile_stats(kb, "sample.exe", report_data)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["profile"], "network")
            profiles = kb.load_dynamic_profiles()
            self.assertEqual(profiles["profiles"]["network"]["runs"], 1)
            self.assertEqual(profiles["profiles"]["network"]["total_events"], 12)

    def test_record_gui_strategy_stats_from_report_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            report_data = {
                "gui_analysis": {
                    "status": "ok",
                    "framework": "wpf",
                    "strategy": {"name": "extract_baml_generate_wpf", "output_stack": "wpf"},
                    "regression": {
                        "visual_similarity": 0.94,
                        "control_match_rate": 0.88,
                        "text_match_rate": 0.96,
                    },
                }
            }

            records = _record_gui_strategy_stats(kb, "sample.exe", report_data)

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["framework"], "wpf")
            self.assertEqual(records[0]["strategy"], "extract_baml_generate_wpf")
            recommendation = kb.recommend_gui_strategy(framework="wpf")
            self.assertEqual(recommendation["strategy"], "extract_baml_generate_wpf")

    def test_analyze_gui_writes_gui_report_and_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            out_dir = root / "analysis"
            sample.write_text("MZ PresentationFramework.dll InitializeComponent .baml", encoding="utf-8")

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "1",
                "--gui",
                "--reconstruct-gui",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["gui_analysis"]["framework"], "wpf")
            self.assertEqual(report["gui_analysis"]["strategy"]["name"], "extract_baml_generate_wpf")
            self.assertTrue((out_dir / "gui" / "fingerprint.json").is_file())
            self.assertTrue((out_dir / "reconstructed_gui" / "README.md").is_file())
            markdown = (out_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## GUI Analysis", markdown)
            self.assertIn("## GUI Reconstruction Strategy", markdown)
            self.assertIn("## GUI Visual Regression", markdown)

    def test_analyze_gui_reconstructs_wpf_from_extracted_xaml_evidence(self) -> None:
        xaml = """<Window xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"
            xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" Title=\"Evidence UI\">
          <Grid>
            <Button x:Name=\"saveButton\" Content=\"Save\" Width=\"90\" Height=\"28\"
                    Canvas.Left=\"10\" Canvas.Top=\"20\" Click=\"SaveButton_Click\" />
          </Grid>
        </Window>"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            out_dir = root / "analysis"
            with zipfile.ZipFile(sample, "w") as archive:
                archive.writestr("Views/MainWindow.xaml", xaml)

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "1",
                "--gui",
                "--reconstruct-gui",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            gui = report["gui_analysis"]
            self.assertEqual(gui["framework"], "wpf")
            self.assertGreater(gui["xaml_evidence"]["node_count"], 0)
            self.assertTrue(gui["evidence_graph"]["nodes"])
            self.assertTrue((out_dir / "gui" / "xaml_evidence.json").is_file())
            self.assertTrue((out_dir / "gui" / "evidence_graph.json").is_file())
            reconstructed = out_dir / "reconstructed_gui"
            self.assertTrue((reconstructed / "analysis" / "xaml_evidence.json").is_file())
            self.assertTrue((reconstructed / "analysis" / "evidence_graph.json").is_file())
            generated_xaml = (reconstructed / "src" / "MainWindow.xaml").read_text(encoding="utf-8")
            generated_code = (reconstructed / "src" / "MainWindow.xaml.cs").read_text(encoding="utf-8")
            self.assertIn('Content="Save"', generated_xaml)
            self.assertIn('Click="SaveButton_Click"', generated_xaml)
            self.assertIn("void SaveButton_Click(", generated_code)
    def test_analyze_writes_reports_and_uses_registered_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_text("MZ hello VirtualAlloc UPX0 CreateRemoteThread", encoding="utf-8")

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "3")

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue((out_dir / "report.json").exists())
            self.assertTrue((out_dir / "report.md").exists())
            tool_names = [item["tool_name"] for item in payload["result"]["tool_results"]]
            self.assertEqual(tool_names, ["file_info", "hash", "strings_extract", "gui_behavior_graph"])
            self.assertNotIn("tool not registered", result.stdout)

    def test_analyze_reconstruct_generates_stub_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_text("MZ hello VirtualAlloc UPX0 CreateRemoteThread", encoding="utf-8")

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "2",
                "--reconstruct",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            tool_names = [item["tool_name"] for item in payload["result"]["tool_results"]]
            self.assertIn("reconstruct_project", tool_names)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["reconstruction"]["status"], "ok")
            self.assertEqual(report["reconstruction"]["flow_status"], "pending")
            project_dir = Path(report["reconstruction"]["project_dir"])
            self.assertTrue(project_dir.is_dir())
            self.assertTrue((project_dir / "CMakeLists.txt").is_file())
            self.assertTrue((project_dir / "src" / "functions.c").is_file())
            self.assertIn("## Reconstruction", (out_dir / "report.md").read_text(encoding="utf-8"))

            session_path = out_dir / "sessions" / f"{payload['session_id']}.json"
            session_data = json.loads(session_path.read_text(encoding="utf-8"))
            self.assertEqual(session_data["status"], "running")
            flow_names = [flow["name"] for flow in session_data["flows"]]
            self.assertIn("source-reconstruction", flow_names)
            reconstruction_flow = next(flow for flow in session_data["flows"] if flow["name"] == "source-reconstruction")
            self.assertIn("tasks", reconstruction_flow)
            event_types = [event["type"] for event in session_data["events"] if "type" in event]
            self.assertIn("reconstruction_plan_registered", event_types)

    def test_install_guide_ghidra(self) -> None:
        result = run_cli("--install-guide", "ghidra")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ghidra Headless installation guide", result.stdout)
        self.assertIn("GHIDRA_HEADLESS", result.stdout)

    def test_install_guide_procmon(self) -> None:
        result = run_cli("--install-guide", "procmon")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Procmon behavioral capture installation guide", result.stdout)
        self.assertIn("dynamic-backend procmon", result.stdout)

    def test_analyze_decompile_gracefully_degrades_without_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_text("MZ hello", encoding="utf-8")

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "1",
                "--decompile",
                "--ghidra-home",
                str(root / "missing-ghidra"),
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Ghidra Headless not configured", result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["decompiler"]["status"], "unavailable")
            self.assertIn("--install-guide ghidra", report["decompiler"]["setup_hint"])
            self.assertIn("Ghidra Headless not configured", (out_dir / "report.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
