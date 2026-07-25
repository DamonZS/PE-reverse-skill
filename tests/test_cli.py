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
    _build_reconstruction_analysis,
    _load_gui_interaction_trace,
    _persist_knowledge,
    _record_dynamic_profile_stats,
    _record_gui_strategy_stats,
    _run_behavior_graph,
    web_command,
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
    def test_web_command_delegates_to_go_control_plane(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            (workspace / "frontend" / "dist").mkdir(parents=True)
            binary = workspace / "build" / ("reverse-analyzer-server.exe" if sys.platform == "win32" else "reverse-analyzer-server")
            binary.parent.mkdir()
            binary.write_bytes(b"go-server")
            args = SimpleNamespace(workspace=str(workspace), frontend_dir=None, host="127.0.0.1", port=8190)
            process = SimpleNamespace(wait=lambda: 0, terminate=lambda: None)
            with patch("reverse_analyzer.cli.subprocess.Popen", return_value=process) as popen:
                self.assertEqual(web_command(args), 0)
            command = popen.call_args.args[0]
            environment = popen.call_args.kwargs["env"]
            self.assertEqual(command, [str(binary)])
            self.assertEqual(environment["REVERSE_ANALYZER_WEB_ADDR"], "127.0.0.1:8190")

    def test_cli_help_lists_commands(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("analyze", result.stdout)
        self.assertIn("capability", result.stdout)
        self.assertIn("init-knowledge", result.stdout)
        self.assertIn("show-knowledge", result.stdout)
        self.assertIn("list-tools", result.stdout)

        analyze_help = run_cli("analyze", "--help")
        self.assertEqual(analyze_help.returncode, 0, analyze_help.stderr)
        self.assertIn("--dynamic-profile", analyze_help.stdout)
        self.assertIn("auto", analyze_help.stdout)
        self.assertIn("--dynamic-backend", analyze_help.stdout)
        self.assertIn("--memory-analysis", analyze_help.stdout)
        self.assertIn("--memory-plan", analyze_help.stdout)
        self.assertIn("--gui", analyze_help.stdout)
        self.assertIn("--reconstruct-gui", analyze_help.stdout)

        capability_help = run_cli("capability", "--help")
        self.assertEqual(capability_help.returncode, 0, capability_help.stderr)
        self.assertIn("run", capability_help.stdout)
        self.assertIn("list", capability_help.stdout)
        self.assertIn("show-audit", capability_help.stdout)

        capability_run_help = run_cli("capability", "run", "--help")
        self.assertEqual(capability_run_help.returncode, 0, capability_run_help.stderr)
        self.assertIn("--capability", capability_run_help.stdout)
        self.assertIn("--action", capability_run_help.stdout)
        self.assertIn("--sample", capability_run_help.stdout)
        self.assertIn("--pid", capability_run_help.stdout)
        self.assertIn("--out", capability_run_help.stdout)
        self.assertIn("--provider", capability_run_help.stdout)
        self.assertIn("--param", capability_run_help.stdout)
        self.assertIn("--rollback", capability_run_help.stdout)

    def test_capability_list_text_and_json(self) -> None:
        result = run_cli("capability", "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("memory_runtime: windows_memory_runtime, mock", result.stdout)
        self.assertIn("injector: windows_controlled_injector, mock", result.stdout)
        self.assertIn("hook_runtime: frida_hook_runtime, mock", result.stdout)
        self.assertIn("android_rebuild: local_android_rebuild, mock", result.stdout)

        json_result = run_cli("capability", "list", "--json")
        self.assertEqual(json_result.returncode, 0, json_result.stderr)
        payload = json.loads(json_result.stdout)
        capabilities = {item["name"]: item["providers"] for item in payload["capabilities"]}
        self.assertEqual(capabilities["memory_runtime"], ["windows_memory_runtime", "mock"])
        self.assertEqual(capabilities["injector"], ["windows_controlled_injector", "mock"])
        self.assertEqual(capabilities["hook_runtime"], ["frida_hook_runtime", "mock"])
        self.assertEqual(capabilities["android_rebuild"], ["local_android_rebuild", "mock"])

    def test_capability_run_writes_report_manifest_and_audit_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ\x90\x90")

            result = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["capability"], "memory_runtime")
            self.assertEqual(payload["action"], "scan")
            self.assertEqual(payload["provider"], "mock")
            self.assertIsNone(payload["rollback"])

            report_json = out_dir / "report.json"
            report_md = out_dir / "report.md"
            manifest = out_dir / "evidence-manifest.json"
            audit_path = out_dir / "capabilities" / "memory_runtime_scan_audit.json"
            self.assertTrue(report_json.is_file())
            self.assertTrue(report_md.is_file())
            self.assertTrue(manifest.is_file())
            self.assertTrue(audit_path.is_file())

            report = json.loads(report_json.read_text(encoding="utf-8"))
            self.assertGreaterEqual(report["capability_audit"]["record_count"], 1)
            self.assertEqual(report["memory_analysis"]["capability"], "memory_runtime")
            self.assertEqual(report["memory_analysis"]["action"], "scan")
            self.assertEqual(report["memory_analysis"]["provider"], "mock")
            self.assertEqual(report["memory_analysis"]["status"], "mocked")
            self.assertEqual(report["platform_core"]["status"], "ok")
            self.assertIn("capability_registry", report["platform_core"])
            self.assertIn("capability_audit", report["platform_core"])
            self.assertIn("memory_runtime", report["platform_core"]["capability_registry"]["capabilities"])
            self.assertGreaterEqual(report["platform_core"]["capability_audit"]["record_count"], 1)

            markdown = report_md.read_text(encoding="utf-8")
            self.assertIn("## Capability Audit", markdown)
            self.assertIn("## Capability Execution", markdown)

            artifact_paths = set(payload["artifacts"])
            self.assertIn(str(report_json), artifact_paths)
            self.assertIn(str(report_md), artifact_paths)
            self.assertIn(str(manifest), artifact_paths)
            self.assertIn(str(audit_path), artifact_paths)

    def test_capability_run_with_rollback_records_rollback_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ\x90\x90")

            result = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
                "--rollback",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIsNotNone(payload["rollback"])
            self.assertTrue(payload["rollback"]["ok"])
            self.assertTrue(payload["rollback"]["restored"])

            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            record = report["capability_audit"]["records"][0]
            event_kinds = [item["kind"] for item in record["events"]]
            self.assertIn("rollback", event_kinds)
            self.assertTrue(report["memory_analysis"]["rollback"]["ok"])

    def test_capability_run_rejects_invalid_param_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ\x90\x90")

            result = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(root / "out"),
                "--param",
                "badvalue",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("expected key=value", result.stderr)

    def test_capability_run_rejects_unknown_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            sample.write_bytes(b"MZ\x90\x90")

            result = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(root / "out"),
                "--provider",
                "nope",
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("Preferred provider 'nope' not found", result.stderr)

    def test_capability_show_audit_reads_report_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "out"
            sample.write_bytes(b"MZ\x90\x90")

            run_result = run_cli(
                "capability",
                "run",
                "--capability",
                "memory_runtime",
                "--action",
                "scan",
                "--sample",
                str(sample),
                "--out",
                str(out_dir),
                "--provider",
                "mock",
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

            result = run_cli("capability", "show-audit", "--report", str(out_dir / "report.json"))
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["record_count"], 1)
            self.assertEqual(payload["records"][0]["capability"], "memory_runtime")
            self.assertEqual(payload["records"][0]["provider"], "mock")
            self.assertEqual(payload["records"][0]["action"], "scan")

    def test_list_tools_reports_scaffolded_runtime(self) -> None:
        result = run_cli("list-tools")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("pe_deep_scan", result.stdout)
        self.assertIn("yara_scan", result.stdout)
        self.assertIn("reconstruct_project", result.stdout)
        self.assertIn("frida_trace", result.stdout)
        self.assertIn("binary_patch_apply", result.stdout)
        self.assertIn("procmon_trace", result.stdout)
        self.assertIn("memory_snapshot", result.stdout)
        self.assertIn("memory_diff", result.stdout)
        self.assertIn("memory_address_map", result.stdout)
        self.assertIn("gui_fingerprint", result.stdout)
        self.assertIn("gui_strategy_select", result.stdout)
        self.assertIn("reconstruct_gui_project", result.stdout)
        self.assertIn("semantic_ir_build", result.stdout)
        self.assertIn("reconstruction_verify", result.stdout)
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
            self.assertIn("PE migration knowledge scaffold", show.stdout)

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
                "semantic_ir": {
                    "status": "ok",
                    "schema_version": 1,
                    "summary": {"entity_count": 5, "relation_count": 4, "capability_count": 2},
                    "capabilities": [
                        {"name": "network", "category": "network"},
                        {"name": "gui", "category": "gui"},
                    ],
                },
                "reconstruction_verification": {
                    "status": "ok",
                    "schema_version": 1,
                    "score": 0.82,
                    "coverage": {"semantic_coverage": 0.8, "module_coverage": 1.0},
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
            self.assertEqual(features["semantic"]["entity_count"], 5)
            self.assertEqual(features["semantic"]["capabilities"], ["network", "gui"])
            self.assertEqual(features["reconstruction"]["verification_score"], 0.82)
            self.assertEqual(features["reconstruction"]["semantic_coverage"], 0.8)
            kinds = [item["kind"] for item in observations]
            self.assertIn("dynamic_behavior", kinds)
            self.assertIn("dynamic_summary", kinds)
            self.assertIn("gui_evidence_graph", kinds)
            self.assertIn("gui_state_machine", kinds)
            self.assertIn("behavior_graph", kinds)
            self.assertIn("semantic_ir", kinds)
            self.assertIn("reconstruction_verification", kinds)

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
                "semantic_ir": {
                    "status": "ok",
                    "schema_version": 1,
                    "summary": {"entity_count": 3, "relation_count": 2, "capability_count": 1},
                    "capabilities": [{"name": "network", "category": "network"}],
                },
                "reconstruction_verification": {
                    "status": "ok",
                    "schema_version": 1,
                    "score": 0.8,
                    "coverage": {"semantic_coverage": 0.75, "module_coverage": 1.0},
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
            self.assertEqual(
                sessions[0]["semantic_ir"],
                {
                    "status": "ok",
                    "schema_version": 1,
                    "entity_count": 3,
                    "relation_count": 2,
                    "capability_count": 1,
                    "capabilities": ["network"],
                },
            )
            self.assertEqual(
                sessions[0]["reconstruction_verification"],
                {
                    "status": "ok",
                    "schema_version": 1,
                    "score": 0.8,
                    "semantic_coverage": 0.75,
                    "module_coverage": 1.0,
                },
            )

    def test_persist_knowledge_recalls_guidance_and_stores_reverse_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "packed.exe"
            sample.write_bytes(b"MZ")
            config = AnalyzerConfig(
                workspace=root,
                knowledge_dir=root / "knowledge",
                sessions_dir=root / "sessions",
                reports_dir=root / "reports",
            )
            knowledge = KnowledgeBase(config.knowledge_dir)
            guide = knowledge.add_document(
                "Use the unpacking Frida profile when shell verdict is suspicious.",
                document_type="guide",
                title="Suspicious PE unpacking",
                tags=["pe", "unpacking", "suspicious"],
            )
            report_data = {
                "sample": {"status": "ok"},
                "pe_analysis": {"shell_verdict": "suspicious", "shell_score": 8},
                "yara": {},
                "dynamic_analysis": {
                    "status": "ok",
                    "backend": "frida",
                    "hook_profile": "unpacking",
                    "event_count": 4,
                    "api_counts": {"VirtualAlloc": 2},
                },
                "decompiler": {},
                "reconstruction": {"status": "ok", "prioritized_modules": [{"module": "loader"}]},
                "semantic_ir": {"status": "ok", "capabilities": [{"name": "unpacking"}]},
                "findings": [],
                "gui_analysis": {},
                "behavior_graph": {},
            }

            _persist_knowledge(
                config,
                sample,
                SimpleNamespace(session_id="reverse-memory"),
                root / "out",
                report_data,
                [],
            )

            context = report_data["knowledge_context"]
            self.assertEqual(context["storage_status"], "stored")
            self.assertEqual(context["matches"][0]["id"], guide["id"])
            documents = KnowledgeBase(config.knowledge_dir).list_documents()
            memories = [item for item in documents if item["type"] == "memory"]
            self.assertEqual(len(memories), 1)
            self.assertTrue(memories[0]["metadata"]["evidence_backed"])

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

    def test_knowledge_helpers_normalize_malformed_semantic_ir_collections(self) -> None:
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
                "semantic_ir": {
                    "status": "ok",
                    "schema_version": 1,
                    "entities": "not-a-list",
                    "relations": {"not": "a-list"},
                    "capabilities": 3,
                },
            }

            features = _knowledge_features(sample, report_data)
            self.assertEqual(features["semantic"]["entity_count"], 0)
            self.assertEqual(features["semantic"]["relation_count"], 0)
            self.assertEqual(features["semantic"]["capability_count"], 0)

            _persist_knowledge(
                config,
                sample,
                SimpleNamespace(session_id="malformed-semantic-ir"),
                root / "out",
                report_data,
                [],
            )

            sessions = KnowledgeBase(config.knowledge_dir).load_sessions()
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0]["semantic_ir"]["entity_count"], 0)
            self.assertEqual(sessions[0]["semantic_ir"]["relation_count"], 0)
            self.assertEqual(sessions[0]["semantic_ir"]["capabilities"], [])

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

    def test_reconstruction_analysis_normalizes_malformed_semantic_ir_collections(self) -> None:
        analysis = _build_reconstruction_analysis(
            [
                {
                    "tool_name": "semantic_ir_build",
                    "result": {
                        "tool": "semantic_ir_build",
                        "status": "ok",
                        "data": {"entities": 1, "relations": {"edge": "bad"}, "capabilities": "network"},
                    },
                }
            ]
        )

        self.assertEqual(analysis["summary"]["semantic_entity_count"], 0)
        self.assertEqual(analysis["summary"]["semantic_relation_count"], 0)
        self.assertEqual(analysis["summary"]["semantic_capability_count"], 0)

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
            reconstructed = out_dir / "reconstructed_gui"
            self.assertTrue((reconstructed / "README.md").is_file())
            self.assertTrue((reconstructed / "analysis" / "semantic_ir.json").is_file())
            self.assertTrue((reconstructed / "analysis" / "reconstruction_plan.json").is_file())
            self.assertTrue((reconstructed / "analysis" / "reconstruction_verification.json").is_file())
            self.assertIn(report["reconstruction_verification"]["status"], {"ok", "partial"})
            self.assertGreater(report["reconstruction_verification"]["score"], 0)
            self.assertEqual(
                Path(report["gui_analysis"]["reconstruction_verification"]["project_dir"]),
                reconstructed,
            )
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

    def test_gui_verification_remains_attached_to_gui_project_with_native_reconstruction(self) -> None:
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
                "--reconstruct",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            gui_project = Path(report["gui_analysis"]["reconstruction"]["project_dir"])
            native_project = Path(report["reconstruction"]["project_dir"])
            self.assertEqual(Path(report["gui_analysis"]["reconstruction_verification"]["project_dir"]), gui_project)
            self.assertEqual(Path(report["reconstruction_verification"]["project_dir"]), native_project)
            self.assertNotEqual(gui_project, native_project)

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
            self.assertEqual(
                tool_names,
                [
                    "file_info",
                    "hash",
                    "strings_extract",
                    "engine_analyze",
                    "android_analyze",
                    "protocol_analyze",
                    "gui_behavior_graph",
                    "semantic_ir_build",
                ],
            )
            self.assertNotIn("tool not registered", result.stdout)

    def test_analyze_memory_without_pid_records_unavailable_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            sample.write_bytes(b"MZ")

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1", "--memory-analysis")

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            snapshot = next(item for item in payload["result"]["tool_results"] if item["tool_name"] == "memory_snapshot")
            self.assertEqual(snapshot["status"], "unavailable")
            self.assertIn("explicit --attach-pid", snapshot["error"])
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["memory_analysis"]["status"], "unavailable")
            self.assertEqual(report["memory_analysis"]["snapshot"]["status"], "unavailable")

    def test_analyze_memory_plan_runs_offline_diff_and_address_map(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            before = root / "before.json"
            after = root / "after.json"
            plan = root / "memory-plan.json"
            sample.write_bytes(b"MZ")
            before.write_text(json.dumps({"kind": "memory_snapshot", "modules": [], "regions": []}), encoding="utf-8")
            after.write_text(json.dumps({"kind": "memory_snapshot", "modules": [], "regions": [{"base_address": "0x1000", "size": 4096}]}), encoding="utf-8")
            plan.write_text(
                json.dumps(
                    {
                        "diff": {"before": "before.json", "after": "after.json"},
                        "address_map": {"snapshot": "after.json", "addresses": ["0x1000"]},
                    }
                ),
                encoding="utf-8",
            )

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1", "--memory-analysis", "--memory-plan", str(plan))

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            statuses = {
                item["tool_name"]: item.get("status")
                for item in payload["result"]["tool_results"]
                if item["tool_name"].startswith("memory_")
            }
            self.assertEqual(statuses["memory_snapshot"], "unavailable")
            self.assertEqual(statuses["memory_diff"], "ok")
            self.assertEqual(statuses["memory_address_map"], "ok")
            self.assertTrue((out_dir / "memory_diff.json").is_file())
            self.assertTrue((out_dir / "memory_address_map.json").is_file())

    def test_analyze_memory_plan_multistage_writes_distinct_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            before = root / "before.json"
            after = root / "after.json"
            later = root / "later.json"
            plan = root / "memory-plan.json"
            sample.write_bytes(b"MZ")
            before.write_text(json.dumps({"kind": "memory_snapshot", "modules": [], "regions": []}), encoding="utf-8")
            after.write_text(
                json.dumps({"kind": "memory_snapshot", "modules": [], "regions": [{"base_address": "0x1000", "size": 4096}]}),
                encoding="utf-8",
            )
            later.write_text(
                json.dumps({"kind": "memory_snapshot", "modules": [], "regions": [{"base_address": "0x2000", "size": 4096}]}),
                encoding="utf-8",
            )
            plan.write_text(
                json.dumps(
                    {
                        "diff": [
                            {"before": "before.json", "after": "after.json"},
                            {"before": "after.json", "after": "later.json"},
                        ],
                        "address_map": [
                            {"snapshot": "after.json", "addresses": ["0x1000"]},
                            {"snapshot": "later.json", "addresses": ["0x2000"]},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1", "--memory-plan", str(plan))

            self.assertEqual(result.returncode, 0, result.stderr)
            expected_artifacts = {
                "memory_diff_stage_1.json",
                "memory_diff_stage_2.json",
                "memory_address_map_stage_1.json",
                "memory_address_map_stage_2.json",
            }
            self.assertTrue(all((out_dir / name).is_file() for name in expected_artifacts))
            self.assertEqual(
                {
                    json.loads((out_dir / name).read_text(encoding="utf-8"))["artifacts"][0]["name"]
                    for name in expected_artifacts
                },
                expected_artifacts,
            )

    def test_analyze_memory_plan_accepts_utf8_bom_from_powershell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            before = root / "before.json"
            after = root / "after.json"
            plan = root / "memory-plan.json"
            sample.write_bytes(b"MZ")
            before.write_text(json.dumps({"kind": "memory_snapshot", "modules": [], "regions": []}), encoding="utf-8")
            after.write_text(json.dumps({"kind": "memory_snapshot", "modules": [], "regions": []}), encoding="utf-8")
            plan.write_text(
                json.dumps({"diff": {"before": "before.json", "after": "after.json"}}),
                encoding="utf-8-sig",
            )

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1", "--memory-plan", str(plan))

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            diff = next(item for item in payload["result"]["tool_results"] if item["tool_name"] == "memory_diff")
            self.assertEqual(diff["status"], "ok")
            self.assertTrue((out_dir / "memory_diff.json").is_file())

    def test_analyze_invalid_memory_plan_does_not_break_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.bin"
            out_dir = root / "analysis"
            plan = root / "invalid-plan.json"
            sample.write_bytes(b"MZ")
            plan.write_text("not json", encoding="utf-8")

            result = run_cli("analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1", "--memory-plan", str(plan))

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            memory_trace = next(item for item in payload["result"]["tool_results"] if item["tool_name"] == "memory_diff")
            self.assertEqual(memory_trace["status"], "failed")
            self.assertIn("invalid memory plan", memory_trace["error"])
            self.assertTrue((out_dir / "report.json").is_file())

    def test_experiment_memory_options_are_persisted_in_analysis_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "memory-plan.json"
            result = run_cli("experiment", "create", "sample.exe", "--workspace", tmp, "--memory-analysis", "--memory-plan", str(plan))

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["experiment"]["options"]["memory_analysis"])
            self.assertEqual(payload["experiment"]["options"]["memory_plan"], str(plan))
            self.assertIn("--memory-analysis", payload["analysis_command"])
            self.assertIn("--memory-plan", payload["analysis_command"])

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

    def test_analyze_reconstruct_emits_semantic_ir_and_static_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "semantic.bin"
            out_dir = root / "analysis"
            sample.write_text("MZ WinHttpSendRequest connect CreateFileW", encoding="utf-8")

            result = run_cli(
                "analyze",
                str(sample),
                "--out",
                str(out_dir),
                "--max-iterations",
                "3",
                "--reconstruct",
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            project_dir = Path(report["reconstruction"]["project_dir"])
            semantic_ir = report["semantic_ir"]
            verification = report["reconstruction_verification"]

            self.assertEqual(semantic_ir["schema_version"], 1)
            self.assertTrue((out_dir / "semantic_ir.json").is_file())
            self.assertTrue((project_dir / "analysis" / "semantic_ir.json").is_file())
            self.assertEqual(verification["schema_version"], 1)
            self.assertEqual(verification["status"], "ok")
            self.assertGreater(verification["score"], 0)
            self.assertTrue((project_dir / "analysis" / "reconstruction_verification.json").is_file())
            markdown = (out_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("## Semantic IR", markdown)
            self.assertIn("## Reconstruction Verification", markdown)

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

    def test_patch_binary_dry_run_and_apply_preserve_original(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "fixture.bin"
            plan = root / "patch.json"
            output = root / "patched.bin"
            artifacts = root / "patch-artifacts"
            original = b"MZ\x90\x90"
            sample.write_bytes(original)
            plan.write_text(
                json.dumps(
                    {
                        "target_sha256": __import__("hashlib").sha256(original).hexdigest(),
                        "operations": [
                            {"kind": "replace_offset", "offset": 2, "expected": "90", "replacement": "cc"}
                        ]
                    }
                ),
                encoding="utf-8",
            )

            dry_run = run_cli("patch-binary", str(sample), "--plan", str(plan), "--out", str(output))
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            self.assertEqual(json.loads(dry_run.stdout)["status"], "planned")
            self.assertFalse(output.exists())

            flags_first = run_cli("patch-binary", "--plan", str(plan), "--out", str(output), str(sample))
            self.assertEqual(flags_first.returncode, 0, flags_first.stderr)
            self.assertEqual(json.loads(flags_first.stdout)["status"], "planned")
            self.assertFalse(output.exists())

            applied = run_cli(
                "patch-binary", str(sample), "--plan", str(plan), "--out", str(output), "--apply", "--artifact-dir", str(artifacts)
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual(json.loads(applied.stdout)["status"], "ok")
            self.assertEqual(sample.read_bytes(), original)
            self.assertEqual(output.read_bytes(), b"MZ\xCC\x90")
            self.assertTrue((artifacts / "patch_manifest.json").is_file())

    def test_validate_patch_plan_and_rollback_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "fixture.bin"
            plan = root / "patch.json"
            patched = root / "patched.bin"
            restored = root / "restored.bin"
            artifacts = root / "artifacts"
            original = b"MZ\x90\x90"
            sample.write_bytes(original)
            plan.write_text(
                json.dumps(
                    {"target_sha256": __import__("hashlib").sha256(original).hexdigest(), "operations": [{"kind": "replace_offset", "offset": 2, "expected": "90", "replacement": "cc"}]}
                ),
                encoding="utf-8",
            )

            validated = run_cli("validate-patch-plan", str(sample), "--plan", str(plan))
            self.assertEqual(validated.returncode, 0, validated.stderr)
            self.assertTrue(json.loads(validated.stdout)["data"]["valid"])
            self.assertFalse(patched.exists())

            applied = run_cli("patch-binary", str(sample), "--plan", str(plan), "--out", str(patched), "--apply", "--artifact-dir", str(artifacts))
            self.assertEqual(applied.returncode, 0, applied.stderr)
            rollback = artifacts / "rollback.json"

            dry_run = run_cli("patch-binary", "rollback", str(patched), "--rollback", str(rollback), "--out", str(restored))
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            self.assertEqual(json.loads(dry_run.stdout)["status"], "planned")
            self.assertFalse(restored.exists())

            flags_first = run_cli("patch-binary", "--rollback", str(rollback), "--out", str(restored), str(patched))
            self.assertEqual(flags_first.returncode, 0, flags_first.stderr)
            self.assertEqual(json.loads(flags_first.stdout)["status"], "planned")
            self.assertFalse(restored.exists())

            rolled_back = run_cli("patch-binary", "rollback", str(patched), "--rollback", str(rollback), "--out", str(restored), "--apply")
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertEqual(restored.read_bytes(), original)
            self.assertEqual(patched.read_bytes(), b"MZ\xCC\x90")

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
