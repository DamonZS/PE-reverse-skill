import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from reverse_analyzer.cli import _run_gui_pipeline
from reverse_analyzer.config import load_config
from reverse_analyzer.report import ReportBuilder
from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.behavior_graph import build_behavior_evidence_graph
from reverse_analyzer.tools.gui import reconstruct_gui_project
from reverse_analyzer.tools.gui_state import build_gui_state_machine
from reverse_analyzer.tools.gui_xaml import extract_xaml_ui_evidence


XAML = """<Window xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"
    xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\" Title=\"Evidence UI\">
  <Grid>
    <Button x:Name=\"saveButton\" Content=\"Save\" Click=\"SaveButton_Click\" />
  </Grid>
</Window>"""


class _GuiPipelineExecutor:
    """Deterministic GUI-stage double that records the pipeline contract."""

    def __init__(self, resources: Mapping[str, Any], evidence_graph: Mapping[str, Any] | None = None) -> None:
        self.resources = dict(resources)
        self.evidence_graph = dict(evidence_graph or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def execute(self, name: str, **kwargs: Any) -> ToolResult:
        self.calls.append((name, dict(kwargs)))
        if name == "gui_fingerprint":
            return ToolResult(
                tool=name,
                status="ok",
                data={
                    "status": "ok",
                    "platform": "windows-pe",
                    "framework": "wpf",
                    "confidence": 0.96,
                    "evidence": ["WPF fixture"],
                },
            )
        if name == "gui_resource_extract":
            return ToolResult(tool=name, status="ok", data=self.resources)
        if name == "gui_xaml_extract":
            return ToolResult(
                tool=name,
                status="ok",
                data=extract_xaml_ui_evidence(kwargs["paths"], kwargs.get("out_dir")),
            )
        if name == "gui_evidence_graph":
            return ToolResult(tool=name, status="ok", data=self.evidence_graph)
        if name == "gui_state_machine":
            return ToolResult(tool=name, status="ok", data=build_gui_state_machine(**kwargs))
        if name == "gui_strategy_select":
            return ToolResult(
                tool=name,
                status="ok",
                data={
                    "status": "ok",
                    "framework": "wpf",
                    "name": "extract_baml_generate_wpf",
                    "output_stack": "wpf",
                    "confidence": 0.96,
                },
            )
        if name == "gui_behavior_graph":
            return ToolResult(tool=name, status="ok", data=build_behavior_evidence_graph(**kwargs))
        if name == "reconstruct_gui_project":
            return ToolResult(tool=name, status="ok", data={"status": "ok", "project_dir": "fixture"})
        if name == "gui_visual_regression":
            return ToolResult(tool=name, status="unavailable", data={"status": "unavailable"})
        raise AssertionError(f"unexpected GUI pipeline tool: {name}")

    def call_args(self, name: str) -> dict[str, Any]:
        calls = [kwargs for tool_name, kwargs in self.calls if tool_name == name]
        if not calls:
            raise AssertionError(f"GUI pipeline did not invoke {name}")
        return calls[-1]


def _gui_args() -> SimpleNamespace:
    return SimpleNamespace(
        gui_runtime=False,
        gui_visual=False,
        gui_screenshot_dir=None,
        gui_target="auto",
        reconstruct_gui=False,
        attach_pid=None,
        adb_path=None,
        android_serial=None,
    )


class GuiPipelineEvidenceTests(unittest.TestCase):
    def test_gui_pipeline_discovers_xaml_from_resource_manifest_or_extracted_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "fixture.exe"
            sample.write_text("not a real PE", encoding="utf-8")

            manifest_xaml = root / "manifest" / "MainWindow.xaml"
            manifest_xaml.parent.mkdir(parents=True)
            manifest_xaml.write_text(XAML, encoding="utf-8")
            manifest_asset = manifest_xaml.parent / "logo.png"
            manifest_asset.write_bytes(b"not-an-image")
            manifest_directory_without_xaml = root / "manifest-directory-without-xaml"
            manifest_directory_without_xaml.mkdir()

            fallback_xaml = root / "fallback" / "Views" / "SecondaryWindow.xaml"
            fallback_xaml.parent.mkdir(parents=True)
            fallback_xaml.write_text(XAML, encoding="utf-8")

            cases = {
                "manifest": (
                    {
                        "status": "ok",
                        "counts": {"layouts": 1},
                        "extracted_files": [str(manifest_xaml), str(manifest_asset)],
                        "extracted_dir": str(manifest_directory_without_xaml),
                    },
                    manifest_xaml,
                ),
                "directory_fallback": (
                    {
                        "status": "ok",
                        "counts": {"layouts": 1},
                        "extracted_files": [],
                        "extracted_dir": str(fallback_xaml.parents[1]),
                    },
                    fallback_xaml,
                ),
            }

            for source, (resources, expected_xaml) in cases.items():
                with self.subTest(source=source):
                    executor = _GuiPipelineExecutor(resources)
                    tool_results: list[dict[str, Any]] = []
                    _run_gui_pipeline(
                        executor,
                        tool_results,
                        SimpleNamespace(tool_results=[]),
                        None,
                        None,
                        sample,
                        root / f"out-{source}",
                        _gui_args(),
                        load_config(root),
                    )

                    xaml_args = executor.call_args("gui_xaml_extract")
                    self.assertIn("paths", xaml_args)
                    raw_paths = xaml_args["paths"]
                    values = [raw_paths] if isinstance(raw_paths, (str, Path)) else list(raw_paths)
                    self.assertEqual({Path(value).resolve() for value in values}, {expected_xaml.resolve()})

    def test_gui_pipeline_preserves_xaml_evidence_graph_for_strategy_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "fixture.exe"
            sample.write_text("not a real PE", encoding="utf-8")
            xaml_path = root / "resources" / "MainWindow.xaml"
            xaml_path.parent.mkdir(parents=True)
            xaml_path.write_text(XAML, encoding="utf-8")
            evidence_graph = {
                "status": "ok",
                "version": 1,
                "framework": "wpf",
                "nodes": [
                    {
                        "id": "saveButton",
                        "type": "Button",
                        "text": "Save",
                        "event_handlers": {"Click": "SaveButton_Click"},
                    }
                ],
                "edges": [],
                "source_summary": {"xaml_node_count": 3},
                "graph_token": "preserve-through-strategy",
            }
            executor = _GuiPipelineExecutor(
                {
                    "status": "ok",
                    "counts": {"layouts": 1},
                    "extracted_files": [str(xaml_path)],
                    "extracted_dir": str(xaml_path.parent),
                },
                evidence_graph,
            )
            tool_results: list[dict[str, Any]] = []
            session = SimpleNamespace(session_id="gui-evidence", target=str(sample), status="running", artifacts=[])

            _run_gui_pipeline(
                executor,
                tool_results,
                SimpleNamespace(tool_results=[]),
                session,
                None,
                sample,
                root / "out",
                _gui_args(),
                load_config(root),
            )

            graph_args = executor.call_args("gui_evidence_graph")
            strategy_args = executor.call_args("gui_strategy_select")
            self.assertGreater(graph_args["xaml_evidence"]["node_count"], 0)
            self.assertEqual(strategy_args["evidence_graph"]["graph_token"], "preserve-through-strategy")

            report = ReportBuilder(session, tool_results).build()
            gui_analysis = report["gui_analysis"]
            self.assertGreater(gui_analysis["xaml_evidence"]["node_count"], 0)
            self.assertEqual(gui_analysis["evidence_graph"]["graph_token"], "preserve-through-strategy")

    def test_gui_reconstruction_writes_xaml_and_evidence_graph_analysis_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "fixture.exe"
            sample.write_text("not a real PE", encoding="utf-8")
            xaml_evidence = {
                "status": "ok",
                "source": "xaml",
                "node_count": 1,
                "nodes": [{"id": "saveButton", "type": "Button", "text": "Save"}],
            }
            evidence_graph = {
                "status": "ok",
                "version": 1,
                "nodes": [{"id": "saveButton", "type": "Button", "text": "Save"}],
                "edges": [],
                "source_summary": {"xaml_node_count": 1},
            }

            result = reconstruct_gui_project(
                sample,
                root / "out",
                {
                    "framework": "wpf",
                    "strategy": {"name": "extract_baml_generate_wpf", "output_stack": "wpf"},
                    "xaml_evidence": xaml_evidence,
                    "evidence_graph": evidence_graph,
                },
            )

            analysis_dir = Path(result["project_dir"]) / "analysis"
            xaml_artifact = analysis_dir / "xaml_evidence.json"
            graph_artifact = analysis_dir / "evidence_graph.json"
            self.assertTrue(xaml_artifact.is_file())
            self.assertTrue(graph_artifact.is_file())
            self.assertEqual(json.loads(xaml_artifact.read_text(encoding="utf-8")), xaml_evidence)
            self.assertEqual(json.loads(graph_artifact.read_text(encoding="utf-8")), evidence_graph)


if __name__ == "__main__":
    unittest.main()
