from __future__ import annotations

import io
import json
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from typing import Any
from unittest.mock import Mock, patch

from reverse_analyzer import cli
from reverse_analyzer.dashboard import build_dashboard
from reverse_analyzer.report.builder import ReportBuilder
from reverse_analyzer.tools.executor import ToolResult


class _FakeLoopResult:
    def __init__(self) -> None:
        self.tool_results: list[dict[str, Any]] = []
        self.stopped_reason = "final_answer"

    def to_dict(self) -> dict[str, Any]:
        return {
            "final_answer": "fixture complete",
            "iterations": 0,
            "stopped_reason": self.stopped_reason,
            "tool_results": list(self.tool_results),
            "provider_messages": [],
            "barrier": False,
        }


class _FakeAgentLoop:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def run(self, *_args: Any, **_kwargs: Any) -> _FakeLoopResult:
        return _FakeLoopResult()


class _FakeReportBuilder:
    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    def build(self) -> dict[str, Any]:
        return {}

    def to_markdown(self) -> str:
        return "# Fixture report\n"


class SourceRuntimeCliIntegrationTests(unittest.TestCase):
    def test_analyze_forwards_runtime_validation_spec_to_reconstruct_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, out_dir, spec_path = self._fixture_paths(root)

            reconstruct_args = self._run_cli_and_capture_reconstruction(
                root,
                [
                    "analyze",
                    str(sample),
                    "--out",
                    str(out_dir),
                    "--max-iterations",
                    "1",
                    "--reconstruct",
                    "--runtime-validation-spec",
                    str(spec_path),
                ],
            )

            self.assertEqual(reconstruct_args["runtime_validation_spec"], str(spec_path))

    def test_source_reconstruct_alias_preserves_runtime_validation_spec_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, out_dir, spec_path = self._fixture_paths(root)

            reconstruct_args = self._run_cli_and_capture_reconstruction(
                root,
                [
                    "source",
                    "reconstruct",
                    str(sample),
                    "--out",
                    str(out_dir),
                    "--runtime-validation-spec",
                    str(spec_path),
                ],
            )

            self.assertEqual(reconstruct_args["runtime_validation_spec"], str(spec_path))

    def test_analyze_forwards_behavior_validation_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, out_dir, spec_path = self._fixture_paths(root)
            original_dir = root / "original"
            original_dir.mkdir()

            reconstruct_args = self._run_cli_and_capture_reconstruction(
                root,
                [
                    "analyze",
                    str(sample),
                    "--out",
                    str(out_dir),
                    "--max-iterations",
                    "1",
                    "--reconstruct",
                    "--behavior-validation-spec",
                    str(spec_path),
                    "--behavior-original-dir",
                    str(original_dir),
                ],
            )

            self.assertEqual(reconstruct_args["behavior_validation_spec"], str(spec_path))
            self.assertEqual(reconstruct_args["behavior_original_dir"], str(original_dir))

    def test_source_reconstruct_alias_forwards_behavior_validation_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample, out_dir, spec_path = self._fixture_paths(root)
            original_dir = root / "original"
            original_dir.mkdir()

            reconstruct_args = self._run_cli_and_capture_reconstruction(
                root,
                [
                    "source",
                    "reconstruct",
                    str(sample),
                    "--out",
                    str(out_dir),
                    "--behavior-validation-spec",
                    str(spec_path),
                    "--behavior-original-dir",
                    str(original_dir),
                ],
            )

            self.assertEqual(reconstruct_args["behavior_validation_spec"], str(spec_path))
            self.assertEqual(reconstruct_args["behavior_original_dir"], str(original_dir))

    def _run_cli_and_capture_reconstruction(
        self,
        root: Path,
        argv: list[str],
    ) -> dict[str, Any]:
        class RecordingToolExecutor:
            instance: RecordingToolExecutor | None = None

            def __init__(self, *_args: Any, **_kwargs: Any) -> None:
                type(self).instance = self
                self.execute = Mock(side_effect=self._execute)

            @staticmethod
            def _execute(name: str, **kwargs: Any) -> ToolResult:
                if name == "reconstruct_project":
                    project_dir = Path(kwargs["out_dir"]) / "reconstructed_fixture"
                    project_dir.mkdir(parents=True, exist_ok=True)
                    return ToolResult(
                        tool=name,
                        status="ok",
                        data={
                            "status": "ok",
                            "project_dir": str(project_dir),
                            "artifacts": [],
                            "reconstruction_plan": {"status": "planned", "tasks": []},
                        },
                    )
                if name == "reconstruction_verify":
                    return ToolResult(
                        tool=name,
                        status="ok",
                        data={"status": "passed", "score": 1.0, "artifacts": []},
                    )
                return ToolResult(tool=name, status="ok", data={"status": "ok", "artifacts": []})

        symbols = {
            "ToolExecutor": RecordingToolExecutor,
            "ReportBuilder": _FakeReportBuilder,
            "AgentLoop": _FakeAgentLoop,
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        config = SimpleNamespace(knowledge_dir=root / "knowledge")

        with ExitStack() as stack:
            stack.enter_context(patch.object(cli, "load_config", return_value=config))
            stack.enter_context(patch.object(cli, "ensure_runtime_dirs"))
            stack.enter_context(patch.object(cli, "_load_symbol", side_effect=symbols.__getitem__))
            stack.enter_context(patch.object(cli, "TraceLogger", None))
            stack.enter_context(patch.object(cli, "SessionStore", None))
            stack.enter_context(patch.object(cli, "RuleBasedProvider", None))
            stack.enter_context(patch.object(cli, "register_builtin_tools", None))
            stack.enter_context(patch.object(cli, "_run_engine_analysis", return_value=[]))
            stack.enter_context(patch.object(cli, "_run_android_analysis", return_value=[]))
            stack.enter_context(patch.object(cli, "_run_ios_analysis", return_value=[]))
            stack.enter_context(patch.object(cli, "_run_protocol_analysis", return_value=[]))
            stack.enter_context(patch.object(cli, "_run_behavior_graph", return_value=[]))
            stack.enter_context(patch.object(cli, "_run_semantic_ir", return_value=({}, [])))
            stack.enter_context(patch.object(cli, "_write_evidence_manifest", return_value=None))
            stack.enter_context(patch.object(cli, "_finalize_platform_core_artifacts", return_value={}))
            stack.enter_context(patch.object(cli, "_persist_knowledge"))
            with redirect_stdout(stdout), redirect_stderr(stderr):
                try:
                    exit_code = cli.main(argv)
                except SystemExit as error:
                    self.fail(
                        f"CLI rejected the runtime validation option with exit {error.code}: "
                        f"{stderr.getvalue()}"
                    )

        self.assertEqual(exit_code, 0, stderr.getvalue() or stdout.getvalue())
        executor = RecordingToolExecutor.instance
        self.assertIsNotNone(executor)
        assert executor is not None
        reconstruct_calls = [
            item
            for item in executor.execute.call_args_list
            if item.args and item.args[0] == "reconstruct_project"
        ]
        self.assertEqual(reconstruct_calls.__len__(), 1, executor.execute.call_args_list)
        return dict(reconstruct_calls[0].kwargs)

    @staticmethod
    def _fixture_paths(root: Path) -> tuple[Path, Path, Path]:
        sample = root / "fixture.bin"
        out_dir = root / "analysis"
        spec_path = root / "runtime-validation.json"
        sample.write_bytes(b"MZ fixture")
        spec_path.write_text(
            json.dumps(
                {
                    "behavior": {
                        "argv": ["fixture-runtime", "--smoke"],
                        "expected_exit_code": 0,
                    }
                }
            ),
            encoding="utf-8",
        )
        return sample, out_dir, spec_path


class SourceRuntimeReportIntegrationTests(unittest.TestCase):
    def test_report_json_exposes_source_runtime_validation_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_artifact = root / "reconstructed_fixture" / "source" / "runtime_validation.json"
            payload = _runtime_reconstruction_payload(runtime_artifact)
            report_path = root / "report.json"
            report_path.write_text(
                _report_builder(payload).to_json(),
                encoding="utf-8",
            )

            source = json.loads(report_path.read_text(encoding="utf-8"))["source_reconstruction"]

            self.assertEqual(source["runtime_validation_status"], "passed")
            self.assertEqual(
                source["runtime_validation_confidence"],
                {"score": 0.93, "level": "high", "basis": ["2 runtime steps passed"]},
            )
            self.assertEqual(source["runtime_validation_artifact"], str(runtime_artifact))
            self.assertIs(source["behavior_equivalent"], False)

    def test_report_markdown_renders_source_runtime_validation_contract(self) -> None:
        runtime_artifact = Path("reconstructed_fixture/source/runtime_validation.json")
        markdown = _report_builder(_runtime_reconstruction_payload(runtime_artifact)).to_markdown()

        self.assertIn("- **Runtime Validation Status:** passed", markdown)
        self.assertIn("- **Runtime Validation Confidence:** 0.93", markdown)
        self.assertIn(f"- **Runtime Validation Artifact:** {runtime_artifact}", markdown)
        self.assertIn("- **Behavior Equivalent:** no", markdown)


class SourceRuntimeDashboardIntegrationTests(unittest.TestCase):
    def test_dashboard_source_metrics_expose_runtime_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            runtime_artifact = workspace / "output" / "source" / "runtime_validation.json"
            runtime_artifact.parent.mkdir(parents=True, exist_ok=True)
            runtime_artifact.write_text("{}\n", encoding="utf-8")
            report_path = workspace / "output" / "report.json"
            report_path.write_text(
                json.dumps(
                    {
                        "sample": {"name": "fixture.bin"},
                        "source_reconstruction": _runtime_reconstruction_payload(runtime_artifact),
                    }
                ),
                encoding="utf-8",
            )

            dashboard = build_dashboard(workspace, out_dir=workspace / "dashboard")
            source_view = dashboard["analysis_views"]["source"]
            metrics = {item["label"]: item["value"] for item in source_view["metrics"]}

            self.assertEqual(metrics["Runtime validation"], "passed")
            self.assertEqual(metrics["Runtime confidence"], 0.93)
            self.assertIs(metrics["Behavior equivalent"], False)


class SourceRuntimeTruthIntegrationTests(unittest.TestCase):
    def test_static_or_empty_validation_cannot_claim_behavior_equivalence(self) -> None:
        cases = {
            "static-validation-only": {
                "validation": {
                    "status": "passed",
                    "level": "syntax",
                    "behavior_equivalent": True,
                },
                "validation_status": "passed",
                "behavior_equivalent": True,
            },
            "empty-runtime-validation": {
                "runtime_validation": {},
                "runtime_validation_status": None,
                "runtime_validation_confidence": {},
                "runtime_validation_artifact": None,
                "behavior_equivalent": True,
            },
        }

        for name, validation_fields in cases.items():
            with self.subTest(name=name):
                payload = {
                    "status": "ok",
                    "project_dir": f"reconstructed_{name}",
                    "artifacts": [],
                    **validation_fields,
                }
                source = _report_builder(payload).build()["source_reconstruction"]

                self.assertIs(source["behavior_equivalent"], False)
                self.assertIsNone(source["runtime_validation_status"])


def _runtime_reconstruction_payload(runtime_artifact: Path) -> dict[str, Any]:
    confidence = {
        "score": 0.93,
        "level": "high",
        "basis": ["2 runtime steps passed"],
    }
    return {
        "status": "ok",
        "project_dir": str(runtime_artifact.parent.parent),
        "language": "c",
        "output_stack": "c-native",
        "function_count": 3,
        "module_count": 2,
        "runtime_validation_status": "passed",
        "runtime_validation_confidence": confidence,
        "runtime_validation_artifact": str(runtime_artifact),
        "runtime_validation_provenance": {
            "validator": {"name": "reverse_analyzer.source.runtime_validation"}
        },
        "behavior_equivalent": False,
        "artifacts": [
            {
                "name": "source/runtime_validation.json",
                "path": str(runtime_artifact),
                "kind": "source_runtime_validation",
                "role": "validation_evidence",
                "status": "passed",
                "confidence": confidence["score"],
                "behavior_equivalent": False,
            }
        ],
    }


def _report_builder(reconstruction_payload: dict[str, Any]) -> ReportBuilder:
    session = SimpleNamespace(
        session_id="source-runtime-platform-fixture",
        target="fixture.bin",
        status="succeeded",
        artifacts=[],
    )
    tool_results = [
        {
            "tool_name": "reconstruct_project",
            "status": "ok",
            "result": ToolResult(
                tool="reconstruct_project",
                status="ok",
                data=reconstruction_payload,
            ).to_dict(),
        }
    ]
    return ReportBuilder(session, tool_results)


if __name__ == "__main__":
    unittest.main()
