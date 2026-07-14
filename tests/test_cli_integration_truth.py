from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

from reverse_analyzer import cli
from reverse_analyzer.tools.executor import ToolExecutor, ToolResult
from tests.test_patch_planner import TEXT_OFFSET, _minimal_pe32


ROOT = Path(__file__).resolve().parents[1]


def run_cli(
    workspace: Path,
    *args: str,
    timeout: int = 90,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["REVERSE_ANALYZER_WORKSPACE"] = str(workspace)
    environment["REVERSE_ANALYZER_KNOWLEDGE_DIR"] = str(workspace / "knowledge")
    environment["REVERSE_ANALYZER_SESSIONS_DIR"] = str(workspace / "sessions")
    environment["REVERSE_ANALYZER_REPORTS_DIR"] = str(workspace / "reports")
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class _AnalysisResult:
    def __init__(self) -> None:
        self.tool_results: list[dict[str, Any]] = []
        self.stopped_reason = "final_answer"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_results": list(self.tool_results),
            "stopped_reason": self.stopped_reason,
        }


class _AgentLoop:
    def __init__(self, **_: Any) -> None:
        self.result = _AnalysisResult()
        self.tool_results = self.result.tool_results

    def run(self, *_: Any, **__: Any) -> _AnalysisResult:
        return self.result


class CliIntegrationTruthTests(unittest.TestCase):
    def test_memory_cli_normalizes_scan_write_and_protection_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured: list[Any] = []

            def capture(forwarded: Any) -> int:
                captured.append(forwarded)
                return 0

            commands = (
                (
                    ("memory", "scan", "--pid", "42", "--out", str(root / "ascii"), "--pattern", "AB", "--pattern-type", "ascii"),
                    {"pattern": "41 42"},
                ),
                (
                    ("memory", "scan", "--pid", "42", "--out", str(root / "utf16"), "--pattern", "AB", "--pattern-type", "utf16"),
                    {"pattern": "41 00 42 00"},
                ),
                (
                    (
                        "memory",
                        "scan",
                        "--pid",
                        "42",
                        "--out",
                        str(root / "pointer"),
                        "--pattern",
                        "0x1234",
                        "--pattern-type",
                        "pointer",
                        "--pointer-size",
                        "4",
                    ),
                    {"pattern": "34 12 00 00"},
                ),
                (
                    (
                        "memory",
                        "write",
                        "--pid",
                        "42",
                        "--out",
                        str(root / "write"),
                        "--address",
                        "0x1000",
                        "--data",
                        "A\u00a9",
                        "--encoding",
                        "utf8",
                        "--expected",
                        "00 00 00",
                    ),
                    {"data": "41 C2 A9", "encoding": "utf8"},
                ),
                (
                    ("memory", "alloc", "--pid", "42", "--out", str(root / "alloc"), "--size", "16"),
                    {"protection": "PAGE_READWRITE"},
                ),
                (
                    (
                        "memory",
                        "protect",
                        "--pid",
                        "42",
                        "--out",
                        str(root / "protect"),
                        "--address",
                        "0x1000",
                        "--size",
                        "4",
                        "--protection",
                        "rx",
                        "--expected-protection",
                        "rw",
                    ),
                    {
                        "protection": "PAGE_EXECUTE_READ",
                        "expected_protection": "PAGE_READWRITE",
                    },
                ),
            )

            with patch.object(cli, "capability_run_command", side_effect=capture):
                for arguments, expected in commands:
                    with self.subTest(arguments=arguments):
                        self.assertEqual(cli.main(list(arguments)), 0)
                        params = cli._parse_capability_params(captured[-1].param)
                        for name, value in expected.items():
                            self.assertEqual(params[name], value)

    def test_memory_cli_rejects_pointer_values_outside_selected_width(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stderr = io.StringIO()
            with patch.object(cli, "capability_run_command") as execute, redirect_stderr(stderr):
                exit_code = cli.main(
                    [
                        "memory",
                        "scan",
                        "--pid",
                        "42",
                        "--out",
                        str(Path(temporary) / "out"),
                        "--pattern",
                        "0x100000000",
                        "--pattern-type",
                        "pointer",
                        "--pointer-size",
                        "4",
                    ]
                )

            self.assertEqual(exit_code, 2)
            execute.assert_not_called()
            self.assertIn("does not fit in 4 bytes", stderr.getvalue())

    def test_hook_cli_loads_bom_plan_and_converts_duration_to_milliseconds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / "hook-plan.json"
            plan.write_text(
                json.dumps({"hooks": [{"module": "kernel32.dll", "export": "CreateFileW"}]}),
                encoding="utf-8-sig",
            )
            captured: list[Any] = []

            def capture(forwarded: Any) -> int:
                captured.append(forwarded)
                return 17

            with patch.object(cli, "capability_run_command", side_effect=capture):
                exit_code = cli.main(
                    [
                        "memory",
                        "hook-trace",
                        "--pid",
                        "43210",
                        "--out",
                        str(root / "out"),
                        "--plan",
                        str(plan),
                        "--duration",
                        "1.25",
                        "--backend",
                        "frida",
                    ]
                )

            self.assertEqual(exit_code, 17)
            self.assertEqual(len(captured), 1)
            forwarded = captured[0]
            params = cli._parse_capability_params(forwarded.param)
            self.assertEqual(forwarded.capability, "hook_runtime")
            self.assertEqual(forwarded.action, "hook-trace")
            self.assertEqual(forwarded.provider, "frida_hook_runtime")
            self.assertEqual(params["duration_ms"], 1250)
            self.assertEqual(params["requested_backend"], "frida")
            self.assertEqual(
                params["hook_specification"],
                {"hooks": [{"module": "kernel32.dll", "export": "CreateFileW"}]},
            )

    def test_hook_cli_rejects_malformed_or_non_object_plans_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures = {
                "malformed.json": "{not-json",
                "array.json": "[]",
            }
            for name, content in fixtures.items():
                with self.subTest(name=name):
                    plan = root / name
                    plan.write_text(content, encoding="utf-8")
                    stderr = io.StringIO()
                    with patch.object(cli, "capability_run_command") as execute, redirect_stderr(stderr):
                        exit_code = cli.main(
                            [
                                "memory",
                                "hook-trace",
                                "--pid",
                                "43210",
                                "--out",
                                str(root / name.replace(".json", "-out")),
                                "--plan",
                                str(plan),
                            ]
                        )
                    self.assertEqual(exit_code, 2)
                    execute.assert_not_called()
                    self.assertIn("error:", stderr.getvalue())

    def test_win32_hook_backend_fails_with_its_requested_provider_and_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            out_dir = root / "hook-output"
            plan = root / "hook-plan.json"
            plan.write_text(json.dumps({"hooks": []}), encoding="utf-8")

            completed = run_cli(
                workspace,
                "memory",
                "hook-trace",
                "--pid",
                "43210",
                "--out",
                str(out_dir),
                "--plan",
                str(plan),
                "--duration",
                "0.25",
                "--backend",
                "win32",
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["provider"], "win32_hook_runtime")
            self.assertEqual(payload["result"]["provider"], "win32_hook_runtime")
            self.assertIn(payload["result"]["status"], {"failed", "unavailable"})
            self.assertEqual(payload["result"]["provenance"]["failure"]["phase"], "resolve")
            self.assertNotEqual(payload["result"]["provider"], "frida_hook_runtime")

            audit = load_json(out_dir / "capabilities" / "hook_runtime_hook-trace_audit.json")
            self.assertEqual(audit["provider"], "win32_hook_runtime")
            self.assertIn(audit["status"], {"failed", "unavailable"})
            session = load_json(out_dir / "sessions" / f"{payload['session_id']}.json")
            self.assertIn(session["status"], {"failed", "skipped"})

    def _analysis_environment(self, workspace: Path) -> dict[str, str]:
        return {
            "REVERSE_ANALYZER_WORKSPACE": str(workspace),
            "REVERSE_ANALYZER_KNOWLEDGE_DIR": str(workspace / "knowledge"),
            "REVERSE_ANALYZER_SESSIONS_DIR": str(workspace / "sessions"),
            "REVERSE_ANALYZER_REPORTS_DIR": str(workspace / "reports"),
        }

    @staticmethod
    def _stage(status: str, tool_name: str):
        def run(
            _executor: Any,
            tool_results: list[dict[str, Any]],
            result: Any,
            session: Any,
            session_store: Any,
            _sample: Path,
            _out_dir: Path,
        ) -> list[str]:
            cli._append_observation(
                tool_results,
                result,
                session,
                session_store,
                tool_name,
                {},
                {
                    "tool": tool_name,
                    "status": "ok",
                    "data": {"status": status, "artifacts": []},
                },
            )
            return []

        return run

    def _run_analysis(
        self,
        root: Path,
        *,
        name: str,
        engine: str,
        android: str,
        protocol: str,
        reconstruct_status: str | None = None,
    ) -> tuple[int, dict[str, Any], dict[str, Any], dict[str, Any]]:
        workspace = root / f"{name}-workspace"
        sample = root / f"{name}.bin"
        out_dir = root / f"{name}-output"
        sample.write_bytes(b"MZ deterministic CLI aggregation fixture")
        original_load_symbol = cli._load_symbol

        def load_symbol(symbol: str) -> Any:
            if symbol == "AgentLoop":
                return _AgentLoop
            return original_load_symbol(symbol)

        original_execute = ToolExecutor.execute

        def execute(executor: ToolExecutor, tool_name: str, **kwargs: Any) -> ToolResult:
            if tool_name == "reconstruct_project" and reconstruct_status is not None:
                return ToolResult(
                    tool=tool_name,
                    status="ok",
                    data={"status": reconstruct_status, "artifacts": []},
                )
            return original_execute(executor, tool_name, **kwargs)

        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = ["analyze", str(sample), "--out", str(out_dir), "--max-iterations", "1"]
        if reconstruct_status is not None:
            arguments.append("--reconstruct")
        with (
            patch.dict(os.environ, self._analysis_environment(workspace), clear=False),
            patch.object(cli, "_load_symbol", side_effect=load_symbol),
            patch.object(cli, "_run_engine_analysis", side_effect=self._stage(engine, "engine_analyze")),
            patch.object(cli, "_run_android_analysis", side_effect=self._stage(android, "android_analyze")),
            patch.object(cli, "_run_protocol_analysis", side_effect=self._stage(protocol, "protocol_analyze")),
            patch.object(cli, "_run_behavior_graph", return_value=[]),
            patch.object(
                cli,
                "_run_semantic_ir",
                return_value=(
                    {"tool": "semantic_ir_build", "status": "ok", "data": {"status": "ok"}},
                    [],
                ),
            ),
            patch.object(ToolExecutor, "execute", new=execute),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = cli.main(arguments)

        payload = json.loads(stdout.getvalue())
        report = load_json(out_dir / "report.json")
        session = load_json(out_dir / "sessions" / f"{payload['session_id']}.json")
        return exit_code, payload, report, session

    def test_analyze_nested_failure_updates_task_session_report_and_exit_code(self) -> None:
        self.assertEqual(
            cli._result_status({"status": "ok", "data": {"status": "cleanup_failed"}}),
            "cleanup_failed",
        )
        with tempfile.TemporaryDirectory() as temporary:
            exit_code, payload, report, session = self._run_analysis(
                Path(temporary),
                name="failed-engine",
                engine="failed",
                android="unavailable",
                protocol="unavailable",
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["status"], "failed")
        self.assertTrue(payload["analysis_outcome"]["hard_failure"])
        self.assertEqual(report["analysis_outcome"]["status"], "failed")
        self.assertEqual(session["status"], "failed")
        self.assertEqual(session["metadata"]["analysis_outcome"]["status"], "failed")
        tasks = {item["name"]: item for item in session["flows"][0]["tasks"]}
        self.assertEqual(tasks["analyze"]["status"], "failed")

    def test_analyze_optional_unavailable_succeeds_and_partial_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unavailable = self._run_analysis(
                root,
                name="all-unavailable",
                engine="unavailable",
                android="unavailable",
                protocol="unavailable",
            )
            partial = self._run_analysis(
                root,
                name="partial-engine",
                engine="partial",
                android="unavailable",
                protocol="unavailable",
            )

        unavailable_code, unavailable_payload, unavailable_report, unavailable_session = unavailable
        self.assertEqual(unavailable_code, 0)
        self.assertEqual(unavailable_payload["status"], "succeeded")
        self.assertEqual(unavailable_report["analysis_outcome"]["status"], "succeeded")
        self.assertEqual(unavailable_session["status"], "succeeded")
        self.assertEqual(len(unavailable_payload["analysis_outcome"]["optional_unavailable_stages"]), 3)

        partial_code, partial_payload, partial_report, partial_session = partial
        self.assertEqual(partial_code, 0)
        self.assertEqual(partial_payload["status"], "partial")
        self.assertTrue(partial_payload["analysis_outcome"]["partial"])
        self.assertEqual(partial_report["analysis_outcome"]["status"], "partial")
        self.assertEqual(partial_session["metadata"]["analysis_outcome"]["status"], "partial")

    def test_requested_source_reconstruction_unavailable_is_a_hard_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            exit_code, payload, report, session = self._run_analysis(
                Path(temporary),
                name="source-unavailable",
                engine="unavailable",
                android="unavailable",
                protocol="unavailable",
                reconstruct_status="unavailable",
            )

        self.assertEqual(exit_code, 2)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(report["analysis_outcome"]["status"], "failed")
        failed_names = {item["name"] for item in payload["analysis_outcome"]["failed_stages"]}
        self.assertIn("reconstruct_project", failed_names)
        self.assertEqual(session["status"], "failed")

    def test_protocol_missing_required_source_returns_nonzero_and_persists_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out_dir = root / "protocol-output"
            completed = run_cli(
                root / "workspace",
                "protocol",
                "capture",
                str(root / "missing.pcap"),
                "--out",
                str(out_dir),
            )

            self.assertEqual(completed.returncode, 2, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["status"], "failed")
            self.assertTrue(payload["protocol_outcome"]["hard_failure"])
            report = load_json(out_dir / "report.json")
            self.assertEqual(report["protocol_outcome"]["status"], "failed")
            session = load_json(out_dir / "sessions" / f"{payload['session_id']}.json")
            self.assertEqual(session["status"], "failed")
            self.assertEqual(session["metadata"]["protocol_outcome"]["status"], "failed")
            tasks = {item["name"]: item for item in session["flows"][0]["tasks"]}
            self.assertEqual(tasks["analyze"]["status"], "failed")

    def test_mock_capability_lifecycle_is_recorded_as_unavailable_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            sample = root / "sample.bin"
            out_dir = root / "capability-output"
            sample.write_bytes(b"MZ mock lifecycle classification fixture")

            completed = run_cli(
                workspace,
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

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["result"]["status"], "mocked")
            session = load_json(out_dir / "sessions" / f"{payload['session_id']}.json")
            knowledge_metadata = session["metadata"]["capability_knowledge"]
            self.assertEqual(knowledge_metadata["status"], "recorded")
            self.assertEqual(knowledge_metadata["lifecycle_status"], "mocked")

            outcomes = load_json(workspace / "knowledge" / "capability_outcomes.json")
            bucket = outcomes["capabilities"]["memory_runtime"]["providers"]["mock"]["actions"]["scan"][
                "target_kinds"
            ]["sample"]
            self.assertEqual(bucket["runs"], 1)
            self.assertEqual(bucket["last_status"], "mocked")
            self.assertEqual(bucket["unavailable"], 1)
            self.assertEqual(bucket["successes"], 0)
            self.assertEqual(bucket["success_rate"], 0.0)

    def test_pe_patch_commands_emit_capability_session_manifest_report_and_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            sample = root / "sample.exe"
            patch_dir = root / "patch"
            patched = root / "patched.exe"
            restored = root / "restored.exe"
            sample.write_bytes(_minimal_pe32())
            original = sample.read_bytes()

            commands = (
                (
                    "plan",
                    "plan",
                    (
                        "patch",
                        "plan",
                        str(sample),
                        "--out",
                        str(patch_dir),
                        "--offset",
                        hex(TEXT_OFFSET),
                        "--replacement",
                        "90",
                    ),
                ),
                (
                    "verify",
                    "validate",
                    (
                        "patch",
                        "verify",
                        str(sample),
                        "--plan",
                        str(patch_dir / "plan.json"),
                        "--out",
                        str(patch_dir),
                    ),
                ),
                (
                    "apply",
                    "apply",
                    (
                        "patch",
                        "apply",
                        str(sample),
                        "--plan",
                        str(patch_dir / "plan.json"),
                        "--out",
                        str(patched),
                    ),
                ),
                (
                    "rollback",
                    "rollback",
                    (
                        "patch",
                        "rollback",
                        str(patched),
                        "--plan",
                        str(patch_dir / "rollback_plan.json"),
                        "--out",
                        str(restored),
                    ),
                ),
            )

            for command_name, capability_action, arguments in commands:
                with self.subTest(command=command_name):
                    completed = run_cli(workspace, *arguments)
                    self.assertEqual(
                        completed.returncode,
                        0,
                        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
                    )
                    payload = json.loads(completed.stdout)
                    self.assertTrue(payload["session_id"])
                    self.assertEqual(payload["provider"], "local_verified_patch")
                    self.assertEqual(payload["action"], capability_action)
                    self.assertTrue(payload["result"]["dashboard_trace"])
                    self.assertTrue((patch_dir / "report.json").is_file())
                    self.assertTrue((patch_dir / "report.md").is_file())
                    self.assertTrue((patch_dir / "evidence-manifest.json").is_file())
                    self.assertTrue((patch_dir / "sessions" / f"{payload['session_id']}.json").is_file())
                    audit_path = patch_dir / "capabilities" / f"patch_executor_{capability_action}_audit.json"
                    self.assertTrue(audit_path.is_file())
                    audit = load_json(audit_path)
                    self.assertEqual(audit["session_id"], payload["session_id"])
                    self.assertTrue(audit["dashboard_trace"])
                    report = load_json(patch_dir / "report.json")
                    self.assertEqual(report["patch_analysis"]["session_id"], payload["session_id"])
                    self.assertTrue(report["patch_analysis"]["dashboard_trace"])

            self.assertEqual(sample.read_bytes(), original)
            self.assertNotEqual(patched.read_bytes(), original)
            self.assertEqual(patched.read_bytes()[TEXT_OFFSET], 0x90)
            self.assertEqual(restored.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
