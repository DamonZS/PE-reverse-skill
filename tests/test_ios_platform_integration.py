from __future__ import annotations

import io
import json
import os
import plistlib
import struct
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

from reverse_analyzer import cli
from reverse_analyzer.core.integration import finalize_platform_core
from reverse_analyzer.dashboard import build_dashboard
from reverse_analyzer.tools.ios import ios_analyze


BUNDLE_ID = "com.example.integration"
APP_ROOT = "Payload/Sample.app"


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


class IosPlatformIntegrationTests(unittest.TestCase):
    def test_ios_analyze_alias_runs_pipeline_and_writes_ios_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample.ipa"
            out_dir = root / "out"
            _write_minimal_ipa(sample)

            exit_code, stdout, stderr = _run_ios_cli(root, sample, out_dir)

            self.assertEqual(exit_code, 0, stderr)
            cli_payload = json.loads(stdout)
            tool_names = [
                item.get("tool_name")
                for item in cli_payload["result"]["tool_results"]
                if isinstance(item, dict)
            ]
            self.assertIn("ios_analyze", tool_names)

            report_path = out_dir / "report.json"
            markdown_path = out_dir / "report.md"
            self.assertTrue(report_path.is_file())
            self.assertTrue(markdown_path.is_file())

            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertIn("ios_analysis", report)
            self.assertEqual(report["ios_analysis"]["status"], "ok")
            self.assertEqual(
                report["ios_analysis"]["manifest"]["bundle_identifier"],
                BUNDLE_ID,
            )
            self.assertIn("## iOS Analysis", markdown_path.read_text(encoding="utf-8"))

    def test_platform_core_absorbs_ios_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample.ipa"
            out_dir = root / "platform-core"
            _write_minimal_ipa(sample)
            ios_analysis = ios_analyze(sample)
            report_data = {
                "sample_name": sample.name,
                "ios_analysis": ios_analysis,
            }

            finalize_platform_core(
                report_data,
                str(out_dir),
                sample_path=str(sample),
            )

            semantic_ir = _load_json(out_dir / "semantic_ir.json")
            evidence_graph = _load_json(out_dir / "evidence_graph.json")

            self.assertEqual(
                semantic_ir["ios"]["manifest"]["bundle_identifier"],
                BUNDLE_ID,
            )
            ios_fragment = semantic_ir["ios"]["semantic_ir_fragment"]
            expected_fragment = ios_analysis["semantic_ir_fragment"]
            self.assertEqual(ios_fragment["source"], "ios_analyze")
            self.assertEqual(ios_fragment["status"], expected_fragment["status"])
            self.assertEqual(
                ios_fragment["schema_version"],
                expected_fragment["schema_version"],
            )
            self.assertEqual(ios_fragment["entities"], expected_fragment["entities"])
            self.assertEqual(semantic_ir["summary"]["domain_statuses"]["ios"], "ok")
            ios_nodes = [
                node
                for node in evidence_graph["nodes"]
                if node.get("node_type") == "ios_analysis"
            ]
            self.assertEqual(len(ios_nodes), 1)
            self.assertEqual(ios_nodes[0]["properties"]["status"], "ok")

    def test_dashboard_analysis_views_include_ios(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            sample = workspace / "sample.ipa"
            report_dir = workspace / "analysis"
            report_dir.mkdir()
            _write_minimal_ipa(sample)
            ios_analysis = ios_analyze(sample)
            (report_dir / "report.json").write_text(
                json.dumps(
                    {
                        "sample": {"name": sample.name, "path": str(sample)},
                        "ios_analysis": ios_analysis,
                    }
                ),
                encoding="utf-8",
            )

            data = build_dashboard(workspace, out_dir=workspace / "dashboard")

            self.assertIn("ios", data["analysis_views"])
            ios_view = data["analysis_views"]["ios"]
            self.assertEqual(ios_view["domain"], "ios")
            self.assertEqual(ios_view["section"], "ios_analysis")
            self.assertEqual(ios_view["status"], "ok")
            self.assertTrue(ios_view["available"])

    def test_ios_cli_does_not_report_success_for_non_ipa(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = root / "sample.txt"
            out_dir = root / "out"
            sample.write_text("not an IPA", encoding="utf-8")

            exit_code, stdout, _stderr = _run_ios_cli(root, sample, out_dir)

            self.assertNotEqual(exit_code, 0)
            cli_payload = json.loads(stdout)
            self.assertEqual(cli_payload["status"], "failed")
            self.assertTrue(cli_payload["analysis_outcome"]["hard_failure"])
            failed_names = {
                item["name"]
                for item in cli_payload["analysis_outcome"]["failed_stages"]
            }
            self.assertIn("ios_analyze", failed_names)

            ios_analysis = _load_json(out_dir / "report.json")["ios_analysis"]
            self.assertEqual(ios_analysis["status"], "failed")
            self.assertEqual(ios_analysis["package_type"], "unknown")
            self.assertIn("not an IPA", ios_analysis["error"])


def _run_ios_cli(
    root: Path,
    sample: Path,
    out_dir: Path,
) -> tuple[int, str, str]:
    original_load_symbol = cli._load_symbol

    def load_symbol(symbol: str) -> Any:
        if symbol == "AgentLoop":
            return _AgentLoop
        return original_load_symbol(symbol)

    environment = {
        "REVERSE_ANALYZER_WORKSPACE": str(root / "workspace"),
        "REVERSE_ANALYZER_KNOWLEDGE_DIR": str(root / "workspace" / "knowledge"),
        "REVERSE_ANALYZER_SESSIONS_DIR": str(root / "workspace" / "sessions"),
        "REVERSE_ANALYZER_REPORTS_DIR": str(root / "workspace" / "reports"),
    }
    stdout = io.StringIO()
    stderr = io.StringIO()
    with (
        patch.dict(os.environ, environment, clear=False),
        patch.object(cli, "_load_symbol", side_effect=load_symbol),
        patch.object(cli, "_run_engine_analysis", return_value=[]),
        patch.object(cli, "_run_android_analysis", return_value=[]),
        patch.object(cli, "_run_protocol_analysis", return_value=[]),
        patch.object(cli, "_run_behavior_graph", return_value=[]),
        patch.object(
            cli,
            "_run_semantic_ir",
            return_value=(
                {
                    "tool": "semantic_ir_build",
                    "status": "ok",
                    "data": {"status": "unavailable"},
                },
                [],
            ),
        ),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        exit_code = cli.main(
            ["ios", "analyze", str(sample), "--out", str(out_dir)]
        )
    return exit_code, stdout.getvalue(), stderr.getvalue()


def _write_minimal_ipa(path: Path) -> None:
    info_plist = plistlib.dumps(
        {
            "CFBundleDisplayName": "Sample",
            "CFBundleExecutable": "Sample",
            "CFBundleIdentifier": BUNDLE_ID,
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1",
            "MinimumOSVersion": "15.0",
            "UIMainStoryboardFile": "Main",
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(f"{APP_ROOT}/Info.plist", info_plist)
        archive.writestr(f"{APP_ROOT}/Sample", _minimal_arm64_macho())
        archive.writestr(
            f"{APP_ROOT}/Base.lproj/Main.storyboardc/Info.plist",
            b"compiled storyboard",
        )


def _minimal_arm64_macho() -> bytes:
    encryption_info = struct.pack("<IIIIII", 0x2C, 24, 0x1000, 0x2000, 0, 0)
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        1,
        len(encryption_info),
        0,
        0,
    )
    return header + encryption_info


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
