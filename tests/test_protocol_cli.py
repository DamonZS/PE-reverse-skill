import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["REVERSE_ANALYZER_WORKSPACE"] = str(workspace)
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class ProtocolCliTests(unittest.TestCase):
    def test_commands_run_complete_evidence_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            source = root / "messages.json"
            source.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "flow_id": "tcp:fixture",
                                "transport": "tcp",
                                "direction": "a_to_b",
                                "payload_base64": base64.b64encode(b'{"request":"status"}').decode("ascii"),
                            },
                            {
                                "flow_id": "tcp:fixture",
                                "transport": "tcp",
                                "direction": "b_to_a",
                                "payload_base64": base64.b64encode(b'{"response":"ok"}').decode("ascii"),
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            for command in ("capture", "infer", "summarize"):
                with self.subTest(command=command):
                    out_dir = root / command
                    completed = run_cli(
                        workspace,
                        "protocol",
                        command,
                        str(source),
                        "--out",
                        str(out_dir),
                        "--format",
                        "json",
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

                    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
                    self.assertIn("protocol_analysis", report)
                    self.assertIn(report["protocol_analysis"]["status"], {"ok", "partial"})
                    self.assertTrue((out_dir / "report.md").is_file())
                    self.assertTrue((out_dir / "protocol" / "capture.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "flows.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "field_stats.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "inference.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "summary.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "semantic_ir_fragment.json").is_file())
                    self.assertTrue((out_dir / "protocol" / "messages" / "message-0001.json").is_file())
                    self.assertTrue((out_dir / "semantic_ir.json").is_file())
                    self.assertTrue((out_dir / "evidence_graph.json").is_file())

                    manifest = json.loads((out_dir / "evidence-manifest.json").read_text(encoding="utf-8"))
                    covered = {str(item.get("path")) for item in manifest.get("artifacts") or []}
                    self.assertIn("protocol/capture.json", covered)
                    self.assertIn("protocol/messages/message-0001.json", covered)
                    self.assertIn("semantic_ir.json", covered)
                    self.assertIn("evidence_graph.json", covered)

    def test_missing_source_is_reported_as_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "analysis"
            missing = root / "missing.pcap"
            completed = run_cli(
                root / "workspace",
                "protocol",
                "capture",
                str(missing),
                "--out",
                str(out_dir),
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["protocol_analysis"]["status"], "unavailable")
            self.assertTrue((out_dir / "protocol" / "messages" / "index.json").is_file())
            self.assertTrue((out_dir / "evidence-manifest.json").is_file())

    def test_protocol_help_lists_all_commands_and_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "workspace"
            group_help = run_cli(workspace, "protocol", "--help")
            self.assertEqual(group_help.returncode, 0, group_help.stderr)
            for command in ("capture", "infer", "summarize"):
                self.assertIn(command, group_help.stdout)

            command_help = run_cli(workspace, "protocol", "infer", "--help")
            self.assertEqual(command_help.returncode, 0, command_help.stderr)
            for option in ("--format", "--max-bytes", "--max-packets", "--max-messages", "--max-message-bytes"):
                self.assertIn(option, command_help.stdout)

            tools = run_cli(workspace, "list-tools", "--json")
            self.assertEqual(tools.returncode, 0, tools.stderr)
            names = {item["name"] for item in json.loads(tools.stdout)}
            self.assertTrue(
                {"protocol_capture", "protocol_infer", "protocol_summarize", "protocol_analyze"}.issubset(names)
            )


if __name__ == "__main__":
    unittest.main()
