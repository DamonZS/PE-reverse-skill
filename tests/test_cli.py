import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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

    def test_list_tools_reports_scaffolded_runtime(self) -> None:
        result = run_cli("list-tools")
        self.assertEqual(result.returncode, 0, result.stderr)
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
            self.assertEqual(tool_names, ["file_info", "hash", "strings_extract"])
            self.assertNotIn("tool not registered", result.stdout)

    def test_install_guide_ghidra(self) -> None:
        result = run_cli("--install-guide", "ghidra")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ghidra Headless installation guide", result.stdout)
        self.assertIn("GHIDRA_HEADLESS", result.stdout)

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
