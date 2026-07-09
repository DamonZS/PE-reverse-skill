import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

from reverse_analyzer.tools.ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide


class GhidraToolTests(unittest.TestCase):
    def test_install_guide_mentions_required_steps(self):
        guide = ghidra_install_guide()
        self.assertEqual(guide["status"], "guide")
        self.assertIn("winget install EclipseAdoptium.Temurin.21.JDK", guide["guide"])
        self.assertIn("GHIDRA_HEADLESS", guide["guide"])
        self.assertIn("github.com/NationalSecurityAgency/ghidra", guide["guide"])

    def test_check_uses_ghidra_headless_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            headless = Path(tmp) / "analyzeHeadless.bat"
            headless.write_text("echo ghidra", encoding="utf-8")
            with patch.dict(os.environ, {"GHIDRA_HEADLESS": str(headless)}, clear=True):
                result = ghidra_check()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["headless_path"], str(headless))

    def test_check_uses_ghidra_home_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            support = Path(tmp) / "support"
            support.mkdir()
            headless = support / "analyzeHeadless.bat"
            headless.write_text("echo ghidra", encoding="utf-8")
            with patch.dict(os.environ, {"GHIDRA_HOME": tmp}, clear=True):
                result = ghidra_check()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["headless_path"], str(headless))

    def test_decompile_unavailable_returns_setup_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.bin"
            sample.write_bytes(b"MZ test")
            with patch.dict(os.environ, {}, clear=True):
                result = ghidra_decompile(sample, Path(tmp) / "out", ghidra_home=Path(tmp) / "missing")
        self.assertEqual(result.status, "unavailable")
        self.assertIn("--install-guide ghidra", result.data["setup_hint"])

    def test_decompile_runs_headless_and_collects_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")
            ghidra_home = root / "ghidra"
            support = ghidra_home / "support"
            support.mkdir(parents=True)
            headless = support / "analyzeHeadless.bat"
            headless.write_text("echo ghidra", encoding="utf-8")
            out_root = root / "analysis"

            def fake_run(command, **kwargs):
                ghidra_out = out_root / "decompiled" / "ghidra"
                (ghidra_out / "pseudocode").mkdir(parents=True, exist_ok=True)
                (ghidra_out / "disassembly").mkdir(parents=True, exist_ok=True)
                (ghidra_out / "functions.json").write_text(
                    '[{"name":"entry","entry":"00401000"}]', encoding="utf-8"
                )
                (ghidra_out / "call_graph.json").write_text('{"nodes":[],"edges":[]}', encoding="utf-8")
                (ghidra_out / "summary.json").write_text('{"function_count":1}', encoding="utf-8")
                (ghidra_out / "pseudocode" / "fn_00401000.c").write_text("void entry() {}", encoding="utf-8")
                return CompletedProcess(command, 0, stdout="ok", stderr="")

            with patch("reverse_analyzer.tools.ghidra.subprocess.run", side_effect=fake_run) as run:
                result = ghidra_decompile(sample, out_root, ghidra_home=ghidra_home, timeout=12)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["function_count"], 1)
        self.assertTrue(any(item["name"] == "functions.json" for item in result["artifacts"]))
        self.assertTrue(any(item["kind"] == "pseudocode" for item in result["artifacts"]))
        command = run.call_args.args[0]
        self.assertEqual(command[0], str(headless))
        self.assertIn("-postScript", command)
        self.assertIn("ExportDecompiler.py", command)


if __name__ == "__main__":
    unittest.main()
