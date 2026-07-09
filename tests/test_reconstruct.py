import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.reconstruct import reconstruct_project


class ReconstructProjectTests(unittest.TestCase):
    def test_minimal_input_generates_stub_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "sample.exe"
            sample.write_bytes(b"MZ")

            result = reconstruct_project(sample, root / "out")
            project_dir = Path(result["project_dir"])

            self.assertEqual(result["status"], "ok")
            self.assertTrue(project_dir.is_dir())
            self.assertTrue((project_dir / "CMakeLists.txt").is_file())
            self.assertTrue((project_dir / "src" / "main.c").is_file())
            self.assertTrue((project_dir / "src" / "functions.c").is_file())
            self.assertTrue((project_dir / "include" / "imports.h").is_file())
            self.assertTrue((project_dir / "analysis" / "summary.json").is_file())
            self.assertTrue((project_dir / "README.md").is_file())
            self.assertIn(str(project_dir / "README.md"), result["generated_files"])

            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["stub_only"])
            self.assertEqual(summary["function_count"], 0)

    def test_analysis_functions_and_imports_populate_stub_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "specimen.bin"
            sample.write_bytes(b"MZ")
            analysis = {
                "functions": [
                    {"name": "entry", "entry": "00401000", "signature": "int entry(void)"},
                    {"name": "helper-routine"},
                ],
                "imports": [
                    {
                        "dll": "KERNEL32.dll",
                        "functions": [{"name": "LoadLibraryA"}, {"name": "GetProcAddress"}],
                    }
                ],
                "summary": {"function_count": 2, "source": "test"},
            }

            result = reconstruct_project(sample, root / "out", analysis=analysis)
            project_dir = Path(result["project_dir"])
            functions_c = (project_dir / "src" / "functions.c").read_text(encoding="utf-8")
            imports_h = (project_dir / "include" / "imports.h").read_text(encoding="utf-8")
            summary = json.loads((project_dir / "analysis" / "summary.json").read_text(encoding="utf-8"))

            self.assertIn("int entry(void)", functions_c)
            self.assertIn("original symbol: helper-routine", functions_c)
            self.assertIn("metadata: entry=00401000, signature=int entry(void)", functions_c)
            self.assertIn("Library: KERNEL32.dll", imports_h)
            self.assertIn("LoadLibraryA", imports_h)
            self.assertIn("GetProcAddress", imports_h)
            self.assertEqual(summary["analysis_summary"]["source"], "test")

    def test_returns_artifacts_list_for_generated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "artifact.exe"
            sample.write_bytes(b"MZ")

            result = reconstruct_project(sample, root / "out")

            self.assertIsInstance(result["artifacts"], list)
            self.assertEqual(len(result["artifacts"]), 6)
            self.assertTrue(any(item["name"] == "src/functions.c" for item in result["artifacts"]))
            self.assertTrue(any(item["kind"] == "analysis" for item in result["artifacts"]))


if __name__ == "__main__":
    unittest.main()
