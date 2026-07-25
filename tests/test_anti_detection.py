import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools import anti_detection_analyze
from reverse_analyzer.tools.static_tools import register_builtin_tools


class AntiDetectionAnalysisTests(unittest.TestCase):
    def test_detects_anti_analysis_indicators_with_defensive_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"MZ\0IsDebuggerPresent\0QueryPerformanceCounter\0VMware\0Process32Next")
            result = anti_detection_analyze(sample)
            self.assertEqual(result["status"], "ok")
            self.assertTrue(result["anti_analysis_likely"])
            self.assertIn("debugger", result["category_counts"])
            self.assertEqual(result["analysis_scope"], "defensive_detection_only")
            self.assertIn("No evasion", result["safety_boundary"])

    def test_tool_is_registered(self) -> None:
        self.assertIn("anti_detection_analyze", register_builtin_tools().tools)


if __name__ == "__main__":
    unittest.main()
