import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.tools.procmon import procmon_check, procmon_install_guide, _category_for_operation, _parse_csv


class ProcmonToolTests(unittest.TestCase):
    def test_procmon_check_gracefully_reports_missing_binary(self):
        with patch("shutil.which", return_value=None):
            result = procmon_check()
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("--install-guide procmon", result["install_guide"])

    def test_install_guide_references_sysinternals(self):
        guide = procmon_install_guide()
        self.assertEqual(guide["status"], "guide")
        self.assertIn("Sysinternals", guide["guide"])
        self.assertIn("dynamic-backend procmon", guide["guide"])

    def test_parse_csv_counts_operations_and_categories(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["Process Name", "Operation", "Path", "Result", "Detail"])
                writer.writeheader()
                writer.writerow({"Process Name": "sample.exe", "Operation": "CreateFile", "Path": "C:/tmp/a", "Result": "SUCCESS", "Detail": ""})
                writer.writerow({"Process Name": "sample.exe", "Operation": "RegSetValue", "Path": "HKCU/Run", "Result": "SUCCESS", "Detail": ""})
                writer.writerow({"Process Name": "other.exe", "Operation": "TCP Connect", "Path": "1.2.3.4:443", "Result": "SUCCESS", "Detail": ""})

            parsed = _parse_csv(path, sample_name="sample.exe")
            self.assertEqual(parsed["event_count"], 2)
            self.assertEqual(parsed["operation_counts"]["CreateFile"], 1)
            self.assertEqual(parsed["category_counts"]["file"], 1)
            self.assertEqual(parsed["category_counts"]["registry"], 1)
            self.assertEqual(parsed["top_paths"][0]["path"], "C:/tmp/a")

    def test_category_for_operation(self):
        self.assertEqual(_category_for_operation("TCP Connect"), "network")
        self.assertEqual(_category_for_operation("Process Create"), "process")
        self.assertEqual(_category_for_operation("RegOpenKey"), "registry")
        self.assertEqual(_category_for_operation("CreateFile"), "file")


if __name__ == "__main__":
    unittest.main()
