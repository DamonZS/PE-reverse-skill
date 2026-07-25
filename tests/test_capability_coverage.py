import json
import subprocess
import sys
import unittest
from pathlib import Path

from reverse_analyzer.coverage import audit_capability_coverage


ROOT = Path(__file__).resolve().parents[1]


class CapabilityCoverageTests(unittest.TestCase):
    def test_matrix_audit_is_machine_readable_and_honest(self) -> None:
        payload = audit_capability_coverage(ROOT / "docs" / "skill_parity_matrix.md")
        self.assertGreaterEqual(payload["capability_count"], 40)
        self.assertEqual(payload["status"], "incomplete")
        self.assertGreater(payload["unresolved_count"], 0)
        self.assertEqual(payload["counts"]["missing"], 0)
        self.assertTrue(all(item["acceptance_command"] for item in payload["unresolved"]))

    def test_cli_exposes_coverage_audit(self) -> None:
        completed = subprocess.run([sys.executable, "-m", "reverse_analyzer", "coverage", "--only-unresolved"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(len(payload["capabilities"]), payload["unresolved_count"])


if __name__ == "__main__":
    unittest.main()
