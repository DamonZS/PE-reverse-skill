from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.platform_catalog import build_platform_catalog


ROOT = Path(__file__).resolve().parents[1]


class PlatformCatalogTests(unittest.TestCase):
    def test_catalog_exposes_master_first_routing_summary(self) -> None:
        payload = build_platform_catalog(ROOT)

        self.assertEqual(payload["routing"]["status"], "ready")
        self.assertIn("protection-review", payload["routing"]["skill_ids"])
        self.assertEqual(payload["routing"]["master_skill"]["path"], "SKILL.md")

    def test_cli_exposes_catalog_and_separate_integration_metric(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "reverse_analyzer", "platform", "audit"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["integration"]["catalog_coverage_percent"], 100.0)
        self.assertIn("live acceptance", payload["integration"]["meaning"])

    def test_catalog_unifies_registered_and_checked_in_assets_without_execution(self) -> None:
        with patch("reverse_analyzer.tools.executor.ToolExecutor.execute") as execute:
            payload = build_platform_catalog(ROOT)

        execute.assert_not_called()
        self.assertGreater(payload["summary"]["skill_total"], 0)
        self.assertGreater(payload["summary"]["tool_total"], 0)
        self.assertGreater(payload["summary"]["provider_total"], 0)
        self.assertGreater(payload["summary"]["script_total"], 0)
        self.assertGreater(payload["summary"]["github_tool_total"], 0)
        self.assertEqual(payload["integration"]["catalog_coverage_percent"], 100.0)
        self.assertIn("does not authorize or execute", payload["execution_boundary"])
        self.assertIn("hash", {item["id"] for item in payload["tools"]})
        self.assertIn("ghidra", {item["id"] for item in payload["github_tools"]})
        self.assertTrue(all(item["execution_boundary"] == "file_inventory_only" for item in payload["scripts"]))
        self.assertTrue(all(item["classification"] for item in payload["scripts"]))
        json.dumps(payload)

    def test_missing_optional_catalog_directories_are_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = build_platform_catalog(temporary)

        self.assertEqual(payload["skills"], [])
        self.assertEqual(payload["scripts"], [])
        self.assertEqual(payload["github_tools"], [])
        self.assertGreater(payload["summary"]["tool_total"], 0)
        self.assertGreater(payload["summary"]["provider_total"], 0)

if __name__ == "__main__":
    unittest.main()
