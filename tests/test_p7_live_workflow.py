from __future__ import annotations

from pathlib import Path
import unittest


class P7LiveWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_manual_and_covers_registered_fixtures(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github/workflows/p7-live.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("workflow_dispatch:", workflow)
        for fixture in (
            "p7-vlm-openai-live",
            "p7-windows-uia-live",
            "p7-graphics-combined-live",
        ):
            self.assertIn(fixture, workflow)
        self.assertIn("environment accept run", workflow)
        self.assertIn("environment accept verify", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)
        self.assertIn("P7_VLM_API_KEY", workflow)
        self.assertIn("P7_VLM_BASE_URL", workflow)


if __name__ == "__main__":
    unittest.main()
