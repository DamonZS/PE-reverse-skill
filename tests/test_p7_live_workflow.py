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

    def test_workflow_isolates_records_per_run_and_verifies_fixture_specific_paths(self) -> None:
        workflow = (Path(__file__).parents[1] / ".github/workflows/p7-live.yml").read_text(
            encoding="utf-8"
        )
        for evidence_root, fixture, separator in (
            ("p7-vlm-evidence", "p7-vlm-openai-live", "/"),
            ("p7-uia-evidence", "p7-windows-uia-live", "\\"),
            ("p7-graphics-evidence", "p7-graphics-combined-live", "\\"),
        ):
            self.assertIn(
                f"{evidence_root}{separator}${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}",
                workflow,
            )
            self.assertIn(f"{fixture}--*.json", workflow)

        # A broad records/*.json glob can verify a stale or different fixture
        # on a persistent self-hosted runner.
        self.assertNotIn("acceptance/records/*.json", workflow)
        self.assertNotIn("Select-Object -First 1", workflow)
        self.assertIn("expected exactly one UIA acceptance record", workflow)
        self.assertIn("expected exactly one graphics acceptance record", workflow)
        for evidence_root in ("p7-vlm-evidence", "p7-uia-evidence", "p7-graphics-evidence"):
            self.assertIn(
                f"path: {evidence_root}/${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}",
                workflow,
            )


if __name__ == "__main__":
    unittest.main()
