from __future__ import annotations

from pathlib import Path
import re
import unittest


WORKFLOW = (
    Path(__file__).resolve().parents[1]
    / ".github"
    / "workflows"
    / "reverse-jailbreak-live-e2e.yml"
)


class LiveWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_periodic_execution_is_explicitly_opt_in(self) -> None:
        self.assertRegex(
            self.source,
            r"(?m)^\s+schedule:\s*$[\s\S]*?cron:\s*[\"']17 3 1 \* \*",
        )
        self.assertIn("vars.LLM_JAILBREAK_PERIODIC_ENABLED == '1'", self.source)
        self.assertIn("github.event_name == 'workflow_dispatch'", self.source)

    def test_schedule_uses_repository_configuration_and_environment_secret(self) -> None:
        self.assertIn(
            "inputs.base_url || vars.LLM_JAILBREAK_E2E_BASE_URL", self.source
        )
        self.assertIn("inputs.model || vars.LLM_JAILBREAK_E2E_MODEL", self.source)
        self.assertIn("MODEL_API_KEY: ${{ secrets.MODEL_API_KEY }}", self.source)
        for name in (
            "LLM_JAILBREAK_E2E_BASE_URL",
            "LLM_JAILBREAK_E2E_MODEL",
            "MODEL_API_KEY",
        ):
            self.assertRegex(self.source, rf'test -n "\${re.escape(name)}"')

    def test_retained_evidence_is_promoted_and_uploaded_on_failure(self) -> None:
        self.assertIn("tests.e2e.test_llm_jailbreak_live", self.source)
        self.assertIn("assert d.get('status') == 'passed'", self.source)
        self.assertIn("if: always()", self.source)
        self.assertIn("path: retained-evidence", self.source)
        self.assertIn("retention-days: 30", self.source)


if __name__ == "__main__":
    unittest.main()
