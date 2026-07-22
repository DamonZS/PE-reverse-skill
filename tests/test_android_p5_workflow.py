"""Regression checks for the manual Android P5 acceptance workflow."""

from pathlib import Path
import unittest


class AndroidP5WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (
            Path(__file__).parents[1] / ".github" / "workflows" / "android-p5-live.yml"
        ).read_text(encoding="utf-8")

    def test_workflow_is_manual_and_self_hosted(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("runs-on: [self-hosted, linux, android-p5]", self.workflow)
        self.assertNotIn("  push:", self.workflow)
        self.assertNotIn("  schedule:", self.workflow)

    def test_all_registered_fixtures_are_selectable_and_verified(self) -> None:
        fixtures = (
            "p5-android-jadx-live",
            "p5-android-rebuild-sign-live",
            "p5-android-frida-live",
            "p5-android-native-patch-live",
        )
        for fixture in fixtures:
            self.assertIn(fixture, self.workflow)
        self.assertIn("environment accept run", self.workflow)
        self.assertIn("environment accept verify", self.workflow)
        self.assertIn("actions/upload-artifact@v4", self.workflow)

    def test_secrets_are_environment_only(self) -> None:
        self.assertIn("environment: android-p5-live", self.workflow)
        self.assertIn("secrets.ANDROID_P5_KS_PASS", self.workflow)
        self.assertIn("secrets.ANDROID_P5_KEY_PASS", self.workflow)
        self.assertNotIn("ANDROID_P5_KS_PASS: ", self.workflow.replace(
            "ANDROID_P5_KS_PASS: ${{ secrets.ANDROID_P5_KS_PASS }}", ""
        ))


if __name__ == "__main__":
    unittest.main()
