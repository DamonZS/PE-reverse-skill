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

    def test_prerequisites_are_scoped_to_selected_fixture(self) -> None:
        self.assertIn('case "$P5_FIXTURE" in', self.workflow)
        self.assertIn('test -n "${ANDROID_JADX_LIVE_APK:-}"', self.workflow)
        self.assertIn('test -n "${ANDROID_REBUILD_LIVE_KEYSTORE:-}"', self.workflow)
        self.assertIn('test -n "${ANDROID_FRIDA_LIVE_PACKAGE:-}"', self.workflow)
        self.assertIn('test -n "${ANDROID_NATIVE_PATCH_LIVE_SPEC:-}"', self.workflow)

        native_patch = self.workflow.split("p5-android-native-patch-live)", 1)[1]
        native_patch = native_patch.split(";;", 1)[0]
        self.assertIn("adb version", native_patch)
        self.assertIn("adb devices", native_patch)

        before_case = self.workflow.split('case "$P5_FIXTURE" in', 1)[0]
        self.assertNotIn("adb version", before_case)
        self.assertNotIn("adb devices", before_case)


if __name__ == "__main__":
    unittest.main()
