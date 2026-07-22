import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from reverse_analyzer.llm_jailbreak.campaign import load_campaign
from reverse_analyzer.llm_jailbreak.cli import main
from reverse_analyzer.llm_jailbreak.templates import TEMPLATE_FILES, initialize_workspace


ROOT = Path(__file__).parents[1]


class JailbreakTemplateTests(unittest.TestCase):
    def test_installed_release_smoke_exercises_init_command(self):
        smoke = (ROOT / "scripts" / "smoke_reverse_jailbreak_release.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('str(executable), "init", str(initialized), "--json"', smoke)

    def test_packaged_templates_match_canonical_release_assets(self):
        packaged = ROOT / "reverse_analyzer" / "llm_jailbreak" / "templates"
        canonical = {
            "jailbreak-campaign.example.json": ROOT / "config" / "jailbreak-campaign.example.json",
            "jailbreak-campaign.schema.json": ROOT / "schemas" / "jailbreak-campaign.schema.json",
        }
        self.assertEqual(set(TEMPLATE_FILES), set(canonical))
        for name, source in canonical.items():
            self.assertEqual((packaged / name).read_bytes(), source.read_bytes(), name)

    def test_initialize_workspace_writes_loadable_campaign_and_digests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "workspace"
            payload = initialize_workspace(root)

            self.assertEqual([item["path"] for item in payload["files"]], list(TEMPLATE_FILES))
            self.assertTrue(all(len(item["sha256"]) == 64 for item in payload["files"]))
            campaign = load_campaign(root / "jailbreak-campaign.example.json")
            self.assertEqual(campaign.id, "fixture-campaign")
            schema = json.loads((root / "jailbreak-campaign.schema.json").read_text())
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_initialize_workspace_is_fail_closed_unless_force_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            initialize_workspace(root)
            campaign = root / "jailbreak-campaign.example.json"
            campaign.write_text("user content", encoding="utf-8")

            with self.assertRaisesRegex(FileExistsError, "refusing to overwrite"):
                initialize_workspace(root)
            self.assertEqual(campaign.read_text(encoding="utf-8"), "user content")

            initialize_workspace(root, force=True)
            self.assertEqual(load_campaign(campaign).id, "fixture-campaign")

    def test_cli_init_supports_machine_readable_output(self):
        with tempfile.TemporaryDirectory() as directory:
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["init", directory, "--json"])
            self.assertEqual(exit_code, 0, stderr.getvalue())
            payload = json.loads(stdout.getvalue())
            self.assertEqual(len(payload["files"]), 2)


if __name__ == "__main__":
    unittest.main()
