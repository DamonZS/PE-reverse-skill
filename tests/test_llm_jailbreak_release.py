import json
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer import __version__
from reverse_analyzer.llm_jailbreak.cli import build_parser, main
from reverse_analyzer.llm_jailbreak import instruction_assets
from reverse_analyzer.llm_jailbreak.instruction_assets import (
    list_instruction_profiles,
    load_instruction_bundle,
)
from reverse_analyzer.llm_jailbreak.release import (
    verify_release_manifest,
    write_release_manifest,
)
from reverse_analyzer.llm_jailbreak.models import Campaign, CampaignValidationError


class ReleaseCliTests(unittest.TestCase):
    def _write_release_fixture(self, root: Path) -> None:
        for name, content in (
            (f"reverse_analyzer-{__version__}-py3-none-any.whl", "wheel"),
            ("CHANGELOG.md", "changelog"),
            ("RELEASE_NOTES.md", "release notes"),
            ("jailbreak-campaign.schema.json", "{}"),
            ("jailbreak-campaign.example.json", "{}"),
            ("reverse_jailbreak_release.md", "release"),
            ("smoke_release.py", "print('ok')"),
        ):
            (root / name).write_text(content, encoding="utf-8")

    def test_build_metadata_uses_runtime_version_source(self):
        pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        self.assertIn('dynamic = ["version"]', pyproject)
        self.assertIn(
            'version = {attr = "reverse_analyzer._version.__version__"}',
            pyproject,
        )
        self.assertRegex(__version__, re.compile(r"^\d+\.\d+\.\d+"))

    def test_release_workflows_separate_package_and_manual_live_acceptance(self):
        root = Path(__file__).parents[1]
        package_workflow = (
            root / ".github/workflows/reverse-jailbreak-release.yml"
        ).read_text(encoding="utf-8")
        live_workflow = (
            root / ".github/workflows/reverse-jailbreak-live-e2e.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("pull_request:", package_workflow)
        self.assertIn("smoke_release.py", package_workflow)
        self.assertIn("workflow_dispatch:", live_workflow)
        self.assertNotIn("pull_request:", live_workflow)
        self.assertNotIn("\n  push:", live_workflow)
        self.assertIn("environment: llm-jailbreak-live", live_workflow)
        self.assertIn("secrets.MODEL_API_KEY", live_workflow)
        self.assertIn("tests.e2e.test_llm_jailbreak_live", live_workflow)
        self.assertIn("actions/upload-artifact", live_workflow)

    def test_release_commands_are_registered(self):
        parser = build_parser()
        commands = {
            parser.parse_args(arguments).command
            for arguments in (
                [
                    "doctor",
                    "--base-url",
                    "http://127.0.0.1/v1",
                    "--model",
                    "fixture",
                ],
                ["profiles"],
                ["strategies"],
                ["validate", "campaign.json"],
                ["run", "campaign.json"],
                ["resume", "campaign.json"],
                ["report", "out"],
                ["promote", "out"],
                ["benchmark", "campaign.json"],
                ["release-verify", "dist"],
            )
        }
        self.assertEqual(
            commands,
            {
                "doctor",
                "profiles",
                "strategies",
                "validate",
                "run",
                "resume",
                "report",
                "promote",
                "benchmark",
                "release-verify",
            },
        )

    def test_campaign_schema_matches_strict_message_and_scoring_contracts(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/jailbreak-campaign.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = schema["properties"]
        self.assertFalse(properties["messages"]["items"]["additionalProperties"])
        self.assertEqual(
            properties["messages"]["items"]["required"], ["role", "content"]
        )
        scoring = properties["scoring"]
        self.assertFalse(scoring["additionalProperties"])
        self.assertEqual(scoring["properties"]["threshold"]["maximum"], 1)

    def test_campaign_schema_matches_loader_defaults_and_model_judge_condition(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "schemas/jailbreak-campaign.schema.json").read_text(
                encoding="utf-8"
            )
        )
        minimal = {"objective": "fixture", "max_context_turns": 0}
        self.assertEqual(schema["required"], ["objective"])
        self.assertEqual(schema["properties"]["max_context_turns"]["minimum"], 0)
        self.assertEqual(
            schema["allOf"][0]["then"]["properties"]["judge_model"]["minLength"],
            1,
        )
        Campaign.from_dict(minimal)

        invalid = {"objective": "fixture", "semantic_judge": "model"}
        with self.assertRaises(CampaignValidationError):
            Campaign.from_dict(invalid)

    def test_cli_reports_runtime_version(self):
        output = StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(output):
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertEqual(
            output.getvalue().strip(),
            f"python -m reverse_analyzer.llm_jailbreak {__version__}",
        )

    def test_report_reads_directory_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.json").write_text(
                json.dumps({"llm_jailbreak_analysis": {"status": "ok", "success": True}}),
                encoding="utf-8",
            )
            self.assertEqual(main(["report", str(root), "--json"]), 0)

    def test_packaged_instruction_assets_work_without_repository_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch(
                "reverse_analyzer.llm_jailbreak.instruction_assets._REPOSITORY_ROOT",
                Path(directory) / "missing-checkout",
            ):
                for profile in list_instruction_profiles():
                    bundle = load_instruction_bundle(profile)
                    self.assertGreater(len(bundle.assets), 0, profile)
                    self.assertTrue(bundle.digest, profile)

    def test_packaged_instruction_assets_match_repository_sources(self):
        sources = {
            asset.path
            for profile in instruction_assets._BUILTIN_PROFILES.values()
            for asset in profile.assets
        }
        for source in sources:
            with self.subTest(source=source.as_posix()):
                self.assertEqual(
                    (instruction_assets._PACKAGED_ASSET_ROOT / source).read_bytes(),
                    (instruction_assets._REPOSITORY_ROOT / source).read_bytes(),
                )

    def test_release_manifest_detects_modification_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            manifest = write_release_manifest(root)
            self.assertEqual(manifest["product_version"], __version__)
            self.assertTrue(verify_release_manifest(root)["ok"])

            (root / "jailbreak-campaign.schema.json").write_text("changed", encoding="utf-8")
            (root / "unexpected.txt").write_text("extra", encoding="utf-8")
            result = verify_release_manifest(root)
            self.assertFalse(result["ok"])
            self.assertTrue(any("sha256 mismatch" in error for error in result["errors"]))
            self.assertTrue(any("untracked release file" in error for error in result["errors"]))

    def test_release_manifest_rejects_malformed_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "release-manifest.json").write_text("[]", encoding="utf-8")

            result = verify_release_manifest(root)

            self.assertFalse(result["ok"])
            self.assertIn("release manifest root must be an object", result["errors"])

    def test_release_manifest_rejects_path_escape_and_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            payload = dict(write_release_manifest(root))
            payload["files"] = list(payload["files"])
            payload["files"].append(dict(payload["files"][0]))
            payload["files"].append(
                {"path": "../outside.txt", "size": 0, "sha256": "0" * 64}
            )
            (root / "release-manifest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )

            result = verify_release_manifest(root)

            self.assertFalse(result["ok"])
            self.assertTrue(any("duplicate path" in error for error in result["errors"]))
            self.assertTrue(
                any("escapes release directory" in error for error in result["errors"])
            )

    def test_release_manifest_rejects_version_drift_and_multiple_wheels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            payload = dict(write_release_manifest(root))
            payload["product_version"] = "999.0.0"
            (root / "release-manifest.json").write_text(
                json.dumps(payload), encoding="utf-8"
            )
            result = verify_release_manifest(root)
            self.assertFalse(result["ok"])
            self.assertTrue(any("product_version" in error for error in result["errors"]))

            (root / "reverse_analyzer-999.0.0-py3-none-any.whl").write_text(
                "other wheel", encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "exactly one wheel"):
                write_release_manifest(root)


if __name__ == "__main__":
    unittest.main()
