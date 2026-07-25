import json
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

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
    write_release_sbom,
)
from reverse_analyzer.llm_jailbreak.models import Campaign, CampaignValidationError
from scripts.smoke_reverse_jailbreak_release import _load_verified_manifest, _run


class ReleaseCliTests(unittest.TestCase):
    def _write_release_fixture(self, root: Path) -> None:
        for name, content in (
            ("CHANGELOG.md", "changelog"),
            ("RELEASE_NOTES.md", "release notes"),
            ("jailbreak-campaign.schema.json", "{}"),
            ("jailbreak-campaign.example.json", "{}"),
            ("reverse_jailbreak_release.md", "release"),
            ("smoke_release.py", "print('ok')"),
        ):
            (root / name).write_text(content, encoding="utf-8")
        wheel = root / f"reverse_analyzer-{__version__}-py3-none-any.whl"
        metadata = "\n".join(
            (
                "Metadata-Version: 2.1",
                "Name: reverse-analyzer",
                f"Version: {__version__}",
                "Requires-Python: >=3.10",
                "Requires-Dist: capstone>=5.0",
                "Requires-Dist: pefile>=2023.2.7",
                "Requires-Dist: requests>=2.28",
                "",
            )
        )
        with ZipFile(wheel, "w", compression=ZIP_DEFLATED) as archive:
            archive.writestr(
                f"reverse_analyzer-{__version__}.dist-info/METADATA", metadata
            )
        write_release_sbom(root)

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

    def test_build_script_resolves_release_notes_from_runtime_version(self):
        script = (Path(__file__).parents[1] / "scripts/build_reverse_jailbreak.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("reverse_analyzer._version", script)
        self.assertIn('$ReleaseNotes = Join-Path "docs/releases" ($Version + ".md")', script)
        self.assertIn("missing release notes for package version", script)
        self.assertNotIn("docs/releases/0.1.0.md", script)

    def test_build_script_supports_offline_build_without_isolation(self):
        script = (Path(__file__).parents[1] / "scripts/build_reverse_jailbreak.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[switch]$NoBuildIsolation", script)
        self.assertIn('"--no-build-isolation"', script)

    def test_posix_build_script_matches_portable_release_contract(self):
        script = (Path(__file__).parents[1] / "scripts/build_reverse_jailbreak.sh").read_text(
            encoding="utf-8"
        )
        self.assertTrue(script.startswith("#!/usr/bin/env bash"))
        for fragment in (
            "--no-build-isolation",
            "SOURCE_DATE_EPOCH",
            "reverse_analyzer.llm_jailbreak.release build",
            "reverse_analyzer.llm_jailbreak.release sbom",
            "reverse_analyzer.llm_jailbreak.release verify",
        ):
            self.assertIn(fragment, script)

    def test_release_sbom_is_deterministic_and_lists_direct_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            first = write_release_sbom(root)
            first_bytes = (root / "sbom.cdx.json").read_bytes()
            second = write_release_sbom(root)

            self.assertEqual(first, second)
            self.assertEqual(first_bytes, (root / "sbom.cdx.json").read_bytes())
            self.assertEqual(first["bomFormat"], "CycloneDX")
            self.assertEqual(first["metadata"]["component"]["version"], __version__)
            names = {component["name"] for component in first["components"]}
            self.assertIn("requests", names)
            requests = next(
                component for component in first["components"]
                if component["name"] == "requests"
            )
            self.assertEqual(requests["purl"], "pkg:pypi/requests")
            self.assertEqual(
                requests["properties"][0]["value"], "requests>=2.28"
            )

    def test_build_script_pins_wheel_timestamp_for_reproducibility(self):
        script = (Path(__file__).parents[1] / "scripts/build_reverse_jailbreak.ps1").read_text(
            encoding="utf-8"
        )
        self.assertIn("[long]$SourceDateEpoch", script)
        self.assertIn("$env:SOURCE_DATE_EPOCH", script)
        self.assertIn("git log -1 --format=%ct", script)
        self.assertIn("315532800", script)

    def test_release_workflow_rebuilds_when_release_metadata_changes(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/reverse-jailbreak-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('"docs/releases/**"', workflow)
        self.assertIn('"CHANGELOG.md"', workflow)
        self.assertIn('"docs/reverse_jailbreak_release.md"', workflow)
        self.assertIn('"reverse_analyzer/**"', workflow)
        self.assertIn('"requirements.txt"', workflow)
        self.assertIn('"scripts/build_reverse_jailbreak.sh"', workflow)
        self.assertIn('"reverse_analyzer/llm_jailbreak/release.py"', workflow)
        self.assertIn('python: "3.10"', workflow)
        self.assertIn('python: "3.13"', workflow)
        self.assertIn("os: ubuntu-latest", workflow)
        self.assertIn("if: matrix.publish", workflow)
        self.assertEqual(workflow.count("publish: true"), 1)

    def test_release_workflow_uses_native_builder_for_each_runner(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/reverse-jailbreak-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("if: runner.os == 'Windows'", workflow)
        self.assertIn("if: runner.os != 'Windows'", workflow)
        self.assertIn("bash scripts/build_reverse_jailbreak.sh", workflow)
        self.assertIn("./scripts/build_reverse_jailbreak.ps1", workflow)

    def test_release_workflow_runs_offline_benchmark_and_dashboard_regressions(self):
        workflow = (Path(__file__).parents[1] / ".github/workflows/reverse-jailbreak-release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("tests.test_llm_jailbreak_templates", workflow)
        self.assertIn("tests.test_llm_jailbreak_live_workflow", workflow)
        self.assertIn("tests.test_llm_jailbreak_benchmark", workflow)
        self.assertIn("tests.test_llm_jailbreak_dashboard", workflow)

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
            f"reverse-jailbreak {__version__}",
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

    def test_release_manifest_rejects_semantically_invalid_sbom(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            (root / "sbom.cdx.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "CycloneDX 1.5"):
                write_release_manifest(root)

    def test_release_manifest_rejects_sbom_dependency_drift_from_wheel(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            payload = json.loads((root / "sbom.cdx.json").read_text(encoding="utf-8"))
            payload["components"] = payload["components"][:-1]
            (root / "sbom.cdx.json").write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "dependencies do not match"):
                write_release_manifest(root)

    def test_release_manifest_rejects_malformed_sbom_component_properties(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            payload = json.loads((root / "sbom.cdx.json").read_text(encoding="utf-8"))
            payload["components"][0]["properties"] = None
            (root / "sbom.cdx.json").write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "invalid dependency component"):
                write_release_manifest(root)

    def test_portable_smoke_verifies_release_before_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            manifest = write_release_manifest(root)
            self.assertEqual(_load_verified_manifest(root), manifest)

            wheel = root / f"reverse_analyzer-{__version__}-py3-none-any.whl"
            wheel.write_text("tampered wheel", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "(size|sha256) mismatch"):
                _load_verified_manifest(root)

    def test_portable_smoke_preserves_bounded_subprocess_diagnostics(self):
        failure = subprocess.CalledProcessError(
            7,
            ["fixture"],
            output="x" * 5000,
            stderr="diagnostic",
        )
        with patch("subprocess.run", side_effect=failure):
            with self.assertRaisesRegex(
                RuntimeError, "exit code 7.*diagnostic"
            ) as raised:
                _run(["fixture"])
        self.assertNotIn("x" * 4001, str(raised.exception))

    def test_release_manifest_rejects_embedded_credential_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_release_fixture(root)
            (root / "RELEASE_NOTES.md").write_text(
                "Authorization: Bearer " + "A" * 32,
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "credential-like material"):
                write_release_manifest(root)

            # A previously generated manifest must not make a modified release
            # acceptable either.
            (root / "RELEASE_NOTES.md").write_text("clean", encoding="utf-8")
            write_release_manifest(root)
            (root / "RELEASE_NOTES.md").write_text(
                "sk-" + "B" * 24,
                encoding="utf-8",
            )
            result = verify_release_manifest(root)
            self.assertFalse(result["ok"])
            self.assertTrue(any("credential-like material" in error for error in result["errors"]))

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

    def test_release_manifest_rejects_symlinks_during_build_and_verify(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as target:
            root = Path(directory)
            self._write_release_fixture(root)
            outside = Path(target) / "outside.txt"
            outside.write_text("outside release", encoding="utf-8")
            link = root / "unexpected-link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "must not contain symlink"):
                write_release_manifest(root)

            # A hand-written manifest must not make a symlink acceptable either.
            link.unlink()
            write_release_manifest(root)
            link.symlink_to(outside)
            result = verify_release_manifest(root)
            self.assertFalse(result["ok"])
            self.assertTrue(any("must not contain symlink" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
