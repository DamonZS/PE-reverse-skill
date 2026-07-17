import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.llm_jailbreak.artifacts import ArtifactWriter
from reverse_analyzer.llm_jailbreak.instruction_assets import (
    InstructionAsset,
    InstructionBundle,
)
from reverse_analyzer.llm_jailbreak.models import Campaign, CampaignResult


class InstructionArtifactTests(unittest.TestCase):
    @staticmethod
    def _campaign():
        return Campaign(
            name="Instruction artifact campaign",
            objective="Exercise instruction artifact persistence.",
            campaign_id="instruction-artifact-test",
        )

    @staticmethod
    def _result():
        return CampaignResult(
            campaign_id="instruction-artifact-test",
            status="completed",
            success=False,
            attempts=(),
            started_at="2026-07-16T00:00:00Z",
            completed_at="2026-07-16T00:00:01Z",
        )

    def test_writes_bundle_markdown_and_manifest_entries(self):
        assets = (
            InstructionAsset(
                name="../Primary Profile.MD",
                content="First\nasset",
                source="fixtures/primary.md",
                provenance={"kind": "fixture", "order": 1},
            ),
            InstructionAsset(
                name="Primary Profile.markdown",
                content="Second asset",
                source="fixtures/secondary.markdown",
                provenance={"kind": "fixture", "order": 2},
            ),
        )
        bundle = InstructionBundle(assets)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            checkpoint = output / "checkpoint.json"
            checkpoint.write_text('{"completed": true}\n', encoding="utf-8")
            artifact_paths = ArtifactWriter(output).finalize(
                self._campaign(),
                self._result(),
                checkpoint_path=checkpoint,
                instruction_bundle=bundle,
            )

            bundle_document = json.loads(
                (output / "instruction-assets.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            markdown_paths = [
                output / item["artifact_path"] for item in bundle_document["assets"]
            ]

            self.assertEqual(
                [path.relative_to(output).as_posix() for path in markdown_paths],
                [
                    "instructions/Primary-Profile.md",
                    "instructions/Primary-Profile-2.md",
                ],
            )
            for asset, path in zip(assets, markdown_paths):
                self.assertEqual(path.read_text(encoding="utf-8"), asset.content)
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    asset.sha256,
                )

            entries = {item["path"]: item for item in manifest["artifacts"]}
            expected_instruction_paths = {
                "instruction-assets.json",
                "instructions/Primary-Profile.md",
                "instructions/Primary-Profile-2.md",
            }
            self.assertTrue(expected_instruction_paths.issubset(entries))
            self.assertIn("checkpoint.json", entries)
            for relative_path in expected_instruction_paths:
                content = (output / relative_path).read_bytes()
                self.assertEqual(entries[relative_path]["size"], len(content))
                self.assertEqual(
                    entries[relative_path]["sha256"],
                    hashlib.sha256(content).hexdigest(),
                )

        self.assertEqual(bundle_document["schema_version"], 1)
        self.assertEqual(bundle_document["digest"], bundle.digest)
        self.assertEqual(bundle_document["content"], bundle.content)
        self.assertEqual(bundle_document["provenance"], bundle.provenance)
        self.assertEqual(
            [item["sha256"] for item in bundle_document["assets"]],
            [item.sha256 for item in assets],
        )
        self.assertEqual(
            artifact_paths["instruction_assets"],
            "instruction-assets.json",
        )
        self.assertEqual(artifact_paths["instructions"], "instructions/")

    def test_none_or_empty_bundle_preserves_legacy_artifact_contract(self):
        for bundle in (None, InstructionBundle()):
            with self.subTest(bundle=bundle):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory)
                    artifact_paths = ArtifactWriter(output).finalize(
                        self._campaign(),
                        self._result(),
                        instruction_bundle=bundle,
                    )
                    manifest = json.loads(
                        (output / "manifest.json").read_text(encoding="utf-8")
                    )

                    self.assertFalse((output / "instruction-assets.json").exists())
                    self.assertFalse((output / "instructions").exists())

                self.assertNotIn("instruction_assets", artifact_paths)
                self.assertNotIn("instructions", artifact_paths)
                self.assertFalse(
                    any(
                        item["path"].startswith("instruction")
                        for item in manifest["artifacts"]
                    )
                )


if __name__ == "__main__":
    unittest.main()
