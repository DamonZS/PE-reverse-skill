import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.llm_jailbreak import instruction_assets
from reverse_analyzer.llm_jailbreak.instruction_assets import (
    InstructionAsset,
    InstructionBundle,
    list_instruction_profiles,
    load_instruction_bundle,
)
from reverse_analyzer.llm_jailbreak.models import Campaign, CampaignValidationError


def campaign_mapping(**overrides):
    value = {
        "name": "Instruction asset campaign",
        "objective": "Return the configured canary.",
    }
    value.update(overrides)
    return value


class InstructionProfileTests(unittest.TestCase):
    LLM_SECURITY_SOURCES = (
        "reverse-skills/skills/llm-security/SKILL.md",
        "reverse-skills/skills/llm-security/references/owasp-llm-top10.md",
        "reverse-skills/skills/llm-security/references/prompt-injection-methodology.md",
        "reverse-skills/skills/llm-security/references/agent-security-testing.md",
        "reverse-skills/skills/llm-security/references/agent-obedience-engineering.md",
    )
    NAMED_PROFILE_SOURCES = {
        "reverse-skills-llm-security": LLM_SECURITY_SOURCES,
        "codex-unified": (
            "scripts/codex-instruct-examples/gpt5.5-unrestricted.md",
        )
        + LLM_SECURITY_SOURCES,
        "ctf-unified": (
            "scripts/codex-instruct-examples/ctf-sandbox.md",
            (
                "reverse-skills/CTF-Sandbox-Orchestrator/"
                "ctf-sandbox-orchestrator/SKILL.md"
            ),
            (
                "reverse-skills/CTF-Sandbox-Orchestrator/"
                "competition-prompt-injection/SKILL.md"
            ),
            (
                "reverse-skills/CTF-Sandbox-Orchestrator/"
                "competition-prompt-injection/references/prompt-injection.md"
            ),
        ),
    }

    def test_lists_canonical_profiles_and_loads_builtins_without_cwd_dependency(self):
        self.assertEqual(
            list_instruction_profiles(),
            (
                "ctf-sandbox",
                "gpt5.5-unrestricted",
                "reverse-skills-llm-security",
                "codex-unified",
                "ctf-unified",
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            previous_cwd = Path.cwd()
            try:
                os.chdir(directory)
                bundle = load_instruction_bundle("ctf-sandbox")
            finally:
                os.chdir(previous_cwd)

        self.assertIsInstance(bundle, InstructionBundle)
        self.assertEqual(len(bundle.assets), 1)
        self.assertIsInstance(bundle.assets[0], InstructionAsset)
        self.assertIn("[MODE: CTF SANDBOX]", bundle.content)
        self.assertEqual(bundle.assets[0].name, "ctf-sandbox")
        self.assertEqual(
            bundle.assets[0].source,
            "scripts/codex-instruct-examples/ctf-sandbox.md",
        )
        self.assertEqual(
            bundle.assets[0].sha256,
            hashlib.sha256(bundle.assets[0].content.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(
            bundle.digest,
            hashlib.sha256(bundle.content.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(bundle.sha256, bundle.digest)

        serialized = json.dumps(bundle.to_dict(), sort_keys=True, allow_nan=False)
        self.assertNotIn("H:\\", serialized)
        self.assertEqual(
            bundle.to_dict()["provenance"]["sources"],
            ["scripts/codex-instruct-examples/ctf-sandbox.md"],
        )

    def test_profile_aliases_resolve_to_identical_canonical_bundles(self):
        aliases = {
            "ctf-sandbox": ("ctf", "CTF_SANDBOX", "ctf-sandbox.md", "sandbox"),
            "gpt5.5-unrestricted": (
                "unrestricted",
                "gpt55-unrestricted",
                "GPT-5.5_UNRESTRICTED",
                "gpt5.5-unrestricted.md",
            ),
            "reverse-skills-llm-security": (
                "llm-security",
                "reverse-skills",
                "REVERSE_SKILLS_LLM_SECURITY.md",
            ),
            "codex-unified": ("codex", "codex-all", "CODEX_UNIFIED.md"),
            "ctf-unified": ("ctf-all", "unified-ctf", "CTF_UNIFIED.md"),
        }

        for canonical, values in aliases.items():
            expected = load_instruction_bundle(canonical)
            for alias in values:
                with self.subTest(canonical=canonical, alias=alias):
                    actual = load_instruction_bundle(alias)
                    self.assertEqual(actual, expected)
                    self.assertEqual(
                        actual.assets[0].provenance["profile"],
                        canonical,
                    )

    def test_named_profiles_have_fixed_order_bounded_size_and_stable_digests(self):
        repository_root = Path(__file__).resolve().parents[1]

        for profile, sources in self.NAMED_PROFILE_SOURCES.items():
            with self.subTest(profile=profile):
                first = load_instruction_bundle(profile)
                second = load_instruction_bundle(profile)
                expected_contents = []
                for source in sources:
                    content = (repository_root / source).read_bytes().decode(
                        "utf-8-sig"
                    )
                    expected_contents.append(
                        content.replace("\r\n", "\n").replace("\r", "\n").strip()
                    )

                self.assertEqual(first, second)
                self.assertEqual(
                    [asset.source for asset in first.assets],
                    list(sources),
                )
                self.assertEqual(
                    [asset.content for asset in first.assets],
                    expected_contents,
                )
                self.assertEqual(first.content, "\n\n".join(expected_contents))
                self.assertLessEqual(len(first.content.encode("utf-8")), 32 * 1024)
                self.assertEqual(
                    first.digest,
                    hashlib.sha256(first.content.encode("utf-8")).hexdigest(),
                )
                self.assertEqual(
                    first.provenance["sources"],
                    list(sources),
                )
                self.assertEqual(
                    first.provenance["asset_sha256"],
                    [asset.sha256 for asset in first.assets],
                )
                for index, asset in enumerate(first.assets):
                    self.assertEqual(asset.provenance["kind"], "builtin-profile")
                    self.assertEqual(asset.provenance["profile"], profile)
                    self.assertEqual(asset.provenance["source"], sources[index])
                    self.assertEqual(asset.provenance["profile_asset_index"], index)
                    self.assertEqual(
                        asset.provenance["profile_asset_count"],
                        len(sources),
                    )
                    self.assertEqual(
                        asset.sha256,
                        hashlib.sha256(asset.content.encode("utf-8")).hexdigest(),
                    )

    def test_named_profile_missing_files_report_profile_and_relative_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(
                instruction_assets,
                "_REPOSITORY_ROOT",
                Path(directory),
            ), mock.patch.object(
                instruction_assets,
                "_PACKAGED_ASSET_ROOT",
                Path(directory) / "missing-package-assets",
            ):
                with self.assertRaises(FileNotFoundError) as raised:
                    load_instruction_bundle("reverse-skills-llm-security")

        message = str(raised.exception)
        self.assertIn("reverse-skills-llm-security", message)
        self.assertIn("missing required Markdown files", message)
        self.assertIn(self.LLM_SECURITY_SOURCES[0], message)

    def test_named_profile_rejects_sources_over_its_fixed_byte_budget(self):
        sources = self.NAMED_PROFILE_SOURCES["reverse-skills-llm-security"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in sources:
                path = root / source
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture", encoding="utf-8")
            (root / sources[0]).write_bytes(b"x" * 100_000)

            with mock.patch.object(
                instruction_assets,
                "_REPOSITORY_ROOT",
                root,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "source size limit",
                ):
                    load_instruction_bundle("reverse-skills-llm-security")

    def test_empty_selection_has_a_stable_sha256_digest(self):
        bundle = load_instruction_bundle()

        self.assertEqual(bundle.assets, ())
        self.assertEqual(bundle.content, "")
        self.assertEqual(bundle.digest, hashlib.sha256(b"").hexdigest())
        json.dumps(bundle.to_dict(), sort_keys=True, allow_nan=False)


class CustomInstructionFileTests(unittest.TestCase):
    def test_merges_profile_then_custom_markdown_in_caller_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.md"
            second = root / "second.markdown"
            first.write_bytes(b"\xef\xbb\xbfFirst\r\n\r\nasset\r\n")
            second.write_text("Second\nasset\n", encoding="utf-8")

            bundle = load_instruction_bundle("ctf", (first, second))
            repeated = load_instruction_bundle("ctf-sandbox", [first, second])

        self.assertEqual(bundle, repeated)
        self.assertEqual(
            [item.name for item in bundle.assets],
            ["ctf-sandbox", "first.md", "second.markdown"],
        )
        self.assertEqual(bundle.assets[1].content, "First\n\nasset")
        self.assertEqual(bundle.assets[2].content, "Second\nasset")
        self.assertEqual(
            bundle.content,
            "\n\n".join(item.content for item in bundle.assets),
        )
        self.assertEqual(
            bundle.to_dict()["provenance"]["asset_sha256"],
            [item.sha256 for item in bundle.assets],
        )
        json.dumps(bundle.to_dict(), sort_keys=True, allow_nan=False)

    def test_rejects_unknown_profiles_and_invalid_custom_files(self):
        with self.assertRaisesRegex(ValueError, "unknown instruction profile"):
            load_instruction_bundle("missing-profile")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_file = root / "instructions.txt"
            text_file.write_text("text", encoding="utf-8")
            empty_file = root / "empty.md"
            empty_file.write_text("\r\n", encoding="utf-8")
            binary_file = root / "binary.md"
            binary_file.write_bytes(b"\xff\xfe")

            with self.assertRaisesRegex(ValueError, "Markdown"):
                load_instruction_bundle(files=(text_file,))
            with self.assertRaisesRegex(ValueError, "empty"):
                load_instruction_bundle(files=(empty_file,))
            with self.assertRaisesRegex(ValueError, "UTF-8"):
                load_instruction_bundle(files=(binary_file,))
            with self.assertRaises(FileNotFoundError):
                load_instruction_bundle(files=(root / "missing.md",))

        with self.assertRaisesRegex(TypeError, "ordered sequence"):
            load_instruction_bundle(files="one.md")

    def test_external_sources_are_content_addressed_and_do_not_leak_host_paths(self):
        bundles = []
        roots = []
        for _ in range(2):
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            root = Path(temporary.name)
            roots.append(str(root.resolve()))
            source = root / "private" / "instructions.md"
            source.parent.mkdir(parents=True)
            source.write_text("stable custom instruction", encoding="utf-8")
            bundles.append(load_instruction_bundle(files=[source]))

        first, second = bundles
        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.assets[0].source, second.assets[0].source)
        self.assertRegex(
            first.assets[0].source,
            r"^external/instructions\.md@sha256-[0-9a-f]{16}$",
        )
        serialized = json.dumps(first.to_dict(), sort_keys=True)
        for root in roots:
            self.assertNotIn(root, serialized)

    def test_bundle_snapshot_rejects_tampered_content_or_digest(self):
        bundle = load_instruction_bundle("ctf-sandbox")
        restored = InstructionBundle.from_dict(bundle.to_dict())
        self.assertEqual(restored, bundle)

        tampered_asset = bundle.to_dict()
        tampered_asset["assets"][0]["content"] += "\nchanged"
        with self.assertRaisesRegex(ValueError, "snapshot digest"):
            InstructionBundle.from_dict(tampered_asset)

        tampered_bundle = bundle.to_dict()
        tampered_bundle["digest"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "bundle snapshot digest"):
            InstructionBundle.from_dict(tampered_bundle)


class CampaignInstructionConfigTests(unittest.TestCase):
    def test_default_instruction_config_preserves_legacy_serialization_and_fingerprint(self):
        legacy = Campaign.from_dict(campaign_mapping())
        explicit_empty = Campaign.from_dict(
            campaign_mapping(instruction_profile="", instruction_files=[])
        )

        self.assertEqual(legacy.instruction_profile, "")
        self.assertEqual(legacy.instruction_files, ())
        self.assertNotIn("instruction_profile", legacy.to_dict())
        self.assertNotIn("instruction_files", legacy.to_dict())
        self.assertEqual(explicit_empty.to_dict(), legacy.to_dict())
        self.assertEqual(explicit_empty.fingerprint(), legacy.fingerprint())

        expected = hashlib.sha256(
            json.dumps(
                legacy.to_dict(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(legacy.fingerprint(), expected)

    def test_round_trips_canonical_profile_and_instruction_files(self):
        campaign = Campaign.from_dict(
            campaign_mapping(
                instruction_profile="CTF_SANDBOX.md",
                instruction_files=[" prompts/one.md ", "prompts/two.markdown"],
            )
        )

        self.assertEqual(campaign.instruction_profile, "ctf-sandbox")
        self.assertEqual(
            campaign.instruction_files,
            ("prompts/one.md", "prompts/two.markdown"),
        )
        self.assertEqual(campaign.to_dict()["instruction_profile"], "ctf-sandbox")
        self.assertEqual(
            campaign.to_dict()["instruction_files"],
            ["prompts/one.md", "prompts/two.markdown"],
        )
        self.assertEqual(
            Campaign.from_dict(campaign.to_dict()).to_dict(),
            campaign.to_dict(),
        )

        alias = Campaign.from_dict(
            campaign_mapping(
                instruction_profile="ctf",
                instruction_files=["prompts/one.md", "prompts/two.markdown"],
            )
        )
        self.assertEqual(alias.fingerprint(), campaign.fingerprint())
        self.assertNotEqual(
            Campaign.from_dict(campaign_mapping()).fingerprint(),
            campaign.fingerprint(),
        )

    def test_validates_instruction_profile_and_file_list(self):
        invalid_values = (
            ({"instruction_profile": 123}, "instruction_profile must be a string"),
            (
                {"instruction_profile": "unknown-profile"},
                "unknown instruction profile",
            ),
            ({"instruction_files": "one.md"}, "instruction_files must be an array"),
            ({"instruction_files": [""]}, "must be a non-empty string"),
            ({"instruction_files": ["one.txt"]}, "must be a Markdown file"),
            (
                {"instruction_files": ["one.md", "one.md"]},
                "contains duplicates",
            ),
        )

        for override, expected_message in invalid_values:
            with self.subTest(override=override):
                with self.assertRaises(CampaignValidationError) as raised:
                    Campaign.from_dict(campaign_mapping(**override))
                self.assertIn(expected_message, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
