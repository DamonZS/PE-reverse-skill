import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.llm_jailbreak import (
    ChatResponse,
    CheckpointError,
    load_campaign,
    load_instruction_bundle,
    run_campaign,
)


class RecordingTransport:
    def __init__(self, outputs):
        self.outputs = list(outputs)
        self.calls = []

    def complete(self, messages, **kwargs):
        self.calls.append({"messages": tuple(messages), "kwargs": dict(kwargs)})
        if not self.outputs:
            raise AssertionError("unexpected transport call")
        output = self.outputs.pop(0)
        if isinstance(output, BaseException):
            raise output
        return ChatResponse(content=str(output), model=kwargs["model"])


def campaign_mapping(**overrides):
    value = {
        "id": "instruction-campaign",
        "name": "Instruction asset integration",
        "objective": "Return the fixture marker.",
        "max_rounds": 1,
        "stop_on_success": False,
        "strategies": ["roleplay"],
        "attack_modes": ["builtin"],
        "target": {
            "base_url": "http://fixture.invalid/v1",
            "model": "fixture-model",
            "api_key_env": "UNUSED_FIXTURE_KEY",
        },
        "scoring": {"canaries": ["FIXTURE_GRANTED"], "threshold": 1.0},
    }
    value.update(overrides)
    return value


class InstructionCampaignIntegrationTests(unittest.TestCase):
    def test_profile_reaches_transport_checkpoint_result_and_manifest(self):
        campaign = load_campaign(
            campaign_mapping(instruction_profile="ctf-sandbox")
        )
        bundle = load_instruction_bundle("ctf-sandbox")
        transport = RecordingTransport(["ordinary fixture response"])

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = run_campaign(campaign, transport=transport, out_dir=output)
            checkpoint = json.loads(
                (output / "checkpoint.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            instruction_document = json.loads(
                (output / "instruction-assets.json").read_text(encoding="utf-8")
            )

        self.assertEqual(len(transport.calls), 1)
        developer_messages = [
            message
            for message in transport.calls[0]["messages"]
            if message.role == "developer" and message.name == "instruction-assets"
        ]
        self.assertEqual(len(developer_messages), 1)
        self.assertEqual(developer_messages[0].content, bundle.content)

        metadata = result.attempts[0].metadata["instruction_asset"]
        self.assertEqual(metadata["profile"], "ctf-sandbox")
        self.assertEqual(metadata["bundle_digest"], bundle.digest)
        self.assertEqual(checkpoint["instruction_bundle_digest"], bundle.digest)
        self.assertEqual(instruction_document["digest"], bundle.digest)
        self.assertEqual(result.artifacts["instruction_assets"], "instruction-assets.json")
        self.assertEqual(result.artifacts["instructions"], "instructions/")

        manifest_paths = {item["path"] for item in manifest["artifacts"]}
        self.assertIn("instruction-assets.json", manifest_paths)
        self.assertIn("instructions/ctf-sandbox.md", manifest_paths)

    def test_resume_rejects_changed_instruction_file_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction_file = root / "custom.md"
            instruction_file.write_text("fixture instruction version one", encoding="utf-8")
            campaign = load_campaign(
                campaign_mapping(
                    max_rounds=2,
                    instruction_files=[str(instruction_file)],
                )
            )
            output = root / "out"
            interrupted = RecordingTransport(
                ["first fixture response", KeyboardInterrupt()]
            )

            with self.assertRaises(KeyboardInterrupt):
                run_campaign(campaign, transport=interrupted, out_dir=output)

            checkpoint = json.loads(
                (output / "checkpoint.json").read_text(encoding="utf-8")
            )
            original_digest = checkpoint["instruction_bundle_digest"]
            instruction_file.write_text("fixture instruction version two", encoding="utf-8")

            with self.assertRaisesRegex(
                CheckpointError,
                "instruction bundle digest does not match",
            ):
                run_campaign(
                    campaign,
                    transport=RecordingTransport(["unused"]),
                    out_dir=output,
                    resume=True,
                )

            self.assertNotEqual(
                original_digest,
                load_instruction_bundle(files=[str(instruction_file)]).digest,
            )

    def test_supplied_bundle_snapshot_is_session_fixed_and_needs_no_source_reread(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instruction_file = root / "custom.md"
            instruction_file.write_text("session fixed instruction", encoding="utf-8")
            campaign = load_campaign(
                campaign_mapping(instruction_files=[str(instruction_file)])
            )
            bundle = load_instruction_bundle(files=[instruction_file])
            instruction_file.unlink()
            transport = RecordingTransport(["fixture response"])

            result = run_campaign(
                campaign,
                transport=transport,
                out_dir=root / "out",
                instruction_bundle=bundle.to_dict(),
            )
            persisted_campaign = json.loads(
                (root / "out" / "campaign.json").read_text(encoding="utf-8")
            )

        self.assertEqual(result.status, "exhausted")
        developer = [
            message
            for message in transport.calls[0]["messages"]
            if message.role == "developer"
        ]
        self.assertEqual([message.content for message in developer], [bundle.content])
        self.assertEqual(
            persisted_campaign["instruction_files"],
            [bundle.assets[0].source],
        )
        self.assertNotIn(str(root), json.dumps(persisted_campaign, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
