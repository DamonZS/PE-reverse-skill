import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.llm_jailbreak.artifacts import ArtifactWriter
from reverse_analyzer.llm_jailbreak.models import (
    Attempt,
    Campaign,
    CampaignResult,
    ChatMessage,
)


class ArtifactMetadataTests(unittest.TestCase):
    @staticmethod
    def _attempt(*, attempt_id, metadata=None):
        kwargs = {}
        if metadata is not None:
            kwargs["metadata"] = metadata
        return Attempt(
            attempt_id=attempt_id,
            campaign_id="artifact-metadata-test",
            round_index=0,
            strategy="roleplay",
            mutation_index=0,
            mutation_id=f"mutation-{attempt_id}",
            prompt="fixture prompt",
            messages=(ChatMessage(role="user", content="fixture prompt"),),
            started_at="2026-07-16T00:00:00Z",
            completed_at="2026-07-16T00:00:01Z",
            **kwargs,
        )

    @staticmethod
    def _result(attempts):
        return CampaignResult(
            campaign_id="artifact-metadata-test",
            status="completed",
            success=False,
            attempts=tuple(attempts),
            started_at="2026-07-16T00:00:00Z",
            completed_at="2026-07-16T00:00:01Z",
        )

    def test_transcript_persists_attack_mode_and_complete_metadata(self):
        metadata = {
            "attack_mode": "tap",
            "candidate_id": "tap-candidate-7",
            "optimizer_recommendation": {
                "mode": "tap",
                "reason": "cold_start",
            },
            "semantic_judge_verdict": {
                "success": True,
                "confidence": 0.91,
            },
        }
        attempt = self._attempt(attempt_id="attempt-1", metadata=metadata)
        campaign = Campaign(
            name="Artifact metadata",
            objective="Exercise artifact serialization.",
            campaign_id="artifact-metadata-test",
        )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            ArtifactWriter(output).finalize(campaign, self._result((attempt,)))

            transcript = json.loads(
                (output / "transcript.json").read_text(encoding="utf-8")
            )
            attempts = json.loads(
                (output / "attempts.json").read_text(encoding="utf-8")
            )
            attempt_log = json.loads(
                (output / "attempts.jsonl").read_text(encoding="utf-8").strip()
            )
            result = json.loads(
                (output / "result.json").read_text(encoding="utf-8")
            )

        turn = transcript["turns"][0]
        self.assertEqual(turn["attack_mode"], "tap")
        self.assertEqual(turn["metadata"], metadata)
        self.assertEqual(attempts["attempts"][0]["metadata"], metadata)
        self.assertEqual(attempt_log["metadata"], metadata)
        self.assertEqual(result["attempts"][0]["metadata"], metadata)

    def test_legacy_attempt_defaults_transcript_attack_mode_to_builtin(self):
        attempt = self._attempt(attempt_id="legacy-attempt")
        campaign = Campaign(
            name="Legacy artifact",
            objective="Exercise legacy attempt serialization.",
            campaign_id="artifact-metadata-test",
        )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            checkpoint = output / "checkpoint.json"
            checkpoint.write_text('{"completed": true}\n', encoding="utf-8")
            ArtifactWriter(output).finalize(
                campaign,
                self._result((attempt,)),
                checkpoint_path=checkpoint,
            )

            transcript = json.loads(
                (output / "transcript.json").read_text(encoding="utf-8")
            )
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )

        turn = transcript["turns"][0]
        self.assertEqual(turn["attack_mode"], "builtin")
        self.assertEqual(turn["metadata"], {})
        manifest_paths = {item["path"] for item in manifest["artifacts"]}
        self.assertIn("checkpoint.json", manifest_paths)
        self.assertIn("transcript.json", manifest_paths)
        self.assertNotIn("manifest.json", manifest_paths)


if __name__ == "__main__":
    unittest.main()
