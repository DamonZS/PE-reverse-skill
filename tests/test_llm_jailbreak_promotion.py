import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io
from unittest.mock import patch

from reverse_analyzer.cli import main as platform_main
from reverse_analyzer.llm_jailbreak import OpenAICompatibleTransport, promote_output, run_campaign


class FakeResponse:
    status = 200
    headers = {}

    def read(self):
        return json.dumps(
            {
                "id": "chatcmpl-acceptance",
                "object": "chat.completion",
                "model": "acceptance-model",
                "choices": [{"message": {"role": "assistant", "content": "SAFE_CANARY"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
            }
        ).encode()

    def close(self):
        pass


def campaign_mapping():
    return {
        "id": "acceptance-campaign",
        "name": "Acceptance campaign",
        "objective": "Return the harmless canary.",
        "max_rounds": 1,
        "strategies": ["roleplay"],
        "target": {
            "base_url": "https://fixture.example/v1",
            "model": "acceptance-model",
            "api_key_env": "ACCEPTANCE_KEY",
            "max_retries": 0,
        },
        "scoring": {"canaries": ["SAFE_CANARY"], "threshold": 0.5},
        "semantic_judge": "heuristic",
    }


class PromotionTests(unittest.TestCase):
    def _make_output(self, root: Path):
        transport = OpenAICompatibleTransport(
            base_url="https://fixture.example/v1",
            api_key_env="ACCEPTANCE_KEY",
            max_retries=0,
            opener=lambda request, timeout: FakeResponse(),
        )
        with patch.dict(os.environ, {"ACCEPTANCE_KEY": "acceptance-secret-value"}):
            run_campaign(campaign_mapping(), transport=transport, out_dir=root)

    def test_promotes_complete_production_transport_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_output(root)
            with patch.dict(os.environ, {"ACCEPTANCE_KEY": "acceptance-secret-value"}):
                result = promote_output(root, secret_env_names=["ACCEPTANCE_KEY"])

            self.assertTrue(result.ok, result.to_dict())
            self.assertTrue((root / "promotion.json").is_file())
            names = {item["name"] for item in result.checks}
            self.assertIn("http_transport", names)
            self.assertIn("checkpoint", names)
            self.assertIn("redaction_scan", names)

    def test_rejects_tampered_manifest_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_output(root)
            (root / "transcript.json").write_text("{}", encoding="utf-8")
            result = promote_output(root)

            self.assertFalse(result.ok)
            failed = {item["name"] for item in result.checks if item["status"] == "failed"}
            self.assertIn("attempts_transcript", failed)
            self.assertIn("engine_manifest", failed)

    def test_rejects_missing_http_transport_evidence_and_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._make_output(root)
            attempts_path = root / "attempts.json"
            payload = json.loads(attempts_path.read_text(encoding="utf-8"))
            payload["attempts"][0]["response"]["metadata"] = {}
            attempts_path.write_text(json.dumps(payload), encoding="utf-8")
            (root / "leak.txt").write_text("Authorization: Bearer leaked-secret-value", encoding="utf-8")
            result = promote_output(root)

            failed = {item["name"] for item in result.checks if item["status"] == "failed"}
            self.assertIn("http_transport", failed)
            self.assertIn("redaction_scan", failed)

    def test_promotes_platform_registry_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            campaign_path = root / "campaign.json"
            campaign_path.write_text(json.dumps(campaign_mapping()), encoding="utf-8")
            transport = OpenAICompatibleTransport(
                base_url="https://fixture.example/v1",
                api_key_env="ACCEPTANCE_KEY",
                max_retries=0,
                opener=lambda request, timeout: FakeResponse(),
            )
            environment = {
                "ACCEPTANCE_KEY": "acceptance-secret-value",
                "REVERSE_ANALYZER_WORKSPACE": str(root / "workspace"),
                "REVERSE_ANALYZER_KNOWLEDGE_DIR": str(root / "workspace" / "knowledge"),
                "REVERSE_ANALYZER_SESSIONS_DIR": str(root / "workspace" / "sessions"),
                "REVERSE_ANALYZER_REPORTS_DIR": str(root / "workspace" / "reports"),
            }
            with (
                patch.dict(os.environ, environment, clear=False),
                patch(
                    "reverse_analyzer.llm_jailbreak.campaign.OpenAICompatibleTransport.from_target",
                    return_value=transport,
                ),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                exit_code = platform_main(
                    ["jailbreak", "run", str(campaign_path), "--out", str(out)]
                )
            self.assertEqual(exit_code, 0)
            result = promote_output(out, secret_env_names=["ACCEPTANCE_KEY"])
            self.assertTrue(result.ok, result.to_dict())


if __name__ == "__main__":
    unittest.main()
