"""Opt-in live image E2E for the OpenAI-compatible GUI VLM adapter."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit

from reverse_analyzer.gui.vlm_provider import load_vlm_provider


def _enabled() -> bool:
    return os.environ.get("REVERSE_ANALYZER_RUN_VLM_LIVE", "").strip() == "1"


def _normalized_canary(value: str) -> str:
    return " ".join(value.split()).casefold()


def _visual_text(output: dict[str, object]) -> list[str]:
    values: list[str] = []
    for collection in (output.get("text_regions"), output.get("widgets")):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                values.append(str(item["text"]))
    return values


@unittest.skipUnless(_enabled(), "set REVERSE_ANALYZER_RUN_VLM_LIVE=1 for live VLM E2E")
class LiveOpenAIVLMTests(unittest.TestCase):
    def test_live_image_analysis_retains_sanitized_acceptance_artifacts(self) -> None:
        base_url = os.environ.get("REVERSE_ANALYZER_VLM_BASE_URL", "").strip()
        model = os.environ.get("REVERSE_ANALYZER_VLM_MODEL", "").strip()
        api_key = os.environ.get("REVERSE_ANALYZER_VLM_API_KEY", "")
        image = Path(os.environ.get("REVERSE_ANALYZER_VLM_IMAGE", ""))
        canary = os.environ.get("REVERSE_ANALYZER_VLM_CANARY", "").strip()
        self.assertTrue(base_url and model and api_key, "live VLM endpoint, model, and API key are required")
        self.assertTrue(image.is_file(), "REVERSE_ANALYZER_VLM_IMAGE must identify a real image")
        self.assertTrue(4 <= len(canary) <= 128, "VLM canary must contain 4 to 128 characters")

        loaded = load_vlm_provider(
            {
                "provider": "reverse_analyzer.gui.openai_vlm:OpenAICompatibleVLM",
                "name": "openai-compatible-live",
                "options": {"base_url": base_url, "model": model},
                "secret_env": {"api_key": "REVERSE_ANALYZER_VLM_API_KEY"},
                "timeout_seconds": 60,
            }
        )
        self.assertTrue(loaded.available, loaded.to_dict())
        invocation = loaded.provider.invoke(image)  # type: ignore[union-attr]
        self.assertIn(invocation.status, {"ok", "partial"}, invocation.to_dict())
        output = invocation.output or {}
        live_items = len(output.get("text_regions", [])) + len(output.get("widgets", []))
        self.assertGreater(live_items, 0, "live VLM response contained no visual evidence")
        expected_canary = _normalized_canary(canary)
        canary_matches = [
            value for value in _visual_text(output)
            if expected_canary in _normalized_canary(value)
        ]
        self.assertTrue(canary_matches, "controlled VLM canary was not observed")

        configured_run_dir = os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR", "").strip()
        temporary: tempfile.TemporaryDirectory[str] | None = None
        if configured_run_dir:
            run_dir = Path(configured_run_dir)
        else:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            run_dir = Path(temporary.name)
        artifact_dir = run_dir / "gui-vlm"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        image_digest = hashlib.sha256(image.read_bytes()).hexdigest()
        endpoint = urlsplit(base_url)
        endpoint_identity = hashlib.sha256(
            f"{endpoint.scheme}://{endpoint.netloc}{endpoint.path.rstrip('/')}".encode("utf-8")
        ).hexdigest()
        canary_digest = hashlib.sha256(canary.encode("utf-8")).hexdigest()
        artifacts = {
            "target-identity.json": {
                "kind": "remote-openai-compatible-vlm",
                "endpoint_sha256": endpoint_identity,
                "model": model,
                "sha256": image_digest,
                "image_sha256": image_digest,
                "canary_sha256": canary_digest,
            },
            "invocation.json": invocation.to_dict(),
            "output.json": output,
            "transport-audit.json": {
                "status": invocation.status,
                "transport": "openai-compatible-http",
                "input_sha256": image_digest,
                "endpoint_sha256": endpoint_identity,
                "response_request_id": output.get("provenance", {}).get("request_id"),
                "secret_source": "environment",
                "authorization_persisted": False,
                "canary_verified": True,
            },
            "canary-verification.json": {
                "status": "ok",
                "verified": True,
                "canary_sha256": canary_digest,
                "matched_items": len(canary_matches),
            },
            "execution-proof.json": {
                "status": "ok",
                "provider": "openai-compatible-vlm",
                "evidence_class": "live_target_proof",
                "executed_tests": 1,
                "skipped_tests": 0,
                "live_operations": 1,
                "visual_items": live_items,
                "canary_verified": True,
                "model": model,
                "input_sha256": image_digest,
                "endpoint_sha256": endpoint_identity,
                "canary_sha256": canary_digest,
                "response_request_id": output.get("provenance", {}).get("request_id"),
            },
        }
        for name, payload in artifacts.items():
            (artifact_dir / name).write_text(
                json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
            )

        persisted = "\n".join(path.read_text(encoding="utf-8") for path in artifact_dir.glob("*.json"))
        self.assertNotIn(api_key, persisted)
        self.assertNotIn("Authorization", persisted)
        self.assertNotIn(str(image.resolve()), persisted)


if __name__ == "__main__":
    unittest.main()
