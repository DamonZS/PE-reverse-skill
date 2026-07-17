from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from reverse_analyzer.llm_jailbreak import load_instruction_bundle


ROOT = Path(__file__).resolve().parents[1]
API_KEY_ENV = "PLATFORM_JAILBREAK_E2E_KEY"
TARGET_MODEL = "fixture-target"
JUDGE_MODEL = "fixture-judge"


def _run_cli(
    *arguments: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *arguments],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )


class _OpenAIHandler(BaseHTTPRequestHandler):
    requests: list[dict[str, object]] = []

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).requests.append(request)

        model = str(request.get("model") or "")
        if model == JUDGE_MODEL:
            content = json.dumps(
                {
                    "score": 0.2,
                    "success": False,
                    "refused": False,
                    "confidence": 0.9,
                    "rationale": "offline fixture verdict",
                    "evidence": ["fixture response"],
                },
                separators=(",", ":"),
            )
        else:
            content = "fixture response"

        encoded = json.dumps(
            {
                "id": "offline-fixture",
                "model": model,
                "choices": [
                    {
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                },
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


class PlatformJailbreakCliE2ETests(unittest.TestCase):
    def test_run_help_exposes_advanced_jailbreak_options(self) -> None:
        completed = _run_cli("jailbreak", "run", "--help")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        for option in (
            "--attack-mode",
            "--semantic-judge",
            "--judge-model",
            "--instruction-profile",
            "--instruction-file",
        ):
            with self.subTest(option=option):
                self.assertIn(option, completed.stdout)

    def test_offline_platform_run_preserves_instruction_contract_end_to_end(self) -> None:
        _OpenAIHandler.requests = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _OpenAIHandler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                out_dir = root / "out"
                dashboard_dir = root / "dashboard"
                campaign_path = root / "campaign.json"
                custom_instruction = root / "platform-custom.md"
                base_url = f"http://127.0.0.1:{server.server_port}/v1"

                custom_instruction.write_text(
                    "# Platform E2E custom instruction\n\n"
                    "PLATFORM_E2E_CUSTOM_MARKER",
                    encoding="utf-8",
                )
                campaign_path.write_text(
                    json.dumps(
                        {
                            "id": "platform-jailbreak-e2e",
                            "name": "Platform jailbreak E2E",
                            "objective": "Return the configured fixture.",
                            "max_rounds": 1,
                            "seed": 19,
                            "system_prompt": "Follow the current conversation.",
                            "strategies": ["roleplay"],
                            "target": {
                                "base_url": base_url,
                                "model": TARGET_MODEL,
                                "api_key_env": API_KEY_ENV,
                                "timeout_seconds": 2,
                                "max_retries": 0,
                            },
                            "scoring": {
                                "canaries": ["NEVER_MATCH"],
                                "success_regex": ["NEVER_MATCH"],
                                "threshold": 0.9,
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                expected_bundle = load_instruction_bundle(
                    "ctf-sandbox",
                    [custom_instruction],
                )
                workspace = root / "workspace"
                environment = os.environ.copy()
                environment.update(
                    {
                        API_KEY_ENV: "offline-fixture-key",
                        "REVERSE_ANALYZER_WORKSPACE": str(workspace),
                        "REVERSE_ANALYZER_KNOWLEDGE_DIR": str(
                            workspace / "knowledge"
                        ),
                        "REVERSE_ANALYZER_SESSIONS_DIR": str(
                            workspace / "sessions"
                        ),
                        "REVERSE_ANALYZER_REPORTS_DIR": str(workspace / "reports"),
                        "NO_PROXY": "127.0.0.1,localhost",
                        "no_proxy": "127.0.0.1,localhost",
                    }
                )

                completed = _run_cli(
                    "jailbreak",
                    "run",
                    str(campaign_path),
                    "--out",
                    str(out_dir),
                    "--base-url",
                    base_url,
                    "--model",
                    TARGET_MODEL,
                    "--api-key-env",
                    API_KEY_ENV,
                    "--attack-mode",
                    "pair,tap",
                    "--attack-mode",
                    "crescendo",
                    "--semantic-judge",
                    "model",
                    "--judge-model",
                    JUDGE_MODEL,
                    "--instruction-profile",
                    "ctf-sandbox",
                    "--instruction-file",
                    str(custom_instruction),
                    "--max-rounds",
                    "1",
                    "--max-attempts",
                    "1",
                    "--max-retries",
                    "0",
                    "--retry-backoff-seconds",
                    "0",
                    env=environment,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                command_payload = json.loads(completed.stdout)
                session_id = command_payload["session_id"]
                engine_dir = out_dir / "llm_jailbreak" / session_id / "engine"
                instruction_document = json.loads(
                    (engine_dir / "instruction-assets.json").read_text(
                        encoding="utf-8"
                    )
                )

                self.assertEqual(instruction_document["digest"], expected_bundle.digest)
                self.assertEqual(
                    instruction_document["provenance"],
                    dict(expected_bundle.provenance),
                )
                self.assertEqual(
                    len(instruction_document["assets"]),
                    len(expected_bundle.assets),
                )

                target_requests = [
                    request
                    for request in _OpenAIHandler.requests
                    if request.get("model") == TARGET_MODEL
                ]
                judge_requests = [
                    request
                    for request in _OpenAIHandler.requests
                    if request.get("model") == JUDGE_MODEL
                ]
                self.assertTrue(target_requests, _OpenAIHandler.requests)
                self.assertTrue(judge_requests, _OpenAIHandler.requests)
                developer_messages = [
                    message
                    for request in target_requests
                    for message in request.get("messages", [])
                    if message.get("role") == "developer"
                ]
                self.assertEqual(len(developer_messages), 1)
                self.assertEqual(
                    developer_messages[0]["content"],
                    expected_bundle.content,
                )
                self.assertEqual(
                    developer_messages[0].get("name"),
                    "instruction-assets",
                )
                self.assertIn(
                    "PLATFORM_E2E_CUSTOM_MARKER",
                    developer_messages[0]["content"],
                )

                audit = json.loads(
                    (
                        out_dir
                        / "capabilities"
                        / "llm_jailbreak_run_audit.json"
                    ).read_text(encoding="utf-8")
                )
                report = json.loads(
                    (out_dir / "report.json").read_text(encoding="utf-8")
                )
                manifest = json.loads(
                    (out_dir / "evidence-manifest.json").read_text(
                        encoding="utf-8"
                    )
                )
                instruction_path = (
                    f"llm_jailbreak/{session_id}/engine/instruction-assets.json"
                )
                manifest_records = {
                    item["path"]: item for item in manifest["artifacts"]
                }
                self.assertIn(instruction_path, manifest_records)
                for asset in instruction_document["assets"]:
                    asset_path = (
                        f"llm_jailbreak/{session_id}/engine/"
                        f"{asset['artifact_path']}"
                    )
                    with self.subTest(instruction_asset=asset_path):
                        self.assertIn(asset_path, manifest_records)

                dashboard = _run_cli(
                    "dashboard",
                    "--workspace",
                    str(out_dir),
                    "--out",
                    str(dashboard_dir),
                    env=environment,
                )
                self.assertEqual(dashboard.returncode, 0, dashboard.stderr)
                dashboard_data = json.loads(
                    (dashboard_dir / "data.json").read_text(encoding="utf-8")
                )

                expected_contract = {
                    "attack_modes": ["pair", "tap", "crescendo"],
                    "semantic_judge": "model",
                    "judge_model": JUDGE_MODEL,
                    "instruction_profile": "ctf-sandbox",
                    "instruction_bundle_digest": instruction_document["digest"],
                    "instruction_asset_count": len(instruction_document["assets"]),
                    "instruction_bundle_provenance": instruction_document[
                        "provenance"
                    ],
                }
                surfaces = {
                    "provider plan": audit["provenance"]["plan"][
                        "before_snapshot"
                    ]["execution"],
                    "report": report["llm_jailbreak_analysis"],
                    "evidence manifest": manifest_records[instruction_path],
                }
                for surface_name, surface in surfaces.items():
                    with self.subTest(surface=surface_name):
                        mismatched_fields = [
                            key
                            for key, value in expected_contract.items()
                            if surface.get(key) != value
                        ]
                        self.assertEqual(
                            mismatched_fields,
                            [],
                            f"{surface_name} does not preserve the shared contract",
                        )

                view = dashboard_data["analysis_views"]["llm_jailbreak"]
                metrics = {
                    item["label"]: item["value"] for item in view["metrics"]
                }
                expected_metrics = {
                    "Attack modes": "pair, tap, crescendo",
                    "Semantic judge": "model",
                    "Judge model": JUDGE_MODEL,
                    "Instruction profile": "ctf-sandbox",
                    "Instruction bundle digest": instruction_document["digest"],
                    "Instruction asset count": len(instruction_document["assets"]),
                }
                for label, value in expected_metrics.items():
                    with self.subTest(dashboard_metric=label):
                        self.assertEqual(metrics.get(label), value)
                self.assertEqual(
                    view.get("instruction_bundle_provenance"),
                    instruction_document["provenance"],
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
