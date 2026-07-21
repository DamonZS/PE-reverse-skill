import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import tempfile
import threading
import unittest
from pathlib import Path

from reverse_analyzer.gui.openai_vlm import OpenAICompatibleVLM
from reverse_analyzer.gui.vlm_provider import load_vlm_provider


_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    b"\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
    b"\x00\x00\x00\rIDAT\x08\xd7c\xf8\xcf\xc0\xf0\x1f\x00\x05"
    b"\x00\x01\xff\x89\x99=\x1d\x00\x00\x00\x00IEND\xaeB`\x82"
)


class _Handler(BaseHTTPRequestHandler):
    observed: dict[str, object] = {}

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract.
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).observed = {
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "payload": payload,
        }
        completion = {
            "status": "ok",
            "text_regions": [{"text": "Save", "confidence": 0.9}],
            "widgets": [
                {
                    "type": "button",
                    "text": "Save",
                    "bbox": {"x": 1, "y": 2, "width": 10, "height": 5},
                }
            ],
        }
        body = json.dumps(
            {
                "id": "vlm-request-1",
                "model": "fixture-vision",
                "choices": [{"message": {"content": f"```json\n{json.dumps(completion)}\n```"}}],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class OpenAICompatibleVLMTests(unittest.TestCase):
    def test_loader_uses_real_http_transport_and_normalizes_completion(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        secret = "loopback-vlm-secret"

        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "screen.png"
            image.write_bytes(_PNG)
            loaded = load_vlm_provider(
                {
                    "provider": "reverse_analyzer.gui.openai_vlm:OpenAICompatibleVLM",
                    "name": "openai-compatible",
                    "options": {
                        "base_url": f"http://127.0.0.1:{server.server_port}/v1",
                        "model": "fixture-vision",
                    },
                    "secret_env": {"api_key": "TEST_VLM_API_KEY"},
                    "timeout_seconds": 2,
                },
                environ={"TEST_VLM_API_KEY": secret},
            )
            self.assertTrue(loaded.available)
            invocation = loaded.provider.invoke(image)  # type: ignore[union-attr]

        self.assertEqual(invocation.status, "ok")
        self.assertEqual(invocation.output["text_regions"][0]["text"], "Save")  # type: ignore[index]
        self.assertEqual(invocation.output["provenance"]["request_id"], "vlm-request-1")  # type: ignore[index]
        observed = _Handler.observed
        self.assertEqual(observed["path"], "/v1/chat/completions")
        self.assertEqual(observed["authorization"], f"Bearer {secret}")
        payload = observed["payload"]
        self.assertEqual(payload["model"], "fixture-vision")  # type: ignore[index]
        image_url = payload["messages"][0]["content"][1]["image_url"]["url"]  # type: ignore[index]
        self.assertTrue(image_url.startswith("data:image/png;base64,"))
        persisted = json.dumps({"load": loaded.to_dict(), "invocation": invocation.to_dict()})
        self.assertNotIn(secret, persisted)
        self.assertNotIn("Authorization", persisted)

    def test_adapter_rechecks_image_identity_before_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "screen.png"
            image.write_bytes(_PNG)
            provider = OpenAICompatibleVLM(
                config={"base_url": "https://example.invalid/v1", "model": "vision", "api_key": "secret"}
            )
            request = {
                "image_path": str(image),
                "media_type": "image/png",
                "size_bytes": len(_PNG),
                "sha256": hashlib.sha256(b"different").hexdigest(),
                "timeout_seconds": 1,
            }
            with self.assertRaisesRegex(ValueError, "changed after request validation"):
                provider.analyze(request)

    def test_constructor_rejects_credentialed_or_unbounded_configuration(self) -> None:
        with self.assertRaisesRegex(ValueError, "credentials"):
            OpenAICompatibleVLM(
                config={"base_url": "https://user:pass@example.invalid/v1", "model": "vision", "api_key": "key"}
            )
        with self.assertRaisesRegex(ValueError, "max_image_bytes"):
            OpenAICompatibleVLM(
                config={
                    "base_url": "https://example.invalid/v1",
                    "model": "vision",
                    "api_key": "key",
                    "max_image_bytes": 100 * 1024 * 1024,
                }
            )


if __name__ == "__main__":
    unittest.main()
