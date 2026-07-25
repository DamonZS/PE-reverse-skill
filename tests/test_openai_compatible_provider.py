import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib import error
from urllib.error import HTTPError
from unittest.mock import Mock, patch

from reverse_analyzer.providers.openai_compatible import OpenAICompatibleProvider


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self):
        return json.dumps(
            {
                "model": "test-model",
                "choices": [{"message": {"content": "evidence result"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
            }
        ).encode()


class OpenAICompatibleProviderTests(unittest.TestCase):
    def test_http_transport_falls_back_to_next_key_without_exposing_secrets(self) -> None:
        provider = OpenAICompatibleProvider(
            enabled=True,
            api_keys=["first-secret", "second-secret"],
            base_url="https://provider.example/v1",
            model="gpt-5.5",
        )
        success = Mock()
        success.__enter__ = Mock(return_value=success)
        success.__exit__ = Mock(return_value=False)
        success.read.return_value = json.dumps({
            "id": "request-2",
            "model": "gpt-5.5",
            "choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
            "usage": {},
        }).encode()
        unauthorized = error.HTTPError("https://provider.example/v1/chat/completions", 401, "unauthorized", {}, None)
        with patch("reverse_analyzer.providers.openai_compatible.request.urlopen", side_effect=[unauthorized, success]) as urlopen:
            result = provider._http_transport({"context": {}})

        self.assertEqual(result["metadata"]["key_slot"], 2)
        self.assertEqual(result["metadata"]["fallback_count"], 1)
        self.assertEqual(result["metadata"]["key_failures"], [{"key_slot": 1, "http_status": 401, "error_type": "HTTPError"}])
        headers = [call.args[0].headers["Authorization"] for call in urlopen.call_args_list]
        self.assertEqual(headers, ["Bearer first-secret", "Bearer second-secret"])
        self.assertNotIn("first-secret", json.dumps(result))
        self.assertNotIn("second-secret", json.dumps(result))

    def test_enabled_provider_uses_default_http_transport(self):
        with patch.dict(os.environ, {"REVERSE_ANALYZER_OPENAI_ENABLED": "1", "OPENAI_API_KEY": "secret"}, clear=False):
            with patch("reverse_analyzer.providers.openai_compatible.request.urlopen", return_value=_Response()) as call:
                message = OpenAICompatibleProvider(base_url="https://provider.example/v1", model="test-model").analyze({"sample": "authorized.bin"})
        self.assertEqual(message.final_answer, "evidence result")
        self.assertEqual(message.metadata["usage"]["completion_tokens"], 3)
        sent_request = call.call_args.args[0]
        self.assertEqual(sent_request.full_url, "https://provider.example/v1/chat/completions")
        self.assertEqual(sent_request.get_header("Authorization"), "Bearer secret")

    def test_disabled_provider_stays_offline(self):
        provider = OpenAICompatibleProvider(enabled=False, api_key="secret")
        with patch("reverse_analyzer.providers.openai_compatible.request.urlopen") as call:
            message = provider.analyze({"sample": "x"})
        self.assertTrue(message.barrier)
        call.assert_not_called()

    def test_request_max_tokens_honors_smaller_behavior_budget(self):
        environment = {
            "REVERSE_ANALYZER_OPENAI_ENABLED": "1",
            "OPENAI_API_KEY": "secret",
            "REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS": "4096",
        }
        with patch.dict(os.environ, environment, clear=False):
            with patch("reverse_analyzer.providers.openai_compatible.request.urlopen", return_value=_Response()) as call:
                OpenAICompatibleProvider(model="test-model").analyze({"max_output_tokens": 7})
        payload = json.loads(call.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(payload["max_tokens"], 7)

    def test_retries_429_then_records_attempt_metadata(self):
        rate_limited = HTTPError("https://provider.example/v1/chat/completions", 429, "rate limited", {}, None)
        environment = {
            "REVERSE_ANALYZER_OPENAI_ENABLED": "1",
            "OPENAI_API_KEY": "secret",
            "REVERSE_ANALYZER_PROVIDER_MAX_RETRIES": "1",
            "REVERSE_ANALYZER_PROVIDER_RETRY_BACKOFF": "0",
        }
        with patch.dict(os.environ, environment, clear=False):
            with patch("reverse_analyzer.providers.openai_compatible.request.urlopen", side_effect=[rate_limited, _Response()]) as call:
                message = OpenAICompatibleProvider(model="test-model").analyze({"sample": "authorized.bin"})
        self.assertFalse(message.barrier)
        self.assertEqual(message.metadata["attempts"], 2)
        self.assertEqual(call.call_count, 2)

    def test_broker_transport_uses_atomic_identity_bound_files_without_http(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "inbox").mkdir()
            (root / "outbox").mkdir()
            observed = {}

            def broker():
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    requests = list((root / "inbox").glob("*.json"))
                    if requests:
                        payload = json.loads(requests[0].read_text(encoding="utf-8"))
                        observed.update(payload)
                        response = {
                            "schema_version": 1,
                            "request_id": payload["request_id"],
                            "status": "ok",
                            "result": {"content": "brokered", "final_answer": "brokered", "metadata": {"model": "local", "usage": {"total_tokens": 9}}},
                        }
                        (root / "outbox" / f'{payload["request_id"]}.json').write_text(json.dumps(response), encoding="utf-8")
                        return
                    time.sleep(0.01)

            thread = threading.Thread(target=broker)
            thread.start()
            environment = {"REVERSE_ANALYZER_OPENAI_ENABLED": "1", "REVERSE_ANALYZER_PROVIDER_BROKER_DIR": str(root)}
            with patch.dict(os.environ, environment, clear=True):
                with patch("reverse_analyzer.providers.openai_compatible.request.urlopen") as http:
                    message = OpenAICompatibleProvider(model="local").analyze({"sample": "authorized.bin"})
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(message.final_answer, "brokered")
            self.assertEqual(observed["provider"], "openai_compatible")
            self.assertEqual(len(observed["request_id"]), 32)
            http.assert_not_called()


if __name__ == "__main__":
    unittest.main()
