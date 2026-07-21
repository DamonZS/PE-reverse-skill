import json
import os
import unittest
from unittest.mock import patch

from reverse_analyzer.llm_jailbreak.doctor import DoctorError, run_doctor
from reverse_analyzer.cli import build_parser as build_platform_parser
from reverse_analyzer.llm_jailbreak.cli import build_parser as build_standalone_parser


class FakeResponse:
    def __init__(self, body, *, headers=None, status=200):
        self._body = body
        self.headers = headers or {}
        self.status = status

    def read(self):
        return self._body

    def close(self):
        pass


class EndpointOpener:
    def __init__(self):
        self.requests = []

    def __call__(self, request, *, timeout):
        self.requests.append((request, timeout))
        if request.full_url.endswith("/models"):
            return FakeResponse(
                json.dumps({"object": "list", "data": [{"id": "fixture-model"}]}).encode(),
                headers={"x-ratelimit-limit-requests": "60"},
            )
        payload = json.loads(request.data)
        if payload.get("stream"):
            return FakeResponse(
                b'data: {"choices":[{"delta":{"content":"READY"}}]}\n\ndata: [DONE]\n'
            )
        return FakeResponse(
            json.dumps(
                {
                    "id": "chatcmpl-fixture",
                    "object": "chat.completion",
                    "model": "fixture-model",
                    "choices": [{"message": {"role": "assistant", "content": "READY"}}],
                }
            ).encode()
        )


class DoctorTests(unittest.TestCase):
    def test_platform_and_standalone_cli_register_doctor_and_promote(self):
        platform = build_platform_parser()
        doctor = platform.parse_args(
            ["jailbreak", "doctor", "--base-url", "https://example.test/v1", "--model", "m"]
        )
        self.assertEqual(doctor.func.__name__, "jailbreak_doctor_command")
        promote = platform.parse_args(["jailbreak", "promote", "output"])
        self.assertEqual(promote.func.__name__, "jailbreak_promote_command")

        standalone = build_standalone_parser()
        self.assertEqual(
            standalone.parse_args(
                ["doctor", "--base-url", "https://example.test/v1", "--model", "m"]
            ).command,
            "doctor",
        )
        self.assertEqual(standalone.parse_args(["promote", "output"]).command, "promote")

    def test_checks_models_non_stream_stream_timeout_and_rate_limit(self):
        opener = EndpointOpener()
        secret = "doctor-secret-value"
        with patch.dict(os.environ, {"DOCTOR_KEY": secret}):
            result = run_doctor(
                base_url="https://fixture.example/v1/chat/completions",
                model="fixture-model",
                api_key_env="DOCTOR_KEY",
                timeout_seconds=7.5,
                opener=opener,
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.base_url, "https://fixture.example/v1")
        self.assertEqual(
            [item["name"] for item in result.checks],
            ["models", "chat_non_stream", "chat_stream", "rate_limit_signals", "timeout"],
        )
        self.assertEqual([timeout for _, timeout in opener.requests], [7.5, 7.5, 7.5])
        checks = {item["name"]: item for item in result.checks}
        self.assertEqual(
            checks["rate_limit_signals"]["verification"],
            "response-header-observation",
        )
        self.assertEqual(
            checks["timeout"]["verification"], "request-deadline-applied"
        )
        self.assertTrue(all(request.get_header("Authorization") == f"Bearer {secret}" for request, _ in opener.requests))
        self.assertNotIn(secret, json.dumps(result.to_dict()))

    def test_rejects_missing_key_and_unlisted_model(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(DoctorError, "not set"):
                run_doctor(
                    base_url="https://fixture.example/v1",
                    model="fixture-model",
                    api_key_env="MISSING_KEY",
                    opener=EndpointOpener(),
                )

        with patch.dict(os.environ, {"DOCTOR_KEY": "secret-value"}):
            with self.assertRaisesRegex(DoctorError, "not listed"):
                run_doctor(
                    base_url="https://fixture.example/v1",
                    model="other-model",
                    api_key_env="DOCTOR_KEY",
                    opener=EndpointOpener(),
                )

    def test_rejects_invalid_stream_schema(self):
        opener = EndpointOpener()

        def invalid_stream(request, *, timeout):
            response = opener(request, timeout=timeout)
            if request.data and json.loads(request.data).get("stream"):
                return FakeResponse(b"data: [DONE]\n")
            return response

        with patch.dict(os.environ, {"DOCTOR_KEY": "secret-value"}):
            with self.assertRaisesRegex(DoctorError, "no chat completion SSE events"):
                run_doctor(
                    base_url="https://fixture.example/v1",
                    model="fixture-model",
                    api_key_env="DOCTOR_KEY",
                    opener=invalid_stream,
                )


if __name__ == "__main__":
    unittest.main()
