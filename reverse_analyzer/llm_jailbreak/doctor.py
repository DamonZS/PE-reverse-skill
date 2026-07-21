from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping


class DoctorError(RuntimeError):
    """Raised when an endpoint fails a production readiness check."""


@dataclass(frozen=True)
class DoctorResult:
    status: str
    base_url: str
    model: str
    checks: tuple[Mapping[str, Any], ...]
    elapsed_seconds: float

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reverse_analyzer.llm_jailbreak.doctor/v1",
            "status": self.status,
            "base_url": self.base_url,
            "model": self.model,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "checks": [dict(item) for item in self.checks],
        }


def _api_root(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DoctorError("base URL must be an absolute HTTP(S) URL")
    suffix = "/chat/completions"
    return value[: -len(suffix)] if value.endswith(suffix) else value


def _headers(api_key_env: str) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "reverse-analyzer-llm-jailbreak-doctor/1",
    }
    if api_key_env:
        key = os.getenv(api_key_env)
        if not key:
            raise DoctorError(
                f"API key environment variable is not set: {api_key_env}"
            )
        headers["Authorization"] = f"Bearer {key}"
    return headers


def _open(
    opener: Callable[..., Any],
    request: urllib.request.Request,
    timeout: float,
) -> tuple[int, Mapping[str, str], bytes]:
    try:
        response = opener(request, timeout=timeout)
        try:
            status = int(getattr(response, "status", 200) or 200)
            headers = dict(getattr(response, "headers", {}) or {})
            body = response.read()
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()
    except urllib.error.HTTPError as exc:
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        suffix = f"; retry-after={retry_after}" if retry_after else ""
        raise DoctorError(f"HTTP {exc.code}{suffix}") from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        raise DoctorError(f"request failed: {exc}") from exc
    if status >= 400:
        raise DoctorError(f"HTTP {status}")
    return status, headers, body


def _json_body(body: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DoctorError(f"{label} response is not valid JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise DoctorError(f"{label} response must be a JSON object")
    return value


def run_doctor(
    *,
    base_url: str,
    model: str,
    api_key_env: str = "OPENAI_API_KEY",
    timeout_seconds: float = 30.0,
    opener: Callable[..., Any] | None = None,
) -> DoctorResult:
    """Probe endpoint compatibility without running a campaign."""

    if not model.strip():
        raise DoctorError("model must be non-empty")
    if timeout_seconds <= 0:
        raise DoctorError("timeout must be greater than zero")
    root = _api_root(base_url)
    request_headers = _headers(api_key_env)
    open_request = opener or urllib.request.urlopen
    checks: list[Mapping[str, Any]] = []
    started = time.monotonic()

    models_request = urllib.request.Request(
        root + "/models", headers=request_headers, method="GET"
    )
    _, model_headers, model_body = _open(open_request, models_request, timeout_seconds)
    models_payload = _json_body(model_body, "models")
    model_items = models_payload.get("data")
    if not isinstance(model_items, list):
        raise DoctorError("models response.data must be an array")
    model_ids = {
        str(item.get("id"))
        for item in model_items
        if isinstance(item, Mapping) and item.get("id") is not None
    }
    if model not in model_ids:
        raise DoctorError(f"model is not listed by the endpoint: {model}")
    checks.append({"name": "models", "status": "ok", "model_found": True})

    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": "Reply with the single word READY. This is a connectivity check.",
            }
        ],
        "temperature": 0,
        "max_tokens": 8,
    }
    chat_url = root + "/chat/completions"
    non_stream_request = urllib.request.Request(
        chat_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    _, chat_headers, chat_body = _open(
        open_request, non_stream_request, timeout_seconds
    )
    chat_payload = _json_body(chat_body, "chat completion")
    choices = chat_payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        raise DoctorError("chat completion response.choices must contain an object")
    if not isinstance(choices[0].get("message"), Mapping):
        raise DoctorError("chat completion response is missing choices[0].message")
    checks.append({"name": "chat_non_stream", "status": "ok"})

    stream_payload = dict(payload)
    stream_payload["stream"] = True
    stream_request = urllib.request.Request(
        chat_url,
        data=json.dumps(stream_payload).encode("utf-8"),
        headers={**request_headers, "Accept": "text/event-stream"},
        method="POST",
    )
    _, stream_headers, stream_body = _open(open_request, stream_request, timeout_seconds)
    events = []
    for raw_line in stream_body.decode("utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith("data:"):
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            continue
        try:
            event = json.loads(data)
        except json.JSONDecodeError as exc:
            raise DoctorError(f"stream response contains invalid SSE JSON: {exc}") from exc
        event_choices = event.get("choices") if isinstance(event, Mapping) else None
        if (
            isinstance(event_choices, list)
            and event_choices
            and isinstance(event_choices[0], Mapping)
            and isinstance(event_choices[0].get("delta"), Mapping)
        ):
            events.append(event)
    if not events:
        raise DoctorError("stream response contains no chat completion SSE events")
    checks.append({"name": "chat_stream", "status": "ok", "event_count": len(events)})

    rate_headers = {**model_headers, **chat_headers, **stream_headers}
    observed = {
        str(key).lower(): str(value)
        for key, value in rate_headers.items()
        if "ratelimit" in str(key).lower() or str(key).lower() == "retry-after"
    }
    checks.append(
        {
            "name": "rate_limit_signals",
            "status": "ok",
            "verification": "response-header-observation",
            "observed": observed,
        }
    )
    checks.append(
        {
            "name": "timeout",
            "status": "ok",
            "verification": "request-deadline-applied",
            "configured_seconds": timeout_seconds,
        }
    )
    return DoctorResult(
        status="ok",
        base_url=root,
        model=model,
        checks=tuple(checks),
        elapsed_seconds=time.monotonic() - started,
    )
