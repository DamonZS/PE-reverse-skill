from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence, Union

from .models import ChatMessage, ChatResponse, TargetConfig


class TransportError(RuntimeError):
    """Base error for model transport failures."""


class TransportConfigurationError(TransportError):
    """Raised when required target configuration is unavailable."""


class TransportResponseError(TransportError):
    """Raised when an endpoint returns a malformed response."""


class ChatTransport(Protocol):
    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float,
        max_tokens: Optional[int],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ChatResponse:
        ...


def _response_content(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, Mapping):
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


def normalize_chat_response(value: Any, *, fallback_model: str = "") -> ChatResponse:
    if isinstance(value, ChatResponse):
        return value
    if isinstance(value, str):
        return ChatResponse(content=value, model=fallback_model)
    if not isinstance(value, Mapping):
        raise TransportResponseError("transport returned neither ChatResponse, string, nor object")

    if "choices" in value:
        choices = value.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
            raise TransportResponseError("response.choices must contain at least one object")
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, Mapping):
            raise TransportResponseError("response.choices[0].message is missing")
        content = _response_content(message.get("content"))
        return ChatResponse(
            content=content,
            model=str(value.get("model", fallback_model)),
            usage=dict(value.get("usage", {})) if isinstance(value.get("usage", {}), Mapping) else {},
            finish_reason=str(choice.get("finish_reason", "")),
            response_id=str(value.get("id", "")),
            metadata={"provider_response_type": "chat.completion"},
        )
    normalized = ChatResponse.from_dict(value)
    if normalized.model or not fallback_model:
        return normalized
    return ChatResponse(
        content=normalized.content,
        model=fallback_model,
        usage=normalized.usage,
        finish_reason=normalized.finish_reason,
        response_id=normalized.response_id,
        latency_seconds=normalized.latency_seconds,
        metadata=normalized.metadata,
    )


class OpenAICompatibleTransport:
    """Standard-library transport for OpenAI-compatible chat completions."""

    RETRYABLE_STATUS_CODES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})

    def __init__(
        self,
        *,
        base_url: str,
        api_key_env: str = "OPENAI_API_KEY",
        timeout_seconds: float = 60.0,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.0,
        requests_per_minute: float = 0.0,
        extra_body: Optional[Mapping[str, Any]] = None,
        opener: Optional[Callable[..., Any]] = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.endpoint = self._endpoint(self.base_url)
        self.api_key_env = api_key_env
        self.timeout_seconds = float(timeout_seconds)
        self.max_retries = int(max_retries)
        self.retry_backoff_seconds = float(retry_backoff_seconds)
        self.requests_per_minute = float(requests_per_minute)
        self.extra_body = dict(extra_body or {})
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep
        self._clock = clock
        self._last_request_at: Optional[float] = None
        self._rate_lock = threading.Lock()

    @classmethod
    def from_target(cls, target: TargetConfig) -> "OpenAICompatibleTransport":
        return cls(
            base_url=target.base_url,
            api_key_env=target.api_key_env,
            timeout_seconds=target.timeout_seconds,
            max_retries=target.max_retries,
            retry_backoff_seconds=target.retry_backoff_seconds,
            requests_per_minute=target.requests_per_minute,
            extra_body=target.extra_body,
        )

    @staticmethod
    def _endpoint(base_url: str) -> str:
        normalized = base_url.rstrip("/")
        if normalized.endswith("/chat/completions"):
            return normalized
        return normalized + "/chat/completions"

    def _headers(self) -> Mapping[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "reverse-analyzer-llm-jailbreak/1",
        }
        if self.api_key_env:
            api_key = os.getenv(self.api_key_env)
            if not api_key:
                raise TransportConfigurationError(
                    f"API key environment variable is not set: {self.api_key_env}"
                )
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _wait_for_rate_limit(self) -> None:
        if self.requests_per_minute <= 0:
            return
        minimum_interval = 60.0 / self.requests_per_minute
        with self._rate_lock:
            now = self._clock()
            if self._last_request_at is not None:
                remaining = minimum_interval - (now - self._last_request_at)
                if remaining > 0:
                    self._sleep(remaining)
                    now = self._clock()
            self._last_request_at = now

    def _retry_delay(self, retry_number: int, retry_after: Optional[str] = None) -> float:
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
        return self.retry_backoff_seconds * (2 ** max(0, retry_number - 1))

    def complete(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        temperature: float,
        max_tokens: Optional[int],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> ChatResponse:
        payload = dict(self.extra_body)
        payload.update(
            {
                "model": model,
                "messages": [
                    item.to_dict() if isinstance(item, ChatMessage) else dict(item)
                    for item in messages
                ],
                "temperature": temperature,
            }
        )
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = self._headers()

        last_error: Optional[BaseException] = None
        for attempt_number in range(self.max_retries + 1):
            self._wait_for_rate_limit()
            request = urllib.request.Request(
                self.endpoint,
                data=encoded,
                headers=dict(headers),
                method="POST",
            )
            started = self._clock()
            try:
                response = self._opener(request, timeout=self.timeout_seconds)
                try:
                    body = response.read()
                    status = int(getattr(response, "status", 200) or 200)
                finally:
                    close = getattr(response, "close", None)
                    if callable(close):
                        close()
                if status >= 400:
                    raise TransportError(f"chat completion endpoint returned HTTP {status}")
                try:
                    decoded = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise TransportResponseError(f"chat completion response is not valid JSON: {exc}") from exc
                normalized = normalize_chat_response(decoded, fallback_model=model)
                return ChatResponse(
                    content=normalized.content,
                    model=normalized.model or model,
                    usage=normalized.usage,
                    finish_reason=normalized.finish_reason,
                    response_id=normalized.response_id,
                    latency_seconds=max(0.0, self._clock() - started),
                    metadata={
                        **dict(normalized.metadata),
                        "endpoint": self.endpoint,
                        "campaign_attempt": dict(metadata or {}),
                    },
                )
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code not in self.RETRYABLE_STATUS_CODES or attempt_number >= self.max_retries:
                    try:
                        detail = exc.read().decode("utf-8", errors="replace")[:500]
                    except Exception:
                        detail = ""
                    suffix = f": {detail}" if detail else ""
                    raise TransportError(f"chat completion HTTP {exc.code}{suffix}") from exc
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                self._sleep(self._retry_delay(attempt_number + 1, retry_after))
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                last_error = exc
                if attempt_number >= self.max_retries:
                    raise TransportError(f"chat completion request failed: {exc}") from exc
                self._sleep(self._retry_delay(attempt_number + 1))

        raise TransportError(f"chat completion request failed: {last_error}")


TransportLike = Union[ChatTransport, Callable[..., Any]]
