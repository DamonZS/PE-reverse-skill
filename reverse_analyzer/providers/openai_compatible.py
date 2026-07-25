"""OpenAI-compatible provider stub.

The class reads configuration from environment variables but is deliberately
offline by default.  It can be wired to a future HTTP client by setting
``enabled=True`` and passing a callable transport.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, Optional
from urllib import error, request

from .base import ProviderMessage


class OpenAICompatibleProvider:
    name = "openai_compatible"

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        transport: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
        api_keys: Optional[list[str]] = None,
    ) -> None:
        local = _load_local_provider_config()
        local_keys = local.get("api_keys", [])
        configured_keys = local_keys if isinstance(local_keys, list) else []
        env_keys = [item.strip() for item in os.getenv("OPENAI_API_KEYS", "").split(",") if item.strip()]
        single_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        if api_keys is not None:
            selected_keys = api_keys
        elif env_keys or single_key:
            selected_keys = [*env_keys, *([single_key] if single_key else [])]
        else:
            selected_keys = configured_keys
        self.api_keys = _deduplicate_secrets(selected_keys)
        self.api_key = self.api_keys[0] if self.api_keys else None
        self.base_url = base_url if base_url is not None else os.getenv("OPENAI_BASE_URL") or local.get("base_url") or "https://api.openai.com/v1"
        self.model = model if model is not None else os.getenv("OPENAI_MODEL") or local.get("model") or "gpt-4.1-mini"
        self.display_name = str(local.get("display_name") or self.model)
        env_enabled = os.getenv("REVERSE_ANALYZER_OPENAI_ENABLED", "").lower() in {"1", "true", "yes", "on"}
        self.enabled = env_enabled if enabled is None else enabled
        self.broker_dir = os.getenv("REVERSE_ANALYZER_PROVIDER_BROKER_DIR", "").strip()
        self.transport = transport or (
            self._broker_transport
            if self.enabled and self.broker_dir
            else self._http_transport
            if self.enabled and self.api_keys
            else None
        )

    def _broker_transport(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        root = Path(self.broker_dir).resolve(strict=True)
        inbox = (root / "inbox").resolve(strict=True)
        outbox = (root / "outbox").resolve(strict=True)
        if root.is_symlink() or inbox.is_symlink() or outbox.is_symlink():
            raise RuntimeError("provider broker directories must not be symbolic links")
        if inbox.parent != root or outbox.parent != root:
            raise RuntimeError("provider broker directory boundary is invalid")
        request_id = uuid.uuid4().hex
        timeout = min(600.0, max(1.0, float(os.getenv("REVERSE_ANALYZER_PROVIDER_TIMEOUT", "60"))))
        max_tokens = max(1, int(os.getenv("REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS", "4096")))
        nested = context.get("context")
        requested = nested.get("max_output_tokens") if isinstance(nested, Mapping) else None
        if isinstance(requested, int) and not isinstance(requested, bool) and requested > 0:
            max_tokens = min(max_tokens, requested)
        payload = {"schema_version": 1, "request_id": request_id, "provider": "openai_compatible", "model": self.model, "timeout_seconds": timeout, "max_output_tokens": max_tokens, "context": dict(context)}
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
        if len(encoded) > 4 * 1024 * 1024:
            raise RuntimeError("provider broker request exceeds 4 MiB")
        temporary = inbox / f".{request_id}.tmp"
        destination = inbox / f"{request_id}.json"
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        response_path = outbox / f"{request_id}.json"
        deadline = time.monotonic() + timeout + 5.0
        while time.monotonic() < deadline:
            try:
                if response_path.is_symlink():
                    raise RuntimeError("provider broker response must not be a symbolic link")
                raw = response_path.read_bytes()
            except FileNotFoundError:
                time.sleep(0.05)
                continue
            if len(raw) > 4 * 1024 * 1024:
                raise RuntimeError("provider broker response exceeds 4 MiB")
            response = json.loads(raw.decode("utf-8"))
            if not isinstance(response, Mapping) or response.get("request_id") != request_id:
                raise RuntimeError("provider broker response identity mismatch")
            if response.get("status") != "ok":
                raise RuntimeError(str(response.get("error") or "provider broker request failed"))
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise RuntimeError("provider broker response result is invalid")
            return result
        raise TimeoutError("provider broker response timed out")

    def _http_transport(self, context: Mapping[str, Any]) -> Mapping[str, Any]:
        configured_max_tokens = max(1, int(os.getenv("REVERSE_ANALYZER_PROVIDER_MAX_OUTPUT_TOKENS", "4096")))
        nested_context = context.get("context")
        requested_max_tokens = nested_context.get("max_output_tokens") if isinstance(nested_context, Mapping) else None
        if isinstance(requested_max_tokens, int) and not isinstance(requested_max_tokens, bool) and requested_max_tokens > 0:
            configured_max_tokens = min(configured_max_tokens, requested_max_tokens)
        payload = {
            "model": self.model,
            "max_tokens": configured_max_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "system",
                    "content": "You are an authorized defensive reverse-analysis assistant. Return concise, evidence-grounded analysis and do not invent observations.",
                },
                {"role": "user", "content": json.dumps(dict(context), ensure_ascii=False, default=str)},
            ],
        }
        endpoint = f"{self.base_url.rstrip('/')}/chat/completions"
        encoded_payload = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        timeout = float(os.getenv("REVERSE_ANALYZER_PROVIDER_TIMEOUT", "60"))
        max_retries = max(0, int(os.getenv("REVERSE_ANALYZER_PROVIDER_MAX_RETRIES", "2")))
        backoff = max(0.0, float(os.getenv("REVERSE_ANALYZER_PROVIDER_RETRY_BACKOFF", "0.5")))
        started = time.monotonic()
        decoded: Mapping[str, Any] | None = None
        attempts = 0
        selected_slot = 0
        failures: list[dict[str, Any]] = []
        for slot, key in enumerate(self.api_keys, start=1):
            switch_key = False
            for attempt in range(max_retries + 1):
                attempts += 1
                http_request = request.Request(endpoint, data=encoded_payload, headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"}, method="POST")
                try:
                    with request.urlopen(http_request, timeout=timeout) as response:
                        decoded = json.loads(response.read().decode("utf-8"))
                    selected_slot = slot
                    break
                except error.HTTPError as exc:
                    failures.append({"key_slot": slot, "http_status": exc.code, "error_type": "HTTPError"})
                    if exc.code in {401, 403}:
                        switch_key = True
                        break
                    if exc.code != 429 and exc.code < 500:
                        raise
                    if attempt >= max_retries:
                        switch_key = True
                        break
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    try:
                        delay = float(retry_after) if retry_after else backoff * (2**attempt)
                    except (TypeError, ValueError):
                        delay = backoff * (2**attempt)
                    time.sleep(max(0.0, delay))
                except (error.URLError, TimeoutError) as exc:
                    failures.append({"key_slot": slot, "http_status": None, "error_type": type(exc).__name__})
                    if attempt >= max_retries:
                        switch_key = True
                        break
                    time.sleep(backoff * (2**attempt))
            if decoded is not None:
                break
            if not switch_key:
                break
        if decoded is None:
            raise RuntimeError("OpenAI-compatible provider exhausted retries without a response")
        choices = decoded.get("choices") or []
        if not choices:
            raise RuntimeError("OpenAI-compatible response did not contain choices")
        message = choices[0].get("message") or {}
        content = str(message.get("content") or "")
        return {
            "content": content,
            "final_answer": content,
            "confidence": 0.7,
            "metadata": {
                "model": decoded.get("model") or self.model,
                "base_url": self.base_url,
                "usage": decoded.get("usage") or {},
                "finish_reason": choices[0].get("finish_reason"),
                "attempts": attempts,
                "latency_ms": round((time.monotonic() - started) * 1000, 3),
                "request_id": decoded.get("id"),
                "key_slot": selected_slot,
                "fallback_count": max(0, selected_slot - 1),
                "key_failures": failures,
                "display_name": self.display_name,
            },
        }

    def analyze(self, context: Mapping[str, Any]) -> ProviderMessage:
        if not self.enabled:
            return ProviderMessage(
                content="OpenAI-compatible provider is configured but disabled; no network call was made.",
                final_answer="OpenAI-compatible provider disabled. Use RuleBasedProvider or enable explicitly.",
                barrier=True,
                confidence=1.0,
                metadata={"model": self.model, "base_url": self.base_url, "enabled": False},
            )
        if self.transport is None:
            return ProviderMessage(
                content="OpenAI-compatible provider enabled without an API key or transport implementation.",
                final_answer="No OpenAI-compatible transport is configured.",
                barrier=True,
                confidence=1.0,
                metadata={"model": self.model, "base_url": self.base_url, "enabled": True},
            )
        response = self.transport({"model": self.model, "context": dict(context)})
        return ProviderMessage.from_mapping(response)


def _load_local_provider_config() -> dict[str, Any]:
    configured = os.getenv("REVERSE_ANALYZER_PROVIDER_CONFIG", "").strip()
    candidates = [Path(configured)] if configured else [Path.cwd() / "config" / "provider.local.json"]
    for path in candidates:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(value, dict):
            return value
    return {}


def _deduplicate_secrets(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in result:
            result.append(text)
    return result
