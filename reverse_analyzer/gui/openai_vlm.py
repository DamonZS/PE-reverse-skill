"""OpenAI-compatible production adapter for GUI image analysis."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest


_DEFAULT_PROMPT = (
    "Analyze this GUI screenshot. Return only one JSON object with keys "
    "status, text_regions, and widgets. status must be ok or partial. "
    "Each text_regions item may contain text, confidence, and bbox. Each "
    "widgets item may contain type, text, confidence, and bbox. A bbox is "
    "an object with numeric x, y, width, and height pixel coordinates."
)
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_MAX_PROMPT_CHARS = 16_384
_DEFAULT_MAX_IMAGE_BYTES = 20 * 1024 * 1024
_MAX_CONFIGURED_IMAGE_BYTES = 64 * 1024 * 1024
_JSON_FENCE_RE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.IGNORECASE | re.DOTALL)
_ALLOWED_CONFIG_KEYS = {
    "api_key",
    "base_url",
    "detail",
    "json_mode",
    "max_image_bytes",
    "max_tokens",
    "model",
    "prompt",
    "temperature",
}


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class OpenAICompatibleVLM:
    """Send a bounded image request to an OpenAI-compatible chat endpoint."""

    name = "openai-compatible-vlm"

    def __init__(self, *, config: Mapping[str, Any]) -> None:
        values = dict(config)
        unknown = sorted(str(key) for key in values if key not in _ALLOWED_CONFIG_KEYS)
        if unknown:
            raise ValueError(f"unsupported OpenAI VLM option(s): {', '.join(unknown)}")

        self.base_url = _endpoint(str(values.get("base_url") or ""))
        self.model = _required_text(values.get("model"), "model", maximum=256)
        self.api_key = _required_text(values.get("api_key"), "api_key", maximum=16_384)
        self.prompt = _optional_text(values.get("prompt"), _DEFAULT_PROMPT, "prompt", _MAX_PROMPT_CHARS)
        self.detail = _choice(values.get("detail", "auto"), "detail", {"auto", "low", "high"})
        self.max_tokens = _integer(values.get("max_tokens", 2_048), "max_tokens", 1, 32_768)
        self.max_image_bytes = _integer(
            values.get("max_image_bytes", _DEFAULT_MAX_IMAGE_BYTES),
            "max_image_bytes",
            1,
            _MAX_CONFIGURED_IMAGE_BYTES,
        )
        self.temperature = _number(values.get("temperature", 0), "temperature", 0, 2)
        json_mode = values.get("json_mode", True)
        if not isinstance(json_mode, bool):
            raise ValueError("json_mode must be a boolean")
        self.json_mode = json_mode
        self._opener = urlrequest.build_opener(_NoRedirect())

    def analyze(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        image_path = Path(str(request.get("image_path") or ""))
        image = image_path.read_bytes()
        if not image or len(image) > self.max_image_bytes:
            raise ValueError("VLM image size is outside the configured range")
        expected_size = request.get("size_bytes")
        expected_digest = str(request.get("sha256") or "").lower()
        actual_digest = hashlib.sha256(image).hexdigest()
        if expected_size != len(image) or expected_digest != actual_digest:
            raise ValueError("VLM image changed after request validation")

        media_type = str(request.get("media_type") or "")
        if not media_type.startswith("image/"):
            raise ValueError("VLM request media_type must be an image type")
        data_url = f"data:{media_type};base64,{base64.b64encode(image).decode('ascii')}"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": self.prompt},
                        {"type": "image_url", "image_url": {"url": data_url, "detail": self.detail}},
                    ],
                }
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": False,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}

        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        http_request = urlrequest.Request(
            self.base_url,
            data=encoded,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "reverse-analyzer-gui-vlm/1",
            },
        )
        timeout = float(request.get("timeout_seconds") or 30)
        try:
            with self._opener.open(http_request, timeout=timeout) as response:
                body = response.read(_MAX_RESPONSE_BYTES + 1)
        except urlerror.HTTPError as exc:
            raise RuntimeError(f"OpenAI-compatible VLM HTTP request failed with status {exc.code}") from exc
        except urlerror.URLError as exc:
            reason = type(getattr(exc, "reason", exc)).__name__
            raise RuntimeError(f"OpenAI-compatible VLM transport failed: {reason}") from exc
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ValueError("OpenAI-compatible VLM response exceeds the size limit")
        try:
            envelope = json.loads(body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("OpenAI-compatible VLM returned invalid JSON") from exc

        content = _completion_content(envelope)
        result = _model_json(content)
        result["schema_version"] = 1
        result.setdefault("status", "ok")
        result.setdefault("text_regions", [])
        result.setdefault("widgets", [])
        provenance = {
            "provider": self.name,
            "model": str(envelope.get("model") or self.model),
        }
        request_id = envelope.get("id")
        if isinstance(request_id, (str, int)) and not isinstance(request_id, bool):
            provenance["request_id"] = request_id
        result["provenance"] = provenance
        return result


def _endpoint(value: str) -> str:
    text = value.strip().rstrip("/")
    parsed = urlparse.urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("base_url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("base_url must not contain credentials, query, or fragment")
    if not parsed.path.rstrip("/").endswith("/chat/completions"):
        text += "/chat/completions"
    return text


def _completion_content(envelope: Any) -> Any:
    if not isinstance(envelope, Mapping):
        raise ValueError("OpenAI-compatible VLM response must be an object")
    choices = envelope.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        raise ValueError("OpenAI-compatible VLM response has no completion choice")
    message = choices[0].get("message")
    if not isinstance(message, Mapping):
        raise ValueError("OpenAI-compatible VLM response has no completion message")
    content = message.get("content")
    if isinstance(content, list):
        parts = [
            str(item.get("text"))
            for item in content
            if isinstance(item, Mapping) and isinstance(item.get("text"), str)
        ]
        content = "".join(parts)
    return content


def _model_json(content: Any) -> dict[str, Any]:
    if isinstance(content, Mapping):
        return dict(content)
    if not isinstance(content, str) or not content.strip():
        raise ValueError("OpenAI-compatible VLM completion content is empty")
    text = content.strip()
    fenced = _JSON_FENCE_RE.fullmatch(text)
    if fenced:
        text = fenced.group(1).strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("OpenAI-compatible VLM completion is not a JSON object") from exc
    if not isinstance(value, Mapping):
        raise ValueError("OpenAI-compatible VLM completion must be a JSON object")
    return dict(value)


def _required_text(value: Any, name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value.strip()


def _optional_text(value: Any, default: str, name: str, maximum: int) -> str:
    return _required_text(default if value is None else value, name, maximum=maximum)


def _choice(value: Any, name: str, allowed: set[str]) -> str:
    text = str(value).strip().lower()
    if text not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return text


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    number = float(value)
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum:g} and {maximum:g}")
    return number
