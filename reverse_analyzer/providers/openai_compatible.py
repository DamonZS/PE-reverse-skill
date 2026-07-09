"""OpenAI-compatible provider stub.

The class reads configuration from environment variables but is deliberately
offline by default.  It can be wired to a future HTTP client by setting
``enabled=True`` and passing a callable transport.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any, Optional

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
    ) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY")
        self.base_url = base_url if base_url is not None else os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.model = model if model is not None else os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
        env_enabled = os.getenv("REVERSE_ANALYZER_OPENAI_ENABLED", "").lower() in {"1", "true", "yes", "on"}
        self.enabled = env_enabled if enabled is None else enabled
        self.transport = transport

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
                content="OpenAI-compatible provider enabled without a transport implementation.",
                final_answer="No OpenAI-compatible transport is configured.",
                barrier=True,
                confidence=1.0,
                metadata={"model": self.model, "base_url": self.base_url, "enabled": True},
            )
        response = self.transport({"model": self.model, "context": dict(context)})
        return ProviderMessage.from_mapping(response)
