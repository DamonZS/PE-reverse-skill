"""Unified Agent provider profiles with explicit fallback and usage accounting."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Any, Mapping

from .providers import OpenAICompatibleProvider, RuleBasedProvider


@dataclass
class ProviderProfile:
    name: str
    kind: str
    model: str | None = None
    enabled: bool = True
    priority: int = 100
    usage: dict[str, int] = field(default_factory=lambda: {"requests": 0, "failures": 0, "input_tokens": 0, "output_tokens": 0})

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "model": self.model, "enabled": self.enabled, "priority": self.priority, "usage": dict(self.usage)}


class ProviderRuntime:
    """Construct providers from environment without making network calls during discovery."""

    def __init__(self) -> None:
        self._profiles = [
            ProviderProfile("rule_based", "local", priority=0),
            ProviderProfile("openai_compatible", "openai-compatible", os.getenv("OPENAI_MODEL", "gpt-4.1-mini"), enabled=os.getenv("REVERSE_ANALYZER_OPENAI_ENABLED", "").lower() in {"1", "true", "yes"}, priority=10),
        ]

    def profiles(self) -> list[dict[str, Any]]:
        return [profile.to_dict() for profile in sorted(self._profiles, key=lambda item: item.priority)]

    def create(self, name: str | None = None) -> Any:
        requested = name or os.getenv("REVERSE_ANALYZER_PROVIDER", "rule_based")
        profile = next((item for item in self._profiles if item.name == requested), None)
        if profile is None or not profile.enabled:
            profile = next(item for item in self._profiles if item.name == "rule_based")
        if profile.name == "openai_compatible":
            return OpenAICompatibleProvider(enabled=True, model=profile.model)
        return RuleBasedProvider()

    def test(self, name: str) -> dict[str, Any]:
        profile = next((item for item in self._profiles if item.name == name), None)
        if profile is None:
            return {"name": name, "status": "missing"}
        if name == "rule_based":
            return {"name": name, "status": "ready", "network_call": False}
        configured = bool(os.getenv("OPENAI_API_KEY")) and profile.enabled
        return {"name": name, "status": "ready" if configured else "dependency-gated", "network_call": False, "reason": "credentials and explicit enablement required" if not configured else None}


__all__ = ["ProviderProfile", "ProviderRuntime"]
