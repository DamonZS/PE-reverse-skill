from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from reverse_analyzer.providers.base import CapabilityProvider


class CapabilityRegistry:
    def __init__(self) -> None:
        self._providers: Dict[str, List["CapabilityProvider"]] = {}

    def register(self, provider: "CapabilityProvider") -> None:
        self._providers.setdefault(provider.capability_name, []).append(provider)
        self._providers[provider.capability_name].sort(key=lambda item: item.priority)

    def list_capabilities(self) -> List[str]:
        return sorted(self._providers.keys())

    def list_providers(self, capability_name: str) -> List[str]:
        return [provider.provider_name for provider in self._providers.get(capability_name, [])]

    def resolve(self, capability_name: str, preferred: Optional[str] = None) -> "CapabilityProvider":
        providers = self._providers.get(capability_name, [])
        if not providers:
            raise LookupError(f"No provider registered for capability: {capability_name}")
        if preferred:
            for provider in providers:
                if provider.provider_name == preferred:
                    return provider
            raise LookupError(
                f"Preferred provider '{preferred}' not found for capability '{capability_name}'"
            )
        return providers[0]
