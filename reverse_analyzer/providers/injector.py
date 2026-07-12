from __future__ import annotations

from reverse_analyzer.providers.mock import MockCapabilityProvider


class InjectorMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("injector")
