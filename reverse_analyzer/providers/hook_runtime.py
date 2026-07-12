from __future__ import annotations

from reverse_analyzer.providers.mock import MockCapabilityProvider


class HookRuntimeMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("hook_runtime")
