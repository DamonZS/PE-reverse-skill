from __future__ import annotations

from reverse_analyzer.providers.mock import MockCapabilityProvider


class PatchExecutorMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("patch_executor")
