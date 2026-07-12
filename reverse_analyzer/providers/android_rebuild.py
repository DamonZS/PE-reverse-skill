from __future__ import annotations

from reverse_analyzer.providers.mock import MockCapabilityProvider


class AndroidRebuildMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("android_rebuild")
