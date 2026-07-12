"""Provider abstractions for agentic reverse-analysis planning."""

from .android_rebuild import AndroidRebuildMockProvider
from .base import BaseProvider, CapabilityProvider, ProviderMessage
from .hook_runtime import HookRuntimeMockProvider
from .injector import InjectorMockProvider
from .memory_runtime import MemoryRuntimeMockProvider
from .mock import MockCapabilityProvider
from .openai_compatible import OpenAICompatibleProvider
from .patch_executor import PatchExecutorMockProvider
from .rule_based import RuleBasedProvider
from reverse_analyzer.core.capabilities.registry import CapabilityRegistry


def build_default_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    for provider in (
        MemoryRuntimeMockProvider(),
        InjectorMockProvider(),
        HookRuntimeMockProvider(),
        PatchExecutorMockProvider(),
        AndroidRebuildMockProvider(),
    ):
        registry.register(provider)
    return registry


__all__ = [
    "AndroidRebuildMockProvider",
    "BaseProvider",
    "CapabilityProvider",
    "HookRuntimeMockProvider",
    "InjectorMockProvider",
    "MemoryRuntimeMockProvider",
    "MockCapabilityProvider",
    "OpenAICompatibleProvider",
    "PatchExecutorMockProvider",
    "ProviderMessage",
    "RuleBasedProvider",
    "build_default_registry",
]
