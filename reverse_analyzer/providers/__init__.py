"""Provider abstractions for agentic reverse-analysis planning."""

from reverse_analyzer.core.capabilities.registry import CapabilityRegistry

from .android_instrumentation import AndroidInstrumentationProvider
from .android_native_patch import AndroidNativePatchProvider
from .android_rebuild import AndroidRebuildMockProvider, AndroidRebuildProvider
from .anti_tamper_lab import AntiTamperLabProvider
from .base import BaseProvider, CapabilityProvider, ProviderMessage
from .dma_memory import DMAMemoryProvider
from .engine_runtime import EngineRuntimeProvider, parse_engine_runtime_dump
from .graphics_runtime import GraphicsRuntimeProvider
from .hardware_identity import HardwareIdentityProvider
from .hook_runtime import HookRuntimeMockProvider, HookRuntimeProvider
from .hook_target_resolver import HookTargetResolverProvider
from .imgui_renderer import ImGuiHostOrchestrator, ImGuiRendererProvider
from .injector import InjectorMockProvider, InjectorProvider
from .ios_instrumentation import IOSInstrumentationProvider
from .ios_rebuild import IOSRebuildProvider, IosRebuildProvider
from .kernel_memory import KernelDriverMemoryProvider
from .memory_runtime import MemoryRuntimeMockProvider, MemoryRuntimeProvider
from .mock import MockCapabilityProvider
from .native_debugger import NativeDebuggerProvider
from .native_hook import NativeHookProvider
from .openai_compatible import OpenAICompatibleProvider
from .patch_executor import PatchExecutorMockProvider, PatchExecutorProvider
from .protocol_runtime import ProtocolRuntimeMockProvider, ProtocolRuntimeProvider
from .render_overlay import RenderOverlayProvider
from .rule_based import RuleBasedProvider
from .target_control import TargetControlProvider


_CAPABILITY_PROVIDER_METHODS = (
    "plan",
    "validate",
    "execute",
    "rollback",
    "collect_artifacts",
)


def build_default_registry() -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registered: set[tuple[str, str]] = set()
    for provider in (
        AndroidInstrumentationProvider(),
        AndroidNativePatchProvider(),
        AntiTamperLabProvider(),
        IOSInstrumentationProvider(),
        EngineRuntimeProvider(),
        DMAMemoryProvider(),
        GraphicsRuntimeProvider(),
        HardwareIdentityProvider(),
        ImGuiRendererProvider(),
        KernelDriverMemoryProvider(),
        MemoryRuntimeProvider(),
        MemoryRuntimeMockProvider(),
        InjectorProvider(),
        InjectorMockProvider(),
        HookRuntimeProvider(),
        HookRuntimeMockProvider(),
        HookTargetResolverProvider(),
        NativeHookProvider(),
        NativeDebuggerProvider(),
        PatchExecutorProvider(),
        PatchExecutorMockProvider(),
        AndroidRebuildProvider(),
        AndroidRebuildMockProvider(),
        IosRebuildProvider(),
        ProtocolRuntimeProvider(),
        ProtocolRuntimeMockProvider(),
        RenderOverlayProvider(),
        TargetControlProvider(),
    ):
        capability_name = str(getattr(provider, "capability_name", "")).strip()
        provider_name = str(getattr(provider, "provider_name", "")).strip()
        if not capability_name or not provider_name:
            raise ValueError("default capability providers must declare non-empty names")
        registration = (capability_name, provider_name)
        if registration in registered:
            raise ValueError(
                "duplicate default capability/provider registration: "
                f"{capability_name}/{provider_name}"
            )
        missing_methods = [
            method
            for method in _CAPABILITY_PROVIDER_METHODS
            if not callable(getattr(provider, method, None))
        ]
        if missing_methods:
            raise TypeError(
                f"default provider {provider_name!r} is missing lifecycle methods: "
                + ", ".join(missing_methods)
            )
        registered.add(registration)
        registry.register(provider)
    return registry


__all__ = [
    "AndroidInstrumentationProvider",
    "AndroidNativePatchProvider",
    "AndroidRebuildMockProvider",
    "AndroidRebuildProvider",
    "AntiTamperLabProvider",
    "BaseProvider",
    "CapabilityProvider",
    "DMAMemoryProvider",
    "EngineRuntimeProvider",
    "GraphicsRuntimeProvider",
    "HardwareIdentityProvider",
    "HookRuntimeMockProvider",
    "HookRuntimeProvider",
    "HookTargetResolverProvider",
    "ImGuiHostOrchestrator",
    "ImGuiRendererProvider",
    "InjectorMockProvider",
    "InjectorProvider",
    "IOSInstrumentationProvider",
    "IOSRebuildProvider",
    "IosRebuildProvider",
    "KernelDriverMemoryProvider",
    "MemoryRuntimeMockProvider",
    "MemoryRuntimeProvider",
    "MockCapabilityProvider",
    "NativeDebuggerProvider",
    "NativeHookProvider",
    "OpenAICompatibleProvider",
    "PatchExecutorMockProvider",
    "PatchExecutorProvider",
    "ProviderMessage",
    "ProtocolRuntimeMockProvider",
    "ProtocolRuntimeProvider",
    "RenderOverlayProvider",
    "RuleBasedProvider",
    "TargetControlProvider",
    "build_default_registry",
    "parse_engine_runtime_dump",
]
