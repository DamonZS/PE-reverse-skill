"""Tool execution abstractions for local static reverse-engineering analysis."""

from importlib import import_module
from typing import Any

from .executor import ToolExecutor, ToolResult
from .frida import frida_check, frida_hook_profiles, frida_hooks_for_profile, frida_install_guide, frida_trace
from .patch import (
    PatchPlanError,
    android_elf_patch_plan,
    android_elf_patch_verify,
    binary_patch_apply_plan,
    binary_patch_rollback_plan,
    dll_proxy_generate,
    validate_patch_plan,
)
from .procmon import procmon_check, procmon_install_guide, procmon_trace
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide
from .gui import (
    gui_fingerprint,
    gui_resource_extract,
    gui_runtime_probe,
    gui_strategy_select,
    gui_visual_parse,
    gui_visual_regression,
    gui_world_projection,
    reconstruct_gui_project,
)
from .gui_evidence import build_gui_evidence_graph
from .behavior_graph import build_behavior_evidence_graph
from .semantic_ir import build_semantic_ir
from .reconstruction_verify import verify_reconstruction
from .gui_state import build_gui_state_machine
from .gui_xaml import extract_xaml_ui_evidence, parse_xaml_file
from .pe_deep import pe_deep_scan
from .engine import engine_analyze
from .android import android_analyze
from .ios import ios_analyze, ipa_analyze
from .protocol import protocol_analyze, protocol_capture, protocol_infer, protocol_summarize
from .memory import memory_address_map, memory_diff, memory_snapshot
from .reconstruct import reconstruct_project
from .static_tools import register_builtin_tools
from .yara_tools import DEFAULT_RULES_DIR, yara_scan


_LAZY_ANDROID_NATIVE_PATCH_EXPORTS = frozenset(
    {
        "AndroidNativePatchError",
        "ApkPatchLimits",
        "DEFAULT_APK_PATCH_LIMITS",
        "android_native_patch_apk",
        "rollback_android_native_patch_apk",
        "verify_android_native_patch_apk",
    }
)


def __getattr__(name: str) -> Any:
    """Load the APK native patch facade without creating a patch/tools cycle."""

    if name not in _LAZY_ANDROID_NATIVE_PATCH_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = import_module(".android_native_patch", __name__)
    value = getattr(module, name)
    globals()[name] = value
    return value

__all__ = [
    "AndroidNativePatchError",
    "ApkPatchLimits",
    "DEFAULT_APK_PATCH_LIMITS",
    "DEFAULT_RULES_DIR",
    "ToolExecutor",
    "ToolResult",
    "frida_check",
    "frida_hook_profiles",
    "frida_hooks_for_profile",
    "frida_trace",
    "frida_install_guide",
    "PatchPlanError",
    "android_elf_patch_plan",
    "android_elf_patch_verify",
    "binary_patch_apply_plan",
    "binary_patch_rollback_plan",
    "dll_proxy_generate",
    "validate_patch_plan",
    "procmon_check",
    "procmon_trace",
    "procmon_install_guide",
    "ghidra_check",
    "ghidra_decompile",
    "ghidra_install_guide",
    "gui_fingerprint",
    "gui_resource_extract",
    "gui_runtime_probe",
    "gui_strategy_select",
    "gui_visual_parse",
    "gui_visual_regression",
    "gui_world_projection",
    "build_gui_evidence_graph",
    "build_behavior_evidence_graph",
    "build_semantic_ir",
    "verify_reconstruction",
    "build_gui_state_machine",
    "extract_xaml_ui_evidence",
    "parse_xaml_file",
    "pe_deep_scan",
    "engine_analyze",
    "android_analyze",
    "android_native_patch_apk",
    "ios_analyze",
    "ipa_analyze",
    "protocol_capture",
    "protocol_infer",
    "protocol_summarize",
    "protocol_analyze",
    "memory_snapshot",
    "memory_diff",
    "memory_address_map",
    "reconstruct_gui_project",
    "reconstruct_project",
    "register_builtin_tools",
    "rollback_android_native_patch_apk",
    "verify_android_native_patch_apk",
    "yara_scan",
]
