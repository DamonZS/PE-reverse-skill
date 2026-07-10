"""Tool execution abstractions for local static reverse-engineering analysis."""

from .executor import ToolExecutor, ToolResult
from .frida import frida_check, frida_hook_profiles, frida_hooks_for_profile, frida_install_guide, frida_trace
from .procmon import procmon_check, procmon_install_guide, procmon_trace
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide
from .gui import (
    gui_fingerprint,
    gui_resource_extract,
    gui_runtime_probe,
    gui_strategy_select,
    gui_visual_parse,
    gui_visual_regression,
    reconstruct_gui_project,
)
from .gui_evidence import build_gui_evidence_graph
from .behavior_graph import build_behavior_evidence_graph
from .semantic_ir import build_semantic_ir
from .reconstruction_verify import verify_reconstruction
from .gui_state import build_gui_state_machine
from .gui_xaml import extract_xaml_ui_evidence, parse_xaml_file
from .pe_deep import pe_deep_scan
from .reconstruct import reconstruct_project
from .static_tools import register_builtin_tools
from .yara_tools import DEFAULT_RULES_DIR, yara_scan

__all__ = [
    "DEFAULT_RULES_DIR",
    "ToolExecutor",
    "ToolResult",
    "frida_check",
    "frida_hook_profiles",
    "frida_hooks_for_profile",
    "frida_trace",
    "frida_install_guide",
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
    "build_gui_evidence_graph",
    "build_behavior_evidence_graph",
    "build_semantic_ir",
    "verify_reconstruction",
    "build_gui_state_machine",
    "extract_xaml_ui_evidence",
    "parse_xaml_file",
    "pe_deep_scan",
    "reconstruct_gui_project",
    "reconstruct_project",
    "register_builtin_tools",
    "yara_scan",
]
