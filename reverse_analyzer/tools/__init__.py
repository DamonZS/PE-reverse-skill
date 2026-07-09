"""Tool execution abstractions for local static reverse-engineering analysis."""

from .executor import ToolExecutor, ToolResult
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide
from .pe_deep import pe_deep_scan
from .reconstruct import reconstruct_project
from .static_tools import register_builtin_tools
from .yara_tools import DEFAULT_RULES_DIR, yara_scan

__all__ = [
    "DEFAULT_RULES_DIR",
    "ToolExecutor",
    "ToolResult",
    "ghidra_check",
    "ghidra_decompile",
    "ghidra_install_guide",
    "pe_deep_scan",
    "reconstruct_project",
    "register_builtin_tools",
    "yara_scan",
]
