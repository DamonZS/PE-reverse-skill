"""Tool execution abstractions for local static reverse-engineering analysis."""

from .executor import ToolExecutor, ToolResult
from .static_tools import register_builtin_tools
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide

__all__ = ["ToolExecutor", "ToolResult", "ghidra_check", "ghidra_decompile", "ghidra_install_guide", "register_builtin_tools"]
