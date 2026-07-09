"""Tool execution abstractions for local static reverse-engineering analysis."""

from .executor import ToolExecutor, ToolResult
from .static_tools import register_builtin_tools

__all__ = ["ToolExecutor", "ToolResult", "register_builtin_tools"]
