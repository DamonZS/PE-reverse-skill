"""Two-stage tool context for model-directed workflow execution."""

from __future__ import annotations

import inspect
from typing import Any, Mapping


DESCRIBE_TOOL = "__describe_tools__"


def shallow_catalog(executor: Any) -> list[dict[str, str]]:
    """Return compact tool identities for the initial model context."""

    tools = _tools(executor)
    return [
        {
            "id": str(name),
            "kind": "tool",
            "summary": _summary(tool),
        }
        for name, tool in sorted(tools.items())
    ]


def tool_details(executor: Any, requested: list[str]) -> list[dict[str, Any]]:
    """Expose detailed contracts only after a model has selected candidates."""

    tools = _tools(executor)
    result: list[dict[str, Any]] = []
    for name in sorted({str(item) for item in requested}):
        tool = tools.get(name)
        if tool is None:
            result.append({"id": name, "available": False, "reason": "not registered"})
            continue
        try:
            signature = str(inspect.signature(tool))
        except (TypeError, ValueError):
            signature = "(**kwargs)"
        result.append(
            {
                "id": name,
                "available": True,
                "summary": _summary(tool),
                "parameters": signature,
                "description": inspect.getdoc(tool) or "No additional description is registered.",
                "execution_boundary": "validated ToolExecutor invocation",
            }
        )
    return result


def _summary(tool: Any) -> str:
    doc = (inspect.getdoc(tool) or "Registered platform tool.").strip().splitlines()[0]
    return doc[:280]


def _tools(executor: Any) -> dict[str, Any]:
    if isinstance(executor, Mapping):
        return {str(name): tool for name, tool in executor.items()}
    return {str(name): tool for name, tool in dict(getattr(executor, "tools", {})).items()}
