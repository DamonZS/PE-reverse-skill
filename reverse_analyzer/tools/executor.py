"""Small, dependency-light tool executor abstraction.

The executor is intentionally generic: tools are normal Python callables that
return JSON-serializable data. Exceptions are captured and normalized into a
failed :class:`ToolResult` instead of escaping through the orchestration layer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Callable, Dict, Mapping, MutableMapping

ToolCallable = Callable[..., Any]


@dataclass(slots=True)
class ToolResult:
    """Normalized result produced by every tool invocation."""

    tool: str
    status: str
    data: Any = None
    error: str | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    started_at: str | None = None
    finished_at: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable dictionary representation."""

        return _json_safe(asdict(self))


class ToolExecutor:
    """Registry and execution facade for local static-analysis tools."""

    def __init__(self) -> None:
        self._tools: MutableMapping[str, ToolCallable] = {}
        self.results: list[ToolResult] = []

    @property
    def tools(self) -> Mapping[str, ToolCallable]:
        """Registered tools keyed by name."""

        return dict(self._tools)

    def register(self, name: str, tool: ToolCallable | None = None) -> ToolCallable:
        """Register a callable by name.

        Can be used directly or as a decorator::

            executor.register("hash", hash_file)

            @executor.register("hash")
            def hash_file(...): ...
        """

        if not name or not isinstance(name, str):
            raise ValueError("tool name must be a non-empty string")

        def decorator(func: ToolCallable) -> ToolCallable:
            if not callable(func):
                raise TypeError("registered tool must be callable")
            self._tools[name] = func
            return func

        if tool is None:
            return decorator
        return decorator(tool)

    def execute(self, name: str, **kwargs: Any) -> ToolResult:
        """Execute a registered tool and record its :class:`ToolResult`."""

        started = _utc_now()
        if name not in self._tools:
            result = ToolResult(
                tool=name,
                status="failed",
                error=f"tool not registered: {name}",
                started_at=started,
                finished_at=_utc_now(),
            )
            self.results.append(result)
            return result

        try:
            raw = self._tools[name](**kwargs)
            if isinstance(raw, ToolResult):
                result = raw
                result.started_at = result.started_at or started
                result.finished_at = result.finished_at or _utc_now()
            else:
                result = ToolResult(
                    tool=name,
                    status="ok",
                    data=_json_safe(raw),
                    started_at=started,
                    finished_at=_utc_now(),
                )
        except Exception as exc:  # noqa: BLE001 - executor boundary normalizes all tool failures.
            result = ToolResult(
                tool=name,
                status="failed",
                error=f"{type(exc).__name__}: {exc}",
                started_at=started,
                finished_at=_utc_now(),
            )

        result.data = _json_safe(result.data)
        result.metadata = _json_safe(result.metadata)
        self.results.append(result)
        return result

    def execute_many(self, plan: Mapping[str, Mapping[str, Any]]) -> list[ToolResult]:
        """Execute several tools from a mapping of tool name to keyword args."""

        return [self.execute(name, **dict(kwargs)) for name, kwargs in plan.items()]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_safe(value: Any) -> Any:
    """Coerce arbitrary Python values into JSON-serializable structures."""

    try:
        json.dumps(value)
        return value
    except TypeError:
        pass

    if isinstance(value, Mapping):
        return {str(_json_safe(k)): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "__dict__"):
        return _json_safe(vars(value))
    return repr(value)
