"""PE-style analyze → tool → observe loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from reverse_analyzer.providers import ProviderMessage, RuleBasedProvider


@dataclass
class ToolObservation:
    tool_name: str
    tool_args: Dict[str, Any]
    result: Any = None
    error: Optional[str] = None
    iteration: int = 0

    @property
    def ok(self) -> bool:
        if self.error is not None:
            return False
        if hasattr(self.result, "status"):
            return str(getattr(self.result, "status", "ok")).lower() == "ok"
        if isinstance(self.result, Mapping) and "status" in self.result:
            return str(self.result.get("status") or "ok").lower() == "ok"
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_args": dict(self.tool_args),
            "result": _jsonish(self.result),
            "error": self.error,
            "iteration": self.iteration,
            "ok": self.ok,
        }


@dataclass
class AgentLoopResult:
    final_answer: Optional[str]
    iterations: int
    stopped_reason: str
    tool_results: list[Dict[str, Any]] = field(default_factory=list)
    provider_messages: list[Dict[str, Any]] = field(default_factory=list)
    barrier: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_answer": self.final_answer,
            "iterations": self.iterations,
            "stopped_reason": self.stopped_reason,
            "tool_results": list(self.tool_results),
            "provider_messages": list(self.provider_messages),
            "barrier": self.barrier,
        }


class AgentLoop:
    """Run provider decisions through a duck-typed tool executor.

    Supported executor shapes:
    - ``execute(tool_name, **tool_args)``
    - ``execute(tool_name, tool_args)``
    - ``run(tool_name, **tool_args)``
    - mapping of ``tool_name -> callable``
    """

    def __init__(
        self,
        provider: Any | None = None,
        tool_executor: Any | None = None,
        *,
        session: Any | None = None,
        max_iterations: int = 8,
        repeat_limit: int = 2,
        trace: Any | None = None,
    ) -> None:
        self.provider = provider or RuleBasedProvider()
        self.tool_executor = tool_executor
        self.session = session
        self.max_iterations = max_iterations
        self.repeat_limit = repeat_limit
        self.trace = trace
        self.tool_results: list[Dict[str, Any]] = []
        self.provider_messages: list[Dict[str, Any]] = []
        self._seen_requests: Dict[tuple[str, str], int] = {}

    def run(self, context: Optional[Mapping[str, Any]] = None) -> AgentLoopResult:
        base_context = dict(context or {})
        if self.session is not None:
            base_context.setdefault("session", self.session)
            base_context.setdefault("target", getattr(self.session, "target", None))

        final_answer: Optional[str] = None
        stopped_reason = "max_iterations"
        barrier = False
        iterations = 0

        for iteration in range(1, self.max_iterations + 1):
            iterations = iteration
            loop_context = dict(base_context)
            loop_context["tool_results"] = list(self.tool_results)
            loop_context["observations"] = list(self.tool_results)
            loop_context["iteration"] = iteration
            message = self.provider.analyze(loop_context)
            if isinstance(message, Mapping):
                message = ProviderMessage.from_mapping(message)
            self.provider_messages.append(message.to_dict())
            self._record_event("provider_message", message.to_dict())

            if message.barrier:
                final_answer = message.final_answer or message.content
                stopped_reason = "barrier"
                barrier = True
                break
            if message.final_answer is not None or not message.tool_name:
                final_answer = message.final_answer or message.content
                stopped_reason = "final_answer"
                break

            request_key = (message.tool_name, _stable_repr(message.tool_args))
            self._seen_requests[request_key] = self._seen_requests.get(request_key, 0) + 1
            if self._seen_requests[request_key] > self.repeat_limit:
                final_answer = f"Stopped after repeated tool request: {message.tool_name}"
                stopped_reason = "repeated_tool"
                barrier = True
                self._record_event("barrier", {"reason": stopped_reason, "tool_name": message.tool_name})
                break

            observation = self._execute_tool(message.tool_name, message.tool_args, iteration)
            observation_dict = observation.to_dict()
            self.tool_results.append(observation_dict)
            self._record_tool_call(observation_dict)
            self._record_event("tool_observation", observation_dict)

        return AgentLoopResult(
            final_answer=final_answer,
            iterations=iterations,
            stopped_reason=stopped_reason,
            tool_results=list(self.tool_results),
            provider_messages=list(self.provider_messages),
            barrier=barrier,
        )

    def _execute_tool(self, tool_name: str, tool_args: Mapping[str, Any], iteration: int) -> ToolObservation:
        if self.tool_executor is None:
            return ToolObservation(tool_name, dict(tool_args), error="No tool executor configured", iteration=iteration)
        try:
            result = _call_executor(self.tool_executor, tool_name, dict(tool_args))
            return ToolObservation(tool_name, dict(tool_args), result=result, iteration=iteration)
        except Exception as exc:  # pragma: no cover - exact executor failures vary by integration
            return ToolObservation(tool_name, dict(tool_args), error=f"{type(exc).__name__}: {exc}", iteration=iteration)

    def _record_event(self, kind: str, payload: Mapping[str, Any]) -> None:
        event = {"kind": kind, **dict(payload)}
        if self.session is not None and hasattr(self.session, "events"):
            self.session.events.append(event)
        if self.trace is not None:
            if hasattr(self.trace, "log"):
                session_id = getattr(self.session, "session_id", "no-session")
                try:
                    self.trace.log(session_id=session_id, status="running", message=kind, data=dict(payload))
                except TypeError:
                    self.trace.log(kind, dict(payload))
            elif callable(self.trace):
                self.trace(kind, dict(payload))

    def _record_tool_call(self, payload: Mapping[str, Any]) -> None:
        if self.session is not None and hasattr(self.session, "tool_calls"):
            self.session.tool_calls.append(dict(payload))


def _call_executor(executor: Any, tool_name: str, tool_args: Dict[str, Any]) -> Any:
    if isinstance(executor, Mapping):
        tool = executor[tool_name]
        return tool(**tool_args)
    if hasattr(executor, "execute"):
        execute = executor.execute
        try:
            return execute(tool_name, **tool_args)
        except TypeError:
            return execute(tool_name, tool_args)
    if hasattr(executor, "run"):
        run = executor.run
        try:
            return run(tool_name, **tool_args)
        except TypeError:
            return run(tool_name, tool_args)
    if callable(executor):
        try:
            return executor(tool_name, **tool_args)
        except TypeError:
            return executor(tool_name, tool_args)
    raise TypeError("Unsupported tool executor")


def _stable_repr(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{" + ",".join(f"{k}:{_stable_repr(value[k])}" for k in sorted(value)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_stable_repr(item) for item in value) + "]"
    return repr(value)


def _jsonish(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return {str(k): _jsonish(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonish(item) for item in value]
    return value
