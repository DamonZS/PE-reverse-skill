"""Common provider contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)


@dataclass(frozen=True)
class ProviderMessage:
    """A provider decision returned to :class:`AgentLoop`."""

    content: str
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    final_answer: Optional[str] = None
    barrier: bool = False
    findings: list[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_final(self) -> bool:
        return self.barrier or self.final_answer is not None or self.tool_name is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_args": dict(self.tool_args),
            "final_answer": self.final_answer,
            "barrier": self.barrier,
            "findings": list(self.findings),
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ProviderMessage":
        return cls(
            content=str(data.get("content") or data.get("message") or ""),
            tool_name=data.get("tool_name") or data.get("tool"),
            tool_args=dict(data.get("tool_args") or data.get("args") or {}),
            final_answer=data.get("final_answer") or data.get("answer"),
            barrier=bool(data.get("barrier", False)),
            findings=list(data.get("findings") or []),
            confidence=float(data.get("confidence") or 0.0),
            metadata=dict(data.get("metadata") or {}),
        )


class BaseProvider(Protocol):
    """Protocol implemented by local and LLM-backed providers."""

    name: str

    def analyze(self, context: Mapping[str, Any]) -> ProviderMessage:
        """Return the next tool-call request or a final answer."""


class CapabilityProvider(Protocol):
    """Protocol implemented by capability execution providers."""

    capability_name: str
    provider_name: str
    priority: int

    def supports(self, request: CapabilityRequest, context: Optional[Dict[str, Any]] = None) -> bool:
        return True

    def plan(self, request: CapabilityRequest, context: Optional[Dict[str, Any]] = None) -> CapabilityPlan:
        raise NotImplementedError

    def validate(self, plan: CapabilityPlan, context: Optional[Dict[str, Any]] = None) -> CapabilityValidation:
        raise NotImplementedError

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        raise NotImplementedError

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        raise NotImplementedError

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        raise NotImplementedError
