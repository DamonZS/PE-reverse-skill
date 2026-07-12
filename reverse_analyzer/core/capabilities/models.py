from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


class JsonMixin:
    def to_dict(self) -> Dict[str, Any]:
        return _prune(asdict(self))


@dataclass
class TargetIdentity(JsonMixin):
    kind: str = "sample"
    path: Optional[str] = None
    pid: Optional[int] = None
    sha256: Optional[str] = None
    display_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityArtifact(JsonMixin):
    path: str
    kind: str = "json"
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityRequest(JsonMixin):
    capability: str
    action: str
    target: TargetIdentity
    params: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None
    requested_provider: Optional[str] = None
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityPlan(JsonMixin):
    capability: str
    provider: str
    session_id: str
    target: TargetIdentity
    action: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    precondition_hash: Optional[str] = None
    before_snapshot: Dict[str, Any] = field(default_factory=dict)
    rollback_plan: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityValidation(JsonMixin):
    capability: str
    provider: str
    session_id: str
    ok: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class CapabilityExecutionResult(JsonMixin):
    capability: str
    provider: str
    session_id: str
    status: str
    action: str
    target: TargetIdentity
    before_snapshot: Dict[str, Any] = field(default_factory=dict)
    after_snapshot: Dict[str, Any] = field(default_factory=dict)
    rollback_plan: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[CapabilityArtifact] = field(default_factory=list)
    evidence_manifest_entries: List[Dict[str, Any]] = field(default_factory=list)
    report_section: Dict[str, Any] = field(default_factory=dict)
    dashboard_trace: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityRollbackResult(JsonMixin):
    capability: str
    provider: str
    session_id: str
    ok: bool
    restored: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CapabilityArtifactBundle(JsonMixin):
    capability: str
    provider: str
    session_id: str
    artifacts: List[CapabilityArtifact] = field(default_factory=list)
    manifest_entries: List[Dict[str, Any]] = field(default_factory=list)
