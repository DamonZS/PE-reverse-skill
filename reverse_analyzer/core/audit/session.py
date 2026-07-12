from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from reverse_analyzer.core.capabilities.models import JsonMixin, TargetIdentity


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditEvent(JsonMixin):
    ts: str
    kind: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditSessionRecord(JsonMixin):
    session_id: str
    capability: str
    provider: str
    target_identity: TargetIdentity
    action: str
    status: str = "planned"
    precondition_hash: Optional[str] = None
    before_snapshot: Dict[str, Any] = field(default_factory=dict)
    after_snapshot: Dict[str, Any] = field(default_factory=dict)
    rollback_plan: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    evidence_manifest_entries: List[Dict[str, Any]] = field(default_factory=list)
    report_section: Dict[str, Any] = field(default_factory=dict)
    dashboard_trace: List[Dict[str, Any]] = field(default_factory=list)
    events: List[AuditEvent] = field(default_factory=list)

    def add_event(self, kind: str, message: str, **data: Any) -> None:
        self.events.append(AuditEvent(ts=_utc_now(), kind=kind, message=message, data=data))

    def write_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2, ensure_ascii=False)
