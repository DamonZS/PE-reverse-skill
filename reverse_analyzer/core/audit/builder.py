from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping

from reverse_analyzer.core.audit.session import AuditSessionRecord
from reverse_analyzer.core.capabilities.models import (
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityValidation,
    TargetIdentity,
)


def _mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _target_identity(value: Any) -> TargetIdentity:
    if isinstance(value, TargetIdentity):
        return value
    payload = _mapping(value)
    return TargetIdentity(
        kind=str(payload.get("kind") or "sample"),
        path=payload.get("path"),
        pid=payload.get("pid"),
        sha256=payload.get("sha256"),
        display_name=payload.get("display_name"),
        metadata=dict(payload.get("metadata") or {}),
    )


class CapabilityAuditBuilder:
    """Build normalized audit-session records from capability executions."""

    def build_record(
        self,
        *,
        plan: CapabilityPlan,
        result: CapabilityExecutionResult,
        validation: CapabilityValidation | None = None,
    ) -> AuditSessionRecord:
        provenance = dict(result.provenance or {})
        if "plan" not in provenance:
            provenance["plan"] = plan.to_dict()
        if validation is not None and "validation" not in provenance:
            provenance["validation"] = validation.to_dict()

        record = AuditSessionRecord(
            session_id=result.session_id or plan.session_id,
            capability=result.capability or plan.capability,
            provider=result.provider or plan.provider,
            target_identity=_target_identity(result.target or plan.target),
            action=result.action or plan.action,
            status=result.status or "unknown",
            precondition_hash=result.provenance.get("precondition_hash") or plan.precondition_hash,
            before_snapshot=dict(result.before_snapshot or plan.before_snapshot or {}),
            after_snapshot=dict(result.after_snapshot or {}),
            rollback_plan=dict(result.rollback_plan or plan.rollback_plan or {}),
            provenance=provenance,
            evidence_manifest_entries=list(result.evidence_manifest_entries or []),
            report_section=dict(result.report_section or {}),
            dashboard_trace=list(result.dashboard_trace or []),
        )
        record.add_event("plan", "capability plan created", provider=plan.provider, action=plan.action)
        if validation is not None:
            record.add_event(
                "validate",
                "capability plan validated",
                ok=validation.ok,
                warning_count=len(validation.warnings or []),
                error_count=len(validation.errors or []),
            )
        record.add_event("execute", "capability execution completed", status=result.status)
        return record


def summarize_audit_records(records: Iterable[Mapping[str, Any] | AuditSessionRecord]) -> Dict[str, Any]:
    normalized = [_mapping(item) for item in records if _mapping(item)]
    status_counts: Dict[str, int] = {}
    rollback_supported = 0
    manifest_refs = 0
    trace_points = 0
    for item in normalized:
        status = str(item.get("status") or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1
        rollback_plan = item.get("rollback_plan") if isinstance(item.get("rollback_plan"), Mapping) else {}
        if rollback_plan.get("supported"):
            rollback_supported += 1
        manifest_refs += len(item.get("evidence_manifest_entries") or [])
        trace_points += len(item.get("dashboard_trace") or [])
    return {
        "record_count": len(normalized),
        "status_counts": status_counts,
        "rollback_supported_count": rollback_supported,
        "manifest_reference_count": manifest_refs,
        "dashboard_trace_count": trace_points,
    }
