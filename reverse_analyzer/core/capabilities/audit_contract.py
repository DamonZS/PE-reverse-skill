from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


CAPABILITY_AUDIT_REQUIRED_FIELDS: Tuple[str, ...] = (
    "session_id",
    "target_identity",
    "precondition_hash",
    "before_snapshot",
    "after_snapshot",
    "rollback_plan",
    "provenance",
    "evidence_manifest_entries",
    "report_section",
    "dashboard_trace",
    "events",
)

CAPABILITY_AUDIT_REQUIRED_EVENT_KINDS: Tuple[str, ...] = (
    "plan",
    "validate",
    "execute",
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


def _mapping_sequence(value: Any) -> List[Dict[str, Any]] | None:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return None
    items: List[Dict[str, Any]] = []
    for item in value:
        payload = _mapping(item)
        if not payload:
            return None
        items.append(payload)
    return items


@dataclass(frozen=True)
class CapabilityAuditContractResult:
    """Result of validating one persisted capability-audit record."""

    ok: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }

    def require_valid(self) -> None:
        if not self.ok:
            raise ValueError("invalid capability audit record: " + "; ".join(self.errors))


def validate_capability_audit_record(
    record: Any,
    *,
    required_event_kinds: Iterable[str] = CAPABILITY_AUDIT_REQUIRED_EVENT_KINDS,
) -> CapabilityAuditContractResult:
    """Validate the durable audit contract shared by all capability providers.

    The validator is provider-independent and accepts either a mapping or an
    object exposing ``to_dict()``. It checks the fields used to correlate a run
    across its audit artifact, report, evidence manifest, and dashboard.
    """

    payload = _mapping(record)
    errors: List[str] = []
    warnings: List[str] = []
    if not payload:
        return CapabilityAuditContractResult(ok=False, errors=["record must be a non-empty mapping"])

    for field_name in CAPABILITY_AUDIT_REQUIRED_FIELDS:
        if field_name not in payload:
            errors.append(f"missing required field: {field_name}")

    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        errors.append("session_id must be a non-empty string")

    target = _mapping(payload.get("target_identity"))
    if not target:
        errors.append("target_identity must be a non-empty mapping")
    else:
        if not str(target.get("kind") or "").strip():
            errors.append("target_identity.kind must be a non-empty string")
        if not any(target.get(key) not in (None, "") for key in ("path", "pid", "sha256", "display_name")):
            errors.append("target_identity must include path, pid, sha256, or display_name")

    precondition_hash = payload.get("precondition_hash")
    if not isinstance(precondition_hash, str) or not precondition_hash.strip():
        errors.append("precondition_hash must be a non-empty string")

    for field_name in ("before_snapshot", "after_snapshot", "rollback_plan", "provenance", "report_section"):
        value = payload.get(field_name)
        if not isinstance(value, Mapping):
            errors.append(f"{field_name} must be a mapping")
        elif not value:
            errors.append(f"{field_name} must not be empty")

    rollback_plan = _mapping(payload.get("rollback_plan"))
    if rollback_plan and not isinstance(rollback_plan.get("supported"), bool):
        errors.append("rollback_plan.supported must be a boolean")

    provenance = _mapping(payload.get("provenance"))
    plan = _mapping(provenance.get("plan")) if provenance else {}
    validation = _mapping(provenance.get("validation")) if provenance else {}
    if provenance:
        if not plan:
            errors.append("provenance.plan must be a non-empty mapping")
        if not validation:
            errors.append("provenance.validation must be a non-empty mapping")
    if plan:
        _check_equal(errors, "session_id", session_id, plan.get("session_id"), "provenance.plan")
        _check_equal(errors, "capability", payload.get("capability"), plan.get("capability"), "provenance.plan")
        _check_equal(errors, "provider", payload.get("provider"), plan.get("provider"), "provenance.plan")
        _check_equal(errors, "action", payload.get("action"), plan.get("action"), "provenance.plan")
        _check_equal(
            errors,
            "precondition_hash",
            precondition_hash,
            plan.get("precondition_hash"),
            "provenance.plan",
        )
    if validation:
        _check_equal(errors, "session_id", session_id, validation.get("session_id"), "provenance.validation")
        _check_equal(
            errors,
            "capability",
            payload.get("capability"),
            validation.get("capability"),
            "provenance.validation",
        )
        _check_equal(errors, "provider", payload.get("provider"), validation.get("provider"), "provenance.validation")

    manifest_entries = _mapping_sequence(payload.get("evidence_manifest_entries"))
    if manifest_entries is None:
        errors.append("evidence_manifest_entries must be a sequence of non-empty mappings")
    elif not manifest_entries:
        errors.append("evidence_manifest_entries must not be empty")
    else:
        for index, entry in enumerate(manifest_entries):
            if not str(entry.get("path") or "").strip():
                errors.append(f"evidence_manifest_entries[{index}].path must be a non-empty string")

    dashboard_trace = _mapping_sequence(payload.get("dashboard_trace"))
    if dashboard_trace is None:
        errors.append("dashboard_trace must be a sequence of non-empty mappings")
    elif not dashboard_trace:
        errors.append("dashboard_trace must not be empty")
    else:
        for index, trace in enumerate(dashboard_trace):
            if not str(trace.get("kind") or "").strip():
                errors.append(f"dashboard_trace[{index}].kind must be a non-empty string")

    events = _mapping_sequence(payload.get("events"))
    if events is None:
        errors.append("events must be a sequence of non-empty mappings")
    elif not events:
        errors.append("events must not be empty")
    else:
        kinds: List[str] = []
        for index, event in enumerate(events):
            kind = str(event.get("kind") or "").strip()
            if not kind:
                errors.append(f"events[{index}].kind must be a non-empty string")
            else:
                kinds.append(kind)
            if not str(event.get("ts") or "").strip():
                errors.append(f"events[{index}].ts must be a non-empty string")
            if not str(event.get("message") or "").strip():
                errors.append(f"events[{index}].message must be a non-empty string")
        required_kinds = [str(item) for item in required_event_kinds]
        missing_kinds = [item for item in required_kinds if item not in kinds]
        if missing_kinds:
            errors.append("events missing required kinds: " + ", ".join(missing_kinds))
        positions = [kinds.index(item) for item in required_kinds if item in kinds]
        if len(positions) == len(required_kinds) and positions != sorted(positions):
            errors.append("events must preserve plan -> validate -> execute order")

    report_section = _mapping(payload.get("report_section"))
    if report_section:
        for field_name in ("capability", "provider", "action", "status"):
            _check_equal(
                errors,
                field_name,
                payload.get(field_name),
                report_section.get(field_name),
                "report_section",
            )

    if payload.get("status") in (None, "", "unknown"):
        warnings.append("status is missing or unknown")

    return CapabilityAuditContractResult(ok=not errors, errors=errors, warnings=warnings)


def _check_equal(
    errors: List[str],
    field_name: str,
    expected: Any,
    actual: Any,
    source_name: str,
) -> None:
    if expected in (None, ""):
        errors.append(f"{field_name} must be present on the audit record")
    elif actual in (None, ""):
        errors.append(f"{source_name}.{field_name} must be present")
    elif actual != expected:
        errors.append(f"{source_name}.{field_name} does not match audit record")


def validate_capability_audit_records(records: Iterable[Any]) -> CapabilityAuditContractResult:
    """Validate a collection while retaining record indexes in diagnostics."""

    errors: List[str] = []
    warnings: List[str] = []
    count = 0
    for index, record in enumerate(records):
        count += 1
        result = validate_capability_audit_record(record)
        errors.extend(f"records[{index}]: {message}" for message in result.errors)
        warnings.extend(f"records[{index}]: {message}" for message in result.warnings)
    if count == 0:
        errors.append("records must not be empty")
    return CapabilityAuditContractResult(ok=not errors, errors=errors, warnings=warnings)
