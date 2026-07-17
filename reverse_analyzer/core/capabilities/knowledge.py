"""CLI-independent bridge from capability lifecycle finalization to knowledge."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
import math
from typing import TYPE_CHECKING, Any, Dict, Optional

from reverse_analyzer.core.capabilities.audit_contract import (
    CAPABILITY_AUDIT_REQUIRED_EVENT_KINDS,
    CAPABILITY_AUDIT_REQUIRED_FIELDS,
)

if TYPE_CHECKING:
    from reverse_analyzer.knowledge.base import KnowledgeBase


# Kept for callers that use the constant for discovery. Recording is no longer
# gated by this snapshot: registry extensions and third-party capabilities are
# accepted as long as the lifecycle result has a non-empty capability name.
KNOWLEDGE_MANAGED_CAPABILITIES = frozenset(
    {
        "android_instrumentation",
        "android_native_patch",
        "android_rebuild",
        "anti_tamper_lab",
        "dma_memory",
        "engine_runtime",
        "graphics_present_runtime",
        "hardware_identity_virtualization",
        "hook_runtime",
        "hook_target_resolver",
        "imgui_renderer_runtime",
        "injector",
        "ios_instrumentation",
        "ios_rebuild",
        "kernel_driver_memory_runtime",
        "llm_jailbreak",
        "memory_runtime",
        "native_debugger",
        "native_hook",
        "patch_executor",
        "protocol_runtime",
        "render_overlay_runtime",
        "target_control_simulation",
    }
)

_QUALITY_FIELD_NAMES = (
    "quality",
    "quality_score",
    "confidence",
    "coverage",
    "coverage_rate",
    "verification_rate",
    "fidelity",
    "accuracy",
    "precision",
    "recall",
)


def _mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
        except (TypeError, ValueError):
            return {}
        if isinstance(payload, Mapping):
            return dict(payload)
    return {}


def _name(value: Any) -> str:
    return "_".join(str(value or "").strip().lower().split())


def _finite_float(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _quality_value(value: Any) -> Optional[float]:
    number = _finite_float(value)
    if number is None or number < 0.0:
        return None
    if 1.0 < number <= 100.0:
        number /= 100.0
    return round(min(1.0, number), 6)


def _quality_metrics(result: Dict[str, Any], audit: Dict[str, Any], explicit: Any) -> Dict[str, float]:
    metrics: Dict[str, float] = {}
    sources = (
        result,
        _mapping(result.get("report_section")),
        audit,
        _mapping(audit.get("report_section")),
    )
    for source in sources:
        for field_name in _QUALITY_FIELD_NAMES:
            value = _quality_value(source.get(field_name))
            if value is not None:
                metrics[_name(field_name).replace("-", "_")] = value
        for container_name in ("quality_metrics", "metrics"):
            for raw_name, raw_value in _mapping(source.get(container_name)).items():
                name = _name(raw_name).replace("-", "_")
                value = _quality_value(raw_value)
                if name and value is not None:
                    metrics[name] = value

    explicit_payload = _mapping(explicit)
    if explicit_payload:
        for raw_name, raw_value in explicit_payload.items():
            name = _name(raw_name).replace("-", "_")
            value = _quality_value(raw_value)
            if name and value is not None:
                metrics[name] = value
    elif explicit is not None:
        value = _quality_value(explicit)
        if value is not None:
            metrics["quality"] = value
    return dict(sorted(metrics.items()))


def _mapping_items(value: Any) -> list[Dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [payload for item in value if (payload := _mapping(item))]


def _audit_field_complete(field_name: str, value: Any) -> bool:
    if field_name == "target_identity":
        target = _mapping(value)
        return bool(
            str(target.get("kind") or "").strip()
            and any(
                target.get(key) not in (None, "")
                for key in ("identity_hash", "path", "pid", "sha256", "display_name")
            )
        )
    if field_name in {
        "before_snapshot",
        "after_snapshot",
        "rollback_plan",
        "provenance",
        "report_section",
    }:
        return bool(_mapping(value))
    if field_name in {"evidence_manifest_entries", "dashboard_trace", "events"}:
        return bool(_mapping_items(value))
    return bool(str(value or "").strip())


def _audit_completeness(audit: Dict[str, Any], explicit: Any) -> float:
    if isinstance(explicit, bool):
        return float(explicit)
    explicit_value = _finite_float(explicit)
    if explicit_value is not None:
        return round(min(1.0, max(0.0, explicit_value)), 6)
    if not audit:
        return 0.0

    completed = sum(
        1
        for field_name in CAPABILITY_AUDIT_REQUIRED_FIELDS
        if _audit_field_complete(field_name, audit.get(field_name))
    )
    event_kinds = {
        _name(event.get("kind"))
        for event in _mapping_items(audit.get("events"))
        if _name(event.get("kind"))
    }
    completed += sum(
        1 for event_kind in CAPABILITY_AUDIT_REQUIRED_EVENT_KINDS if _name(event_kind) in event_kinds
    )
    requirement_count = len(CAPABILITY_AUDIT_REQUIRED_FIELDS) + len(
        CAPABILITY_AUDIT_REQUIRED_EVENT_KINDS
    )
    return round(completed / requirement_count, 6) if requirement_count else 1.0


def _valid_path_count(value: Any) -> tuple[int, int]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return 0, 0
    items = list(value)
    valid = sum(
        1
        for item in items
        if str(_mapping(item).get("path") or "").strip()
    )
    return valid, len(items)


def _artifact_completeness(result: Dict[str, Any], bundle: Any) -> float:
    expected_artifacts = result.get("artifacts")
    expected_manifest = result.get("evidence_manifest_entries")
    bundle_payload = _mapping(bundle)
    scores = []
    for expected, bundled in (
        (expected_artifacts, bundle_payload.get("artifacts")),
        (expected_manifest, bundle_payload.get("manifest_entries")),
    ):
        expected_valid, expected_count = _valid_path_count(expected)
        if bundle is None:
            if expected_count:
                scores.append(expected_valid / expected_count)
            continue
        bundled_valid, _ = _valid_path_count(bundled)
        if expected_count:
            scores.append(min(1.0, bundled_valid / expected_count))
        else:
            scores.append(1.0)
    if not scores:
        return 1.0
    return round(sum(scores) / len(scores), 6)


def _rollback_completeness(result: Dict[str, Any], rollback_result: Any) -> float:
    plan = _mapping(result.get("rollback_plan"))
    if plan.get("supported") is False:
        return 1.0
    rollback = _mapping(rollback_result)
    if not rollback:
        return 0.0 if plan.get("supported") is True else 1.0
    if not bool(rollback.get("ok")):
        return 0.0
    if bool(rollback.get("restored")):
        return 1.0
    details = _mapping(rollback.get("details"))
    terminal_status = _name(details.get("status"))
    if terminal_status in {
        "already_completed",
        "cleanup_complete",
        "cleanup_completed",
        "completed",
        "not_required",
        "restored",
        "rolled_back",
    }:
        return 1.0
    return 0.5


def _first_value(primary: Dict[str, Any], fallback: Dict[str, Any], *names: str) -> Any:
    for source in (primary, fallback):
        for name in names:
            if source.get(name) not in (None, ""):
                return source[name]
    return None


def _duration_ms(result: Dict[str, Any], audit: Dict[str, Any], explicit: Any) -> float:
    explicit_value = _finite_float(explicit)
    if explicit_value is not None:
        return max(0.0, explicit_value)
    for source in (
        result,
        _mapping(result.get("report_section")),
        _mapping(result.get("provenance")),
        audit,
        _mapping(audit.get("report_section")),
        _mapping(audit.get("provenance")),
    ):
        for name in ("duration_ms", "elapsed_ms", "runtime_ms"):
            value = _finite_float(source.get(name))
            if value is not None:
                return max(0.0, value)

    events = _mapping_items(audit.get("events") or result.get("events"))
    timestamps = []
    for event in events:
        raw_timestamp = str(event.get("ts") or "").strip()
        if not raw_timestamp:
            continue
        try:
            timestamps.append(datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00")))
        except ValueError:
            continue
    if len(timestamps) >= 2:
        try:
            return max(0.0, (max(timestamps) - min(timestamps)).total_seconds() * 1000.0)
        except TypeError:
            pass
    return 0.0


def record_capability_lifecycle_outcome(
    knowledge_base: "KnowledgeBase",
    result: Any,
    *,
    artifact_bundle: Any = None,
    rollback_result: Any = None,
    audit_record: Any = None,
    duration_ms: Any = None,
    artifact_completeness: Any = None,
    rollback_completeness: Any = None,
    audit_completeness: Any = None,
    quality_metrics: Any = None,
) -> Optional[Dict[str, Any]]:
    """Finalize one capability run into privacy-safe knowledge.

    The helper accepts dataclass instances or mappings and intentionally has no
    CLI dependency. A capability audit writer or lifecycle finalizer can call
    it after artifact collection and rollback have reached their terminal
    states. Capability names are intentionally open-ended so registry plugins
    and future dependency-gated providers participate without bridge changes.
    """

    result_payload = _mapping(result)
    audit_payload = _mapping(audit_record)
    capability = _name(_first_value(result_payload, audit_payload, "capability"))
    if not capability:
        return None
    provider = _first_value(result_payload, audit_payload, "provider") or "unknown"
    action = _first_value(result_payload, audit_payload, "action") or "unknown"
    status = _first_value(result_payload, audit_payload, "status") or "unknown"
    target = _first_value(
        result_payload,
        audit_payload,
        "target",
        "target_identity",
    )

    record = getattr(knowledge_base, "record_capability_outcome", None)
    if not callable(record):
        raise TypeError("knowledge_base must provide record_capability_outcome()")
    artifact_value = (
        _artifact_completeness(result_payload or audit_payload, artifact_bundle)
        if artifact_completeness is None
        else artifact_completeness
    )
    rollback_value = (
        _rollback_completeness(result_payload or audit_payload, rollback_result)
        if rollback_completeness is None
        else rollback_completeness
    )
    return record(
        capability,
        provider,
        action,
        status=status,
        target=target,
        duration_ms=_duration_ms(result_payload, audit_payload, duration_ms),
        artifact_completeness=artifact_value,
        rollback_completeness=rollback_value,
        audit_completeness=_audit_completeness(audit_payload, audit_completeness),
        quality_metrics=_quality_metrics(result_payload, audit_payload, quality_metrics),
    )


def record_capability_audit_outcome(
    knowledge_base: "KnowledgeBase",
    audit_record: Any,
    **kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """Record an audit record when no execution-result object is retained."""

    return record_capability_lifecycle_outcome(
        knowledge_base,
        audit_record,
        audit_record=audit_record,
        **kwargs,
    )


finalize_capability_knowledge = record_capability_lifecycle_outcome


__all__ = [
    "KNOWLEDGE_MANAGED_CAPABILITIES",
    "finalize_capability_knowledge",
    "record_capability_audit_outcome",
    "record_capability_lifecycle_outcome",
]
