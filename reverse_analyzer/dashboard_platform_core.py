from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping
from typing import Any


ANALYSIS_DOMAINS = (
    ("memory", "Memory", "memory_analysis"),
    ("patch", "Patch", "patch_analysis"),
    ("engine", "Engine", "engine_analysis"),
    ("android", "Android", "android_analysis"),
    ("ios", "iOS", "ios_analysis"),
    ("protocol", "Protocol", "protocol_analysis"),
    ("gui", "GUI", "gui_analysis"),
    ("source", "Source", "source_reconstruction"),
)

LOW_CONFIDENCE_THRESHOLD = 0.6

_ANALYSIS_STATUS_ALIASES = {
    "failed": frozenset(
        {
            "failed",
            "failure",
            "error",
            "invalid",
            "unsafe",
            "timeout",
            "timed_out",
            "cancelled",
            "canceled",
            "blocked",
        }
    ),
    "unavailable": frozenset(
        {
            "unavailable",
            "unsupported",
            "not_available",
            "not_run",
            "not_applicable",
            "skipped",
            "disabled",
            "pending",
        }
    ),
    "partial": frozenset(
        {
            "partial",
            "degraded",
            "incomplete",
            "mock",
            "mocked",
            "dry_run",
            "simulated",
            "planned",
            "unknown",
            "discovered",
        }
    ),
    "ok": frozenset(
        {
            "ok",
            "success",
            "succeeded",
            "complete",
            "completed",
            "available",
            "ready",
            "passed",
        }
    ),
}

_AVAILABLE_ANALYSIS_STATUSES = frozenset({"ok", "partial"})

_DOMAIN_METRICS = {
    "memory": (
        ("Snapshot regions", "snapshot.region_count"),
        ("Snapshot bytes", "snapshot.total_bytes"),
        ("Changed regions", "diff.changed_region_count"),
        ("Address mappings", "address_map.mapping_count"),
        ("Stages", "stages"),
    ),
    "patch": (
        ("Operations", "operations"),
        ("Verification", "verification_status"),
        ("Apply", "apply_status"),
        ("Rollback", "rollback_status"),
        ("Risks", "risks"),
    ),
    "engine": (
        ("Platform", "platform"),
        ("Engine", "engine"),
        ("Assets", "assets"),
        ("Symbols", "symbols"),
        ("Strategy", "strategy"),
    ),
    "android": (
        ("Package type", "package_type"),
        ("Framework", "framework"),
        ("Package", "manifest.package"),
        ("Resources", "resources"),
        ("DEX classes", "dex_summary.class_count"),
        ("Native libraries", "native_libs"),
    ),
    "ios": (
        ("Bundle", "manifest.bundle_identifier"),
        ("Executable", "manifest.executable"),
        ("Framework", "framework.name"),
        ("Storyboards", "resources.storyboard_count"),
        ("XIB files", "resources.xib_count"),
        ("Native binaries", "native_binaries.count"),
        ("Architectures", "native_binaries.architectures"),
        ("Encrypted", "native_binaries.encrypted"),
        ("Strategy", "strategy.name"),
    ),
    "protocol": (
        ("Protocols", "protocols"),
        ("Flows", "flows"),
        ("Fields", "field_stats"),
        ("Inferred format", "inference.format"),
        ("Strategy", "strategy"),
    ),
    "gui": (
        ("Platform", "platform"),
        ("Framework", "framework"),
        ("Resources", "resources"),
        ("Runtime controls", "runtime_tree.control_count"),
        ("States", "state_machine.state_count"),
        ("Transitions", "state_machine.transition_count"),
        ("Visual similarity", "visual.similarity"),
        ("Strategy", "strategy"),
    ),
    "source": (
        ("Language", "language"),
        ("Output stack", "output_stack"),
        ("Functions", "function_count"),
        ("Imports", "import_count"),
        ("Modules", "module_count"),
        ("Dynamic evidence", "dynamic_evidence_count"),
        ("Verification", "verification_status"),
        ("Verification score", "verification_score"),
        ("Runtime validation", "runtime_validation_status"),
        ("Runtime confidence", "runtime_validation_confidence.score"),
        ("Behavior validation", "behavior_validation_status"),
        ("Behavior comparisons", "behavior_validation_summary.comparison_count"),
        ("Behavior matches", "behavior_validation_summary.matched_comparison_count"),
        ("Behavior mismatches", "behavior_validation_summary.mismatched_comparison_count"),
        ("Behavior artifact", "behavior_validation_artifact"),
        ("Behavior equivalent", "behavior_equivalent"),
        ("Strategy", "strategy"),
    ),
}

_CONFIDENCE_PATHS = {
    "memory": ("confidence", "snapshot.confidence", "diff.confidence"),
    "patch": ("confidence", "verification_score"),
    "engine": ("confidence",),
    "android": ("confidence", "framework.confidence"),
    "ios": ("confidence", "framework.confidence"),
    "protocol": ("confidence", "inference.confidence"),
    "gui": ("confidence", "reconstruction_verification.score"),
    "source": ("confidence", "runtime_validation_confidence.score", "verification_score"),
}

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "warning": 3,
    "low": 4,
    "info": 5,
    "unknown": 6,
}


def build_platform_core_view(
    report_data: Mapping[str, Any] | None,
    *,
    capability_audit: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a stable, compact Platform Core view for the offline dashboard."""

    report = dict(report_data or {})
    platform_core = _mapping(report.get("platform_core"))
    registry = _mapping(platform_core.get("capability_registry"))
    semantic_ir = _mapping(platform_core.get("semantic_ir")) or _mapping(report.get("semantic_ir"))
    evidence_graph = _mapping(platform_core.get("evidence_graph")) or _mapping(report.get("evidence_graph"))
    audit = dict(
        capability_audit
        or _mapping(platform_core.get("capability_audit"))
        or _mapping(report.get("capability_audit"))
    )

    capabilities = _mapping(registry.get("capabilities"))
    audit_summary = _mapping(audit.get("summary"))
    provider_count = sum(_provider_count(value) for value in capabilities.values())

    return {
        "status": platform_core.get("status", "unavailable"),
        "cards": [
            {
                "title": "Capability Registry",
                "value": _safe_int(registry.get("capability_count"), len(capabilities)),
                "subtitle": f"{provider_count} providers",
            },
            {
                "title": "Semantic IR",
                "value": _safe_int(semantic_ir.get("module_count")),
                "subtitle": f"runtime={_safe_int(semantic_ir.get('runtime_count'))}",
            },
            {
                "title": "Evidence Graph",
                "value": _safe_int(evidence_graph.get("node_count")),
                "subtitle": f"edges={_safe_int(evidence_graph.get('edge_count'))}",
            },
            {
                "title": "Capability Audit",
                "value": _safe_int(audit.get("record_count"), len(_list(audit.get("records")))),
                "subtitle": f"rollback={_safe_int(audit_summary.get('rollback_supported_count'))}",
            },
        ],
        "capabilities": dict(capabilities),
        "capability_audit": audit,
        "artifacts": {
            "semantic_ir": semantic_ir.get("path"),
            "evidence_graph": evidence_graph.get("path"),
        },
    }


def build_analysis_views(
    reports: Iterable[Mapping[str, Any]],
    *,
    source_summary: Mapping[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Normalize the latest result for each dashboard analysis domain."""

    entries = list(reports)
    views: dict[str, dict[str, Any]] = {}
    for domain, title, section in ANALYSIS_DOMAINS:
        matches: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        for entry in entries:
            report = _report_payload(entry)
            value = report.get(section)
            if isinstance(value, Mapping) and value:
                matches.append((entry, value))

        if matches:
            entry, payload = matches[0]
            views[domain] = _analysis_view(
                domain,
                title,
                section,
                payload,
                entry,
                history_count=len(matches),
            )
            continue

        if domain == "source" and _mapping(source_summary).get("projects"):
            summary = _mapping(_mapping(source_summary).get("summary"))
            fallback = {
                "status": "discovered",
                "project_count": summary.get("project_total"),
                "function_count": summary.get("function_total"),
                "module_count": summary.get("module_total"),
                "dynamic_evidence_count": summary.get("dynamic_evidence_total"),
                "artifacts": [
                    item.get("relative_path") or item.get("project_dir")
                    for item in _list(_mapping(source_summary).get("projects"))
                    if isinstance(item, Mapping)
                ],
            }
            views[domain] = _analysis_view(
                domain,
                title,
                section,
                fallback,
                {},
                history_count=1,
            )
            continue

        views[domain] = {
            "domain": domain,
            "title": title,
            "section": section,
            "available": False,
            "status": "unavailable",
            "confidence": None,
            "low_confidence": False,
            "history_count": 0,
            "report_source": None,
            "report_timestamp": None,
            "metrics": [],
            "evidence": [],
            "strategy": None,
            "artifact_count": 0,
        }
    return views


def build_capability_audit_view(
    reports: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Aggregate capability audit records and dashboard traces across reports."""

    records: list[dict[str, Any]] = []
    seen_records: set[str] = set()
    seen_audits: set[str] = set()
    claimed = {
        "rollback_supported_count": 0,
        "manifest_reference_count": 0,
        "dashboard_trace_count": 0,
    }
    claimed_statuses: dict[str, int] = {}

    for entry in reports:
        report = _report_payload(entry)
        source = _report_source(entry)
        audits = [
            report.get("capability_audit"),
            _mapping(report.get("platform_core")).get("capability_audit"),
        ]
        for raw_audit in audits:
            if not isinstance(raw_audit, Mapping) or not raw_audit:
                continue
            audit_key = _stable_key(raw_audit)
            if audit_key in seen_audits:
                continue
            seen_audits.add(audit_key)
            summary = _mapping(raw_audit.get("summary"))
            for key in claimed:
                claimed[key] += _safe_int(summary.get(key))
            for status, count in _mapping(summary.get("status_counts")).items():
                status_name = str(status or "unknown").lower()
                claimed_statuses[status_name] = claimed_statuses.get(status_name, 0) + _safe_int(count)

            for raw_record in _list(raw_audit.get("records")):
                if not isinstance(raw_record, Mapping):
                    continue
                record = _normalize_audit_record(raw_record, source=source)
                record_key = _stable_key({key: value for key, value in record.items() if key != "report_source"})
                if record_key in seen_records:
                    continue
                seen_records.add(record_key)
                records.append(record)

    status_counts: dict[str, int] = {}
    rollback_count = 0
    manifest_count = 0
    trace_count = 0
    precondition_count = 0
    before_snapshot_count = 0
    after_snapshot_count = 0
    provenance_count = 0
    event_count = 0
    traces: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        status = str(record.get("status") or "unknown").lower()
        status_counts[status] = status_counts.get(status, 0) + 1
        if record.get("rollback_plan") or record.get("rollback_supported"):
            rollback_count += 1
        manifest_count += _reference_count(record.get("evidence_manifest_entries"))
        precondition_count += bool(record.get("precondition_hash"))
        before_snapshot_count += bool(record.get("before_snapshot"))
        after_snapshot_count += bool(record.get("after_snapshot"))
        provenance_count += bool(record.get("provenance"))
        event_count += _reference_count(record.get("events"))
        steps = _list(record.get("trace_steps"))
        if steps:
            trace_count += 1
        for step_index, step in enumerate(steps):
            traces.append(
                {
                    "record_index": index,
                    "step_index": step_index,
                    "session_id": record.get("session_id"),
                    "capability": record.get("capability"),
                    "action": record.get("action"),
                    "step": step,
                }
            )

    for status, count in claimed_statuses.items():
        status_counts[status] = max(status_counts.get(status, 0), count)

    summary = {
        "status_counts": status_counts,
        "rollback_supported_count": max(rollback_count, claimed["rollback_supported_count"]),
        "manifest_reference_count": max(manifest_count, claimed["manifest_reference_count"]),
        "dashboard_trace_count": max(trace_count, claimed["dashboard_trace_count"]),
        "precondition_hash_count": precondition_count,
        "before_snapshot_count": before_snapshot_count,
        "after_snapshot_count": after_snapshot_count,
        "provenance_count": provenance_count,
        "event_count": event_count,
    }
    return {
        "record_count": len(records),
        "trace_count": len(traces),
        "records": records[:100],
        "traces": traces[:300],
        "summary": summary,
    }


def build_risk_highlights(
    reports: Iterable[Mapping[str, Any]],
    analysis_views: Mapping[str, Mapping[str, Any]],
    *,
    low_confidence_threshold: float = LOW_CONFIDENCE_THRESHOLD,
) -> dict[str, Any]:
    """Build a concise queue of report risks and low-confidence results."""

    items: list[dict[str, Any]] = []
    seen: set[str] = set()

    def append(item: dict[str, Any]) -> None:
        key = _stable_key(item)
        if key not in seen:
            seen.add(key)
            items.append(item)

    for entry in reports:
        report = _report_payload(entry)
        source = _report_source(entry)
        findings = _finding_items(report.get("findings"))
        patch_analysis = _mapping(report.get("patch_analysis"))
        findings.extend(_finding_items(patch_analysis.get("risks")))
        findings.extend(_finding_items(patch_analysis.get("warnings")))
        for finding in findings:
            severity = str(finding.get("severity") or finding.get("risk") or "unknown").lower()
            confidence = _confidence(finding.get("confidence"))
            title = _first_text(
                finding.get("title"),
                finding.get("name"),
                finding.get("message"),
                finding.get("description"),
                finding.get("rule"),
                "Report finding",
            )
            detail = _first_text(
                finding.get("description"),
                finding.get("detail"),
                finding.get("evidence"),
            )
            if severity in {"critical", "high", "medium", "warning"}:
                append(
                    {
                        "kind": "risk",
                        "severity": severity,
                        "domain": str(finding.get("domain") or finding.get("category") or "finding"),
                        "title": title,
                        "detail": detail,
                        "confidence": confidence,
                        "report_source": source,
                    }
                )
            if confidence is not None and confidence < low_confidence_threshold:
                append(
                    {
                        "kind": "low_confidence",
                        "severity": severity,
                        "domain": str(finding.get("domain") or finding.get("category") or "finding"),
                        "title": title,
                        "detail": detail,
                        "confidence": confidence,
                        "report_source": source,
                    }
                )

    for domain, view in analysis_views.items():
        status = str(view.get("status") or "unknown").lower()
        confidence = _confidence(view.get("confidence"))
        source = view.get("report_source")
        if status in {"failed", "failure", "error", "unsafe"}:
            append(
                {
                    "kind": "risk",
                    "severity": "high",
                    "domain": domain,
                    "title": f"{view.get('title') or domain} analysis {status}",
                    "detail": None,
                    "confidence": confidence,
                    "report_source": source,
                }
            )
        if confidence is not None and confidence < low_confidence_threshold:
            append(
                {
                    "kind": "low_confidence",
                    "severity": "warning",
                    "domain": domain,
                    "title": f"{view.get('title') or domain} confidence below threshold",
                    "detail": f"confidence={confidence:.3f}; threshold={low_confidence_threshold:.3f}",
                    "confidence": confidence,
                    "report_source": source,
                }
            )

    items.sort(
        key=lambda item: (
            0 if item.get("kind") == "risk" else 1,
            _SEVERITY_RANK.get(str(item.get("severity") or "unknown"), 6),
            str(item.get("domain") or ""),
            str(item.get("title") or ""),
        )
    )
    return {
        "count": len(items),
        "risk_count": sum(item.get("kind") == "risk" for item in items),
        "low_confidence_count": sum(item.get("kind") == "low_confidence" for item in items),
        "low_confidence_threshold": low_confidence_threshold,
        "items": items[:100],
    }


def collect_report_artifacts(
    reports: Iterable[Mapping[str, Any]],
    capability_audit: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Extract artifact references without resolving or linking filesystem paths."""

    references: list[dict[str, Any]] = []
    for entry in reports:
        report = _report_payload(entry)
        source = _report_source(entry)
        references.extend(
            _artifact_references(
                report.get("artifacts"),
                domain="report",
                kind="report_artifact",
                source=source,
            )
        )
        for domain, _, section in ANALYSIS_DOMAINS:
            payload = _mapping(report.get(section))
            references.extend(
                _artifact_references(
                    payload,
                    domain=domain,
                    kind=f"{domain}_artifact",
                    source=source,
                )
            )
        platform_core = _mapping(report.get("platform_core"))
        for section in ("semantic_ir", "evidence_graph"):
            section_payload = _mapping(platform_core.get(section)) or _mapping(report.get(section))
            artifact_path = section_payload.get("path") or section_payload.get("artifact_path")
            if artifact_path:
                references.append(
                    {
                        "path": str(artifact_path),
                        "label": section.replace("_", " ").title(),
                        "domain": "platform",
                        "kind": section,
                        "source": source,
                    }
                )

    for record in _list(_mapping(capability_audit).get("records")):
        if not isinstance(record, Mapping):
            continue
        source = _first_text(record.get("report_source"), record.get("session_id"))
        references.extend(
            _artifact_references(
                record.get("evidence_manifest_entries"),
                domain="capability",
                kind="evidence_manifest",
                source=source,
            )
        )
        references.extend(
            _artifact_references(
                record.get("rollback_plan"),
                domain="capability",
                kind="rollback_plan",
                source=source,
            )
        )
        for field, kind in (
            ("before_snapshot", "before_snapshot"),
            ("after_snapshot", "after_snapshot"),
            ("provenance", "provenance"),
            ("events", "audit_event"),
        ):
            references.extend(
                _artifact_references(
                    record.get(field),
                    domain="capability",
                    kind=kind,
                    source=source,
                )
            )
    return references


def _analysis_view(
    domain: str,
    title: str,
    section: str,
    payload: Mapping[str, Any],
    report_entry: Mapping[str, Any],
    *,
    history_count: int,
) -> dict[str, Any]:
    normalized_payload = dict(payload)
    if domain == "source":
        normalized_payload["behavior_equivalent"] = _source_behavior_equivalent(payload)

    status = _normalized_analysis_status(normalized_payload)
    confidence = _analysis_confidence(domain, normalized_payload)
    evidence = _evidence_items(normalized_payload.get("evidence"))
    strategy = _compact_value(normalized_payload.get("strategy"))
    artifacts = _artifact_references(
        normalized_payload.get("artifacts"),
        domain=domain,
        kind=f"{domain}_artifact",
        source=_report_source(report_entry),
    )
    view = {
        "domain": domain,
        "title": title,
        "section": section,
        "available": status in _AVAILABLE_ANALYSIS_STATUSES,
        "status": status,
        "confidence": confidence,
        "low_confidence": confidence is not None and confidence < LOW_CONFIDENCE_THRESHOLD,
        "history_count": history_count,
        "report_source": _report_source(report_entry),
        "report_timestamp": _report_timestamp(report_entry),
        "metrics": _analysis_metrics(domain, normalized_payload),
        "evidence": evidence[:12],
        "strategy": strategy,
        "artifact_count": len(artifacts),
    }
    for key in (
        "platform",
        "engine",
        "package_type",
        "framework",
        "language",
        "output_stack",
        "project_dir",
        "verification_status",
        "verification_score",
    ):
        if key in normalized_payload:
            view[key] = _compact_value(normalized_payload.get(key))
    return view


def _source_behavior_equivalent(payload: Mapping[str, Any]) -> bool:
    if payload.get("behavior_validation_status") != "passed":
        return False
    if payload.get("behavior_equivalent") is not True:
        return False
    provenance = _mapping(payload.get("behavior_validation_provenance"))
    validator = _mapping(provenance.get("validator"))
    return (
        validator.get("real_subprocess") is True
        and validator.get("runner_injected") is False
        and validator.get("shell") is False
    )


def _normalized_analysis_status(payload: Mapping[str, Any]) -> str:
    """Return the dashboard's canonical availability status for a domain result."""

    raw_status = getattr(payload.get("status"), "value", payload.get("status"))
    value = str(raw_status or "").strip().lower().replace("-", "_").replace(" ", "_")
    for canonical, aliases in _ANALYSIS_STATUS_ALIASES.items():
        if value in aliases:
            return canonical

    has_result = any(
        key != "status" and _has_analysis_value(item)
        for key, item in payload.items()
    )
    if not value:
        return "ok" if has_result else "unavailable"
    return "partial" if has_result else "unavailable"


def _has_analysis_value(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, (Mapping, list, tuple, set)):
        return bool(value)
    return True


def _analysis_metrics(domain: str, payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    seen_labels: set[str] = set()
    for label, path in _DOMAIN_METRICS.get(domain, ()):
        value = _path_value(payload, path)
        compact = _metric_value(value)
        if compact is None:
            continue
        metrics.append({"label": label, "value": compact})
        seen_labels.add(label.lower())

    for key, value in payload.items():
        label = str(key).replace("_", " ").title()
        if label.lower() in seen_labels or key in {
            "status",
            "confidence",
            "evidence",
            "artifacts",
            "strategy",
        }:
            continue
        if not isinstance(value, (str, int, float, bool)) or value in (None, ""):
            continue
        compact = _metric_value(value)
        if compact is None:
            continue
        metrics.append({"label": label, "value": compact})
        if len(metrics) >= 12:
            break
    return metrics


def _analysis_confidence(domain: str, payload: Mapping[str, Any]) -> float | None:
    for path in _CONFIDENCE_PATHS.get(domain, ("confidence",)):
        confidence = _confidence(_path_value(payload, path))
        if confidence is not None:
            return confidence
    return None


def _normalize_audit_record(record: Mapping[str, Any], *, source: str | None) -> dict[str, Any]:
    trace = _bounded_value(record.get("dashboard_trace"), depth=0)
    normalized = {
        "session_id": _first_text(record.get("session_id")),
        "capability": _first_text(record.get("capability"), "unknown"),
        "provider": _first_text(record.get("provider"), "unknown"),
        "action": _first_text(record.get("action"), "unknown"),
        "status": _first_text(record.get("status"), "unknown"),
        "timestamp": _first_text(record.get("timestamp"), record.get("created_at"), record.get("updated_at")),
        "target_identity": _bounded_value(record.get("target_identity"), depth=0),
        "precondition_hash": _first_text(
            record.get("precondition_hash"),
            _mapping(record.get("precondition")).get("hash"),
        ),
        "before_snapshot": _bounded_value(record.get("before_snapshot"), depth=0),
        "after_snapshot": _bounded_value(record.get("after_snapshot"), depth=0),
        "rollback_supported": bool(record.get("rollback_supported")),
        "rollback_plan": _bounded_value(record.get("rollback_plan"), depth=0),
        "provenance": _bounded_value(record.get("provenance"), depth=0),
        "evidence_manifest_entries": _bounded_value(record.get("evidence_manifest_entries"), depth=0),
        "report_section": _first_text(record.get("report_section")),
        "events": _bounded_value(record.get("events"), depth=0),
        "dashboard_trace": trace,
        "trace_steps": _trace_steps(trace),
        "report_source": source,
    }
    return {key: value for key, value in normalized.items() if value not in (None, [], {})}


def _trace_steps(trace: Any) -> list[Any]:
    if trace in (None, "", [], {}):
        return []
    if isinstance(trace, list):
        return [_bounded_value(item, depth=1) for item in trace[:50]]
    if isinstance(trace, Mapping):
        steps = trace.get("steps")
        if isinstance(steps, list):
            return [_bounded_value(item, depth=1) for item in steps[:50]]
        return [
            {"label": str(key), "value": _compact_value(value)}
            for key, value in list(trace.items())[:50]
        ]
    return [_bounded_value(trace, depth=1)]


def _reference_count(value: Any) -> int:
    if isinstance(value, (list, tuple, set, Mapping)):
        return len(value)
    return 1 if value not in (None, "") else 0


def _finding_items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [dict(item) for item in value if isinstance(item, Mapping)]
    if isinstance(value, Mapping):
        for key in ("items", "findings", "risks", "warnings"):
            nested = value.get(key)
            if isinstance(nested, list):
                return [dict(item) for item in nested if isinstance(item, Mapping)]
        if any(key in value for key in ("severity", "title", "message", "description")):
            return [dict(value)]
        return [
            {"title": str(key), **dict(item)}
            for key, item in value.items()
            if isinstance(item, Mapping)
        ]
    return []


def _artifact_references(
    value: Any,
    *,
    domain: str,
    kind: str,
    source: str | None,
    label: str | None = None,
) -> list[dict[str, Any]]:
    references: list[dict[str, Any]] = []
    if isinstance(value, str):
        if _looks_like_path(value):
            references.append(
                {
                    "path": value,
                    "label": label or value.rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                    "domain": domain,
                    "kind": kind,
                    "source": source,
                }
            )
        return references
    if isinstance(value, list):
        for item in value[:500]:
            references.extend(
                _artifact_references(
                    item,
                    domain=domain,
                    kind=kind,
                    source=source,
                    label=label,
                )
            )
        return references
    if not isinstance(value, Mapping):
        return references

    path_keys = (
        "path",
        "artifact_path",
        "manifest_path",
        "output_path",
        "file",
        "filename",
        "project_dir",
    )
    record_path = next(
        (value.get(key) for key in path_keys if isinstance(value.get(key), str) and value.get(key)),
        None,
    )
    record_label = _first_text(value.get("label"), value.get("name"), value.get("kind"), label)
    record_kind = _first_text(value.get("kind"), value.get("type"), kind) or kind
    if record_path and _looks_like_path(str(record_path)):
        references.append(
            {
                "path": str(record_path),
                "label": record_label or str(record_path).rsplit("/", 1)[-1].rsplit("\\", 1)[-1],
                "domain": domain,
                "kind": record_kind,
                "source": source,
            }
        )

    for key, item in list(value.items())[:500]:
        lowered = str(key).lower()
        if key in path_keys:
            continue
        if isinstance(item, (Mapping, list)) or any(
            token in lowered
            for token in ("artifact", "manifest", "rollback", "evidence", "output", "project", "file", "path")
        ):
            references.extend(
                _artifact_references(
                    item,
                    domain=domain,
                    kind=record_kind,
                    source=source,
                    label=str(key).replace("_", " ").title(),
                )
            )
    return references


def _report_payload(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = entry.get("payload")
    return payload if isinstance(payload, Mapping) else entry


def _report_source(entry: Mapping[str, Any]) -> str | None:
    return _first_text(entry.get("source_path"), entry.get("report_source"))


def _report_timestamp(entry: Mapping[str, Any]) -> str | None:
    return _first_text(entry.get("timestamp"), entry.get("updated_at"), entry.get("created_at"))


def _provider_count(value: Any) -> int:
    if isinstance(value, (list, tuple, set, Mapping)):
        return len(value)
    return 1 if value not in (None, "") else 0


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        try:
            return max(0, int(default))
        except (TypeError, ValueError, OverflowError):
            return 0


def _confidence(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        named = {"high": 0.85, "medium": 0.5, "low": 0.25}
        lowered = value.strip().lower()
        if lowered in named:
            return named[lowered]
        value = lowered.rstrip("%")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    if number > 1.0 and number <= 100.0:
        number /= 100.0
    if number < 0.0 or number > 1.0:
        return None
    return round(number, 4)


def _path_value(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for key in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _metric_value(value: Any) -> Any:
    if value in (None, ""):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, Mapping):
        for key in (
            "name",
            "key",
            "strategy",
            "framework",
            "format",
            "count",
            "total",
            "status",
        ):
            if value.get(key) not in (None, ""):
                return _compact_value(value.get(key))
        return len(value)
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)[:240]


def _evidence_items(value: Any) -> list[str]:
    if isinstance(value, list):
        items = value
    elif value in (None, "", {}):
        return []
    else:
        items = [value]
    return [str(_compact_value(item))[:500] for item in items[:50]]


def _compact_value(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        parts = []
        for key, item in list(value.items())[:8]:
            if isinstance(item, (str, int, float, bool)) and item not in (None, ""):
                parts.append(f"{key}={item}")
        return " | ".join(parts) if parts else f"{len(value)} fields"
    if isinstance(value, list):
        if len(value) <= 4 and all(isinstance(item, (str, int, float, bool)) for item in value):
            return ", ".join(str(item) for item in value)
        return f"{len(value)} items"
    return str(value)[:500]


def _bounded_value(value: Any, *, depth: int) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        return value[:2048]
    if depth >= 3:
        return _compact_value(value)
    if isinstance(value, Mapping):
        return {
            str(key)[:120]: _bounded_value(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, list):
        return [_bounded_value(item, depth=depth + 1) for item in value[:100]]
    return str(value)[:2048]


def _looks_like_path(value: str) -> bool:
    candidate = value.strip()
    if not candidate or len(candidate) > 4096 or "\x00" in candidate:
        return False
    return (
        "/" in candidate
        or "\\" in candidate
        or candidate.startswith(".")
        or "." in candidate.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    )


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value not in (None, ""):
            if isinstance(value, (Mapping, list)):
                return str(_compact_value(value))[:2048]
            return str(value)[:2048]
    return None


def _stable_key(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(value)
