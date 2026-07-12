from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from reverse_analyzer.core.audit import summarize_audit_records
from reverse_analyzer.core.ir import EvidenceGraph, SemanticIR
from reverse_analyzer.providers import build_default_registry

DEFAULT_REPORT_SECTIONS = (
    "evidence_integrity",
    "memory_analysis",
    "patch_analysis",
    "engine_analysis",
    "android_analysis",
    "protocol_analysis",
    "gui_analysis",
    "source_reconstruction",
)


def ensure_platform_sections(report_data: Dict[str, Any]) -> Dict[str, Any]:
    for key in DEFAULT_REPORT_SECTIONS:
        report_data.setdefault(key, {"status": "unavailable"})
    report_data.setdefault("platform_core", {"status": "pending"})
    return report_data


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def _sample_label(report_data: Dict[str, Any], sample_path: Optional[str]) -> str:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return (
        report_data.get("sample_name")
        or report_data.get("target_name")
        or report_data.get("input_name")
        or sample.get("name")
        or sample.get("filename")
        or sample.get("path")
        or (Path(sample_path).name if sample_path else "sample")
    )


def _sample_path(report_data: Dict[str, Any], sample_path: Optional[str]) -> Optional[str]:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return (
        sample_path
        or report_data.get("sample_path")
        or report_data.get("target_path")
        or report_data.get("input_path")
        or sample.get("path")
    )


def _sample_attr(report_data: Dict[str, Any], key: str) -> Any:
    sample = report_data.get("sample") if isinstance(report_data.get("sample"), dict) else {}
    return report_data.get(key) or sample.get(key)


def build_semantic_ir(
    report_data: Dict[str, Any],
    sample_path: Optional[str] = None,
) -> SemanticIR:
    ensure_platform_sections(report_data)
    resolved_sample_path = _sample_path(report_data, sample_path)

    ir = SemanticIR(
        sample={
            "name": _sample_label(report_data, resolved_sample_path),
            "path": resolved_sample_path,
            "sha256": _sample_attr(report_data, "sha256"),
            "platform": _sample_attr(report_data, "platform"),
            "file_type": _sample_attr(report_data, "file_type"),
        }
    )

    if report_data.get("memory_analysis"):
        ir.runtime.append(report_data["memory_analysis"])

    ir.engine = report_data.get("engine_analysis") or {}
    ir.android = report_data.get("android_analysis") or {}
    ir.protocol = report_data.get("protocol_analysis") or {}
    ir.gui = report_data.get("gui_analysis") or {}
    ir.source = report_data.get("source_reconstruction") or {}

    capability_audit = report_data.get("capability_audit") or {}
    if capability_audit:
        ir.notes.append({"type": "capability_audit", "summary": capability_audit})

    if report_data.get("static_analysis"):
        ir.modules.append(
            {
                "type": "static_analysis",
                "summary": report_data.get("static_analysis"),
            }
        )

    if report_data.get("imports"):
        ir.modules.append(
            {
                "type": "imports",
                "summary": report_data.get("imports"),
            }
        )

    pe_analysis = report_data.get("pe_analysis")
    if isinstance(pe_analysis, dict) and pe_analysis:
        ir.modules.append({"type": "pe_analysis", "summary": pe_analysis})

    return ir


def build_evidence_graph(
    report_data: Dict[str, Any],
    sample_path: Optional[str] = None,
) -> EvidenceGraph:
    ensure_platform_sections(report_data)
    resolved_sample_path = _sample_path(report_data, sample_path)
    label = _sample_label(report_data, resolved_sample_path)
    sample_node_id = f"sample:{_stable_hash({'path': resolved_sample_path, 'label': label})}"

    graph = EvidenceGraph()
    graph.add_node(
        sample_node_id,
        "sample",
        label,
        path=resolved_sample_path,
        sha256=_sample_attr(report_data, "sha256"),
        platform=_sample_attr(report_data, "platform"),
        file_type=_sample_attr(report_data, "file_type"),
    )

    section_to_node_type = {
        "evidence_integrity": "evidence_integrity",
        "memory_analysis": "memory_analysis",
        "patch_analysis": "patch_analysis",
        "engine_analysis": "engine_analysis",
        "android_analysis": "android_analysis",
        "protocol_analysis": "protocol_analysis",
        "gui_analysis": "gui_analysis",
        "source_reconstruction": "source_reconstruction",
    }

    for section_name, node_type in section_to_node_type.items():
        payload = report_data.get(section_name) or {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        node_id = f"{section_name}:{_stable_hash(payload)}"
        strategy = payload.get("strategy") if isinstance(payload.get("strategy"), dict) else {}
        label_value = (
            payload.get("framework")
            or payload.get("engine")
            or strategy.get("name")
            or section_name
        )
        graph.add_node(
            node_id,
            node_type,
            str(label_value),
            status=payload.get("status", "unknown"),
            confidence=payload.get("confidence"),
        )
        graph.add_edge(
            sample_node_id,
            node_id,
            "has_analysis",
            section=section_name,
        )

    capability_audit = report_data.get("capability_audit")
    if isinstance(capability_audit, dict):
        for index, record in enumerate(capability_audit.get("records") or [], start=1):
            if not isinstance(record, dict):
                continue
            node_id = f"capability_audit:{index}:{_stable_hash(record)}"
            label_value = record.get("capability") or f"audit-{index}"
            graph.add_node(
                node_id,
                "capability_audit",
                str(label_value),
                status=record.get("status"),
                provider=record.get("provider"),
                action=record.get("action"),
            )
            graph.add_edge(sample_node_id, node_id, "has_audit_record", section="capability_audit")

    return graph


def summarize_registry(registry=None) -> Dict[str, Any]:
    registry = registry or build_default_registry()
    capabilities = registry.list_capabilities()
    return {
        "capability_count": len(capabilities),
        "capabilities": {
            capability: registry.list_providers(capability)
            for capability in capabilities
        },
    }


def summarize_capability_audit(report_data: Dict[str, Any]) -> Dict[str, Any]:
    capability_audit = report_data.get("capability_audit")
    if not isinstance(capability_audit, dict):
        return {"record_count": 0, "records": [], "summary": summarize_audit_records([])}
    records = capability_audit.get("records")
    if not isinstance(records, list):
        records = []
    return {
        "record_count": len(records),
        "records": records,
        "summary": summarize_audit_records(records),
    }


def finalize_platform_core(
    report_data: Dict[str, Any],
    out_dir: str,
    sample_path: Optional[str] = None,
    registry=None,
) -> Dict[str, Any]:
    ensure_platform_sections(report_data)
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    ir = build_semantic_ir(report_data, sample_path=sample_path)
    graph = build_evidence_graph(report_data, sample_path=sample_path)
    registry_summary = summarize_registry(registry)

    semantic_ir_path = out_path / "semantic_ir.json"
    evidence_graph_path = out_path / "evidence_graph.json"

    ir.write_json(str(semantic_ir_path))
    graph.write_json(str(evidence_graph_path))

    report_data["platform_core"] = {
        "status": "ok",
        "semantic_ir": {
            "path": str(semantic_ir_path),
            "module_count": len(ir.modules),
            "runtime_count": len(ir.runtime),
        },
        "evidence_graph": {
            "path": str(evidence_graph_path),
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "capability_registry": registry_summary,
        "capability_audit": summarize_capability_audit(report_data),
    }

    return report_data["platform_core"]
