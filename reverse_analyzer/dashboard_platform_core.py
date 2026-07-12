from __future__ import annotations

from typing import Any, Dict


def build_platform_core_view(report_data: Dict[str, Any]) -> Dict[str, Any]:
    platform_core = report_data.get("platform_core") or {}
    registry = platform_core.get("capability_registry") or {}
    semantic_ir = platform_core.get("semantic_ir") or {}
    evidence_graph = platform_core.get("evidence_graph") or {}
    capability_audit = platform_core.get("capability_audit") or {}

    capabilities = registry.get("capabilities") or {}
    audit_summary = capability_audit.get("summary") or {}

    return {
        "status": platform_core.get("status", "unavailable"),
        "cards": [
            {
                "title": "Capability Registry",
                "value": registry.get("capability_count", 0),
                "subtitle": f"{sum(len(v) for v in capabilities.values())} providers",
            },
            {
                "title": "Semantic IR",
                "value": semantic_ir.get("module_count", 0),
                "subtitle": f"runtime={semantic_ir.get('runtime_count', 0)}",
            },
            {
                "title": "Evidence Graph",
                "value": evidence_graph.get("node_count", 0),
                "subtitle": f"edges={evidence_graph.get('edge_count', 0)}",
            },
            {
                "title": "Capability Audit",
                "value": capability_audit.get("record_count", 0),
                "subtitle": f"rollback={audit_summary.get('rollback_supported_count', 0)}",
            },
        ],
        "capabilities": capabilities,
        "capability_audit": capability_audit,
        "artifacts": {
            "semantic_ir": semantic_ir.get("path"),
            "evidence_graph": evidence_graph.get("path"),
        },
    }
