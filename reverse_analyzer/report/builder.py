"""Markdown and JSON report builder."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Dict, Optional


class ReportBuilder:
    """Build portable reports from sessions, tool results, and knowledge."""

    def __init__(self, session: Any = None, tool_results: Optional[Sequence[Any]] = None, knowledge: Any = None) -> None:
        self.session = session
        self.tool_results = list(tool_results) if tool_results is not None else _session_list(session, "tool_calls")
        self.knowledge = knowledge

    def build(self) -> Dict[str, Any]:
        sample = _sample_overview(self.session)
        tool_trace = [_normalize_tool_result(item) for item in self.tool_results]
        findings = _findings(self.knowledge, tool_trace)
        recommendations = _recommendations(findings, tool_trace)
        artifacts = _artifacts(self.session, self.knowledge, tool_trace)
        decompiler = _decompiler(tool_trace)
        return {
            "sample": sample,
            "tool_trace": tool_trace,
            "findings": findings,
            "recommendations": recommendations,
            "artifacts": artifacts,
            "decompiler": decompiler,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.build(), indent=indent, ensure_ascii=False, sort_keys=True)

    def to_markdown(self) -> str:
        report = self.build()
        lines = ["# Reverse Analysis Report", ""]
        lines.extend(["## Sample Overview", ""])
        for key, value in report["sample"].items():
            lines.append(f"- **{_label(key)}:** {value if value is not None else 'unknown'}")
        lines.extend(["", "## Tool Trace", ""])
        if report["tool_trace"]:
            for idx, item in enumerate(report["tool_trace"], 1):
                status = "ok" if item.get("ok", item.get("error") is None) else "error"
                lines.append(f"{idx}. `{item.get('tool_name') or item.get('tool') or 'unknown'}` — {status}")
                if item.get("error"):
                    lines.append(f"   - Error: {item['error']}")
        else:
            lines.append("No tool calls recorded.")
        decompiler = report.get("decompiler") or {}
        if decompiler:
            lines.extend(["", "## Decompiler", ""])
            status = decompiler.get("status") or "unknown"
            lines.append(f"- **Status:** {status}")
            if decompiler.get("setup_hint"):
                lines.append(f"- **Setup Hint:** {decompiler['setup_hint']}")
            if decompiler.get("output_dir"):
                lines.append(f"- **Output:** {decompiler['output_dir']}")
            if decompiler.get("function_count") is not None:
                lines.append(f"- **Functions:** {decompiler['function_count']}")
        lines.extend(["", "## Findings", ""])
        if report["findings"]:
            for item in report["findings"]:
                severity = item.get("severity") or "info"
                title = item.get("title") or item.get("name") or item.get("summary") or "Finding"
                lines.append(f"- **[{severity}] {title}**")
                detail = item.get("detail") or item.get("description")
                if detail:
                    lines.append(f"  - {detail}")
        else:
            lines.append("No findings extracted from the available observations.")
        lines.extend(["", "## Recommendations", ""])
        for item in report["recommendations"]:
            lines.append(f"- {item}")
        lines.extend(["", "## Artifacts", ""])
        if report["artifacts"]:
            for item in report["artifacts"]:
                name = item.get("name") or item.get("path") or item.get("uri") or "artifact"
                lines.append(f"- {name}")
        else:
            lines.append("No artifacts recorded.")
        return "\n".join(lines) + "\n"


def _sample_overview(session: Any) -> Dict[str, Any]:
    if session is None:
        return {"session_id": None, "target": None, "status": None}
    if isinstance(session, Mapping):
        metadata = session.get("metadata") or {}
        return {
            "session_id": session.get("session_id") or session.get("id"),
            "target": session.get("target") or metadata.get("target"),
            "status": _status_value(session.get("status")),
            "created_at": session.get("created_at"),
            "updated_at": session.get("updated_at"),
        }
    metadata = getattr(session, "metadata", {}) or {}
    return {
        "session_id": getattr(session, "session_id", getattr(session, "id", None)),
        "target": getattr(session, "target", None) or metadata.get("target"),
        "status": _status_value(getattr(session, "status", None)),
        "created_at": getattr(session, "created_at", None),
        "updated_at": getattr(session, "updated_at", None),
    }


def _normalize_tool_result(item: Any) -> Dict[str, Any]:
    if hasattr(item, "to_dict"):
        raw = item.to_dict()
    elif isinstance(item, Mapping):
        raw = dict(item)
    else:
        raw = {"tool_name": getattr(item, "tool_name", getattr(item, "name", None)), "result": getattr(item, "result", item)}
    if "tool_name" not in raw:
        raw["tool_name"] = raw.get("tool") or raw.get("name")
    if "ok" not in raw:
        raw["ok"] = raw.get("error") is None
    return raw


def _findings(knowledge: Any, tool_trace: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    for item in _extract_items(knowledge, "findings"):
        if isinstance(item, Mapping):
            findings.append(dict(item))
    for trace in tool_trace:
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            for item in payload.get("findings") or []:
                if isinstance(item, Mapping):
                    findings.append(dict(item))
            if payload.get("verdict") and not payload.get("findings"):
                findings.append({"title": str(payload["verdict"]), "severity": payload.get("severity", "info")})
            findings.extend(_heuristic_findings(trace, payload))
    return findings


def _recommendations(findings: Sequence[Mapping[str, Any]], tool_trace: Sequence[Mapping[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    if not tool_trace:
        recommendations.append("Run the analysis toolchain to collect sample metadata and behavioral indicators.")
    if any(str(item.get("severity", "")).lower() in {"high", "critical"} for item in findings):
        recommendations.append("Prioritize containment and deeper manual validation of high-severity indicators.")
    if findings:
        recommendations.append("Preserve generated artifacts and correlate findings against trusted threat-intelligence sources.")
    else:
        recommendations.append("Expand static and dynamic coverage if higher confidence is required.")
    return recommendations


def _artifacts(session: Any, knowledge: Any, tool_trace: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    artifacts: list[Dict[str, Any]] = []
    for item in _session_list(session, "artifacts"):
        if isinstance(item, Mapping):
            artifacts.append(dict(item))
    for item in _extract_items(knowledge, "artifacts"):
        if isinstance(item, Mapping):
            artifacts.append(dict(item))
    for trace in tool_trace:
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            for item in payload.get("artifacts") or []:
                if isinstance(item, Mapping):
                    artifacts.append(dict(item))
    return artifacts



def _decompiler(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "ghidra_decompile":
            continue
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            return {
                "status": payload.get("status") or ("ok" if trace.get("ok") else "failed"),
                "setup_hint": payload.get("setup_hint"),
                "install_guide": payload.get("install_guide"),
                "output_dir": payload.get("output_dir"),
                "project_dir": payload.get("project_dir"),
                "function_count": payload.get("function_count"),
                "artifacts": payload.get("artifacts") or [],
            }
        return {"status": "unknown"}
    return {}

def _tool_payload(trace: Mapping[str, Any]) -> Any:
    payload = trace.get("result") or trace.get("output") or {}
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    if isinstance(payload, Mapping) and "data" in payload and ("status" in payload or "tool" in payload):
        return payload.get("data") or payload
    return payload


def _heuristic_findings(trace: Mapping[str, Any], payload: Mapping[str, Any]) -> list[Dict[str, Any]]:
    tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
    findings: list[Dict[str, Any]] = []
    if tool_name == "packer_detect" and payload.get("packed_likely"):
        findings.append(
            {
                "title": "Packer indicators detected",
                "severity": "medium",
                "detail": f"score={payload.get('score')} indicators={len(payload.get('indicators') or [])}",
            }
        )
    if tool_name == "section_entropy_scan" and float(payload.get("max_entropy") or 0) >= 7.2:
        findings.append(
            {
                "title": "High entropy section or chunk",
                "severity": "medium",
                "detail": f"max_entropy={payload.get('max_entropy')}",
            }
        )
    if tool_name == "strings_extract":
        suspicious = []
        for value in payload.get("strings") or []:
            text = str(value)
            for needle in ("VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", "GetProcAddress"):
                if needle in text and needle not in suspicious:
                    suspicious.append(needle)
        if suspicious:
            findings.append(
                {
                    "title": "Suspicious Windows API strings",
                    "severity": "medium",
                    "detail": ", ".join(suspicious),
                }
            )
    if tool_name == "ghidra_decompile":
        status = str(payload.get("status") or "").lower()
        if status == "unavailable":
            findings.append(
                {
                    "title": "Ghidra Headless not configured",
                    "severity": "info",
                    "detail": payload.get("setup_hint") or "Run the Ghidra install guide before decompilation.",
                    "recommendation": payload.get("setup_hint"),
                }
            )
        elif status == "failed":
            findings.append(
                {
                    "title": "Ghidra Headless decompilation failed",
                    "severity": "medium",
                    "detail": "See ghidra.log for details.",
                }
            )
        elif status == "ok":
            findings.append(
                {
                    "title": "Ghidra Headless decompilation completed",
                    "severity": "info",
                    "detail": f"functions={payload.get('function_count', 0)}",
                }
            )
    return findings


def _session_list(session: Any, name: str) -> list[Any]:
    if session is None:
        return []
    if isinstance(session, Mapping):
        value = session.get(name) or []
    else:
        value = getattr(session, name, []) or []
    return list(value) if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _extract_items(source: Any, key: str) -> list[Any]:
    if source is None:
        return []
    if isinstance(source, Mapping):
        value = source.get(key) or source.get("items") or []
    else:
        value = getattr(source, key, None)
        if callable(value):
            value = value()
        if value is None and hasattr(source, "to_dict"):
            value = source.to_dict().get(key)
    return list(value) if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _status_value(status: Any) -> Any:
    return getattr(status, "value", status)


def _label(key: str) -> str:
    return key.replace("_", " ").title()
