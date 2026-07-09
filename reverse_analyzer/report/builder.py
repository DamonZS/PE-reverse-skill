"""Markdown and JSON report builder."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Dict, Optional


class ReportBuilder:
    """Build portable reports from sessions, tool results, and knowledge."""

    def __init__(
        self,
        session: Any = None,
        tool_results: Optional[Sequence[Any]] = None,
        knowledge: Any = None,
        *,
        config: Any = None,
        out_dir: Any = None,
    ) -> None:
        self.session = session
        self.tool_results = list(tool_results) if tool_results is not None else _session_list(session, "tool_calls")
        self.knowledge = knowledge
        self.config = config
        self.out_dir = str(out_dir) if out_dir is not None else None

    def build(self) -> Dict[str, Any]:
        sample = _sample_overview(self.session)
        tool_trace = [_normalize_tool_result(item) for item in self.tool_results]
        pe_analysis = _pe_analysis(tool_trace)
        yara = _yara(tool_trace)
        decompiler = _decompiler(tool_trace)
        reconstruction = _reconstruction(tool_trace)
        findings = _findings(self.knowledge, tool_trace)
        recommendations = _recommendations(
            findings,
            tool_trace,
            pe_analysis=pe_analysis,
            yara=yara,
            decompiler=decompiler,
            reconstruction=reconstruction,
        )
        artifacts = _artifacts(self.session, self.knowledge, tool_trace)
        return {
            "sample": sample,
            "tool_trace": tool_trace,
            "pe_analysis": pe_analysis,
            "yara": yara,
            "decompiler": decompiler,
            "reconstruction": reconstruction,
            "findings": findings,
            "recommendations": recommendations,
            "artifacts": artifacts,
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
                lines.append(f"{idx}. `{item.get('tool_name') or item.get('tool') or 'unknown'}` — {item.get('status', 'unknown')}")
                if item.get("error"):
                    lines.append(f"   - Error: {item['error']}")
        else:
            lines.append("No tool calls recorded.")

        if report.get("pe_analysis"):
            pe = report["pe_analysis"]
            lines.extend(["", "## PE Deep Analysis", ""])
            lines.append(f"- **Status:** {pe.get('status', 'unknown')}")
            if pe.get("shell_score") is not None:
                lines.append(f"- **Shell Score:** {pe['shell_score']}")
            if pe.get("shell_verdict"):
                lines.append(f"- **Shell Verdict:** {pe['shell_verdict']}")
            if isinstance(pe.get("entrypoint"), Mapping):
                entry = pe["entrypoint"]
                lines.append(f"- **Entrypoint Section:** {entry.get('section') or 'unknown'}")
            lines.append(f"- **Import DLLs:** {pe.get('import_dll_count', 0)}")
            lines.append(f"- **Exported Symbols:** {pe.get('export_count', 0)}")
            lines.append(f"- **Resources:** {pe.get('resource_count', 0)}")
            lines.append(f"- **TLS Callbacks:** {pe.get('tls_callback_count', 0)}")
            lines.append(f"- **Overlay Present:** {_bool_word(pe.get('overlay_present'))}")
            if pe.get("overlay_size") is not None:
                lines.append(f"- **Overlay Size:** {pe['overlay_size']}")
            lines.append(f"- **Section Anomalies:** {pe.get('section_anomaly_count', 0)}")
            lines.append(f"- **IAT Anomalies:** {pe.get('iat_anomaly_count', 0)}")

        if report.get("yara"):
            yara = report["yara"]
            lines.extend(["", "## YARA", ""])
            lines.append(f"- **Status:** {yara.get('status', 'unknown')}")
            if yara.get("rules_path"):
                lines.append(f"- **Rules Path:** {yara['rules_path']}")
            lines.append(f"- **Matches:** {yara.get('match_count', 0)}")
            for match in yara.get("matches") or []:
                title = match.get("rule") or "match"
                tags = ", ".join(match.get("tags") or [])
                detail = match.get("meta", {}).get("description") or match.get("namespace")
                lines.append(f"- `{title}`{f' [{tags}]' if tags else ''}")
                if detail:
                    lines.append(f"  - {detail}")
                preview = _string_preview(match.get("strings"))
                if preview:
                    lines.append(f"  - Evidence: {preview}")

        decompiler = report.get("decompiler") or {}
        if decompiler:
            lines.extend(["", "## Decompiler", ""])
            lines.append(f"- **Status:** {decompiler.get('status') or 'unknown'}")
            if decompiler.get("setup_hint"):
                lines.append(f"- **Setup Hint:** {decompiler['setup_hint']}")
            if decompiler.get("output_dir"):
                lines.append(f"- **Output:** {decompiler['output_dir']}")
            if decompiler.get("function_count") is not None:
                lines.append(f"- **Functions:** {decompiler['function_count']}")

        reconstruction = report.get("reconstruction") or {}
        if reconstruction:
            lines.extend(["", "## Reconstruction", ""])
            lines.append(f"- **Status:** {reconstruction.get('status') or 'unknown'}")
            if reconstruction.get("project_dir"):
                lines.append(f"- **Project Dir:** {reconstruction['project_dir']}")
            if reconstruction.get("function_count") is not None:
                lines.append(f"- **Function Stubs:** {reconstruction['function_count']}")
            if reconstruction.get("import_count") is not None:
                lines.append(f"- **Imported APIs:** {reconstruction['import_count']}")
            if reconstruction.get("stub_only") is not None:
                lines.append(f"- **Stub Only:** {_bool_word(reconstruction['stub_only'])}")

        lines.extend(["", "## Findings", ""])
        if report["findings"]:
            for item in report["findings"]:
                severity = item.get("severity") or "info"
                title = item.get("title") or item.get("name") or item.get("summary") or "Finding"
                lines.append(f"- **[{severity}] {title}**")
                if item.get("source"):
                    lines.append(f"  - Source: `{item['source']}`")
                if item.get("detail"):
                    lines.append(f"  - Detail: {item['detail']}")
                if item.get("confidence") is not None:
                    lines.append(f"  - Confidence: {item['confidence']:.2f}")
                if item.get("evidence"):
                    lines.append(f"  - Evidence: {_evidence_text(item['evidence'])}")
                if item.get("recommendation"):
                    lines.append(f"  - Recommendation: {item['recommendation']}")
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
    raw = _json_safe(raw)
    if "tool_name" not in raw:
        raw["tool_name"] = raw.get("tool") or raw.get("name")
    raw["status"] = _tool_status(raw)
    raw["ok"] = raw.get("ok") if isinstance(raw.get("ok"), bool) else raw["status"] == "ok"
    return raw


def _findings(knowledge: Any, tool_trace: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    for item in _extract_items(knowledge, "findings"):
        if isinstance(item, Mapping):
            findings.append(_normalize_finding(item))
    for trace in tool_trace:
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            for item in payload.get("findings") or []:
                if isinstance(item, Mapping):
                    findings.append(_normalize_finding(item, source=str(trace.get("tool_name") or trace.get("tool") or "tool")))
            if payload.get("verdict") and not payload.get("findings"):
                findings.append(
                    _finding(
                        str(payload["verdict"]),
                        severity=payload.get("severity", "info"),
                        source=str(trace.get("tool_name") or trace.get("tool") or "tool"),
                        confidence=0.5,
                    )
                )
            findings.extend(_heuristic_findings(trace, payload))
    return _dedupe_findings(findings)


def _recommendations(
    findings: Sequence[Mapping[str, Any]],
    tool_trace: Sequence[Mapping[str, Any]],
    *,
    pe_analysis: Mapping[str, Any],
    yara: Mapping[str, Any],
    decompiler: Mapping[str, Any],
    reconstruction: Mapping[str, Any],
) -> list[str]:
    recommendations: list[str] = []
    if not tool_trace:
        recommendations.append("Run the analysis toolchain to collect sample metadata and behavioral indicators.")
    for item in findings:
        recommendation = item.get("recommendation")
        if recommendation:
            recommendations.append(str(recommendation))
    if any(str(item.get("severity", "")).lower() in {"high", "critical"} for item in findings):
        recommendations.append("Prioritize containment and deeper manual validation of high-severity indicators.")
    if int(pe_analysis.get("shell_score") or 0) >= 40:
        recommendations.append("Inspect the entry point, suspicious sections, and overlay to confirm packer or obfuscation behavior.")
    if yara.get("status") == "unavailable":
        recommendations.append("Install yara-python to enable rule-based scanning, or provide a compatible environment for YARA.")
    elif yara.get("match_count", 0):
        recommendations.append("Review YARA matches and correlate them with imports, strings, and PE anomalies before assigning a family label.")
    if decompiler.get("status") == "unavailable":
        recommendations.append("Configure Ghidra Headless with `python -m reverse_analyzer --install-guide ghidra` for deeper pseudocode output.")
    if reconstruction.get("status") == "ok":
        recommendations.append("Review the generated reconstruction scaffold and replace placeholder stubs with validated manual analysis.")
    if findings:
        recommendations.append("Preserve generated artifacts and correlate findings against trusted threat-intelligence sources.")
    else:
        recommendations.append("Expand static and dynamic coverage if higher confidence is required.")
    return _dedupe_strings(recommendations)


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
    return _dedupe_artifacts(artifacts)


def _pe_analysis(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "pe_deep_scan":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            return {"status": _tool_status(trace)}
        imports = payload.get("imports") or []
        exports = payload.get("exports") or {}
        resources = payload.get("resources") or {}
        tls_callbacks = payload.get("tls_callbacks") or {}
        overlay = payload.get("overlay") or {}
        rich_header = payload.get("rich_header") or {}
        section_anomalies = payload.get("section_anomalies") or []
        iat_anomalies = payload.get("iat_anomalies") or []
        return {
            "status": _tool_status(trace),
            "entrypoint": payload.get("entrypoint") or {},
            "import_dll_count": len(imports),
            "import_function_count": sum(len(item.get("functions") or []) for item in imports if isinstance(item, Mapping)),
            "export_count": exports.get("count", 0),
            "resource_count": resources.get("count", 0),
            "resource_types": resources.get("types") or [],
            "tls_callback_count": tls_callbacks.get("count", 0),
            "tls_callbacks": tls_callbacks.get("callbacks") or [],
            "overlay_present": overlay.get("present"),
            "overlay_size": overlay.get("size"),
            "rich_header_present": rich_header.get("present"),
            "section_anomaly_count": len(section_anomalies),
            "section_anomalies": section_anomalies,
            "iat_anomaly_count": len(iat_anomalies),
            "iat_anomalies": iat_anomalies,
            "shell_score": payload.get("shell_score"),
            "shell_verdict": payload.get("shell_verdict"),
            "shell_indicators": payload.get("shell_indicators") or [],
        }
    return {}


def _yara(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name not in {"yara_scan", "yara_scan_stub"}:
            continue
        payload = _tool_payload(trace)
        raw = _raw_result(trace)
        if not isinstance(payload, Mapping):
            return {"status": _tool_status(trace)}
        return {
            "status": _tool_status(trace),
            "rules_path": payload.get("rules_path"),
            "rule_files": payload.get("rule_files") or [],
            "match_count": payload.get("match_count", len(payload.get("matches") or [])),
            "matches": payload.get("matches") or [],
            "error": raw.get("error") if isinstance(raw, Mapping) else trace.get("error"),
        }
    return {}


def _decompiler(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "ghidra_decompile":
            continue
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            return {
                "status": payload.get("status") or _tool_status(trace),
                "setup_hint": payload.get("setup_hint"),
                "install_guide": payload.get("install_guide"),
                "output_dir": payload.get("output_dir"),
                "project_dir": payload.get("project_dir"),
                "function_count": payload.get("function_count"),
                "artifacts": payload.get("artifacts") or [],
            }
        return {"status": _tool_status(trace)}
    return {}


def _reconstruction(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "reconstruct_project":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            return {"status": _tool_status(trace)}
        return {
            "status": payload.get("status") or _tool_status(trace),
            "project_dir": payload.get("project_dir"),
            "generated_files": payload.get("generated_files") or [],
            "function_count": payload.get("function_count"),
            "import_count": payload.get("import_count"),
            "stub_only": payload.get("stub_only"),
            "artifacts": payload.get("artifacts") or [],
        }
    return {}


def _raw_result(trace: Mapping[str, Any]) -> Any:
    payload = trace.get("result") or trace.get("output")
    if hasattr(payload, "to_dict"):
        payload = payload.to_dict()
    return payload


def _tool_status(trace: Mapping[str, Any]) -> str:
    if trace.get("status"):
        return str(trace.get("status")).lower()
    raw = _raw_result(trace)
    if isinstance(raw, Mapping):
        if raw.get("status"):
            return str(raw.get("status")).lower()
        nested = raw.get("data")
        if isinstance(nested, Mapping) and nested.get("status"):
            return str(nested.get("status")).lower()
    if trace.get("error"):
        return "failed"
    return "ok"


def _tool_payload(trace: Mapping[str, Any]) -> Any:
    payload = _raw_result(trace)
    if isinstance(payload, Mapping) and "data" in payload and ("status" in payload or "tool" in payload):
        return payload.get("data") or payload
    return payload or {}


def _heuristic_findings(trace: Mapping[str, Any], payload: Mapping[str, Any]) -> list[Dict[str, Any]]:
    tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
    status = _tool_status(trace)
    findings: list[Dict[str, Any]] = []

    if tool_name == "packer_detect" and payload.get("packed_likely"):
        score = int(payload.get("score") or 0)
        findings.append(
            _finding(
                "Packer indicators detected",
                severity="high" if score >= 75 else "medium",
                confidence=max(0.6, min(0.95, score / 100 if score else 0.6)),
                source=tool_name,
                detail=f"score={score} indicators={len(payload.get('indicators') or [])}",
                evidence={"score": score, "indicators": payload.get("indicators") or []},
                recommendation="Inspect unpacking behavior and confirm whether imports or control flow are reconstructed at runtime.",
            )
        )

    if tool_name == "section_entropy_scan" and float(payload.get("max_entropy") or 0) >= 7.2:
        findings.append(
            _finding(
                "High entropy section or chunk",
                severity="medium",
                confidence=0.7,
                source=tool_name,
                detail=f"max_entropy={payload.get('max_entropy')}",
                evidence={"max_entropy": payload.get("max_entropy"), "sections": payload.get("sections") or []},
                recommendation="Inspect high-entropy regions for compression, encryption, or packed payloads.",
            )
        )

    if tool_name == "strings_extract":
        suspicious: list[str] = []
        for value in payload.get("strings") or []:
            text = str(value)
            for needle in ("VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", "GetProcAddress"):
                if needle in text and needle not in suspicious:
                    suspicious.append(needle)
        if suspicious:
            findings.append(
                _finding(
                    "Suspicious Windows API strings",
                    severity="medium",
                    confidence=0.65,
                    source=tool_name,
                    detail=", ".join(suspicious),
                    evidence={"matched_strings": suspicious},
                    recommendation="Trace these APIs through imports or decompiler output to determine whether the sample injects code or resolves APIs dynamically.",
                )
            )

    if tool_name == "pe_deep_scan":
        shell_score = int(payload.get("shell_score") or 0)
        if shell_score >= 40:
            findings.append(
                _finding(
                    "Packed or obfuscated PE characteristics",
                    severity="high" if shell_score >= 70 else "medium",
                    confidence=max(0.6, min(0.95, shell_score / 100)),
                    source=tool_name,
                    detail=f"shell_score={shell_score} verdict={payload.get('shell_verdict')}",
                    evidence={
                        "entrypoint": payload.get("entrypoint"),
                        "section_anomalies": payload.get("section_anomalies") or [],
                        "shell_indicators": payload.get("shell_indicators") or [],
                    },
                    recommendation="Validate whether the sample is packed, then focus manual reversing on the unpacked entry point and import resolution path.",
                )
            )
        if int((payload.get("tls_callbacks") or {}).get("count") or 0) > 0:
            findings.append(
                _finding(
                    "TLS callbacks present",
                    severity="medium",
                    confidence=0.75,
                    source=tool_name,
                    detail=f"callbacks={int((payload.get('tls_callbacks') or {}).get('count') or 0)}",
                    evidence={"callbacks": (payload.get("tls_callbacks") or {}).get("callbacks") or []},
                    recommendation="Review TLS callbacks before trusting the reported PE entry point; they may execute first.",
                )
            )
        if payload.get("iat_anomalies"):
            findings.append(
                _finding(
                    "IAT anomalies detected",
                    severity="medium",
                    confidence=0.75,
                    source=tool_name,
                    detail=f"anomalies={len(payload.get('iat_anomalies') or [])}",
                    evidence={"iat_anomalies": payload.get("iat_anomalies") or []},
                    recommendation="Validate import descriptors and determine whether the sample reconstructs its IAT dynamically.",
                )
            )
        if (payload.get("overlay") or {}).get("present"):
            findings.append(
                _finding(
                    "Overlay data present",
                    severity="low",
                    confidence=0.6,
                    source=tool_name,
                    detail=f"overlay_size={(payload.get('overlay') or {}).get('size')}",
                    evidence={"overlay": payload.get("overlay") or {}},
                    recommendation="Inspect overlay data for appended payloads, installers, or secondary stages.",
                )
            )

    if tool_name in {"yara_scan", "yara_scan_stub"}:
        if status == "unavailable":
            findings.append(
                _finding(
                    "YARA scanning unavailable",
                    severity="info",
                    confidence=0.95,
                    source=tool_name,
                    detail="yara-python is not installed or the scanner could not start.",
                    evidence={"rules_path": payload.get("rules_path"), "error": _tool_error(trace)},
                    recommendation="Install yara-python to enable rule-based scanning with the bundled ruleset.",
                )
            )
        else:
            for match in payload.get("matches") or []:
                if not isinstance(match, Mapping):
                    continue
                meta = match.get("meta") or {}
                strings = match.get("strings") or {}
                findings.append(
                    _finding(
                        f"YARA match: {match.get('rule') or 'rule'}",
                        severity=meta.get("severity", "medium"),
                        confidence=0.85,
                        source=tool_name,
                        detail=str(meta.get("description") or match.get("namespace") or "Rule matched sample content."),
                        evidence={
                            "rule": match.get("rule"),
                            "namespace": match.get("namespace"),
                            "tags": match.get("tags") or [],
                            "meta": meta,
                            "strings": strings,
                        },
                        recommendation="Review the matched strings and combine them with PE metadata before assigning malware family or capability labels.",
                    )
                )

    if tool_name == "ghidra_decompile":
        status_value = str(payload.get("status") or status).lower()
        if status_value == "unavailable":
            findings.append(
                _finding(
                    "Ghidra Headless not configured",
                    severity="info",
                    confidence=0.95,
                    source=tool_name,
                    detail=payload.get("setup_hint") or "Run the Ghidra install guide before decompilation.",
                    evidence={"checked_paths": payload.get("checked_paths") or []},
                    recommendation=payload.get("setup_hint") or "Run: python -m reverse_analyzer --install-guide ghidra",
                )
            )
        elif status_value == "failed":
            findings.append(
                _finding(
                    "Ghidra Headless decompilation failed",
                    severity="medium",
                    confidence=0.75,
                    source=tool_name,
                    detail="See ghidra.log for details.",
                    evidence={"artifacts": payload.get("artifacts") or []},
                    recommendation="Inspect ghidra.log and rerun with a longer timeout or a verified GHIDRA_HOME.",
                )
            )
        elif status_value == "ok":
            findings.append(
                _finding(
                    "Ghidra Headless decompilation completed",
                    severity="info",
                    confidence=0.9,
                    source=tool_name,
                    detail=f"functions={payload.get('function_count', 0)}",
                    evidence={"output_dir": payload.get("output_dir"), "function_count": payload.get("function_count", 0)},
                    recommendation="Review pseudocode, call graph, and cross-references to prioritize manual reconstruction work.",
                )
            )

    if tool_name == "reconstruct_project" and status == "ok":
        findings.append(
            _finding(
                "Reconstruction scaffold generated",
                severity="info",
                confidence=0.9,
                source=tool_name,
                detail=str(payload.get("project_dir") or "stub project created"),
                evidence={
                    "project_dir": payload.get("project_dir"),
                    "function_count": payload.get("function_count"),
                    "import_count": payload.get("import_count"),
                },
                recommendation="Use the generated stub project as a manual reconstruction workspace; it is not source-equivalent by itself.",
            )
        )

    return findings


def _finding(
    title: str,
    *,
    severity: str = "info",
    confidence: float = 0.5,
    source: str | None = None,
    detail: str | None = None,
    evidence: Any = None,
    recommendation: str | None = None,
    **extra: Any,
) -> Dict[str, Any]:
    item = {
        "id": _finding_id(source, title, detail),
        "title": str(title),
        "severity": _severity(severity),
        "confidence": _confidence(confidence),
        "source": source,
        "detail": str(detail) if detail is not None else None,
        "description": str(detail) if detail is not None else None,
        "evidence": _json_safe(evidence) if evidence is not None else {},
        "recommendation": recommendation,
    }
    item.update({key: _json_safe(value) for key, value in extra.items()})
    return item


def _normalize_finding(item: Mapping[str, Any], source: str | None = None) -> Dict[str, Any]:
    detail = item.get("detail") or item.get("description")
    normalized = _finding(
        str(item.get("title") or item.get("name") or item.get("summary") or "Finding"),
        severity=str(item.get("severity") or "info"),
        confidence=item.get("confidence", 0.5),
        source=source or (str(item.get("source")) if item.get("source") is not None else None),
        detail=str(detail) if detail is not None else None,
        evidence=item.get("evidence") or {},
        recommendation=item.get("recommendation"),
    )
    for key, value in item.items():
        if key not in normalized:
            normalized[key] = _json_safe(value)
    return normalized


def _finding_id(source: str | None, title: str, detail: str | None) -> str:
    parts = [source or "finding", title, detail or ""]
    slug = "_".join(
        "".join(ch.lower() if ch.isalnum() else "_" for ch in part).strip("_")
        for part in parts
        if part
    )
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug[:120] or "finding"


def _dedupe_findings(findings: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[Dict[str, Any]] = []
    for item in findings:
        key = json.dumps(
            {
                "title": item.get("title"),
                "severity": item.get("severity"),
                "detail": item.get("detail"),
                "source": item.get("source"),
                "evidence": item.get("evidence"),
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(item))
    return deduped


def _dedupe_artifacts(artifacts: Sequence[Mapping[str, Any]]) -> list[Dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[Dict[str, Any]] = []
    for item in artifacts:
        key = json.dumps(
            {"name": item.get("name"), "path": item.get("path"), "kind": item.get("kind")},
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(dict(item))
    return deduped


def _dedupe_strings(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        text = str(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def _string_preview(strings: Any) -> str:
    if not isinstance(strings, Mapping):
        return ""
    items = strings.get("items") or []
    previews = []
    for item in items[:3]:
        if not isinstance(item, Mapping):
            continue
        preview = item.get("preview")
        identifier = item.get("identifier")
        if preview:
            previews.append(f"{identifier}={preview}")
    return "; ".join(previews)


def _tool_error(trace: Mapping[str, Any]) -> Any:
    if trace.get("error"):
        return trace.get("error")
    raw = _raw_result(trace)
    if isinstance(raw, Mapping):
        return raw.get("error")
    return None


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


def _severity(value: Any) -> str:
    text = str(value or "info").lower()
    if text not in {"info", "low", "medium", "high", "critical"}:
        return "info"
    return text


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except Exception:
        number = 0.5
    return max(0.0, min(1.0, number))


def _label(key: str) -> str:
    return key.replace("_", " ").title()


def _bool_word(value: Any) -> str:
    return "yes" if bool(value) else "no"


def _evidence_text(evidence: Any) -> str:
    if isinstance(evidence, Mapping):
        parts = []
        for key, value in list(evidence.items())[:5]:
            if isinstance(value, (list, tuple)):
                rendered = ", ".join(str(item) for item in list(value)[:3])
            elif isinstance(value, Mapping):
                rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
            else:
                rendered = str(value)
            parts.append(f"{key}={rendered}")
        return "; ".join(parts)
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes)):
        return ", ".join(str(item) for item in list(evidence)[:5])
    return str(evidence)


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        pass
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if hasattr(value, "__dict__"):
        return _json_safe(vars(value))
    return repr(value)
