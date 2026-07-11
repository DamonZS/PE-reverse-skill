"""Markdown and JSON report builder."""

from __future__ import annotations

import json
import re
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
        dynamic_analysis = _dynamic_analysis(tool_trace)
        gui_analysis = _gui_analysis(tool_trace)
        behavior_graph = _behavior_graph(tool_trace)
        decompiler = _decompiler(tool_trace)
        reconstruction = _reconstruction(self.session, tool_trace)
        semantic_ir = _semantic_ir(tool_trace)
        reconstruction_verification = _reconstruction_verification(tool_trace)
        findings = _findings(self.knowledge, tool_trace)
        recommendations = _recommendations(
            findings,
            tool_trace,
            pe_analysis=pe_analysis,
            yara=yara,
            dynamic_analysis=dynamic_analysis,
            gui_analysis=gui_analysis,
            decompiler=decompiler,
            reconstruction=reconstruction,
        )
        artifacts = _artifacts(self.session, self.knowledge, tool_trace)
        return {
            "sample": sample,
            "tool_trace": tool_trace,
            "pe_analysis": pe_analysis,
            "yara": yara,
            "dynamic_analysis": dynamic_analysis,
            "gui_analysis": gui_analysis,
            "behavior_graph": behavior_graph,
            "decompiler": decompiler,
            "reconstruction": reconstruction,
            "semantic_ir": semantic_ir,
            "reconstruction_verification": reconstruction_verification,
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

        dynamic_analysis = report.get("dynamic_analysis") or {}
        if dynamic_analysis:
            lines.extend(["", "## Dynamic Analysis", ""])
            lines.append(f"- **Status:** {dynamic_analysis.get('status') or 'unknown'}")
            if dynamic_analysis.get("backend"):
                lines.append(f"- **Backend:** {dynamic_analysis['backend']}")
            if dynamic_analysis.get("backends"):
                lines.append(f"- **Backends:** {', '.join(str(item) for item in dynamic_analysis['backends'])}")
            if dynamic_analysis.get("setup_hint"):
                lines.append(f"- **Setup Hint:** {dynamic_analysis['setup_hint']}")
            if dynamic_analysis.get("output_dir"):
                lines.append(f"- **Output:** {dynamic_analysis['output_dir']}")
            if dynamic_analysis.get("mode"):
                lines.append(f"- **Mode:** {dynamic_analysis['mode']}")
            if dynamic_analysis.get("duration_seconds") is not None:
                lines.append(f"- **Duration (s):** {dynamic_analysis['duration_seconds']}")
            if dynamic_analysis.get("hook_profile"):
                lines.append(f"- **Hook Profile:** {dynamic_analysis['hook_profile']}")
            if dynamic_analysis.get("planned_hook_count") is not None:
                lines.append(f"- **Planned Hooks:** {dynamic_analysis['planned_hook_count']}")
            if dynamic_analysis.get("event_count") is not None:
                lines.append(f"- **Events:** {dynamic_analysis['event_count']}")
            if dynamic_analysis.get("return_event_count") is not None:
                lines.append(f"- **Return Events:** {dynamic_analysis['return_event_count']}")
            if dynamic_analysis.get("installed_hook_count") is not None:
                lines.append(f"- **Installed Hooks:** {dynamic_analysis['installed_hook_count']}")
            if dynamic_analysis.get("missing_hook_count") is not None:
                lines.append(f"- **Missing Hooks:** {dynamic_analysis['missing_hook_count']}")
            process = dynamic_analysis.get("process") or {}
            if isinstance(process, Mapping):
                if process.get("id") or process.get("spawned_pid") or process.get("attached_pid"):
                    lines.append(
                        f"- **Process:** pid={process.get('id') or process.get('spawned_pid') or process.get('attached_pid')} "
                        f"arch={process.get('arch') or 'unknown'}"
                    )
                modules = process.get("modules")
                if isinstance(modules, list):
                    lines.append(f"- **Loaded Modules Snapshot:** {len(modules)} entries captured")
            if dynamic_analysis.get("api_counts"):
                lines.append("- **Top APIs:**")
                for name, count in list((dynamic_analysis.get("api_counts") or {}).items())[:8]:
                    lines.append(f"  - {name}: {count}")
            if dynamic_analysis.get("category_counts"):
                lines.append("- **Categories:**")
                for name, count in list((dynamic_analysis.get("category_counts") or {}).items())[:8]:
                    lines.append(f"  - {name}: {count}")
            if dynamic_analysis.get("operation_counts"):
                lines.append("- **Top OS Operations:**")
                for name, count in list((dynamic_analysis.get("operation_counts") or {}).items())[:8]:
                    lines.append(f"  - {name}: {count}")
            if dynamic_analysis.get("top_paths"):
                lines.append("- **Top Paths:**")
                for item in (dynamic_analysis.get("top_paths") or [])[:5]:
                    if isinstance(item, Mapping):
                        lines.append(f"  - {item.get('path')}: {item.get('count')}")
            if dynamic_analysis.get("sample_events"):
                lines.append("- **Sample Events:**")
                for event in (dynamic_analysis.get("sample_events") or [])[:5]:
                    if not isinstance(event, Mapping):
                        continue
                    params = event.get("params") or {}
                    preview = ", ".join(f"{key}={value}" for key, value in list(params.items())[:3]) if isinstance(params, Mapping) else ""
                    name = event.get("name") or event.get("operation")
                    if not preview and event.get("path"):
                        preview = str(event.get("path"))
                    lines.append(f"  - {name} [{event.get('category')}] {preview}".rstrip())

        behavior_graph = report.get("behavior_graph") or {}
        if isinstance(behavior_graph, Mapping) and behavior_graph:
            graph_nodes = behavior_graph.get("nodes") or []
            graph_edges = behavior_graph.get("edges") or []
            summary = behavior_graph.get("summary") if isinstance(behavior_graph.get("summary"), Mapping) else {}
            lines.extend(["", "## Behavior Evidence Graph", ""])
            lines.append(f"- **Status**: {behavior_graph.get('status') or 'unknown'}")
            lines.append(f"- **Nodes**: {summary.get('node_count', len(graph_nodes))}")
            lines.append(f"- **Edges**: {summary.get('edge_count', len(graph_edges))}")
            if summary.get("linked_handler_count") is not None:
                lines.append(f"- **Linked Handlers:** {summary.get('linked_handler_count')}")
            if summary.get("dynamic_event_count") is not None:
                lines.append(f"- **Dynamic Events:** {summary.get('dynamic_event_count')}")

        semantic_ir = report.get("semantic_ir") or {}
        if isinstance(semantic_ir, Mapping) and semantic_ir:
            summary = semantic_ir.get("summary") if isinstance(semantic_ir.get("summary"), Mapping) else {}
            entities = semantic_ir.get("entities") if isinstance(semantic_ir.get("entities"), list) else []
            relations = semantic_ir.get("relations") if isinstance(semantic_ir.get("relations"), list) else []
            capabilities = semantic_ir.get("capabilities") if isinstance(semantic_ir.get("capabilities"), list) else []
            lines.extend(["", "## Semantic IR", ""])
            lines.append(f"- **Status:** {semantic_ir.get('status') or 'unknown'}")
            lines.append(f"- **Schema Version:** {semantic_ir.get('schema_version') or 'unknown'}")
            lines.append(f"- **Entities:** {summary.get('entity_count', len(entities))}")
            lines.append(f"- **Relations:** {summary.get('relation_count', len(relations))}")
            lines.append(f"- **Capabilities:** {summary.get('capability_count', len(capabilities))}")
            if capabilities:
                lines.append("- **Top Capabilities:**")
                for capability in capabilities[:8]:
                    if not isinstance(capability, Mapping):
                        continue
                    lines.append(
                        f"  - {capability.get('name') or capability.get('category')}: "
                        f"confidence={capability.get('confidence')} evidence={capability.get('evidence_count')}"
                    )

        gui_analysis = report.get("gui_analysis") or {}
        if gui_analysis:
            lines.extend(["", "## GUI Analysis", ""])
            lines.append(f"- **Status:** {gui_analysis.get('status') or 'unknown'}")
            if gui_analysis.get("platform"):
                lines.append(f"- **Platform:** {gui_analysis['platform']}")
            if gui_analysis.get("framework"):
                lines.append(f"- **Framework:** {gui_analysis['framework']}")
            if gui_analysis.get("confidence") is not None:
                lines.append(f"- **Fingerprint Confidence:** {gui_analysis['confidence']}")
            if gui_analysis.get("evidence"):
                lines.append("- **Evidence:**")
                for item in (gui_analysis.get("evidence") or [])[:8]:
                    lines.append(f"  - {item}")
            resources = gui_analysis.get("resources") or {}
            if isinstance(resources, Mapping):
                resource_bits = [
                    f"{key}={resources.get(key, 0)}"
                    for key in ("icons", "images", "dialogs", "menus", "strings", "layouts", "web_assets", "asar")
                    if resources.get(key)
                ]
                if resource_bits:
                    lines.append(f"- **Resources:** {', '.join(resource_bits)}")
            xaml_evidence = gui_analysis.get("xaml_evidence") or {}
            evidence_graph = gui_analysis.get("evidence_graph") or {}
            if isinstance(xaml_evidence, Mapping) or isinstance(evidence_graph, Mapping):
                xaml_nodes = xaml_evidence.get("nodes") or [] if isinstance(xaml_evidence, Mapping) else []
                graph_nodes = evidence_graph.get("nodes") or [] if isinstance(evidence_graph, Mapping) else []
                graph_edges = evidence_graph.get("edges") or [] if isinstance(evidence_graph, Mapping) else []
                handler_links = sum(
                    len(node.get("handler_evidence") or [])
                    for node in graph_nodes
                    if isinstance(node, Mapping)
                )
                xaml_node_count = xaml_evidence.get("node_count") if isinstance(xaml_evidence, Mapping) else None
                lines.append(f"- **XAML Static Nodes:** {_safe_count(xaml_node_count) if xaml_node_count is not None else len(xaml_nodes)}")
                lines.append(f"- **Evidence Graph Nodes:** {len(graph_nodes)}")
                lines.append(f"- **Evidence Graph Edges:** {len(graph_edges)}")
                lines.append(f"- **Event Handler Links:** {handler_links}")
            runtime_tree = gui_analysis.get("runtime_tree") or {}
            if isinstance(runtime_tree, Mapping):
                lines.append(
                    "- **Runtime Tree:** "
                    f"status={runtime_tree.get('status') or 'unknown'} "
                    f"windows={runtime_tree.get('window_count', 0)} controls={runtime_tree.get('control_count', 0)}"
                )
            visual = gui_analysis.get("visual") or {}
            if isinstance(visual, Mapping):
                lines.append(
                    "- **Visual Evidence:** "
                    f"status={visual.get('status') or 'unknown'} "
                    f"screenshots={visual.get('screenshot_count', 0)} "
                    f"text={visual.get('ocr_text_count', 0)} widgets={visual.get('detected_widget_count', 0)}"
                )

            state_machine = gui_analysis.get("state_machine") or {}
            if isinstance(state_machine, Mapping) and state_machine:
                states = state_machine.get("states") or []
                transitions = state_machine.get("transitions") or []
                actions = state_machine.get("actions") or []
                summary = state_machine.get("summary") if isinstance(state_machine.get("summary"), Mapping) else {}
                lines.extend(["", "## GUI State Machine", ""])
                lines.append(f"- **Status**: {state_machine.get('status') or 'unknown'}")
                lines.append(f"- **States**: {summary.get('state_count', len(states))}")
                lines.append(f"- **Transitions**: {summary.get('transition_count', len(transitions))}")
                lines.append(f"- **Actions**: {summary.get('action_count', len(actions))}")
                if state_machine.get("initial_state"):
                    lines.append(f"- **Initial State:** {state_machine.get('initial_state')}")

            strategy = gui_analysis.get("strategy") or {}
            if isinstance(strategy, Mapping):
                lines.extend(["", "## GUI Reconstruction Strategy", ""])
                lines.append(f"- **Name:** {strategy.get('name') or strategy.get('strategy') or 'unknown'}")
                if strategy.get("output_stack"):
                    lines.append(f"- **Output Stack:** {strategy['output_stack']}")
                if strategy.get("confidence") is not None:
                    lines.append(f"- **Strategy Confidence:** {strategy['confidence']}")
                if strategy.get("reason"):
                    lines.append(f"- **Reason:** {strategy['reason']}")
                if strategy.get("steps"):
                    lines.append(f"- **Steps:** {', '.join(str(item) for item in strategy['steps'])}")
            gui_reconstruction = gui_analysis.get("reconstruction") or {}
            if isinstance(gui_reconstruction, Mapping) and gui_reconstruction:
                lines.append(f"- **GUI Reconstruction:** {gui_reconstruction.get('status') or 'unknown'}")
                if gui_reconstruction.get("project_dir"):
                    lines.append(f"  - Project Dir: {gui_reconstruction['project_dir']}")
            gui_verification = gui_analysis.get("reconstruction_verification") or {}
            if isinstance(gui_verification, Mapping) and gui_verification:
                lines.append(
                    "  - Static Verification: "
                    f"{gui_verification.get('status') or 'unknown'}"
                    + (f" (score={gui_verification['score']})" if gui_verification.get("score") is not None else "")
                )

            regression = gui_analysis.get("regression") or {}
            if isinstance(regression, Mapping):
                lines.extend(["", "## GUI Visual Regression", ""])
                lines.append(f"- **Status:** {regression.get('status') or 'unknown'}")
                if regression.get("pair_count") is not None:
                    lines.append(f"- **Screenshot Pairs:** {regression.get('pair_count')}")
                if regression.get("visual_similarity") is not None:
                    lines.append(f"- **Visual Similarity:** {regression.get('visual_similarity')}")
                if regression.get("text_match_rate") is not None:
                    lines.append(f"- **Text Match Rate:** {regression.get('text_match_rate')}")
                if regression.get("control_match_rate") is not None:
                    lines.append(f"- **Control Match Rate:** {regression.get('control_match_rate')}")

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
            if decompiler.get("call_graph_edge_count") is not None:
                lines.append(f"- **Call Graph Edges:** {decompiler['call_graph_edge_count']}")
            if decompiler.get("string_count") is not None:
                lines.append(f"- **Strings:** {decompiler['string_count']}")
            if decompiler.get("import_count") is not None:
                lines.append(f"- **Import References:** {decompiler['import_count']}")
            if decompiler.get("language"):
                lines.append(f"- **Language:** {decompiler['language']}")
            if decompiler.get("compiler"):
                lines.append(f"- **Compiler:** {decompiler['compiler']}")
            if decompiler.get("image_base"):
                lines.append(f"- **Image Base:** {decompiler['image_base']}")

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
            if reconstruction.get("module_count") is not None:
                lines.append(f"- **Capability Modules:** {reconstruction['module_count']}")
            if reconstruction.get("stub_only") is not None:
                lines.append(f"- **Stub Only:** {_bool_word(reconstruction['stub_only'])}")
            if reconstruction.get("module_files"):
                lines.append(f"- **Module Files:** {', '.join(reconstruction['module_files'])}")
            if reconstruction.get("task_count") is not None:
                lines.append(f"- **Plan Tasks:** {reconstruction['task_count']}")
            if reconstruction.get("next_task"):
                lines.append(f"- **Next Task:** {reconstruction['next_task']}")
            if reconstruction.get("flow_status"):
                lines.append(f"- **Flow Status:** {reconstruction['flow_status']}")
            if reconstruction.get("completed_task_count") is not None:
                lines.append(
                    f"- **Task Progress:** {reconstruction.get('completed_task_count', 0)}/{reconstruction.get('task_count', 0)}"
                )
            if reconstruction.get("completed_subtask_count") is not None:
                lines.append(
                    f"- **Subtask Progress:** {reconstruction.get('completed_subtask_count', 0)}/{reconstruction.get('subtask_count', 0)}"
                )
            if reconstruction.get("next_subtask"):
                lines.append(f"- **Next Subtask:** {reconstruction['next_subtask']}")
            if reconstruction.get("prioritized_modules"):
                lines.append("- **Module Priority:**")
                for item in reconstruction.get("prioritized_modules") or []:
                    if not isinstance(item, Mapping):
                        continue
                    lines.append(
                        f"  - {item.get('module')}: score={item.get('priority_score')} functions={item.get('function_count')} top={', '.join(item.get('top_functions') or []) or 'n/a'}"
                    )
            if reconstruction.get("high_value_functions"):
                lines.append("- **High-Value Functions:**")
                for item in (reconstruction.get("high_value_functions") or [])[:5]:
                    if not isinstance(item, Mapping):
                        continue
                    lines.append(
                        f"  - {item.get('name')} [{item.get('module')}] score={item.get('priority_score')}"
                    )
            if reconstruction.get("reconstruction_plan"):
                lines.append("- **Reconstruction Plan:**")
                for task in (reconstruction.get("reconstruction_plan") or {}).get("tasks", [])[:4]:
                    if not isinstance(task, Mapping):
                        continue
                    lines.append(
                        f"  - {task.get('name')}: {len(task.get('subtasks') or [])} subtasks"
                    )

        reconstruction_verification = report.get("reconstruction_verification") or {}
        if isinstance(reconstruction_verification, Mapping) and reconstruction_verification:
            coverage = (
                reconstruction_verification.get("coverage")
                if isinstance(reconstruction_verification.get("coverage"), Mapping)
                else {}
            )
            lines.extend(["", "## Reconstruction Verification", ""])
            lines.append(f"- **Status:** {reconstruction_verification.get('status') or 'unknown'}")
            if reconstruction_verification.get("score") is not None:
                lines.append(f"- **Score:** {reconstruction_verification.get('score')}")
            if coverage:
                lines.append(
                    "- **Coverage:** "
                    f"semantic={coverage.get('semantic_coverage', 0)} "
                    f"modules={coverage.get('module_coverage', 0)} "
                    f"source_files={coverage.get('source_file_count', 0)}"
                )
            recommendations = reconstruction_verification.get("recommendations") or []
            if recommendations:
                lines.append("- **Verification Recommendations:**")
                for item in recommendations[:6]:
                    lines.append(f"  - {item}")

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
    dynamic_analysis: Mapping[str, Any],
    gui_analysis: Mapping[str, Any],
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
    if dynamic_analysis.get("status") == "unavailable":
        recommendations.append("Configure Frida with `python -m reverse_analyzer --install-guide frida` to add dynamic API tracing coverage.")
    elif dynamic_analysis.get("event_count", 0):
        recommendations.append("Correlate dynamic API traces with static imports and decompiler output to validate which capabilities execute at runtime.")
    if int(dynamic_analysis.get("missing_hook_count") or 0) > 0:
        recommendations.append("Review missing Frida hooks and extend the dynamic hook set for target-specific DLLs or custom exports.")
    if gui_analysis:
        framework = gui_analysis.get("framework") or "unknown"
        strategy = gui_analysis.get("strategy") or {}
        strategy_name = strategy.get("name") if isinstance(strategy, Mapping) else None
        recommendations.append(
            f"Use GUI strategy `{strategy_name or 'manual_assisted_visual_reconstruction'}` for `{framework}` and validate fidelity with screenshots."
        )
    if decompiler.get("status") == "unavailable":
        recommendations.append("Configure Ghidra Headless with `python -m reverse_analyzer --install-guide ghidra` for deeper pseudocode output.")
    if reconstruction.get("status") == "ok":
        recommendations.append("Review the generated reconstruction scaffold and replace placeholder stubs with validated manual analysis.")
    prioritized_modules = reconstruction.get("prioritized_modules") or []
    if prioritized_modules and isinstance(prioritized_modules[0], Mapping):
        top_module = prioritized_modules[0]
        recommendations.append(
            f"Start manual reconstruction with the `{top_module.get('module')}` module; it currently has the highest inferred priority score."
        )
    if reconstruction.get("next_task"):
        recommendations.append(
            f"Resume the reconstruction plan at task `{reconstruction.get('next_task')}` to keep progress resumable."
        )
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


def _dynamic_analysis(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    dynamic_items: list[Dict[str, Any]] = []
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name not in {"frida_trace", "procmon_trace"}:
            continue
        payload = _tool_payload(trace)
        raw = _raw_result(trace)
        if not isinstance(payload, Mapping):
            dynamic_items.append({"status": _tool_status(trace), "backend": tool_name.replace("_trace", "")})
            continue
        backend = payload.get("backend") or tool_name.replace("_trace", "")
        item = {
            "status": payload.get("status") or _tool_status(trace),
            "backend": backend,
            "setup_hint": payload.get("setup_hint"),
            "install_guide": payload.get("install_guide"),
            "docs_url": payload.get("docs_url"),
            "output_dir": payload.get("output_dir"),
            "mode": payload.get("mode"),
            "duration_seconds": payload.get("duration_seconds"),
            "hook_profile": payload.get("hook_profile"),
            "planned_hook_count": payload.get("planned_hook_count"),
            "event_count": payload.get("event_count", len(payload.get("events") or [])),
            "return_event_count": payload.get("return_event_count", len(payload.get("return_events") or [])),
            "installed_hook_count": payload.get("installed_hook_count", len(payload.get("installed_hooks") or [])),
            "missing_hook_count": payload.get("missing_hook_count", len(payload.get("missing_hooks") or [])),
            "api_counts": payload.get("api_counts") or {},
            "operation_counts": payload.get("operation_counts") or {},
            "category_counts": payload.get("category_counts") or {},
            "sample_events": list(payload.get("events") or payload.get("sample_events") or [])[:10],
            "sample_return_events": list(payload.get("return_events") or [])[:10],
            "top_paths": list(payload.get("top_paths") or [])[:10],
            "process": payload.get("process") or {},
            "artifacts": payload.get("artifacts") or [],
            "error": raw.get("error") if isinstance(raw, Mapping) else trace.get("error"),
        }
        dynamic_items.append(item)

    if not dynamic_items:
        return {}
    if len(dynamic_items) == 1:
        return dynamic_items[0]

    status_values = {str(item.get("status") or "") for item in dynamic_items}
    combined = {
        "status": "failed" if "failed" in status_values else ("unavailable" if status_values == {"unavailable"} else "ok"),
        "backend": "all",
        "backends": [item.get("backend") for item in dynamic_items],
        "event_count": sum(int(item.get("event_count") or 0) for item in dynamic_items),
        "return_event_count": sum(int(item.get("return_event_count") or 0) for item in dynamic_items),
        "hook_profile": ",".join(str(item.get("hook_profile")) for item in dynamic_items if item.get("hook_profile")) or None,
        "planned_hook_count": sum(int(item.get("planned_hook_count") or 0) for item in dynamic_items),
        "installed_hook_count": sum(int(item.get("installed_hook_count") or 0) for item in dynamic_items),
        "missing_hook_count": sum(int(item.get("missing_hook_count") or 0) for item in dynamic_items),
        "api_counts": _sum_count_maps(item.get("api_counts") for item in dynamic_items),
        "operation_counts": _sum_count_maps(item.get("operation_counts") for item in dynamic_items),
        "category_counts": _sum_count_maps(item.get("category_counts") for item in dynamic_items),
        "sample_events": [event for item in dynamic_items for event in (item.get("sample_events") or [])][:10],
        "sample_return_events": [event for item in dynamic_items for event in (item.get("sample_return_events") or [])][:10],
        "top_paths": [path for item in dynamic_items for path in (item.get("top_paths") or [])][:10],
        "artifacts": [artifact for item in dynamic_items for artifact in (item.get("artifacts") or [])],
        "children": dynamic_items,
    }
    return combined


def _gui_analysis(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Merge GUI pipeline observations into the stable report schema.

    GUI tools deliberately run independently so that unavailable runtime, OCR,
    or regression dependencies do not discard static fingerprint evidence.
    This normalizer keeps those stage statuses while exposing a compact schema
    that the knowledge base and reconstruction generators can consume.
    """

    stage_names = {
        "gui_fingerprint",
        "gui_resource_extract",
        "gui_xaml_extract",
        "gui_runtime_probe",
        "gui_visual_parse",
        "gui_evidence_graph",
        "gui_interaction_trace",
        "gui_state_machine",
        "gui_strategy_select",
        "reconstruct_gui_project",
        "gui_visual_regression",
    }
    stages: Dict[str, tuple[Dict[str, Any], str]] = {}
    artifacts: list[Dict[str, Any]] = []
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name not in stage_names:
            continue
        payload = _tool_payload(trace)
        normalized = dict(payload) if isinstance(payload, Mapping) else {}
        status = str(normalized.get("status") or _tool_status(trace) or "unknown").lower()
        normalized.setdefault("status", status)
        stages[tool_name] = (normalized, status)
        for artifact in normalized.get("artifacts") or []:
            if isinstance(artifact, Mapping):
                artifacts.append(dict(artifact))

    if not stages:
        return {}

    def stage(name: str) -> tuple[Dict[str, Any], str]:
        # Runtime probing is optional. If it was not requested, represent that
        # explicitly as unavailable rather than conflating it with an unknown
        # result from an executed probe.
        default_status = "unavailable" if name == "gui_runtime_probe" else "unknown"
        return stages.get(name, ({}, default_status))

    fingerprint, fingerprint_status = stage("gui_fingerprint")
    resources_payload, resource_status = stage("gui_resource_extract")
    xaml_payload, xaml_status = stage("gui_xaml_extract")
    runtime_payload, runtime_status = stage("gui_runtime_probe")
    visual_payload, visual_status = stage("gui_visual_parse")
    evidence_graph, evidence_graph_status = stage("gui_evidence_graph")
    interaction_trace, interaction_trace_status = stage("gui_interaction_trace")
    state_machine, state_machine_status = stage("gui_state_machine")
    strategy, strategy_status = stage("gui_strategy_select")
    reconstruction, reconstruction_status = stage("reconstruct_gui_project")
    regression, regression_status = stage("gui_visual_regression")
    gui_verification: Dict[str, Any] = {}
    gui_project_dir = reconstruction.get("project_dir") if isinstance(reconstruction, Mapping) else None
    if gui_project_dir:
        expected_project = str(gui_project_dir).replace("\\", "/").rstrip("/").casefold()
        for trace in reversed(tool_trace):
            tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
            if tool_name != "reconstruction_verify":
                continue
            tool_args = trace.get("tool_args") if isinstance(trace.get("tool_args"), Mapping) else {}
            candidate_project = tool_args.get("project_dir") if isinstance(tool_args, Mapping) else None
            candidate = str(candidate_project).replace("\\", "/").rstrip("/").casefold() if candidate_project else ""
            if candidate != expected_project:
                continue
            payload = _tool_payload(trace)
            if isinstance(payload, Mapping):
                gui_verification = dict(payload)
                gui_verification.setdefault("status", _tool_status(trace))
            break

    core_statuses = [status for status in (fingerprint_status, strategy_status) if status != "unknown"]
    if "failed" in core_statuses:
        status = "failed"
    elif "ok" in core_statuses:
        status = "ok"
    elif core_statuses and all(item == "unavailable" for item in core_statuses):
        status = "unavailable"
    else:
        status = next((item for item in core_statuses if item), "unknown")

    counts = resources_payload.get("counts") if isinstance(resources_payload.get("counts"), Mapping) else {}
    resources = {
        key: _safe_count(counts.get(key))
        for key in ("icons", "images", "dialogs", "menus", "strings", "layouts", "web_assets", "asar", "other")
    }
    runtime_tree = {
        "status": runtime_status,
        "window_count": _safe_count(runtime_payload.get("window_count")),
        "control_count": _safe_count(runtime_payload.get("control_count")),
        "windows": runtime_payload.get("windows") or [],
        "setup_hint": runtime_payload.get("setup_hint"),
    }
    visual = {
        "status": visual_status,
        "screenshot_count": _safe_count(visual_payload.get("screenshot_count")),
        "ocr_text_count": _safe_count(visual_payload.get("ocr_text_count")),
        "detected_widget_count": _safe_count(visual_payload.get("detected_widget_count")),
        "text_regions": visual_payload.get("text_regions") or [],
        "widgets": visual_payload.get("widgets") or [],
        "vlm_provider": visual_payload.get("vlm_provider"),
    }
    regression_data = dict(regression)
    regression_data["status"] = regression_status
    reconstruction_data = dict(reconstruction)
    if reconstruction_data:
        reconstruction_data["status"] = reconstruction_status
    evidence_graph_data = dict(evidence_graph)
    evidence_graph_data["status"] = evidence_graph_status
    xaml_data = dict(xaml_payload)
    xaml_data["status"] = xaml_status
    interaction_trace_data = dict(interaction_trace)
    interaction_trace_data["status"] = interaction_trace_status
    state_machine_data = dict(state_machine)
    state_machine_data["status"] = state_machine_status

    return {
        "status": status,
        "platform": fingerprint.get("platform") or strategy.get("platform"),
        "framework": fingerprint.get("framework") or strategy.get("framework"),
        "confidence": fingerprint.get("confidence") if fingerprint.get("confidence") is not None else strategy.get("confidence"),
        "evidence": fingerprint.get("evidence") or [],
        "candidates": fingerprint.get("candidates") or [],
        "strategy": strategy,
        "resources": resources,
        "resource_manifest": {
            "status": resource_status,
            "resource_dir": resources_payload.get("resource_dir"),
            "extracted_dir": resources_payload.get("extracted_dir"),
            "extracted_count": _safe_count(resources_payload.get("extracted_count")),
            "extracted_files": resources_payload.get("extracted_files") or [],
            "entries": resources_payload.get("entries") or [],
            "pe_resources": resources_payload.get("pe_resources") or {},
        },
        "xaml_evidence": xaml_data,
        "evidence_graph": evidence_graph_data,
        "interaction_trace": interaction_trace_data,
        "state_machine": state_machine_data,
        "runtime_tree": runtime_tree,
        "visual": visual,
        "reconstruction": reconstruction_data,
        "reconstruction_verification": gui_verification,
        "regression": regression_data,
        "artifacts": _dedupe_artifacts(artifacts),
    }


def _behavior_graph(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Expose the normalized cross-domain evidence graph when its stage ran."""

    for trace in reversed(tool_trace):
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "gui_behavior_graph":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            return {}
        result = dict(payload)
        result.setdefault("status", _tool_status(trace))
        return result
    return {}


def _semantic_ir(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Expose the deterministic semantic intermediate representation stage."""

    for trace in reversed(tool_trace):
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "semantic_ir_build":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            return {"status": _tool_status(trace)}
        result = dict(payload)
        for field in ("entities", "relations", "capabilities"):
            if field in result and not isinstance(result[field], list):
                result[field] = []
        result.setdefault("status", _tool_status(trace))
        return result
    return {}


def _reconstruction_verification(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Expose static reconstruction verification without re-running a project."""

    for trace in reversed(tool_trace):
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "reconstruction_verify":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            return {"status": _tool_status(trace)}
        result = dict(payload)
        result.setdefault("status", _tool_status(trace))
        return result
    return {}


def _safe_count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _decompiler(tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "ghidra_decompile":
            continue
        payload = _tool_payload(trace)
        if isinstance(payload, Mapping):
            summary = payload.get("summary") or {}
            call_graph = payload.get("call_graph") or {}
            strings_xrefs = payload.get("strings_xrefs") or []
            imports_xrefs = payload.get("imports_xrefs") or []
            return {
                "status": payload.get("status") or _tool_status(trace),
                "setup_hint": payload.get("setup_hint"),
                "install_guide": payload.get("install_guide"),
                "output_dir": payload.get("output_dir"),
                "project_dir": payload.get("project_dir"),
                "function_count": payload.get("function_count") or (summary.get("function_count") if isinstance(summary, Mapping) else None),
                "call_graph_edge_count": len((call_graph.get("edges") or [])) if isinstance(call_graph, Mapping) else 0,
                "string_count": summary.get("string_count") if isinstance(summary, Mapping) and summary.get("string_count") is not None else len(strings_xrefs),
                "import_count": summary.get("import_count") if isinstance(summary, Mapping) and summary.get("import_count") is not None else len(imports_xrefs),
                "language": summary.get("language") if isinstance(summary, Mapping) else None,
                "compiler": summary.get("compiler") if isinstance(summary, Mapping) else None,
                "image_base": summary.get("image_base") if isinstance(summary, Mapping) else None,
                "artifacts": payload.get("artifacts") or [],
            }
        return {"status": _tool_status(trace)}
    return {}


def _sum_count_maps(values: Sequence[Any]) -> Dict[str, int]:
    merged: Dict[str, int] = {}
    for value in values:
        if not isinstance(value, Mapping):
            continue
        for key, count in value.items():
            try:
                numeric = int(count)
            except (TypeError, ValueError):
                continue
            merged[str(key)] = merged.get(str(key), 0) + numeric
    return dict(sorted(merged.items(), key=lambda item: item[1], reverse=True))


def _reconstruction(session: Any, tool_trace: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    session_progress = _reconstruction_session_progress(session)
    for trace in tool_trace:
        tool_name = str(trace.get("tool_name") or trace.get("tool") or "")
        if tool_name != "reconstruct_project":
            continue
        payload = _tool_payload(trace)
        if not isinstance(payload, Mapping):
            result = {"status": _tool_status(trace)}
            result.update(session_progress)
            return result
        result = {
            "status": payload.get("status") or _tool_status(trace),
            "project_dir": payload.get("project_dir"),
            "generated_files": payload.get("generated_files") or [],
            "function_count": payload.get("function_count"),
            "import_count": payload.get("import_count"),
            "module_count": payload.get("module_count"),
            "module_files": payload.get("module_files") or [],
            "prioritized_modules": payload.get("prioritized_modules") or [],
            "high_value_functions": payload.get("high_value_functions") or [],
            "dynamic_evidence_count": payload.get("dynamic_evidence_count"),
            "reconstruction_plan": payload.get("reconstruction_plan") or {},
            "task_count": payload.get("task_count"),
            "next_task": payload.get("next_task"),
            "stub_only": payload.get("stub_only"),
            "artifacts": payload.get("artifacts") or [],
        }
        for key in ("flow_name", "flow_status", "completed_task_count", "pending_task_count", "subtask_count", "completed_subtask_count", "next_subtask", "session_tasks"):
            if session_progress.get(key) is not None:
                result[key] = session_progress.get(key)
        if result.get("next_task") is None and session_progress.get("next_task") is not None:
            result["next_task"] = session_progress.get("next_task")
        return result
    return session_progress


def _reconstruction_session_progress(session: Any) -> Dict[str, Any]:
    flow = _session_reconstruction_flow(session)
    if flow is None:
        return {}
    tasks = _flow_list(flow, "tasks")
    task_count = len(tasks)
    completed_task_count = sum(1 for task in tasks if _status_value(_get(task, "status")) == "succeeded")
    subtask_count = sum(len(_task_subtasks(task)) for task in tasks)
    completed_subtask_count = sum(
        1 for task in tasks for subtask in _task_subtasks(task) if _status_value(_get(subtask, "status")) == "succeeded"
    )
    next_task = None
    next_subtask = None
    for task in tasks:
        task_status = _status_value(_get(task, "status"))
        if task_status in {"pending", "running"}:
            next_task = _get(task, "name")
            for subtask in _task_subtasks(task):
                subtask_status = _status_value(_get(subtask, "status"))
                if subtask_status in {"pending", "running"}:
                    next_subtask = _get(subtask, "name")
                    break
            break
    return {
        "flow_name": _get(flow, "name"),
        "flow_status": _status_value(_get(flow, "status")),
        "task_count": task_count,
        "completed_task_count": completed_task_count,
        "pending_task_count": max(0, task_count - completed_task_count),
        "subtask_count": subtask_count,
        "completed_subtask_count": completed_subtask_count,
        "next_task": next_task,
        "next_subtask": next_subtask,
        "session_tasks": [
            {
                "name": _get(task, "name"),
                "status": _status_value(_get(task, "status")),
                "subtasks": [
                    {"name": _get(subtask, "name"), "status": _status_value(_get(subtask, "status"))}
                    for subtask in _task_subtasks(task)
                ],
            }
            for task in tasks
        ],
    }


def _session_reconstruction_flow(session: Any) -> Any:
    for flow in _session_list(session, "flows"):
        if _get(flow, "name") == "source-reconstruction":
            return flow
    return None


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

    if tool_name in {"frida_trace", "procmon_trace"}:
        findings.extend(_dynamic_trace_findings(payload, status=status, source=tool_name))

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
            findings.extend(_ghidra_content_findings(payload, source=tool_name))

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


def _dynamic_trace_findings(payload: Mapping[str, Any], *, status: str, source: str) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    status_value = str(payload.get("status") or status).lower()
    backend_label = str(payload.get("backend") or source.replace("_trace", "")).capitalize()
    if status_value == "unavailable":
        findings.append(
            _finding(
                f"{backend_label} dynamic tracing not configured",
                severity="info",
                confidence=0.95,
                source=source,
                detail=payload.get("setup_hint") or f"Install {backend_label} before enabling this dynamic backend.",
                evidence={"docs_url": payload.get("docs_url"), "error": payload.get("error")},
                recommendation=payload.get("setup_hint") or f"Run: python -m reverse_analyzer --install-guide {backend_label.lower()}",
            )
        )
        return findings

    if status_value == "failed":
        findings.append(
            _finding(
                "Frida dynamic tracing failed",
                severity="medium",
                confidence=0.75,
                source=source,
                detail=str(payload.get("error") or "Dynamic trace could not complete."),
                evidence={"artifacts": payload.get("artifacts") or [], "output_dir": payload.get("output_dir")},
                recommendation="Verify the sample can be spawned or attached locally, then rerun dynamic tracing with a longer duration if needed.",
            )
        )
        return findings

    event_count = int(payload.get("event_count") or len(payload.get("events") or []))
    if event_count:
        findings.append(
            _finding(
                "Dynamic API trace collected",
                severity="info",
                confidence=0.9,
                source=source,
                detail=f"events={event_count} mode={payload.get('mode')}",
                evidence={"api_counts": payload.get("api_counts") or {}, "category_counts": payload.get("category_counts") or {}},
                recommendation="Pivot from the highest-frequency dynamic APIs into the corresponding static imports, decompiler output, and reconstruction tasks.",
            )
        )

    api_counts = payload.get("api_counts") if isinstance(payload.get("api_counts"), Mapping) else {}
    categories = payload.get("category_counts") if isinstance(payload.get("category_counts"), Mapping) else {}
    events = payload.get("events") if isinstance(payload.get("events"), list) else []

    injection_names = {
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
    }
    injection_hits = [name for name in api_counts if name in injection_names]
    if injection_hits:
        findings.append(
            _finding(
                "Dynamic process injection or memory manipulation observed",
                severity="high" if any(name in api_counts for name in ("WriteProcessMemory", "CreateRemoteThread")) else "medium",
                confidence=0.88,
                source=source,
                detail=", ".join(injection_hits),
                evidence={"api_counts": {name: api_counts.get(name) for name in injection_hits}, "sample_events": _filter_events(events, injection_hits)},
                recommendation="Inspect the traced allocation, protection, and remote-thread APIs to confirm whether the sample stages code in memory or injects into another process.",
            )
        )

    anti_debug_hits = [name for name in api_counts if name in {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"}]
    if anti_debug_hits or int(categories.get("anti_debug") or 0) > 0:
        findings.append(
            _finding(
                "Dynamic anti-debugging checks observed",
                severity="medium",
                confidence=0.82,
                source=source,
                detail=", ".join(anti_debug_hits) if anti_debug_hits else "anti_debug category activity",
                evidence={"api_counts": {name: api_counts.get(name) for name in anti_debug_hits}, "sample_events": _filter_events(events, anti_debug_hits)},
                recommendation="Correlate anti-debug checks with branch decisions in decompiler output and rerun dynamic analysis with debugger-neutral instrumentation if behavior diverges.",
            )
        )

    network_hits = [
        name
        for name in api_counts
        if name
        in {
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "InternetConnectA",
            "InternetConnectW",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "connect",
            "WSAConnect",
            "send",
            "recv",
            "getaddrinfo",
        }
    ]
    if network_hits or int(categories.get("network") or 0) > 0:
        findings.append(
            _finding(
                "Dynamic network activity observed",
                severity="medium",
                confidence=0.82,
                source=source,
                detail=", ".join(network_hits) if network_hits else "network category activity",
                evidence={"api_counts": {name: api_counts.get(name) for name in network_hits}, "sample_events": _filter_events(events, network_hits[:3] or ["WinHttpSendRequest", "URLDownloadToFileA", "URLDownloadToFileW"])},
                recommendation="Review traced URL, host, and request-path parameters to determine whether the sample beacons, stages a payload, or exfiltrates data.",
            )
        )

    exec_hits = [name for name in api_counts if name in {"CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec"}]
    if exec_hits or int(categories.get("exec") or 0) > 0 or int(categories.get("process") or 0) > 0:
        findings.append(
            _finding(
                "Dynamic child-process or command execution observed",
                severity="medium",
                confidence=0.8,
                source=source,
                detail=", ".join(exec_hits) if exec_hits else "process/exec category activity",
                evidence={"api_counts": {name: api_counts.get(name) for name in exec_hits}, "category_counts": {"process": categories.get("process", 0), "exec": categories.get("exec", 0)}, "sample_events": _filter_events(events, exec_hits[:3] or ["Process Create", "Thread Create", "Load Image", "CreateProcessW", "ShellExecuteW", "WinExec"])},
                recommendation="Inspect command-line parameters and follow-on process creation to identify secondary stages or LOLBin usage.",
            )
        )

    file_or_registry = int(categories.get("file") or 0) + int(categories.get("registry") or 0)
    if file_or_registry:
        findings.append(
            _finding(
                "Dynamic file or registry access observed",
                severity="low",
                confidence=0.72,
                source=source,
                detail=f"file={int(categories.get('file') or 0)} registry={int(categories.get('registry') or 0)}",
                evidence={"category_counts": {"file": categories.get("file", 0), "registry": categories.get("registry", 0)}, "sample_events": _filter_events(events, ["CreateFileA", "CreateFileW", "RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW"])},
                recommendation="Correlate touched paths and registry keys with persistence, staging, or configuration behavior.",
            )
        )

    return findings


def _ghidra_content_findings(payload: Mapping[str, Any], *, source: str) -> list[Dict[str, Any]]:
    findings: list[Dict[str, Any]] = []
    import_names = _ghidra_import_names(payload)
    string_values = _ghidra_string_values(payload)
    functions = payload.get("functions") if isinstance(payload.get("functions"), list) else []
    call_graph = payload.get("call_graph") if isinstance(payload.get("call_graph"), Mapping) else {}

    dynamic_apis = _match_symbol_names(
        import_names,
        ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress"),
    )
    if dynamic_apis:
        findings.append(
            _finding(
                "Dynamic API resolution indicators",
                severity="medium",
                confidence=0.82 if {"LoadLibraryA", "GetProcAddress"} <= set(dynamic_apis) or {"LoadLibraryW", "GetProcAddress"} <= set(dynamic_apis) else 0.74,
                source=source,
                detail=", ".join(dynamic_apis),
                evidence={"apis": dynamic_apis, "functions": _ghidra_import_context(payload, dynamic_apis)},
                recommendation="Trace the recovered pseudocode around LoadLibrary*/GetProcAddress to identify which APIs are resolved at runtime.",
            )
        )

    injection_apis = _match_symbol_names(
        import_names,
        (
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualProtect",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtWriteVirtualMemory",
            "NtCreateThreadEx",
            "QueueUserAPC",
            "SetThreadContext",
            "MapViewOfFile",
            "ResumeThread",
        ),
    )
    if injection_apis:
        severity = "high" if len(injection_apis) >= 3 or any(name in injection_apis for name in ("WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx")) else "medium"
        confidence = 0.88 if severity == "high" else 0.74
        findings.append(
            _finding(
                "Process injection or in-memory execution indicators",
                severity=severity,
                confidence=confidence,
                source=source,
                detail=", ".join(injection_apis),
                evidence={"apis": injection_apis, "functions": _ghidra_import_context(payload, injection_apis)},
                recommendation="Review the involved call sites to confirm whether the sample allocates executable memory or injects into another process.",
            )
        )

    network_apis = _match_symbol_names(
        import_names,
        (
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetConnectW",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "WSAStartup",
            "connect",
            "socket",
            "send",
            "recv",
        ),
    )
    url_hits = _ghidra_url_hits(string_values)
    string_markers = _ghidra_string_hits(string_values, ("User-Agent", ".onion", "/api/", "Cookie:", "Authorization:"))
    if network_apis or url_hits or string_markers:
        severity = "high" if url_hits and any(api in network_apis for api in ("URLDownloadToFileA", "URLDownloadToFileW", "WinHttpSendRequest", "HttpSendRequestA", "HttpSendRequestW")) else "medium"
        findings.append(
            _finding(
                "Network communication indicators",
                severity=severity,
                confidence=0.84 if url_hits else 0.72,
                source=source,
                detail=f"apis={len(network_apis)} urls={len(url_hits)} markers={len(string_markers)}",
                evidence={
                    "apis": network_apis,
                    "urls": url_hits,
                    "markers": string_markers,
                    "functions": _ghidra_import_context(payload, network_apis),
                    "string_locations": _ghidra_string_context(payload, url_hits + string_markers),
                },
                recommendation="Correlate recovered network APIs with URL or header strings to identify possible C2, staging, or beacon traffic.",
            )
        )

    execution_apis = _match_symbol_names(
        import_names,
        (
            "CreateProcessA",
            "CreateProcessW",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "system",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
        ),
    )
    execution_strings = _ghidra_string_hits(string_values, ("cmd.exe", "powershell", "rundll32", "regsvr32", "mshta", "wscript", "cscript"))
    if execution_apis or execution_strings:
        severity = "high" if any(api in execution_apis for api in ("CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW")) and execution_strings else "medium"
        findings.append(
            _finding(
                "Command execution or staging indicators",
                severity=severity,
                confidence=0.86 if severity == "high" else 0.73,
                source=source,
                detail=", ".join((execution_apis + execution_strings)[:8]),
                evidence={
                    "apis": execution_apis,
                    "strings": execution_strings,
                    "functions": _ghidra_import_context(payload, execution_apis),
                    "string_locations": _ghidra_string_context(payload, execution_strings),
                },
                recommendation="Inspect whether the sample launches child processes, shell commands, or follow-on download stages from these code paths.",
            )
        )

    body_sizes = [int(item.get("body_size") or 0) for item in functions if isinstance(item, Mapping)]
    max_body_size = max(body_sizes) if body_sizes else 0
    edge_count = len(call_graph.get("edges") or []) if isinstance(call_graph, Mapping) else 0
    if max_body_size >= 1024 or (functions and edge_count >= max(8, len(functions) * 2)):
        findings.append(
            _finding(
                "Large recovered function or dense call graph",
                severity="info",
                confidence=0.58,
                source=source,
                detail=f"max_body_size={max_body_size} call_graph_edges={edge_count}",
                evidence={
                    "max_body_size": max_body_size,
                    "function_count": len(functions),
                    "call_graph_edges": edge_count,
                },
                recommendation="Prioritize the largest functions and most-connected call graph regions for manual decompilation review.",
            )
        )

    return findings


def _ghidra_import_names(payload: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for item in payload.get("imports_xrefs") or []:
        if isinstance(item, Mapping):
            value = item.get("label") or item.get("name") or item.get("symbol")
            if value is not None:
                names.append(str(value))
    for item in payload.get("functions") or []:
        if not isinstance(item, Mapping):
            continue
        for call in item.get("calls") or []:
            if isinstance(call, Mapping):
                value = call.get("name") or call.get("symbol") or call.get("label")
            else:
                value = call
            if value is not None:
                names.append(str(value))
    return _dedupe_strings(names)


def _filter_events(events: Sequence[Any], names: Sequence[str]) -> list[Dict[str, Any]]:
    wanted = {str(name) for name in names}
    selected: list[Dict[str, Any]] = []
    for event in events:
        if not isinstance(event, Mapping):
            continue
        event_name = str(event.get("name") or event.get("operation") or "")
        if wanted and event_name not in wanted:
            continue
        selected.append(
            {
                "name": event.get("name"),
                "operation": event.get("operation"),
                "category": event.get("category"),
                "params": event.get("params") if isinstance(event.get("params"), Mapping) else {},
                "path": event.get("path"),
                "result": event.get("result"),
            }
        )
        if len(selected) >= 5:
            break
    return selected


def _ghidra_string_values(payload: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    for item in payload.get("strings_xrefs") or []:
        if isinstance(item, Mapping):
            value = item.get("value") or item.get("string")
            if value is not None:
                values.append(str(value))
    return _dedupe_strings(values)


def _ghidra_import_context(payload: Mapping[str, Any], names: Sequence[str]) -> Dict[str, list[str]]:
    wanted = {name.lower() for name in names}
    context: Dict[str, list[str]] = {}
    for item in payload.get("imports_xrefs") or []:
        if not isinstance(item, Mapping):
            continue
        label = _normalize_symbol_name(item.get("label") or item.get("name") or item.get("symbol"))
        if label.lower() not in wanted:
            continue
        functions: list[str] = []
        for function in item.get("functions") or []:
            if not isinstance(function, Mapping):
                continue
            name_value = function.get("name")
            if name_value is not None:
                functions.append(str(name_value))
        if not functions:
            for xref in item.get("xrefs") or []:
                if not isinstance(xref, Mapping):
                    continue
                name_value = xref.get("function_name")
                if name_value is not None:
                    functions.append(str(name_value))
        context[label] = _dedupe_strings(functions)
    return context


def _ghidra_string_context(payload: Mapping[str, Any], needles: Sequence[str]) -> list[Dict[str, Any]]:
    contexts: list[Dict[str, Any]] = []
    seen: set[str] = set()
    lowered = [str(needle).lower() for needle in needles if str(needle).strip()]
    if not lowered:
        return contexts
    for item in payload.get("strings_xrefs") or []:
        if not isinstance(item, Mapping):
            continue
        value = str(item.get("value") or item.get("string") or "")
        lower_value = value.lower()
        if not any(needle in lower_value for needle in lowered):
            continue
        key = str(item.get("address") or value[:64]).lower()
        if key in seen:
            continue
        seen.add(key)
        contexts.append(
            {
                "address": item.get("address"),
                "value": value[:160],
                "functions": [
                    str(function.get("name"))
                    for function in item.get("functions") or []
                    if isinstance(function, Mapping) and function.get("name") is not None
                ],
                "xref_count": item.get("xref_count"),
            }
        )
    return contexts[:5]


def _match_symbol_names(candidates: Sequence[str], targets: Sequence[str]) -> list[str]:
    wanted = {target.lower(): target for target in targets}
    matches: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        normalized = _normalize_symbol_name(candidate)
        key = normalized.lower()
        if key in wanted and wanted[key] not in seen:
            seen.add(wanted[key])
            matches.append(wanted[key])
    return matches


def _normalize_symbol_name(value: Any) -> str:
    text = str(value or "").strip()
    for separator in ("!", "::"):
        if separator in text:
            text = text.split(separator)[-1]
    return text.strip()


def _ghidra_url_hits(values: Sequence[str]) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for value in values:
        for match in re.findall(r"https?://[^\s\"']+", value, flags=re.IGNORECASE):
            if match.lower() in seen:
                continue
            seen.add(match.lower())
            hits.append(match)
    return hits[:5]


def _ghidra_string_hits(values: Sequence[str], needles: Sequence[str]) -> list[str]:
    hits: list[str] = []
    seen: set[str] = set()
    for value in values:
        lower = value.lower()
        for needle in needles:
            key = str(needle).lower()
            if key in lower and key not in seen:
                seen.add(key)
                hits.append(str(needle))
    return hits


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


def _flow_list(flow: Any, name: str) -> list[Any]:
    if flow is None:
        return []
    if isinstance(flow, Mapping):
        value = flow.get(name) or []
    else:
        value = getattr(flow, name, []) or []
    return list(value) if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) else []


def _task_subtasks(task: Any) -> list[Any]:
    return _flow_list(task, "subtasks")


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


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
