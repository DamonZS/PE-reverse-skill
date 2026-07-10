"""Deterministic GUI state-machine construction.

This module turns already-collected GUI observations into a JSON-safe
interaction model.  It uses only the standard library and never launches a
sample or invokes an external tool.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Callable


__all__ = ["build_gui_state_machine"]


_SOURCE_DEFAULT_CONFIDENCE = {
    "runtime_tree": 0.85,
    "visual": 0.65,
    "evidence_graph": 0.9,
    "snapshot": 0.7,
}
_MAX_TRACE_STEPS = 1000


def build_gui_state_machine(
    *,
    runtime_tree: Mapping[str, Any] | None = None,
    visual: Mapping[str, Any] | None = None,
    evidence_graph: Mapping[str, Any] | None = None,
    interaction_trace: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Build a stable GUI state machine without mutating supplied evidence.

    Anonymous snapshot states receive content-derived IDs.  Explicit state
    labels supplied by a trace are preserved as their state IDs, so a trace
    referring to "editing" and "saved" keeps those identifiers in both states
    and transitions.
    """

    runtime = _as_mapping(runtime_tree)
    visual_data = _as_mapping(visual)
    graph = _as_mapping(evidence_graph)
    steps, trace_summary = _trace_steps(interaction_trace)
    input_summary = _input_summary(runtime_tree, visual, evidence_graph, trace_summary)
    trace_initial_label = _trace_initial_label(interaction_trace)

    registry = _StateRegistry()
    aliases: dict[str, str] = {}
    initial_state_id: str | None = None
    has_static_input = any(value is not None for value in (runtime_tree, visual, evidence_graph))

    if has_static_input or trace_initial_label is not None:
        initial_label = trace_initial_label or "initial"
        initial_state_id = registry.add(
            _describe_state(
                runtime_tree=runtime,
                visual=visual_data,
                evidence_graph=graph,
                label=initial_label,
                label_identity=trace_initial_label is not None,
            )
        )
        aliases[initial_label.casefold()] = initial_state_id
        if trace_initial_label is None:
            aliases["start"] = initial_state_id

    actions_by_id: dict[str, dict[str, Any]] = {}
    transitions_by_key: dict[str, dict[str, Any]] = {}
    previous_state_id = initial_state_id

    def ensure_initial() -> str:
        nonlocal initial_state_id
        if initial_state_id is None:
            initial_state_id = registry.add(
                _describe_state(
                    runtime_tree=None,
                    visual=None,
                    evidence_graph=None,
                    label="initial",
                    label_identity=True,
                )
            )
            aliases["initial"] = initial_state_id
            aliases["start"] = initial_state_id
        return initial_state_id

    for step in steps:
        before = _as_mapping(step.get("before"))
        after = _as_mapping(step.get("after"))
        snapshot = _as_mapping(step.get("snapshot"))

        from_state_id = _resolve_state(
            reference=step.get("from_state"),
            snapshot=before,
            registry=registry,
            aliases=aliases,
            default_state_id=previous_state_id,
            ensure_initial=ensure_initial,
        )
        to_state_id = _resolve_state(
            reference=step.get("to_state"),
            snapshot=after if after is not None else snapshot,
            registry=registry,
            aliases=aliases,
            default_state_id=from_state_id,
            ensure_initial=ensure_initial,
        )

        action = _normalize_action(step)
        actions_by_id.setdefault(action["id"], action)
        transition = {
            "from": from_state_id,
            "to": to_state_id,
            "source": from_state_id,
            "target": to_state_id,
            "action": dict(action),
            "action_id": action["id"],
        }
        transitions_by_key.setdefault(_canonical_json(transition), transition)
        previous_state_id = to_state_id

    states = registry.values()
    result: dict[str, Any] = {
        "status": _machine_status(states, runtime, visual_data, graph, steps),
        "version": 1,
        "states": states,
        "transitions": sorted(transitions_by_key.values(), key=_transition_sort_key),
        "actions": sorted(actions_by_id.values(), key=_action_sort_key),
        "summary": {
            "state_count": len(states),
            "transition_count": len(transitions_by_key),
            "action_count": len(actions_by_id),
            "trace_step_count": len(steps),
            "initial_state_id": initial_state_id,
            "input": input_summary,
        },
    }

    if out_dir is not None:
        _write_artifacts(result, Path(out_dir), interaction_trace)
    return result


class _StateRegistry:
    """Own derived state records so caller-owned mappings are never exposed."""

    def __init__(self) -> None:
        self._states: dict[str, dict[str, Any]] = {}

    def add(self, candidate: Mapping[str, Any]) -> str:
        state_id = str(candidate["id"])
        if state_id not in self._states:
            self._states[state_id] = _copy_state(candidate)
        else:
            self.merge(state_id, candidate)
        return state_id

    def merge(self, state_id: str, candidate: Mapping[str, Any]) -> None:
        target = self._states[state_id]
        if target.get("title") is None and candidate.get("title") is not None:
            target["title"] = candidate["title"]
        if target.get("label") is None and candidate.get("label") is not None:
            target["label"] = candidate["label"]
        target["control_count"] = max(_integer(target.get("control_count")), _integer(candidate.get("control_count")))
        target["screenshots"] = sorted(
            {
                *_string_values(target.get("screenshots")),
                *_string_values(candidate.get("screenshots")),
            }
        )
        target["evidence"] = _merge_evidence(target.get("evidence"), candidate.get("evidence"))
        target["confidence"] = round(
            max(_number(target.get("confidence")), _number(candidate.get("confidence"))),
            3,
        )

    def values(self) -> list[dict[str, Any]]:
        return [_copy_state(self._states[state_id]) for state_id in sorted(self._states)]


def _resolve_state(
    *,
    reference: Any,
    snapshot: Mapping[str, Any] | None,
    registry: _StateRegistry,
    aliases: dict[str, str],
    default_state_id: str | None,
    ensure_initial: Callable[[], str],
) -> str:
    label = _state_label(reference)
    state_snapshot = snapshot if snapshot is not None else (_as_mapping(reference) if isinstance(reference, Mapping) else None)

    if label is not None:
        alias_key = label.casefold()
        candidate = _describe_state(
            runtime_tree=None,
            visual=None,
            evidence_graph=None,
            snapshot=state_snapshot,
            label=label,
            label_identity=True,
        )
        existing_id = aliases.get(alias_key)
        if existing_id is not None:
            registry.merge(existing_id, candidate)
            return existing_id
        state_id = registry.add(candidate)
        aliases[alias_key] = state_id
        return state_id

    if state_snapshot is not None:
        return registry.add(
            _describe_state(
                runtime_tree=None,
                visual=None,
                evidence_graph=None,
                snapshot=state_snapshot,
            )
        )
    if default_state_id is not None:
        return default_state_id
    return ensure_initial()


def _describe_state(
    *,
    runtime_tree: Mapping[str, Any] | None,
    visual: Mapping[str, Any] | None,
    evidence_graph: Mapping[str, Any] | None,
    snapshot: Mapping[str, Any] | None = None,
    label: str | None = None,
    label_identity: bool = False,
) -> dict[str, Any]:
    runtime, visual_data, graph = _snapshot_sources(snapshot, runtime_tree, visual, evidence_graph)
    fingerprint_material: dict[str, Any]
    if snapshot is not None:
        fingerprint_material = {"snapshot": snapshot}
    else:
        fingerprint_material = {
            "runtime_tree": runtime,
            "visual": visual_data,
            "evidence_graph": graph,
        }
    fingerprint = _fingerprint(fingerprint_material)
    state_id = label if label_identity and label is not None else f"state_{fingerprint[:16]}"

    title = _first_text(
        snapshot.get("title") if snapshot is not None else None,
        _title_from_runtime(runtime),
        _title_from_mapping(visual_data),
        _title_from_mapping(graph),
    )
    if title is None and label not in (None, "initial"):
        title = label

    explicit_count = _declared_count(snapshot, "control_count") if snapshot is not None else None
    control_count = explicit_count if explicit_count is not None else max(
        _runtime_control_count(runtime),
        _visual_control_count(visual_data),
        _graph_control_count(graph),
    )
    evidence = _state_evidence(runtime, visual_data, graph, snapshot)
    if not evidence and label is not None:
        evidence = [{"source": "trace", "state_id": label, "confidence": 0.5}]
    return {
        "id": state_id,
        "fingerprint": fingerprint,
        "label": label,
        "title": title,
        "control_count": control_count,
        "screenshots": _screenshots(snapshot, visual_data),
        "evidence": evidence,
        "confidence": _state_confidence(evidence),
    }


def _snapshot_sources(
    snapshot: Mapping[str, Any] | None,
    runtime_tree: Mapping[str, Any] | None,
    visual: Mapping[str, Any] | None,
    evidence_graph: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any] | None, Mapping[str, Any] | None, Mapping[str, Any] | None]:
    if snapshot is None:
        return runtime_tree, visual, evidence_graph
    runtime = _as_mapping(snapshot.get("runtime_tree"))
    if runtime is None and ("windows" in snapshot or "controls" in snapshot):
        runtime = snapshot
    return runtime, _as_mapping(snapshot.get("visual")), _as_mapping(snapshot.get("evidence_graph"))


def _state_evidence(
    runtime_tree: Mapping[str, Any] | None,
    visual: Mapping[str, Any] | None,
    evidence_graph: Mapping[str, Any] | None,
    snapshot: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    if runtime_tree is not None:
        evidence.append(
            {
                "source": "runtime_tree",
                "status": _source_status(runtime_tree),
                "window_count": _runtime_window_count(runtime_tree),
                "control_count": _runtime_control_count(runtime_tree),
                "confidence": _source_confidence("runtime_tree", runtime_tree),
            }
        )
    if visual is not None:
        evidence.append(
            {
                "source": "visual",
                "status": _source_status(visual),
                "widget_count": _visual_widget_count(visual),
                "text_region_count": len(_mapping_sequence(visual.get("text_regions"))),
                "confidence": _source_confidence("visual", visual),
            }
        )
    if evidence_graph is not None:
        evidence.append(
            {
                "source": "evidence_graph",
                "status": _source_status(evidence_graph),
                "node_count": _graph_control_count(evidence_graph),
                "confidence": _source_confidence("evidence_graph", evidence_graph),
            }
        )
    if not evidence and snapshot is not None:
        evidence.append(
            {
                "source": "snapshot",
                "field_count": len(snapshot),
                "confidence": _source_confidence("snapshot", snapshot),
            }
        )
    return _merge_evidence([], evidence)


def _normalize_action(step: Mapping[str, Any]) -> dict[str, Any]:
    action_payload = _as_mapping(step.get("action"))
    event_payload = _as_mapping(step.get("event"))
    action_type = _first_value(
        _mapping_value(action_payload, "type", "action", "event", "name"),
        step.get("action") if action_payload is None else None,
        _mapping_value(event_payload, "type", "action", "event", "name"),
        step.get("event") if event_payload is None else None,
        step.get("action_type"),
        step.get("event_type"),
    )
    control = _first_value(
        _mapping_value(action_payload, "control_id", "target_id"),
        _mapping_value(event_payload, "control_id", "target_id"),
        step.get("control_id"),
        _control_identifier(step.get("control")),
        _control_identifier(step.get("target")),
    )
    text = _first_value(
        _mapping_value(action_payload, "text", "label", "title", "content"),
        _mapping_value(event_payload, "text", "label", "title", "content"),
        step.get("text"),
        _control_text(step.get("control")),
        _control_text(step.get("target")),
    )
    normalized = {
        "type": _normalized_action_type(action_type),
        "control_id": _text(control),
        "text": _text(text),
    }
    normalized["id"] = f"action_{_fingerprint(normalized)[:16]}"
    return normalized


def _trace_steps(
    interaction_trace: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None,
) -> tuple[list[Mapping[str, Any]], dict[str, Any]]:
    if interaction_trace is None:
        return [], {
            "provided": False,
            "format": "none",
            "step_key": None,
            "step_count": 0,
            "ignored_step_count": 0,
            "raw_step_count": 0,
            "truncated": False,
        }
    if isinstance(interaction_trace, Mapping):
        if "steps" in interaction_trace:
            raw_steps = interaction_trace.get("steps")
            step_key = "steps"
        else:
            raw_steps = interaction_trace.get("interactions")
            step_key = "interactions" if "interactions" in interaction_trace else None
        trace_format = "object"
    elif isinstance(interaction_trace, Sequence) and not isinstance(interaction_trace, (str, bytes, bytearray)):
        raw_steps = interaction_trace
        trace_format = "sequence"
        step_key = None
    else:
        return [], {
            "provided": True,
            "format": "invalid",
            "step_key": None,
            "step_count": 0,
            "ignored_step_count": 1,
            "raw_step_count": 0,
            "truncated": False,
        }

    if not isinstance(raw_steps, Sequence) or isinstance(raw_steps, (str, bytes, bytearray)):
        return [], {
            "provided": True,
            "format": trace_format,
            "step_key": step_key,
            "step_count": 0,
            "ignored_step_count": 0,
            "raw_step_count": 0,
            "truncated": False,
        }
    raw_step_count = len(raw_steps)
    bounded_step_count = min(raw_step_count, _MAX_TRACE_STEPS)
    steps = [raw_steps[index] for index in range(bounded_step_count) if isinstance(raw_steps[index], Mapping)]
    return steps, {
        "provided": True,
        "format": trace_format,
        "step_key": step_key,
        "step_count": len(steps),
        "ignored_step_count": raw_step_count - len(steps),
        "raw_step_count": raw_step_count,
        "truncated": raw_step_count > _MAX_TRACE_STEPS,
    }


def _trace_initial_label(interaction_trace: Any) -> str | None:
    if not isinstance(interaction_trace, Mapping):
        return None
    return _state_label(interaction_trace.get("initial_state"))


def _input_summary(
    runtime_tree: Any,
    visual: Any,
    evidence_graph: Any,
    trace_summary: Mapping[str, Any],
) -> dict[str, Any]:
    runtime = _as_mapping(runtime_tree)
    visual_data = _as_mapping(visual)
    graph = _as_mapping(evidence_graph)
    return {
        "runtime_tree": {
            "provided": runtime_tree is not None,
            "valid": runtime is not None,
            "status": _source_status(runtime) if runtime is not None else None,
            "window_count": _runtime_window_count(runtime),
            "control_count": _runtime_control_count(runtime),
        },
        "visual": {
            "provided": visual is not None,
            "valid": visual_data is not None,
            "status": _source_status(visual_data) if visual_data is not None else None,
            "screenshot_count": len(_screenshots(None, visual_data)),
            "widget_count": _visual_widget_count(visual_data),
            "text_region_count": len(_mapping_sequence(visual_data.get("text_regions"))) if visual_data is not None else 0,
        },
        "evidence_graph": {
            "provided": evidence_graph is not None,
            "valid": graph is not None,
            "status": _source_status(graph) if graph is not None else None,
            "node_count": _graph_control_count(graph),
            "edge_count": len(_mapping_sequence(graph.get("edges"))) if graph is not None else 0,
        },
        "interaction_trace": dict(trace_summary),
    }


def _machine_status(
    states: Sequence[Mapping[str, Any]],
    runtime_tree: Mapping[str, Any] | None,
    visual: Mapping[str, Any] | None,
    evidence_graph: Mapping[str, Any] | None,
    steps: Sequence[Mapping[str, Any]],
) -> str:
    if not states:
        return "unavailable"
    if steps:
        return "ok"
    statuses = [
        _source_status(source)
        for source in (runtime_tree, visual, evidence_graph)
        if source is not None
    ]
    if statuses and all(status == "failed" for status in statuses):
        return "failed"
    if statuses and all(status == "unavailable" for status in statuses):
        return "unavailable"
    return "ok"


def _write_artifacts(
    result: dict[str, Any],
    out_dir: Path,
    interaction_trace: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None,
) -> None:
    gui_dir = out_dir / "gui"
    gui_dir.mkdir(parents=True, exist_ok=True)
    state_path = gui_dir / "state_machine.json"
    trace_path = gui_dir / "interaction_trace.json"
    result["artifacts"] = [
        {"name": "gui/state_machine.json", "path": str(state_path), "kind": "gui-state-machine"},
        {"name": "gui/interaction_trace.json", "path": str(trace_path), "kind": "gui-interaction-trace"},
    ]
    _write_json(state_path, result)
    _write_json(trace_path, _trace_artifact(interaction_trace, result))


def _trace_artifact(
    interaction_trace: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None,
    result: Mapping[str, Any],
) -> dict[str, Any]:
    steps, trace_summary = _trace_steps(interaction_trace)
    raw = _safe_output(interaction_trace)
    normalized_steps = [_safe_output(dict(step)) for step in steps]
    if isinstance(raw, Mapping):
        payload = dict(raw)
        step_key = trace_summary.get("step_key")
        if isinstance(step_key, str):
            payload[step_key] = normalized_steps
        else:
            payload.setdefault("steps", normalized_steps)
    elif raw is None:
        payload = {"steps": []}
    else:
        payload = {"steps": normalized_steps}
    normalized_key = "normalized" if "normalized" not in payload else "state_machine"
    payload[normalized_key] = {
        "status": result["status"],
        "version": result["version"],
        "actions": result["actions"],
        "transitions": result["transitions"],
        "summary": {
            "trace_step_count": result["summary"]["trace_step_count"],
            "transition_count": result["summary"]["transition_count"],
            "action_count": result["summary"]["action_count"],
            "raw_trace_step_count": trace_summary["raw_step_count"],
            "trace_truncated": trace_summary["truncated"],
        },
    }
    return payload


def _write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _runtime_window_count(runtime_tree: Mapping[str, Any] | None) -> int:
    if runtime_tree is None:
        return 0
    declared = _declared_count(runtime_tree, "window_count")
    return declared if declared is not None else len(_mapping_sequence(runtime_tree.get("windows")))


def _runtime_control_count(runtime_tree: Mapping[str, Any] | None) -> int:
    if runtime_tree is None:
        return 0
    declared = _declared_count(runtime_tree, "control_count")
    if declared is not None:
        return declared
    windows = _mapping_sequence(runtime_tree.get("windows"))
    if windows:
        total = 0
        for window in windows:
            count = _declared_count(window, "control_count")
            total += count if count is not None else len(_mapping_sequence(window.get("controls")))
        return total
    return len(_mapping_sequence(runtime_tree.get("controls")))


def _visual_widget_count(visual: Mapping[str, Any] | None) -> int:
    if visual is None:
        return 0
    declared = _declared_count(visual, "detected_widget_count", "widget_count")
    return max(declared or 0, len(_mapping_sequence(visual.get("widgets"))))


def _visual_control_count(visual: Mapping[str, Any] | None) -> int:
    if visual is None:
        return 0
    return _visual_widget_count(visual) + len(_mapping_sequence(visual.get("text_regions")))


def _graph_control_count(evidence_graph: Mapping[str, Any] | None) -> int:
    if evidence_graph is None:
        return 0
    declared = _declared_count(evidence_graph, "node_count", "control_count")
    return declared if declared is not None else len(_mapping_sequence(evidence_graph.get("nodes")))


def _title_from_runtime(runtime_tree: Mapping[str, Any] | None) -> str | None:
    if runtime_tree is None:
        return None
    title = _first_text(runtime_tree.get("title"), runtime_tree.get("window_title"))
    if title is not None:
        return title
    for window in _mapping_sequence(runtime_tree.get("windows")):
        title = _first_text(window.get("title"), window.get("name"))
        if title is not None:
            return title
    return None


def _title_from_mapping(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    return _first_text(value.get("title"), value.get("window_title"), value.get("name"))


def _screenshots(snapshot: Mapping[str, Any] | None, visual: Mapping[str, Any] | None) -> list[str]:
    values: list[str] = []
    for source in (snapshot, visual):
        if source is None:
            continue
        values.extend(_screenshot_values(source.get("screenshot")))
        values.extend(_screenshot_values(source.get("screenshots")))
    return sorted(set(values))


def _screenshot_values(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, Mapping):
        return _screenshot_values(_first_value(value.get("path"), value.get("file"), value.get("screenshot")))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        values: list[str] = []
        for item in value:
            values.extend(_screenshot_values(item))
        return values
    if isinstance(value, (set, frozenset)):
        values: list[str] = []
        for item in sorted(value, key=_canonical_json):
            values.extend(_screenshot_values(item))
        return values
    if isinstance(value, bytes):
        return [f"sha256:{hashlib.sha256(value).hexdigest()}"]
    return [str(value)]


def _state_label(reference: Any) -> str | None:
    if isinstance(reference, Mapping):
        return _first_text(
            reference.get("state_id"),
            reference.get("id"),
            reference.get("name"),
            reference.get("label"),
            reference.get("state"),
        )
    return _text(reference)


def _control_identifier(value: Any) -> Any:
    if isinstance(value, Mapping):
        return _first_value(value.get("control_id"), value.get("id"), value.get("automation_id"), value.get("name"))
    return value


def _control_text(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return None
    return _first_value(value.get("text"), value.get("label"), value.get("title"), value.get("content"))


def _mapping_value(value: Mapping[str, Any] | None, *keys: str) -> Any:
    if value is None:
        return None
    return _first_value(*(value.get(key) for key in keys))


def _first_value(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def _first_text(*values: Any) -> str | None:
    for value in values:
        text = _text(value)
        if text is not None:
            return text
    return None


def _text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return text or None


def _normalized_action_type(value: Any) -> str:
    text = _text(value)
    if text is None:
        return "unknown"
    normalized = "_".join(text.casefold().replace("-", " ").split())
    return normalized or "unknown"


def _source_status(source: Mapping[str, Any] | None) -> str:
    if source is None:
        return "unavailable"
    status = _text(source.get("status"))
    return status.casefold() if status is not None else "observed"


def _source_confidence(source_name: str, source: Mapping[str, Any]) -> float:
    value = _finite_number(source.get("confidence"))
    if value is not None:
        return round(min(1.0, max(0.0, value)), 3)
    if _source_status(source) in {"unavailable", "failed"}:
        return 0.0
    return _SOURCE_DEFAULT_CONFIDENCE[source_name]


def _state_confidence(evidence: Sequence[Mapping[str, Any]]) -> float:
    values = [_number(item.get("confidence")) for item in evidence]
    return round(sum(values) / len(values), 3) if values else 0.0


def _merge_evidence(left: Any, right: Any) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in (*_mapping_sequence(left), *_mapping_sequence(right)):
        copied = {str(key): _safe_output(value) for key, value in item.items()}
        merged.setdefault(_canonical_json(copied), copied)
    return [merged[key] for key in sorted(merged)]


def _copy_state(state: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(state["id"]),
        "fingerprint": str(state["fingerprint"]),
        "label": _text(state.get("label")),
        "title": _text(state.get("title")),
        "control_count": _integer(state.get("control_count")),
        "screenshots": sorted(set(_string_values(state.get("screenshots")))),
        "evidence": _merge_evidence([], state.get("evidence")),
        "confidence": round(_number(state.get("confidence")), 3),
    }


def _action_sort_key(action: Mapping[str, Any]) -> tuple[str, str]:
    return str(action.get("id") or ""), _canonical_json(action)


def _transition_sort_key(transition: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(transition.get("from") or ""),
        str(transition.get("to") or ""),
        str(transition.get("action_id") or ""),
    )


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _string_values(value: Any) -> list[str]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [str(item) for item in value if item not in (None, "")]


def _declared_count(value: Mapping[str, Any] | None, *keys: str) -> int | None:
    if value is None:
        return None
    for key in keys:
        if key in value:
            number = _finite_number(value.get(key))
            if number is not None:
                return max(0, int(number))
    return None


def _integer(value: Any) -> int:
    number = _finite_number(value)
    return max(0, int(number)) if number is not None else 0


def _number(value: Any) -> float:
    number = _finite_number(value)
    return number if number is not None else 0.0


def _finite_number(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _as_mapping(value: Any) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"__float__": repr(value)}
    if isinstance(value, bytes):
        return {"__bytes_sha256__": hashlib.sha256(value).hexdigest(), "length": len(value)}
    if isinstance(value, Path):
        return {"__path__": str(value)}
    if isinstance(value, Mapping):
        pairs = [[_canonical_value(key), _canonical_value(item)] for key, item in value.items()]
        pairs.sort(key=lambda pair: _canonical_json(pair[0]))
        return {"__mapping__": pairs}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        values = [_canonical_value(item) for item in value]
        values.sort(key=_canonical_json)
        return {"__set__": values}
    return {"__type__": f"{type(value).__module__}.{type(value).__qualname__}"}


def _safe_output(value: Any) -> Any:
    """Return a detached, JSON-safe representation of arbitrary input data."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, bytes):
        return f"sha256:{hashlib.sha256(value).hexdigest()}"
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _safe_output(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_safe_output(item) for item in value]
    return f"<{type(value).__module__}.{type(value).__qualname__}>"
