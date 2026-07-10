"""Build a deterministic, evidence-backed behavior graph.

The builder intentionally consumes already-produced analysis payloads only.  It
does not inspect a sample, start a process, contact a network service, or invoke
an external command.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any


_REQUIRED_NODE_TYPES = (
    "function",
    "api",
    "dynamic_event",
    "ui_control",
    "ui_handler",
    "resource",
    "ui_state",
    "ui_action",
)


def build_behavior_evidence_graph(
    *,
    fingerprint: Mapping[str, Any] | None = None,
    decompiler: Mapping[str, Any] | None = None,
    dynamic_analysis: Mapping[str, Any] | None = None,
    gui_analysis: Mapping[str, Any] | None = None,
    resources: Mapping[str, Any] | None = None,
    state_machine: Mapping[str, Any] | None = None,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Fuse supplied analysis payloads into a stable behavior evidence graph.

    All associations are intentionally conservative: event handlers are linked
    only to decompiler functions with the same name, dynamic events only to APIs
    named by those events, and state-machine edges only to their declared
    source/action/target values.  Input mappings are read-only throughout.
    """

    source_maps = {
        "fingerprint": _as_mapping(fingerprint),
        "decompiler": _as_mapping(decompiler),
        "dynamic_analysis": _as_mapping(dynamic_analysis),
        "gui_analysis": _as_mapping(gui_analysis),
        "resources": _as_mapping(resources),
        "state_machine": _as_mapping(state_machine),
    }
    builder = _GraphBuilder()

    functions_by_name = _add_functions(builder, source_maps["decompiler"])
    _add_dynamic_evidence(builder, source_maps["dynamic_analysis"])
    handler_nodes = _add_gui_evidence(builder, source_maps["gui_analysis"])
    _add_resources(builder, source_maps["resources"])
    transition_count = _add_state_machine(builder, source_maps["state_machine"])

    linked_handler_ids: set[str] = set()
    for handler in sorted(handler_nodes.values(), key=lambda item: item["id"]):
        for function_id in functions_by_name.get(handler["name"], []):
            builder.add_edge(
                relation="ui_handler_to_function",
                source_id=handler["id"],
                target_id=function_id,
                evidence_source="gui_analysis.evidence_graph.nodes.event_handlers",
                detail={
                    "handler": handler["name"],
                    "function": functions_by_name[handler["name"]],
                    "match": "same_name",
                },
                confidence=0.9,
            )
            linked_handler_ids.add(handler["id"])

    nodes = builder.nodes()
    edges = builder.edges()
    type_counts = {node_type: 0 for node_type in _REQUIRED_NODE_TYPES}
    for node in nodes:
        type_counts[node["type"]] = type_counts.get(node["type"], 0) + 1

    summary: dict[str, Any] = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "type_counts": dict(type_counts),
        "node_type_counts": dict(type_counts),
        "counts": dict(type_counts),
        "linked_handler_count": len(linked_handler_ids),
        "dynamic_event_count": type_counts["dynamic_event"],
        "state_count": type_counts["ui_state"],
        "transition_count": transition_count,
    }
    for node_type, count in type_counts.items():
        summary[f"{node_type}_count"] = count

    graph: dict[str, Any] = {
        "status": _graph_status(source_maps.values()),
        "version": 1,
        "nodes": nodes,
        "edges": edges,
        "summary": summary,
    }
    if out_dir is not None:
        target = Path(out_dir) / "analysis_graph.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        graph["artifacts"] = [
            {
                "name": "analysis_graph.json",
                "path": str(target),
                "kind": "behavior-evidence-graph",
            }
        ]
    return graph


class _GraphBuilder:
    """Small deterministic registry for graph nodes, edges, and their evidence."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, dict[str, Any]] = {}

    def add_node(
        self,
        *,
        node_type: str,
        name: str,
        identity: Any,
        source: str,
        detail: Any,
        confidence: float,
        attributes: Any,
    ) -> dict[str, Any]:
        node_id = _node_id(node_type, name, identity)
        evidence = _evidence(source, detail, confidence)
        safe_attributes = _json_safe(attributes)
        node = self._nodes.get(node_id)
        if node is None:
            node = {
                "id": node_id,
                "type": node_type,
                "name": str(name),
                "source": source,
                "evidence": [evidence],
                "confidence": confidence,
                "attributes": safe_attributes,
            }
            self._nodes[node_id] = node
            return node

        _append_evidence(node["evidence"], evidence)
        node["confidence"] = max(float(node["confidence"]), confidence)
        if _canonical_json(safe_attributes) < _canonical_json(node["attributes"]):
            node["attributes"] = safe_attributes
        return node

    def add_edge(
        self,
        *,
        relation: str,
        source_id: str,
        target_id: str,
        evidence_source: str,
        detail: Any,
        confidence: float,
        discriminator: Any = None,
    ) -> dict[str, Any]:
        edge_id = _edge_id(relation, source_id, target_id, discriminator)
        evidence = _evidence(evidence_source, detail, confidence)
        edge = self._edges.get(edge_id)
        if edge is None:
            edge = {
                "id": edge_id,
                "type": relation,
                "source": source_id,
                "target": target_id,
                "evidence": [evidence],
                "confidence": confidence,
            }
            self._edges[edge_id] = edge
            return edge

        _append_evidence(edge["evidence"], evidence)
        edge["confidence"] = max(float(edge["confidence"]), confidence)
        return edge

    def nodes(self) -> list[dict[str, Any]]:
        return [self._nodes[node_id] for node_id in sorted(self._nodes)]

    def edges(self) -> list[dict[str, Any]]:
        return [self._edges[edge_id] for edge_id in sorted(self._edges)]


def _add_functions(builder: _GraphBuilder, source: Mapping[str, Any]) -> dict[str, list[str]]:
    payload = _payload(source, ("functions",))
    by_name: dict[str, set[str]] = {}
    for record in _records(
        payload.get("functions"),
        key_field="name",
        record_markers=("name", "function_name", "symbol", "qualified_name", "address"),
    ):
        raw = _record_mapping(record, "name")
        name = _record_name(raw, ("name", "function_name", "symbol", "qualified_name", "label"), "function")
        confidence = _confidence(raw, 0.8)
        node = builder.add_node(
            node_type="function",
            name=name,
            identity=_identified_object(
                raw,
                name,
                ("id", "address", "rva", "va", "offset", "start", "source_path", "path", "module", "namespace"),
            ),
            source="decompiler.functions",
            detail=raw,
            confidence=confidence,
            attributes=raw,
        )
        by_name.setdefault(name, set()).add(node["id"])
    return {name: sorted(ids) for name, ids in sorted(by_name.items())}


def _add_dynamic_evidence(builder: _GraphBuilder, source: Mapping[str, Any]) -> None:
    payload = _payload(source, ("api_counts", "sample_events", "events", "api_events"))
    api_counts = payload.get("api_counts")
    if isinstance(api_counts, Mapping):
        for api_name, count in sorted(api_counts.items(), key=lambda item: _canonical_json(item[0])):
            name = _text(api_name)
            if not name:
                continue
            raw = _record_mapping(count, "count") if isinstance(count, Mapping) else {"api": name, "count": count}
            if "api" not in raw:
                raw = {"api": name, **raw}
            _add_api_node(
                builder,
                name,
                raw,
                source_name="dynamic_analysis.api_counts",
                confidence=_confidence(raw, 0.75),
            )
    elif isinstance(api_counts, (list, tuple, set, frozenset)):
        for record in _records(
            api_counts,
            key_field="api",
            record_markers=("api", "api_name", "name", "function", "operation"),
        ):
            raw = _record_mapping(record, "api")
            name = _record_name(raw, ("api", "api_name", "function", "function_name", "operation", "name"), "api")
            _add_api_node(
                builder,
                name,
                raw,
                source_name="dynamic_analysis.api_counts",
                confidence=_confidence(raw, 0.75),
            )

    for event_source, record in _dynamic_event_records(payload):
        raw = _record_mapping(record, "api")
        confidence = _confidence(raw, 0.8)
        api_names = _event_api_names(raw)
        event_name = api_names[0] if api_names else _record_name(
            raw,
            ("event", "event_type", "operation", "name", "id"),
            "dynamic-event",
        )
        event_node = builder.add_node(
            node_type="dynamic_event",
            name=event_name,
            identity={"event": _json_safe(raw)},
            source=event_source,
            detail=raw,
            confidence=confidence,
            attributes=raw,
        )
        for api_name in api_names:
            api_node = _add_api_node(
                builder,
                api_name,
                raw,
                source_name=event_source,
                confidence=confidence,
            )
            builder.add_edge(
                relation="dynamic_event_to_api",
                source_id=event_node["id"],
                target_id=api_node["id"],
                evidence_source=event_source,
                detail={"event": raw, "api": api_name},
                confidence=confidence,
            )


def _add_api_node(
    builder: _GraphBuilder,
    name: str,
    raw: Mapping[str, Any],
    *,
    source_name: str,
    confidence: float,
) -> dict[str, Any]:
    scope = {
        key: value
        for key in ("module", "dll", "library", "provider", "namespace")
        if (value := _text(raw.get(key)))
    }
    return builder.add_node(
        node_type="api",
        name=name,
        identity={"api": name, "scope": scope},
        source=source_name,
        detail=raw,
        confidence=confidence,
        attributes={"api": name, **scope},
    )


def _dynamic_event_records(payload: Mapping[str, Any]) -> list[tuple[str, Any]]:
    records: list[tuple[str, Any]] = []
    for key in ("sample_events", "api_events", "events", "trace_events", "samples"):
        value = payload.get(key)
        if isinstance(value, Mapping) and any(nested in value for nested in ("events", "items", "samples")):
            for nested_key in ("events", "items", "samples"):
                for record in _records(
                    value.get(nested_key),
                    key_field="api",
                    record_markers=("api", "api_name", "function", "operation", "name", "event"),
                ):
                    records.append((f"dynamic_analysis.{key}", record))
            continue
        for record in _records(
            value,
            key_field="api",
            record_markers=("api", "api_name", "function", "operation", "name", "event"),
        ):
            records.append((f"dynamic_analysis.{key}", record))
    return sorted(records, key=lambda item: (item[0], _canonical_json(item[1])))


def _event_api_names(raw: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("api", "api_name", "function", "function_name", "operation"):
        names.extend(_reference_values(raw.get(key), ("api", "api_name", "function", "function_name", "operation", "name")))
    for key in ("apis", "api_calls", "functions", "operations"):
        names.extend(_reference_values(raw.get(key), ("api", "api_name", "function", "function_name", "operation", "name")))
    return sorted(set(names))


def _add_gui_evidence(builder: _GraphBuilder, source: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    payload = _payload(source, ("evidence_graph", "nodes"))
    graph = _as_mapping(payload.get("evidence_graph"))
    node_source = graph if graph else payload
    handlers: dict[str, dict[str, Any]] = {}
    for record in _records(
        node_source.get("nodes"),
        key_field="id",
        record_markers=("id", "control_id", "automation_id", "name", "type", "text"),
    ):
        raw = _record_mapping(record, "id")
        name = _record_name(
            raw,
            ("id", "control_id", "automation_id", "name", "text", "title", "label", "type"),
            "ui-control",
        )
        confidence = _confidence(raw, 0.75)
        control = builder.add_node(
            node_type="ui_control",
            name=name,
            identity=_identified_object(
                raw,
                name,
                ("id", "control_id", "automation_id", "source_path", "document", "path", "window", "parent_id"),
            ),
            source="gui_analysis.evidence_graph.nodes",
            detail=raw,
            confidence=confidence,
            attributes=raw,
        )
        for event_name, handler_name, binding in _handler_bindings(raw):
            handler_confidence = _confidence(binding, confidence)
            handler = builder.add_node(
                node_type="ui_handler",
                name=handler_name,
                identity={"control": control["id"], "event": event_name, "handler": handler_name},
                source="gui_analysis.evidence_graph.nodes.event_handlers",
                detail={"control": raw, "event": event_name, "binding": binding},
                confidence=handler_confidence,
                attributes={
                    "control_id": control["id"],
                    "event": event_name,
                    "handler": handler_name,
                },
            )
            handlers[handler["id"]] = handler
            builder.add_edge(
                relation="ui_control_to_handler",
                source_id=control["id"],
                target_id=handler["id"],
                evidence_source="gui_analysis.evidence_graph.nodes.event_handlers",
                detail={"control": raw, "event": event_name, "handler": handler_name},
                confidence=handler_confidence,
                discriminator=event_name,
            )
    return handlers


def _handler_bindings(raw: Mapping[str, Any]) -> list[tuple[str, str, Any]]:
    bindings: list[tuple[str, str, Any]] = []
    for collection_key in ("event_handlers", "handlers", "events"):
        collection = raw.get(collection_key)
        if isinstance(collection, Mapping):
            for event, value in collection.items():
                event_name = _text(event) or collection_key
                for handler_name in _binding_handler_names(value):
                    bindings.append((event_name, handler_name, value))
        elif isinstance(collection, (list, tuple, set, frozenset)):
            for value in collection:
                value_map = _record_mapping(value, "handler")
                event_name = _record_name(value_map, ("event", "event_name", "type"), collection_key)
                for handler_name in _binding_handler_names(value_map):
                    bindings.append((event_name, handler_name, value_map))

    for key in ("handler", "handler_name", "callback", "click_handler"):
        if key not in raw:
            continue
        event_name = _text(raw.get("event")) or key
        for handler_name in _binding_handler_names(raw.get(key)):
            bindings.append((event_name, handler_name, raw.get(key)))

    unique: dict[tuple[str, str, str], tuple[str, str, Any]] = {}
    for event_name, handler_name, detail in bindings:
        if not event_name or not handler_name:
            continue
        key = (event_name, handler_name, _canonical_json(detail))
        unique[key] = (event_name, handler_name, detail)
    return [unique[key] for key in sorted(unique)]


def _binding_handler_names(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        name = _first_text(
            value,
            ("handler", "handler_name", "function", "function_name", "method", "callback", "name"),
        )
        if name:
            return [name]
        for nested_key in ("handlers", "callbacks", "items"):
            if nested_key in value:
                return _binding_handler_names(value.get(nested_key))
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        names: list[str] = []
        for item in value:
            names.extend(_binding_handler_names(item))
        return sorted(set(names))
    name = _text(value)
    return [name] if name else []


def _add_resources(builder: _GraphBuilder, source: Mapping[str, Any]) -> None:
    payload = _payload(source, ("entries", "extracted_files"))
    for collection_key in ("entries", "extracted_files"):
        for record in _records(
            payload.get(collection_key),
            key_field="path",
            record_markers=("path", "file", "filename", "name", "resource_path"),
        ):
            raw = _record_mapping(record, "path")
            path = _first_text(raw, ("path", "file", "filename", "resource_path", "name"))
            name = path or _record_name(raw, ("id", "name", "kind", "type"), "resource")
            identity: Any
            if path:
                identity = {"path": path}
            else:
                identity = {"resource": _json_safe(raw)}
            builder.add_node(
                node_type="resource",
                name=name,
                identity=identity,
                source=f"resources.{collection_key}",
                detail=raw,
                confidence=_confidence(raw, 0.7),
                attributes=raw,
            )


def _add_state_machine(builder: _GraphBuilder, source: Mapping[str, Any]) -> int:
    payload = _payload(source, ("states", "actions", "transitions", "nodes", "edges"))
    state_index: dict[str, set[str]] = {}
    action_index: dict[str, set[str]] = {}

    state_records = _records(
        payload.get("states"),
        key_field="name",
        record_markers=("id", "state_id", "state", "name", "label"),
    )
    action_records = _records(
        payload.get("actions"),
        key_field="name",
        record_markers=("id", "action_id", "action", "name", "label"),
    )
    if not state_records or not action_records:
        for record in _records(
            payload.get("nodes"),
            key_field="name",
            record_markers=("id", "type", "kind", "name", "label"),
        ):
            raw = _record_mapping(record, "name")
            category = (_first_text(raw, ("type", "kind", "node_type")) or "").lower()
            if "state" in category:
                state_records.append(raw)
            elif "action" in category or "event" in category:
                action_records.append(raw)

    for record in sorted(state_records, key=_canonical_json):
        raw = _record_mapping(record, "name")
        node = _add_state_node(builder, raw, "state_machine.states")
        _index_node(state_index, node, raw, ("name", "state", "id", "state_id", "key", "code"))
    for record in sorted(action_records, key=_canonical_json):
        raw = _record_mapping(record, "name")
        node = _add_action_node(builder, raw, "state_machine.actions")
        _index_node(action_index, node, raw, ("name", "action", "id", "action_id", "key", "code"))

    transition_value = payload.get("transitions")
    if transition_value is None:
        transition_value = payload.get("edges")
    if transition_value is None:
        transition_value = [
            record
            for record in action_records
            if isinstance(record, Mapping)
            and any(key in record for key in ("from", "source", "source_state", "from_state"))
            and any(key in record for key in ("to", "target", "target_state", "to_state"))
        ]
    transition_records = _records(
        transition_value,
        key_field="id",
        record_markers=("from", "to", "source", "target", "action", "event", "trigger"),
    )
    seen_transitions: set[str] = set()
    for record in sorted(transition_records, key=_canonical_json):
        raw = _record_mapping(record, "id")
        transition_key = _canonical_json(raw)
        if transition_key in seen_transitions:
            continue
        seen_transitions.add(transition_key)
        confidence = _confidence(raw, 0.8)
        detail = {"transition": raw}
        source_nodes = _resolve_state_references(
            builder,
            state_index,
            _transition_references(raw, ("from", "source", "source_state", "from_state", "current_state", "state")),
            raw,
        )
        action_nodes = _resolve_action_references(
            builder,
            action_index,
            _transition_references(raw, ("action", "event", "trigger", "command", "input")),
            raw,
        )
        target_nodes = _resolve_state_references(
            builder,
            state_index,
            _transition_references(raw, ("to", "target", "target_state", "to_state", "next_state", "destination")),
            raw,
        )

        if action_nodes:
            for source_node in source_nodes:
                for action_node in action_nodes:
                    builder.add_edge(
                        relation="state_transition_action",
                        source_id=source_node["id"],
                        target_id=action_node["id"],
                        evidence_source="state_machine.transitions",
                        detail=detail,
                        confidence=confidence,
                    )
            for action_node in action_nodes:
                for target_node in target_nodes:
                    builder.add_edge(
                        relation="state_transition_result",
                        source_id=action_node["id"],
                        target_id=target_node["id"],
                        evidence_source="state_machine.transitions",
                        detail=detail,
                        confidence=confidence,
                    )
        else:
            for source_node in source_nodes:
                for target_node in target_nodes:
                    builder.add_edge(
                        relation="state_transition",
                        source_id=source_node["id"],
                        target_id=target_node["id"],
                        evidence_source="state_machine.transitions",
                        detail=detail,
                        confidence=confidence,
                    )
    return len(seen_transitions)


def _add_state_node(builder: _GraphBuilder, raw: Mapping[str, Any], source_name: str) -> dict[str, Any]:
    name = _record_name(raw, ("name", "state", "label", "id", "state_id"), "ui-state")
    confidence = _confidence(raw, 0.75)
    return builder.add_node(
        node_type="ui_state",
        name=name,
        identity=_identified_object(raw, name, ("id", "state_id", "key", "code", "source_path", "path")),
        source=source_name,
        detail=raw,
        confidence=confidence,
        attributes=raw,
    )


def _add_action_node(builder: _GraphBuilder, raw: Mapping[str, Any], source_name: str) -> dict[str, Any]:
    name = _record_name(raw, ("name", "action", "event", "trigger", "label", "id", "action_id"), "ui-action")
    confidence = _confidence(raw, 0.75)
    return builder.add_node(
        node_type="ui_action",
        name=name,
        identity=_identified_object(raw, name, ("id", "action_id", "key", "code", "source_path", "path")),
        source=source_name,
        detail=raw,
        confidence=confidence,
        attributes=raw,
    )


def _index_node(
    index: dict[str, set[str]],
    node: Mapping[str, Any],
    raw: Mapping[str, Any],
    keys: tuple[str, ...],
) -> None:
    for key in keys:
        value = _text(raw.get(key))
        if value:
            index.setdefault(value, set()).add(str(node["id"]))
    index.setdefault(str(node["name"]), set()).add(str(node["id"]))


def _transition_references(raw: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        if key in raw:
            values.extend(_reference_values(raw.get(key), ("id", "name", "state", "action", "event", "trigger", "value", "label")))
    return sorted(set(values))


def _resolve_state_references(
    builder: _GraphBuilder,
    index: dict[str, set[str]],
    references: list[str],
    transition: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return _resolve_references(
        builder,
        index,
        references,
        transition,
        node_type="ui_state",
        source_name="state_machine.transitions",
    )


def _resolve_action_references(
    builder: _GraphBuilder,
    index: dict[str, set[str]],
    references: list[str],
    transition: Mapping[str, Any],
) -> list[dict[str, Any]]:
    return _resolve_references(
        builder,
        index,
        references,
        transition,
        node_type="ui_action",
        source_name="state_machine.transitions",
    )


def _resolve_references(
    builder: _GraphBuilder,
    index: dict[str, set[str]],
    references: list[str],
    transition: Mapping[str, Any],
    *,
    node_type: str,
    source_name: str,
) -> list[dict[str, Any]]:
    resolved: dict[str, dict[str, Any]] = {}
    for reference in references:
        node_ids = index.get(reference, set())
        if node_ids:
            for node_id in sorted(node_ids):
                node = builder._nodes[node_id]
                resolved[node_id] = node
            continue
        node = builder.add_node(
            node_type=node_type,
            name=reference,
            identity={"inferred_reference": reference},
            source=source_name,
            detail={"reference": reference, "transition": transition},
            confidence=_confidence(transition, 0.7),
            attributes={"inferred": True, "reference": reference},
        )
        index.setdefault(reference, set()).add(node["id"])
        resolved[node["id"]] = node
    return [resolved[node_id] for node_id in sorted(resolved)]


def _payload(source: Mapping[str, Any], expected_keys: tuple[str, ...]) -> Mapping[str, Any]:
    if any(key in source for key in expected_keys):
        return source
    candidates: list[Any] = [source.get("data"), source.get("result")]
    result = source.get("result")
    if isinstance(result, Mapping):
        candidates.append(result.get("data"))
    for candidate in candidates:
        if isinstance(candidate, Mapping) and any(key in candidate for key in expected_keys):
            return candidate
    return source


def _records(
    value: Any,
    *,
    key_field: str,
    record_markers: tuple[str, ...],
) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        if any(marker in value for marker in record_markers):
            return [value]
        records: list[Any] = []
        for key, item in value.items():
            if isinstance(item, Mapping):
                record = dict(item)
                record.setdefault(key_field, _text(key) or _canonical_json(key))
                records.append(record)
            else:
                records.append({key_field: _text(key) or _canonical_json(key), "value": item})
        return sorted(records, key=_canonical_json)
    if isinstance(value, (list, tuple, set, frozenset)):
        return sorted(value, key=_canonical_json)
    return [value]


def _record_mapping(record: Any, default_key: str) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return {str(key): value for key, value in record.items()}
    return {default_key: record}


def _record_name(raw: Mapping[str, Any], keys: tuple[str, ...], fallback: str) -> str:
    name = _first_text(raw, keys)
    if name:
        return name
    return f"{fallback}-{_digest(raw, length=12)}"


def _identified_object(raw: Mapping[str, Any], name: str, fields: tuple[str, ...]) -> dict[str, Any]:
    identifiers = {key: _json_safe(raw.get(key)) for key in fields if _present(raw.get(key))}
    if identifiers:
        return {"name": name, "identifiers": identifiers}
    return {"name": name, "object": _json_safe(raw)}


def _reference_values(value: Any, keys: tuple[str, ...]) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        name = _first_text(value, keys)
        return [name] if name else []
    if isinstance(value, (list, tuple, set, frozenset)):
        names: list[str] = []
        for item in value:
            names.extend(_reference_values(item, keys))
        return names
    name = _text(value)
    return [name] if name else []


def _first_text(raw: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        text = _text(raw.get(key))
        if text:
            return text
    return None


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, Mapping) or isinstance(value, (list, tuple, set, frozenset)):
        return None
    text = str(value).strip()
    return text or None


def _confidence(raw: Any, default: float) -> float:
    value = raw.get("confidence") if isinstance(raw, Mapping) else raw
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        confidence = float(default)
    if not math.isfinite(confidence):
        confidence = float(default)
    return max(0.0, min(1.0, confidence))


def _evidence(source: str, detail: Any, confidence: float) -> dict[str, Any]:
    return {
        "source": source,
        "detail": _json_safe(detail),
        "confidence": float(confidence),
    }


def _append_evidence(evidence_list: list[dict[str, Any]], evidence: dict[str, Any]) -> None:
    encoded = _canonical_json(evidence)
    if all(_canonical_json(existing) != encoded for existing in evidence_list):
        evidence_list.append(evidence)
        evidence_list.sort(key=_canonical_json)


def _node_id(node_type: str, name: str, identity: Any) -> str:
    return f"{node_type}:{_slug(name)}:{_digest({'type': node_type, 'identity': identity})}"


def _edge_id(relation: str, source_id: str, target_id: str, discriminator: Any) -> str:
    return f"edge:{relation}:{_digest({'source': source_id, 'target': target_id, 'relation': relation, 'discriminator': discriminator})}"


def _slug(value: Any) -> str:
    text = str(value).strip().lower()
    pieces: list[str] = []
    previous_separator = False
    for character in text:
        if character.isalnum() or character in ("_", "-"):
            pieces.append(character)
            previous_separator = False
        elif not previous_separator:
            pieces.append("-")
            previous_separator = True
    slug = "".join(pieces).strip("-")
    return slug[:64] or "unnamed"


def _digest(value: Any, *, length: int = 20) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()[:length]


def _canonical_json(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_safe(value: Any, active: set[int] | None = None) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value).lower()
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value.hex()}

    active = active if active is not None else set()
    object_id = id(value)
    if object_id in active:
        return "<cycle>"
    active.add(object_id)
    try:
        if isinstance(value, Mapping):
            converted: dict[str, Any] = {}
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
                base_key = str(key)
                safe_key = base_key
                suffix = 2
                while safe_key in converted:
                    safe_key = f"{base_key}#{suffix}"
                    suffix += 1
                converted[safe_key] = _json_safe(item, active)
            return converted
        if isinstance(value, (list, tuple)):
            return [_json_safe(item, active) for item in value]
        if isinstance(value, (set, frozenset)):
            converted_items = [_json_safe(item, active) for item in value]
            return sorted(
                converted_items,
                key=lambda item: json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False),
            )
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    finally:
        active.remove(object_id)


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, frozenset, Mapping)):
        return bool(value)
    return True


def _as_mapping(value: Mapping[str, Any] | None) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _graph_status(sources: Any) -> str:
    statuses: list[str] = []
    for source in sources:
        if not isinstance(source, Mapping) or not source:
            continue
        status = _text(source.get("status"))
        if status:
            statuses.append(status.lower())
            continue
        nested = _payload(source, tuple())
        nested_status = _text(nested.get("status")) if nested is not source else None
        if nested_status:
            statuses.append(nested_status.lower())
    if any(status in {"failed", "failure", "error"} for status in statuses):
        return "failed"
    if statuses and all(status == "unavailable" for status in statuses):
        return "unavailable"
    return "ok"
