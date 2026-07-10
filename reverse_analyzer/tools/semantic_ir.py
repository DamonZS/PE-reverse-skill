"""Build a deterministic semantic IR from already-collected reverse evidence.

The module deliberately consumes analysis payloads only.  It does not inspect a
sample, execute a program, invoke a build, use the network, or call an external
tool.  The resulting dictionary is safe to serialize as JSON and is intended to
be a small, stable contract shared by reconstruction and reporting layers.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any


_ENTITY_KINDS = (
    "function",
    "api",
    "dynamic_event",
    "ui_control",
    "ui_handler",
    "ui_state",
    "ui_action",
    "resource",
)

_KIND_ALIASES = {
    "function": "function",
    "func": "function",
    "method": "function",
    "routine": "function",
    "api": "api",
    "import": "api",
    "dynamic_event": "dynamic_event",
    "dynamic-event": "dynamic_event",
    "event": "dynamic_event",
    "trace_event": "dynamic_event",
    "ui_control": "ui_control",
    "ui-control": "ui_control",
    "control": "ui_control",
    "widget": "ui_control",
    "ui_handler": "ui_handler",
    "ui-handler": "ui_handler",
    "handler": "ui_handler",
    "callback": "ui_handler",
    "ui_state": "ui_state",
    "ui-state": "ui_state",
    "state": "ui_state",
    "ui_action": "ui_action",
    "ui-action": "ui_action",
    "action": "ui_action",
    "resource": "resource",
    "asset": "resource",
}

_NETWORK_TOKENS = (
    "winhttp",
    "wininet",
    "internet",
    "http",
    "https",
    "websocket",
    "socket",
    "ws2_32",
    "dns",
    "getaddrinfo",
    "url",
    "curl",
    "ftp",
)
_FILE_TOKENS = (
    "createfile",
    "readfile",
    "writefile",
    "deletefile",
    "movefile",
    "copyfile",
    "findfirstfile",
    "findnextfile",
    "ntcreatefile",
    "setfile",
    "getfile",
    "fopen",
    "fread",
    "fwrite",
    "filesystem",
    "file create",
    "file read",
    "file write",
    "file delete",
    "file copy",
    "file move",
    "create file",
    "read file",
    "write file",
    "delete file",
    "copy file",
    "move file",
)
_REGISTRY_TOKENS = (
    "registry",
    "regopenkey",
    "regcreatekey",
    "regsetvalue",
    "regqueryvalue",
    "regdelete",
    "hkey_",
    "hkey",
)
_PROCESS_TOKENS = (
    "createprocess",
    "openprocess",
    "terminateprocess",
    "process create",
    "process_create",
    "process-create",
    "shellexecute",
    "winexec",
    "startprocess",
)
_CRYPTO_TOKENS = (
    "crypto",
    "crypt",
    "bcrypt",
    "encrypt",
    "decrypt",
    "aes",
    "rsa",
    "rc4",
    "sha1",
    "sha256",
    "sha512",
    "md5",
    "hash",
)


def build_semantic_ir(
    *,
    behavior_graph: Mapping[str, Any] | None = None,
    decompiler: Mapping[str, Any] | None = None,
    dynamic_analysis: Mapping[str, Any] | None = None,
    gui_analysis: Mapping[str, Any] | None = None,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Normalize supplied analysis evidence into a stable semantic IR.

    A valid behavior evidence graph is authoritative because it already carries
    cross-domain provenance.  When it is absent or malformed, the function uses
    conservative decompiler, dynamic, and GUI fallbacks.  Inputs are never
    mutated and all output values are JSON-safe standard-library values.
    """

    source_maps = {
        "behavior_graph": _as_mapping(behavior_graph),
        "decompiler": _as_mapping(decompiler),
        "dynamic_analysis": _as_mapping(dynamic_analysis),
        "gui_analysis": _as_mapping(gui_analysis),
    }
    builder = _SemanticBuilder()

    graph_payload = _payload(source_maps["behavior_graph"], ("nodes", "edges"))
    if _has_supported_graph_nodes(graph_payload):
        _add_behavior_graph(builder, graph_payload)
    else:
        _add_decompiler_fallback(builder, _payload(source_maps["decompiler"], ("functions", "imports", "call_graph")))
        _add_dynamic_fallback(
            builder,
            _payload(source_maps["dynamic_analysis"], ("api_counts", "events", "sample_events", "api_events")),
        )
        _add_gui_fallback(builder, _payload(source_maps["gui_analysis"], ("evidence_graph", "state_machine", "controls")))

    entities = builder.entities()
    relations = builder.relations()
    capabilities = _build_capabilities(entities)
    kind_counts = {kind: 0 for kind in _ENTITY_KINDS}
    for entity in entities:
        kind_counts[entity["kind"]] = kind_counts.get(entity["kind"], 0) + 1

    result: dict[str, Any] = {
        "status": _overall_status(source_maps.values()),
        "schema_version": 1,
        "entities": entities,
        "relations": relations,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "capability_count": len(capabilities),
            "function_count": kind_counts["function"],
            "api_count": kind_counts["api"],
            "dynamic_event_count": kind_counts["dynamic_event"],
            "ui_control_count": kind_counts["ui_control"],
            "ui_state_count": kind_counts["ui_state"],
        },
        "artifacts": [],
    }

    if out_dir is not None and str(out_dir).strip():
        target = Path(out_dir) / "semantic_ir.json"
        artifact = {
            "name": "semantic_ir.json",
            "path": str(target),
            "kind": "semantic-ir",
        }
        result["artifacts"] = [artifact]
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(_json_dump(result), encoding="utf-8")
        except (OSError, TypeError, ValueError):
            result["artifacts"] = []
            result["status"] = "failed" if result["status"] == "failed" else "partial"
    return result


class _SemanticBuilder:
    """Deterministic entity/relation registry with conservative reference lookup."""

    def __init__(self) -> None:
        self._entities: dict[str, dict[str, Any]] = {}
        self._relations: dict[str, dict[str, Any]] = {}
        self._graph_ids: dict[str, set[str]] = {}
        self._references: dict[str, dict[str, set[str]]] = {}

    def add_entity(
        self,
        *,
        kind: str,
        name: str,
        identity: Any,
        confidence: float,
        sources: list[str],
        attributes: Any,
        references: list[Any] | None = None,
        graph_id: Any = None,
    ) -> dict[str, Any]:
        entity_id = _entity_id(kind, name, identity)
        safe_attributes = _attribute_mapping(attributes)
        entity = self._entities.get(entity_id)
        if entity is None:
            entity = {
                "id": entity_id,
                "kind": kind,
                "name": name,
                "confidence": confidence,
                "sources": sorted(set(sources)),
                "attributes": safe_attributes,
            }
            self._entities[entity_id] = entity
        else:
            entity["confidence"] = max(float(entity["confidence"]), confidence)
            entity["sources"] = sorted(set(entity["sources"]).union(sources))
            if _canonical_json(safe_attributes) < _canonical_json(entity["attributes"]):
                entity["attributes"] = safe_attributes

        values = [name]
        if references:
            values.extend(references)
        for value in values:
            reference = _reference_text(value)
            if reference:
                self._references.setdefault(kind, {}).setdefault(reference, set()).add(entity_id)
        graph_reference = _reference_text(graph_id)
        if graph_reference:
            self._graph_ids.setdefault(graph_reference, set()).add(entity_id)
        return entity

    def add_relation(
        self,
        *,
        relation_type: str,
        source_id: str,
        target_id: str,
        confidence: float,
        sources: list[str],
        identity: Any = None,
    ) -> None:
        if source_id not in self._entities or target_id not in self._entities:
            return
        relation_type = _text(relation_type) or "related_to"
        relation_id = _relation_id(relation_type, source_id, target_id, identity)
        relation = self._relations.get(relation_id)
        if relation is None:
            self._relations[relation_id] = {
                "id": relation_id,
                "type": relation_type,
                "source": source_id,
                "target": target_id,
                "confidence": confidence,
                "sources": sorted(set(sources)),
            }
            return
        relation["confidence"] = max(float(relation["confidence"]), confidence)
        relation["sources"] = sorted(set(relation["sources"]).union(sources))

    def resolve_graph(self, value: Any) -> list[str]:
        reference = _reference_text(value)
        return sorted(self._graph_ids.get(reference, set())) if reference else []

    def resolve(self, value: Any, preferred_kinds: tuple[str, ...] = ()) -> list[str]:
        reference = _reference_text(value)
        if not reference:
            return []
        kinds = preferred_kinds or _ENTITY_KINDS
        matches: set[str] = set()
        for kind in kinds:
            matches.update(self._references.get(kind, {}).get(reference, set()))
        return sorted(matches)

    def ensure_reference(
        self,
        *,
        kind: str,
        name: str,
        source: str,
        confidence: float,
        attributes: Mapping[str, Any],
    ) -> str:
        matches = self.resolve(name, (kind,))
        if len(matches) == 1:
            return matches[0]
        entity = self.add_entity(
            kind=kind,
            name=name,
            identity={"reference": name, "kind": kind},
            confidence=confidence,
            sources=[source],
            attributes=attributes,
            references=[name],
        )
        return str(entity["id"])

    def entities(self) -> list[dict[str, Any]]:
        return [self._entities[entity_id] for entity_id in sorted(self._entities)]

    def relations(self) -> list[dict[str, Any]]:
        return [self._relations[relation_id] for relation_id in sorted(self._relations)]


def _add_behavior_graph(builder: _SemanticBuilder, graph: Mapping[str, Any]) -> None:
    for record in _records(
        graph.get("nodes"),
        key_field="id",
        markers=("id", "type", "kind", "node_type", "name", "label"),
    ):
        raw = _record_mapping(record, "id")
        kind = _kind(raw.get("type") or raw.get("kind") or raw.get("node_type"))
        if kind is None:
            continue
        name = _record_name(raw, ("name", "label", "title", "id", "key"), kind)
        graph_id = raw.get("id")
        identity = {"graph_id": _json_safe(graph_id)} if _reference_text(graph_id) else {"node": _json_safe(raw)}
        builder.add_entity(
            kind=kind,
            name=name,
            identity=identity,
            confidence=_confidence(raw, 0.7),
            sources=_sources(raw, "behavior_graph.nodes"),
            attributes=_attributes(raw),
            references=_references_from_record(raw),
            graph_id=graph_id,
        )

    for record in _records(
        graph.get("edges"),
        key_field="id",
        markers=("id", "type", "relation", "source", "target", "from", "to"),
    ):
        raw = _record_mapping(record, "id")
        source_values = _reference_values(raw.get("source") if "source" in raw else raw.get("from"))
        target_values = _reference_values(raw.get("target") if "target" in raw else raw.get("to"))
        if len(source_values) != 1 or len(target_values) != 1:
            continue
        source_matches = builder.resolve_graph(source_values[0])
        target_matches = builder.resolve_graph(target_values[0])
        if not source_matches:
            source_matches = builder.resolve(source_values[0])
        if not target_matches:
            target_matches = builder.resolve(target_values[0])
        if len(source_matches) != 1 or len(target_matches) != 1:
            continue
        builder.add_relation(
            relation_type=_text(raw.get("type") or raw.get("relation") or raw.get("kind")) or "related_to",
            source_id=source_matches[0],
            target_id=target_matches[0],
            confidence=_confidence(raw, 0.7),
            sources=_sources(raw, "behavior_graph.edges"),
            identity={"graph_id": _json_safe(raw.get("id"))} if _reference_text(raw.get("id")) else None,
        )


def _add_decompiler_fallback(builder: _SemanticBuilder, payload: Mapping[str, Any]) -> None:
    function_records = _records(
        payload.get("functions"),
        key_field="name",
        markers=("name", "function_name", "symbol", "qualified_name", "address", "entry"),
    )
    normalized_functions: list[dict[str, Any]] = []
    for record in function_records:
        raw = _record_mapping(record, "name")
        name = _record_name(raw, ("name", "function_name", "symbol", "qualified_name", "label", "entry", "address"), "function")
        references = _references_from_record(raw, ("name", "function_name", "symbol", "qualified_name", "id", "entry", "address", "rva", "va"))
        identity = _identity_from_record(raw, name, ("id", "entry", "address", "rva", "va", "offset", "start"))
        builder.add_entity(
            kind="function",
            name=name,
            identity=identity,
            confidence=_confidence(raw, 0.8),
            sources=["decompiler.functions"],
            attributes=_attributes(raw),
            references=references,
        )
        normalized_functions.append(raw)

    for library, api_raw in _import_api_records(payload.get("imports")):
        name = _record_name(api_raw, ("name", "api", "function", "function_name", "label"), "api")
        attributes = _attributes(api_raw)
        if library:
            attributes.setdefault("library", library)
        _add_api(builder, name, attributes, "decompiler.imports", _confidence(api_raw, 0.75))

    for record in _records(
        payload.get("imports_xrefs"),
        key_field="label",
        markers=("label", "name", "api", "function", "library", "dll"),
    ):
        raw = _record_mapping(record, "label")
        name = _record_name(raw, ("label", "name", "api", "function", "function_name"), "api")
        api = _add_api(builder, name, _attributes(raw), "decompiler.imports_xrefs", _confidence(raw, 0.75))
        for function_ref in _reference_values(raw.get("functions")):
            _add_unambiguous_relation(
                builder,
                "calls",
                function_ref,
                str(api["id"]),
                ("function",),
                _confidence(raw, 0.7),
                ["decompiler.imports_xrefs"],
            )

    call_graph = _as_mapping(payload.get("call_graph"))
    call_edges = call_graph.get("edges") if call_graph else payload.get("call_graph_edges")
    for record in _records(
        call_edges,
        key_field="source",
        markers=("source", "target", "from", "to", "caller", "callee"),
    ):
        raw = _record_mapping(record, "source")
        source_values = _reference_values(raw.get("source") or raw.get("from") or raw.get("caller"))
        target_values = _reference_values(raw.get("target") or raw.get("to") or raw.get("callee"))
        if len(source_values) != 1 or len(target_values) != 1:
            continue
        _add_unambiguous_relation(
            builder,
            "calls",
            source_values[0],
            target_values[0],
            ("function",),
            _confidence(raw, 0.75),
            ["decompiler.call_graph"],
            target_kinds=("function", "api"),
        )

    for raw in normalized_functions:
        source_refs = _references_from_record(raw, ("name", "function_name", "symbol", "qualified_name", "id", "entry", "address"))
        if not source_refs:
            continue
        for call_value in _reference_values(raw.get("calls")):
            _add_unambiguous_relation(
                builder,
                "calls",
                source_refs[0],
                call_value,
                ("function",),
                _confidence(raw, 0.7),
                ["decompiler.functions.calls"],
                target_kinds=("function", "api"),
            )


def _add_dynamic_fallback(builder: _SemanticBuilder, payload: Mapping[str, Any]) -> None:
    api_counts = payload.get("api_counts")
    if isinstance(api_counts, Mapping):
        for api_name, count in sorted(api_counts.items(), key=lambda item: _canonical_json(item[0])):
            name = _text(api_name)
            if not name:
                continue
            raw = _record_mapping(count, "count") if isinstance(count, Mapping) else {"api": name, "count": count}
            raw.setdefault("api", name)
            _add_api(builder, name, _attributes(raw), "dynamic_analysis.api_counts", _confidence(raw, 0.75))
    else:
        for record in _records(
            api_counts,
            key_field="api",
            markers=("api", "api_name", "name", "function", "operation"),
        ):
            raw = _record_mapping(record, "api")
            name = _record_name(raw, ("api", "api_name", "function", "function_name", "operation", "name"), "api")
            _add_api(builder, name, _attributes(raw), "dynamic_analysis.api_counts", _confidence(raw, 0.75))

    for source, record in _dynamic_event_records(payload):
        raw = _record_mapping(record, "api")
        api_names = _event_api_names(raw)
        event_name = api_names[0] if api_names else _record_name(
            raw,
            ("event", "event_type", "operation", "name", "id", "category"),
            "dynamic-event",
        )
        event = builder.add_entity(
            kind="dynamic_event",
            name=event_name,
            identity={"event": _json_safe(raw)},
            confidence=_confidence(raw, 0.8),
            sources=[source],
            attributes=_attributes(raw),
            references=_references_from_record(raw),
        )
        for api_name in api_names:
            api = _add_api(builder, api_name, _attributes(raw), source, _confidence(raw, 0.8))
            builder.add_relation(
                relation_type="dynamic_event_to_api",
                source_id=str(event["id"]),
                target_id=str(api["id"]),
                confidence=_confidence(raw, 0.8),
                sources=[source],
            )


def _add_gui_fallback(builder: _SemanticBuilder, payload: Mapping[str, Any]) -> None:
    evidence_graph = _as_mapping(payload.get("evidence_graph"))
    node_source = evidence_graph if evidence_graph else payload
    for record in _records(
        node_source.get("nodes") or node_source.get("controls"),
        key_field="id",
        markers=("id", "control_id", "automation_id", "name", "type", "text", "label"),
    ):
        raw = _record_mapping(record, "id")
        explicit_kind = _kind(raw.get("type") or raw.get("kind") or raw.get("node_type"))
        kind = explicit_kind if explicit_kind in {"ui_control", "ui_handler", "ui_state", "ui_action", "resource"} else "ui_control"
        name = _record_name(raw, ("id", "control_id", "automation_id", "name", "text", "title", "label", "type"), kind)
        control = builder.add_entity(
            kind=kind,
            name=name,
            identity=_identity_from_record(
                raw,
                name,
                ("id", "control_id", "automation_id", "source_path", "document", "path", "window", "parent_id"),
            ),
            confidence=_confidence(raw, 0.75),
            sources=["gui_analysis.evidence_graph.nodes"],
            attributes=_attributes(raw),
            references=_references_from_record(raw),
        )
        if kind != "ui_control":
            continue
        for event_name, handler_name, binding in _handler_bindings(raw):
            handler = builder.add_entity(
                kind="ui_handler",
                name=handler_name,
                identity={"control": control["id"], "event": event_name, "handler": handler_name},
                confidence=_confidence(binding, _confidence(raw, 0.75)),
                sources=["gui_analysis.evidence_graph.nodes.event_handlers"],
                attributes={"control_id": control["id"], "event": event_name, "handler": handler_name},
                references=[handler_name],
            )
            builder.add_relation(
                relation_type="ui_control_to_handler",
                source_id=str(control["id"]),
                target_id=str(handler["id"]),
                confidence=_confidence(binding, _confidence(raw, 0.75)),
                sources=["gui_analysis.evidence_graph.nodes.event_handlers"],
                identity={"event": event_name},
            )

    _add_gui_resources(builder, payload)
    state_machine = _as_mapping(payload.get("state_machine"))
    if not state_machine and any(key in payload for key in ("states", "actions", "transitions", "edges")):
        state_machine = payload
    _add_state_machine(builder, state_machine)


def _add_gui_resources(builder: _SemanticBuilder, payload: Mapping[str, Any]) -> None:
    sources: list[tuple[str, Mapping[str, Any]]] = [("gui_analysis", payload)]
    resource_manifest = _as_mapping(payload.get("resource_manifest"))
    if resource_manifest:
        sources.append(("gui_analysis.resource_manifest", resource_manifest))
    xaml_evidence = _as_mapping(payload.get("xaml_evidence"))
    if xaml_evidence:
        sources.append(("gui_analysis.xaml_evidence", xaml_evidence))
    for source_name, source in sources:
        for key in ("entries", "extracted_files", "resources", "files"):
            for record in _records(
                source.get(key),
                key_field="path",
                markers=("path", "file", "filename", "name", "resource_path"),
            ):
                raw = _record_mapping(record, "path")
                name = _record_name(raw, ("path", "file", "filename", "resource_path", "name", "id"), "resource")
                builder.add_entity(
                    kind="resource",
                    name=name,
                    identity=_identity_from_record(raw, name, ("id", "path", "file", "filename", "resource_path")),
                    confidence=_confidence(raw, 0.7),
                    sources=[f"{source_name}.{key}"],
                    attributes=_attributes(raw),
                    references=_references_from_record(raw),
                )


def _add_state_machine(builder: _SemanticBuilder, payload: Mapping[str, Any]) -> None:
    if not payload:
        return
    state_ids: dict[str, set[str]] = {}
    action_ids: dict[str, set[str]] = {}
    for record in _records(
        payload.get("states"),
        key_field="name",
        markers=("id", "state_id", "state", "name", "label"),
    ):
        raw = _record_mapping(record, "name")
        entity = _add_gui_state_or_action(builder, "ui_state", raw, "gui_analysis.state_machine.states")
        _index_entity_references(state_ids, entity, raw, ("id", "state_id", "state", "name", "label", "key"))
    for record in _records(
        payload.get("actions"),
        key_field="name",
        markers=("id", "action_id", "action", "event", "name", "label"),
    ):
        raw = _record_mapping(record, "name")
        entity = _add_gui_state_or_action(builder, "ui_action", raw, "gui_analysis.state_machine.actions")
        _index_entity_references(action_ids, entity, raw, ("id", "action_id", "action", "event", "name", "label", "key"))

    transition_value = payload.get("transitions") if payload.get("transitions") is not None else payload.get("edges")
    for record in _records(
        transition_value,
        key_field="id",
        markers=("id", "from", "to", "source", "target", "action", "event", "trigger"),
    ):
        raw = _record_mapping(record, "id")
        confidence = _confidence(raw, 0.8)
        source_names = _transition_references(raw, ("from", "source", "source_state", "from_state", "current_state", "state"))
        action_names = _transition_references(raw, ("action", "event", "trigger", "command", "input"))
        target_names = _transition_references(raw, ("to", "target", "target_state", "to_state", "next_state", "destination"))
        source_entities = _state_action_entities(
            builder,
            state_ids,
            "ui_state",
            source_names,
            raw,
            "gui_analysis.state_machine.transitions",
            confidence,
        )
        action_entities = _state_action_entities(
            builder,
            action_ids,
            "ui_action",
            action_names,
            raw,
            "gui_analysis.state_machine.transitions",
            confidence,
        )
        target_entities = _state_action_entities(
            builder,
            state_ids,
            "ui_state",
            target_names,
            raw,
            "gui_analysis.state_machine.transitions",
            confidence,
        )
        if action_entities:
            for source_id in source_entities:
                for action_id in action_entities:
                    builder.add_relation(
                        relation_type="state_transition_action",
                        source_id=source_id,
                        target_id=action_id,
                        confidence=confidence,
                        sources=["gui_analysis.state_machine.transitions"],
                        identity={"transition": _json_safe(raw), "part": "action"},
                    )
            for action_id in action_entities:
                for target_id in target_entities:
                    builder.add_relation(
                        relation_type="state_transition_result",
                        source_id=action_id,
                        target_id=target_id,
                        confidence=confidence,
                        sources=["gui_analysis.state_machine.transitions"],
                        identity={"transition": _json_safe(raw), "part": "result"},
                    )
        else:
            for source_id in source_entities:
                for target_id in target_entities:
                    builder.add_relation(
                        relation_type="state_transition",
                        source_id=source_id,
                        target_id=target_id,
                        confidence=confidence,
                        sources=["gui_analysis.state_machine.transitions"],
                        identity={"transition": _json_safe(raw)},
                    )


def _add_gui_state_or_action(
    builder: _SemanticBuilder,
    kind: str,
    raw: Mapping[str, Any],
    source: str,
) -> dict[str, Any]:
    names = ("name", "state", "action", "event", "label", "id", "state_id", "action_id")
    name = _record_name(raw, names, kind)
    return builder.add_entity(
        kind=kind,
        name=name,
        identity=_identity_from_record(raw, name, ("id", "state_id", "action_id", "key", "code", "path")),
        confidence=_confidence(raw, 0.75),
        sources=[source],
        attributes=_attributes(raw),
        references=_references_from_record(raw, names),
    )


def _state_action_entities(
    builder: _SemanticBuilder,
    index: dict[str, set[str]],
    kind: str,
    names: list[str],
    transition: Mapping[str, Any],
    source: str,
    confidence: float,
) -> list[str]:
    result: set[str] = set()
    for name in names:
        matches = index.get(name, set())
        if len(matches) == 1:
            result.update(matches)
            continue
        entity_id = builder.ensure_reference(
            kind=kind,
            name=name,
            source=source,
            confidence=confidence,
            attributes={"inferred": True, "reference": name, "transition": _json_safe(transition)},
        )
        index.setdefault(name, set()).add(entity_id)
        result.add(entity_id)
    return sorted(result)


def _index_entity_references(
    index: dict[str, set[str]],
    entity: Mapping[str, Any],
    raw: Mapping[str, Any],
    keys: tuple[str, ...],
) -> None:
    index.setdefault(str(entity["name"]), set()).add(str(entity["id"]))
    for key in keys:
        value = _reference_text(raw.get(key))
        if value:
            index.setdefault(value, set()).add(str(entity["id"]))


def _add_api(
    builder: _SemanticBuilder,
    name: str,
    attributes: Mapping[str, Any],
    source: str,
    confidence: float,
) -> dict[str, Any]:
    references = [name]
    for key in ("api", "api_name", "function", "function_name", "name", "label", "id"):
        if key in attributes:
            references.append(attributes.get(key))
    return builder.add_entity(
        kind="api",
        name=name,
        identity={"api": name.casefold()},
        confidence=confidence,
        sources=[source],
        attributes=attributes,
        references=references,
    )


def _add_unambiguous_relation(
    builder: _SemanticBuilder,
    relation_type: str,
    source_reference: Any,
    target_reference: Any,
    source_kinds: tuple[str, ...],
    confidence: float,
    sources: list[str],
    *,
    target_kinds: tuple[str, ...] = (),
) -> None:
    source_ids = builder.resolve(source_reference, source_kinds)
    target_ids = builder.resolve(target_reference, target_kinds)
    if len(source_ids) == 1 and len(target_ids) == 1:
        builder.add_relation(
            relation_type=relation_type,
            source_id=source_ids[0],
            target_id=target_ids[0],
            confidence=confidence,
            sources=sources,
        )


def _import_api_records(value: Any) -> list[tuple[str | None, dict[str, Any]]]:
    records: list[tuple[str | None, dict[str, Any]]] = []
    if isinstance(value, Mapping) and not any(key in value for key in ("dll", "library", "module", "functions", "imports")):
        for library, functions in sorted(value.items(), key=lambda item: _canonical_json(item[0])):
            records.extend(_import_api_records({"library": _text(library), "functions": functions}))
        return records
    for record in _records(
        value,
        key_field="library",
        markers=("dll", "library", "module", "functions", "imports", "name"),
    ):
        raw = _record_mapping(record, "library")
        library = _first_text(raw, ("dll", "library", "module", "provider"))
        functions = raw.get("functions") if raw.get("functions") is not None else raw.get("imports")
        if functions is None and _first_text(raw, ("name", "api", "function", "function_name")):
            records.append((library, raw))
            continue
        for api_record in _records(
            functions,
            key_field="name",
            markers=("name", "api", "function", "function_name", "label"),
        ):
            records.append((library, _record_mapping(api_record, "name")))
    return sorted(records, key=lambda item: (_canonical_json(item[0]), _canonical_json(item[1])))


def _dynamic_event_records(payload: Mapping[str, Any]) -> list[tuple[str, Any]]:
    records: list[tuple[str, Any]] = []
    for key in ("sample_events", "api_events", "events", "trace_events", "samples", "operations"):
        value = payload.get(key)
        if isinstance(value, Mapping) and any(nested in value for nested in ("events", "items", "samples")):
            for nested_key in ("events", "items", "samples"):
                for record in _records(
                    value.get(nested_key),
                    key_field="api",
                    markers=("api", "api_name", "function", "operation", "name", "event", "event_type"),
                ):
                    records.append((f"dynamic_analysis.{key}", record))
            continue
        for record in _records(
            value,
            key_field="api",
            markers=("api", "api_name", "function", "operation", "name", "event", "event_type"),
        ):
            records.append((f"dynamic_analysis.{key}", record))
    return sorted(records, key=lambda item: (item[0], _canonical_json(item[1])))


def _event_api_names(raw: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    for key in ("api", "api_name", "function", "function_name", "operation"):
        names.extend(_reference_values(raw.get(key)))
    for key in ("apis", "api_calls", "functions", "operations"):
        names.extend(_reference_values(raw.get(key)))
    return sorted(set(names))


def _handler_bindings(raw: Mapping[str, Any]) -> list[tuple[str, str, Any]]:
    bindings: list[tuple[str, str, Any]] = []
    for collection_key in ("event_handlers", "handlers", "events"):
        collection = raw.get(collection_key)
        if isinstance(collection, Mapping):
            for event, value in sorted(collection.items(), key=lambda item: _canonical_json(item[0])):
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
    unique = {(event, handler, _canonical_json(detail)): (event, handler, detail) for event, handler, detail in bindings if event and handler}
    return [unique[key] for key in sorted(unique)]


def _binding_handler_names(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        name = _first_text(value, ("handler", "handler_name", "function", "function_name", "method", "callback", "name"))
        if name:
            return [name]
        for key in ("handlers", "callbacks", "items"):
            if key in value:
                return _binding_handler_names(value.get(key))
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        names: list[str] = []
        for item in value:
            names.extend(_binding_handler_names(item))
        return sorted(set(names))
    name = _text(value)
    return [name] if name else []


def _transition_references(raw: Mapping[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        if key in raw:
            values.extend(_reference_values(raw.get(key)))
    return sorted(set(values))


def _build_capabilities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    categories: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        category = _capability_category(entity)
        if category is None:
            continue
        categories.setdefault(category, []).append(entity)
    capabilities: list[dict[str, Any]] = []
    for category in sorted(categories):
        members = sorted(categories[category], key=lambda item: str(item["id"]))
        entity_ids = [str(member["id"]) for member in members]
        evidence_count = sum(max(1, len(member.get("sources") or [])) for member in members)
        capabilities.append(
            {
                "id": f"capability:{category}:{_digest(entity_ids)}",
                "name": category,
                "category": category,
                "confidence": max(float(member["confidence"]) for member in members),
                "entity_ids": entity_ids,
                "evidence_count": evidence_count,
            }
        )
    return sorted(capabilities, key=lambda item: str(item["id"]))


def _capability_category(entity: Mapping[str, Any]) -> str | None:
    kind = str(entity.get("kind") or "")
    if kind in {"ui_control", "ui_handler", "ui_state", "ui_action"}:
        return "gui"
    if kind == "resource":
        return None
    attributes = _as_mapping(entity.get("attributes"))
    explicit_values = [
        attributes.get(key)
        for key in ("category", "module", "capability", "operation", "api", "api_name", "library", "dll", "provider")
        if key in attributes
    ]
    explicit_text = " ".join(value for value in (_text(item) for item in explicit_values) if value).casefold()
    name = _text(entity.get("name")) or ""
    name_text = name.casefold()
    # Function labels alone are not considered proof of a specific capability;
    # APIs and dynamic events can be classified from their explicit operation.
    searchable = explicit_text if kind == "function" else f"{name_text} {explicit_text}".strip()
    if _contains_any(searchable, _REGISTRY_TOKENS):
        return "registry"
    if _contains_any(searchable, _CRYPTO_TOKENS):
        return "crypto"
    if _contains_any(searchable, _NETWORK_TOKENS) or _contains_exact_signal(searchable, ("connect", "send", "recv")):
        return "network"
    if _contains_any(searchable, _PROCESS_TOKENS):
        return "process"
    if _contains_any(searchable, _FILE_TOKENS):
        return "file"
    if kind in {"function", "api", "dynamic_event"}:
        return "general"
    return None


def _contains_any(text: str, tokens: tuple[str, ...]) -> bool:
    return any(token in text for token in tokens)


def _contains_exact_signal(text: str, tokens: tuple[str, ...]) -> bool:
    values = set(text.split())
    return any(token in values for token in tokens)


def _has_supported_graph_nodes(payload: Mapping[str, Any]) -> bool:
    for record in _records(payload.get("nodes"), key_field="id", markers=("id", "type", "kind", "node_type", "name")):
        raw = _record_mapping(record, "id")
        if _kind(raw.get("type") or raw.get("kind") or raw.get("node_type")) is not None:
            return True
    return False


def _kind(value: Any) -> str | None:
    text = _text(value)
    if not text:
        return None
    return _KIND_ALIASES.get(text.casefold().replace(" ", "_"))


def _payload(source: Mapping[str, Any], expected_keys: tuple[str, ...]) -> Mapping[str, Any]:
    if not source:
        return source
    if expected_keys and any(key in source for key in expected_keys):
        return source
    candidates: list[Any] = [source.get("data"), source.get("result")]
    result = source.get("result")
    if isinstance(result, Mapping):
        candidates.append(result.get("data"))
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        if not expected_keys or any(key in candidate for key in expected_keys):
            return candidate
    return source


def _records(value: Any, *, key_field: str, markers: tuple[str, ...]) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        if any(marker in value for marker in markers):
            return [value]
        records: list[Any] = []
        for key, item in value.items():
            if isinstance(item, Mapping):
                record = {str(record_key): record_value for record_key, record_value in item.items()}
                record.setdefault(key_field, _text(key) or _canonical_json(key))
                records.append(record)
            else:
                records.append({key_field: _text(key) or _canonical_json(key), "value": item})
        return sorted(records, key=_canonical_json)
    if isinstance(value, (list, tuple, set, frozenset)):
        return sorted(value, key=_canonical_json)
    return []


def _record_mapping(record: Any, default_key: str) -> dict[str, Any]:
    if isinstance(record, Mapping):
        return {str(key): value for key, value in record.items()}
    return {default_key: record}


def _record_name(raw: Mapping[str, Any], keys: tuple[str, ...], fallback: str) -> str:
    name = _first_text(raw, keys)
    return name or f"{fallback}-{_digest(raw, length=12)}"


def _identity_from_record(raw: Mapping[str, Any], name: str, keys: tuple[str, ...]) -> dict[str, Any]:
    values = {key: _json_safe(raw.get(key)) for key in keys if _present(raw.get(key))}
    return {"name": name, "identifiers": values} if values else {"name": name}


def _attributes(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    supplied = raw.get("attributes")
    if isinstance(supplied, Mapping):
        return {str(key): value for key, value in supplied.items()}
    omitted = {"id", "type", "kind", "node_type", "name", "label", "confidence", "source", "sources", "evidence"}
    return {str(key): value for key, value in raw.items() if str(key) not in omitted}


def _attribute_mapping(value: Any) -> dict[str, Any]:
    safe = _json_safe(value)
    return safe if isinstance(safe, dict) else {"value": safe}


def _sources(raw: Mapping[str, Any], fallback: str) -> list[str]:
    values: list[str] = []
    for key in ("source", "sources"):
        if key in raw:
            values.extend(_reference_values(raw.get(key)))
    evidence = raw.get("evidence")
    if isinstance(evidence, Mapping):
        evidence = [evidence]
    if isinstance(evidence, (list, tuple, set, frozenset)):
        for item in evidence:
            if isinstance(item, Mapping):
                value = _text(item.get("source"))
                if value:
                    values.append(value)
    return sorted(set(values)) or [fallback]


def _references_from_record(raw: Mapping[str, Any], keys: tuple[str, ...] | None = None) -> list[str]:
    keys = keys or ("id", "name", "label", "key", "address", "entry", "rva", "va", "function_name", "api", "api_name")
    references: list[str] = []
    for key in keys:
        references.extend(_reference_values(raw.get(key)))
    return sorted(set(references))


def _reference_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        names: list[str] = []
        for key in ("id", "name", "label", "value", "api", "api_name", "function", "function_name", "operation", "state", "action", "event"):
            text = _reference_text(value.get(key))
            if text:
                names.append(text)
        return sorted(set(names))
    if isinstance(value, (list, tuple, set, frozenset)):
        names: list[str] = []
        for item in value:
            names.extend(_reference_values(item))
        return sorted(set(names))
    text = _reference_text(value)
    return [text] if text else []


def _reference_text(value: Any) -> str | None:
    if value is None or isinstance(value, Mapping) or isinstance(value, (list, tuple, set, frozenset)):
        return None
    text = str(value).strip()
    return text or None


def _first_text(raw: Mapping[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        text = _text(raw.get(key))
        if text:
            return text
    return None


def _text(value: Any) -> str | None:
    return _reference_text(value)


def _confidence(value: Any, default: float) -> float:
    raw = value.get("confidence") if isinstance(value, Mapping) else value
    try:
        confidence = float(raw)
    except (TypeError, ValueError):
        confidence = float(default)
    if not math.isfinite(confidence):
        confidence = float(default)
    return max(0.0, min(1.0, confidence))


def _entity_id(kind: str, name: str, identity: Any) -> str:
    return f"entity:{kind}:{_slug(name)}:{_digest({'kind': kind, 'identity': identity})}"


def _relation_id(relation_type: str, source_id: str, target_id: str, identity: Any) -> str:
    return f"relation:{relation_type}:{_digest({'type': relation_type, 'source': source_id, 'target': target_id, 'identity': identity})}"


def _slug(value: Any) -> str:
    text = str(value).strip().casefold()
    parts: list[str] = []
    separator = False
    for character in text:
        if character.isalnum() or character in {"_", "-"}:
            parts.append(character)
            separator = False
        elif not separator:
            parts.append("-")
            separator = True
    return "".join(parts).strip("-")[:64] or "unnamed"


def _digest(value: Any, *, length: int = 20) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()[:length]


def _canonical_json(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _json_dump(value: Any) -> str:
    return json.dumps(_json_safe(value), ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"


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
            items = [_json_safe(item, active) for item in value]
            return sorted(items, key=_canonical_json)
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    finally:
        active.remove(object_id)


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return bool(value)
    return True


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _overall_status(sources: Any) -> str:
    statuses: list[str] = []
    for source in sources:
        if not isinstance(source, Mapping) or not source:
            continue
        payload = _payload(source, tuple())
        value = _text(source.get("status")) or _text(payload.get("status"))
        if value:
            statuses.append(value.casefold())
    if any(status in {"failed", "failure", "error"} for status in statuses):
        return "failed"
    if statuses and all(status == "unavailable" for status in statuses):
        return "unavailable"
    return "ok"
