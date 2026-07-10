"""Canonical GUI Evidence Graph construction.

The graph is deliberately JSON-only so static resource parsers, runtime probes,
visual models, decompilers, and project generators can collaborate without a
shared optional dependency stack.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable


def build_gui_evidence_graph(
    *,
    fingerprint: Mapping[str, Any] | None = None,
    resources: Mapping[str, Any] | None = None,
    xaml_evidence: Mapping[str, Any] | None = None,
    runtime_tree: Mapping[str, Any] | None = None,
    visual: Mapping[str, Any] | None = None,
    decompiler: Mapping[str, Any] | None = None,
    out_dir: str | Path | None = None,
) -> Dict[str, Any]:
    """Fuse heterogeneous GUI observations into a stable control graph.

    Every node has an id, normalized type, text, optional bbox/style/properties,
    event handlers, source evidence, and a combined confidence.  Sources are
    merged by explicit IDs first, then text/bounding-box heuristics.
    """

    fingerprint = fingerprint or {}
    resources = resources or {}
    xaml_evidence = xaml_evidence or {}
    runtime_tree = runtime_tree or {}
    visual = visual or {}
    decompiler = decompiler or {}
    nodes: list[Dict[str, Any]] = []
    title = str(xaml_evidence.get("title") or "") if isinstance(xaml_evidence, Mapping) else ""

    def add(raw: Mapping[str, Any], source: str, index: int) -> Dict[str, Any]:
        candidate = _normalize_node(raw, source=source, index=index)
        match = _find_match(nodes, candidate)
        if match is None:
            nodes.append(candidate)
            return candidate
        _merge_node(match, candidate)
        return match

    for index, item in enumerate(_mapping_list(xaml_evidence.get("nodes") if isinstance(xaml_evidence, Mapping) else [])):
        add(item, "xaml", index)

    runtime_nodes, runtime_title = _runtime_nodes(runtime_tree)
    if not title and runtime_title:
        title = runtime_title
    for index, item in enumerate(runtime_nodes):
        add(item, "runtime", index)

    visual_nodes = _visual_nodes(visual)
    for index, item in enumerate(visual_nodes):
        add(item, "visual", index)

    function_names = _function_names(decompiler)
    for node in nodes:
        handlers = node.get("event_handlers") or {}
        node["handler_evidence"] = [
            {"handler": handler, "source": "decompiler", "confidence": 0.8}
            for handler in handlers.values()
            if str(handler) in function_names
        ]

    edges = _parent_edges(nodes)
    statuses = [
        str(value.get("status") or "ok").lower()
        for value in (fingerprint, xaml_evidence, runtime_tree, visual)
        if isinstance(value, Mapping) and value
    ]
    status = "failed" if "failed" in statuses else ("unavailable" if statuses and all(value == "unavailable" for value in statuses) else "ok")
    graph: Dict[str, Any] = {
        "status": status,
        "version": 1,
        "platform": fingerprint.get("platform") if isinstance(fingerprint, Mapping) else None,
        "framework": fingerprint.get("framework") if isinstance(fingerprint, Mapping) else None,
        "title": title or None,
        "confidence": _graph_confidence(fingerprint, nodes),
        "nodes": nodes,
        "edges": edges,
        "source_summary": {
            "xaml_node_count": len(_mapping_list(xaml_evidence.get("nodes") if isinstance(xaml_evidence, Mapping) else [])),
            "runtime_node_count": len(runtime_nodes),
            "visual_node_count": len(visual_nodes),
            "resource_counts": dict(resources.get("counts") or resources.get("resource_counts") or {}) if isinstance(resources, Mapping) else {},
            "decompiler_function_count": len(function_names),
        },
    }
    if out_dir is not None:
        target = Path(out_dir) / "gui" / "evidence_graph.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(graph, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        graph["artifacts"] = [{"name": "gui/evidence_graph.json", "path": str(target), "kind": "gui-evidence-graph"}]
    return graph


def _normalize_node(raw: Mapping[str, Any], *, source: str, index: int) -> Dict[str, Any]:
    properties = dict(raw.get("properties") or {}) if isinstance(raw.get("properties"), Mapping) else {}
    style = dict(raw.get("style") or {}) if isinstance(raw.get("style"), Mapping) else {}
    handlers = dict(raw.get("event_handlers") or {}) if isinstance(raw.get("event_handlers"), Mapping) else {}
    raw_node_id = raw.get("id") or raw.get("name") or raw.get("resource_id") or raw.get("automation_id")
    source_path = raw.get("source_path")
    source_scope = _source_scope(source, source_path)
    node_id = _scoped_identifier(raw_node_id or f"{source}_{index + 1}", source_scope)
    parent_id = raw.get("parent_id")
    if parent_id not in (None, ""):
        parent_id = _scoped_identifier(parent_id, source_scope)
    node_type = _control_type(raw.get("type") or raw.get("class_name") or raw.get("class") or "Control")
    text = raw.get("text") or raw.get("title") or raw.get("content") or raw.get("header") or properties.get("Content") or properties.get("Text")
    bbox = _normalize_bbox(raw.get("bbox") or raw.get("bounds"))
    confidence = _float(raw.get("confidence"), default=_source_confidence(source))
    evidence = _mapping_list(raw.get("evidence"))
    evidence.append({"source": source, "confidence": confidence})
    return {
        "id": str(node_id),
        "source_id": str(raw_node_id or f"{source}_{index + 1}"),
        "source": source,
        "source_path": str(source_path) if source_path not in (None, "") else None,
        "type": node_type,
        "text": str(text) if text not in (None, "") else None,
        "bbox": bbox,
        "properties": properties,
        "style": style,
        "event_handlers": {str(key): str(value) for key, value in handlers.items() if value not in (None, "")},
        "parent_id": parent_id,
        "evidence": evidence,
        "confidence": round(max(0.0, min(0.99, confidence)), 3),
    }


def _runtime_nodes(runtime_tree: Mapping[str, Any]) -> tuple[list[Dict[str, Any]], str | None]:
    nodes: list[Dict[str, Any]] = []
    title: str | None = None
    for window_index, window in enumerate(_mapping_list(runtime_tree.get("windows"))):
        if title is None and window.get("title"):
            title = str(window.get("title"))
        for control_index, control in enumerate(_mapping_list(window.get("controls"))):
            item = dict(control)
            item.setdefault("id", item.get("handle") or item.get("resource_id") or f"runtime_{window_index}_{control_index}")
            item.setdefault("text", item.get("text") or item.get("title") or item.get("content_description"))
            nodes.append(item)
    return nodes, title


def _visual_nodes(visual: Mapping[str, Any]) -> list[Dict[str, Any]]:
    nodes: list[Dict[str, Any]] = []
    for index, widget in enumerate(_mapping_list(visual.get("widgets"))):
        item = dict(widget)
        item.setdefault("id", f"visual_widget_{index + 1}")
        item.setdefault("type", item.get("type") or "Control")
        nodes.append(item)
    for index, region in enumerate(_mapping_list(visual.get("text_regions"))):
        item = dict(region)
        item.setdefault("id", f"visual_text_{index + 1}")
        item.setdefault("type", "TextBlock")
        nodes.append(item)
    return nodes


def _find_match(existing: Iterable[Dict[str, Any]], candidate: Mapping[str, Any]) -> Dict[str, Any] | None:
    candidate_id = str(candidate.get("id") or "")
    candidate_text = str(candidate.get("text") or "").strip().casefold()
    candidate_type = _control_type(candidate.get("type"))
    candidate_bbox = candidate.get("bbox") if isinstance(candidate.get("bbox"), Mapping) else None
    for node in existing:
        # Static XAML nodes are already an exact description of source layout;
        # never fuse two of them merely because designers reused text or local
        # element IDs in separate XAML documents.
        if str(candidate.get("source") or "") == "xaml" and _has_evidence_source(node, "xaml"):
            continue
        node_id = str(node.get("id") or "")
        if candidate_id and node_id == candidate_id and not candidate_id.startswith(("runtime_", "visual_")) and _types_compatible(candidate_type, _control_type(node.get("type"))):
            return node
        node_text = str(node.get("text") or "").strip().casefold()
        if candidate_text and node_text == candidate_text:
            return node
        node_bbox = node.get("bbox") if isinstance(node.get("bbox"), Mapping) else None
        if candidate_bbox and node_bbox and _bbox_iou(candidate_bbox, node_bbox) >= 0.55 and _types_compatible(candidate_type, _control_type(node.get("type"))):
            return node
    return None


def _source_scope(source: str, source_path: Any) -> str | None:
    """Scope XAML-local IDs so separate documents cannot collide in one graph."""

    if source != "xaml" or source_path in (None, ""):
        return None
    digest = hashlib.sha1(str(source_path).encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"xaml_{digest}"


def _scoped_identifier(value: Any, scope: str | None) -> str:
    identifier = str(value)
    return f"{scope}_{identifier}" if scope else identifier


def _has_evidence_source(node: Mapping[str, Any], source: str) -> bool:
    if str(node.get("source") or "") == source:
        return True
    return any(
        isinstance(item, Mapping) and str(item.get("source") or "") == source
        for item in node.get("evidence") or []
    )


def _merge_node(target: Dict[str, Any], candidate: Mapping[str, Any]) -> None:
    for key in ("text", "bbox", "parent_id"):
        if target.get(key) in (None, "", {}):
            target[key] = candidate.get(key)
    for key in ("properties", "style", "event_handlers"):
        merged = dict(target.get(key) or {})
        for item_key, value in (candidate.get(key) or {}).items():
            merged.setdefault(item_key, value)
        target[key] = merged
    evidence = list(target.get("evidence") or [])
    for item in candidate.get("evidence") or []:
        if not isinstance(item, Mapping):
            continue
        signature = (str(item.get("source")), str(item.get("detail") or ""))
        if any((str(current.get("source")), str(current.get("detail") or "")) == signature for current in evidence if isinstance(current, Mapping)):
            continue
        evidence.append(dict(item))
    target["evidence"] = evidence
    old_confidence = _float(target.get("confidence"))
    new_confidence = _float(candidate.get("confidence"))
    target["confidence"] = round(min(0.99, 1.0 - (1.0 - old_confidence) * (1.0 - new_confidence)), 3)


def _parent_edges(nodes: Sequence[Mapping[str, Any]]) -> list[Dict[str, str]]:
    known = {str(node.get("id")) for node in nodes}
    return [
        {"source": str(node.get("parent_id")), "target": str(node.get("id")), "type": "contains"}
        for node in nodes
        if node.get("parent_id") and str(node.get("parent_id")) in known
    ]


def _function_names(decompiler: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in _mapping_list(decompiler.get("functions")):
        if item.get("name"):
            names.add(str(item.get("name")))
    return names


def _control_type(value: Any) -> str:
    text = str(value or "Control").split(".")[-1].split(":")[-1]
    aliases = {"text": "TextBlock", "label": "Label", "button": "Button", "edit": "TextBox", "checkbox": "CheckBox", "combobox": "ComboBox", "listview": "ListView"}
    return aliases.get(text.casefold(), text or "Control")


def _types_compatible(left: str, right: str) -> bool:
    return left.casefold() == right.casefold() or {left.casefold(), right.casefold()} <= {"label", "textblock"}


def _normalize_bbox(value: Any) -> Dict[str, float] | None:
    if not isinstance(value, Mapping):
        return None
    x = value.get("x", value.get("left"))
    y = value.get("y", value.get("top"))
    width = value.get("width")
    height = value.get("height")
    if any(item is None for item in (x, y, width, height)):
        return None
    return {"x": _float(x), "y": _float(y), "width": max(0.0, _float(width)), "height": max(0.0, _float(height))}


def _bbox_iou(left: Mapping[str, Any], right: Mapping[str, Any]) -> float:
    lx, ly, lw, lh = (_float(left.get(key)) for key in ("x", "y", "width", "height"))
    rx, ry, rw, rh = (_float(right.get(key)) for key in ("x", "y", "width", "height"))
    overlap_width = max(0.0, min(lx + lw, rx + rw) - max(lx, rx))
    overlap_height = max(0.0, min(ly + lh, ry + rh) - max(ly, ry))
    overlap = overlap_width * overlap_height
    union = lw * lh + rw * rh - overlap
    return overlap / union if union > 0 else 0.0


def _source_confidence(source: str) -> float:
    return {"xaml": 0.95, "runtime": 0.85, "visual": 0.65}.get(source, 0.5)


def _graph_confidence(fingerprint: Mapping[str, Any], nodes: Sequence[Mapping[str, Any]]) -> float:
    values = [_float(fingerprint.get("confidence"))]
    values.extend(_float(node.get("confidence")) for node in nodes)
    return round(sum(values) / len(values), 3) if values else 0.0


def _mapping_list(value: Any) -> list[Dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
