"""Dependency-free WPF/XAML static UI evidence extraction."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET


XAML_NS = "http://schemas.microsoft.com/winfx/2006/xaml"
SUPPORTED_WPF_CONTROLS = frozenset(
    {
        "Window",
        "Grid",
        "StackPanel",
        "Button",
        "Label",
        "TextBox",
        "TextBlock",
        "CheckBox",
        "ComboBox",
        "ListView",
    }
)
EVENT_ATTRIBUTES = frozenset(
    {
        "Activated",
        "CanExecute",
        "Checked",
        "Click",
        "Closed",
        "Closing",
        "Command",
        "Deactivated",
        "DragEnter",
        "DragLeave",
        "DragOver",
        "Drop",
        "GotFocus",
        "KeyDown",
        "KeyUp",
        "Loaded",
        "LostFocus",
        "MouseDown",
        "MouseEnter",
        "MouseLeave",
        "MouseMove",
        "MouseUp",
        "PreviewKeyDown",
        "PreviewKeyUp",
        "PreviewMouseDown",
        "PreviewMouseUp",
        "SelectionChanged",
        "TextChanged",
        "Unchecked",
        "Unloaded",
    }
)


def parse_xaml_file(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Parse a XAML document into GUI Evidence Graph-compatible control nodes."""

    path_text = _display_path(path)
    result: dict[str, Any] = {
        "status": "error",
        "source": "xaml",
        "path": path_text,
        "title": None,
        "root_type": None,
        "nodes": [],
        "errors": [],
        "confidence": 0.0,
        "evidence": [],
    }
    try:
        root = ET.parse(Path(path)).getroot()
    except ET.ParseError as exc:
        result["errors"].append(_error("xml_parse_error", str(exc), path_text))
        return result
    except (OSError, UnicodeError) as exc:
        result["errors"].append(_error("file_read_error", str(exc), path_text))
        return result
    except (TypeError, ValueError) as exc:
        result["errors"].append(_error("invalid_path", str(exc), path_text))
        return result

    nodes: list[dict[str, Any]] = []
    state: dict[str, Any] = {"index": 0, "ids": {}}
    root_type = _local_name(root.tag)
    _walk(root, None, f"/{root_type}[0]", path_text, state, nodes)
    root_attrs = _attributes(root)
    result.update(
        {
            "status": "ok",
            "root_type": root_type,
            "title": _text_value(root_type, root_attrs, root),
            "nodes": nodes,
            "confidence": 0.98,
            "evidence": [
                {
                    "source": "xaml",
                    "type": "xaml_document",
                    "path": path_text,
                    "detail": f"Parsed {len(nodes)} supported WPF control node(s).",
                }
            ],
        }
    )
    return result


def extract_xaml_ui_evidence(
    paths: Iterable[str | os.PathLike[str]] | str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Aggregate one or more XAML files without failing the whole pipeline."""

    if isinstance(paths, (str, os.PathLike)):
        values: list[Any] = [paths]
    else:
        try:
            values = list(paths)
        except TypeError:
            values = [paths]
    files = [parse_xaml_file(path) for path in values]
    successful = [item for item in files if item["status"] == "ok"]
    errors = [error for item in files for error in item["errors"]]
    nodes = [node for item in successful for node in item["nodes"]]
    title = next((item["title"] for item in successful if item["title"]), None)
    result = {
        "status": "partial" if successful and errors else ("error" if errors else ("ok" if successful else "unavailable")),
        "source": "xaml",
        "paths": [item["path"] for item in files],
        "files": files,
        "title": title,
        "nodes": nodes,
        "node_count": len(nodes),
        "errors": errors,
        "confidence": round(sum(float(item["confidence"]) for item in successful) / len(successful), 3) if successful else 0.0,
        "evidence": [
            {
                "source": "xaml",
                "type": "xaml_file",
                "path": item["path"],
                "detail": f"Parsed {len(item['nodes'])} supported WPF control node(s).",
            }
            for item in successful
        ],
    }
    if out_dir is not None:
        target = Path(out_dir) / "gui" / "xaml_evidence.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        result["artifacts"] = [{"name": "gui/xaml_evidence.json", "path": str(target), "kind": "gui-xaml-evidence"}]
    return result


def _walk(
    element: ET.Element,
    parent_id: str | None,
    element_path: str,
    source_path: str,
    state: dict[str, Any],
    nodes: list[dict[str, Any]],
) -> None:
    control_type = _local_name(element.tag)
    current_parent = parent_id
    if control_type in SUPPORTED_WPF_CONTROLS:
        state["index"] += 1
        attrs = _attributes(element)
        requested_id = _clean(attrs.get("x:Name")) or _clean(attrs.get("Name")) or f"{control_type.lower()}_{state['index']}"
        control_id = _unique_id(requested_id, state["ids"])
        properties, handlers = _split_attributes(attrs)
        nodes.append(
            {
                "id": control_id,
                "type": control_type,
                "text": _text_value(control_type, attrs, element),
                "bbox": _bbox(attrs),
                "properties": properties,
                "event_handlers": handlers,
                "evidence": [
                    {
                        "source": "xaml",
                        "type": "xaml_element",
                        "path": element_path,
                        "detail": f"Parsed <{control_type}> element.",
                    }
                ],
                "confidence": 0.98,
                "source": "xaml",
                "source_path": source_path,
                "parent_id": parent_id,
            }
        )
        current_parent = control_id
    for index, child in enumerate(list(element)):
        child_type = _local_name(child.tag)
        _walk(child, current_parent, f"{element_path}/{child_type}[{index}]", source_path, state, nodes)


def _attributes(element: ET.Element) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in element.attrib.items():
        if key.startswith("{") and "}" in key:
            namespace, local = key[1:].split("}", 1)
            key = f"x:{local}" if namespace == XAML_NS else local
        result[key] = value
    return result


def _local_name(name: str) -> str:
    if name.startswith("{") and "}" in name:
        return name.split("}", 1)[1]
    return name.split(":", 1)[-1]


def _split_attributes(attrs: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    properties: dict[str, str] = {}
    handlers: dict[str, str] = {}
    for name, value in attrs.items():
        if name in {"x:Name", "Name"}:
            continue
        if name in EVENT_ATTRIBUTES or (name.endswith(("Click", "Changed", "Command", "Checked", "Unchecked")) and name not in {"CommandParameter", "CommandTarget"}):
            handlers[name] = value
        else:
            properties[name] = value
    return dict(sorted(properties.items())), dict(sorted(handlers.items()))


def _text_value(control_type: str, attrs: dict[str, str], element: ET.Element) -> str | None:
    for name in ("Text", "Content", "Header", "Title"):
        value = _clean(attrs.get(name))
        if value:
            return value
    for name in ("Text", "Content", "Header", "Title"):
        property_tag = f"{control_type}.{name}"
        for child in element:
            if _local_name(child.tag) == property_tag:
                value = _clean(" ".join(child.itertext()))
                if value:
                    return value
    return _clean(element.text)


def _bbox(attrs: dict[str, str]) -> dict[str, float] | None:
    try:
        return {
            "x": float(attrs["Canvas.Left"]),
            "y": float(attrs["Canvas.Top"]),
            "width": float(attrs["Width"]),
            "height": float(attrs["Height"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _unique_id(value: str, counts: dict[str, int]) -> str:
    counts[value] = counts.get(value, 0) + 1
    return value if counts[value] == 1 else f"{value}__{counts[value]}"


def _clean(value: str | None) -> str | None:
    return " ".join(value.split()) or None if value is not None else None


def _display_path(path: object) -> str:
    try:
        return os.fsdecode(os.fspath(path))
    except TypeError:
        return str(path)


def _error(error_type: str, message: str, path: str) -> dict[str, str]:
    return {"type": error_type, "kind": error_type, "message": message, "path": path, "source": "xaml"}
