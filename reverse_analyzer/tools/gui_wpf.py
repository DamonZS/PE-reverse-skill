"""Evidence-driven WPF project rendering.

The renderer deliberately keeps its inputs and outputs as plain mappings so it
can be called by the GUI orchestration layer without importing that layer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import html
import math
from pathlib import Path
import re
from typing import Any


_CONTROL_TYPES = {
    "button": "Button",
    "label": "Label",
    "textblock": "TextBlock",
    "textbox": "TextBox",
    "checkbox": "CheckBox",
    "combobox": "ComboBox",
    "listview": "ListView",
}

_STRUCTURAL_NODE_TYPES = {
    "window",
    "grid",
    "stackpanel",
    "canvas",
    "dockpanel",
    "wrappanel",
    "scrollviewer",
}

_EVENTS_BY_CONTROL = {
    "Button": {"Click"},
    "CheckBox": {"Click", "Checked", "Unchecked"},
    "TextBox": {"TextChanged"},
    "ComboBox": {"SelectionChanged"},
    "ListView": {"SelectionChanged"},
}

_EVENT_NAMES = {
    "click": "Click",
    "checked": "Checked",
    "unchecked": "Unchecked",
    "textchanged": "TextChanged",
    "selectionchanged": "SelectionChanged",
}

_EVENT_ARGUMENT_TYPES = {
    "Click": "RoutedEventArgs",
    "Checked": "RoutedEventArgs",
    "Unchecked": "RoutedEventArgs",
    "TextChanged": "TextChangedEventArgs",
    "SelectionChanged": "SelectionChangedEventArgs",
}

_CSHARP_KEYWORDS = {
    "abstract",
    "as",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sbyte",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
}

_IDENTIFIER_CHARACTERS = re.compile(r"[^A-Za-z0-9_]+")


def generate_wpf_project(project_dir: str | Path, evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Generate a small, buildable WPF project from normalized GUI evidence."""

    destination = Path(project_dir)
    nodes = _nodes_from_evidence(evidence)
    used_identifiers = {"App", "InitializeComponent", "MainWindow"}
    handler_names = _handler_names(nodes, used_identifiers)

    positioned_controls: list[str] = []
    fallback_controls: list[str] = []
    for index, node in enumerate(nodes, start=1):
        control, has_bbox = _render_control(node, index, handler_names, used_identifiers)
        if has_bbox:
            positioned_controls.append(control)
        else:
            fallback_controls.append(control)

    title = _window_value(evidence, "Title", "Reconstructed GUI")
    width = _window_value(evidence, "Width", "900")
    height = _window_value(evidence, "Height", "640")
    contents = _render_layout(positioned_controls, fallback_controls)

    generated_contents = {
        "ReconstructedGui.csproj": _project_file(),
        "App.xaml": _app_xaml(),
        "App.xaml.cs": _app_code_behind(),
        "src/MainWindow.xaml": _main_window_xaml(title, width, height, contents),
        "src/MainWindow.xaml.cs": _main_window_code_behind(handler_names),
    }
    generated_files = {
        relative_path: _write_file(destination / relative_path, content)
        for relative_path, content in generated_contents.items()
    }
    artifacts = [
        {
            "name": relative_path,
            "path": path,
            "kind": "wpf-project-file",
        }
        for relative_path, path in generated_files.items()
    ]

    return {
        "status": "ok",
        "project_dir": str(destination),
        "generated_files": generated_files,
        "control_count": len(nodes),
        "event_handler_count": len({name for name, _ in handler_names.values()}),
        "artifacts": artifacts,
    }


def _nodes_from_evidence(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw_nodes = evidence.get("nodes") if isinstance(evidence, Mapping) else None
    if not isinstance(raw_nodes, Sequence) or isinstance(raw_nodes, (str, bytes, bytearray)):
        return []
    return [
        node
        for node in raw_nodes
        if isinstance(node, Mapping) and not _is_structural_node(node)
    ]


def _is_structural_node(node: Mapping[str, Any]) -> bool:
    value = node.get("type") or node.get("class_name") or node.get("class")
    normalized = re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())
    return normalized in _STRUCTURAL_NODE_TYPES


def _handler_names(nodes: Sequence[Mapping[str, Any]], used_identifiers: set[str]) -> dict[tuple[str, str], tuple[str, str]]:
    """Build valid, deduplicated C# handler bindings keyed by handler and event type."""

    names: dict[tuple[str, str], tuple[str, str]] = {}
    names_by_signature: dict[tuple[str, str], tuple[str, str]] = {}
    for node in nodes:
        control_type = _control_type(node.get("type") or node.get("class_name") or node.get("class"))
        for event_name, handler in _event_handlers(node).items():
            canonical_event = _canonical_event_name(event_name)
            if not (
                handler
                and canonical_event
                and canonical_event in _EVENTS_BY_CONTROL.get(control_type, set())
            ):
                continue
            key = (handler, canonical_event)
            if key not in names:
                event_argument_type = _EVENT_ARGUMENT_TYPES[canonical_event]
                signature = (handler, event_argument_type)
                names_by_signature.setdefault(
                    signature,
                    (_identifier(handler, "Handler", used_identifiers), event_argument_type),
                )
                names[key] = names_by_signature[signature]
    return names


def _event_handlers(node: Mapping[str, Any]) -> dict[str, str]:
    raw_handlers = node.get("event_handlers")
    if not isinstance(raw_handlers, Mapping):
        return {}
    handlers: dict[str, str] = {}
    for event_name, handler_name in raw_handlers.items():
        if handler_name is None:
            continue
        handler = str(handler_name).strip()
        if handler:
            handlers[str(event_name)] = handler
    return handlers


def _render_control(
    node: Mapping[str, Any],
    index: int,
    handler_names: Mapping[tuple[str, str], tuple[str, str]],
    used_identifiers: set[str],
) -> tuple[str, bool]:
    control_type = _control_type(node.get("type") or node.get("class_name") or node.get("class"))
    properties = _properties(node)
    node_id = _first_value(node.get("id"), node.get("name"), f"Control_{index}")
    xaml_name = _identifier(node_id, "Control", used_identifiers)
    bbox = _bbox(node)

    attributes: list[tuple[str, str]] = [("x:Name", xaml_name)]
    _append_dimension(attributes, "Width", _property_or_bbox(properties, "Width", bbox, "width"))
    _append_dimension(attributes, "Height", _property_or_bbox(properties, "Height", bbox, "height"))
    tooltip = _first_value(_property(properties, "ToolTip"), _property(properties, "Title"))
    if tooltip is not None:
        attributes.append(("ToolTip", tooltip))
    if bbox is not None:
        attributes.append(("Canvas.Left", bbox["x"]))
        attributes.append(("Canvas.Top", bbox["y"]))

    handlers = _event_handlers(node)
    attached_events: set[str] = set()
    for event_name, handler in handlers.items():
        canonical_event = _canonical_event_name(event_name)
        if (
            canonical_event
            and canonical_event not in attached_events
            and canonical_event in _EVENTS_BY_CONTROL.get(control_type, set())
            and (handler, canonical_event) in handler_names
        ):
            attributes.append((canonical_event, handler_names[(handler, canonical_event)][0]))
            attached_events.add(canonical_event)

    if control_type in {"Button", "Label", "CheckBox"}:
        content = _content_value(node, properties)
        if content is not None:
            attributes.append(("Content", content))
    elif control_type in {"TextBlock", "TextBox"}:
        text = _text_value(node, properties)
        if text is not None:
            attributes.append(("Text", text))

    items = _items_value(node, properties) if control_type in {"ComboBox", "ListView"} else []
    if items:
        item_type = "ComboBoxItem" if control_type == "ComboBox" else "ListViewItem"
        children = [f'<{item_type} Content="{_xml_escape(item)}" />' for item in items]
        return _render_element(control_type, attributes, children), bbox is not None
    return _render_element(control_type, attributes), bbox is not None


def _control_type(value: Any) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())
    if normalized in _CONTROL_TYPES:
        return _CONTROL_TYPES[normalized]
    for token, control_type in _CONTROL_TYPES.items():
        if normalized.endswith(token):
            return control_type
    return "TextBlock"


def _properties(node: Mapping[str, Any]) -> Mapping[str, Any]:
    properties = node.get("properties")
    return properties if isinstance(properties, Mapping) else {}


def _property(properties: Mapping[str, Any], name: str) -> str | None:
    for key, value in properties.items():
        if str(key).casefold() == name.casefold() and value is not None:
            text = str(value)
            if text:
                return text
    return None


def _first_value(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value)
        if text:
            return text
    return None


def _content_value(node: Mapping[str, Any], properties: Mapping[str, Any]) -> str | None:
    return _first_value(
        _property(properties, "Content"),
        node.get("content"),
        node.get("text"),
        _property(properties, "Text"),
        node.get("title"),
    )


def _text_value(node: Mapping[str, Any], properties: Mapping[str, Any]) -> str | None:
    return _first_value(
        _property(properties, "Text"),
        node.get("text"),
        _property(properties, "Content"),
        node.get("content"),
        node.get("title"),
    )


def _items_value(node: Mapping[str, Any], properties: Mapping[str, Any]) -> list[str]:
    raw_items = _property_value(properties, "Items")
    if isinstance(raw_items, Sequence) and not isinstance(raw_items, (str, bytes, bytearray)):
        return [str(item) for item in raw_items if item is not None]
    text = _text_value(node, properties)
    return [text] if text is not None else []


def _property_value(properties: Mapping[str, Any], name: str) -> Any:
    for key, value in properties.items():
        if str(key).casefold() == name.casefold():
            return value
    return None


def _bbox(node: Mapping[str, Any]) -> dict[str, str] | None:
    raw_bbox = node.get("bbox") if node.get("bbox") is not None else node.get("bounds")
    values: tuple[Any, Any, Any, Any] | None = None
    if isinstance(raw_bbox, Mapping):
        values = (
            _mapping_value(raw_bbox, "x", "left"),
            _mapping_value(raw_bbox, "y", "top"),
            _mapping_value(raw_bbox, "width", "w"),
            _mapping_value(raw_bbox, "height", "h"),
        )
    elif isinstance(raw_bbox, Sequence) and not isinstance(raw_bbox, (str, bytes, bytearray)) and len(raw_bbox) >= 4:
        values = (raw_bbox[0], raw_bbox[1], raw_bbox[2], raw_bbox[3])
    if values is None:
        return None
    x, y, width, height = (_number(value) for value in values)
    if None in {x, y, width, height}:
        return None
    return {"x": x, "y": y, "width": width, "height": height}


def _mapping_value(mapping: Mapping[Any, Any], *names: str) -> Any:
    normalized_names = {name.casefold() for name in names}
    for key, value in mapping.items():
        if str(key).casefold() in normalized_names:
            return value
    return None


def _number(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return str(int(number)) if number.is_integer() else format(number, ".15g")


def _property_or_bbox(
    properties: Mapping[str, Any],
    property_name: str,
    bbox: Mapping[str, str] | None,
    bbox_name: str,
) -> str | None:
    value = _property(properties, property_name)
    if value is not None:
        return value
    return bbox.get(bbox_name) if bbox is not None else None


def _append_dimension(attributes: list[tuple[str, str]], name: str, value: str | None) -> None:
    if value is not None:
        attributes.append((name, value))


def _canonical_event_name(value: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", "", value.casefold())
    if normalized.startswith("on"):
        normalized = normalized[2:]
    return _EVENT_NAMES.get(normalized)


def _identifier(value: Any, prefix: str, used_identifiers: set[str]) -> str:
    candidate = _IDENTIFIER_CHARACTERS.sub("_", str(value or "").strip()).strip("_")
    if not candidate:
        candidate = prefix
    if candidate[0].isdigit() or candidate.casefold() in _CSHARP_KEYWORDS:
        candidate = f"{prefix}_{candidate}"
    base = candidate
    suffix = 2
    while candidate in used_identifiers:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used_identifiers.add(candidate)
    return candidate


def _render_element(tag: str, attributes: Sequence[tuple[str, str]], children: Sequence[str] | None = None) -> str:
    rendered_attributes = " ".join(f'{name}="{_xml_escape(value)}"' for name, value in attributes)
    opening = f"<{tag}{(' ' + rendered_attributes) if rendered_attributes else ''}"
    if not children:
        return f"{opening} />"
    lines = [f"{opening}>"]
    lines.extend(f"  {child}" for child in children)
    lines.append(f"</{tag}>")
    return "\n".join(lines)


def _render_layout(positioned_controls: Sequence[str], fallback_controls: Sequence[str]) -> str:
    if positioned_controls and fallback_controls:
        return "\n".join(
            [
                "    <Grid>",
                "      <Grid.RowDefinitions>",
                "        <RowDefinition Height=\"*\" />",
                "        <RowDefinition Height=\"Auto\" />",
                "      </Grid.RowDefinitions>",
                "      <Canvas Grid.Row=\"0\">",
                *_indented(positioned_controls, 8),
                "      </Canvas>",
                "      <StackPanel Grid.Row=\"1\" Margin=\"12\">",
                *_indented(fallback_controls, 8),
                "      </StackPanel>",
                "    </Grid>",
            ]
        )
    if positioned_controls:
        return "\n".join(["    <Canvas>", *_indented(positioned_controls, 6), "    </Canvas>"])
    if fallback_controls:
        return "\n".join(["    <StackPanel Margin=\"12\">", *_indented(fallback_controls, 6), "    </StackPanel>"])
    return "    <Grid />"


def _indented(elements: Sequence[str], spaces: int) -> list[str]:
    indentation = " " * spaces
    return [f"{indentation}{line}" for element in elements for line in element.splitlines()]


def _window_value(evidence: Mapping[str, Any], name: str, default: str) -> str:
    properties = evidence.get("properties") if isinstance(evidence.get("properties"), Mapping) else {}
    return _first_value(
        _property(properties, name),
        _property_value(evidence, name),
        default,
    ) or default


def _project_file() -> str:
    return """<Project Sdk=\"Microsoft.NET.Sdk\">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net8.0-windows</TargetFramework>
    <UseWPF>true</UseWPF>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"""


def _app_xaml() -> str:
    return """<Application x:Class=\"ReconstructedGui.App\"
             xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\"
             xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"
             StartupUri=\"src/MainWindow.xaml\">
  <Application.Resources />
</Application>
"""


def _app_code_behind() -> str:
    return """namespace ReconstructedGui;

public partial class App : System.Windows.Application
{
}
"""


def _main_window_xaml(title: str, width: str, height: str, contents: str) -> str:
    return "\n".join(
        [
            '<Window x:Class="ReconstructedGui.MainWindow"',
            '        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"',
            '        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"',
            f'        Title="{_xml_escape(title)}"',
            f'        Width="{_xml_escape(width)}"',
            f'        Height="{_xml_escape(height)}">',
            contents,
            "</Window>",
            "",
        ]
    )


def _main_window_code_behind(handler_names: Mapping[tuple[str, str], tuple[str, str]]) -> str:
    lines = [
        "using System.Windows;",
        "using System.Windows.Controls;",
        "",
        "namespace ReconstructedGui;",
        "",
        "public partial class MainWindow : Window",
        "{",
        "    public MainWindow()",
        "    {",
        "        InitializeComponent();",
        "    }",
    ]
    emitted_handlers: set[str] = set()
    for handler_name, event_argument_type in handler_names.values():
        if handler_name in emitted_handlers:
            continue
        emitted_handlers.add(handler_name)
        lines.extend(
            [
                "",
                f"    private void {handler_name}(object sender, {event_argument_type} e)",
                "    {",
                "    }",
            ]
        )
    lines.extend(["}", ""])
    return "\n".join(lines)


def _write_file(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return str(path)


def _xml_escape(value: Any) -> str:
    text = "".join(character for character in str(value) if _is_valid_xml_character(character))
    return html.escape(text, quote=True)


def _is_valid_xml_character(character: str) -> bool:
    codepoint = ord(character)
    return codepoint in {0x9, 0xA, 0xD} or 0x20 <= codepoint <= 0xD7FF or 0xE000 <= codepoint <= 0xFFFD or 0x10000 <= codepoint <= 0x10FFFF
