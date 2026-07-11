"""Stub project reconstruction helpers.

This module turns reverse-analysis output into a small, compilable C project
skeleton. The generated code is intentionally approximate and only provides
placeholders for manual reconstruction.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

MODULE_ORDER = ("loader", "process", "network", "crypto", "core")


def reconstruct_project(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    analysis: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Generate a compilable reconstruction skeleton for a sample.

    The output is a stub project only; it does not attempt to recreate the
    original source code faithfully.
    """

    sample = Path(path)
    if not sample.is_file():
        raise FileNotFoundError(str(sample))

    analysis = analysis or {}
    project_dir = Path(out_dir) / f"reconstructed_{_safe_name(sample.stem)}"
    src_dir = project_dir / "src"
    include_dir = project_dir / "include"
    analysis_dir = project_dir / "analysis"
    for directory in (src_dir, include_dir, analysis_dir):
        directory.mkdir(parents=True, exist_ok=True)

    functions = _normalize_functions(analysis.get("functions"))
    imports = _normalize_imports(_merge_analysis_lists(analysis, "imports", "imports_xrefs"))
    call_graph = _normalize_call_graph(analysis.get("call_graph"))
    strings_xrefs = _normalize_string_xrefs(analysis.get("strings_xrefs"))
    imports_xrefs = _normalize_import_xrefs(analysis.get("imports_xrefs"))
    dynamic_evidence = _normalize_dynamic_evidence(analysis.get("dynamic_evidence"))
    semantic_ir = _normalize_semantic_ir(analysis.get("semantic_ir"))
    semantic_ir_summary = _semantic_ir_summary(semantic_ir)
    module_map = _build_module_map(functions, call_graph, strings_xrefs, imports_xrefs, dynamic_evidence)
    reconstruction_plan = _build_reconstruction_plan(module_map)
    if semantic_ir_summary:
        reconstruction_plan["semantic_ir"] = semantic_ir_summary
    summary_payload = _build_summary(
        sample,
        functions,
        imports,
        analysis.get("summary"),
        call_graph=call_graph,
        strings_xrefs=strings_xrefs,
        imports_xrefs=imports_xrefs,
        dynamic_evidence=dynamic_evidence,
        module_map=module_map,
        reconstruction_plan=reconstruction_plan,
        semantic_ir=semantic_ir_summary,
    )

    file_map = {
        "CMakeLists.txt": project_dir / "CMakeLists.txt",
        "src/main.c": src_dir / "main.c",
        "src/functions.c": src_dir / "functions.c",
        "include/imports.h": include_dir / "imports.h",
        "analysis/call_graph.json": analysis_dir / "call_graph.json",
        "analysis/strings_xrefs.json": analysis_dir / "strings_xrefs.json",
        "analysis/imports_xrefs.json": analysis_dir / "imports_xrefs.json",
        "analysis/dynamic_evidence.json": analysis_dir / "dynamic_evidence.json",
        "analysis/module_map.json": analysis_dir / "module_map.json",
        "analysis/reconstruction_plan.json": analysis_dir / "reconstruction_plan.json",
        "analysis/summary.json": analysis_dir / "summary.json",
        "README.md": project_dir / "README.md",
    }
    if semantic_ir:
        file_map["analysis/semantic_ir.json"] = analysis_dir / "semantic_ir.json"
    module_files = _module_files(src_dir, module_map)
    file_map.update(module_files)

    c_sources = [name for name in file_map if name.startswith("src/") and name.endswith(".c")]
    file_map["CMakeLists.txt"].write_text(_render_cmake(project_dir.name, c_sources), encoding="utf-8")
    file_map["src/main.c"].write_text(_render_main(sample.name), encoding="utf-8")
    file_map["src/functions.c"].write_text(_render_entry_source(module_map), encoding="utf-8")
    file_map["include/imports.h"].write_text(_render_imports_header(imports), encoding="utf-8")
    file_map["analysis/call_graph.json"].write_text(json.dumps(call_graph, indent=2), encoding="utf-8")
    file_map["analysis/strings_xrefs.json"].write_text(json.dumps(strings_xrefs, indent=2), encoding="utf-8")
    file_map["analysis/imports_xrefs.json"].write_text(json.dumps(imports_xrefs, indent=2), encoding="utf-8")
    file_map["analysis/dynamic_evidence.json"].write_text(json.dumps(dynamic_evidence, indent=2), encoding="utf-8")
    file_map["analysis/module_map.json"].write_text(json.dumps(module_map, indent=2), encoding="utf-8")
    file_map["analysis/reconstruction_plan.json"].write_text(json.dumps(reconstruction_plan, indent=2), encoding="utf-8")
    file_map["analysis/summary.json"].write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
    if semantic_ir:
        file_map["analysis/semantic_ir.json"].write_text(
            json.dumps(semantic_ir, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
            encoding="utf-8",
        )
    file_map["README.md"].write_text(_render_readme(sample.name, functions, imports, summary_payload), encoding="utf-8")

    for name, path_obj in module_files.items():
        module_name = Path(name).stem
        path_obj.write_text(_render_module_source(module_name, module_map["modules"].get(module_name) or []), encoding="utf-8")

    artifacts = [
        {"name": name, "path": str(path_obj), "kind": _artifact_kind(name)}
        for name, path_obj in file_map.items()
    ]
    generated_files = [str(path_obj) for path_obj in file_map.values()]
    return {
        "status": "ok",
        "project_dir": str(project_dir),
        "artifacts": artifacts,
        "generated_files": generated_files,
        "function_count": len(functions),
        "import_count": sum(len(item["functions"]) for item in imports),
        "module_count": len(module_map.get("modules") or {}),
        "module_files": [f"src/{name}.c" for name in module_map.get("files") or []],
        "prioritized_modules": module_map.get("priorities") or [],
        "high_value_functions": module_map.get("high_value_functions") or [],
        "dynamic_evidence_count": len(dynamic_evidence),
        "reconstruction_plan": reconstruction_plan,
        "task_count": len(reconstruction_plan.get("tasks") or []),
        "next_task": ((reconstruction_plan.get("tasks") or [{}])[0].get("name") if reconstruction_plan.get("tasks") else None),
        "semantic_ir": semantic_ir_summary,
        "stub_only": True,
    }


def _safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in value).strip("_")
    return cleaned or "sample"


def _normalize_functions(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw, start=1):
        if isinstance(item, dict):
            original_name = str(item.get("name") or item.get("symbol") or item.get("label") or f"function_{index}")
            comment_bits = []
            for key in ("entry", "address", "signature", "prototype"):
                value = item.get(key)
                if value:
                    comment_bits.append(f"{key}={value}")
            body_size = item.get("body_size")
            if body_size not in (None, ""):
                comment_bits.append(f"body_size={body_size}")
            calls = _extract_call_names(item.get("calls"))
            if calls:
                preview = ", ".join(calls[:5])
                if len(calls) > 5:
                    preview += " ..."
                comment_bits.append(f"calls={preview}")
            entry = str(item.get("entry") or item.get("address") or "")
        else:
            original_name = str(item or f"function_{index}")
            comment_bits = []
            body_size = None
            calls = []
            entry = ""
        identifier = _c_identifier(original_name, fallback=f"function_{index}")
        if identifier in seen:
            suffix = 2
            deduped = f"{identifier}_{suffix}"
            while deduped in seen:
                suffix += 1
                deduped = f"{identifier}_{suffix}"
            identifier = deduped
        seen.add(identifier)
        normalized.append(
            {
                "name": original_name,
                "identifier": identifier,
                "comment": ", ".join(comment_bits),
                "body_size": body_size,
                "calls": calls,
                "entry": entry,
            }
        )
    return normalized


def _normalize_imports(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    merged: Dict[str, Dict[str, Any]] = {}
    for item in raw:
        if isinstance(item, dict):
            library = str(item.get("dll") or item.get("library") or item.get("module") or "unknown")
            is_xref_style = item.get("label") is not None and (
                item.get("xrefs") is not None or item.get("xref_count") is not None or item.get("address") is not None
            )
            functions = item.get("functions")
            names = [] if is_xref_style else _extract_import_function_names(functions)
            if not names and item.get("name"):
                names = [str(item["name"])]
            if not names and item.get("label"):
                names = [str(item["label"])]
        else:
            library = "unknown"
            names = [str(item)]
        library_key = library.lower()
        entry = merged.setdefault(library_key, {"library": library, "functions": [], "_seen": set()})
        seen = entry["_seen"]
        for name in names:
            normalized_name = str(name).strip()
            if not normalized_name:
                continue
            key = normalized_name.lower()
            if key in seen:
                continue
            seen.add(key)
            entry["functions"].append(normalized_name)
    normalized: List[Dict[str, Any]] = []
    for item in merged.values():
        normalized.append({"library": item["library"], "functions": item["functions"]})
    return normalized


def _extract_import_function_names(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    names: List[str] = []
    for item in raw:
        if isinstance(item, dict):
            value = item.get("name") or item.get("symbol") or item.get("ordinal")
            if value is not None:
                names.append(str(value))
        elif item is not None:
            names.append(str(item))
    return names


def _extract_call_names(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    names: List[str] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, dict):
            value = item.get("name") or item.get("symbol") or item.get("label") or item.get("entry")
        else:
            value = item
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        names.append(text)
    return names


def _merge_analysis_lists(analysis: Dict[str, Any], *keys: str) -> List[Any]:
    merged: List[Any] = []
    for key in keys:
        value = analysis.get(key)
        if isinstance(value, list):
            merged.extend(value)
    return merged


def _normalize_call_graph(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {"nodes": [], "edges": []}
    nodes = raw.get("nodes") if isinstance(raw.get("nodes"), list) else []
    edges = raw.get("edges") if isinstance(raw.get("edges"), list) else []
    return {"nodes": nodes, "edges": edges}


def _normalize_string_xrefs(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        address = str(item.get("address") or item.get("addr") or "unknown")
        value = str(item.get("value") or item.get("string") or "").strip()
        if not value:
            continue
        key = (address.lower(), value.lower())
        if key in seen:
            continue
        seen.add(key)
        functions = _normalize_xref_functions(item.get("functions"))
        xrefs = _normalize_xref_entries(item.get("xrefs"))
        normalized.append(
            {
                "address": address,
                "value": value[:500],
                "xref_count": int(item.get("xref_count") or len(xrefs)),
                "functions": functions,
                "xrefs": xrefs,
            }
        )
    return normalized


def _normalize_import_xrefs(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        library = str(item.get("library") or item.get("dll") or item.get("module") or "unknown").strip() or "unknown"
        label = str(item.get("label") or item.get("name") or item.get("symbol") or "").strip()
        if not label:
            continue
        key = (library.lower(), label.lower())
        if key in seen:
            continue
        seen.add(key)
        functions = _normalize_xref_functions(item.get("functions"))
        xrefs = _normalize_xref_entries(item.get("xrefs"))
        normalized.append(
            {
                "library": library,
                "label": label,
                "address": str(item.get("address") or "unknown"),
                "xref_count": int(item.get("xref_count") or len(xrefs)),
                "functions": functions,
                "xrefs": xrefs,
            }
        )
    return normalized


def _normalize_xref_functions(raw: Any) -> List[Dict[str, str]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "unknown").strip() or "unknown"
        entry = str(item.get("entry") or "unknown").strip() or "unknown"
        key = (name.lower(), entry.lower())
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"name": name, "entry": entry})
    return normalized


def _normalize_xref_entries(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        from_address = str(item.get("from_address") or item.get("from") or "unknown").strip() or "unknown"
        ref_type = str(item.get("ref_type") or "unknown").strip() or "unknown"
        function_name = str(item.get("function_name") or item.get("name") or "").strip()
        function_entry = str(item.get("function_entry") or item.get("entry") or "").strip()
        key = (from_address.lower(), ref_type.lower(), function_entry.lower())
        if key in seen:
            continue
        seen.add(key)
        normalized_item: Dict[str, Any] = {"from_address": from_address, "ref_type": ref_type}
        if function_name:
            normalized_item["function_name"] = function_name
        if function_entry:
            normalized_item["function_entry"] = function_entry
        if item.get("operand_index") is not None:
            normalized_item["operand_index"] = item.get("operand_index")
        normalized.append(normalized_item)
    return normalized


def _normalize_dynamic_evidence(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        module = str(item.get("module") or "").strip().lower()
        if module not in MODULE_ORDER:
            module = "core"
        try:
            count = int(item.get("count") or 0)
        except (TypeError, ValueError):
            count = 0
        normalized.append(
            {
                "backend": str(item.get("backend") or "dynamic"),
                "module": module,
                "kind": str(item.get("kind") or "event"),
                "name": str(item.get("name") or "event"),
                "count": max(1, count),
                "detail": str(item.get("detail") or "")[:300],
            }
        )
    return normalized


def _normalize_semantic_ir(raw: Any) -> Dict[str, Any]:
    """Normalize semantic IR to strict, JSON-safe values at the boundary."""

    if not isinstance(raw, Mapping):
        return {}
    try:
        return _normalize_json_value(raw)
    except (RecursionError, TypeError, ValueError):
        return {}


def _normalize_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _normalize_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_json_value(item) for item in value]
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)


def _semantic_ir_summary(semantic_ir: Dict[str, Any]) -> Dict[str, Any]:
    if not semantic_ir:
        return {}
    supplied = semantic_ir.get("summary") if isinstance(semantic_ir.get("summary"), dict) else {}
    return {
        "schema_version": semantic_ir.get("schema_version"),
        "entity_count": _safe_count(supplied.get("entity_count"), _semantic_ir_item_count(semantic_ir.get("entities"))),
        "relation_count": _safe_count(supplied.get("relation_count"), _semantic_ir_item_count(semantic_ir.get("relations"))),
        "capability_count": _safe_count(supplied.get("capability_count"), _semantic_ir_item_count(semantic_ir.get("capabilities"))),
    }


def _semantic_ir_item_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _safe_count(value: Any, fallback: int = 0) -> int:
    try:
        return max(0, int(value))
    except (OverflowError, TypeError, ValueError):
        return fallback


def _build_summary(
    sample: Path,
    functions: List[Dict[str, Any]],
    imports: List[Dict[str, Any]],
    summary: Any,
    *,
    call_graph: Dict[str, Any],
    strings_xrefs: List[Dict[str, Any]],
    imports_xrefs: List[Dict[str, Any]],
    dynamic_evidence: List[Dict[str, Any]],
    module_map: Dict[str, Any],
    reconstruction_plan: Dict[str, Any],
    semantic_ir: Dict[str, Any],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "sample": sample.name,
        "source_path": str(sample),
        "project_type": "reconstruction_stub",
        "stub_only": True,
        "function_count": len(functions),
        "import_library_count": len(imports),
        "import_count": sum(len(item["functions"]) for item in imports),
        "notes": [
            "Generated by reverse_analyzer.tools.reconstruct.",
            "This output is a compilable scaffold, not a promise of source equivalence.",
        ],
        "call_graph": {
            "node_count": len(call_graph.get("nodes") or []),
            "edge_count": len(call_graph.get("edges") or []),
        },
        "string_xref_count": len(strings_xrefs),
        "import_xref_count": len(imports_xrefs),
        "string_xref_function_count": len(_xref_function_names(strings_xrefs)),
        "import_xref_function_count": len(_xref_function_names(imports_xrefs)),
        "dynamic_evidence_count": len(dynamic_evidence),
        "top_strings": [_string_xref_summary(item) for item in strings_xrefs[:5]],
        "top_imports": [_import_xref_summary(item) for item in imports_xrefs[:10]],
        "top_dynamic_evidence": [_dynamic_evidence_summary(item) for item in dynamic_evidence[:12]],
        "modules": {
            "module_count": len(module_map.get("modules") or {}),
            "function_count_by_module": {
                name: len(items)
                for name, items in (module_map.get("modules") or {}).items()
            },
            "files": [f"{name}.c" for name in module_map.get("files") or []],
            "priorities": module_map.get("priorities") or [],
            "high_value_functions": module_map.get("high_value_functions") or [],
            "dynamic_evidence_by_module": module_map.get("dynamic_evidence_by_module") or {},
        },
        "reconstruction_plan": {
            "task_count": len(reconstruction_plan.get("tasks") or []),
            "subtask_count": sum(len(task.get("subtasks") or []) for task in reconstruction_plan.get("tasks") or [] if isinstance(task, dict)),
            "next_task": ((reconstruction_plan.get("tasks") or [{}])[0].get("name") if reconstruction_plan.get("tasks") else None),
        },
    }
    if semantic_ir:
        payload["semantic_ir"] = semantic_ir
    ghidra_summary: Dict[str, Any] = {}
    if isinstance(summary, dict):
        payload["analysis_summary"] = summary
        nested_ghidra = summary.get("ghidra")
        if isinstance(nested_ghidra, dict):
            ghidra_summary.update(nested_ghidra)
        for source_key, target_key in (
            ("ghidra_program", "program"),
            ("ghidra_language", "language"),
            ("ghidra_compiler", "compiler"),
            ("ghidra_image_base", "image_base"),
            ("ghidra_function_count", "function_count"),
            ("ghidra_string_count", "string_count"),
            ("ghidra_import_count", "import_count"),
        ):
            if summary.get(source_key) is not None and target_key not in ghidra_summary:
                ghidra_summary[target_key] = summary.get(source_key)
    elif summary is not None:
        payload["analysis_summary"] = {"value": summary}
    if ghidra_summary or functions or strings_xrefs or imports_xrefs or (call_graph.get("edges") or []):
        payload["ghidra"] = {
            "program": ghidra_summary.get("program"),
            "language": ghidra_summary.get("language"),
            "compiler": ghidra_summary.get("compiler"),
            "image_base": ghidra_summary.get("image_base"),
            "function_count": ghidra_summary.get("function_count", len(functions)),
            "string_count": ghidra_summary.get("string_count", len(strings_xrefs)),
            "import_count": ghidra_summary.get("import_count", len(imports_xrefs)),
            "call_graph_edge_count": len(call_graph.get("edges") or []),
        }
    return payload


def _render_cmake(project_name: str, sources: List[str]) -> str:
    lines = [
        "cmake_minimum_required(VERSION 3.16)",
        f"project({project_name} C)",
        "",
        "set(CMAKE_C_STANDARD 99)",
        "set(CMAKE_C_STANDARD_REQUIRED ON)",
        "",
        "add_executable(${PROJECT_NAME}",
    ]
    for source in sorted(sources):
        lines.append(f"    {source.replace(os.sep, '/')}")
    lines.extend(
        [
            ")",
            "",
            "target_include_directories(${PROJECT_NAME} PRIVATE include)",
            "",
        ]
    )
    return "\n".join(lines)


def _render_main(sample_name: str) -> str:
    return (
        "#include <stdio.h>\n\n"
        "int reconstructed_entry(void);\n\n"
        "int main(void) {\n"
        f"    puts(\"Stub reconstruction for {sample_name}\");\n"
        "    return reconstructed_entry();\n"
        "}\n"
    )


def _render_entry_source(module_map: Dict[str, Any]) -> str:
    lines = [
        '#include "imports.h"',
        "",
        "int reconstructed_entry(void) {",
        "    /* Entry stub for manual reconstruction.",
    ]
    modules = module_map.get("modules") or {}
    if modules:
        lines.append(f"     * capability modules: {', '.join(sorted(modules))}")
    else:
        lines.append("     * no capability modules were inferred.")
    lines.extend(
        [
            "     */",
            "    return 0;",
            "}",
            "",
        ]
    )
    if not modules:
        lines.extend(
            [
                "int reconstructed_placeholder(void) {",
                "    /* No function metadata was available. */",
                "    return 0;",
                "}",
                "",
            ]
        )
    return "\n".join(lines)


def _render_module_source(module_name: str, functions: List[Dict[str, Any]]) -> str:
    lines = [
        '#include "imports.h"',
        "",
    ]
    if not functions:
        lines.extend(
            [
                f"int {module_name}_placeholder(void) {{",
                f"    /* No functions were assigned to the {module_name} module. */",
                "    return 0;",
                "}",
                "",
            ]
        )
        return "\n".join(lines)

    for item in functions:
        lines.append(f"int {item['identifier']}(void) {{")
        lines.append("    /* Reconstructed stub.")
        lines.append(f"     * inferred module: {module_name}")
        lines.append(f"     * original symbol: {item['name']}")
        if item["comment"]:
            lines.append(f"     * metadata: {item['comment']}")
        if item.get("calls"):
            lines.append(f"     * recovered calls: {', '.join(item['calls'][:8])}")
        if item.get("module_reasons"):
            lines.append(f"     * module reasons: {'; '.join(item['module_reasons'][:6])}")
        lines.append("     */")
        lines.append("    return 0;")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


def _render_imports_header(imports: List[Dict[str, Any]]) -> str:
    lines = [
        "#ifndef REVERSE_ANALYZER_RECONSTRUCT_IMPORTS_H",
        "#define REVERSE_ANALYZER_RECONSTRUCT_IMPORTS_H",
        "",
        "/* Imported APIs observed during analysis.",
        " * These are comments for orientation only; wire real declarations manually.",
        " */",
        "",
    ]
    if not imports:
        lines.append("/* No import metadata was available. */")
    else:
        for item in imports:
            lines.append(f"/* Library: {item['library']} */")
            if item["functions"]:
                for func in item["functions"]:
                    lines.append(f"/*   - {func} */")
            else:
                lines.append("/*   - no named imports recovered */")
            lines.append("")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def _render_readme(
    sample_name: str,
    functions: List[Dict[str, Any]],
    imports: List[Dict[str, Any]],
    summary_payload: Dict[str, Any],
) -> str:
    ghidra = summary_payload.get("ghidra") or {}
    call_graph = summary_payload.get("call_graph") or {}
    module_summary = (summary_payload.get("modules") or {}).get("function_count_by_module") or {}
    lines = [
        f"# Reconstructed stub project for {sample_name}",
        "",
        "This directory contains a compilable reconstruction scaffold.",
        "It does not claim to reproduce the original source code exactly.",
        "",
        "## Included content",
        f"- Function stubs: {len(functions)}",
        f"- Import libraries: {len(imports)}",
        f"- Imported APIs: {sum(len(item['functions']) for item in imports)}",
        f"- Call graph edges: {call_graph.get('edge_count', 0)}",
        f"- String cross-references: {summary_payload.get('string_xref_count', 0)}",
        f"- Functions with string references: {summary_payload.get('string_xref_function_count', 0)}",
        f"- Import cross-references: {summary_payload.get('import_xref_count', 0)}",
        f"- Functions with import references: {summary_payload.get('import_xref_function_count', 0)}",
        f"- Dynamic evidence items: {summary_payload.get('dynamic_evidence_count', 0)}",
        f"- Capability modules: {len(module_summary)}",
        "- Analysis summary: `analysis/summary.json`",
        "- Call graph: `analysis/call_graph.json`",
        "- String references: `analysis/strings_xrefs.json`",
        "- Import references: `analysis/imports_xrefs.json`",
        "- Dynamic evidence: `analysis/dynamic_evidence.json`",
        "- Module map: `analysis/module_map.json`",
        "",
        "## Ghidra metadata",
        f"- Program: {ghidra.get('program') or 'unknown'}",
        f"- Language: {ghidra.get('language') or 'unknown'}",
        f"- Compiler: {ghidra.get('compiler') or 'unknown'}",
        f"- Image base: {ghidra.get('image_base') or 'unknown'}",
        f"- Recovered functions: {ghidra.get('function_count', len(functions))}",
        "",
        "## Capability modules",
    ]
    for name, count in sorted(module_summary.items()):
        lines.append(f"- {name}: {count} function stub(s)")
    module_priorities = (summary_payload.get("modules") or {}).get("priorities") or []
    if module_priorities:
        lines.extend(["", "## Module priority order"])
        for item in module_priorities:
            lines.append(
                f"- {item.get('module')}: score={item.get('priority_score')} functions={item.get('function_count')} top={', '.join(item.get('top_functions') or []) or 'n/a'}"
            )
    high_value_functions = (summary_payload.get("modules") or {}).get("high_value_functions") or []
    if high_value_functions:
        lines.extend(["", "## High-value functions"])
        for item in high_value_functions[:8]:
            lines.append(
                f"- {item.get('name')} [{item.get('module')}] score={item.get('priority_score')} reasons={'; '.join(item.get('reasons') or []) or 'n/a'}"
            )
    dynamic_by_module = (summary_payload.get("modules") or {}).get("dynamic_evidence_by_module") or {}
    if dynamic_by_module:
        lines.extend(["", "## Dynamic evidence by module"])
        for module_name, items in dynamic_by_module.items():
            lines.append(f"- {module_name}: {len(items)} evidence item(s)")
            for item in (items or [])[:4]:
                lines.append(
                    f"  - {item.get('backend')} {item.get('kind')} `{item.get('name')}` count={item.get('count')} detail={item.get('detail') or 'n/a'}"
                )
    semantic_ir = summary_payload.get("semantic_ir") or {}
    if semantic_ir:
        lines.extend(
            [
                "",
                "## Semantic IR",
                f"- Entities: {semantic_ir.get('entity_count', 0)}",
                f"- Relations: {semantic_ir.get('relation_count', 0)}",
                f"- Capabilities: {semantic_ir.get('capability_count', 0)}",
                "- Semantic IR artifact: `analysis/semantic_ir.json`",
            ]
        )
    reconstruction_plan = summary_payload.get("reconstruction_plan") or {}
    if reconstruction_plan.get("task_count"):
        lines.extend(
            [
                "",
                "## Reconstruction plan",
                f"- Task count: {reconstruction_plan.get('task_count')}",
                f"- Subtask count: {reconstruction_plan.get('subtask_count')}",
                f"- Next task: {reconstruction_plan.get('next_task')}",
                "- Plan artifact: `analysis/reconstruction_plan.json`",
            ]
        )
    lines.extend(
        [
            "",
            "## Next steps",
            "1. Review `analysis/summary.json` and reverse-engineering notes.",
            "2. Use `analysis/call_graph.json` plus xref exports to prioritize manual reconstruction.",
            "3. Start with the highest-signal capability modules (`src/network.c`, `src/loader.c`, `src/process.c`, `src/crypto.c`).",
            "4. Replace stub bodies in module source files and keep `src/functions.c` as the entry shim.",
            "5. Add real headers, types, and imported API declarations as needed.",
            "",
        ]
    )
    return "\n".join(lines)


def _xref_function_names(items: List[Dict[str, Any]]) -> List[str]:
    names: List[str] = []
    seen: set[str] = set()
    for item in items:
        for function in item.get("functions") or []:
            if not isinstance(function, dict):
                continue
            name = str(function.get("name") or "").strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            names.append(name)
    return names


def _string_xref_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "value": item.get("value"),
        "address": item.get("address"),
        "xref_count": item.get("xref_count"),
        "functions": [function.get("name") for function in item.get("functions") or [] if isinstance(function, dict)],
    }


def _import_xref_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "symbol": f"{item.get('library')}!{item.get('label')}",
        "address": item.get("address"),
        "xref_count": item.get("xref_count"),
        "functions": [function.get("name") for function in item.get("functions") or [] if isinstance(function, dict)],
    }


def _dynamic_evidence_summary(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "backend": item.get("backend"),
        "module": item.get("module"),
        "kind": item.get("kind"),
        "name": item.get("name"),
        "count": item.get("count"),
        "detail": item.get("detail"),
    }


def _module_files(src_dir: Path, module_map: Dict[str, Any]) -> Dict[str, Path]:
    return {f"src/{name}.c": src_dir / f"{name}.c" for name in module_map.get("files") or []}


def _build_module_map(
    functions: List[Dict[str, Any]],
    call_graph: Dict[str, Any],
    strings_xrefs: List[Dict[str, Any]],
    imports_xrefs: List[Dict[str, Any]],
    dynamic_evidence: List[Dict[str, Any]],
) -> Dict[str, Any]:
    score_map: Dict[str, Dict[str, float]] = {}
    reason_map: Dict[str, List[str]] = {}
    function_lookup = _function_lookup(functions)
    dynamic_by_module = _dynamic_evidence_by_module(dynamic_evidence)

    for function in functions:
        function_key = _function_key(function)
        score_map.setdefault(function_key, {})
        reason_map.setdefault(function_key, [])
        for call_name in function.get("calls") or []:
            for module_name, reason in _module_reasons_from_symbol(call_name):
                _add_module_score(score_map, reason_map, function_key, module_name, 2.0, f"call:{reason}")

    for item in imports_xrefs:
        symbol_name = item.get("label") or item.get("name") or item.get("symbol")
        function_keys = _xref_function_keys(item, function_lookup)
        for function_key in function_keys:
            for module_name, reason in _module_reasons_from_symbol(symbol_name):
                _add_module_score(score_map, reason_map, function_key, module_name, 3.0, f"import:{reason}")

    for item in strings_xrefs:
        function_keys = _xref_function_keys(item, function_lookup)
        for function_key in function_keys:
            for module_name, reason in _module_reasons_from_string(item.get("value")):
                _add_module_score(score_map, reason_map, function_key, module_name, 2.5, f"string:{reason}")

    dynamic_function_targets = _dynamic_function_targets(dynamic_evidence, function_lookup)
    for item in dynamic_evidence:
        module_name = str(item.get("module") or "core")
        if module_name not in MODULE_ORDER:
            module_name = "core"
        weight = min(8.0, 1.0 + float(item.get("count") or 1) * 0.25)
        reason = f"dynamic:{item.get('backend')}:{item.get('kind')}:{item.get('name')}"
        for function_key in dynamic_function_targets.get(str(item.get("name") or "").lower(), []):
            _add_module_score(score_map, reason_map, function_key, module_name, weight, reason)

    _propagate_module_scores(score_map, reason_map, functions, call_graph)

    modules: Dict[str, List[Dict[str, Any]]] = {}
    assignments: List[Dict[str, Any]] = []
    high_value_functions: List[Dict[str, Any]] = []
    for function in functions:
        function_key = _function_key(function)
        scores = score_map.get(function_key) or {}
        module_name = _dominant_module(scores)
        priority_score = _function_priority_score(function, scores, reason_map.get(function_key, []))
        enriched = dict(function)
        enriched["module"] = module_name
        enriched["module_reasons"] = reason_map.get(function_key, [])
        enriched["module_scores"] = {name: round(score, 2) for name, score in sorted(scores.items())}
        enriched["priority_score"] = priority_score
        modules.setdefault(module_name, []).append(enriched)
        assignments.append(
            {
                "name": function.get("name"),
                "identifier": function.get("identifier"),
                "entry": function.get("entry"),
                "module": module_name,
                "reasons": enriched["module_reasons"],
                "scores": enriched["module_scores"],
                "priority_score": priority_score,
            }
        )
        high_value_functions.append(
            {
                "name": function.get("name"),
                "identifier": function.get("identifier"),
                "entry": function.get("entry"),
                "module": module_name,
                "priority_score": priority_score,
                "reasons": enriched["module_reasons"],
            }
        )

    dynamic_modules = {str(item.get("module") or "core") for item in dynamic_evidence if str(item.get("module") or "core") in MODULE_ORDER}
    ordered_modules = {name: modules.get(name, []) for name in MODULE_ORDER if modules.get(name) or name in dynamic_modules}
    priorities = _module_priorities(ordered_modules, dynamic_by_module)
    high_value_functions = sorted(
        high_value_functions,
        key=lambda item: (-float(item.get("priority_score") or 0), str(item.get("module") or ""), str(item.get("name") or "")),
    )
    return {
        "modules": ordered_modules,
        "assignments": assignments,
        "files": list(ordered_modules.keys()),
        "priorities": priorities,
        "high_value_functions": high_value_functions[:12],
        "dynamic_evidence_by_module": dynamic_by_module,
    }


def _function_lookup(functions: List[Dict[str, Any]]) -> Dict[str, str]:
    lookup: Dict[str, str] = {}
    for function in functions:
        key = _function_key(function)
        name = str(function.get("name") or "").strip().lower()
        entry = str(function.get("entry") or "").strip().lower()
        if name:
            lookup[name] = key
        if entry:
            lookup[entry] = key
    return lookup


def _function_key(function: Dict[str, Any]) -> str:
    entry = str(function.get("entry") or "").strip()
    if entry:
        return f"entry:{entry.lower()}"
    return f"name:{str(function.get('name') or function.get('identifier') or 'unknown').strip().lower()}"


def _xref_function_keys(item: Dict[str, Any], function_lookup: Dict[str, str]) -> List[str]:
    keys: List[str] = []
    seen: set[str] = set()
    for function in item.get("functions") or []:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "").strip().lower()
        entry = str(function.get("entry") or "").strip().lower()
        for candidate in (entry, name):
            if not candidate:
                continue
            resolved = function_lookup.get(candidate)
            if resolved and resolved not in seen:
                seen.add(resolved)
                keys.append(resolved)
    for xref in item.get("xrefs") or []:
        if not isinstance(xref, dict):
            continue
        name = str(xref.get("function_name") or "").strip().lower()
        entry = str(xref.get("function_entry") or "").strip().lower()
        for candidate in (entry, name):
            if not candidate:
                continue
            resolved = function_lookup.get(candidate)
            if resolved and resolved not in seen:
                seen.add(resolved)
                keys.append(resolved)
    return keys


def _module_reasons_from_symbol(symbol: Any) -> List[tuple[str, str]]:
    name = str(symbol or "").strip()
    lower = name.lower()
    reasons: List[tuple[str, str]] = []
    if any(token in lower for token in ("loadlibrary", "getprocaddress", "ldrloaddll", "ldrgetprocedureaddress")):
        reasons.append(("loader", name))
    if any(token in lower for token in ("virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread", "openprocess", "resumethread", "setthreadcontext", "createprocess", "winexec", "shellexecute")):
        reasons.append(("process", name))
    if any(token in lower for token in ("winhttp", "internet", "httpopenrequest", "httpsendrequest", "urldownloadtofile", "wsastartup", "socket", "connect", "recv", "send")):
        reasons.append(("network", name))
    if any(token in lower for token in ("crypt", "bcrypt", "md5", "sha", "aes", "rc4", "des", "tea", "xxtea")):
        reasons.append(("crypto", name))
    return reasons


def _module_reasons_from_string(value: Any) -> List[tuple[str, str]]:
    text = str(value or "").strip()
    lower = text.lower()
    reasons: List[tuple[str, str]] = []
    if any(token in lower for token in ("http://", "https://", "user-agent", "cookie:", "authorization:", ".onion", "/api/")):
        reasons.append(("network", text[:80]))
    if any(token in lower for token in ("cmd.exe", "powershell", "rundll32", "regsvr32", "mshta", "wscript", "cscript")):
        reasons.append(("process", text[:80]))
    if any(token in lower for token in ("loadlibrary", "getprocaddress", ".dll")):
        reasons.append(("loader", text[:80]))
    if any(token in lower for token in ("aes", "rsa", "md5", "sha1", "sha256", "rc4", "xxtea", "base64")):
        reasons.append(("crypto", text[:80]))
    return reasons


def _add_module_score(
    score_map: Dict[str, Dict[str, float]],
    reason_map: Dict[str, List[str]],
    function_key: str,
    module_name: str,
    weight: float,
    reason: str,
) -> None:
    scores = score_map.setdefault(function_key, {})
    scores[module_name] = scores.get(module_name, 0.0) + weight
    reasons = reason_map.setdefault(function_key, [])
    if reason not in reasons:
        reasons.append(reason)


def _propagate_module_scores(
    score_map: Dict[str, Dict[str, float]],
    reason_map: Dict[str, List[str]],
    functions: List[Dict[str, Any]],
    call_graph: Dict[str, Any],
) -> None:
    entry_lookup = {
        str(function.get("entry") or "").strip().lower(): _function_key(function)
        for function in functions
        if str(function.get("entry") or "").strip()
    }
    for edge in call_graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        source_key = entry_lookup.get(str(edge.get("source") or "").strip().lower())
        target_key = entry_lookup.get(str(edge.get("target") or "").strip().lower())
        if not source_key or not target_key:
            continue
        target_scores = score_map.get(target_key) or {}
        source_scores = score_map.get(source_key) or {}
        for module_name, score in target_scores.items():
            if score > 0:
                _add_module_score(score_map, reason_map, source_key, module_name, 0.5, f"call_graph:{module_name}:{edge.get('target')}")
        for module_name, score in source_scores.items():
            if score > 0:
                _add_module_score(score_map, reason_map, target_key, module_name, 0.25, f"call_graph:{module_name}:{edge.get('source')}")


def _dynamic_evidence_by_module(dynamic_evidence: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in dynamic_evidence:
        module_name = str(item.get("module") or "core")
        if module_name not in MODULE_ORDER:
            module_name = "core"
        grouped.setdefault(module_name, []).append(dict(item))
    for module_name, items in grouped.items():
        grouped[module_name] = sorted(
            items,
            key=lambda item: (-float(item.get("count") or 0), str(item.get("backend") or ""), str(item.get("name") or "")),
        )[:12]
    return grouped


def _dynamic_function_targets(dynamic_evidence: List[Dict[str, Any]], function_lookup: Dict[str, str]) -> Dict[str, List[str]]:
    targets: Dict[str, List[str]] = {}
    if not function_lookup:
        return targets
    for item in dynamic_evidence:
        name = str(item.get("name") or "").lower()
        if not name:
            continue
        resolved: List[str] = []
        for candidate, function_key in function_lookup.items():
            if name == candidate or name in candidate or candidate in name:
                resolved.append(function_key)
        if resolved:
            targets[name] = list(dict.fromkeys(resolved))
    return targets


def _dominant_module(scores: Dict[str, float]) -> str:
    if not scores:
        return "core"
    ranked = sorted(
        scores.items(),
        key=lambda item: (
            -item[1],
            MODULE_ORDER.index(item[0]) if item[0] in MODULE_ORDER else 999,
            item[0],
        ),
    )
    top_name, top_score = ranked[0]
    return top_name if top_score > 0 else "core"


def _function_priority_score(function: Dict[str, Any], scores: Dict[str, float], reasons: List[str]) -> float:
    body_size = int(function.get("body_size") or 0)
    call_count = len(function.get("calls") or [])
    score = sum(float(value) for value in scores.values())
    score += min(4.0, body_size / 512.0)
    score += min(2.0, call_count * 0.5)
    score += min(2.0, len(reasons) * 0.25)
    return round(score, 2)


def _module_priorities(
    modules: Dict[str, List[Dict[str, Any]]],
    dynamic_by_module: Dict[str, List[Dict[str, Any]]] | None = None,
) -> List[Dict[str, Any]]:
    priorities: List[Dict[str, Any]] = []
    dynamic_by_module = dynamic_by_module or {}
    for module_name, items in modules.items():
        dynamic_items = dynamic_by_module.get(module_name) or []
        dynamic_priority = min(12.0, sum(float(item.get("count") or 0) for item in dynamic_items) * 0.35)
        total_priority = round(sum(float(item.get("priority_score") or 0) for item in items) + dynamic_priority, 2)
        top_functions = [
            str(item.get("name"))
            for item in sorted(
                items,
                key=lambda value: (-float(value.get("priority_score") or 0), str(value.get("name") or "")),
            )[:3]
        ]
        priorities.append(
            {
                "module": module_name,
                "priority_score": total_priority,
                "dynamic_priority": round(dynamic_priority, 2),
                "function_count": len(items),
                "top_functions": top_functions,
                "top_dynamic_evidence": [_dynamic_evidence_summary(item) for item in dynamic_items[:5]],
            }
        )
    return sorted(
        priorities,
        key=lambda item: (
            -float(item.get("priority_score") or 0),
            MODULE_ORDER.index(str(item.get("module"))) if str(item.get("module")) in MODULE_ORDER else 999,
            str(item.get("module") or ""),
        ),
    )


def _build_reconstruction_plan(module_map: Dict[str, Any]) -> Dict[str, Any]:
    now = _utc_now()
    tasks: List[Dict[str, Any]] = []
    module_lookup = module_map.get("modules") or {}
    high_value_lookup = {
        str(item.get("name")): item
        for item in module_map.get("high_value_functions") or []
        if isinstance(item, dict) and item.get("name") is not None
    }
    for item in module_map.get("priorities") or []:
        if not isinstance(item, dict):
            continue
        module_name = str(item.get("module") or "").strip()
        if not module_name:
            continue
        functions = module_lookup.get(module_name) or []
        subtasks: List[Dict[str, Any]] = [
            _plan_subtask(
                f"review_{module_name}_xrefs",
                f"Review xrefs, imports, and strings mapped to the {module_name} module.",
                now=now,
                metadata={
                    "module": module_name,
                    "kind": "triage",
                    "priority_score": item.get("priority_score"),
                },
            )
        ]
        for function_name in item.get("top_functions") or []:
            detail = high_value_lookup.get(str(function_name)) or {}
            subtasks.append(
                _plan_subtask(
                    f"recover_{_slug(function_name)}",
                    f"Reconstruct function `{function_name}` in module `{module_name}`.",
                    now=now,
                    metadata={
                        "module": module_name,
                        "kind": "function_recovery",
                        "function": function_name,
                        "priority_score": detail.get("priority_score"),
                        "reasons": detail.get("reasons") or [],
                    },
                )
            )
        dynamic_items = item.get("top_dynamic_evidence") or []
        if dynamic_items:
            subtasks.append(
                _plan_subtask(
                    f"replay_{module_name}_dynamic_evidence",
                    f"Replay and correlate dynamic evidence for module `{module_name}`.",
                    now=now,
                    metadata={
                        "module": module_name,
                        "kind": "dynamic_correlation",
                        "dynamic_evidence": dynamic_items,
                        "dynamic_priority": item.get("dynamic_priority"),
                    },
                )
            )
        subtasks.append(
            _plan_subtask(
                f"verify_{module_name}",
                f"Verify module `{module_name}` stubs, TODOs, and cross-module assumptions.",
                now=now,
                metadata={
                    "module": module_name,
                    "kind": "verification",
                    "function_count": len(functions),
                },
            )
        )
        tasks.append(
            _plan_task(
                f"reconstruct_{module_name}",
                f"Reconstruct the `{module_name}` capability module using prioritized functions and xref evidence.",
                now=now,
                metadata={
                    "module": module_name,
                    "priority_score": item.get("priority_score"),
                    "function_count": item.get("function_count"),
                    "module_file": f"src/{module_name}.c",
                },
                subtasks=subtasks,
            )
        )
    return {
        "status": "planned",
        "created_at": now,
        "updated_at": now,
        "tasks": tasks,
    }


def _plan_task(
    name: str,
    description: str,
    *,
    now: str,
    metadata: Dict[str, Any],
    subtasks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": "pending",
        "metadata": metadata,
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
        "subtasks": subtasks,
    }


def _plan_subtask(name: str, description: str, *, now: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "status": "pending",
        "metadata": metadata,
        "result": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
    }


def _slug(value: Any) -> str:
    text = str(value or "").strip().lower()
    slug = "".join(ch if ch.isalnum() else "_" for ch in text).strip("_")
    return slug or "item"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _artifact_kind(name: str) -> str:
    if name.startswith("analysis/"):
        return "analysis"
    if name.startswith("include/"):
        return "header"
    if name.startswith("src/"):
        return "source"
    if name.endswith(".md"):
        return "documentation"
    return "build"


def _c_identifier(value: str, fallback: str = "function_stub") -> str:
    chars = [ch if ch.isalnum() or ch == "_" else "_" for ch in value.strip()]
    identifier = "".join(chars).strip("_")
    if not identifier:
        identifier = fallback
    if identifier[0].isdigit():
        identifier = f"fn_{identifier}"
    return identifier
