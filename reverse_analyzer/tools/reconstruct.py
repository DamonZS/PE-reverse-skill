"""Stub project reconstruction helpers.

This module turns reverse-analysis output into a small, compilable C project
skeleton. The generated code is intentionally approximate and only provides
placeholders for manual reconstruction.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List


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
    imports = _normalize_imports(analysis.get("imports"))
    summary_payload = _build_summary(sample, functions, imports, analysis.get("summary"))

    file_map = {
        "CMakeLists.txt": project_dir / "CMakeLists.txt",
        "src/main.c": src_dir / "main.c",
        "src/functions.c": src_dir / "functions.c",
        "include/imports.h": include_dir / "imports.h",
        "analysis/summary.json": analysis_dir / "summary.json",
        "README.md": project_dir / "README.md",
    }

    file_map["CMakeLists.txt"].write_text(_render_cmake(project_dir.name), encoding="utf-8")
    file_map["src/main.c"].write_text(_render_main(sample.name), encoding="utf-8")
    file_map["src/functions.c"].write_text(_render_functions(functions), encoding="utf-8")
    file_map["include/imports.h"].write_text(_render_imports_header(imports), encoding="utf-8")
    file_map["analysis/summary.json"].write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")
    file_map["README.md"].write_text(_render_readme(sample.name, functions, imports), encoding="utf-8")

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
        else:
            original_name = str(item or f"function_{index}")
            comment_bits = []
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
            }
        )
    return normalized


def _normalize_imports(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    normalized: List[Dict[str, Any]] = []
    for item in raw:
        if isinstance(item, dict):
            library = str(item.get("dll") or item.get("library") or item.get("module") or "unknown")
            functions = item.get("functions")
            names = _extract_import_function_names(functions)
            if not names and item.get("name"):
                names = [str(item["name"])]
        else:
            library = "unknown"
            names = [str(item)]
        normalized.append({"library": library, "functions": names})
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


def _build_summary(
    sample: Path,
    functions: List[Dict[str, Any]],
    imports: List[Dict[str, Any]],
    summary: Any,
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
    }
    if isinstance(summary, dict):
        payload["analysis_summary"] = summary
    elif summary is not None:
        payload["analysis_summary"] = {"value": summary}
    return payload


def _render_cmake(project_name: str) -> str:
    return (
        "cmake_minimum_required(VERSION 3.16)\n"
        f"project({project_name} C)\n\n"
        "set(CMAKE_C_STANDARD 99)\n"
        "set(CMAKE_C_STANDARD_REQUIRED ON)\n\n"
        "add_executable(${PROJECT_NAME}\n"
        "    src/main.c\n"
        "    src/functions.c\n"
        ")\n\n"
        "target_include_directories(${PROJECT_NAME} PRIVATE include)\n"
    )


def _render_main(sample_name: str) -> str:
    return (
        "#include <stdio.h>\n\n"
        "int reconstructed_entry(void);\n\n"
        "int main(void) {\n"
        f"    puts(\"Stub reconstruction for {sample_name}\");\n"
        "    return reconstructed_entry();\n"
        "}\n"
    )


def _render_functions(functions: List[Dict[str, Any]]) -> str:
    lines = [
        '#include "imports.h"',
        "",
        "int reconstructed_entry(void) {",
        "    /* Entry stub for manual reconstruction. */",
        "    return 0;",
        "}",
        "",
    ]
    if not functions:
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

    for item in functions:
        lines.append(f"int {item['identifier']}(void) {{")
        lines.append("    /* Reconstructed stub.")
        lines.append(f"     * original symbol: {item['name']}")
        if item["comment"]:
            lines.append(f"     * metadata: {item['comment']}")
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


def _render_readme(sample_name: str, functions: List[Dict[str, Any]], imports: List[Dict[str, Any]]) -> str:
    return "\n".join(
        [
            f"# Reconstructed stub project for {sample_name}",
            "",
            "This directory contains a compilable reconstruction scaffold.",
            "It does not claim to reproduce the original source code exactly.",
            "",
            "## Included content",
            f"- Function stubs: {len(functions)}",
            f"- Import libraries: {len(imports)}",
            "- Analysis summary: `analysis/summary.json`",
            "",
            "## Next steps",
            "1. Review `analysis/summary.json` and reverse-engineering notes.",
            "2. Replace stub bodies in `src/functions.c`.",
            "3. Add real headers, types, and imported API declarations as needed.",
            "",
        ]
    )


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
