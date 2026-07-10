"""Read-only discovery of generated source-reconstruction projects.

The dashboard must be able to describe reconstruction output without running a
sample, importing a generated project, or trusting paths embedded in reports.
This module only walks directories below a caller-supplied workspace and
normalizes the small amount of project metadata needed by the UI.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping


_IGNORED_DIRECTORIES = {
    ".git",
    ".codebase-memory",
    ".reverse_analyzer",
    "__pycache__",
    "dashboard",
    "node_modules",
    "build",
    "dist",
    "bin",
    "obj",
    ".vs",
}
_SOURCE_PRIORITY_DIRECTORIES = {"src", "source", "sources", "include", "app", "lib"}
_SOURCE_LANGUAGES = {
    ".c": "c",
    ".h": "c",
    ".cc": "c++",
    ".cpp": "c++",
    ".cxx": "c++",
    ".hpp": "c++",
    ".cs": "csharp",
    ".xaml": "xaml",
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "css",
    ".dart": "dart",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-c++",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".qml": "qml",
    ".ui": "qt-ui",
}
_RESOURCE_SUFFIXES = {
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
    ".qrc",
    ".dfm",
    ".storyboard",
    ".xib",
}
_ENTRYPOINT_NAMES = {
    "main.c",
    "main.cc",
    "main.cpp",
    "main.cxx",
    "main.py",
    "main.swift",
    "main.dart",
    "main.js",
    "main.mjs",
    "main.ts",
    "main.tsx",
    "index.js",
    "index.ts",
    "index.tsx",
    "program.cs",
    "app.xaml",
    "mainactivity.kt",
    "mainactivity.java",
}
_BUILD_ENTRYPOINT_NAMES = {
    "cmakelists.txt",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
}
_MAX_PROJECTS = 100
_MAX_FILES_PER_PROJECT = 2000
_MAX_SOURCE_FILES_RETURNED = 200
_MAX_PREVIEW_BYTES = 16 * 1024
_MAX_PREVIEW_CHARACTERS = 1200


def summarize_source_reconstruction(
    workspace: str | Path,
    *,
    diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return JSON-serializable source-reconstruction data below ``workspace``.

    A project is discovered by the directory names emitted by the built-in C
    and GUI reconstructors: ``reconstructed_*`` and ``reconstructed_gui``.
    Project and source-file paths are relative to the workspace/project.
    Invalid optional JSON metadata is recorded as a diagnostic and never
    prevents other projects from reaching the dashboard.
    """

    root = Path(workspace).expanduser()
    state = diagnostics if diagnostics is not None else {}
    _initialize_diagnostics(state)
    summary = {
        "project_total": 0,
        "source_file_total": 0,
        "resource_file_total": 0,
        "function_total": 0,
        "dynamic_evidence_total": 0,
        "semantic_entity_total": 0,
        "semantic_capability_total": 0,
        "verified_project_total": 0,
        "language_counts": {},
        "output_stack_counts": {},
    }
    if not root.is_dir():
        state["workspace_unavailable"] = str(root)
        return {"summary": summary, "projects": [], "diagnostics": state}

    root = root.resolve()
    projects = [_summarize_project(root, path, state) for path in _project_directories(root, state)]
    projects.sort(key=lambda item: (str(item.get("relative_path") or ""), str(item.get("name") or "")))

    language_counts: dict[str, int] = {}
    output_stack_counts: dict[str, int] = {}
    for project in projects:
        summary["source_file_total"] += _as_int(project.get("source_file_count"))
        summary["resource_file_total"] += _as_int(project.get("resource_file_count"))
        summary["function_total"] += _as_int(project.get("function_count"))
        summary["dynamic_evidence_total"] += _as_int(project.get("dynamic_evidence_count"))
        summary["semantic_entity_total"] += _as_int(project.get("semantic_entity_count"))
        summary["semantic_capability_total"] += _as_int(project.get("semantic_capability_count"))
        if project.get("verification_score") is not None:
            summary["verified_project_total"] += 1
        _increment(language_counts, project.get("language"))
        _increment(output_stack_counts, project.get("output_stack"))
    summary["project_total"] = len(projects)
    summary["language_counts"] = dict(sorted(language_counts.items()))
    summary["output_stack_counts"] = dict(sorted(output_stack_counts.items()))
    return {"summary": summary, "projects": projects, "diagnostics": state}


def _initialize_diagnostics(diagnostics: dict[str, Any]) -> None:
    diagnostics.setdefault("directories_scanned", 0)
    diagnostics.setdefault("projects_discovered", 0)
    diagnostics.setdefault("metadata_files_loaded", 0)
    diagnostics.setdefault("malformed_metadata", 0)
    diagnostics.setdefault("skipped_files", [])
    diagnostics.setdefault("truncated_projects", 0)
    diagnostics.setdefault("truncated_file_lists", 0)


def _project_directories(root: Path, diagnostics: dict[str, Any]) -> Iterable[Path]:
    """Yield reconstruction project roots while pruning non-artifact trees."""

    found = 0
    for current_root, directory_names, _ in os.walk(root, topdown=True):
        diagnostics["directories_scanned"] += 1
        directory_names[:] = sorted(
            name for name in directory_names if name.lower() not in _IGNORED_DIRECTORIES
        )
        candidates = [name for name in directory_names if _is_project_directory(name)]
        for name in candidates:
            if found >= _MAX_PROJECTS:
                diagnostics["truncated_projects"] += 1
                return
            candidate = Path(current_root) / name
            if not _is_within(root, candidate):
                diagnostics["skipped_files"].append({"path": str(candidate), "reason": "outside workspace"})
                directory_names.remove(name)
                continue
            found += 1
            diagnostics["projects_discovered"] += 1
            directory_names.remove(name)
            yield candidate


def _is_project_directory(name: str) -> bool:
    normalized = name.lower()
    return normalized == "reconstructed_gui" or normalized.startswith("reconstructed_")


def _summarize_project(root: Path, project_dir: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    project_dir = project_dir.resolve()
    metadata = _load_project_metadata(project_dir, diagnostics)
    (
        source_files,
        source_file_count,
        source_languages,
        resource_file_count,
        entrypoints,
        file_scan_truncated,
    ) = _collect_project_files(project_dir, diagnostics)
    summary_data = _mapping(metadata.get("summary"))
    reconstruction_plan = _mapping(metadata.get("reconstruction_plan"))
    module_map = _mapping(metadata.get("module_map"))
    gui_strategy = _mapping(metadata.get("gui_strategy"))
    gui_analysis = _mapping(metadata.get("gui_analysis"))
    semantic_ir = _mapping(metadata.get("semantic_ir"))
    semantic_summary = _mapping(semantic_ir.get("summary"))
    verification = _mapping(metadata.get("reconstruction_verification"))
    verification_coverage = _mapping(verification.get("coverage"))
    dynamic_evidence = metadata.get("dynamic_evidence")

    gui_strategy_data = _mapping(gui_analysis.get("strategy"))
    output_stack = _first_text(
        gui_strategy.get("output_stack"),
        gui_strategy_data.get("output_stack"),
        gui_strategy.get("framework"),
        gui_analysis.get("framework"),
    )
    language = _dominant_language(source_languages) or _language_from_stack(output_stack) or _detect_project_language(project_dir)
    modules = module_map.get("modules")
    module_count = len(modules) if isinstance(modules, Mapping) else _as_int(summary_data.get("module_count"))
    function_count = _as_int(summary_data.get("function_count"))
    dynamic_evidence_count = (
        len(dynamic_evidence)
        if isinstance(dynamic_evidence, list)
        else _as_int(summary_data.get("dynamic_evidence_count"))
    )
    if dynamic_evidence_count == 0:
        dynamic_evidence_count = _as_int(gui_analysis.get("dynamic_evidence_count"))

    status = _first_text(gui_strategy.get("status"), gui_analysis.get("status"), summary_data.get("status")) or "discovered"
    return {
        "name": project_dir.name,
        "relative_path": _relative_path(root, project_dir),
        "status": status,
        "language": language,
        "output_stack": output_stack,
        "readme_present": (project_dir / "README.md").is_file(),
        "source_file_count": source_file_count,
        "resource_file_count": resource_file_count,
        "function_count": function_count,
        "import_count": _as_int(summary_data.get("import_count")),
        "module_count": module_count,
        "dynamic_evidence_count": dynamic_evidence_count,
        "semantic_entity_count": _as_int(semantic_summary.get("entity_count")),
        "semantic_relation_count": _as_int(semantic_summary.get("relation_count")),
        "semantic_capability_count": _as_int(semantic_summary.get("capability_count")),
        "verification_status": _first_text(verification.get("status")),
        "verification_score": _number_or_none(verification.get("score")),
        "semantic_coverage": _number_or_none(verification_coverage.get("semantic_coverage")),
        "module_coverage": _number_or_none(verification_coverage.get("module_coverage")),
        "next_task": _next_task(reconstruction_plan),
        "entrypoints": entrypoints,
        "source_files": source_files,
        "source_files_truncated": file_scan_truncated or source_file_count > len(source_files),
        "stub_only": _first_bool(gui_strategy.get("stub_only"), summary_data.get("stub_only")),
        "artifacts": _artifact_names(metadata.get("gui_analysis")),
    }


def _load_project_metadata(project_dir: Path, diagnostics: dict[str, Any]) -> dict[str, Any]:
    analysis_dir = project_dir / "analysis"
    filenames = {
        "summary": "summary.json",
        "reconstruction_plan": "reconstruction_plan.json",
        "module_map": "module_map.json",
        "dynamic_evidence": "dynamic_evidence.json",
        "gui_strategy": "gui_strategy.json",
        "gui_analysis": "gui_analysis.json",
        "semantic_ir": "semantic_ir.json",
        "reconstruction_verification": "reconstruction_verification.json",
    }
    result: dict[str, Any] = {}
    for key, filename in filenames.items():
        value = _load_json(analysis_dir / filename, diagnostics)
        if value is not None:
            result[key] = value
    return result


def _load_json(path: Path, diagnostics: dict[str, Any]) -> Any:
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        diagnostics["malformed_metadata"] += 1
        diagnostics["skipped_files"].append({"path": str(path), "reason": str(error)})
        return None
    diagnostics["metadata_files_loaded"] += 1
    return value


def _collect_project_files(
    project_dir: Path, diagnostics: dict[str, Any]
) -> tuple[list[dict[str, Any]], int, dict[str, int], int, list[str], bool]:
    source_files: list[dict[str, Any]] = []
    source_file_count = 0
    source_languages: dict[str, int] = {}
    resource_file_count = 0
    entrypoints: list[str] = []
    scanned_files = 0
    for current_root, directory_names, filenames in os.walk(project_dir, topdown=True):
        directory_names[:] = sorted(
            (name for name in directory_names if name.lower() not in _IGNORED_DIRECTORIES),
            key=lambda name: (name.lower() not in _SOURCE_PRIORITY_DIRECTORIES, name.lower()),
        )
        for filename in sorted(filenames):
            scanned_files += 1
            if scanned_files > _MAX_FILES_PER_PROJECT:
                diagnostics["truncated_file_lists"] += 1
                return source_files, source_file_count, source_languages, resource_file_count, entrypoints, True
            path = Path(current_root) / filename
            if not _is_within(project_dir, path):
                diagnostics["skipped_files"].append({"path": str(path), "reason": "outside project"})
                continue
            suffix = path.suffix.lower()
            relative = path.relative_to(project_dir).as_posix()
            lower_name = path.name.lower()
            if suffix in _RESOURCE_SUFFIXES:
                resource_file_count += 1
            if lower_name in _ENTRYPOINT_NAMES or lower_name in _BUILD_ENTRYPOINT_NAMES:
                entrypoints.append(relative)
            language = _SOURCE_LANGUAGES.get(suffix)
            if language is None:
                continue
            source_file_count += 1
            source_languages[language] = source_languages.get(language, 0) + 1
            if len(source_files) < _MAX_SOURCE_FILES_RETURNED:
                source_files.append(
                    {
                        "path": relative,
                        "language": language,
                        "size_bytes": _file_size(path),
                        "preview": _text_preview(path),
                    }
                )
    return source_files, source_file_count, source_languages, resource_file_count, entrypoints, False


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def _text_preview(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            content = handle.read(_MAX_PREVIEW_BYTES)
    except OSError:
        return None
    if not content or b"\x00" in content:
        return None
    text = content.decode("utf-8", errors="replace").strip()
    return text[:_MAX_PREVIEW_CHARACTERS] if text else None


def _next_task(plan: Mapping[str, Any]) -> str | None:
    tasks = plan.get("tasks")
    if not isinstance(tasks, list):
        return None
    for task in tasks:
        if isinstance(task, Mapping):
            value = _first_text(task.get("name"), task.get("id"), task.get("description"))
            if value:
                return value
    return None


def _artifact_names(value: Any) -> list[str]:
    data = _mapping(value)
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list):
        return []
    names: list[str] = []
    for item in artifacts:
        if isinstance(item, Mapping):
            name = _first_text(item.get("name"), item.get("path"))
            if name:
                names.append(name)
    return names[:50]


def _dominant_language(counts: Mapping[str, int]) -> str | None:
    if not counts:
        return None
    return sorted(counts, key=lambda item: (-counts[item], item))[0]


def _detect_project_language(project_dir: Path) -> str | None:
    if any(project_dir.glob("*.csproj")):
        return "csharp"
    if (project_dir / "package.json").is_file():
        return "javascript"
    if (project_dir / "pyproject.toml").is_file():
        return "python"
    if (project_dir / "CMakeLists.txt").is_file():
        return "c"
    return None


def _language_from_stack(stack: str | None) -> str | None:
    if not stack:
        return None
    normalized = stack.lower()
    if "wpf" in normalized or "winforms" in normalized or "c#" in normalized:
        return "csharp"
    if "pyside" in normalized or "python" in normalized:
        return "python"
    if "electron" in normalized or "react" in normalized:
        return "javascript"
    if "flutter" in normalized:
        return "dart"
    if "qt" in normalized or "win32" in normalized:
        return "c++"
    if "xcode" in normalized or "uikit" in normalized or "swift" in normalized:
        return "swift"
    if "android" in normalized:
        return "kotlin"
    return None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _first_bool(*values: Any) -> bool | None:
    for value in values:
        if isinstance(value, bool):
            return value
    return None


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _number_or_none(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return round(float(value), 4)
    except (TypeError, ValueError):
        return None


def _increment(values: dict[str, int], value: Any) -> None:
    text = _first_text(value)
    if text:
        values[text] = values.get(text, 0) + 1


def _relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _is_within(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False
