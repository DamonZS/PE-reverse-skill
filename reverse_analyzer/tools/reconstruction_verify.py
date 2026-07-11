"""Static verification for generated reconstruction projects.

This verifier is intentionally non-executing.  It only inspects paths and
bounded text files below a supplied project directory; it never starts a sample,
builds a project, invokes an external command, or contacts the network.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import os
from pathlib import Path
import re
from typing import Any


_SCHEMA_VERSION = 1
_MAX_TEXT_BYTES = 1_000_000
_MAX_METADATA_BYTES = 2_000_000
_MAX_PROJECT_FILES = 10_000
_SOURCE_SUFFIXES = {
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hpp",
    ".cs",
    ".dart",
    ".html",
    ".xaml",
    ".xml",
    ".vb",
    ".fs",
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".go",
    ".rs",
    ".swift",
    ".pas",
    ".lpr",
}
_BUILD_FILENAMES = {
    "cmakelists.txt",
    "makefile",
    "meson.build",
    "build.ninja",
    "package.json",
    "pubspec.yaml",
    "requirements.txt",
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    "podfile",
}
_BUILD_SUFFIXES = {".sln", ".vcxproj", ".csproj", ".fsproj", ".vbproj", ".xcodeproj"}
_SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    "bin",
    "obj",
}
_CHECK_WEIGHTS = {
    "readme": 0.10,
    "source_files": 0.20,
    "build_entry": 0.20,
    "semantic_ir": 0.15,
    "reconstruction_plan": 0.15,
    "semantic_mapping": 0.10,
    "module_coverage": 0.10,
}
_STATUS_VALUES = {"pass": 1.0, "partial": 0.5, "unavailable": 0.0, "fail": 0.0}
_INVALID_SEMANTIC_STATUSES = {"unavailable", "failed", "error"}


def verify_reconstruction(
    project_dir: str | Path,
    *,
    semantic_ir: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Statically assess reconstruction evidence and source coverage.

    A caller-provided semantic IR is authoritative.  Otherwise, the verifier
    attempts to read ``analysis/semantic_ir.json`` inside the project.  All
    filesystem reads are bounded and resolved paths must remain beneath the
    supplied project directory.
    """

    root = _resolve_root(project_dir)
    if not _is_directory(root):
        return _unavailable_result(root, "Project directory is unavailable for static verification.")

    project_files = _project_files(root)
    readme_files = _readme_files(project_files)
    readable_readmes = [item for item in readme_files if _read_text_file(item[1], _MAX_TEXT_BYTES) is not None]
    source_files = _source_files(project_files)
    build_files = _build_files(project_files)

    if isinstance(semantic_ir, Mapping):
        semantic_payload: Mapping[str, Any] | None = semantic_ir
        semantic_detail = "Using caller-supplied semantic IR."
    else:
        semantic_payload, semantic_detail = _load_json_mapping(root, "analysis/semantic_ir.json")

    plan_payload, plan_detail = _load_json_mapping(root, "analysis/reconstruction_plan.json")
    semantic_entities = _semantic_entities(semantic_payload)
    mapped_entity_ids = _mapped_entity_ids(semantic_entities, source_files)
    planned_modules = _planned_modules(plan_payload, root)
    covered_modules = _covered_modules(planned_modules, source_files)
    semantic_valid = _has_semantic_entities_collection(semantic_payload)
    plan_valid = _has_plan_collection(plan_payload)

    coverage = {
        "source_file_count": len(source_files),
        "build_manifest_count": len(build_files),
        "semantic_entity_count": len(semantic_entities),
        "mapped_entity_count": len(mapped_entity_ids),
        "semantic_coverage": _ratio(len(mapped_entity_ids), len(semantic_entities)),
        "planned_module_count": len(planned_modules),
        "covered_module_count": len(covered_modules),
        "module_coverage": _ratio(len(covered_modules), len(planned_modules)),
    }

    checks = [
        _check(
            "readme",
            "pass" if readable_readmes else "unavailable",
            f"{len(readable_readmes)} readable README file(s) found.",
        ),
        _check(
            "source_files",
            "pass" if source_files else "unavailable",
            f"{len(source_files)} readable text source file(s) available for static scanning.",
        ),
        _check(
            "build_entry",
            "pass" if build_files else "unavailable",
            f"{len(build_files)} build manifest file(s) found.",
        ),
        _check(
            "semantic_ir",
            "pass" if semantic_valid else "unavailable",
            semantic_detail,
        ),
        _check(
            "reconstruction_plan",
            "pass" if plan_valid else "unavailable",
            plan_detail,
        ),
        _check(
            "semantic_mapping",
            _coverage_status(len(mapped_entity_ids), len(semantic_entities), valid=semantic_valid),
            f"{len(mapped_entity_ids)}/{len(semantic_entities)} semantic entities mapped in readable text source files.",
        ),
        _check(
            "module_coverage",
            _coverage_status(len(covered_modules), len(planned_modules), valid=plan_valid),
            f"{len(covered_modules)}/{len(planned_modules)} planned module(s) covered by readable text source files.",
        ),
    ]
    score = round(sum(_STATUS_VALUES[check["status"]] * float(check["weight"]) for check in checks), 4)
    recommendations = _recommendations(checks, coverage)
    result: dict[str, Any] = {
        "status": _result_status(checks),
        "schema_version": _SCHEMA_VERSION,
        "project_dir": str(root),
        "score": max(0.0, min(1.0, score)),
        "checks": checks,
        "coverage": coverage,
        "recommendations": recommendations,
        "artifacts": [],
    }

    target = _safe_project_path(root, "analysis/reconstruction_verification.json")
    if target is not None:
        artifact = {
            "name": "analysis/reconstruction_verification.json",
            "path": str(target),
            "kind": "reconstruction-verification",
        }
        result["artifacts"] = [artifact]
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if not _is_within(root, target):
                raise OSError("verification artifact would leave project directory")
            target.write_text(_json_dump(result), encoding="utf-8")
        except (OSError, TypeError, ValueError):
            result["artifacts"] = []
            result["status"] = "partial"
            result["recommendations"] = sorted(
                set(result["recommendations"]).union({"Ensure the analysis directory is writable inside the project directory."})
            )
    return result


def _unavailable_result(root: Path, detail: str) -> dict[str, Any]:
    checks = [
        _check("readme", "unavailable", detail),
        _check("source_files", "unavailable", detail),
        _check("build_entry", "unavailable", detail),
        _check("semantic_ir", "unavailable", detail),
        _check("reconstruction_plan", "unavailable", detail),
        _check("semantic_mapping", "unavailable", detail),
        _check("module_coverage", "unavailable", detail),
    ]
    return {
        "status": "unavailable",
        "schema_version": _SCHEMA_VERSION,
        "project_dir": str(root),
        "score": 0.0,
        "checks": checks,
        "coverage": _empty_coverage(),
        "recommendations": ["Create or select an existing reconstruction project directory before verification."],
        "artifacts": [],
    }


def _empty_coverage() -> dict[str, Any]:
    return {
        "source_file_count": 0,
        "build_manifest_count": 0,
        "semantic_entity_count": 0,
        "mapped_entity_count": 0,
        "semantic_coverage": 0.0,
        "planned_module_count": 0,
        "covered_module_count": 0,
        "module_coverage": 0.0,
    }


def _check(name: str, status: str, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "detail": detail,
        "weight": _CHECK_WEIGHTS[name],
    }


def _resolve_root(value: str | Path) -> Path:
    try:
        return Path(value).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, TypeError):
        try:
            return Path(value).absolute()
        except (OSError, TypeError):
            return Path(".").resolve()


def _is_directory(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _project_files(root: Path) -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    try:
        walker = os.walk(root, topdown=True, followlinks=False, onerror=lambda _error: None)
        for current, directories, filenames in walker:
            current_path = Path(current)
            directories[:] = sorted(
                directory
                for directory in directories
                if directory.casefold() not in _SKIP_DIRECTORIES
                and _is_within(root, current_path / directory)
            )
            for filename in sorted(filenames):
                candidate = current_path / filename
                if not _is_within(root, candidate) or not _is_regular_file(candidate):
                    continue
                relative = _relative_path(root, candidate)
                if relative is None:
                    continue
                files.append((relative, candidate))
                if len(files) >= _MAX_PROJECT_FILES:
                    return sorted(files, key=lambda item: item[0].casefold())
    except OSError:
        return sorted(files, key=lambda item: item[0].casefold())
    return sorted(files, key=lambda item: item[0].casefold())


def _is_regular_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _relative_path(root: Path, path: Path) -> str | None:
    try:
        return path.resolve(strict=False).relative_to(root).as_posix()
    except (OSError, RuntimeError, ValueError):
        return None


def _readme_files(files: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for relative, path in files:
        if "/" in relative:
            continue
        name = path.name.casefold()
        if name == "readme" or name.startswith("readme."):
            result.append((relative, path))
    return result


def _source_files(files: list[tuple[str, Path]]) -> list[tuple[str, Path, str]]:
    sources: list[tuple[str, Path, str]] = []
    for relative, path in files:
        if path.suffix.casefold() not in _SOURCE_SUFFIXES:
            continue
        content = _read_text_file(path, _MAX_TEXT_BYTES)
        if content is not None:
            sources.append((relative, path, content))
    return sources


def _build_files(files: list[tuple[str, Path]]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    for relative, path in files:
        name = path.name.casefold()
        suffix = path.suffix.casefold()
        if name in _BUILD_FILENAMES or suffix in _BUILD_SUFFIXES:
            result.append((relative, path))
    return result


def _read_text_file(path: Path, byte_limit: int) -> str | None:
    try:
        size = path.stat().st_size
        if size < 0 or size > byte_limit:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    else:
        if b"\x00" in raw:
            return None
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
    if not _looks_like_text(text):
        return None
    return text


def _looks_like_text(text: str) -> bool:
    if not text:
        return True
    controls = sum(1 for character in text if ord(character) < 32 and character not in "\n\r\t\f")
    return controls * 100 <= len(text)


def _load_json_mapping(root: Path, relative: str) -> tuple[Mapping[str, Any] | None, str]:
    path = _safe_project_path(root, relative)
    if path is None or not _is_regular_file(path):
        return None, f"{relative} is unavailable."
    text = _read_text_file(path, _MAX_METADATA_BYTES)
    if text is None:
        return None, f"{relative} is unreadable, binary, or too large."
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None, f"{relative} is not valid JSON."
    if not isinstance(payload, Mapping):
        return None, f"{relative} does not contain a JSON object."
    return payload, f"Loaded {relative}."


def _safe_project_path(root: Path, relative: str | Path) -> Path | None:
    try:
        candidate_relative = Path(relative)
    except (TypeError, ValueError):
        return None
    if candidate_relative.is_absolute():
        return None
    candidate = root / candidate_relative
    return candidate if _is_within(root, candidate) else None


def _semantic_entities(payload: Mapping[str, Any] | None) -> list[dict[str, str]]:
    if not isinstance(payload, Mapping):
        return []
    source = _payload_mapping(payload, ("entities",))
    value = source.get("entities")
    records = _records(value, key_field="id", markers=("id", "name", "kind", "type"))
    entities: dict[str, dict[str, str]] = {}
    for record in records:
        raw = _record_mapping(record, "id")
        name = _text(raw.get("name") or raw.get("label") or raw.get("id"))
        if not name:
            continue
        kind = _text(raw.get("kind") or raw.get("type")) or "entity"
        entity_id = _text(raw.get("id")) or f"semantic:{kind}:{name}:{_digest(raw, length=12)}"
        item = {"id": entity_id, "name": name, "kind": kind}
        existing = entities.get(entity_id)
        if existing is None or _canonical_json(item) < _canonical_json(existing):
            entities[entity_id] = item
    return [entities[key] for key in sorted(entities)]


def _mapped_entity_ids(entities: list[dict[str, str]], source_files: list[tuple[str, Path, str]]) -> set[str]:
    mapped: set[str] = set()
    contents = [content for _relative, _path, content in source_files]
    for entity in entities:
        pattern = _entity_pattern(entity["name"])
        if pattern is None:
            continue
        if any(pattern.search(content) is not None for content in contents):
            mapped.add(entity["id"])
    return mapped


def _entity_pattern(name: str) -> re.Pattern[str] | None:
    if not name or len(name) > 512:
        return None
    escaped = re.escape(name)
    start_boundary = r"(?<![A-Za-z0-9_])" if name[0].isalnum() or name[0] == "_" else ""
    end_boundary = r"(?![A-Za-z0-9_])" if name[-1].isalnum() or name[-1] == "_" else ""
    try:
        return re.compile(f"{start_boundary}{escaped}{end_boundary}", re.IGNORECASE)
    except re.error:
        return None


def _planned_modules(payload: Mapping[str, Any] | None, root: Path) -> dict[str, set[str]]:
    if not isinstance(payload, Mapping):
        return {}
    source = _payload_mapping(payload, ("tasks", "modules", "priorities"))
    modules: dict[str, set[str]] = {}

    def add(module_value: Any, file_value: Any = None) -> None:
        module = _text(module_value)
        if not module:
            return
        files = modules.setdefault(module, set())
        for raw_file in _reference_values(file_value):
            safe = _safe_project_path(root, raw_file)
            relative = _relative_path(root, safe) if safe is not None else None
            if relative:
                files.add(relative)

    for record in _records(source.get("tasks"), key_field="name", markers=("name", "metadata", "module", "module_file")):
        raw = _record_mapping(record, "name")
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
        add(
            metadata.get("module") if isinstance(metadata, Mapping) else raw.get("module"),
            metadata.get("module_file") if isinstance(metadata, Mapping) else raw.get("module_file"),
        )
        if isinstance(metadata, Mapping) and not metadata.get("module"):
            add(raw.get("module"), raw.get("module_file"))

    raw_modules = source.get("modules")
    if isinstance(raw_modules, Mapping):
        for module, detail in sorted(raw_modules.items(), key=lambda item: _canonical_json(item[0])):
            if isinstance(detail, Mapping):
                add(module, detail.get("module_file") or detail.get("file") or detail.get("path"))
            else:
                add(module)
    for record in _records(source.get("priorities"), key_field="module", markers=("module", "module_file", "file", "path")):
        raw = _record_mapping(record, "module")
        add(raw.get("module"), raw.get("module_file") or raw.get("file") or raw.get("path"))
    return {module: modules[module] for module in sorted(modules, key=str.casefold)}


def _covered_modules(
    planned_modules: Mapping[str, set[str]],
    source_files: list[tuple[str, Path, str]],
) -> set[str]:
    source_relatives = {relative.casefold() for relative, _path, _content in source_files}
    source_stems = {Path(relative).stem.casefold() for relative, _path, _content in source_files}
    covered: set[str] = set()
    for module, declared_files in planned_modules.items():
        module_key = module.casefold()
        if any(path.casefold() in source_relatives for path in declared_files):
            covered.add(module)
            continue
        if module_key in source_stems:
            covered.add(module)
    return covered


def _coverage_status(mapped: int, total: int, *, valid: bool) -> str:
    if not valid:
        return "unavailable"
    if total <= 0:
        return "pass"
    if mapped >= total:
        return "pass"
    return "partial"


def _has_semantic_entities_collection(payload: Mapping[str, Any] | None) -> bool:
    if not isinstance(payload, Mapping):
        return False
    source = _payload_mapping(payload, ("entities",))
    statuses = {
        status.casefold()
        for status in (_text(payload.get("status")), _text(source.get("status")))
        if status
    }
    if statuses.intersection(_INVALID_SEMANTIC_STATUSES):
        return False
    return isinstance(source.get("entities"), (Mapping, list, tuple, set, frozenset))


def _has_plan_collection(payload: Mapping[str, Any] | None) -> bool:
    if not isinstance(payload, Mapping):
        return False
    source = _payload_mapping(payload, ("tasks", "modules", "priorities"))
    return any(
        isinstance(source.get(key), (Mapping, list, tuple, set, frozenset))
        for key in ("tasks", "modules", "priorities")
    )


def _ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(max(0.0, min(1.0, numerator / denominator)), 4)


def _result_status(checks: list[dict[str, Any]]) -> str:
    statuses = [str(check.get("status") or "unavailable") for check in checks]
    if statuses and all(status == "unavailable" for status in statuses):
        return "unavailable"
    if statuses and all(status == "pass" for status in statuses):
        return "ok"
    return "partial"


def _recommendations(checks: list[dict[str, Any]], coverage: Mapping[str, Any]) -> list[str]:
    status_by_name = {str(check["name"]): str(check["status"]) for check in checks}
    recommendations: set[str] = set()
    if status_by_name.get("readme") != "pass":
        recommendations.add("Add a readable README.md describing the reconstruction scope.")
    if status_by_name.get("source_files") != "pass":
        recommendations.add("Add readable text source files before attempting static reconstruction validation.")
    if status_by_name.get("build_entry") != "pass":
        recommendations.add("Add a static build entry such as CMakeLists.txt, Makefile, or a project file.")
    if status_by_name.get("semantic_ir") != "pass":
        recommendations.add("Provide analysis/semantic_ir.json or pass semantic_ir directly to verify_reconstruction.")
    if status_by_name.get("reconstruction_plan") != "pass":
        recommendations.add("Provide a valid analysis/reconstruction_plan.json with planned modules.")
    if status_by_name.get("semantic_mapping") == "partial":
        recommendations.add("Add stable semantic entity names to readable source files to improve semantic coverage.")
    if status_by_name.get("module_coverage") == "partial":
        recommendations.add("Add or reference readable source files for each planned reconstruction module.")
    semantic_entity_count = coverage.get("semantic_entity_count")
    if (
        not recommendations
        and isinstance(semantic_entity_count, int)
        and semantic_entity_count > 0
        and float(coverage.get("semantic_coverage") or 0.0) < 1.0
    ):
        recommendations.add("Increase semantic entity coverage in the generated source files.")
    return sorted(recommendations)


def _payload_mapping(payload: Mapping[str, Any], expected_keys: tuple[str, ...]) -> Mapping[str, Any]:
    if any(key in payload for key in expected_keys):
        return payload
    for candidate in (payload.get("data"), payload.get("result")):
        if isinstance(candidate, Mapping):
            if any(key in candidate for key in expected_keys):
                return candidate
            nested = candidate.get("data")
            if isinstance(nested, Mapping) and any(key in nested for key in expected_keys):
                return nested
    return payload


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


def _reference_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        values: list[str] = []
        for key in ("path", "file", "module_file", "name", "value"):
            text = _text(value.get(key))
            if text:
                values.append(text)
        return sorted(set(values))
    if isinstance(value, (list, tuple, set, frozenset)):
        values: list[str] = []
        for item in value:
            values.extend(_reference_values(item))
        return sorted(set(values))
    text = _text(value)
    return [text] if text else []


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, Mapping) or isinstance(value, (list, tuple, set, frozenset)):
        return None
    text = str(value).strip()
    return text or None


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
