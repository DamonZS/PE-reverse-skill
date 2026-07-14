"""Read-only Windows runtime evidence for Unity IL2CPP, Unity Mono, and Unreal.

The production backend deliberately exposes only process probing, module
enumeration, and ``ReadProcessMemory``.  Evidence extraction is bounded by
provider-owned limits even when a request or injected backend is untrusted.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Optional, Protocol, Sequence

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)


_AUDIT_SCHEMA_VERSION = 1
_DEFAULT_MAX_TOTAL_READ_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_MODULE_READ_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_SINGLE_READ_BYTES = 64 * 1024
_DEFAULT_MAX_MODULES = 64
_DEFAULT_MAX_EVIDENCE = 256
_DEFAULT_MAX_EXPORT_NAMES = 1024

_HARD_MAX_TOTAL_READ_BYTES = 64 * 1024 * 1024
_HARD_MAX_MODULE_READ_BYTES = 16 * 1024 * 1024
_HARD_MAX_SINGLE_READ_BYTES = 1024 * 1024
_HARD_MAX_MODULES = 256
_HARD_MAX_EVIDENCE = 2048
_HARD_MAX_EXPORT_NAMES = 8192
_MAX_EXPORT_NAME_BYTES = 512
_MAX_PE_HEADER_OFFSET = 1024 * 1024
_MAX_READ_LOG_ENTRIES = 256
_MAX_PE_SECTIONS = 96
_MAX_RUNTIME_CODE_SCAN_BYTES = 512 * 1024
_MAX_RUNTIME_STRING_BYTES = 256
_MAX_IL2CPP_REGISTRATION_COUNT = 8_000_000
_MAX_IL2CPP_CODEGEN_MODULES = 65_536
_MAX_IL2CPP_CODEGEN_MODULE_BYTES = 2 * 1024 * 1024
_MAX_IL2CPP_CODEGEN_MODULE_NAMES = 128
_MAX_IL2CPP_METHOD_TOKEN_MAPPINGS = 4096
_MAX_UNREAL_OBJECTS = 16_000_000
_MAX_UNREAL_CHUNKS = 65_536
_MAX_UNREAL_REFLECTION_SCAN_BYTES = 512 * 1024
_MAX_UNREAL_REFLECTION_CLUES = 256
_MAX_MONO_METADATA_BYTES = 8 * 1024 * 1024
_MAX_MONO_STREAMS = 64
_MAX_MONO_TYPES = 100_000
_MAX_MONO_METHODS = 500_000
_MAX_RUNTIME_DUMP_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_DUMP_ENTITIES = 100_000
_MAX_RUNTIME_DUMP_RELATIONS = 200_000
_MAX_RUNTIME_DUMP_ERRORS = 128
_RUNTIME_DUMP_SCHEMA_VERSION = 1

_SUPPORTED_ACTIONS = {"analyze"}
_ACTION_ALIASES = {
    "collect": "analyze",
    "detect": "analyze",
    "extract": "analyze",
    "inspect": "analyze",
    "runtime_analyze": "analyze",
    "runtime_inspect": "analyze",
    "scan": "analyze",
}
_MUTATION_PARAMETER_KEYS = {
    "allocation_type",
    "data",
    "data_hex",
    "expected",
    "expected_hex",
    "free_type",
    "new_protection",
    "patch",
    "replacement",
    "write",
}

_ENGINE_LABELS = {
    "unity_il2cpp": "Unity IL2CPP",
    "unity_mono": "Unity Mono",
    "unreal": "Unreal Engine",
}

_MONO_MODULE_NAMES = frozenset(
    {
        "mono.dll",
        "mono-2.0-bdwgc.dll",
        "mono-2.0-sgen.dll",
    }
)

# These are embedding entry points exported by the Mono runtime.  A string
# match is only a candidate; the Mono extractor separately proves the export
# RVA, loaded VA, and executable section.
_MONO_EMBEDDING_EXPORT_ROLES = {
    "mono_get_root_domain": "root_domain",
    "mono_domain_get": "current_domain",
    "mono_thread_attach": "thread_attach",
    "mono_thread_detach": "thread_detach",
    "mono_assembly_open": "assembly_open",
    "mono_assembly_foreach": "assembly_foreach",
    "mono_assembly_get_image": "assembly_get_image",
    "mono_image_get_name": "image_get_name",
    "mono_class_from_name": "class_from_name",
    "mono_class_get_methods": "class_get_methods",
    "mono_method_get_name": "method_get_name",
    "mono_runtime_invoke": "runtime_invoke",
    "mono_object_get_class": "object_get_class",
    "mono_string_to_utf8": "string_to_utf8",
}

# The strings are candidates, not proof by themselves. Export-table matches
# and module identities receive stronger weights during summarization.
_STRING_MARKERS: tuple[tuple[str, str, float], ...] = (
    ("unity_il2cpp", "il2cpp_init", 2.0),
    ("unity_il2cpp", "il2cpp_domain_get", 2.0),
    ("unity_il2cpp", "il2cpp_thread_attach", 2.0),
    ("unity_il2cpp", "il2cpp_class_from_name", 2.0),
    ("unity_il2cpp", "il2cpp_resolve_icall", 2.0),
    ("unity_il2cpp", "global-metadata.dat", 2.5),
    ("unity_il2cpp", "GameAssembly.dll", 2.5),
    ("unity_il2cpp", "UnityPlayer.dll", 1.0),
    ("unity_il2cpp", "Il2CppGlobalMetadataHeader", 2.0),
    ("unity_il2cpp", "UnityEngine.CoreModule", 1.0),
    ("unreal", "FNamePool", 2.0),
    ("unreal", "GNames", 1.5),
    ("unreal", "GUObjectArray", 2.0),
    ("unreal", "GObjects", 1.5),
    ("unreal", "GWorld", 1.5),
    ("unreal", "ProcessEvent", 2.0),
    ("unreal", "StaticFindObject", 2.0),
    ("unreal", "FEngineLoop", 1.5),
    ("unreal", "/Script/Engine", 2.0),
    ("unreal", "/Game/", 1.0),
    ("unreal", "UnrealEngine", 1.5),
    ("unreal", "UE4Game", 1.5),
)

# Generated IL2CPP releases have used several count/pointer layouts.  A
# profile is accepted only when every pair is range checked and its final
# codeGenModules table resolves at least one real module-name string.
_IL2CPP_CODE_REGISTRATION_PROFILES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "legacy-v24",
        (
            "method_pointers",
            "reverse_pinvoke_wrappers",
            "generic_method_pointers",
            "invoker_pointers",
            "custom_attribute_generators",
            "unresolved_virtual_call_pointers",
            "interop_data",
            "windows_runtime_factories",
            "codegen_modules",
        ),
    ),
    (
        "v24.2-v27",
        (
            "reverse_pinvoke_wrappers",
            "generic_method_pointers",
            "invoker_pointers",
            "unresolved_virtual_call_pointers",
            "interop_data",
            "windows_runtime_factories",
            "codegen_modules",
        ),
    ),
    (
        "v27.1+",
        (
            "reverse_pinvoke_wrappers",
            "generic_method_pointers",
            "generic_adjustor_thunks",
            "invoker_pointers",
            "unresolved_virtual_call_pointers",
            "interop_data",
            "windows_runtime_factories",
            "codegen_modules",
        ),
    ),
)

_IL2CPP_METADATA_REGISTRATION_FIELDS: tuple[tuple[str, int], ...] = (
    ("generic_classes", 0),
    ("generic_insts", 0),
    ("generic_method_table", 12),
    ("types", 0),
    ("method_specs", 12),
    ("field_offsets", 0),
    ("type_definition_sizes", 0),
    ("metadata_usages", 0),
)

_UNREAL_GLOBAL_EXPORT_ROLES = {
    "fnamepool": "gnames",
    "gnames": "gnames",
    "gobjects": "gobjects",
    "guobjectarray": "gobjects",
    "gworld": "gworld",
}

_UNREAL_CALLABLE_EXPORT_ROLES = {
    "processevent": "process_event",
    "staticclass": "static_class",
    "staticfindobject": "static_find_object",
}

_UNREAL_CONTEXTUAL_MODULES = frozenset(
    {
        "engine.dll",
        "inputcore.dll",
        "rendercore.dll",
        "rhi.dll",
        "slate.dll",
        "slatecore.dll",
        "umg.dll",
    }
)

# Marker addresses below are always string-storage addresses.  They become
# runtime object or pool addresses only through a separate structural proof.
_UNREAL_REFLECTION_MARKERS: tuple[tuple[str, str, str, float], ...] = (
    ("WidgetBlueprintGeneratedClass", "umg_generated_class", "umg_name", 2.5),
    ("/Script/CoreUObject", "reflection_package", "script_package_name", 2.5),
    ("StaticFindObject", "uobject_lookup", "reflection_api_name", 2.5),
    ("WidgetBlueprint", "umg_blueprint", "umg_name", 2.0),
    ("GUObjectArray", "object_array_global", "runtime_global_name", 2.5),
    ("/Script/Engine", "engine_package", "script_package_name", 2.0),
    ("/Script/UMG", "umg_package", "umg_name", 3.0),
    ("ProcessEvent", "ufunction_dispatch", "reflection_api_name", 2.5),
    ("UUserWidget", "umg_widget", "umg_name", 2.5),
    ("FNamePool", "name_pool", "name_system_name", 2.5),
    ("StaticClass", "uclass_lookup", "reflection_api_name", 2.0),
    ("UFunction", "ufunction", "reflection_type_name", 2.5),
    ("UProperty", "property", "reflection_type_name", 2.0),
    ("FProperty", "property", "reflection_type_name", 2.0),
    ("UObject", "uobject", "reflection_type_name", 2.5),
    ("UClass", "uclass", "reflection_type_name", 2.5),
    ("UStruct", "ustruct", "reflection_type_name", 2.0),
    ("GObjects", "object_array_global", "runtime_global_name", 2.0),
    ("GNames", "name_global", "runtime_global_name", 2.0),
    ("GWorld", "world_global", "runtime_global_name", 2.0),
    ("FName", "name", "name_system_name", 1.5),
    ("WBP_", "umg_blueprint_name", "umg_name", 2.0),
)

_RUNTIME_ENGINE_ALIASES = {
    "il2cpp": "unity_il2cpp",
    "mono": "unity_mono",
    "ue": "unreal",
    "ue4": "unreal",
    "ue5": "unreal",
    "unity-il2cpp": "unity_il2cpp",
    "unity-mono": "unity_mono",
    "unity_il2cpp": "unity_il2cpp",
    "unity_mono": "unity_mono",
    "unreal": "unreal",
    "unreal-engine": "unreal",
}

_RUNTIME_COLLECTOR_SUCCESS_STATES = frozenset(
    {"available", "captured", "complete", "ok", "ready", "success"}
)
_RUNTIME_COLLECTOR_TEST_DOUBLE_MARKERS = (
    "fake",
    "mock",
    "stub",
    "synthetic",
    "test-double",
    "test_double",
)
_KNOWN_RUNTIME_COLLECTORS = frozenset(
    {
        "frida",
        "offline-runtime-dump",
        "process-memory",
        "readprocessmemory",
        "runtime-dump",
        "win32-readprocessmemory",
    }
)

# Profiles describe only the global layouts used by the offline parser.  A
# profile never proves that a dump belongs to that version; compatibility and
# every address are validated independently from the captured evidence.
_UNREAL_RUNTIME_PROFILES: dict[str, dict[str, Any]] = {
    "ue4.22-win64": {
        "id": "ue4.22-win64",
        "engine_family": "unreal",
        "version": {"major": 4, "minor_min": 0, "minor_max": 22},
        "pointer_size": 8,
        "globals": {
            "name_store": {
                "symbol": "GNames",
                "kind": "TNameEntryArray",
                "indirection": 1,
            },
            "object_array": {
                "symbol": "GObjects",
                "kind": "FUObjectArray",
                "indirection": 0,
            },
            "world": {"symbol": "GWorld", "kind": "UWorld", "indirection": 1},
        },
    },
    "ue4.23-win64": {
        "id": "ue4.23-win64",
        "engine_family": "unreal",
        "version": {"major": 4, "minor_min": 23, "minor_max": 27},
        "pointer_size": 8,
        "globals": {
            "name_store": {
                "symbol": "FNamePool",
                "kind": "FNamePool",
                "indirection": 0,
            },
            "object_array": {
                "symbol": "GObjects",
                "kind": "FUObjectArray",
                "indirection": 0,
            },
            "world": {"symbol": "GWorld", "kind": "UWorld", "indirection": 1},
        },
    },
    "ue5-win64": {
        "id": "ue5-win64",
        "engine_family": "unreal",
        "version": {"major": 5, "minor_min": 0, "minor_max": 99},
        "pointer_size": 8,
        "globals": {
            "name_store": {
                "symbol": "FNamePool",
                "kind": "FNamePool",
                "indirection": 0,
            },
            "object_array": {
                "symbol": "GObjects",
                "kind": "FUObjectArray",
                "indirection": 0,
            },
            "world": {"symbol": "GWorld", "kind": "UWorld", "indirection": 1},
        },
    },
}


def parse_engine_runtime_dump(
    payload: Mapping[str, Any] | str | Path | bytes,
    *,
    source_path: str | Path | None = None,
) -> dict[str, Any]:
    """Parse a captured runtime dump without attaching to a process.

    Offline parsing is evidence-preserving rather than a fallback collector.
    The payload must identify an available, non-test-double collector; absent
    runtime dependencies therefore remain explicitly unavailable.
    """

    loaded, load_provenance, load_error = _load_engine_runtime_dump(
        payload,
        source_path=source_path,
    )
    if load_error is not None or loaded is None:
        return _runtime_dump_unavailable(
            engine="unknown",
            reason=load_error or "runtime dump payload is unavailable",
            dependency_status="unavailable",
            provenance=load_provenance,
        )

    schema = loaded.get("schema_version", loaded.get("schema"))
    if not _supported_runtime_dump_schema(schema):
        return _runtime_dump_unavailable(
            engine=_normalize_runtime_engine(loaded.get("engine")) or "unknown",
            reason=(
                "runtime dump schema_version must identify engine-runtime-dump v1"
            ),
            dependency_status="unavailable",
            provenance=load_provenance,
        )

    collector, collector_error = _runtime_dump_collector(loaded)
    if collector_error is not None:
        return _runtime_dump_unavailable(
            engine=_normalize_runtime_engine(loaded.get("engine")) or "unknown",
            reason=collector_error,
            dependency_status="unavailable",
            provenance={**load_provenance, "collector": collector},
        )

    engine = _normalize_runtime_engine(
        loaded.get("engine")
        or ((loaded.get("runtime") or {}).get("engine") if isinstance(loaded.get("runtime"), Mapping) else None)
    )
    if engine is None:
        return _runtime_dump_unavailable(
            engine="unknown",
            reason="runtime dump does not declare a supported engine",
            dependency_status="unavailable",
            provenance={**load_provenance, "collector": collector},
        )

    engine_data = _runtime_engine_payload(loaded, engine)
    provenance = {
        **load_provenance,
        "collector": collector,
        "capture_provenance": _json_mapping(loaded.get("provenance")),
        "read_only": True,
        "remote_api_calls": False,
        "parser": "engine-runtime-dump-v1",
    }
    if engine == "unity_mono":
        parsed = _parse_mono_runtime_dump(engine_data, provenance)
    elif engine == "unity_il2cpp":
        parsed = _parse_il2cpp_runtime_dump(loaded, engine_data, provenance)
    else:
        parsed = _parse_unreal_runtime_dump(loaded, engine_data, provenance)

    result = {
        "schema_version": _RUNTIME_DUMP_SCHEMA_VERSION,
        "status": parsed.get("status", "partial"),
        "engine": engine,
        "operation": "parse_engine_runtime_dump",
        "mode": "offline-runtime-dump",
        "dependency_status": parsed.get(
            "dependency_status",
            {
                "status": "available",
                "collector": collector,
                "parser": "engine-runtime-dump-v1",
            },
        ),
        "engine_analysis": parsed,
        engine: parsed,
        "evidence": list(parsed.get("evidence") or []),
        "semantic_ir_fragment": _json_mapping(parsed.get("semantic_ir_fragment")),
        "provenance": {
            **provenance,
            "normalizer": parsed.get("provenance", {}).get("normalizer"),
        },
        "confidence": float(parsed.get("confidence") or 0.0),
        "errors": [str(item) for item in parsed.get("errors") or []],
    }
    return _prune(result)


def _load_engine_runtime_dump(
    payload: Mapping[str, Any] | str | Path | bytes,
    *,
    source_path: str | Path | None,
) -> tuple[Optional[dict[str, Any]], dict[str, Any], Optional[str]]:
    source_kind = "inline"
    resolved_path: Optional[Path] = None
    raw: bytes
    if isinstance(payload, Mapping):
        loaded = _json_mapping(payload)
        raw = json.dumps(
            loaded, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    else:
        if isinstance(payload, Path):
            resolved_path = payload.expanduser().resolve()
        elif isinstance(payload, str) and not payload.lstrip().startswith(("{", "[")):
            candidate = Path(payload).expanduser()
            if candidate.exists():
                resolved_path = candidate.resolve()
        if source_path is not None:
            resolved_path = Path(source_path).expanduser().resolve()
        if resolved_path is not None:
            source_kind = "file"
            try:
                size = resolved_path.stat().st_size
                if size > _MAX_RUNTIME_DUMP_BYTES:
                    return None, {
                        "source_kind": source_kind,
                        "source_path": str(resolved_path),
                        "size": size,
                    }, f"runtime dump exceeds the {_MAX_RUNTIME_DUMP_BYTES}-byte limit"
                raw = resolved_path.read_bytes()
            except OSError as exc:
                return None, {
                    "source_kind": source_kind,
                    "source_path": str(resolved_path),
                }, f"runtime dump could not be read: {exc}"
        elif isinstance(payload, bytes):
            raw = payload
        elif isinstance(payload, str):
            raw = payload.encode("utf-8")
        else:
            return None, {"source_kind": source_kind}, "unsupported runtime dump payload type"
        if len(raw) > _MAX_RUNTIME_DUMP_BYTES:
            return None, {
                "source_kind": source_kind,
                "size": len(raw),
            }, f"runtime dump exceeds the {_MAX_RUNTIME_DUMP_BYTES}-byte limit"
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return None, {
                "source_kind": source_kind,
                "source_path": str(resolved_path) if resolved_path else None,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }, f"runtime dump is not valid UTF-8 JSON: {exc}"
        if not isinstance(decoded, Mapping):
            return None, {
                "source_kind": source_kind,
                "source_path": str(resolved_path) if resolved_path else None,
                "size": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }, "runtime dump JSON root must be an object"
        loaded = _json_mapping(decoded)
    return loaded, _prune(
        {
            "source_kind": source_kind,
            "source_path": str(resolved_path) if resolved_path else None,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
    ), None


def _supported_runtime_dump_schema(value: Any) -> bool:
    if _coerce_int(value) == _RUNTIME_DUMP_SCHEMA_VERSION:
        return True
    normalized = str(value or "").strip().lower().replace("_", "-")
    return normalized in {
        "engine-runtime-dump-v1",
        "engine-runtime-dump/1",
        "engine-runtime-dump/v1",
    }


def _runtime_dump_collector(
    payload: Mapping[str, Any],
) -> tuple[dict[str, Any], Optional[str]]:
    raw: Any = payload.get("collector")
    provenance = payload.get("provenance")
    if raw is None and isinstance(provenance, Mapping):
        raw = provenance.get("collector")
    capture = payload.get("capture")
    if raw is None and isinstance(capture, Mapping):
        raw = capture.get("collector")
    if raw is None:
        return {}, "runtime dump collector dependency is not declared"
    if isinstance(raw, str):
        collector = {"name": raw}
    elif isinstance(raw, Mapping):
        collector = _json_mapping(raw)
    else:
        return {}, "runtime dump collector declaration must be an object or string"
    name = str(
        collector.get("name")
        or collector.get("kind")
        or collector.get("backend")
        or ""
    ).strip()
    normalized_name = name.lower().replace("_", "-")
    if not normalized_name:
        return collector, "runtime dump collector name is missing"
    if any(marker in normalized_name for marker in _RUNTIME_COLLECTOR_TEST_DOUBLE_MARKERS):
        return collector, "test-double runtime collectors cannot satisfy the capability dependency"
    if bool(collector.get("test_double") or collector.get("mock") or collector.get("synthetic")):
        return collector, "test-double runtime collectors cannot satisfy the capability dependency"
    status = str(collector.get("status") or "").strip().lower()
    available = collector.get("available")
    if available is False or status in {"blocked", "failed", "missing", "unavailable"}:
        reason = str(collector.get("reason") or "runtime collector is unavailable")
        return collector, reason
    declared_available = (
        available is True
        or status in _RUNTIME_COLLECTOR_SUCCESS_STATES
        or (not status and normalized_name in _KNOWN_RUNTIME_COLLECTORS)
    )
    if not declared_available:
        return collector, "runtime collector availability is not proven"
    collector.update({"name": name, "status": status or "available", "available": True})
    return collector, None


def _normalize_runtime_engine(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace(" ", "-")
    return _RUNTIME_ENGINE_ALIASES.get(normalized)


def _runtime_engine_payload(
    payload: Mapping[str, Any], engine: str
) -> dict[str, Any]:
    aliases = {
        "unity_mono": ("unity_mono", "unity-mono", "mono"),
        "unity_il2cpp": ("unity_il2cpp", "unity-il2cpp", "il2cpp"),
        "unreal": ("unreal", "ue", "ue4", "ue5"),
    }[engine]
    runtime = payload.get("runtime")
    containers = [runtime, payload.get("data"), payload]
    for container in containers:
        if not isinstance(container, Mapping):
            continue
        for alias in aliases:
            value = container.get(alias)
            if isinstance(value, Mapping):
                return _json_mapping(value)
    if isinstance(runtime, Mapping):
        return _json_mapping(runtime)
    data = payload.get("data")
    return _json_mapping(data if isinstance(data, Mapping) else payload)


def _runtime_dump_unavailable(
    *,
    engine: str,
    reason: str,
    dependency_status: str,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    fragment = _empty_runtime_semantic_fragment(engine, "unavailable")
    dependency = {
        "status": dependency_status,
        "parser": "engine-runtime-dump-v1",
        "reason": reason,
    }
    return _prune(
        {
            "schema_version": _RUNTIME_DUMP_SCHEMA_VERSION,
            "status": "unavailable",
            "engine": engine,
            "operation": "parse_engine_runtime_dump",
            "mode": "offline-runtime-dump",
            "dependency_status": dependency,
            "evidence": [],
            "semantic_ir_fragment": fragment,
            "provenance": _json_mapping(provenance),
            "confidence": 0.0,
            "errors": [reason],
        }
    )


def _parse_mono_runtime_dump(
    payload: Mapping[str, Any], provenance: Mapping[str, Any]
) -> dict[str, Any]:
    return _parse_structured_runtime_dump(
        payload,
        engine="unity_mono",
        collections={
            "domains": "mono_domain",
            "assemblies": "mono_assembly",
            "images": "mono_image",
            "classes": "mono_class",
            "methods": "mono_method",
            "fields": "mono_field",
        },
        provenance=provenance,
    )


def _parse_il2cpp_runtime_dump(
    root: Mapping[str, Any],
    payload: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    combined = dict(payload)
    for key in ("code_registration", "metadata_registration"):
        if key not in combined and key in root:
            combined[key] = root[key]
    parsed = _parse_structured_runtime_dump(
        combined,
        engine="unity_il2cpp",
        collections={
            "code_registration": "code_registration",
            "metadata_registration": "metadata_registration",
            "codegen_modules": "codegen_module",
            "assemblies": "il2cpp_assembly",
            "classes": "il2cpp_class",
            "methods": "il2cpp_method",
            "fields": "il2cpp_field",
        },
        provenance=provenance,
    )
    counts = parsed.get("entity_counts") or {}
    missing = [
        role
        for role in ("code_registration", "metadata_registration")
        if not counts.get(role)
    ]
    if missing and parsed.get("status") != "unavailable":
        parsed["status"] = "partial"
        parsed.setdefault("errors", []).append(
            "IL2CPP runtime dump is missing validated " + ", ".join(missing)
        )
        parsed["semantic_ir_fragment"]["status"] = "partial"
    return parsed


def _parse_unreal_runtime_dump(
    root: Mapping[str, Any],
    payload: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    combined = dict(payload)
    if "version" not in combined and "version" in root:
        combined["version"] = root["version"]
    parsed = _parse_structured_runtime_dump(
        combined,
        engine="unreal",
        collections={
            "globals": "unreal_global",
            "names": "unreal_name",
            "objects": "uobject",
            "classes": "uclass",
            "functions": "ufunction",
            "properties": "uproperty",
            "widgets": "umg_widget",
        },
        provenance=provenance,
    )
    version = combined.get("version") or combined.get("engine_version")
    parsed["engine_version"] = _json_value(version)
    if not version and parsed.get("status") != "unavailable":
        parsed["status"] = "partial"
        parsed.setdefault("errors", []).append(
            "Unreal runtime dump does not declare a version or layout profile"
        )
        parsed["semantic_ir_fragment"]["status"] = "partial"
    return parsed


def _parse_structured_runtime_dump(
    payload: Mapping[str, Any],
    *,
    engine: str,
    collections: Mapping[str, str],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    entities: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    errors: list[str] = []
    aliases: dict[str, str] = {}
    pending_parents: list[tuple[str, str, str]] = []
    counts: dict[str, int] = {}

    for collection_name, role in collections.items():
        entries = _runtime_dump_collection(payload.get(collection_name))
        if len(entities) + len(entries) > _MAX_RUNTIME_DUMP_ENTITIES:
            errors.append(
                f"runtime dump exceeds the {_MAX_RUNTIME_DUMP_ENTITIES}-entity limit"
            )
            entries = entries[: max(0, _MAX_RUNTIME_DUMP_ENTITIES - len(entities))]
        for index, entry in enumerate(entries):
            address = _runtime_dump_address(entry)
            name = str(
                entry.get("name")
                or entry.get("full_name")
                or entry.get("symbol")
                or entry.get("id")
                or f"{role}_{index}"
            ).strip()
            if address is None or address <= 0:
                _append_runtime_dump_error(
                    errors,
                    f"{collection_name}[{index}] lacks a positive runtime address",
                )
                continue
            raw_id = str(entry.get("id") or "").strip()
            entity_id = "engine-runtime:" + _canonical_hash(
                [engine, role, address, raw_id or name]
            )[:24]
            attributes = {
                key: _json_value(value)
                for key, value in entry.items()
                if key not in {"address", "runtime_address", "va", "pointer"}
            }
            attributes.update(
                {
                    "engine": engine,
                    "role": role,
                    "address": address,
                    "address_hex": _hex(address),
                    "address_kind": "runtime_va",
                    "collector_verified": True,
                }
            )
            entities.append(
                {
                    "id": entity_id,
                    "kind": "runtime_symbol",
                    "name": name,
                    "confidence": 0.95,
                    "attributes": attributes,
                    "evidence": [
                        {
                            "source": "engine_runtime_dump",
                            "collection": collection_name,
                            "runtime_address": address,
                        }
                    ],
                }
            )
            counts[role] = counts.get(role, 0) + 1
            for alias in (raw_id, name, str(address), _hex(address)):
                if alias:
                    aliases.setdefault(alias.lower(), entity_id)
            parent = next(
                (
                    entry.get(key)
                    for key in (
                        "parent_id",
                        "parent",
                        "owner",
                        "assembly",
                        "class",
                        "module",
                        "outer",
                    )
                    if entry.get(key) not in (None, "")
                ),
                None,
            )
            if parent is not None:
                pending_parents.append((entity_id, str(parent), role))

    for source_id, parent, role in pending_parents:
        target_id = aliases.get(parent.lower())
        if target_id is None or target_id == source_id:
            continue
        if len(relations) >= _MAX_RUNTIME_DUMP_RELATIONS:
            _append_runtime_dump_error(
                errors,
                f"runtime dump exceeds the {_MAX_RUNTIME_DUMP_RELATIONS}-relation limit",
            )
            break
        relations.append(
            {
                "id": "engine-runtime:"
                + _canonical_hash([source_id, target_id, "member_of"])[:24],
                "type": "member_of",
                "source": source_id,
                "target": target_id,
                "confidence": 0.95,
                "attributes": {"source_role": role},
                "evidence": [{"source": "engine_runtime_dump"}],
            }
        )

    if not entities:
        status = "unavailable"
        _append_runtime_dump_error(
            errors, "runtime dump contains no validated runtime-address entities"
        )
    else:
        status = "partial" if errors else "ok"
    semantic = {
        "status": status,
        "schema_version": 1,
        "engine": engine,
        "entities": entities,
        "relations": relations,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "validated_symbol_count": len(entities),
        },
    }
    return {
        "status": status,
        "engine": engine,
        "entities": entities,
        "entity_counts": counts,
        "relations": relations,
        "evidence": [
            {
                "kind": "runtime_dump_inventory",
                "entity_count": len(entities),
                "relation_count": len(relations),
                "collector": _json_mapping(provenance.get("collector")),
            }
        ],
        "semantic_ir_fragment": semantic,
        "provenance": {
            **_json_mapping(provenance),
            "normalizer": "engine-runtime-dump-v1",
        },
        "confidence": 0.95 if status == "ok" else (0.7 if entities else 0.0),
        "errors": errors,
    }


def _runtime_dump_collection(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        if any(
            key in value
            for key in ("address", "runtime_address", "va", "pointer", "id")
        ):
            return [_json_mapping(value)]
        result: list[dict[str, Any]] = []
        for key, item in value.items():
            if isinstance(item, Mapping):
                normalized = _json_mapping(item)
                normalized.setdefault("name", str(key))
            else:
                normalized = {"name": str(key), "address": item}
            result.append(normalized)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_mapping(item) for item in value if isinstance(item, Mapping)]
    return []


def _runtime_dump_address(entry: Mapping[str, Any]) -> Optional[int]:
    for key in ("address", "runtime_address", "va", "pointer"):
        parsed = _coerce_int(entry.get(key))
        if parsed is not None:
            return parsed
    return None


def _append_runtime_dump_error(errors: list[str], message: str) -> None:
    if len(errors) < _MAX_RUNTIME_DUMP_ERRORS:
        errors.append(message)


class EngineRuntimeBackendError(RuntimeError):
    """A backend failure with serializable operation details."""

    def __init__(
        self,
        operation: str,
        message: str,
        *,
        code: Optional[int] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(f"{operation}: {message}")
        self.operation = operation
        self.message = message
        self.code = code
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        return _prune(
            {
                "type": type(self).__name__,
                "operation": self.operation,
                "message": self.message,
                "winerror": self.code,
                "details": self.details,
            }
        )


class EngineRuntimeBackend(Protocol):
    """The intentionally read-only backend surface used by the provider."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_process(self, pid: int) -> Mapping[str, Any]: ...

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]: ...

    def read_process_memory(self, pid: int, address: int, size: int) -> bytes: ...


class UnavailableEngineRuntimeBackend:
    """Structured no-op backend for non-Windows or failed Win32 setup."""

    name = "unavailable"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        return {
            "pid": pid,
            "exists": None,
            "accessible": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
            "side_effects": False,
        }

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        del pid
        return []

    def read_process_memory(self, pid: int, address: int, size: int) -> bytes:
        del pid, address, size
        return b""

    read = read_process_memory
    read_memory = read_process_memory
    list_modules = enumerate_modules


class WindowsEngineRuntimeBackend:
    """Read-only Win32 backend implemented with documented APIs via ctypes."""

    name = "windows_ctypes_engine_runtime"

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    ERROR_NO_MORE_FILES = 18
    ERROR_INVALID_PARAMETER = 87
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(
        self,
        *,
        max_single_read_bytes: int = _DEFAULT_MAX_SINGLE_READ_BYTES,
        platform_name: Optional[str] = None,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.max_single_read_bytes = max(
            1,
            min(int(max_single_read_bytes), _HARD_MAX_SINGLE_READ_BYTES),
        )
        self.available = self.platform_name == "win32"
        self.unavailable_reason: Optional[str] = None
        self._kernel32: Any = None
        self._module_entry_type: Any = None
        if not self.available:
            self.unavailable_reason = (
                f"Windows process APIs are unavailable on {self.platform_name}"
            )
            return
        try:
            self._configure_api()
        except Exception as exc:  # pragma: no cover - host API dependent
            self.available = False
            self.unavailable_reason = (
                f"failed to initialize Win32 engine-runtime bindings: {exc}"
            )

    def _configure_api(self) -> None:  # pragma: no cover - exercised on Windows
        from ctypes import wintypes

        byte_pointer = ctypes.POINTER(ctypes.c_ubyte)

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", byte_pointer),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HMODULE),
                ("szModule", wintypes.WCHAR * 256),
                ("szExePath", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        size_type = ctypes.c_size_t
        void_pointer = ctypes.c_void_p

        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Module32FirstW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(MODULEENTRY32W),
        ]
        kernel32.Module32FirstW.restype = wintypes.BOOL
        kernel32.Module32NextW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(MODULEENTRY32W),
        ]
        kernel32.Module32NextW.restype = wintypes.BOOL
        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            void_pointer,
            size_type,
            ctypes.POINTER(size_type),
        ]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL

        self._kernel32 = kernel32
        self._module_entry_type = MODULEENTRY32W

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        if not self.available:
            return UnavailableEngineRuntimeBackend(
                self.unavailable_reason or "Win32 backend unavailable"
            ).probe_process(pid)
        access = self.PROCESS_QUERY_LIMITED_INFORMATION | self.PROCESS_VM_READ
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            code = ctypes.get_last_error()
            return {
                "pid": pid,
                "exists": False if code == self.ERROR_INVALID_PARAMETER else None,
                "accessible": False,
                "status": "unavailable",
                "required_access": access,
                "winerror": code,
                "error": ctypes.FormatError(code).strip(),
                "side_effects": False,
            }
        try:
            from ctypes import wintypes

            image_path = None
            buffer = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(buffer))
            if self._kernel32.QueryFullProcessImageNameW(
                handle,
                0,
                buffer,
                ctypes.byref(length),
            ):
                image_path = buffer.value
            return {
                "pid": pid,
                "exists": True,
                "accessible": True,
                "status": "ok",
                "required_access": access,
                "image_path": image_path,
                "side_effects": False,
            }
        finally:
            self._kernel32.CloseHandle(handle)

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        self._require_available("CreateToolhelp32Snapshot")
        flags = self.TH32CS_SNAPMODULE | self.TH32CS_SNAPMODULE32
        snapshot = self._kernel32.CreateToolhelp32Snapshot(flags, pid)
        if _pointer_value(snapshot) == self.INVALID_HANDLE_VALUE:
            self._raise_last_error(
                "CreateToolhelp32Snapshot",
                details={"pid": pid, "flags": flags},
            )
        modules: list[dict[str, Any]] = []
        try:
            entry = self._module_entry_type()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
                code = ctypes.get_last_error()
                if code == self.ERROR_NO_MORE_FILES:
                    return modules
                self._raise_last_error(
                    "Module32FirstW",
                    code=code,
                    details={"pid": pid},
                )
            while True:
                base = _pointer_value(entry.modBaseAddr)
                size = int(entry.modBaseSize)
                modules.append(
                    {
                        "name": entry.szModule,
                        "path": entry.szExePath,
                        "base_address": base,
                        "size": size,
                        "module_handle": _pointer_value(entry.hModule),
                    }
                )
                entry.dwSize = ctypes.sizeof(entry)
                if not self._kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                    code = ctypes.get_last_error()
                    if code in (0, self.ERROR_NO_MORE_FILES):
                        break
                    self._raise_last_error(
                        "Module32NextW",
                        code=code,
                        details={"pid": pid},
                    )
        finally:
            self._kernel32.CloseHandle(snapshot)
        return modules

    def read_process_memory(self, pid: int, address: int, size: int) -> bytes:
        self._require_available("ReadProcessMemory")
        if address < 0:
            raise EngineRuntimeBackendError(
                "ReadProcessMemory",
                "address must be non-negative",
                details={"pid": pid, "address": address, "size": size},
            )
        if size <= 0 or size > self.max_single_read_bytes:
            raise EngineRuntimeBackendError(
                "ReadProcessMemory",
                "read size is outside the backend limit",
                details={
                    "pid": pid,
                    "address": address,
                    "size": size,
                    "max_single_read_bytes": self.max_single_read_bytes,
                },
            )
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            self._raise_last_error(
                "OpenProcess",
                details={"pid": pid, "required_access": access},
            )
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            ok = self._kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read),
            )
            count = min(int(bytes_read.value), size)
            if not ok and count == 0:
                self._raise_last_error(
                    "ReadProcessMemory",
                    details={"pid": pid, "address": address, "size": size},
                )
            return bytes(buffer.raw[:count])
        finally:
            self._kernel32.CloseHandle(handle)

    read = read_process_memory
    read_memory = read_process_memory
    list_modules = enumerate_modules

    def _require_available(self, operation: str) -> None:
        if not self.available or self._kernel32 is None:
            raise EngineRuntimeBackendError(
                operation,
                self.unavailable_reason or "Win32 backend unavailable",
            )

    def _raise_last_error(
        self,
        operation: str,
        *,
        code: Optional[int] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        selected = ctypes.get_last_error() if code is None else code
        raise EngineRuntimeBackendError(
            operation,
            ctypes.FormatError(selected).strip() or f"Win32 error {selected}",
            code=selected,
            details=details,
        )


@dataclass
class _ReadBudget:
    total_limit: int
    module_limit: int
    single_limit: int
    requested_bytes: int = 0
    returned_bytes: int = 0
    call_count: int = 0
    max_observed_request: int = 0
    truncated: bool = False
    module_requested: dict[str, int] = field(default_factory=dict)
    module_returned: dict[str, int] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def remaining_total(self) -> int:
        return max(0, self.total_limit - self.requested_bytes)

    def remaining_module(self, module_key: str) -> int:
        return max(
            0,
            self.module_limit - self.module_requested.get(module_key, 0),
        )

    def read(
        self,
        backend: Any,
        pid: int,
        module_key: str,
        address: int,
        size: int,
        *,
        purpose: str,
    ) -> bytes:
        if size <= 0:
            return b""
        allowed = min(
            int(size),
            self.single_limit,
            self.remaining_total(),
            self.remaining_module(module_key),
        )
        if allowed < size:
            self.truncated = True
        if allowed <= 0:
            self.truncated = True
            return b""

        self.requested_bytes += allowed
        self.module_requested[module_key] = (
            self.module_requested.get(module_key, 0) + allowed
        )
        self.call_count += 1
        self.max_observed_request = max(self.max_observed_request, allowed)
        call = {
            "module": module_key,
            "address": address,
            "address_hex": _hex(address),
            "requested_bytes": allowed,
            "purpose": purpose,
        }
        try:
            data = _backend_read(backend, pid, address, allowed)
        except Exception as exc:  # a single unreadable page must not abort collection
            error = {
                **call,
                "error": _exception_payload(exc),
            }
            self.errors.append(error)
            self._record_call(error)
            return b""
        if len(data) > allowed:
            data = data[:allowed]
            self.truncated = True
        self.returned_bytes += len(data)
        self.module_returned[module_key] = (
            self.module_returned.get(module_key, 0) + len(data)
        )
        call["returned_bytes"] = len(data)
        call["partial"] = len(data) != allowed
        self._record_call(call)
        return data

    def summary(self) -> dict[str, Any]:
        return {
            "limits": {
                "max_total_read_bytes": self.total_limit,
                "max_module_read_bytes": self.module_limit,
                "max_single_read_bytes": self.single_limit,
            },
            "requested_bytes": self.requested_bytes,
            "returned_bytes": self.returned_bytes,
            "remaining_bytes": self.remaining_total(),
            "call_count": self.call_count,
            "max_observed_request": self.max_observed_request,
            "module_requested_bytes": dict(self.module_requested),
            "module_returned_bytes": dict(self.module_returned),
            "truncated": self.truncated,
            "errors": list(self.errors),
            "calls": list(self.calls),
        }

    def _record_call(self, value: Mapping[str, Any]) -> None:
        if len(self.calls) < _MAX_READ_LOG_ENTRIES:
            self.calls.append(_json_mapping(value))
        else:
            self.truncated = True


@dataclass
class _EvidenceCollector:
    limit: int
    items: list[dict[str, Any]] = field(default_factory=list)
    keys: set[tuple[Any, ...]] = field(default_factory=set)
    truncated: bool = False

    def add(self, item: Mapping[str, Any]) -> None:
        key = (
            item.get("engine"),
            item.get("kind"),
            item.get("module_identity_sha256"),
            item.get("address"),
            str(item.get("marker") or item.get("symbol") or "").lower(),
        )
        if key in self.keys:
            return
        if len(self.items) >= self.limit:
            self.truncated = True
            return
        self.keys.add(key)
        self.items.append(_json_mapping(item))


class EngineRuntimeProvider:
    """Plan and collect bounded, read-only engine runtime evidence."""

    capability_name = "engine_runtime"
    provider_name = "windows_engine_runtime"
    priority = 10

    def __init__(
        self,
        backend: Optional[EngineRuntimeBackend] = None,
        *,
        platform_name: Optional[str] = None,
        max_total_read_bytes: int = _DEFAULT_MAX_TOTAL_READ_BYTES,
        max_module_read_bytes: int = _DEFAULT_MAX_MODULE_READ_BYTES,
        max_single_read_bytes: int = _DEFAULT_MAX_SINGLE_READ_BYTES,
        max_modules: int = _DEFAULT_MAX_MODULES,
        max_evidence: int = _DEFAULT_MAX_EVIDENCE,
        max_export_names: int = _DEFAULT_MAX_EXPORT_NAMES,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.max_total_read_bytes = _configuration_limit(
            max_total_read_bytes,
            _DEFAULT_MAX_TOTAL_READ_BYTES,
            _HARD_MAX_TOTAL_READ_BYTES,
        )
        self.max_module_read_bytes = min(
            self.max_total_read_bytes,
            _configuration_limit(
                max_module_read_bytes,
                _DEFAULT_MAX_MODULE_READ_BYTES,
                _HARD_MAX_MODULE_READ_BYTES,
            ),
        )
        self.max_single_read_bytes = min(
            self.max_module_read_bytes,
            _configuration_limit(
                max_single_read_bytes,
                _DEFAULT_MAX_SINGLE_READ_BYTES,
                _HARD_MAX_SINGLE_READ_BYTES,
            ),
        )
        self.max_modules = _configuration_limit(
            max_modules,
            _DEFAULT_MAX_MODULES,
            _HARD_MAX_MODULES,
        )
        self.max_evidence = _configuration_limit(
            max_evidence,
            _DEFAULT_MAX_EVIDENCE,
            _HARD_MAX_EVIDENCE,
        )
        self.max_export_names = _configuration_limit(
            max_export_names,
            _DEFAULT_MAX_EXPORT_NAMES,
            _HARD_MAX_EXPORT_NAMES,
        )
        if backend is not None:
            self.backend: EngineRuntimeBackend = backend
        elif self.platform_name == "win32":
            self.backend = WindowsEngineRuntimeBackend(
                max_single_read_bytes=self.max_single_read_bytes,
                platform_name=self.platform_name,
            )
        else:
            self.backend = UnavailableEngineRuntimeBackend(
                f"Windows process APIs are unavailable on {self.platform_name}"
            )

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) in _SUPPORTED_ACTIONS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        action = _normalize_action(request.action)
        raw_pid, pid, pid_conflict = _request_pid(request)
        parameters = self._normalize_parameters(request.params)
        parameters.update(
            {
                "pid": pid if pid is not None else raw_pid,
                "pid_conflict": pid_conflict,
                "requested_action": request.action,
                "read_only": True,
            }
        )
        session_id = request.session_id or "engine-runtime-session"
        before = _capture_inventory(
            backend,
            pid,
            parameters,
            platform_name=self.platform_name,
            phase="plan",
        )
        precondition_hash = _inventory_precondition_hash(action, before, parameters)
        before["precondition_hash"] = precondition_hash
        rollback_plan = _read_only_rollback_plan(precondition_hash)
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters,
            steps=[
                {
                    "name": "probe_process",
                    "operation": "query read access without mutation",
                    "read_only": True,
                },
                {
                    "name": "enumerate_modules",
                    "operation": "capture module identities and candidate ranges",
                    "read_only": True,
                },
                {
                    "name": "verify_precondition",
                    "operation": "recheck PID and selected module identities",
                    "read_only": True,
                },
                {
                    "name": "collect_runtime_evidence",
                    "operation": (
                        "bounded PE exports, readable Unreal PE sections, "
                        "Mono CLI metadata, and marker strings"
                    ),
                    "read_only": True,
                    "limits": _read_limits(parameters),
                },
                {
                    "name": "emit_audit",
                    "operation": "produce manifest, report, and dashboard trace",
                    "read_only": True,
                },
            ],
            precondition_hash=precondition_hash,
            before_snapshot=before,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "backend": _backend_info(backend, self.platform_name),
                "platform": self.platform_name,
                "requested_action": request.action,
                "action": action,
                "pid": pid if pid is not None else raw_pid,
                "read_only": True,
                "side_effects": False,
                "read_limits": _read_limits(parameters),
                "precondition_hash": precondition_hash,
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        validation, _ = self._validate_plan(plan, context=context)
        return validation

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        validation, current = self._validate_plan(plan, context=context)
        before = dict(current or plan.before_snapshot or {})
        before.update(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "before",
                "precondition_hash": plan.precondition_hash,
                "side_effects": False,
            }
        )

        unavailable_reason = _execution_unavailable_reason(
            backend,
            plan,
            current,
        )
        if unavailable_reason:
            empty_usage = _empty_read_usage(plan.parameters)
            return self._result(
                plan,
                validation=validation,
                status="unavailable",
                before=before,
                after={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": "unavailable",
                    "reason": unavailable_reason,
                    "side_effects": False,
                },
                operation={
                    "status": "unavailable",
                    "reason": unavailable_reason,
                    "read_only": True,
                    "side_effects": False,
                    "module_identities": list(current.get("modules") or []),
                    "evidence": [],
                    "engine_candidates": [],
                    "detected_engines": [],
                    "semantic_ir_fragment": _empty_runtime_semantic_fragment(
                        "unreal", "unavailable"
                    ),
                    "engine_analysis": _empty_unreal_engine_analysis(
                        "unavailable",
                        unavailable_reason,
                        plan.parameters,
                        empty_usage,
                    ),
                    "dependency_status": {"status": "unavailable", "parser": None},
                    "read_usage": empty_usage,
                },
                errors=[unavailable_reason],
            )

        if _normalize_action(plan.action) not in _SUPPORTED_ACTIONS or not validation.ok:
            reason = (
                f"unsupported engine_runtime action: {plan.action}"
                if _normalize_action(plan.action) not in _SUPPORTED_ACTIONS
                else "execution was blocked by plan validation"
            )
            empty_usage = _empty_read_usage(plan.parameters)
            return self._result(
                plan,
                validation=validation,
                status="failed",
                before=before,
                after={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": "blocked",
                    "reason": reason,
                    "side_effects": False,
                },
                operation={
                    "status": "blocked",
                    "reason": reason,
                    "read_only": True,
                    "side_effects": False,
                    "module_identities": list(current.get("modules") or []),
                    "evidence": [],
                    "engine_candidates": [],
                    "detected_engines": [],
                    "semantic_ir_fragment": _empty_runtime_semantic_fragment(
                        "unreal", "blocked"
                    ),
                    "engine_analysis": _empty_unreal_engine_analysis(
                        "blocked",
                        reason,
                        plan.parameters,
                        empty_usage,
                    ),
                    "dependency_status": {"status": "not_used", "parser": None},
                    "read_usage": empty_usage,
                },
                errors=list(validation.errors) or [reason],
            )

        pid = int(_coerce_int(plan.parameters.get("pid")) or 0)
        budget = _ReadBudget(
            total_limit=_required_int(plan.parameters, "max_total_read_bytes"),
            module_limit=_required_int(plan.parameters, "max_module_read_bytes"),
            single_limit=_required_int(plan.parameters, "max_single_read_bytes"),
        )
        evidence = _EvidenceCollector(
            limit=_required_int(plan.parameters, "max_evidence")
        )
        modules = [dict(item) for item in current.get("selected_modules") or []]
        mono_context = any(_is_mono_runtime_module(item) for item in modules)
        unreal_context = _has_unreal_runtime_context(current.get("modules") or modules)
        analyzed_modules: list[dict[str, Any]] = []
        extraction_errors: list[dict[str, Any]] = []
        for module in modules:
            if budget.remaining_total() <= 0:
                budget.truncated = True
                break
            analysis = _analyze_module(
                backend,
                pid,
                module,
                plan.parameters,
                budget,
                evidence,
                mono_context=mono_context,
                unreal_context=unreal_context,
            )
            analyzed_modules.append(analysis)
            extraction_errors.extend(analysis.get("errors") or [])

        runtime_extractions = [
            item.get("runtime_extraction")
            for item in analyzed_modules
            if isinstance(item.get("runtime_extraction"), Mapping)
            and item["runtime_extraction"].get("attempted")
        ]
        runtime_symbols = [
            symbol
            for extraction in runtime_extractions
            for symbol in extraction.get("symbols") or []
            if isinstance(symbol, Mapping)
        ]
        runtime_semantic_ir = _merge_runtime_semantic_fragments(
            [
                extraction.get("semantic_ir_fragment")
                for extraction in runtime_extractions
                if isinstance(extraction.get("semantic_ir_fragment"), Mapping)
            ]
        )
        runtime_status = _component_status(runtime_extractions)
        execution_status = (
            "partial"
            if any(item.get("status") == "partial" for item in runtime_extractions)
            else "ok"
        )
        engine_candidates = _summarize_engines(evidence.items)
        detected_engines = [
            item["engine"]
            for item in engine_candidates
            if item.get("status") == "detected"
        ]
        read_usage = budget.summary()
        engine_analysis = _build_unreal_engine_analysis(
            modules=current.get("modules") or [],
            analyzed_modules=analyzed_modules,
            engine_candidates=engine_candidates,
            read_limits=_read_limits(plan.parameters),
            read_usage=read_usage,
        )
        operation = {
            "status": execution_status,
            "operation": "analyze_engine_runtime",
            "read_only": True,
            "side_effects": False,
            "module_identities": list(current.get("modules") or []),
            "module_count": len(current.get("modules") or []),
            "selected_module_count": len(modules),
            "analyzed_modules": analyzed_modules,
            "runtime_extraction_status": runtime_status,
            "runtime_extractions": runtime_extractions,
            "symbols": runtime_symbols,
            "semantic_ir_fragment": runtime_semantic_ir,
            "engine_analysis": engine_analysis,
            "dependency_status": _runtime_dependency_status(runtime_extractions),
            "remote_api_calls": False,
            "runtime_object_addresses": {
                "status": "unresolved",
                "reason": (
                    "read-only module, export, and name evidence does not by itself "
                    "prove live engine object addresses"
                ),
            },
            "evidence": evidence.items,
            "evidence_count": len(evidence.items),
            "evidence_truncated": evidence.truncated,
            "engine_candidates": engine_candidates,
            "detected_engines": detected_engines,
            "read_limits": _read_limits(plan.parameters),
            "read_usage": read_usage,
            "errors": extraction_errors,
        }
        after_inventory = _capture_inventory(
            backend,
            pid,
            plan.parameters,
            platform_name=self.platform_name,
            phase="after",
        )
        after_inventory.update(
            {
                "operation": operation,
                "postcondition_hash": _inventory_precondition_hash(
                    plan.action,
                    after_inventory,
                    plan.parameters,
                ),
                "side_effects": False,
            }
        )
        return self._result(
            plan,
            validation=validation,
            status=execution_status,
            before=before,
            after=after_inventory,
            operation=operation,
            errors=extraction_errors,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": "not_required",
            "reason": "engine_runtime is read-only and performs no process mutation",
            "read_only": True,
            "side_effects": False,
            "attempted": False,
            "restored": False,
            "session_id": result.session_id,
            "precondition_hash": result.provenance.get("precondition_hash"),
        }
        result.rollback_plan.update(
            {
                "supported": False,
                "mode": "not_required",
                "rollback_attempted": False,
                "rollback_status": "not_required",
                "completed": True,
                "restored": False,
            }
        )
        result.after_snapshot["rollback"] = dict(details)
        result.report_section["rollback"] = dict(details)
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "engine_runtime_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "action": result.action,
                "session_id": result.session_id,
                "status": "not_required",
                "read_only": True,
                "side_effects": False,
            }
        )
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=True,
            restored=False,
            details=details,
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or [])
        entries = {
            str(item.get("path")): dict(item)
            for item in result.evidence_manifest_entries or []
            if item.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            destination = _artifact_destination(root, artifact.path)
            if artifact.kind != "engine-runtime-evidence":
                raise ValueError(
                    f"unsupported engine_runtime artifact kind: {artifact.kind}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            payload = _audit_payload(result)
            encoded = (
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n"
            ).encode("utf-8")
            destination.write_bytes(encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update(
                {
                    "collection_root": str(root),
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                }
            )
            entry = entries.get(
                artifact.path,
                _manifest_entry(result, artifact),
            )
            entry.update(
                {
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                }
            )
            manifest_entries.append(entry)

        result.artifacts = artifacts
        result.evidence_manifest_entries = manifest_entries
        _sync_report(result)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []

        def check(
            name: str,
            ok: bool,
            message: str,
            *,
            unavailable: bool = False,
            **details: Any,
        ) -> None:
            status = "ok" if ok else ("unavailable" if unavailable else "failed")
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": status,
                        "message": message,
                        **details,
                    }
                )
            )
            if not ok:
                if unavailable:
                    warnings.append(message)
                else:
                    errors.append(message)

        check(
            "capability_identity",
            plan.capability == self.capability_name
            and plan.provider == self.provider_name,
            "plan capability/provider identity does not match engine_runtime provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        action = _normalize_action(plan.action)
        check(
            "supported_action",
            action in _SUPPORTED_ACTIONS,
            f"unsupported engine_runtime action: {plan.action}",
            action=action,
        )
        pid = _coerce_int(plan.parameters.get("pid"))
        target_pid = _coerce_int(getattr(plan.target, "pid", None))
        planned_pid = _coerce_int(plan.before_snapshot.get("pid"))
        pid_ok = bool(pid and pid > 0 and not plan.parameters.get("pid_conflict"))
        if target_pid is not None:
            pid_ok = pid_ok and pid == target_pid
        if planned_pid is not None:
            pid_ok = pid_ok and pid == planned_pid
        check(
            "target_pid",
            pid_ok,
            "target PID must be positive and match the planned target identity",
            pid=pid,
            target_pid=target_pid,
            planned_pid=planned_pid,
        )
        parameter_errors = [
            str(item) for item in plan.parameters.get("parameter_errors") or []
        ]
        check(
            "parameters",
            not parameter_errors,
            "; ".join(parameter_errors)
            if parameter_errors
            else "engine-runtime parameters are valid",
        )
        mutation_keys = sorted(
            key for key in _MUTATION_PARAMETER_KEYS if key in plan.parameters
        )
        check(
            "read_only_parameters",
            not mutation_keys,
            "engine_runtime rejects process-mutation parameters",
            rejected_keys=mutation_keys,
        )
        limits_ok, limit_details = self._validate_limits(plan.parameters)
        check(
            "read_limits",
            limits_ok,
            "read limits must be positive and stay within provider ceilings",
            **limit_details,
        )

        api_missing = [
            name
            for name in ("probe", "modules", "read")
            if _backend_method(backend, name, required=False) is None
        ]
        check(
            "backend_api",
            not api_missing,
            (
                "backend implements the read-only runtime API"
                if not api_missing
                else "backend is missing read-only APIs: " + ", ".join(api_missing)
            ),
            unavailable=bool(api_missing),
            missing=api_missing,
        )
        available = _backend_available(backend)
        check(
            "windows_backend",
            available,
            (
                "Windows read-only backend is available"
                if available
                else _backend_reason(backend)
            ),
            unavailable=not available,
            platform=self.platform_name,
        )

        current = _capture_inventory(
            backend,
            pid,
            plan.parameters,
            platform_name=self.platform_name,
            phase="validate",
        )
        if available and not api_missing and pid and pid > 0:
            process = current.get("process") or {}
            process_ok = bool(
                process.get("accessible") and process.get("status") == "ok"
            )
            check(
                "process_access",
                process_ok,
                "target process is unavailable for read-only inspection",
                unavailable=not process_ok,
                process=process,
            )
            inventory_errors = list(current.get("errors") or [])
            check(
                "module_inventory",
                not inventory_errors,
                (
                    "module inventory captured"
                    if not inventory_errors
                    else "module inventory is unavailable"
                ),
                unavailable=bool(inventory_errors),
                errors=inventory_errors,
                module_count=current.get("module_count"),
            )
            current_hash = _inventory_precondition_hash(
                action,
                current,
                plan.parameters,
            )
            check(
                "precondition_hash",
                bool(plan.precondition_hash and current_hash == plan.precondition_hash),
                "live process/module identity no longer matches the plan precondition",
                expected=plan.precondition_hash,
                actual=current_hash,
            )

        return (
            CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=_deduplicate(warnings),
                errors=_deduplicate(errors),
            ),
            current,
        )

    def _normalize_parameters(self, params: Mapping[str, Any]) -> dict[str, Any]:
        source = dict(params or {})
        errors: list[str] = []
        clamps: list[dict[str, Any]] = []

        def limit(
            name: str,
            default: int,
            ceiling: int,
            aliases: Sequence[str] = (),
        ) -> int:
            raw = _first_value(source, (name, *aliases))
            if raw is None:
                return default
            parsed = _coerce_int(raw)
            if parsed is None or parsed <= 0:
                errors.append(f"{name} must be a positive integer")
                return default
            selected = min(parsed, ceiling)
            if selected != parsed:
                clamps.append(
                    {"name": name, "requested": parsed, "applied": selected}
                )
            return selected

        total = limit(
            "max_total_read_bytes",
            self.max_total_read_bytes,
            self.max_total_read_bytes,
            ("max_read_bytes", "read_limit"),
        )
        module = min(
            total,
            limit(
                "max_module_read_bytes",
                min(self.max_module_read_bytes, total),
                min(self.max_module_read_bytes, total),
                ("module_read_limit",),
            ),
        )
        single = min(
            module,
            limit(
                "max_single_read_bytes",
                min(self.max_single_read_bytes, module),
                min(self.max_single_read_bytes, module),
                ("chunk_size", "max_chunk_bytes"),
            ),
        )
        module_filters, filter_error = _normalize_module_filters(
            source.get("module_names", source.get("modules"))
        )
        if filter_error:
            errors.append(filter_error)
        return {
            "max_total_read_bytes": total,
            "max_module_read_bytes": module,
            "max_single_read_bytes": single,
            "max_modules": limit(
                "max_modules",
                self.max_modules,
                self.max_modules,
            ),
            "max_evidence": limit(
                "max_evidence",
                self.max_evidence,
                self.max_evidence,
                ("max_results",),
            ),
            "max_export_names": limit(
                "max_export_names",
                self.max_export_names,
                self.max_export_names,
            ),
            "module_filters": module_filters,
            "scan_all_modules": bool(source.get("scan_all_modules", False)),
            "include_exports": bool(source.get("include_exports", True)),
            "include_utf16": bool(source.get("include_utf16", True)),
            "parameter_errors": errors,
            "limit_clamps": clamps,
        }

    def _validate_limits(
        self,
        parameters: Mapping[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        limits = _read_limits(parameters)
        total = _coerce_int(limits.get("max_total_read_bytes"))
        module = _coerce_int(limits.get("max_module_read_bytes"))
        single = _coerce_int(limits.get("max_single_read_bytes"))
        modules = _coerce_int(limits.get("max_modules"))
        evidence = _coerce_int(limits.get("max_evidence"))
        exports = _coerce_int(limits.get("max_export_names"))
        ok = bool(
            total
            and module
            and single
            and modules
            and evidence
            and exports
            and 0 < single <= module <= total <= self.max_total_read_bytes
            and module <= self.max_module_read_bytes
            and single <= self.max_single_read_bytes
            and modules <= self.max_modules
            and evidence <= self.max_evidence
            and exports <= self.max_export_names
        )
        return ok, {
            "limits": limits,
            "provider_ceilings": {
                "max_total_read_bytes": self.max_total_read_bytes,
                "max_module_read_bytes": self.max_module_read_bytes,
                "max_single_read_bytes": self.max_single_read_bytes,
                "max_modules": self.max_modules,
                "max_evidence": self.max_evidence,
                "max_export_names": self.max_export_names,
            },
        }

    def _result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        operation: Mapping[str, Any],
        errors: Sequence[Any],
    ) -> CapabilityExecutionResult:
        target = _target_payload(plan.target)
        rollback_plan = dict(plan.rollback_plan or {})
        provenance = {
            **_json_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "execution": {
                "status": status,
                "action": plan.action,
                "read_only": True,
                "side_effects": False,
                "read_limits": _read_limits(plan.parameters),
                "read_usage": _json_mapping(operation.get("read_usage")),
            },
        }
        artifact = CapabilityArtifact(
            path=(
                f"engine_runtime/{_safe_segment(plan.session_id)}/"
                f"{_safe_segment(plan.action)}.json"
            ),
            kind="engine-runtime-evidence",
            description=(
                "Bounded Unity IL2CPP, Unity Mono, and Unreal runtime evidence"
            ),
            metadata={
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "status": status,
                "action": plan.action,
                "session_id": plan.session_id,
                "target": target,
                "precondition_hash": plan.precondition_hash,
                "read_only": True,
                "materialized": False,
            },
        )
        manifest = _manifest_entry_values(
            plan.capability,
            plan.provider,
            plan.session_id,
            plan.action,
            status,
            target,
            plan.precondition_hash,
            artifact,
            plan.parameters.get("pid"),
        )
        precondition = {
            "hash": plan.precondition_hash,
            "validation": {
                "ok": validation.ok,
                "check": next(
                    (
                        dict(item)
                        for item in validation.checks
                        if item.get("name") == "precondition_hash"
                    ),
                    None,
                ),
            },
        }
        report = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "capability": plan.capability,
            "provider": plan.provider,
            "platform": self.platform_name,
            "action": plan.action,
            "session_id": plan.session_id,
            "session": {"id": plan.session_id},
            "target": target,
            "target_identity": target,
            "pid": plan.parameters.get("pid"),
            "read_only": True,
            "side_effects": False,
            "precondition": precondition,
            "precondition_hash": plan.precondition_hash,
            "before": dict(before),
            "after": dict(after),
            "before_snapshot": dict(before),
            "after_snapshot": dict(after),
            "rollback": rollback_plan,
            "rollback_plan": rollback_plan,
            "provenance": provenance,
            "operation": dict(operation),
            "module_identities": list(operation.get("module_identities") or []),
            "engine_candidates": list(operation.get("engine_candidates") or []),
            "detected_engines": list(operation.get("detected_engines") or []),
            "engine_analysis": _json_mapping(operation.get("engine_analysis")),
            "semantic_ir_fragment": _json_mapping(
                operation.get("semantic_ir_fragment")
            ),
            "dependency_status": _json_mapping(operation.get("dependency_status")),
            "evidence": list(operation.get("evidence") or []),
            "read_limits": _read_limits(plan.parameters),
            "read_usage": _json_mapping(operation.get("read_usage")),
            "validation": validation.to_dict(),
            "errors": [_json_value(item) for item in errors],
            "artifacts": [artifact.to_dict()],
            "evidence_manifest_entries": [manifest],
        }
        trace = {
            "kind": "engine_runtime_execution",
            "capability": plan.capability,
            "provider": plan.provider,
            "action": plan.action,
            "session_id": plan.session_id,
            "status": status,
            "pid": plan.parameters.get("pid"),
            "read_only": True,
            "side_effects": False,
            "module_count": operation.get("module_count", 0),
            "selected_module_count": operation.get("selected_module_count", 0),
            "evidence_count": operation.get("evidence_count", 0),
            "detected_engines": list(operation.get("detected_engines") or []),
            "engine_candidates": list(operation.get("engine_candidates") or []),
            "read_bytes": (operation.get("read_usage") or {}).get(
                "requested_bytes",
                0,
            ),
            "read_truncated": bool(
                (operation.get("read_usage") or {}).get("truncated")
                or operation.get("evidence_truncated")
            ),
        }
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(before),
            after_snapshot=dict(after),
            rollback_plan=rollback_plan,
            artifacts=[artifact],
            evidence_manifest_entries=[manifest],
            report_section=report,
            dashboard_trace=[trace],
            provenance=provenance,
        )

    def _select_backend(
        self,
        context: Optional[dict[str, Any]],
    ) -> EngineRuntimeBackend:
        if context:
            candidate = context.get("engine_runtime_backend")
            if candidate is not None:
                return candidate
        return self.backend


def _capture_inventory(
    backend: Any,
    pid: Optional[int],
    parameters: Mapping[str, Any],
    *,
    platform_name: str,
    phase: str,
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capture_phase": phase,
        "platform": platform_name,
        "backend": _backend_info(backend, platform_name),
        "pid": pid,
        "read_only": True,
        "side_effects": False,
        "process": {},
        "modules": [],
        "selected_modules": [],
        "module_count": 0,
        "selected_module_count": 0,
        "errors": [],
    }
    if pid is None or pid <= 0:
        snapshot["errors"].append(
            {"operation": "target_pid", "message": "target PID is unavailable"}
        )
        return snapshot
    if not _backend_available(backend):
        snapshot["process"] = {
            "pid": pid,
            "exists": None,
            "accessible": False,
            "status": "unavailable",
            "reason": _backend_reason(backend),
        }
        return snapshot

    probe_method = _backend_method(backend, "probe", required=False)
    modules_method = _backend_method(backend, "modules", required=False)
    if probe_method is None:
        snapshot["errors"].append(
            {"operation": "probe_process", "message": "backend API is missing"}
        )
    else:
        try:
            snapshot["process"] = _json_mapping(probe_method(pid))
        except Exception as exc:
            snapshot["process"] = {
                "pid": pid,
                "accessible": False,
                "status": "unavailable",
                "error": _exception_payload(exc),
            }
            snapshot["errors"].append(
                {"operation": "probe_process", "error": _exception_payload(exc)}
            )
    if modules_method is None:
        snapshot["errors"].append(
            {"operation": "enumerate_modules", "message": "backend API is missing"}
        )
        return snapshot
    if not (snapshot.get("process") or {}).get("accessible"):
        return snapshot
    try:
        modules = _normalize_modules(modules_method(pid))
    except Exception as exc:
        snapshot["errors"].append(
            {"operation": "enumerate_modules", "error": _exception_payload(exc)}
        )
        return snapshot
    snapshot["modules"] = modules
    snapshot["module_count"] = len(modules)
    selected = _select_modules(modules, parameters)
    snapshot["selected_modules"] = selected
    snapshot["selected_module_count"] = len(selected)
    snapshot["selection"] = {
        "scan_all_modules": bool(parameters.get("scan_all_modules")),
        "module_filters": list(parameters.get("module_filters") or []),
        "max_modules": parameters.get("max_modules"),
        "selected_identity_sha256": [
            item.get("identity_sha256") for item in selected
        ],
    }
    return snapshot


def _analyze_module(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    parameters: Mapping[str, Any],
    budget: _ReadBudget,
    evidence: _EvidenceCollector,
    *,
    mono_context: bool = False,
    unreal_context: bool = False,
) -> dict[str, Any]:
    normalized = dict(module)
    module_key = str(
        normalized.get("identity_sha256")
        or normalized.get("base_address_hex")
        or normalized.get("name")
    )
    errors: list[dict[str, Any]] = []
    for signal in _module_signals(normalized, unreal_context=unreal_context):
        evidence.add(
            _evidence_item(
                engine=signal[0],
                kind="module_identity",
                marker=signal[1],
                weight=signal[2],
                module=normalized,
                address=_coerce_int(normalized.get("base_address")),
                rva=0,
                source="module_enumeration",
            )
        )

    if _should_extract_mono_module(normalized, mono_context=mono_context):
        mono_identity = _validate_mono_module_identity(normalized)
        if not mono_identity.get("valid"):
            runtime_extraction = _extract_module_runtime(
                backend,
                pid,
                normalized,
                module_key,
                {},
                [],
                budget,
                parameters,
                mono_context=mono_context,
                unreal_context=unreal_context,
            )
            errors.extend(
                item
                for item in runtime_extraction.get("errors") or []
                if isinstance(item, Mapping)
            )
            return _prune(
                {
                    "module": normalized,
                    "pe": {
                        "status": "skipped",
                        "reason": "Mono candidate failed path or identity constraints",
                        "path_identity": mono_identity,
                    },
                    "export_candidate_count": 0,
                    "runtime_extraction": runtime_extraction,
                    "scan": {
                        "status": "skipped",
                        "reason": "Mono candidate failed path or identity constraints",
                    },
                    "errors": errors,
                    "read_usage": {
                        "requested_bytes": budget.module_requested.get(module_key, 0),
                        "returned_bytes": budget.module_returned.get(module_key, 0),
                        "max_module_read_bytes": budget.module_limit,
                    },
                }
            )

    pe: dict[str, Any] = {}
    exports: list[dict[str, Any]] = []
    pe, exports, pe_errors = _inspect_remote_pe(
        backend,
        pid,
        normalized,
        module_key,
        parameters,
        budget,
    )
    errors.extend(pe_errors)
    for item in exports:
        evidence.add(item)

    runtime_extraction = _extract_module_runtime(
        backend,
        pid,
        normalized,
        module_key,
        pe,
        exports,
        budget,
        parameters,
        mono_context=mono_context,
        unreal_context=unreal_context,
    )
    for item in runtime_extraction.get("evidence") or []:
        if isinstance(item, Mapping):
            evidence.add(item)
    errors.extend(
        item
        for item in runtime_extraction.get("errors") or []
        if isinstance(item, Mapping)
    )

    scan = _scan_module_strings(
        backend,
        pid,
        normalized,
        module_key,
        parameters,
        budget,
        evidence,
    )
    return _prune(
        {
            "module": normalized,
            "pe": pe,
            "export_candidate_count": len(exports),
            "runtime_extraction": runtime_extraction,
            "scan": scan,
            "errors": errors,
            "read_usage": {
                "requested_bytes": budget.module_requested.get(module_key, 0),
                "returned_bytes": budget.module_returned.get(module_key, 0),
                "max_module_read_bytes": budget.module_limit,
            },
        }
    )


def _inspect_remote_pe(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    parameters: Mapping[str, Any],
    budget: _ReadBudget,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    base = _coerce_int(module.get("base_address"))
    module_size = _coerce_int(module.get("size"))
    errors: list[dict[str, Any]] = []
    if base is None or module_size is None or module_size <= 0:
        return {}, [], [{"operation": "pe_headers", "message": "invalid module range"}]

    dos = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base,
        64,
        budget,
        purpose="pe_dos_header",
    )
    if len(dos) != 64 or dos[:2] != b"MZ":
        return {"status": "not_pe"}, [], errors
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    if pe_offset < 64 or pe_offset > min(_MAX_PE_HEADER_OFFSET, module_size - 24):
        return {
            "status": "invalid",
            "dos_signature": "MZ",
            "pe_header_offset": pe_offset,
        }, [], errors
    file_header = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base + pe_offset,
        24,
        budget,
        purpose="pe_file_header",
    )
    if len(file_header) != 24 or file_header[:4] != b"PE\x00\x00":
        return {
            "status": "invalid",
            "dos_signature": "MZ",
            "pe_header_offset": pe_offset,
        }, [], errors
    machine, section_count, timestamp, _, _, optional_size, characteristics = (
        struct.unpack_from("<HHIIIHH", file_header, 4)
    )
    optional = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base + pe_offset + 24,
        optional_size,
        budget,
        purpose="pe_optional_header",
    )
    if len(optional) != optional_size or len(optional) < 68:
        return {
            "status": "partial",
            "dos_signature": "MZ",
            "pe_signature": "PE",
            "machine": machine,
            "section_count": section_count,
            "timestamp": timestamp,
            "optional_header_size": optional_size,
        }, [], errors
    magic = struct.unpack_from("<H", optional, 0)[0]
    if magic == 0x20B:
        directory_count_offset = 108
        directory_offset = 112
        pe_kind = "PE32+"
        pointer_size = 8
        architecture = "amd64"
    elif magic == 0x10B:
        directory_count_offset = 92
        directory_offset = 96
        pe_kind = "PE32"
        pointer_size = 4
        architecture = "i386"
    else:
        return {
            "status": "invalid",
            "dos_signature": "MZ",
            "pe_signature": "PE",
            "optional_magic": magic,
        }, [], errors
    entry_point_rva = struct.unpack_from("<I", optional, 16)[0]
    size_of_image = struct.unpack_from("<I", optional, 56)[0]
    checksum = struct.unpack_from("<I", optional, 64)[0]
    directory_count = (
        struct.unpack_from("<I", optional, directory_count_offset)[0]
        if len(optional) >= directory_count_offset + 4
        else 0
    )
    data_directories: list[dict[str, Any]] = []
    if directory_count and len(optional) >= directory_offset:
        inspected_directories = min(int(directory_count), 32)
        for directory_index in range(inspected_directories):
            directory_cursor = directory_offset + directory_index * 8
            if directory_cursor + 8 > len(optional):
                break
            directory_rva, directory_size = struct.unpack_from(
                "<II", optional, directory_cursor
            )
            data_directories.append(
                {
                    "index": directory_index,
                    "rva": directory_rva,
                    "rva_hex": _hex(directory_rva),
                    "size": directory_size,
                }
            )
    export_rva = 0
    export_size = 0
    if directory_count and len(optional) >= directory_offset + 8:
        export_rva, export_size = struct.unpack_from("<II", optional, directory_offset)
    cli_rva = 0
    cli_size = 0
    if len(data_directories) > 14:
        cli_rva = int(data_directories[14].get("rva") or 0)
        cli_size = int(data_directories[14].get("size") or 0)
    sections: list[dict[str, Any]] = []
    section_errors: list[str] = []
    if not 1 <= section_count <= _MAX_PE_SECTIONS:
        section_errors.append(f"implausible PE section count: {section_count}")
    else:
        section_table_rva = pe_offset + 24 + optional_size
        section_table_size = section_count * 40
        section_data = _read_module_exact(
            backend,
            pid,
            module_key,
            base,
            module_size,
            base + section_table_rva,
            section_table_size,
            budget,
            purpose="pe_section_headers",
        )
        if len(section_data) != section_table_size:
            section_errors.append("PE section table is truncated")
        else:
            for index in range(section_count):
                offset = index * 40
                raw_name = section_data[offset : offset + 8].split(b"\x00", 1)[0]
                name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
                virtual_size, virtual_rva, raw_size = struct.unpack_from(
                    "<III", section_data, offset + 8
                )
                characteristics_value = struct.unpack_from("<I", section_data, offset + 36)[0]
                mapped_size = max(virtual_size, raw_size)
                range_valid = bool(
                    mapped_size
                    and virtual_rva < module_size
                    and mapped_size <= module_size - virtual_rva
                )
                if mapped_size and not range_valid:
                    section_errors.append(f"PE section {name} is outside the loaded module")
                sections.append(
                    {
                        "index": index,
                        "name": name,
                        "rva": virtual_rva,
                        "rva_hex": _hex(virtual_rva),
                        "virtual_size": virtual_size,
                        "raw_size": raw_size,
                        "mapped_size": mapped_size,
                        "address": base + virtual_rva,
                        "address_hex": _hex(base + virtual_rva),
                        "characteristics": characteristics_value,
                        "characteristics_hex": _hex(characteristics_value),
                        "readable": bool(characteristics_value & 0x40000000),
                        "writable": bool(characteristics_value & 0x80000000),
                        "executable": bool(characteristics_value & 0x20000000),
                        "range_valid": range_valid,
                    }
                )
    pe = {
        "status": "ok",
        "kind": pe_kind,
        "architecture": architecture,
        "pointer_size": pointer_size,
        "machine": machine,
        "machine_hex": _hex(machine),
        "section_count": section_count,
        "timestamp": timestamp,
        "characteristics": characteristics,
        "entry_point_rva": entry_point_rva,
        "entry_point_rva_hex": _hex(entry_point_rva),
        "size_of_image": size_of_image,
        "checksum": checksum,
        "export_directory_rva": export_rva,
        "export_directory_rva_hex": _hex(export_rva),
        "export_directory_size": export_size,
        "sections": sections,
        "section_errors": section_errors,
        "data_directories": data_directories,
        "cli_directory_rva": cli_rva,
        "cli_directory_rva_hex": _hex(cli_rva),
        "cli_directory_size": cli_size,
    }
    if not parameters.get("include_exports", True):
        pe["export_status"] = "skipped"
        pe["export_reason"] = "PE export collection disabled by request"
        return pe, [], errors
    if not export_rva or export_size < 40:
        pe["export_status"] = "absent"
        return pe, [], errors
    export_address = base + export_rva
    directory = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        export_address,
        40,
        budget,
        purpose="pe_export_directory",
    )
    if len(directory) != 40:
        pe["export_status"] = "partial"
        return pe, [], errors
    (
        _,
        export_timestamp,
        major,
        minor,
        dll_name_rva,
        ordinal_base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack("<IIHHIIIIIII", directory)
    capped_names = min(
        int(name_count),
        _required_int(parameters, "max_export_names"),
    )
    pe.update(
        {
            "export_status": "ok",
            "export_timestamp": export_timestamp,
            "export_version": f"{major}.{minor}",
            "export_ordinal_base": ordinal_base,
            "export_function_count": function_count,
            "export_name_count": name_count,
            "export_names_inspected": capped_names,
            "export_names_truncated": capped_names < name_count,
        }
    )
    dll_name, _ = _read_remote_cstring(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base + dll_name_rva,
        budget,
        purpose="pe_export_dll_name",
    )
    if dll_name:
        pe["export_dll_name"] = dll_name
    name_table = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base + names_rva,
        capped_names * 4,
        budget,
        purpose="pe_export_name_table",
    )
    ordinal_table = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        base + ordinals_rva,
        capped_names * 2,
        budget,
        purpose="pe_export_ordinal_table",
    )
    available_names = min(len(name_table) // 4, len(ordinal_table) // 2)
    candidates: list[dict[str, Any]] = []
    for index in range(available_names):
        name_rva = struct.unpack_from("<I", name_table, index * 4)[0]
        symbol, name_bytes = _read_remote_cstring(
            backend,
            pid,
            module_key,
            base,
            module_size,
            base + name_rva,
            budget,
            purpose="pe_export_name",
        )
        if not symbol:
            continue
        signals = _text_signals(symbol, source="pe_export")
        if not signals:
            continue
        ordinal_index = struct.unpack_from("<H", ordinal_table, index * 2)[0]
        if ordinal_index >= function_count:
            continue
        function_data = _read_module_exact(
            backend,
            pid,
            module_key,
            base,
            module_size,
            base + functions_rva + ordinal_index * 4,
            4,
            budget,
            purpose="pe_export_function_rva",
        )
        if len(function_data) != 4:
            continue
        function_rva = struct.unpack("<I", function_data)[0]
        function_address = base + function_rva
        forwarded = export_rva <= function_rva < export_rva + export_size
        function_location = _remote_pe_location(pe, module, function_address)
        for engine, marker, weight in signals:
            candidates.append(
                _evidence_item(
                    engine=engine,
                    kind="symbol",
                    marker=marker,
                    symbol=symbol,
                    weight=max(3.0, weight + 1.5),
                    module=module,
                    address=function_address,
                    rva=function_rva,
                    source="pe_export",
                    details={
                        "ordinal": ordinal_base + ordinal_index,
                        "name_address": base + name_rva,
                        "name_address_hex": _hex(base + name_rva),
                        "name_bytes": name_bytes,
                        "forwarded": forwarded,
                        "section": (function_location or {}).get("section"),
                        "executable": (function_location or {}).get("executable"),
                        "runtime_va_proof": _runtime_va_proof(
                            base, function_rva, function_address
                        ),
                    },
                )
            )
    pe["candidate_export_count"] = len(candidates)
    return pe, candidates, errors


def _extract_module_runtime(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    exports: Sequence[Mapping[str, Any]],
    budget: _ReadBudget,
    parameters: Mapping[str, Any],
    *,
    mono_context: bool = False,
    unreal_context: bool = False,
) -> dict[str, Any]:
    engines = {
        item[0]
        for item in _module_signals(module, unreal_context=unreal_context)
    }
    components: list[dict[str, Any]] = []
    if "unity_il2cpp" in engines:
        components.append(
            _discover_il2cpp_registrations(
                backend, pid, module, module_key, pe, budget
            )
        )
    if "unreal" in engines:
        components.append(
            _discover_unreal_globals(
                backend,
                pid,
                module,
                module_key,
                pe,
                exports,
                budget,
                parameters,
            )
        )
    if _should_extract_mono_module(module, mono_context=mono_context):
        components.append(
            _discover_mono_runtime(
                backend,
                pid,
                module,
                module_key,
                pe,
                exports,
                budget,
                mono_context=mono_context,
            )
        )
    evidence = [
        item
        for component in components
        for item in component.get("evidence") or []
        if isinstance(item, Mapping)
    ]
    symbols = [
        item
        for component in components
        for item in component.get("symbols") or []
        if isinstance(item, Mapping)
    ]
    errors = [
        item
        for component in components
        for item in component.get("errors") or []
        if isinstance(item, Mapping)
    ]
    return _prune(
        {
            "status": _component_status(components),
            "attempted": bool(components),
            "components": components,
            "symbols": symbols,
            "semantic_ir_fragment": _merge_runtime_semantic_fragments(
                [
                    component.get("semantic_ir_fragment")
                    for component in components
                    if isinstance(component.get("semantic_ir_fragment"), Mapping)
                ]
            ),
            "evidence": evidence,
            "errors": errors,
        }
    )


def _discover_mono_runtime(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    exports: Sequence[Mapping[str, Any]],
    budget: _ReadBudget,
    *,
    mono_context: bool,
) -> dict[str, Any]:
    """Collect proof-only Mono embedding and managed metadata evidence.

    This function intentionally never follows a Mono pointer or invokes an
    embedding API.  Function addresses come from PE export RVAs, and managed
    symbols come from the CLI metadata tables stored in the loaded PE image.
    """

    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    empty_fragment = _empty_runtime_semantic_fragment("unity_mono", "unavailable")
    result: dict[str, Any] = {
        "engine": "unity_mono",
        "status": "unavailable",
        "attempted": True,
        "discovery": "mono-embedding-exports-and-cli-metadata",
        "mono_context": bool(mono_context),
        "module": module.get("name"),
        "module_path": module.get("path"),
        "module_identity_sha256": module.get("identity_sha256"),
        "module_base": base,
        "module_base_hex": _hex(base),
        "remote_api_calls": False,
        "runtime_object_addresses": {
            "status": "unresolved",
            "reason": (
                "no read-only evidence proves a live Mono domain, assembly, "
                "class, method, or object address"
            ),
        },
        "embedding_exports": [],
        "managed_assembly": None,
        "symbols": [],
        "evidence": [],
        "ambiguities": [],
        "errors": [],
        "dependency_status": {
            "metadata_parser": "not_used",
            "status": "not_used",
        },
        "semantic_ir_fragment": empty_fragment,
        "provenance": {
            "source": "ReadProcessMemory",
            "read_only": True,
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": base,
            "remote_api_calls": False,
        },
    }
    if base is None or size is None or size <= 0:
        result["errors"].append(
            _mono_error("mono_runtime", "validated module range is unavailable")
        )
        result["status"] = "partial"
        return _prune(result)

    identity = _validate_mono_module_identity(module)
    result["path_identity"] = identity
    if not identity.get("valid"):
        result["errors"].append(
            _mono_error(
                "module_identity",
                "managed/Mono association rejected by path or identity constraints",
                details=identity,
            )
        )
        result["status"] = "partial"
        return _prune(result)

    symbols: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if _is_unity_player_module(module) and mono_context:
        evidence.append(
            _evidence_item(
                engine="unity_mono",
                kind="unity_player_module",
                marker=str(module.get("name") or "UnityPlayer.dll"),
                weight=2.0,
                module=module,
                address=base,
                rva=0,
                source="module_enumeration",
                details={
                    "association": "mono_runtime_module_present",
                    "runtime_object_address": "unresolved",
                },
            )
        )

    validated_exports: list[dict[str, Any]] = []
    seen_export_keys: set[tuple[str, int]] = set()
    for export in exports:
        if not isinstance(export, Mapping):
            continue
        export_name = str(export.get("symbol") or export.get("marker") or "")
        role = _MONO_EMBEDDING_EXPORT_ROLES.get(export_name.lower())
        if role is None:
            continue
        address = _coerce_int(export.get("address"))
        rva = _coerce_int(export.get("rva"))
        forwarded = bool((export.get("details") or {}).get("forwarded"))
        location = _remote_pe_location(pe, module, address or -1)
        proof = _runtime_va_proof(base, rva, address)
        candidate = {
            "status": "rejected",
            "name": export_name,
            "role": role,
            "address_kind": "unvalidated_pe_export_target_va",
            "address": address,
            "address_hex": _hex(address),
            "rva": rva,
            "rva_hex": _hex(rva),
            "module_base": base,
            "module_base_hex": _hex(base),
            "runtime_va_proof": proof,
            "section": (location or {}).get("section"),
            "executable": (location or {}).get("executable"),
            "forwarded": forwarded,
            "source": "pe_export",
            "errors": [],
        }
        candidate_errors: list[str] = []
        if address is None or rva is None:
            candidate_errors.append("export address or RVA is unavailable")
        if not proof.get("verified"):
            candidate_errors.append("module base + export RVA does not prove the export VA")
        if forwarded:
            candidate_errors.append("forwarded exports are not executable embedding functions")
        if location is None:
            candidate_errors.append("export RVA is outside a validated loaded PE section")
        elif not location.get("executable"):
            candidate_errors.append("export RVA is not in an executable PE section")
        if candidate_errors:
            candidate["errors"] = candidate_errors
            errors.extend(
                _mono_error(
                    "mono_embedding_export",
                    message,
                    details={"name": export_name, "rva": rva},
                )
                for message in candidate_errors
            )
            result["embedding_exports"].append(_prune(candidate))
            continue
        key = (role, int(address))
        if key in seen_export_keys:
            continue
        seen_export_keys.add(key)
        candidate["status"] = "validated"
        candidate["address_kind"] = "embedding_function_va"
        candidate["section_proof"] = {
            "section": location.get("section"),
            "range_valid": True,
            "executable": True,
            "readable": bool(location.get("readable")),
        }
        validated_exports.append(candidate)
        result["embedding_exports"].append(_prune(candidate))
        symbol = _mono_runtime_symbol(
            module,
            role=role,
            display_name=export_name,
            name_kind="mono_embedding_export",
            source="pe_export",
            address=int(address),
            attributes={
                "export_name": export_name,
                "section": location.get("section"),
                "executable": True,
                "address_kind": "embedding_function_va",
                "runtime_va_proof": proof,
                "runtime_object_address": "unresolved",
                "runtime_object_address_reason": (
                    "the export VA identifies a Mono embedding function, not a "
                    "returned runtime object"
                ),
            },
        )
        symbols.append(symbol)
        evidence.append(
            _evidence_item(
                engine="unity_mono",
                kind="mono_embedding_export",
                marker=export_name,
                symbol=export_name,
                weight=6.0,
                module=module,
                address=int(address),
                rva=int(rva),
                source="pe_export",
                details={
                    "role": role,
                    "section": location.get("section"),
                    "range_valid": True,
                    "executable": True,
                    "forwarded": False,
                    "address_kind": "embedding_function_va",
                    "runtime_va_proof": proof,
                    "remote_api_calls": False,
                    "runtime_object_address": "unresolved",
                },
            )
        )

    roles_to_addresses: dict[str, set[int]] = {}
    for item in validated_exports:
        role = str(item.get("role") or "")
        address = _coerce_int(item.get("address"))
        if role and address is not None:
            roles_to_addresses.setdefault(role, set()).add(address)
    for role, addresses in sorted(roles_to_addresses.items()):
        if len(addresses) > 1:
            ambiguity = {
                "kind": "mono_embedding_export",
                "role": role,
                "addresses": sorted(addresses),
                "message": "multiple validated export addresses have the same role",
            }
            result["ambiguities"].append(ambiguity)
            errors.append(_mono_error("ambiguity", ambiguity["message"], details=ambiguity))

    managed_record: Optional[dict[str, Any]] = None
    if _is_managed_module_candidate(module) and not _is_mono_runtime_module(module):
        managed_record = _parse_mono_managed_assembly(
            backend,
            pid,
            module,
            module_key,
            pe,
            budget,
        )
        result["managed_assembly"] = managed_record
        parser_dependency = managed_record.get("dependency_status") or {}
        result["dependency_status"] = parser_dependency
        errors.extend(
            item
            for item in managed_record.get("errors") or []
            if isinstance(item, Mapping)
        )
        managed_symbols, managed_evidence = _mono_managed_symbols_and_evidence(
            module,
            managed_record,
            pe,
        )
        symbols.extend(managed_symbols)
        evidence.extend(managed_evidence)

    result["symbols"] = _stable_mono_symbols(symbols)
    result["evidence"] = _stable_mono_evidence(evidence)
    result["errors"] = _stable_mono_errors(errors)
    result["semantic_ir_fragment"] = _mono_semantic_fragment(
        "ok" if result["symbols"] else ("partial" if result["errors"] else "unavailable"),
        result["symbols"],
        module,
        dependency_status=result.get("dependency_status"),
    )
    if result["ambiguities"]:
        result["status"] = "partial"
    elif managed_record and managed_record.get("status") == "partial":
        result["status"] = "partial"
    elif result["errors"]:
        result["status"] = "partial"
    elif result["symbols"]:
        result["status"] = "ok"
    elif managed_record and managed_record.get("status") == "not_managed":
        result["status"] = "ok" if validated_exports else "unavailable"
    elif errors:
        result["status"] = "partial"
    else:
        result["status"] = "unavailable"
    result["semantic_ir_fragment"]["status"] = result["status"]
    result["provenance"].update(
        {
            "parser": (result.get("dependency_status") or {}).get("parser"),
            "embedding_export_count": len(validated_exports),
            "managed_metadata_validated": bool(
                managed_record and managed_record.get("validated")
            ),
        }
    )
    return _prune(result)


def _parse_mono_managed_assembly(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    module_size = _coerce_int(module.get("size"))
    record: dict[str, Any] = {
        "status": "not_managed",
        "validated": False,
        "name": module.get("name"),
        "path": module.get("path"),
        "module_identity_sha256": module.get("identity_sha256"),
        "module_base": base,
        "module_base_hex": _hex(base),
        "file_header": {
            "pe_status": pe.get("status"),
            "kind": pe.get("kind"),
            "architecture": pe.get("architecture"),
            "machine": pe.get("machine"),
            "section_count": pe.get("section_count"),
        },
        "cli": None,
        "metadata": None,
        "assembly_name": None,
        "assembly_name_source": None,
        "type_definitions": [],
        "method_definitions": [],
        "errors": [],
        "dependency_status": {
            "parser": "not_used",
            "status": "not_used",
        },
        "provenance": {
            "source": "ReadProcessMemory",
            "read_only": True,
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": base,
        },
    }
    identity = _validate_mono_module_identity(module)
    record["path_identity"] = identity
    if not identity.get("valid"):
        record["status"] = "rejected"
        record["errors"].append(
            _mono_error(
                "module_identity",
                "managed assembly path or enumerated module identity is invalid",
                details=identity,
            )
        )
        return _prune(record)
    if base is None or module_size is None or module_size <= 0:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error("managed_assembly", "validated module range is unavailable")
        )
        return _prune(record)
    cli_rva = _coerce_int(pe.get("cli_directory_rva")) or 0
    cli_size = _coerce_int(pe.get("cli_directory_size")) or 0
    if cli_rva == 0 or cli_size < 24:
        return _prune(record)
    cli_address = base + cli_rva
    cli_location = _remote_pe_location(pe, module, cli_address)
    if cli_location is None:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error(
                "cli_header",
                "CLI directory RVA is outside a validated loaded PE section",
                details={"rva": cli_rva, "size": cli_size},
            )
        )
        return _prune(record)
    cli_data = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        cli_address,
        24,
        budget,
        purpose="mono_cli_header",
    )
    if len(cli_data) != 24:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error(
                "cli_header",
                "CLI header is unreadable or budget-truncated",
                details={"requested_bytes": 24, "returned_bytes": len(cli_data)},
            )
        )
        return _prune(record)
    try:
        cb, major, minor, metadata_rva, metadata_size, flags, entry_point = struct.unpack(
            "<IHHIIII", cli_data
        )
    except struct.error as exc:
        record["status"] = "partial"
        record["errors"].append(_mono_error("cli_header", str(exc)))
        return _prune(record)
    record["cli"] = {
        "rva": cli_rva,
        "rva_hex": _hex(cli_rva),
        "address": cli_address,
        "address_hex": _hex(cli_address),
        "size": cli_size,
        "section": cli_location.get("section"),
        "readable": cli_location.get("readable"),
        "executable": cli_location.get("executable"),
        "runtime_va_proof": _runtime_va_proof(base, cli_rva, cli_address),
        "cb": cb,
        "runtime_version": {"major": major, "minor": minor},
        "metadata_rva": metadata_rva,
        "metadata_rva_hex": _hex(metadata_rva),
        "metadata_size": metadata_size,
        "flags": flags,
        "entry_point_token": entry_point,
    }
    cli_errors: list[str] = []
    if cb < 24 or cb > cli_size:
        cli_errors.append("CLI header size is inconsistent with the directory")
    if major == 0 or minor > 99:
        cli_errors.append("CLI runtime version is inconsistent")
    if metadata_rva == 0 or metadata_size < 20:
        cli_errors.append("CLI metadata RVA or size is empty")
    if metadata_size > _MAX_MONO_METADATA_BYTES:
        cli_errors.append(
            f"CLI metadata exceeds the {_MAX_MONO_METADATA_BYTES}-byte parser limit"
        )
    if metadata_rva and metadata_size and not _module_contains(
        base, module_size, base + metadata_rva, metadata_size
    ):
        cli_errors.append("CLI metadata range is outside the loaded module")
    metadata_location = (
        _remote_pe_location(pe, module, base + metadata_rva)
        if metadata_rva
        else None
    )
    if metadata_rva and metadata_location is None:
        cli_errors.append("CLI metadata RVA is outside a validated PE section")
    if cli_errors:
        record["status"] = "partial"
        record["errors"].extend(
            _mono_error("cli_header", message, details={"metadata_rva": metadata_rva})
            for message in cli_errors
        )
        return _prune(record)

    metadata_address = base + metadata_rva
    read_size = min(
        int(metadata_size),
        _MAX_MONO_METADATA_BYTES,
        budget.remaining_total(),
        budget.remaining_module(module_key),
    )
    if read_size < metadata_size:
        budget.truncated = True
    metadata_data = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        module_size,
        metadata_address,
        read_size,
        budget,
        purpose="mono_cli_metadata",
    )
    record["metadata_read"] = {
        "rva": metadata_rva,
        "rva_hex": _hex(metadata_rva),
        "address": metadata_address,
        "address_hex": _hex(metadata_address),
        "requested_bytes": read_size,
        "returned_bytes": len(metadata_data),
        "declared_size": metadata_size,
        "complete": len(metadata_data) == metadata_size,
        "section": metadata_location.get("section") if metadata_location else None,
        "readable": metadata_location.get("readable") if metadata_location else None,
        "runtime_va_proof": _runtime_va_proof(base, metadata_rva, metadata_address),
    }
    if len(metadata_data) != metadata_size:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error(
                "cli_metadata",
                "CLI metadata is budget-truncated or unreadable",
                details={
                    "declared_size": metadata_size,
                    "returned_bytes": len(metadata_data),
                },
            )
        )
        return _prune(record)

    parsed, dependency = _parse_mono_metadata_root_remote(metadata_data)
    record["dependency_status"] = dependency
    record["metadata"] = _annotate_mono_metadata_provenance(
        parsed,
        base=base,
        metadata_rva=metadata_rva,
        metadata_address=metadata_address,
    )
    metadata_errors = [str(item) for item in parsed.get("errors") or []]
    metadata_error = str(parsed.get("error") or "").strip()
    if metadata_error and metadata_error not in metadata_errors:
        metadata_errors.append(metadata_error)
    if not parsed.get("present") or parsed.get("status") != "ok":
        record["status"] = "partial"
        record["errors"].extend(
            _mono_error("cli_metadata", message) for message in metadata_errors
        )
        if not metadata_errors:
            record["errors"].append(
                _mono_error("cli_metadata", "CLR metadata root was not structurally validated")
            )
        return _prune(record)

    streams = list(parsed.get("streams") or [])
    if len(streams) > _MAX_MONO_STREAMS:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error("cli_metadata", "metadata stream count exceeds bounded limit")
        )
        return _prune(record)
    tables = parsed.get("tables_header") or {}
    if tables.get("status") != "ok" or tables.get("errors"):
        record["status"] = "partial"
        record["errors"].extend(
            _mono_error("cli_tables", str(message))
            for message in (tables.get("errors") or ["CLR tables are not validated"])
        )
        return _prune(record)
    required_streams = {str(item.get("name")) for item in streams}
    if "#Strings" not in required_streams or not ({"#~", "#-"} & required_streams):
        record["status"] = "partial"
        record["errors"].append(
            _mono_error("cli_metadata", "required CLR metadata streams are missing")
        )
        return _prune(record)
    assembly_name = str(parsed.get("assembly_name") or "").strip()
    types = [
        dict(item)
        for item in parsed.get("type_definitions") or []
        if isinstance(item, Mapping)
    ]
    methods = [
        dict(item)
        for item in parsed.get("method_definitions") or []
        if isinstance(item, Mapping)
    ]
    if not assembly_name:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error("assembly_table", "Assembly table row did not resolve a name")
        )
        return _prune(record)
    if len(types) > _MAX_MONO_TYPES or len(methods) > _MAX_MONO_METHODS:
        record["status"] = "partial"
        record["errors"].append(
            _mono_error("cli_tables", "TypeDef or MethodDef count exceeds bounded limit")
        )
        return _prune(record)
    record.update(
        {
            "status": "ok",
            "validated": True,
            "assembly_name": assembly_name,
            "assembly_name_source": "assembly-table",
            "type_definitions": types,
            "method_definitions": methods,
            "type_count": len(types),
            "method_count": len(methods),
            "stream_count": len(streams),
            "provenance": {
                **record["provenance"],
                "parser": dependency.get("parser"),
                "metadata_signature": "BSJB",
                "metadata_streams": [str(item.get("name")) for item in streams],
            },
        }
    )
    return _prune(record)


def _parse_mono_metadata_root_remote(
    data: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Reuse the repository ECMA-335 parser without reading from disk."""

    try:
        from reverse_analyzer.tools.engine import _parse_dotnet_metadata_root

        parsed = _parse_dotnet_metadata_root(data)
        if not isinstance(parsed, Mapping):
            raise TypeError("repository metadata parser returned a non-mapping result")
        return (
            _json_mapping(parsed),
            {
                "parser": "reverse_analyzer.tools.engine._parse_dotnet_metadata_root",
                "status": "available",
                "mode": "reused-bounded-remote-bytes",
            },
        )
    except Exception as exc:
        # Keep the failure explicit.  A missing parser must never turn a
        # filename or a BSJB-looking string into a recovered symbol.
        return (
            {
                "status": "unavailable",
                "present": False,
                "streams": [],
                "type_definitions": [],
                "method_definitions": [],
                "errors": [str(exc)],
                "error": str(exc),
            },
            {
                "parser": "reverse_analyzer.tools.engine._parse_dotnet_metadata_root",
                "status": "unavailable",
                "mode": "import-or-parser-failure",
                "error": str(exc),
            },
        )


def _annotate_mono_metadata_provenance(
    parsed: Mapping[str, Any],
    *,
    base: int,
    metadata_rva: int,
    metadata_address: int,
) -> dict[str, Any]:
    result = _json_mapping(parsed)
    streams: list[dict[str, Any]] = []
    for item in parsed.get("streams") or []:
        if not isinstance(item, Mapping):
            continue
        offset = _coerce_int(item.get("offset"))
        size = _coerce_int(item.get("size"))
        stream = dict(item)
        if offset is not None:
            stream["rva"] = metadata_rva + offset
            stream["rva_hex"] = _hex(metadata_rva + offset)
            stream["address"] = metadata_address + offset
            stream["address_hex"] = _hex(metadata_address + offset)
            stream["runtime_va_proof"] = _runtime_va_proof(
                base, metadata_rva + offset, metadata_address + offset
            )
        if size is not None:
            stream["declared_size"] = size
        streams.append(stream)
    result["streams"] = streams
    result["metadata_rva"] = metadata_rva
    result["metadata_rva_hex"] = _hex(metadata_rva)
    result["metadata_address"] = metadata_address
    result["metadata_address_hex"] = _hex(metadata_address)
    result["runtime_va_proof"] = _runtime_va_proof(
        base, metadata_rva, metadata_address
    )
    return result


def _mono_managed_symbols_and_evidence(
    module: Mapping[str, Any],
    record: Mapping[str, Any],
    pe: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if record.get("status") != "ok" or not record.get("validated"):
        return [], []
    assembly_name = str(record.get("assembly_name") or "").strip()
    if not assembly_name:
        return [], []
    base = _coerce_int(module.get("base_address")) or 0
    identity = module.get("identity_sha256")
    assembly_attrs = {
        "engine": "unity_mono",
        "role": "managed_assembly",
        "assembly": assembly_name,
        "assembly_token": "0x20000001",
        "metadata_rva": (record.get("metadata") or {}).get("metadata_rva"),
        "metadata_size": (record.get("cli") or {}).get("metadata_size"),
        "module_base": base,
        "module_base_hex": _hex(base),
        "module_identity_sha256": identity,
        "runtime_object_address": "unresolved",
        "runtime_object_address_reason": (
            "Assembly table metadata does not prove a live MonoAssembly object address"
        ),
    }
    assembly_symbol = _mono_runtime_symbol(
        module,
        role="managed_assembly",
        display_name=assembly_name,
        name_kind="assembly_table",
        source="ecma-335-assembly-table",
        address=None,
        token="0x20000001",
        attributes=assembly_attrs,
    )
    symbols = [assembly_symbol]
    evidence = [
        _evidence_item(
            engine="unity_mono",
            kind="managed_assembly",
            marker=assembly_name,
            symbol=assembly_name,
            weight=5.0,
            module=module,
            address=None,
            rva=None,
            source="ecma-335-assembly-table",
            details={
                "token": "0x20000001",
                "metadata_signature": "BSJB",
                "metadata_streams": [
                    item.get("name")
                    for item in (record.get("metadata") or {}).get("streams") or []
                    if isinstance(item, Mapping)
                ],
                "runtime_object_address": "unresolved",
            },
        )
    ]
    for type_row in record.get("type_definitions") or []:
        if not isinstance(type_row, Mapping):
            continue
        full_name = str(type_row.get("full_name") or type_row.get("name") or "").strip()
        token = str(type_row.get("token") or "").strip()
        if not full_name or not token:
            continue
        type_attrs = {
            "engine": "unity_mono",
            "role": "managed_type",
            "assembly": assembly_name,
            "assembly_symbol_id": assembly_symbol["id"],
            "token": token,
            "namespace": type_row.get("namespace") or "",
            "base_type": type_row.get("base_type"),
            "flags": type_row.get("flags"),
            "module_base": base,
            "module_base_hex": _hex(base),
            "module_identity_sha256": identity,
            "runtime_object_address": "unresolved",
            "runtime_object_address_reason": (
                "TypeDef metadata does not prove a live MonoClass object address"
            ),
        }
        type_symbol = _mono_runtime_symbol(
            module,
            role="managed_type",
            display_name=full_name,
            name_kind="typedef",
            source="ecma-335-typedef-table",
            address=None,
            token=token,
            attributes=type_attrs,
        )
        symbols.append(type_symbol)
        evidence.append(
            _evidence_item(
                engine="unity_mono",
                kind="managed_type",
                marker=full_name,
                symbol=full_name,
                weight=3.0,
                module=module,
                address=None,
                rva=None,
                source="ecma-335-typedef-table",
                details={
                    "token": token,
                    "assembly": assembly_name,
                    "runtime_object_address": "unresolved",
                },
            )
        )
        for method_row in type_row.get("methods") or []:
            if not isinstance(method_row, Mapping):
                continue
            method_name = str(method_row.get("name") or "").strip()
            method_token = str(method_row.get("token") or "").strip()
            if not method_name or not method_token:
                continue
            method_rva = _coerce_int(method_row.get("rva")) or 0
            method_address: Optional[int] = None
            method_location: Optional[dict[str, Any]] = None
            unresolved_reason = (
                "MethodDef metadata does not prove a live MonoMethod object address"
            )
            if method_rva:
                candidate_address = base + method_rva
                method_location = _remote_pe_location(
                    pe, module, candidate_address
                )
                if method_location and method_location.get("executable"):
                    method_address = candidate_address
                    unresolved_reason = (
                        "MethodDef RVA proves only the loaded managed method body VA, "
                        "not a live MonoMethod object address"
                    )
                else:
                    unresolved_reason = (
                        "MethodDef RVA is not proven executable in the loaded PE and "
                        "does not prove a live MonoMethod object address"
                    )
            method_attrs = {
                "engine": "unity_mono",
                "role": "managed_method",
                "assembly": assembly_name,
                "assembly_symbol_id": assembly_symbol["id"],
                "declaring_type": full_name,
                "declaring_type_symbol_id": type_symbol["id"],
                "token": method_token,
                "method_rva": method_rva,
                "impl_flags": method_row.get("impl_flags"),
                "flags": method_row.get("flags"),
                "module_base": base,
                "module_base_hex": _hex(base),
                "module_identity_sha256": identity,
                "address_kind": (
                    "managed_method_body_va" if method_address is not None else "unresolved"
                ),
                "runtime_object_address": "unresolved",
                "runtime_object_address_reason": unresolved_reason,
            }
            if method_location:
                method_attrs["native_section"] = method_location.get("section")
                method_attrs["native_executable"] = bool(method_location.get("executable"))
            method_symbol = _mono_runtime_symbol(
                module,
                role="managed_method",
                display_name=method_name,
                name_kind="methoddef",
                source="ecma-335-methoddef-table",
                address=method_address,
                token=method_token,
                attributes=method_attrs,
            )
            symbols.append(method_symbol)
            evidence.append(
                _evidence_item(
                    engine="unity_mono",
                    kind="managed_method",
                    marker=method_name,
                    symbol=method_name,
                    weight=2.5,
                    module=module,
                    address=method_address,
                    rva=method_rva if method_address is not None else None,
                    source="ecma-335-methoddef-table",
                    details={
                        "token": method_token,
                        "assembly": assembly_name,
                        "declaring_type": full_name,
                        "method_rva": method_rva,
                        "section": (method_location or {}).get("section"),
                        "executable": (method_location or {}).get("executable"),
                        "address_kind": (
                            "managed_method_body_va"
                            if method_address is not None
                            else "unresolved"
                        ),
                        "runtime_object_address": "unresolved",
                        "runtime_object_address_reason": unresolved_reason,
                    },
                )
            )
    return _stable_mono_symbols(symbols), _stable_mono_evidence(evidence)


def _mono_runtime_symbol(
    module: Mapping[str, Any],
    *,
    role: str,
    display_name: str,
    name_kind: str,
    source: str,
    address: Optional[int],
    token: Optional[str] = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address")) or 0
    rva = address - base if isinstance(address, int) else None
    attrs = _json_mapping(attributes)
    attrs.setdefault("engine", "unity_mono")
    attrs.setdefault("runtime_object_address", "unresolved")
    if address is not None:
        attrs.setdefault("runtime_va_proof", _runtime_va_proof(base, rva, address))
    return _prune(
        {
            "id": "runtime:" + _canonical_hash(
                [module.get("identity_sha256"), role, token or display_name, address]
            )[:20],
            "kind": "runtime_symbol",
            "role": role,
            "name": display_name,
            "name_kind": name_kind,
            "token": token,
            "address": address,
            "address_hex": _hex(address),
            "rva": rva,
            "rva_hex": _hex(rva),
            "module": module.get("name"),
            "module_path": module.get("path"),
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": base,
            "module_base_hex": _hex(base),
            "runtime_va_proof": (
                _runtime_va_proof(base, rva, address)
                if address is not None
                else None
            ),
            "confidence": 0.99 if role == "managed_assembly" else 0.97,
            "validated": True,
            "source": source,
            "attributes": attrs,
        }
    )


def _mono_semantic_fragment(
    status: str,
    symbols: Sequence[Mapping[str, Any]],
    module: Mapping[str, Any],
    *,
    dependency_status: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    entities: dict[str, dict[str, Any]] = {}
    relations: dict[str, dict[str, Any]] = {}
    for symbol in symbols:
        symbol_id = str(symbol.get("id") or "")
        role = str(symbol.get("role") or "")
        if not symbol_id or role not in {
            "managed_assembly",
            "managed_type",
            "managed_method",
            "root_domain",
            "current_domain",
            "thread_attach",
            "assembly_open",
            "assembly_foreach",
            "assembly_get_image",
            "image_get_name",
            "class_from_name",
            "class_get_methods",
            "method_get_name",
            "runtime_invoke",
            "object_get_class",
            "string_to_utf8",
            "thread_detach",
        }:
            continue
        if role == "managed_assembly":
            kind = "assembly"
        elif role == "managed_type":
            kind = "class"
        elif role == "managed_method":
            kind = "function"
        else:
            kind = "runtime_symbol"
        attrs = {
            "engine": "unity_mono",
            "role": role,
            "module": module.get("name"),
            "module_path": module.get("path"),
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": module.get("base_address"),
            "module_base_hex": module.get("base_address_hex"),
            "address": symbol.get("address"),
            "rva": symbol.get("rva"),
            "runtime_va_proof": symbol.get("runtime_va_proof"),
            "runtime_object_address": "unresolved",
            **_json_mapping(symbol.get("attributes")),
        }
        entities[symbol_id] = {
            "id": symbol_id,
            "kind": kind,
            "name": symbol.get("name"),
            "confidence": symbol.get("confidence"),
            "attributes": attrs,
            "evidence": [{"source": symbol.get("source")}],
        }
    for entity in list(entities.values()):
        attrs = entity.get("attributes") or {}
        role = attrs.get("role")
        if role == "managed_type":
            assembly_id = attrs.get("assembly_symbol_id")
            if assembly_id in entities:
                relation = _mono_relation(
                    assembly_id,
                    entity["id"],
                    "contains_type",
                    "ecma-335-assembly-table",
                )
                relations[relation["id"]] = relation
        elif role == "managed_method":
            type_id = attrs.get("declaring_type_symbol_id")
            if type_id in entities:
                relation = _mono_relation(
                    type_id,
                    entity["id"],
                    "declares_method",
                    "ecma-335-typedef-table",
                )
                relations[relation["id"]] = relation
    unresolved_count = sum(
        1
        for symbol in symbols
        if symbol.get("role") in {"managed_assembly", "managed_type", "managed_method"}
    )
    return {
        "status": status,
        "schema_version": 1,
        "engine": "unity_mono",
        "entities": [entities[key] for key in sorted(entities)],
        "relations": [relations[key] for key in sorted(relations)],
        "dependency_status": _json_mapping(dependency_status),
        "remote_api_calls": False,
        "runtime_object_addresses": {
            "status": "unresolved",
            "count": unresolved_count,
            "reason": "read-only evidence does not prove live Mono object addresses",
        },
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "validated_symbol_count": len(entities),
            "assembly_count": sum(
                1 for item in entities.values() if item["attributes"].get("role") == "managed_assembly"
            ),
            "type_count": sum(
                1 for item in entities.values() if item["attributes"].get("role") == "managed_type"
            ),
            "method_count": sum(
                1 for item in entities.values() if item["attributes"].get("role") == "managed_method"
            ),
            "unresolved_count": unresolved_count,
        },
    }


def _mono_relation(source: str, target: str, relation_type: str, evidence: str) -> dict[str, Any]:
    return {
        "id": "runtime:" + _canonical_hash([source, target, relation_type])[:20],
        "type": relation_type,
        "source": source,
        "target": target,
        "confidence": 0.99,
        "evidence": [{"source": evidence}],
    }


def _stable_mono_symbols(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[str, dict[str, Any]] = {}
    for value in values:
        if isinstance(value, Mapping) and value.get("id"):
            dedup[str(value["id"])] = _json_mapping(value)
    return [dedup[key] for key in sorted(dedup)]


def _stable_mono_evidence(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping):
            continue
        key = _canonical_hash(
            [
                value.get("kind"),
                value.get("marker"),
                value.get("symbol"),
                value.get("module_identity_sha256"),
                value.get("address"),
                value.get("rva"),
            ]
        )
        dedup[key] = _json_mapping(value)
    return [dedup[key] for key in sorted(dedup)]


def _stable_mono_errors(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    dedup: dict[str, dict[str, Any]] = {}
    for value in values:
        if isinstance(value, Mapping):
            item = _json_mapping(value)
        else:
            item = {"operation": "mono_runtime", "message": str(value)}
        dedup[_canonical_hash(item)] = item
    return [dedup[key] for key in sorted(dedup)]


def _mono_error(
    operation: str,
    message: str,
    *,
    details: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "message": str(message),
        "details": _json_mapping(details),
    }


def _runtime_dependency_status(
    extractions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    statuses: list[dict[str, Any]] = []
    for extraction in extractions:
        dependency = extraction.get("dependency_status")
        if isinstance(dependency, Mapping) and dependency:
            statuses.append(_json_mapping(dependency))
        for component in extraction.get("components") or []:
            if isinstance(component, Mapping) and isinstance(
                component.get("dependency_status"), Mapping
            ):
                statuses.append(_json_mapping(component["dependency_status"]))
    if not statuses:
        return {"status": "not_used", "parser": None}
    unique = {
        _canonical_hash(item): item
        for item in statuses
    }
    ordered = [unique[key] for key in sorted(unique)]
    dependency_states = {str(item.get("status") or "") for item in ordered}
    unavailable = "unavailable" in dependency_states
    dependency_gated = "dependency-gated" in dependency_states
    partial = "partial" in dependency_states
    available = "available" in dependency_states
    if unavailable:
        status = "unavailable"
    elif dependency_gated:
        status = "dependency-gated"
    elif partial:
        status = "partial"
    elif available:
        status = "available"
    elif dependency_states <= {"", "not_used"}:
        status = "not_used"
    else:
        status = "available"
    return {
        "status": status,
        "dependencies": ordered,
        "parser": ordered[0].get("parser") if ordered else None,
    }


def _empty_unreal_engine_analysis(
    status: str,
    reason: str,
    parameters: Mapping[str, Any],
    read_usage: Mapping[str, Any],
) -> dict[str, Any]:
    dependency_state = "unavailable" if status == "unavailable" else "not_used"
    return {
        "schema_version": 1,
        "status": status,
        "engine": "unreal",
        "platform": "windows-process-runtime",
        "mode": "read-only-loaded-image-evidence",
        "reason": reason,
        "confidence": 0.0,
        "loaded_module_detection": {
            "status": "unavailable",
            "module_count": 0,
            "modules": [],
        },
        "modules": [],
        "pe_identity_proofs": [],
        "runtime_collection_status": status,
        "runtime_components": [],
        "normalized_clues": {
            "total_count": 0,
            "uobject": [],
            "uclass": [],
            "ufunction": [],
            "umg": [],
            "fname": [],
            "other": [],
        },
        "runtime_globals": {
            "candidates": [],
            "validated": [],
            "callable_exports": [],
        },
        "address_resolution": {
            "string_storage": {"status": "unavailable", "count": 0},
            "global_storage": {"status": "unavailable", "count": 0},
            "name_pool": {"status": "dependency-gated", "addresses": []},
            "object_array": {"status": "dependency-gated", "addresses": []},
            "uobject_instances": {"status": "unresolved"},
            "uclass_instances": {"status": "unresolved"},
            "ufunction_instances": {"status": "unresolved"},
            "umg_instances": {"status": "unresolved"},
            "world_object": {"status": "dependency-gated"},
        },
        "dependency_status": {
            "status": dependency_state,
            "parser": None,
            "reason": reason,
        },
        "ambiguities": [
            {
                "kind": "collection_availability",
                "status": status,
                "reason": reason,
            }
        ],
        "read_budget": {
            "limits": _read_limits(parameters),
            "usage": _json_mapping(read_usage),
            "truncated": bool(read_usage.get("truncated")),
            "unreal_components": [],
        },
        "semantic_ir_fragment": _empty_runtime_semantic_fragment("unreal", status),
        "provenance": {
            "sources": [],
            "read_only": True,
            "remote_api_calls": False,
            "module_identity_scope": "normalized enumerated name/path/base/size",
            "module_content_hash": "not_collected",
            "address_semantics": {
                "string_hits": "string_storage_only",
                "runtime_objects": "unresolved",
            },
        },
        "completion_boundary": {
            "done": [],
            "dependency_gated": [
                "FName entry decoding",
                "FUObjectItem/UObject traversal",
                "UClass/UFunction/UMG instance resolution",
            ],
            "unresolved": ["runtime object addresses"],
        },
        "evidence": [],
    }


def _build_unreal_engine_analysis(
    *,
    modules: Sequence[Mapping[str, Any]],
    analyzed_modules: Sequence[Mapping[str, Any]],
    engine_candidates: Sequence[Mapping[str, Any]],
    read_limits: Mapping[str, Any],
    read_usage: Mapping[str, Any],
) -> dict[str, Any]:
    unreal_context = _has_unreal_runtime_context(modules)
    analyzed_by_identity = {
        str((item.get("module") or {}).get("identity_sha256") or ""): item
        for item in analyzed_modules
        if isinstance(item, Mapping) and isinstance(item.get("module"), Mapping)
    }
    loaded_records: list[dict[str, Any]] = []
    component_records: list[tuple[dict[str, Any], Mapping[str, Any]]] = []
    pe_proofs: list[dict[str, Any]] = []
    for module in modules:
        if not isinstance(module, Mapping):
            continue
        classification = _unreal_module_classification(
            module,
            unreal_context=unreal_context,
        )
        if not classification.get("matched"):
            continue
        identity = str(module.get("identity_sha256") or "")
        analyzed = analyzed_by_identity.get(identity)
        pe = (
            analyzed.get("pe")
            if isinstance(analyzed, Mapping) and isinstance(analyzed.get("pe"), Mapping)
            else {}
        )
        components = [
            dict(item)
            for item in (
                ((analyzed.get("runtime_extraction") or {}).get("components") or [])
                if isinstance(analyzed, Mapping)
                else []
            )
            if isinstance(item, Mapping) and item.get("engine") == "unreal"
        ]
        for component in components:
            component_records.append((component, module))
        proof = (
            dict(components[0].get("pe_identity") or {})
            if components and isinstance(components[0].get("pe_identity"), Mapping)
            else _unreal_pe_identity_proof(module, pe)
        )
        proof_record = {
            "module": module.get("name"),
            "module_identity_sha256": identity or None,
            **proof,
        }
        pe_proofs.append(proof_record)
        loaded_records.append(
            {
                "name": module.get("name"),
                "path": module.get("path"),
                "identity_sha256": identity or None,
                "identity_scope": "normalized enumerated name/path/base/size",
                "content_hash_status": "not_collected",
                "base_address": module.get("base_address"),
                "base_address_hex": module.get("base_address_hex"),
                "size": module.get("size"),
                "end_address": module.get("end_address"),
                "end_address_hex": module.get("end_address_hex"),
                "classification": classification,
                "pe_identity_status": proof.get("status"),
                "pe_identity_verified": bool(proof.get("verified")),
                "runtime_component_count": len(components),
                "runtime_collection_status": _component_status(components),
            }
        )

    if not loaded_records:
        return _empty_unreal_engine_analysis(
            "unavailable",
            "no loaded module matched a bounded Unreal runtime identity rule",
            read_limits,
            read_usage,
        )

    components = [item for item, _ in component_records]
    clues_by_id: dict[str, dict[str, Any]] = {}
    symbols_by_id: dict[str, dict[str, Any]] = {}
    candidates: list[dict[str, Any]] = []
    callables: list[dict[str, Any]] = []
    ambiguity_by_id: dict[str, dict[str, Any]] = {}
    component_budgets: list[dict[str, Any]] = []
    fragments: list[Mapping[str, Any]] = []
    for component, module in component_records:
        module_name = module.get("name")
        module_identity = module.get("identity_sha256")
        for raw_clue in component.get("normalized_clues") or []:
            if not isinstance(raw_clue, Mapping):
                continue
            clue = {
                **_json_mapping(raw_clue),
                "module": module_name,
                "module_identity_sha256": module_identity,
                "address_kind": "string_storage",
                "object_address": {
                    "status": "unresolved",
                    "reason": (
                        "a reflection/name string does not prove a live Unreal object"
                    ),
                },
            }
            clue_id = str(
                clue.get("id")
                or "runtime:"
                + _canonical_hash(
                    [
                        module_identity,
                        clue.get("marker"),
                        clue.get("encoding"),
                        clue.get("address"),
                    ]
                )[:20]
            )
            clue["id"] = clue_id
            clues_by_id[clue_id] = clue
        for raw_symbol in component.get("symbols") or []:
            if isinstance(raw_symbol, Mapping) and raw_symbol.get("id"):
                symbols_by_id[str(raw_symbol["id"])] = _json_mapping(raw_symbol)
        for raw_candidate in component.get("candidates") or []:
            if isinstance(raw_candidate, Mapping):
                candidates.append(
                    {
                        **_json_mapping(raw_candidate),
                        "module": module_name,
                        "module_identity_sha256": module_identity,
                    }
                )
        for raw_callable in component.get("callable_exports") or []:
            if isinstance(raw_callable, Mapping):
                callables.append(
                    {
                        **_json_mapping(raw_callable),
                        "module": module_name,
                        "module_identity_sha256": module_identity,
                    }
                )
        for raw_ambiguity in component.get("ambiguities") or []:
            if not isinstance(raw_ambiguity, Mapping):
                continue
            ambiguity = {
                **_json_mapping(raw_ambiguity),
                "module": module_name,
                "module_identity_sha256": module_identity,
            }
            ambiguity_by_id[_canonical_hash(ambiguity)] = ambiguity
        if isinstance(component.get("read_budget"), Mapping):
            component_budgets.append(
                {
                    "module": module_name,
                    "module_identity_sha256": module_identity,
                    **_json_mapping(component["read_budget"]),
                }
            )
        if isinstance(component.get("semantic_ir_fragment"), Mapping):
            fragments.append(component["semantic_ir_fragment"])

    normalized_clues = [clues_by_id[key] for key in sorted(clues_by_id)]
    clue_groups: dict[str, list[dict[str, Any]]] = {
        "uobject": [],
        "uclass": [],
        "ufunction": [],
        "umg": [],
        "fname": [],
        "other": [],
    }
    for clue in normalized_clues:
        normalized_kind = str(clue.get("normalized_kind") or "")
        categories: list[str] = []
        if normalized_kind.startswith("umg_"):
            categories.append("umg")
        if normalized_kind in {
            "uobject",
            "uobject_lookup",
            "object_array_global",
        }:
            categories.append("uobject")
        if normalized_kind in {"uclass", "uclass_lookup", "umg_generated_class"}:
            categories.append("uclass")
        if normalized_kind in {"ufunction", "ufunction_dispatch"}:
            categories.append("ufunction")
        if normalized_kind in {"name", "name_pool", "name_global"}:
            categories.append("fname")
        if not categories:
            categories.append("other")
        clue["normalized_categories"] = categories
        for category in categories:
            clue_groups[category].append(clue)

    validated_globals = [item for item in candidates if item.get("status") == "validated"]
    validated_callables = [item for item in callables if item.get("status") == "validated"]
    name_pool_addresses = sorted(
        {
            int(pool)
            for item in validated_globals
            for pool in [(item.get("validation") or {}).get("pool_address")]
            if _coerce_int(pool) is not None
        }
    )
    object_array_addresses = sorted(
        {
            int(array)
            for item in validated_globals
            for array in [(item.get("validation") or {}).get("array_address")]
            if _coerce_int(array) is not None
        }
    )
    world_candidates = sorted(
        {
            int(value)
            for item in validated_globals
            for value in [
                ((item.get("validation") or {}).get("world_object_address") or {}).get(
                    "candidate_value"
                )
            ]
            if _coerce_int(value) is not None
        }
    )
    global_storage_addresses = sorted(
        {
            int(item["address"])
            for item in validated_globals
            if _coerce_int(item.get("address")) is not None
        }
    )
    address_resolution = {
        "string_storage": {
            "status": "validated" if normalized_clues else "unavailable",
            "count": len(normalized_clues),
            "address_kind": "string_storage",
        },
        "global_storage": {
            "status": "validated" if global_storage_addresses else "unavailable",
            "count": len(global_storage_addresses),
            "addresses": global_storage_addresses,
            "address_kind": "unreal_global_storage_va",
        },
        "name_pool": {
            "status": "validated" if name_pool_addresses else "dependency-gated",
            "addresses": name_pool_addresses,
            "reason": (
                None
                if name_pool_addresses
                else "no exported global plus bounded FNamePool header was validated"
            ),
        },
        "object_array": {
            "status": "validated" if object_array_addresses else "dependency-gated",
            "addresses": object_array_addresses,
            "reason": (
                None
                if object_array_addresses
                else "no exported global plus bounded FUObjectArray header was validated"
            ),
        },
        "uobject_instances": {
            "status": "unresolved",
            "reason": "FUObjectItem/UObject traversal was not performed",
        },
        "uclass_instances": {
            "status": "unresolved",
            "reason": "UClass name evidence is not an object address",
        },
        "ufunction_instances": {
            "status": "unresolved",
            "reason": "UFunction name evidence is not an object address",
        },
        "umg_instances": {
            "status": "unresolved",
            "reason": "UMG name evidence is not a widget instance address",
        },
        "world_object": {
            "status": "dependency-gated",
            "candidate_values": world_candidates,
            "reason": "readability does not prove the pointed-to UWorld type/layout",
        },
    }

    dependency_status = (
        _runtime_dependency_status([{"components": components}])
        if components
        else {
            "status": "dependency-gated",
            "parser": "builtin_bounded_unreal_runtime_probes",
            "reason": "the loaded Unreal module was not runtime-inspected",
        }
    )
    ambiguities = [ambiguity_by_id[key] for key in sorted(ambiguity_by_id)]
    if not ambiguities:
        ambiguities = [
            {
                "kind": "unreal_version_layout",
                "status": "dependency-gated",
                "reason": "no exact Unreal build layout profile was established",
            }
        ]

    collection_status = _component_status(components)
    all_components_complete = bool(components) and all(
        item.get("status") == "ok" for item in components
    )
    all_pe_verified = len(pe_proofs) == len(loaded_records) and all(
        item.get("verified") for item in pe_proofs
    )
    status = "ok" if all_components_complete and all_pe_verified else "partial"
    unreal_candidate = next(
        (item for item in engine_candidates if item.get("engine") == "unreal"),
        {},
    )
    confidence = float(
        unreal_candidate.get("confidence")
        or max(
            float((item.get("classification") or {}).get("confidence") or 0.0)
            for item in loaded_records
        )
    )
    semantic_fragment = (
        _merge_runtime_semantic_fragments(fragments)
        if fragments
        else _empty_runtime_semantic_fragment("unreal", collection_status)
    )
    semantic_fragment.update(
        {
            "engine": "unreal",
            "dependency_status": dependency_status,
            "address_resolution": address_resolution,
            "ambiguities": ambiguities,
        }
    )
    semantic_summary = dict(semantic_fragment.get("summary") or {})
    semantic_summary.update(
        {
            "validated_symbol_count": len(symbols_by_id),
            "name_evidence_count": len(normalized_clues),
            "unresolved_object_address_count": len(normalized_clues),
        }
    )
    semantic_fragment["summary"] = semantic_summary
    evidence_summary = [
        f"enumerated {len(loaded_records)} loaded Unreal module(s)",
        f"verified {sum(bool(item.get('verified')) for item in pe_proofs)} PE identity/range proof(s)",
        f"collected {len(normalized_clues)} bounded reflection/name clue(s)",
        f"validated {len(validated_globals)} runtime global storage candidate(s)",
        f"validated {len(validated_callables)} callable export(s)",
    ]
    return _prune(
        {
            "schema_version": 1,
            "status": status,
            "engine": "unreal",
            "platform": "windows-process-runtime",
            "mode": "read-only-loaded-image-evidence",
            "reason": (
                None
                if status == "ok"
                else "loaded-module evidence is available, but runtime collection or PE proof is partial"
            ),
            "confidence": round(confidence, 4),
            "loaded_module_detection": {
                "status": "detected",
                "module_count": len(loaded_records),
                "strong_module_count": sum(
                    bool((item.get("classification") or {}).get("strong"))
                    for item in loaded_records
                ),
                "contextual_module_count": sum(
                    bool((item.get("classification") or {}).get("contextual"))
                    for item in loaded_records
                ),
                "modules": loaded_records,
                "provenance": {
                    "source": "module_enumeration",
                    "identity_scope": "normalized name/path/base/size",
                },
            },
            "modules": loaded_records,
            "pe_identity_proofs": pe_proofs,
            "runtime_collection_status": collection_status,
            "runtime_components": components,
            "normalized_clues": {
                "total_count": len(normalized_clues),
                **clue_groups,
            },
            "runtime_globals": {
                "candidates": candidates,
                "validated": validated_globals,
                "callable_exports": callables,
                "validated_callable_exports": validated_callables,
            },
            "symbols": [symbols_by_id[key] for key in sorted(symbols_by_id)],
            "address_resolution": address_resolution,
            "dependency_status": dependency_status,
            "ambiguities": ambiguities,
            "read_budget": {
                "limits": _json_mapping(read_limits),
                "usage": _json_mapping(read_usage),
                "truncated": bool(read_usage.get("truncated")),
                "unreal_components": component_budgets,
            },
            "semantic_ir_fragment": semantic_fragment,
            "provenance": {
                "sources": [
                    "module_enumeration",
                    "remote_pe_headers",
                    "pe_export_table",
                    "ReadProcessMemory",
                ],
                "read_only": True,
                "remote_api_calls": False,
                "module_identity_scope": "normalized enumerated name/path/base/size",
                "module_content_hash": "not_collected",
                "address_semantics": {
                    "string_hits": "string_storage_only",
                    "callable_exports": "code_addresses_only",
                    "runtime_globals": "validated_storage_and_bounded_header_only",
                    "runtime_objects": "unresolved_without_versioned_layout_proof",
                },
            },
            "completion_boundary": {
                "done": [
                    "loaded Unreal module identification",
                    "PE identity/architecture/image range proof",
                    "bounded readable-section reflection/name scan",
                    "UObject/UClass/UFunction/UMG clue normalization",
                ],
                "dependency_gated": [
                    "FName entry decoding beyond the bounded header probe",
                    "FUObjectItem/UObject traversal",
                    "UClass/UFunction/UMG instance resolution",
                    "GWorld target type proof",
                ],
                "unresolved": [
                    "object addresses derived only from strings",
                    "live reflection instances without a matching Unreal layout",
                ],
            },
            "evidence": evidence_summary,
        }
    )


def _discover_il2cpp_registrations(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    pointer_size = _coerce_int(pe.get("pointer_size"))
    empty = {
        "engine": "unity_il2cpp",
        "status": "unavailable",
        "discovery": "generated-registration-call-arguments",
        "candidates": [],
        "symbols": [],
        "evidence": [],
        "semantic_ir_fragment": _empty_runtime_semantic_fragment(
            "unity_il2cpp", "unavailable"
        ),
        "errors": [],
    }
    if base is None or size is None or size <= 0 or pointer_size not in {4, 8}:
        empty["reason"] = "validated PE module range and pointer size are unavailable"
        return empty
    sites, scan_errors, scan_truncated = _find_il2cpp_registration_sites(
        backend, pid, module, module_key, pe, budget
    )
    if not sites:
        empty["reason"] = "no bounded generated IL2CPP registration call site was found"
        empty["scan_truncated"] = scan_truncated
        empty["errors"] = scan_errors
        return empty

    candidates: list[dict[str, Any]] = []
    errors = list(scan_errors)
    for site in sites:
        code, code_errors = _parse_il2cpp_code_registration(
            backend,
            pid,
            module,
            module_key,
            pe,
            budget,
            int(site["code_registration_address"]),
        )
        metadata, metadata_errors = _parse_il2cpp_metadata_registration(
            backend,
            pid,
            module,
            module_key,
            budget,
            int(site["metadata_registration_address"]),
            pointer_size,
        )
        candidate_errors = [*code_errors, *metadata_errors]
        validated = code is not None and metadata is not None
        candidate = {
            "status": "validated" if validated else "rejected",
            "registration_site": site,
            "code_registration": code,
            "metadata_registration": metadata,
            "errors": candidate_errors,
        }
        candidates.append(_prune(candidate))
        errors.extend(candidate_errors)

    valid_by_target: dict[tuple[int, int], dict[str, Any]] = {}
    for candidate in candidates:
        if candidate.get("status") != "validated":
            continue
        site = candidate["registration_site"]
        valid_by_target[
            (
                int(site["code_registration_address"]),
                int(site["metadata_registration_address"]),
            )
        ] = candidate
    valid = list(valid_by_target.values())
    status = "ok" if len(valid) == 1 else "partial"
    if len(valid) > 1:
        errors.append(
            {
                "operation": "il2cpp_registration",
                "message": "multiple distinct validated registration pairs are ambiguous",
            }
        )
    elif not valid:
        errors.append(
            {
                "operation": "il2cpp_registration",
                "message": "registration call candidates failed structural validation",
            }
        )

    symbols: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    selected = valid[0] if len(valid) == 1 else None
    if selected is not None:
        site = selected["registration_site"]
        for role, marker, address in (
            ("code_registration", "Il2CppCodeRegistration", site["code_registration_address"]),
            (
                "metadata_registration",
                "Il2CppMetadataRegistration",
                site["metadata_registration_address"],
            ),
        ):
            symbol = _runtime_symbol(
                module,
                role=role,
                display_name=marker,
                address=int(address),
                confidence=0.99,
                name_kind="inferred_semantic_role",
                source="generated_registration_call_argument",
            )
            symbols.append(symbol)
            evidence.append(
                _evidence_item(
                    engine="unity_il2cpp",
                    kind="runtime_registration",
                    marker=marker,
                    symbol=marker,
                    weight=6.0,
                    module=module,
                    address=int(address),
                    rva=int(address) - base,
                    source="generated_registration_call_argument",
                    details={
                        "role": role,
                        "name_kind": "inferred_semantic_role",
                        "validation": "count_pointer_ranges_and_codegen_modules",
                        "registration_site": site.get("address"),
                    },
                )
            )
        for codegen_module in selected["code_registration"].get("codegen_modules") or []:
            name = str(codegen_module.get("name") or "")
            address = _coerce_int(codegen_module.get("address"))
            if not name or address is None:
                continue
            codegen_symbol = _runtime_symbol(
                module,
                role="codegen_module",
                display_name=name,
                address=address,
                confidence=0.99,
                name_kind="runtime_string",
                source="Il2CppCodeGenModule.moduleName",
                attributes={
                    "method_pointer_count": codegen_module.get(
                        "method_pointer_count"
                    )
                },
            )
            symbols.append(codegen_symbol)
            evidence.append(
                _evidence_item(
                    engine="unity_il2cpp",
                    kind="runtime_symbol",
                    marker=name,
                    symbol=name,
                    weight=2.0,
                    module=module,
                    address=address,
                    rva=address - base,
                    source="Il2CppCodeGenModule.moduleName",
                    details={
                        "role": "codegen_module",
                        "method_pointer_count": codegen_module.get(
                            "method_pointer_count"
                        ),
                    },
                )
            )
            for mapping in codegen_module.get("method_token_mappings") or []:
                token = str(mapping.get("token") or "")
                method_address = _coerce_int(mapping.get("address"))
                pointer_index = _coerce_int(mapping.get("pointer_index"))
                if not token or method_address is None or pointer_index is None:
                    continue
                symbols.append(
                    _runtime_symbol(
                        module,
                        role="il2cpp_method",
                        display_name=f"{name}!{token}",
                        address=method_address,
                        confidence=0.98,
                        name_kind="metadata_token",
                        source="Il2CppCodeGenModule.methodPointers",
                        identity_key={"codegen_module": name.lower(), "token": token},
                        attributes={
                            "token": token,
                            "pointer_index": pointer_index,
                            "codegen_module": name,
                            "address_kind": "runtime_va",
                            "section": mapping.get("section"),
                        },
                    )
                )
    semantic = _runtime_semantic_fragment(
        "unity_il2cpp", status, symbols, module
    )
    return _prune(
        {
            "engine": "unity_il2cpp",
            "status": status,
            "discovery": "generated-registration-call-arguments",
            "architecture": pe.get("architecture"),
            "pointer_size": pointer_size,
            "scan_truncated": scan_truncated,
            "candidate_count": len(candidates),
            "validated_candidate_count": len(valid),
            "candidates": candidates,
            "selected": selected,
            "symbols": symbols,
            "evidence": evidence,
            "semantic_ir_fragment": semantic,
            "errors": errors,
        }
    )


def _find_il2cpp_registration_sites(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    budget: _ReadBudget,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    base = int(module["base_address"])
    size = int(module["size"])
    pointer_size = int(pe.get("pointer_size") or 0)
    sections = [
        item
        for item in pe.get("sections") or []
        if isinstance(item, Mapping)
        and item.get("range_valid")
        and item.get("executable")
    ]
    if not sections:
        return [], [], False
    remaining_scan = min(
        _MAX_RUNTIME_CODE_SCAN_BYTES,
        budget.remaining_total(),
        budget.remaining_module(module_key),
    )
    sites: dict[tuple[int, int], dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    truncated = False
    for section in sections:
        if remaining_scan <= 0:
            truncated = True
            break
        section_rva = int(section.get("rva") or 0)
        section_size = int(section.get("mapped_size") or 0)
        allowance = min(section_size, remaining_scan)
        if allowance < section_size:
            truncated = True
        ranges = _sample_ranges(
            section_size,
            allowance,
            min(budget.single_limit, 64 * 1024),
        )
        for relative, requested in ranges:
            data = _read_module_exact(
                backend,
                pid,
                module_key,
                base,
                size,
                base + section_rva + relative,
                requested,
                budget,
                purpose="il2cpp_registration_code_scan",
            )
            remaining_scan -= requested
            if len(data) != requested:
                errors.append(
                    {
                        "operation": "il2cpp_registration_code_scan",
                        "message": "an executable scan range was unreadable or truncated",
                        "address": base + section_rva + relative,
                        "requested_bytes": requested,
                        "returned_bytes": len(data),
                    }
                )
                continue
            chunk_address = base + section_rva + relative
            found = (
                _x64_registration_sites(data, chunk_address, base, size)
                if pointer_size == 8
                else _x86_registration_sites(data, chunk_address, base, size)
            )
            for site in found:
                code_address = int(site["code_registration_address"])
                metadata_address = int(site["metadata_registration_address"])
                code_location = _remote_pe_location(pe, module, code_address)
                metadata_location = _remote_pe_location(pe, module, metadata_address)
                options_location = _remote_pe_location(
                    pe, module, int(site["codegen_options_address"])
                )
                if not all((code_location, metadata_location, options_location)):
                    continue
                if code_location.get("executable") or metadata_location.get("executable"):
                    continue
                site.update(
                    {
                        "rva": int(site["address"]) - base,
                        "rva_hex": _hex(int(site["address"]) - base),
                        "code_registration_rva": code_address - base,
                        "metadata_registration_rva": metadata_address - base,
                        "codegen_options_rva": int(site["codegen_options_address"]) - base,
                    }
                )
                sites[(code_address, metadata_address)] = site
    return list(sites.values()), errors, truncated


def _x64_registration_sites(
    data: bytes, chunk_address: int, module_base: int, module_size: int
) -> list[dict[str, Any]]:
    instructions: dict[bytes, list[int]] = {
        b"\x48\x8d\x0d": [],
        b"\x48\x8d\x15": [],
        b"\x4c\x8d\x05": [],
    }
    for opcode in instructions:
        start = 0
        while True:
            found = data.find(opcode, start)
            if found < 0:
                break
            if found + 7 <= len(data):
                instructions[opcode].append(found)
            start = found + 1
    sites: list[dict[str, Any]] = []
    for rcx in instructions[b"\x48\x8d\x0d"]:
        for rdx in instructions[b"\x48\x8d\x15"]:
            if abs(rcx - rdx) > 64:
                continue
            for r8 in instructions[b"\x4c\x8d\x05"]:
                if max(rcx, rdx, r8) - min(rcx, rdx, r8) > 96:
                    continue
                targets = []
                for offset in (rcx, rdx, r8):
                    displacement = struct.unpack_from("<i", data, offset + 3)[0]
                    targets.append(chunk_address + offset + 7 + displacement)
                if not all(
                    _module_contains(module_base, module_size, target, 1)
                    for target in targets
                ):
                    continue
                site_offset = min(rcx, rdx, r8)
                sites.append(
                    {
                        "address": chunk_address + site_offset,
                        "address_hex": _hex(chunk_address + site_offset),
                        "instruction_encoding": "amd64-rip-relative-lea",
                        "code_registration_address": targets[0],
                        "code_registration_address_hex": _hex(targets[0]),
                        "metadata_registration_address": targets[1],
                        "metadata_registration_address_hex": _hex(targets[1]),
                        "codegen_options_address": targets[2],
                        "codegen_options_address_hex": _hex(targets[2]),
                    }
                )
    return sites


def _x86_registration_sites(
    data: bytes, chunk_address: int, module_base: int, module_size: int
) -> list[dict[str, Any]]:
    pushes: list[tuple[int, int]] = []
    for offset in range(0, max(0, len(data) - 4)):
        if data[offset] == 0x68:
            pushes.append((offset, struct.unpack_from("<I", data, offset + 1)[0]))
    sites: list[dict[str, Any]] = []
    for index in range(len(pushes) - 2):
        first, second, third = pushes[index : index + 3]
        if third[0] - first[0] > 32:
            continue
        options, metadata, code = first[1], second[1], third[1]
        if not all(
            _module_contains(module_base, module_size, target, 1)
            for target in (code, metadata, options)
        ):
            continue
        sites.append(
            {
                "address": chunk_address + first[0],
                "address_hex": _hex(chunk_address + first[0]),
                "instruction_encoding": "i386-push-immediate",
                "code_registration_address": code,
                "code_registration_address_hex": _hex(code),
                "metadata_registration_address": metadata,
                "metadata_registration_address_hex": _hex(metadata),
                "codegen_options_address": options,
                "codegen_options_address_hex": _hex(options),
            }
        )
    return sites


def _parse_il2cpp_code_registration(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    budget: _ReadBudget,
    address: int,
) -> tuple[Optional[dict[str, Any]], list[dict[str, Any]]]:
    base = int(module["base_address"])
    size = int(module["size"])
    pointer_size = int(pe["pointer_size"])
    stride = pointer_size * 2
    maximum_fields = max(len(fields) for _, fields in _IL2CPP_CODE_REGISTRATION_PROFILES)
    data = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        size,
        address,
        maximum_fields * stride,
        budget,
        purpose="il2cpp_code_registration",
    )
    if len(data) < min(len(fields) for _, fields in _IL2CPP_CODE_REGISTRATION_PROFILES) * stride:
        return None, [
            {
                "operation": "il2cpp_code_registration",
                "message": "candidate structure is truncated",
                "address": address,
            }
        ]
    valid_profiles: list[dict[str, Any]] = []
    rejected: list[str] = []
    for layout, names in _IL2CPP_CODE_REGISTRATION_PROFILES:
        if len(data) < len(names) * stride:
            continue
        fields = _decode_count_pointer_pairs(data, names, pointer_size)
        field_error = _validate_registration_fields(
            fields, base, size, pointer_size
        )
        codegen = fields[-1]
        codegen_count = int(codegen["count"])
        if codegen_count <= 0 or codegen_count > _MAX_IL2CPP_CODEGEN_MODULES:
            field_error = field_error or "codegen_modules count is outside its bounded range"
        elif codegen_count * pointer_size > _MAX_IL2CPP_CODEGEN_MODULE_BYTES:
            field_error = field_error or "codegen_modules table exceeds its byte limit"
        if field_error:
            rejected.append(f"{layout}: {field_error}")
            continue
        modules, module_errors = _parse_runtime_codegen_modules(
            backend,
            pid,
            module,
            module_key,
            pe,
            budget,
            codegen_count,
            int(codegen["pointer"]),
        )
        if not modules:
            rejected.append(
                f"{layout}: codegen_modules did not resolve a validated module descriptor"
            )
            rejected.extend(f"{layout}: {message}" for message in module_errors[:3])
            continue
        valid_profiles.append(
            {
                "status": "validated",
                "layout": layout,
                "address": address,
                "address_hex": _hex(address),
                "rva": address - base,
                "rva_hex": _hex(address - base),
                "field_count": len(fields),
                "fields": fields,
                "codegen_modules_count": codegen_count,
                "codegen_modules_pointer": codegen["pointer"],
                "codegen_modules": modules,
                "codegen_modules_inspected": min(
                    codegen_count, _MAX_IL2CPP_CODEGEN_MODULE_NAMES
                ),
                "codegen_modules_truncated": (
                    codegen_count > _MAX_IL2CPP_CODEGEN_MODULE_NAMES
                ),
            }
        )
    if not valid_profiles:
        return None, [
            {
                "operation": "il2cpp_code_registration",
                "message": "; ".join(rejected[:8]) or "no known layout validated",
                "address": address,
            }
        ]
    valid_profiles.sort(
        key=lambda item: (
            len(item.get("codegen_modules") or []),
            int(item.get("field_count") or 0),
        ),
        reverse=True,
    )
    return valid_profiles[0], []


def _parse_il2cpp_metadata_registration(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    budget: _ReadBudget,
    address: int,
    pointer_size: int,
) -> tuple[Optional[dict[str, Any]], list[dict[str, Any]]]:
    base = int(module["base_address"])
    size = int(module["size"])
    stride = pointer_size * 2
    data = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        size,
        address,
        len(_IL2CPP_METADATA_REGISTRATION_FIELDS) * stride,
        budget,
        purpose="il2cpp_metadata_registration",
    )
    if len(data) != len(_IL2CPP_METADATA_REGISTRATION_FIELDS) * stride:
        return None, [
            {
                "operation": "il2cpp_metadata_registration",
                "message": "candidate structure is truncated",
                "address": address,
            }
        ]
    names = tuple(name for name, _ in _IL2CPP_METADATA_REGISTRATION_FIELDS)
    fields = _decode_count_pointer_pairs(data, names, pointer_size)
    element_sizes = {
        name: (minimum or pointer_size)
        for name, minimum in _IL2CPP_METADATA_REGISTRATION_FIELDS
    }
    error = _validate_registration_fields(
        fields, base, size, pointer_size, element_sizes=element_sizes
    )
    populated = sum(int(item["count"]) > 0 for item in fields)
    if populated < 2:
        error = error or "fewer than two metadata tables are populated"
    if error:
        return None, [
            {
                "operation": "il2cpp_metadata_registration",
                "message": error,
                "address": address,
            }
        ]
    return (
        {
            "status": "validated",
            "layout": "Il2CppMetadataRegistration-8-pairs",
            "address": address,
            "address_hex": _hex(address),
            "rva": address - base,
            "rva_hex": _hex(address - base),
            "field_count": len(fields),
            "populated_field_count": populated,
            "fields": fields,
        },
        [],
    )


def _decode_count_pointer_pairs(
    data: bytes, names: Sequence[str], pointer_size: int
) -> list[dict[str, Any]]:
    stride = pointer_size * 2
    fields: list[dict[str, Any]] = []
    for index, name in enumerate(names):
        offset = index * stride
        if pointer_size == 8:
            count = struct.unpack_from("<I", data, offset)[0]
            pointer = struct.unpack_from("<Q", data, offset + 8)[0]
        else:
            count, pointer = struct.unpack_from("<II", data, offset)
        fields.append(
            {
                "name": name,
                "count": count,
                "pointer": pointer,
                "pointer_hex": _hex(pointer),
                "offset": offset,
            }
        )
    return fields


def _validate_registration_fields(
    fields: Sequence[Mapping[str, Any]],
    module_base: int,
    module_size: int,
    pointer_size: int,
    *,
    element_sizes: Optional[Mapping[str, int]] = None,
) -> Optional[str]:
    sizes = dict(element_sizes or {})
    for field in fields:
        name = str(field.get("name") or "field")
        count = int(field.get("count") or 0)
        pointer = int(field.get("pointer") or 0)
        if count < 0 or count > _MAX_IL2CPP_REGISTRATION_COUNT:
            return f"{name} count {count} is outside its bounded range"
        if count == 0:
            if pointer and not _module_contains(module_base, module_size, pointer, 1):
                return f"{name} has an out-of-module pointer for an empty table"
            continue
        element_size = max(1, int(sizes.get(name, pointer_size)))
        span = count * element_size
        if not _module_contains(module_base, module_size, pointer, span):
            return f"{name} pointer/span is outside the loaded module"
    return None


def _parse_runtime_codegen_modules(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    budget: _ReadBudget,
    count: int,
    table_address: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    base = int(module["base_address"])
    size = int(module["size"])
    pointer_size = int(pe["pointer_size"])
    table_size = count * pointer_size
    if not _module_contains(base, size, table_address, table_size):
        return [], ["codegen module pointer table is outside the loaded module"]
    inspect_count = min(count, _MAX_IL2CPP_CODEGEN_MODULE_NAMES)
    table = _read_module_exact(
        backend,
        pid,
        module_key,
        base,
        size,
        table_address,
        inspect_count * pointer_size,
        budget,
        purpose="il2cpp_codegen_module_table",
    )
    if len(table) != inspect_count * pointer_size:
        return [], ["codegen module pointer table is truncated"]
    pointer_format = "<Q" if pointer_size == 8 else "<I"
    descriptor_size = 24 if pointer_size == 8 else 12
    modules: list[dict[str, Any]] = []
    errors: list[str] = []
    seen_names: set[str] = set()
    for index in range(inspect_count):
        descriptor_address = struct.unpack_from(
            pointer_format, table, index * pointer_size
        )[0]
        if not _module_contains(base, size, descriptor_address, descriptor_size):
            errors.append(f"codegen module {index} descriptor is outside the module")
            continue
        descriptor = _read_module_exact(
            backend,
            pid,
            module_key,
            base,
            size,
            descriptor_address,
            descriptor_size,
            budget,
            purpose="il2cpp_codegen_module_descriptor",
        )
        if len(descriptor) != descriptor_size:
            errors.append(f"codegen module {index} descriptor is truncated")
            continue
        if pointer_size == 8:
            name_address = struct.unpack_from("<Q", descriptor, 0)[0]
            method_count = struct.unpack_from("<I", descriptor, 8)[0]
            method_table = struct.unpack_from("<Q", descriptor, 16)[0]
        else:
            name_address, method_count, method_table = struct.unpack_from(
                "<III", descriptor, 0
            )
        name = _read_runtime_cstring(
            backend,
            pid,
            module_key,
            base,
            size,
            name_address,
            budget,
            purpose="il2cpp_codegen_module_name",
        )
        if not name or not name.lower().endswith(".dll"):
            errors.append(f"codegen module {index} has no validated DLL name")
            continue
        if method_count > _MAX_IL2CPP_REGISTRATION_COUNT:
            errors.append(f"codegen module {name} has an implausible method count")
            continue
        if method_count and not _module_contains(
            base, size, method_table, method_count * pointer_size
        ):
            errors.append(f"codegen module {name} method table is outside the module")
            continue
        executable_pointers = 0
        method_token_mappings: list[dict[str, Any]] = []
        mapping_count = min(method_count, _MAX_IL2CPP_METHOD_TOKEN_MAPPINGS)
        if method_count:
            pointer_data = _read_module_exact(
                backend,
                pid,
                module_key,
                base,
                size,
                method_table,
                mapping_count * pointer_size,
                budget,
                purpose="il2cpp_method_pointer_mapping",
            )
            if len(pointer_data) != mapping_count * pointer_size:
                errors.append(f"codegen module {name} method table is truncated")
                continue
            # Validate every pointer in the same bounded prefix emitted below.
            for pointer_index in range(mapping_count):
                target = struct.unpack_from(
                    pointer_format, pointer_data, pointer_index * pointer_size
                )[0]
                location = _remote_pe_location(pe, module, target) if target else None
                if target and (location is None or not location.get("executable")):
                    errors.append(
                        f"codegen module {name} has a non-executable sampled method pointer"
                    )
                    executable_pointers = -1
                    break
                if target:
                    executable_pointers += 1
            if executable_pointers < 0:
                continue
            for pointer_index in range(mapping_count):
                target = struct.unpack_from(
                    pointer_format, pointer_data, pointer_index * pointer_size
                )[0]
                location = _remote_pe_location(pe, module, target) if target else None
                if not target or location is None or not location.get("executable"):
                    continue
                rva = int(location["rva"])
                method_token_mappings.append(
                    {
                        "token": f"0x{0x06000000 | (pointer_index + 1):08x}",
                        "pointer_index": pointer_index,
                        "address": target,
                        "address_hex": _hex(target),
                        "rva": rva,
                        "rva_hex": _hex(rva),
                        "section": location.get("section"),
                    }
                )
        normalized_name = name.lower()
        if normalized_name in seen_names:
            errors.append(f"duplicate codegen module name {name}")
            continue
        seen_names.add(normalized_name)
        modules.append(
            {
                "name": name,
                "address": descriptor_address,
                "address_hex": _hex(descriptor_address),
                "rva": descriptor_address - base,
                "rva_hex": _hex(descriptor_address - base),
                "name_address": name_address,
                "name_address_hex": _hex(name_address),
                "method_pointer_count": method_count,
                "method_pointer_table": method_table,
                "method_pointer_table_hex": _hex(method_table),
                "sampled_executable_pointer_count": max(0, executable_pointers),
                "method_token_mapping_count": len(method_token_mappings),
                "method_token_mappings": method_token_mappings,
                "method_token_mappings_inspected": mapping_count,
                "method_token_mappings_truncated": method_count > mapping_count,
            }
        )
    return modules, errors


def _discover_unreal_globals(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    exports: Sequence[Mapping[str, Any]],
    budget: _ReadBudget,
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    base = int(module.get("base_address") or 0)
    pointer_size = int(pe.get("pointer_size") or 0)
    started_requested = budget.requested_bytes
    started_returned = budget.returned_bytes
    started_errors = len(budget.errors)
    classification = _unreal_module_classification(
        module,
        unreal_context=True,
    )
    pe_identity = _unreal_pe_identity_proof(module, pe)
    candidates: list[dict[str, Any]] = []
    callable_exports: list[dict[str, Any]] = []
    symbols: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for exported in exports:
        if not isinstance(exported, Mapping):
            continue
        export_name = str(exported.get("symbol") or "")
        role = _UNREAL_GLOBAL_EXPORT_ROLES.get(export_name.lower())
        callable_role = _UNREAL_CALLABLE_EXPORT_ROLES.get(export_name.lower())
        address = _coerce_int(exported.get("address"))
        if address is None or (role is None and callable_role is None):
            continue
        if callable_role is not None:
            callable_candidate = _validate_unreal_callable_export(
                module,
                pe,
                exported,
                callable_role,
            )
            callable_exports.append(callable_candidate)
            if callable_candidate.get("status") != "validated":
                errors.append(
                    {
                        "operation": f"unreal_{callable_role}",
                        "message": callable_candidate.get("reason")
                        or "callable export failed validation",
                        "address": address,
                    }
                )
            else:
                callable_attributes = {
                    "address_kind": "unreal_callable_export_va",
                    "section": callable_candidate.get("section"),
                    "executable": True,
                    "runtime_object_address": "unresolved",
                    "runtime_object_address_reason": (
                        "the PE export VA identifies executable code, not a returned "
                        "UObject, UClass, or UFunction instance"
                    ),
                }
                symbols.append(
                    _runtime_symbol(
                        module,
                        role=callable_role,
                        display_name=export_name,
                        address=address,
                        confidence=0.99,
                        name_kind="pe_export",
                        source="pe_export_and_executable_section",
                        attributes=callable_attributes,
                    )
                )
                evidence.append(
                    _evidence_item(
                        engine="unreal",
                        kind="unreal_callable_export",
                        marker=export_name,
                        symbol=export_name,
                        weight=5.0,
                        module=module,
                        address=address,
                        rva=address - base,
                        source="pe_export_and_executable_section",
                        details={
                            "role": callable_role,
                            "address_kind": "unreal_callable_export_va",
                            "validation": callable_candidate,
                            "runtime_object_address": {"status": "unresolved"},
                        },
                    )
                )
            if role is None:
                continue
        location = _remote_pe_location(pe, module, address)
        export_details = exported.get("details") or {}
        runtime_proof = _runtime_va_proof(
            base,
            _coerce_int(exported.get("rva")),
            address,
        )
        validation: dict[str, Any]
        if not runtime_proof.get("verified"):
            validation = {
                "status": "rejected",
                "reason": "module base + export RVA does not prove the global VA",
            }
        elif bool(export_details.get("forwarded")):
            validation = {
                "status": "rejected",
                "reason": "forwarded exports cannot identify loaded global storage",
            }
        elif location is None or location.get("executable") or not location.get("readable"):
            validation = {
                "status": "rejected",
                "reason": "export does not resolve to readable non-executable module data",
            }
        elif pointer_size not in {4, 8}:
            validation = {"status": "rejected", "reason": "pointer size is unavailable"}
        elif role == "gworld":
            validation = _validate_unreal_gworld(
                backend, pid, module_key, address, pointer_size, budget
            )
        elif role == "gnames":
            validation = _validate_unreal_gnames(
                backend, pid, module, module_key, address, pointer_size, budget
            )
        else:
            validation = _validate_unreal_gobjects(
                backend, pid, module, module_key, address, pointer_size, budget
            )
        candidate = {
            "status": validation.get("status"),
            "role": role,
            "symbol": export_name,
            "address": address,
            "address_hex": _hex(address),
            "rva": address - base,
            "rva_hex": _hex(address - base),
            "address_kind": "pe_export_data_va",
            "source": "pe_export",
            "section": (location or {}).get("section"),
            "runtime_va_proof": runtime_proof,
            "validation": validation,
        }
        candidates.append(candidate)
        if validation.get("status") != "validated":
            errors.append(
                {
                    "operation": f"unreal_{role}",
                    "message": validation.get("reason") or "candidate failed validation",
                    "address": address,
                }
            )
            continue
        symbols.append(
            _runtime_symbol(
                module,
                role=role,
                display_name=export_name,
                address=address,
                confidence=0.98,
                name_kind="pe_export",
                source="pe_export_and_runtime_structure",
                attributes={
                    "address_kind": "unreal_global_storage_va",
                    "global_storage_address": {
                        "status": "validated",
                        "address": address,
                        "address_hex": _hex(address),
                    },
                    **validation,
                },
            )
        )
        evidence.append(
            _evidence_item(
                engine="unreal",
                kind="runtime_global_candidate",
                marker=export_name,
                symbol=export_name,
                weight=5.0,
                module=module,
                address=address,
                rva=address - base,
                source="pe_export_and_runtime_structure",
                details={
                    "role": role,
                    "address_kind": "unreal_global_storage_va",
                    "validation": validation,
                    "runtime_object_address": (
                        validation.get("world_object_address")
                        or {"status": "unresolved"}
                    ),
                },
            )
        )

    reflection_scan = _scan_unreal_reflection_evidence(
        backend,
        pid,
        module,
        module_key,
        pe,
        parameters,
        budget,
    )
    normalized_clues = [
        dict(item)
        for item in reflection_scan.get("clues") or []
        if isinstance(item, Mapping)
    ]
    for clue in normalized_clues:
        address = _coerce_int(clue.get("address"))
        rva = _coerce_int(clue.get("rva"))
        if address is None or rva is None:
            continue
        evidence.append(
            _evidence_item(
                engine="unreal",
                kind=str(clue.get("evidence_kind") or "unreal_name_evidence"),
                marker=str(clue.get("marker") or ""),
                weight=float(clue.get("weight") or 1.0),
                module=module,
                address=address,
                rva=rva,
                source="readable_pe_section_string_storage",
                details={
                    "normalized_kind": clue.get("normalized_kind"),
                    "encoding": clue.get("encoding"),
                    "byte_length": clue.get("byte_length"),
                    "section_proof": clue.get("section_proof"),
                    "address_kind": "string_storage",
                    "string_storage": clue.get("string_storage"),
                    "object_address": clue.get("object_address"),
                    "name_pool_address": clue.get("name_pool_address"),
                },
            )
        )
    errors.extend(
        item
        for item in reflection_scan.get("errors") or []
        if isinstance(item, Mapping)
    )
    validated = [item for item in candidates if item.get("status") == "validated"]
    validated_callables = [
        item for item in callable_exports if item.get("status") == "validated"
    ]
    status = _unreal_component_status(
        pe_identity=pe_identity,
        reflection_scan=reflection_scan,
        normalized_clues=normalized_clues,
        global_candidates=candidates,
        validated_globals=validated,
        callable_exports=callable_exports,
        validated_callables=validated_callables,
    )
    address_resolution = _unreal_address_resolution(
        normalized_clues,
        validated,
    )
    dependency_status = _unreal_dependency_status(
        validated,
        normalized_clues,
        pe_identity=pe_identity,
        reflection_scan=reflection_scan,
    )
    ambiguities = _unreal_ambiguities(
        normalized_clues,
        validated,
        callable_exports,
    )
    semantic_fragment = _unreal_semantic_fragment(
        status,
        symbols,
        normalized_clues,
        module,
        dependency_status=dependency_status,
        address_resolution=address_resolution,
        ambiguities=ambiguities,
    )
    component_errors = [
        *errors,
        *(
            _json_mapping(item)
            for item in budget.errors[started_errors:]
            if isinstance(item, Mapping)
            and item not in (reflection_scan.get("errors") or [])
        ),
    ]
    read_budget = {
        "scope": "unreal_runtime_component",
        "limits": {
            "max_total_read_bytes": budget.total_limit,
            "max_module_read_bytes": budget.module_limit,
            "max_single_read_bytes": budget.single_limit,
            "max_reflection_scan_bytes": _MAX_UNREAL_REFLECTION_SCAN_BYTES,
            "max_reflection_clues": _MAX_UNREAL_REFLECTION_CLUES,
        },
        "requested_bytes": budget.requested_bytes - started_requested,
        "returned_bytes": budget.returned_bytes - started_returned,
        "module_requested_bytes_total": budget.module_requested.get(module_key, 0),
        "module_returned_bytes_total": budget.module_returned.get(module_key, 0),
        "remaining_total_bytes": budget.remaining_total(),
        "remaining_module_bytes": budget.remaining_module(module_key),
        "truncated": bool(
            reflection_scan.get("truncated")
            or reflection_scan.get("status") in {"partial", "truncated"}
        ),
        "reflection_scan": {
            "eligible_bytes": reflection_scan.get("eligible_bytes", 0),
            "requested_bytes": reflection_scan.get("requested_bytes", 0),
            "returned_bytes": reflection_scan.get("returned_bytes", 0),
            "coverage_complete": reflection_scan.get("coverage_complete", False),
        },
    }
    return _prune(
        {
            "engine": "unreal",
            "status": status,
            "attempted": True,
            "discovery": "loaded-pe-identity-exports-and-readable-section-evidence",
            "loaded_module": {
                "name": module.get("name"),
                "path": module.get("path"),
                "identity_sha256": module.get("identity_sha256"),
                "base_address": base,
                "base_address_hex": _hex(base),
                "size": module.get("size"),
                "end_address": module.get("end_address"),
                "classification": classification,
            },
            "pe_identity": pe_identity,
            "reason": (
                "no structurally validated Unreal globals, callable exports, or "
                "readable-section reflection/name clues were collected"
                if status == "unavailable"
                else None
            ),
            "candidate_count": len(candidates),
            "validated_candidate_count": len(validated),
            "candidates": candidates,
            "callable_exports": callable_exports,
            "validated_callable_count": len(validated_callables),
            "reflection_evidence": normalized_clues,
            "normalized_clues": normalized_clues,
            "reflection_scan": reflection_scan,
            "address_resolution": address_resolution,
            "ambiguities": ambiguities,
            "dependency_status": dependency_status,
            "read_budget": read_budget,
            "symbols": symbols,
            "evidence": evidence,
            "semantic_ir_fragment": semantic_fragment,
            "provenance": {
                "sources": [
                    "module_enumeration",
                    "remote_pe_headers",
                    "pe_export_table",
                    "ReadProcessMemory",
                ],
                "read_only": True,
                "remote_api_calls": False,
                "module_identity_sha256": module.get("identity_sha256"),
                "module_identity_scope": "name/path/base/size inventory identity",
                "module_content_hash": "not_collected",
                "address_semantics": {
                    "string_hits": "string_storage_only",
                    "runtime_globals": "validated_export_storage_and_structure_only",
                    "runtime_objects": "unresolved_without_versioned_layout_proof",
                },
            },
            "errors": component_errors,
        }
    )


def _unreal_pe_identity_proof(
    module: Mapping[str, Any],
    pe: Mapping[str, Any],
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    end = _coerce_int(module.get("end_address"))
    actual_identity = str(module.get("identity_sha256") or "")
    expected_identity = _canonical_hash(
        {
            "name": str(module.get("name") or "").lower(),
            "path": str(module.get("path") or "").lower(),
            "base_address": base,
            "size": size,
        }
    )
    machine = _coerce_int(pe.get("machine"))
    architecture = str(pe.get("architecture") or "")
    pointer_size = _coerce_int(pe.get("pointer_size"))
    expected_machine = {
        0x14C: ("i386", 4),
        0x8664: ("amd64", 8),
    }.get(machine)
    architecture_matches = bool(
        expected_machine
        and expected_machine == (architecture, pointer_size)
    )
    image_size = _coerce_int(pe.get("size_of_image"))
    enumerated_range_valid = bool(
        base is not None
        and base >= 0
        and size is not None
        and size > 0
        and end == base + size
    )
    size_matches = bool(size and image_size and image_size == size)
    section_proofs: list[dict[str, Any]] = []
    for section in pe.get("sections") or []:
        if not isinstance(section, Mapping):
            continue
        rva = _coerce_int(section.get("rva"))
        mapped_size = _coerce_int(section.get("mapped_size"))
        address = _coerce_int(section.get("address"))
        range_valid = bool(
            section.get("range_valid")
            and base is not None
            and size is not None
            and rva is not None
            and mapped_size is not None
            and address == base + rva
            and _module_contains(base, size, address, mapped_size)
        )
        section_proofs.append(
            {
                "name": section.get("name"),
                "rva": rva,
                "address": address,
                "mapped_size": mapped_size,
                "range_valid": range_valid,
                "readable": bool(section.get("readable")),
                "writable": bool(section.get("writable")),
                "executable": bool(section.get("executable")),
            }
        )
    identity_matches = bool(actual_identity and actual_identity == expected_identity)
    verified = bool(
        pe.get("status") == "ok"
        and identity_matches
        and enumerated_range_valid
        and architecture_matches
        and size_matches
    )
    return {
        "status": "verified" if verified else "partial",
        "verified": verified,
        "module_identity": {
            "algorithm": "sha256",
            "value": actual_identity or None,
            "expected_value": expected_identity,
            "verified": identity_matches,
            "scope": "normalized enumerated name/path/base/size",
            "content_hash_status": "not_collected",
            "content_hash_reason": (
                "the inventory identity is not a hash of disk or loaded image bytes"
            ),
        },
        "pe_header": {
            "status": pe.get("status"),
            "kind": pe.get("kind"),
            "machine": machine,
            "machine_hex": _hex(machine),
            "architecture": architecture or None,
            "pointer_size": pointer_size,
            "machine_architecture_verified": architecture_matches,
        },
        "image_range": {
            "base_address": base,
            "base_address_hex": _hex(base),
            "enumerated_size": size,
            "pe_size_of_image": image_size,
            "size_matches": size_matches,
            "end_address": end,
            "end_address_hex": _hex(end),
            "range_equation": (
                f"{_hex(base)} + {_hex(size)} = {_hex(end)}"
                if base is not None and size is not None and end is not None
                else None
            ),
            "verified": enumerated_range_valid and size_matches,
        },
        "sections": section_proofs,
        "section_count": len(section_proofs),
        "valid_section_count": sum(
            bool(item.get("range_valid")) for item in section_proofs
        ),
        "readable_section_count": sum(
            bool(item.get("range_valid") and item.get("readable"))
            for item in section_proofs
        ),
    }


def _validate_unreal_callable_export(
    module: Mapping[str, Any],
    pe: Mapping[str, Any],
    exported: Mapping[str, Any],
    role: str,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    address = _coerce_int(exported.get("address"))
    rva = _coerce_int(exported.get("rva"))
    location = _remote_pe_location(pe, module, address or -1)
    proof = _runtime_va_proof(base, rva, address)
    reasons: list[str] = []
    if not proof.get("verified"):
        reasons.append("module base + export RVA does not prove the callable VA")
    if bool((exported.get("details") or {}).get("forwarded")):
        reasons.append("forwarded export does not identify executable code in this module")
    if location is None:
        reasons.append("export VA is outside validated loaded PE sections")
    elif not location.get("executable"):
        reasons.append("export VA is not in an executable PE section")
    return _prune(
        {
            "status": "rejected" if reasons else "validated",
            "role": role,
            "symbol": exported.get("symbol"),
            "address": address,
            "address_hex": _hex(address),
            "rva": rva,
            "rva_hex": _hex(rva),
            "address_kind": "unreal_callable_export_va",
            "section": (location or {}).get("section"),
            "executable": bool((location or {}).get("executable")),
            "runtime_va_proof": proof,
            "reason": "; ".join(reasons),
            "runtime_object_address": {
                "status": "unresolved",
                "reason": "an executable function VA is not a live Unreal object address",
            },
        }
    )


def _scan_unreal_reflection_evidence(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    pe: Mapping[str, Any],
    parameters: Mapping[str, Any],
    budget: _ReadBudget,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    if base is None or size is None or size <= 0:
        return {
            "status": "unavailable",
            "reason": "validated loaded module range is unavailable",
            "clues": [],
            "errors": [],
        }
    sections = [
        dict(item)
        for item in pe.get("sections") or []
        if isinstance(item, Mapping)
        and item.get("range_valid")
        and item.get("readable")
        and (_coerce_int(item.get("mapped_size")) or 0) > 0
    ]
    sections.sort(
        key=lambda item: (
            bool(item.get("executable")),
            int(item.get("rva") or 0),
        )
    )
    if not sections:
        return {
            "status": "unavailable",
            "reason": "no readable, range-validated loaded PE section is available",
            "eligible_section_count": 0,
            "eligible_bytes": 0,
            "clues": [],
            "errors": [],
            "coverage_complete": False,
            "truncated": False,
        }

    patterns: list[dict[str, Any]] = []
    for marker, normalized_kind, evidence_kind, weight in _UNREAL_REFLECTION_MARKERS:
        patterns.append(
            {
                "marker": marker,
                "normalized_kind": normalized_kind,
                "evidence_kind": evidence_kind,
                "weight": weight,
                "encoding": "ascii",
                "bytes": marker.encode("ascii"),
            }
        )
        if parameters.get("include_utf16", True):
            patterns.append(
                {
                    "marker": marker,
                    "normalized_kind": normalized_kind,
                    "evidence_kind": evidence_kind,
                    "weight": weight,
                    "encoding": "utf-16-le",
                    "bytes": marker.encode("utf-16-le"),
                }
            )
    max_pattern_bytes = max(len(item["bytes"]) for item in patterns)
    eligible_bytes = sum(int(item.get("mapped_size") or 0) for item in sections)
    available = min(
        budget.remaining_total(),
        budget.remaining_module(module_key),
        _MAX_UNREAL_REFLECTION_SCAN_BYTES,
    )
    if available <= 0:
        budget.truncated = True
        return {
            "status": "truncated",
            "reason": "read budget was exhausted before Unreal section scanning",
            "eligible_section_count": len(sections),
            "eligible_bytes": eligible_bytes,
            "requested_bytes": 0,
            "returned_bytes": 0,
            "clues": [],
            "errors": [],
            "coverage_complete": False,
            "truncated": True,
        }

    started_requested = budget.requested_bytes
    started_returned = budget.returned_bytes
    started_errors = len(budget.errors)
    scan_remaining = available
    ranges: list[dict[str, Any]] = []
    clues: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    partial_read = False
    clue_truncated = False
    for section in sections:
        if scan_remaining <= 0:
            break
        section_rva = int(section.get("rva") or 0)
        section_size = int(section.get("mapped_size") or 0)
        section_address = base + section_rva
        section_limit = min(section_size, scan_remaining)
        cursor = 0
        tail = b""
        requested_in_section = 0
        returned_in_section = 0
        while cursor < section_limit:
            wanted = min(
                section_limit - cursor,
                budget.single_limit,
                budget.remaining_total(),
                budget.remaining_module(module_key),
            )
            if wanted <= 0:
                budget.truncated = True
                partial_read = True
                break
            data = budget.read(
                backend,
                pid,
                module_key,
                section_address + cursor,
                wanted,
                purpose="unreal_readable_section_scan",
            )
            requested_in_section += wanted
            if not data:
                partial_read = True
                tail = b""
                break
            returned_in_section += len(data)
            combined = tail + data
            combined_address = section_address + cursor - len(tail)
            for pattern in patterns:
                pattern_bytes = pattern["bytes"]
                start = 0
                while True:
                    offset = combined.find(pattern_bytes, start)
                    if offset < 0:
                        break
                    address = combined_address + offset
                    key = (pattern["marker"], pattern["encoding"], address)
                    if key not in seen:
                        if len(clues) >= _MAX_UNREAL_REFLECTION_CLUES:
                            clue_truncated = True
                            break
                        seen.add(key)
                        rva = address - base
                        clue: dict[str, Any] = {
                            "id": "runtime:" + _canonical_hash(
                                [module.get("identity_sha256"), pattern["marker"], address]
                            )[:20],
                            "marker": pattern["marker"],
                            "normalized_kind": pattern["normalized_kind"],
                            "evidence_kind": pattern["evidence_kind"],
                            "weight": pattern["weight"],
                            "confidence": 0.65,
                            "encoding": pattern["encoding"],
                            "byte_length": len(pattern_bytes),
                            "address": address,
                            "address_hex": _hex(address),
                            "rva": rva,
                            "rva_hex": _hex(rva),
                            "address_kind": "string_storage",
                            "string_storage": {
                                "status": "validated",
                                "address": address,
                                "address_hex": _hex(address),
                                "rva": rva,
                                "rva_hex": _hex(rva),
                            },
                            "object_address": {
                                "status": "unresolved",
                                "reason": (
                                    "a reflection/name string does not prove a UObject, "
                                    "UClass, UFunction, or widget instance address"
                                ),
                            },
                            "section_proof": {
                                "name": section.get("name"),
                                "readable": True,
                                "executable": bool(section.get("executable")),
                                "range_valid": True,
                            },
                            "provenance": {
                                "source": "ReadProcessMemory",
                                "module_identity_sha256": module.get("identity_sha256"),
                                "address_semantics": "string_storage_only",
                            },
                        }
                        if pattern["normalized_kind"] in {
                            "name",
                            "name_pool",
                            "name_global",
                        }:
                            clue["name_pool_address"] = {
                                "status": "dependency-gated",
                                "reason": (
                                    "string evidence alone cannot resolve a live FNamePool"
                                ),
                            }
                        clues.append(clue)
                    start = offset + max(1, len(pattern_bytes))
                if clue_truncated:
                    break
            cursor += len(data)
            if max_pattern_bytes > 1:
                tail = combined[-(max_pattern_bytes - 1) :]
            if len(data) < wanted:
                partial_read = True
            if clue_truncated:
                break
        ranges.append(
            {
                "section": section.get("name"),
                "rva": section_rva,
                "rva_hex": _hex(section_rva),
                "address": section_address,
                "address_hex": _hex(section_address),
                "eligible_bytes": section_size,
                "planned_bytes": section_limit,
                "requested_bytes": requested_in_section,
                "returned_bytes": returned_in_section,
                "readable": True,
                "executable": bool(section.get("executable")),
                "range_valid": True,
            }
        )
        scan_remaining -= requested_in_section
        if clue_truncated:
            break
    requested_bytes = budget.requested_bytes - started_requested
    returned_bytes = budget.returned_bytes - started_returned
    coverage_complete = bool(
        requested_bytes >= eligible_bytes
        and returned_bytes >= eligible_bytes
        and not partial_read
        and not clue_truncated
    )
    truncated = bool(not coverage_complete)
    if truncated and (
        budget.remaining_total() <= 0 or budget.remaining_module(module_key) <= 0
    ):
        budget.truncated = True
    errors = [
        _json_mapping(item)
        for item in budget.errors[started_errors:]
        if isinstance(item, Mapping)
    ]
    status = "ok" if coverage_complete else "partial"
    return _prune(
        {
            "status": status,
            "eligible_section_count": len(sections),
            "eligible_bytes": eligible_bytes,
            "requested_bytes": requested_bytes,
            "returned_bytes": returned_bytes,
            "coverage_complete": coverage_complete,
            "sampled": not coverage_complete,
            "truncated": truncated,
            "hard_scan_limit_bytes": _MAX_UNREAL_REFLECTION_SCAN_BYTES,
            "max_clues": _MAX_UNREAL_REFLECTION_CLUES,
            "max_pattern_bytes": max_pattern_bytes,
            "ranges": ranges,
            "clue_count": len(clues),
            "clue_truncated": clue_truncated,
            "clues": clues,
            "errors": errors,
        }
    )


def _unreal_component_status(
    *,
    pe_identity: Mapping[str, Any],
    reflection_scan: Mapping[str, Any],
    normalized_clues: Sequence[Mapping[str, Any]],
    global_candidates: Sequence[Mapping[str, Any]],
    validated_globals: Sequence[Mapping[str, Any]],
    callable_exports: Sequence[Mapping[str, Any]],
    validated_callables: Sequence[Mapping[str, Any]],
) -> str:
    scan_status = str(reflection_scan.get("status") or "unavailable")
    has_runtime_evidence = bool(
        normalized_clues or validated_globals or validated_callables
    )
    if not has_runtime_evidence:
        return "partial" if scan_status in {"partial", "truncated"} else "unavailable"
    rejected = bool(
        len(validated_globals) < len(global_candidates)
        or len(validated_callables) < len(callable_exports)
    )
    if (
        not pe_identity.get("verified")
        or scan_status in {"partial", "truncated"}
        or rejected
        or (normalized_clues and not validated_globals)
    ):
        return "partial"
    return "ok"


def _unreal_address_resolution(
    clues: Sequence[Mapping[str, Any]],
    validated_globals: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    by_role: dict[str, list[Mapping[str, Any]]] = {}
    for item in validated_globals:
        by_role.setdefault(str(item.get("role") or ""), []).append(item)
    name_pools = [
        (item.get("validation") or {}).get("pool_address")
        for item in by_role.get("gnames", [])
        if (item.get("validation") or {}).get("pool_address") is not None
    ]
    object_arrays = [
        (item.get("validation") or {}).get("array_address")
        for item in by_role.get("gobjects", [])
        if (item.get("validation") or {}).get("array_address") is not None
    ]
    return {
        "string_storage": {
            "status": "validated" if clues else "unavailable",
            "count": len(clues),
            "address_kind": "string_storage",
        },
        "global_storage": {
            "status": "validated" if validated_globals else "unavailable",
            "count": len(validated_globals),
            "addresses": [
                item.get("address") for item in validated_globals
                if item.get("address") is not None
            ],
            "address_kind": "unreal_global_storage_va",
        },
        "name_pool": {
            "status": "validated" if name_pools else "dependency-gated",
            "addresses": name_pools,
            "reason": (
                None
                if name_pools
                else "no exported global plus bounded FNamePool structure was validated"
            ),
        },
        "object_array": {
            "status": "validated" if object_arrays else "dependency-gated",
            "addresses": object_arrays,
            "reason": (
                None
                if object_arrays
                else "no exported global plus bounded FUObjectArray header was validated"
            ),
        },
        "uobject_instances": {
            "status": "unresolved",
            "reason": "no versioned FUObjectItem/UObject layout traversal was performed",
        },
        "uclass_instances": {
            "status": "unresolved",
            "reason": "class-name evidence is not a UClass instance address",
        },
        "ufunction_instances": {
            "status": "unresolved",
            "reason": "function-name evidence is not a UFunction instance address",
        },
        "umg_instances": {
            "status": "unresolved",
            "reason": "UMG name evidence is not a widget instance address",
        },
        "world_object": {
            "status": "dependency-gated",
            "reason": "a readable GWorld pointer value does not prove the target UWorld type",
        },
    }


def _unreal_dependency_status(
    validated_globals: Sequence[Mapping[str, Any]],
    clues: Sequence[Mapping[str, Any]],
    *,
    pe_identity: Mapping[str, Any],
    reflection_scan: Mapping[str, Any],
) -> dict[str, Any]:
    roles = {str(item.get("role") or "") for item in validated_globals}
    scan_status = str(reflection_scan.get("status") or "unavailable")
    if scan_status == "ok":
        readable_scan = "available"
    elif scan_status in {"partial", "truncated"}:
        readable_scan = "partial"
    else:
        readable_scan = "unavailable"
    return {
        "status": "dependency-gated",
        "parser": "builtin_bounded_unreal_runtime_probes",
        "mode": "version-agnostic-loaded-image-evidence",
        "module_and_pe_identity": (
            "available" if pe_identity.get("verified") else "partial"
        ),
        "readable_section_name_scan": readable_scan,
        "readable_section_name_evidence": "available" if clues else "not_observed",
        "fname_pool_layout": "available" if "gnames" in roles else "dependency-gated",
        "fuobject_array_header": (
            "available" if "gobjects" in roles else "dependency-gated"
        ),
        "uobject_iteration": "dependency-gated",
        "reflection_object_resolution": "dependency-gated",
        "umg_instance_resolution": "dependency-gated",
        "required_for_resolution": [
            "matching Unreal build/version layout",
            "validated FUObjectItem and UObject field offsets",
            "validated FName entry decoding profile",
        ],
    }


def _unreal_ambiguities(
    clues: Sequence[Mapping[str, Any]],
    validated_globals: Sequence[Mapping[str, Any]],
    callable_exports: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    ambiguities: list[dict[str, Any]] = [
        {
            "kind": "unreal_version_layout",
            "status": "dependency-gated",
            "reason": "the loaded PE evidence does not identify one exact Unreal layout profile",
        }
    ]
    if clues:
        ambiguities.append(
            {
                "kind": "string_semantics",
                "status": "unresolved",
                "count": len(clues),
                "reason": (
                    "a marker may be reflection metadata, code text, or diagnostics; "
                    "it is not promoted to an object instance"
                ),
            }
        )
    role_counts: dict[str, int] = {}
    for item in validated_globals:
        role = str(item.get("role") or "")
        role_counts[role] = role_counts.get(role, 0) + 1
    for role, count in sorted(role_counts.items()):
        if count > 1:
            ambiguities.append(
                {
                    "kind": "multiple_global_candidates",
                    "status": "unresolved",
                    "role": role,
                    "count": count,
                }
            )
    if any(item.get("role") == "process_event" for item in callable_exports):
        ambiguities.append(
            {
                "kind": "process_event_owner",
                "status": "unresolved",
                "reason": "the exported function VA does not resolve owning UFunction objects",
            }
        )
    return ambiguities


def _unreal_semantic_fragment(
    status: str,
    symbols: Sequence[Mapping[str, Any]],
    clues: Sequence[Mapping[str, Any]],
    module: Mapping[str, Any],
    *,
    dependency_status: Mapping[str, Any],
    address_resolution: Mapping[str, Any],
    ambiguities: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    base_fragment = _runtime_semantic_fragment("unreal", status, symbols, module)
    entities = {
        str(item.get("id")): _json_mapping(item)
        for item in base_fragment.get("entities") or []
        if isinstance(item, Mapping) and item.get("id")
    }
    for clue in clues:
        clue_id = str(clue.get("id") or "")
        if not clue_id:
            continue
        entities[clue_id] = {
            "id": clue_id,
            "kind": "runtime_name_evidence",
            "name": clue.get("marker"),
            "confidence": clue.get("confidence"),
            "attributes": {
                "engine": "unreal",
                "normalized_kind": clue.get("normalized_kind"),
                "encoding": clue.get("encoding"),
                "address_kind": "string_storage",
                "string_storage_address": clue.get("address"),
                "string_storage_rva": clue.get("rva"),
                "section": (clue.get("section_proof") or {}).get("name"),
                "object_address_status": "unresolved",
                "module": module.get("name"),
            },
            "evidence": [
                {
                    "source": "readable_pe_section_string_storage",
                    "module_identity_sha256": module.get("identity_sha256"),
                }
            ],
        }
    entity_values = [entities[key] for key in sorted(entities)]
    validated_symbol_count = sum(
        item.get("kind") == "runtime_symbol" for item in entity_values
    )
    return {
        "status": status,
        "schema_version": 1,
        "engine": "unreal",
        "entities": entity_values,
        "relations": list(base_fragment.get("relations") or []),
        "dependency_status": _json_mapping(dependency_status),
        "address_resolution": _json_mapping(address_resolution),
        "ambiguities": [_json_mapping(item) for item in ambiguities],
        "summary": {
            "entity_count": len(entity_values),
            "relation_count": len(base_fragment.get("relations") or []),
            "validated_symbol_count": validated_symbol_count,
            "name_evidence_count": len(clues),
            "unresolved_object_address_count": len(clues),
        },
    }


def _validate_unreal_gworld(
    backend: Any,
    pid: int,
    module_key: str,
    address: int,
    pointer_size: int,
    budget: _ReadBudget,
) -> dict[str, Any]:
    pointer = _read_runtime_pointer(
        backend, pid, module_key, address, pointer_size, budget, "unreal_gworld"
    )
    if not _valid_user_pointer(pointer, pointer_size):
        return {"status": "rejected", "reason": "GWorld pointer is null or non-canonical"}
    probe = budget.read(
        backend, pid, module_key, pointer, pointer_size * 2, purpose="unreal_gworld_probe"
    )
    if len(probe) != pointer_size * 2:
        return {"status": "rejected", "reason": "GWorld target is not readable", "value": pointer}
    return {
        "status": "validated",
        "value": pointer,
        "value_hex": _hex(pointer),
        "validation": "global storage contains a canonical readable pointer",
        "global_storage_address": {
            "status": "validated",
            "address": address,
            "address_hex": _hex(address),
        },
        "pointer_readability": {
            "status": "validated",
            "probe_bytes": pointer_size * 2,
        },
        "world_object_address": {
            "status": "dependency-gated",
            "candidate_value": pointer,
            "candidate_value_hex": _hex(pointer),
            "reason": (
                "pointer readability does not prove the target uses the matching "
                "UWorld layout or type"
            ),
        },
    }


def _validate_unreal_gnames(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    address: int,
    pointer_size: int,
    budget: _ReadBudget,
) -> dict[str, Any]:
    bases = [address]
    indirect = _read_runtime_pointer(
        backend, pid, module_key, address, pointer_size, budget, "unreal_gnames_pointer"
    )
    if _valid_user_pointer(indirect, pointer_size):
        bases.append(indirect)
    for pool in bases:
        data = budget.read(
            backend, pid, module_key, pool, 16 + pointer_size, purpose="unreal_fname_pool"
        )
        if len(data) != 16 + pointer_size:
            continue
        current_block, cursor = struct.unpack_from("<II", data, 8)
        first_block = struct.unpack_from("<Q" if pointer_size == 8 else "<I", data, 16)[0]
        if current_block >= _MAX_UNREAL_CHUNKS or cursor >= 128 * 1024:
            continue
        if not _valid_user_pointer(first_block, pointer_size):
            continue
        probe = budget.read(
            backend, pid, module_key, first_block, 2, purpose="unreal_fname_block_probe"
        )
        if len(probe) != 2:
            continue
        return {
            "status": "validated",
            "pool_address": pool,
            "pool_address_hex": _hex(pool),
            "indirect": pool != address,
            "current_block": current_block,
            "current_byte_cursor": cursor,
            "first_block": first_block,
            "first_block_hex": _hex(first_block),
            "global_storage_address": {
                "status": "validated",
                "address": address,
                "address_hex": _hex(address),
            },
            "name_pool_address": {
                "status": "validated",
                "address": pool,
                "address_hex": _hex(pool),
            },
            "structure_proof": {
                "status": "validated",
                "layout": "bounded FNamePool header probe",
                "header_bytes": 16 + pointer_size,
                "first_block_probe_bytes": 2,
            },
            "name_entry_decoding": {
                "status": "dependency-gated",
                "reason": "no matching Unreal FName entry layout profile was selected",
            },
        }
    return {"status": "rejected", "reason": "no bounded readable FNamePool layout validated"}


def _validate_unreal_gobjects(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    address: int,
    pointer_size: int,
    budget: _ReadBudget,
) -> dict[str, Any]:
    del module
    bases = [address, address + 0x10]
    indirect = _read_runtime_pointer(
        backend, pid, module_key, address, pointer_size, budget, "unreal_gobjects_pointer"
    )
    if _valid_user_pointer(indirect, pointer_size):
        bases.extend((indirect, indirect + 0x10))
    header_size = pointer_size * 2 + 16
    pointer_format = "<Q" if pointer_size == 8 else "<I"
    for objects in bases:
        data = budget.read(
            backend, pid, module_key, objects, header_size, purpose="unreal_object_array"
        )
        if len(data) != header_size:
            continue
        chunks = struct.unpack_from(pointer_format, data, 0)[0]
        counts_offset = pointer_size * 2
        max_elements, num_elements, max_chunks, num_chunks = struct.unpack_from(
            "<IIII", data, counts_offset
        )
        if not (
            0 < num_elements <= max_elements <= _MAX_UNREAL_OBJECTS
            and 0 < num_chunks <= max_chunks <= _MAX_UNREAL_CHUNKS
            and num_chunks * 64 * 1024 >= num_elements
            and _valid_user_pointer(chunks, pointer_size)
        ):
            continue
        first_chunk = _read_runtime_pointer(
            backend, pid, module_key, chunks, pointer_size, budget, "unreal_object_chunk"
        )
        if not _valid_user_pointer(first_chunk, pointer_size):
            continue
        probe = budget.read(
            backend, pid, module_key, first_chunk, pointer_size, purpose="unreal_object_item_probe"
        )
        if len(probe) != pointer_size:
            continue
        return {
            "status": "validated",
            "array_address": objects,
            "array_address_hex": _hex(objects),
            "chunks": chunks,
            "chunks_hex": _hex(chunks),
            "first_chunk": first_chunk,
            "first_chunk_hex": _hex(first_chunk),
            "num_elements": num_elements,
            "max_elements": max_elements,
            "num_chunks": num_chunks,
            "max_chunks": max_chunks,
            "global_storage_address": {
                "status": "validated",
                "address": address,
                "address_hex": _hex(address),
            },
            "object_array_address": {
                "status": "validated",
                "address": objects,
                "address_hex": _hex(objects),
            },
            "structure_proof": {
                "status": "validated",
                "layout": "bounded FUObjectArray header probe",
                "header_bytes": header_size,
                "first_chunk_pointer": first_chunk,
                "first_item_probe_bytes": pointer_size,
            },
            "object_instances": {
                "status": "unresolved",
                "reason": "FUObjectItem and UObject layouts were not traversed",
            },
        }
    return {"status": "rejected", "reason": "no bounded FUObjectArray layout validated"}


def _read_runtime_pointer(
    backend: Any,
    pid: int,
    module_key: str,
    address: int,
    pointer_size: int,
    budget: _ReadBudget,
    purpose: str,
) -> int:
    data = budget.read(
        backend, pid, module_key, address, pointer_size, purpose=purpose
    )
    if len(data) != pointer_size:
        return 0
    return struct.unpack("<Q" if pointer_size == 8 else "<I", data)[0]


def _read_runtime_cstring(
    backend: Any,
    pid: int,
    module_key: str,
    module_base: int,
    module_size: int,
    address: int,
    budget: _ReadBudget,
    *,
    purpose: str,
) -> str:
    if not _module_contains(module_base, module_size, address, 1):
        return ""
    maximum = min(_MAX_RUNTIME_STRING_BYTES, module_base + module_size - address)
    data = bytearray()
    while len(data) < maximum:
        wanted = min(64, maximum - len(data), budget.single_limit)
        chunk = budget.read(
            backend,
            pid,
            module_key,
            address + len(data),
            wanted,
            purpose=purpose,
        )
        if not chunk:
            break
        terminator = chunk.find(b"\x00")
        data.extend(chunk if terminator < 0 else chunk[:terminator])
        if terminator >= 0 or len(chunk) < wanted:
            break
    try:
        value = bytes(data).decode("utf-8")
    except UnicodeDecodeError:
        return ""
    return value if value and all(char.isprintable() for char in value) else ""


def _remote_pe_location(
    pe: Mapping[str, Any], module: Mapping[str, Any], address: int
) -> Optional[dict[str, Any]]:
    base = int(module.get("base_address") or 0)
    size = int(module.get("size") or 0)
    if not _module_contains(base, size, address, 1):
        return None
    rva = address - base
    for section in pe.get("sections") or []:
        if not isinstance(section, Mapping) or not section.get("range_valid"):
            continue
        start = int(section.get("rva") or 0)
        span = int(section.get("mapped_size") or 0)
        if start <= rva < start + span:
            return {
                "section": section.get("name"),
                "rva": rva,
                "readable": bool(section.get("readable")),
                "writable": bool(section.get("writable")),
                "executable": bool(section.get("executable")),
            }
    return None


def _runtime_symbol(
    module: Mapping[str, Any],
    *,
    role: str,
    display_name: str,
    address: int,
    confidence: float,
    name_kind: str,
    source: str,
    identity_key: Any = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    base = int(module.get("base_address") or 0)
    identity = [module.get("identity_sha256"), role, address]
    if identity_key is not None:
        identity.append(identity_key)
    return _prune(
        {
            "id": "runtime:" + _canonical_hash(identity)[:20],
            "kind": "runtime_symbol",
            "role": role,
            "name": display_name,
            "name_kind": name_kind,
            "address": address,
            "address_hex": _hex(address),
            "rva": address - base,
            "rva_hex": _hex(address - base),
            "module": module.get("name"),
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": base,
            "module_base_hex": _hex(base),
            "runtime_va_proof": _runtime_va_proof(base, address - base, address),
            "confidence": confidence,
            "validated": True,
            "source": source,
            "attributes": _json_mapping(attributes),
        }
    )


def _runtime_semantic_fragment(
    engine: str,
    status: str,
    symbols: Sequence[Mapping[str, Any]],
    module: Mapping[str, Any],
) -> dict[str, Any]:
    entities: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    by_role: dict[str, list[str]] = {}
    codegen_by_name: dict[str, list[str]] = {}
    method_links: list[tuple[str, str, str]] = []
    for symbol in symbols:
        entity_id = str(symbol.get("id") or "")
        if not entity_id:
            continue
        role = str(symbol.get("role") or "runtime_symbol")
        by_role.setdefault(role, []).append(entity_id)
        symbol_attributes = _json_mapping(symbol.get("attributes"))
        if role == "codegen_module":
            codegen_by_name.setdefault(
                str(symbol.get("name") or "").lower(), []
            ).append(entity_id)
        elif role == "il2cpp_method":
            method_links.append(
                (
                    str(symbol_attributes.get("codegen_module") or "").lower(),
                    entity_id,
                    str(symbol_attributes.get("token") or ""),
                )
            )
        entities.append(
            {
                "id": entity_id,
                "kind": "runtime_symbol",
                "name": symbol.get("name"),
                "confidence": symbol.get("confidence"),
                "attributes": {
                    "engine": engine,
                    "role": role,
                    "name_kind": symbol.get("name_kind"),
                    "address": symbol.get("address"),
                    "rva": symbol.get("rva"),
                    "module": module.get("name"),
                    **symbol_attributes,
                },
                "evidence": [{"source": symbol.get("source")}],
            }
        )
    for code_id in by_role.get("code_registration", []):
        for metadata_id in by_role.get("metadata_registration", []):
            relations.append(
                {
                    "id": "runtime:" + _canonical_hash([code_id, metadata_id, "paired_with"])[:20],
                    "type": "paired_with",
                    "source": code_id,
                    "target": metadata_id,
                    "confidence": 0.99,
                    "evidence": [{"source": "generated_registration_call_argument"}],
                }
            )
        for module_id in by_role.get("codegen_module", []):
            relations.append(
                {
                    "id": "runtime:" + _canonical_hash([code_id, module_id, "registers"])[:20],
                    "type": "registers",
                    "source": code_id,
                    "target": module_id,
                    "confidence": 0.99,
                    "evidence": [{"source": "Il2CppCodeRegistration.codeGenModules"}],
                }
            )
    for codegen_name, method_id, token in method_links:
        for module_id in codegen_by_name.get(codegen_name, []):
            relations.append(
                {
                    "id": "runtime:"
                    + _canonical_hash([module_id, method_id, "maps_method"])[:20],
                    "type": "maps_method",
                    "source": module_id,
                    "target": method_id,
                    "confidence": 0.98,
                    "attributes": {"token": token},
                    "evidence": [
                        {"source": "Il2CppCodeGenModule.methodPointers"}
                    ],
                }
            )
    return {
        "status": status,
        "schema_version": 1,
        "engine": engine,
        "entities": entities,
        "relations": relations,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "validated_symbol_count": len(entities),
        },
    }


def _empty_runtime_semantic_fragment(engine: str, status: str) -> dict[str, Any]:
    return {
        "status": status,
        "schema_version": 1,
        "engine": engine,
        "entities": [],
        "relations": [],
        "summary": {
            "entity_count": 0,
            "relation_count": 0,
            "validated_symbol_count": 0,
        },
    }


def _merge_runtime_semantic_fragments(
    fragments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    entities: dict[str, dict[str, Any]] = {}
    relations: dict[str, dict[str, Any]] = {}
    for fragment in fragments:
        for entity in fragment.get("entities") or []:
            if isinstance(entity, Mapping) and entity.get("id"):
                entities[str(entity["id"])] = _json_mapping(entity)
        for relation in fragment.get("relations") or []:
            if isinstance(relation, Mapping) and relation.get("id"):
                relations[str(relation["id"])] = _json_mapping(relation)
    status = _component_status(fragments)
    return {
        "status": status,
        "schema_version": 1,
        "entities": list(entities.values()),
        "relations": list(relations.values()),
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "validated_symbol_count": len(entities),
        },
    }


def _component_status(components: Sequence[Mapping[str, Any]]) -> str:
    statuses = {str(item.get("status") or "unavailable") for item in components}
    if "partial" in statuses:
        return "partial"
    if "ok" in statuses or "validated" in statuses:
        return "ok"
    return "unavailable"


def _module_contains(base: int, size: int, address: int, span: int) -> bool:
    return bool(
        base >= 0
        and size > 0
        and span > 0
        and address >= base
        and address - base <= size
        and span <= size - (address - base)
    )


def _valid_user_pointer(value: int, pointer_size: int) -> bool:
    if value < 0x10000 or value % max(1, pointer_size):
        return False
    maximum = 0x00007FFFFFFFFFFF if pointer_size == 8 else 0x7FFFFFFF
    return value <= maximum


def _scan_module_strings(
    backend: Any,
    pid: int,
    module: Mapping[str, Any],
    module_key: str,
    parameters: Mapping[str, Any],
    budget: _ReadBudget,
    evidence: _EvidenceCollector,
) -> dict[str, Any]:
    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    if base is None or size is None or size <= 0:
        return {"status": "skipped", "reason": "invalid module range"}
    remaining = min(budget.remaining_total(), budget.remaining_module(module_key))
    if remaining <= 0:
        budget.truncated = True
        return {"status": "truncated", "reason": "read budget exhausted"}
    patterns: list[tuple[str, str, float, str, bytes]] = []
    for engine, marker, weight in _STRING_MARKERS:
        patterns.append((engine, marker, weight, "ascii", marker.encode("ascii")))
        if parameters.get("include_utf16", True):
            patterns.append(
                (engine, marker, weight, "utf-16-le", marker.encode("utf-16-le"))
            )
    max_pattern = max(len(item[4]) for item in patterns)
    ranges = _sample_ranges(
        size,
        remaining,
        _required_int(parameters, "max_single_read_bytes"),
    )
    scanned_ranges: list[dict[str, Any]] = []
    marker_count_before = len(evidence.items)
    for relative, requested in ranges:
        if budget.remaining_total() <= 0 or budget.remaining_module(module_key) <= 0:
            budget.truncated = True
            break
        data = budget.read(
            backend,
            pid,
            module_key,
            base + relative,
            requested,
            purpose="module_marker_scan",
        )
        scanned_ranges.append(
            {
                "rva": relative,
                "rva_hex": _hex(relative),
                "address": base + relative,
                "address_hex": _hex(base + relative),
                "requested_bytes": requested,
                "returned_bytes": len(data),
            }
        )
        if not data:
            continue
        for engine, marker, weight, encoding, pattern in patterns:
            start = 0
            while True:
                offset = data.find(pattern, start)
                if offset < 0:
                    break
                address = base + relative + offset
                evidence.add(
                    _evidence_item(
                        engine=engine,
                        kind="candidate_string",
                        marker=marker,
                        weight=weight,
                        module=module,
                        address=address,
                        rva=relative + offset,
                        source="module_memory",
                        details={
                            "encoding": encoding,
                            "byte_length": len(pattern),
                            "address_kind": "string_storage",
                            "string_storage": {
                                "status": "validated",
                                "address": address,
                                "address_hex": _hex(address),
                                "rva": relative + offset,
                                "rva_hex": _hex(relative + offset),
                            },
                            "object_address": {
                                "status": "unresolved",
                                "reason": (
                                    "a marker string is not a live engine object address"
                                ),
                            },
                        },
                    )
                )
                start = offset + max(1, len(pattern))
        if evidence.truncated:
            break
    return {
        "status": "ok",
        "sampled": sum(item["requested_bytes"] for item in scanned_ranges) < size,
        "module_size": size,
        "max_marker_bytes": max_pattern,
        "ranges": scanned_ranges,
        "candidate_count": len(evidence.items) - marker_count_before,
        "evidence_truncated": evidence.truncated,
    }


def _sample_ranges(size: int, budget: int, chunk_size: int) -> list[tuple[int, int]]:
    amount = min(max(0, budget), max(0, size))
    if amount <= 0:
        return []
    chunk = max(1, min(chunk_size, amount))
    if amount >= size:
        return [
            (offset, min(chunk, size - offset))
            for offset in range(0, size, chunk)
        ]
    count = (amount + chunk - 1) // chunk
    lengths = [chunk] * count
    lengths[-1] = amount - chunk * (count - 1)
    if count == 1:
        return [(0, lengths[0])]
    ranges: list[tuple[int, int]] = []
    for index, length in enumerate(lengths):
        maximum_offset = max(0, size - length)
        offset = (maximum_offset * index) // (count - 1)
        ranges.append((offset, length))
    return ranges


def _read_module_exact(
    backend: Any,
    pid: int,
    module_key: str,
    module_base: int,
    module_size: int,
    address: int,
    size: int,
    budget: _ReadBudget,
    *,
    purpose: str,
) -> bytes:
    if size < 0 or address < module_base or address + size > module_base + module_size:
        return b""
    if size == 0:
        return b""
    chunks: list[bytes] = []
    consumed = 0
    while consumed < size:
        wanted = min(size - consumed, budget.single_limit)
        data = budget.read(
            backend,
            pid,
            module_key,
            address + consumed,
            wanted,
            purpose=purpose,
        )
        if not data:
            break
        chunks.append(data)
        consumed += len(data)
        if len(data) < wanted:
            break
    value = b"".join(chunks)
    return value if len(value) == size else value


def _read_remote_cstring(
    backend: Any,
    pid: int,
    module_key: str,
    module_base: int,
    module_size: int,
    address: int,
    budget: _ReadBudget,
    *,
    purpose: str,
) -> tuple[str, int]:
    if address < module_base or address >= module_base + module_size:
        return "", 0
    remaining = min(_MAX_EXPORT_NAME_BYTES, module_base + module_size - address)
    data = bytearray()
    while remaining > 0:
        wanted = min(remaining, 64, budget.single_limit)
        chunk = budget.read(
            backend,
            pid,
            module_key,
            address + len(data),
            wanted,
            purpose=purpose,
        )
        if not chunk:
            break
        terminator = chunk.find(b"\x00")
        if terminator >= 0:
            data.extend(chunk[:terminator])
            break
        data.extend(chunk)
        remaining -= len(chunk)
        if len(chunk) < wanted:
            break
    try:
        return bytes(data).decode("ascii"), len(data)
    except UnicodeDecodeError:
        return "", len(data)


def _module_basename(value: Any) -> str:
    text = str(value or "").replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def _is_mono_runtime_module(module: Mapping[str, Any]) -> bool:
    name = _module_basename(module.get("name"))
    path = _module_basename(module.get("path"))
    return name in _MONO_MODULE_NAMES or path in _MONO_MODULE_NAMES


def _is_unity_player_module(module: Mapping[str, Any]) -> bool:
    return _module_basename(module.get("name")) == "unityplayer.dll" or (
        _module_basename(module.get("path")) == "unityplayer.dll"
    )


def _is_managed_module_candidate(module: Mapping[str, Any]) -> bool:
    """Select PE module candidates without treating a filename as CLR proof."""

    name = _module_basename(module.get("name"))
    if not (name.endswith(".dll") or name.endswith(".exe")):
        return False
    if name in _MONO_MODULE_NAMES or name == "unityplayer.dll":
        return False
    return True


def _should_extract_mono_module(
    module: Mapping[str, Any],
    *,
    mono_context: bool,
) -> bool:
    return bool(
        _is_mono_runtime_module(module)
        or mono_context
        and (
            _is_unity_player_module(module)
            or _is_managed_module_candidate(module)
        )
    )


def _validate_mono_module_identity(module: Mapping[str, Any]) -> dict[str, Any]:
    path = str(module.get("path") or "").strip()
    normalized_path = path.replace("\\", "/")
    path_errors: list[str] = []
    if not path:
        path_errors.append("module path is missing")
    if "\x00" in path:
        path_errors.append("module path contains NUL")
    windows_path = PureWindowsPath(path)
    absolute = windows_path.is_absolute()
    if not absolute:
        path_errors.append("module path is not absolute")
    if ".." in windows_path.parts or ".." in PurePosixPath(normalized_path).parts:
        path_errors.append("module path contains parent traversal")
    base = _coerce_int(module.get("base_address"))
    size = _coerce_int(module.get("size"))
    if base is None or base < 0 or size is None or size <= 0:
        path_errors.append("module range is invalid")
    expected_identity = _canonical_hash(
        {
            "name": str(module.get("name") or "").lower(),
            "path": path.lower(),
            "base_address": base,
            "size": size,
        }
    )
    actual_identity = str(module.get("identity_sha256") or "")
    if not actual_identity:
        path_errors.append("enumerated module identity is missing")
    elif actual_identity != expected_identity:
        path_errors.append("enumerated module identity does not match its name/path/range")
    return {
        "valid": not path_errors,
        "path": path,
        "normalized_path": normalized_path,
        "absolute": absolute,
        "identity_sha256": actual_identity or None,
        "expected_identity_sha256": expected_identity,
        "errors": path_errors,
    }


def _runtime_va_proof(
    module_base: Optional[int],
    rva: Optional[int],
    runtime_va: Optional[int],
) -> dict[str, Any]:
    verified = bool(
        isinstance(module_base, int)
        and isinstance(rva, int)
        and isinstance(runtime_va, int)
        and module_base >= 0
        and rva >= 0
        and runtime_va == module_base + rva
    )
    return {
        "module_base": module_base,
        "module_base_hex": _hex(module_base),
        "rva": rva,
        "rva_hex": _hex(rva),
        "runtime_va": runtime_va,
        "runtime_va_hex": _hex(runtime_va),
        "equation": (
            f"{_hex(module_base)} + {_hex(rva)} = {_hex(runtime_va)}"
            if isinstance(module_base, int)
            and isinstance(rva, int)
            and isinstance(runtime_va, int)
            else None
        ),
        "verified": verified,
    }


def _unreal_module_classification(
    module: Mapping[str, Any],
    *,
    unreal_context: bool,
) -> dict[str, Any]:
    name = _module_basename(module.get("name"))
    path = str(module.get("path") or "").replace("\\", "/").lower()
    combined = f"{name} {path}"
    reasons: list[str] = []
    strong = False
    role = "companion_runtime"

    primary_prefixes = (
        "unrealeditor",
        "ue4",
        "ue5",
        "ue4editor",
        "ue5editor",
        "ue4game",
        "ue5game",
        "libue4",
        "libunreal",
    )
    if name.startswith(primary_prefixes) or any(
        token in combined
        for token in ("unrealengine", "libue4", "libunreal")
    ):
        strong = True
        role = "primary_runtime"
        reasons.append("unreal runtime/editor module naming convention")
    if name == "coreuobject.dll" or name.endswith("-coreuobject.dll"):
        strong = True
        role = "core_runtime"
        reasons.append("CoreUObject runtime module")
    if name.endswith(
        (
            "-win64-shipping.exe",
            "-win64-development.exe",
            "-win64-test.exe",
        )
    ):
        strong = True
        role = "packaged_game"
        reasons.append("Unreal packaged Win64 executable naming convention")

    contextual = bool(
        unreal_context
        and (
            name in _UNREAL_CONTEXTUAL_MODULES
            or name.endswith(("-engine.dll", "-umg.dll", "-slate.dll"))
            or name.startswith(("slate", "umg"))
        )
    )
    if contextual:
        reasons.append("Unreal companion module in a process with a strong Unreal module")
        if "umg" in name:
            role = "ui_runtime"
        elif "engine" in name:
            role = "engine_runtime"
    matched = strong or contextual
    return {
        "matched": matched,
        "strong": strong,
        "contextual": contextual and not strong,
        "role": role if matched else None,
        "confidence": 0.99 if strong else 0.85 if contextual else 0.0,
        "reasons": reasons,
    }


def _has_unreal_runtime_context(modules: Sequence[Mapping[str, Any]]) -> bool:
    return any(
        _unreal_module_classification(item, unreal_context=False).get("strong")
        for item in modules
        if isinstance(item, Mapping)
    )


def _module_signals(
    module: Mapping[str, Any],
    *,
    unreal_context: bool = False,
) -> list[tuple[str, str, float]]:
    name = str(module.get("name") or "").lower()
    path = str(module.get("path") or "").lower()
    combined = f"{name} {path}"
    signals: list[tuple[str, str, float]] = []
    if _is_mono_runtime_module(module):
        signals.append(
            (
                "unity_mono",
                str(module.get("name") or "mono.dll"),
                6.0,
            )
        )
    if "gameassembly" in combined or "il2cpp" in combined:
        signals.append(("unity_il2cpp", str(module.get("name") or "GameAssembly"), 6.0))
    elif "unityplayer" in combined or "unity" in name:
        signals.append(("unity_il2cpp", str(module.get("name") or "UnityPlayer"), 2.0))
    unreal = _unreal_module_classification(
        module,
        unreal_context=unreal_context,
    )
    if unreal.get("matched"):
        signals.append(
            (
                "unreal",
                str(module.get("name") or "Unreal"),
                6.0 if unreal.get("strong") else 3.5,
            )
        )
    return signals


def _text_signals(
    value: str,
    *,
    source: str,
) -> list[tuple[str, str, float]]:
    lowered = value.lower()
    signals: list[tuple[str, str, float]] = []
    if lowered.startswith("il2cpp_") or "il2cpp::" in lowered:
        signals.append(("unity_il2cpp", value, 3.0 if source == "pe_export" else 2.0))
    if lowered in _MONO_EMBEDDING_EXPORT_ROLES or lowered.startswith("mono_"):
        signals.append(("unity_mono", value, 3.0 if source == "pe_export" else 2.0))
    unreal_tokens = (
        "processevent",
        "staticclass",
        "staticfindobject",
        "fnamepool",
        "gnames",
        "guobjectarray",
        "gobjects",
        "gworld",
        "fengineloop",
    )
    if any(token in lowered for token in unreal_tokens):
        signals.append(("unreal", value, 3.0 if source == "pe_export" else 2.0))
    return signals


def _evidence_item(
    *,
    engine: str,
    kind: str,
    marker: str,
    weight: float,
    module: Mapping[str, Any],
    address: Optional[int],
    rva: Optional[int],
    source: str,
    symbol: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    module_base = _coerce_int(module.get("base_address"))
    runtime_proof = (
        _runtime_va_proof(module_base, rva, address)
        if address is not None and rva is not None
        else None
    )
    return _prune(
        {
            "engine": engine,
            "engine_label": _ENGINE_LABELS.get(engine, engine),
            "kind": kind,
            "marker": marker,
            "symbol": symbol,
            "source": source,
            "weight": float(weight),
            "module": module.get("name"),
            "module_path": module.get("path"),
            "module_identity_sha256": module.get("identity_sha256"),
            "module_base": module.get("base_address"),
            "module_base_hex": module.get("base_address_hex"),
            "address": address,
            "address_hex": _hex(address),
            "rva": rva,
            "rva_hex": _hex(rva),
            "runtime_va_proof": runtime_proof,
            "details": _json_mapping(details),
        }
    )


def _summarize_engines(evidence: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for item in evidence:
        engine = str(item.get("engine") or "")
        if not engine:
            continue
        group = groups.setdefault(
            engine,
            {
                "engine": engine,
                "label": _ENGINE_LABELS.get(engine, engine),
                "score": 0.0,
                "evidence_count": 0,
                "module_identity_sha256": set(),
                "kinds": set(),
            },
        )
        group["score"] += float(item.get("weight") or 0.0)
        group["evidence_count"] += 1
        if item.get("module_identity_sha256"):
            group["module_identity_sha256"].add(item["module_identity_sha256"])
        if item.get("kind"):
            group["kinds"].add(item["kind"])
    result: list[dict[str, Any]] = []
    for group in groups.values():
        score = round(float(group["score"]), 3)
        threshold = 5.0
        result.append(
            {
                "engine": group["engine"],
                "label": group["label"],
                "status": "detected" if score >= threshold else "candidate",
                "score": score,
                "confidence": round(min(0.99, score / (score + 4.0)), 4),
                "evidence_count": group["evidence_count"],
                "module_count": len(group["module_identity_sha256"]),
                "kinds": sorted(group["kinds"]),
            }
        )
    return sorted(result, key=lambda item: (-item["score"], item["engine"]))


def _normalize_modules(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        return []
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            continue
        name = str(
            value.get("name")
            or value.get("module_name")
            or Path(str(value.get("path") or value.get("image_path") or "")).name
            or f"module-{index}"
        )
        path = str(value.get("path") or value.get("image_path") or value.get("exe_path") or "")
        base = _coerce_int(
            value.get("base_address", value.get("base", value.get("address")))
        )
        size = _coerce_int(value.get("size", value.get("module_size")))
        if base is None or base < 0 or size is None or size <= 0:
            continue
        key = (base, path.lower() or name.lower())
        if key in seen:
            continue
        seen.add(key)
        identity_payload = {
            "name": name.lower(),
            "path": path.lower(),
            "base_address": base,
            "size": size,
        }
        normalized.append(
            {
                "name": name,
                "path": path,
                "base_address": base,
                "base_address_hex": _hex(base),
                "size": size,
                "end_address": base + size,
                "end_address_hex": _hex(base + size),
                "identity_sha256": _canonical_hash(identity_payload),
            }
        )
    return sorted(normalized, key=lambda item: (item["base_address"], item["name"].lower()))


def _select_modules(
    modules: Sequence[Mapping[str, Any]],
    parameters: Mapping[str, Any],
) -> list[dict[str, Any]]:
    limit = max(1, _coerce_int(parameters.get("max_modules")) or 1)
    filters = [str(item).lower() for item in parameters.get("module_filters") or []]
    scan_all = bool(parameters.get("scan_all_modules"))
    mono_context = any(_is_mono_runtime_module(item) for item in modules)
    unreal_context = _has_unreal_runtime_context(modules)
    selected: list[dict[str, Any]] = []
    for index, item in enumerate(modules):
        name = str(item.get("name") or "").lower()
        path = str(item.get("path") or "").lower()
        combined = f"{name} {path}"
        direct = bool(
            _module_signals(item, unreal_context=unreal_context)
        )
        main_executable = index == 0 or name.endswith(".exe")
        filtered = bool(filters and any(token in combined for token in filters))
        managed_candidate = mono_context and _is_managed_module_candidate(item)
        if (
            scan_all
            or filtered
            or direct
            or managed_candidate
            or (not filters and main_executable)
        ):
            selected.append(dict(item))
        if len(selected) >= limit:
            break
    return selected


def _inventory_precondition_hash(
    action: str,
    snapshot: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> str:
    process = snapshot.get("process") if isinstance(snapshot.get("process"), Mapping) else {}
    selected = snapshot.get("selected_modules") or []
    payload = {
        "action": _normalize_action(action),
        "pid": _coerce_int(snapshot.get("pid", parameters.get("pid"))),
        "process": {
            "pid": _coerce_int(process.get("pid")),
            "exists": process.get("exists"),
            "accessible": process.get("accessible"),
            "image_path": str(process.get("image_path") or "").lower(),
        },
        "selected_modules": [
            {
                "identity_sha256": item.get("identity_sha256"),
                "base_address": item.get("base_address"),
                "size": item.get("size"),
            }
            for item in selected
            if isinstance(item, Mapping)
        ],
        "selection": {
            "module_filters": list(parameters.get("module_filters") or []),
            "scan_all_modules": bool(parameters.get("scan_all_modules")),
            "max_modules": parameters.get("max_modules"),
        },
        "read_limits": _read_limits(parameters),
        "read_only": True,
    }
    return _canonical_hash(payload)


def _execution_unavailable_reason(
    backend: Any,
    plan: CapabilityPlan,
    snapshot: Mapping[str, Any],
) -> Optional[str]:
    if not _backend_available(backend):
        return _backend_reason(backend)
    missing = [
        name
        for name in ("probe", "modules", "read")
        if _backend_method(backend, name, required=False) is None
    ]
    if missing:
        return "backend is missing read-only APIs: " + ", ".join(missing)
    pid = _coerce_int(plan.parameters.get("pid"))
    if pid is None or pid <= 0:
        return "target PID is unavailable"
    process = snapshot.get("process") or {}
    if not process.get("accessible") or process.get("status") != "ok":
        return str(
            process.get("reason")
            or process.get("error")
            or "target process is unavailable for read-only inspection"
        )
    if snapshot.get("errors"):
        return "target module inventory is unavailable"
    return None


_BACKEND_METHOD_NAMES = {
    "probe": ("probe_process", "probe"),
    "modules": ("enumerate_modules", "list_modules", "modules"),
    "read": ("read_process_memory", "read_memory", "read"),
}


def _backend_method(
    backend: Any,
    operation: str,
    *,
    required: bool,
) -> Any:
    for name in _BACKEND_METHOD_NAMES.get(operation, (operation,)):
        method = getattr(backend, name, None)
        if callable(method):
            return method
    if required:
        raise EngineRuntimeBackendError(
            operation,
            f"backend does not implement the {operation} operation",
        )
    return None


def _backend_read(backend: Any, pid: int, address: int, size: int) -> bytes:
    method = _backend_method(backend, "read", required=True)
    value = method(pid, address, size)
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, Mapping):
        for key in ("data", "bytes", "data_hex", "hex"):
            item = value.get(key)
            if isinstance(item, bytes):
                return item
            if isinstance(item, (bytearray, memoryview)):
                return bytes(item)
            if isinstance(item, str):
                try:
                    return bytes.fromhex(item)
                except ValueError:
                    continue
    raise EngineRuntimeBackendError(
        "read_process_memory",
        "backend returned a non-byte result",
        details={"type": type(value).__name__},
    )


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", True))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "Windows read-only process inspection backend is unavailable"
    )


def _backend_info(backend: Any, platform_name: str) -> dict[str, Any]:
    return {
        "name": str(getattr(backend, "name", type(backend).__name__)),
        "available": _backend_available(backend),
        "unavailable_reason": (
            None if _backend_available(backend) else _backend_reason(backend)
        ),
        "platform": platform_name,
        "read_only": True,
        "apis": ["OpenProcess", "CreateToolhelp32Snapshot", "ReadProcessMemory"],
    }


def _read_limits(parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "max_total_read_bytes": parameters.get("max_total_read_bytes"),
        "max_module_read_bytes": parameters.get("max_module_read_bytes"),
        "max_single_read_bytes": parameters.get("max_single_read_bytes"),
        "max_modules": parameters.get("max_modules"),
        "max_evidence": parameters.get("max_evidence"),
        "max_export_names": parameters.get("max_export_names"),
    }


def _empty_read_usage(parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "limits": {
            key: value
            for key, value in _read_limits(parameters).items()
            if key in {
                "max_total_read_bytes",
                "max_module_read_bytes",
                "max_single_read_bytes",
            }
        },
        "requested_bytes": 0,
        "returned_bytes": 0,
        "remaining_bytes": parameters.get("max_total_read_bytes", 0),
        "call_count": 0,
        "max_observed_request": 0,
        "module_requested_bytes": {},
        "module_returned_bytes": {},
        "truncated": False,
        "errors": [],
        "calls": [],
    }


def _read_only_rollback_plan(precondition_hash: str) -> dict[str, Any]:
    return {
        "supported": False,
        "mode": "not_required",
        "reason": "engine_runtime is read-only",
        "read_only": True,
        "side_effects": False,
        "precondition_hash": precondition_hash,
    }


def _normalize_action(value: Any) -> str:
    action = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ACTION_ALIASES.get(action, action)


def _request_pid(request: CapabilityRequest) -> tuple[Any, Optional[int], bool]:
    target_pid = getattr(request.target, "pid", None)
    parameter_pid = request.params.get("pid")
    raw = parameter_pid if parameter_pid is not None else target_pid
    pid = _coerce_int(raw)
    target_value = _coerce_int(target_pid)
    parameter_value = _coerce_int(parameter_pid)
    conflict = (
        target_pid is not None
        and parameter_pid is not None
        and target_value != parameter_value
    )
    return raw, pid, conflict


def _normalize_module_filters(value: Any) -> tuple[list[str], Optional[str]]:
    if value in (None, ""):
        return [], None
    if isinstance(value, str):
        items = [item.strip() for item in value.replace(",", " ").split()]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = [str(item).strip() for item in value]
    else:
        return [], "module_names must be text or a sequence of names"
    selected = [item for item in items if item]
    if len(selected) > 64:
        return [], "module_names exceeds the maximum of 64 filters"
    if any(len(item) > 260 for item in selected):
        return [], "module_names contains a filter longer than 260 characters"
    return _deduplicate(selected), None


def _first_value(values: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        if name in values:
            return values[name]
    return None


def _configuration_limit(value: Any, default: int, maximum: int) -> int:
    parsed = _coerce_int(value)
    if parsed is None or parsed <= 0:
        return default
    return min(parsed, maximum)


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16) if all(item in "0123456789abcdefABCDEF" for item in text) else None
        except ValueError:
            return None


def _required_int(values: Mapping[str, Any], key: str) -> int:
    value = _coerce_int(values.get(key))
    if value is None:
        raise ValueError(f"{key} must be an integer")
    return value


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest_entry_values(
    capability: str,
    provider: str,
    session_id: str,
    action: str,
    status: str,
    target: Mapping[str, Any],
    precondition_hash: Optional[str],
    artifact: CapabilityArtifact,
    pid: Any,
) -> dict[str, Any]:
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "path": artifact.path,
        "kind": artifact.kind,
        "tool": capability,
        "provider": provider,
        "status": status,
        "role": "engine-runtime-evidence",
        "session_id": session_id,
        "action": action,
        "pid": pid,
        "target": dict(target),
        "precondition_hash": precondition_hash,
        "read_only": True,
    }


def _manifest_entry(
    result: CapabilityExecutionResult,
    artifact: CapabilityArtifact,
) -> dict[str, Any]:
    return _manifest_entry_values(
        result.capability,
        result.provider,
        result.session_id,
        result.action,
        result.status,
        _target_payload(result.target),
        result.provenance.get("precondition_hash"),
        artifact,
        getattr(result.target, "pid", None),
    )


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    target = _target_payload(result.target)
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
        "session_id": result.session_id,
        "session": {"id": result.session_id},
        "target": target,
        "target_identity": target,
        "precondition": result.report_section.get("precondition")
        or {"hash": result.provenance.get("precondition_hash")},
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before": _json_mapping(result.before_snapshot),
        "after": _json_mapping(result.after_snapshot),
        "before_snapshot": _json_mapping(result.before_snapshot),
        "after_snapshot": _json_mapping(result.after_snapshot),
        "rollback": _json_mapping(result.rollback_plan),
        "rollback_plan": _json_mapping(result.rollback_plan),
        "provenance": _json_mapping(result.provenance),
        "artifacts": [artifact.to_dict() for artifact in result.artifacts],
        "evidence_manifest_entries": [
            _json_mapping(item) for item in result.evidence_manifest_entries
        ],
        "dashboard_trace": [
            _json_mapping(item) for item in result.dashboard_trace
        ],
        "report": _json_mapping(result.report_section),
        "report_section": _json_mapping(result.report_section),
    }


def _sync_report(result: CapabilityExecutionResult) -> None:
    target = _target_payload(result.target)
    result.report_section.update(
        {
            "session_id": result.session_id,
            "target_identity": target,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "before": _json_mapping(result.before_snapshot),
            "after": _json_mapping(result.after_snapshot),
            "before_snapshot": _json_mapping(result.before_snapshot),
            "after_snapshot": _json_mapping(result.after_snapshot),
            "rollback_plan": _json_mapping(result.rollback_plan),
            "provenance": _json_mapping(result.provenance),
            "artifacts": [artifact.to_dict() for artifact in result.artifacts],
            "evidence_manifest_entries": [
                _json_mapping(item) for item in result.evidence_manifest_entries
            ],
        }
    )


def _artifact_destination(root: Path, artifact_path: str) -> Path:
    text = str(artifact_path or "").strip()
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text)
    if (
        not text
        or text in {".", ".."}
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.is_absolute()
        or ".." in windows.parts
        or ".." in posix.parts
    ):
        raise ValueError("artifact path must stay inside the collection directory")
    destination = (root / Path(text)).resolve()
    if destination != root and root not in destination.parents:
        raise ValueError("artifact path escapes the collection directory")
    return destination


def _target_payload(target: Any) -> dict[str, Any]:
    to_dict = getattr(target, "to_dict", None)
    if callable(to_dict):
        value = to_dict()
        if isinstance(value, Mapping):
            return _json_mapping(value)
    return _prune(
        {
            "kind": getattr(target, "kind", None),
            "path": getattr(target, "path", None),
            "pid": getattr(target, "pid", None),
            "sha256": getattr(target, "sha256", None),
            "display_name": getattr(target, "display_name", None),
            "metadata": getattr(target, "metadata", None),
        }
    )


def _exception_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, EngineRuntimeBackendError):
        return exc.to_dict()
    return {"type": type(exc).__name__, "message": str(exc)}


def _pointer_value(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(ctypes.cast(value, ctypes.c_void_p).value or 0)
    except (TypeError, ValueError):
        return int(getattr(value, "value", 0) or 0)


def _hex(value: Optional[int]) -> Optional[str]:
    return f"0x{value:x}" if isinstance(value, int) and value >= 0 else None


def _safe_segment(value: Any) -> str:
    selected = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in str(value or "session")
    ).strip(".")
    return selected or "session"


def _deduplicate(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def _json_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _prune(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value
