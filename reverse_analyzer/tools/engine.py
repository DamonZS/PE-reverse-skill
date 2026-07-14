"""Static engine fingerprinting helpers for game/application runtimes."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import zipfile
from typing import Any, Iterable, Mapping


_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UNREAL_PACKAGE_RE = re.compile(r"/(?:Game|Script|Engine)(?:/[A-Za-z0-9_.+\-]+)+")
_UNREAL_ASSET_RE = re.compile(r"\b(?:WBP|BP|ABP|SM|SK|T|M|MI|S|FX|DT|DA)_[A-Za-z0-9_]+\b")

_GLOBAL_METADATA_MAGIC = 0xFAB11BAF
_MIN_GLOBAL_METADATA_PAIRS = 3
_MIN_ENGINE_SCORE = 6.0
_UNREAL_PACKAGE_MAGIC = 0x9E2A83C1
_UNREAL_PAK_MAGIC = 0x5A6F12E1
_MAX_MANAGED_METADATA_BYTES = 8 * 1024 * 1024
_MAX_IL2CPP_TABLE_BYTES = 8 * 1024 * 1024
_MAX_PE_HEADER_BYTES = 1024 * 1024
_MAX_PE_SECTION_SCAN_BYTES = 64 * 1024 * 1024
_MAX_PE_TOTAL_SCAN_BYTES = 128 * 1024 * 1024
_MAX_IL2CPP_METHOD_POINTERS = 1_000_000
_MAX_IL2CPP_POINTER_TABLE_BYTES = 8 * 1024 * 1024
_MAX_UNREAL_PAK_INDEX_BYTES = 8 * 1024 * 1024
_GLOBAL_METADATA_TABLES = (
    "string_literals",
    "string_literal_data",
    "strings",
    "events",
    "properties",
    "methods",
    "parameter_default_values",
    "field_default_values",
    "field_and_parameter_default_value_data",
    "field_marshaled_sizes",
    "parameters",
    "fields",
    "generic_parameters",
    "generic_parameter_constraints",
    "generic_containers",
    "nested_types",
    "interfaces",
    "vtable_methods",
    "interface_offsets",
    "type_definitions",
    "rgctx_entries",
    "images",
    "assemblies",
    "metadata_usage_lists",
    "metadata_usage_pairs",
    "field_refs",
    "referenced_assemblies",
    "attributes_info",
    "attribute_types",
    "unresolved_virtual_call_parameter_types",
    "unresolved_virtual_call_parameter_ranges",
    "windows_runtime_type_names",
    "windows_runtime_strings",
    "exported_type_definitions",
)

_UNITY_UI_MARKERS = (
    "unityengine.ui",
    "canvas",
    "recttransform",
    "button",
    "dropdown",
    "eventsystem",
    "inputfield",
    "scrollrect",
    "slider",
    "textmeshpro",
    "tmp_",
    "toggle",
)
_UNREAL_REFLECTION_MARKERS = (
    "UObject",
    "UClass",
    "UFunction",
    "UStruct",
    "UProperty",
    "FProperty",
    "AActor",
    "ProcessEvent",
    "StaticClass",
    "BlueprintGeneratedClass",
    "WidgetBlueprint",
    "PersistentLevel",
)
_UNREAL_FORWARD_DECLARATION_MARKERS = frozenset(
    {
        "AActor",
        "FProperty",
        "UClass",
        "UFunction",
        "UObject",
        "UProperty",
        "UStruct",
    }
)
_KNOWN_RUNTIME_FILES = {
    "assembly-csharp.dll",
    "gameassembly.dll",
    "global-metadata.dat",
    "globalgamemanagers",
    "libil2cpp.so",
    "libue4.so",
    "libunity.so",
    "libunreal.so",
    "mono.dll",
    "mono-2.0-bdwgc.dll",
    "resources.assets",
    "unityplayer.dll",
}
_ARCHIVE_SUFFIXES = {".apk", ".ipa", ".jar", ".zip"}
_ENGINE_FILE_SUFFIXES = {".assets", ".dll", ".pak", ".so", ".uasset", ".umap"}
_MAX_DISCOVERED_FILES = 6000
_MAX_DISCOVERED_ENTRIES = 30000
_MAX_ARCHIVE_NAMES = 20000
_MAX_ARCHIVE_SKIP = 64 * 1024 * 1024
_MAX_STRINGS_PER_FILE = 2000

_DOTNET_TABLE_NAMES = (
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "ENCLog",
    "ENCMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
)

_DOTNET_CODED_INDEXES: dict[str, tuple[int, tuple[int, ...]]] = {
    "TypeDefOrRef": (2, (2, 1, 27)),
    "HasConstant": (2, (4, 8, 23)),
    "HasCustomAttribute": (5, (6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43)),
    "HasFieldMarshal": (1, (4, 8)),
    "HasDeclSecurity": (2, (2, 6, 32)),
    "MemberRefParent": (3, (2, 1, 26, 6, 27)),
    "HasSemantics": (1, (20, 23)),
    "MethodDefOrRef": (1, (6, 10)),
    "MemberForwarded": (1, (4, 6)),
    "Implementation": (2, (38, 35, 39)),
    "CustomAttributeType": (3, (6, 10)),
    "ResolutionScope": (2, (0, 26, 35, 1)),
    "TypeOrMethodDef": (1, (2, 6)),
}

_DOTNET_TABLE_SCHEMAS: dict[int, tuple[str, ...]] = {
    0: ("u2", "string", "guid", "guid", "guid"),
    1: ("coded:ResolutionScope", "string", "string"),
    2: ("u4", "string", "string", "coded:TypeDefOrRef", "table:4", "table:6"),
    3: ("table:4",),
    4: ("u2", "string", "blob"),
    5: ("table:6",),
    6: ("u4", "u2", "u2", "string", "blob", "table:8"),
    7: ("table:8",),
    8: ("u2", "u2", "string"),
    9: ("table:2", "coded:TypeDefOrRef"),
    10: ("coded:MemberRefParent", "string", "blob"),
    11: ("u2", "coded:HasConstant", "blob"),
    12: ("coded:HasCustomAttribute", "coded:CustomAttributeType", "blob"),
    13: ("coded:HasFieldMarshal", "blob"),
    14: ("u2", "coded:HasDeclSecurity", "blob"),
    15: ("u2", "u4", "table:2"),
    16: ("u4", "table:4"),
    17: ("blob",),
    18: ("table:2", "table:20"),
    19: ("table:20",),
    20: ("u2", "string", "coded:TypeDefOrRef"),
    21: ("table:2", "table:23"),
    22: ("table:23",),
    23: ("u2", "string", "blob"),
    24: ("u2", "table:6", "coded:HasSemantics"),
    25: ("table:2", "coded:MethodDefOrRef", "coded:MethodDefOrRef"),
    26: ("string",),
    27: ("blob",),
    28: ("u2", "coded:MemberForwarded", "string", "table:26"),
    29: ("u4", "table:4"),
    30: ("u4", "u4"),
    31: ("u4",),
    32: ("u4", "u2", "u2", "u2", "u2", "u4", "blob", "string", "string"),
    33: ("u4",),
    34: ("u4", "u4", "u4"),
    35: ("u2", "u2", "u2", "u2", "u4", "blob", "string", "string", "blob"),
    36: ("u4", "table:35"),
    37: ("u4", "u4", "u4", "table:35"),
    38: ("u4", "string", "blob"),
    39: ("u4", "u4", "string", "string", "coded:Implementation"),
    40: ("u4", "u4", "string", "coded:Implementation"),
    41: ("table:2", "table:2"),
    42: ("u2", "u2", "coded:TypeOrMethodDef", "string"),
    43: ("coded:MethodDefOrRef", "blob"),
    44: ("table:42", "coded:TypeDefOrRef"),
}


@dataclass(frozen=True)
class _EvidenceFile:
    name: str
    size: int | None
    local_path: Path | None = None
    archive_path: Path | None = None
    archive_name: str | None = None

    @property
    def basename(self) -> str:
        return Path(self.name.replace("\\", "/")).name

    @property
    def display_path(self) -> str:
        if self.archive_path is not None and self.archive_name is not None:
            return f"{self.archive_path}!{self.archive_name}"
        if self.local_path is not None:
            return str(self.local_path)
        return self.name


def engine_analyze(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Fingerprint Unity/Unreal runtimes and recover bounded static evidence."""

    sample = Path(path)
    if not sample.exists():
        return _unavailable_result(sample, f"sample not found: {sample}")
    if not sample.is_file():
        return _unavailable_result(sample, f"sample is not a file: {sample}")

    sample_data, sample_error = _read_local_segment(sample, limit=2 * 1024 * 1024)
    if sample_error is not None:
        return _unavailable_result(sample, f"sample could not be read: {sample_error}")

    diagnostics: list[dict[str, Any]] = []
    container_names, container_files, container_diagnostics = _container_evidence(sample)
    local_files, local_diagnostics = _local_evidence_files(sample)
    diagnostics.extend(container_diagnostics)
    diagnostics.extend(local_diagnostics)

    sample_ref = _EvidenceFile(sample.name, _safe_size(sample), local_path=sample)
    evidence_files = _dedupe_evidence([sample_ref, *local_files, *container_files])
    names = _unique_sorted([*container_names, *[item.name for item in evidence_files]])

    sample_strings = _extract_strings(sample_data)
    managed_refs = [item for item in evidence_files if _is_managed_assembly(item.name)]
    metadata_refs = [item for item in evidence_files if item.basename.lower() == "global-metadata.dat"]
    asset_refs = [item for item in evidence_files if _is_engine_asset(item.name)]
    runtime_refs = [item for item in evidence_files if _is_runtime_binary(item.name)]

    managed_files, managed_strings, managed_diagnostics = _managed_assembly_inventory(managed_refs)
    diagnostics.extend(managed_diagnostics)

    global_metadata_files: list[dict[str, Any]] = []
    global_metadata_strings: list[str] = []
    for metadata_ref in metadata_refs[:8]:
        parsed, parsed_strings = _analyze_global_metadata(metadata_ref)
        global_metadata_files.append(parsed)
        global_metadata_strings.extend(parsed_strings)
        if parsed["status"] == "partial":
            diagnostics.append(
                _diagnostic(
                    "global-metadata",
                    "partial",
                    str(parsed.get("error") or "metadata parsing incomplete"),
                    parsed["path"],
                )
            )

    asset_files, asset_diagnostics = _engine_asset_inventory(asset_refs)
    diagnostics.extend(asset_diagnostics)

    evidence_strings = [*sample_strings, *managed_strings, *global_metadata_strings]
    content_diagnostics: list[dict[str, Any]] = []
    validated_asset_paths = {
        str(item.get("path"))
        for item in asset_files
        if item.get("format_validated") and item.get("path")
    }
    content_refs = _dedupe_evidence(
        [
            *[
                ref
                for ref in asset_refs
                if ref.display_path in validated_asset_paths
            ],
            *runtime_refs,
        ]
    )
    for ref in content_refs[:64]:
        if ref.local_path == sample:
            continue
        data, error = _read_evidence_segment(ref, limit=1024 * 1024)
        if error is not None:
            content_diagnostics.append(_diagnostic("engine-content", "partial", error, ref.display_path))
            continue
        evidence_strings.extend(_extract_strings(data))
    diagnostics.extend(content_diagnostics)
    evidence_strings = _unique_strings(evidence_strings, limit=8000)

    unreal_evidence = _extract_unreal_evidence(evidence_strings, names)
    ranked = _rank_candidates(
        sample=sample,
        names=names,
        strings=evidence_strings,
        managed_files=managed_files,
        global_metadata_files=global_metadata_files,
        unreal_evidence=unreal_evidence,
        asset_files=asset_files,
    )
    best = ranked[0]
    engine_name = str(best["engine"])
    engine_scores = [float(item["score"]) for item in ranked if item["engine"] != "unknown"]
    second_engine_score = sorted(engine_scores, reverse=True)[1] if len(engine_scores) > 1 else 0.0
    confidence = (
        0.0
        if engine_name == "unknown"
        else _candidate_confidence(float(best["score"]), second_engine_score)
    )
    status = "partial" if any(item.get("status") == "partial" for item in diagnostics) else "ok"
    platform = _platform_for_suffix(sample.suffix.lower())
    native_mapping = _native_mapping_summary(
        engine_name=engine_name,
        platform=platform,
        global_metadata_files=global_metadata_files,
        runtime_refs=runtime_refs,
    )
    if (
        engine_name == "unity-il2cpp"
        and platform == "windows-pe"
        and native_mapping.get("status") != "ok"
    ):
        status = "partial"
        native_errors = list(native_mapping.get("errors") or [])
        diagnostics.append(
            _diagnostic(
                "engine-native-mapping",
                "partial",
                str(native_errors[0] if native_errors else "IL2CPP native mapping could not be proven"),
                str(native_mapping.get("binary_path") or sample),
            )
        )

    metadata = _metadata_summary(
        engine_name=engine_name,
        names=names,
        strings=evidence_strings,
        managed_files=managed_files,
        global_metadata_files=global_metadata_files,
        unreal_evidence=unreal_evidence,
        status=status,
    )
    metadata["native_mapping_status"] = native_mapping.get("status", "unavailable")
    metadata["native_mapped_method_count"] = int(native_mapping.get("mapped_method_count") or 0)
    assets = _asset_summary(names, unreal_evidence, asset_files, status=status)
    symbols = _symbol_summary(
        evidence_strings,
        engine_name,
        unreal_evidence,
        managed_files=managed_files,
        global_metadata_files=global_metadata_files,
        native_mapping=native_mapping,
        status=status,
    )
    sdk_skeleton = _unreal_sdk_skeleton(
        engine_name=engine_name,
        assets=assets,
        symbols=symbols,
    )
    semantic_ir_fragment = _semantic_ir_fragment(
        engine_name=engine_name,
        confidence=confidence,
        status=status,
        metadata=metadata,
        assets=assets,
        symbols=symbols,
        native_mapping=native_mapping,
        sdk_skeleton=sdk_skeleton,
    )

    result: dict[str, Any] = {
        "status": status,
        "schema_version": 1,
        "path": str(sample),
        "platform": platform,
        "engine": engine_name,
        "confidence": confidence,
        "evidence": list(best["evidence"]),
        "candidates": [
            {
                "engine": item["engine"],
                "score": round(float(item["score"]), 3),
                "confidence": (
                    0.0
                    if item["engine"] == "unknown"
                    else _candidate_confidence(
                        float(item["score"]),
                        max(
                            (
                                float(other["score"])
                                for other in ranked
                                if other["engine"] not in {"unknown", item["engine"]}
                            ),
                            default=0.0,
                        ),
                    )
                ),
                "evidence": list(item["evidence"]),
            }
            for item in ranked
        ],
        "metadata": metadata,
        "assets": assets,
        "symbols": symbols,
        "native_mapping": native_mapping,
        "sdk_skeleton": sdk_skeleton,
        "semantic_ir_fragment": semantic_ir_fragment,
        "strategy": _default_strategy(engine_name),
        "diagnostics": diagnostics,
        "artifacts": [],
    }
    if out_dir:
        _emit_artifacts(result, Path(out_dir))
    return result


def _rank_candidates(
    *,
    sample: Path,
    names: list[str],
    strings: list[str],
    managed_files: list[dict[str, Any]],
    global_metadata_files: list[dict[str, Any]],
    unreal_evidence: Mapping[str, list[str]],
    asset_files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    lower_names = [name.lower() for name in names]
    basenames = {Path(name.replace("\\", "/")).name.lower() for name in names}
    combined = "\n".join([sample.name.lower(), *lower_names, *[value.lower() for value in strings]])

    def add(engine: str, score: float, evidence: str) -> None:
        item = candidates.setdefault(engine, {"engine": engine, "score": 0.0, "evidence": []})
        item["score"] += score
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)

    validated_managed = [item for item in managed_files if item.get("status") == "ok"]
    assembly_csharp = [item for item in validated_managed if item["name"].lower() == "assembly-csharp.dll"]
    assembly_csharp_candidates = [item for item in managed_files if item["name"].lower() == "assembly-csharp.dll"]
    unity_managed = [
        item
        for item in validated_managed
        if item["name"].lower().startswith(("assembly-csharp", "unityengine"))
    ]
    if assembly_csharp:
        add("unity-mono", 9.0, f"Validated Assembly-CSharp CLI metadata: {assembly_csharp[0]['path']}")
    elif assembly_csharp_candidates:
        add("unity-mono", 3.0, f"Unvalidated Assembly-CSharp candidate: {assembly_csharp_candidates[0]['path']}")
    elif "assembly-csharp.dll" in combined:
        add("unity-mono", 2.0, "Assembly-CSharp.dll string reference detected")
    if unity_managed:
        add(
            "unity-mono",
            2.0 + min(2.0, len(unity_managed) * 0.25),
            f"Validated Unity managed assembly inventory contains {len(unity_managed)} DLL(s)",
        )
    mono_runtime_files = basenames & {"mono.dll", "mono-2.0-bdwgc.dll"}
    if mono_runtime_files or any("monobleedingedge" in name for name in lower_names):
        add("unity-mono", 6.0, "Unity Mono runtime file/directory detected")
    elif any(token in combined for token in ("mono.dll", "mono-2.0-bdwgc.dll")):
        add("unity-mono", 3.0, "Unity Mono runtime string reference detected")
    if "monobehaviour" in combined and unity_managed:
        add("unity-mono", 2.0, "MonoBehaviour metadata/string evidence detected")

    valid_global_metadata = [item for item in global_metadata_files if item.get("status") == "ok"]
    if valid_global_metadata:
        parsed = valid_global_metadata[0]
        version = parsed.get("version")
        detail = f"global-metadata.dat detected ({parsed['path']})"
        if version is not None:
            detail += f", version {version}"
        add("unity-il2cpp", 11.0, detail)
    elif global_metadata_files:
        parsed = global_metadata_files[0]
        add("unity-il2cpp", 3.0, f"Unvalidated global-metadata.dat candidate: {parsed['path']}")
    elif "global-metadata.dat" in combined:
        add("unity-il2cpp", 2.0, "global-metadata.dat string reference detected")
    if "gameassembly.dll" in basenames:
        add("unity-il2cpp", 8.0, "GameAssembly.dll detected")
    elif "gameassembly.dll" in combined:
        add("unity-il2cpp", 4.0, "GameAssembly.dll string reference detected")
    if "libil2cpp.so" in basenames:
        add("unity-il2cpp", 8.0, "libil2cpp.so detected")
    elif any(token in combined for token in ("il2cpp_init", "il2cpp::vm")):
        add("unity-il2cpp", 5.0, "IL2CPP native runtime symbols detected")

    resources_present = "resources.assets" in basenames
    if resources_present:
        for engine in ("unity-mono", "unity-il2cpp"):
            if engine in candidates:
                add(engine, 1.5, "resources.assets detected")

    validated_assets = [item for item in asset_files if item.get("format_validated")]
    pak_count = sum(item.get("kind") == "unreal-pak" for item in validated_assets)
    uasset_count = sum(item.get("kind") == "unreal-uasset" for item in validated_assets)
    umap_count = sum(item.get("kind") == "unreal-umap" for item in validated_assets)
    if pak_count:
        add("unreal", 8.0 + min(2.0, pak_count * 0.25), f"{pak_count} validated Unreal PAK file(s) detected")
    if uasset_count:
        add("unreal", 9.0 + min(2.0, uasset_count * 0.25), f"{uasset_count} validated UAsset package(s) detected")
    if umap_count:
        add("unreal", 9.0 + min(2.0, umap_count * 0.25), f"{umap_count} validated UMap package(s) detected")
    if basenames & {"libue4.so", "libunreal.so"}:
        add("unreal", 8.0, "Unreal runtime library detected")
    elif any(token in combined for token in ("unrealengine", "ue4game", "processevent")):
        add("unreal", 4.0, "Unreal runtime string signature detected")
    package_names = list(unreal_evidence.get("package_names") or [])
    if package_names:
        add("unreal", 4.0 + min(2.0, len(package_names) * 0.1), f"{len(package_names)} Unreal package path(s) recovered")
    reflection_names = list(unreal_evidence.get("reflection_names") or [])
    if len(reflection_names) >= 2:
        add(
            "unreal",
            2.0 + min(2.0, len(reflection_names) * 0.15),
            f"{len(reflection_names)} Unreal reflection name(s) recovered",
        )

    suffix = sample.suffix.lower()
    if suffix == ".apk":
        if any(token in combined for token in ("libunity.so", "assets/bin/data", "globalgamemanagers")):
            target = "unity-il2cpp" if (valid_global_metadata or "libil2cpp.so" in basenames) else "unity-mono"
            add(target, 6.0, "Unity Android runtime/assets detected")
        if pak_count or uasset_count or umap_count or basenames & {"libue4.so", "libunreal.so"}:
            add("unreal", 6.0, "Unreal Android assets/libs detected")
    elif suffix == ".ipa":
        if any(
            token in combined
            for token in ("unityframework.framework", "data/globalgamemanagers", "global-metadata.dat")
        ):
            target = "unity-il2cpp" if valid_global_metadata else "unity-mono"
            add(target, 6.0, "Unity iOS framework/assets detected")
        if pak_count or uasset_count or umap_count:
            add("unreal", 5.5, "Unreal iOS assets detected")

    qualified = {
        "unity-mono": bool(
            validated_managed
            or mono_runtime_files
            or any("monobleedingedge" in name for name in lower_names)
            or (
                assembly_csharp_candidates
                and any(token in combined for token in ("mono.dll", "mono-2.0-bdwgc.dll"))
            )
        ),
        "unity-il2cpp": bool(
            valid_global_metadata
            or basenames & {"gameassembly.dll", "libil2cpp.so"}
            or (
                global_metadata_files
                and any(token in combined for token in ("gameassembly.dll", "il2cpp_init", "il2cpp::vm"))
            )
        ),
        "unreal": bool(
            validated_assets
            or basenames & {"libue4.so", "libunreal.so"}
        ),
    }
    ranked = sorted(candidates.values(), key=lambda item: (-float(item["score"]), str(item["engine"])))
    eligible = [item for item in ranked if qualified.get(str(item["engine"]), False)]
    if not eligible or float(eligible[0]["score"]) < _MIN_ENGINE_SCORE:
        unknown = {
            "engine": "unknown",
            "score": 0.0,
            "evidence": ["No independently corroborated engine signal reached the detection threshold"],
        }
        return [unknown, *ranked]
    return [*eligible, *[item for item in ranked if item not in eligible]]


def _candidate_confidence(score: float, runner_up_score: float) -> float:
    if score <= 0:
        return 0.0
    absolute = score / (score + 6.0)
    margin = max(0.0, min(1.0, (score - runner_up_score) / score))
    return round(absolute * (0.75 + (0.25 * margin)), 3)


def _default_strategy(engine_name: str) -> dict[str, Any]:
    mapping = {
        "unity-mono": {
            "name": "unity_mono_metadata_recovery",
            "reason": "Managed assemblies preserve high-value symbols and UI/gameplay scripts.",
        },
        "unity-il2cpp": {
            "name": "unity_il2cpp_metadata_recovery",
            "reason": "IL2CPP metadata plus GameAssembly/libil2cpp provide recoverable type/method evidence.",
        },
        "unreal": {
            "name": "unreal_asset_reflection_recovery",
            "reason": "PAK/UAsset/UMap plus reflection strings preserve engine object relationships.",
        },
        "unknown": {
            "name": "generic_engine_fingerprint",
            "reason": "No dominant engine signal found; keep evidence for later fusion.",
        },
    }
    strategy = dict(mapping.get(engine_name, mapping["unknown"]))
    strategy["engine"] = engine_name
    strategy["key"] = f"{engine_name}:{strategy['name']}"
    return strategy


def _metadata_summary(
    *,
    engine_name: str,
    names: list[str],
    strings: list[str],
    managed_files: list[dict[str, Any]],
    global_metadata_files: list[dict[str, Any]],
    unreal_evidence: Mapping[str, list[str]],
    status: str,
) -> dict[str, Any]:
    combined = "\n".join([*[name.lower() for name in names], *[value.lower() for value in strings]])
    validated_managed = [item for item in managed_files if item.get("status") == "ok"]
    managed_names = _unique_sorted([item["name"] for item in validated_managed])
    if global_metadata_files:
        primary = next((item for item in global_metadata_files if item["status"] == "ok"), global_metadata_files[0])
    else:
        primary = _empty_global_metadata()
    basenames = {Path(name.replace("\\", "/")).name.lower() for name in names}
    reflection_tokens = sorted(
        {token for token in ("uobject", "uclass", "ufunction", "blueprint", "widget") if token in combined}
    )
    unreal_metadata = bool(reflection_tokens or unreal_evidence.get("package_names"))
    metadata_available = bool(validated_managed or global_metadata_files or unreal_metadata)
    parse_incomplete = any(item.get("status") != "ok" for item in managed_files) or any(
        item.get("status") != "ok" for item in global_metadata_files
    )
    if not metadata_available:
        component_status = "unavailable"
    elif parse_incomplete or status == "partial":
        component_status = "partial"
    else:
        component_status = "ok"
    return {
        "status": component_status,
        "schema_version": 1,
        "engine": engine_name,
        "managed_assembly_count": len(managed_names),
        "managed_assembly_candidate_count": len(managed_files),
        "managed_assemblies": managed_names[:100],
        "managed_assembly_files": managed_files[:100],
        "managed_type_definition_count": sum(
            len(item.get("type_definitions") or []) for item in validated_managed
        ),
        "managed_method_definition_count": sum(
            len(item.get("method_definitions") or []) for item in validated_managed
        ),
        "managed_field_definition_count": sum(
            len(item.get("field_definitions") or []) for item in validated_managed
        ),
        "global_metadata_present": bool(global_metadata_files) or "global-metadata.dat" in combined,
        "global_metadata_file_present": bool(global_metadata_files),
        "global_metadata": primary,
        "global_metadata_header": primary,
        "global_metadata_files": global_metadata_files,
        "global_metadata_version": primary.get("version"),
        "global_metadata_tables": list(primary.get("tables") or []),
        "gameassembly_present": "gameassembly.dll" in combined,
        "gameassembly_file_present": "gameassembly.dll" in basenames,
        "mono_present": any(
            token in combined for token in ("mono.dll", "mono-2.0-bdwgc.dll", "monobleedingedge")
        ),
        "unreal_reflection_strings": reflection_tokens,
        "unreal_package_names": list(unreal_evidence.get("package_names") or [])[:100],
    }


def _asset_summary(
    names: list[str],
    unreal_evidence: Mapping[str, list[str]],
    asset_files: list[dict[str, Any]],
    *,
    status: str,
) -> dict[str, Any]:
    pak_candidates = _names_with_suffix(names, ".pak")
    uasset_candidates = _names_with_suffix(names, ".uasset")
    umap_candidates = _names_with_suffix(names, ".umap")
    validated = [item for item in asset_files if item.get("format_validated")]
    pak = _unique_sorted(item["path"] for item in validated if item.get("kind") == "unreal-pak")
    uasset = _unique_sorted(item["path"] for item in validated if item.get("kind") == "unreal-uasset")
    umap = _unique_sorted(item["path"] for item in validated if item.get("kind") == "unreal-umap")
    scenes = _unique_sorted(
        [
            name
            for name in names
            if any(token in name.lower() for token in ("scene", "prefab", "resources.assets", "globalgamemanagers"))
            or name.lower().endswith(".umap")
        ]
    )
    unity_assets = _unique_sorted(
        item["path"]
        for item in validated
        if item.get("kind") in {"unity-serialized", "unity-bundle"}
    )
    resources_assets = [
        name for name in unity_assets if Path(name.replace("\\", "/")).name.lower() == "resources.assets"
    ]
    examples = _unique_sorted([*pak, *uasset, *umap, *scenes])
    component_status = (
        "unavailable"
        if not (unity_assets or pak or uasset or umap or unreal_evidence.get("package_names"))
        else ("partial" if status == "partial" else "ok")
    )
    return {
        "status": component_status,
        "schema_version": 1,
        "pak_count": len(pak),
        "uasset_count": len(uasset),
        "umap_count": len(umap),
        "pak_candidate_count": len(pak_candidates),
        "uasset_candidate_count": len(uasset_candidates),
        "umap_candidate_count": len(umap_candidates),
        "validated_package_count": len(pak) + len(uasset) + len(umap),
        "package_files": asset_files[:200],
        "scene_like_asset_count": len(scenes),
        "asset_examples": examples[:100],
        "resources_assets_present": bool(resources_assets),
        "resources_assets_count": len(resources_assets),
        "unity_asset_count": len(unity_assets),
        "unity_assets": unity_assets[:100],
        "unreal_package_names": list(unreal_evidence.get("package_names") or [])[:100],
        "unreal_asset_names": list(unreal_evidence.get("asset_names") or [])[:100],
    }


def _symbol_summary(
    strings: Iterable[str],
    engine_name: str,
    unreal_evidence: Mapping[str, list[str]],
    *,
    managed_files: Iterable[Mapping[str, Any]],
    global_metadata_files: Iterable[Mapping[str, Any]],
    native_mapping: Mapping[str, Any],
    status: str,
) -> dict[str, Any]:
    values = _unique_strings(strings, limit=8000)
    raw_markers = {
        "mono_behaviour": _marker_clues(values, "MonoBehaviour"),
        "scriptable_object": _marker_clues(values, "ScriptableObject"),
        "ui": _ui_clues(values),
    }
    reflection_names = list(unreal_evidence.get("reflection_names") or [])
    package_names = list(unreal_evidence.get("package_names") or [])
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    native_records = [
        item for item in native_mapping.get("mappings") or [] if isinstance(item, Mapping)
    ]

    def native_attributes(method: Mapping[str, Any]) -> dict[str, Any]:
        token = str(method.get("token") or "").lower()
        image_name = str(method.get("image_name") or "").lower()
        candidates = [
            item
            for item in native_records
            if str(item.get("token") or "").lower() == token
            and (
                not image_name
                or str(item.get("image_name") or "").lower() == image_name
            )
        ]
        if len(candidates) != 1:
            return {"image_name": method.get("image_name")}
        mapped = candidates[0]
        return {
            "image_name": mapped.get("image_name"),
            "native_va": mapped.get("native_va"),
            "native_rva": mapped.get("native_rva"),
            "native_file_offset": mapped.get("file_offset"),
            "native_section": mapped.get("section"),
            "native_mapping_confidence": mapped.get("confidence"),
            "native_mapping_source": mapped.get("binary_path"),
        }

    def add_record(
        kind: str,
        name: str,
        source: str,
        *,
        confidence: float,
        **attributes: Any,
    ) -> None:
        text = str(name).strip()
        key = (kind, text, str(attributes.get("declaring_type") or ""))
        if not text or key in seen:
            return
        seen.add(key)
        records.append(
            {
                "kind": kind,
                "name": text,
                "confidence": round(confidence, 3),
                "provenance": {"source": source, "parser": attributes.pop("parser", None)},
                **{key: value for key, value in attributes.items() if value is not None},
            }
        )

    if engine_name == "unity-mono":
        for assembly in managed_files:
            if assembly.get("status") != "ok":
                continue
            source = str(assembly.get("path") or assembly.get("name") or "managed-assembly")
            for type_row in assembly.get("type_definitions") or []:
                if not isinstance(type_row, Mapping):
                    continue
                full_name = str(type_row.get("full_name") or type_row.get("name") or "")
                if not full_name or full_name == "<Module>":
                    continue
                base_type = str(type_row.get("base_type") or "") or None
                add_record(
                    "class",
                    full_name,
                    source,
                    confidence=0.98,
                    parser="ecma-335-tables",
                    token=type_row.get("token"),
                    base_type=base_type,
                    assembly=assembly.get("assembly_name"),
                )
                for method in type_row.get("methods") or []:
                    if isinstance(method, Mapping):
                        add_record(
                            "method",
                            str(method.get("name") or ""),
                            source,
                            confidence=0.97,
                            parser="ecma-335-tables",
                            token=method.get("token"),
                            declaring_type=full_name,
                            rva=method.get("rva"),
                        )
                for field in type_row.get("fields") or []:
                    if isinstance(field, Mapping):
                        add_record(
                            "field",
                            str(field.get("name") or ""),
                            source,
                            confidence=0.97,
                            parser="ecma-335-tables",
                            token=field.get("token"),
                            declaring_type=full_name,
                        )
    elif engine_name == "unity-il2cpp":
        for metadata in global_metadata_files:
            if not metadata.get("definition_layout_supported"):
                continue
            source = str(metadata.get("path") or "global-metadata.dat")
            for type_row in metadata.get("type_definitions") or []:
                if not isinstance(type_row, Mapping):
                    continue
                full_name = str(type_row.get("full_name") or type_row.get("name") or "")
                if not full_name:
                    continue
                add_record(
                    "class",
                    full_name,
                    source,
                    confidence=0.92,
                    parser="il2cpp-global-metadata-v1",
                    token=type_row.get("token"),
                )
                for method in type_row.get("methods") or []:
                    if isinstance(method, Mapping):
                        native = native_attributes(method)
                        add_record(
                            "method",
                            str(method.get("name") or ""),
                            source,
                            confidence=0.9,
                            parser="il2cpp-global-metadata-v1",
                            token=method.get("token"),
                            declaring_type=full_name,
                            **native,
                        )
                for field in type_row.get("fields") or []:
                    if isinstance(field, Mapping):
                        add_record(
                            "field",
                            str(field.get("name") or ""),
                            source,
                            confidence=0.9,
                            parser="il2cpp-global-metadata-v1",
                            token=field.get("token"),
                            declaring_type=full_name,
                        )
    elif engine_name == "unreal":
        for name in reflection_names:
            add_record(
                "reflection-api",
                name,
                "engine-content-strings",
                confidence=0.82,
                parser="unreal-reflection-marker",
            )
        for name in package_names:
            add_record(
                "package",
                name,
                "engine-content-strings",
                confidence=0.86,
                parser="unreal-package-path",
            )

    class_records = [item for item in records if item["kind"] == "class"]
    mono_behaviour = _unique_strings(
        (
            item["name"]
            for item in class_records
            if str(item.get("base_type") or "").lower().endswith("monobehaviour")
        ),
        limit=80,
    )
    scriptable_object = _unique_strings(
        (
            item["name"]
            for item in class_records
            if str(item.get("base_type") or "").lower().endswith("scriptableobject")
        ),
        limit=80,
    )
    ui_symbols = _unique_strings(
        (
            item["name"]
            for item in class_records
            if any(marker in str(item["name"]).lower() for marker in _UNITY_UI_MARKERS)
        ),
        limit=80,
    )
    recovered = _unique_strings((item["name"] for item in records), limit=240)
    component_status = "unavailable" if not recovered else ("partial" if status == "partial" else "ok")
    return {
        "status": component_status,
        "schema_version": 1,
        "recovered_symbol_count": len(recovered),
        "recovered_symbols": recovered,
        "symbol_records": records[:500],
        "type_symbols": _unique_strings((item["name"] for item in records if item["kind"] == "class"), limit=160),
        "method_symbols": _unique_strings((item["name"] for item in records if item["kind"] == "method"), limit=160),
        "field_symbols": _unique_strings((item["name"] for item in records if item["kind"] == "field"), limit=160),
        "mono_behaviour_symbols": mono_behaviour[:80],
        "monobehaviour_symbols": mono_behaviour[:80],
        "scriptable_object_symbols": scriptable_object[:80],
        "ui_symbols": ui_symbols[:80],
        "unreal_reflection_names": reflection_names[:100],
        "unreal_package_names": package_names[:100],
        "raw_string_markers": raw_markers,
    }


def _semantic_ir_fragment(
    *,
    engine_name: str,
    confidence: float,
    status: str,
    metadata: Mapping[str, Any],
    assets: Mapping[str, Any],
    symbols: Mapping[str, Any],
    native_mapping: Mapping[str, Any],
    sdk_skeleton: Mapping[str, Any],
) -> dict[str, Any]:
    if engine_name == "unknown":
        return {
            "status": "unavailable",
            "schema_version": 1,
            "engine": engine_name,
            "entities": [],
            "relations": [],
            "capabilities": [],
            "summary": {
                "entity_count": 0,
                "relation_count": 0,
                "resource_count": 0,
                "ui_control_count": 0,
                "native_mapped_method_count": 0,
                "sdk_declaration_count": 0,
            },
            "artifacts": [],
        }

    entities: dict[str, dict[str, Any]] = {}
    relations: dict[str, dict[str, Any]] = {}

    def add_entity(kind: str, name: str, source: str, attributes: Mapping[str, Any], entity_confidence: float) -> str:
        entity_id = _stable_id(
            "engine-entity",
            kind,
            name,
            attributes.get("resource_kind"),
            attributes.get("declaring_type"),
            attributes.get("token"),
        )
        if entity_id not in entities:
            entities[entity_id] = {
                "id": entity_id,
                "kind": kind,
                "name": name,
                "confidence": round(max(0.0, min(1.0, entity_confidence)), 3),
                "sources": [source],
                "evidence": [{"source": source}],
                "attributes": dict(attributes),
            }
        return entity_id

    def relate(source_id: str, target_id: str, relation_type: str, source: str) -> None:
        relation_id = _stable_id("engine-relation", source_id, target_id, relation_type)
        relations[relation_id] = {
            "id": relation_id,
            "type": relation_type,
            "source": source_id,
            "target": target_id,
            "confidence": 0.85,
            "evidence": [{"source": source}],
        }

    root_id = add_entity(
        "resource",
        engine_name,
        "engine.fingerprint",
        {"resource_kind": "engine", "engine": engine_name},
        confidence,
    )
    for assembly in metadata.get("managed_assembly_files") or []:
        if not isinstance(assembly, Mapping):
            continue
        name = str(assembly.get("name") or "").strip()
        if not name:
            continue
        entity_id = add_entity(
            "resource",
            name,
            "engine.metadata.managed_assembly_files",
            {
                "resource_kind": "managed-assembly",
                "path": assembly.get("path"),
                "dotnet_metadata_present": bool(assembly.get("dotnet_metadata_present")),
            },
            0.9,
        )
        relate(root_id, entity_id, "contains", "engine.metadata.managed_assembly_files")

    for asset_name in assets.get("asset_examples") or []:
        name = str(asset_name).strip()
        if not name:
            continue
        entity_id = add_entity(
            "resource",
            name,
            "engine.assets.asset_examples",
            {"resource_kind": "engine-asset"},
            0.85,
        )
        relate(root_id, entity_id, "contains", "engine.assets.asset_examples")

    ui_names = {str(item) for item in symbols.get("ui_symbols") or []}
    symbol_records = [
        item for item in symbols.get("symbol_records") or [] if isinstance(item, Mapping)
    ]
    class_entities: dict[str, str] = {}
    for record in symbol_records:
        if record.get("kind") != "class":
            continue
        name = str(record.get("name") or "").strip()
        if not name:
            continue
        source = str((record.get("provenance") or {}).get("source") or "engine.symbols")
        kind = "ui_control" if name in ui_names else "class"
        attributes = {
            key: record.get(key)
            for key in ("token", "base_type", "assembly")
            if record.get(key) is not None
        }
        attributes.update({"resource_kind": "engine-symbol", "engine": engine_name})
        entity_id = add_entity(
            kind,
            name,
            source,
            attributes,
            float(record.get("confidence") or 0.7),
        )
        class_entities[name] = entity_id
        relate(root_id, entity_id, "declares", source)

    for record in symbol_records:
        record_kind = str(record.get("kind") or "")
        if record_kind == "class":
            continue
        name = str(record.get("name") or "").strip()
        if not name:
            continue
        source = str((record.get("provenance") or {}).get("source") or "engine.symbols")
        kind = {
            "method": "function",
            "field": "field",
            "package": "resource",
            "reflection-api": "resource",
        }.get(record_kind, "resource")
        attributes = {
            key: record.get(key)
            for key in (
                "token",
                "declaring_type",
                "rva",
                "image_name",
                "native_va",
                "native_rva",
                "native_file_offset",
                "native_section",
                "native_mapping_confidence",
            )
            if record.get(key) is not None
        }
        attributes.update({"resource_kind": f"engine-{record_kind or 'symbol'}", "engine": engine_name})
        entity_id = add_entity(
            kind,
            name,
            source,
            attributes,
            float(record.get("confidence") or 0.7),
        )
        mapping_source = str(record.get("native_mapping_source") or "").strip()
        if mapping_source:
            entities[entity_id]["sources"].append(mapping_source)
            entities[entity_id]["evidence"].append(
                {
                    "source": mapping_source,
                    "kind": "il2cpp-native-method-pointer",
                    "confidence": record.get("native_mapping_confidence"),
                }
            )
        declaring_id = class_entities.get(str(record.get("declaring_type") or ""))
        relate(declaring_id or root_id, entity_id, "declares", source)

    if not symbol_records:
        for symbol_name in symbols.get("recovered_symbols") or []:
            name = str(symbol_name).strip()
            if not name:
                continue
            entity_id = add_entity(
                "resource",
                name,
                "engine.symbols.recovered_symbols",
                {"resource_kind": "unstructured-engine-symbol", "engine": engine_name},
                0.5,
            )
            relate(root_id, entity_id, "declares", "engine.symbols.recovered_symbols")

    entity_list = sorted(entities.values(), key=lambda item: item["id"])
    relation_list = sorted(relations.values(), key=lambda item: item["id"])
    resource_count = sum(item["kind"] == "resource" for item in entity_list)
    ui_control_count = sum(item["kind"] == "ui_control" for item in entity_list)
    source_statuses = {
        str(metadata.get("status") or "unavailable"),
        str(assets.get("status") or "unavailable"),
        str(symbols.get("status") or "unavailable"),
    }
    fragment_status = (
        "partial"
        if status == "partial" or "partial" in source_statuses or source_statuses == {"unavailable"}
        else "ok"
    )
    capabilities: list[dict[str, Any]] = []
    if native_mapping.get("status") != "unavailable":
        capabilities.append(
            {
                "name": "il2cpp-native-mapping",
                "status": native_mapping.get("status"),
                "confidence": native_mapping.get("confidence", 0.0),
                "mapped_method_count": native_mapping.get("mapped_method_count", 0),
                "eligible_method_count": native_mapping.get("eligible_method_count", 0),
                "provenance": native_mapping.get("provenance", {}),
            }
        )
    if sdk_skeleton.get("status") != "unavailable":
        capabilities.append(
            {
                "name": "unreal-static-sdk-skeleton",
                "status": sdk_skeleton.get("status"),
                "confidence": sdk_skeleton.get("confidence", 0.0),
                "declaration_count": sdk_skeleton.get("declaration_count", 0),
                "runtime_uobject_enumeration": False,
                "provenance": sdk_skeleton.get("provenance", {}),
            }
        )
    return {
        "status": fragment_status,
        "schema_version": 1,
        "engine": engine_name,
        "entities": entity_list,
        "relations": relation_list,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entity_list),
            "relation_count": len(relation_list),
            "resource_count": resource_count,
            "ui_control_count": ui_control_count,
            "native_mapped_method_count": int(native_mapping.get("mapped_method_count") or 0),
            "sdk_declaration_count": int(sdk_skeleton.get("declaration_count") or 0),
        },
        "artifacts": [],
    }


def _engine_asset_inventory(
    refs: list[_EvidenceFile],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for ref in sorted(_dedupe_evidence(refs), key=lambda item: item.name.lower())[:200]:
        record, error = _inspect_engine_asset(ref)
        records.append(record)
        if error is not None:
            diagnostics.append(_diagnostic("engine-asset", "partial", error, ref.display_path))
    return records, diagnostics


def _inspect_engine_asset(ref: _EvidenceFile) -> tuple[dict[str, Any], str | None]:
    suffix = Path(ref.name.replace("\\", "/")).suffix.lower()
    basename = ref.basename.lower()
    prefix, error = _read_evidence_segment(ref, limit=4096)
    base: dict[str, Any] = {
        "status": "unavailable",
        "schema_version": 1,
        "name": ref.basename,
        "path": ref.display_path,
        "size": ref.size,
        "kind": "unknown",
        "format_validated": False,
        "magic": None,
        "version": None,
        "validation_error": None,
    }
    if error is not None:
        base["validation_error"] = error
        return base, error

    if suffix in {".uasset", ".umap"}:
        base["kind"] = "unreal-uasset" if suffix == ".uasset" else "unreal-umap"
        if len(prefix) < 20:
            base["validation_error"] = "Unreal package header is truncated"
            return base, None
        magic = struct.unpack_from("<I", prefix, 0)[0]
        base["magic"] = f"0x{magic:08x}"
        legacy_file_version, legacy_ue3_version, file_version_ue4, licensee_version = (
            struct.unpack_from("<iiii", prefix, 4)
        )
        base.update(
            {
                "legacy_file_version": legacy_file_version,
                "legacy_ue3_version": legacy_ue3_version,
                "file_version_ue4": file_version_ue4,
                "licensee_version": licensee_version,
                "version": file_version_ue4,
            }
        )
        summary_plausible = (
            -20 <= legacy_file_version <= 0
            and 0 <= legacy_ue3_version <= 100_000
            and 0 <= file_version_ue4 <= 100_000
            and 0 <= licensee_version <= 100_000
            and (legacy_ue3_version > 0 or file_version_ue4 > 0)
        )
        base["format_validated"] = magic == _UNREAL_PACKAGE_MAGIC and summary_plausible
        base["status"] = "ok" if base["format_validated"] else "unavailable"
        if magic != _UNREAL_PACKAGE_MAGIC:
            base["validation_error"] = "Unreal package magic is missing"
        elif not summary_plausible:
            base["validation_error"] = "Unreal package summary version fields are inconsistent"
        return base, None

    if suffix == ".pak":
        base["kind"] = "unreal-pak"
        tail, tail_error = _read_evidence_tail(ref, limit=1024)
        if tail_error is not None:
            base["validation_error"] = tail_error
            return base, None
        marker = struct.pack("<I", _UNREAL_PAK_MAGIC)
        marker_offset = tail.rfind(marker)
        if marker_offset < 0:
            base["validation_error"] = "Unreal PAK footer magic is missing"
            return base, None
        base["magic"] = f"0x{_UNREAL_PAK_MAGIC:08x}"
        footer_valid = marker_offset + 44 <= len(tail) and ref.size is not None
        version = None
        if marker_offset + 8 <= len(tail):
            version = struct.unpack_from("<I", tail, marker_offset + 4)[0]
            base["version"] = version
        footer_valid = footer_valid and version is not None and 1 <= version <= 20
        if marker_offset + 44 <= len(tail):
            index_offset, index_size = struct.unpack_from("<QQ", tail, marker_offset + 8)
            index_hash = tail[marker_offset + 24 : marker_offset + 44]
            tail_start = int(ref.size or len(tail)) - len(tail)
            footer_offset = tail_start + marker_offset
            base.update(
                {
                    "footer_offset": footer_offset,
                    "index_offset": index_offset,
                    "index_size": index_size,
                    "index_hash": index_hash.hex(),
                    "index_hash_validated": None,
                }
            )
            footer_valid = footer_valid and (
                index_offset <= footer_offset
                and index_size <= footer_offset - index_offset
            )
            if footer_valid and index_size <= _MAX_UNREAL_PAK_INDEX_BYTES:
                index_data, index_error = _read_evidence_segment(
                    ref,
                    limit=int(index_size),
                    offset=int(index_offset),
                )
                if index_error is None and len(index_data) == index_size:
                    hash_matches = hashlib.sha1(index_data).digest() == index_hash
                    base["index_hash_validated"] = hash_matches
                    footer_valid = hash_matches
                else:
                    base["index_hash_validated"] = False
                    footer_valid = False
        base["format_validated"] = footer_valid
        base["status"] = "ok" if footer_valid else "partial"
        if not footer_valid:
            base["validation_error"] = "Unreal PAK footer fields are inconsistent"
        return base, None

    if basename in {"resources.assets", "globalgamemanagers"} or suffix == ".assets":
        if prefix.startswith((b"UnityFS", b"UnityRaw", b"UnityWeb")):
            base["kind"] = "unity-bundle"
            base.update(_parse_unity_bundle_header(prefix, ref.size))
            return base, None
        serialized = _parse_unity_serialized_header(prefix, ref.size)
        base["kind"] = "unity-serialized"
        base.update(serialized)
        return base, None

    return base, None


def _parse_unity_bundle_header(data: bytes, file_size: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unavailable",
        "format_validated": False,
        "magic": None,
        "version": None,
        "validation_error": "Unity bundle header is missing",
    }
    try:
        signature_end = data.find(b"\x00", 0, 16)
        if signature_end < 0:
            raise ValueError("Unity bundle signature is not null terminated")
        signature = data[:signature_end].decode("ascii", errors="strict")
        result["magic"] = signature
        if signature != "UnityFS":
            raise ValueError(f"Unity bundle signature {signature!r} is not supported")
        cursor = signature_end + 1
        if cursor + 4 > len(data):
            raise ValueError("UnityFS format version is truncated")
        version = struct.unpack_from(">I", data, cursor)[0]
        cursor += 4

        def read_cstring(label: str) -> str:
            nonlocal cursor
            end = data.find(b"\x00", cursor, min(len(data), cursor + 256))
            if end < 0:
                raise ValueError(f"UnityFS {label} is not null terminated")
            value = data[cursor:end].decode("utf-8", errors="replace")
            cursor = end + 1
            return value

        unity_version = read_cstring("Unity version")
        generator_version = read_cstring("generator version")
        if cursor + 20 > len(data):
            raise ValueError("UnityFS size/block-info header is truncated")
        declared_size, compressed_size, uncompressed_size, flags = struct.unpack_from(
            ">QIII", data, cursor
        )
        plausible = (
            6 <= version <= 20
            and bool(unity_version)
            and bool(generator_version)
            and declared_size >= cursor + 20
            and compressed_size > 0
            and uncompressed_size > 0
        )
        if file_size is not None:
            plausible = plausible and declared_size == file_size
        result.update(
            {
                "status": "ok" if plausible else "unavailable",
                "format_validated": plausible,
                "version": version,
                "unity_version": unity_version,
                "generator_version": generator_version,
                "declared_file_size": declared_size,
                "compressed_blocks_info_size": compressed_size,
                "uncompressed_blocks_info_size": uncompressed_size,
                "flags": f"0x{flags:08x}",
                "validation_error": None if plausible else "UnityFS header fields are inconsistent",
            }
        )
    except (UnicodeDecodeError, ValueError, struct.error) as exc:
        result["validation_error"] = str(exc)
    return result


def _parse_unity_serialized_header(data: bytes, file_size: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unavailable",
        "format_validated": False,
        "magic": None,
        "version": None,
        "validation_error": "Unity serialized-file header is missing",
    }
    if len(data) < 20:
        return result
    metadata_size, declared_size, version, data_offset = struct.unpack_from(">IIII", data, 0)
    header_size = 20
    if version >= 22:
        if len(data) < 48:
            result["validation_error"] = "Unity serialized-file extended header is truncated"
            return result
        metadata_size = struct.unpack_from(">I", data, 20)[0]
        declared_size, data_offset, _ = struct.unpack_from(">QQQ", data, 24)
        header_size = 48
    plausible = (
        1 <= version <= 50
        and metadata_size > 0
        and declared_size >= header_size + metadata_size
        and data_offset >= header_size + metadata_size
        and data_offset <= declared_size
        and data[16] in {0, 1}
    )
    if file_size is not None:
        plausible = plausible and declared_size == file_size
    result.update(
        {
            "status": "ok" if plausible else "unavailable",
            "format_validated": plausible,
            "version": version,
            "metadata_size": metadata_size,
            "declared_file_size": declared_size,
            "data_offset": data_offset,
            "endianness": data[16],
            "header_size": header_size,
            "validation_error": None if plausible else "Unity serialized-file header fields are inconsistent",
        }
    )
    return result


def _managed_assembly_inventory(
    refs: list[_EvidenceFile],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    strings: list[str] = []
    diagnostics: list[dict[str, Any]] = []
    for ref in sorted(_dedupe_evidence(refs), key=lambda item: item.name.lower())[:100]:
        header_data, error = _read_evidence_segment(ref, limit=1024 * 1024)
        if error is not None:
            records.append(
                {
                    "status": "unavailable",
                    "name": ref.basename,
                    "path": ref.display_path,
                    "size": ref.size,
                    "dotnet_metadata_present": False,
                    "dotnet_metadata_signature_present": False,
                    "cli_header_present": False,
                    "assembly_name": Path(ref.basename).stem,
                    "assembly_name_source": "filename",
                    "metadata": {"status": "unavailable", "error": error},
                }
            )
            diagnostics.append(_diagnostic("managed-assembly", "partial", error, ref.display_path))
            continue

        pe = _locate_cli_metadata(header_data, ref.size)
        if pe["status"] != "ok":
            parser_status = str(pe["status"])
            records.append(
                {
                    "status": parser_status,
                    "name": ref.basename,
                    "path": ref.display_path,
                    "size": ref.size,
                    "dotnet_metadata_present": False,
                    "dotnet_metadata_signature_present": False,
                    "cli_header_present": bool(pe.get("cli_header_present")),
                    "assembly_name": Path(ref.basename).stem,
                    "assembly_name_source": "filename",
                    "runtime_version": None,
                    "metadata_streams": [],
                    "type_definitions": [],
                    "method_definitions": [],
                    "field_definitions": [],
                    "pe": pe,
                    "metadata": {"status": parser_status, "error": pe.get("error"), "pe": pe},
                }
            )
            diagnostics.append(
                _diagnostic(
                    "managed-assembly",
                    "partial",
                    str(pe.get("error") or "PE/CLI metadata directory validation failed"),
                    ref.display_path,
                )
            )
            continue

        metadata_size = min(int(pe["metadata_size"]), _MAX_MANAGED_METADATA_BYTES)
        metadata_data, metadata_error = _read_evidence_segment(
            ref,
            limit=metadata_size,
            offset=int(pe["metadata_file_offset"]),
        )
        if metadata_error is not None:
            dotnet: dict[str, Any] = {
                "status": "partial",
                "present": False,
                "error": metadata_error,
                "errors": [metadata_error],
            }
        else:
            dotnet = _parse_dotnet_metadata_root(metadata_data)
            strings.extend(_extract_strings(metadata_data))
            if int(pe["metadata_size"]) > _MAX_MANAGED_METADATA_BYTES:
                truncation = (
                    f"CLI metadata scan capped at {_MAX_MANAGED_METADATA_BYTES} "
                    f"of {pe['metadata_size']} bytes"
                )
                dotnet["status"] = "partial"
                dotnet.setdefault("errors", []).append(truncation)
                dotnet["error"] = "; ".join(_unique_strings(dotnet["errors"], limit=20))
        dotnet["pe"] = pe
        parser_status = str(dotnet.get("status") or "partial")
        if parser_status not in {"ok", "partial", "unavailable"}:
            parser_status = "partial"
        metadata_valid = parser_status == "ok"
        records.append(
            {
                "status": parser_status,
                "name": ref.basename,
                "path": ref.display_path,
                "size": ref.size,
                "dotnet_metadata_present": metadata_valid,
                "dotnet_metadata_signature_present": bool(dotnet.get("present")),
                "cli_header_present": True,
                "assembly_name": str(dotnet.get("assembly_name") or Path(ref.basename).stem),
                "assembly_name_source": str(dotnet.get("assembly_name_source") or "filename"),
                "runtime_version": dotnet.get("runtime_version"),
                "metadata_streams": list(dotnet.get("streams") or []),
                "type_definitions": list(dotnet.get("type_definitions") or []),
                "method_definitions": list(dotnet.get("method_definitions") or []),
                "field_definitions": list(dotnet.get("field_definitions") or []),
                "pe": pe,
                "metadata": dotnet,
            }
        )
        if not metadata_valid:
            diagnostics.append(
                _diagnostic(
                    "managed-assembly",
                    "partial",
                    str(dotnet.get("error") or ".NET metadata parsing incomplete"),
                    ref.display_path,
                )
            )
    return records, _unique_strings(strings, limit=6000), diagnostics


def _locate_cli_metadata(data: bytes, file_size: int | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unavailable",
        "schema_version": 1,
        "pe_valid": False,
        "cli_header_present": False,
        "machine": None,
        "pe_format": None,
        "cli_rva": None,
        "cli_size": None,
        "cli_file_offset": None,
        "metadata_rva": None,
        "metadata_size": None,
        "metadata_file_offset": None,
        "flags": None,
        "entry_point_token": None,
        "error": None,
    }
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("DOS MZ header is missing")
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset < 64 or pe_offset + 24 > len(data):
            raise ValueError("PE header offset is outside the scan window")
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise ValueError("PE signature is missing")
        result["pe_valid"] = True
        machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", data, pe_offset + 4
        )
        if section_count == 0 or section_count > 96:
            raise ValueError(f"implausible PE section count: {section_count}")
        optional_offset = pe_offset + 24
        optional_end = optional_offset + optional_size
        if optional_size < 112 or optional_end > len(data):
            raise ValueError("PE optional header is truncated")
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        if magic == 0x10B:
            directory_count_offset = 92
            directory_offset = 96
            pe_format = "pe32"
        elif magic == 0x20B:
            directory_count_offset = 108
            directory_offset = 112
            pe_format = "pe32+"
        else:
            raise ValueError(f"unsupported PE optional-header magic: 0x{magic:04x}")
        if directory_count_offset + 4 > optional_size:
            raise ValueError("PE data-directory count is truncated")
        directory_count = struct.unpack_from("<I", data, optional_offset + directory_count_offset)[0]
        if directory_count <= 14 or directory_offset + (15 * 8) > optional_size:
            raise ValueError("PE COM descriptor data directory is absent")
        cli_rva, cli_size = struct.unpack_from("<II", data, optional_offset + directory_offset + (14 * 8))
        if cli_rva == 0 or cli_size < 24:
            raise ValueError("PE COM descriptor data directory is empty")

        section_offset = optional_end
        section_end = section_offset + (section_count * 40)
        if section_end > len(data):
            raise ValueError("PE section table is truncated")
        sections: list[dict[str, int | str]] = []
        for index in range(section_count):
            cursor = section_offset + (index * 40)
            name = data[cursor : cursor + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, cursor + 8)
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_offset": raw_offset,
                }
            )

        cli_offset = _pe_rva_to_offset(cli_rva, sections, file_size)
        if cli_offset is None:
            raise ValueError(f"COM descriptor RVA 0x{cli_rva:x} does not map to a PE section")
        if cli_offset + 24 > len(data):
            raise ValueError("COM descriptor header lies outside the scan window")
        result["cli_header_present"] = True
        cb, major, minor, metadata_rva, metadata_size, flags, entry_point = struct.unpack_from(
            "<IHHIIII", data, cli_offset
        )
        if cb < 24 or major == 0 or metadata_rva == 0 or metadata_size < 20:
            raise ValueError("COM descriptor header fields are inconsistent")
        metadata_offset = _pe_rva_to_offset(metadata_rva, sections, file_size)
        if metadata_offset is None:
            raise ValueError(f"CLI metadata RVA 0x{metadata_rva:x} does not map to a PE section")
        if file_size is not None and (
            metadata_offset > file_size or metadata_size > file_size - metadata_offset
        ):
            raise ValueError("CLI metadata range is outside the assembly file")
        result.update(
            {
                "status": "ok",
                "pe_valid": True,
                "cli_header_present": True,
                "machine": f"0x{machine:04x}",
                "pe_format": pe_format,
                "cli_rva": cli_rva,
                "cli_size": cli_size,
                "cli_file_offset": cli_offset,
                "runtime_version": {"major": major, "minor": minor},
                "metadata_rva": metadata_rva,
                "metadata_size": metadata_size,
                "metadata_file_offset": metadata_offset,
                "flags": f"0x{flags:08x}",
                "entry_point_token": f"0x{entry_point:08x}",
            }
        )
    except (ValueError, struct.error) as exc:
        result["status"] = "partial" if result["pe_valid"] or result["cli_header_present"] else "unavailable"
        result["error"] = str(exc)
    return result


def _pe_rva_to_offset(
    rva: int,
    sections: Iterable[Mapping[str, Any]],
    file_size: int | None,
) -> int | None:
    for section in sections:
        virtual_address = int(section["virtual_address"])
        raw_size = int(section["raw_size"])
        virtual_size = int(section["virtual_size"])
        span = max(raw_size, virtual_size)
        if not (virtual_address <= rva < virtual_address + span):
            continue
        delta = rva - virtual_address
        if delta >= raw_size:
            return None
        offset = int(section["raw_offset"]) + delta
        if file_size is not None and offset >= file_size:
            return None
        return offset
    return None


def _parse_dotnet_metadata_root(data: bytes) -> dict[str, Any]:
    marker = 0 if data.startswith(b"BSJB") else -1
    if marker < 0:
        return {
            "status": "unavailable",
            "present": False,
            "runtime_version": None,
            "streams": [],
            "assembly_name": None,
            "assembly_name_source": None,
            "tables_header": None,
            "error": ".NET metadata signature BSJB not found at the CLI metadata RVA",
        }
    result: dict[str, Any] = {
        "status": "partial",
        "present": True,
        "offset": marker,
        "runtime_version": None,
        "streams": [],
        "assembly_name": None,
        "assembly_name_source": None,
        "tables_header": None,
    }
    try:
        if marker + 20 > len(data):
            raise ValueError("truncated .NET metadata root")
        major, minor = struct.unpack_from("<HH", data, marker + 4)
        reserved = struct.unpack_from("<I", data, marker + 8)[0]
        version_length = struct.unpack_from("<I", data, marker + 12)[0]
        if version_length <= 0 or version_length > 512:
            raise ValueError(f"invalid .NET metadata version length: {version_length}")
        version_start = marker + 16
        version_end = version_start + version_length
        if version_end > len(data):
            raise ValueError("truncated .NET metadata version string")
        runtime_version = data[version_start:version_end].rstrip(b"\x00").decode("utf-8", errors="replace")
        if not runtime_version:
            raise ValueError("empty .NET metadata runtime version")
        cursor = marker + _align(version_end - marker, 4)
        if cursor + 4 > len(data):
            raise ValueError("truncated .NET metadata stream header")
        flags, stream_count = struct.unpack_from("<HH", data, cursor)
        cursor += 4
        if stream_count == 0 or stream_count > 64:
            raise ValueError(f"implausible .NET metadata stream count: {stream_count}")
        stream_records: list[dict[str, Any]] = []
        strings_heap: bytes | None = None
        tables_stream: bytes | None = None
        stream_names: set[str] = set()
        issues: list[str] = []
        if reserved != 0:
            issues.append(f"invalid .NET metadata reserved value: {reserved}")
        for _ in range(stream_count):
            if cursor + 8 > len(data):
                raise ValueError("truncated .NET metadata stream record")
            offset, size = struct.unpack_from("<II", data, cursor)
            name_start = cursor + 8
            name_end = data.find(b"\x00", name_start, min(len(data), name_start + 32))
            if name_end < 0:
                raise ValueError("unterminated .NET metadata stream name")
            stream_name = data[name_start:name_end].decode("ascii", errors="replace")
            if not stream_name.startswith("#"):
                issues.append(f"invalid .NET metadata stream name: {stream_name!r}")
            if stream_name in stream_names:
                issues.append(f"duplicate .NET metadata stream: {stream_name}")
            stream_names.add(stream_name)
            absolute_offset = marker + offset
            in_bounds = absolute_offset <= len(data) and size <= len(data) - absolute_offset
            stream_records.append({"name": stream_name, "offset": offset, "size": size, "in_bounds": in_bounds})
            if not in_bounds:
                issues.append(
                    f".NET metadata stream {stream_name or '<unnamed>'} is outside the scan window: "
                    f"offset={offset}, size={size}"
                )
            if stream_name == "#Strings" and in_bounds:
                strings_heap = data[absolute_offset : absolute_offset + size]
            if stream_name in {"#~", "#-"} and in_bounds:
                tables_stream = data[absolute_offset : absolute_offset + size]
            cursor = marker + _align(name_end + 1 - marker, 4)

        metadata_header_size = cursor - marker
        for stream in stream_records:
            if stream["size"] and stream["offset"] < metadata_header_size:
                issues.append(
                    f".NET metadata stream {stream['name']} overlaps the metadata root header: "
                    f"offset={stream['offset']}, header_size={metadata_header_size}"
                )

        tables_header = (
            _parse_dotnet_tables_stream(tables_stream, strings_heap)
            if tables_stream is not None
            else None
        )
        if tables_header is None:
            issues.append(".NET metadata tables stream (#~ or #-) not found")
        elif tables_header["status"] != "ok":
            issues.extend(str(item) for item in tables_header.get("errors") or [])

        assembly_name = None
        string_heap_preview: list[str] = []
        if strings_heap:
            candidates = _extract_null_strings(strings_heap)
            string_heap_preview = candidates[:40]
        if tables_header is not None:
            assembly_name = tables_header.get("assembly_name")
        issues = _unique_strings(issues, limit=20)
        result.update(
            {
                "status": "ok" if not issues else "partial",
                "metadata_version": {"major": major, "minor": minor},
                "reserved": reserved,
                "runtime_version": runtime_version,
                "flags": flags,
                "stream_count": stream_count,
                "header_size": metadata_header_size,
                "streams": stream_records,
                "assembly_name": assembly_name,
                "assembly_name_source": "assembly-table" if assembly_name else None,
                "string_heap_preview": string_heap_preview,
                "tables_header": tables_header,
                "type_definitions": list((tables_header or {}).get("type_definitions") or []),
                "method_definitions": list((tables_header or {}).get("method_definitions") or []),
                "field_definitions": list((tables_header or {}).get("field_definitions") or []),
                "errors": issues,
                "error": "; ".join(issues) if issues else None,
            }
        )
    except (ValueError, struct.error) as exc:
        result["error"] = str(exc)
        result["errors"] = [str(exc)]
    return result


def _parse_dotnet_tables_stream(data: bytes, strings_heap: bytes | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "partial",
        "major": None,
        "minor": None,
        "heap_sizes": None,
        "valid_mask": None,
        "sorted_mask": None,
        "row_counts": [],
        "table_layouts": [],
        "row_data_offset": None,
        "assembly_name": None,
        "type_definitions": [],
        "method_definitions": [],
        "field_definitions": [],
        "errors": [],
        "error": None,
    }
    if len(data) < 24:
        result["errors"] = [".NET metadata tables stream header is truncated"]
        result["error"] = result["errors"][0]
        return result

    reserved, major, minor, heap_sizes, reserved_byte = struct.unpack_from("<IBBBB", data, 0)
    valid_mask, sorted_mask = struct.unpack_from("<QQ", data, 8)
    errors: list[str] = []
    if reserved != 0:
        errors.append(f"invalid .NET tables stream reserved value: {reserved}")
    if reserved_byte != 1:
        errors.append(f"invalid .NET tables stream reserved byte: {reserved_byte}")
    if valid_mask == 0:
        errors.append(".NET metadata tables stream declares no tables")

    cursor = 24
    row_counts: list[dict[str, int]] = []
    for table_index in range(64):
        if not valid_mask & (1 << table_index):
            continue
        if cursor + 4 > len(data):
            errors.append(".NET metadata tables stream row counts are truncated")
            break
        row_count = struct.unpack_from("<I", data, cursor)[0]
        row_counts.append({"index": table_index, "count": row_count})
        cursor += 4

    if row_counts and not any(item["count"] for item in row_counts):
        errors.append(".NET metadata tables stream contains no rows")
    if any(item["count"] for item in row_counts) and cursor >= len(data):
        errors.append(".NET metadata tables stream row data is missing")

    row_count_map = {item["index"]: item["count"] for item in row_counts}
    table_layouts: list[dict[str, Any]] = []
    row_cursor = cursor
    for table_index in range(64):
        row_count = row_count_map.get(table_index, 0)
        if row_count == 0:
            continue
        schema = _DOTNET_TABLE_SCHEMAS.get(table_index)
        if schema is None:
            errors.append(f"unsupported .NET metadata table index: {table_index}")
            break
        row_size = sum(
            _dotnet_column_size(column, row_count_map, heap_sizes)
            for column in schema
        )
        byte_count = row_size * row_count
        in_bounds = row_cursor <= len(data) and byte_count <= len(data) - row_cursor
        table_layouts.append(
            {
                "index": table_index,
                "name": _DOTNET_TABLE_NAMES[table_index],
                "row_count": row_count,
                "row_size": row_size,
                "offset": row_cursor,
                "size": byte_count,
                "in_bounds": in_bounds,
            }
        )
        if not in_bounds:
            errors.append(
                f".NET metadata table {_DOTNET_TABLE_NAMES[table_index]} row data is truncated"
            )
            break
        row_cursor += byte_count

    parsed_rows: dict[str, Any] = {
        "assembly_name": None,
        "type_definitions": [],
        "method_definitions": [],
        "field_definitions": [],
        "errors": [],
    }
    if strings_heap is not None and table_layouts:
        parsed_rows = _parse_dotnet_named_rows(
            data,
            table_layouts,
            row_count_map,
            heap_sizes,
            strings_heap,
        )
        errors.extend(str(item) for item in parsed_rows.get("errors") or [])

    errors = _unique_strings(errors, limit=20)
    result.update(
        {
            "status": "ok" if not errors else "partial",
            "major": major,
            "minor": minor,
            "heap_sizes": heap_sizes,
            "valid_mask": f"0x{valid_mask:016x}",
            "sorted_mask": f"0x{sorted_mask:016x}",
            "row_counts": row_counts,
            "table_layouts": table_layouts,
            "row_data_offset": cursor,
            "assembly_name": parsed_rows.get("assembly_name"),
            "type_definitions": list(parsed_rows.get("type_definitions") or []),
            "method_definitions": list(parsed_rows.get("method_definitions") or []),
            "field_definitions": list(parsed_rows.get("field_definitions") or []),
            "errors": errors,
            "error": "; ".join(errors) if errors else None,
        }
    )
    return result


def _dotnet_column_size(column: str, row_counts: Mapping[int, int], heap_sizes: int) -> int:
    if column == "u2":
        return 2
    if column == "u4":
        return 4
    if column == "string":
        return 4 if heap_sizes & 0x01 else 2
    if column == "guid":
        return 4 if heap_sizes & 0x02 else 2
    if column == "blob":
        return 4 if heap_sizes & 0x04 else 2
    if column.startswith("table:"):
        table_index = int(column.split(":", 1)[1])
        return 4 if int(row_counts.get(table_index, 0)) >= 65536 else 2
    if column.startswith("coded:"):
        coded_name = column.split(":", 1)[1]
        tag_bits, tables = _DOTNET_CODED_INDEXES[coded_name]
        threshold = 1 << (16 - tag_bits)
        return 4 if max((int(row_counts.get(index, 0)) for index in tables), default=0) >= threshold else 2
    raise ValueError(f"unsupported .NET metadata column type: {column}")


def _read_sized_uint(data: bytes, offset: int, size: int) -> tuple[int, int]:
    if size not in {2, 4} or offset + size > len(data):
        raise ValueError("metadata index lies outside its table row")
    if size == 2:
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _read_heap_string(heap: bytes, index: int) -> str | None:
    if index == 0:
        return ""
    if index < 0 or index >= len(heap):
        return None
    end = heap.find(b"\x00", index)
    if end < 0:
        return None
    value = heap[index:end].decode("utf-8", errors="replace")
    return value if value and all(char.isprintable() for char in value) else None


def _parse_dotnet_named_rows(
    data: bytes,
    layouts: Iterable[Mapping[str, Any]],
    row_counts: Mapping[int, int],
    heap_sizes: int,
    strings_heap: bytes,
) -> dict[str, Any]:
    layout_by_index = {int(item["index"]): item for item in layouts if item.get("in_bounds")}
    errors: list[str] = []

    def string_index(cursor: int) -> tuple[str | None, int]:
        size = _dotnet_column_size("string", row_counts, heap_sizes)
        index, cursor = _read_sized_uint(data, cursor, size)
        return _read_heap_string(strings_heap, index), cursor

    type_refs: dict[int, str] = {}
    layout = layout_by_index.get(1)
    if layout:
        cursor = int(layout["offset"])
        resolution_size = _dotnet_column_size("coded:ResolutionScope", row_counts, heap_sizes)
        for row_id in range(1, int(layout["row_count"]) + 1):
            _, cursor = _read_sized_uint(data, cursor, resolution_size)
            name, cursor = string_index(cursor)
            namespace, cursor = string_index(cursor)
            if name:
                type_refs[row_id] = f"{namespace}.{name}" if namespace else name

    field_rows: list[dict[str, Any]] = []
    layout = layout_by_index.get(4)
    if layout:
        cursor = int(layout["offset"])
        blob_size = _dotnet_column_size("blob", row_counts, heap_sizes)
        for row_id in range(1, int(layout["row_count"]) + 1):
            flags = struct.unpack_from("<H", data, cursor)[0]
            cursor += 2
            name, cursor = string_index(cursor)
            _, cursor = _read_sized_uint(data, cursor, blob_size)
            if name:
                field_rows.append({"row_id": row_id, "token": f"0x04{row_id:06x}", "name": name, "flags": flags})

    method_rows: list[dict[str, Any]] = []
    layout = layout_by_index.get(6)
    if layout:
        cursor = int(layout["offset"])
        blob_size = _dotnet_column_size("blob", row_counts, heap_sizes)
        param_size = _dotnet_column_size("table:8", row_counts, heap_sizes)
        for row_id in range(1, int(layout["row_count"]) + 1):
            rva, impl_flags, flags = struct.unpack_from("<IHH", data, cursor)
            cursor += 8
            name, cursor = string_index(cursor)
            _, cursor = _read_sized_uint(data, cursor, blob_size)
            param_list, cursor = _read_sized_uint(data, cursor, param_size)
            if name:
                method_rows.append(
                    {
                        "row_id": row_id,
                        "token": f"0x06{row_id:06x}",
                        "name": name,
                        "rva": rva,
                        "impl_flags": impl_flags,
                        "flags": flags,
                        "parameter_list_start": param_list,
                    }
                )

    type_rows: list[dict[str, Any]] = []
    layout = layout_by_index.get(2)
    if layout:
        cursor = int(layout["offset"])
        extends_size = _dotnet_column_size("coded:TypeDefOrRef", row_counts, heap_sizes)
        field_size = _dotnet_column_size("table:4", row_counts, heap_sizes)
        method_size = _dotnet_column_size("table:6", row_counts, heap_sizes)
        for row_id in range(1, int(layout["row_count"]) + 1):
            flags = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            name, cursor = string_index(cursor)
            namespace, cursor = string_index(cursor)
            extends, cursor = _read_sized_uint(data, cursor, extends_size)
            field_start, cursor = _read_sized_uint(data, cursor, field_size)
            method_start, cursor = _read_sized_uint(data, cursor, method_size)
            if not name:
                errors.append(f"TypeDef row {row_id} has an invalid name index")
                continue
            type_rows.append(
                {
                    "row_id": row_id,
                    "token": f"0x02{row_id:06x}",
                    "name": name,
                    "namespace": namespace or "",
                    "full_name": f"{namespace}.{name}" if namespace else name,
                    "flags": flags,
                    "extends_raw": extends,
                    "field_list_start": field_start,
                    "method_list_start": method_start,
                    "fields": [],
                    "methods": [],
                }
            )

    type_names = {item["row_id"]: item["full_name"] for item in type_rows}
    for index, item in enumerate(type_rows):
        extends = int(item.pop("extends_raw"))
        tag = extends & 0x03
        target_row = extends >> 2
        if target_row and tag < 3:
            target_table = (2, 1, 27)[tag]
            if target_table == 2:
                item["base_type"] = type_names.get(target_row)
            elif target_table == 1:
                item["base_type"] = type_refs.get(target_row)
            else:
                item["base_type"] = f"TypeSpec:{target_row}"
        else:
            item["base_type"] = None
        next_field = (
            int(type_rows[index + 1]["field_list_start"])
            if index + 1 < len(type_rows)
            else int(row_counts.get(4, 0)) + 1
        )
        next_method = (
            int(type_rows[index + 1]["method_list_start"])
            if index + 1 < len(type_rows)
            else int(row_counts.get(6, 0)) + 1
        )
        field_start = int(item["field_list_start"])
        method_start = int(item["method_list_start"])
        item["fields"] = [
            {**row, "declaring_type": item["full_name"]}
            for row in field_rows
            if field_start <= int(row["row_id"]) < next_field
        ]
        item["methods"] = [
            {**row, "declaring_type": item["full_name"]}
            for row in method_rows
            if method_start <= int(row["row_id"]) < next_method
        ]

    assembly_name = None
    layout = layout_by_index.get(32)
    if layout and int(layout["row_count"]) > 0:
        cursor = int(layout["offset"]) + 16
        cursor += _dotnet_column_size("blob", row_counts, heap_sizes)
        assembly_name, _ = string_index(cursor)

    methods = [method for item in type_rows for method in item["methods"]]
    fields = [field for item in type_rows for field in item["fields"]]
    return {
        "assembly_name": assembly_name,
        "type_definitions": type_rows,
        "method_definitions": methods,
        "field_definitions": fields,
        "errors": _unique_strings(errors, limit=20),
    }


def _analyze_global_metadata(ref: _EvidenceFile) -> tuple[dict[str, Any], list[str]]:
    header_data, error = _read_evidence_segment(ref, limit=4096)
    if error is not None:
        return (
            {
                **_empty_global_metadata(),
                "status": "partial",
                "path": ref.display_path,
                "size": ref.size,
                "error": error,
                "errors": [error],
            },
            [],
        )
    parsed = _parse_global_metadata_header(header_data, ref.size if ref.size is not None else len(header_data))
    parsed["path"] = ref.display_path
    strings: list[str] = []
    strings_data = b""
    strings_table = next((item for item in parsed["tables"] if item["name"] == "strings"), None)
    if strings_table and strings_table["size"] > 0 and strings_table["in_bounds"]:
        table_data, table_error = _read_evidence_segment(
            ref,
            limit=min(int(strings_table["size"]), 4 * 1024 * 1024),
            offset=int(strings_table["offset"]),
        )
        if table_error is None:
            strings_data = table_data
            strings = _extract_null_strings(strings_data)
        else:
            parsed["status"] = "partial"
            parsed["errors"].append(table_error)
            parsed["error"] = "; ".join(parsed["errors"])
    parsed["string_count_scanned"] = len(strings)
    parsed["strings_truncated"] = bool(strings_table and strings_table["size"] > 4 * 1024 * 1024)
    definitions = _parse_il2cpp_definitions(ref, parsed, strings_data)
    parsed.update(definitions)
    definition_errors = list(definitions.get("definition_errors") or [])
    if definition_errors:
        parsed["status"] = "partial"
        parsed["errors"] = _unique_strings([*parsed.get("errors", []), *definition_errors], limit=20)
        parsed["error"] = "; ".join(parsed["errors"])
    return parsed, strings


def _parse_il2cpp_definitions(
    ref: _EvidenceFile,
    metadata: Mapping[str, Any],
    strings_heap: bytes,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "definition_parser": "il2cpp-global-metadata-v1",
        "definition_layout_supported": False,
        "type_definition_count": 0,
        "method_definition_count": 0,
        "field_definition_count": 0,
        "type_definition_record_count": 0,
        "method_definition_record_count": 0,
        "field_definition_record_count": 0,
        "image_definition_count": 0,
        "image_definition_record_count": 0,
        "image_definition_record_size": None,
        "method_definition_record_size": None,
        "type_definitions": [],
        "method_definitions": [],
        "field_definitions": [],
        "image_definitions": [],
        "image_definition_errors": [],
        "definition_errors": [],
    }
    tables = {str(item.get("name")): item for item in metadata.get("tables") or []}
    type_table = tables.get("type_definitions")
    if not type_table or int(type_table.get("size") or 0) == 0:
        result["definition_errors"] = ["IL2CPP type-definition table is missing or empty"]
        return result
    version = int(metadata.get("version") or 0)
    if not 24 <= version <= 31:
        result["definition_errors"] = [
            f"IL2CPP type-definition layout is not supported for metadata version {version}"
        ]
        return result

    type_data, type_error = _read_bounded_metadata_table(ref, type_table)
    if type_error is not None:
        result["definition_errors"] = [type_error]
        return result
    if len(type_data) % 104 != 0:
        result["definition_errors"] = [
            f"IL2CPP type-definition table size {len(type_data)} is not divisible by the supported 104-byte layout"
        ]
        return result

    errors: list[str] = []
    raw_type_rows: list[dict[str, Any]] = []
    type_record_count = len(type_data) // 104
    for row_id, offset in enumerate(range(0, len(type_data), 104)):
        values = struct.unpack_from("<11iI8i8HII", type_data, offset)
        name = _read_il2cpp_string(strings_heap, values[0])
        namespace = _read_il2cpp_string(strings_heap, values[1]) or ""
        token = int(values[29])
        if not name:
            errors.append(f"IL2CPP TypeDefinition row {row_id} has an invalid name index")
            continue
        if token >> 24 != 0x02:
            errors.append(
                f"IL2CPP TypeDefinition row {row_id} has an invalid metadata token 0x{token:08x}"
            )
            continue
        raw_type_rows.append(
            {
                "row_id": row_id,
                "token": f"0x{token:08x}",
                "name": name,
                "namespace": namespace,
                "full_name": f"{namespace}.{name}" if namespace else name,
                "flags": values[11],
                "field_start": values[12],
                "method_start": values[13],
                "field_count": values[22],
                "method_count": values[20],
            }
        )

    expected_method_count = max(
        (
            int(item["method_start"]) + int(item["method_count"])
            for item in raw_type_rows
            if int(item["method_start"]) >= 0 and int(item["method_count"]) > 0
        ),
        default=0,
    )
    expected_field_count = max(
        (
            int(item["field_start"]) + int(item["field_count"])
            for item in raw_type_rows
            if int(item["field_start"]) >= 0 and int(item["field_count"]) > 0
        ),
        default=0,
    )
    image_rows, image_record_count, image_errors = _parse_il2cpp_image_rows(
        ref,
        tables.get("images"),
        strings_heap,
        type_record_count=type_record_count,
    )
    image_by_type: dict[int, str] = {}
    for image in image_rows:
        start = int(image["type_start"])
        count = int(image["type_count"])
        for type_index in range(start, start + count):
            if type_index in image_by_type:
                image_errors.append(
                    f"IL2CPP type definition {type_index} is claimed by multiple metadata images"
                )
                image_by_type.pop(type_index, None)
                continue
            image_by_type[type_index] = str(image["name"])

    method_rows: list[dict[str, Any]] = []
    method_record_count = 0
    method_record_size: int | None = None
    method_table = tables.get("methods")
    if method_table and int(method_table.get("size") or 0):
        method_data, method_error = _read_bounded_metadata_table(ref, method_table)
        if method_error is not None:
            errors.append(method_error)
        else:
            (
                method_rows,
                method_record_size,
                method_record_count,
                method_errors,
            ) = _parse_il2cpp_method_rows(
                method_data,
                strings_heap,
                version=version,
                expected_count=expected_method_count,
            )
            errors.extend(method_errors)
    elif expected_method_count:
        errors.append(
            f"IL2CPP type definitions reference {expected_method_count} method row(s), but the method table is empty"
        )

    field_rows: list[dict[str, Any]] = []
    field_record_count = 0
    field_table = tables.get("fields")
    if field_table and int(field_table.get("size") or 0):
        field_data, field_error = _read_bounded_metadata_table(ref, field_table)
        if field_error is not None:
            errors.append(field_error)
        elif len(field_data) % 12 != 0:
            errors.append(
                f"IL2CPP field-definition table size {len(field_data)} is not divisible by 12"
            )
        else:
            field_record_count = len(field_data) // 12
            for row_id, offset in enumerate(range(0, len(field_data), 12)):
                name_index, _, token = struct.unpack_from("<iiI", field_data, offset)
                name = _read_il2cpp_string(strings_heap, name_index)
                if not name:
                    errors.append(f"IL2CPP FieldDefinition row {row_id} has an invalid name index")
                    continue
                if token >> 24 != 0x04:
                    errors.append(
                        f"IL2CPP FieldDefinition row {row_id} has an invalid metadata token 0x{token:08x}"
                    )
                    continue
                field_rows.append(
                    {"row_id": row_id, "token": f"0x{token:08x}", "name": name}
                )
    elif expected_field_count:
        errors.append(
            f"IL2CPP type definitions reference {expected_field_count} field row(s), but the field table is empty"
        )

    type_rows: list[dict[str, Any]] = []
    for raw_type in raw_type_rows:
        row_id = int(raw_type["row_id"])
        field_start = int(raw_type["field_start"])
        method_start = int(raw_type["method_start"])
        method_count = int(raw_type["method_count"])
        field_count = int(raw_type["field_count"])
        full_name = str(raw_type["full_name"])
        method_range_valid = (
            (method_count == 0 and -1 <= method_start <= method_record_count)
            or (
                method_count > 0
                and method_start >= 0
                and method_start <= method_record_count
                and method_count <= method_record_count - method_start
            )
        )
        field_range_valid = (
            (field_count == 0 and -1 <= field_start <= field_record_count)
            or (
                field_count > 0
                and field_start >= 0
                and field_start <= field_record_count
                and field_count <= field_record_count - field_start
            )
        )
        if not method_range_valid:
            errors.append(
                f"IL2CPP TypeDefinition row {row_id} method range is outside the method table"
            )
        if not field_range_valid:
            errors.append(
                f"IL2CPP TypeDefinition row {row_id} field range is outside the field table"
            )
        fields = [
            {
                **item,
                "declaring_type": full_name,
                "image_name": image_by_type.get(row_id),
            }
            for item in field_rows
            if field_range_valid
            and field_start <= int(item["row_id"]) < field_start + field_count
        ]
        methods: list[dict[str, Any]] = []
        if method_range_valid:
            for item in method_rows:
                if not method_start <= int(item["row_id"]) < method_start + method_count:
                    continue
                declaring_type_index = int(item.get("declaring_type_index", -1))
                if declaring_type_index != row_id:
                    errors.append(
                        f"IL2CPP MethodDefinition row {item['row_id']} declares type "
                        f"{declaring_type_index}, expected {row_id}"
                    )
                    continue
                methods.append(
                    {
                        **item,
                        "declaring_type": full_name,
                        "image_name": image_by_type.get(row_id),
                    }
                )
        type_rows.append(
            {
                **raw_type,
                "image_name": image_by_type.get(row_id),
                "fields": fields,
                "methods": methods,
            }
        )

    assigned_methods = [item for row in type_rows for item in row["methods"]]
    assigned_fields = [item for row in type_rows for item in row["fields"]]
    result.update(
        {
            "definition_layout_supported": True,
            "type_definition_count": len(type_rows),
            "method_definition_count": len(assigned_methods),
            "field_definition_count": len(assigned_fields),
            "type_definition_record_count": type_record_count,
            "method_definition_record_count": method_record_count,
            "field_definition_record_count": field_record_count,
            "image_definition_count": len(image_rows),
            "image_definition_record_count": image_record_count,
            "image_definition_record_size": 40 if image_record_count else None,
            "method_definition_record_size": method_record_size,
            "type_definitions": type_rows,
            "method_definitions": assigned_methods,
            "field_definitions": assigned_fields,
            "image_definitions": image_rows,
            "image_definition_errors": _unique_strings(image_errors, limit=20),
            "definition_errors": _unique_strings(errors, limit=20),
        }
    )
    return result


def _parse_il2cpp_image_rows(
    ref: _EvidenceFile,
    table: Mapping[str, Any] | None,
    strings_heap: bytes,
    *,
    type_record_count: int,
) -> tuple[list[dict[str, Any]], int, list[str]]:
    if not table or int(table.get("size") or 0) == 0:
        return [], 0, ["IL2CPP image-definition table is missing or empty"]
    data, error = _read_bounded_metadata_table(ref, table)
    if error is not None:
        return [], 0, [error]
    if len(data) % 40 != 0:
        return (
            [],
            0,
            [
                f"IL2CPP image-definition table size {len(data)} is not divisible by "
                "the supported 40-byte layout"
            ],
        )

    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    row_count = len(data) // 40
    for row_id, offset in enumerate(range(0, len(data), 40)):
        (
            name_index,
            assembly_index,
            type_start,
            type_count,
            exported_type_start,
            exported_type_count,
            entry_point_index,
            token,
            custom_attribute_start,
            custom_attribute_count,
        ) = struct.unpack_from("<iiiIiIiIiI", data, offset)
        name = _read_il2cpp_string(strings_heap, name_index)
        if not name:
            errors.append(f"IL2CPP ImageDefinition row {row_id} has an invalid name index")
            continue
        if token >> 24 != 0x20:
            errors.append(
                f"IL2CPP ImageDefinition row {row_id} has an invalid metadata token 0x{token:08x}"
            )
            continue
        if type_start < 0 or type_count > type_record_count - type_start:
            errors.append(
                f"IL2CPP ImageDefinition row {row_id} type range is outside the type-definition table"
            )
            continue
        rows.append(
            {
                "row_id": row_id,
                "name": name,
                "assembly_index": assembly_index,
                "type_start": type_start,
                "type_count": type_count,
                "exported_type_start": exported_type_start,
                "exported_type_count": exported_type_count,
                "entry_point_index": entry_point_index,
                "token": f"0x{token:08x}",
                "custom_attribute_start": custom_attribute_start,
                "custom_attribute_count": custom_attribute_count,
            }
        )
    return rows, row_count, _unique_strings(errors, limit=20)


def _parse_il2cpp_method_rows(
    data: bytes,
    strings_heap: bytes,
    *,
    version: int,
    expected_count: int,
) -> tuple[list[dict[str, Any]], int | None, int, list[str]]:
    layouts = (
        ((56, 44), (52, 40), (36, 24), (32, 20))
        if version <= 24
        else ((36, 24), (32, 20), (56, 44), (52, 40))
        if version <= 28
        else ((32, 20), (36, 24))
    )
    candidates: list[tuple[float, int, int, list[dict[str, Any]], list[str]]] = []
    for preference, (record_size, token_offset) in enumerate(layouts):
        if not data or len(data) % record_size != 0:
            continue
        row_count = len(data) // record_size
        rows: list[dict[str, Any]] = []
        issues: list[str] = []
        valid_name_count = 0
        valid_token_count = 0
        for row_id, offset in enumerate(range(0, len(data), record_size)):
            name_index, declaring_type_index = struct.unpack_from("<ii", data, offset)
            name = _read_il2cpp_string(strings_heap, name_index)
            token = struct.unpack_from("<I", data, offset + token_offset)[0]
            if name:
                valid_name_count += 1
            else:
                issues.append(f"IL2CPP MethodDefinition row {row_id} has an invalid name index")
            if token >> 24 == 0x06:
                valid_token_count += 1
            else:
                issues.append(
                    f"IL2CPP MethodDefinition row {row_id} has an invalid metadata token 0x{token:08x}"
                )
            if name and token >> 24 == 0x06:
                rows.append(
                    {
                        "row_id": row_id,
                        "token": f"0x{token:08x}",
                        "name": name,
                        "declaring_type_index": declaring_type_index,
                        "record_size": record_size,
                    }
                )
        score = float(valid_name_count + valid_token_count) - (preference * 0.25)
        if row_count == expected_count:
            score += 20.0
        elif row_count >= expected_count:
            score += 5.0
        else:
            score -= 20.0
        candidates.append((score, record_size, row_count, rows, issues))

    if not candidates:
        return (
            [],
            None,
            0,
            [f"IL2CPP method-definition table size {len(data)} has no supported record layout"],
        )
    _, record_size, row_count, rows, issues = max(candidates, key=lambda item: item[0])
    return rows, record_size, row_count, _unique_strings(issues, limit=20)


def _read_bounded_metadata_table(
    ref: _EvidenceFile,
    table: Mapping[str, Any],
) -> tuple[bytes, str | None]:
    size = int(table.get("size") or 0)
    if size > _MAX_IL2CPP_TABLE_BYTES:
        return b"", (
            f"IL2CPP table {table.get('name')} exceeds the {_MAX_IL2CPP_TABLE_BYTES}-byte scan limit"
        )
    return _read_evidence_segment(ref, limit=size, offset=int(table.get("offset") or 0))


def _read_il2cpp_string(heap: bytes, index: int) -> str | None:
    if index < 0 or index >= len(heap):
        return None
    end = heap.find(b"\x00", index)
    if end < 0:
        return None
    value = heap[index:end].decode("utf-8", errors="replace")
    return value if value and all(char.isprintable() for char in value) else None


def _parse_global_metadata_header(data: bytes, file_size: int) -> dict[str, Any]:
    base = {
        "status": "partial",
        "schema_version": 1,
        "size": file_size,
        "magic": None,
        "magic_valid": False,
        "version": None,
        "header_size": None,
        "table_count": 0,
        "table_offsets": {},
        "tables": [],
        "errors": [],
        "error": None,
    }
    if len(data) < 8:
        base["errors"] = ["global metadata header is truncated before magic/version"]
        base["error"] = base["errors"][0]
        return base

    magic, version = struct.unpack_from("<Ii", data, 0)
    base["magic"] = f"0x{magic:08x}"
    base["magic_valid"] = magic == _GLOBAL_METADATA_MAGIC
    base["version"] = version
    if magic != _GLOBAL_METADATA_MAGIC:
        base["errors"].append(f"invalid global metadata magic: 0x{magic:08x}")
    if not 16 <= version <= 40:
        base["errors"].append(f"implausible global metadata version: {version}")

    available_pair_count = min((len(data) - 8) // 8, len(_GLOBAL_METADATA_TABLES))
    raw_pairs = [struct.unpack_from("<II", data, 8 + index * 8) for index in range(available_pair_count)]
    possible_header_offsets = [
        offset
        for offset, _ in raw_pairs
        if offset >= 8 and offset <= file_size and offset <= 4096 and offset % 4 == 0
    ]
    header_size = min(possible_header_offsets) if possible_header_offsets else None
    if header_size is not None and (header_size - 8) % 8 == 0:
        pair_count = min((header_size - 8) // 8, available_pair_count)
        base["header_size"] = header_size
        minimum_header_size = 8 + (_MIN_GLOBAL_METADATA_PAIRS * 8)
        if header_size < minimum_header_size:
            base["errors"].append(
                f"derived global metadata header size {header_size} is smaller than "
                f"the minimum {minimum_header_size}-byte table header"
            )
    else:
        pair_count = available_pair_count
        base["errors"].append("could not derive a bounded global metadata header size")

    if pair_count < _MIN_GLOBAL_METADATA_PAIRS:
        base["errors"].append(
            f"global metadata header exposes only {pair_count} table pairs; "
            f"at least {_MIN_GLOBAL_METADATA_PAIRS} are required"
        )

    tables: list[dict[str, Any]] = []
    for index, (offset, size) in enumerate(raw_pairs[:pair_count]):
        empty = offset == 0 and size == 0
        in_bounds = empty or (offset <= file_size and size <= file_size - offset)
        if size > 0 and header_size is not None and offset < header_size:
            in_bounds = False
            base["errors"].append(
                f"table {_GLOBAL_METADATA_TABLES[index]} overlaps the metadata header: "
                f"offset={offset}, header_size={header_size}"
            )
        if not in_bounds:
            base["errors"].append(
                f"table {_GLOBAL_METADATA_TABLES[index]} range is outside the metadata file: "
                f"offset={offset}, size={size}"
            )
        tables.append(
            {
                "index": index,
                "name": _GLOBAL_METADATA_TABLES[index],
                "offset": offset,
                "size": size,
                "in_bounds": in_bounds,
            }
        )
    base["tables"] = tables
    base["table_offsets"] = {item["name"]: item["offset"] for item in tables}
    base["table_count"] = sum(item["size"] > 0 for item in tables)
    if base["table_count"] == 0:
        base["errors"].append("global metadata header contains no non-empty tables")
    strings_table = next((item for item in tables if item["name"] == "strings"), None)
    if strings_table is None or strings_table["size"] == 0:
        base["errors"].append("global metadata strings table is missing or empty")
    base["errors"] = _unique_strings(base["errors"], limit=20)
    base["error"] = "; ".join(base["errors"]) if base["errors"] else None
    base["status"] = "ok" if not base["errors"] else "partial"
    return base


def _native_mapping_summary(
    *,
    engine_name: str,
    platform: str,
    global_metadata_files: Iterable[Mapping[str, Any]],
    runtime_refs: Iterable[_EvidenceFile],
) -> dict[str, Any]:
    result = _empty_native_mapping()
    if engine_name != "unity-il2cpp":
        return result
    if platform != "windows-pe":
        result["reason"] = "native mapping currently supports GameAssembly PE images only"
        return result

    result["status"] = "partial"
    metadata_candidates = [
        item
        for item in global_metadata_files
        if item.get("status") == "ok" and item.get("definition_layout_supported")
    ]
    if not metadata_candidates:
        result["errors"] = ["no structurally valid IL2CPP metadata definition set is available"]
        return result
    metadata = next(
        (item for item in metadata_candidates if item.get("image_definitions")),
        metadata_candidates[0],
    )
    result["metadata_path"] = metadata.get("path")
    result["metadata_version"] = metadata.get("version")
    image_rows = [
        item for item in metadata.get("image_definitions") or [] if isinstance(item, Mapping)
    ]
    if not image_rows:
        result["errors"] = _unique_strings(
            [
                "IL2CPP metadata does not expose a validated image-definition table",
                *list(metadata.get("image_definition_errors") or []),
            ],
            limit=20,
        )
        return result

    gameassembly_refs = [
        ref for ref in runtime_refs if ref.basename.lower() == "gameassembly.dll"
    ]
    if len(gameassembly_refs) != 1:
        result["errors"] = [
            "GameAssembly.dll evidence is missing"
            if not gameassembly_refs
            else "multiple GameAssembly.dll candidates make native mapping ambiguous"
        ]
        return result
    binary_ref = gameassembly_refs[0]
    result["binary_path"] = binary_ref.display_path
    result["binary_size"] = binary_ref.size

    pe = _parse_native_pe_image(binary_ref)
    result["pe"] = pe
    if pe.get("status") != "ok":
        result["errors"] = list(pe.get("errors") or ["GameAssembly PE parsing failed"])
        return result

    method_rows = [
        item for item in metadata.get("method_definitions") or [] if isinstance(item, Mapping)
    ]
    eligible_methods = [
        item
        for item in method_rows
        if item.get("image_name") and str(item.get("token") or "").lower().startswith("0x06")
    ]
    result["eligible_method_count"] = len(eligible_methods)
    if not eligible_methods:
        result["errors"] = ["metadata images contain no validated MethodDefinition tokens"]
        return result

    required_method_counts: dict[str, int] = {}
    for method in eligible_methods:
        image_name = str(method["image_name"])
        try:
            token = int(str(method.get("token")), 16)
        except (TypeError, ValueError):
            continue
        image_key = next(
            (key for key in required_method_counts if key.lower() == image_name.lower()),
            image_name,
        )
        required_method_counts[image_key] = max(
            required_method_counts.get(image_key, 0),
            token & 0x00FFFFFF,
        )
    modules, module_errors = _locate_il2cpp_codegen_modules(
        binary_ref,
        pe,
        required_method_counts,
    )
    result["codegen_modules"] = [
        {key: value for key, value in item.items() if not key.startswith("_")}
        for item in modules
    ]

    errors = list(module_errors)
    modules_by_name: dict[str, list[Mapping[str, Any]]] = {}
    for module in modules:
        modules_by_name.setdefault(str(module.get("name") or "").lower(), []).append(module)

    mappings: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    seen_tokens: set[tuple[str, str]] = set()
    for method in eligible_methods:
        image_name = str(method.get("image_name") or "")
        token_text = str(method.get("token") or "")
        identity = (image_name.lower(), token_text.lower())
        if identity in seen_tokens:
            errors.append(f"duplicate MethodDefinition token {token_text} in image {image_name}")
            unmapped.append(_unmapped_native_method(method, "duplicate metadata token"))
            continue
        seen_tokens.add(identity)
        matching_modules = modules_by_name.get(image_name.lower(), [])
        if len(matching_modules) != 1:
            reason = (
                "codegen module not found"
                if not matching_modules
                else "multiple validated codegen modules matched the metadata image"
            )
            unmapped.append(_unmapped_native_method(method, reason))
            continue
        module = matching_modules[0]
        try:
            token = int(token_text, 16)
        except ValueError:
            unmapped.append(_unmapped_native_method(method, "metadata token is not hexadecimal"))
            continue
        pointer_index = (token & 0x00FFFFFF) - 1
        pointers = list(module.get("_method_pointers") or [])
        if pointer_index < 0 or pointer_index >= len(pointers):
            unmapped.append(_unmapped_native_method(method, "method token is outside the pointer table"))
            continue
        native_va = int(pointers[pointer_index])
        location = _pe_va_location(pe, native_va)
        if native_va == 0 or location is None or not location.get("executable"):
            unmapped.append(
                _unmapped_native_method(method, "method pointer does not resolve to a PE executable section")
            )
            continue
        mappings.append(
            {
                "name": method.get("name"),
                "declaring_type": method.get("declaring_type"),
                "image_name": image_name,
                "token": token_text,
                "pointer_index": pointer_index,
                "native_va": native_va,
                "native_va_hex": f"0x{native_va:x}",
                "native_rva": location["rva"],
                "native_rva_hex": f"0x{int(location['rva']):x}",
                "file_offset": location.get("file_offset"),
                "section": location.get("section"),
                "binary_path": binary_ref.display_path,
                "confidence": 0.98,
                "evidence": [
                    {
                        "source": metadata.get("path"),
                        "kind": "il2cpp-method-definition-token",
                        "token": token_text,
                        "image_name": image_name,
                    },
                    {
                        "source": binary_ref.display_path,
                        "kind": "il2cpp-codegen-module-method-pointer",
                        "module_rva": module.get("module_rva"),
                        "pointer_table_rva": module.get("method_pointer_table_rva"),
                        "pointer_index": pointer_index,
                    },
                    {
                        "source": binary_ref.display_path,
                        "kind": "pe-executable-section",
                        "section": location.get("section"),
                        "native_rva": location.get("rva"),
                        "file_offset": location.get("file_offset"),
                    },
                ],
            }
        )

    result["mappings"] = mappings
    result["unmapped_methods"] = unmapped[:500]
    result["mapped_method_count"] = len(mappings)
    result["errors"] = _unique_strings(errors, limit=20)
    complete = len(mappings) == len(eligible_methods) and not unmapped and not result["errors"]
    result["status"] = "ok" if complete else "partial"
    result["confidence"] = 0.98 if complete else (0.8 if mappings else 0.0)
    result["provenance"] = {
        "parser": "il2cpp-codegen-module-pe-v1",
        "metadata_source": metadata.get("path"),
        "binary_source": binary_ref.display_path,
        "mapping_rule": "metadata image + MethodDef RID indexes the validated Il2CppCodeGenModule method pointer table",
        "requires_unique_codegen_module": True,
        "requires_executable_target": True,
        "runtime_uobject_enumeration": False,
    }
    return result


def _empty_native_mapping() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "schema_version": 1,
        "engine": "unity-il2cpp",
        "parser": "il2cpp-codegen-module-pe-v1",
        "metadata_path": None,
        "metadata_version": None,
        "binary_path": None,
        "binary_size": None,
        "pe": {"status": "unavailable", "sections": [], "errors": []},
        "eligible_method_count": 0,
        "mapped_method_count": 0,
        "codegen_modules": [],
        "mappings": [],
        "unmapped_methods": [],
        "confidence": 0.0,
        "provenance": {},
        "errors": [],
        "reason": None,
    }


def _unmapped_native_method(method: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "name": method.get("name"),
        "declaring_type": method.get("declaring_type"),
        "image_name": method.get("image_name"),
        "token": method.get("token"),
        "reason": reason,
    }


def _parse_native_pe_image(ref: _EvidenceFile) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "partial",
        "path": ref.display_path,
        "size": ref.size,
        "format": None,
        "machine": None,
        "architecture": None,
        "pointer_size": None,
        "image_base": None,
        "size_of_image": None,
        "size_of_headers": None,
        "section_count": 0,
        "sections": [],
        "errors": [],
    }
    prefix, error = _read_evidence_segment(ref, limit=4096)
    if error is not None:
        result["errors"] = [error]
        return result
    if len(prefix) < 0x40 or prefix[:2] != b"MZ":
        result["errors"] = ["GameAssembly is not a structurally valid DOS/PE image"]
        return result
    pe_offset = struct.unpack_from("<I", prefix, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > _MAX_PE_HEADER_BYTES - 24:
        result["errors"] = ["PE header offset is outside the bounded header range"]
        return result
    minimum, error = _read_evidence_segment(ref, limit=pe_offset + 24)
    if error is not None or len(minimum) < pe_offset + 24:
        result["errors"] = [error or "PE COFF header is truncated"]
        return result
    if minimum[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        result["errors"] = ["PE signature is missing"]
        return result
    machine, section_count, _, _, _, optional_size, _ = struct.unpack_from(
        "<HHIIIHH", minimum, pe_offset + 4
    )
    if not 1 <= section_count <= 96:
        result["errors"] = [f"implausible PE section count: {section_count}"]
        return result
    optional_offset = pe_offset + 24
    section_table_offset = optional_offset + optional_size
    header_end = section_table_offset + section_count * 40
    if optional_size < 64 or header_end > _MAX_PE_HEADER_BYTES:
        result["errors"] = ["PE optional/section headers exceed the bounded header range"]
        return result
    headers, error = _read_evidence_segment(ref, limit=header_end)
    if error is not None or len(headers) < header_end:
        result["errors"] = [error or "PE optional/section headers are truncated"]
        return result
    optional_magic = struct.unpack_from("<H", headers, optional_offset)[0]
    if optional_magic == 0x20B:
        pointer_size = 8
        architecture = "amd64"
        image_base = struct.unpack_from("<Q", headers, optional_offset + 24)[0]
        expected_machine = 0x8664
        pe_format = "pe32+"
    elif optional_magic == 0x10B:
        pointer_size = 4
        architecture = "i386"
        image_base = struct.unpack_from("<I", headers, optional_offset + 28)[0]
        expected_machine = 0x14C
        pe_format = "pe32"
    else:
        result["errors"] = [f"unsupported PE optional header magic: 0x{optional_magic:04x}"]
        return result
    result.update(
        {
            "format": pe_format,
            "machine": f"0x{machine:04x}",
            "architecture": architecture,
            "pointer_size": pointer_size,
            "image_base": image_base,
            "image_base_hex": f"0x{image_base:x}",
            "section_count": section_count,
        }
    )
    if machine != expected_machine:
        result["errors"] = [
            f"PE machine 0x{machine:04x} is inconsistent with {pe_format} IL2CPP mapping"
        ]
        return result

    size_of_image = struct.unpack_from("<I", headers, optional_offset + 56)[0]
    size_of_headers = struct.unpack_from("<I", headers, optional_offset + 60)[0]
    result["size_of_image"] = size_of_image
    result["size_of_headers"] = size_of_headers
    errors: list[str] = []
    if size_of_image == 0 or image_base == 0:
        errors.append("PE image base/size is zero")
    if size_of_headers < header_end or (ref.size is not None and size_of_headers > ref.size):
        errors.append("PE SizeOfHeaders does not cover the parsed headers")

    sections: list[dict[str, Any]] = []
    virtual_ranges: list[tuple[int, int, str]] = []
    for index in range(section_count):
        offset = section_table_offset + index * 40
        raw_name = headers[offset : offset + 8].split(b"\x00", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<IIII", headers, offset + 8
        )
        characteristics = struct.unpack_from("<I", headers, offset + 36)[0]
        mapped_size = max(virtual_size, raw_size)
        virtual_valid = (
            mapped_size == 0
            or (
                virtual_address < size_of_image
                and mapped_size <= size_of_image - virtual_address
            )
        )
        raw_valid = (
            raw_size == 0
            or (
                ref.size is not None
                and raw_offset <= ref.size
                and raw_size <= ref.size - raw_offset
            )
        )
        if not virtual_valid:
            errors.append(f"PE section {name} has an out-of-bounds virtual range")
        if not raw_valid:
            errors.append(f"PE section {name} has an out-of-bounds raw range")
        if mapped_size and virtual_valid:
            start = virtual_address
            end = virtual_address + mapped_size
            if any(start < other_end and other_start < end for other_start, other_end, _ in virtual_ranges):
                errors.append(f"PE section {name} overlaps another virtual section")
            virtual_ranges.append((start, end, name))
        sections.append(
            {
                "index": index,
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": f"0x{characteristics:08x}",
                "readable": bool(characteristics & 0x40000000),
                "writable": bool(characteristics & 0x80000000),
                "executable": bool(characteristics & 0x20000000),
                "range_valid": virtual_valid and raw_valid,
            }
        )
    if not any(item["executable"] and item["range_valid"] for item in sections):
        errors.append("PE image has no validated executable section")
    result["sections"] = sections
    result["errors"] = _unique_strings(errors, limit=20)
    result["status"] = "ok" if not result["errors"] else "partial"
    return result


def _locate_il2cpp_codegen_modules(
    ref: _EvidenceFile,
    pe: Mapping[str, Any],
    required_method_counts: Mapping[str, int],
) -> tuple[list[dict[str, Any]], list[str]]:
    pointer_size = int(pe.get("pointer_size") or 0)
    image_base = int(pe.get("image_base") or 0)
    if pointer_size not in {4, 8} or image_base <= 0:
        return [], ["validated PE pointer size/image base is unavailable"]

    scanned: list[tuple[Mapping[str, Any], bytes]] = []
    errors: list[str] = []
    total_scanned = 0
    for section in pe.get("sections") or []:
        if not isinstance(section, Mapping) or not section.get("range_valid"):
            continue
        if not section.get("readable") or int(section.get("raw_size") or 0) <= 0:
            continue
        raw_size = int(section["raw_size"])
        remaining = _MAX_PE_TOTAL_SCAN_BYTES - total_scanned
        if remaining <= 0:
            errors.append("PE section scan stopped at the total byte limit")
            break
        read_size = min(raw_size, _MAX_PE_SECTION_SCAN_BYTES, remaining)
        data, error = _read_evidence_segment(
            ref,
            limit=read_size,
            offset=int(section["raw_offset"]),
        )
        if error is not None or len(data) != read_size:
            errors.append(error or f"PE section {section.get('name')} could not be read completely")
            continue
        if read_size < raw_size:
            errors.append(
                f"PE section {section.get('name')} was truncated at the bounded scan limit"
            )
        scanned.append((section, data))
        total_scanned += len(data)

    candidates: list[dict[str, Any]] = []
    seen_locations: set[tuple[str, int]] = set()
    for image_name, required_count in sorted(required_method_counts.items()):
        encoded = image_name.encode("utf-8", errors="strict") + b"\x00"
        string_vas: set[int] = set()
        for section, data in scanned:
            start = 0
            while True:
                found = data.find(encoded, start)
                if found < 0:
                    break
                string_vas.add(
                    image_base + int(section["virtual_address"]) + found
                )
                start = found + 1
        if not string_vas:
            errors.append(f"codegen module name string was not found for {image_name}")
            continue
        for string_va in sorted(string_vas):
            pointer_bytes = int(string_va).to_bytes(pointer_size, "little")
            for section, data in scanned:
                if section.get("executable"):
                    continue
                start = 0
                while True:
                    found = data.find(pointer_bytes, start)
                    if found < 0:
                        break
                    start = found + 1
                    module_rva = int(section["virtual_address"]) + found
                    identity = (image_name, module_rva)
                    if identity in seen_locations or module_rva % pointer_size:
                        continue
                    seen_locations.add(identity)
                    module_file_offset = int(section["raw_offset"]) + found
                    candidate, candidate_error = _parse_codegen_module_candidate(
                        ref,
                        pe,
                        name=image_name,
                        module_rva=module_rva,
                        module_file_offset=module_file_offset,
                        expected_name_va=string_va,
                        required_method_count=required_count,
                    )
                    if candidate is not None:
                        candidates.append(candidate)
                    elif candidate_error:
                        errors.append(candidate_error)

    unique: dict[tuple[str, int], dict[str, Any]] = {}
    for candidate in candidates:
        unique[(str(candidate["name"]).lower(), int(candidate["module_rva"]))] = candidate
    candidates = list(unique.values())
    for image_name in required_method_counts:
        matches = [
            item for item in candidates if str(item["name"]).lower() == image_name.lower()
        ]
        if len(matches) > 1:
            errors.append(f"multiple structurally valid Il2CppCodeGenModule candidates found for {image_name}")
    return candidates, _unique_strings(errors, limit=20)


def _parse_codegen_module_candidate(
    ref: _EvidenceFile,
    pe: Mapping[str, Any],
    *,
    name: str,
    module_rva: int,
    module_file_offset: int,
    expected_name_va: int,
    required_method_count: int,
) -> tuple[dict[str, Any] | None, str | None]:
    pointer_size = int(pe["pointer_size"])
    structure_size = 24 if pointer_size == 8 else 12
    data, error = _read_evidence_segment(
        ref,
        limit=structure_size,
        offset=module_file_offset,
    )
    if error is not None or len(data) != structure_size:
        return None, error or f"Il2CppCodeGenModule candidate for {name} is truncated"
    if pointer_size == 8:
        name_va = struct.unpack_from("<Q", data, 0)[0]
        method_count = struct.unpack_from("<I", data, 8)[0]
        pointer_table_va = struct.unpack_from("<Q", data, 16)[0]
    else:
        name_va, method_count, pointer_table_va = struct.unpack_from("<III", data, 0)
    if name_va != expected_name_va:
        return None, None
    if (
        method_count < required_method_count
        or method_count == 0
        or method_count > _MAX_IL2CPP_METHOD_POINTERS
    ):
        return None, (
            f"Il2CppCodeGenModule candidate for {name} has implausible method count {method_count}"
        )
    table_size = method_count * pointer_size
    if table_size > _MAX_IL2CPP_POINTER_TABLE_BYTES:
        return None, f"Il2CppCodeGenModule pointer table for {name} exceeds the scan limit"
    table_location = _pe_va_location(pe, pointer_table_va)
    if table_location is None or table_location.get("file_offset") is None:
        return None, f"Il2CppCodeGenModule pointer table for {name} is outside the PE image"
    table_data, error = _read_evidence_segment(
        ref,
        limit=table_size,
        offset=int(table_location["file_offset"]),
    )
    if error is not None or len(table_data) != table_size:
        return None, error or f"Il2CppCodeGenModule pointer table for {name} is truncated"
    format_char = "Q" if pointer_size == 8 else "I"
    pointers = list(struct.unpack(f"<{method_count}{format_char}", table_data))
    resolved = 0
    for pointer in pointers:
        if pointer == 0:
            continue
        location = _pe_va_location(pe, int(pointer))
        if location is None or not location.get("executable"):
            return None, (
                f"Il2CppCodeGenModule pointer table for {name} contains a non-executable target"
            )
        resolved += 1
    if resolved == 0:
        return None, f"Il2CppCodeGenModule pointer table for {name} has no executable targets"
    return (
        {
            "name": name,
            "module_rva": module_rva,
            "module_va": int(pe["image_base"]) + module_rva,
            "module_file_offset": module_file_offset,
            "method_pointer_count": method_count,
            "resolved_executable_pointer_count": resolved,
            "method_pointer_table_va": pointer_table_va,
            "method_pointer_table_rva": table_location["rva"],
            "method_pointer_table_file_offset": table_location["file_offset"],
            "confidence": 0.98,
            "provenance": {
                "source": ref.display_path,
                "parser": "il2cpp-codegen-module-pe-v1",
                "name_anchor_va": expected_name_va,
            },
            "_method_pointers": pointers,
        },
        None,
    )


def _pe_va_location(pe: Mapping[str, Any], va: int) -> dict[str, Any] | None:
    image_base = int(pe.get("image_base") or 0)
    size_of_image = int(pe.get("size_of_image") or 0)
    if va < image_base:
        return None
    rva = va - image_base
    if rva >= size_of_image:
        return None
    for section in pe.get("sections") or []:
        if not isinstance(section, Mapping) or not section.get("range_valid"):
            continue
        start = int(section.get("virtual_address") or 0)
        virtual_size = int(section.get("virtual_size") or 0)
        raw_size = int(section.get("raw_size") or 0)
        span = max(virtual_size, raw_size)
        if not start <= rva < start + span:
            continue
        delta = rva - start
        return {
            "rva": rva,
            "section": section.get("name"),
            "file_offset": (
                int(section.get("raw_offset") or 0) + delta
                if delta < raw_size
                else None
            ),
            "readable": bool(section.get("readable")),
            "writable": bool(section.get("writable")),
            "executable": bool(section.get("executable")),
        }
    return None


def _extract_unreal_evidence(strings: Iterable[str], names: Iterable[str]) -> dict[str, list[str]]:
    package_names: list[str] = []
    asset_names: list[str] = []
    reflection_names: list[str] = []
    values = list(strings)
    for value in values:
        for match in _UNREAL_PACKAGE_RE.finditer(value):
            package_names.append(match.group(0).rstrip(".'\""))
        asset_names.extend(_UNREAL_ASSET_RE.findall(value))
        for marker in _UNREAL_REFLECTION_MARKERS:
            if re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(marker)}(?![A-Za-z0-9_])",
                value,
                flags=re.IGNORECASE,
            ):
                reflection_names.append(marker)
    for name in names:
        normalized = name.replace("\\", "/")
        suffix = Path(normalized).suffix.lower()
        if suffix in {".uasset", ".umap"}:
            asset_names.append(Path(normalized).stem)
    for package in package_names:
        leaf = package.rsplit("/", 1)[-1]
        object_name = leaf.split(".", 1)[0]
        if object_name:
            asset_names.append(object_name)
    return {
        "package_names": _unique_sorted(package_names)[:200],
        "asset_names": _unique_sorted(asset_names)[:200],
        "reflection_names": _unique_sorted(reflection_names)[:100],
    }


def _unreal_sdk_skeleton(
    *,
    engine_name: str,
    assets: Mapping[str, Any],
    symbols: Mapping[str, Any],
) -> dict[str, Any]:
    empty = {
        "status": "unavailable",
        "schema_version": 1,
        "language": "c++17",
        "kind": "static-evidence-skeleton",
        "confidence": 0.0,
        "declaration_count": 0,
        "declarations": [],
        "reflection_marker_count": 0,
        "reflection_markers": [],
        "package_paths": [],
        "source": "",
        "runtime_uobject_enumeration": False,
        "sdk_dump_complete": False,
        "provenance": {},
        "limitations": [
            "No runtime UObject traversal was performed.",
            "Forward declarations do not prove class layout, inheritance, fields, or callable addresses.",
            "Non-type reflection markers are retained as evidence and are not emitted as C++ types.",
        ],
    }
    if engine_name != "unreal":
        return empty

    validated_packages = [
        item
        for item in assets.get("package_files") or []
        if isinstance(item, Mapping)
        and item.get("format_validated")
        and str(item.get("kind") or "").startswith("unreal-")
    ]
    reflection_records = [
        item
        for item in symbols.get("symbol_records") or []
        if isinstance(item, Mapping) and item.get("kind") == "reflection-api"
    ]
    reflection_markers: list[dict[str, Any]] = []
    declarations: list[dict[str, Any]] = []
    for record in reflection_records:
        name = str(record.get("name") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            continue
        marker = {
            "name": name,
            "confidence": min(0.9, float(record.get("confidence") or 0.0)),
            "evidence": [
                {
                    "source": (record.get("provenance") or {}).get("source"),
                    "parser": (record.get("provenance") or {}).get("parser"),
                }
            ],
        }
        reflection_markers.append(marker)
        if name in _UNREAL_FORWARD_DECLARATION_MARKERS:
            declarations.append(
                {
                    **marker,
                    "kind": "forward-declaration",
                    "layout_known": False,
                }
            )
    reflection_markers = sorted(reflection_markers, key=lambda item: item["name"])
    declarations = sorted(declarations, key=lambda item: item["name"])
    package_paths = _unique_strings(
        (str(item.get("path") or "") for item in validated_packages),
        limit=200,
    )
    source_lines = [
        "#pragma once",
        "// Generated from bounded static Unreal package/reflection evidence.",
        "// Class layouts and runtime UObject enumeration are intentionally not claimed.",
        "",
    ]
    source_lines.extend(f"struct {item['name']};" for item in declarations)
    non_type_markers = [
        item["name"]
        for item in reflection_markers
        if item["name"] not in _UNREAL_FORWARD_DECLARATION_MARKERS
    ]
    if non_type_markers:
        source_lines.append("")
        source_lines.append("// Static markers only; no callable address or type layout was recovered:")
        source_lines.extend(f"// - {name}" for name in non_type_markers)
    source_lines.extend(
        [
            "",
            "namespace reverse_analyzer_evidence {",
            "struct PackagePath { const char* value; };",
            "inline constexpr PackagePath kValidatedPackages[] = {",
        ]
    )
    source_lines.extend(f"    {{{json.dumps(path)}}}," for path in package_paths)
    source_lines.extend(["};", "}  // namespace reverse_analyzer_evidence", ""])
    if validated_packages and declarations:
        status = "ok"
        confidence = 0.88
    elif validated_packages or declarations:
        status = "partial"
        confidence = 0.65
    else:
        status = "partial"
        confidence = 0.0
    return {
        **empty,
        "status": status,
        "confidence": confidence,
        "declaration_count": len(declarations),
        "declarations": declarations,
        "reflection_marker_count": len(reflection_markers),
        "reflection_markers": reflection_markers,
        "package_paths": package_paths,
        "source": "\n".join(source_lines),
        "provenance": {
            "parser": "unreal-static-sdk-skeleton-v1",
            "validated_package_files": [
                {
                    "path": item.get("path"),
                    "kind": item.get("kind"),
                    "magic": item.get("magic"),
                    "version": item.get("version"),
                    "index_hash_validated": item.get("index_hash_validated"),
                }
                for item in validated_packages
            ],
            "reflection_source": "engine.symbols.symbol_records",
            "runtime_uobject_enumeration": False,
        },
    }


def _container_evidence(
    sample: Path,
) -> tuple[list[str], list[_EvidenceFile], list[dict[str, Any]]]:
    if sample.suffix.lower() not in _ARCHIVE_SUFFIXES:
        return [], [], []
    names: list[str] = []
    files: list[_EvidenceFile] = []
    diagnostics: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(sample) as archive:
            infos = archive.infolist()
            for info in infos[:_MAX_ARCHIVE_NAMES]:
                normalized = info.filename.replace("\\", "/")
                names.append(normalized)
                if not info.is_dir() and _is_relevant_evidence_name(normalized):
                    files.append(
                        _EvidenceFile(
                            normalized,
                            info.file_size,
                            archive_path=sample,
                            archive_name=info.filename,
                        )
                    )
                    if len(files) >= _MAX_DISCOVERED_FILES:
                        break
            if len(infos) > _MAX_ARCHIVE_NAMES:
                diagnostics.append(
                    _diagnostic(
                        "container",
                        "partial",
                        f"archive entry scan capped at {_MAX_ARCHIVE_NAMES} of {len(infos)} entries",
                        str(sample),
                    )
                )
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        diagnostics.append(_diagnostic("container", "partial", f"invalid or unreadable archive: {exc}", str(sample)))
    return names, files, diagnostics


def _local_evidence_files(sample: Path) -> tuple[list[_EvidenceFile], list[dict[str, Any]]]:
    base = sample.parent
    files: list[_EvidenceFile] = []
    diagnostics: list[dict[str, Any]] = []
    roots: set[Path] = set()

    try:
        children = sorted(base.iterdir(), key=lambda item: item.name.lower())
    except OSError as exc:
        return [], [_diagnostic("runtime-discovery", "partial", str(exc), str(base))]

    for child in children:
        if child.is_file() and _is_relevant_evidence_name(child.name):
            files.append(_local_ref(child, base))
        elif child.is_dir():
            lower = child.name.lower()
            if lower.endswith("_data") or lower in {"content", "managed", "metadata", "paks", "il2cpp_data"}:
                roots.add(child)
            for nested_name in ("Content", "Managed", "Metadata", "Paks", "il2cpp_data"):
                nested = child / nested_name
                if nested.is_dir():
                    roots.add(nested)

    exact_data = base / f"{sample.stem}_Data"
    if exact_data.is_dir():
        roots.add(exact_data)

    for ancestor in list(sample.parents)[:4]:
        if ancestor.name.lower() in {"binaries", "win32", "win64", "linux", "mac"}:
            content = ancestor.parent / "Content"
            if content.is_dir():
                roots.add(content)

    scan_roots: list[Path] = []
    for root in sorted(roots, key=lambda item: (len(item.parts), str(item).lower())):
        if any(_path_is_within(root, existing) for existing in scan_roots):
            continue
        scan_roots.append(root)

    visited_entries = 0
    for root in scan_roots:
        try:
            for child in root.rglob("*"):
                visited_entries += 1
                if visited_entries > _MAX_DISCOVERED_ENTRIES:
                    diagnostics.append(
                        _diagnostic(
                            "runtime-discovery",
                            "partial",
                            f"local evidence traversal capped at {_MAX_DISCOVERED_ENTRIES} entries",
                            str(root),
                        )
                    )
                    return _dedupe_evidence(files), diagnostics
                if len(files) >= _MAX_DISCOVERED_FILES:
                    diagnostics.append(
                        _diagnostic(
                            "runtime-discovery",
                            "partial",
                            f"local evidence scan capped at {_MAX_DISCOVERED_FILES} files",
                            str(root),
                        )
                    )
                    return _dedupe_evidence(files), diagnostics
                if child.is_file() and _is_relevant_evidence_name(child.name):
                    files.append(_local_ref(child, base))
        except (OSError, RuntimeError) as exc:
            diagnostics.append(_diagnostic("runtime-discovery", "partial", str(exc), str(root)))
    return _dedupe_evidence(files), diagnostics


def _local_ref(path: Path, base: Path) -> _EvidenceFile:
    try:
        name = str(path.relative_to(base)).replace("\\", "/")
    except ValueError:
        name = str(path).replace("\\", "/")
    return _EvidenceFile(name=name, size=_safe_size(path), local_path=path)


def _read_evidence_segment(
    ref: _EvidenceFile,
    *,
    limit: int,
    offset: int = 0,
) -> tuple[bytes, str | None]:
    if limit < 0 or offset < 0:
        return b"", "negative evidence read offset/limit"
    if ref.local_path is not None:
        return _read_local_segment(ref.local_path, limit=limit, offset=offset)
    if ref.archive_path is None or ref.archive_name is None:
        return b"", "evidence file has no readable source"
    if offset > _MAX_ARCHIVE_SKIP:
        return b"", f"archive evidence offset {offset} exceeds the {_MAX_ARCHIVE_SKIP}-byte scan limit"
    try:
        with zipfile.ZipFile(ref.archive_path) as archive, archive.open(ref.archive_name) as handle:
            remaining = offset
            while remaining > 0:
                chunk = handle.read(min(remaining, 1024 * 1024))
                if not chunk:
                    return b"", f"evidence offset {offset} is outside archive entry"
                remaining -= len(chunk)
            return handle.read(limit), None
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
        return b"", f"{type(exc).__name__}: {exc}"


def _read_evidence_tail(ref: _EvidenceFile, *, limit: int) -> tuple[bytes, str | None]:
    if limit < 0:
        return b"", "negative evidence tail limit"
    if ref.local_path is not None:
        try:
            with ref.local_path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - limit))
                return handle.read(limit), None
        except OSError as exc:
            return b"", f"{type(exc).__name__}: {exc}"
    if ref.size is None:
        return b"", "archive evidence size is unavailable"
    offset = max(0, ref.size - limit)
    if offset > _MAX_ARCHIVE_SKIP:
        return b"", f"archive tail offset {offset} exceeds the {_MAX_ARCHIVE_SKIP}-byte scan limit"
    return _read_evidence_segment(ref, limit=limit, offset=offset)


def _read_local_segment(path: Path, *, limit: int, offset: int = 0) -> tuple[bytes, str | None]:
    try:
        with path.open("rb") as handle:
            if offset:
                handle.seek(offset)
            return handle.read(limit), None
    except OSError as exc:
        return b"", f"{type(exc).__name__}: {exc}"


def _is_relevant_evidence_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    basename = Path(normalized).name.lower()
    suffix = Path(basename).suffix.lower()
    if basename in _KNOWN_RUNTIME_FILES or suffix in _ENGINE_FILE_SUFFIXES:
        return True
    return any(token in normalized.lower() for token in ("monobleedingedge", "globalgamemanagers"))


def _is_managed_assembly(name: str) -> bool:
    normalized = "/" + name.replace("\\", "/").lower().lstrip("/")
    basename = Path(normalized).name
    return basename.endswith(".dll") and ("/managed/" in normalized or basename == "assembly-csharp.dll")


def _is_engine_asset(name: str) -> bool:
    normalized = name.replace("\\", "/").lower()
    basename = Path(normalized).name
    return basename in {"resources.assets", "globalgamemanagers"} or Path(normalized).suffix in {
        ".assets",
        ".pak",
        ".uasset",
        ".umap",
    }


def _is_runtime_binary(name: str) -> bool:
    basename = Path(name.replace("\\", "/")).name.lower()
    return basename in _KNOWN_RUNTIME_FILES and basename not in {"resources.assets", "global-metadata.dat"}


def _marker_clues(values: list[str], marker: str) -> list[str]:
    clues: list[str] = []
    marker_lower = marker.lower()
    for index, value in enumerate(values):
        if marker_lower not in value.lower():
            continue
        clues.append(marker)
        if _looks_symbol_name(value):
            clues.append(value)
        for neighbor in values[max(0, index - 2) : min(len(values), index + 3)]:
            if _looks_symbol_name(neighbor):
                clues.append(neighbor)
    return _unique_strings(clues, limit=80)


def _ui_clues(values: Iterable[str]) -> list[str]:
    clues: list[str] = []
    for value in values:
        lower = value.lower()
        if any(marker in lower for marker in _UNITY_UI_MARKERS):
            if _looks_symbol_name(value):
                clues.append(value)
            for marker in _UNITY_UI_MARKERS:
                if marker in lower and marker in {"canvas", "recttransform"}:
                    clues.append("Canvas" if marker == "canvas" else "RectTransform")
    return _unique_strings(clues, limit=80)


def _looks_symbol_name(value: str) -> bool:
    text = value.strip()
    if not 2 <= len(text) <= 160 or any(char.isspace() for char in text):
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.+`/:\-]*", text))


def _extract_strings(data: bytes) -> list[str]:
    ascii_strings = [match.group(0).decode("ascii", errors="ignore") for match in _PRINTABLE_RE.finditer(data)]
    utf16_strings = [match.group(0).decode("utf-16le", errors="ignore") for match in _UTF16LE_RE.finditer(data)]
    return _unique_strings([*ascii_strings, *utf16_strings], limit=_MAX_STRINGS_PER_FILE)


def _extract_null_strings(data: bytes) -> list[str]:
    values = [item.decode("utf-8", errors="ignore") for item in data.split(b"\x00") if len(item) >= 2]
    return _unique_strings([item for item in values if item and all(char.isprintable() for char in item)], limit=4000)


def _unique_strings(values: Iterable[Any], *, limit: int) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _unique_sorted(values: Iterable[Any]) -> list[str]:
    by_lower: dict[str, str] = {}
    for value in values:
        text = str(value).strip()
        if text:
            by_lower.setdefault(text.lower(), text)
    return sorted(by_lower.values(), key=lambda item: (item.lower(), item))


def _names_with_suffix(names: Iterable[str], suffix: str) -> list[str]:
    return _unique_sorted(name for name in names if name.lower().endswith(suffix))


def _dedupe_evidence(refs: Iterable[_EvidenceFile]) -> list[_EvidenceFile]:
    result: list[_EvidenceFile] = []
    seen: set[str] = set()
    for ref in refs:
        if ref.local_path is not None:
            key = f"local:{os.path.normcase(str(ref.local_path.absolute()))}"
        else:
            key = f"archive:{os.path.normcase(str(ref.archive_path))}:{(ref.archive_name or '').lower()}"
        if key in seen:
            continue
        seen.add(key)
        result.append(ref)
    return result


def _safe_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def _path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _stable_id(*parts: Any) -> str:
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8", errors="replace")).hexdigest()
    return f"engine:{digest[:20]}"


def _diagnostic(component: str, status: str, message: str, path: str | None = None) -> dict[str, Any]:
    item: dict[str, Any] = {"component": component, "status": status, "message": message}
    if path:
        item["path"] = path
    return item


def _empty_global_metadata() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "schema_version": 1,
        "path": None,
        "size": None,
        "magic": None,
        "magic_valid": False,
        "version": None,
        "header_size": None,
        "table_count": 0,
        "table_offsets": {},
        "tables": [],
        "errors": ["global-metadata.dat not found"],
        "error": "global-metadata.dat not found",
        "string_count_scanned": 0,
        "strings_truncated": False,
        "definition_parser": "il2cpp-global-metadata-v1",
        "definition_layout_supported": False,
        "type_definition_count": 0,
        "method_definition_count": 0,
        "field_definition_count": 0,
        "type_definition_record_count": 0,
        "method_definition_record_count": 0,
        "field_definition_record_count": 0,
        "image_definition_count": 0,
        "image_definition_record_count": 0,
        "image_definition_record_size": None,
        "method_definition_record_size": None,
        "type_definitions": [],
        "method_definitions": [],
        "field_definitions": [],
        "image_definitions": [],
        "image_definition_errors": [],
        "definition_errors": [],
    }


def _unavailable_result(sample: Path, error: str) -> dict[str, Any]:
    metadata = {
        "status": "unavailable",
        "schema_version": 1,
        "engine": "unknown",
        "managed_assembly_count": 0,
        "managed_assembly_candidate_count": 0,
        "managed_assemblies": [],
        "managed_assembly_files": [],
        "managed_type_definition_count": 0,
        "managed_method_definition_count": 0,
        "managed_field_definition_count": 0,
        "global_metadata_present": False,
        "global_metadata_file_present": False,
        "global_metadata": _empty_global_metadata(),
        "global_metadata_header": _empty_global_metadata(),
        "global_metadata_files": [],
        "global_metadata_version": None,
        "global_metadata_tables": [],
        "native_mapping_status": "unavailable",
        "native_mapped_method_count": 0,
        "gameassembly_present": False,
        "gameassembly_file_present": False,
        "mono_present": False,
        "unreal_reflection_strings": [],
        "unreal_package_names": [],
    }
    assets = {
        "status": "unavailable",
        "schema_version": 1,
        "pak_count": 0,
        "uasset_count": 0,
        "umap_count": 0,
        "pak_candidate_count": 0,
        "uasset_candidate_count": 0,
        "umap_candidate_count": 0,
        "validated_package_count": 0,
        "package_files": [],
        "scene_like_asset_count": 0,
        "asset_examples": [],
        "resources_assets_present": False,
        "resources_assets_count": 0,
        "unity_asset_count": 0,
        "unity_assets": [],
        "unreal_package_names": [],
        "unreal_asset_names": [],
    }
    symbols = {
        "status": "unavailable",
        "schema_version": 1,
        "recovered_symbol_count": 0,
        "recovered_symbols": [],
        "symbol_records": [],
        "type_symbols": [],
        "method_symbols": [],
        "field_symbols": [],
        "mono_behaviour_symbols": [],
        "monobehaviour_symbols": [],
        "scriptable_object_symbols": [],
        "ui_symbols": [],
        "unreal_reflection_names": [],
        "unreal_package_names": [],
        "raw_string_markers": {"mono_behaviour": [], "scriptable_object": [], "ui": []},
    }
    semantic = {
        "status": "unavailable",
        "schema_version": 1,
        "engine": "unknown",
        "entities": [],
        "relations": [],
        "capabilities": [],
        "summary": {
            "entity_count": 0,
            "relation_count": 0,
            "resource_count": 0,
            "ui_control_count": 0,
            "native_mapped_method_count": 0,
            "sdk_declaration_count": 0,
        },
        "artifacts": [],
    }
    return {
        "status": "unavailable",
        "schema_version": 1,
        "path": str(sample),
        "platform": _platform_for_suffix(sample.suffix.lower()),
        "engine": "unknown",
        "confidence": 0.0,
        "evidence": [],
        "candidates": [
            {"engine": "unknown", "score": 0.0, "confidence": 0.0, "evidence": [error]}
        ],
        "metadata": metadata,
        "assets": assets,
        "symbols": symbols,
        "native_mapping": _empty_native_mapping(),
        "sdk_skeleton": _unreal_sdk_skeleton(
            engine_name="unknown",
            assets=assets,
            symbols=symbols,
        ),
        "semantic_ir_fragment": semantic,
        "strategy": _default_strategy("unknown"),
        "diagnostics": [_diagnostic("sample", "unavailable", error, str(sample))],
        "artifacts": [],
        "error": error,
    }


def _emit_artifacts(result: dict[str, Any], out_dir: Path) -> None:
    engine_dir = out_dir / "engine"
    try:
        engine_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result["status"] = "partial"
        result["diagnostics"].append(_diagnostic("artifacts", "partial", str(exc), str(engine_dir)))
        return

    targets: list[tuple[str, Path, Mapping[str, Any], str]] = [
        (
            "engine/fingerprint.json",
            engine_dir / "fingerprint.json",
            {key: value for key, value in result.items() if key != "artifacts"},
            "engine-analysis",
        ),
        ("engine/metadata.json", engine_dir / "metadata.json", result["metadata"], "engine-analysis"),
        ("engine/assets.json", engine_dir / "assets.json", result["assets"], "engine-analysis"),
        ("engine/symbols.json", engine_dir / "symbols.json", result["symbols"], "engine-analysis"),
        (
            "engine/native_mapping.json",
            engine_dir / "native_mapping.json",
            result["native_mapping"],
            "engine-native-mapping",
        ),
        (
            "engine/sdk_skeleton.json",
            engine_dir / "sdk_skeleton.json",
            result["sdk_skeleton"],
            "engine-sdk-skeleton",
        ),
        (
            "engine/semantic_ir_fragment.json",
            engine_dir / "semantic_ir_fragment.json",
            result["semantic_ir_fragment"],
            "semantic-ir-fragment",
        ),
    ]
    artifacts: list[dict[str, Any]] = []
    for name, target, payload, kind in targets:
        try:
            _write_json(target, payload)
        except (OSError, TypeError, ValueError) as exc:
            result["status"] = "partial"
            result["diagnostics"].append(_diagnostic("artifacts", "partial", str(exc), str(target)))
            continue
        artifacts.append({"name": name, "path": str(target), "kind": kind})
    sdk_source = str((result.get("sdk_skeleton") or {}).get("source") or "")
    if sdk_source:
        sdk_target = engine_dir / "unreal_sdk_skeleton.hpp"
        try:
            sdk_target.write_text(sdk_source, encoding="utf-8")
        except OSError as exc:
            result["status"] = "partial"
            result["diagnostics"].append(
                _diagnostic("artifacts", "partial", str(exc), str(sdk_target))
            )
        else:
            artifacts.append(
                {
                    "name": "engine/unreal_sdk_skeleton.hpp",
                    "path": str(sdk_target),
                    "kind": "engine-sdk-skeleton-source",
                }
            )
    result["artifacts"] = artifacts


def _platform_for_suffix(suffix: str) -> str:
    if suffix == ".apk":
        return "android-apk"
    if suffix == ".ipa":
        return "ios-ipa"
    if suffix in {".exe", ".dll"}:
        return "windows-pe"
    return "unknown"


def _read_prefix(path: Path, limit: int = 2 * 1024 * 1024) -> bytes:
    data, _ = _read_local_segment(path, limit=limit)
    return data


def _container_names(path: Path) -> list[str]:
    names, _, _ = _container_evidence(path)
    return names


def _sibling_runtime_names(sample: Path) -> list[str]:
    files, _ = _local_evidence_files(sample)
    return [item.name for item in files if item.local_path != sample]


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
