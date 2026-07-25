"""Deterministic, evidence-backed multi-stack source skeleton generation."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping, Sequence


_SCHEMA_VERSION = 1
_GENERATOR_VERSION = "2.0"
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_EVIDENCE_DEPTH = 8
_MAX_MAPPING_ITEMS = 256
_MAX_SEQUENCE_ITEMS = 512
_MAX_TEXT_LENGTH = 4096
_MAX_SYMBOLS = 160
_MAX_PROVENANCE_ITEMS = 16
_MAX_BODY_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_BODY_ARTIFACTS = 512
_BODY_ARTIFACT_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".cs"})

_STACK_ORDER = (
    "unity-csharp",
    "android-kotlin",
    "android-java",
    "electron",
    "pyinstaller-python",
    "csharp",
    "cpp",
    "c",
)
_SUPPORTED_STACKS = frozenset(_STACK_ORDER)
_STACK_ALIASES = {
    "auto": "auto",
    "c": "c",
    "c-native": "c",
    "native-c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cpp-native": "cpp",
    "native-cpp": "cpp",
    "csharp": "csharp",
    "c#": "csharp",
    "dotnet": "csharp",
    ".net": "csharp",
    "wpf": "csharp",
    "winforms": "csharp",
    "electron": "electron",
    "electron-js": "electron",
    "javascript": "electron",
    "android-java": "android-java",
    "java": "android-java",
    "android-kotlin": "android-kotlin",
    "kotlin": "android-kotlin",
    "android": "android",
    "unity": "unity-csharp",
    "unity-csharp": "unity-csharp",
    "python": "pyinstaller-python",
    "pyinstaller": "pyinstaller-python",
    "pyinstaller-python": "pyinstaller-python",
}
_EVIDENCE_ALIASES = {
    "semantic_ir": ("semantic_ir", "semantic", "semantic_ir_fragment"),
    "gui_analysis": ("gui_analysis", "gui", "gui_evidence", "gui_evidence_graph"),
    "engine_analysis": ("engine_analysis", "engine", "engine_evidence"),
    "android_analysis": ("android_analysis", "android", "android_evidence"),
    "protocol_analysis": ("protocol_analysis", "protocol", "protocol_evidence"),
    "dynamic_analysis": ("dynamic_analysis", "dynamic", "dynamic_evidence", "runtime_evidence"),
    "static_analysis": ("static_analysis", "static", "static_evidence"),
}
_KNOWN_ANALYSIS_KEYS = frozenset(
    alias for aliases in _EVIDENCE_ALIASES.values() for alias in aliases
) | {"evidence"}

_C_RESERVED = frozenset(
    "auto break case char const continue default do double else enum extern float for goto if int long "
    "register return short signed sizeof static struct switch typedef union unsigned void volatile while "
    "alignas alignof atomic bool complex generic imaginary inline noreturn restrict static_assert thread_local main".split()
)
_CPP_RESERVED = _C_RESERVED | frozenset(
    "and and_eq asm bitand bitor catch class compl concept consteval constexpr constinit const_cast co_await "
    "co_return co_yield decltype delete dynamic_cast explicit export false friend mutable namespace new noexcept "
    "not not_eq nullptr operator or or_eq private protected public reinterpret_cast requires static_cast template "
    "this throw true try typeid typename using virtual wchar_t xor xor_eq".split()
)
_CS_RESERVED = frozenset(
    "abstract as base bool break byte case catch char checked class const continue decimal default delegate do "
    "double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface "
    "internal is lock long namespace new null object operator out override params private protected public readonly "
    "ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint "
    "ulong unchecked unsafe ushort using virtual void volatile while async await record required file scoped".split()
)
_JAVA_RESERVED = frozenset(
    "abstract assert boolean break byte case catch char class const continue default do double else enum extends "
    "final finally float for goto if implements import instanceof int interface long native new package private "
    "protected public return short static strictfp super switch synchronized this throw throws transient try void "
    "volatile while true false null var record sealed permits non-sealed yield".split()
)
_JS_RESERVED = frozenset(
    "await break case catch class const continue debugger default delete do else enum export extends false finally "
    "for function if implements import in instanceof interface let new null package private protected public return "
    "static super switch this throw true try typeof var void while with yield constructor prototype main".split()
)
_PY_RESERVED = frozenset(
    "False None True and as assert async await break class continue def del elif else except finally for from global "
    "if import in is lambda nonlocal not or pass raise return try while with yield match case main".lower().split()
)


def generate_source_project(
    sample: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    analysis: Mapping[str, Any] | None = None,
    *,
    strategy: str = "auto",
    evidence_overrides: Mapping[str, Any] | None = None,
    max_sample_bytes: int,
) -> dict[str, Any]:
    """Generate one bounded source project and return its metadata contract."""

    sample_path = _validate_sample(sample, max_sample_bytes)
    sample_before = _sample_snapshot(sample_path, max_sample_bytes)
    evidence = _collect_evidence(analysis, evidence_overrides)
    evidence_summary = _summarize_evidence(evidence)
    behavior_hints = _build_behavior_hints(evidence, evidence_summary)
    evidence_index = _build_evidence_index(evidence, evidence_summary, behavior_hints)
    selection = _select_stack(sample_path.suffix.lower(), evidence, evidence_summary, strategy)
    confidence = _build_confidence(selection, evidence, evidence_summary)
    decompiler_input = _collect_decompiler_input(analysis, evidence_overrides, out_dir)
    symbols = _extract_symbols(
        evidence,
        confidence["score"],
        decompiler_functions=decompiler_input["functions"],
    )
    symbols, body_recovery = _recover_function_bodies(
        symbols,
        decompiler_input["artifacts"],
        stack=selection["stack"],
    )
    slug = _safe_slug(sample_path.stem)
    project_name = f"reconstructed_{slug}"

    rendered = _render_stack(
        selection["stack"],
        slug=slug,
        sample_name=sample_path.name,
        symbols=symbols,
        evidence_summary=evidence_summary,
        overall_confidence=confidence["score"],
    )
    project_dir = _prepare_project_directory(out_dir, project_name)
    placeholders = _placeholder_notes(symbols, evidence)
    analysis_payload = {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok",
        "selected_stack": selection["stack"],
        "language": rendered["language"],
        "strategy": {
            "requested": str(strategy),
            "resolved": selection["stack"],
            "signals": selection["signals"],
            "scores": selection["scores"],
        },
        "evidence": evidence_summary,
        "evidence_used": [name for name in _evidence_names() if _has_content(evidence.get(name))],
        "evidence_index": "analysis/evidence_index.json",
        "behavior_hints": "analysis/behavior_hints.json",
        "behavior_hint_count": _behavior_hint_count(behavior_hints),
        "body_recovery": "analysis/body_recovery.json",
        "diagnostics": list(evidence.get("_diagnostics") or []),
        "semantic_symbol_count": len(symbols),
        "placeholders": placeholders,
        "behavior_equivalent": False,
        "limitations": [
            "Decompiler bodies are emitted only after strict parsing and an unambiguous function match.",
            "Generated signatures and types are conservative placeholders and are not claims about original source.",
            "Recovered bodies are evidence-backed reconstructions, not claims of behavioral equivalence.",
        ],
    }
    provenance = _build_provenance(sample_before, evidence, evidence_summary, selection)

    specs: dict[str, dict[str, Any]] = dict(rendered["files"])
    metadata_paths = (
        "analysis/behavior_hints.json",
        "analysis/body_recovery.json",
        "analysis/confidence.json",
        "analysis/evidence_index.json",
        "analysis/project.json",
        "analysis/provenance.json",
        "analysis/source_reconstruction.json",
        "analysis/summary.json",
    )
    semantic_projection = _semantic_projection(evidence.get("semantic_ir"))
    if semantic_projection:
        metadata_paths += ("analysis/semantic_ir.json",)
    for relative_path in metadata_paths:
        name = PurePosixPath(relative_path).stem
        specs[relative_path] = _file_spec(
            "",
            kind="analysis",
            provenance=("generator:source-reconstruction", f"derived:{name}"),
            confidence=confidence["score"],
            placeholder=False,
        )

    file_records = [_file_record(path, specs[path]) for path in sorted(specs)]
    public_symbols = [_public_symbol(item) for item in rendered["symbols"]]
    project = {
        "schema_version": _SCHEMA_VERSION,
        "name": project_name,
        "project_dir": project_name,
        "stack": selection["stack"],
        "output_stack": rendered["output_stack"],
        "language": rendered["language"],
        "confidence": confidence["score"],
        "confidence_level": confidence["level"],
        "evidence_used": list(analysis_payload["evidence_used"]),
        "entrypoints": rendered["entrypoints"],
        "build_files": rendered["build_files"],
        "analysis_files": list(metadata_paths),
        "placeholder": any(bool(item.get("placeholder", True)) for item in public_symbols),
        "behavior_equivalent": False,
        "file_count": len(file_records),
        "files": file_records,
        "symbol_count": len(public_symbols),
        "symbols": sorted(
            public_symbols,
            key=lambda item: (
                str(item["file"]),
                str(item["kind"]),
                str(item["name"]).casefold(),
                str(item.get("address") or ""),
                str(item.get("signature") or ""),
            ),
        ),
    }
    summary_payload = {
        "status": "ok",
        "sample": sample_path.name,
        "selected_stack": selection["stack"],
        "output_stack": rendered["output_stack"],
        "language": rendered["language"],
        "function_count": sum(1 for item in project["symbols"] if item["kind"] in {"function", "method"}),
        "class_count": sum(1 for item in project["symbols"] if item["kind"] == "class"),
        "module_count": len({item["file"] for item in project["symbols"]}),
        "dynamic_evidence_count": evidence_summary["dynamic_analysis"]["event_count"],
        "semantic_entity_count": evidence_summary["semantic_ir"]["entity_count"],
        "semantic_capability_count": evidence_summary["semantic_ir"]["capability_count"],
        "evidence_source_count": len(analysis_payload["evidence_used"]),
        "behavior_hint_count": analysis_payload["behavior_hint_count"],
        "confidence": confidence["score"],
        "stub_only": body_recovery["recovered_count"] == 0,
        "behavior_equivalent": False,
    }

    metadata_payloads: dict[str, Any] = {
        "analysis/behavior_hints.json": behavior_hints,
        "analysis/body_recovery.json": body_recovery,
        "analysis/confidence.json": confidence,
        "analysis/evidence_index.json": evidence_index,
        "analysis/project.json": project,
        "analysis/provenance.json": provenance,
        "analysis/source_reconstruction.json": analysis_payload,
        "analysis/summary.json": summary_payload,
    }
    if semantic_projection:
        metadata_payloads["analysis/semantic_ir.json"] = semantic_projection
    for relative_path, payload in metadata_payloads.items():
        specs[relative_path]["content"] = _json_text(payload)

    for relative_path in sorted(specs):
        _write_bounded(project_dir, relative_path, specs[relative_path]["content"])

    sample_after = _sample_snapshot(sample_path, max_sample_bytes)
    if sample_after != sample_before:
        raise RuntimeError("input sample changed while source reconstruction was running")

    generated_files = [str(project_dir / PurePosixPath(path)) for path in sorted(specs)]
    artifacts = [
        {"name": item["path"], "path": str(project_dir / PurePosixPath(item["path"])), "kind": item["kind"]}
        for item in file_records
    ]
    return {
        "status": "ok",
        "analysis": analysis_payload,
        "provenance": provenance,
        "confidence": confidence,
        "evidence_index": evidence_index,
        "behavior_hints": behavior_hints,
        "project": project,
        "project_dir": str(project_dir),
        "language": rendered["language"],
        "output_stack": rendered["output_stack"],
        "function_count": summary_payload["function_count"],
        "class_count": summary_payload["class_count"],
        "generated_files": generated_files,
        "artifacts": artifacts,
        "body_recovery": body_recovery,
        "stub_only": summary_payload["stub_only"],
        "behavior_equivalent": False,
    }


def _collect_decompiler_input(
    analysis: Mapping[str, Any] | None,
    overrides: Mapping[str, Any] | None,
    out_dir: str | os.PathLike[str],
) -> dict[str, list[dict[str, Any]]]:
    """Collect raw decompiler paths before evidence normalization removes host paths."""

    containers: list[tuple[str, Mapping[str, Any]]] = []
    seen_containers: set[int] = set()

    def register(value: Any, source: str) -> None:
        if not isinstance(value, Mapping) or id(value) in seen_containers:
            return
        seen_containers.add(id(value))
        if any(key in value for key in ("functions", "artifacts", "output_dir", "pseudocode_dir")):
            containers.append((source, value))
        for key in ("decompiler", "ghidra"):
            nested = value.get(key)
            if isinstance(nested, Mapping):
                register(nested, f"{source}.{key}")

    if isinstance(analysis, Mapping):
        register(analysis, "analysis")
        for key in ("static_analysis", "static", "static_evidence"):
            register(analysis.get(key), f"analysis.{key}")
        nested_evidence = analysis.get("evidence")
        if isinstance(nested_evidence, Mapping):
            register(nested_evidence, "analysis.evidence")
            for key in ("static_analysis", "static", "static_evidence"):
                register(nested_evidence.get(key), f"analysis.evidence.{key}")
    if isinstance(overrides, Mapping):
        register(overrides.get("static_analysis"), "overrides.static_analysis")

    functions: list[dict[str, Any]] = []
    output_dirs: list[Path] = []
    artifact_seeds: list[tuple[Mapping[str, Any], Path | None, str]] = []

    for source, container in containers:
        output_dir = _raw_path(container.get("output_dir") or container.get("pseudocode_dir"))
        if output_dir is not None:
            if output_dir.name.casefold() == "pseudocode":
                output_dir = output_dir.parent
            output_dirs.append(output_dir)

        raw_functions = container.get("functions")
        if isinstance(raw_functions, Sequence) and not isinstance(raw_functions, (str, bytes, bytearray)):
            for index, raw in enumerate(raw_functions[:_MAX_SYMBOLS], start=1):
                if not isinstance(raw, Mapping):
                    continue
                record = dict(raw)
                record["_source"] = f"{source}.functions[{index}]"
                functions.append(record)
                for key in ("pseudocode_path", "artifact_path", "decompiled_path", "body_path"):
                    path_value = raw.get(key)
                    if path_value:
                        artifact_seeds.append(
                            (
                                {
                                    "path": path_value,
                                    "kind": "pseudocode",
                                    "entry": raw.get("entry") or raw.get("address"),
                                    "function_name": raw.get("name"),
                                    "signature": raw.get("signature"),
                                    "confidence": raw.get("confidence"),
                                },
                                output_dir,
                                f"{source}.functions[{index}].{key}",
                            )
                        )

        raw_artifacts = container.get("artifacts")
        if isinstance(raw_artifacts, Sequence) and not isinstance(raw_artifacts, (str, bytes, bytearray)):
            for index, raw in enumerate(raw_artifacts[:_MAX_BODY_ARTIFACTS], start=1):
                if isinstance(raw, Mapping):
                    artifact_seeds.append((raw, output_dir, f"{source}.artifacts[{index}]"))

    adjacency_root = _raw_path(out_dir)
    discovery_roots = list(output_dirs)
    if adjacency_root is not None:
        discovery_roots.extend(
            [
                adjacency_root / "decompiled" / "ghidra",
                adjacency_root / "ghidra",
                adjacency_root / "decompiled",
            ]
        )

    artifacts: list[dict[str, Any]] = []
    artifacts_by_path: dict[str, dict[str, Any]] = {}

    def add_artifact(raw: Mapping[str, Any], base: Path | None, source: str) -> None:
        kind = str(raw.get("kind") or "pseudocode").strip().casefold()
        if kind not in {"pseudocode", "decompiler", "decompilation", "source", "function"}:
            return
        raw_value = raw.get("path") or raw.get("file") or raw.get("filename") or raw.get("name")
        path = _resolve_artifact_path(raw_value, base)
        if path is None or path.suffix.casefold() not in _BODY_ARTIFACT_SUFFIXES:
            return
        key = os.path.normcase(str(path.resolve(strict=False)))
        address = _normalize_address(
            raw.get("entry") or raw.get("address") or raw.get("offset") or _address_from_artifact_name(path.name)
        )
        existing = artifacts_by_path.get(key)
        if existing is not None:
            if not existing.get("address") and address:
                existing["address"] = address
            return
        artifact = {
            "path": path,
            "logical_path": _logical_artifact_path(path, base, output_dirs),
            "address": address,
            "name_hint": _first_text(raw.get("function_name"), raw.get("symbol")),
            "signature_hint": _first_text(raw.get("signature")),
            "confidence": _clamp(raw.get("confidence"), 0.6),
            "source": source,
        }
        artifacts_by_path[key] = artifact
        artifacts.append(artifact)

    for raw, base, source in artifact_seeds:
        add_artifact(raw, base, source)

    seen_roots: set[str] = set()
    for root in discovery_roots:
        normalized_root = root.resolve(strict=False)
        root_key = os.path.normcase(str(normalized_root))
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)
        pseudocode = normalized_root if normalized_root.name.casefold() == "pseudocode" else normalized_root / "pseudocode"
        if not pseudocode.is_dir() or pseudocode.is_symlink():
            continue
        for path in sorted(pseudocode.iterdir(), key=lambda item: item.name.casefold())[:_MAX_BODY_ARTIFACTS]:
            if path.is_file() and path.suffix.casefold() in _BODY_ARTIFACT_SUFFIXES:
                add_artifact({"path": path, "kind": "pseudocode"}, normalized_root, "adjacent:ghidra")

    normalized_functions = [_normalize_decompiler_function(item) for item in functions]
    normalized_functions = [item for item in normalized_functions if item is not None]
    for artifact in artifacts:
        matches = [
            item
            for item in normalized_functions
            if artifact.get("address") and item.get("address") == artifact.get("address")
        ]
        if len(matches) == 1:
            match = matches[0]
            artifact["name_hint"] = artifact.get("name_hint") or match.get("name")
            artifact["signature_hint"] = artifact.get("signature_hint") or match.get("signature")
            artifact["confidence"] = max(float(artifact["confidence"]), float(match["confidence"]))
    if len(artifacts) == 1 and len(normalized_functions) == 1:
        artifact = artifacts[0]
        function = normalized_functions[0]
        artifact["address"] = artifact.get("address") or function.get("address")
        artifact["name_hint"] = artifact.get("name_hint") or function.get("name")
        artifact["signature_hint"] = artifact.get("signature_hint") or function.get("signature")
        artifact["confidence"] = max(float(artifact["confidence"]), float(function["confidence"]))

    artifacts.sort(
        key=lambda item: (
            _address_sort_key(item.get("address")),
            str(item["logical_path"]).casefold(),
        )
    )
    normalized_functions.sort(
        key=lambda item: (
            _address_sort_key(item.get("address")),
            str(item.get("name") or "").casefold(),
            str(item.get("signature") or ""),
        )
    )
    return {"functions": normalized_functions, "artifacts": artifacts[:_MAX_BODY_ARTIFACTS]}


def _normalize_decompiler_function(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    name = _first_text(raw.get("name"), raw.get("symbol"), raw.get("label"))
    address = _normalize_address(raw.get("entry") or raw.get("address") or raw.get("offset"))
    signature = _first_text(raw.get("signature"), raw.get("prototype"))
    if not any((name, address, signature)):
        return None
    return {
        "kind": "function",
        "name": name or f"sub_{str(address or 'unknown').removeprefix('0x')}",
        "entry": address,
        "address": address,
        "signature": signature,
        "confidence": _clamp(raw.get("confidence"), 0.65),
        "_source": _safe_provenance(raw.get("_source") or "decompiler.functions"),
    }


def _raw_path(value: Any) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(os.fspath(value)).expanduser()
    except (TypeError, ValueError, OSError):
        return None
    return path if path.is_absolute() else (Path.cwd() / path)


def _resolve_artifact_path(value: Any, base: Path | None) -> Path | None:
    if value is None:
        return None
    try:
        path = Path(os.fspath(value)).expanduser()
    except (TypeError, ValueError, OSError):
        return None
    if path.is_absolute():
        return path
    candidates = []
    if base is not None:
        candidates.extend((base / path, base / "pseudocode" / path))
    candidates.append(Path.cwd() / path)
    return next((candidate for candidate in candidates if candidate.is_file()), candidates[0])


def _logical_artifact_path(path: Path, base: Path | None, output_dirs: Sequence[Path]) -> str:
    roots = [item for item in (base, *output_dirs) if item is not None]
    resolved = path.resolve(strict=False)
    for root in roots:
        try:
            relative = resolved.relative_to(root.resolve(strict=False))
        except (ValueError, OSError):
            continue
        value = PurePosixPath(*relative.parts).as_posix()
        if value and value != ".":
            return value
    if path.parent.name.casefold() == "pseudocode":
        return f"pseudocode/{path.name}"
    return f"pseudocode/{path.name}"


def _address_from_artifact_name(name: str) -> str | None:
    match = re.search(r"(?:^|[_-])(?:fn|fun|sub)?[_-]?([0-9A-Fa-f]{4,16})(?=\.[^.]+$)", name)
    return _normalize_address(match.group(1)) if match else None


def _normalize_address(value: Any) -> str | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"0x{value:x}" if value >= 0 else None
    text = str(value).strip()
    match = re.search(r"(?:0[xX])?([0-9A-Fa-f]{1,16})$", text)
    if not match:
        return None
    try:
        return f"0x{int(match.group(1), 16):x}"
    except ValueError:
        return None


def _address_sort_key(value: Any) -> tuple[int, str]:
    normalized = _normalize_address(value)
    if normalized is None:
        return (1, "")
    return (0, f"{int(normalized[2:], 16):016x}")


def _signature_key(value: Any) -> str | None:
    text = _first_text(value)
    if not text:
        return None
    text = text.strip().rstrip(";").strip()
    return re.sub(r"\s+", "", text)


def _symbol_name_key(value: Any) -> str:
    text = str(value or "").strip()
    return text.rsplit("::", 1)[-1].rsplit(".", 1)[-1].casefold()


def _public_symbol(symbol: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in symbol.items() if not str(key).startswith("_")}


def _recover_function_bodies(
    symbols: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
    *,
    stack: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    parsed_artifacts: list[dict[str, Any]] = []
    for item in artifacts:
        parsed_artifacts.extend(_parse_body_artifacts(item, stack=stack))
    recovered_symbols: list[dict[str, Any]] = []
    function_reports: list[dict[str, Any]] = []

    for raw_symbol in symbols:
        symbol = dict(raw_symbol)
        if symbol.get("kind") not in {"function", "method"}:
            recovered_symbols.append(symbol)
            continue

        match_basis, matches = _matching_body_artifacts(symbol, parsed_artifacts)
        report: dict[str, Any] = {
            "name": symbol.get("name"),
            "kind": symbol.get("kind"),
            "address": symbol.get("address"),
            "signature": symbol.get("signature"),
            "status": "unavailable",
            "match_basis": match_basis,
            "confidence": round(float(symbol.get("confidence") or 0.0) * 0.5, 3),
            "behavior_equivalent": False,
        }

        if len(matches) > 1:
            report["status"] = "ambiguous"
            report["reason"] = f"multiple artifacts matched by {match_basis or 'symbol'}"
            report["candidates"] = [item["artifact"] for item in matches]
        elif len(matches) == 1:
            matched = matches[0]
            report["artifact"] = matched["artifact"]
            report["confidence"] = round(
                min(
                    float(symbol.get("confidence") or 0.0),
                    float(matched.get("confidence") or 0.0),
                ),
                3,
            )
            if matched["status"] == "parsed":
                report["status"] = "recovered"
                report["line_provenance"] = matched["line_provenance"]
                symbol["placeholder"] = False
                symbol["_recovered_definition"] = matched["definition"]
                symbol["_recovered_declaration"] = matched["declaration"]
                artifact_ref = f"artifact:{matched['artifact']['path']}"
                symbol["provenance"] = _unique_text([*(symbol.get("provenance") or []), artifact_ref])
            else:
                report["status"] = "parse_failed"
                report["reason"] = matched.get("reason") or "artifact could not be parsed"
        else:
            report["reason"] = "no pseudocode artifact matched this function"

        symbol["body_recovery"] = dict(report)
        recovered_symbols.append(symbol)
        function_reports.append(report)

    function_reports.sort(
        key=lambda item: (
            _address_sort_key(item.get("address")),
            str(item.get("name") or "").casefold(),
            str(item.get("signature") or ""),
        )
    )
    recovered_count = sum(1 for item in function_reports if item["status"] == "recovered")
    parse_failure_count = sum(1 for item in function_reports if item["status"] == "parse_failed")
    ambiguous_count = sum(1 for item in function_reports if item["status"] == "ambiguous")
    placeholder_count = len(function_reports) - recovered_count
    if function_reports and placeholder_count == 0:
        status = "recovered"
    elif recovered_count:
        status = "partial"
    else:
        status = "unavailable"
    report = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "function_count": len(function_reports),
        "recovered_count": recovered_count,
        "placeholder_count": placeholder_count,
        "parse_failure_count": parse_failure_count,
        "ambiguous_count": ambiguous_count,
        "behavior_equivalent": False,
        "functions": function_reports,
    }
    return recovered_symbols, report


def _matching_body_artifacts(
    symbol: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
) -> tuple[str | None, list[Mapping[str, Any]]]:
    address = _normalize_address(symbol.get("address"))
    if address:
        matches = [item for item in artifacts if item.get("address") == address]
        if matches:
            return "address", matches

    signature = _signature_key(symbol.get("signature"))
    if signature:
        matches = [item for item in artifacts if item.get("signature_key") == signature]
        if matches:
            return "signature", matches

    name = _symbol_name_key(symbol.get("name"))
    if name:
        matches = [item for item in artifacts if item.get("name_key") == name]
        if matches:
            return "symbol", matches
    return None, []


def _parse_body_artifacts(raw: Mapping[str, Any], *, stack: str) -> list[dict[str, Any]]:
    path = raw.get("path")
    logical_path = str(raw.get("logical_path") or "pseudocode/unknown")
    artifact = {
        "path": logical_path,
        "kind": "pseudocode",
        "sha256": None,
        "size_bytes": None,
    }
    result: dict[str, Any] = {
        "status": "parse_failed",
        "artifact": artifact,
        "address": _normalize_address(raw.get("address")),
        "name_key": _symbol_name_key(raw.get("name_hint")),
        "signature_key": _signature_key(raw.get("signature_hint")),
        "confidence": _clamp(raw.get("confidence"), 0.5),
    }
    if not isinstance(path, Path):
        result["reason"] = "artifact path is invalid"
        return [result]

    try:
        payload = _read_body_artifact(path)
    except (OSError, RuntimeError, ValueError) as error:
        result["reason"] = f"artifact read failed: {type(error).__name__}"
        return [result]
    artifact["sha256"] = hashlib.sha256(payload).hexdigest()
    artifact["size_bytes"] = len(payload)

    suffix = path.suffix.casefold()
    compatible = {
        "c": {".c"},
        "cpp": {".c", ".cc", ".cpp", ".cxx"},
        "csharp": {".cs"},
    }
    if suffix not in compatible.get(stack, set()):
        result["reason"] = f"artifact language is incompatible with {stack}"
        return [result]
    try:
        text = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError:
        result["reason"] = "artifact is not valid UTF-8"
        return [result]
    parsed_definitions, reason = _parse_c_like_definitions(text)
    if not parsed_definitions:
        result["reason"] = reason
        return [result]

    variants: list[dict[str, Any]] = []
    for index, parsed in enumerate(parsed_definitions, start=1):
        variant = dict(result)
        variant_artifact = dict(artifact)
        if len(parsed_definitions) > 1:
            variant_artifact["function_index"] = index
            variant_artifact["function_name"] = parsed["name"]
        variant.update(
            {
                "status": "parsed",
                "artifact": variant_artifact,
                "address": result.get("address") if len(parsed_definitions) == 1 else None,
                "name_key": _symbol_name_key(parsed["name"]),
                "signature_key": _signature_key(parsed["signature"]),
                "definition": parsed["definition"],
                "declaration": parsed["declaration"],
                "line_provenance": parsed["line_provenance"],
            }
        )
        variants.append(variant)
    return variants


def _parse_body_artifact(raw: Mapping[str, Any], *, stack: str) -> dict[str, Any]:
    parsed = _parse_body_artifacts(raw, stack=stack)
    if len(parsed) == 1:
        return parsed[0]
    result = dict(parsed[0])
    result["status"] = "parse_failed"
    result["reason"] = "artifact contains multiple top-level function definitions"
    result.pop("definition", None)
    result.pop("declaration", None)
    result.pop("line_provenance", None)
    return result


def _read_body_artifact(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("artifact must be a regular non-symlink file")
    expected_size = path.stat().st_size
    if expected_size > _MAX_BODY_ARTIFACT_BYTES:
        raise ValueError("artifact exceeds bounded read limit")
    chunks: list[bytes] = []
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_BODY_ARTIFACT_BYTES:
                raise ValueError("artifact exceeds bounded read limit")
            chunks.append(chunk)
    if total != expected_size:
        raise RuntimeError("artifact changed while it was being read")
    return b"".join(chunks)


def _parse_c_like_definition(text: str) -> tuple[dict[str, Any] | None, str]:
    definitions, reason = _parse_c_like_definitions(text)
    if len(definitions) == 1:
        return definitions[0], ""
    if definitions:
        return None, "artifact contains multiple top-level function definitions"
    return None, reason


def _parse_c_like_definitions(text: str) -> tuple[list[dict[str, Any]], str]:
    if "\x00" in text:
        return [], "artifact contains NUL bytes"
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip(" \t") for line in normalized.split("\n"))
    if re.search(
        r"\b(?:decompilation failed|failed to decompile|decompiler error|no function body)\b",
        normalized,
        flags=re.IGNORECASE,
    ):
        return [], "decompiler reported a failed body"

    masked, lexical_error = _mask_c_like_noncode(normalized)
    if lexical_error:
        return [], lexical_error
    brace_pairs: dict[int, int] = {}
    brace_stack: list[int] = []
    top_level_opens: list[int] = []
    for index, character in enumerate(masked):
        if character == "{":
            if not brace_stack:
                top_level_opens.append(index)
            brace_stack.append(index)
        elif character == "}":
            if not brace_stack:
                return [], "unbalanced closing brace"
            opening = brace_stack.pop()
            brace_pairs[opening] = index
    if brace_stack:
        return [], "unbalanced opening brace"

    candidates: list[dict[str, Any]] = []
    for opening in top_level_opens:
        signature = _function_signature_before(masked, opening)
        if signature is None:
            continue
        closing = brace_pairs[opening]
        candidates.append({**signature, "body_start": opening, "function_end": closing + 1})
    if not candidates:
        return [], "artifact does not contain a top-level function definition"

    definitions: list[dict[str, Any]] = []
    for candidate in candidates:
        parsed, reason = _definition_from_candidate(normalized, masked, candidate)
        if parsed is None:
            return [], reason
        definitions.append(parsed)
    return definitions, ""


def _definition_from_candidate(
    normalized: str,
    masked: str,
    candidate: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    signature_text = re.sub(
        r"\s+",
        " ",
        masked[candidate["function_start"] : candidate["body_start"]].strip(),
    )
    if not signature_text or len(signature_text) > _MAX_TEXT_LENGTH:
        return None, "function signature is empty or too large"
    body = normalized[candidate["body_start"] : candidate["function_end"]]
    definition = f"{signature_text}\n{body}\n"
    function_start_line = normalized.count("\n", 0, candidate["function_start"]) + 1
    function_end_line = normalized.count("\n", 0, candidate["function_end"] - 1) + 1
    body_start_line = normalized.count("\n", 0, candidate["body_start"]) + 1
    body_end_line = normalized.count("\n", 0, candidate["function_end"] - 1) + 1
    return {
        "name": candidate["name"],
        "signature": signature_text,
        "declaration": f"{signature_text};",
        "definition": definition,
        "line_provenance": {
            "function": {"start": function_start_line, "end": function_end_line},
            "body": {"start": body_start_line, "end": body_end_line},
        },
    }, ""


def _function_signature_before(masked: str, body_start: int) -> dict[str, Any] | None:
    end = body_start
    while end > 0 and masked[end - 1].isspace():
        end -= 1
    close_paren = masked.rfind(")", 0, end)
    if close_paren < 0:
        return None
    suffix = masked[close_paren + 1 : end]
    if any(character in suffix for character in ";{}="):
        return None

    depth = 1
    open_paren = close_paren - 1
    while open_paren >= 0:
        character = masked[open_paren]
        if character == ")":
            depth += 1
        elif character == "(":
            depth -= 1
            if depth == 0:
                break
        open_paren -= 1
    if open_paren < 0:
        return None

    boundary = max(masked.rfind(";", 0, open_paren), masked.rfind("}", 0, open_paren)) + 1
    segment = masked[boundary:body_start]
    for directive in re.finditer(r"(?m)^[ \t]*#.*(?:\n|$)", segment):
        boundary += directive.end()
        segment = masked[boundary:body_start]
    leading = len(segment) - len(segment.lstrip())
    function_start = boundary + leading
    name_prefix = masked[function_start:open_paren].rstrip()
    name_match = re.search(
        r"((?:[~A-Za-z_][A-Za-z0-9_~]*::)*[~A-Za-z_][A-Za-z0-9_~]*)$",
        name_prefix,
    )
    if not name_match:
        return None
    name = name_match.group(1)
    if _symbol_name_key(name) in {"if", "for", "while", "switch", "catch", "sizeof"}:
        return None
    return {"function_start": function_start, "name": name}


def _mask_c_like_noncode(text: str) -> tuple[str, str | None]:
    masked = list(text)
    index = 0
    length = len(text)
    while index < length:
        if text.startswith("//", index):
            cursor = index
            while cursor < length and text[cursor] != "\n":
                masked[cursor] = " "
                cursor += 1
            index = cursor
            continue
        if text.startswith("/*", index):
            closing = text.find("*/", index + 2)
            if closing < 0:
                return "".join(masked), "unterminated block comment"
            for cursor in range(index, closing + 2):
                if text[cursor] != "\n":
                    masked[cursor] = " "
            index = closing + 2
            continue
        if text.startswith('R"', index):
            delimiter_end = text.find("(", index + 2, min(length, index + 20))
            if delimiter_end > 0:
                delimiter = text[index + 2 : delimiter_end]
                terminator = f"){delimiter}\""
                closing = text.find(terminator, delimiter_end + 1)
                if closing < 0:
                    return "".join(masked), "unterminated raw string literal"
                literal_end = closing + len(terminator)
                for cursor in range(index, literal_end):
                    if text[cursor] != "\n":
                        masked[cursor] = " "
                index = literal_end
                continue
        if text[index] in {'"', "'"}:
            quote = text[index]
            verbatim = quote == '"' and index > 0 and text[index - 1] == "@"
            masked[index] = " "
            cursor = index + 1
            closed = False
            while cursor < length:
                if text[cursor] == "\n" and not verbatim:
                    break
                if text[cursor] == quote:
                    if verbatim and cursor + 1 < length and text[cursor + 1] == quote:
                        masked[cursor] = " "
                        masked[cursor + 1] = " "
                        cursor += 2
                        continue
                    masked[cursor] = " "
                    cursor += 1
                    closed = True
                    break
                if text[cursor] == "\\" and not verbatim and cursor + 1 < length:
                    masked[cursor] = " "
                    if text[cursor + 1] != "\n":
                        masked[cursor + 1] = " "
                    cursor += 2
                    continue
                if text[cursor] != "\n":
                    masked[cursor] = " "
                cursor += 1
            if not closed:
                return "".join(masked), "unterminated string or character literal"
            index = cursor
            continue
        index += 1
    return "".join(masked), None


def _validate_sample(value: str | os.PathLike[str], max_sample_bytes: int) -> Path:
    if isinstance(max_sample_bytes, bool) or int(max_sample_bytes) <= 0:
        raise ValueError("max_sample_bytes must be a positive integer")
    path = Path(value).expanduser()
    if path.is_symlink():
        raise ValueError("input sample must not be a symbolic link")
    if not path.is_file():
        raise FileNotFoundError(str(path))
    resolved = path.resolve(strict=True)
    size = resolved.stat().st_size
    if size > int(max_sample_bytes):
        raise ValueError(f"sample exceeds bounded read limit of {int(max_sample_bytes)} bytes")
    return resolved


def _sample_snapshot(path: Path, max_sample_bytes: int) -> dict[str, Any]:
    before = path.stat()
    if before.st_size > max_sample_bytes:
        raise ValueError(f"sample exceeds bounded read limit of {max_sample_bytes} bytes")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_sample_bytes:
                raise ValueError(f"sample exceeds bounded read limit of {max_sample_bytes} bytes")
            digest.update(chunk)
    after = path.stat()
    before_identity = (before.st_size, before.st_mtime_ns, getattr(before, "st_ino", None))
    after_identity = (after.st_size, after.st_mtime_ns, getattr(after, "st_ino", None))
    if before_identity != after_identity or total != after.st_size:
        raise RuntimeError("input sample changed while it was being read")
    return {"name": path.name, "sha256": digest.hexdigest(), "size_bytes": total}


def _prepare_project_directory(out_dir: str | os.PathLike[str], project_name: str) -> Path:
    requested_root = Path(out_dir).expanduser()
    if requested_root.exists() and not requested_root.is_dir():
        raise NotADirectoryError(str(requested_root))
    requested_root.mkdir(parents=True, exist_ok=True)
    root = requested_root.resolve(strict=True)
    candidate = root / project_name
    if candidate.is_symlink():
        raise ValueError("reconstruction project path must not be a symbolic link")
    resolved = candidate.resolve(strict=False)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError("reconstruction project escapes output directory") from error
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def _write_bounded(project_dir: Path, relative_path: str, content: str) -> None:
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"unsafe generated path: {relative_path!r}")
    target = project_dir.joinpath(*pure.parts)
    try:
        target.resolve(strict=False).relative_to(project_dir.resolve(strict=True))
    except ValueError as error:
        raise ValueError(f"generated path escapes project: {relative_path!r}") from error
    cursor = target
    while cursor != project_dir:
        if cursor.exists() and cursor.is_symlink():
            raise ValueError(f"generated path traverses a symbolic link: {relative_path!r}")
        cursor = cursor.parent
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not target.is_file():
        raise IsADirectoryError(str(target))
    target.write_text(content, encoding="utf-8", newline="\n")


def _collect_evidence(
    analysis: Mapping[str, Any] | None,
    overrides: Mapping[str, Any] | None,
) -> dict[str, Any]:
    diagnostics: list[dict[str, str]] = []
    if analysis is None:
        aggregate: Mapping[str, Any] = {}
    elif isinstance(analysis, Mapping):
        aggregate = analysis
    else:
        diagnostics.append(
            {
                "code": "malformed_analysis",
                "source": "analysis",
                "message": "ignored non-mapping aggregate analysis",
                "received_type": _type_name(analysis),
            }
        )
        aggregate = {}

    nested = aggregate.get("evidence")
    if nested is not None and not isinstance(nested, Mapping):
        diagnostics.append(
            {
                "code": "malformed_evidence",
                "source": "analysis.evidence",
                "message": "ignored non-mapping evidence container",
                "received_type": _type_name(nested),
            }
        )
    nested_evidence = nested if isinstance(nested, Mapping) else {}
    result: dict[str, Any] = {}
    for canonical, aliases in _EVIDENCE_ALIASES.items():
        value = _first_present(aggregate, aliases)
        if value is None:
            value = _first_present(nested_evidence, aliases)
        result[canonical] = _normalize_evidence_value(canonical, value, diagnostics)

    if result["semantic_ir"] is None and any(key in aggregate for key in ("entities", "relations", "capabilities")):
        result["semantic_ir"] = _normalize_evidence_value("semantic_ir", aggregate, diagnostics)

    loose_static_payload = {
        str(key): value
        for key, value in aggregate.items()
        if str(key) not in _KNOWN_ANALYSIS_KEYS
    }
    if loose_static_payload:
        merged_static = dict(_as_mapping(_bounded_json(loose_static_payload)))
        merged_static.update(_as_mapping(result.get("static_analysis")))
        result["static_analysis"] = merged_static

    normalized_overrides = _normalize_overrides(overrides)
    for name, value in normalized_overrides.items():
        if value is not None:
            normalized = _normalize_evidence_value(name, value, diagnostics)
            if normalized is not None:
                if name == "static_analysis" and isinstance(result.get(name), Mapping):
                    merged_static = dict(_as_mapping(result[name]))
                    merged_static.update(_as_mapping(normalized))
                    result[name] = merged_static
                else:
                    result[name] = normalized
    result["_diagnostics"] = diagnostics
    return result


def _normalize_evidence_value(
    name: str,
    value: Any,
    diagnostics: list[dict[str, str]],
) -> Any:
    if value is None:
        return None
    mapping_sources = {
        "semantic_ir",
        "gui_analysis",
        "engine_analysis",
        "android_analysis",
        "protocol_analysis",
        "static_analysis",
    }
    dynamic_sequence = isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    valid = isinstance(value, Mapping) if name in mapping_sources else isinstance(value, Mapping) or dynamic_sequence
    if not valid:
        diagnostics.append(
            {
                "code": "malformed_evidence",
                "source": name,
                "message": "ignored evidence with an unsupported shape",
                "received_type": _type_name(value),
            }
        )
        return None
    try:
        return _bounded_json(value)
    except (AttributeError, KeyError, TypeError, ValueError, RuntimeError) as error:
        diagnostics.append(
            {
                "code": "malformed_evidence",
                "source": name,
                "message": f"ignored evidence that could not be normalized: {type(error).__name__}",
                "received_type": _type_name(value),
            }
        )
        return None


def _normalize_overrides(overrides: Mapping[str, Any] | None) -> dict[str, Any]:
    if overrides is None:
        return {}
    if not isinstance(overrides, Mapping):
        raise TypeError("evidence overrides must be a mapping")
    alias_to_canonical = {
        alias: canonical for canonical, aliases in _EVIDENCE_ALIASES.items() for alias in aliases
    }
    normalized: dict[str, Any] = {}
    for key, value in overrides.items():
        name = str(key)
        if name == "evidence":
            if value is not None and not isinstance(value, Mapping):
                raise TypeError("evidence override must be a mapping")
            for nested_key, nested_value in (value or {}).items():
                nested_name = str(nested_key)
                canonical = alias_to_canonical.get(nested_name)
                if canonical is None:
                    raise TypeError(f"unexpected evidence argument: {nested_name}")
                normalized[canonical] = nested_value
            continue
        canonical = alias_to_canonical.get(name)
        if canonical is None:
            raise TypeError(f"unexpected evidence argument: {name}")
        normalized[canonical] = value
    return normalized


def _bounded_json(value: Any, depth: int = 0, active: set[int] | None = None) -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return round(value, 8) if math.isfinite(value) else str(value)
    if isinstance(value, str):
        return _safe_evidence_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"bytes_sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    if isinstance(value, os.PathLike):
        return Path(value).name
    if depth >= _MAX_EVIDENCE_DEPTH:
        return "<truncated:depth>"

    seen = active if active is not None else set()
    identity = id(value)
    if identity in seen:
        return "<truncated:cycle>"
    seen.add(identity)
    try:
        if isinstance(value, Mapping):
            pairs = sorted(value.items(), key=lambda item: str(item[0]))[:_MAX_MAPPING_ITEMS]
            return {
                _safe_evidence_text(str(key), limit=160): _bounded_json(item, depth + 1, seen)
                for key, item in pairs
            }
        if isinstance(value, (set, frozenset)):
            ordered = sorted(value, key=lambda item: _canonical_text(_bounded_json(item)))
            return [_bounded_json(item, depth + 1, seen) for item in ordered[:_MAX_SEQUENCE_ITEMS]]
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [_bounded_json(item, depth + 1, seen) for item in value[:_MAX_SEQUENCE_ITEMS]]
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}
    finally:
        seen.remove(identity)


def _safe_evidence_text(value: str, *, limit: int = _MAX_TEXT_LENGTH) -> str:
    text = "".join(character for character in value if character >= " " and character != "\x7f").strip()
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith(("/", "\\\\")):
        text = Path(text.replace("\\", "/")).name
    return text[:limit]


def _first_present(mapping: Mapping[str, Any], names: Iterable[str]) -> Any:
    for name in names:
        if name in mapping and mapping[name] is not None:
            return mapping[name]
    return None


def _evidence_names() -> tuple[str, ...]:
    return tuple(_EVIDENCE_ALIASES)


def _has_content(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (Mapping, Sequence, set, frozenset)) and not isinstance(value, (str, bytes, bytearray)):
        return bool(value)
    if isinstance(value, str):
        return bool(value.strip())
    return True


def _summarize_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    semantic = _as_mapping(evidence.get("semantic_ir"))
    entities = _mapping_list(semantic.get("entities"))
    relations = semantic.get("relations")
    capabilities = semantic.get("capabilities")
    semantic_summary = {
        "present": _has_content(semantic),
        "entity_count": len(entities),
        "relation_count": len(relations) if isinstance(relations, list) else 0,
        "capability_count": len(capabilities) if isinstance(capabilities, list) else 0,
        "confidence": _entity_confidence(entities),
    }

    gui = _as_mapping(evidence.get("gui_analysis"))
    gui_strategy = _as_mapping(gui.get("strategy"))
    gui_runtime = _as_mapping(gui.get("runtime_tree"))
    gui_visual = _as_mapping(gui.get("visual"))
    gui_framework = _first_text(
        gui.get("framework"), gui.get("output_stack"), gui_strategy.get("framework"), gui_strategy.get("output_stack")
    )
    gui_summary = {
        "present": _has_content(gui),
        "status": _first_text(gui.get("status")),
        "framework": gui_framework,
        "control_count": max(
            _best_count(gui, "control_count", "widget_count", "node_count"),
            _best_count(gui_runtime, "control_count", "widget_count", "node_count"),
            _best_count(gui_visual, "detected_widget_count", "widget_count", "control_count"),
        ),
        "confidence": _source_confidence("gui_analysis", gui),
    }

    engine = _as_mapping(evidence.get("engine_analysis"))
    engine_assets = _as_mapping(engine.get("assets"))
    engine_symbols = _as_mapping(engine.get("symbols"))
    engine_fragment = _as_mapping(engine.get("semantic_ir_fragment"))
    engine_fragment_summary = _as_mapping(engine_fragment.get("summary"))
    engine_summary = {
        "present": _has_content(engine),
        "engine": _first_text(engine.get("engine"), engine.get("framework"), engine.get("name")),
        "asset_count": max(
            _best_count(engine_assets, "asset_count", "resource_count", "file_count"),
            _sequence_count(engine_assets.get("asset_examples")),
            _best_count(engine_fragment_summary, "resource_count"),
        ),
        "symbol_count": max(
            _best_count(engine_symbols, "recovered_symbol_count", "symbol_count"),
            _sequence_count(engine_symbols.get("recovered_symbols")),
            _best_count(engine_fragment_summary, "entity_count"),
        ),
        "confidence": _source_confidence("engine_analysis", engine),
    }

    android = _as_mapping(evidence.get("android_analysis"))
    manifest = _as_mapping(android.get("manifest"))
    android_framework = _as_mapping(android.get("framework"))
    android_native = _as_mapping(android.get("native_libs"))
    android_summary = {
        "present": _has_content(android),
        "package_type": _first_text(android.get("package_type"), android.get("type")),
        "framework": _first_text(
            android_framework.get("name"), android.get("framework"), android.get("language")
        ),
        "application_id": _first_text(
            manifest.get("package"), manifest.get("package_name"), android.get("package_name")
        ),
        "native_library_count": max(
            _best_count(android_native, "library_count", "native_library_count", "count"),
            _sequence_count(android_native.get("entries")),
        ),
        "confidence": _source_confidence("android_analysis", android),
    }

    protocol = _as_mapping(evidence.get("protocol_analysis"))
    protocols = []
    for item in _mapping_list(protocol.get("protocols"))[:20]:
        name = _first_text(item.get("name"), item.get("protocol"))
        if name:
            protocols.append({"name": name[:80], "confidence": _clamp(item.get("confidence"), 0.5)})
    flows = []
    for item in _mapping_list(protocol.get("flows"))[:20]:
        endpoint = _first_text(item.get("endpoint"), item.get("url"), item.get("host"))
        if endpoint:
            flows.append({"endpoint": endpoint[:300], "kind": _first_text(item.get("kind")) or "unknown"})
    inference = _as_mapping(protocol.get("inference"))
    protocol_summary = {
        "present": _has_content(protocol),
        "primary_protocol": _first_text(inference.get("primary_protocol"), protocols[0]["name"] if protocols else None),
        "protocols": protocols,
        "flows": flows,
        "confidence": max(
            [_clamp(inference.get("confidence"), 0.0), *[item["confidence"] for item in protocols]],
            default=0.0,
        ),
    }

    dynamic = evidence.get("dynamic_analysis")
    dynamic_mapping = _as_mapping(dynamic)
    events = dynamic_mapping.get("events") if dynamic_mapping else dynamic
    dynamic_summary = {
        "present": _has_content(dynamic),
        "event_count": _sequence_count(events),
        "api_count": _best_count(dynamic_mapping, "api_count", "observed_api_count", "call_count"),
        "confidence": _source_confidence("dynamic_analysis", dynamic_mapping) if dynamic_mapping else (0.65 if _has_content(dynamic) else 0.0),
    }

    static = _as_mapping(evidence.get("static_analysis"))
    static_summary = {
        "present": _has_content(static),
        "function_count": _sequence_count(static.get("functions")),
        "import_count": _sequence_count(static.get("imports")),
        "confidence": _source_confidence("static_analysis", static),
    }
    return {
        "semantic_ir": semantic_summary,
        "gui_analysis": gui_summary,
        "engine_analysis": engine_summary,
        "android_analysis": android_summary,
        "protocol_analysis": protocol_summary,
        "dynamic_analysis": dynamic_summary,
        "static_analysis": static_summary,
    }


def _build_evidence_index(
    evidence: Mapping[str, Any],
    summary: Mapping[str, Any],
    behavior_hints: Mapping[str, Any],
) -> dict[str, Any]:
    sources = []
    for name in _evidence_names():
        value = evidence.get(name)
        present = _has_content(value)
        sources.append(
            {
                "name": name,
                "present": present,
                "sha256": _json_digest(value) if present else None,
                "confidence": round(float(_as_mapping(summary.get(name)).get("confidence") or 0.0), 3),
                "consumed_paths": _consumed_evidence_paths(name, value) if present else [],
                "summary": dict(_as_mapping(summary.get(name))),
            }
        )
    return {
        "schema_version": _SCHEMA_VERSION,
        "sources": sources,
        "present_sources": [item["name"] for item in sources if item["present"]],
        "behavior_hint_count": _behavior_hint_count(behavior_hints),
        "diagnostic_count": len(evidence.get("_diagnostics") or []),
    }


def _consumed_evidence_paths(name: str, value: Any) -> list[str]:
    candidates = {
        "semantic_ir": ("entities", "relations", "capabilities", "summary"),
        "gui_analysis": (
            "framework",
            "strategy",
            "runtime_tree",
            "visual",
            "resources",
            "handlers",
            "event_handlers",
        ),
        "engine_analysis": (
            "engine",
            "confidence",
            "metadata",
            "assets",
            "symbols",
            "semantic_ir_fragment",
        ),
        "android_analysis": (
            "package_type",
            "framework",
            "manifest",
            "resources",
            "dex_summary",
            "native_libs",
            "semantic_ir_fragment",
        ),
        "protocol_analysis": (
            "protocols",
            "flows",
            "field_stats",
            "inference",
            "messages",
            "semantic_ir_fragment",
        ),
        "dynamic_analysis": ("events", "calls", "api_calls", "modules", "status", "confidence"),
        "static_analysis": ("functions", "classes", "imports", "exports", "strings", "resources"),
    }
    mapping = _as_mapping(value)
    return [f"{name}.{key}" for key in candidates.get(name, ()) if _has_content(mapping.get(key))]


def _build_behavior_hints(
    evidence: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    gui = _as_mapping(evidence.get("gui_analysis"))
    engine = _as_mapping(evidence.get("engine_analysis"))
    engine_symbols = _as_mapping(engine.get("symbols"))
    android = _as_mapping(evidence.get("android_analysis"))
    manifest = _as_mapping(android.get("manifest"))
    protocol = _as_mapping(evidence.get("protocol_analysis"))
    inference = _as_mapping(protocol.get("inference"))
    dynamic = evidence.get("dynamic_analysis")
    dynamic_mapping = _as_mapping(dynamic)
    dynamic_events = dynamic_mapping.get("events") if dynamic_mapping else dynamic
    static = _as_mapping(evidence.get("static_analysis"))

    gui_controls = _named_nodes(
        gui.get("runtime_tree") or gui.get("controls") or gui.get("widgets"),
        source="gui_analysis.runtime_tree",
        limit=64,
    )
    gui_handlers = [
        {"name": name, "source": "gui_analysis.handlers"}
        for name in _gui_handler_names(gui)[:64]
    ]

    recovered_engine_symbols: list[dict[str, Any]] = []
    for key in (
        "mono_behaviour_symbols",
        "monobehaviour_symbols",
        "scriptable_object_symbols",
        "ui_symbols",
        "recovered_symbols",
    ):
        for item in _text_values(engine_symbols.get(key)):
            recovered_engine_symbols.append(
                {"name": _safe_symbol_name(item), "source": f"engine_analysis.symbols.{key}"}
            )
    recovered_engine_symbols = _dedupe_named_records(recovered_engine_symbols, limit=96)

    android_components: list[dict[str, Any]] = []
    for key in ("activities", "services", "receivers", "providers"):
        for item in _mapping_list(manifest.get(key))[:64]:
            component_name = _first_text(item.get("name"), item.get("class"))
            if component_name:
                android_components.append(
                    {
                        "name": _safe_symbol_name(component_name),
                        "kind": key[:-1] if key.endswith("s") else key,
                        "source": f"android_analysis.manifest.{key}",
                    }
                )

    protocol_flows = []
    for item in _mapping_list(protocol.get("flows"))[:64]:
        endpoint = _first_text(item.get("endpoint"), item.get("url"), item.get("host"), item.get("flow_id"))
        if endpoint:
            protocol_flows.append(
                {
                    "endpoint": endpoint[:300],
                    "transport": _first_text(item.get("transport"), item.get("kind")) or "unknown",
                    "source": "protocol_analysis.flows",
                }
            )
    format_values = inference.get("message_formats") or protocol.get("message_formats") or []
    protocol_formats = [
        {"name": _safe_symbol_name(item), "source": "protocol_analysis.inference.message_formats"}
        for item in _text_values(format_values)[:64]
    ]

    dynamic_calls = []
    if isinstance(dynamic_events, Sequence) and not isinstance(dynamic_events, (str, bytes, bytearray)):
        for item in dynamic_events[:96]:
            if not isinstance(item, Mapping):
                continue
            name = _first_text(
                item.get("api"), item.get("function"), item.get("symbol"), item.get("name"), item.get("event")
            )
            if name:
                dynamic_calls.append(
                    {
                        "name": _safe_symbol_name(name),
                        "category": _first_text(item.get("category"), item.get("type")) or "unknown",
                        "source": "dynamic_analysis.events",
                    }
                )

    static_imports = []
    imports = static.get("imports")
    if isinstance(imports, Sequence) and not isinstance(imports, (str, bytes, bytearray)):
        for item in imports[:96]:
            if isinstance(item, Mapping):
                name = _first_text(item.get("name"), item.get("symbol"), item.get("api"), item.get("dll"))
            else:
                name = _first_text(item)
            if name:
                static_imports.append(
                    {"name": _safe_symbol_name(name), "source": "static_analysis.imports"}
                )

    return {
        "schema_version": _SCHEMA_VERSION,
        "framework": _first_text(
            _as_mapping(android.get("framework")).get("name"),
            _as_mapping(summary.get("gui_analysis")).get("framework"),
        ),
        "gui_controls": gui_controls,
        "gui_handlers": gui_handlers,
        "engine_symbols": recovered_engine_symbols,
        "android_components": _dedupe_named_records(android_components, limit=96),
        "protocol_flows": protocol_flows,
        "protocol_formats": _dedupe_named_records(protocol_formats, limit=64),
        "dynamic_calls": _dedupe_named_records(dynamic_calls, limit=96),
        "static_imports": _dedupe_named_records(static_imports, limit=96),
    }


def _named_nodes(value: Any, *, source: str, limit: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    stack: list[Any] = [value]
    visited = 0
    while stack and len(records) < limit and visited < 1000:
        current = stack.pop()
        visited += 1
        if isinstance(current, Mapping):
            name = _first_text(
                current.get("name"), current.get("label"), current.get("title"), current.get("automation_id")
            )
            if name:
                records.append(
                    {
                        "name": _safe_symbol_name(name),
                        "kind": _first_text(current.get("type"), current.get("control_type"), current.get("role"))
                        or "control",
                        "source": source,
                    }
                )
            for nested in reversed(list(current.values())[:_MAX_MAPPING_ITEMS]):
                if isinstance(nested, (Mapping, list, tuple)):
                    stack.append(nested)
        elif isinstance(current, (list, tuple)):
            stack.extend(reversed(current[:_MAX_SEQUENCE_ITEMS]))
    return _dedupe_named_records(records, limit=limit)


def _dedupe_named_records(records: Iterable[Mapping[str, Any]], *, limit: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in records:
        name = _first_text(item.get("name"), item.get("endpoint"))
        if not name:
            continue
        key = (str(item.get("source") or "").casefold(), name.casefold())
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(item))
        if len(result) >= limit:
            break
    return result


def _behavior_hint_count(value: Mapping[str, Any]) -> int:
    return sum(len(item) for item in value.values() if isinstance(item, list))


def _select_stack(
    sample_suffix: str,
    evidence: Mapping[str, Any],
    summary: Mapping[str, Any],
    strategy: str,
) -> dict[str, Any]:
    requested = _STACK_ALIASES.get(str(strategy).strip().lower())
    if requested is None:
        supported = ", ".join(sorted(_STACK_ALIASES))
        raise ValueError(f"unsupported source reconstruction strategy {strategy!r}; expected one of: {supported}")

    scores = {stack: 0.0 for stack in _SUPPORTED_STACKS}
    scores["c"] = 0.12
    signals: list[dict[str, Any]] = []

    def add(stack: str, weight: float, source: str, reason: str) -> None:
        scores[stack] += weight
        signals.append({"stack": stack, "source": source, "weight": round(weight, 3), "reason": reason})

    android_text = _canonical_text(evidence.get("android_analysis")).lower()
    if sample_suffix in {".apk", ".aab"}:
        add("android-java", 0.72, "sample.extension", f"{sample_suffix} is an Android package")
        add("android-kotlin", 0.72, "sample.extension", f"{sample_suffix} is an Android package")
    if summary["android_analysis"]["present"]:
        add("android-java", 0.78, "android_analysis", "Android package evidence is present")
        add("android-kotlin", 0.78, "android_analysis", "Android package evidence is present")
        if "kotlin" in android_text or any(token in android_text for token in ("kotlin_metadata", ".kt", "kotlinx")):
            add("android-kotlin", 0.38, "android_analysis", "Kotlin runtime or source indicators are present")
        elif "java" in android_text or ".java" in android_text:
            add("android-java", 0.34, "android_analysis", "Java source indicators are present")
        else:
            add("android-java", 0.04, "android_analysis", "Java is the conservative Android fallback")

    engine_name = str(summary["engine_analysis"].get("engine") or "").lower()
    engine_text = _canonical_text(evidence.get("engine_analysis")).lower()
    if engine_name.startswith("unity") or any(token in engine_text for token in ("unityplayer", "assembly-csharp", "globalgamemanagers")):
        add("unity-csharp", 1.18, "engine_analysis", "Unity engine evidence is present")
    if engine_name.startswith("unreal") or any(token in engine_text for token in ("unrealengine", "ue4", "ue5")):
        add("cpp", 1.08, "engine_analysis", "Unreal engine evidence favors C++")

    gui_text = _canonical_text(evidence.get("gui_analysis")).lower()
    if any(token in gui_text for token in ("electron", "chromium", "node.js", "nodejs", "asar")):
        add("electron", 1.02, "gui_analysis", "Electron/Chromium GUI evidence is present")
    if any(token in gui_text for token in ("wpf", "winforms", "windows forms", "xaml", ".net", "dotnet")):
        add("csharp", 0.98, "gui_analysis", ".NET desktop GUI evidence is present")
    if any(token in gui_text for token in ("qt", "qml", "mfc")):
        add("cpp", 0.96, "gui_analysis", "Native C++ GUI framework evidence is present")

    all_text = _canonical_text(evidence).lower()
    if any(token in all_text for token in ("pyinstaller", "_meipass", "pyz-", "pyz_", "python3.dll", "python311.dll")):
        add("pyinstaller-python", 1.04, "combined_evidence", "PyInstaller/Python loader evidence is present")
    if any(token in all_text for token in ("mscoree.dll", "system.windows.forms", "presentationframework")):
        add("csharp", 0.66, "combined_evidence", "CLR assembly/import evidence is present")
    if any(token in all_text for token in ("libstdc++", "msvcp", "std::", "qtcore")):
        add("cpp", 0.56, "combined_evidence", "C++ runtime or symbol evidence is present")

    if requested == "android":
        requested = "android-kotlin" if "kotlin" in android_text else "android-java"
    if requested != "auto":
        add(requested, max(0.8, max(scores.values()) + 0.01), "strategy", "Caller explicitly selected this stack")
        selected = requested
    else:
        selected = min(_STACK_ORDER, key=lambda stack: (-scores[stack], _STACK_ORDER.index(stack)))

    return {
        "stack": selected,
        "strength": round(min(0.99, scores[selected]), 3),
        "scores": {stack: round(scores[stack], 3) for stack in sorted(scores)},
        "signals": sorted(signals, key=lambda item: (item["source"], item["stack"], item["reason"])),
    }


def _build_confidence(
    selection: Mapping[str, Any],
    evidence: Mapping[str, Any],
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    components = {
        name: round(float(summary[name].get("confidence") or 0.0), 3)
        for name in _evidence_names()
    }
    present = [name for name in _evidence_names() if _has_content(evidence.get(name))]
    if not present:
        score = 0.2
    else:
        strength = float(selection["strength"])
        strongest = max((components[name] for name in present), default=0.5)
        coverage = min(1.0, len(present) / float(len(_evidence_names())))
        score = min(0.98, (0.45 * strength) + (0.4 * strongest) + (0.15 * coverage))
        score = max(0.3, score)
    rounded = round(score, 3)
    level = "high" if rounded >= 0.8 else "medium" if rounded >= 0.5 else "low"
    reasons = [
        f"stack selection strength={float(selection['strength']):.3f}",
        f"evidence sources present={len(present)}/{len(_evidence_names())}",
    ]
    if not present:
        reasons.append("No reconstruction evidence was supplied; the native C fallback is speculative.")
    else:
        reasons.append(f"strongest evidence confidence={max(components[name] for name in present):.3f}")
    return {
        "schema_version": _SCHEMA_VERSION,
        "score": rounded,
        "level": level,
        "components": components,
        "reasons": reasons,
        "method": "bounded weighted evidence fusion",
    }


def _build_provenance(
    sample: Mapping[str, Any],
    evidence: Mapping[str, Any],
    summary: Mapping[str, Any],
    selection: Mapping[str, Any],
) -> dict[str, Any]:
    inputs = []
    for name in _evidence_names():
        value = evidence.get(name)
        present = _has_content(value)
        inputs.append(
            {
                "name": name,
                "present": present,
                "sha256": _json_digest(value) if present else None,
                "confidence": round(float(summary[name].get("confidence") or 0.0), 3),
                "consumed_paths": _consumed_evidence_paths(name, value) if present else [],
            }
        )
    return {
        "schema_version": _SCHEMA_VERSION,
        "generator": {
            "name": "reverse_analyzer.source_reconstruction",
            "version": _GENERATOR_VERSION,
            "deterministic": True,
        },
        "sample": dict(sample),
        "inputs": inputs,
        "selection": {
            "stack": selection["stack"],
            "signals": selection["signals"],
        },
    }


def _extract_symbols(
    evidence: Mapping[str, Any],
    fallback_confidence: float,
    *,
    decompiler_functions: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []

    def add_entity(raw: Mapping[str, Any], source: str, index: int) -> None:
        kind = _symbol_kind(raw.get("kind") or raw.get("type") or raw.get("entity_type"))
        if kind is None:
            return
        name = _first_text(raw.get("name"), raw.get("symbol"), raw.get("label"), raw.get("id"))
        if not name:
            name = f"recovered_{kind}_{index}"
        provenance = [_safe_provenance(source)]
        raw_sources = raw.get("sources") or raw.get("provenance")
        if isinstance(raw_sources, str):
            raw_sources = [raw_sources]
        if isinstance(raw_sources, Sequence):
            provenance.extend(_safe_provenance(item) for item in raw_sources[:_MAX_PROVENANCE_ITEMS])
        entity_id = _first_text(raw.get("id"))
        if entity_id:
            provenance.append(_safe_provenance(f"{source}:{entity_id}"))
        attributes = _as_mapping(raw.get("attributes"))
        address = _normalize_address(
            raw.get("entry")
            or raw.get("address")
            or raw.get("offset")
            or attributes.get("entry")
            or attributes.get("address")
            or attributes.get("offset")
        )
        signature = _first_text(
            raw.get("signature"),
            raw.get("prototype"),
            attributes.get("signature"),
            attributes.get("prototype"),
        )
        item = {
            "name": _safe_symbol_name(name),
            "kind": kind,
            "confidence": _clamp(raw.get("confidence"), max(0.2, fallback_confidence * 0.7)),
            "provenance": _unique_text(provenance),
            "placeholder": True,
        }
        if address:
            item["address"] = address
        if signature:
            item["signature"] = signature
        if entity_id:
            item["entity_id"] = entity_id
        collected.append(item)

    semantic = _as_mapping(evidence.get("semantic_ir"))
    for index, entity in enumerate(_mapping_list(semantic.get("entities")), start=1):
        add_entity(entity, "semantic_ir.entities", index)

    for index, function in enumerate(decompiler_functions[:_MAX_SYMBOLS], start=1):
        add_entity(
            function,
            _safe_provenance(function.get("_source") or "decompiler.functions"),
            index,
        )

    engine = _as_mapping(evidence.get("engine_analysis"))
    engine_fragment = _as_mapping(engine.get("semantic_ir_fragment"))
    for index, entity in enumerate(_mapping_list(engine_fragment.get("entities")), start=1):
        add_entity(entity, "engine_analysis.semantic_ir_fragment.entities", index)

    engine_symbols = _as_mapping(engine.get("symbols"))
    engine_symbol_groups = (
        ("mono_behaviour_symbols", "class"),
        ("monobehaviour_symbols", "class"),
        ("scriptable_object_symbols", "class"),
        ("ui_symbols", "class"),
        ("class_symbols", "class"),
        ("method_symbols", "method"),
        ("recovered_symbols", "class"),
    )
    engine_index = 0
    for key, default_kind in engine_symbol_groups:
        for value in _text_values(engine_symbols.get(key)):
            engine_index += 1
            add_entity(
                {
                    "kind": default_kind,
                    "name": value,
                    "confidence": _source_confidence("engine_analysis", engine),
                },
                f"engine_analysis.symbols.{key}",
                engine_index,
            )

    android = _as_mapping(evidence.get("android_analysis"))
    fragment = _as_mapping(android.get("semantic_ir_fragment"))
    for index, entity in enumerate(_mapping_list(fragment.get("entities")), start=1):
        add_entity(entity, "android_analysis.semantic_ir_fragment.entities", index)

    manifest = _as_mapping(android.get("manifest"))
    android_index = 0
    for key, entity_kind in (
        ("activities", "android_activity"),
        ("services", "android_service"),
        ("receivers", "android_receiver"),
        ("providers", "android_provider"),
    ):
        values = manifest.get(key)
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
            continue
        for raw in values[:64]:
            android_index += 1
            if isinstance(raw, Mapping):
                item = dict(raw)
                item.setdefault("kind", entity_kind)
            else:
                item = {"kind": entity_kind, "name": raw}
            item.setdefault("confidence", _source_confidence("android_analysis", android))
            add_entity(item, f"android_analysis.manifest.{key}", android_index)

    static = _as_mapping(evidence.get("static_analysis"))
    classes = static.get("classes")
    if isinstance(classes, Sequence) and not isinstance(classes, (str, bytes, bytearray)):
        for index, raw in enumerate(classes[:_MAX_SYMBOLS], start=1):
            if isinstance(raw, Mapping):
                item = dict(raw)
                item.setdefault("kind", "class")
            else:
                item = {"kind": "class", "name": raw}
            add_entity(item, "static_analysis.classes", index)

    functions = static.get("functions")
    if isinstance(functions, Sequence) and not isinstance(functions, (str, bytes, bytearray)):
        for index, raw in enumerate(functions[:_MAX_SYMBOLS], start=1):
            if isinstance(raw, Mapping):
                item = dict(raw)
                item.setdefault("kind", "function")
            else:
                item = {"kind": "function", "name": raw}
            add_entity(item, "static_analysis.functions", index)

    gui = _as_mapping(evidence.get("gui_analysis"))
    for index, handler in enumerate(_gui_handler_names(gui), start=1):
        add_entity(
            {"kind": "function", "name": handler, "confidence": _source_confidence("gui_analysis", gui)},
            "gui_analysis.handlers",
            index,
        )

    dynamic = evidence.get("dynamic_analysis")
    dynamic_mapping = _as_mapping(dynamic)
    events = dynamic_mapping.get("events") if dynamic_mapping else dynamic
    if isinstance(events, Sequence) and not isinstance(events, (str, bytes, bytearray)):
        for index, raw in enumerate(events[:96], start=1):
            if not isinstance(raw, Mapping):
                continue
            name = _first_text(raw.get("api"), raw.get("function"), raw.get("symbol"))
            if not name:
                continue
            add_entity(
                {
                    "kind": "function",
                    "name": name,
                    "confidence": _source_confidence("dynamic_analysis", dynamic_mapping),
                },
                "dynamic_analysis.events",
                index,
            )

    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in collected:
        key = _symbol_identity(item)
        existing = merged.get(key)
        if existing is None:
            merged[key] = item
        else:
            _merge_symbol(existing, item)

    values = list(merged.values())
    retained: list[dict[str, Any]] = []
    identified = [item for item in values if item.get("address") or item.get("signature")]
    for item in values:
        if item.get("address") or item.get("signature") or item.get("kind") == "class":
            retained.append(item)
            continue
        candidates = [
            candidate
            for candidate in identified
            if candidate.get("kind") in {"function", "method"}
            and item.get("kind") in {"function", "method"}
            and _symbol_name_key(candidate.get("name")) == _symbol_name_key(item.get("name"))
        ]
        if len(candidates) == 1:
            _merge_symbol(candidates[0], item)
        else:
            retained.append(item)
    return sorted(
        retained,
        key=lambda item: (
            item["kind"],
            item["name"].casefold(),
            _address_sort_key(item.get("address")),
            str(item.get("signature") or ""),
        ),
    )[:_MAX_SYMBOLS]


def _symbol_identity(item: Mapping[str, Any]) -> tuple[str, str, str]:
    category = "callable" if item.get("kind") in {"function", "method"} else str(item.get("kind"))
    address = _normalize_address(item.get("address"))
    if address and category == "callable":
        return (category, "address", address)
    signature = _signature_key(item.get("signature"))
    if signature and category == "callable":
        return (category, "signature", signature)
    return (category, "name", _symbol_name_key(item.get("name")))


def _merge_symbol(target: dict[str, Any], incoming: Mapping[str, Any]) -> None:
    target["confidence"] = max(float(target["confidence"]), float(incoming["confidence"]))
    target["provenance"] = _unique_text([*target["provenance"], *incoming["provenance"]])
    for key in ("address", "signature", "entity_id"):
        if not target.get(key) and incoming.get(key):
            target[key] = incoming[key]


def _gui_handler_names(gui: Mapping[str, Any]) -> list[str]:
    names: list[str] = []
    stack: list[Any] = [gui]
    visited = 0
    while stack and visited < 1000:
        current = stack.pop()
        visited += 1
        if isinstance(current, Mapping):
            for key, value in sorted(current.items(), key=lambda item: str(item[0]), reverse=True):
                normalized = str(key).lower()
                if normalized in {"handler", "handlers", "event_handler", "event_handlers", "callback", "callbacks"}:
                    names.extend(_text_values(value))
                if isinstance(value, (Mapping, list, tuple)):
                    stack.append(value)
        elif isinstance(current, (list, tuple)):
            stack.extend(reversed(current[:_MAX_SEQUENCE_ITEMS]))
    return sorted({_safe_symbol_name(item) for item in names if item})[:64]


def _text_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        results: list[str] = []
        for key, item in value.items():
            if isinstance(item, str):
                results.append(item)
            elif isinstance(key, str) and isinstance(item, (bool, int, float)):
                results.append(key)
        return results
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        results = []
        for item in value:
            if isinstance(item, str):
                results.append(item)
            elif isinstance(item, Mapping):
                text = _first_text(item.get("name"), item.get("handler"), item.get("callback"))
                if text:
                    results.append(text)
        return results
    return []


def _symbol_kind(value: Any) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_")
    if not normalized:
        return None
    if "class" in normalized or normalized in {
        "type", "component", "controller", "view", "view_model", "model", "service", "module",
        "mono_behaviour", "monobehaviour", "scriptable_object", "unity_component", "ui_component",
        "android_activity", "android_service", "android_receiver", "android_provider", "java_class",
        "uobject", "uclass", "actor", "widget",
    }:
        return "class"
    if "method" in normalized or normalized in {"ufunction", "android_method"}:
        return "method"
    if "function" in normalized or normalized in {
        "handler", "ui_handler", "callback", "action", "ui_action", "entrypoint", "procedure", "proc"
    }:
        return "function"
    return None


def _semantic_projection(value: Any) -> dict[str, Any] | None:
    semantic = _as_mapping(value)
    if not semantic:
        return None
    entities = []
    for index, item in enumerate(_mapping_list(semantic.get("entities"))[:_MAX_SYMBOLS], start=1):
        entities.append(
            {
                "id": _first_text(item.get("id")) or f"entity:{index}",
                "kind": _first_text(item.get("kind")) or "unknown",
                "name": _first_text(item.get("name"), item.get("label")) or f"entity_{index}",
                "confidence": _clamp(item.get("confidence"), 0.5),
                "sources": _normalized_provenance(item.get("sources") or ["semantic_ir.entities"]),
            }
        )
    raw_relations = semantic.get("relations")
    raw_capabilities = semantic.get("capabilities")
    relations = []
    for index, item in enumerate(_mapping_list(raw_relations)[:_MAX_SEQUENCE_ITEMS], start=1):
        source = _first_text(item.get("source"), item.get("from"), item.get("source_id"))
        target = _first_text(item.get("target"), item.get("to"), item.get("target_id"))
        if not source and not target:
            continue
        relations.append(
            {
                "id": _first_text(item.get("id")) or f"relation:{index}",
                "kind": _first_text(item.get("kind"), item.get("type"), item.get("relation")) or "related_to",
                "source": source,
                "target": target,
                "confidence": _clamp(item.get("confidence"), 0.5),
                "sources": _normalized_provenance(item.get("sources") or ["semantic_ir.relations"]),
            }
        )

    capabilities = []
    if isinstance(raw_capabilities, Sequence) and not isinstance(raw_capabilities, (str, bytes, bytearray)):
        for index, item in enumerate(raw_capabilities[:_MAX_SEQUENCE_ITEMS], start=1):
            if isinstance(item, Mapping):
                name = _first_text(item.get("name"), item.get("capability"), item.get("id"))
                confidence = item.get("confidence")
                sources = item.get("sources")
            else:
                name = _first_text(item)
                confidence = None
                sources = None
            if not name:
                continue
            capabilities.append(
                {
                    "id": f"capability:{index}",
                    "name": name,
                    "confidence": _clamp(confidence, 0.5),
                    "sources": _normalized_provenance(sources or ["semantic_ir.capabilities"]),
                }
            )

    raw_relation_count = len(raw_relations) if isinstance(raw_relations, list) else 0
    raw_capability_count = len(raw_capabilities) if isinstance(raw_capabilities, list) else 0
    return {
        "schema_version": semantic.get("schema_version") or _SCHEMA_VERSION,
        "entities": entities,
        "relations": relations,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "capability_count": len(capabilities),
            "input_entity_count": len(_mapping_list(semantic.get("entities"))),
            "input_relation_count": raw_relation_count,
            "input_capability_count": raw_capability_count,
            "projection": True,
        },
    }


def _placeholder_notes(symbols: Sequence[Mapping[str, Any]], evidence: Mapping[str, Any]) -> list[str]:
    unresolved = sum(
        1
        for item in symbols
        if item.get("kind") in {"function", "method"} and item.get("placeholder", True)
    )
    notes = ["Generated class fields and inheritance are placeholders unless directly represented by evidence."]
    if unresolved:
        notes.insert(0, f"{unresolved} function or method bodies remain explicit placeholders.")
    if not symbols:
        notes.append("No semantic symbols were supplied; a recovered_entry placeholder was generated.")
    if not _has_content(evidence.get("protocol_analysis")):
        notes.append("No protocol contract was supplied; transport behavior is intentionally unimplemented.")
    if not _has_content(evidence.get("dynamic_analysis")):
        notes.append("No dynamic trace was supplied; runtime ordering and side effects remain unknown.")
    return notes


def _render_stack(
    stack: str,
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    renderers = {
        "c": _render_c,
        "cpp": _render_cpp,
        "csharp": _render_csharp,
        "electron": _render_electron,
        "android-java": _render_android_java,
        "android-kotlin": _render_android_kotlin,
        "unity-csharp": _render_unity,
        "pyinstaller-python": _render_python,
    }
    return renderers[stack](
        slug=slug,
        sample_name=sample_name,
        symbols=symbols,
        evidence_summary=evidence_summary,
        overall_confidence=overall_confidence,
    )


def _prepare_symbols(
    symbols: Sequence[Mapping[str, Any]],
    *,
    style: str,
    function_file: str,
    class_file: str,
    reserved: Iterable[str],
) -> list[dict[str, Any]]:
    used = {str(item).casefold() for item in reserved}
    prepared = []
    for item in symbols:
        identifier = _identifier(item["name"], style=style, used=used)
        prepared_item = {
            "name": item["name"],
            "identifier": identifier,
            "kind": item["kind"],
            "file": class_file if item["kind"] == "class" else function_file,
            "provenance": _normalized_provenance(item["provenance"]),
            "confidence": round(float(item["confidence"]), 3),
            "placeholder": bool(item.get("placeholder", True)),
        }
        for key in (
            "address",
            "signature",
            "entity_id",
            "body_recovery",
            "_recovered_definition",
            "_recovered_declaration",
        ):
            if key in item:
                prepared_item[key] = item[key]
        prepared.append(prepared_item)
    return prepared


def _builtin_symbol(
    name: str,
    kind: str,
    file: str,
    stack: str,
    confidence: float,
    *,
    placeholder: bool,
) -> dict[str, Any]:
    return {
        "name": name,
        "identifier": name,
        "kind": kind,
        "file": file,
        "provenance": [f"generator:{stack}-template"],
        "confidence": round(_clamp(confidence, 0.2), 3),
        "placeholder": placeholder,
    }


def _file_spec(
    content: str,
    *,
    kind: str,
    provenance: Iterable[Any],
    confidence: float,
    placeholder: bool,
) -> dict[str, Any]:
    return {
        "content": content if content.endswith("\n") or not content else content + "\n",
        "kind": kind,
        "provenance": _normalized_provenance(provenance),
        "confidence": round(_clamp(confidence, 0.0), 3),
        "placeholder": bool(placeholder),
    }


def _source_spec(
    content: str,
    *,
    stack: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_sources: Iterable[str],
    overall_confidence: float,
    kind: str = "source",
) -> dict[str, Any]:
    provenance = [f"generator:{stack}-template"]
    provenance.extend(f"evidence:{name}" for name in evidence_sources)
    for symbol in symbols:
        provenance.extend(symbol.get("provenance") or [])
    confidence = max(
        [overall_confidence * 0.85, *[float(item.get("confidence") or 0.0) for item in symbols]],
        default=overall_confidence * 0.85,
    )
    return _file_spec(
        content,
        kind=kind,
        provenance=provenance,
        confidence=confidence,
        placeholder=any(bool(item.get("placeholder", True)) for item in symbols),
    )


def _config_spec(content: str, stack: str, overall_confidence: float, *, kind: str = "build") -> dict[str, Any]:
    return _file_spec(
        content,
        kind=kind,
        provenance=(f"generator:{stack}-template", f"selection:{stack}"),
        confidence=max(0.2, overall_confidence * 0.8),
        placeholder=False,
    )


def _file_record(path: str, spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path": path,
        "kind": spec["kind"],
        "provenance": list(spec["provenance"]),
        "confidence": spec["confidence"],
        "placeholder": spec["placeholder"],
    }


def _identifier(value: Any, *, style: str, used: set[str]) -> str:
    text = _ascii_text(str(value or ""), fallback="recovered_symbol")
    words = re.findall(r"[A-Za-z0-9]+", text)
    if not words:
        words = ["recovered", "symbol"]
    if style in {"pascal", "csharp", "java-class", "js-class", "python-class"}:
        base = "".join(word[:1].upper() + word[1:] for word in words)
    elif style in {"camel", "java", "js"}:
        first, *rest = words
        base = first[:1].lower() + first[1:] + "".join(word[:1].upper() + word[1:] for word in rest)
    else:
        base = "_".join(word.lower() for word in words)
    base = base[:80] or "recovered_symbol"
    if base[0].isdigit():
        base = f"recovered_{base}"
    reserved = _reserved_for_style(style)
    if base.casefold() in reserved:
        base = f"recovered_{base}"
    candidate = base
    suffix = 2
    while candidate.casefold() in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate.casefold())
    return candidate


def _reserved_for_style(style: str) -> frozenset[str]:
    if style == "c":
        return _C_RESERVED
    if style == "cpp":
        return _CPP_RESERVED
    if style in {"csharp", "pascal"}:
        return _CS_RESERVED
    if style in {"java", "java-class"}:
        return _JAVA_RESERVED
    if style in {"js", "js-class"}:
        return _JS_RESERVED
    if style in {"python", "python-class"}:
        return _PY_RESERVED
    return frozenset()


def _readme(
    *,
    sample_name: str,
    stack: str,
    confidence: float,
    evidence_summary: Mapping[str, Any],
    run_lines: Sequence[str],
) -> str:
    present = [name for name in _evidence_names() if evidence_summary[name]["present"]]
    evidence_text = ", ".join(present) if present else "none"
    commands = "\n".join(f"- `{line}`" for line in run_lines)
    return (
        f"# Reconstructed {_ascii_text(sample_name, fallback='sample')}\n\n"
        f"Stack: `{stack}`  \n"
        f"Confidence: `{confidence:.3f}`  \n"
        f"Evidence consumed: `{evidence_text}`\n\n"
        "This is an editable reconstruction skeleton. It does not claim source equivalence with the input binary.\n"
        "Unmatched or invalid body artifacts remain explicit placeholders.\n\n"
        "## Open or run\n\n"
        f"{commands}\n"
    )


def _evidence_comment(summary: Mapping[str, Any], marker: str = "//") -> str:
    parts = []
    framework = summary["gui_analysis"].get("framework")
    engine = summary["engine_analysis"].get("engine")
    protocol = summary["protocol_analysis"].get("primary_protocol")
    if framework:
        parts.append(f"gui={framework}")
    if engine:
        parts.append(f"engine={engine}")
    if protocol:
        parts.append(f"protocol={protocol}")
    dynamic_count = summary["dynamic_analysis"].get("event_count") or 0
    if dynamic_count:
        parts.append(f"dynamic_events={dynamic_count}")
    text = ", ".join(parts) if parts else "no direct behavioral evidence"
    return f"{marker} Evidence: {_ascii_text(text, fallback='none')}"


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mapping_list(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _first_text(*values: Any) -> str | None:
    for value in values:
        if value is None or isinstance(value, (Mapping, Sequence, set, frozenset)) and not isinstance(value, str):
            continue
        try:
            text = _safe_evidence_text(str(value))
        except (TypeError, ValueError):
            continue
        if text:
            return text
    return None


def _clamp(value: Any, default: float) -> float:
    fallback = float(default)
    if not math.isfinite(fallback):
        fallback = 0.0
    if isinstance(value, bool):
        return round(max(0.0, min(1.0, fallback)), 3)
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        number = fallback
    if not math.isfinite(number):
        number = fallback
    return round(max(0.0, min(1.0, number)), 3)


def _source_confidence(source: str, value: Mapping[str, Any]) -> float:
    if not value:
        return 0.0
    defaults = {
        "semantic_ir": 0.6,
        "gui_analysis": 0.7,
        "engine_analysis": 0.75,
        "android_analysis": 0.75,
        "protocol_analysis": 0.7,
        "dynamic_analysis": 0.65,
        "static_analysis": 0.55,
    }
    nested = _as_mapping(value.get("summary"))
    candidate = _first_present(value, ("confidence", "score", "certainty"))
    if candidate is None:
        candidate = _first_present(nested, ("confidence", "score", "certainty"))
    return _clamp(candidate, defaults.get(source, 0.5))


def _entity_confidence(entities: Sequence[Mapping[str, Any]]) -> float:
    values = [_clamp(item.get("confidence"), 0.5) for item in entities]
    return round(sum(values) / len(values), 3) if values else 0.0


def _best_count(mapping: Mapping[str, Any], *names: str) -> int:
    for name in names:
        value = mapping.get(name)
        if isinstance(value, bool):
            continue
        try:
            number = int(value)
        except (TypeError, ValueError, OverflowError):
            continue
        return max(0, number)
    return 0


def _sequence_count(value: Any) -> int:
    if isinstance(value, (str, bytes, bytearray)) or value is None:
        return 0
    if isinstance(value, (Mapping, Sequence, set, frozenset)):
        try:
            return len(value)
        except (TypeError, OverflowError):
            return 0
    return 0


def _canonical_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, OverflowError):
        return json.dumps(_bounded_json(value), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _json_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_text(value).encode("utf-8")).hexdigest()


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"


def _type_name(value: Any) -> str:
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"[:160]


def _ascii_text(value: Any, *, fallback: str) -> str:
    try:
        text = str(value).encode("ascii", errors="ignore").decode("ascii")
    except (TypeError, ValueError):
        text = ""
    text = re.sub(r"[^A-Za-z0-9_.:,=+@() -]+", "_", text)
    text = re.sub(r"\s+", " ", text).strip(" ._")
    return (text[:240] or fallback)[:240]


def _safe_slug(value: Any) -> str:
    text = _ascii_text(value, fallback="sample").lower()
    text = re.sub(r"[^a-z0-9]+", "_", text).strip("_")[:48] or "sample"
    if text[0].isdigit():
        text = f"sample_{text}"
    return text


def _safe_symbol_name(value: Any) -> str:
    text = _first_text(value) or "recovered_symbol"
    text = text.replace("*/", "* /").replace("<!--", "< !--")
    return text[:160]


def _safe_provenance(value: Any) -> str:
    text = _first_text(value) or "evidence:unknown"
    text = text.replace("\\", "/").encode("ascii", errors="ignore").decode("ascii")
    text = re.sub(r"[^A-Za-z0-9_.:,=+@()/ -]+", "_", text)
    text = re.sub(r"\s+", " ", text).strip(" ._") or "evidence:unknown"
    return text[:240]


def _unique_text(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = _safe_provenance(value)
        key = text.casefold()
        if key not in seen:
            seen.add(key)
            result.append(text)
    return result[:_MAX_PROVENANCE_ITEMS]


def _normalized_provenance(value: Any) -> list[str]:
    if isinstance(value, str):
        values: Iterable[Any] = (value,)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        values = value
    elif isinstance(value, Iterable) and not isinstance(value, (Mapping, bytes, bytearray)):
        values = value
    else:
        values = ()
    normalized = _unique_text(values)
    return normalized or ["generator:source-reconstruction"]


def _present_evidence(summary: Mapping[str, Any]) -> list[str]:
    return [name for name in _evidence_names() if _as_mapping(summary.get(name)).get("present")]


def _symbol_comment(symbol: Mapping[str, Any], marker: str = "//") -> str:
    references = ", ".join(_normalized_provenance(symbol.get("provenance")))
    confidence = _clamp(symbol.get("confidence"), 0.0)
    placeholder = str(bool(symbol.get("placeholder", True))).lower()
    return f"{marker} Evidence refs: {references}; confidence={confidence:.3f}; placeholder={placeholder}"


def _render_c(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    function_file = "src/reconstructed.c"
    prepared = _prepare_symbols(
        symbols,
        style="c",
        function_file=function_file,
        class_file=function_file,
        reserved=(*_C_RESERVED, "recovered_entry"),
    )
    if not prepared:
        prepared = [_builtin_symbol("recovered_entry", "function", function_file, "c", overall_confidence, placeholder=True)]
    main_symbol = _builtin_symbol("main", "function", "src/main.c", "c", overall_confidence, placeholder=False)
    guard = f"RECONSTRUCTED_{slug.upper()}_H"
    declarations = []
    implementations = []
    for symbol in prepared:
        identifier = symbol["identifier"]
        comment = _symbol_comment(symbol)
        if symbol["kind"] == "class":
            declarations.extend(
                [comment, f"typedef struct {identifier} {{", "    unsigned char placeholder_state;", f"}} {identifier};", ""]
            )
            implementations.extend([comment, f"// TODO: recover fields and behavior for struct {identifier}.", ""])
        else:
            definition = symbol.get("_recovered_definition")
            declaration = symbol.get("_recovered_declaration")
            if isinstance(definition, str) and isinstance(declaration, str):
                declarations.extend([comment, declaration, ""])
                implementations.extend([comment, definition.rstrip(), ""])
            else:
                status = _as_mapping(symbol.get("body_recovery")).get("status") or "unavailable"
                declarations.extend([comment, f"int {identifier}(void);", ""])
                implementations.extend(
                    [
                        comment,
                        f"int {identifier}(void)",
                        "{",
                        f"    /* BODY RECOVERY UNAVAILABLE [{status}]; TODO: reconstruct behavior from cited evidence. */",
                        "    return 0;",
                        "}",
                        "",
                    ]
                )
    header = "\n".join(
        [f"#ifndef {guard}", f"#define {guard}", "", *declarations, f"#endif /* {guard} */", ""]
    )
    source = "\n".join(["#include \"reconstructed.h\"", "", _evidence_comment(evidence_summary), "", *implementations])
    main = "\n".join(
        [
            "#include \"reconstructed.h\"",
            "",
            _evidence_comment(evidence_summary),
            "int main(void)",
            "{",
            "    /* TODO: restore startup ordering and side effects from runtime evidence. */",
            "    return 0;",
            "}",
            "",
        ]
    )
    target = f"reconstructed_{slug}"
    cmake = "\n".join(
        [
            "cmake_minimum_required(VERSION 3.16)",
            f"project({target} LANGUAGES C)",
            "set(CMAKE_C_STANDARD 11)",
            "set(CMAKE_C_STANDARD_REQUIRED ON)",
            f"add_executable({target} src/main.c src/reconstructed.c)",
            f"target_include_directories({target} PRIVATE include)",
            "",
        ]
    )
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        "CMakeLists.txt": _config_spec(cmake, "c", overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="c",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=("cmake -S . -B build", "cmake --build build"),
            ),
            "c",
            overall_confidence,
            kind="documentation",
        ),
        "include/reconstructed.h": _source_spec(
            header,
            stack="c",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
            kind="header",
        ),
        "src/main.c": _source_spec(
            main,
            stack="c",
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        function_file: _source_spec(
            source,
            stack="c",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
    }
    return {
        "language": "c",
        "output_stack": "cmake-c",
        "entrypoints": ["src/main.c"],
        "build_files": ["CMakeLists.txt"],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }


def _render_cpp(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    source_path = "src/reconstructed.cpp"
    header_path = "include/reconstructed.hpp"
    prepared = _prepare_symbols(
        symbols,
        style="cpp",
        function_file=source_path,
        class_file=header_path,
        reserved=(*_CPP_RESERVED, "recovered_entry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol("recovered_entry", "function", source_path, "cpp", overall_confidence, placeholder=True)
        ]
    main_symbol = _builtin_symbol("main", "function", "src/main.cpp", "cpp", overall_confidence, placeholder=False)
    declarations = []
    implementations = []
    for symbol in prepared:
        identifier = symbol["identifier"]
        comment = _symbol_comment(symbol)
        if symbol["kind"] == "class":
            declarations.extend(
                [
                    comment,
                    f"class {identifier} final {{",
                    "public:",
                    f"    {identifier}() = default;",
                    "    int run();",
                    "};",
                    "",
                ]
            )
            implementations.extend(
                [
                    comment,
                    f"int {identifier}::run()",
                    "{",
                    "    // TODO: reconstruct class state and behavior from cited evidence.",
                    "    return 0;",
                    "}",
                    "",
                ]
            )
        else:
            definition = symbol.get("_recovered_definition")
            declaration = symbol.get("_recovered_declaration")
            if isinstance(definition, str) and isinstance(declaration, str):
                declarations.extend([comment, declaration, ""])
                implementations.extend([comment, definition.rstrip(), ""])
            else:
                status = _as_mapping(symbol.get("body_recovery")).get("status") or "unavailable"
                declarations.extend([comment, f"int {identifier}();", ""])
                implementations.extend(
                    [
                        comment,
                        f"int {identifier}()",
                        "{",
                        f"    // BODY RECOVERY UNAVAILABLE [{status}]; TODO: reconstruct behavior from cited evidence.",
                        "    return 0;",
                        "}",
                        "",
                    ]
                )
    header = "\n".join(["#pragma once", "", *declarations])
    source = "\n".join(["#include \"reconstructed.hpp\"", "", _evidence_comment(evidence_summary), "", *implementations])
    main = "\n".join(
        [
            "#include \"reconstructed.hpp\"",
            "",
            _evidence_comment(evidence_summary),
            "int main()",
            "{",
            "    // TODO: restore startup ordering and side effects from runtime evidence.",
            "    return 0;",
            "}",
            "",
        ]
    )
    target = f"reconstructed_{slug}"
    cmake = "\n".join(
        [
            "cmake_minimum_required(VERSION 3.16)",
            f"project({target} LANGUAGES CXX)",
            "set(CMAKE_CXX_STANDARD 17)",
            "set(CMAKE_CXX_STANDARD_REQUIRED ON)",
            f"add_executable({target} src/main.cpp src/reconstructed.cpp)",
            f"target_include_directories({target} PRIVATE include)",
            "",
        ]
    )
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        "CMakeLists.txt": _config_spec(cmake, "cpp", overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="cpp",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=("cmake -S . -B build", "cmake --build build"),
            ),
            "cpp",
            overall_confidence,
            kind="documentation",
        ),
        header_path: _source_spec(
            header,
            stack="cpp",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
            kind="header",
        ),
        "src/main.cpp": _source_spec(
            main,
            stack="cpp",
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        source_path: _source_spec(
            source,
            stack="cpp",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
    }
    return {
        "language": "c++",
        "output_stack": "cmake-cpp",
        "entrypoints": ["src/main.cpp"],
        "build_files": ["CMakeLists.txt"],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }


def _render_csharp(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    source_path = "src/Reconstructed.cs"
    prepared = _prepare_symbols(
        symbols,
        style="csharp",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_CS_RESERVED, "Program", "RecoveredFunctions", "RecoveredEntry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol("RecoveredEntry", "function", source_path, "csharp", overall_confidence, placeholder=True)
        ]
    namespace = f"Reconstructed.{_pascal_name(slug)}"
    project_name = f"Reconstructed.{_pascal_name(slug)}"
    project_file = f"{project_name}.csproj"
    methods = []
    classes = []
    for symbol in prepared:
        comment = _symbol_comment(symbol)
        identifier = symbol["identifier"]
        if symbol["kind"] == "class":
            classes.extend(
                [
                    comment,
                    f"public sealed class {identifier}",
                    "{",
                    "    public void Execute()",
                    "    {",
                    "        // TODO: reconstruct class state and behavior from cited evidence.",
                    "        throw new NotImplementedException(\"Recovered class behavior is not implemented.\");",
                    "    }",
                    "}",
                    "",
                ]
            )
        else:
            definition = symbol.get("_recovered_definition")
            if isinstance(definition, str):
                methods.extend(
                    [
                        f"    {comment}",
                        *[f"    {line}" if line else "" for line in definition.rstrip().splitlines()],
                        "",
                    ]
                )
            else:
                status = _as_mapping(symbol.get("body_recovery")).get("status") or "unavailable"
                methods.extend(
                    [
                        f"    {comment}",
                        f"    public static int {identifier}()",
                        "    {",
                        f"        // BODY RECOVERY UNAVAILABLE [{status}]; TODO: reconstruct behavior from cited evidence.",
                        "        return 0;",
                        "    }",
                        "",
                    ]
                )
    recovered = "\n".join(
        [
            "using System;",
            "",
            f"namespace {namespace};",
            "",
            _evidence_comment(evidence_summary),
            "public static class RecoveredFunctions",
            "{",
            *methods,
            "}",
            "",
            *classes,
        ]
    )
    program = "\n".join(
        [
            "using System;",
            "",
            f"namespace {namespace};",
            "",
            _evidence_comment(evidence_summary),
            "internal static class Program",
            "{",
            "    private static int Main(string[] args)",
            "    {",
            "        Console.WriteLine(\"Reconstructed placeholder project; see analysis metadata.\");",
            "        // TODO: restore startup ordering and side effects from runtime evidence.",
            "        return 0;",
            "    }",
            "}",
            "",
        ]
    )
    csproj = "\n".join(
        [
            '<Project Sdk="Microsoft.NET.Sdk">',
            "  <PropertyGroup>",
            "    <OutputType>Exe</OutputType>",
            "    <TargetFramework>net8.0</TargetFramework>",
            "    <ImplicitUsings>enable</ImplicitUsings>",
            "    <Nullable>enable</Nullable>",
            "  </PropertyGroup>",
            "</Project>",
            "",
        ]
    )
    main_symbol = _builtin_symbol("Program.Main", "method", "src/Program.cs", "csharp", overall_confidence, placeholder=False)
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        project_file: _config_spec(csproj, "csharp", overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="csharp",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=(f"dotnet build {project_file}", f"dotnet run --project {project_file}"),
            ),
            "csharp",
            overall_confidence,
            kind="documentation",
        ),
        "src/Program.cs": _source_spec(
            program,
            stack="csharp",
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        source_path: _source_spec(
            recovered,
            stack="csharp",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
    }
    return {
        "language": "csharp",
        "output_stack": "dotnet-console",
        "entrypoints": ["src/Program.cs"],
        "build_files": [project_file],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }


def _pascal_name(value: Any) -> str:
    words = re.findall(r"[A-Za-z0-9]+", _ascii_text(value, fallback="Sample"))
    result = "".join(word[:1].upper() + word[1:] for word in words) or "Sample"
    return f"Sample{result}" if result[0].isdigit() else result


def _render_electron(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    source_path = "src/reconstructed.js"
    prepared = _prepare_symbols(
        symbols,
        style="js",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_JS_RESERVED, "createWindow", "start", "recoveredEntry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol("recoveredEntry", "function", source_path, "electron", overall_confidence, placeholder=True)
        ]
    definitions = []
    exports = []
    for symbol in prepared:
        comment = _symbol_comment(symbol)
        identifier = symbol["identifier"]
        exports.append(identifier)
        if symbol["kind"] == "class":
            definitions.extend(
                [
                    comment,
                    f"class {identifier} {{",
                    "  run() {",
                    "    // TODO: reconstruct class state and behavior from cited evidence.",
                    "    return null;",
                    "  }",
                    "}",
                    "",
                ]
            )
        else:
            definitions.extend(
                [
                    comment,
                    f"function {identifier}() {{",
                    "  // TODO: reconstruct behavior from cited evidence.",
                    "  return null;",
                    "}",
                    "",
                ]
            )
    recovered = "\n".join(
        [
            '"use strict";',
            "",
            _evidence_comment(evidence_summary),
            *definitions,
            f"module.exports = {{ {', '.join(exports)} }};",
            "",
        ]
    )
    main = "\n".join(
        [
            '"use strict";',
            "",
            'const path = require("node:path");',
            "",
            _evidence_comment(evidence_summary),
            "function createWindow(electron) {",
            "  const window = new electron.BrowserWindow({",
            "    width: 960,",
            "    height: 640,",
            "    webPreferences: { contextIsolation: true, nodeIntegration: false },",
            "  });",
            '  void window.loadFile(path.join(__dirname, "web", "index.html"));',
            "  return window;",
            "}",
            "",
            "async function start() {",
            "  let electron;",
            "  try {",
            '    electron = require("electron");',
            "  } catch (error) {",
            '    console.log("Electron runtime is optional; open web/index.html to inspect this skeleton.");',
            "    return;",
            "  }",
            "  await electron.app.whenReady();",
            "  createWindow(electron);",
            "  // TODO: restore application lifecycle and IPC behavior from runtime evidence.",
            "}",
            "",
            "if (require.main === module) {",
            "  void start();",
            "}",
            "",
            "module.exports = { createWindow, start };",
            "",
        ]
    )
    renderer = "\n".join(
        [
            '"use strict";',
            "",
            _evidence_comment(evidence_summary),
            'const status = document.querySelector("[data-reconstruction-status]");',
            "if (status) {",
            '  status.textContent = "Editable placeholder loaded";',
            "}",
            "// TODO: reconnect recovered controls, handlers, and IPC channels.",
            "",
        ]
    )
    html = "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '  <meta charset="utf-8">',
            '  <meta name="viewport" content="width=device-width, initial-scale=1">',
            "  <title>Reconstructed application</title>",
            '  <link rel="stylesheet" href="styles.css">',
            "</head>",
            "<body>",
            "  <main>",
            "    <h1>Reconstructed application skeleton</h1>",
            "    <p data-reconstruction-status>Loading placeholder...</p>",
            "    <!-- TODO: restore recovered views and controls from GUI evidence. -->",
            "  </main>",
            '  <script src="renderer.js"></script>',
            "</body>",
            "</html>",
            "",
        ]
    )
    css = "\n".join(
        [
            ":root { color-scheme: light dark; font-family: system-ui, sans-serif; }",
            "body { margin: 0; padding: 2rem; }",
            "main { max-width: 52rem; margin: 0 auto; }",
            "",
        ]
    )
    package = {
        "name": f"reconstructed-{slug.replace('_', '-')}",
        "version": "0.0.0-reconstructed",
        "private": True,
        "description": "Evidence-backed Electron/JavaScript reconstruction skeleton",
        "main": "main.js",
        "type": "commonjs",
        "scripts": {
            "check": "node --check main.js && node --check src/reconstructed.js && node --check web/renderer.js",
            "start": "node main.js",
        },
        "dependencies": {},
        "devDependencies": {},
    }
    main_symbol = _builtin_symbol("start", "function", "main.js", "electron", overall_confidence, placeholder=False)
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="electron",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=("npm run check", "npm start", "open web/index.html without Electron"),
            ),
            "electron",
            overall_confidence,
            kind="documentation",
        ),
        "main.js": _source_spec(
            main,
            stack="electron",
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "package.json": _config_spec(_json_text(package), "electron", overall_confidence),
        source_path: _source_spec(
            recovered,
            stack="electron",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "web/index.html": _source_spec(
            html,
            stack="electron",
            symbols=(),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
            kind="source",
        ),
        "web/renderer.js": _source_spec(
            renderer,
            stack="electron",
            symbols=(),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "web/styles.css": _source_spec(
            css,
            stack="electron",
            symbols=(),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
            kind="source",
        ),
    }
    return {
        "language": "javascript",
        "output_stack": "electron-js",
        "entrypoints": ["main.js", "web/index.html"],
        "build_files": ["package.json"],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }


def _render_android_java(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    package = _android_package(evidence_summary, slug)
    package_path = package.replace(".", "/")
    activity_path = f"app/src/main/java/{package_path}/MainActivity.java"
    source_path = f"app/src/main/java/{package_path}/RecoveredSymbols.java"
    prepared = _prepare_symbols(
        symbols,
        style="java",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_JAVA_RESERVED, "MainActivity", "RecoveredSymbols", "recoveredEntry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol("recoveredEntry", "function", source_path, "android-java", overall_confidence, placeholder=True)
        ]
    methods = []
    classes = []
    for symbol in prepared:
        identifier = symbol["identifier"]
        comment = _symbol_comment(symbol)
        if symbol["kind"] == "class":
            classes.extend(
                [
                    f"    {comment}",
                    f"    public static final class {identifier} {{",
                    "        public void execute() {",
                    "            // TODO: reconstruct class state and behavior from cited evidence.",
                    '            throw new UnsupportedOperationException("Recovered class behavior is not implemented");',
                    "        }",
                    "    }",
                    "",
                ]
            )
        else:
            methods.extend(
                [
                    f"    {comment}",
                    f"    public static int {identifier}() {{",
                    "        // TODO: reconstruct behavior from cited evidence.",
                    "        return 0;",
                    "    }",
                    "",
                ]
            )
    recovered = "\n".join(
        [
            f"package {package};",
            "",
            _evidence_comment(evidence_summary),
            "public final class RecoveredSymbols {",
            "    private RecoveredSymbols() {}",
            "",
            *methods,
            *classes,
            "}",
            "",
        ]
    )
    activity = "\n".join(
        [
            f"package {package};",
            "",
            "import android.app.Activity;",
            "import android.os.Bundle;",
            "",
            _evidence_comment(evidence_summary),
            "public final class MainActivity extends Activity {",
            "    @Override",
            "    protected void onCreate(Bundle savedInstanceState) {",
            "        super.onCreate(savedInstanceState);",
            "        // TODO: restore the recovered layout, navigation, and event handlers.",
            "    }",
            "}",
            "",
        ]
    )
    return _android_result(
        stack="android-java",
        language="java",
        slug=slug,
        sample_name=sample_name,
        package=package,
        activity_path=activity_path,
        activity_source=activity,
        recovered_path=source_path,
        recovered_source=recovered,
        prepared=prepared,
        evidence_summary=evidence_summary,
        overall_confidence=overall_confidence,
        kotlin=False,
    )


def _render_android_kotlin(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    package = _android_package(evidence_summary, slug)
    package_path = package.replace(".", "/")
    activity_path = f"app/src/main/kotlin/{package_path}/MainActivity.kt"
    source_path = f"app/src/main/kotlin/{package_path}/RecoveredSymbols.kt"
    prepared = _prepare_symbols(
        symbols,
        style="java",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_JAVA_RESERVED, "MainActivity", "RecoveredSymbols", "recoveredEntry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol(
                "recoveredEntry", "function", source_path, "android-kotlin", overall_confidence, placeholder=True
            )
        ]
    methods = []
    classes = []
    for symbol in prepared:
        identifier = symbol["identifier"]
        comment = _symbol_comment(symbol)
        if symbol["kind"] == "class":
            classes.extend(
                [
                    f"    {comment}",
                    f"    class {identifier} {{",
                    "        fun execute(): Nothing {",
                    "            TODO(\"Reconstruct class state and behavior from cited evidence\")",
                    "        }",
                    "    }",
                    "",
                ]
            )
        else:
            methods.extend(
                [
                    f"    {comment}",
                    f"    fun {identifier}(): Int {{",
                    "        // TODO: reconstruct behavior from cited evidence.",
                    "        return 0",
                    "    }",
                    "",
                ]
            )
    recovered = "\n".join(
        [
            f"package {package}",
            "",
            _evidence_comment(evidence_summary),
            "object RecoveredSymbols {",
            *methods,
            *classes,
            "}",
            "",
        ]
    )
    activity = "\n".join(
        [
            f"package {package}",
            "",
            "import android.app.Activity",
            "import android.os.Bundle",
            "",
            _evidence_comment(evidence_summary),
            "class MainActivity : Activity() {",
            "    override fun onCreate(savedInstanceState: Bundle?) {",
            "        super.onCreate(savedInstanceState)",
            "        // TODO: restore the recovered layout, navigation, and event handlers.",
            "    }",
            "}",
            "",
        ]
    )
    return _android_result(
        stack="android-kotlin",
        language="kotlin",
        slug=slug,
        sample_name=sample_name,
        package=package,
        activity_path=activity_path,
        activity_source=activity,
        recovered_path=source_path,
        recovered_source=recovered,
        prepared=prepared,
        evidence_summary=evidence_summary,
        overall_confidence=overall_confidence,
        kotlin=True,
    )


def _android_result(
    *,
    stack: str,
    language: str,
    slug: str,
    sample_name: str,
    package: str,
    activity_path: str,
    activity_source: str,
    recovered_path: str,
    recovered_source: str,
    prepared: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
    kotlin: bool,
) -> dict[str, Any]:
    plugin_lines = ["    id 'com.android.application' version '8.2.2' apply false"]
    app_plugins = ["    id 'com.android.application'"]
    if kotlin:
        plugin_lines.append("    id 'org.jetbrains.kotlin.android' version '1.9.22' apply false")
        app_plugins.append("    id 'org.jetbrains.kotlin.android'")
    root_build = "\n".join(["plugins {", *plugin_lines, "}", ""])
    settings = "\n".join(
        [
            "pluginManagement {",
            "    repositories { google(); mavenCentral(); gradlePluginPortal() }",
            "}",
            "dependencyResolutionManagement {",
            "    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)",
            "    repositories { google(); mavenCentral() }",
            "}",
            f"rootProject.name = 'Reconstructed{_pascal_name(slug)}'",
            "include ':app'",
            "",
        ]
    )
    app_build = "\n".join(
        [
            "plugins {",
            *app_plugins,
            "}",
            "",
            "android {",
            f"    namespace '{package}'",
            "    compileSdk 34",
            "",
            "    defaultConfig {",
            f"        applicationId '{package}'",
            "        minSdk 23",
            "        targetSdk 34",
            "        versionCode 1",
            "        versionName '0.0-reconstructed'",
            "    }",
            "}",
            "",
            "dependencies {}",
            "",
        ]
    )
    manifest = "\n".join(
        [
            '<?xml version="1.0" encoding="utf-8"?>',
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
            '  <application android:allowBackup="false" android:label="Reconstructed application">',
            '    <activity android:name=".MainActivity" android:exported="true">',
            "      <intent-filter>",
            '        <action android:name="android.intent.action.MAIN" />',
            '        <category android:name="android.intent.category.LAUNCHER" />',
            "      </intent-filter>",
            "    </activity>",
            "  </application>",
            "</manifest>",
            "",
        ]
    )
    main_symbol = _builtin_symbol("MainActivity.onCreate", "method", activity_path, stack, overall_confidence, placeholder=True)
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        ".gitignore": _config_spec(".gradle/\nbuild/\n**/build/\nlocal.properties\n", stack, overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack=stack,
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=("open the project in Android Studio", "gradle :app:assembleDebug"),
            ),
            stack,
            overall_confidence,
            kind="documentation",
        ),
        "app/build.gradle": _config_spec(app_build, stack, overall_confidence),
        "app/src/main/AndroidManifest.xml": _config_spec(
            manifest, stack, overall_confidence, kind="manifest"
        ),
        activity_path: _source_spec(
            activity_source,
            stack=stack,
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        recovered_path: _source_spec(
            recovered_source,
            stack=stack,
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "build.gradle": _config_spec(root_build, stack, overall_confidence),
        "gradle.properties": _config_spec(
            "org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8\nandroid.useAndroidX=true\n",
            stack,
            overall_confidence,
        ),
        "settings.gradle": _config_spec(settings, stack, overall_confidence),
    }
    return {
        "language": language,
        "output_stack": stack,
        "entrypoints": [activity_path, "app/src/main/AndroidManifest.xml"],
        "build_files": ["settings.gradle", "build.gradle", "app/build.gradle"],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }


def _java_package_component(value: Any) -> str:
    component = re.sub(r"[^a-z0-9_]", "_", _safe_slug(value).lower()) or "sample"
    if component[0].isdigit() or component in _JAVA_RESERVED:
        component = f"sample_{component}"
    return component[:60]


def _android_package(evidence_summary: Mapping[str, Any], slug: str) -> str:
    android = _as_mapping(evidence_summary.get("android_analysis"))
    candidate = _first_text(android.get("application_id"))
    if candidate and len(candidate) <= 200:
        parts = candidate.split(".")
        if len(parts) >= 2 and all(
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) and part.casefold() not in _JAVA_RESERVED
            for part in parts
        ):
            return candidate
    return f"com.reconstructed.{_java_package_component(slug)}"


def _render_unity(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    behaviour_path = "Assets/Scripts/ReconstructedBehaviour.cs"
    source_path = "Assets/Scripts/RecoveredSymbols.cs"
    prepared = _prepare_symbols(
        symbols,
        style="csharp",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_CS_RESERVED, "ReconstructedBehaviour", "RecoveredSymbols", "Start"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol(
                "RecoveredEntry", "function", source_path, "unity-csharp", overall_confidence, placeholder=True
            )
        ]

    namespace = f"Reconstructed.{_pascal_name(slug)}.Unity"
    methods: list[str] = []
    classes: list[str] = []
    for symbol in prepared:
        comment = _symbol_comment(symbol)
        identifier = symbol["identifier"]
        if symbol["kind"] == "class":
            classes.extend(
                [
                    comment,
                    f"public sealed class {identifier}",
                    "{",
                    "    public void Execute()",
                    "    {",
                    "        // TODO: restore Unity object state and lifecycle behavior from cited evidence.",
                    "        throw new NotImplementedException(\"Recovered Unity class behavior is not implemented.\");",
                    "    }",
                    "}",
                    "",
                ]
            )
        else:
            methods.extend(
                [
                    f"    {comment}",
                    f"    public static int {identifier}()",
                    "    {",
                    "        // TODO: restore method behavior and Unity object references from cited evidence.",
                    "        return 0;",
                    "    }",
                    "",
                ]
            )

    recovered = "\n".join(
        [
            "using System;",
            "",
            f"namespace {namespace};",
            "",
            _evidence_comment(evidence_summary),
            "public static class RecoveredSymbols",
            "{",
            *methods,
            "}",
            "",
            *classes,
        ]
    )
    behaviour = "\n".join(
        [
            f"namespace {namespace};",
            "",
            _evidence_comment(evidence_summary),
            "#if UNITY_5_3_OR_NEWER",
            "public sealed class ReconstructedBehaviour : UnityEngine.MonoBehaviour",
            "#else",
            "public sealed class ReconstructedBehaviour",
            "#endif",
            "{",
            "#if UNITY_5_3_OR_NEWER",
            "    private void Start()",
            "#else",
            "    public void Start()",
            "#endif",
            "    {",
            "        // TODO: reconnect recovered MonoBehaviour fields, scene objects, and lifecycle ordering.",
            "    }",
            "}",
            "",
        ]
    )
    project_name = f"Reconstructed.{_pascal_name(slug)}.Unity"
    project_file = f"{project_name}.csproj"
    csproj = "\n".join(
        [
            '<Project Sdk="Microsoft.NET.Sdk">',
            "  <PropertyGroup>",
            "    <TargetFramework>net8.0</TargetFramework>",
            "    <ImplicitUsings>enable</ImplicitUsings>",
            "    <Nullable>enable</Nullable>",
            "  </PropertyGroup>",
            "</Project>",
            "",
        ]
    )
    package_manifest = {
        "dependencies": {},
        "reconstruction": {
            "note": "Add packages matching the recovered Unity editor version when that evidence is available."
        },
    }
    start_symbol = _builtin_symbol(
        "ReconstructedBehaviour.Start",
        "method",
        behaviour_path,
        "unity-csharp",
        overall_confidence,
        placeholder=True,
    )
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        ".gitignore": _config_spec("[Ll]ibrary/\n[Tt]emp/\n[Oo]bj/\n[Bb]uild/\n.vs/\n", "unity-csharp", overall_confidence),
        project_file: _config_spec(csproj, "unity-csharp", overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="unity-csharp",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=(
                    f"dotnet build {project_file}",
                    "open the directory as a Unity project after selecting the matching editor version",
                ),
            ),
            "unity-csharp",
            overall_confidence,
            kind="documentation",
        ),
        behaviour_path: _source_spec(
            behaviour,
            stack="unity-csharp",
            symbols=(start_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        source_path: _source_spec(
            recovered,
            stack="unity-csharp",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "Packages/manifest.json": _config_spec(
            _json_text(package_manifest), "unity-csharp", overall_confidence, kind="manifest"
        ),
        "ProjectSettings/ProjectVersion.txt": _config_spec(
            "m_EditorVersion: unknown\nm_EditorVersionWithRevision: unknown\n",
            "unity-csharp",
            overall_confidence,
            kind="configuration",
        ),
    }
    return {
        "language": "csharp",
        "output_stack": "unity-csharp",
        "entrypoints": [behaviour_path],
        "build_files": [project_file, "Packages/manifest.json"],
        "files": files,
        "symbols": [start_symbol, *prepared],
    }


def _render_python(
    *,
    slug: str,
    sample_name: str,
    symbols: Sequence[Mapping[str, Any]],
    evidence_summary: Mapping[str, Any],
    overall_confidence: float,
) -> dict[str, Any]:
    source_path = "reconstructed.py"
    prepared = _prepare_symbols(
        symbols,
        style="python",
        function_file=source_path,
        class_file=source_path,
        reserved=(*_PY_RESERVED, "main", "RecoveredEntry"),
    )
    if not prepared:
        prepared = [
            _builtin_symbol(
                "recovered_entry",
                "function",
                source_path,
                "pyinstaller-python",
                overall_confidence,
                placeholder=True,
            )
        ]

    definitions: list[str] = []
    exported: list[str] = []
    for symbol in prepared:
        comment = _symbol_comment(symbol, "#")
        identifier = symbol["identifier"]
        exported.append(identifier)
        if symbol["kind"] == "class":
            definitions.extend(
                [
                    comment,
                    f"class {identifier}:",
                    "    def execute(self) -> None:",
                    "        # TODO: restore class state and behavior from cited evidence.",
                    "        raise NotImplementedError(\"Recovered class behavior is not implemented\")",
                    "",
                    "",
                ]
            )
        else:
            definitions.extend(
                [
                    comment,
                    f"def {identifier}() -> int:",
                    "    # TODO: restore behavior from cited evidence.",
                    "    return 0",
                    "",
                    "",
                ]
            )

    recovered = "\n".join(
        [
            '"""Evidence-backed placeholders recovered from a packaged Python application."""',
            "",
            _evidence_comment(evidence_summary, "#"),
            "",
            *definitions,
            f"__all__ = {exported!r}",
            "",
        ]
    )
    app = "\n".join(
        [
            '"""Browsable entry point for the reconstructed application skeleton."""',
            "",
            "from __future__ import annotations",
            "",
            _evidence_comment(evidence_summary, "#"),
            "",
            "def main() -> int:",
            '    print("Reconstructed PyInstaller/Python placeholder; see analysis metadata.")',
            "    # TODO: restore startup ordering, imports, and side effects from runtime evidence.",
            "    return 0",
            "",
            "",
            'if __name__ == "__main__":',
            "    raise SystemExit(main())",
            "",
        ]
    )
    package_name = f"reconstructed-{slug.replace('_', '-')}"
    pyproject = "\n".join(
        [
            "[project]",
            f'name = "{package_name}"',
            'version = "0.0.0"',
            'description = "Evidence-backed PyInstaller/Python reconstruction skeleton"',
            'requires-python = ">=3.10"',
            "dependencies = []",
            "",
            "[project.scripts]",
            'reconstructed-app = "app:main"',
            "",
        ]
    )
    main_symbol = _builtin_symbol(
        "main", "function", "app.py", "pyinstaller-python", overall_confidence, placeholder=False
    )
    evidence_sources = _present_evidence(evidence_summary)
    files = {
        ".gitignore": _config_spec("__pycache__/\n*.py[cod]\n.venv/\nbuild/\ndist/\n", "pyinstaller-python", overall_confidence),
        "README.md": _config_spec(
            _readme(
                sample_name=sample_name,
                stack="pyinstaller-python",
                confidence=overall_confidence,
                evidence_summary=evidence_summary,
                run_lines=("python -m compileall app.py reconstructed.py", "python app.py"),
            ),
            "pyinstaller-python",
            overall_confidence,
            kind="documentation",
        ),
        "app.py": _source_spec(
            app,
            stack="pyinstaller-python",
            symbols=(main_symbol,),
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
        "pyproject.toml": _config_spec(pyproject, "pyinstaller-python", overall_confidence),
        source_path: _source_spec(
            recovered,
            stack="pyinstaller-python",
            symbols=prepared,
            evidence_sources=evidence_sources,
            overall_confidence=overall_confidence,
        ),
    }
    return {
        "language": "python",
        "output_stack": "python",
        "entrypoints": ["app.py"],
        "build_files": ["pyproject.toml"],
        "files": files,
        "symbols": [main_symbol, *prepared],
    }
