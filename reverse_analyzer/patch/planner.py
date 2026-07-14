"""PE-aware planning for verified, layout-preserving binary patches.

The planner never modifies its input. It turns an explicit offset, RVA, or AOB
intent into a patch-engine plan, verifies PE layout and instruction boundaries,
and emits deterministic risk and rollback artifacts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.patch import _validate_patch_plan_engine


_STRATEGY_ALIASES = {
    "auto": "inline_patch",
    "inline": "inline_patch",
    "inline_patch": "inline_patch",
    "code_cave": "code_cave_patch",
    "code_cave_patch": "code_cave_patch",
    "section_extend": "section_extend_patch",
    "section_extend_patch": "section_extend_patch",
    "resource_replace": "resource_replace",
    "iat_thunk": "iat_thunk_patch",
    "iat_thunk_patch": "iat_thunk_patch",
    "entrypoint_redirect": "entrypoint_redirect",
    "overlay_preserve": "overlay_preserve_patch",
    "overlay_preserve_patch": "overlay_preserve_patch",
}
_SUPPORTED_STRATEGIES = frozenset(_STRATEGY_ALIASES.values())
_CAVE_BYTES = frozenset({0x00, 0x90, 0xCC})
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DIRECTORY_NAMES = {
    0: "export",
    1: "import",
    2: "resource",
    3: "exception",
    4: "security",
    5: "base_relocation",
    6: "debug",
    7: "architecture",
    8: "global_pointer",
    9: "tls",
    10: "load_config",
    11: "bound_import",
    12: "iat",
    13: "delay_import",
    14: "com_descriptor",
}


class PatchPlanningError(ValueError):
    """Raised when an explicit patch intent cannot produce a verified plan."""


class PatchPlannerUnavailable(RuntimeError):
    """Raised when an optional dependency required by the planner is absent."""


@dataclass(frozen=True)
class _Section:
    index: int
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass(frozen=True)
class _Directory:
    name: str
    index: int
    rva: int
    size: int
    file_offset: int | None


@dataclass(frozen=True)
class _ResourceLeaf:
    type_name: str
    name: str
    language: int
    rva: int
    size: int
    file_offset: int
    size_field_offset: int


@dataclass(frozen=True)
class _ImportThunk:
    dll: str
    symbol: str
    rva: int
    file_offset: int
    size: int


@dataclass(frozen=True)
class _RelocationSite:
    rva: int
    file_offset: int
    size: int
    type: int


@dataclass
class _PeContext:
    machine: int
    bits: int
    image_base: int
    entrypoint_rva: int
    entrypoint_offset: int | None
    entrypoint_field_offset: int
    checksum_field_offset: int
    security_directory_entry_offset: int
    size_of_headers: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_image_field_offset: int
    section_table_offset: int
    sections: list[_Section]
    directories: list[_Directory]
    resources: list[_ResourceLeaf]
    import_thunks: list[_ImportThunk]
    relocation_sites: list[_RelocationSite]
    overlay_offset: int | None
    overlay_size: int


def plan_pe_patch(
    path: str | Path,
    *,
    out_dir: str | Path,
    strategy: str = "auto",
    offset: int | str | None = None,
    rva: int | str | None = None,
    aob: str | None = None,
    replacement: str | bytes | None = None,
    occurrence: int | str = 0,
    operation_id: str | None = None,
    intent: Mapping[str, Any] | None = None,
) -> ToolResult:
    """Create and persist a verified patch plan from one explicit intent."""

    target_value = str(path)
    try:
        target = _require_file(path)
        normalized_intent = _merge_intent(
            intent,
            offset=offset,
            rva=rva,
            aob=aob,
            replacement=replacement,
            occurrence=occurrence,
            operation_id=operation_id,
        )
        selected_strategy = _normalize_strategy(strategy)
        selectors = [name for name in ("offset", "rva", "aob") if normalized_intent.get(name) is not None]
        if selected_strategy == "inline_patch" and not selectors:
            return ToolResult(
                tool="pe_patch_plan",
                status="needs_intent",
                data={
                    "status": "needs_intent",
                    "target_path": str(target),
                    "message": "provide exactly one of offset, rva, or aob together with replacement",
                    "supported_intents": ["offset", "rva", "aob"],
                    "artifacts": [],
                },
            )
        if len(selectors) != 1:
            if selectors:
                raise PatchPlanningError("provide exactly one patch selector: offset, rva, or aob")

        data = target.read_bytes()
        pe = _load_pe_context(target, data)
        if selected_strategy == "inline_patch":
            operations = [
                _operation_from_intent(
                    data,
                    pe,
                    normalized_intent,
                    selector=selectors[0],
                )
            ]
            strategy_details: dict[str, Any] = {"mode": "equal_length_replace"}
        else:
            operations, strategy_details = _operations_for_strategy(
                data,
                pe,
                normalized_intent,
                strategy=selected_strategy,
            )
        plan = {
            "schema_version": 1,
            "target_sha256": _sha256(data),
            "strategy": selected_strategy,
            "target": _target_summary(target, data, pe),
            "operations": operations,
            "strategy_details": strategy_details,
            "planner": {
                "name": "pe_aware_patch_planner",
                "schema_version": 1,
                "explicit_intent": True,
                "layout_preserving": True,
                "operation_model": "checked_equal_length_byte_replacements",
            },
        }
        verification, risk_report, rollback_plan = _verify_payload(target, data, pe, plan)
        artifact_root = Path(out_dir).resolve()
        artifacts = _write_planning_artifacts(
            artifact_root,
            plan=plan,
            verification=verification,
            risk_report=risk_report,
            rollback_plan=rollback_plan,
            include_plan=True,
            protected_paths={"target": target},
        )
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="pe_patch_plan",
            status=status,
            error=None if status == "ok" else "; ".join(verification["errors"]),
            data={
                "status": status,
                "target_path": str(target),
                "strategy": selected_strategy,
                "valid": verification["valid"],
                "overall_risk": risk_report["overall_risk"],
                "operation_count": len(operations),
                "plan_path": str(artifact_root / "plan.json"),
                "verify_path": str(artifact_root / "verify.json"),
                "risk_report_path": str(artifact_root / "risk_report.json"),
                "rollback_plan_path": str(artifact_root / "rollback_plan.json"),
                "artifacts": artifacts,
            },
        )
    except PatchPlannerUnavailable as exc:
        return ToolResult(
            tool="pe_patch_plan",
            status="unavailable",
            error=str(exc),
            data={"status": "unavailable", "target": target_value, "artifacts": []},
        )
    except (OSError, PatchPlanningError, TypeError, ValueError) as exc:
        return _failure("pe_patch_plan", path, exc)


def validate_pe_patch_plan(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
) -> ToolResult:
    """Validate PE policy and rollback recoverability without writing artifacts."""

    target_value = str(path)
    try:
        target = _require_file(path)
        plan_payload, _ = _load_mapping(plan, "patch plan")
        data = target.read_bytes()
        pe = _load_pe_context(target, data)
        verification, risk_report, rollback_plan = _verify_payload(target, data, pe, plan_payload)
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="pe_patch_validate",
            status=status,
            error=None if status == "ok" else "; ".join(verification["errors"]),
            data={
                **verification,
                "status": status,
                "risk_report": risk_report,
                "rollback_plan": rollback_plan,
                "artifacts": [],
            },
        )
    except PatchPlannerUnavailable as exc:
        return ToolResult(
            tool="pe_patch_validate",
            status="unavailable",
            error=str(exc),
            data={
                "status": "unavailable",
                "valid": False,
                "target": target_value,
                "artifacts": [],
            },
        )
    except (OSError, PatchPlanningError, TypeError, ValueError) as exc:
        return _failure("pe_patch_validate", path, exc)


def verify_pe_patch(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_dir: str | Path | None = None,
) -> ToolResult:
    """Verify an existing patch plan and emit risk/rollback artifacts."""

    target_value = str(path)
    try:
        target = _require_file(path)
        plan_source = Path(plan).resolve() if not isinstance(plan, Mapping) else None
        plan_payload, plan_parent = _load_mapping(plan, "patch plan")
        data = target.read_bytes()
        pe = _load_pe_context(target, data)
        verification, risk_report, rollback_plan = _verify_payload(target, data, pe, plan_payload)
        artifact_root = (
            Path(out_dir).resolve()
            if out_dir is not None
            else plan_parent or target.parent / "patch"
        )
        artifacts = _write_planning_artifacts(
            artifact_root,
            plan=plan_payload,
            verification=verification,
            risk_report=risk_report,
            rollback_plan=rollback_plan,
            include_plan=False,
            protected_paths={
                "target": target,
                **({"plan_input": plan_source} if plan_source is not None else {}),
            },
        )
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="pe_patch_verify",
            status=status,
            error=None if status == "ok" else "; ".join(verification["errors"]),
            data={
                **verification,
                "status": status,
                "overall_risk": risk_report["overall_risk"],
                "verify_path": str(artifact_root / "verify.json"),
                "risk_report_path": str(artifact_root / "risk_report.json"),
                "rollback_plan_path": str(artifact_root / "rollback_plan.json"),
                "artifacts": artifacts,
            },
        )
    except PatchPlannerUnavailable as exc:
        return ToolResult(
            tool="pe_patch_verify",
            status="unavailable",
            error=str(exc),
            data={"status": "unavailable", "target": target_value, "artifacts": []},
        )
    except (OSError, PatchPlanningError, TypeError, ValueError) as exc:
        return _failure("pe_patch_verify", path, exc)


def _merge_intent(
    intent: Mapping[str, Any] | None,
    **explicit: Any,
) -> dict[str, Any]:
    result = {str(key): value for key, value in (intent or {}).items()}
    for key, value in explicit.items():
        if value is not None and (key not in result or result[key] is None):
            result[key] = value
    return result


def _normalize_strategy(value: str) -> str:
    strategy = str(value or "auto").strip().casefold().replace("-", "_")
    normalized = _STRATEGY_ALIASES.get(strategy)
    if normalized is None:
        raise PatchPlanningError(f"unsupported patch strategy: {value!r}")
    return normalized


def _operation_from_intent(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    *,
    selector: str,
) -> dict[str, Any]:
    replacement = _hex_bytes(intent.get("replacement"), field="replacement")
    operation_id = str(intent.get("operation_id") or intent.get("id") or f"inline-{selector}").strip()
    if not operation_id:
        operation_id = f"inline-{selector}"

    if selector == "offset":
        file_offset = _integer(intent["offset"], field="offset")
        expected = _read_preimage(data, file_offset, len(replacement))
        return {
            "id": operation_id,
            "kind": "replace_offset",
            "offset": file_offset,
            "expected": expected.hex(),
            "replacement": replacement.hex(),
        }
    if selector == "rva":
        patch_rva = _integer(intent["rva"], field="rva")
        file_offset = _rva_to_offset(pe, patch_rva, len(replacement), file_size=len(data))
        expected = _read_preimage(data, file_offset, len(replacement))
        return {
            "id": operation_id,
            "kind": "replace_rva",
            "rva": patch_rva,
            "expected": expected.hex(),
            "replacement": replacement.hex(),
        }

    pattern = _parse_aob(str(intent["aob"]))
    if len(pattern) != len(replacement):
        raise PatchPlanningError("replacement length must equal the AOB pattern length")
    matches = _find_aob(data, pattern)
    selected_occurrence = _integer(intent.get("occurrence", 0), field="occurrence")
    if not matches:
        raise PatchPlanningError("AOB pattern did not match the target")
    if selected_occurrence >= len(matches):
        raise PatchPlanningError(
            f"occurrence {selected_occurrence} is outside {len(matches)} AOB matches"
        )
    selected_offset = matches[selected_occurrence]
    expected = _read_preimage(data, selected_offset, len(pattern))
    return {
        "id": operation_id,
        "kind": "replace_aob",
        "pattern": _format_aob(pattern),
        "expected": expected.hex(),
        "replacement": replacement.hex(),
        "expected_match_count": len(matches),
        "occurrence": selected_occurrence,
    }


def _operations_for_strategy(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    *,
    strategy: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    builders = {
        "code_cave_patch": _plan_code_cave,
        "section_extend_patch": _plan_section_extend,
        "resource_replace": _plan_resource_replace,
        "iat_thunk_patch": _plan_iat_thunk,
        "entrypoint_redirect": _plan_entrypoint_redirect,
        "overlay_preserve_patch": _plan_overlay_preserve,
    }
    builder = builders.get(strategy)
    if builder is None:
        raise PatchPlanningError(f"strategy {strategy!r} has no planner")
    return builder(data, pe, intent)


def _plan_code_cave(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = _intent_bytes(intent, "replacement", "payload", field="replacement")
    operation_id = _operation_id(intent, "code-cave")
    selectors = _selectors(intent)
    if len(selectors) > 1:
        raise PatchPlanningError("code_cave_patch accepts at most one of offset, rva, or aob")
    if selectors:
        selected = dict(intent)
        selected["replacement"] = payload
        operation = _operation_from_intent(data, pe, selected, selector=selectors[0])
        resolved = _resolve_operations(data, pe, {"operations": [operation]})[0]
        cave_offset = int(resolved["file_offset"])
    else:
        cave_offset = _find_code_cave(data, pe, intent, len(payload))
        operation = _replace_operation(
            data,
            cave_offset,
            payload,
            operation_id=operation_id,
            role="code_cave_payload",
        )
    operation["id"] = operation_id
    operation["role"] = "code_cave_payload"
    section = _section_for_range(pe, cave_offset, len(payload))
    if section is None or not section.executable:
        raise PatchPlanningError("code_cave_patch target must be wholly inside an executable section")
    preimage = _read_preimage(data, cave_offset, len(payload))
    if any(value not in _CAVE_BYTES for value in preimage):
        raise PatchPlanningError(
            "code_cave_patch target is not cave padding; expected only 00, 90, or CC bytes"
        )
    _reject_protected_range(pe, cave_offset, len(payload), strategy="code_cave_patch")
    cave_rva = _offset_to_rva(pe, cave_offset, len(payload))
    return [operation], {
        "mode": "existing_executable_cave",
        "section": section.name,
        "section_index": section.index,
        "cave_offset": cave_offset,
        "cave_rva": cave_rva,
        "payload_size": len(payload),
        "accepted_fill_bytes": ["00", "90", "CC"],
        "control_transfer_modified": False,
    }


def _plan_section_extend(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = _intent_bytes(intent, "replacement", "payload", field="replacement")
    selectors = _selectors(intent)
    if "aob" in selectors or len(selectors) > 1:
        raise PatchPlanningError(
            "section_extend_patch accepts one offset/RVA selector or an explicit section name/index"
        )
    selected_offset: int | None = None
    if selectors:
        selected_offset = _selector_offset(data, pe, intent, selectors[0], len(payload))
    section = _select_section_for_extension(data, pe, intent, selected_offset, len(payload))
    if pe.file_alignment <= 0 or pe.section_alignment <= 0:
        raise PatchPlanningError("PE section/file alignment values must be positive")
    if section.raw_offset % pe.file_alignment or section.raw_size % pe.file_alignment:
        raise PatchPlanningError(
            f"section {section.name} raw layout is not aligned to FileAlignment 0x{pe.file_alignment:X}"
        )
    if section.virtual_address % pe.section_alignment:
        raise PatchPlanningError(
            f"section {section.name} RVA is not aligned to SectionAlignment 0x{pe.section_alignment:X}"
        )

    payload_offset = selected_offset if selected_offset is not None else section.raw_offset + section.virtual_size
    if payload_offset < section.raw_offset + section.virtual_size:
        raise PatchPlanningError(
            "section_extend_patch selector must begin at or after the section's current VirtualSize"
        )
    relative_end = payload_offset - section.raw_offset + len(payload)
    new_virtual_size = max(section.virtual_size, relative_end)
    next_virtual = min(
        (item.virtual_address for item in pe.sections if item.virtual_address > section.virtual_address),
        default=None,
    )
    if next_virtual is not None and section.virtual_address + new_virtual_size > next_virtual:
        raise PatchPlanningError(
            f"section extension would overlap the next section at RVA 0x{next_virtual:X}"
        )

    new_raw_size = section.raw_size
    mode = "preallocated_raw_slack"
    if relative_end > section.raw_size:
        new_raw_size = _align_up(relative_end, pe.file_alignment)
        next_raw = min(
            (item.raw_offset for item in pe.sections if item.raw_offset > section.raw_offset),
            default=pe.overlay_offset if pe.overlay_offset is not None else len(data),
        )
        if section.raw_offset + new_raw_size > next_raw:
            raise PatchPlanningError(
                "section extension needs file growth or section movement; provide payload that fits existing aligned slack"
            )
        mode = "existing_inter_section_gap"
    allocation_end = section.raw_offset + new_raw_size
    if allocation_end > len(data):
        raise PatchPlanningError("section extension would grow the file, which the current apply engine cannot execute")
    if pe.overlay_offset is not None and allocation_end > pe.overlay_offset:
        raise PatchPlanningError("section extension would consume or move the existing overlay")
    payload_preimage = _read_preimage(data, payload_offset, len(payload))
    annexed_padding = (
        _read_preimage(data, section.raw_end, allocation_end - section.raw_end)
        if new_raw_size > section.raw_size
        else b""
    )
    if any(value not in _CAVE_BYTES for value in payload_preimage + annexed_padding):
        raise PatchPlanningError(
            "section extension target contains non-padding data; choose an unused 00/90/CC-backed range"
        )
    _reject_protected_range(pe, payload_offset, len(payload), strategy="section_extend_patch")

    operation_id = _operation_id(intent, "section-extend")
    operations = [
        _replace_operation(
            data,
            payload_offset,
            payload,
            operation_id=f"{operation_id}-payload",
            role="section_extension_payload",
        )
    ]
    section_header = pe.section_table_offset + (section.index * 40)
    operations.append(
        _replace_integer_operation(
            data,
            section_header + 8,
            new_virtual_size,
            operation_id=f"{operation_id}-virtual-size",
            role="section_virtual_size",
        )
    )
    if new_raw_size != section.raw_size:
        operations.append(
            _replace_integer_operation(
                data,
                section_header + 16,
                new_raw_size,
                operation_id=f"{operation_id}-raw-size",
                role="section_raw_size",
            )
        )
    new_size_of_image = _size_of_image_after_extension(pe, section, new_virtual_size, new_raw_size)
    if new_size_of_image != pe.size_of_image:
        operations.append(
            _replace_integer_operation(
                data,
                pe.size_of_image_field_offset,
                new_size_of_image,
                operation_id=f"{operation_id}-image-size",
                role="size_of_image",
            )
        )
    return operations, {
        "mode": mode,
        "section": section.name,
        "section_index": section.index,
        "payload_offset": payload_offset,
        "payload_rva": section.virtual_address + (payload_offset - section.raw_offset),
        "payload_size": len(payload),
        "old_virtual_size": section.virtual_size,
        "new_virtual_size": new_virtual_size,
        "old_raw_size": section.raw_size,
        "new_raw_size": new_raw_size,
        "old_size_of_image": pe.size_of_image,
        "new_size_of_image": new_size_of_image,
        "file_alignment": pe.file_alignment,
        "section_alignment": pe.section_alignment,
        "overlay_preserved": True,
    }


def _plan_resource_replace(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    payload = _intent_bytes(intent, "replacement", "payload", field="replacement")
    resource_directory = _directory(pe, "resource")
    if resource_directory is None or resource_directory.file_offset is None:
        raise PatchPlanningError("resource_replace requires a file-backed PE resource directory")
    leaf, resource_offset, allocation_size, size_field_offset = _select_resource(data, pe, intent)
    if len(payload) > allocation_size:
        raise PatchPlanningError(
            f"replacement is {len(payload)} bytes but the selected resource allocation is {allocation_size} bytes"
        )
    if not _range_inside_directory(resource_directory, resource_offset, allocation_size):
        raise PatchPlanningError("selected resource bytes are outside the declared PE resource directory")
    pad_byte = _single_byte(intent.get("pad_byte", "00"), field="pad_byte")
    replacement = payload + (pad_byte * (allocation_size - len(payload)))
    operation_id = _operation_id(intent, "resource-replace")
    operations = [
        _replace_operation(
            data,
            resource_offset,
            replacement,
            operation_id=f"{operation_id}-data",
            role="resource_data",
        )
    ]
    if len(payload) != allocation_size:
        if not _range_inside_directory(resource_directory, size_field_offset, 4):
            raise PatchPlanningError("resource_size_field_offset must identify a field in the resource directory")
        observed_size = int.from_bytes(_read_preimage(data, size_field_offset, 4), "little")
        if observed_size != allocation_size:
            raise PatchPlanningError(
                f"resource size field contains {observed_size}, expected selected allocation size {allocation_size}"
            )
        operations.append(
            _replace_integer_operation(
                data,
                size_field_offset,
                len(payload),
                operation_id=f"{operation_id}-size",
                role="resource_size",
            )
        )
    resource_rva = _offset_to_rva(pe, resource_offset, allocation_size)
    return operations, {
        "mode": "in_place_resource_allocation",
        "resource_type": leaf.type_name,
        "resource_name": leaf.name,
        "language": leaf.language,
        "resource_offset": resource_offset,
        "resource_rva": resource_rva,
        "allocation_size": allocation_size,
        "replacement_size": len(payload),
        "size_field_offset": size_field_offset,
        "allocation_preserved": True,
    }


def _plan_iat_thunk(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pointer_size = pe.bits // 8
    replacement = _iat_replacement(pe, intent, pointer_size)
    thunk, thunk_offset, thunk_rva = _select_iat_thunk(data, pe, intent, pointer_size)
    iat_directory = _directory(pe, "iat")
    in_iat = bool(
        iat_directory
        and iat_directory.file_offset is not None
        and _range_inside_directory(iat_directory, thunk_offset, pointer_size)
    )
    if thunk is None and not in_iat:
        raise PatchPlanningError(
            "iat_thunk_patch selector must identify a parsed import thunk or a pointer-sized slot in the IAT directory"
        )
    base_rva = iat_directory.rva if iat_directory is not None else thunk_rva
    if (thunk_rva - base_rva) % pointer_size:
        raise PatchPlanningError(f"IAT thunk RVA 0x{thunk_rva:X} is not {pointer_size}-byte aligned")
    _reject_relocation_overlap(pe, thunk_offset, pointer_size, strategy="iat_thunk_patch")
    operation_id = _operation_id(intent, "iat-thunk")
    operation = _replace_operation(
        data,
        thunk_offset,
        replacement,
        operation_id=operation_id,
        role="iat_thunk",
    )
    return [operation], {
        "mode": "checked_pointer_replacement",
        "pointer_size": pointer_size,
        "thunk_offset": thunk_offset,
        "thunk_rva": thunk_rva,
        "dll": thunk.dll if thunk else intent.get("dll"),
        "symbol": thunk.symbol if thunk else intent.get("symbol", intent.get("import_name")),
        "iat_directory_present": iat_directory is not None,
        "loader_may_overwrite_unbound_iat": True,
    }


def _plan_entrypoint_redirect(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    target_rva = _entrypoint_target_rva(data, pe, intent)
    target_offset = _rva_to_offset(pe, target_rva, 1, file_size=len(data))
    section = _section_for_range(pe, target_offset, 1)
    if section is None or not section.executable:
        raise PatchPlanningError("entrypoint_redirect target must map to file-backed executable code")
    if target_rva == pe.entrypoint_rva:
        raise PatchPlanningError("entrypoint_redirect target equals the current AddressOfEntryPoint")
    operation_id = _operation_id(intent, "entrypoint-redirect")
    operations: list[dict[str, Any]] = []
    payload_value = intent.get("replacement", intent.get("payload"))
    payload_size = 0
    if payload_value is not None:
        payload = _hex_bytes(payload_value, field="replacement")
        payload_size = len(payload)
        _rva_to_offset(pe, target_rva, payload_size, file_size=len(data))
        _reject_protected_range(pe, target_offset, payload_size, strategy="entrypoint_redirect")
        operations.append(
            {
                "id": f"{operation_id}-target",
                "kind": "replace_rva",
                "rva": target_rva,
                "expected": _read_preimage(data, target_offset, payload_size).hex(),
                "replacement": payload.hex(),
                "role": "entrypoint_target_payload",
            }
        )
    operations.append(
        _replace_integer_operation(
            data,
            pe.entrypoint_field_offset,
            target_rva,
            operation_id=f"{operation_id}-header",
            role="address_of_entrypoint",
        )
    )
    return operations, {
        "mode": "address_of_entrypoint_rva_redirect",
        "old_entrypoint_rva": pe.entrypoint_rva,
        "new_entrypoint_rva": target_rva,
        "target_offset": target_offset,
        "target_section": section.name,
        "payload_size": payload_size,
        "uses_rva_not_absolute_va": True,
    }


def _plan_overlay_preserve(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if pe.overlay_offset is None or pe.overlay_size <= 0:
        raise PatchPlanningError("overlay_preserve_patch requires an existing PE overlay")
    selectors = _selectors(intent)
    if len(selectors) != 1:
        raise PatchPlanningError("overlay_preserve_patch requires exactly one offset, RVA, or AOB selector")
    selected = dict(intent)
    selected["replacement"] = _intent_bytes(intent, "replacement", "payload", field="replacement")
    operation = _operation_from_intent(data, pe, selected, selector=selectors[0])
    operation["role"] = "overlay_preserving_patch"
    operation["id"] = _operation_id(intent, "overlay-preserve")
    resolved = _resolve_operations(data, pe, {"operations": [operation]})[0]
    patch_offset = int(resolved["file_offset"])
    patch_size = int(resolved["size"])
    if patch_offset + patch_size > pe.overlay_offset:
        raise PatchPlanningError("overlay_preserve_patch selector intersects the overlay; choose a PE image range")
    overlay = data[pe.overlay_offset : pe.overlay_offset + pe.overlay_size]
    return [operation], {
        "mode": "equal_length_image_patch_with_immutable_overlay",
        "overlay_offset": pe.overlay_offset,
        "overlay_size": pe.overlay_size,
        "overlay_sha256": _sha256(overlay),
        "patch_offset": patch_offset,
        "patch_size": patch_size,
    }


def _verify_payload(
    target: Path,
    data: bytes,
    pe: _PeContext,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = [
        {"name": "pe_parse", "status": "passed", "details": {"bits": pe.bits, "machine": f"0x{pe.machine:04X}"}},
    ]

    target_hash = _sha256(data)
    declared_hash = plan.get("target_sha256")
    hash_format_valid = (
        isinstance(declared_hash, str)
        and len(declared_hash) == 64
        and all(character in "0123456789abcdefABCDEF" for character in declared_hash)
    )
    hash_valid = hash_format_valid and declared_hash.casefold() == target_hash.casefold()
    checks.append({"name": "target_hash", "status": "passed" if hash_valid else "failed", "observed": target_hash, "expected": declared_hash})
    if not hash_format_valid:
        errors.append("target_sha256 is required and must be a 64-character hexadecimal SHA-256 digest")
    elif not hash_valid:
        errors.append("target_sha256 does not match the supplied target")

    engine_result = _validate_patch_plan_engine(target, plan=plan)
    engine_ok = getattr(engine_result, "status", "failed") == "ok"
    checks.append(
        {
            "name": "patch_engine_validation",
            "status": "passed" if engine_ok else "failed",
            "error": getattr(engine_result, "error", None),
        }
    )
    if not engine_ok:
        errors.append(getattr(engine_result, "error", None) or "patch engine validation failed")

    resolved: list[dict[str, Any]] = []
    try:
        resolved = _resolve_operations(data, pe, plan)
        checks.append({"name": "section_ranges", "status": "passed", "operation_count": len(resolved)})
    except PatchPlanningError as exc:
        errors.append(str(exc))
        checks.append({"name": "section_ranges", "status": "failed", "error": str(exc)})

    source_layout_errors = _pe_layout_errors(pe, len(data))
    checks.append(
        {
            "name": "source_pe_layout",
            "status": "failed" if source_layout_errors else "passed",
            "errors": source_layout_errors,
            "file_alignment": pe.file_alignment,
            "section_alignment": pe.section_alignment,
        }
    )
    errors.extend(source_layout_errors)

    if resolved:
        strategy_errors, strategy_warnings, strategy_findings = _validate_strategy_contract(
            data, pe, plan, resolved
        )
        errors.extend(strategy_errors)
        warnings.extend(strategy_warnings)
        findings.extend(strategy_findings)
        checks.append(
            {
                "name": "strategy_contract",
                "status": "failed" if strategy_errors else "warning" if strategy_warnings else "passed",
                "strategy": str(plan.get("strategy") or "unspecified"),
                "errors": strategy_errors,
                "warnings": strategy_warnings,
            }
        )
        try:
            planned_data = _apply_resolved_operations(data, resolved)
            planned_pe = _load_pe_context_from_bytes(planned_data)
            planned_layout_errors = _pe_layout_errors(planned_pe, len(planned_data))
            try:
                planned_strategy = _normalize_strategy(str(plan.get("strategy") or "inline_patch"))
            except PatchPlanningError:
                planned_strategy = str(plan.get("strategy") or "")
            if pe.overlay_offset is not None and planned_strategy == "overlay_preserve_patch":
                original_overlay = data[pe.overlay_offset :]
                planned_overlay = planned_data[pe.overlay_offset :]
                if original_overlay != planned_overlay:
                    planned_layout_errors.append("overlay_preserve_patch changed existing overlay bytes")
            checks.append(
                {
                    "name": "resulting_pe_layout",
                    "status": "failed" if planned_layout_errors else "passed",
                    "errors": planned_layout_errors,
                    "size_of_image": planned_pe.size_of_image,
                }
            )
            errors.extend(planned_layout_errors)
        except (PatchPlannerUnavailable, PatchPlanningError, TypeError, ValueError) as exc:
            message = f"planned byte operations do not produce a parseable PE: {exc}"
            errors.append(message)
            checks.append({"name": "resulting_pe_layout", "status": "failed", "error": message})

    instruction_results: list[dict[str, Any]] = []
    instruction_failed = False
    instruction_unavailable = False
    if resolved:
        _append_authenticode_findings(resolved, pe, findings)
        for operation in resolved:
            _append_structural_findings(operation, pe, findings)
            analysis = _instruction_analysis(data, pe, operation)
            if analysis is None:
                continue
            instruction_results.append(analysis)
            if analysis["status"] == "failed":
                instruction_failed = True
                errors.extend(analysis.get("errors", []))
            elif analysis["status"] == "unavailable":
                instruction_unavailable = True
                message = analysis.get("message", "instruction analysis unavailable")
                warnings.append(message)
                errors.append(f"{operation['id']}: {message}")
            findings.extend(analysis.get("findings", []))

    if instruction_failed:
        instruction_status = "failed"
    elif instruction_unavailable:
        instruction_status = "unavailable"
    else:
        instruction_status = "passed"
    checks.append({"name": "instruction_boundaries", "status": instruction_status, "operations": instruction_results})

    cfg_failed = any(item.get("cfg_status") == "failed" for item in instruction_results)
    cfg_risky = any(item.get("cfg_status") == "risky" for item in instruction_results)
    cfg_unavailable = any(item.get("cfg_status") == "unavailable" for item in instruction_results)
    entrypoint_cfg = _entrypoint_redirect_cfg_evidence(data, pe, plan)
    if entrypoint_cfg is not None and entrypoint_cfg.get("status") != "passed":
        cfg_failed = True
    checks.append(
        {
            "name": "basic_cfg",
            "status": (
                "failed"
                if cfg_failed
                else "unavailable"
                if cfg_unavailable
                else "warning"
                if cfg_risky
                else "passed"
            ),
            "operations": [
                {
                    "operation_id": item.get("operation_id"),
                    "patch_range": item.get("patch_range"),
                    "cfg_status": item.get("cfg_status"),
                    "basic_block_entries": item.get("basic_block_entries", []),
                    "patch_entry_sources": item.get("patch_entry_sources", []),
                    "incoming_interior_branches": item.get("incoming_interior_branches", []),
                    "invalid_direct_targets": item.get("invalid_direct_targets", []),
                }
                for item in instruction_results
            ],
            "entrypoint_redirect": entrypoint_cfg,
        }
    )
    if cfg_failed:
        errors.append("basic CFG validation failed for a patch range or redirected entrypoint")

    directory_hits = [item for item in findings if item["category"] == "pe_directory"]
    checks.append({"name": "pe_directories", "status": "warning" if directory_hits else "passed", "intersection_count": len(directory_hits)})

    signature_findings = [item for item in findings if item["category"] == "signature"]
    security = _directory(pe, "security")
    checks.append(
        {
            "name": "authenticode_signature",
            "status": "warning" if signature_findings else "passed",
            "certificate_present": security is not None,
            "certificate_offset": security.file_offset if security is not None else None,
            "certificate_size": security.size if security is not None else 0,
            "finding_ids": [str(item["id"]) for item in signature_findings],
        }
    )

    if pe.overlay_size:
        overlay_hit = any(item["id"] == "overlay_intersection" for item in findings)
        checks.append(
            {
                "name": "overlay_preservation",
                "status": "warning" if overlay_hit else "passed",
                "overlay_offset": pe.overlay_offset,
                "overlay_size": pe.overlay_size,
            }
        )
    else:
        checks.append({"name": "overlay_preservation", "status": "passed", "overlay_size": 0})

    relocation_hits = [item for item in findings if item["category"] == "relocation"]
    checks.append(
        {
            "name": "base_relocations",
            "status": "warning" if relocation_hits else "passed",
            "intersection_count": len(relocation_hits),
        }
    )

    planned_hash = None
    if engine_ok and isinstance(getattr(engine_result, "data", None), Mapping):
        planned_hash = engine_result.data.get("planned_sha256")
    rollback_plan = _build_rollback_plan(
        target,
        data,
        plan,
        resolved,
        planned_hash=planned_hash,
        errors=errors,
    )
    checks.append(
        {
            "name": "rollback_recoverability",
            "status": "passed" if rollback_plan.get("reversible") else "failed",
        }
    )

    risk_report = _risk_report(findings)
    verification = {
        "schema_version": 1,
        "status": "ok" if not errors else "failed",
        "valid": not errors,
        "target_path": str(target),
        "target_sha256": target_hash,
        "planned_sha256": planned_hash,
        "strategy": str(plan.get("strategy") or "unspecified"),
        "checks": checks,
        "operations": resolved,
        "errors": _dedupe(errors),
        "warnings": _dedupe(warnings),
        "overall_risk": risk_report["overall_risk"],
    }
    return verification, risk_report, rollback_plan


def _load_pe_context(target: Path, data: bytes) -> _PeContext:
    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise PatchPlannerUnavailable(f"optional dependency pefile unavailable: {exc}") from exc
    try:
        parsed = pefile.PE(str(target), fast_load=False)
    except Exception as exc:  # noqa: BLE001
        raise PatchPlanningError(f"unable to parse PE target: {exc}") from exc

    try:
        return _pe_context_from_parsed(parsed, data)
    finally:
        close = getattr(parsed, "close", None)
        if callable(close):
            close()


def _load_pe_context_from_bytes(data: bytes) -> _PeContext:
    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise PatchPlannerUnavailable(f"optional dependency pefile unavailable: {exc}") from exc
    try:
        parsed = pefile.PE(data=data, fast_load=False)
    except Exception as exc:  # noqa: BLE001
        raise PatchPlanningError(f"unable to parse planned PE bytes: {exc}") from exc
    try:
        return _pe_context_from_parsed(parsed, data)
    finally:
        close = getattr(parsed, "close", None)
        if callable(close):
            close()


def _pe_context_from_parsed(parsed: Any, data: bytes) -> _PeContext:
    """Copy the PE layout needed by the planner before closing pefile."""

    sections = [
        _Section(
            index=index,
            name=bytes(section.Name).split(b"\x00", 1)[0].decode("ascii", errors="replace") or "<unnamed>",
            virtual_address=int(section.VirtualAddress),
            virtual_size=int(section.Misc_VirtualSize),
            raw_offset=int(section.PointerToRawData),
            raw_size=int(section.SizeOfRawData),
            characteristics=int(section.Characteristics),
        )
        for index, section in enumerate(parsed.sections)
    ]
    magic = int(parsed.OPTIONAL_HEADER.Magic)
    bits = 64 if magic == 0x20B else 32
    headers = int(parsed.OPTIONAL_HEADER.SizeOfHeaders)
    optional_offset = int(parsed.OPTIONAL_HEADER.get_file_offset())
    section_table_offset = (
        int(parsed.sections[0].get_file_offset())
        if parsed.sections
        else optional_offset + int(parsed.FILE_HEADER.SizeOfOptionalHeader)
    )
    context = _PeContext(
        machine=int(parsed.FILE_HEADER.Machine),
        bits=bits,
        image_base=int(parsed.OPTIONAL_HEADER.ImageBase),
        entrypoint_rva=int(parsed.OPTIONAL_HEADER.AddressOfEntryPoint),
        entrypoint_offset=None,
        entrypoint_field_offset=optional_offset + 16,
        checksum_field_offset=optional_offset + 64,
        security_directory_entry_offset=optional_offset + (112 if bits == 64 else 96) + (4 * 8),
        size_of_headers=headers,
        section_alignment=int(parsed.OPTIONAL_HEADER.SectionAlignment),
        file_alignment=int(parsed.OPTIONAL_HEADER.FileAlignment),
        size_of_image=int(parsed.OPTIONAL_HEADER.SizeOfImage),
        size_of_image_field_offset=optional_offset + 56,
        section_table_offset=section_table_offset,
        sections=sections,
        directories=[],
        resources=[],
        import_thunks=[],
        relocation_sites=[],
        overlay_offset=None,
        overlay_size=0,
    )
    try:
        context.entrypoint_offset = _rva_to_offset(
            context,
            context.entrypoint_rva,
            1,
            file_size=len(data),
        )
    except PatchPlanningError:
        context.entrypoint_offset = None

    directories: list[_Directory] = []
    for index, directory in enumerate(getattr(parsed.OPTIONAL_HEADER, "DATA_DIRECTORY", []) or []):
        rva = int(getattr(directory, "VirtualAddress", 0) or 0)
        size = int(getattr(directory, "Size", 0) or 0)
        if not rva or not size:
            continue
        file_offset: int | None
        if index == 4:
            file_offset = rva if rva < len(data) else None
        else:
            try:
                file_offset = _rva_to_offset(context, rva, min(size, 1), file_size=len(data))
            except PatchPlanningError:
                file_offset = None
        directories.append(
            _Directory(
                name=_DIRECTORY_NAMES.get(index, f"directory_{index}"),
                index=index,
                rva=rva,
                size=size,
                file_offset=file_offset,
            )
        )
    context.directories = directories
    context.resources = _resource_leaves_from_parsed(parsed, context, len(data))
    context.import_thunks = _import_thunks_from_parsed(parsed, context, len(data))
    context.relocation_sites = _relocation_sites_from_parsed(parsed, context, len(data))

    overlay_offset = parsed.get_overlay_data_start_offset()
    if overlay_offset is not None:
        normalized_overlay = int(overlay_offset)
        if 0 <= normalized_overlay < len(data):
            context.overlay_offset = normalized_overlay
            context.overlay_size = len(data) - normalized_overlay
    return context


def _resource_leaves_from_parsed(
    parsed: Any,
    pe: _PeContext,
    file_size: int,
) -> list[_ResourceLeaf]:
    root = getattr(parsed, "DIRECTORY_ENTRY_RESOURCE", None)
    leaves: list[_ResourceLeaf] = []
    for type_entry in getattr(root, "entries", []) or []:
        type_directory = getattr(type_entry, "directory", None)
        for name_entry in getattr(type_directory, "entries", []) or []:
            name_directory = getattr(name_entry, "directory", None)
            for language_entry in getattr(name_directory, "entries", []) or []:
                data_entry = getattr(language_entry, "data", None)
                structure = getattr(data_entry, "struct", None)
                if structure is None:
                    continue
                rva = int(getattr(structure, "OffsetToData", 0) or 0)
                size = int(getattr(structure, "Size", 0) or 0)
                if not rva or size <= 0:
                    continue
                try:
                    file_offset = _rva_to_offset(pe, rva, size, file_size=file_size)
                    structure_offset = int(structure.get_file_offset())
                except (PatchPlanningError, AttributeError, TypeError, ValueError):
                    continue
                leaves.append(
                    _ResourceLeaf(
                        type_name=_resource_entry_name(type_entry),
                        name=_resource_entry_name(name_entry),
                        language=int(getattr(language_entry, "id", 0) or 0),
                        rva=rva,
                        size=size,
                        file_offset=file_offset,
                        size_field_offset=structure_offset + 4,
                    )
                )
    return leaves


def _resource_entry_name(entry: Any) -> str:
    name = getattr(entry, "name", None)
    if name is not None:
        return str(name)
    return str(int(getattr(entry, "id", 0) or 0))


def _import_thunks_from_parsed(
    parsed: Any,
    pe: _PeContext,
    file_size: int,
) -> list[_ImportThunk]:
    pointer_size = pe.bits // 8
    thunks: list[_ImportThunk] = []
    for descriptor in getattr(parsed, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll_value = getattr(descriptor, "dll", b"")
        dll = (
            bytes(dll_value).decode("ascii", errors="replace")
            if isinstance(dll_value, (bytes, bytearray))
            else str(dll_value or "")
        )
        for imported in getattr(descriptor, "imports", []) or []:
            address = int(getattr(imported, "address", 0) or 0)
            rva = address - pe.image_base if address >= pe.image_base else address
            try:
                file_offset = _rva_to_offset(pe, rva, pointer_size, file_size=file_size)
            except PatchPlanningError:
                continue
            name_value = getattr(imported, "name", None)
            if isinstance(name_value, (bytes, bytearray)):
                symbol = bytes(name_value).decode("ascii", errors="replace")
            elif name_value is not None:
                symbol = str(name_value)
            else:
                symbol = f"ordinal:{int(getattr(imported, 'ordinal', 0) or 0)}"
            thunks.append(
                _ImportThunk(
                    dll=dll,
                    symbol=symbol,
                    rva=rva,
                    file_offset=file_offset,
                    size=pointer_size,
                )
            )
    return thunks


def _relocation_sites_from_parsed(
    parsed: Any,
    pe: _PeContext,
    file_size: int,
) -> list[_RelocationSite]:
    type_sizes = {1: 2, 2: 2, 3: 4, 4: 2, 10: 8}
    sites: list[_RelocationSite] = []
    for block in getattr(parsed, "DIRECTORY_ENTRY_BASERELOC", []) or []:
        for entry in getattr(block, "entries", []) or []:
            relocation_type = int(getattr(entry, "type", 0) or 0)
            size = type_sizes.get(relocation_type)
            if size is None:
                continue
            rva = int(getattr(entry, "rva", 0) or 0)
            try:
                file_offset = _rva_to_offset(pe, rva, size, file_size=file_size)
            except PatchPlanningError:
                continue
            sites.append(
                _RelocationSite(
                    rva=rva,
                    file_offset=file_offset,
                    size=size,
                    type=relocation_type,
                )
            )
    return sites


def _resolve_operations(
    data: bytes,
    pe: _PeContext,
    plan: Mapping[str, Any],
) -> list[dict[str, Any]]:
    operations = plan.get("operations")
    if not isinstance(operations, list) or not operations:
        raise PatchPlanningError("patch plan must contain a non-empty operations array")
    resolved: list[dict[str, Any]] = []
    simulated = bytearray(data)
    planner_metadata = plan.get("planner")
    planner_generated = bool(
        isinstance(planner_metadata, Mapping)
        and str(planner_metadata.get("name") or "").casefold() == "pe_aware_patch_planner"
    )
    for index, raw_operation in enumerate(operations):
        if not isinstance(raw_operation, Mapping):
            raise PatchPlanningError(f"operations[{index}] must be an object")
        operation = dict(raw_operation)
        operation_id = str(operation.get("id") or f"operation-{index + 1}")
        role = str(operation.get("role") or "byte_replacement")
        kind = str(operation.get("kind") or operation.get("type") or "").casefold()
        rva: int | None = None
        if kind in {"replace_offset", "replace_bytes", "replace_file_offset"}:
            offset = _integer(operation.get("offset"), field=f"{operation_id}.offset")
            replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
        elif kind == "replace_rva":
            rva = _integer(operation.get("rva"), field=f"{operation_id}.rva")
            replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
            offset = _rva_to_offset(pe, rva, len(replacement), file_size=len(data))
        elif kind in {"replace_aob", "replace_pattern", "aob_replace"}:
            pattern = _parse_aob(str(operation.get("pattern") or ""))
            replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
            if len(pattern) != len(replacement):
                raise PatchPlanningError(f"{operation_id}: replacement length must equal AOB pattern length")
            matches = _find_aob(bytes(simulated), pattern)
            expected_count = _integer(operation.get("expected_match_count", 1), field=f"{operation_id}.expected_match_count")
            if len(matches) != expected_count:
                raise PatchPlanningError(f"{operation_id}: expected {expected_count} AOB matches, found {len(matches)}")
            occurrence = _integer(operation.get("occurrence", 0), field=f"{operation_id}.occurrence")
            if occurrence >= len(matches):
                raise PatchPlanningError(f"{operation_id}: occurrence is outside the AOB matches")
            offset = matches[occurrence]
        else:
            raise PatchPlanningError(
                f"{operation_id}: PE planner verifies only layout-preserving replace operations"
            )
        original = _read_preimage(bytes(simulated), offset, len(replacement))
        if kind in {"replace_aob", "replace_pattern", "aob_replace"}:
            expected_value = operation.get("expected", operation.get("resolved_preimage"))
            if expected_value is None and planner_generated:
                raise PatchPlanningError(
                    f"{operation_id}: PE planner AOB operations must pin the resolved expected bytes"
                )
            if expected_value is not None:
                expected = _hex_bytes(expected_value, field=f"{operation_id}.expected")
                if len(expected) != len(replacement):
                    raise PatchPlanningError(
                        f"{operation_id}: expected AOB pre-image length must equal pattern length"
                    )
                if original != expected:
                    raise PatchPlanningError(
                        f"{operation_id}: resolved AOB pre-image does not match expected bytes"
                    )
        try:
            section = _section_for_range(pe, offset, len(replacement))
        except PatchPlanningError:
            section = None
            if role == "section_extension_payload" and isinstance(plan.get("strategy_details"), Mapping):
                details = plan["strategy_details"]
                section_index = _integer(
                    details.get("section_index"), field="strategy_details.section_index"
                )
                new_raw_size = _integer(
                    details.get("new_raw_size"), field="strategy_details.new_raw_size"
                )
                if section_index < len(pe.sections):
                    candidate = pe.sections[section_index]
                    if (
                        candidate.raw_offset <= offset
                        and offset + len(replacement) <= candidate.raw_offset + new_raw_size
                    ):
                        section = candidate
            if section is None:
                raise
        if rva is None:
            rva = _offset_to_rva(pe, offset, len(replacement))
            if rva is None and section is not None and offset >= section.raw_offset:
                rva = section.virtual_address + (offset - section.raw_offset)
        for previous in resolved:
            previous_start = int(previous["file_offset"])
            previous_end = previous_start + int(previous["size"])
            if _overlaps(offset, offset + len(replacement), previous_start, previous_end):
                raise PatchPlanningError(
                    f"{operation_id}: patch range overlaps operation {previous['id']}; "
                    "overlapping plans cannot produce an unambiguous rollback"
                )
        resolved.append(
            {
                "id": operation_id,
                "kind": kind,
                "role": role,
                "file_offset": offset,
                "file_offset_hex": f"0x{offset:X}",
                "rva": rva,
                "rva_hex": f"0x{rva:X}" if rva is not None else None,
                "size": len(replacement),
                "original_hex": original.hex(),
                "replacement_hex": replacement.hex(),
                "section_index": section.index if section else None,
                "section": section.name if section else "headers_or_overlay",
                "section_executable": bool(section and section.executable),
                "section_analysis_end": (
                    section.raw_offset
                    + _integer(plan["strategy_details"].get("new_raw_size"), field="strategy_details.new_raw_size")
                    if role == "section_extension_payload"
                    and section is not None
                    and isinstance(plan.get("strategy_details"), Mapping)
                    else section.raw_end if section is not None else None
                ),
            }
        )
        simulated[offset : offset + len(replacement)] = replacement
    return resolved


def _append_structural_findings(
    operation: Mapping[str, Any],
    pe: _PeContext,
    findings: list[dict[str, Any]],
) -> None:
    start = int(operation["file_offset"])
    end = start + int(operation["size"])
    operation_id = str(operation["id"])
    if start < pe.size_of_headers:
        findings.append(
            _finding(
                "pe_header_modification",
                "high",
                "pe_layout",
                "patch intersects PE headers",
                operation_id,
                {"file_offset": start, "size_of_headers": pe.size_of_headers},
            )
        )
    if pe.entrypoint_offset is not None and start <= pe.entrypoint_offset < end:
        findings.append(
            _finding(
                "entrypoint_intersection",
                "high",
                "control_flow",
                "patch intersects the PE entrypoint",
                operation_id,
                {"entrypoint_rva": pe.entrypoint_rva, "entrypoint_offset": pe.entrypoint_offset},
            )
        )
    for directory in pe.directories:
        if directory.file_offset is None:
            continue
        if _overlaps(start, end, directory.file_offset, directory.file_offset + directory.size):
            severity = "critical" if directory.name in {"import", "iat", "base_relocation"} else "high"
            findings.append(
                _finding(
                    f"directory_intersection:{directory.name}",
                    severity,
                    "pe_directory",
                    f"patch intersects the PE {directory.name} directory",
                    operation_id,
                    {
                        "directory": directory.name,
                        "directory_rva": directory.rva,
                        "directory_file_offset": directory.file_offset,
                        "directory_size": directory.size,
                    },
                )
            )
    for relocation in pe.relocation_sites:
        if _overlaps(start, end, relocation.file_offset, relocation.file_offset + relocation.size):
            findings.append(
                _finding(
                    "relocation_target_intersection",
                    "critical",
                    "relocation",
                    "patch intersects a base-relocation target",
                    operation_id,
                    {
                        "relocation_rva": relocation.rva,
                        "relocation_file_offset": relocation.file_offset,
                        "relocation_size": relocation.size,
                        "relocation_type": relocation.type,
                    },
                )
            )
    if pe.overlay_offset is not None and _overlaps(start, end, pe.overlay_offset, pe.overlay_offset + pe.overlay_size):
        findings.append(
            _finding(
                "overlay_intersection",
                "high",
                "overlay",
                "patch intersects an existing overlay",
                operation_id,
                {"overlay_offset": pe.overlay_offset, "overlay_size": pe.overlay_size},
            )
        )


def _append_authenticode_findings(
    operations: list[Mapping[str, Any]],
    pe: _PeContext,
    findings: list[dict[str, Any]],
) -> None:
    security = _directory(pe, "security")
    if security is None:
        return

    certificate_range = (
        (security.file_offset, security.file_offset + security.size)
        if security.file_offset is not None
        else None
    )
    findings.append(
        _finding(
            "authenticode_certificate_table_present",
            "high",
            "signature",
            "a PE certificate table is present and patch effects require Authenticode revalidation",
            "plan",
            {
                "certificate_offset": security.file_offset,
                "certificate_size": security.size,
                "signature_validated": False,
            },
        )
    )

    checksum_range = (pe.checksum_field_offset, pe.checksum_field_offset + 4)
    security_entry_range = (
        pe.security_directory_entry_offset,
        pe.security_directory_entry_offset + 8,
    )
    digest_exclusions = [checksum_range, security_entry_range]
    if certificate_range is not None:
        digest_exclusions.append(certificate_range)

    for operation in operations:
        start = int(operation["file_offset"])
        end = start + int(operation["size"])
        operation_id = str(operation["id"])
        if _overlaps(start, end, *checksum_range):
            findings.append(
                _finding(
                    "authenticode_checksum_excluded_range",
                    "low",
                    "signature",
                    "patch intersects the checksum field excluded from the Authenticode digest",
                    operation_id,
                    {
                        "checksum_field_offset": pe.checksum_field_offset,
                        "digest_excluded": True,
                    },
                )
            )
        if _overlaps(start, end, *security_entry_range):
            findings.append(
                _finding(
                    "authenticode_security_directory_entry_intersection",
                    "critical",
                    "signature",
                    "patch changes the certificate-table directory entry used to locate Authenticode data",
                    operation_id,
                    {
                        "security_directory_entry_offset": pe.security_directory_entry_offset,
                        "entry_size": 8,
                    },
                )
            )
        if certificate_range is not None and _overlaps(start, end, *certificate_range):
            findings.append(
                _finding(
                    "authenticode_certificate_table_intersection",
                    "critical",
                    "signature",
                    "patch changes bytes inside the Authenticode certificate table",
                    operation_id,
                    {
                        "certificate_offset": security.file_offset,
                        "certificate_size": security.size,
                    },
                )
            )
        if _range_has_uncovered_bytes(start, end, digest_exclusions):
            findings.append(
                _finding(
                    "authenticode_digest_invalidation",
                    "high",
                    "signature",
                    "patch changes image or overlay bytes covered by the Authenticode digest",
                    operation_id,
                    {
                        "file_offset": start,
                        "size": end - start,
                        "signature_validated": False,
                    },
                )
            )


def _range_has_uncovered_bytes(
    start: int,
    end: int,
    excluded_ranges: list[tuple[int, int]],
) -> bool:
    cursor = start
    for excluded_start, excluded_end in sorted(excluded_ranges):
        if excluded_end <= cursor or excluded_start >= end:
            continue
        if excluded_start > cursor:
            return True
        cursor = max(cursor, min(end, excluded_end))
        if cursor >= end:
            return False
    return cursor < end


def _instruction_analysis(
    data: bytes,
    pe: _PeContext,
    operation: Mapping[str, Any],
) -> dict[str, Any] | None:
    if not operation.get("section_executable"):
        return None
    try:
        import capstone  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return {
            "operation_id": operation["id"],
            "status": "unavailable",
            "cfg_status": "unavailable",
            "message": f"optional dependency capstone unavailable: {exc}",
            "findings": [
                _finding(
                    "capstone_unavailable",
                    "high",
                    "disassembly",
                    "instruction-boundary verification is unavailable",
                    str(operation["id"]),
                    {},
                )
            ],
        }

    decoder = _capstone_decoder_config(capstone, pe)
    if decoder is None:
        machine = f"0x{pe.machine:04X}"
        return {
            "operation_id": operation["id"],
            "status": "unavailable",
            "cfg_status": "unavailable",
            "message": f"instruction-boundary verification does not support PE machine {machine}",
            "findings": [
                _finding(
                    "unsupported_pe_machine",
                    "high",
                    "disassembly",
                    "the executable section cannot be verified with a supported decoder",
                    str(operation["id"]),
                    {"machine": machine, "bits": pe.bits},
                )
            ],
        }

    section_index = operation.get("section_index")
    section = next((item for item in pe.sections if item.index == section_index), None)
    if section is None:
        return {
            "operation_id": operation["id"],
            "status": "failed",
            "cfg_status": "failed",
            "errors": [f"{operation['id']}: executable section identity could not be resolved"],
            "findings": [
                _finding(
                    "executable_section_unresolved",
                    "critical",
                    "disassembly",
                    "the executable section identity could not be resolved",
                    str(operation["id"]),
                    {"section_index": section_index},
                )
            ],
        }
    patch_start = int(operation["file_offset"])
    patch_end = patch_start + int(operation["size"])
    section_end = min(
        max(section.raw_end, int(operation.get("section_analysis_end") or section.raw_end)),
        len(data),
    )
    section_span = section_end - section.raw_offset
    if section_span > 4 * 1024 * 1024:
        return {
            "operation_id": operation["id"],
            "status": "unavailable",
            "cfg_status": "unavailable",
            "message": "executable section exceeds the bounded 4 MiB CFG window",
            "findings": [
                _finding(
                    "disassembly_window_exceeded",
                    "medium",
                    "disassembly",
                    "instruction-boundary verification exceeded its bounded window",
                    str(operation["id"]),
                    {"section_size": section_span},
                )
            ],
        }

    architecture, mode = decoder
    md = capstone.Cs(architecture, mode)
    md.detail = True
    md.skipdata = False
    decode_end = section_end
    base_address = pe.image_base + section.virtual_address
    original_instructions = list(md.disasm(data[section.raw_offset:decode_end], base_address))
    instruction_starts = {
        section.raw_offset + (int(instruction.address) - base_address)
        for instruction in original_instructions
    }
    boundaries = set(instruction_starts)
    boundaries.add(section.raw_offset)
    if original_instructions:
        last = original_instructions[-1]
        boundaries.add(section.raw_offset + int(last.address - base_address) + int(last.size))
    start_aligned = patch_start in boundaries
    end_aligned = patch_end in boundaries

    replacement = bytes.fromhex(str(operation["replacement_hex"]))
    relative_start = patch_start - section.raw_offset
    replacement_address = base_address + relative_start
    replacement_decoder = capstone.Cs(architecture, mode)
    replacement_decoder.detail = True
    replacement_decoder.skipdata = False
    replacement_instructions = list(replacement_decoder.disasm(replacement, replacement_address))
    replacement_decoded_size = sum(int(instruction.size) for instruction in replacement_instructions)
    resynchronized = (
        bool(replacement_instructions)
        and replacement_decoded_size == len(replacement)
        and int(replacement_instructions[-1].address) + int(replacement_instructions[-1].size)
        == replacement_address + len(replacement)
    )

    covered = [
        instruction
        for instruction in original_instructions
        if patch_start <= section.raw_offset + int(instruction.address - base_address) < patch_end
    ]
    control_flow = []
    for instruction in covered:
        groups = set(getattr(instruction, "groups", []) or [])
        if groups.intersection({capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET}):
            control_flow.append(f"{instruction.mnemonic} {instruction.op_str}".strip())

    incoming_interior: list[dict[str, Any]] = []
    invalid_direct_targets: list[dict[str, Any]] = []
    basic_block_entry_sources: dict[int, set[str]] = {}

    def add_block_entry(file_offset: int, source: str) -> None:
        if file_offset in instruction_starts:
            basic_block_entry_sources.setdefault(file_offset, set()).add(source)

    add_block_entry(section.raw_offset, "section_start")
    if pe.entrypoint_offset is not None and section.raw_offset <= pe.entrypoint_offset < section_end:
        add_block_entry(pe.entrypoint_offset, "address_of_entrypoint")

    for instruction in original_instructions:
        groups = set(getattr(instruction, "groups", []) or [])
        source_offset = section.raw_offset + (int(instruction.address) - base_address)
        is_jump = capstone.CS_GRP_JUMP in groups
        is_call = capstone.CS_GRP_CALL in groups
        is_control_flow = bool(
            groups.intersection({capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET})
        )
        if is_control_flow:
            add_block_entry(source_offset + int(instruction.size), "after_control_flow")
        if not (is_jump or is_call):
            continue
        target_source = "direct_jump_target" if is_jump else "direct_call_target"
        for operand in getattr(instruction, "operands", []) or []:
            if operand.type != capstone.CS_OP_IMM:
                continue
            target_rva = int(operand.imm) - pe.image_base
            try:
                target_offset = _rva_to_offset(pe, target_rva, 1, file_size=len(data))
            except PatchPlanningError:
                continue
            target_record = {
                "source": f"0x{int(instruction.address):X}",
                "source_file_offset": source_offset,
                "target": f"0x{int(operand.imm):X}",
                "target_rva": target_rva,
                "target_file_offset": target_offset,
            }
            if section.raw_offset <= target_offset < section_end:
                if target_offset in instruction_starts:
                    add_block_entry(target_offset, target_source)
                else:
                    invalid_direct_targets.append(target_record)
            if patch_start < target_offset < patch_end:
                incoming_interior.append(target_record)

    basic_block_entries = []
    for file_offset, sources in sorted(basic_block_entry_sources.items()):
        entry_rva = _offset_to_rva(pe, file_offset, 1)
        basic_block_entries.append(
            {
                "file_offset": file_offset,
                "file_offset_hex": f"0x{file_offset:X}",
                "rva": entry_rva,
                "rva_hex": f"0x{entry_rva:X}" if entry_rva is not None else None,
                "sources": sorted(sources),
            }
        )

    errors: list[str] = []
    findings: list[dict[str, Any]] = []
    if not start_aligned or not end_aligned:
        errors.append(
            f"{operation['id']}: patch range does not align to complete instruction boundaries"
        )
        findings.append(
            _finding(
                "instruction_boundary_violation",
                "critical",
                "disassembly",
                "patch starts or ends inside an instruction",
                str(operation["id"]),
                {"start_aligned": start_aligned, "end_aligned": end_aligned},
            )
        )
    if not resynchronized:
        errors.append(f"{operation['id']}: patched instruction stream does not resynchronize at range end")
        findings.append(
            _finding(
                "disassembly_resync_failed",
                "critical",
                "disassembly",
                "replacement bytes do not decode exactly to the original range end",
                str(operation["id"]),
                {},
            )
        )
    if control_flow:
        findings.append(
            _finding(
                "control_flow_instruction_modified",
                "high",
                "control_flow",
                "patch replaces one or more control-flow instructions",
                str(operation["id"]),
                {"instructions": control_flow},
            )
        )
    if incoming_interior:
        findings.append(
            _finding(
                "incoming_branch_to_range_interior",
                "critical",
                "control_flow",
                "a direct branch targets the interior of the patch range",
                str(operation["id"]),
                {"branches": incoming_interior},
            )
        )
    if invalid_direct_targets:
        findings.append(
            _finding(
                "direct_branch_target_not_instruction_boundary",
                "critical",
                "control_flow",
                "a direct branch or call target is not an instruction boundary",
                str(operation["id"]),
                {"branches": invalid_direct_targets},
            )
        )
    operation_rva = operation.get("rva")
    return {
        "operation_id": operation["id"],
        "status": "failed" if errors else "passed",
        "patch_range": {
            "file_offset_start": patch_start,
            "file_offset_end": patch_end,
            "file_offset_start_hex": f"0x{patch_start:X}",
            "file_offset_end_hex": f"0x{patch_end:X}",
            "rva_start": operation_rva,
            "rva_end": int(operation_rva) + int(operation["size"]) if operation_rva is not None else None,
            "rva_start_hex": f"0x{int(operation_rva):X}" if operation_rva is not None else None,
            "rva_end_hex": (
                f"0x{int(operation_rva) + int(operation['size']):X}"
                if operation_rva is not None
                else None
            ),
            "start_instruction_boundary": start_aligned,
            "end_instruction_boundary": end_aligned,
        },
        "start_aligned": start_aligned,
        "end_aligned": end_aligned,
        "resynchronized": resynchronized,
        "replacement_instruction_count": len(replacement_instructions),
        "replacement_decoded_size": replacement_decoded_size,
        "original_instruction_count": len(covered),
        "control_flow_instructions": control_flow,
        "basic_block_entries": basic_block_entries,
        "patch_entry_sources": sorted(basic_block_entry_sources.get(patch_start, set())),
        "incoming_interior_branches": incoming_interior,
        "invalid_direct_targets": invalid_direct_targets,
        "cfg_status": (
            "failed"
            if incoming_interior or invalid_direct_targets
            else "risky"
            if control_flow
            else "preserved"
        ),
        "errors": errors,
        "findings": findings,
    }


def _entrypoint_redirect_cfg_evidence(
    data: bytes,
    pe: _PeContext,
    plan: Mapping[str, Any],
) -> dict[str, Any] | None:
    try:
        strategy = _normalize_strategy(str(plan.get("strategy") or "inline_patch"))
    except PatchPlanningError:
        return None
    if strategy != "entrypoint_redirect":
        return None
    details = plan.get("strategy_details")
    if not isinstance(details, Mapping):
        return {
            "status": "failed",
            "instruction_boundary": False,
            "basic_block_entry": False,
            "error": "entrypoint_redirect strategy details are missing",
        }
    try:
        target_rva = _integer(
            details.get("new_entrypoint_rva"), field="strategy_details.new_entrypoint_rva"
        )
        target_offset = _rva_to_offset(pe, target_rva, 1, file_size=len(data))
        section = _section_for_range(pe, target_offset, 1)
        boundary_error = _instruction_boundary_error(data, pe, target_offset)
    except (PatchPlanningError, TypeError, ValueError) as exc:
        return {
            "status": "failed",
            "instruction_boundary": False,
            "basic_block_entry": False,
            "error": str(exc),
        }
    boundary_ok = boundary_error is None
    return {
        "status": "passed" if boundary_ok else "failed",
        "old_entrypoint_rva": pe.entrypoint_rva,
        "new_entrypoint_rva": target_rva,
        "new_entrypoint_rva_hex": f"0x{target_rva:X}",
        "new_entrypoint_file_offset": target_offset,
        "new_entrypoint_file_offset_hex": f"0x{target_offset:X}",
        "section": section.name if section is not None else None,
        "instruction_boundary": boundary_ok,
        "basic_block_entry": boundary_ok,
        "entry_sources": ["address_of_entrypoint"] if boundary_ok else [],
        "payload_size": _integer(details.get("payload_size", 0), field="strategy_details.payload_size"),
        "error": boundary_error,
    }


def _capstone_decoder_config(capstone: Any, pe: _PeContext) -> tuple[int, int] | None:
    if pe.machine == 0x014C and pe.bits == 32:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    if pe.machine == 0x8664 and pe.bits == 64:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    return None


def _build_rollback_plan(
    target: Path,
    data: bytes,
    plan: Mapping[str, Any],
    resolved: list[Mapping[str, Any]],
    *,
    planned_hash: Any,
    errors: list[str],
) -> dict[str, Any]:
    reversible = not errors and bool(resolved) and isinstance(planned_hash, str)
    operations = [
        {
            "kind": "restore_bytes",
            "id": item["id"],
            "file_offset": item["file_offset"],
            "rva": item.get("rva"),
            "original_hex": item["original_hex"],
            "patched_hex": item["replacement_hex"],
        }
        for item in resolved
    ]
    return {
        "schema_version": 1,
        "status": "planned" if reversible else "unavailable",
        "reversible": reversible,
        "strategy": str(plan.get("strategy") or "unspecified"),
        "source_path": str(target),
        "source_sha256": _sha256(data),
        "patched_sha256": planned_hash,
        "operations": operations,
        "requires_patched_copy": True,
        "errors": _dedupe(errors) if not reversible else [],
    }


def _risk_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        findings,
        key=lambda item: (-_SEVERITY_ORDER.get(str(item.get("severity")), 0), str(item.get("id"))),
    )
    highest = max((_SEVERITY_ORDER.get(str(item.get("severity")), 0) for item in ordered), default=0)
    overall = next((name for name, value in _SEVERITY_ORDER.items() if value == highest), "info")
    counts = {name: 0 for name in _SEVERITY_ORDER}
    for item in ordered:
        counts[str(item.get("severity") or "info")] += 1
    score = min(100, sum(counts[name] * weight for name, weight in {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}.items()))
    return {
        "schema_version": 1,
        "status": "ok",
        "overall_risk": overall,
        "risk_score": score,
        "counts": counts,
        "findings": ordered,
    }


def _write_planning_artifacts(
    out_dir: Path,
    *,
    plan: Mapping[str, Any],
    verification: Mapping[str, Any],
    risk_report: Mapping[str, Any],
    rollback_plan: Mapping[str, Any],
    include_plan: bool,
    protected_paths: Mapping[str, Path] | None = None,
) -> list[dict[str, Any]]:
    values: list[tuple[str, Mapping[str, Any], str]] = []
    if include_plan:
        values.append(("plan.json", plan, "patch-plan"))
    values.extend(
        [
            ("verify.json", verification, "patch-verification"),
            ("risk_report.json", risk_report, "patch-risk-report"),
            ("rollback_plan.json", rollback_plan, "patch-rollback-plan"),
        ]
    )
    outputs = {name: (out_dir / name).resolve() for name, _, _ in values}
    named_paths = dict(protected_paths or {})
    named_paths.update({f"artifact:{name}": path for name, path in outputs.items()})
    _ensure_distinct_paths(named_paths)
    _write_json_bundle([(outputs[name], payload) for name, payload, _ in values])
    return [
        {"name": name, "path": str(outputs[name]), "kind": kind}
        for name, _, kind in values
    ]


def _target_summary(target: Path, data: bytes, pe: _PeContext) -> dict[str, Any]:
    return {
        "path": str(target),
        "format": "pe",
        "sha256": _sha256(data),
        "size": len(data),
        "machine": f"0x{pe.machine:04X}",
        "bits": pe.bits,
        "image_base": pe.image_base,
        "entrypoint_rva": pe.entrypoint_rva,
        "section_count": len(pe.sections),
        "has_overlay": bool(pe.overlay_size),
    }


def _intent_bytes(intent: Mapping[str, Any], *names: str, field: str) -> bytes:
    for name in names:
        if intent.get(name) is not None:
            return _hex_bytes(intent[name], field=field)
    joined = " or ".join(names)
    raise PatchPlanningError(f"{field} is required; provide {joined} as hexadecimal bytes")


def _operation_id(intent: Mapping[str, Any], fallback: str) -> str:
    value = str(intent.get("operation_id") or intent.get("id") or fallback).strip()
    return value or fallback


def _selectors(intent: Mapping[str, Any]) -> list[str]:
    return [name for name in ("offset", "rva", "aob") if intent.get(name) is not None]


def _replace_operation(
    data: bytes,
    offset: int,
    replacement: bytes,
    *,
    operation_id: str,
    role: str,
) -> dict[str, Any]:
    return {
        "id": operation_id,
        "kind": "replace_offset",
        "offset": offset,
        "expected": _read_preimage(data, offset, len(replacement)).hex(),
        "replacement": replacement.hex(),
        "role": role,
    }


def _replace_integer_operation(
    data: bytes,
    offset: int,
    value: int,
    *,
    operation_id: str,
    role: str,
    size: int = 4,
) -> dict[str, Any]:
    if value < 0 or value >= 1 << (size * 8):
        raise PatchPlanningError(f"{operation_id}: integer value does not fit in {size} bytes")
    return _replace_operation(
        data,
        offset,
        value.to_bytes(size, "little"),
        operation_id=operation_id,
        role=role,
    )


def _selector_offset(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    selector: str,
    size: int,
) -> int:
    if selector == "offset":
        offset = _integer(intent[selector], field="offset")
        _read_preimage(data, offset, size)
        return offset
    if selector == "rva":
        return _rva_to_offset(pe, _integer(intent[selector], field="rva"), size, file_size=len(data))
    pattern = _parse_aob(str(intent["aob"]))
    if len(pattern) != size:
        raise PatchPlanningError("AOB selector length must equal the replacement length")
    matches = _find_aob(data, pattern)
    occurrence = _integer(intent.get("occurrence", 0), field="occurrence")
    if not matches:
        raise PatchPlanningError("AOB pattern did not match the target")
    if occurrence >= len(matches):
        raise PatchPlanningError(f"occurrence {occurrence} is outside {len(matches)} AOB matches")
    return matches[occurrence]


def _find_code_cave(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    size: int,
) -> int:
    alignment = _integer(intent.get("cave_alignment", 1), field="cave_alignment")
    if alignment <= 0:
        raise PatchPlanningError("cave_alignment must be positive")
    requested = _section_from_intent(pe, intent)
    sections = [requested] if requested is not None else [item for item in pe.sections if item.executable]
    sections = [item for item in sections if item is not None and item.executable]
    if not sections:
        raise PatchPlanningError("code_cave_patch requires an executable section")
    for section in sections:
        scan_start = section.raw_offset + min(section.virtual_size, section.raw_size)
        scan_end = min(section.raw_end, len(data), pe.overlay_offset or len(data))
        if scan_end - scan_start > 16 * 1024 * 1024:
            raise PatchPlanningError(
                f"section {section.name} cave search exceeds the bounded 16 MiB window; provide offset or RVA"
            )
        candidate = _align_up(scan_start, alignment)
        while candidate + size <= scan_end:
            block = data[candidate : candidate + size]
            if all(value in _CAVE_BYTES for value in block):
                try:
                    _reject_protected_range(pe, candidate, size, strategy="code_cave_patch")
                except PatchPlanningError:
                    candidate += alignment
                    continue
                return candidate
            candidate += alignment
    raise PatchPlanningError(
        f"no executable 00/90/CC code cave can hold {size} bytes; provide an explicit verified offset/RVA"
    )


def _section_from_intent(pe: _PeContext, intent: Mapping[str, Any]) -> _Section | None:
    raw_value = intent.get("section", intent.get("section_name", intent.get("section_index")))
    if raw_value is None:
        return None
    if isinstance(raw_value, int) or (isinstance(raw_value, str) and raw_value.strip().isdigit()):
        index = _integer(raw_value, field="section_index")
        if index >= len(pe.sections):
            raise PatchPlanningError(f"section_index {index} is outside {len(pe.sections)} sections")
        return pe.sections[index]
    name = str(raw_value).strip().casefold()
    matches = [item for item in pe.sections if item.name.casefold() == name]
    if len(matches) != 1:
        available = ", ".join(item.name for item in pe.sections)
        raise PatchPlanningError(f"section {raw_value!r} was not found; available sections: {available}")
    return matches[0]


def _select_section_for_extension(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    selected_offset: int | None,
    payload_size: int,
) -> _Section:
    requested = _section_from_intent(pe, intent)
    if selected_offset is not None:
        matches = [
            item
            for item in pe.sections
            if item.raw_offset <= selected_offset < min(item.raw_end, len(data))
        ]
        if len(matches) != 1:
            raise PatchPlanningError("section extension selector is not inside one file-backed section")
        if requested is not None and matches[0].index != requested.index:
            raise PatchPlanningError("section selector and explicit section identify different sections")
        return matches[0]
    if requested is not None:
        return requested
    candidates = []
    for section in pe.sections:
        start = section.raw_offset + section.virtual_size
        if start + payload_size <= section.raw_end and all(
            value in _CAVE_BYTES for value in data[start : start + payload_size]
        ):
            candidates.append(section)
    if len(candidates) != 1:
        names = ", ".join(item.name for item in candidates) or "none"
        raise PatchPlanningError(
            f"section_extend_patch cannot choose a unique section ({names}); provide section or section_index"
        )
    return candidates[0]


def _size_of_image_after_extension(
    pe: _PeContext,
    extended: _Section,
    new_virtual_size: int,
    new_raw_size: int,
) -> int:
    image_end = pe.size_of_headers
    for section in pe.sections:
        virtual_size = new_virtual_size if section.index == extended.index else section.virtual_size
        raw_size = new_raw_size if section.index == extended.index else section.raw_size
        image_end = max(image_end, section.virtual_address + max(virtual_size, raw_size))
    return _align_up(image_end, pe.section_alignment)


def _directory(pe: _PeContext, name: str) -> _Directory | None:
    return next((item for item in pe.directories if item.name == name), None)


def _range_inside_directory(directory: _Directory, offset: int, size: int) -> bool:
    return bool(
        directory.file_offset is not None
        and directory.file_offset <= offset
        and offset + size <= directory.file_offset + directory.size
    )


def _select_resource(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
) -> tuple[_ResourceLeaf, int, int, int]:
    type_value = intent.get("resource_type")
    name_value = intent.get("resource_name", intent.get("resource_id"))
    language_value = intent.get("resource_lang", intent.get("language"))
    matches = list(pe.resources)
    if type_value is not None:
        matches = [item for item in matches if _identifier_matches(item.type_name, type_value)]
    if name_value is not None:
        matches = [item for item in matches if _identifier_matches(item.name, name_value)]
    if language_value is not None:
        language = _integer(language_value, field="resource_lang")
        matches = [item for item in matches if item.language == language]

    selector_values = [
        ("resource_offset", intent.get("resource_offset")),
        ("offset", intent.get("offset")),
        ("resource_rva", intent.get("resource_rva")),
        ("rva", intent.get("rva")),
    ]
    provided = [(name, value) for name, value in selector_values if value is not None]
    if len(provided) > 1:
        raise PatchPlanningError("resource_replace accepts only one resource offset/RVA selector")
    explicit_offset: int | None = None
    if provided:
        field, value = provided[0]
        if field.endswith("rva"):
            explicit_offset = _rva_to_offset(
                pe, _integer(value, field=field), 1, file_size=len(data)
            )
        else:
            explicit_offset = _integer(value, field=field)
        matches = [item for item in matches if item.file_offset == explicit_offset]
        if not matches:
            raise PatchPlanningError(
                "resource selector must identify the exact start of a parsed resource data leaf"
            )

    if len(matches) != 1:
        raise PatchPlanningError(
            f"resource_replace matched {len(matches)} resources; provide resource_type/name/lang or resource_offset/RVA"
        )
    leaf = matches[0]
    resource_offset = leaf.file_offset

    size_value = intent.get("resource_size", intent.get("allocation_size"))
    allocation_size = (
        _integer(size_value, field="resource_size")
        if size_value is not None
        else leaf.size
    )
    if allocation_size <= 0:
        raise PatchPlanningError("resource_size must be positive")
    if allocation_size != leaf.size:
        raise PatchPlanningError(
            f"resource_size must equal the parsed allocation size {leaf.size} for an in-place replacement"
        )
    _read_preimage(data, resource_offset, allocation_size)
    size_field_value = intent.get("resource_size_field_offset")
    size_field_offset = (
        _integer(size_field_value, field="resource_size_field_offset")
        if size_field_value is not None
        else leaf.size_field_offset
    )
    if size_field_offset != leaf.size_field_offset:
        raise PatchPlanningError(
            "resource_size_field_offset must identify the selected parsed resource data entry"
        )
    return leaf, resource_offset, allocation_size, size_field_offset


def _identifier_matches(observed: str, requested: Any) -> bool:
    left = str(observed).strip().lstrip("#").casefold()
    right = str(requested).strip().lstrip("#").casefold()
    return left == right


def _single_byte(value: Any, *, field: str) -> bytes:
    result = _hex_bytes(value, field=field)
    if len(result) != 1:
        raise PatchPlanningError(f"{field} must contain exactly one byte")
    return result


def _iat_replacement(pe: _PeContext, intent: Mapping[str, Any], pointer_size: int) -> bytes:
    if intent.get("replacement") is not None or intent.get("payload") is not None:
        replacement = _intent_bytes(intent, "replacement", "payload", field="replacement")
    elif intent.get("target_va") is not None:
        target = _integer(intent["target_va"], field="target_va")
        replacement = target.to_bytes(pointer_size, "little", signed=False)
    elif intent.get("target_rva") is not None:
        target_rva = _integer(intent["target_rva"], field="target_rva")
        target = pe.image_base + target_rva
        replacement = target.to_bytes(pointer_size, "little", signed=False)
    else:
        raise PatchPlanningError(
            "iat_thunk_patch requires pointer-sized replacement bytes, target_va, or target_rva"
        )
    if len(replacement) != pointer_size:
        raise PatchPlanningError(
            f"iat_thunk_patch replacement must be exactly {pointer_size} bytes for PE{pe.bits}"
        )
    return replacement


def _select_iat_thunk(
    data: bytes,
    pe: _PeContext,
    intent: Mapping[str, Any],
    pointer_size: int,
) -> tuple[_ImportThunk | None, int, int]:
    dll_value = intent.get("dll")
    symbol_value = intent.get("symbol", intent.get("import_name"))
    ordinal_value = intent.get("ordinal")
    matches = list(pe.import_thunks)
    if dll_value is not None:
        matches = [item for item in matches if item.dll.casefold() == str(dll_value).strip().casefold()]
    if symbol_value is not None:
        matches = [item for item in matches if item.symbol.casefold() == str(symbol_value).strip().casefold()]
    if ordinal_value is not None:
        wanted = f"ordinal:{_integer(ordinal_value, field='ordinal')}"
        matches = [item for item in matches if item.symbol.casefold() == wanted.casefold()]

    selectors = [
        ("thunk_offset", intent.get("thunk_offset", intent.get("iat_offset"))),
        ("offset", intent.get("offset")),
        ("thunk_rva", intent.get("thunk_rva", intent.get("iat_rva"))),
        ("rva", intent.get("rva")),
    ]
    provided = [(name, value) for name, value in selectors if value is not None]
    if len(provided) > 1:
        raise PatchPlanningError("iat_thunk_patch accepts only one thunk offset/RVA selector")
    if provided:
        field, value = provided[0]
        if field.endswith("rva") or field == "rva":
            thunk_rva = _integer(value, field=field)
            thunk_offset = _rva_to_offset(pe, thunk_rva, pointer_size, file_size=len(data))
        else:
            thunk_offset = _integer(value, field=field)
            _read_preimage(data, thunk_offset, pointer_size)
            mapped_rva = _offset_to_rva(pe, thunk_offset, pointer_size)
            if mapped_rva is None:
                raise PatchPlanningError("IAT thunk offset is not mapped by a PE section")
            thunk_rva = mapped_rva
        exact = [item for item in matches if item.file_offset == thunk_offset]
        if exact:
            matches = exact
        elif any(value is not None for value in (dll_value, symbol_value, ordinal_value)):
            raise PatchPlanningError("IAT selector does not match the requested import")
        thunk = matches[0] if len(matches) == 1 and matches[0].file_offset == thunk_offset else None
        return thunk, thunk_offset, thunk_rva

    if len(matches) == 1:
        thunk = matches[0]
        return thunk, thunk.file_offset, thunk.rva
    iat = _directory(pe, "iat")
    if iat is not None and iat.file_offset is not None and intent.get("thunk_index") is not None:
        index = _integer(intent["thunk_index"], field="thunk_index")
        thunk_offset = iat.file_offset + (index * pointer_size)
        if thunk_offset + pointer_size > iat.file_offset + iat.size:
            raise PatchPlanningError("thunk_index is outside the IAT directory")
        return None, thunk_offset, iat.rva + (index * pointer_size)
    raise PatchPlanningError(
        f"iat_thunk_patch matched {len(matches)} parsed imports; provide dll/symbol, thunk_index, or offset/RVA"
    )


def _entrypoint_target_rva(data: bytes, pe: _PeContext, intent: Mapping[str, Any]) -> int:
    rva_values = [
        (name, intent.get(name))
        for name in ("new_entrypoint_rva", "entrypoint_rva", "target_rva", "rva")
        if intent.get(name) is not None
    ]
    offset_values = [
        (name, intent.get(name))
        for name in ("target_offset", "entrypoint_offset", "offset")
        if intent.get(name) is not None
    ]
    if len(rva_values) > 1 or len(offset_values) > 1 or (rva_values and offset_values):
        raise PatchPlanningError("entrypoint_redirect requires exactly one target RVA, offset, or AOB")
    if rva_values:
        return _integer(rva_values[0][1], field=rva_values[0][0])
    if offset_values:
        offset = _integer(offset_values[0][1], field=offset_values[0][0])
        target_rva = _offset_to_rva(pe, offset, 1)
        if target_rva is None:
            raise PatchPlanningError("entrypoint target offset is not mapped by a PE section")
        return target_rva
    if intent.get("aob") is not None:
        pattern = _parse_aob(str(intent["aob"]))
        matches = _find_aob(data, pattern)
        occurrence = _integer(intent.get("occurrence", 0), field="occurrence")
        if not matches or occurrence >= len(matches):
            raise PatchPlanningError(
                f"entrypoint AOB occurrence {occurrence} is outside {len(matches)} matches"
            )
        target_rva = _offset_to_rva(pe, matches[occurrence], len(pattern))
        if target_rva is None:
            raise PatchPlanningError("entrypoint AOB match is not mapped by a PE section")
        return target_rva
    raise PatchPlanningError(
        "entrypoint_redirect requires new_entrypoint_rva, target_rva, target_offset, or aob"
    )


def _reject_protected_range(
    pe: _PeContext,
    offset: int,
    size: int,
    *,
    strategy: str,
) -> None:
    for directory in pe.directories:
        if directory.file_offset is None:
            continue
        if _overlaps(offset, offset + size, directory.file_offset, directory.file_offset + directory.size):
            raise PatchPlanningError(
                f"{strategy} target intersects the PE {directory.name} directory; choose an unowned range"
            )
    _reject_relocation_overlap(pe, offset, size, strategy=strategy)
    if pe.overlay_offset is not None and offset + size > pe.overlay_offset:
        raise PatchPlanningError(f"{strategy} target intersects the existing overlay")


def _reject_relocation_overlap(
    pe: _PeContext,
    offset: int,
    size: int,
    *,
    strategy: str,
) -> None:
    for relocation in pe.relocation_sites:
        if _overlaps(offset, offset + size, relocation.file_offset, relocation.file_offset + relocation.size):
            raise PatchPlanningError(
                f"{strategy} target intersects base relocation RVA 0x{relocation.rva:X}"
            )


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise PatchPlanningError("alignment must be positive")
    return ((value + alignment - 1) // alignment) * alignment


def _validate_strategy_contract(
    data: bytes,
    pe: _PeContext,
    plan: Mapping[str, Any],
    resolved: list[Mapping[str, Any]],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    raw_strategy = str(plan.get("strategy") or "inline_patch")
    try:
        strategy = _normalize_strategy(raw_strategy)
    except PatchPlanningError:
        return [f"unsupported patch strategy in plan: {raw_strategy!r}"], warnings, findings
    roles: dict[str, list[Mapping[str, Any]]] = {}
    for operation in resolved:
        roles.setdefault(str(operation.get("role") or ""), []).append(operation)
    if strategy == "inline_patch":
        unexpected_roles = sorted(set(roles) - {"byte_replacement"})
        if unexpected_roles:
            errors.append(
                "inline_patch contains PE-strategy operation roles: " + ", ".join(unexpected_roles)
            )
        return errors, warnings, findings
    details = plan.get("strategy_details")
    if not isinstance(details, Mapping):
        return [f"{strategy} requires a strategy_details object produced by the PE planner"], warnings, findings
    allowed_roles = {
        "code_cave_patch": {"code_cave_payload"},
        "section_extend_patch": {
            "section_extension_payload",
            "section_virtual_size",
            "section_raw_size",
            "size_of_image",
        },
        "resource_replace": {"resource_data", "resource_size"},
        "iat_thunk_patch": {"iat_thunk"},
        "entrypoint_redirect": {"entrypoint_target_payload", "address_of_entrypoint"},
        "overlay_preserve_patch": {"overlay_preserving_patch"},
    }[strategy]
    unexpected_roles = sorted(set(roles) - allowed_roles)
    if unexpected_roles:
        return [f"{strategy} contains unexpected operation roles: {', '.join(unexpected_roles)}"], warnings, findings

    try:
        if strategy == "code_cave_patch":
            cave = _single_role(roles, "code_cave_payload", strategy)
            offset = int(cave["file_offset"])
            size = int(cave["size"])
            section = _section_for_range(pe, offset, size)
            if section is None or not section.executable:
                raise PatchPlanningError("code_cave_patch operation is not in an executable section")
            if any(value not in _CAVE_BYTES for value in bytes.fromhex(str(cave["original_hex"]))):
                raise PatchPlanningError("code_cave_patch preimage is not 00/90/CC cave padding")
            _reject_protected_range(pe, offset, size, strategy=strategy)
            warnings.append(
                "code_cave_patch writes executable cave bytes but does not add a control-flow redirect"
            )
            findings.append(
                _finding(
                    "code_cave_execution_surface",
                    "high",
                    "control_flow",
                    "executable section padding is replaced with new instructions",
                    str(cave["id"]),
                    {"section": section.name, "offset": offset, "size": size},
                )
            )
        elif strategy == "section_extend_patch":
            payload = _single_role(roles, "section_extension_payload", strategy)
            virtual_size = _single_role(roles, "section_virtual_size", strategy)
            section_index = _integer(details.get("section_index"), field="strategy_details.section_index")
            if section_index >= len(pe.sections):
                raise PatchPlanningError("section_extend_patch section_index is outside the section table")
            section = pe.sections[section_index]
            expected_virtual_field = pe.section_table_offset + (section.index * 40) + 8
            if int(virtual_size["file_offset"]) != expected_virtual_field:
                raise PatchPlanningError("section_extend_patch VirtualSize operation targets the wrong header field")
            new_virtual_size = int.from_bytes(bytes.fromhex(str(virtual_size["replacement_hex"])), "little")
            if new_virtual_size != _integer(
                details.get("new_virtual_size"), field="strategy_details.new_virtual_size"
            ) or new_virtual_size <= section.virtual_size:
                raise PatchPlanningError("section_extend_patch must increase VirtualSize to its declared value")
            new_raw_size = _integer(details.get("new_raw_size"), field="strategy_details.new_raw_size")
            if new_raw_size < section.raw_size or new_raw_size % pe.file_alignment:
                raise PatchPlanningError("section_extend_patch new raw size is smaller or misaligned")
            raw_roles = roles.get("section_raw_size", [])
            if new_raw_size != section.raw_size:
                raw_size = _single_role(roles, "section_raw_size", strategy)
                expected_raw_field = pe.section_table_offset + (section.index * 40) + 16
                if int(raw_size["file_offset"]) != expected_raw_field:
                    raise PatchPlanningError("section_extend_patch SizeOfRawData targets the wrong field")
                observed_new_raw = int.from_bytes(
                    bytes.fromhex(str(raw_size["replacement_hex"])), "little"
                )
                if observed_new_raw != new_raw_size:
                    raise PatchPlanningError("section_extend_patch raw-size operation differs from metadata")
            elif raw_roles:
                raise PatchPlanningError("section_extend_patch has an unnecessary raw-size operation")
            declared_image_size = _integer(
                details.get("new_size_of_image"), field="strategy_details.new_size_of_image"
            )
            image_roles = roles.get("size_of_image", [])
            if declared_image_size != pe.size_of_image:
                image_size = _single_role(roles, "size_of_image", strategy)
                if int(image_size["file_offset"]) != pe.size_of_image_field_offset:
                    raise PatchPlanningError("section_extend_patch SizeOfImage targets the wrong field")
                observed_image_size = int.from_bytes(
                    bytes.fromhex(str(image_size["replacement_hex"])), "little"
                )
                if observed_image_size != declared_image_size:
                    raise PatchPlanningError("section_extend_patch SizeOfImage differs from metadata")
            elif image_roles:
                raise PatchPlanningError("section_extend_patch has an unnecessary SizeOfImage operation")
            payload_offset = int(payload["file_offset"])
            if payload_offset != _integer(details.get("payload_offset"), field="strategy_details.payload_offset"):
                raise PatchPlanningError("section extension payload offset differs from strategy metadata")
            payload_size = int(payload["size"])
            if payload_offset < section.raw_offset + section.virtual_size:
                raise PatchPlanningError("section extension payload overwrites bytes inside the old VirtualSize")
            if payload_offset + payload_size > section.raw_offset + new_raw_size:
                raise PatchPlanningError("section extension payload exceeds the declared new raw allocation")
            if any(value not in _CAVE_BYTES for value in bytes.fromhex(str(payload["original_hex"]))):
                raise PatchPlanningError("section extension payload preimage is not 00/90/CC padding")
            if new_raw_size > section.raw_size:
                next_raw = min(
                    (item.raw_offset for item in pe.sections if item.raw_offset > section.raw_offset),
                    default=pe.overlay_offset if pe.overlay_offset is not None else len(data),
                )
                if section.raw_offset + new_raw_size > next_raw:
                    raise PatchPlanningError("section extension overlaps a following section or overlay")
                annexed = data[section.raw_end : section.raw_offset + new_raw_size]
                if any(value not in _CAVE_BYTES for value in annexed):
                    raise PatchPlanningError("section extension annexes non-padding bytes")
            _reject_protected_range(pe, payload_offset, int(payload["size"]), strategy=strategy)
            findings.append(
                _finding(
                    "section_header_extension",
                    "high",
                    "pe_layout",
                    "section VirtualSize is extended into existing file-backed padding",
                    str(virtual_size["id"]),
                    {"section": section.name, "new_virtual_size": new_virtual_size, "new_raw_size": new_raw_size},
                )
            )
        elif strategy == "resource_replace":
            resource_data = _single_role(roles, "resource_data", strategy)
            directory = _directory(pe, "resource")
            if directory is None or not _range_inside_directory(
                directory, int(resource_data["file_offset"]), int(resource_data["size"])
            ):
                raise PatchPlanningError("resource_replace data operation is outside the resource directory")
            matching_leaves = [
                item
                for item in pe.resources
                if item.file_offset == int(resource_data["file_offset"])
            ]
            if len(matching_leaves) != 1:
                raise PatchPlanningError(
                    "resource_replace data operation must target exactly one parsed resource data leaf"
                )
            leaf = matching_leaves[0]
            _reject_relocation_overlap(
                pe, int(resource_data["file_offset"]), int(resource_data["size"]), strategy=strategy
            )
            replacement_size = _integer(
                details.get("replacement_size"), field="strategy_details.replacement_size"
            )
            allocation_size = _integer(
                details.get("allocation_size"), field="strategy_details.allocation_size"
            )
            if (
                int(resource_data["size"]) != allocation_size
                or allocation_size != leaf.size
                or replacement_size > allocation_size
            ):
                raise PatchPlanningError("resource replacement size/allocation metadata is inconsistent")
            if _integer(
                details.get("resource_offset"), field="strategy_details.resource_offset"
            ) != leaf.file_offset:
                raise PatchPlanningError("resource replacement offset differs from the parsed resource leaf")
            if _integer(
                details.get("resource_rva"), field="strategy_details.resource_rva"
            ) != leaf.rva:
                raise PatchPlanningError("resource replacement RVA differs from the parsed resource leaf")
            declared_size_field = _integer(
                details.get("size_field_offset"), field="strategy_details.size_field_offset"
            )
            if declared_size_field != leaf.size_field_offset:
                raise PatchPlanningError(
                    "resource replacement size field differs from the parsed resource data entry"
                )
            if replacement_size < allocation_size:
                size_operation = _single_role(roles, "resource_size", strategy)
                if int(size_operation["file_offset"]) != leaf.size_field_offset:
                    raise PatchPlanningError("resource size operation targets the wrong data-entry field")
                if not _range_inside_directory(directory, int(size_operation["file_offset"]), 4):
                    raise PatchPlanningError("resource size operation is outside the resource directory")
                old_size = int.from_bytes(bytes.fromhex(str(size_operation["original_hex"])), "little")
                new_size = int.from_bytes(bytes.fromhex(str(size_operation["replacement_hex"])), "little")
                if old_size != allocation_size or new_size != replacement_size:
                    raise PatchPlanningError("resource size operation values do not match allocation metadata")
            elif roles.get("resource_size"):
                raise PatchPlanningError("resource_replace has an unnecessary resource-size operation")
            findings.append(
                _finding(
                    "resource_directory_replacement",
                    "high",
                    "pe_directory",
                    "a resource payload is replaced inside its existing allocation",
                    str(resource_data["id"]),
                    {"allocation_size": allocation_size, "replacement_size": replacement_size},
                )
            )
        elif strategy == "iat_thunk_patch":
            thunk = _single_role(roles, "iat_thunk", strategy)
            pointer_size = pe.bits // 8
            if int(thunk["size"]) != pointer_size:
                raise PatchPlanningError(f"IAT operation must replace exactly {pointer_size} bytes")
            offset = int(thunk["file_offset"])
            iat = _directory(pe, "iat")
            parsed_match = any(item.file_offset == offset and item.size == pointer_size for item in pe.import_thunks)
            if not parsed_match and (iat is None or not _range_inside_directory(iat, offset, pointer_size)):
                raise PatchPlanningError("IAT operation is outside parsed import thunks and the IAT directory")
            _reject_relocation_overlap(pe, offset, pointer_size, strategy=strategy)
            warning = "IAT contents may be overwritten by the PE loader unless the selected thunk is bound/runtime-patched"
            warnings.append(warning)
            findings.append(
                _finding(
                    "iat_loader_overwrite_risk",
                    "critical",
                    "import",
                    warning,
                    str(thunk["id"]),
                    {"thunk_offset": offset, "pointer_size": pointer_size},
                )
            )
        elif strategy == "entrypoint_redirect":
            header = _single_role(roles, "address_of_entrypoint", strategy)
            if int(header["file_offset"]) != pe.entrypoint_field_offset:
                raise PatchPlanningError("entrypoint redirect does not target AddressOfEntryPoint")
            target_rva = int.from_bytes(bytes.fromhex(str(header["replacement_hex"])), "little")
            declared_rva = _integer(
                details.get("new_entrypoint_rva"), field="strategy_details.new_entrypoint_rva"
            )
            if target_rva != declared_rva or target_rva == pe.entrypoint_rva:
                raise PatchPlanningError("entrypoint redirect target is unchanged or differs from metadata")
            target_offset = _rva_to_offset(pe, target_rva, 1, file_size=len(data))
            section = _section_for_range(pe, target_offset, 1)
            if section is None or not section.executable:
                raise PatchPlanningError("entrypoint redirect target is not executable and file-backed")
            boundary_error = _instruction_boundary_error(data, pe, target_offset)
            if boundary_error:
                raise PatchPlanningError(boundary_error)
            payload_roles = roles.get("entrypoint_target_payload", [])
            declared_payload_size = _integer(
                details.get("payload_size", 0), field="strategy_details.payload_size"
            )
            if declared_payload_size:
                payload = _single_role(roles, "entrypoint_target_payload", strategy)
                if int(payload["file_offset"]) != target_offset or int(payload["size"]) != declared_payload_size:
                    raise PatchPlanningError("entrypoint target payload differs from strategy metadata")
            elif payload_roles:
                raise PatchPlanningError("entrypoint redirect has an undeclared target payload")
            findings.append(
                _finding(
                    "entrypoint_redirect",
                    "critical",
                    "control_flow",
                    "AddressOfEntryPoint is redirected to a different executable RVA",
                    str(header["id"]),
                    {"old_rva": pe.entrypoint_rva, "new_rva": target_rva},
                )
            )
        elif strategy == "overlay_preserve_patch":
            operation = _single_role(roles, "overlay_preserving_patch", strategy)
            if pe.overlay_offset is None or pe.overlay_size <= 0:
                raise PatchPlanningError("overlay_preserve_patch target has no overlay")
            offset = int(operation["file_offset"])
            if offset + int(operation["size"]) > pe.overlay_offset:
                raise PatchPlanningError("overlay-preserving operation intersects the overlay")
            expected_hash = str(details.get("overlay_sha256") or "")
            observed_hash = _sha256(data[pe.overlay_offset : pe.overlay_offset + pe.overlay_size])
            if expected_hash.casefold() != observed_hash:
                raise PatchPlanningError("overlay SHA-256 metadata does not match the target overlay")
            findings.append(
                _finding(
                    "overlay_immutability_guard",
                    "low",
                    "overlay",
                    "existing overlay offset, size, and bytes are pinned by the strategy contract",
                    str(operation["id"]),
                    {"overlay_offset": pe.overlay_offset, "overlay_size": pe.overlay_size},
                )
            )
    except (PatchPlanningError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return _dedupe(errors), _dedupe(warnings), findings


def _single_role(
    roles: Mapping[str, list[Mapping[str, Any]]],
    role: str,
    strategy: str,
) -> Mapping[str, Any]:
    matches = roles.get(role, [])
    if len(matches) != 1:
        raise PatchPlanningError(f"{strategy} requires exactly one {role!r} byte operation")
    return matches[0]


def _instruction_boundary_error(data: bytes, pe: _PeContext, offset: int) -> str | None:
    section = _section_for_range(pe, offset, 1)
    if section is None or not section.executable:
        return "entrypoint target is not in an executable section"
    try:
        import capstone  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return f"entrypoint boundary verification requires capstone: {exc}"
    decoder = _capstone_decoder_config(capstone, pe)
    if decoder is None:
        return f"entrypoint boundary verification does not support PE{pe.bits} machine 0x{pe.machine:04X}"
    section_end = min(section.raw_end, len(data))
    if section_end - section.raw_offset > 4 * 1024 * 1024:
        return "entrypoint section exceeds the bounded 4 MiB disassembly window"
    architecture, mode = decoder
    md = capstone.Cs(architecture, mode)
    base_address = pe.image_base + section.virtual_address
    boundaries = {
        section.raw_offset + (int(instruction.address) - base_address)
        for instruction in md.disasm(data[section.raw_offset:section_end], base_address)
    }
    if offset not in boundaries:
        return f"entrypoint target at file offset 0x{offset:X} is not an instruction boundary"
    return None


def _pe_layout_errors(pe: _PeContext, file_size: int) -> list[str]:
    errors: list[str] = []
    if pe.file_alignment <= 0 or pe.section_alignment <= 0:
        return ["PE FileAlignment and SectionAlignment must be positive"]
    if pe.size_of_headers > file_size:
        errors.append("SizeOfHeaders exceeds the file size")
    if pe.size_of_headers % pe.file_alignment:
        errors.append("SizeOfHeaders is not FileAlignment-aligned")
    raw_sections = sorted((item for item in pe.sections if item.raw_size), key=lambda item: item.raw_offset)
    for section in pe.sections:
        if section.raw_size:
            if section.raw_offset % pe.file_alignment:
                errors.append(f"section {section.name} PointerToRawData is not FileAlignment-aligned")
            if section.raw_size % pe.file_alignment:
                errors.append(f"section {section.name} SizeOfRawData is not FileAlignment-aligned")
            if section.raw_end > file_size:
                errors.append(f"section {section.name} raw range exceeds the file")
        if section.virtual_address % pe.section_alignment:
            errors.append(f"section {section.name} VirtualAddress is not SectionAlignment-aligned")
    for left, right in zip(raw_sections, raw_sections[1:]):
        if left.raw_end > right.raw_offset:
            errors.append(f"section {left.name} raw range overlaps section {right.name}")
    virtual_sections = sorted(pe.sections, key=lambda item: item.virtual_address)
    for left, right in zip(virtual_sections, virtual_sections[1:]):
        if left.virtual_address + max(left.virtual_size, left.raw_size) > right.virtual_address:
            errors.append(f"section {left.name} virtual range overlaps section {right.name}")
    minimum_image_size = _align_up(
        max(
            [pe.size_of_headers]
            + [item.virtual_address + max(item.virtual_size, item.raw_size) for item in pe.sections]
        ),
        pe.section_alignment,
    )
    if pe.size_of_image < minimum_image_size or pe.size_of_image % pe.section_alignment:
        errors.append(
            f"SizeOfImage 0x{pe.size_of_image:X} is smaller than/aligned differently from required 0x{minimum_image_size:X}"
        )
    if pe.section_table_offset + (len(pe.sections) * 40) > pe.size_of_headers:
        errors.append("section table extends beyond SizeOfHeaders")
    return _dedupe(errors)


def _apply_resolved_operations(data: bytes, resolved: list[Mapping[str, Any]]) -> bytes:
    simulated = bytearray(data)
    for operation in resolved:
        offset = int(operation["file_offset"])
        original = bytes.fromhex(str(operation["original_hex"]))
        replacement = bytes.fromhex(str(operation["replacement_hex"]))
        if len(original) != len(replacement):
            raise PatchPlanningError(f"{operation['id']}: planned byte replacement changes file length")
        if bytes(simulated[offset : offset + len(original)]) != original:
            raise PatchPlanningError(f"{operation['id']}: resolved preimage is not sequentially reproducible")
        simulated[offset : offset + len(replacement)] = replacement
    return bytes(simulated)


def _section_for_range(pe: _PeContext, offset: int, size: int) -> _Section | None:
    for section in pe.sections:
        if section.raw_offset <= offset and offset + size <= section.raw_end:
            return section
        if _overlaps(offset, offset + size, section.raw_offset, section.raw_end):
            raise PatchPlanningError(
                f"patch range 0x{offset:X}+{size} crosses section {section.name} raw boundary"
            )
    return None


def _rva_to_offset(pe: _PeContext, rva: int, size: int, *, file_size: int) -> int:
    if rva < 0 or size <= 0:
        raise PatchPlanningError("RVA and replacement size must be positive file-backed values")
    if rva < pe.size_of_headers:
        if rva + size > pe.size_of_headers or rva + size > file_size:
            raise PatchPlanningError(f"RVA 0x{rva:X} is outside PE headers")
        return rva
    for section in pe.sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            relative = rva - section.virtual_address
            if relative >= section.raw_size:
                raise PatchPlanningError(f"RVA 0x{rva:X} is in a section virtual-only tail")
            if relative + size > section.raw_size:
                raise PatchPlanningError(f"RVA 0x{rva:X}+{size} exceeds section {section.name} raw size")
            offset = section.raw_offset + relative
            if offset + size > file_size:
                raise PatchPlanningError(f"RVA 0x{rva:X} resolves outside the file")
            return offset
    raise PatchPlanningError(f"RVA 0x{rva:X} is not mapped by any PE section")


def _offset_to_rva(pe: _PeContext, offset: int, size: int) -> int | None:
    if offset < pe.size_of_headers and offset + size <= pe.size_of_headers:
        return offset
    for section in pe.sections:
        if section.raw_offset <= offset and offset + size <= section.raw_end:
            return section.virtual_address + (offset - section.raw_offset)
    return None


def _read_preimage(data: bytes, offset: int, size: int) -> bytes:
    if size <= 0:
        raise PatchPlanningError("replacement must contain at least one byte")
    if offset < 0 or offset + size > len(data):
        raise PatchPlanningError(f"patch range 0x{offset:X}+{size} is outside the target")
    return data[offset : offset + size]


def _parse_aob(value: str) -> list[int | None]:
    tokens = value.replace(",", " ").split()
    if not tokens:
        raise PatchPlanningError("AOB pattern must not be empty")
    pattern: list[int | None] = []
    for token in tokens:
        if token in {"?", "??", "**"}:
            pattern.append(None)
            continue
        if len(token) != 2:
            raise PatchPlanningError(f"invalid AOB token: {token!r}")
        try:
            pattern.append(int(token, 16))
        except ValueError as exc:
            raise PatchPlanningError(f"invalid AOB token: {token!r}") from exc
    return pattern


def _find_aob(data: bytes, pattern: list[int | None]) -> list[int]:
    if len(pattern) > len(data):
        return []
    return [
        offset
        for offset in range(len(data) - len(pattern) + 1)
        if all(value is None or data[offset + index] == value for index, value in enumerate(pattern))
    ]


def _format_aob(pattern: list[int | None]) -> str:
    return " ".join("??" if value is None else f"{value:02X}" for value in pattern)


def _hex_bytes(value: Any, *, field: str) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, str):
        compact = "".join(value.split())
        if compact.casefold().startswith("0x"):
            compact = compact[2:]
        try:
            result = bytes.fromhex(compact)
        except ValueError as exc:
            raise PatchPlanningError(f"{field} must be an even-length hexadecimal string") from exc
    else:
        raise PatchPlanningError(f"{field} must be a hexadecimal string")
    if not result:
        raise PatchPlanningError(f"{field} must contain at least one byte")
    return result


def _integer(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise PatchPlanningError(f"{field} must be an integer")
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise PatchPlanningError(f"{field} must be a decimal or 0x-prefixed integer") from exc
    if parsed < 0:
        raise PatchPlanningError(f"{field} must not be negative")
    return parsed


def _load_mapping(
    value: Mapping[str, Any] | str | Path,
    label: str,
) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        return dict(value), None
    source = Path(value).resolve()
    if not source.is_file():
        raise PatchPlanningError(f"{label} does not exist: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise PatchPlanningError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PatchPlanningError(f"{label} JSON must be an object")
    return dict(payload), source.parent


def _require_file(path: str | Path) -> Path:
    target = Path(path).resolve()
    if not target.is_file():
        raise PatchPlanningError(f"target file does not exist: {target}")
    return target


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _finding(
    finding_id: str,
    severity: str,
    category: str,
    message: str,
    operation_id: str,
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "message": message,
        "operation_id": operation_id,
        "evidence": dict(evidence),
    }


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in values if item))


def _ensure_distinct_paths(named_paths: Mapping[str, Path]) -> None:
    normalized = [(name, Path(path).resolve()) for name, path in named_paths.items()]
    for index, (left_name, left_path) in enumerate(normalized):
        for right_name, right_path in normalized[index + 1 :]:
            if _paths_collide(left_path, right_path):
                raise PatchPlanningError(
                    f"path collision between {left_name} and {right_name}: {left_path}"
                )


def _paths_collide(left: Path, right: Path) -> bool:
    if left == right:
        return True
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def _write_json_bundle(values: list[tuple[Path, Mapping[str, Any]]]) -> None:
    staged: list[tuple[Path, Path]] = []
    previous: dict[Path, bytes | None] = {}
    committed: list[Path] = []
    try:
        for output, payload in values:
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists() and not output.is_file():
                raise PatchPlanningError(f"artifact path is not a regular file: {output}")
            previous[output] = output.read_bytes() if output.is_file() else None
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=output.parent,
                prefix=f".{output.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(
                    (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
                )
                temporary.flush()
                os.fsync(temporary.fileno())
            staged.append((temporary_path, output))

        for temporary_path, output in staged:
            os.replace(temporary_path, output)
            committed.append(output)
    except Exception:
        for output in reversed(committed):
            try:
                original = previous.get(output)
                if original is None:
                    output.unlink(missing_ok=True)
                else:
                    _atomic_write_bytes(output, original)
            except OSError:
                pass
        raise
    finally:
        for temporary_path, _ in staged:
            temporary_path.unlink(missing_ok=True)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_write_bytes(
        path,
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _failure(tool: str, path: str | Path, exc: Exception) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=f"{type(exc).__name__}: {exc}",
        data={"status": "failed", "target": str(path), "artifacts": []},
    )
