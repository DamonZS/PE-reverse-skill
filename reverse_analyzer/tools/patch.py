"""Verified binary patching and inert payload embedding.

The patch engine operates on a copy of an input file.  Every byte replacement
requires a pre-image, mutations are prepared in memory before the output is
written, and a rollback manifest is emitted for every successful patch.  The
supported operations are intentionally layout-preserving except for explicit
overlay embedding:

* ``replace_bytes`` / ``replace_offset`` — replace equal-length bytes at a
  file offset after checking the expected bytes.
* ``replace_rva`` — resolve a PE RVA to a file offset, then do an equal-length
  checked replacement.
* ``replace_aob`` — locate one expected AOB pattern in the file and replace it
  with equal-length bytes.
* ``embed_overlay`` — append a self-describing payload record.  The payload is
  data only; this operation does not alter a PE entry point or make the payload
  executable.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import string
import struct
import tempfile
from typing import Any

from .executor import ToolResult


_OVERLAY_MAGIC = b"RAPATCH\x00"
_MAX_PLAN_BYTES = 4 * 1024 * 1024
_MAX_EMBED_PAYLOAD_BYTES = 128 * 1024 * 1024


class PatchPlanError(ValueError):
    """Raised when a patch plan cannot be validated against a target."""


def android_elf_patch_plan(
    path: str | Path,
    *,
    out_dir: str | Path,
    virtual_address: int | str | None = None,
    file_offset: int | str | None = None,
    replacement: str | bytes | None = None,
    instruction_mode: str = "auto",
    operation_id: str | None = None,
    intent: Mapping[str, Any] | None = None,
) -> ToolResult:
    """Expose the Android ELF planner through the common tool registry."""

    from ..patch.android_elf import plan_android_elf_patch

    return plan_android_elf_patch(
        path,
        out_dir=out_dir,
        virtual_address=virtual_address,
        file_offset=file_offset,
        replacement=replacement,
        instruction_mode=instruction_mode,
        operation_id=operation_id,
        intent=intent,
    )


def android_elf_patch_verify(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_dir: str | Path | None = None,
) -> ToolResult:
    """Expose Android ELF verification through the common tool registry."""

    from ..patch.android_elf import verify_android_elf_patch

    return verify_android_elf_patch(path, plan=plan, out_dir=out_dir)


def dll_proxy_generate(
    path: str | Path,
    *,
    copy_dir: str | Path,
    project_dir: str | Path | None = None,
    expected_architecture: str | None = None,
    proxy_name: str | None = None,
) -> ToolResult:
    """Generate a forwarding-DLL project and normalize its audit result."""

    try:
        from ..patch.dll_proxy import generate_dll_proxy_project

        project = generate_dll_proxy_project(
            path,
            copy_dir=copy_dir,
            project_dir=project_dir,
            expected_architecture=expected_architecture,
            proxy_name=proxy_name,
        )
        return ToolResult(
            tool="dll_proxy_generate",
            status="ok",
            data=project.to_dict(),
        )
    except (OSError, TypeError, ValueError) as exc:
        return ToolResult(
            tool="dll_proxy_generate",
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "artifacts": []},
        )


_PATCH_OPERATION_KINDS = {
    "replace_bytes",
    "replace_offset",
    "replace_file_offset",
    "replace_rva",
    "replace_aob",
    "replace_pattern",
    "aob_replace",
    "embed_overlay",
    "append_overlay",
}
_PE_PATCH_STRATEGIES = {
    "code_cave",
    "code_cave_patch",
    "section_extend",
    "section_extend_patch",
    "resource_replace",
    "iat_thunk",
    "iat_thunk_patch",
    "entrypoint_redirect",
    "overlay_preserve",
    "overlay_preserve_patch",
}
_PE_OPERATION_ROLES = {
    "code_cave_payload",
    "section_extension_payload",
    "section_virtual_size",
    "section_raw_size",
    "size_of_image",
    "resource_data",
    "resource_size",
    "iat_thunk",
    "entrypoint_target_payload",
    "address_of_entrypoint",
    "overlay_preserving_patch",
}


def _validate_patch_plan_engine(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
) -> ToolResult:
    """Run the generic byte-patch validator without PE policy dispatch.

    Validation checks the plan schema, target hash, operation parameters and
    pre-images.  Payload files are opened/read for overlay operations, but the
    target and filesystem are never modified.
    """

    try:
        source = _require_file(path)
        plan_payload, plan_dir = _load_json_mapping(plan, label="patch plan")
        original = source.read_bytes()
        operations, schema_version = _validate_patch_plan_schema(plan_payload, source_hash=_sha256(original))

        simulated = bytearray(original)
        applied_operations: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            applied, _ = _apply_operation(simulated, operation, index=index, plan_dir=plan_dir)
            applied_operations.append(applied)

        return ToolResult(
            tool="validate_patch_plan",
            status="ok",
            data={
                "status": "ok",
                "valid": True,
                "schema_version": schema_version,
                "strategy": str(plan_payload.get("strategy") or "inline_patch"),
                "target_path": str(source),
                "target_sha256": _sha256(original),
                "planned_sha256": _sha256(bytes(simulated)),
                "operation_count": len(applied_operations),
                "operations": applied_operations,
                "dry_run": True,
                "artifacts": [],
            },
        )
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return ToolResult(
            tool="validate_patch_plan",
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "valid": False, "target": str(path), "artifacts": []},
        )


def validate_patch_plan(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
) -> ToolResult:
    """Validate a patch plan, including PE policy when the plan requires it."""

    engine_result = _validate_patch_plan_engine(path, plan=plan)
    if engine_result.status != "ok":
        return engine_result
    try:
        plan_payload, _ = _load_json_mapping(plan, label="patch plan")
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return ToolResult(
            tool="validate_patch_plan",
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "valid": False, "target": str(path), "artifacts": []},
        )
    if not _requires_pe_patch_validation(plan_payload):
        return engine_result
    return _merge_pe_validation_result(
        tool="validate_patch_plan",
        target=path,
        plan=plan_payload,
        engine_result=engine_result,
    )


def _requires_pe_patch_validation(plan: Mapping[str, Any]) -> bool:
    planner = plan.get("planner")
    if isinstance(planner, Mapping) and str(planner.get("name") or "").casefold() == "pe_aware_patch_planner":
        return True
    if isinstance(plan.get("strategy_details"), Mapping):
        return True
    strategy = str(plan.get("strategy") or "").strip().casefold().replace("-", "_")
    if strategy in _PE_PATCH_STRATEGIES:
        return True
    operations = plan.get("operations")
    if not isinstance(operations, list):
        return False
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        kind = str(operation.get("kind") or operation.get("type") or "").casefold()
        role = str(operation.get("role") or "").casefold()
        if kind == "replace_rva" or role in _PE_OPERATION_ROLES:
            return True
    return False


def _merge_pe_validation_result(
    *,
    tool: str,
    target: str | Path,
    plan: Mapping[str, Any],
    engine_result: ToolResult,
) -> ToolResult:
    try:
        from reverse_analyzer.patch.planner import validate_pe_patch_plan

        pe_result = validate_pe_patch_plan(target, plan=plan)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool=tool,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            data={"status": "failed", "valid": False, "target": str(target), "artifacts": []},
        )
    engine_data = dict(engine_result.data) if isinstance(engine_result.data, Mapping) else {}
    pe_data = dict(pe_result.data) if isinstance(pe_result.data, Mapping) else {}
    status = str(pe_result.status or "failed")
    return ToolResult(
        tool=tool,
        status=status,
        error=pe_result.error,
        data={
            **engine_data,
            "status": status,
            "valid": status == "ok" and bool(pe_data.get("valid", True)),
            "pe_verification": pe_data,
            "artifacts": [],
        },
    )


def _validate_pe_before_apply(
    *,
    tool: str,
    target: str | Path,
    plan: Mapping[str, Any],
) -> ToolResult | None:
    if not _requires_pe_patch_validation(plan):
        return None
    generic = ToolResult(tool=tool, status="ok", data={"status": "ok", "valid": True, "artifacts": []})
    result = _merge_pe_validation_result(
        tool=tool,
        target=target,
        plan=plan,
        engine_result=generic,
    )
    return None if result.status == "ok" else result


def binary_patch_apply(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_dir: str | Path,
    output_name: str | None = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> ToolResult:
    """Apply a verified patch plan to a copy of ``path``.

    The original target is never overwritten.  On success the output directory
    receives a patched binary, ``patch_manifest.json``, and ``rollback.json``.
    ``dry_run`` performs every validation and computes the resulting hash but
    writes no artifacts.
    """

    try:
        source = _require_file(path)
        plan_input = _mapping_input_path(plan)
        plan_payload, plan_dir = _load_json_mapping(plan, label="patch plan")
        original = source.read_bytes()
        source_hash = _sha256(original)
        operations, schema_version = _validate_patch_plan_schema(plan_payload, source_hash=source_hash)

        patched = bytearray(original)
        applied_operations: list[dict[str, Any]] = []
        rollback_operations: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            applied, rollback = _apply_operation(patched, operation, index=index, plan_dir=plan_dir)
            applied_operations.append(applied)
            rollback_operations.append(rollback)

        pe_validation = _validate_pe_before_apply(
            tool="binary_patch_apply",
            target=source,
            plan=plan_payload,
        )
        if pe_validation is not None:
            return pe_validation

        patched_bytes = bytes(patched)
        patched_hash = _sha256(patched_bytes)
        destination_dir = Path(out_dir).resolve()
        destination = destination_dir / "patched" / (output_name or _patched_name(source))
        manifest_path = destination_dir / "patch_manifest.json"
        rollback_path = destination_dir / "rollback.json"
        named_paths = {
            "source": source,
            "patched_output": destination,
            "patch_manifest": manifest_path,
            "rollback_manifest": rollback_path,
        }
        if plan_input is not None:
            named_paths["plan_input"] = plan_input
        _ensure_distinct_paths(named_paths)
        manifest = {
            "status": "planned" if dry_run else "ok",
            "schema_version": 1,
            "strategy": str(plan_payload.get("strategy") or "inline_patch"),
            "source_path": str(source),
            "patched_path": str(destination),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "source_size": len(original),
            "patched_size": len(patched_bytes),
            "plan_schema_version": schema_version,
            "operations": applied_operations,
            "rollback_path": str(rollback_path),
            "dry_run": bool(dry_run),
        }
        rollback_manifest = {
            "schema_version": 1,
            "source_path": str(source),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "operations": rollback_operations,
        }
        if dry_run:
            return ToolResult(tool="binary_patch_apply", status="planned", data={**manifest, "artifacts": []})

        _publish_file_bundle(
            [
                (destination, patched_bytes),
                (manifest_path, _json_bytes(manifest)),
                (rollback_path, _json_bytes(rollback_manifest)),
            ],
            overwrite=overwrite,
        )
        return ToolResult(
            tool="binary_patch_apply",
            status="ok",
            data={
                **manifest,
                "artifacts": [
                    {"name": destination.name, "path": str(destination), "kind": "patched-binary"},
                    {"name": "patch_manifest.json", "path": str(manifest_path), "kind": "patch-manifest"},
                    {"name": "rollback.json", "path": str(rollback_path), "kind": "patch-rollback"},
                ],
            },
        )
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return _failure("binary_patch_apply", exc, path)


def binary_patch_rollback(
    path: str | Path,
    *,
    rollback: Mapping[str, Any] | str | Path,
    out_dir: str | Path,
    output_name: str | None = None,
    overwrite: bool = False,
    dry_run: bool = False,
) -> ToolResult:
    """Create a restored copy of a patched file from its rollback manifest."""

    try:
        source = _require_file(path)
        rollback_input = _mapping_input_path(rollback)
        rollback_payload, _ = _load_json_mapping(rollback, label="rollback manifest")
        original = source.read_bytes()
        restored_bytes, restored_operations, expected_source_hash = _restore_rollback_bytes(
            rollback_payload,
            patched_bytes=original,
        )
        restored_hash = _sha256(restored_bytes)

        destination_dir = Path(out_dir).resolve()
        destination = destination_dir / "rolled_back" / (output_name or _rollback_name(source))
        manifest_path = destination_dir / "rollback_manifest.json"
        named_paths = {
            "patched_input": source,
            "restored_output": destination,
            "rollback_manifest": manifest_path,
        }
        if rollback_input is not None:
            named_paths["rollback_input"] = rollback_input
        _ensure_distinct_paths(named_paths)
        manifest = {
            "status": "planned" if dry_run else "ok",
            "schema_version": 1,
            "patched_path": str(source),
            "restored_path": str(destination),
            "patched_sha256": _sha256(original),
            "source_sha256": expected_source_hash,
            "restored_sha256": restored_hash,
            "restored_size": len(restored_bytes),
            "operations": restored_operations,
            "dry_run": bool(dry_run),
        }
        if dry_run:
            return ToolResult(tool="binary_patch_rollback", status="planned", data={**manifest, "artifacts": []})

        _publish_file_bundle(
            [
                (destination, restored_bytes),
                (manifest_path, _json_bytes(manifest)),
            ],
            overwrite=overwrite,
        )
        return ToolResult(
            tool="binary_patch_rollback",
            status="ok",
            data={
                **manifest,
                "artifacts": [
                    {"name": destination.name, "path": str(destination), "kind": "restored-binary"},
                    {"name": "rollback_manifest.json", "path": str(manifest_path), "kind": "patch-rollback-manifest"},
                ],
            },
        )
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return _failure("binary_patch_rollback", exc, path)


def binary_patch_apply_plan(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_path: str | Path,
    apply: bool = False,
    artifact_dir: str | Path | None = None,
    plan_source_path: str | Path | None = None,
) -> ToolResult:
    """Apply a verified patch plan to one explicit output path.

    This is the CLI-facing adapter for :func:`binary_patch_apply`.  It retains
    the existing engine's pre-image/hash verification and rollback manifest,
    while making the destination path deterministic for automation.  The
    original input is never modified.
    """

    try:
        destination = Path(out_path).resolve()
        source = _require_file(path)
        plan_input = Path(plan_source_path).resolve() if plan_source_path is not None else _mapping_input_path(plan)
        plan_payload, plan_dir = _load_json_mapping(plan, label="patch plan")
        original = source.read_bytes()
        source_hash = _sha256(original)
        operations, schema_version = _validate_patch_plan_schema(plan_payload, source_hash=source_hash)

        patched = bytearray(original)
        applied_operations: list[dict[str, Any]] = []
        rollback_operations: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            applied_item, rollback_item = _apply_operation(patched, operation, index=index, plan_dir=plan_dir)
            applied_operations.append(applied_item)
            rollback_operations.append(rollback_item)

        pe_validation = _validate_pe_before_apply(
            tool="binary_patch_apply",
            target=source,
            plan=plan_payload,
        )
        if pe_validation is not None:
            return pe_validation

        patched_bytes = bytes(patched)
        patched_hash = _sha256(patched_bytes)
        artifact_root = Path(artifact_dir).resolve() if artifact_dir is not None else destination.parent / f"{destination.name}.patch-artifacts"
        manifest_path = artifact_root / "patch_manifest.json"
        rollback_path = artifact_root / "rollback.json"
        named_paths = {
            "source": source,
            "patched_output": destination,
            "patch_manifest": manifest_path,
            "rollback_manifest": rollback_path,
        }
        if plan_input is not None:
            named_paths["plan_input"] = plan_input
        _ensure_distinct_paths(named_paths)
        manifest = {
            "status": "planned" if not apply else "ok",
            "schema_version": 1,
            "strategy": str(plan_payload.get("strategy") or "inline_patch"),
            "source_path": str(source),
            "patched_path": str(destination),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "source_size": len(original),
            "patched_size": len(patched_bytes),
            "plan_schema_version": schema_version,
            "operations": applied_operations,
            "rollback_path": str(rollback_path),
            "dry_run": not apply,
        }
        rollback_manifest = {
            "schema_version": 1,
            "source_path": str(source),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "operations": rollback_operations,
        }
        if not apply:
            return ToolResult(tool="binary_patch_apply", status="planned", data={**manifest, "artifacts": []})

        _publish_file_bundle(
            [
                (destination, patched_bytes),
                (manifest_path, _json_bytes(manifest)),
                (rollback_path, _json_bytes(rollback_manifest)),
            ],
            overwrite=False,
        )
        return ToolResult(
            tool="binary_patch_apply",
            status="ok",
            data={
                **manifest,
                "artifacts": [
                    {"name": destination.name, "path": str(destination), "kind": "patched-binary"},
                    {"name": "patch_manifest.json", "path": str(manifest_path), "kind": "patch-manifest"},
                    {"name": "rollback.json", "path": str(rollback_path), "kind": "patch-rollback"},
                ],
            },
        )
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return _failure("binary_patch_apply", exc, path)


def binary_patch_rollback_plan(
    path: str | Path,
    *,
    rollback: Mapping[str, Any] | str | Path,
    out_path: str | Path,
    apply: bool = False,
    artifact_dir: str | Path | None = None,
) -> ToolResult:
    """Restore a patched file to an explicit new output path.

    This CLI-facing adapter reuses :func:`binary_patch_rollback`, defaults to a
    dry-run, and rejects in-place restoration.
    """

    try:
        source = _require_file(path)
        destination = Path(out_path).resolve()
        rollback_input = _mapping_input_path(rollback)
        rollback_payload, _ = _load_json_mapping(rollback, label="rollback manifest")
        original = source.read_bytes()
        restored_bytes, restored_operations, expected_source_hash = _restore_rollback_bytes(
            rollback_payload,
            patched_bytes=original,
        )
        restored_hash = _sha256(restored_bytes)
        artifact_root = Path(artifact_dir).resolve() if artifact_dir is not None else destination.parent / f"{destination.name}.rollback-artifacts"
        manifest_path = artifact_root / "rollback_manifest.json"
        named_paths = {
            "patched_input": source,
            "restored_output": destination,
            "rollback_manifest": manifest_path,
        }
        if rollback_input is not None:
            named_paths["rollback_input"] = rollback_input
        _ensure_distinct_paths(named_paths)
        manifest = {
            "status": "ok" if apply else "planned",
            "schema_version": 1,
            "patched_path": str(source),
            "restored_path": str(destination),
            "patched_sha256": _sha256(original),
            "source_sha256": expected_source_hash,
            "restored_sha256": restored_hash,
            "restored_size": len(restored_bytes),
            "operations": restored_operations,
            "dry_run": not apply,
        }
        if not apply:
            return ToolResult(tool="binary_patch_rollback", status="planned", data={**manifest, "artifacts": []})
        _publish_file_bundle(
            [
                (destination, restored_bytes),
                (manifest_path, _json_bytes(manifest)),
            ],
            overwrite=False,
        )
        return ToolResult(
            tool="binary_patch_rollback",
            status="ok",
            data={
                **manifest,
                "artifacts": [
                    {"name": destination.name, "path": str(destination), "kind": "restored-binary"},
                    {"name": "rollback_manifest.json", "path": str(manifest_path), "kind": "patch-rollback-manifest"},
                ],
            },
        )
    except (OSError, PatchPlanError, TypeError, ValueError) as exc:
        return _failure("binary_patch_rollback", exc, path)


def _apply_operation(
    data: bytearray,
    operation: Mapping[str, Any],
    *,
    index: int,
    plan_dir: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    kind = str(operation.get("kind") or operation.get("type") or "").casefold()
    operation_id = _optional_text(operation.get("id") or operation.get("name")) or f"operation-{index + 1}"
    if kind in {"replace_bytes", "replace_offset", "replace_file_offset"}:
        offset = _nonnegative_int(operation.get("offset"), field=f"{operation_id}.offset")
        return _replace_at_offset(data, operation, operation_id=operation_id, kind="replace_bytes", offset=offset)
    if kind == "replace_rva":
        rva = _nonnegative_int(operation.get("rva"), field=f"{operation_id}.rva")
        expected = _hex_bytes(operation.get("expected"), field=f"{operation_id}.expected")
        offset = _pe_rva_to_offset(bytes(data), rva, size=len(expected))
        return _replace_at_offset(data, operation, operation_id=operation_id, kind="replace_rva", offset=offset, rva=rva)
    if kind in {"replace_aob", "replace_pattern", "aob_replace"}:
        return _replace_aob(data, operation, operation_id=operation_id)
    if kind in {"embed_overlay", "append_overlay"}:
        return _embed_overlay(data, operation, operation_id=operation_id, plan_dir=plan_dir)
    raise PatchPlanError(f"{operation_id}: unsupported operation kind {kind!r}")


def _replace_at_offset(
    data: bytearray,
    operation: Mapping[str, Any],
    *,
    operation_id: str,
    kind: str,
    offset: int,
    rva: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = _hex_bytes(operation.get("expected"), field=f"{operation_id}.expected")
    replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
    if len(expected) != len(replacement):
        raise PatchPlanError(f"{operation_id}: replacement length must equal expected length to preserve file layout")
    _require_range(data, offset, len(expected), operation_id)
    observed = bytes(data[offset : offset + len(expected)])
    if observed != expected:
        raise PatchPlanError(
            f"{operation_id}: expected bytes do not match at file offset 0x{offset:X}; observed={observed.hex()}"
        )
    resolved_rva = rva if rva is not None else _pe_offset_to_rva(bytes(data), offset, size=len(expected))
    data[offset : offset + len(expected)] = replacement
    applied = {
        "id": operation_id,
        "kind": kind,
        "file_offset": f"0x{offset:X}",
        "file_offset_value": offset,
        "rva": f"0x{resolved_rva:X}" if resolved_rva is not None else None,
        "rva_value": resolved_rva,
        "size": len(expected),
        "expected_hex": expected.hex(),
        "replacement_hex": replacement.hex(),
    }
    rollback = {
        "kind": "restore_bytes",
        "id": operation_id,
        "file_offset": offset,
        "rva": resolved_rva,
        "original_hex": expected.hex(),
        "patched_hex": replacement.hex(),
    }
    return applied, rollback


def _replace_aob(data: bytearray, operation: Mapping[str, Any], *, operation_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    pattern = _aob_pattern(operation.get("pattern"), field=f"{operation_id}.pattern")
    replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
    if len(pattern) != len(replacement):
        raise PatchPlanError(f"{operation_id}: replacement length must equal AOB pattern length")
    matches = _find_aob_matches(bytes(data), pattern)
    expected_count = _positive_int(operation.get("expected_match_count"), default=1, field=f"{operation_id}.expected_match_count")
    if len(matches) != expected_count:
        raise PatchPlanError(f"{operation_id}: expected {expected_count} AOB matches, found {len(matches)}")
    occurrence = _nonnegative_int(operation.get("occurrence"), field=f"{operation_id}.occurrence", default=0)
    if occurrence >= len(matches):
        raise PatchPlanError(f"{operation_id}: occurrence {occurrence} is outside {len(matches)} AOB matches")
    offset = matches[occurrence]
    original = bytes(data[offset : offset + len(pattern)])
    pinned_preimage = _aob_expected_preimage(operation, operation_id=operation_id)
    if pinned_preimage is not None:
        if len(pinned_preimage) != len(pattern):
            raise PatchPlanError(f"{operation_id}: expected AOB pre-image length must equal pattern length")
        if original != pinned_preimage:
            raise PatchPlanError(
                f"{operation_id}: resolved AOB pre-image does not match expected bytes at file offset 0x{offset:X}"
            )
    rva = _pe_offset_to_rva(bytes(data), offset, size=len(pattern))
    data[offset : offset + len(pattern)] = replacement
    applied = {
        "id": operation_id,
        "kind": "replace_aob",
        "file_offset": f"0x{offset:X}",
        "file_offset_value": offset,
        "rva": f"0x{rva:X}" if rva is not None else None,
        "rva_value": rva,
        "pattern": _format_aob(pattern),
        "match_count": len(matches),
        "occurrence": occurrence,
        "size": len(pattern),
        "expected_hex": original.hex(),
        "replacement_hex": replacement.hex(),
    }
    rollback = {
        "kind": "restore_bytes",
        "id": operation_id,
        "file_offset": offset,
        "rva": rva,
        "original_hex": original.hex(),
        "patched_hex": replacement.hex(),
    }
    return applied, rollback


def _aob_expected_preimage(
    operation: Mapping[str, Any],
    *,
    operation_id: str,
) -> bytes | None:
    values = [
        (field, operation.get(field))
        for field in ("expected", "resolved_preimage")
        if operation.get(field) is not None
    ]
    if not values:
        return None
    parsed = [
        (field, _hex_bytes(value, field=f"{operation_id}.{field}"))
        for field, value in values
    ]
    if any(value != parsed[0][1] for _, value in parsed[1:]):
        raise PatchPlanError(f"{operation_id}: expected and resolved_preimage must describe the same bytes")
    return parsed[0][1]


def _embed_overlay(
    data: bytearray,
    operation: Mapping[str, Any],
    *,
    operation_id: str,
    plan_dir: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload, payload_name = _overlay_payload(operation, plan_dir=plan_dir, operation_id=operation_id)
    if len(payload) > _MAX_EMBED_PAYLOAD_BYTES:
        raise PatchPlanError(f"{operation_id}: payload exceeds {_MAX_EMBED_PAYLOAD_BYTES} byte limit")
    marker = _optional_text(operation.get("marker")) or "embedded-payload"
    metadata = {
        "schema_version": 1,
        "operation_id": operation_id,
        "marker": marker,
        "payload_name": payload_name,
        "payload_sha256": _sha256(payload),
        "payload_size": len(payload),
    }
    metadata_bytes = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    record = _OVERLAY_MAGIC + struct.pack("<II", len(metadata_bytes), len(payload)) + metadata_bytes + payload
    offset = len(data)
    data.extend(record)
    applied = {
        "id": operation_id,
        "kind": "embed_overlay",
        "file_offset": f"0x{offset:X}",
        "marker": marker,
        "payload_name": payload_name,
        "payload_sha256": metadata["payload_sha256"],
        "payload_size": len(payload),
        "record_size": len(record),
        "executable": False,
    }
    rollback = {
        "kind": "truncate",
        "id": operation_id,
        "size_before": offset,
        "size_after": len(data),
        "payload_sha256": metadata["payload_sha256"],
    }
    return applied, rollback


def _apply_rollback_operation(data: bytearray, operation: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(operation.get("kind") or "").casefold()
    operation_id = _optional_text(operation.get("id")) or "operation"
    if kind == "restore_bytes":
        offset = _nonnegative_int(operation.get("file_offset"), field=f"{operation_id}.file_offset")
        original = _hex_bytes(operation.get("original_hex"), field=f"{operation_id}.original_hex")
        patched = _hex_bytes(operation.get("patched_hex"), field=f"{operation_id}.patched_hex")
        if len(original) != len(patched):
            raise PatchPlanError(f"{operation_id}: rollback byte lengths differ")
        _require_range(data, offset, len(patched), operation_id)
        observed = bytes(data[offset : offset + len(patched)])
        if observed != patched:
            raise PatchPlanError(f"{operation_id}: rollback pre-image mismatch at file offset 0x{offset:X}")
        declared_rva = operation.get("rva")
        rva = (
            _nonnegative_int(declared_rva, field=f"{operation_id}.rva")
            if declared_rva is not None
            else _pe_offset_to_rva(bytes(data), offset, size=len(patched))
        )
        data[offset : offset + len(patched)] = original
        return {
            "id": operation_id,
            "kind": "restore_bytes",
            "file_offset": f"0x{offset:X}",
            "file_offset_value": offset,
            "rva": f"0x{rva:X}" if rva is not None else None,
            "rva_value": rva,
            "size": len(original),
        }
    if kind == "truncate":
        before = _nonnegative_int(operation.get("size_before"), field=f"{operation_id}.size_before")
        after = _nonnegative_int(operation.get("size_after"), field=f"{operation_id}.size_after")
        if len(data) != after:
            raise PatchPlanError(f"{operation_id}: rollback expects file size {after}, found {len(data)}")
        del data[before:]
        return {"id": operation_id, "kind": "truncate", "size_before": before, "size_after": after}
    raise PatchPlanError(f"{operation_id}: unsupported rollback operation {kind!r}")


def _overlay_payload(operation: Mapping[str, Any], *, plan_dir: Path | None, operation_id: str) -> tuple[bytes, str]:
    if operation.get("payload_hex") is not None:
        return _hex_bytes(operation.get("payload_hex"), field=f"{operation_id}.payload_hex"), "inline-hex"
    source_value = operation.get("payload_file") or operation.get("payload_path")
    if not source_value:
        raise PatchPlanError(f"{operation_id}: embed_overlay requires payload_file or payload_hex")
    payload_path = Path(str(source_value))
    if not payload_path.is_absolute() and plan_dir is not None:
        payload_path = plan_dir / payload_path
    payload_path = payload_path.resolve()
    if not payload_path.is_file():
        raise PatchPlanError(f"{operation_id}: payload file does not exist: {payload_path}")
    if payload_path.stat().st_size > _MAX_EMBED_PAYLOAD_BYTES:
        raise PatchPlanError(f"{operation_id}: payload exceeds {_MAX_EMBED_PAYLOAD_BYTES} byte limit")
    return payload_path.read_bytes(), payload_path.name


def _aob_pattern(value: Any, *, field: str) -> list[int | None]:
    if not isinstance(value, str):
        raise PatchPlanError(f"{field} must be a string")
    tokens = value.replace(",", " ").split()
    if not tokens:
        raise PatchPlanError(f"{field} must not be empty")
    pattern: list[int | None] = []
    for token in tokens:
        if token in {"?", "??"}:
            pattern.append(None)
            continue
        if len(token) != 2:
            raise PatchPlanError(f"{field} contains invalid token {token!r}")
        try:
            pattern.append(int(token, 16))
        except ValueError as exc:
            raise PatchPlanError(f"{field} contains invalid token {token!r}") from exc
    return pattern


def _find_aob_matches(data: bytes, pattern: list[int | None]) -> list[int]:
    if len(pattern) > len(data):
        return []
    matches: list[int] = []
    for offset in range(0, len(data) - len(pattern) + 1):
        if all(expected is None or data[offset + index] == expected for index, expected in enumerate(pattern)):
            matches.append(offset)
    return matches


def _format_aob(pattern: list[int | None]) -> str:
    return " ".join("??" if value is None else f"{value:02X}" for value in pattern)


def _pe_rva_to_offset(data: bytes, rva: int, *, size: int) -> int:
    """Map a replacement range from PE RVA to file offset.

    PE section virtual sizes can exceed their on-disk raw sizes.  Those
    virtual-only bytes do not have a file-backed pre-image and must never be
    treated as patchable simply because another byte range happens to follow
    them in the file (for example, an overlay or the next section).
    """

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PatchPlanError("replace_rva requires a valid PE file beginning with MZ")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise PatchPlanError("replace_rva requires a valid PE signature")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    if section_table + section_count * 40 > len(data):
        raise PatchPlanError("PE section table is truncated")
    first_raw = min(
        (struct.unpack_from("<I", data, section_table + index * 40 + 20)[0] for index in range(section_count)),
        default=0,
    )
    if rva < first_raw:
        if rva + size > first_raw or rva + size > len(data):
            raise PatchPlanError(f"RVA 0x{rva:X} is outside PE headers")
        return rva
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size = struct.unpack_from("<I", data, entry + 8)[0]
        virtual_address = struct.unpack_from("<I", data, entry + 12)[0]
        raw_size = struct.unpack_from("<I", data, entry + 16)[0]
        raw_offset = struct.unpack_from("<I", data, entry + 20)[0]
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            section_offset = rva - virtual_address
            if section_offset >= raw_size:
                raise PatchPlanError(f"RVA 0x{rva:X} is in a section virtual-only tail")
            if size > raw_size - section_offset:
                raise PatchPlanError(
                    f"RVA replacement at 0x{rva:X} exceeds the section raw_size"
                )
            result = raw_offset + section_offset
            if result + size > len(data):
                raise PatchPlanError(f"RVA 0x{rva:X} resolves outside the file")
            return result
    raise PatchPlanError(f"RVA 0x{rva:X} is not mapped by any PE section")


def _pe_offset_to_rva(data: bytes, offset: int, *, size: int) -> int | None:
    """Best-effort inverse mapping used only to enrich operation manifests."""

    if offset < 0 or size <= 0 or offset + size > len(data):
        return None
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        section_table = pe_offset + 24 + optional_size
        if section_table + section_count * 40 > len(data):
            return None
        raw_offsets = [
            struct.unpack_from("<I", data, section_table + index * 40 + 20)[0]
            for index in range(section_count)
            if struct.unpack_from("<I", data, section_table + index * 40 + 16)[0] > 0
        ]
        first_raw = min(raw_offsets, default=len(data))
        if offset < first_raw and offset + size <= first_raw:
            return offset
        for index in range(section_count):
            entry = section_table + index * 40
            virtual_address = struct.unpack_from("<I", data, entry + 12)[0]
            raw_size = struct.unpack_from("<I", data, entry + 16)[0]
            raw_offset = struct.unpack_from("<I", data, entry + 20)[0]
            if raw_offset <= offset and offset + size <= raw_offset + raw_size:
                return virtual_address + (offset - raw_offset)
    except (IndexError, struct.error, ValueError):
        return None
    return None


def _load_json_mapping(value: Mapping[str, Any] | str | Path, *, label: str) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}, None
    input_path = Path(value).resolve()
    if not input_path.is_file():
        raise PatchPlanError(f"{label} does not exist: {input_path}")
    if input_path.stat().st_size > _MAX_PLAN_BYTES:
        raise PatchPlanError(f"{label} exceeds {_MAX_PLAN_BYTES} byte limit")
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PatchPlanError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PatchPlanError(f"{label} JSON must be an object")
    return {str(key): item for key, item in payload.items()}, input_path.parent


def _validate_patch_plan_schema(
    plan: Mapping[str, Any],
    *,
    source_hash: str,
) -> tuple[list[dict[str, Any]], int]:
    """Validate the serializable plan shape before execution/simulation."""

    unknown_required = plan.get("schema_version", 1)
    if isinstance(unknown_required, bool) or not isinstance(unknown_required, int) or unknown_required != 1:
        raise PatchPlanError("patch plan schema_version must be the supported integer 1")
    target_hash = plan.get("target_sha256")
    if not isinstance(target_hash, str) or len(target_hash) != 64 or any(
        char not in string.hexdigits for char in target_hash
    ):
        raise PatchPlanError(
            "target_sha256 is required and must be a 64-character hexadecimal SHA-256 digest"
        )
    if target_hash.casefold() != source_hash.casefold():
        raise PatchPlanError("target_sha256 does not match the supplied target")
    operations_value = plan.get("operations")
    if not isinstance(operations_value, list) or not operations_value:
        raise PatchPlanError("patch plan must contain a non-empty operations array")

    operations: list[dict[str, Any]] = []
    for index, operation in enumerate(operations_value):
        if not isinstance(operation, Mapping):
            raise PatchPlanError(f"operations[{index}] must be an object")
        normalized = {str(key): value for key, value in operation.items()}
        _validate_operation_schema(normalized, index=index)
        operations.append(normalized)
    return operations, unknown_required


def _validate_operation_schema(operation: Mapping[str, Any], *, index: int) -> None:
    operation_id = _optional_text(operation.get("id") or operation.get("name")) or f"operation-{index + 1}"
    kind_value = operation.get("kind", operation.get("type"))
    if not isinstance(kind_value, str) or not kind_value.strip():
        raise PatchPlanError(f"{operation_id}: operation kind must be a non-empty string")
    kind = kind_value.casefold()
    if kind not in _PATCH_OPERATION_KINDS:
        raise PatchPlanError(f"{operation_id}: unsupported operation kind {kind_value!r}")

    if kind in {"replace_bytes", "replace_offset", "replace_file_offset"}:
        _nonnegative_int(operation.get("offset"), field=f"{operation_id}.offset")
        expected = _hex_bytes(operation.get("expected"), field=f"{operation_id}.expected")
        replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
        if len(expected) != len(replacement):
            raise PatchPlanError(f"{operation_id}: replacement length must equal expected length to preserve file layout")
        return
    if kind == "replace_rva":
        _nonnegative_int(operation.get("rva"), field=f"{operation_id}.rva")
        expected = _hex_bytes(operation.get("expected"), field=f"{operation_id}.expected")
        replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
        if len(expected) != len(replacement):
            raise PatchPlanError(f"{operation_id}: replacement length must equal expected length to preserve file layout")
        return
    if kind in {"replace_aob", "replace_pattern", "aob_replace"}:
        pattern = _aob_pattern(operation.get("pattern"), field=f"{operation_id}.pattern")
        replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
        if len(pattern) != len(replacement):
            raise PatchPlanError(f"{operation_id}: replacement length must equal AOB pattern length")
        pinned_preimage = _aob_expected_preimage(operation, operation_id=operation_id)
        if pinned_preimage is not None and len(pinned_preimage) != len(pattern):
            raise PatchPlanError(f"{operation_id}: expected AOB pre-image length must equal pattern length")
        _positive_int(operation.get("expected_match_count"), default=1, field=f"{operation_id}.expected_match_count")
        _nonnegative_int(operation.get("occurrence"), default=0, field=f"{operation_id}.occurrence")
        return
    if operation.get("payload_hex") is not None:
        _hex_bytes(operation.get("payload_hex"), field=f"{operation_id}.payload_hex")
        return
    payload_file = operation.get("payload_file") or operation.get("payload_path")
    if not isinstance(payload_file, str) or not payload_file.strip():
        raise PatchPlanError(f"{operation_id}: embed_overlay requires payload_file or payload_hex")


def _validate_rollback_manifest(rollback: Mapping[str, Any], *, patched_bytes: bytes) -> None:
    schema_version = rollback.get("schema_version", 1)
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        raise PatchPlanError("rollback manifest schema_version must be the supported integer 1")
    patched_hash = rollback.get("patched_sha256")
    if not isinstance(patched_hash, str) or len(patched_hash) != 64 or any(char not in string.hexdigits for char in patched_hash):
        raise PatchPlanError("rollback manifest patched_sha256 must be a 64-character hexadecimal SHA-256 digest")
    if _sha256(patched_bytes).casefold() != patched_hash.casefold():
        raise PatchPlanError("patched_sha256 does not match the supplied rollback target")
    source_hash = rollback.get("source_sha256")
    if not isinstance(source_hash, str) or len(source_hash) != 64 or any(char not in string.hexdigits for char in source_hash):
        raise PatchPlanError("rollback manifest source_sha256 must be a 64-character hexadecimal SHA-256 digest")
    operations = rollback.get("operations")
    if not isinstance(operations, list):
        raise PatchPlanError("rollback manifest must contain an operations array")
    for index, operation in enumerate(operations):
        if not isinstance(operation, Mapping):
            raise PatchPlanError(f"rollback operations[{index}] must be an object")


def _restore_rollback_bytes(
    rollback: Mapping[str, Any],
    *,
    patched_bytes: bytes,
) -> tuple[bytes, list[dict[str, Any]], str]:
    """Apply and verify a rollback manifest entirely in memory.

    The returned bytes are safe to commit only after their digest matches the
    manifest's required source digest.  Keeping this check here ensures both
    public rollback entry points validate before creating any output artifact.
    """

    _validate_rollback_manifest(rollback, patched_bytes=patched_bytes)
    restored = bytearray(patched_bytes)
    restored_operations = [
        _apply_rollback_operation(restored, operation)
        for operation in reversed(rollback["operations"])
    ]
    restored_bytes = bytes(restored)
    expected_source_hash = str(rollback["source_sha256"])
    if _sha256(restored_bytes).casefold() != expected_source_hash.casefold():
        raise PatchPlanError("rollback result hash does not match source_sha256")
    return restored_bytes, restored_operations, expected_source_hash


def _hex_bytes(value: Any, *, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise PatchPlanError(f"{field} must be a hexadecimal string")
    compact = "".join(value.split())
    if compact.startswith("0x"):
        compact = compact[2:]
    if not compact or len(compact) % 2:
        raise PatchPlanError(f"{field} must contain an even number of hexadecimal characters")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise PatchPlanError(f"{field} must be hexadecimal") from exc


def _nonnegative_int(value: Any, *, field: str, default: int | None = None) -> int:
    if value is None and default is not None:
        return default
    if isinstance(value, bool):
        raise PatchPlanError(f"{field} must be an integer")
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise PatchPlanError(f"{field} must be a decimal or 0x-prefixed integer") from exc
    if parsed < 0:
        raise PatchPlanError(f"{field} must not be negative")
    return parsed


def _positive_int(value: Any, *, default: int, field: str) -> int:
    parsed = _nonnegative_int(value, field=field, default=default)
    if parsed <= 0:
        raise PatchPlanError(f"{field} must be positive")
    return parsed


def _require_range(data: bytearray, offset: int, size: int, operation_id: str) -> None:
    if not size or offset + size > len(data):
        raise PatchPlanError(f"{operation_id}: file range 0x{offset:X}+{size} is outside the target")


def _require_file(path: str | Path) -> Path:
    source = Path(path).resolve()
    if not source.is_file():
        raise PatchPlanError(f"target file does not exist: {source}")
    return source


def _optional_text(value: Any) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple, set, frozenset)):
        return None
    text = str(value).strip()
    return text or None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _patched_name(source: Path) -> str:
    return f"{source.stem}.patched{source.suffix}" if source.suffix else f"{source.name}.patched"


def _rollback_name(source: Path) -> str:
    return f"{source.stem}.restored{source.suffix}" if source.suffix else f"{source.name}.restored"


def _mapping_input_path(value: Mapping[str, Any] | str | Path) -> Path | None:
    if isinstance(value, Mapping):
        return None
    return Path(value).expanduser().resolve()


def _ensure_distinct_paths(named_paths: Mapping[str, Path]) -> None:
    normalized = [
        (str(name), Path(path).expanduser().resolve())
        for name, path in named_paths.items()
    ]
    for index, (left_name, left_path) in enumerate(normalized):
        for right_name, right_path in normalized[index + 1 :]:
            same_resolved_path = os.path.normcase(str(left_path)) == os.path.normcase(str(right_path))
            same_existing_file = False
            if not same_resolved_path and left_path.exists() and right_path.exists():
                try:
                    same_existing_file = os.path.samefile(left_path, right_path)
                except OSError:
                    same_existing_file = False
            if same_resolved_path or same_existing_file:
                raise PatchPlanError(
                    f"path collision between {left_name} and {right_name}: {left_path}"
                )


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _publish_file_bundle(
    values: list[tuple[Path, bytes]],
    *,
    overwrite: bool,
) -> None:
    """Publish a related set of files with rollback on partial failure."""

    if not values:
        return

    normalized: list[tuple[Path, bytes]] = []
    for output, payload in values:
        destination = Path(output).expanduser().resolve()
        if not isinstance(payload, bytes):
            raise TypeError(f"artifact payload for {destination} must be bytes")
        normalized.append((destination, payload))

    _ensure_distinct_paths(
        {f"bundle_output[{index}]": output for index, (output, _) in enumerate(normalized)}
    )
    for output, _ in normalized:
        if output.exists() and not output.is_file():
            raise PatchPlanError(f"artifact path is not a regular file: {output}")
        if output.exists() and not overwrite:
            raise PatchPlanError(f"artifact already exists: {output}")

    staged: list[tuple[Path, Path, bytes]] = []
    backups: dict[Path, Path] = {}
    committed: list[Path] = []
    try:
        for output, payload in normalized:
            output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=output.parent,
                prefix=f".{output.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
            staged.append((temporary_path, output, payload))

        if overwrite:
            for _, output, _ in staged:
                if not output.exists():
                    continue
                backup = _unused_temporary_path(output, suffix=".bak")
                os.replace(output, backup)
                backups[output] = backup
                _fsync_directory(output.parent)
        else:
            for _, output, _ in staged:
                if output.exists():
                    raise PatchPlanError(f"artifact already exists: {output}")

        for temporary_path, output, payload in staged:
            if overwrite:
                os.replace(temporary_path, output)
            else:
                _publish_staged_without_overwrite(temporary_path, output, payload)
            committed.append(output)
            _fsync_directory(output.parent)
    except Exception as exc:
        restore_errors: list[str] = []
        for output in reversed(committed):
            try:
                output.unlink(missing_ok=True)
            except OSError as restore_exc:
                restore_errors.append(f"remove {output}: {restore_exc}")
        for output, backup in backups.items():
            try:
                os.replace(backup, output)
                _fsync_directory(output.parent)
            except OSError as restore_exc:
                restore_errors.append(f"restore {output}: {restore_exc}")
        if restore_errors:
            raise PatchPlanError(
                f"artifact bundle publish failed ({exc}); rollback incomplete: {'; '.join(restore_errors)}"
            ) from exc
        raise
    finally:
        for temporary_path, _, _ in staged:
            temporary_path.unlink(missing_ok=True)
        for backup in backups.values():
            backup.unlink(missing_ok=True)


def _unused_temporary_path(output: Path, *, suffix: str) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=suffix,
    )
    os.close(descriptor)
    temporary_path = Path(raw_path)
    temporary_path.unlink()
    return temporary_path


def _publish_staged_without_overwrite(staged: Path, output: Path, payload: bytes) -> None:
    try:
        os.link(staged, output)
    except FileExistsError as exc:
        raise PatchPlanError(f"artifact already exists: {output}") from exc
    except OSError:
        descriptor: int | None = None
        try:
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError as exc:
            raise PatchPlanError(f"artifact already exists: {output}") from exc
        except Exception:
            output.unlink(missing_ok=True)
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
    else:
        staged.unlink()


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
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
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_write_bytes(path, _json_bytes(value))


def _failure(tool: str, exc: Exception, path: str | Path) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=f"{type(exc).__name__}: {exc}",
        data={"status": "failed", "target": str(path), "artifacts": []},
    )
