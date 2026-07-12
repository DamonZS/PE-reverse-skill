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
from pathlib import Path
import struct
from typing import Any

from .executor import ToolResult


_OVERLAY_MAGIC = b"RAPATCH\x00"
_MAX_PLAN_BYTES = 4 * 1024 * 1024
_MAX_EMBED_PAYLOAD_BYTES = 128 * 1024 * 1024


class PatchPlanError(ValueError):
    """Raised when a patch plan cannot be validated against a target."""


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
        plan_payload, plan_dir = _load_json_mapping(plan, label="patch plan")
        original = source.read_bytes()
        source_hash = _sha256(original)
        expected_hash = _optional_text(plan_payload.get("target_sha256"))
        if expected_hash and source_hash.casefold() != expected_hash.casefold():
            raise PatchPlanError("target_sha256 does not match the supplied target")

        operations = plan_payload.get("operations")
        if not isinstance(operations, list) or not operations:
            raise PatchPlanError("patch plan must contain a non-empty operations array")

        patched = bytearray(original)
        applied_operations: list[dict[str, Any]] = []
        rollback_operations: list[dict[str, Any]] = []
        for index, operation in enumerate(operations):
            if not isinstance(operation, Mapping):
                raise PatchPlanError(f"operations[{index}] must be an object")
            applied, rollback = _apply_operation(patched, operation, index=index, plan_dir=plan_dir)
            applied_operations.append(applied)
            rollback_operations.append(rollback)

        patched_bytes = bytes(patched)
        patched_hash = _sha256(patched_bytes)
        destination_dir = Path(out_dir).resolve()
        destination = destination_dir / "patched" / (output_name or _patched_name(source))
        manifest_path = destination_dir / "patch_manifest.json"
        rollback_path = destination_dir / "rollback.json"
        manifest = {
            "status": "planned" if dry_run else "ok",
            "schema_version": 1,
            "source_path": str(source),
            "patched_path": str(destination),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "source_size": len(original),
            "patched_size": len(patched_bytes),
            "plan_schema_version": plan_payload.get("schema_version", 1),
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

        if destination.exists() and not overwrite:
            raise PatchPlanError(f"patched output already exists: {destination}; pass overwrite=True to replace it")
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(destination, patched_bytes)
        _write_json(manifest_path, manifest)
        _write_json(rollback_path, rollback_manifest)
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
        rollback_payload, _ = _load_json_mapping(rollback, label="rollback manifest")
        original = source.read_bytes()
        patched_hash = _optional_text(rollback_payload.get("patched_sha256"))
        if patched_hash and _sha256(original).casefold() != patched_hash.casefold():
            raise PatchPlanError("patched_sha256 does not match the supplied rollback target")
        operations = rollback_payload.get("operations")
        if not isinstance(operations, list):
            raise PatchPlanError("rollback manifest must contain an operations array")

        restored = bytearray(original)
        restored_operations: list[dict[str, Any]] = []
        for index, operation in enumerate(reversed(operations)):
            if not isinstance(operation, Mapping):
                raise PatchPlanError(f"rollback operations[{index}] must be an object")
            restored_operations.append(_apply_rollback_operation(restored, operation))

        restored_bytes = bytes(restored)
        restored_hash = _sha256(restored_bytes)
        expected_source_hash = _optional_text(rollback_payload.get("source_sha256"))
        if expected_source_hash and restored_hash.casefold() != expected_source_hash.casefold():
            raise PatchPlanError("rollback result hash does not match source_sha256")

        destination_dir = Path(out_dir).resolve()
        destination = destination_dir / "rolled_back" / (output_name or _rollback_name(source))
        manifest_path = destination_dir / "rollback_manifest.json"
        manifest = {
            "status": "planned" if dry_run else "ok",
            "schema_version": 1,
            "patched_path": str(source),
            "restored_path": str(destination),
            "patched_sha256": _sha256(original),
            "restored_sha256": restored_hash,
            "restored_size": len(restored_bytes),
            "operations": restored_operations,
            "dry_run": bool(dry_run),
        }
        if dry_run:
            return ToolResult(tool="binary_patch_rollback", status="planned", data={**manifest, "artifacts": []})

        if destination.exists() and not overwrite:
            raise PatchPlanError(f"rollback output already exists: {destination}; pass overwrite=True to replace it")
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(destination, restored_bytes)
        _write_json(manifest_path, manifest)
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
) -> ToolResult:
    """Apply a verified patch plan to one explicit output path.

    This is the CLI-facing adapter for :func:`binary_patch_apply`.  It retains
    the existing engine's pre-image/hash verification and rollback manifest,
    while making the destination path deterministic for automation.  The
    original input is never modified.
    """

    try:
        destination = Path(out_path).resolve()
        source = Path(path).resolve()
        if source == destination:
            raise PatchPlanError("out_path must differ from the source; in-place patching is not supported")
        plan_payload, _ = _load_json_mapping(plan, label="patch plan")
        original = source.read_bytes()
        source_hash = _sha256(original)
        expected_hash = _optional_text(plan_payload.get("target_sha256"))
        if expected_hash and source_hash.casefold() != expected_hash.casefold():
            raise PatchPlanError("target_sha256 does not match the supplied target")
        operations = plan_payload.get("operations")
        if not isinstance(operations, list) or not operations:
            raise PatchPlanError("patch plan must contain a non-empty operations array")

        patched = bytearray(original)
        applied_operations: list[dict[str, Any]] = []
        rollback_operations: list[dict[str, Any]] = []
        plan_dir = Path(plan).resolve().parent if isinstance(plan, (str, Path)) else None
        for index, operation in enumerate(operations):
            if not isinstance(operation, Mapping):
                raise PatchPlanError(f"operations[{index}] must be an object")
            applied_item, rollback_item = _apply_operation(patched, operation, index=index, plan_dir=plan_dir)
            applied_operations.append(applied_item)
            rollback_operations.append(rollback_item)

        patched_bytes = bytes(patched)
        patched_hash = _sha256(patched_bytes)
        artifact_root = Path(artifact_dir).resolve() if artifact_dir is not None else destination.parent / f"{destination.name}.patch-artifacts"
        manifest_path = artifact_root / "patch_manifest.json"
        rollback_path = artifact_root / "rollback.json"
        manifest = {
            "status": "planned" if not apply else "ok",
            "schema_version": 1,
            "source_path": str(source),
            "patched_path": str(destination),
            "source_sha256": source_hash,
            "patched_sha256": patched_hash,
            "source_size": len(original),
            "patched_size": len(patched_bytes),
            "plan_schema_version": plan_payload.get("schema_version", 1),
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

        if destination.exists():
            raise PatchPlanError(f"patched output already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        artifact_root.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(destination, patched_bytes)
        _write_json(manifest_path, manifest)
        _write_json(rollback_path, rollback_manifest)
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
        offset = _pe_rva_to_offset(bytes(data), rva)
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
    data[offset : offset + len(expected)] = replacement
    applied = {
        "id": operation_id,
        "kind": kind,
        "file_offset": f"0x{offset:X}",
        "rva": f"0x{rva:X}" if rva is not None else None,
        "size": len(expected),
        "expected_hex": expected.hex(),
        "replacement_hex": replacement.hex(),
    }
    rollback = {
        "kind": "restore_bytes",
        "id": operation_id,
        "file_offset": offset,
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
    data[offset : offset + len(pattern)] = replacement
    applied = {
        "id": operation_id,
        "kind": "replace_aob",
        "file_offset": f"0x{offset:X}",
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
        "original_hex": original.hex(),
        "patched_hex": replacement.hex(),
    }
    return applied, rollback


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
        data[offset : offset + len(patched)] = original
        return {"id": operation_id, "kind": "restore_bytes", "file_offset": f"0x{offset:X}", "size": len(original)}
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


def _pe_rva_to_offset(data: bytes, rva: int) -> int:
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
        if rva >= len(data):
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
            result = raw_offset + (rva - virtual_address)
            if result >= len(data):
                raise PatchPlanError(f"RVA 0x{rva:X} resolves outside the file")
            return result
    raise PatchPlanError(f"RVA 0x{rva:X} is not mapped by any PE section")


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


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _failure(tool: str, exc: Exception, path: str | Path) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=f"{type(exc).__name__}: {exc}",
        data={"status": "failed", "target": str(path), "artifacts": []},
    )
