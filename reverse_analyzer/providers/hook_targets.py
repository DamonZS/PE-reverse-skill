"""Deterministic resolution of common native hook targets.

The resolver is intentionally read-only.  It turns module/export, module/RVA,
byte-pattern, and vtable evidence into an address plus an executable-range
proof that can be consumed by runtime hook providers.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import struct
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from reverse_analyzer.patch.dll_proxy import (
    DllProxyGenerationError,
    parse_pe_exports,
)


_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
_MAX_MODULE_SIZE = 1 << 31
_MAX_PATTERN_BYTES = 4096
_MAX_LIVE_MODULES = 4096
_MAX_PATH_CHARS = 32768
_MAX_FORWARDER_DEPTH = 8
_MAX_IMPORT_MODULES = 4096
_MAX_IMPORT_SYMBOLS = 65536
_MAX_IMPORT_NAME_BYTES = 4096
_PAGE_EXECUTE_MASK = 0xF0
_PAGE_GUARD = 0x100
_PAGE_NOACCESS = 0x01
_MEM_COMMIT = 0x1000
_MEM_IMAGE = 0x1000000
_LIST_MODULES_ALL = 0x03
_BENIGN_SYSTEM_MODULES = frozenset(
    {
        "advapi32.dll",
        "combase.dll",
        "d3d11.dll",
        "d3d9.dll",
        "dxgi.dll",
        "gdi32.dll",
        "kernel32.dll",
        "kernelbase.dll",
        "mswsock.dll",
        "ntdll.dll",
        "ole32.dll",
        "opengl32.dll",
        "user32.dll",
        "ws2_32.dll",
    }
)
_PINNED_SYSTEM_MODULE_HANDLES: dict[str, int] = {}
_PINNED_SYSTEM_MODULES_LOCK = threading.Lock()
_WIN32_BINDINGS: Any = None
_WIN32_BINDINGS_LOCK = threading.Lock()
_COMMON_TARGETS: dict[str, dict[str, Any]] = {
    "winsock_send": {
        "method": "module_export",
        "module": "ws2_32.dll",
        "export": "send",
        "api": "winsock",
    },
    "winsock_recv": {
        "method": "module_export",
        "module": "ws2_32.dll",
        "export": "recv",
        "api": "winsock",
    },
    "opengl_swap_buffers": {
        "method": "module_export",
        "module": "opengl32.dll",
        "export": "wglSwapBuffers",
        "api": "opengl",
    },
    "gdi_swap_buffers": {
        "method": "module_export",
        "module": "gdi32.dll",
        "export": "SwapBuffers",
        "api": "opengl",
    },
    "vulkan_present": {
        "method": "module_export",
        "module": "vulkan-1.dll",
        "export": "vkQueuePresentKHR",
        "api": "vulkan",
    },
    "dxgi_present": {
        "method": "vtable_slot",
        "vtable_index": 8,
        "api": "direct3d",
        "interface": "IDXGISwapChain",
        "symbol": "Present",
        "dependencies": ["dxgi.dll"],
    },
    "d3d11_present": {
        "method": "vtable_slot",
        "vtable_index": 8,
        "api": "direct3d11",
        "interface": "IDXGISwapChain",
        "symbol": "Present",
        "dependencies": ["dxgi.dll", "d3d11.dll"],
    },
    "dxgi_present1": {
        "method": "vtable_slot",
        "vtable_index": 22,
        "api": "direct3d",
        "interface": "IDXGISwapChain1",
        "symbol": "Present1",
    },
    "d3d9_present": {
        "method": "vtable_slot",
        "vtable_index": 17,
        "api": "direct3d9",
        "interface": "IDirect3DDevice9",
        "symbol": "Present",
    },
    "d3d9_end_scene": {
        "method": "vtable_slot",
        "vtable_index": 42,
        "api": "direct3d9",
        "interface": "IDirect3DDevice9",
        "symbol": "EndScene",
    },
}


class HookTargetResolutionError(ValueError):
    """Raised when a hook target specification is malformed."""


@dataclass(frozen=True)
class PESectionEvidence:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def virtual_extent(self) -> int:
        return max(self.virtual_size, self.raw_size)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)

    def contains_rva(self, rva: int, size: int = 1) -> bool:
        return (
            size > 0
            and self.virtual_address <= rva
            and rva + size <= self.virtual_address + self.virtual_extent
        )

    def file_offset(self, rva: int, size: int = 1) -> int | None:
        if not self.contains_rva(rva, size):
            return None
        relative = rva - self.virtual_address
        if relative + size > self.raw_size:
            return None
        return self.raw_offset + relative


@dataclass(frozen=True)
class PEHookModule:
    path: Path
    architecture: str
    image_base: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[PESectionEvidence, ...]
    sha256: str
    file_size: int
    machine: int
    pe_timestamp: int
    checksum: int
    dll_characteristics: int

    def section_for_rva(self, rva: int, size: int = 1) -> PESectionEvidence | None:
        matches = [item for item in self.sections if item.contains_rva(rva, size)]
        if len(matches) > 1:
            raise HookTargetResolutionError(f"RVA 0x{rva:x} maps to multiple PE sections")
        return matches[0] if matches else None

    @property
    def dynamic_base(self) -> bool:
        return bool(
            self.dll_characteristics & _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        )


@dataclass(frozen=True)
class LoadedHookModule:
    """One module mapped into the current process by the Windows loader."""

    name: str
    path: Path
    base: int
    size_of_image: int
    entry_point: int | None

    @property
    def end(self) -> int:
        return self.base + self.size_of_image

    def contains(self, address: int, size: int = 1) -> bool:
        return (
            size > 0
            and self.base <= address
            and address + size <= self.end
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "base": self.base,
            "base_hex": f"0x{self.base:x}",
            "size_of_image": self.size_of_image,
            "end": self.end,
            "end_hex": f"0x{self.end:x}",
            "entry_point": self.entry_point,
            "entry_point_hex": (
                f"0x{self.entry_point:x}"
                if self.entry_point is not None
                else None
            ),
        }


@dataclass(frozen=True)
class PEImportEvidence:
    imported_module: str
    iat_rva: int
    lookup_rva: int
    index: int
    pointer_size: int
    descriptor_timestamp: int
    symbol: str | None = None
    ordinal: int | None = None
    hint: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "imported_module": self.imported_module,
            "iat_rva": self.iat_rva,
            "iat_rva_hex": f"0x{self.iat_rva:x}",
            "lookup_rva": self.lookup_rva,
            "lookup_rva_hex": f"0x{self.lookup_rva:x}",
            "index": self.index,
            "pointer_size": self.pointer_size,
            "descriptor_timestamp": self.descriptor_timestamp,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "hint": self.hint,
        }


@dataclass
class HookTargetResolution:
    status: str
    method: str
    target: str | None = None
    api: str | None = None
    module: str | None = None
    symbol: str | None = None
    address: int | None = None
    rva: int | None = None
    slot_address: int | None = None
    source: dict[str, Any] = field(default_factory=dict)
    executable_range: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    ambiguity: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)
    evidence_plan: dict[str, Any] = field(default_factory=dict)
    production_ready: bool = False
    evidence_tier: str = "offline"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.address is not None and not self.errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "status": self.status,
            "method": self.method,
            "target": self.target,
            "api": self.api,
            "module": self.module,
            "symbol": self.symbol,
            "address": self.address,
            "address_hex": f"0x{self.address:x}" if self.address is not None else None,
            "rva": self.rva,
            "rva_hex": f"0x{self.rva:x}" if self.rva is not None else None,
            "slot_address": self.slot_address,
            "slot_address_hex": (
                f"0x{self.slot_address:x}" if self.slot_address is not None else None
            ),
            "source": dict(self.source),
            "executable_range": dict(self.executable_range),
            "confidence": self.confidence,
            "ambiguity": dict(self.ambiguity),
            "provenance": dict(self.provenance),
            "evidence_plan": dict(self.evidence_plan),
            "production_ready": self.production_ready,
            "evidence_tier": self.evidence_tier,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


def common_hook_targets() -> dict[str, dict[str, Any]]:
    """Return a detached copy of the built-in target catalogue."""

    return json.loads(json.dumps(_COMMON_TARGETS, sort_keys=True))


def live_hook_target_capability() -> dict[str, Any]:
    """Describe whether real current-process hook evidence is available."""

    if os.name != "nt" or sys.platform != "win32":
        return {
            "status": "unavailable",
            "platform": sys.platform,
            "production_ready": False,
            "reason": "live hook target resolution requires Windows",
        }
    try:
        _win32()
        architecture = _current_process_architecture()
    except (HookTargetResolutionError, OSError) as exc:
        return {
            "status": "unavailable",
            "platform": sys.platform,
            "production_ready": False,
            "reason": str(exc),
        }
    return {
        "status": "available",
        "platform": sys.platform,
        "pid": os.getpid(),
        "architecture": architecture,
        "pointer_size": struct.calcsize("P"),
        "production_ready": True,
        "backend": "win32-current-process",
        "injected_backend": False,
    }


def enumerate_current_process_modules() -> tuple[LoadedHookModule, ...]:
    """Enumerate modules mapped by the Windows loader in this process."""

    if os.name != "nt" or sys.platform != "win32":
        raise HookTargetResolutionError(
            "current-process module enumeration is unavailable outside Windows"
        )
    return _enumerate_windows_modules()


def resolve_live_common_hook_target(
    specification: str | Mapping[str, Any],
    *,
    load_if_missing: bool = False,
) -> HookTargetResolution:
    """Resolve a target against real modules and memory in this process.

    This path deliberately has no injectable backend.  Only observations made
    through the Windows loader and current-process memory APIs can set
    ``production_ready``.
    """

    if isinstance(specification, str):
        raw_spec: Mapping[str, Any] = {"target": specification}
    elif isinstance(specification, Mapping):
        raw_spec = specification
    else:
        raise HookTargetResolutionError(
            "live hook target specification must be a target name or object"
        )
    spec, target, alias_error = _expanded_specification(raw_spec)
    method = str(spec.get("method") or "").strip().casefold().replace("-", "_")
    provenance = _live_provenance()
    if alias_error:
        return _live_failed("catalogue", target, alias_error, provenance=provenance)
    requested_load = spec.get("load_if_missing")
    if requested_load is not None and not isinstance(requested_load, bool):
        return _live_failed(
            method or "unknown",
            target,
            "load_if_missing must be a boolean",
            provenance=provenance,
        )
    should_load = load_if_missing or requested_load is True
    if os.name != "nt" or sys.platform != "win32":
        return HookTargetResolution(
            status="unavailable",
            method=method or "unknown",
            target=target,
            api=_optional_text(spec.get("api")),
            provenance=provenance,
            production_ready=False,
            evidence_tier="unavailable",
            warnings=["live hook target resolution requires Windows"],
        )
    try:
        modules = list(enumerate_current_process_modules())
    except (HookTargetResolutionError, OSError) as exc:
        result = _live_failed(
            method or "unknown",
            target,
            str(exc),
            provenance=provenance,
        )
        result.status = "unavailable"
        result.evidence_tier = "unavailable"
        return result
    if method in {"export", "module_export"}:
        return _resolve_live_export(
            spec,
            target=target,
            modules=modules,
            load_if_missing=should_load,
            provenance=provenance,
        )
    if method in {"iat", "iat_slot", "import_thunk"}:
        return _resolve_live_iat(
            spec,
            target=target,
            modules=modules,
            load_if_missing=should_load,
            provenance=provenance,
        )
    if method in {"vtable", "vtable_slot", "com_vtable"}:
        return _resolve_live_vtable(
            spec,
            target=target,
            modules=modules,
            provenance=provenance,
        )
    if method in {"rva", "module_rva", "pattern", "aob", "signature"}:
        return _resolve_live_disk_target(
            spec,
            target=target,
            modules=modules,
            load_if_missing=should_load,
            provenance=provenance,
        )
    return _live_failed(
        method or "unknown",
        target,
        "unsupported live hook target resolution method",
        provenance=provenance,
    )


def plan_live_common_hook_target(
    specification: str | Mapping[str, Any],
) -> HookTargetResolution:
    """Build an explicit dependency-gated plan for a live vtable target."""

    if isinstance(specification, str):
        raw_spec: Mapping[str, Any] = {"target": specification}
    elif isinstance(specification, Mapping):
        raw_spec = specification
    else:
        raise HookTargetResolutionError(
            "live hook target plan requires a target name or object"
        )
    spec, target, alias_error = _expanded_specification(raw_spec)
    method = str(spec.get("method") or "").strip().casefold().replace("-", "_")
    provenance = _live_provenance()
    if alias_error:
        return _live_failed("catalogue", target, alias_error, provenance=provenance)
    if method not in {"vtable", "vtable_slot", "com_vtable"}:
        return _live_failed(
            method or "unknown",
            target,
            "a dependency plan is only defined for live vtable targets",
            provenance=provenance,
        )
    modules: Sequence[LoadedHookModule] = ()
    if os.name == "nt" and sys.platform == "win32":
        try:
            modules = enumerate_current_process_modules()
        except (HookTargetResolutionError, OSError):
            modules = ()
    return _vtable_dependency_plan(
        spec,
        target=target,
        modules=modules,
        provenance=provenance,
    )


def inspect_hook_module(path: str | os.PathLike[str]) -> PEHookModule:
    """Read the bounded PE layout needed to prove executable addresses."""

    module_path = Path(path).expanduser().resolve()
    if not module_path.is_file():
        raise HookTargetResolutionError(f"module is not a regular file: {module_path}")
    file_size = module_path.stat().st_size
    if file_size <= 0 or file_size > _MAX_MODULE_SIZE:
        raise HookTargetResolutionError("module size is outside the supported range")
    data = module_path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise HookTargetResolutionError("module does not contain a valid DOS header")
    pe_offset = _u32(data, 0x3C, "DOS e_lfanew")
    if pe_offset < 0x40 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise HookTargetResolutionError("module does not contain a valid PE signature")
    coff = pe_offset + 4
    machine = _u16(data, coff, "COFF machine")
    pe_timestamp = _u32(data, coff + 4, "COFF timestamp")
    section_count = _u16(data, coff + 2, "COFF section count")
    optional_size = _u16(data, coff + 16, "COFF optional-header size")
    if section_count <= 0 or section_count > 96:
        raise HookTargetResolutionError("PE section count is outside the supported range")
    optional = coff + 20
    if optional + optional_size > len(data):
        raise HookTargetResolutionError("PE optional header exceeds the file")
    magic = _u16(data, optional, "optional-header magic")
    if magic == 0x10B:
        architecture = _machine_architecture(machine, bits=32)
        image_base = _u32(data, optional + 28, "PE32 image base")
    elif magic == 0x20B:
        architecture = _machine_architecture(machine, bits=64)
        image_base = _u64(data, optional + 24, "PE32+ image base")
    else:
        raise HookTargetResolutionError(f"unsupported PE optional-header magic 0x{magic:04x}")
    size_of_image = _u32(data, optional + 56, "SizeOfImage")
    size_of_headers = _u32(data, optional + 60, "SizeOfHeaders")
    checksum = _u32(data, optional + 64, "PE checksum")
    dll_characteristics = _u16(
        data,
        optional + 70,
        "PE DLL characteristics",
    )
    if size_of_image <= 0 or size_of_image > _MAX_MODULE_SIZE:
        raise HookTargetResolutionError("PE SizeOfImage is outside the supported range")
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise HookTargetResolutionError("PE section table exceeds the file")
    sections: list[PESectionEvidence] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section-{index}"
        virtual_size = _u32(data, offset + 8, f"section {index} virtual size")
        virtual_address = _u32(data, offset + 12, f"section {index} RVA")
        raw_size = _u32(data, offset + 16, f"section {index} raw size")
        raw_offset = _u32(data, offset + 20, f"section {index} raw offset")
        characteristics = _u32(data, offset + 36, f"section {index} characteristics")
        if raw_size and (raw_offset >= len(data) or raw_offset + raw_size > len(data)):
            raise HookTargetResolutionError(f"section {name} raw data exceeds the file")
        if virtual_address + max(virtual_size, raw_size) > size_of_image:
            raise HookTargetResolutionError(f"section {name} exceeds SizeOfImage")
        sections.append(
            PESectionEvidence(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )
    _reject_overlapping_sections(sections)
    return PEHookModule(
        path=module_path,
        architecture=architecture,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        sections=tuple(sections),
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
        machine=machine,
        pe_timestamp=pe_timestamp,
        checksum=checksum,
        dll_characteristics=dll_characteristics,
    )


def resolve_common_hook_target(
    specification: Mapping[str, Any],
    *,
    modules: Sequence[Mapping[str, Any]] = (),
) -> HookTargetResolution:
    """Resolve one target and retain all ambiguity and provenance evidence."""

    if not isinstance(specification, Mapping):
        raise HookTargetResolutionError("hook target specification must be an object")
    spec = dict(specification)
    mode = str(spec.get("mode") or "").strip().casefold()
    if spec.get("live") is True or spec.get("current_process") is True or mode == "live":
        return resolve_live_common_hook_target(
            spec,
            load_if_missing=spec.get("load_if_missing") is True,
        )
    target = _optional_text(spec.get("target") or spec.get("name"))
    if target:
        alias = _COMMON_TARGETS.get(target.casefold())
        if alias is None:
            return _failed("catalogue", target, f"unknown common hook target: {target}")
        spec = {**alias, **spec}
    method = str(spec.get("method") or "").strip().casefold().replace("-", "_")
    if method in {"export", "module_export"}:
        return _resolve_export(spec, target=target, modules=modules)
    if method in {"rva", "module_rva"}:
        return _resolve_rva(spec, target=target)
    if method in {"iat", "iat_slot", "import_thunk"}:
        return _resolve_iat(spec, target=target)
    if method in {"pattern", "aob", "signature"}:
        return _resolve_pattern(spec, target=target)
    if method in {"vtable", "vtable_slot", "com_vtable"}:
        return _resolve_vtable(spec, target=target, modules=modules)
    return _failed(method or "unknown", target, "unsupported hook target resolution method")


def write_hook_target_resolution(
    resolution: HookTargetResolution | Mapping[str, Any],
    out_dir: str | os.PathLike[str],
) -> Path:
    """Persist a resolution as the standard hook-target evidence artifact."""

    root = Path(out_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    destination = (root / "hook-targets" / "resolution.json").resolve()
    if root != destination and root not in destination.parents:
        raise HookTargetResolutionError("resolution artifact escapes the output directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = resolution.to_dict() if isinstance(resolution, HookTargetResolution) else dict(resolution)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, destination)
    return destination


def _resolve_live_export(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: list[LoadedHookModule],
    load_if_missing: bool,
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    requested_name, candidates, selection_error = _live_module_candidates(
        spec,
        modules,
    )
    loaded_by_resolver = _system_module_is_resolver_pinned(requested_name)
    if not candidates and selection_error is None and load_if_missing:
        try:
            loaded_by_resolver = _pin_benign_system_module(requested_name)
            modules[:] = enumerate_current_process_modules()
            _, candidates, selection_error = _live_module_candidates(spec, modules)
        except (HookTargetResolutionError, OSError) as exc:
            selection_error = str(exc)
    live_provenance = {
        **provenance,
        "requested_module": requested_name,
        "loaded_by_resolver": loaded_by_resolver,
    }
    if selection_error:
        return _live_failed(
            "module_export",
            target,
            selection_error,
            provenance=live_provenance,
        )
    if len(candidates) != 1:
        status = "ambiguous" if len(candidates) > 1 else "unavailable"
        result = _live_failed(
            "module_export",
            target,
            f"loaded module {requested_name} resolved to {len(candidates)} candidates",
            provenance=live_provenance,
        )
        result.status = status
        result.evidence_tier = "live-unavailable" if not candidates else "live-ambiguous"
        result.ambiguity = {
            "ambiguous": len(candidates) > 1,
            "candidate_count": len(candidates),
            "candidates": [item.to_dict() for item in candidates],
            "scope": "current_process_modules",
        }
        return result
    source_loaded = candidates[0]
    try:
        source_pe, source_identity = _loaded_module_identity(source_loaded)
        table = parse_pe_exports(
            source_loaded.path,
            expected_architecture=source_pe.architecture,
        )
        symbol = _optional_text(spec.get("export", spec.get("symbol")))
        ordinal = (
            _strict_int(spec.get("ordinal"), minimum=1, maximum=0xFFFF)
            if spec.get("ordinal") is not None
            else None
        )
    except (
        HookTargetResolutionError,
        DllProxyGenerationError,
        OSError,
        TypeError,
    ) as exc:
        return _live_failed(
            "module_export",
            target,
            str(exc),
            provenance=live_provenance,
        )
    if source_identity.get("status") != "ok":
        result = _live_failed(
            "module_export",
            target,
            str(source_identity.get("reason") or "loaded PE identity did not match"),
            provenance=live_provenance,
        )
        result.source = {"source_module_identity": source_identity}
        return result
    if symbol is None and ordinal is None:
        return _live_failed(
            "module_export",
            target,
            "module_export requires export or ordinal",
            provenance=live_provenance,
        )
    exports = [
        item
        for item in table.exports
        if (symbol is not None and item.name == symbol)
        or (ordinal is not None and item.ordinal == ordinal)
    ]
    if len(exports) != 1:
        label = symbol if symbol is not None else f"#{ordinal}"
        result = _live_failed(
            "module_export",
            target,
            f"export {label} resolved to {len(exports)} entries",
            provenance=live_provenance,
        )
        result.status = "ambiguous" if len(exports) > 1 else "failed"
        result.ambiguity = {
            "ambiguous": len(exports) > 1,
            "candidate_count": len(exports),
            "candidates": [item.to_dict() for item in exports],
            "scope": "pe_export_table",
        }
        return result
    export = exports[0]
    try:
        address = _windows_get_proc_address(
            source_loaded.base,
            symbol=export.name,
            ordinal=export.ordinal if export.name is None else None,
        )
        # A forwarded GetProcAddress can cause the loader to map its host DLL.
        modules[:] = enumerate_current_process_modules()
        proof, owner, owner_identity, owner_ambiguity = _live_address_proof(
            address,
            modules,
        )
    except (HookTargetResolutionError, OSError) as exc:
        return _live_failed(
            "module_export",
            target,
            str(exc),
            provenance=live_provenance,
        )
    if owner is None or proof.get("status") != "ok":
        result = _live_failed(
            "module_export",
            target,
            str(proof.get("reason") or "loader address lacks executable proof"),
            provenance=live_provenance,
        )
        result.address = address
        result.executable_range = proof
        result.ambiguity = owner_ambiguity
        result.source = {
            "source_module_identity": source_identity,
            "resolved_module_identity": owner_identity,
        }
        if owner_ambiguity.get("ambiguous"):
            result.status = "ambiguous"
        return result

    forwarder_chain: list[dict[str, Any]] = []
    resolved_symbol = export.name or f"#{export.ordinal}"
    trace_error: str | None = None
    trace_ambiguity: dict[str, Any] = {}
    if export.forwarder:
        forwarder_chain.append(
            {
                "module": source_loaded.name,
                "path": str(source_loaded.path),
                "export": export.name,
                "ordinal": export.ordinal,
                "forwarder": export.forwarder,
                "sha256": source_pe.sha256,
                "loaded_base": source_loaded.base,
            }
        )
        (
            traced,
            traced_symbol,
            trace_error,
            trace_ambiguity,
        ) = _trace_live_forwarder(
            export.forwarder,
            modules=modules,
            resolved_address=address,
            depth=1,
            seen={(source_loaded.name.casefold(), resolved_symbol.casefold())},
        )
        forwarder_chain.extend(traced)
        if traced_symbol:
            resolved_symbol = traced_symbol
    else:
        expected_address = source_loaded.base + export.target_rva
        if address != expected_address:
            trace_error = (
                "GetProcAddress disagrees with loaded_base + export RVA: "
                f"0x{address:x} != 0x{expected_address:x}"
            )
    if trace_error:
        result = _live_failed(
            "module_export",
            target,
            trace_error,
            provenance=live_provenance,
        )
        result.address = address
        result.executable_range = proof
        result.ambiguity = trace_ambiguity or owner_ambiguity
        result.source = {
            "source_module_identity": source_identity,
            "resolved_module_identity": owner_identity,
            "forwarder_chain": forwarder_chain,
        }
        if result.ambiguity.get("ambiguous"):
            result.status = "ambiguous"
        return result

    resolved_rva = address - owner.base
    source = {
        "kind": "live_pe_export",
        "path": str(owner.path),
        "sha256": owner_identity["file_sha256"],
        "architecture": owner_identity["architecture"],
        "module_base": owner.base,
        "ordinal": export.ordinal,
        "forwarder": export.forwarder,
        "requested_export": {
            "module": source_loaded.name,
            "name": export.name,
            "ordinal": export.ordinal,
            "target_rva": export.target_rva,
            "forwarder": export.forwarder,
        },
        "source_module_identity": source_identity,
        "resolved_module_identity": owner_identity,
        "loader_resolution": {
            "api": "GetProcAddress",
            "module_handle": source_loaded.base,
            "resolved_address": address,
            "owner_module": owner.name,
            "owner_rva": resolved_rva,
        },
        "aslr_address_proof": proof.get("aslr_address_proof", {}),
    }
    if forwarder_chain:
        source["forwarder_chain"] = forwarder_chain
    return HookTargetResolution(
        status="ok",
        method="module_export",
        target=target,
        api=_optional_text(spec.get("api")),
        module=owner.name,
        symbol=resolved_symbol,
        address=address,
        rva=resolved_rva,
        source=source,
        executable_range=proof,
        confidence=1.0,
        ambiguity={
            "ambiguous": False,
            "candidate_count": 1,
            "source_module_candidate_count": 1,
            "address_owner_candidate_count": 1,
        },
        provenance={
            **live_provenance,
            "forwarded_export": export.forwarder is not None,
            "evidence_sources": [
                "EnumProcessModulesEx",
                "GetModuleInformation",
                "GetProcAddress",
                "ReadProcessMemory",
                "VirtualQuery",
                "on_disk_pe_sha256",
            ],
        },
        production_ready=True,
        evidence_tier="live-production",
    )


def _resolve_live_iat(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: list[LoadedHookModule],
    load_if_missing: bool,
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    requested_name, candidates, selection_error = _live_module_candidates(spec, modules)
    loaded_by_resolver = _system_module_is_resolver_pinned(requested_name)
    if not candidates and selection_error is None and load_if_missing:
        try:
            loaded_by_resolver = _pin_benign_system_module(requested_name)
            modules[:] = enumerate_current_process_modules()
            _, candidates, selection_error = _live_module_candidates(spec, modules)
        except (HookTargetResolutionError, OSError) as exc:
            selection_error = str(exc)
    live_provenance = {
        **provenance,
        "requested_module": requested_name,
        "loaded_by_resolver": loaded_by_resolver,
    }
    if selection_error:
        return _live_failed("iat_slot", target, selection_error, provenance=live_provenance)
    if len(candidates) != 1:
        result = _live_failed(
            "iat_slot",
            target,
            f"loaded module {requested_name} resolved to {len(candidates)} candidates",
            provenance=live_provenance,
        )
        result.status = "ambiguous" if len(candidates) > 1 else "unavailable"
        result.evidence_tier = "live-ambiguous" if candidates else "live-unavailable"
        result.ambiguity = {
            "ambiguous": len(candidates) > 1,
            "candidate_count": len(candidates),
            "candidates": [item.to_dict() for item in candidates],
            "scope": "current_process_modules",
        }
        return result

    loaded = candidates[0]
    resolution = _resolve_iat(
        {
            **spec,
            "module": loaded.name,
            "module_path": str(loaded.path),
            "module_base": loaded.base,
        },
        target=target,
    )
    resolution.provenance = dict(live_provenance)
    resolution.production_ready = False
    resolution.evidence_tier = "live-address-proof"
    if not resolution.ok or resolution.slot_address is None:
        return resolution
    pointer_size = int(resolution.source.get("pointer_size") or 0)
    if pointer_size != struct.calcsize("P"):
        resolution.status = "failed"
        resolution.errors.append("IAT pointer size does not match the current process")
        return resolution
    try:
        observed_target = _read_current_process_pointer(
            resolution.slot_address,
            pointer_size,
        )
    except (HookTargetResolutionError, OSError) as exc:
        resolution.status = "failed"
        resolution.errors.append(str(exc))
        return resolution
    if observed_target <= 0:
        resolution.status = "failed"
        resolution.errors.append("live IAT slot contains a null target pointer")
        return resolution
    proof, owner, identity, ambiguity = _live_address_proof(observed_target, modules)
    resolution.source.update(
        {
            "kind": "live_pe_iat_slot",
            "observed_target_address": observed_target,
            "observed_target_address_hex": f"0x{observed_target:x}",
            "target_module_identity": identity,
        }
    )
    resolution.executable_range = proof
    resolution.ambiguity = ambiguity
    if owner is None or proof.get("status") != "ok":
        resolution.status = "ambiguous" if ambiguity.get("ambiguous") else "failed"
        resolution.errors.append(
            str(proof.get("reason") or "live IAT target lacks executable module proof")
        )
        return resolution
    resolution.provenance.update(
        {
            "evidence_sources": [
                "EnumProcessModulesEx",
                "GetModuleInformation",
                "ReadProcessMemory",
                "VirtualQuery",
                "on_disk_pe_import_directory",
                "on_disk_pe_sha256",
            ]
        }
    )
    resolution.production_ready = True
    resolution.evidence_tier = "live-production"
    resolution.warnings = []
    return resolution


def _resolve_live_disk_target(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: list[LoadedHookModule],
    load_if_missing: bool,
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    requested_name, candidates, selection_error = _live_module_candidates(
        spec,
        modules,
    )
    loaded_by_resolver = _system_module_is_resolver_pinned(requested_name)
    if not candidates and selection_error is None and load_if_missing:
        try:
            loaded_by_resolver = _pin_benign_system_module(requested_name)
            modules[:] = enumerate_current_process_modules()
            _, candidates, selection_error = _live_module_candidates(spec, modules)
        except (HookTargetResolutionError, OSError) as exc:
            selection_error = str(exc)
    live_provenance = {
        **provenance,
        "requested_module": requested_name,
        "loaded_by_resolver": loaded_by_resolver,
    }
    method = str(spec.get("method") or "").strip().casefold().replace("-", "_")
    if selection_error:
        return _live_failed(method, target, selection_error, provenance=live_provenance)
    if len(candidates) != 1:
        result = _live_failed(
            method,
            target,
            f"loaded module {requested_name} resolved to {len(candidates)} candidates",
            provenance=live_provenance,
        )
        result.status = "ambiguous" if len(candidates) > 1 else "unavailable"
        result.ambiguity = {
            "ambiguous": len(candidates) > 1,
            "candidate_count": len(candidates),
            "candidates": [item.to_dict() for item in candidates],
            "scope": "current_process_modules",
        }
        return result
    loaded = candidates[0]
    resolved_spec = {
        **spec,
        "module": loaded.name,
        "module_path": str(loaded.path),
        "module_base": loaded.base,
    }
    resolution = (
        _resolve_rva(resolved_spec, target=target)
        if method in {"rva", "module_rva"}
        else _resolve_pattern(resolved_spec, target=target)
    )
    resolution.provenance = dict(live_provenance)
    resolution.production_ready = False
    resolution.evidence_tier = "live-address-proof"
    if not resolution.ok or resolution.address is None:
        return resolution
    proof, owner, identity, ambiguity = _live_address_proof(
        resolution.address,
        modules,
    )
    if owner is None or owner.base != loaded.base or proof.get("status") != "ok":
        resolution.status = "ambiguous" if ambiguity.get("ambiguous") else "failed"
        resolution.errors.append(
            str(proof.get("reason") or "resolved address lacks live module proof")
        )
        resolution.executable_range = proof
        resolution.ambiguity = ambiguity
        return resolution
    resolution.source.update(
        {
            "kind": f"live_{resolution.source.get('kind', method)}",
            "module_identity": identity,
            "aslr_address_proof": proof.get("aslr_address_proof", {}),
        }
    )
    resolution.executable_range = proof
    resolution.ambiguity = ambiguity
    resolution.provenance.update(
        {
            "evidence_sources": [
                "EnumProcessModulesEx",
                "GetModuleInformation",
                "ReadProcessMemory",
                "VirtualQuery",
                "on_disk_pe_sha256",
            ],
            "production_limitation": (
                "RVA/pattern semantics are caller-defined and were not proven by "
                "the Windows loader"
            ),
        }
    )
    resolution.warnings.append(
        "live address ownership is proven, but caller-defined RVA/pattern semantics "
        "are not production-certified"
    )
    return resolution


def _resolve_live_vtable(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: list[LoadedHookModule],
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    if spec.get("object_address") is None and spec.get("vtable_address") is None:
        return _vtable_dependency_plan(
            spec,
            target=target,
            modules=modules,
            provenance=provenance,
        )
    process_architecture = _current_process_architecture()
    pointer_size = struct.calcsize("P")
    requested_architecture = _optional_text(spec.get("architecture"))
    if requested_architecture:
        normalized_architecture = requested_architecture.casefold()
        if normalized_architecture != process_architecture:
            return _live_failed(
                "vtable_slot",
                target,
                "vtable architecture does not match the current process",
                provenance=provenance,
            )
    try:
        object_address = _optional_int(spec.get("object_address"), minimum=1)
        supplied_vtable = _optional_int(spec.get("vtable_address"), minimum=1)
        if object_address is not None:
            observed_vtable = _read_current_process_pointer(
                object_address,
                pointer_size,
            )
            if supplied_vtable is not None and supplied_vtable != observed_vtable:
                raise HookTargetResolutionError(
                    "caller-provided vtable_address disagrees with the live COM object"
                )
            vtable_address = observed_vtable
        elif supplied_vtable is not None:
            vtable_address = supplied_vtable
        else:
            raise HookTargetResolutionError("live vtable address is missing")
        index = _strict_int(
            spec.get("vtable_index", spec.get("index")),
            minimum=0,
            maximum=4095,
        )
        slot_address = vtable_address + index * pointer_size
        method_address = _read_current_process_pointer(slot_address, pointer_size)
        supplied_method = _optional_int(
            spec.get("method_address", spec.get("address")),
            minimum=1,
        )
        if supplied_method is not None and supplied_method != method_address:
            raise HookTargetResolutionError(
                "caller-provided method address disagrees with the live vtable slot"
            )
        entries = spec.get("entries")
        if isinstance(entries, Sequence) and not isinstance(
            entries,
            (str, bytes, bytearray),
        ):
            if index >= len(entries):
                raise HookTargetResolutionError(
                    "vtable index exceeds the supplied entry snapshot"
                )
            expected = _strict_int(entries[index], minimum=1)
            if expected != method_address:
                raise HookTargetResolutionError(
                    "supplied entry snapshot disagrees with the live vtable slot"
                )
        slot_memory = _virtual_memory_evidence(
            slot_address,
            size=pointer_size,
            require_executable=False,
            require_image=True,
        )
        if slot_memory.get("status") != "ok":
            raise HookTargetResolutionError(
                str(slot_memory.get("reason") or "vtable slot is not readable image memory")
            )
        proof, owner, identity, ambiguity = _live_address_proof(
            method_address,
            modules,
        )
    except (HookTargetResolutionError, OSError) as exc:
        return _live_failed(
            "vtable_slot",
            target,
            str(exc),
            provenance=provenance,
        )
    if owner is None or proof.get("status") != "ok":
        result = _live_failed(
            "vtable_slot",
            target,
            str(proof.get("reason") or "vtable method lacks executable proof"),
            provenance=provenance,
        )
        result.address = method_address
        result.slot_address = slot_address
        result.executable_range = proof
        result.ambiguity = ambiguity
        if ambiguity.get("ambiguous"):
            result.status = "ambiguous"
        return result
    plan = _vtable_plan_payload(spec, modules=modules)
    plan.update(
        {
            "status": "live_address_proved",
            "observed_object_address": object_address,
            "observed_vtable_address": vtable_address,
            "observed_slot_address": slot_address,
            "observed_method_address": method_address,
            "remaining_dependency": "independent COM interface provenance",
        }
    )
    return HookTargetResolution(
        status="ok",
        method="vtable_slot",
        target=target,
        api=_optional_text(spec.get("api")),
        module=owner.name,
        symbol=_optional_text(spec.get("symbol")),
        address=method_address,
        rva=method_address - owner.base,
        slot_address=slot_address,
        source={
            "kind": "live_vtable_slot",
            "architecture": process_architecture,
            "pointer_size": pointer_size,
            "object_address": object_address,
            "vtable_address": vtable_address,
            "vtable_index": index,
            "interface": _optional_text(spec.get("interface")),
            "slot_memory": slot_memory,
            "module_identity": identity,
            "aslr_address_proof": proof.get("aslr_address_proof", {}),
        },
        executable_range=proof,
        confidence=0.98,
        ambiguity=ambiguity,
        provenance={
            **provenance,
            "evidence_sources": [
                "EnumProcessModulesEx",
                "GetModuleInformation",
                "ReadProcessMemory",
                "VirtualQuery",
                "on_disk_pe_sha256",
            ],
            "production_limitation": (
                "the resolver did not create or QueryInterface the COM object"
            ),
        },
        evidence_plan=plan,
        production_ready=False,
        evidence_tier="live-address-proof",
        warnings=[
            "vtable address is live-proven, but interface identity remains "
            "dependency-gated"
        ],
    )


def _vtable_dependency_plan(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: Sequence[LoadedHookModule],
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    plan = _vtable_plan_payload(spec, modules=modules)
    available = os.name == "nt" and sys.platform == "win32"
    status = "dependency_gated" if available else "unavailable"
    warning = (
        "a caller-owned live COM object is required; the resolver does not create "
        "a window, D3D device, or swap chain"
        if available
        else "live DXGI/D3D vtable evidence requires Windows"
    )
    architecture = (
        _current_process_architecture() if available else None
    )
    return HookTargetResolution(
        status=status,
        method="vtable_slot",
        target=target,
        api=_optional_text(spec.get("api")),
        symbol=_optional_text(spec.get("symbol")),
        source={
            "kind": "live_vtable_evidence_plan",
            "architecture": architecture,
            "interface": _optional_text(spec.get("interface")),
            "vtable_index": spec.get("vtable_index", spec.get("index")),
        },
        ambiguity={"ambiguous": False, "candidate_count": 0},
        provenance=dict(provenance),
        evidence_plan=plan,
        production_ready=False,
        evidence_tier=status,
        warnings=[warning],
    )


def _vtable_plan_payload(
    spec: Mapping[str, Any],
    *,
    modules: Sequence[LoadedHookModule],
) -> dict[str, Any]:
    dependencies_value = spec.get("dependencies", ())
    dependencies = (
        list(dependencies_value)
        if isinstance(dependencies_value, Sequence)
        and not isinstance(dependencies_value, (str, bytes, bytearray))
        else []
    )
    dependency_status: list[dict[str, Any]] = []
    for dependency in dependencies:
        name = str(dependency)
        matches = [
            item for item in modules if _module_name_matches(item.name, name)
        ]
        dependency_status.append(
            {
                "module": name,
                "status": "loaded" if len(matches) == 1 else (
                    "ambiguous" if len(matches) > 1 else "not_loaded"
                ),
                "candidate_count": len(matches),
                "candidates": [item.to_dict() for item in matches],
            }
        )
    return {
        "schema_version": 1,
        "status": "dependency_gated",
        "interface": _optional_text(spec.get("interface")),
        "symbol": _optional_text(spec.get("symbol")),
        "vtable_index": spec.get("vtable_index", spec.get("index")),
        "creation_policy": "caller_owned_object_only",
        "creation_performed": False,
        "required_inputs": ["object_address or vtable_address"],
        "dependency_status": dependency_status,
        "observations": [
            "read the object's vtable pointer with ReadProcessMemory",
            "read the selected vtable slot with ReadProcessMemory",
            "map the method to exactly one EnumProcessModulesEx range",
            "match loaded and on-disk PE identity and architecture",
            "prove loaded_base + RVA equals the observed method address",
            "prove the method is in an executable PE section and MEM_IMAGE region",
        ],
        "semantic_gate": (
            "the caller must retain provenance showing how the exact COM interface "
            "was obtained"
        ),
    }


def _resolve_export(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: Sequence[Mapping[str, Any]],
    depth: int = 0,
) -> HookTargetResolution:
    if depth > 8:
        return _failed("module_export", target, "forwarded-export chain exceeds 8 modules")
    module_path, module_base, module_name, error = _module_input(spec)
    symbol_value = spec.get("export", spec.get("symbol"))
    symbol = _optional_text(symbol_value)
    ordinal = _strict_int(spec.get("ordinal"), minimum=1) if spec.get("ordinal") is not None else None
    if error:
        return _failed("module_export", target, error)
    if symbol is None and ordinal is None:
        return _failed("module_export", target, "module_export requires export or ordinal")
    try:
        module = inspect_hook_module(module_path)
        table = parse_pe_exports(module_path, expected_architecture=module.architecture)
    except (HookTargetResolutionError, DllProxyGenerationError, OSError) as exc:
        return _failed("module_export", target, str(exc))
    candidates = [
        item
        for item in table.exports
        if (symbol is not None and item.name == symbol)
        or (ordinal is not None and item.ordinal == ordinal)
    ]
    if len(candidates) != 1:
        label = symbol if symbol is not None else f"#{ordinal}"
        status = "ambiguous" if len(candidates) > 1 else "failed"
        result = _failed("module_export", target, f"export {label} resolved to {len(candidates)} entries")
        result.status = status
        result.ambiguity = {"candidate_count": len(candidates), "candidates": [item.to_dict() for item in candidates]}
        return result
    export = candidates[0]
    if export.forwarder:
        forwarded = _resolve_forwarder(
            export.forwarder,
            modules=modules,
            target=target,
            inherited={"api": spec.get("api")},
            depth=depth + 1,
        )
        forwarded.source.setdefault("forwarder_chain", []).insert(
            0,
            {
                "module": module_name,
                "export": export.name,
                "ordinal": export.ordinal,
                "forwarder": export.forwarder,
                "sha256": module.sha256,
            },
        )
        return forwarded
    proof = _executable_proof(module, module_base, export.target_rva)
    if proof.get("status") != "ok":
        return _failed("module_export", target, str(proof.get("reason") or "export is not executable"))
    address = module_base + export.target_rva
    return HookTargetResolution(
        status="ok",
        method="module_export",
        target=target,
        api=_optional_text(spec.get("api")),
        module=module_name,
        symbol=export.name or f"#{export.ordinal}",
        address=address,
        rva=export.target_rva,
        source={
            "kind": "pe_export",
            "path": str(module.path),
            "sha256": module.sha256,
            "architecture": module.architecture,
            "module_base": module_base,
            "ordinal": export.ordinal,
            "forwarder": None,
        },
        executable_range=proof,
        confidence=1.0,
        ambiguity={"candidate_count": 1, "ambiguous": False},
    )


def _resolve_rva(spec: Mapping[str, Any], *, target: str | None) -> HookTargetResolution:
    module_path, module_base, module_name, error = _module_input(spec)
    if error:
        return _failed("module_rva", target, error)
    try:
        rva = _strict_int(spec.get("rva", spec.get("offset")), minimum=1)
    except HookTargetResolutionError as exc:
        return _failed("module_rva", target, str(exc))
    try:
        module = inspect_hook_module(module_path)
    except (HookTargetResolutionError, OSError) as exc:
        return _failed("module_rva", target, str(exc))
    proof = _executable_proof(module, module_base, rva)
    if proof.get("status") != "ok":
        return _failed("module_rva", target, str(proof.get("reason") or "RVA is not executable"))
    return HookTargetResolution(
        status="ok",
        method="module_rva",
        target=target,
        api=_optional_text(spec.get("api")),
        module=module_name,
        symbol=_optional_text(spec.get("symbol")),
        address=module_base + rva,
        rva=rva,
        source={
            "kind": "module_rva",
            "path": str(module.path),
            "sha256": module.sha256,
            "architecture": module.architecture,
            "module_base": module_base,
        },
        executable_range=proof,
        confidence=0.98,
        ambiguity={"candidate_count": 1, "ambiguous": False},
    )


def _resolve_iat(spec: Mapping[str, Any], *, target: str | None) -> HookTargetResolution:
    module_path, module_base, module_name, error = _module_input(spec)
    if error:
        return _failed("iat_slot", target, error)
    imported_module = _optional_text(
        spec.get("dll", spec.get("import_module", spec.get("imported_module")))
    )
    symbol = _optional_text(
        spec.get("import", spec.get("import_name", spec.get("symbol")))
    )
    try:
        ordinal = (
            _strict_int(spec.get("ordinal"), minimum=1, maximum=0xFFFF)
            if spec.get("ordinal") is not None
            else None
        )
    except HookTargetResolutionError as exc:
        return _failed("iat_slot", target, str(exc))
    if imported_module is None:
        return _failed("iat_slot", target, "iat_slot requires dll or import_module")
    if symbol is None and ordinal is None:
        return _failed("iat_slot", target, "iat_slot requires symbol/import or ordinal")
    try:
        module = inspect_hook_module(module_path)
        imports = _parse_pe_import_evidence(module)
    except (HookTargetResolutionError, OSError) as exc:
        return _failed("iat_slot", target, str(exc))
    candidates = [
        item
        for item in imports
        if _module_name_matches(item.imported_module, imported_module)
        and (symbol is None or item.symbol == symbol)
        and (ordinal is None or item.ordinal == ordinal)
    ]
    if len(candidates) != 1:
        label = symbol if symbol is not None else f"#{ordinal}"
        result = _failed(
            "iat_slot",
            target,
            f"import {imported_module}!{label} resolved to {len(candidates)} IAT slots",
        )
        result.status = "ambiguous" if len(candidates) > 1 else "failed"
        result.ambiguity = {
            "candidate_count": len(candidates),
            "ambiguous": len(candidates) > 1,
            "candidates": [item.to_dict() for item in candidates],
        }
        return result
    selected = candidates[0]
    section = module.section_for_rva(selected.iat_rva, selected.pointer_size)
    if section is None:
        return _failed("iat_slot", target, "selected IAT slot is outside mapped PE sections")
    file_offset = section.file_offset(selected.iat_rva, selected.pointer_size)
    if file_offset is None:
        return _failed("iat_slot", target, "selected IAT slot is not file-backed")
    slot_address = module_base + selected.iat_rva
    selected_symbol = selected.symbol or f"#{selected.ordinal}"
    return HookTargetResolution(
        status="ok",
        method="iat_slot",
        target=target,
        api=_optional_text(spec.get("api")),
        module=module_name,
        symbol=selected_symbol,
        address=slot_address,
        rva=selected.iat_rva,
        slot_address=slot_address,
        source={
            "kind": "pe_iat_slot",
            "path": str(module.path),
            "sha256": module.sha256,
            "architecture": module.architecture,
            "module_base": module_base,
            "imported_module": selected.imported_module,
            "import_symbol": selected.symbol,
            "import_ordinal": selected.ordinal,
            "hint": selected.hint,
            "pointer_size": selected.pointer_size,
            "lookup_rva": selected.lookup_rva,
            "file_offset": file_offset,
            "section": section.name,
            "descriptor_timestamp": selected.descriptor_timestamp,
        },
        executable_range={
            "status": "not_observed",
            "executable": None,
            "slot_address": slot_address,
            "reason": (
                "offline IAT resolution identifies the pointer slot; the imported "
                "target requires a live memory observation"
            ),
        },
        confidence=0.99,
        ambiguity={"candidate_count": 1, "ambiguous": False},
        warnings=[
            "offline evidence does not prove the loader-bound target pointer"
        ],
    )


def _resolve_pattern(spec: Mapping[str, Any], *, target: str | None) -> HookTargetResolution:
    module_path, module_base, module_name, error = _module_input(spec)
    if error:
        return _failed("pattern", target, error)
    try:
        pattern, mask = _parse_pattern(spec.get("pattern", spec.get("signature")), spec.get("mask"))
        module = inspect_hook_module(module_path)
        data = module.path.read_bytes()
    except (HookTargetResolutionError, OSError) as exc:
        return _failed("pattern", target, str(exc))
    matches: list[dict[str, Any]] = []
    for section in module.sections:
        if not section.executable or section.raw_size < len(pattern):
            continue
        raw = data[section.raw_offset : section.raw_offset + section.raw_size]
        for relative in _pattern_offsets(raw, pattern, mask):
            rva = section.virtual_address + relative
            matches.append({"rva": rva, "address": module_base + rva, "section": section.name})
            if len(matches) > 256:
                return _failed("pattern", target, "pattern produced more than 256 matches")
    if len(matches) != 1:
        result = _failed("pattern", target, f"pattern resolved to {len(matches)} executable matches")
        result.status = "ambiguous" if len(matches) > 1 else "failed"
        result.ambiguity = {"candidate_count": len(matches), "ambiguous": len(matches) > 1, "candidates": matches}
        return result
    match = matches[0]
    proof = _executable_proof(module, module_base, int(match["rva"]), len(pattern))
    return HookTargetResolution(
        status="ok",
        method="pattern",
        target=target,
        api=_optional_text(spec.get("api")),
        module=module_name,
        symbol=_optional_text(spec.get("symbol")),
        address=int(match["address"]),
        rva=int(match["rva"]),
        source={
            "kind": "aob_pattern",
            "path": str(module.path),
            "sha256": module.sha256,
            "architecture": module.architecture,
            "module_base": module_base,
            "pattern": _format_pattern(pattern, mask),
            "pattern_sha256": hashlib.sha256(pattern + mask).hexdigest(),
        },
        executable_range=proof,
        confidence=0.95,
        ambiguity={"candidate_count": 1, "ambiguous": False},
    )


def _resolve_vtable(
    spec: Mapping[str, Any],
    *,
    target: str | None,
    modules: Sequence[Mapping[str, Any]],
) -> HookTargetResolution:
    try:
        architecture = str(spec.get("architecture") or "x64").strip().casefold()
        if architecture not in {"x86", "x64"}:
            raise HookTargetResolutionError("vtable architecture must be x86 or x64")
        pointer_size = 4 if architecture == "x86" else 8
        vtable_address = _strict_int(spec.get("vtable_address"), minimum=1)
        index = _strict_int(spec.get("vtable_index", spec.get("index")), minimum=0, maximum=4095)
        method_address = _optional_int(spec.get("method_address", spec.get("address")), minimum=1)
        entries = spec.get("entries")
        if method_address is None and isinstance(entries, Sequence) and not isinstance(entries, (str, bytes, bytearray)):
            if index >= len(entries):
                raise HookTargetResolutionError("vtable index exceeds the supplied entry snapshot")
            method_address = _strict_int(entries[index], minimum=1)
        if method_address is None:
            raise HookTargetResolutionError("vtable resolution requires method_address or an entry snapshot")
    except HookTargetResolutionError as exc:
        return _failed("vtable_slot", target, str(exc))
    proof, module_name, source = _proof_from_module_evidence(method_address, modules)
    if proof.get("status") != "ok":
        result = _failed("vtable_slot", target, str(proof.get("reason") or "method address lacks executable proof"))
        result.address = method_address
        result.slot_address = vtable_address + index * pointer_size
        result.executable_range = proof
        return result
    return HookTargetResolution(
        status="ok",
        method="vtable_slot",
        target=target,
        api=_optional_text(spec.get("api")),
        module=module_name,
        symbol=_optional_text(spec.get("symbol")),
        address=method_address,
        slot_address=vtable_address + index * pointer_size,
        source={
            "kind": "vtable_snapshot",
            "architecture": architecture,
            "pointer_size": pointer_size,
            "vtable_address": vtable_address,
            "vtable_index": index,
            "interface": _optional_text(spec.get("interface")),
            **source,
        },
        executable_range=proof,
        confidence=0.98,
        ambiguity={"candidate_count": 1, "ambiguous": False},
    )


def _resolve_forwarder(
    value: str,
    *,
    modules: Sequence[Mapping[str, Any]],
    target: str | None,
    inherited: Mapping[str, Any],
    depth: int,
) -> HookTargetResolution:
    module_token, separator, symbol_token = value.rpartition(".")
    if not separator or not module_token or not symbol_token:
        return _failed("module_export", target, f"malformed forwarded export: {value}")
    candidates = [item for item in modules if _module_name_matches(item.get("name") or item.get("module"), module_token)]
    if len(candidates) != 1:
        result = _failed("module_export", target, f"forwarded module {module_token} resolved to {len(candidates)} candidates")
        result.status = "ambiguous" if len(candidates) > 1 else "failed"
        result.ambiguity = {"candidate_count": len(candidates), "ambiguous": len(candidates) > 1}
        return result
    forwarded_spec: dict[str, Any] = {
        "method": "module_export",
        "module": candidates[0].get("name") or candidates[0].get("module"),
        "module_path": candidates[0].get("path"),
        "module_base": candidates[0].get("base", candidates[0].get("module_base")),
        **inherited,
    }
    if symbol_token.startswith("#"):
        forwarded_spec["ordinal"] = symbol_token[1:]
    else:
        forwarded_spec["export"] = symbol_token
    return _resolve_export(forwarded_spec, target=target, modules=modules, depth=depth)


def _proof_from_module_evidence(
    address: int,
    modules: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], str | None, dict[str, Any]]:
    matches: list[tuple[PEHookModule, int, str]] = []
    errors: list[str] = []
    for item in modules:
        try:
            path = item.get("path")
            base = _strict_int(item.get("base", item.get("module_base")), minimum=1)
            module = inspect_hook_module(path)
            if base <= address < base + module.size_of_image:
                matches.append((module, base, str(item.get("name") or Path(path).name)))
        except (HookTargetResolutionError, OSError, TypeError) as exc:
            errors.append(str(exc))
    if len(matches) != 1:
        return (
            {
                "status": "ambiguous" if len(matches) > 1 else "failed",
                "reason": f"address belongs to {len(matches)} supplied module ranges",
                "candidate_count": len(matches),
                "module_errors": errors,
            },
            None,
            {},
        )
    module, base, name = matches[0]
    proof = _executable_proof(module, base, address - base)
    return proof, name, {"module_path": str(module.path), "module_sha256": module.sha256, "module_base": base}


def _module_input(spec: Mapping[str, Any]) -> tuple[Path, int, str, str | None]:
    path_value = spec.get("module_path", spec.get("path"))
    if not isinstance(path_value, (str, os.PathLike)) or not str(path_value).strip():
        return Path(), 0, "", "module resolution requires module_path"
    path = Path(path_value).expanduser().resolve()
    try:
        base = _strict_int(spec.get("module_base", spec.get("base")), minimum=1)
    except HookTargetResolutionError as exc:
        return path, 0, path.name, str(exc)
    requested_name = _optional_text(spec.get("module"))
    if requested_name and not _module_name_matches(path.name, requested_name):
        return path, base, requested_name, f"module path {path.name} does not match requested module {requested_name}"
    return path, base, requested_name or path.name, None


def _executable_proof(
    module: PEHookModule,
    module_base: int,
    rva: int,
    size: int = 1,
) -> dict[str, Any]:
    try:
        section = module.section_for_rva(rva, size)
    except HookTargetResolutionError as exc:
        return {"status": "failed", "reason": str(exc)}
    if section is None:
        return {"status": "failed", "reason": f"RVA 0x{rva:x} is outside mapped PE sections"}
    if not section.executable:
        return {"status": "failed", "reason": f"RVA 0x{rva:x} is in non-executable section {section.name}"}
    return {
        "status": "ok",
        "executable": True,
        "section": section.name,
        "characteristics": section.characteristics,
        "characteristics_hex": f"0x{section.characteristics:08x}",
        "range_start": module_base + section.virtual_address,
        "range_end": module_base + section.virtual_address + section.virtual_extent,
        "address": module_base + rva,
        "size": size,
    }


def _expanded_specification(
    specification: Mapping[str, Any],
) -> tuple[dict[str, Any], str | None, str | None]:
    spec = dict(specification)
    target = _optional_text(spec.get("target") or spec.get("name"))
    if not target:
        return spec, None, None
    alias = _COMMON_TARGETS.get(target.casefold())
    if alias is None:
        return spec, target, f"unknown common hook target: {target}"
    return {**alias, **spec}, target, None


def _live_provenance() -> dict[str, Any]:
    available = os.name == "nt" and sys.platform == "win32"
    return {
        "kind": "current_process_observation",
        "platform": sys.platform,
        "platform_machine": platform.machine(),
        "pid": os.getpid(),
        "backend": "win32-current-process" if available else None,
        "injected_backend": False,
        "synthetic": False,
    }


def _live_failed(
    method: str,
    target: str | None,
    error: str,
    *,
    provenance: Mapping[str, Any],
) -> HookTargetResolution:
    return HookTargetResolution(
        status="failed",
        method=method,
        target=target,
        provenance=dict(provenance),
        production_ready=False,
        evidence_tier="live-failed",
        errors=[error],
    )


def _live_module_candidates(
    spec: Mapping[str, Any],
    modules: Sequence[LoadedHookModule],
) -> tuple[str, list[LoadedHookModule], str | None]:
    path_value = spec.get("module_path", spec.get("path"))
    requested_name = _optional_text(spec.get("module"))
    requested_path: Path | None = None
    if path_value is not None:
        if not isinstance(path_value, (str, os.PathLike)) or not str(path_value).strip():
            return requested_name or "", [], "module_path must be a non-empty path"
        requested_path = Path(path_value).expanduser().resolve()
        if requested_name and not _module_name_matches(
            requested_path.name,
            requested_name,
        ):
            return (
                requested_name,
                [],
                f"module path {requested_path.name} does not match requested module "
                f"{requested_name}",
            )
        requested_name = requested_name or requested_path.name
    if not requested_name:
        return "", [], "live module resolution requires module or module_path"
    try:
        requested_base = _optional_int(
            spec.get("module_base", spec.get("base")),
            minimum=1,
        )
    except HookTargetResolutionError as exc:
        return requested_name, [], str(exc)
    candidates = [
        item
        for item in modules
        if _module_name_matches(item.name, requested_name)
        and (requested_path is None or _same_path(item.path, requested_path))
        and (requested_base is None or item.base == requested_base)
    ]
    return requested_name, candidates, None


def _pin_benign_system_module(module_name: str) -> bool:
    normalized = Path(module_name).name.casefold()
    if normalized not in _BENIGN_SYSTEM_MODULES:
        raise HookTargetResolutionError(
            f"automatic loading is not allowed for module {module_name}"
        )
    api = _win32()
    with _PINNED_SYSTEM_MODULES_LOCK:
        pinned_handle = _PINNED_SYSTEM_MODULE_HANDLES.get(normalized)
        existing = api.kernel32.GetModuleHandleW(normalized)
        if pinned_handle is not None:
            if _pointer_value(existing) != pinned_handle:
                raise HookTargetResolutionError(
                    f"resolver-pinned system module handle changed: {normalized}"
                )
            return True
        if existing:
            return False
        buffer = api.ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
        length = api.kernel32.GetSystemDirectoryW(buffer, len(buffer))
        if not length or length >= len(buffer):
            raise _last_win32_error("GetSystemDirectoryW")
        system_path = (Path(buffer.value) / normalized).resolve()
        if not system_path.is_file():
            raise HookTargetResolutionError(
                f"system module is unavailable: {system_path}"
            )
        handle = api.kernel32.LoadLibraryExW(str(system_path), None, 0)
        if not handle:
            raise _last_win32_error(f"LoadLibraryExW({system_path})")
        _PINNED_SYSTEM_MODULE_HANDLES[normalized] = _pointer_value(handle)
    return True


def _system_module_is_resolver_pinned(module_name: str) -> bool:
    normalized = Path(module_name).name.casefold()
    with _PINNED_SYSTEM_MODULES_LOCK:
        return normalized in _PINNED_SYSTEM_MODULE_HANDLES


def _loaded_module_identity(
    loaded: LoadedHookModule,
) -> tuple[PEHookModule, dict[str, Any]]:
    module = inspect_hook_module(loaded.path)
    memory_header = _read_loaded_pe_header(loaded.base)
    process_architecture = _current_process_architecture()
    executable_ranges = [
        {
            "section": section.name,
            "rva_start": section.virtual_address,
            "rva_end": section.virtual_address + section.virtual_extent,
            "address_start": loaded.base + section.virtual_address,
            "address_end": (
                loaded.base + section.virtual_address + section.virtual_extent
            ),
            "characteristics": section.characteristics,
            "characteristics_hex": f"0x{section.characteristics:08x}",
        }
        for section in module.sections
        if section.executable
    ]
    header_fields_match = all(
        (
            memory_header["machine"] == module.machine,
            memory_header["architecture"] == module.architecture,
            memory_header["pe_timestamp"] == module.pe_timestamp,
            memory_header["checksum"] == module.checksum,
            memory_header["size_of_image"] == module.size_of_image,
        )
    )
    memory_base_matches = memory_header["image_base"] == loaded.base
    loaded_size_matches = loaded.size_of_image == module.size_of_image
    architecture_matches = module.architecture == process_architecture
    identity_core = {
        "file_sha256": module.sha256,
        "machine": module.machine,
        "pe_timestamp": module.pe_timestamp,
        "checksum": module.checksum,
        "size_of_image": module.size_of_image,
        "preferred_image_base": module.image_base,
    }
    identity_hash = hashlib.sha256(
        json.dumps(identity_core, sort_keys=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()
    errors: list[str] = []
    if not header_fields_match:
        errors.append("loaded PE header does not match the module file identity")
    if not memory_base_matches:
        errors.append("loaded PE header image base does not match the loader base")
    if not loaded_size_matches:
        errors.append("loader SizeOfImage does not match the module file")
    if not architecture_matches:
        errors.append("loaded module architecture does not match the current process")
    if not executable_ranges:
        errors.append("loaded module has no executable PE section ranges")
    identity = {
        "status": "ok" if not errors else "failed",
        "reason": "; ".join(errors) if errors else None,
        "kind": "loaded_pe_image",
        "name": loaded.name,
        "path": str(loaded.path),
        "file_sha256": module.sha256,
        "file_size": module.file_size,
        "pe_identity_sha256": identity_hash,
        "machine": module.machine,
        "machine_hex": f"0x{module.machine:04x}",
        "architecture": module.architecture,
        "process_architecture": process_architecture,
        "architecture_matches_process": architecture_matches,
        "pe_timestamp": module.pe_timestamp,
        "pe_timestamp_hex": f"0x{module.pe_timestamp:08x}",
        "checksum": module.checksum,
        "checksum_hex": f"0x{module.checksum:08x}",
        "dll_characteristics": module.dll_characteristics,
        "dll_characteristics_hex": f"0x{module.dll_characteristics:04x}",
        "dynamic_base": module.dynamic_base,
        "preferred_image_base": module.image_base,
        "loaded_base": loaded.base,
        "loaded_end": loaded.end,
        "aslr_delta": loaded.base - module.image_base,
        "aslr_applied": loaded.base != module.image_base,
        "size_of_image": module.size_of_image,
        "loader_size_of_image": loaded.size_of_image,
        "loader_size_matches_pe": loaded_size_matches,
        "memory_header_matches_file": header_fields_match,
        "memory_header_base_matches_loader": memory_base_matches,
        "memory_header": memory_header,
        "entry_point": loaded.entry_point,
        "executable_ranges": executable_ranges,
    }
    return module, identity


def _live_address_proof(
    address: int,
    modules: Sequence[LoadedHookModule],
    *,
    size: int = 1,
) -> tuple[
    dict[str, Any],
    LoadedHookModule | None,
    dict[str, Any],
    dict[str, Any],
]:
    owners = [item for item in modules if item.contains(address, size)]
    ambiguity = {
        "ambiguous": len(owners) > 1,
        "candidate_count": len(owners),
        "candidates": [item.to_dict() for item in owners],
        "scope": "loaded_address_ownership",
    }
    if len(owners) != 1:
        status = "ambiguous" if len(owners) > 1 else "failed"
        return (
            {
                "status": status,
                "reason": f"address belongs to {len(owners)} loaded module ranges",
                "candidate_count": len(owners),
            },
            None,
            {},
            ambiguity,
        )
    owner = owners[0]
    try:
        module, identity = _loaded_module_identity(owner)
        rva = address - owner.base
        pe_proof = _executable_proof(module, owner.base, rva, size)
        memory_proof = _virtual_memory_evidence(
            address,
            size=size,
            require_executable=True,
            require_image=True,
        )
    except (HookTargetResolutionError, OSError) as exc:
        return (
            {"status": "failed", "reason": str(exc), "candidate_count": 1},
            owner,
            {},
            ambiguity,
        )
    computed_address = owner.base + rva
    formula_matches = computed_address == address
    allocation_matches = memory_proof.get("allocation_base") == owner.base
    errors: list[str] = []
    if identity.get("status") != "ok":
        errors.append(str(identity.get("reason") or "loaded PE identity failed"))
    if pe_proof.get("status") != "ok":
        errors.append(str(pe_proof.get("reason") or "PE section is not executable"))
    if memory_proof.get("status") != "ok":
        errors.append(
            str(memory_proof.get("reason") or "virtual memory is not executable")
        )
    if not formula_matches:
        errors.append("loaded_base + RVA does not equal the observed address")
    if not allocation_matches:
        errors.append("VirtualQuery allocation base does not match the module base")
    proof = {
        **pe_proof,
        "status": "ok" if not errors else "failed",
        "reason": "; ".join(errors) if errors else None,
        "candidate_count": 1,
        "address_owner": owner.to_dict(),
        "virtual_memory": memory_proof,
        "module_identity_status": identity.get("status"),
        "aslr_address_proof": {
            "status": "ok" if formula_matches else "failed",
            "preferred_image_base": module.image_base,
            "loaded_base": owner.base,
            "aslr_delta": owner.base - module.image_base,
            "rva": rva,
            "computed_address": computed_address,
            "observed_address": address,
            "formula": "loaded_base + rva",
            "matches": formula_matches,
        },
        "allocation_base_matches_module": allocation_matches,
    }
    return proof, owner, identity, ambiguity


def _trace_live_forwarder(
    value: str,
    *,
    modules: Sequence[LoadedHookModule],
    resolved_address: int,
    depth: int,
    seen: set[tuple[str, str]],
) -> tuple[list[dict[str, Any]], str | None, str | None, dict[str, Any]]:
    if depth > _MAX_FORWARDER_DEPTH:
        return [], None, "forwarded-export chain exceeds 8 modules", {}
    module_token, separator, symbol_token = value.rpartition(".")
    if not separator or not module_token or not symbol_token:
        return [], None, f"malformed forwarded export: {value}", {}
    normalized_module = module_token.casefold().removesuffix(".dll")
    normalized_symbol = symbol_token.casefold()
    key = (normalized_module, normalized_symbol)
    if key in seen:
        return [], None, f"forwarded-export cycle detected at {value}", {}
    candidates = [
        item
        for item in modules
        if _module_name_matches(item.name, module_token)
    ]
    ambiguity = {
        "ambiguous": len(candidates) > 1,
        "candidate_count": len(candidates),
        "candidates": [item.to_dict() for item in candidates],
        "scope": f"forwarded_module:{module_token}",
    }
    if not candidates:
        virtual_contract = normalized_module.startswith(("api-ms-", "ext-ms-"))
        record = {
            "module": module_token,
            "export": None if symbol_token.startswith("#") else symbol_token,
            "ordinal": (
                int(symbol_token[1:]) if symbol_token.startswith("#") else None
            ),
            "forwarder": None,
            "virtual_contract": virtual_contract,
            "status": (
                "resolved_by_windows_loader" if virtual_contract else "not_loaded"
            ),
            "resolved_address": resolved_address,
        }
        if virtual_contract:
            return [record], symbol_token, None, ambiguity
        return (
            [record],
            None,
            f"forwarded module {module_token} is not loaded",
            ambiguity,
        )
    if len(candidates) > 1:
        return (
            [],
            None,
            f"forwarded module {module_token} resolved to multiple loaded modules",
            ambiguity,
        )
    loaded = candidates[0]
    try:
        module, identity = _loaded_module_identity(loaded)
        table = parse_pe_exports(
            loaded.path,
            expected_architecture=module.architecture,
        )
        ordinal = (
            _strict_int(symbol_token[1:], minimum=1, maximum=0xFFFF)
            if symbol_token.startswith("#")
            else None
        )
        symbol = None if ordinal is not None else symbol_token
    except (
        HookTargetResolutionError,
        DllProxyGenerationError,
        OSError,
        TypeError,
    ) as exc:
        return [], None, str(exc), ambiguity
    if identity.get("status") != "ok":
        return (
            [],
            None,
            str(identity.get("reason") or "forwarded module identity failed"),
            ambiguity,
        )
    exports = [
        item
        for item in table.exports
        if (symbol is not None and item.name == symbol)
        or (ordinal is not None and item.ordinal == ordinal)
    ]
    if len(exports) != 1:
        ambiguity = {
            "ambiguous": len(exports) > 1,
            "candidate_count": len(exports),
            "candidates": [item.to_dict() for item in exports],
            "scope": f"forwarded_export:{value}",
        }
        return (
            [],
            None,
            f"forwarded export {value} resolved to {len(exports)} entries",
            ambiguity,
        )
    export = exports[0]
    record = {
        "module": loaded.name,
        "path": str(loaded.path),
        "export": export.name,
        "ordinal": export.ordinal,
        "target_rva": export.target_rva,
        "forwarder": export.forwarder,
        "sha256": module.sha256,
        "loaded_base": loaded.base,
        "pe_identity_sha256": identity["pe_identity_sha256"],
        "status": "ok",
    }
    resolved_symbol = export.name or f"#{export.ordinal}"
    if export.forwarder:
        traced, final_symbol, error, nested_ambiguity = _trace_live_forwarder(
            export.forwarder,
            modules=modules,
            resolved_address=resolved_address,
            depth=depth + 1,
            seen={*seen, key},
        )
        return (
            [record, *traced],
            final_symbol or resolved_symbol,
            error,
            nested_ambiguity,
        )
    expected = loaded.base + export.target_rva
    if expected != resolved_address:
        return (
            [record],
            resolved_symbol,
            (
                "forwarder chain endpoint disagrees with GetProcAddress: "
                f"0x{expected:x} != 0x{resolved_address:x}"
            ),
            ambiguity,
        )
    return [record], resolved_symbol, None, ambiguity


def _virtual_memory_evidence(
    address: int,
    *,
    size: int,
    require_executable: bool,
    require_image: bool,
) -> dict[str, Any]:
    api = _win32()
    info = api.memory_basic_information_type()
    queried = api.kernel32.VirtualQuery(
        api.ctypes.c_void_p(address),
        api.ctypes.byref(info),
        api.ctypes.sizeof(info),
    )
    if not queried:
        raise _last_win32_error(f"VirtualQuery(0x{address:x})")
    base = _pointer_value(info.BaseAddress)
    allocation_base = _pointer_value(info.AllocationBase)
    region_size = int(info.RegionSize)
    protect = int(info.Protect)
    state = int(info.State)
    memory_type = int(info.Type)
    executable = bool(protect & _PAGE_EXECUTE_MASK)
    guarded = bool(protect & _PAGE_GUARD)
    inaccessible = bool(protect & _PAGE_NOACCESS)
    errors: list[str] = []
    if state != _MEM_COMMIT:
        errors.append("memory region is not committed")
    if require_image and memory_type != _MEM_IMAGE:
        errors.append("memory region is not MEM_IMAGE")
    if require_executable and not executable:
        errors.append("memory protection is not executable")
    if guarded:
        errors.append("memory region is guarded")
    if inaccessible:
        errors.append("memory region is inaccessible")
    if not (base <= address and address + size <= base + region_size):
        errors.append("requested range exceeds the VirtualQuery region")
    return {
        "status": "ok" if not errors else "failed",
        "reason": "; ".join(errors) if errors else None,
        "base_address": base,
        "allocation_base": allocation_base,
        "region_size": region_size,
        "region_end": base + region_size,
        "state": state,
        "state_hex": f"0x{state:x}",
        "protect": protect,
        "protect_hex": f"0x{protect:x}",
        "type": memory_type,
        "type_hex": f"0x{memory_type:x}",
        "committed": state == _MEM_COMMIT,
        "image": memory_type == _MEM_IMAGE,
        "executable": executable,
        "guarded": guarded,
        "address": address,
        "size": size,
    }


def _read_loaded_pe_header(base: int) -> dict[str, Any]:
    dos = _read_current_process_memory(base, 0x40)
    if dos[:2] != b"MZ":
        raise HookTargetResolutionError(
            f"loaded image at 0x{base:x} has no DOS signature"
        )
    pe_offset = _u32(dos, 0x3C, "loaded DOS e_lfanew")
    if pe_offset < 0x40 or pe_offset > 0x10000:
        raise HookTargetResolutionError("loaded PE e_lfanew is outside bounds")
    header = _read_current_process_memory(base, pe_offset + 0x100)
    if header[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise HookTargetResolutionError("loaded image has no PE signature")
    coff = pe_offset + 4
    machine = _u16(header, coff, "loaded COFF machine")
    pe_timestamp = _u32(header, coff + 4, "loaded COFF timestamp")
    optional = coff + 20
    magic = _u16(header, optional, "loaded optional-header magic")
    if magic == 0x10B:
        architecture = _machine_architecture(machine, bits=32)
        preferred_image_base = _u32(
            header,
            optional + 28,
            "loaded PE32 image base",
        )
    elif magic == 0x20B:
        architecture = _machine_architecture(machine, bits=64)
        preferred_image_base = _u64(
            header,
            optional + 24,
            "loaded PE32+ image base",
        )
    else:
        raise HookTargetResolutionError(
            f"unsupported loaded PE optional-header magic 0x{magic:04x}"
        )
    return {
        "machine": machine,
        "machine_hex": f"0x{machine:04x}",
        "architecture": architecture,
        "pe_timestamp": pe_timestamp,
        "checksum": _u32(header, optional + 64, "loaded PE checksum"),
        "size_of_image": _u32(
            header,
            optional + 56,
            "loaded SizeOfImage",
        ),
        # The loader relocates this OptionalHeader field in the mapped image.
        "image_base": preferred_image_base,
        "dll_characteristics": _u16(
            header,
            optional + 70,
            "loaded DLL characteristics",
        ),
    }


def _read_current_process_pointer(address: int, pointer_size: int) -> int:
    if pointer_size not in {4, 8}:
        raise HookTargetResolutionError("unsupported current-process pointer size")
    value = int.from_bytes(
        _read_current_process_memory(address, pointer_size),
        "little",
    )
    if value <= 0:
        raise HookTargetResolutionError(
            f"current-process pointer at 0x{address:x} is null"
        )
    return value


def _read_current_process_memory(address: int, size: int) -> bytes:
    if address <= 0 or size <= 0 or size > 0x20000:
        raise HookTargetResolutionError("current-process memory read is outside bounds")
    api = _win32()
    buffer = (api.ctypes.c_ubyte * size)()
    read = api.ctypes.c_size_t()
    ok = api.kernel32.ReadProcessMemory(
        api.process,
        api.ctypes.c_void_p(address),
        api.ctypes.byref(buffer),
        size,
        api.ctypes.byref(read),
    )
    if not ok or read.value != size:
        raise _last_win32_error(
            f"ReadProcessMemory(0x{address:x}, {size})"
        )
    return bytes(buffer)


def _current_process_architecture() -> str:
    pointer_bits = struct.calcsize("P") * 8
    machine = platform.machine().strip().casefold()
    if pointer_bits == 32:
        return "arm" if machine.startswith("arm") else "x86"
    if pointer_bits == 64:
        return "arm64" if "arm" in machine or "aarch64" in machine else "x64"
    raise HookTargetResolutionError(
        f"unsupported current-process pointer width: {pointer_bits}"
    )


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.realpath(left)) == os.path.normcase(
        os.path.realpath(right)
    )


class _Win32API:
    def __init__(self) -> None:
        if os.name != "nt" or sys.platform != "win32":
            raise HookTargetResolutionError("Win32 APIs are unavailable")
        import ctypes
        from ctypes import wintypes

        class ModuleInfo(ctypes.Structure):
            _fields_ = [
                ("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p),
            ]

        class MemoryBasicInformation(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("PartitionId", wintypes.WORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.module_info_type = ModuleInfo
        self.memory_basic_information_type = MemoryBasicInformation
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)

        self.kernel32.GetCurrentProcess.argtypes = []
        self.kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        self.kernel32.GetProcAddress.argtypes = [
            wintypes.HMODULE,
            ctypes.c_void_p,
        ]
        self.kernel32.GetProcAddress.restype = ctypes.c_void_p
        self.kernel32.GetSystemDirectoryW.argtypes = [
            wintypes.LPWSTR,
            wintypes.UINT,
        ]
        self.kernel32.GetSystemDirectoryW.restype = wintypes.UINT
        self.kernel32.LoadLibraryExW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        self.kernel32.LoadLibraryExW.restype = wintypes.HMODULE
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        self.kernel32.VirtualQuery.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(MemoryBasicInformation),
            ctypes.c_size_t,
        ]
        self.kernel32.VirtualQuery.restype = ctypes.c_size_t

        self.psapi.EnumProcessModulesEx.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HMODULE),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
        ]
        self.psapi.EnumProcessModulesEx.restype = wintypes.BOOL
        self.psapi.GetModuleFileNameExW.argtypes = [
            wintypes.HANDLE,
            wintypes.HMODULE,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        self.psapi.GetModuleFileNameExW.restype = wintypes.DWORD
        self.psapi.GetModuleInformation.argtypes = [
            wintypes.HANDLE,
            wintypes.HMODULE,
            ctypes.POINTER(ModuleInfo),
            wintypes.DWORD,
        ]
        self.psapi.GetModuleInformation.restype = wintypes.BOOL
        self.process = self.kernel32.GetCurrentProcess()


def _win32() -> _Win32API:
    global _WIN32_BINDINGS
    if _WIN32_BINDINGS is not None:
        return _WIN32_BINDINGS
    with _WIN32_BINDINGS_LOCK:
        if _WIN32_BINDINGS is None:
            _WIN32_BINDINGS = _Win32API()
    return _WIN32_BINDINGS


def _enumerate_windows_modules() -> tuple[LoadedHookModule, ...]:
    api = _win32()
    capacity = 256
    handles: Any = None
    count = 0
    while capacity <= _MAX_LIVE_MODULES:
        handles = (api.wintypes.HMODULE * capacity)()
        needed = api.wintypes.DWORD()
        api.ctypes.set_last_error(0)
        ok = api.psapi.EnumProcessModulesEx(
            api.process,
            handles,
            api.ctypes.sizeof(handles),
            api.ctypes.byref(needed),
            _LIST_MODULES_ALL,
        )
        if not ok:
            raise _last_win32_error("EnumProcessModulesEx")
        count = (needed.value + api.ctypes.sizeof(api.wintypes.HMODULE) - 1) // (
            api.ctypes.sizeof(api.wintypes.HMODULE)
        )
        if count <= capacity:
            break
        capacity = max(capacity * 2, count)
    else:
        raise HookTargetResolutionError(
            f"current process has more than {_MAX_LIVE_MODULES} modules"
        )
    if handles is None or count <= 0:
        raise HookTargetResolutionError(
            "EnumProcessModulesEx returned no current-process modules"
        )
    modules: list[LoadedHookModule] = []
    for raw_handle in handles[:count]:
        handle = _pointer_value(raw_handle)
        if handle <= 0:
            raise HookTargetResolutionError(
                "EnumProcessModulesEx returned a null module handle"
            )
        info = api.module_info_type()
        api.ctypes.set_last_error(0)
        if not api.psapi.GetModuleInformation(
            api.process,
            raw_handle,
            api.ctypes.byref(info),
            api.ctypes.sizeof(info),
        ):
            raise _last_win32_error(
                f"GetModuleInformation(0x{handle:x})"
            )
        path_buffer = api.ctypes.create_unicode_buffer(_MAX_PATH_CHARS)
        api.ctypes.set_last_error(0)
        path_length = api.psapi.GetModuleFileNameExW(
            api.process,
            raw_handle,
            path_buffer,
            len(path_buffer),
        )
        if not path_length:
            raise _last_win32_error(
                f"GetModuleFileNameExW(0x{handle:x})"
            )
        if path_length >= len(path_buffer) - 1:
            raise HookTargetResolutionError(
                f"loaded module path at 0x{handle:x} exceeds the supported length"
            )
        path = Path(path_buffer.value).resolve()
        base = _pointer_value(info.lpBaseOfDll)
        size_of_image = int(info.SizeOfImage)
        if base <= 0 or size_of_image <= 0 or size_of_image > _MAX_MODULE_SIZE:
            raise HookTargetResolutionError(
                f"loaded module {path} has an invalid image range"
            )
        entry_point_value = _pointer_value(info.EntryPoint)
        modules.append(
            LoadedHookModule(
                name=path.name,
                path=path,
                base=base,
                size_of_image=size_of_image,
                entry_point=entry_point_value or None,
            )
        )
    modules.sort(key=lambda item: item.base)
    duplicate_bases = [
        left.base
        for left, right in zip(modules, modules[1:])
        if left.base == right.base
    ]
    if duplicate_bases:
        raise HookTargetResolutionError(
            "current-process module snapshot contains duplicate loader bases"
        )
    return tuple(modules)


def _windows_get_proc_address(
    module_handle: int,
    *,
    symbol: str | None,
    ordinal: int | None,
) -> int:
    api = _win32()
    if symbol is not None:
        try:
            encoded = symbol.encode("ascii", errors="strict")
        except UnicodeEncodeError as exc:
            raise HookTargetResolutionError(
                "PE export names must be ASCII"
            ) from exc
        name_pointer = api.ctypes.c_char_p(encoded)
        argument = api.ctypes.cast(name_pointer, api.ctypes.c_void_p)
    elif ordinal is not None:
        if not 1 <= ordinal <= 0xFFFF:
            raise HookTargetResolutionError("PE export ordinal is out of range")
        argument = api.ctypes.c_void_p(ordinal)
    else:
        raise HookTargetResolutionError("GetProcAddress requires a name or ordinal")
    api.ctypes.set_last_error(0)
    address = api.kernel32.GetProcAddress(module_handle, argument)
    if not address:
        label = symbol if symbol is not None else f"#{ordinal}"
        raise _last_win32_error(f"GetProcAddress({label})")
    return _pointer_value(address)


def _parse_pe_import_evidence(module: PEHookModule) -> list[PEImportEvidence]:
    data = module.path.read_bytes()
    pe_offset = _u32(data, 0x3C, "DOS e_lfanew")
    coff = pe_offset + 4
    optional_size = _u16(data, coff + 16, "COFF optional-header size")
    optional = coff + 20
    magic = _u16(data, optional, "optional-header magic")
    if magic == 0x10B:
        pointer_size = 4
        directory_count_offset = optional + 92
        directory_offset = optional + 96
    elif magic == 0x20B:
        pointer_size = 8
        directory_count_offset = optional + 108
        directory_offset = optional + 112
    else:  # inspect_hook_module already rejects this, retain a local invariant.
        raise HookTargetResolutionError(
            f"unsupported PE optional-header magic 0x{magic:04x}"
        )
    optional_end = optional + optional_size
    if directory_count_offset + 4 > optional_end:
        raise HookTargetResolutionError("PE optional header omits NumberOfRvaAndSizes")
    directory_count = _u32(data, directory_count_offset, "NumberOfRvaAndSizes")
    if directory_count <= 1:
        return []
    import_entry = directory_offset + 8
    if import_entry + 8 > optional_end:
        raise HookTargetResolutionError("PE import data directory exceeds the optional header")
    import_rva = _u32(data, import_entry, "import directory RVA")
    import_size = _u32(data, import_entry + 4, "import directory size")
    if import_rva == 0 and import_size == 0:
        return []
    if import_rva == 0 or import_size < 20:
        raise HookTargetResolutionError("PE import directory is incomplete")
    if import_rva + import_size > module.size_of_image:
        raise HookTargetResolutionError("PE import directory exceeds SizeOfImage")

    results: list[PEImportEvidence] = []
    cursor = import_rva
    end = import_rva + import_size
    descriptor_count = 0
    terminated = False
    while cursor + 20 <= end:
        descriptor_offset = _rva_file_offset(module, cursor, 20)
        descriptor = struct.unpack_from("<IIIII", data, descriptor_offset)
        original_thunk, timestamp, forwarder_chain, name_rva, first_thunk = descriptor
        cursor += 20
        if not any(descriptor):
            terminated = True
            break
        descriptor_count += 1
        if descriptor_count > _MAX_IMPORT_MODULES:
            raise HookTargetResolutionError("PE import module count exceeds the supported limit")
        if not name_rva or not first_thunk:
            raise HookTargetResolutionError(
                "PE import descriptor is missing Name or FirstThunk"
            )
        imported_module = _read_ascii_rva(
            data,
            module,
            name_rva,
            label="import module name",
            maximum=260,
        )
        if any(character in imported_module for character in ("/", "\\", ":")):
            raise HookTargetResolutionError(
                f"import module is not a bare DLL name: {imported_module!r}"
            )
        lookup_table = original_thunk or first_thunk
        ordinal_flag = 1 << (pointer_size * 8 - 1)
        value_mask = ordinal_flag - 1
        index = 0
        while True:
            if len(results) >= _MAX_IMPORT_SYMBOLS:
                raise HookTargetResolutionError(
                    "PE import symbol count exceeds the supported limit"
                )
            lookup_rva = lookup_table + index * pointer_size
            iat_rva = first_thunk + index * pointer_size
            lookup_offset = _rva_file_offset(module, lookup_rva, pointer_size)
            _rva_file_offset(module, iat_rva, pointer_size)
            value = (
                _u32(data, lookup_offset, "PE32 import lookup thunk")
                if pointer_size == 4
                else _u64(data, lookup_offset, "PE32+ import lookup thunk")
            )
            if value == 0:
                break
            if value & ordinal_flag:
                ordinal = value & 0xFFFF
                if not ordinal or value & value_mask != ordinal:
                    raise HookTargetResolutionError("PE import-by-ordinal thunk is invalid")
                results.append(
                    PEImportEvidence(
                        imported_module=imported_module,
                        iat_rva=iat_rva,
                        lookup_rva=lookup_rva,
                        index=index,
                        pointer_size=pointer_size,
                        descriptor_timestamp=timestamp,
                        ordinal=ordinal,
                    )
                )
            else:
                name_entry_rva = value & value_mask
                hint_offset = _rva_file_offset(module, name_entry_rva, 2)
                hint = _u16(data, hint_offset, "import hint")
                import_name = _read_ascii_rva(
                    data,
                    module,
                    name_entry_rva + 2,
                    label="import symbol name",
                    maximum=_MAX_IMPORT_NAME_BYTES,
                )
                results.append(
                    PEImportEvidence(
                        imported_module=imported_module,
                        iat_rva=iat_rva,
                        lookup_rva=lookup_rva,
                        index=index,
                        pointer_size=pointer_size,
                        descriptor_timestamp=timestamp,
                        symbol=import_name,
                        hint=hint,
                    )
                )
            index += 1
            if index >= _MAX_IMPORT_SYMBOLS:
                raise HookTargetResolutionError(
                    "PE import thunk table is not null-terminated within the supported limit"
                )
        if forwarder_chain not in {0, 0xFFFFFFFF}:
            # Preserve valid legacy metadata without pretending it affects slot identity.
            pass
    if not terminated:
        raise HookTargetResolutionError(
            "PE import descriptor table is not null-terminated within its directory"
        )
    return results


def _rva_file_offset(module: PEHookModule, rva: int, size: int) -> int:
    if rva < 0 or size <= 0 or rva + size > module.size_of_image:
        raise HookTargetResolutionError(
            f"RVA 0x{rva:x}+{size} is outside the PE image"
        )
    if rva < module.size_of_headers:
        if rva + size > module.size_of_headers or rva + size > module.file_size:
            raise HookTargetResolutionError(
                f"RVA 0x{rva:x}+{size} exceeds the PE headers"
            )
        return rva
    section = module.section_for_rva(rva, size)
    if section is None:
        raise HookTargetResolutionError(
            f"RVA 0x{rva:x}+{size} is not mapped by a PE section"
        )
    offset = section.file_offset(rva, size)
    if offset is None or offset + size > module.file_size:
        raise HookTargetResolutionError(
            f"RVA 0x{rva:x}+{size} is not backed by the PE file"
        )
    return offset


def _read_ascii_rva(
    data: bytes,
    module: PEHookModule,
    rva: int,
    *,
    label: str,
    maximum: int,
) -> str:
    offset = _rva_file_offset(module, rva, 1)
    end_limit = min(len(data), offset + maximum + 1)
    end = data.find(b"\0", offset, end_limit)
    if end < 0:
        raise HookTargetResolutionError(
            f"{label} is not null-terminated within {maximum} bytes"
        )
    raw = data[offset:end]
    if not raw:
        raise HookTargetResolutionError(f"{label} is empty")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HookTargetResolutionError(f"{label} is not ASCII") from exc


def _last_win32_error(operation: str) -> HookTargetResolutionError:
    api = _WIN32_BINDINGS
    if api is None:
        return HookTargetResolutionError(f"{operation} failed")
    code = int(api.ctypes.get_last_error())
    detail = api.ctypes.FormatError(code).strip() if code else "unknown Win32 error"
    return HookTargetResolutionError(
        f"{operation} failed with Win32 error {code}: {detail}"
    )


def _pointer_value(value: Any) -> int:
    if value is None:
        return 0
    raw = getattr(value, "value", value)
    return int(raw or 0)


def _parse_pattern(value: Any, explicit_mask: Any) -> tuple[bytes, bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        pattern = bytes(value)
        mask = _mask_bytes(explicit_mask, len(pattern)) if explicit_mask is not None else b"\x01" * len(pattern)
    elif isinstance(value, str):
        tokens = value.strip().split()
        if not tokens:
            raise HookTargetResolutionError("pattern must not be empty")
        values: list[int] = []
        masks: list[int] = []
        for token in tokens:
            if token in {"?", "??", "*"}:
                values.append(0)
                masks.append(0)
                continue
            if not re.fullmatch(r"[0-9A-Fa-f]{2}", token):
                raise HookTargetResolutionError(f"invalid pattern token: {token}")
            values.append(int(token, 16))
            masks.append(1)
        pattern = bytes(values)
        mask = bytes(masks)
        if explicit_mask is not None:
            mask = _mask_bytes(explicit_mask, len(pattern))
    else:
        raise HookTargetResolutionError("pattern must be bytes or space-separated hexadecimal")
    if not 1 <= len(pattern) <= _MAX_PATTERN_BYTES:
        raise HookTargetResolutionError(f"pattern length must be from 1 to {_MAX_PATTERN_BYTES}")
    if not any(mask):
        raise HookTargetResolutionError("pattern must contain at least one exact byte")
    return pattern, mask


def _mask_bytes(value: Any, length: int) -> bytes:
    if isinstance(value, str):
        normalized = value.strip().replace(" ", "")
        if len(normalized) != length or any(item not in "xX?*" for item in normalized):
            raise HookTargetResolutionError("pattern mask must contain one x/? character per byte")
        return bytes(1 if item in "xX" else 0 for item in normalized)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) != length:
            raise HookTargetResolutionError("pattern mask length does not match the pattern")
        return bytes(1 if bool(item) else 0 for item in value)
    raise HookTargetResolutionError("pattern mask must be a string or boolean sequence")


def _pattern_offsets(data: bytes, pattern: bytes, mask: bytes) -> list[int]:
    limit = len(data) - len(pattern) + 1
    if limit <= 0:
        return []
    anchor = next(index for index, exact in enumerate(mask) if exact)
    expected = pattern[anchor]
    return [
        offset
        for offset in range(limit)
        if data[offset + anchor] == expected
        and all(not mask[index] or data[offset + index] == byte for index, byte in enumerate(pattern))
    ]


def _format_pattern(pattern: bytes, mask: bytes) -> str:
    return " ".join(f"{byte:02X}" if mask[index] else "??" for index, byte in enumerate(pattern))


def _machine_architecture(machine: int, *, bits: int) -> str:
    expected = {(0x14C, 32): "x86", (0x8664, 64): "x64", (0x1C4, 32): "arm", (0xAA64, 64): "arm64"}
    architecture = expected.get((machine, bits))
    if architecture is None:
        raise HookTargetResolutionError(f"unsupported or inconsistent PE machine 0x{machine:04x}/{bits}")
    return architecture


def _reject_overlapping_sections(sections: Sequence[PESectionEvidence]) -> None:
    ordered = sorted(sections, key=lambda item: item.virtual_address)
    for left, right in zip(ordered, ordered[1:]):
        if left.virtual_address + left.virtual_extent > right.virtual_address:
            raise HookTargetResolutionError(f"PE sections {left.name} and {right.name} overlap")


def _module_name_matches(value: Any, expected: Any) -> bool:
    left = Path(str(value or "")).name.casefold()
    right = Path(str(expected or "")).name.casefold()
    if not left or not right:
        return False
    return left == right or left.removesuffix(".dll") == right.removesuffix(".dll")


def _strict_int(value: Any, *, minimum: int, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or value is None:
        raise HookTargetResolutionError("required integer value is missing")
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise HookTargetResolutionError(f"invalid integer value: {value!r}") from exc
    if not minimum <= parsed <= maximum:
        raise HookTargetResolutionError(f"integer value {parsed} is outside [{minimum}, {maximum}]")
    return parsed


def _optional_int(value: Any, *, minimum: int) -> int | None:
    return None if value is None else _strict_int(value, minimum=minimum)


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _u16(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise HookTargetResolutionError(f"{label} exceeds the file")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise HookTargetResolutionError(f"{label} exceeds the file")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int, label: str) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise HookTargetResolutionError(f"{label} exceeds the file")
    return struct.unpack_from("<Q", data, offset)[0]


def _failed(method: str, target: str | None, error: str) -> HookTargetResolution:
    return HookTargetResolution(status="failed", method=method, target=target, errors=[error])


__all__ = [
    "HookTargetResolution",
    "HookTargetResolutionError",
    "LoadedHookModule",
    "PEHookModule",
    "PEImportEvidence",
    "PESectionEvidence",
    "common_hook_targets",
    "enumerate_current_process_modules",
    "inspect_hook_module",
    "live_hook_target_capability",
    "plan_live_common_hook_target",
    "resolve_common_hook_target",
    "resolve_live_common_hook_target",
    "write_hook_target_resolution",
]
