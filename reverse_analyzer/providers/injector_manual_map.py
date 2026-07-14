"""Strict PE parsing and the native Win32 manual-map implementation.

The parser intentionally supports a narrow, auditable loader subset.  It is
host-independent so validation can reject unsupported images before any
remote-process mutation occurs.  ``Win32ManualMapper`` is instantiated only by
the real Windows injector backend.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_DLL = 0x2000

IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
IMAGE_DIRECTORY_ENTRY_RESERVED = 15

IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

_DIRECTORY_NAMES = (
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "base_relocation",
    "debug",
    "architecture",
    "global_pointer",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr",
    "reserved",
)
_UNSUPPORTED_DIRECTORIES = {
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: "architecture-specific directory",
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR: "global pointer directory",
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: "load-config initialization",
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: "bound imports",
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: "CLR/.NET image",
    IMAGE_DIRECTORY_ENTRY_RESERVED: "reserved data directory",
}

_DELAY_IMPORT_ATTRIBUTE_RVA = 0x1
_LOADER_SUBSET = "manual_map_v3_x64_tls_unwind"
_LOADER_SUPPORTED_FEATURES = (
    "base relocations (HIGHLOW/DIR64)",
    "target-context normal imports",
    "RVA-based delay imports with eager target-context binding",
    "x64 callback-only TLS process attach/detach lifecycle",
    "x64 RUNTIME_FUNCTION registration with rollback deletion",
    "W^X section protections and instruction-cache flush",
    "DLL_PROCESS_ATTACH/DLL_PROCESS_DETACH entry-point calls",
)
_LOADER_FAIL_CLOSED_FEATURES = (
    "x86 TLS directories and static TLS storage/index initialization",
    "TLS thread attach/detach notifications after mapping",
    "non-x64 exception directories",
    "load-config initialization and Control Flow Guard",
    "architecture/global-pointer directories",
    "bound imports",
    "bound or unloadable delay-import descriptors",
    "CLR/.NET images",
)

_MAX_IMAGE_SIZE = 256 * 1024 * 1024
_MAX_FILE_SIZE = 256 * 1024 * 1024
_MAX_SECTIONS = 96
_MAX_IMPORT_MODULES = 512
_MAX_IMPORT_SYMBOLS = 65536
_MAX_TLS_CALLBACKS = 64
_MAX_RUNTIME_FUNCTIONS = 1_000_000
_MAX_UNWIND_CHAIN_DEPTH = 32
_MAX_STRING = 4096
_PAGE_SIZE = 0x1000


class ManualMapValidationError(ValueError):
    """A PE is malformed or requires unsupported loader behavior."""

    def __init__(self, issues: str | Sequence[str]) -> None:
        self.issues = [str(issues)] if isinstance(issues, str) else [str(item) for item in issues]
        super().__init__("; ".join(self.issues))


class ManualMapBackendError(RuntimeError):
    """A native mapping operation failed with serializable cleanup details."""

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
        payload: dict[str, Any] = {
            "type": type(self).__name__,
            "operation": self.operation,
            "message": self.message,
        }
        if self.code is not None:
            payload["winerror"] = self.code
        if self.details:
            payload["details"] = _json_value(self.details)
        return payload


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "virtual_size": self.virtual_size,
            "raw_offset": self.raw_offset,
            "raw_size": self.raw_size,
            "mapped_size": self.mapped_size,
            "characteristics": self.characteristics,
            "readable": bool(self.characteristics & IMAGE_SCN_MEM_READ),
            "writable": bool(self.characteristics & IMAGE_SCN_MEM_WRITE),
            "executable": bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE),
        }


@dataclass(frozen=True)
class PEImportSymbol:
    iat_rva: int
    name: Optional[str] = None
    ordinal: Optional[int] = None
    hint: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"iat_rva": self.iat_rva}
        if self.name is not None:
            payload["name"] = self.name
            payload["hint"] = self.hint
        if self.ordinal is not None:
            payload["ordinal"] = self.ordinal
        return payload


@dataclass(frozen=True)
class PEImportModule:
    name: str
    symbols: tuple[PEImportSymbol, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "symbol_count": len(self.symbols),
            "by_name": sum(item.name is not None for item in self.symbols),
            "by_ordinal": sum(item.ordinal is not None for item in self.symbols),
        }


@dataclass(frozen=True)
class PEDelayImportModule:
    name: str
    module_handle_rva: int
    iat_rva: int
    name_table_rva: int
    symbols: tuple[PEImportSymbol, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "module_handle_rva": self.module_handle_rva,
            "iat_rva": self.iat_rva,
            "name_table_rva": self.name_table_rva,
            "symbol_count": len(self.symbols),
            "by_name": sum(item.name is not None for item in self.symbols),
            "by_ordinal": sum(item.ordinal is not None for item in self.symbols),
            "binding": "eager_target_context",
        }


@dataclass(frozen=True)
class PERelocation:
    rva: int
    type: int


@dataclass(frozen=True)
class PETLSDirectory:
    directory_rva: int
    directory_size: int
    start_raw_data_va: int
    end_raw_data_va: int
    address_of_index_va: int
    address_of_callbacks_va: int
    callback_array_rva: Optional[int]
    callback_rvas: tuple[int, ...]
    size_of_zero_fill: int
    characteristics: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory_rva": self.directory_rva,
            "directory_size": self.directory_size,
            "start_raw_data_va": self.start_raw_data_va,
            "end_raw_data_va": self.end_raw_data_va,
            "address_of_index_va": self.address_of_index_va,
            "address_of_callbacks_va": self.address_of_callbacks_va,
            "callback_array_rva": self.callback_array_rva,
            "callback_rvas": list(self.callback_rvas),
            "callback_count": len(self.callback_rvas),
            "callback_limit": _MAX_TLS_CALLBACKS,
            "array_null_terminated": True,
            "static_tls": False,
            "size_of_zero_fill": self.size_of_zero_fill,
            "characteristics": self.characteristics,
        }


@dataclass(frozen=True)
class PERuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_info_rva: int

    def to_dict(self) -> dict[str, int]:
        return {
            "begin_rva": self.begin_rva,
            "end_rva": self.end_rva,
            "unwind_info_rva": self.unwind_info_rva,
        }


@dataclass(frozen=True)
class PEImage:
    path: str
    data: bytes = field(repr=False)
    sha256: str
    format: str
    machine: int
    pointer_size: int
    characteristics: int
    dll_characteristics: int
    image_base: int
    entry_point_rva: int
    section_alignment: int
    file_alignment: int
    size_of_image: int
    size_of_headers: int
    sections: tuple[PESection, ...]
    directories: tuple[tuple[int, int], ...]
    imports: tuple[PEImportModule, ...]
    delay_imports: tuple[PEDelayImportModule, ...]
    relocations: tuple[PERelocation, ...]
    tls_directory: Optional[PETLSDirectory]
    runtime_functions: tuple[PERuntimeFunction, ...]
    protection_ranges: tuple[Mapping[str, int], ...]
    ignored_file_directories: tuple[str, ...] = ()

    @property
    def architecture(self) -> str:
        return "x86" if self.machine == IMAGE_FILE_MACHINE_I386 else "x64"

    @property
    def import_symbol_count(self) -> int:
        return sum(len(module.symbols) for module in self.imports)

    @property
    def delay_import_symbol_count(self) -> int:
        return sum(len(module.symbols) for module in self.delay_imports)

    @property
    def tls_callback_count(self) -> int:
        return len(self.tls_directory.callback_rvas) if self.tls_directory is not None else 0

    def to_audit_dict(self) -> dict[str, Any]:
        active_directories = []
        for index, (rva, size) in enumerate(self.directories):
            if not rva and not size:
                continue
            active_directories.append(
                {
                    "index": index,
                    "name": _DIRECTORY_NAMES[index] if index < len(_DIRECTORY_NAMES) else str(index),
                    "rva": rva,
                    "size": size,
                }
            )
        relocation_types = sorted({item.type for item in self.relocations})
        return {
            "ok": True,
            "path": self.path,
            "sha256": self.sha256,
            "format": self.format,
            "machine": self.machine,
            "machine_hex": f"0x{self.machine:04x}",
            "architecture": self.architecture,
            "pointer_size": self.pointer_size,
            "image_base": self.image_base,
            "entry_point_rva": self.entry_point_rva,
            "section_alignment": self.section_alignment,
            "file_alignment": self.file_alignment,
            "size_of_image": self.size_of_image,
            "size_of_headers": self.size_of_headers,
            "sections": [item.to_dict() for item in self.sections],
            "section_count": len(self.sections),
            "directories": active_directories,
            "imports": [item.to_dict() for item in self.imports],
            "import_module_count": len(self.imports),
            "import_symbol_count": self.import_symbol_count,
            "delay_imports": [item.to_dict() for item in self.delay_imports],
            "delay_import_module_count": len(self.delay_imports),
            "delay_import_symbol_count": self.delay_import_symbol_count,
            "total_import_symbol_count": (
                self.import_symbol_count + self.delay_import_symbol_count
            ),
            "relocation_count": len(self.relocations),
            "relocation_types": relocation_types,
            "tls": (
                self.tls_directory.to_dict() if self.tls_directory is not None else None
            ),
            "tls_callback_count": self.tls_callback_count,
            "exception_table": {
                "present": bool(self.runtime_functions),
                "directory_rva": self.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0],
                "directory_size": self.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][1],
                "entry_size": 12,
                "entry_count": len(self.runtime_functions),
                "sorted_and_non_overlapping": bool(self.runtime_functions),
                "registration_required": bool(self.runtime_functions),
            },
            "runtime_function_count": len(self.runtime_functions),
            "protection_ranges": [dict(item) for item in self.protection_ranges],
            "protection_range_count": len(self.protection_ranges),
            "writable_executable_pages": False,
            "ignored_file_directories": list(self.ignored_file_directories),
            "unsupported_features": [],
            "loader_semantics": "partial",
            "loader_coverage": _loader_coverage(),
            "loader_subset": _LOADER_SUBSET,
        }


def inspect_manual_map_image(path_value: str) -> dict[str, Any]:
    """Return a serializable, fail-closed assessment of a candidate DLL."""

    try:
        return parse_manual_map_image(path_value).to_audit_dict()
    except ManualMapValidationError as exc:
        return {
            "ok": False,
            "path": str(path_value or ""),
            "errors": list(exc.issues),
            "unsupported_features": [
                issue.removeprefix("unsupported: ")
                for issue in exc.issues
                if issue.startswith("unsupported: ")
            ],
            "loader_semantics": "partial",
            "loader_coverage": _loader_coverage(),
            "loader_subset": _LOADER_SUBSET,
        }
    except OSError as exc:
        return {
            "ok": False,
            "path": str(path_value or ""),
            "errors": [f"unable to read PE image: {type(exc).__name__}: {exc}"],
            "unsupported_features": [],
            "loader_semantics": "partial",
            "loader_coverage": _loader_coverage(),
            "loader_subset": _LOADER_SUBSET,
        }


def parse_manual_map_image(path_value: str) -> PEImage:
    path = Path(path_value)
    try:
        size = path.stat().st_size
    except OSError:
        raise
    if size > _MAX_FILE_SIZE:
        raise ManualMapValidationError(
            f"PE file exceeds the {_MAX_FILE_SIZE}-byte validation limit"
        )
    return parse_manual_map_bytes(path.read_bytes(), path=str(path))


def parse_manual_map_bytes(data: bytes, *, path: str = "<memory>") -> PEImage:
    """Parse the supported PE loader subset and reject everything else."""

    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ManualMapValidationError("invalid DOS/MZ header")
    pe_offset = _u32(data, 0x3C, "DOS e_lfanew")
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ManualMapValidationError("PE header offset is outside the file")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ManualMapValidationError("invalid PE signature")

    coff = pe_offset + 4
    machine = _u16(data, coff, "COFF machine")
    section_count = _u16(data, coff + 2, "COFF section count")
    optional_size = _u16(data, coff + 16, "COFF optional-header size")
    characteristics = _u16(data, coff + 18, "COFF characteristics")
    if machine not in {IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64}:
        raise ManualMapValidationError(
            f"unsupported: machine type 0x{machine:04x}; only i386 and amd64 are supported"
        )
    if not 1 <= section_count <= _MAX_SECTIONS:
        raise ManualMapValidationError(f"invalid PE section count: {section_count}")
    if not characteristics & IMAGE_FILE_DLL:
        raise ManualMapValidationError("manual_map requires an IMAGE_FILE_DLL image")

    optional = coff + 20
    _require_range(data, optional, optional_size, "optional header")
    magic = _u16(data, optional, "optional-header magic")
    if magic == 0x10B:
        format_name = "PE32"
        pointer_size = 4
        expected_machine = IMAGE_FILE_MACHINE_I386
        minimum_optional_size = 0xE0
        image_base = _u32(data, optional + 28, "PE32 image base")
        directory_count_offset = 92
        directory_offset = 96
    elif magic == 0x20B:
        format_name = "PE32+"
        pointer_size = 8
        expected_machine = IMAGE_FILE_MACHINE_AMD64
        minimum_optional_size = 0xF0
        image_base = _u64(data, optional + 24, "PE32+ image base")
        directory_count_offset = 108
        directory_offset = 112
    else:
        raise ManualMapValidationError(f"unsupported: optional-header magic 0x{magic:04x}")
    if machine != expected_machine:
        raise ManualMapValidationError(
            f"PE format/machine mismatch: {format_name} with machine 0x{machine:04x}"
        )
    if optional_size < minimum_optional_size:
        raise ManualMapValidationError(
            f"optional header is too small for {format_name}: {optional_size}"
        )

    entry_point_rva = _u32(data, optional + 16, "entry-point RVA")
    section_alignment = _u32(data, optional + 32, "section alignment")
    file_alignment = _u32(data, optional + 36, "file alignment")
    size_of_image = _u32(data, optional + 56, "image size")
    size_of_headers = _u32(data, optional + 60, "header size")
    dll_characteristics = _u16(data, optional + 70, "DLL characteristics")
    directory_count = _u32(data, optional + directory_count_offset, "data-directory count")

    issues: list[str] = []
    if not _is_power_of_two(section_alignment) or section_alignment < _PAGE_SIZE:
        issues.append(
            "unsupported: section alignment must be a power of two and at least one page"
        )
    if not _is_power_of_two(file_alignment) or not 0x200 <= file_alignment <= 0x10000:
        issues.append("invalid PE file alignment")
    if not 0 < size_of_image <= _MAX_IMAGE_SIZE:
        issues.append(f"invalid or excessive SizeOfImage: {size_of_image}")
    pointer_max = (1 << (pointer_size * 8)) - 1
    if not image_base or (size_of_image and image_base > pointer_max - (size_of_image - 1)):
        issues.append(f"image VA range overflows {pointer_size * 8}-bit address space")
    if size_of_image and section_alignment and size_of_image % section_alignment:
        issues.append("SizeOfImage is not section-aligned")
    if not 0 < size_of_headers <= len(data) or size_of_headers > size_of_image:
        issues.append("SizeOfHeaders is outside the file or image")
    if size_of_headers and file_alignment and size_of_headers % file_alignment:
        issues.append("SizeOfHeaders is not file-aligned")
    if dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF:
        issues.append("unsupported: Control Flow Guard images require load-config processing")

    directory_total = min(directory_count, 16)
    if optional_size < directory_offset + directory_total * 8:
        issues.append("data-directory table exceeds the optional header")
        directory_total = max(0, (optional_size - directory_offset) // 8)
    directories: list[tuple[int, int]] = [(0, 0)] * 16
    for index in range(directory_total):
        entry = optional + directory_offset + index * 8
        directories[index] = (
            _u32(data, entry, f"data directory {index} RVA"),
            _u32(data, entry + 4, f"data directory {index} size"),
        )

    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise ManualMapValidationError("section table exceeds the file")
    sections: list[PESection] = []
    virtual_ranges: list[tuple[int, int, str]] = []
    raw_ranges: list[tuple[int, int, str]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
        virtual_size = _u32(data, offset + 8, f"{name} virtual size")
        virtual_address = _u32(data, offset + 12, f"{name} RVA")
        raw_size = _u32(data, offset + 16, f"{name} raw size")
        raw_offset = _u32(data, offset + 20, f"{name} raw offset")
        section_characteristics = _u32(data, offset + 36, f"{name} characteristics")
        section = PESection(
            name=name,
            virtual_address=virtual_address,
            virtual_size=virtual_size,
            raw_offset=raw_offset,
            raw_size=raw_size,
            characteristics=section_characteristics,
        )
        mapped_size = section.mapped_size
        if mapped_size:
            if section_alignment and virtual_address % section_alignment:
                issues.append(f"section {name} RVA is not section-aligned")
            if virtual_address < size_of_headers or virtual_address + mapped_size > size_of_image:
                issues.append(f"section {name} mapped range is outside SizeOfImage")
            else:
                virtual_ranges.append((virtual_address, virtual_address + mapped_size, name))
        if raw_size:
            if file_alignment and raw_offset % file_alignment:
                issues.append(f"section {name} raw offset is not file-aligned")
            if raw_offset < size_of_headers or raw_offset + raw_size > len(data):
                issues.append(f"section {name} raw range is outside the file")
            else:
                raw_ranges.append((raw_offset, raw_offset + raw_size, name))
        if section_characteristics & IMAGE_SCN_MEM_SHARED:
            issues.append(f"unsupported: shared section {name}")
        if (
            section_characteristics & IMAGE_SCN_MEM_EXECUTE
            and section_characteristics & IMAGE_SCN_MEM_WRITE
        ):
            issues.append(f"unsupported: writable executable section {name}")
        sections.append(section)

    issues.extend(_overlap_issues(virtual_ranges, "virtual"))
    issues.extend(_overlap_issues(raw_ranges, "raw"))
    for index, label in _UNSUPPORTED_DIRECTORIES.items():
        rva, size = directories[index]
        if rva or size:
            issues.append(f"unsupported: {label} is present")
    exception_rva, exception_size = directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    if machine != IMAGE_FILE_MACHINE_AMD64 and (exception_rva or exception_size):
        issues.append("unsupported: non-x64 exception directory is present")
    tls_rva, tls_size = directories[IMAGE_DIRECTORY_ENTRY_TLS]
    if machine != IMAGE_FILE_MACHINE_AMD64 and (tls_rva or tls_size):
        issues.append("unsupported: x86 TLS directories are not implemented")
    for index, (rva, size) in enumerate(directories):
        if not rva and not size:
            continue
        if bool(rva) != bool(size):
            issues.append(f"data directory {_DIRECTORY_NAMES[index]} has an incomplete range")
            continue
        if index == IMAGE_DIRECTORY_ENTRY_SECURITY:
            if rva + size > len(data):
                issues.append("security directory is outside the file")
        elif rva + size > size_of_image:
            issues.append(f"data directory {_DIRECTORY_NAMES[index]} is outside SizeOfImage")

    if issues:
        raise ManualMapValidationError(_deduplicate(issues))

    mapped = _map_image_bytes(data, size_of_image, size_of_headers, sections)
    tls_directory = _parse_tls_directory(
        mapped,
        directories[IMAGE_DIRECTORY_ENTRY_TLS],
        image_base,
        size_of_image,
        sections,
        machine,
    )
    runtime_functions = _parse_runtime_functions(
        mapped,
        directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION],
        size_of_image,
        sections,
        machine,
    )
    imports = _parse_imports(mapped, directories[IMAGE_DIRECTORY_ENTRY_IMPORT], pointer_size)
    delay_imports = _parse_delay_imports(
        mapped,
        directories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT],
        pointer_size,
    )
    _validate_import_storage(imports, delay_imports, pointer_size)
    relocations = _parse_relocations(
        mapped,
        directories[IMAGE_DIRECTORY_ENTRY_BASERELOC],
        machine,
    )
    if characteristics & IMAGE_FILE_RELOCS_STRIPPED and relocations:
        raise ManualMapValidationError("relocations are marked stripped but a relocation table exists")
    if entry_point_rva:
        entry_section = _section_for_rva(sections, entry_point_rva)
        if entry_section is None:
            raise ManualMapValidationError("entry point is not contained in a section")
        if not entry_section.characteristics & IMAGE_SCN_MEM_EXECUTE:
            raise ManualMapValidationError("entry point is not in an executable section")

    protection_ranges = _build_page_protection_plan(size_of_image, size_of_headers, sections)
    ignored = ()
    security_rva, security_size = directories[IMAGE_DIRECTORY_ENTRY_SECURITY]
    if security_rva and security_size:
        ignored = ("security (file-only Authenticode data)",)
    return PEImage(
        path=path,
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        format=format_name,
        machine=machine,
        pointer_size=pointer_size,
        characteristics=characteristics,
        dll_characteristics=dll_characteristics,
        image_base=image_base,
        entry_point_rva=entry_point_rva,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        sections=tuple(sections),
        directories=tuple(directories),
        imports=tuple(imports),
        delay_imports=tuple(delay_imports),
        relocations=tuple(relocations),
        tls_directory=tls_directory,
        runtime_functions=tuple(runtime_functions),
        protection_ranges=tuple(protection_ranges),
        ignored_file_directories=ignored,
    )


def map_image_bytes(image: PEImage) -> bytearray:
    """Construct the zero-filled virtual image before relocations/imports."""

    return _map_image_bytes(
        image.data,
        image.size_of_image,
        image.size_of_headers,
        image.sections,
    )


def apply_base_relocations(
    image: PEImage,
    mapped: bytearray,
    remote_base: int,
) -> dict[str, Any]:
    """Apply every validated relocation to a local mapped-image buffer."""

    delta = int(remote_base) - int(image.image_base)
    if not delta:
        return {
            "required": False,
            "delta": 0,
            "available_count": len(image.relocations),
            "applied_count": 0,
            "complete": True,
            "types": sorted({item.type for item in image.relocations}),
        }
    if not image.relocations:
        raise ManualMapBackendError(
            "base_relocations",
            "preferred image base was unavailable and the image has no relocations",
            details={"preferred_base": image.image_base, "actual_base": remote_base, "delta": delta},
        )
    applied = 0
    mask = (1 << (image.pointer_size * 8)) - 1
    for relocation in image.relocations:
        if relocation.type == IMAGE_REL_BASED_HIGHLOW:
            current = _buffer_u32(mapped, relocation.rva, "HIGHLOW relocation target")
            relocated = current + delta
            if not 0 <= relocated <= mask:
                raise ManualMapBackendError(
                    "base_relocations",
                    "HIGHLOW relocation value overflows the 32-bit address space",
                    details={"rva": relocation.rva, "value": current, "delta": delta},
                )
            struct.pack_into("<I", mapped, relocation.rva, relocated)
        elif relocation.type == IMAGE_REL_BASED_DIR64:
            current = _buffer_u64(mapped, relocation.rva, "DIR64 relocation target")
            relocated = current + delta
            if not 0 <= relocated <= mask:
                raise ManualMapBackendError(
                    "base_relocations",
                    "DIR64 relocation value overflows the 64-bit address space",
                    details={"rva": relocation.rva, "value": current, "delta": delta},
                )
            struct.pack_into("<Q", mapped, relocation.rva, relocated)
        else:  # The parser rejects unknown types; keep execution independently fail-closed.
            raise ManualMapBackendError(
                "base_relocations",
                f"unsupported relocation type {relocation.type}",
                details={"rva": relocation.rva},
            )
        applied += 1
    return {
        "required": True,
        "delta": delta,
        "available_count": len(image.relocations),
        "applied_count": applied,
        "complete": applied == len(image.relocations),
        "types": sorted({item.type for item in image.relocations}),
    }


def _plan_tls_callbacks(
    image: PEImage,
    mapped: bytes | bytearray,
    remote_base: int,
) -> dict[str, Any]:
    tls = image.tls_directory
    evidence: dict[str, Any] = {
        "directory_present": tls is not None,
        "required": bool(tls and tls.callback_rvas),
        "complete": not bool(tls and tls.callback_rvas),
        "callback_count": len(tls.callback_rvas) if tls is not None else 0,
        "callback_limit": _MAX_TLS_CALLBACKS,
        "attach_completed_count": 0,
        "array_null_terminated": True,
        "address_translation": "preferred image VA -> image RVA -> remote image base + RVA",
        "callbacks": [],
    }
    if tls is None:
        return evidence
    if image.machine != IMAGE_FILE_MACHINE_AMD64 or image.pointer_size != 8:
        raise ManualMapBackendError(
            "tls_callback_plan",
            "TLS callback execution is limited to validated PE32+/x64 images",
        )
    if tls.callback_array_rva is None:
        if tls.callback_rvas:
            raise ManualMapBackendError(
                "tls_callback_plan",
                "TLS callbacks exist without a callback-array RVA",
            )
        return evidence

    callback_array_address = _checked_remote_address(
        remote_base,
        tls.callback_array_rva,
        image.pointer_size,
        "remote TLS callback array",
    )
    relocated_array_address = _buffer_u64(
        mapped,
        tls.directory_rva + 24,
        "relocated TLS AddressOfCallbacks",
    )
    if relocated_array_address != callback_array_address:
        raise ManualMapBackendError(
            "tls_callback_plan",
            "TLS AddressOfCallbacks was not relocated to the remote image",
            details={
                "field_rva": tls.directory_rva + 24,
                "expected": callback_array_address,
                "actual": relocated_array_address,
            },
        )

    callbacks: list[dict[str, Any]] = []
    for index, callback_rva in enumerate(tls.callback_rvas):
        callback_address = _checked_remote_address(
            remote_base,
            callback_rva,
            image.pointer_size,
            f"remote TLS callback {index + 1}",
        )
        slot_rva = tls.callback_array_rva + index * image.pointer_size
        relocated_callback = _buffer_u64(mapped, slot_rva, "relocated TLS callback")
        if relocated_callback != callback_address:
            raise ManualMapBackendError(
                "tls_callback_plan",
                f"TLS callback {index + 1} was not relocated to the remote image",
                details={
                    "slot_rva": slot_rva,
                    "expected": callback_address,
                    "actual": relocated_callback,
                },
            )
        callbacks.append(
            {
                "sequence": index + 1,
                "rva": callback_rva,
                "address": callback_address,
                "attach_completed": False,
            }
        )
    terminator_rva = tls.callback_array_rva + len(callbacks) * image.pointer_size
    if _buffer_u64(mapped, terminator_rva, "relocated TLS callback terminator"):
        raise ManualMapBackendError(
            "tls_callback_plan",
            "relocated TLS callback array lost its null terminator",
        )
    evidence["callback_array_rva"] = tls.callback_array_rva
    evidence["callback_array_address"] = callback_array_address
    evidence["callbacks"] = callbacks
    return evidence


def _checked_pointer_value(value: Any, pointer_size: int, label: str) -> int:
    try:
        address = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ManualMapBackendError(
            "address_validation",
            f"{label} is not an integer address",
        ) from exc
    maximum = (1 << (pointer_size * 8)) - 1
    if not 0 < address <= maximum:
        raise ManualMapBackendError(
            "address_validation",
            f"{label} is outside the {pointer_size * 8}-bit address space",
            details={"address": address},
        )
    return address


def _checked_remote_address(
    image_base: int,
    rva: int,
    pointer_size: int,
    label: str,
) -> int:
    base = _checked_pointer_value(image_base, pointer_size, "remote image base")
    maximum = (1 << (pointer_size * 8)) - 1
    if rva < 0 or rva > maximum - base:
        raise ManualMapBackendError(
            "address_validation",
            f"{label} overflows the {pointer_size * 8}-bit address space",
            details={"image_base": base, "rva": rva},
        )
    return base + rva


def _checked_remote_range(
    address: Any,
    size: Any,
    pointer_size: int,
    label: str,
) -> tuple[int, int]:
    base = _checked_pointer_value(address, pointer_size, f"{label} base")
    try:
        length = int(size)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ManualMapBackendError(
            "address_validation",
            f"{label} size is not an integer",
        ) from exc
    maximum = (1 << (pointer_size * 8)) - 1
    if length <= 0 or length - 1 > maximum - base:
        raise ManualMapBackendError(
            "address_validation",
            f"{label} range overflows the {pointer_size * 8}-bit address space",
            details={"address": base, "size": length},
        )
    return base, base + length


def _require_completed_remote_call(
    value: Any,
    operation: str,
    pointer_size: int,
) -> tuple[Mapping[str, Any], int]:
    if not isinstance(value, Mapping):
        raise ManualMapBackendError(
            operation,
            "remote call returned invalid audit evidence",
        )
    if value.get("completed") is not True:
        raise ManualMapBackendError(
            operation,
            "remote call did not complete",
            details={
                "completed": value.get("completed"),
                "thread_id": value.get("thread_id"),
            },
        )
    try:
        result = int(value["result"])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ManualMapBackendError(
            operation,
            "remote call omitted an integer result",
        ) from exc
    maximum = (1 << (pointer_size * 8)) - 1
    if not 0 <= result <= maximum:
        raise ManualMapBackendError(
            operation,
            f"remote call result exceeds {pointer_size * 8} bits",
            details={"result": result},
        )
    return value, result


def _pointer_size_for_architecture(architecture: str) -> int:
    if architecture == "x86":
        return 4
    if architecture == "x64":
        return 8
    raise ManualMapValidationError(f"unsupported rollback architecture {architecture!r}")


def _validate_rollback_tls_callbacks(
    value: Any,
    image_base: int,
    image_size: int,
    architecture: str,
) -> list[dict[str, int]]:
    if value in (None, []):
        return []
    if not isinstance(value, (list, tuple)):
        raise ManualMapValidationError("TLS callback rollback data is not a list")
    if architecture != "x64":
        raise ManualMapValidationError("TLS callback rollback data requires x64")
    if len(value) > _MAX_TLS_CALLBACKS:
        raise ManualMapValidationError("TLS callback rollback count exceeds the limit")
    callbacks: list[dict[str, int]] = []
    previous_sequence = 0
    for item in value:
        if not isinstance(item, Mapping):
            raise ManualMapValidationError("TLS callback rollback entry is not an object")
        sequence = int(item.get("sequence") or 0)
        rva = int(item.get("rva") or 0)
        if item.get("attach_completed") is not True:
            raise ManualMapValidationError("TLS callback rollback entry was not attached")
        if (
            not previous_sequence < sequence <= _MAX_TLS_CALLBACKS
            or not 0 < rva < image_size
        ):
            raise ManualMapValidationError("TLS callback rollback sequence or RVA is invalid")
        callbacks.append(
            {
                "sequence": sequence,
                "rva": rva,
                "address": _checked_remote_address(
                    image_base,
                    rva,
                    8,
                    f"rollback TLS callback {sequence}",
                ),
            }
        )
        previous_sequence = sequence
    return callbacks


def _validate_rollback_function_table(
    value: Any,
    image_base: int,
    image_size: int,
    architecture: str,
) -> dict[str, Any]:
    if value is None:
        return {"registered": False}
    if not isinstance(value, Mapping):
        raise ManualMapValidationError("function-table rollback data is not an object")
    registered = value.get("registered")
    if registered is False:
        return {"registered": False}
    if registered is not True:
        raise ManualMapValidationError("function-table rollback registration state is invalid")
    if architecture != "x64":
        raise ManualMapValidationError("registered function-table rollback data requires x64")
    table_rva = int(value.get("table_rva") or 0)
    table_address = int(value.get("table_address") or 0)
    entry_count = int(value.get("entry_count") or 0)
    if not 0 < entry_count <= _MAX_RUNTIME_FUNCTIONS:
        raise ManualMapValidationError("function-table rollback entry count is invalid")
    table_size = entry_count * 12
    if table_rva % 4 or not 0 < table_rva <= image_size - table_size:
        raise ManualMapValidationError("function-table rollback range is outside the image")
    expected_address = _checked_remote_address(
        image_base,
        table_rva,
        8,
        "rollback RUNTIME_FUNCTION table",
    )
    if table_address != expected_address:
        raise ManualMapValidationError("function-table rollback address does not match its RVA")
    delete_function_address = int(value.get("delete_function_address") or 0)
    if delete_function_address:
        delete_function_address = _checked_pointer_value(
            delete_function_address,
            8,
            "rollback RtlDeleteFunctionTable",
        )
    return {
        "registered": True,
        "table_rva": table_rva,
        "table_address": table_address,
        "entry_count": entry_count,
        "delete_function_address": delete_function_address,
    }


def _validate_rollback_dependencies(
    value: Any,
    pointer_size: int,
) -> list[dict[str, Any]]:
    if value in (None, []):
        return []
    if not isinstance(value, (list, tuple)):
        raise ManualMapValidationError("dependency rollback data is not a list")
    if len(value) > _MAX_IMPORT_MODULES * 2:
        raise ManualMapValidationError("dependency rollback count exceeds the limit")

    dependencies: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping):
            raise ManualMapValidationError("dependency rollback entry is not an object")
        name = item.get("name")
        if not isinstance(name, str) or not name or len(name) > _MAX_STRING:
            raise ManualMapValidationError("dependency rollback module name is invalid")
        folded_name = name.casefold()
        if folded_name in names:
            raise ManualMapValidationError("dependency rollback module names are duplicated")
        names.add(folded_name)

        reference_added = item.get("reference_added")
        if reference_added is not True and reference_added is not False:
            raise ManualMapValidationError("dependency rollback reference state is invalid")
        handle = int(item.get("handle") or 0)
        if reference_added:
            handle = _checked_pointer_value(
                handle,
                pointer_size,
                f"rollback dependency {name} handle",
            )
        elif handle:
            handle = _checked_pointer_value(
                handle,
                pointer_size,
                f"rollback dependency {name} handle",
            )
        dependencies.append(
            {
                **dict(item),
                "name": name,
                "handle": handle,
                "reference_added": reference_added,
            }
        )
    return dependencies


def bind_imports(
    image: PEImage,
    mapped: bytearray,
    resolver: Callable[[str, Optional[str], Optional[int]], int],
) -> dict[str, Any]:
    """Resolve and write every IAT slot through a target-context resolver."""

    resolved = 0
    module_records: list[dict[str, Any]] = []
    pointer_format = "<I" if image.pointer_size == 4 else "<Q"
    pointer_limit = (1 << (image.pointer_size * 8)) - 1
    for module in image.imports:
        module_count = 0
        for symbol in module.symbols:
            address = int(resolver(module.name, symbol.name, symbol.ordinal))
            if not 0 < address <= pointer_limit:
                identity = symbol.name if symbol.name is not None else f"#{symbol.ordinal}"
                raise ManualMapBackendError(
                    "import_resolution",
                    f"resolver returned an invalid address for {module.name}!{identity}",
                    details={"address": address},
                )
            _require_buffer_range(mapped, symbol.iat_rva, image.pointer_size, "IAT slot")
            struct.pack_into(pointer_format, mapped, symbol.iat_rva, address)
            resolved += 1
            module_count += 1
        module_records.append({"name": module.name, "resolved_count": module_count})
    return {
        "module_count": len(image.imports),
        "expected_count": image.import_symbol_count,
        "resolved_count": resolved,
        "complete": resolved == image.import_symbol_count,
        "modules": module_records,
    }


def bind_delay_imports(
    image: PEImage,
    mapped: bytearray,
    module_loader: Callable[[str], int],
    resolver: Callable[[str, Optional[str], Optional[int]], int],
) -> dict[str, Any]:
    """Eagerly bind the validated delay-IAT subset into a mapped image.

    The production mapper invokes both callbacks in the target process.  Eager
    binding intentionally bypasses the compiler delay helper: every delay IAT
    slot and its descriptor's HMODULE cache are populated before the image is
    made executable or ``DllMain`` runs.
    """

    resolved = 0
    handles_written = 0
    module_records: list[dict[str, Any]] = []
    pointer_format = "<I" if image.pointer_size == 4 else "<Q"
    pointer_limit = (1 << (image.pointer_size * 8)) - 1
    for module in image.delay_imports:
        module_handle = int(module_loader(module.name))
        if not 0 < module_handle <= pointer_limit:
            raise ManualMapBackendError(
                "delay_import_resolution",
                f"loader returned an invalid module handle for {module.name}",
                details={"handle": module_handle},
            )
        _require_buffer_range(
            mapped,
            module.module_handle_rva,
            image.pointer_size,
            "delay-import module handle slot",
        )
        struct.pack_into(pointer_format, mapped, module.module_handle_rva, module_handle)
        handles_written += 1

        module_count = 0
        for symbol in module.symbols:
            address = int(resolver(module.name, symbol.name, symbol.ordinal))
            if not 0 < address <= pointer_limit:
                identity = symbol.name if symbol.name is not None else f"#{symbol.ordinal}"
                raise ManualMapBackendError(
                    "delay_import_resolution",
                    f"resolver returned an invalid address for {module.name}!{identity}",
                    details={"address": address},
                )
            _require_buffer_range(mapped, symbol.iat_rva, image.pointer_size, "delay IAT slot")
            struct.pack_into(pointer_format, mapped, symbol.iat_rva, address)
            resolved += 1
            module_count += 1
        module_records.append(
            {
                "name": module.name,
                "module_handle": module_handle,
                "module_handle_rva": module.module_handle_rva,
                "module_handle_written": True,
                "resolved_count": module_count,
            }
        )
    return {
        "strategy": "eager_target_context",
        "module_count": len(image.delay_imports),
        "expected_count": image.delay_import_symbol_count,
        "resolved_count": resolved,
        "module_handle_slots_expected": len(image.delay_imports),
        "module_handle_slots_written": handles_written,
        "complete": (
            resolved == image.delay_import_symbol_count
            and handles_written == len(image.delay_imports)
        ),
        "modules": module_records,
    }


def _delay_import_storage_matches(
    image: PEImage,
    expected: bytes | bytearray,
    actual: bytes | bytearray,
) -> bool:
    for module in image.delay_imports:
        rvas = [module.module_handle_rva, *(item.iat_rva for item in module.symbols)]
        for rva in rvas:
            _require_buffer_range(expected, rva, image.pointer_size, "delay-import readback")
            _require_buffer_range(actual, rva, image.pointer_size, "delay-import readback")
            expected_value = int.from_bytes(expected[rva : rva + image.pointer_size], "little")
            if not expected_value or (
                expected[rva : rva + image.pointer_size]
                != actual[rva : rva + image.pointer_size]
            ):
                return False
    return True


class Win32ManualMapper:
    """Narrow native mapper built on the real injector backend's Win32 bindings."""

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    MEM_FREE = 0x10000
    PAGE_NOACCESS = 0x01
    PAGE_READONLY = 0x02
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    DLL_PROCESS_DETACH = 0
    DLL_PROCESS_ATTACH = 1

    _IDENTITY_FIELDS = ("pid", "creation_time_100ns", "image_path", "machine")

    def __init__(self, host: Any) -> None:
        self.host = host
        self.kernel32 = host._kernel32

    def map_image(
        self,
        pid: int,
        dll_path: str,
        expected_sha256: str,
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        """Map an already validated PE and return independently checkable evidence."""

        process: Any = None
        remote_base = 0
        dependencies: list[dict[str, Any]] = []
        api_calls: list[dict[str, Any]] = []
        attach_succeeded = False
        image: Optional[PEImage] = None
        entry_point_address = 0
        attached_tls_callbacks: list[dict[str, Any]] = []
        function_table_registered = False
        function_table_address = 0
        rtl_delete_function_table = 0
        actual_identity: dict[str, Any] = {}
        delay_import_evidence: dict[str, Any] = {
            "strategy": "eager_target_context",
            "complete": False,
            "resolved_count": 0,
        }
        tls_evidence: dict[str, Any] = {
            "directory_present": False,
            "required": False,
            "complete": True,
            "callback_count": 0,
            "callback_limit": _MAX_TLS_CALLBACKS,
            "attach_completed_count": 0,
            "callbacks": [],
        }
        exception_evidence: dict[str, Any] = {
            "required": False,
            "complete": True,
            "registered": False,
            "entry_count": 0,
        }
        execution_trace: list[dict[str, Any]] = []

        def record_stage(stage: str, status: str = "completed", **details: Any) -> None:
            execution_trace.append(
                {
                    "sequence": len(execution_trace) + 1,
                    "stage": stage,
                    "status": status,
                    **details,
                }
            )

        try:
            image = parse_manual_map_image(dll_path)
            expected_hash = str(expected_sha256 or "").lower()
            if image.sha256 != expected_hash:
                raise ManualMapBackendError(
                    "sha256_precondition",
                    "DLL bytes changed after validation",
                    details={"expected": expected_hash, "actual": image.sha256},
                )

            process = self.host._open_process(pid)
            api_calls.append({"api": "OpenProcess", "status": "ok"})
            actual_identity = dict(self.host._process_identity(process, pid))
            self._require_same_identity(expected_identity, actual_identity)
            if int(actual_identity.get("machine") or 0) != image.machine:
                raise ManualMapBackendError(
                    "architecture_match",
                    "PE machine does not match the target process",
                    details={
                        "pe_machine": image.machine,
                        "target_machine": actual_identity.get("machine"),
                    },
                )
            injector_machine = int(actual_identity.get("injector_machine") or 0)
            if injector_machine and injector_machine != image.machine:
                raise ManualMapBackendError(
                    "architecture_match",
                    "manual mapping requires a same-bitness injector",
                    details={
                        "pe_machine": image.machine,
                        "target_machine": actual_identity.get("machine"),
                        "injector_machine": injector_machine,
                        "strategy": "same-bitness local-export-owner RVA",
                    },
                )
            if image.pointer_size > ctypes.sizeof(ctypes.c_void_p):
                raise ManualMapBackendError(
                    "architecture_match",
                    "a 32-bit injector cannot safely address a 64-bit target",
                )
            record_stage("validate_image_and_target_identity")

            remote_base = self._allocate_image(process, image)
            remote_base, _ = _checked_remote_range(
                remote_base,
                image.size_of_image,
                image.pointer_size,
                "remote image",
            )
            api_calls.append(
                {
                    "api": "VirtualAllocEx",
                    "status": "ok",
                    "address": remote_base,
                    "size": image.size_of_image,
                    "preferred_base": image.image_base,
                }
            )
            record_stage("allocate_remote_image", image_base=remote_base)
            mapped = map_image_bytes(image)
            relocation_evidence = apply_base_relocations(image, mapped, remote_base)
            record_stage(
                "apply_base_relocations",
                applied_count=relocation_evidence["applied_count"],
            )
            tls_evidence = _plan_tls_callbacks(image, mapped, remote_base)
            if image.tls_directory is not None:
                record_stage(
                    "plan_tls_callbacks",
                    callback_count=tls_evidence["callback_count"],
                    address_translation=tls_evidence["address_translation"],
                )

            load_library, load_library_evidence = self.host._remote_export_address(
                pid,
                module_name="kernel32.dll",
                export_name="LoadLibraryW",
            )
            get_proc_address, get_proc_evidence = self.host._remote_export_address(
                pid,
                module_name="kernel32.dll",
                export_name="GetProcAddress",
            )
            free_library, free_library_evidence = self.host._remote_export_address(
                pid,
                module_name="kernel32.dll",
                export_name="FreeLibrary",
            )
            if not all(
                isinstance(item, Mapping)
                for item in (
                    load_library_evidence,
                    get_proc_evidence,
                    free_library_evidence,
                )
            ):
                raise ManualMapBackendError(
                    "remote_export_resolution",
                    "loader API resolution omitted structured audit evidence",
                )
            load_library = _checked_pointer_value(
                load_library,
                image.pointer_size,
                "remote LoadLibraryW",
            )
            get_proc_address = _checked_pointer_value(
                get_proc_address,
                image.pointer_size,
                "remote GetProcAddress",
            )
            free_library = _checked_pointer_value(
                free_library,
                image.pointer_size,
                "remote FreeLibrary",
            )
            api_calls.extend(
                [
                    {"api": "resolve_remote_LoadLibraryW", "status": "ok", **load_library_evidence},
                    {"api": "resolve_remote_GetProcAddress", "status": "ok", **get_proc_evidence},
                    {"api": "resolve_remote_FreeLibrary", "status": "ok", **free_library_evidence},
                ]
            )

            module_handles: dict[str, int] = {}
            dependency_records: dict[str, dict[str, Any]] = {}

            def ensure_dependency(module_name: str, required_by: str) -> int:
                key = module_name.casefold()
                if key in module_handles:
                    reasons = dependency_records[key]["required_by"]
                    if required_by not in reasons:
                        reasons.append(required_by)
                    return module_handles[key]
                before = self._find_module_by_name(pid, module_name)
                payload = (module_name + "\0").encode("utf-16-le")
                call = self._call_with_bytes_argument(
                    process,
                    image.architecture,
                    load_library,
                    [None],
                    payload,
                    timeout_ms,
                )
                call, handle = _require_completed_remote_call(
                    call,
                    "LoadLibraryW",
                    image.pointer_size,
                )
                if not handle:
                    raise ManualMapBackendError(
                        "LoadLibraryW",
                        f"target failed to load import dependency {module_name}",
                    )
                module_handles[key] = handle
                record = {
                    "name": module_name,
                    "handle": handle,
                    "reference_added": True,
                    "present_before": before is not None,
                    "required_by": [required_by],
                }
                dependency_records[key] = record
                dependencies.append(record)
                return handle

            for imported_module in image.imports:
                ensure_dependency(imported_module.name, "normal_import")

            def resolve_symbol(
                module_name: str,
                symbol_name: Optional[str],
                ordinal: Optional[int],
                required_by: str,
            ) -> int:
                module_handle = ensure_dependency(module_name, required_by)
                if symbol_name is not None:
                    call = self._call_with_bytes_argument(
                        process,
                        image.architecture,
                        get_proc_address,
                        [module_handle, None],
                        symbol_name.encode("ascii") + b"\0",
                        timeout_ms,
                    )
                else:
                    if ordinal is None:
                        raise ManualMapBackendError(
                            "GetProcAddress",
                            f"import from {module_name} has neither a name nor ordinal",
                        )
                    call = self._remote_call(
                        process,
                        image.architecture,
                        get_proc_address,
                        [module_handle, int(ordinal)],
                        timeout_ms,
                    )
                call, address = _require_completed_remote_call(
                    call,
                    "GetProcAddress",
                    image.pointer_size,
                )
                if not address:
                    identity = symbol_name if symbol_name is not None else f"#{ordinal}"
                    raise ManualMapBackendError(
                        "GetProcAddress",
                        f"target could not resolve {module_name}!{identity}",
                    )
                return address

            import_evidence = bind_imports(
                image,
                mapped,
                lambda module_name, symbol_name, ordinal: resolve_symbol(
                    module_name,
                    symbol_name,
                    ordinal,
                    "normal_import",
                ),
            )
            record_stage(
                "bind_normal_imports",
                resolved_count=import_evidence["resolved_count"],
            )
            delay_import_evidence = bind_delay_imports(
                image,
                mapped,
                lambda module_name: ensure_dependency(module_name, "delay_import"),
                lambda module_name, symbol_name, ordinal: resolve_symbol(
                    module_name,
                    symbol_name,
                    ordinal,
                    "delay_import",
                ),
            )
            record_stage(
                "bind_delay_imports",
                resolved_count=delay_import_evidence["resolved_count"],
                strategy=delay_import_evidence["strategy"],
            )
            mapped_sha256 = hashlib.sha256(mapped).hexdigest()
            self._write(process, remote_base, mapped, "mapped PE image")
            api_calls.append(
                {
                    "api": "WriteProcessMemory",
                    "status": "ok",
                    "address": remote_base,
                    "bytes_written": len(mapped),
                }
            )
            readback = self._read(process, remote_base, len(mapped), "mapped PE readback")
            readback_sha256 = hashlib.sha256(readback).hexdigest()
            if readback_sha256 != mapped_sha256:
                raise ManualMapBackendError(
                    "ReadProcessMemory",
                    "remote mapped-image readback hash mismatch",
                    details={"expected": mapped_sha256, "actual": readback_sha256},
                )
            delay_import_evidence["readback_verified"] = _delay_import_storage_matches(
                image,
                mapped,
                readback,
            )
            if not delay_import_evidence["readback_verified"]:
                raise ManualMapBackendError(
                    "ReadProcessMemory",
                    "remote delay-import IAT or module-handle readback mismatch",
                )
            record_stage("write_and_verify_remote_image", sha256=readback_sha256)

            protection_records = []
            for protection_range in image.protection_ranges:
                rights = int(protection_range["rights"])
                native = self._native_protection(rights)
                old = self._protect(
                    process,
                    remote_base + int(protection_range["rva"]),
                    int(protection_range["size"]),
                    native,
                )
                protection_records.append(
                    {
                        **dict(protection_range),
                        "protection": native,
                        "previous_protection": old,
                        "writable_executable": bool((rights & 0x2) and (rights & 0x4)),
                    }
                )
            if not self.kernel32.FlushInstructionCache(
                process,
                ctypes.c_void_p(remote_base),
                image.size_of_image,
            ):
                raise self._last_error("FlushInstructionCache")
            api_calls.append({"api": "FlushInstructionCache", "status": "ok"})
            record_stage(
                "apply_final_protections_and_flush",
                range_count=len(protection_records),
            )

            if image.runtime_functions:
                function_table_address = _checked_remote_address(
                    remote_base,
                    image.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0],
                    image.pointer_size,
                    "remote RUNTIME_FUNCTION table",
                )
                exception_evidence = {
                    "required": True,
                    "complete": False,
                    "registered": False,
                    "table_rva": image.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0],
                    "table_address": function_table_address,
                    "entry_size": 12,
                    "entry_count": len(image.runtime_functions),
                    "base_address": remote_base,
                    "delete_resolved_before_registration": False,
                }
                try:
                    registration = self._register_function_table(
                        process,
                        pid,
                        function_table_address,
                        len(image.runtime_functions),
                        remote_base,
                        timeout_ms,
                    )
                except Exception:
                    record_stage(
                        "register_x64_function_table",
                        status="failed",
                        table_address=function_table_address,
                        entry_count=len(image.runtime_functions),
                    )
                    raise
                function_table_registered = True
                rtl_delete_function_table = int(registration["delete_function_address"])
                api_calls.extend(registration["api_calls"])
                exception_evidence = {
                    "required": True,
                    "complete": True,
                    "registered": True,
                    "table_rva": image.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0],
                    "table_address": function_table_address,
                    "entry_size": 12,
                    "entry_count": len(image.runtime_functions),
                    "base_address": remote_base,
                    "registration_thread_id": registration.get("thread_id"),
                    "delete_resolved_before_registration": True,
                }
                record_stage(
                    "register_x64_function_table",
                    table_address=function_table_address,
                    entry_count=len(image.runtime_functions),
                )

            for callback in tls_evidence["callbacks"]:
                try:
                    callback_call = self._remote_call(
                        process,
                        image.architecture,
                        int(callback["address"]),
                        [remote_base, self.DLL_PROCESS_ATTACH, 0],
                        timeout_ms,
                    )
                    callback_call, _ = _require_completed_remote_call(
                        callback_call,
                        "TLS callback(DLL_PROCESS_ATTACH)",
                        image.pointer_size,
                    )
                except Exception:
                    record_stage(
                        "tls_callback_process_attach",
                        status="failed",
                        callback_sequence=callback["sequence"],
                        callback_rva=callback["rva"],
                        callback_address=callback["address"],
                    )
                    raise
                callback["attach_completed"] = True
                callback["attach_thread_id"] = callback_call.get("thread_id")
                attached_tls_callbacks.append(dict(callback))
                tls_evidence["attach_completed_count"] = len(attached_tls_callbacks)
                record_stage(
                    "tls_callback_process_attach",
                    callback_sequence=callback["sequence"],
                    callback_rva=callback["rva"],
                    callback_address=callback["address"],
                )
            tls_evidence["complete"] = (
                len(attached_tls_callbacks) == tls_evidence["callback_count"]
            )

            entry_point_address = (
                _checked_remote_address(
                    remote_base,
                    image.entry_point_rva,
                    image.pointer_size,
                    "remote DLL entry point",
                )
                if image.entry_point_rva
                else 0
            )
            if entry_point_address:
                try:
                    entry_call = self._remote_call(
                        process,
                        image.architecture,
                        entry_point_address,
                        [remote_base, self.DLL_PROCESS_ATTACH, 0],
                        timeout_ms,
                    )
                    entry_call, entry_result = _require_completed_remote_call(
                        entry_call,
                        "DllMain(DLL_PROCESS_ATTACH)",
                        image.pointer_size,
                    )
                except Exception:
                    record_stage(
                        "dll_process_attach",
                        status="failed",
                        required=True,
                        completed=False,
                    )
                    raise
                attach_succeeded = bool(entry_result & 0xFFFFFFFF)
                if not attach_succeeded:
                    record_stage(
                        "dll_process_attach",
                        status="failed",
                        required=True,
                        completed=True,
                    )
                    raise ManualMapBackendError(
                        "DllMain(DLL_PROCESS_ATTACH)",
                        "DLL entry point returned FALSE",
                    )
            else:
                entry_call = {
                    "completed": True,
                    "result": 1,
                    "thread_id": None,
                    "not_present": True,
                }
                entry_result = 1
            record_stage(
                "dll_process_attach",
                required=bool(entry_point_address),
                completed=bool(entry_call.get("completed")),
            )

            return {
                "ok": True,
                "status": "ok",
                "method": "manual_map",
                "pid": pid,
                "dll_path": dll_path,
                "dll_sha256": image.sha256,
                "target_identity": actual_identity,
                "target_identity_verified": True,
                "image": image.to_audit_dict(),
                "image_base": remote_base,
                "image_size": image.size_of_image,
                "preferred_image_base": image.image_base,
                "entry_point_address": entry_point_address,
                "headers_sections": {
                    "complete": True,
                    "header_bytes": image.size_of_headers,
                    "section_count": len(image.sections),
                    "mapped_size": len(mapped),
                },
                "relocations": relocation_evidence,
                "imports": import_evidence,
                "delay_imports": delay_import_evidence,
                "tls_callbacks": tls_evidence,
                "exception_table": exception_evidence,
                "readback": {
                    "complete": True,
                    "bytes_read": len(readback),
                    "mapped_sha256": mapped_sha256,
                    "readback_sha256": readback_sha256,
                },
                "protections": {
                    "complete": len(protection_records) == len(image.protection_ranges),
                    "range_count": len(image.protection_ranges),
                    "applied_count": len(protection_records),
                    "writable_executable": any(
                        item["writable_executable"] for item in protection_records
                    ),
                    "ranges": protection_records,
                    "instruction_cache_flushed": True,
                },
                "entrypoint": {
                    "required": bool(entry_point_address),
                    "called": bool(entry_point_address),
                    "completed": bool(entry_call.get("completed")),
                    "attach_returned": bool(entry_result & 0xFFFFFFFF),
                    "thread_id": entry_call.get("thread_id"),
                },
                "dependencies": dependencies,
                "rollback": {
                    "safe_to_unmap": True,
                    "image_base": remote_base,
                    "image_size": image.size_of_image,
                    "entry_point_address": entry_point_address,
                    "architecture": image.architecture,
                    "attach_succeeded": attach_succeeded,
                    "tls_callbacks": [
                        {
                            "sequence": item["sequence"],
                            "rva": item["rva"],
                            "attach_completed": True,
                        }
                        for item in attached_tls_callbacks
                    ],
                    "function_table": {
                        "registered": function_table_registered,
                        "table_rva": (
                            image.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0]
                            if function_table_registered
                            else None
                        ),
                        "table_address": (
                            function_table_address if function_table_registered else None
                        ),
                        "entry_count": (
                            len(image.runtime_functions) if function_table_registered else 0
                        ),
                        "delete_function_address": (
                            rtl_delete_function_table if function_table_registered else None
                        ),
                    },
                    "dependencies": dependencies,
                    "target_identity": actual_identity,
                },
                "side_effects": True,
                "api_calls": api_calls,
                "execution_trace": execution_trace,
            }
        except Exception as exc:
            error = self._exception_payload(exc)
            record_stage(
                "mapping_failure",
                status="failed",
                operation=error.get("operation") or error.get("type"),
            )
            unsafe = bool(
                isinstance(error.get("details"), Mapping)
                and error["details"].get("thread_running")
            )
            cleanup: dict[str, Any] = {"attempted": not unsafe, "safe_to_unmap": not unsafe}
            if process and not unsafe:
                tls_cleanup: list[dict[str, Any]] = []
                if not unsafe:
                    for callback in attached_tls_callbacks:
                        callback_cleanup = {
                            "sequence": callback["sequence"],
                            "rva": callback["rva"],
                            "address": callback["address"],
                            "detach_order": len(tls_cleanup) + 1,
                        }
                        try:
                            callback_detach = self._remote_call(
                                process,
                                image.architecture if image is not None else "x64",
                                int(callback["address"]),
                                [remote_base, self.DLL_PROCESS_DETACH, 0],
                                timeout_ms,
                            )
                            callback_detach, _ = _require_completed_remote_call(
                                callback_detach,
                                "TLS callback(DLL_PROCESS_DETACH)",
                                image.pointer_size if image is not None else 8,
                            )
                            callback_cleanup["completed"] = True
                            callback_cleanup["thread_id"] = callback_detach.get("thread_id")
                        except Exception as cleanup_exc:
                            callback_cleanup["completed"] = False
                            callback_cleanup["error"] = self._exception_payload(cleanup_exc)
                            cleanup["safe_to_unmap"] = False
                            unsafe = self._error_has_running_thread(cleanup_exc)
                        tls_cleanup.append(callback_cleanup)
                        record_stage(
                            "compensate_tls_callback_process_detach",
                            status=(
                                "completed" if callback_cleanup["completed"] else "failed"
                            ),
                            callback_sequence=callback["sequence"],
                            callback_rva=callback["rva"],
                        )
                        if unsafe:
                            break
                cleanup["tls_callbacks"] = tls_cleanup
                cleanup["tls_callbacks_detached"] = (
                    len(tls_cleanup) == len(attached_tls_callbacks)
                    and all(item.get("completed") for item in tls_cleanup)
                )

                if (
                    attach_succeeded
                    and entry_point_address
                    and image is not None
                    and not unsafe
                ):
                    try:
                        detach = self._remote_call(
                            process,
                            image.architecture,
                            entry_point_address,
                            [remote_base, self.DLL_PROCESS_DETACH, 0],
                            timeout_ms,
                        )
                        detach, _ = _require_completed_remote_call(
                            detach,
                            "DllMain(DLL_PROCESS_DETACH)",
                            image.pointer_size,
                        )
                        cleanup["detach_completed"] = True
                        attach_succeeded = False
                        record_stage(
                            "compensate_dll_process_detach",
                            status=(
                                "completed" if cleanup["detach_completed"] else "failed"
                            ),
                        )
                    except Exception as cleanup_exc:
                        cleanup["detach_error"] = self._exception_payload(cleanup_exc)
                        cleanup["safe_to_unmap"] = False
                        unsafe = self._error_has_running_thread(cleanup_exc)
                        record_stage("compensate_dll_process_detach", status="failed")

                if function_table_registered and not unsafe:
                    try:
                        deletion = self._delete_function_table(
                            process,
                            pid,
                            function_table_address,
                            timeout_ms,
                            function_address=rtl_delete_function_table,
                        )
                        function_table_registered = False
                        cleanup["function_table"] = {
                            "delete_attempted": True,
                            "deleted": True,
                            "table_address": function_table_address,
                            "thread_id": deletion.get("thread_id"),
                        }
                        api_calls.extend(deletion["api_calls"])
                        record_stage("compensate_delete_x64_function_table")
                    except Exception as cleanup_exc:
                        cleanup["function_table"] = {
                            "delete_attempted": True,
                            "deleted": False,
                            "table_address": function_table_address,
                            "error": self._exception_payload(cleanup_exc),
                        }
                        cleanup["safe_to_unmap"] = False
                        unsafe = self._error_has_running_thread(cleanup_exc)
                        record_stage(
                            "compensate_delete_x64_function_table",
                            status="failed",
                        )
                elif function_table_registered:
                    cleanup["function_table"] = {
                        "delete_attempted": False,
                        "deleted": False,
                        "table_address": function_table_address,
                        "reason": "a remote lifecycle call may still be executing",
                    }

                if cleanup.get("safe_to_unmap") and not function_table_registered:
                    dependency_cleanup = self._release_dependencies(
                        process,
                        image.architecture if image is not None else "x64",
                        free_library if "free_library" in locals() else 0,
                        dependencies,
                        timeout_ms,
                    )
                    cleanup["dependencies"] = dependency_cleanup
                    cleanup["dependencies_released"] = all(
                        item.get("released")
                        for item in dependency_cleanup
                        if item.get("reference_added")
                    )
                    record_stage(
                        "compensate_dependencies",
                        status=(
                            "completed" if cleanup["dependencies_released"] else "failed"
                        ),
                    )
                    if remote_base:
                        image_cleanup = self._release_image(process, remote_base)
                        cleanup["image"] = image_cleanup
                        cleanup["image_released"] = bool(image_cleanup.get("released"))
                        cleanup["image_release_verified"] = bool(
                            image_cleanup.get("release_verified")
                        )
                        record_stage(
                            "compensate_image_allocation",
                            status=(
                                "completed"
                                if cleanup["image_release_verified"]
                                else "failed"
                            ),
                        )
                else:
                    cleanup["dependencies"] = [
                        {
                            **item,
                            "released": False,
                            "reason": "remote lifecycle cleanup was incomplete or unsafe",
                        }
                        for item in dependencies
                    ]
                    cleanup["dependencies_released"] = not dependencies
            image_released = bool(cleanup.get("image_release_verified"))
            retained_dependencies = [
                dict(item)
                for item in cleanup.get("dependencies", dependencies)
                if isinstance(item, Mapping)
                and item.get("reference_added")
                and not item.get("released")
            ]
            image_retained = bool(remote_base and not image_released)
            exception_evidence["registered"] = function_table_registered
            if isinstance(cleanup.get("function_table"), Mapping):
                exception_evidence["cleanup_deleted"] = bool(
                    cleanup["function_table"].get("deleted")
                )
            cleanup["ok"] = bool(
                not image_retained
                and not retained_dependencies
                and not function_table_registered
                and cleanup.get("safe_to_unmap", not unsafe)
            )
            rollback_metadata = {
                "safe_to_unmap": bool(cleanup.get("safe_to_unmap", not unsafe)),
                "image_base": remote_base or None,
                "image_size": image.size_of_image if image is not None else None,
                "entry_point_address": entry_point_address or None,
                "architecture": image.architecture if image is not None else None,
                "attach_succeeded": attach_succeeded,
                "tls_callbacks": [
                    {
                        "sequence": item["sequence"],
                        "rva": item["rva"],
                        "attach_completed": True,
                    }
                    for item in attached_tls_callbacks
                    if not any(
                        cleanup_item.get("sequence") == item["sequence"]
                        and cleanup_item.get("completed")
                        for cleanup_item in cleanup.get("tls_callbacks", [])
                    )
                ],
                "function_table": {
                    "registered": function_table_registered,
                    "table_rva": (
                        image.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION][0]
                        if image is not None and function_table_registered
                        else None
                    ),
                    "table_address": (
                        function_table_address if function_table_registered else None
                    ),
                    "entry_count": (
                        len(image.runtime_functions)
                        if image is not None and function_table_registered
                        else 0
                    ),
                    "delete_function_address": (
                        rtl_delete_function_table if function_table_registered else None
                    ),
                },
                "dependencies": retained_dependencies,
                "target_identity": actual_identity,
            }
            return {
                "ok": False,
                "status": "failed",
                "method": "manual_map",
                "pid": pid,
                "dll_path": dll_path,
                "dll_sha256": image.sha256 if image is not None else None,
                "target_identity": actual_identity,
                "target_identity_verified": bool(actual_identity),
                "image_base": remote_base or None,
                "image_size": image.size_of_image if image is not None else None,
                "entry_point_address": entry_point_address or None,
                "dependencies": dependencies,
                "delay_imports": delay_import_evidence,
                "tls_callbacks": tls_evidence,
                "exception_table": exception_evidence,
                "safe_to_unmap": bool(cleanup.get("safe_to_unmap", not unsafe)),
                "image_retained": image_retained,
                "cleanup": cleanup,
                "rollback": rollback_metadata,
                "side_effects": bool(
                    image_retained or retained_dependencies or function_table_registered
                ),
                "error": error,
                "api_calls": api_calls,
                "execution_trace": execution_trace,
            }
        finally:
            if process:
                self.kernel32.CloseHandle(process)

    def rollback_image(
        self,
        pid: int,
        mapping: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        """Detach and release a mapped image, proving the address range is free."""

        try:
            if not isinstance(mapping, Mapping):
                raise ManualMapValidationError("rollback data is not an object")
            architecture = str(mapping.get("architecture") or "")
            pointer_size = _pointer_size_for_architecture(architecture)
            image_base = int(mapping.get("image_base") or 0)
            image_size = int(mapping.get("image_size") or 0)
            if not 0 < image_size <= _MAX_IMAGE_SIZE:
                raise ManualMapValidationError("rollback image size is invalid")
            image_base, image_end = _checked_remote_range(
                image_base,
                image_size,
                pointer_size,
                "rollback image",
            )
            entry_point = int(mapping.get("entry_point_address") or 0)
            if entry_point:
                entry_point = _checked_pointer_value(
                    entry_point,
                    pointer_size,
                    "rollback DLL entry point",
                )
                if not image_base <= entry_point < image_end:
                    raise ManualMapValidationError(
                        "rollback DLL entry point is outside the image"
                    )
            attach_succeeded = mapping.get("attach_succeeded", False)
            if attach_succeeded is not True and attach_succeeded is not False:
                raise ManualMapValidationError("rollback attach state is invalid")
            if attach_succeeded and not entry_point:
                raise ManualMapValidationError(
                    "rollback attach state requires a DLL entry point"
                )
            safe_to_unmap = mapping.get("safe_to_unmap", True)
            if safe_to_unmap is not True and safe_to_unmap is not False:
                raise ManualMapValidationError("rollback safety state is invalid")
            recorded_identity = mapping.get("target_identity")
            if recorded_identity is not None and not isinstance(recorded_identity, Mapping):
                raise ManualMapValidationError("rollback target identity is not an object")
            recorded_identity = dict(recorded_identity or {})
            dependencies = _validate_rollback_dependencies(
                mapping.get("dependencies"),
                pointer_size,
            )
            tls_callbacks = _validate_rollback_tls_callbacks(
                mapping.get("tls_callbacks"),
                image_base,
                image_size,
                architecture,
            )
            function_table = _validate_rollback_function_table(
                mapping.get("function_table"),
                image_base,
                image_size,
                architecture,
            )
        except (TypeError, ValueError, OverflowError, ManualMapValidationError, ManualMapBackendError) as exc:
            return {
                "ok": False,
                "status": "failed",
                "reason": f"manual-map rollback metadata is invalid: {exc}",
                "mapping_released": False,
                "release_verified": False,
            }

        process: Any = None
        api_calls: list[dict[str, Any]] = []
        identity: dict[str, Any] = {}
        identity_verified = False
        before_region: dict[str, Any] = {}
        after_region: dict[str, Any] = {}
        detach: dict[str, Any] = {"required": False, "completed": False}
        tls_cleanup: list[dict[str, Any]] = []
        tls_detached = not tls_callbacks
        function_table_deleted = not function_table["registered"]
        function_table_cleanup: dict[str, Any] = {
            "required": bool(function_table["registered"]),
            "deleted": function_table_deleted,
        }
        dependency_cleanup: list[dict[str, Any]] = []
        dependencies_released = not dependencies
        image_cleanup: dict[str, Any] = {}
        mapping_release_attempted = False
        mapping_released = False
        release_verified = False
        rollback_trace: list[dict[str, Any]] = []
        remaining_tls_callbacks = list(tls_callbacks)
        remaining_attach = bool(attach_succeeded)
        remaining_function_table = dict(function_table)
        remaining_dependencies = [dict(item) for item in dependencies]
        remaining_safe_to_unmap = bool(safe_to_unmap)

        def record_rollback(stage: str, status: str = "completed", **details: Any) -> None:
            rollback_trace.append(
                {
                    "sequence": len(rollback_trace) + 1,
                    "stage": stage,
                    "status": status,
                    **details,
                }
            )

        def remaining_rollback() -> dict[str, Any]:
            remaining_table: dict[str, Any]
            if remaining_function_table.get("registered"):
                remaining_table = {
                    "registered": True,
                    "table_rva": remaining_function_table["table_rva"],
                    "table_address": remaining_function_table["table_address"],
                    "entry_count": remaining_function_table["entry_count"],
                    "delete_function_address": remaining_function_table.get(
                        "delete_function_address"
                    ),
                }
            else:
                remaining_table = {"registered": False}
            return {
                "safe_to_unmap": remaining_safe_to_unmap,
                "image_base": image_base,
                "image_size": image_size,
                "entry_point_address": entry_point or None,
                "architecture": architecture,
                "attach_succeeded": remaining_attach,
                "tls_callbacks": [
                    {
                        "sequence": item["sequence"],
                        "rva": item["rva"],
                        "attach_completed": True,
                    }
                    for item in remaining_tls_callbacks
                ],
                "function_table": remaining_table,
                "dependencies": [dict(item) for item in remaining_dependencies],
                "target_identity": identity or recorded_identity,
            }

        if not safe_to_unmap:
            return {
                "ok": False,
                "status": "blocked",
                "reason": "a remote call may still be executing; unmapping is unsafe",
                "mapping_released": False,
                "release_verified": False,
                "rollback": remaining_rollback(),
            }

        try:
            process = self.host._open_process(pid)
            identity = dict(self.host._process_identity(process, pid))
            self._require_same_identity(expected_identity, identity)
            identity_verified = True
            record_rollback("verify_target_identity")
            region = self._query_region(process, image_base)
            if not isinstance(region, Mapping):
                raise ManualMapBackendError(
                    "VirtualQueryEx",
                    "mapping query omitted structured audit evidence",
                )
            before_region = dict(region)
            allocation_base = int(before_region.get("allocation_base") or 0)
            mapping_present = before_region.get("state") == self.MEM_COMMIT
            if mapping_present and allocation_base != image_base:
                raise ManualMapBackendError(
                    "VirtualQueryEx",
                    "the recorded address belongs to a different allocation",
                    details={"expected_base": image_base, "region": before_region},
                )
            if not mapping_present and before_region.get("state") != self.MEM_FREE:
                raise ManualMapBackendError(
                    "VirtualQueryEx",
                    "the recorded image allocation has an unexpected state",
                    details={"expected_base": image_base, "region": before_region},
                )
            if not mapping_present and (
                remaining_tls_callbacks
                or remaining_attach
                or remaining_function_table.get("registered")
            ):
                raise ManualMapBackendError(
                    "rollback_state",
                    "the image is absent before its loader lifecycle was compensated",
                )

            if mapping_present:
                for callback in list(remaining_tls_callbacks):
                    callback_cleanup = {
                        **callback,
                        "detach_order": len(tls_cleanup) + 1,
                        "completed": False,
                    }
                    try:
                        callback_call = self._remote_call(
                            process,
                            architecture,
                            int(callback["address"]),
                            [image_base, self.DLL_PROCESS_DETACH, 0],
                            timeout_ms,
                        )
                        callback_call, _ = _require_completed_remote_call(
                            callback_call,
                            "TLS callback(DLL_PROCESS_DETACH)",
                            pointer_size,
                        )
                        callback_cleanup["completed"] = True
                        callback_cleanup["thread_id"] = callback_call.get("thread_id")
                    except Exception as callback_exc:
                        callback_cleanup["error"] = self._exception_payload(callback_exc)
                        tls_cleanup.append(callback_cleanup)
                        record_rollback(
                            "tls_callback_process_detach",
                            status="failed",
                            callback_sequence=callback["sequence"],
                            callback_rva=callback["rva"],
                        )
                        raise
                    tls_cleanup.append(callback_cleanup)
                    remaining_tls_callbacks = [
                        item
                        for item in remaining_tls_callbacks
                        if item["sequence"] != callback["sequence"]
                    ]
                    record_rollback(
                        "tls_callback_process_detach",
                        callback_sequence=callback["sequence"],
                        callback_rva=callback["rva"],
                    )
                tls_detached = not remaining_tls_callbacks

            detach = {"required": False, "completed": True}
            if mapping_present and remaining_attach:
                detach = {"required": True, "completed": False}
                try:
                    detach_call = self._remote_call(
                        process,
                        architecture,
                        entry_point,
                        [image_base, self.DLL_PROCESS_DETACH, 0],
                        timeout_ms,
                    )
                    detach_call, detach_result = _require_completed_remote_call(
                        detach_call,
                        "DllMain(DLL_PROCESS_DETACH)",
                        pointer_size,
                    )
                except Exception as detach_exc:
                    detach["error"] = self._exception_payload(detach_exc)
                    record_rollback(
                        "dll_process_detach",
                        status="failed",
                        required=True,
                        completed=False,
                    )
                    raise
                detach = {
                    "required": True,
                    "completed": True,
                    "thread_id": detach_call.get("thread_id"),
                    "return_value_ignored": detach_result,
                }
                remaining_attach = False
            record_rollback(
                "dll_process_detach",
                required=bool(detach.get("required")),
                completed=bool(detach.get("completed")),
            )

            if remaining_function_table.get("registered"):
                function_table_cleanup = {
                    "required": True,
                    "delete_attempted": True,
                    "deleted": False,
                    "table_rva": remaining_function_table["table_rva"],
                    "table_address": remaining_function_table["table_address"],
                    "entry_count": remaining_function_table["entry_count"],
                }
                try:
                    deletion = self._delete_function_table(
                        process,
                        pid,
                        int(remaining_function_table["table_address"]),
                        timeout_ms,
                        function_address=int(
                            remaining_function_table.get("delete_function_address") or 0
                        ),
                    )
                except Exception as deletion_exc:
                    function_table_cleanup["error"] = self._exception_payload(deletion_exc)
                    record_rollback(
                        "delete_x64_function_table",
                        status="failed",
                        table_address=remaining_function_table["table_address"],
                        entry_count=remaining_function_table["entry_count"],
                    )
                    raise
                api_calls.extend(deletion["api_calls"])
                function_table_deleted = True
                remaining_function_table = {"registered": False}
                function_table_cleanup = {
                    **function_table_cleanup,
                    "deleted": True,
                    "thread_id": deletion.get("thread_id"),
                }
                record_rollback(
                    "delete_x64_function_table",
                    table_address=function_table_cleanup["table_address"],
                    entry_count=function_table_cleanup["entry_count"],
                )

            if remaining_dependencies:
                try:
                    free_library, free_library_evidence = self.host._remote_export_address(
                        pid,
                        module_name="kernel32.dll",
                        export_name="FreeLibrary",
                    )
                    if not isinstance(free_library_evidence, Mapping):
                        raise ManualMapBackendError(
                            "FreeLibrary",
                            "remote export resolution omitted structured audit evidence",
                        )
                    free_library = _checked_pointer_value(
                        free_library,
                        pointer_size,
                        "remote FreeLibrary",
                    )
                    api_calls.append(
                        {
                            "api": "resolve_remote_FreeLibrary",
                            "status": "ok",
                            **free_library_evidence,
                        }
                    )
                    dependency_cleanup = self._release_dependencies(
                        process,
                        architecture,
                        free_library,
                        remaining_dependencies,
                        timeout_ms,
                    )
                except Exception:
                    record_rollback(
                        "release_import_dependencies",
                        status="failed",
                        dependency_count=len(remaining_dependencies),
                    )
                    raise
                remaining_dependencies = [
                    {
                        key: value
                        for key, value in item.items()
                        if key not in {"release_order", "released", "thread_id", "error"}
                    }
                    for item in dependency_cleanup
                    if item.get("reference_added") and not item.get("released")
                ]
                dependencies_released = not remaining_dependencies
            record_rollback(
                "release_import_dependencies",
                status="completed" if dependencies_released else "failed",
                dependency_count=len(dependencies),
            )
            try:
                released_image = self._release_image(process, image_base)
                if not isinstance(released_image, Mapping):
                    raise ManualMapBackendError(
                        "VirtualFreeEx",
                        "image release omitted structured audit evidence",
                    )
                image_cleanup = dict(released_image)
            except Exception:
                record_rollback("release_and_verify_image", status="failed")
                raise
            mapping_release_attempted = bool(image_cleanup.get("attempted"))
            mapping_released = bool(image_cleanup.get("released")) or bool(
                image_cleanup.get("already_free")
            )
            release_verified = bool(image_cleanup.get("release_verified"))
            after_region = dict(image_cleanup.get("after_region") or {})
            record_rollback(
                "release_and_verify_image",
                status="completed" if release_verified else "failed",
            )
            ok = (
                release_verified
                and bool(detach.get("completed"))
                and not remaining_tls_callbacks
                and not remaining_attach
                and not remaining_function_table.get("registered")
                and not remaining_dependencies
            )
            result = {
                "ok": ok,
                "status": "ok" if ok else "failed",
                "pid": pid,
                "target_identity": identity,
                "target_identity_verified": True,
                "image_base": image_base,
                "image_size": image_size,
                "detach": detach,
                "tls_callbacks": tls_cleanup,
                "tls_callbacks_detached": tls_detached,
                "function_table": function_table_cleanup,
                "mapping_release_attempted": mapping_release_attempted,
                "mapping_released": mapping_released,
                "release_verified": release_verified,
                "before_region": before_region,
                "after_region": after_region,
                "image_cleanup": image_cleanup,
                "dependencies": dependency_cleanup,
                "dependencies_released": dependencies_released,
                "api_calls": api_calls,
                "rollback_trace": rollback_trace,
            }
            if not ok:
                result["rollback"] = remaining_rollback()
                result["side_effects"] = bool(
                    not release_verified or remaining_dependencies
                )
            return result
        except Exception as exc:
            if self._error_has_running_thread(exc):
                remaining_safe_to_unmap = False
            tls_detached = not remaining_tls_callbacks
            function_table_deleted = not remaining_function_table.get("registered")
            dependencies_released = not remaining_dependencies
            record_rollback(
                "rollback_failure",
                status="failed",
                operation=getattr(exc, "operation", type(exc).__name__),
            )
            return {
                "ok": False,
                "status": "failed",
                "pid": pid,
                "target_identity": identity,
                "target_identity_verified": identity_verified,
                "image_base": image_base,
                "image_size": image_size,
                "detach": detach,
                "tls_callbacks": tls_cleanup,
                "tls_callbacks_detached": tls_detached,
                "function_table": function_table_cleanup,
                "mapping_release_attempted": mapping_release_attempted,
                "mapping_released": mapping_released,
                "release_verified": release_verified,
                "before_region": before_region,
                "after_region": after_region,
                "dependencies": dependency_cleanup,
                "dependencies_released": dependencies_released,
                "error": self._exception_payload(exc),
                "api_calls": api_calls,
                "rollback_trace": rollback_trace,
                "rollback": remaining_rollback(),
                "side_effects": bool(
                    not release_verified
                    or remaining_function_table.get("registered")
                    or remaining_dependencies
                ),
            }
        finally:
            if process:
                self.kernel32.CloseHandle(process)

    def _register_function_table(
        self,
        process: Any,
        pid: int,
        table_address: int,
        entry_count: int,
        image_base: int,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if not 0 < entry_count <= _MAX_RUNTIME_FUNCTIONS:
            raise ManualMapBackendError(
                "RtlAddFunctionTable",
                "RUNTIME_FUNCTION entry count is outside the validated limit",
            )
        table_address = _checked_pointer_value(
            table_address,
            8,
            "remote RUNTIME_FUNCTION table",
        )
        image_base = _checked_pointer_value(image_base, 8, "remote image base")
        add_function, add_evidence = self.host._remote_export_address(
            pid,
            module_name="ntdll.dll",
            export_name="RtlAddFunctionTable",
        )
        delete_function, delete_evidence = self.host._remote_export_address(
            pid,
            module_name="ntdll.dll",
            export_name="RtlDeleteFunctionTable",
        )
        if not isinstance(add_evidence, Mapping) or not isinstance(delete_evidence, Mapping):
            raise ManualMapBackendError(
                "RtlAddFunctionTable",
                "remote export resolution omitted structured audit evidence",
            )
        add_address = _checked_pointer_value(add_function, 8, "remote RtlAddFunctionTable")
        delete_address = _checked_pointer_value(
            delete_function,
            8,
            "remote RtlDeleteFunctionTable",
        )
        call = self._remote_call(
            process,
            "x64",
            add_address,
            [table_address, entry_count, image_base],
            timeout_ms,
        )
        call, raw_result = _require_completed_remote_call(
            call,
            "RtlAddFunctionTable",
            8,
        )
        boolean_result = raw_result & 0xFF
        if not boolean_result:
            raise ManualMapBackendError(
                "RtlAddFunctionTable",
                "target rejected the validated RUNTIME_FUNCTION table",
                details={
                    "table_address": table_address,
                    "entry_count": entry_count,
                    "base_address": image_base,
                    "add_function_address": add_address,
                    "delete_function_address": delete_address,
                    "delete_resolved_before_registration": True,
                    "completed": True,
                    "raw_result": raw_result,
                    "boolean_result": boolean_result,
                },
            )
        return {
            "registered": True,
            "thread_id": call.get("thread_id"),
            "delete_function_address": delete_address,
            "api_calls": [
                {
                    "api": "resolve_remote_RtlAddFunctionTable",
                    "status": "ok",
                    **add_evidence,
                },
                {
                    "api": "resolve_remote_RtlDeleteFunctionTable",
                    "status": "ok",
                    **delete_evidence,
                },
                {
                    "api": "RtlAddFunctionTable",
                    "status": "ok",
                    "table_address": table_address,
                    "entry_count": entry_count,
                    "base_address": image_base,
                },
            ],
        }

    def _delete_function_table(
        self,
        process: Any,
        pid: int,
        table_address: int,
        timeout_ms: int,
        *,
        function_address: int = 0,
    ) -> dict[str, Any]:
        api_calls: list[dict[str, Any]] = []
        table_address = _checked_pointer_value(
            table_address,
            8,
            "remote RUNTIME_FUNCTION table",
        )
        delete_address = int(function_address or 0)
        if not delete_address:
            resolved, evidence = self.host._remote_export_address(
                pid,
                module_name="ntdll.dll",
                export_name="RtlDeleteFunctionTable",
            )
            if not isinstance(evidence, Mapping):
                raise ManualMapBackendError(
                    "RtlDeleteFunctionTable",
                    "remote export resolution omitted structured audit evidence",
                )
            delete_address = _checked_pointer_value(
                resolved,
                8,
                "remote RtlDeleteFunctionTable",
            )
            api_calls.append(
                {
                    "api": "resolve_remote_RtlDeleteFunctionTable",
                    "status": "ok",
                    **evidence,
                }
            )
        else:
            delete_address = _checked_pointer_value(
                delete_address,
                8,
                "remote RtlDeleteFunctionTable",
            )
        call = self._remote_call(
            process,
            "x64",
            delete_address,
            [table_address],
            timeout_ms,
        )
        call, raw_result = _require_completed_remote_call(
            call,
            "RtlDeleteFunctionTable",
            8,
        )
        boolean_result = raw_result & 0xFF
        if not boolean_result:
            raise ManualMapBackendError(
                "RtlDeleteFunctionTable",
                "target did not delete the registered RUNTIME_FUNCTION table",
                details={
                    "table_address": table_address,
                    "completed": True,
                    "raw_result": raw_result,
                    "boolean_result": boolean_result,
                },
            )
        api_calls.append(
            {
                "api": "RtlDeleteFunctionTable",
                "status": "ok",
                "table_address": table_address,
            }
        )
        return {
            "deleted": True,
            "thread_id": call.get("thread_id"),
            "api_calls": api_calls,
        }

    def _allocate_image(self, process: Any, image: PEImage) -> int:
        preferred = self.kernel32.VirtualAllocEx(
            process,
            ctypes.c_void_p(image.image_base),
            image.size_of_image,
            self.MEM_RESERVE | self.MEM_COMMIT,
            self.PAGE_READWRITE,
        )
        address = self._pointer_value(preferred)
        if address:
            return address
        fallback = self.kernel32.VirtualAllocEx(
            process,
            None,
            image.size_of_image,
            self.MEM_RESERVE | self.MEM_COMMIT,
            self.PAGE_READWRITE,
        )
        address = self._pointer_value(fallback)
        if not address:
            raise self._last_error("VirtualAllocEx")
        return address

    def _remote_call(
        self,
        process: Any,
        architecture: str,
        function: int,
        arguments: Sequence[int],
        timeout_ms: int,
    ) -> dict[str, Any]:
        if architecture == "x86":
            if any(not 0 <= int(value) <= 0xFFFFFFFF for value in [function, *arguments]):
                raise ManualMapBackendError("remote_call", "x86 call argument exceeds 32 bits")
            code = self._x86_call_stub(len(arguments))
            padded = [int(value) for value in arguments[:3]] + [0] * (3 - len(arguments))
            parameter = struct.pack("<6I", int(function), *padded, 0, 0)
            result_offset = 16
            complete_offset = 20
            result_format = "<I"
        elif architecture == "x64":
            if any(
                not 0 <= int(value) <= 0xFFFFFFFFFFFFFFFF
                for value in [function, *arguments]
            ):
                raise ManualMapBackendError("remote_call", "x64 call argument exceeds 64 bits")
            code = self._x64_call_stub()
            padded = [int(value) for value in arguments[:3]] + [0] * (3 - len(arguments))
            parameter = struct.pack("<5QI4x", int(function), *padded, 0, 0)
            result_offset = 32
            complete_offset = 40
            result_format = "<Q"
        else:
            raise ManualMapBackendError("remote_call", f"unsupported architecture {architecture}")
        if len(arguments) > 3:
            raise ManualMapBackendError("remote_call", "only up to three arguments are supported")

        code_address = 0
        parameter_address = 0
        thread_running = False
        try:
            code_address = self._allocate(process, len(code), self.PAGE_READWRITE)
            parameter_address = self._allocate(process, len(parameter), self.PAGE_READWRITE)
            self._write(process, code_address, code, "remote call stub")
            self._write(process, parameter_address, parameter, "remote call parameters")
            self._protect(process, code_address, len(code), self.PAGE_EXECUTE_READ)
            if not self.kernel32.FlushInstructionCache(
                process,
                ctypes.c_void_p(code_address),
                len(code),
            ):
                raise self._last_error("FlushInstructionCache")
            thread = self.host._run_remote_thread(
                process,
                start_address=code_address,
                parameter=parameter_address,
                timeout_ms=timeout_ms,
            )
            raw = self._read(process, parameter_address, len(parameter), "remote call result")
            completed = bool(struct.unpack_from("<I", raw, complete_offset)[0])
            if not completed:
                raise ManualMapBackendError("remote_call", "completion marker was not written")
            return {
                "completed": True,
                "result": int(struct.unpack_from(result_format, raw, result_offset)[0]),
                "thread_id": thread.get("thread_id"),
            }
        except Exception as exc:
            details = getattr(exc, "details", {})
            thread_running = bool(
                isinstance(details, Mapping)
                and details.get("thread_started")
                and not details.get("wait_completed")
            )
            if thread_running:
                raise ManualMapBackendError(
                    "remote_call",
                    "remote thread did not reach a completed state",
                    details={
                        "thread_running": True,
                        "code_allocation": code_address,
                        "parameter_allocation": parameter_address,
                    },
                ) from exc
            raise
        finally:
            if not thread_running:
                if parameter_address:
                    self.host._virtual_free(process, parameter_address)
                if code_address:
                    self.host._virtual_free(process, code_address)

    def _call_with_bytes_argument(
        self,
        process: Any,
        architecture: str,
        function: int,
        arguments: Sequence[Optional[int]],
        payload: bytes,
        timeout_ms: int,
    ) -> dict[str, Any]:
        payload_address = self._allocate(process, len(payload), self.PAGE_READWRITE)
        safe_to_free = True
        try:
            self._write(process, payload_address, payload, "remote call string")
            concrete = [payload_address if value is None else int(value) for value in arguments]
            return self._remote_call(process, architecture, function, concrete, timeout_ms)
        except ManualMapBackendError as exc:
            safe_to_free = not bool(exc.details.get("thread_running"))
            if not safe_to_free:
                exc.details.setdefault("retained_payload_allocation", payload_address)
            raise
        finally:
            if safe_to_free:
                self.host._virtual_free(process, payload_address)

    def _release_dependencies(
        self,
        process: Any,
        architecture: str,
        free_library: int,
        dependencies: Sequence[Mapping[str, Any]],
        timeout_ms: int,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        pointer_size = _pointer_size_for_architecture(architecture)
        if free_library:
            free_library = _checked_pointer_value(
                free_library,
                pointer_size,
                "remote FreeLibrary",
            )
        for dependency in reversed(dependencies):
            record = dict(dependency)
            record["release_order"] = len(records) + 1
            if not dependency.get("reference_added"):
                record["released"] = True
            elif not free_library:
                record["released"] = False
                record["error"] = "remote FreeLibrary address is unavailable"
            else:
                try:
                    call = self._remote_call(
                        process,
                        architecture,
                        free_library,
                        [int(dependency.get("handle") or 0)],
                        timeout_ms,
                    )
                    call, raw_result = _require_completed_remote_call(
                        call,
                        "FreeLibrary",
                        pointer_size,
                    )
                    record["released"] = bool(raw_result & 0xFFFFFFFF)
                    record["thread_id"] = call.get("thread_id")
                    if not record["released"]:
                        raise ManualMapBackendError(
                            "FreeLibrary",
                            f"target rejected release of dependency {record.get('name')}",
                            details={"raw_result": raw_result},
                        )
                except Exception as exc:
                    record["released"] = False
                    record["error"] = self._exception_payload(exc)
            records.append(record)
        return records

    def _find_module_by_name(self, pid: int, module_name: str) -> Optional[Mapping[str, Any]]:
        expected = module_name.casefold()
        return next(
            (
                item
                for item in self.host.list_modules(pid)
                if str(item.get("name") or "").casefold() == expected
            ),
            None,
        )

    def _allocate(self, process: Any, size: int, protection: int) -> int:
        pointer = self.kernel32.VirtualAllocEx(
            process,
            None,
            size,
            self.MEM_RESERVE | self.MEM_COMMIT,
            protection,
        )
        address = self._pointer_value(pointer)
        if not address:
            raise self._last_error("VirtualAllocEx")
        return address

    def _write(self, process: Any, address: int, payload: bytes | bytearray, label: str) -> None:
        data = bytes(payload)
        written = ctypes.c_size_t(0)
        buffer = ctypes.create_string_buffer(data, len(data))
        if not self.kernel32.WriteProcessMemory(
            process,
            ctypes.c_void_p(address),
            ctypes.cast(buffer, ctypes.c_void_p),
            len(data),
            ctypes.byref(written),
        ):
            raise self._last_error("WriteProcessMemory", details={"label": label})
        if int(written.value) != len(data):
            raise ManualMapBackendError(
                "WriteProcessMemory",
                f"partial write for {label}",
                details={"expected": len(data), "actual": int(written.value)},
            )

    def _read(self, process: Any, address: int, size: int, label: str) -> bytes:
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if not self.kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(address),
            ctypes.cast(buffer, ctypes.c_void_p),
            size,
            ctypes.byref(read),
        ):
            raise self._last_error("ReadProcessMemory", details={"label": label})
        if int(read.value) != size:
            raise ManualMapBackendError(
                "ReadProcessMemory",
                f"partial read for {label}",
                details={"expected": size, "actual": int(read.value)},
            )
        return bytes(buffer.raw[:size])

    def _protect(self, process: Any, address: int, size: int, protection: int) -> int:
        from ctypes import wintypes

        old = wintypes.DWORD(0)
        if not self.kernel32.VirtualProtectEx(
            process,
            ctypes.c_void_p(address),
            size,
            protection,
            ctypes.byref(old),
        ):
            raise self._last_error("VirtualProtectEx")
        return int(old.value)

    def _query_region(self, process: Any, address: int) -> dict[str, Any]:
        info = self.host._memory_basic_information_type()
        queried = int(
            self.kernel32.VirtualQueryEx(
                process,
                ctypes.c_void_p(address),
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
        )
        if queried != ctypes.sizeof(info):
            raise self._last_error("VirtualQueryEx")
        return {
            "base_address": self._pointer_value(info.BaseAddress),
            "allocation_base": self._pointer_value(info.AllocationBase),
            "region_size": int(info.RegionSize),
            "state": int(info.State),
            "protect": int(info.Protect),
            "type": int(info.Type),
        }

    def _release_image(self, process: Any, address: int) -> dict[str, Any]:
        """Release one image allocation and verify the resulting VAD state."""

        before = self._query_region(process, address)
        if before.get("state") == self.MEM_FREE:
            return {
                "attempted": False,
                "released": False,
                "already_free": True,
                "release_verified": True,
                "before_region": before,
                "after_region": before,
            }
        allocation_base = int(before.get("allocation_base") or 0)
        if before.get("state") != self.MEM_COMMIT or allocation_base != address:
            raise ManualMapBackendError(
                "VirtualQueryEx",
                "refusing to free an unexpected allocation",
                details={"expected_base": address, "region": before},
            )
        released = bool(
            self.kernel32.VirtualFreeEx(
                process,
                ctypes.c_void_p(address),
                0,
                self.MEM_RELEASE,
            )
        )
        after = self._query_region(process, address)
        verified = after.get("state") == self.MEM_FREE
        return {
            "attempted": True,
            "released": released,
            "already_free": False,
            "release_verified": verified,
            "winerror": None if released else ctypes.get_last_error(),
            "before_region": before,
            "after_region": after,
        }

    @classmethod
    def _native_protection(cls, rights: int) -> int:
        table = {
            0: cls.PAGE_NOACCESS,
            1: cls.PAGE_READONLY,
            2: cls.PAGE_READWRITE,
            3: cls.PAGE_READWRITE,
            4: cls.PAGE_EXECUTE,
            5: cls.PAGE_EXECUTE_READ,
        }
        if rights not in table:
            raise ManualMapBackendError(
                "VirtualProtectEx",
                "writable executable image pages are not permitted",
                details={"rights": rights},
            )
        return table[rights]

    @staticmethod
    def _x64_call_stub() -> bytes:
        return bytes.fromhex(
            "53 48 83 EC 20 48 89 CB 48 8B 03 48 8B 4B 08 "
            "48 8B 53 10 4C 8B 43 18 FF D0 48 89 43 20 "
            "C7 43 28 01 00 00 00 31 C0 48 83 C4 20 5B C3"
        )

    @staticmethod
    def _x86_call_stub(argument_count: int) -> bytes:
        if not 0 <= argument_count <= 3:
            raise ManualMapBackendError("remote_call", "invalid x86 argument count")
        code = bytearray.fromhex("53 8B 5C 24 08")
        for index in reversed(range(argument_count)):
            code.extend((0xFF, 0x73, 4 + index * 4))
        code.extend(bytes.fromhex("FF 13 89 43 10 C7 43 14 01 00 00 00 31 C0 5B C2 04 00"))
        return bytes(code)

    @classmethod
    def _require_same_identity(
        cls,
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
    ) -> None:
        missing = [field for field in cls._IDENTITY_FIELDS if expected.get(field) in (None, "")]
        if missing:
            raise ManualMapBackendError(
                "target_identity",
                "expected target identity is incomplete",
                details={"missing": missing},
            )
        mismatches: dict[str, Any] = {}
        for field in cls._IDENTITY_FIELDS:
            left = expected.get(field)
            right = actual.get(field)
            if field == "image_path":
                equal = os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
                    os.path.normpath(str(right))
                )
            else:
                equal = left == right
            if not equal:
                mismatches[field] = {"expected": left, "actual": right}
        if mismatches:
            raise ManualMapBackendError(
                "target_identity",
                "target process identity changed",
                details={"mismatches": mismatches},
            )

    @staticmethod
    def _pointer_value(value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, int):
            return value
        return int(ctypes.cast(value, ctypes.c_void_p).value or 0)

    @staticmethod
    def _exception_payload(exc: Exception) -> dict[str, Any]:
        if isinstance(exc, ManualMapBackendError):
            return exc.to_dict()
        payload = {"type": type(exc).__name__, "message": str(exc)}
        details = getattr(exc, "details", None)
        if isinstance(details, Mapping):
            payload["details"] = _json_value(details)
        return payload

    @staticmethod
    def _error_has_running_thread(exc: Exception) -> bool:
        details = getattr(exc, "details", {})
        return bool(isinstance(details, Mapping) and details.get("thread_running"))

    @staticmethod
    def _last_error(
        operation: str,
        *,
        details: Optional[Mapping[str, Any]] = None,
    ) -> ManualMapBackendError:
        code = ctypes.get_last_error()
        return ManualMapBackendError(
            operation,
            ctypes.FormatError(code).strip() or f"Win32 error {code}",
            code=code,
            details=details,
        )


def _map_image_bytes(
    data: bytes,
    size_of_image: int,
    size_of_headers: int,
    sections: Sequence[PESection],
) -> bytearray:
    mapped = bytearray(size_of_image)
    mapped[:size_of_headers] = data[:size_of_headers]
    for section in sections:
        if not section.raw_size:
            continue
        start = section.virtual_address
        end = start + section.raw_size
        mapped[start:end] = data[section.raw_offset : section.raw_offset + section.raw_size]
    return mapped


def _parse_tls_directory(
    mapped: bytes | bytearray,
    directory: tuple[int, int],
    image_base: int,
    size_of_image: int,
    sections: Sequence[PESection],
    machine: int,
) -> Optional[PETLSDirectory]:
    rva, size = directory
    if not rva and not size:
        return None
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ManualMapValidationError("unsupported: x86 TLS directories are not implemented")
    if size < 40:
        raise ManualMapValidationError("x64 TLS directory is smaller than IMAGE_TLS_DIRECTORY64")
    _require_buffer_range(mapped, rva, size, "TLS directory")
    tls_section = _section_for_range(sections, rva, size)
    if tls_section is None or not (tls_section.characteristics & IMAGE_SCN_MEM_READ):
        raise ManualMapValidationError("TLS directory is not contained in one section")
    (
        start_raw_data_va,
        end_raw_data_va,
        address_of_index_va,
        address_of_callbacks_va,
        size_of_zero_fill,
        characteristics,
    ) = struct.unpack_from("<QQQQII", mapped, rva)

    if bool(start_raw_data_va) != bool(end_raw_data_va):
        raise ManualMapValidationError("TLS raw-data VA range is incomplete")
    if start_raw_data_va:
        start_raw_data_rva = _image_va_to_rva(
            start_raw_data_va,
            image_base,
            size_of_image,
            "TLS StartAddressOfRawData",
        )
        end_raw_data_rva = _image_va_to_rva(
            end_raw_data_va,
            image_base,
            size_of_image,
            "TLS EndAddressOfRawData",
            allow_image_end=True,
        )
        if end_raw_data_rva < start_raw_data_rva:
            raise ManualMapValidationError("TLS raw-data VA range is reversed")
    if address_of_index_va:
        index_rva = _image_va_to_rva(
            address_of_index_va,
            image_base,
            size_of_image,
            "TLS AddressOfIndex",
        )
        _require_buffer_range(mapped, index_rva, 4, "TLS index storage")
        if index_rva % 4:
            raise ManualMapValidationError("TLS AddressOfIndex is not DWORD-aligned")
    if any((start_raw_data_va, end_raw_data_va, address_of_index_va, size_of_zero_fill)):
        raise ManualMapValidationError(
            "unsupported: static TLS storage/index initialization is required"
        )
    if characteristics:
        raise ManualMapValidationError(
            "unsupported: callback-only TLS directory has nonzero Characteristics"
        )

    callback_array_rva: Optional[int] = None
    callback_rvas: list[int] = []
    if address_of_callbacks_va:
        callback_array_rva = _image_va_to_rva(
            address_of_callbacks_va,
            image_base,
            size_of_image,
            "TLS AddressOfCallbacks",
        )
        if callback_array_rva % 8:
            raise ManualMapValidationError("TLS callback array is not pointer-aligned")
        callback_array_section = _section_for_range(sections, callback_array_rva, 8)
        if callback_array_section is None or not (
            callback_array_section.characteristics & IMAGE_SCN_MEM_READ
        ):
            raise ManualMapValidationError("TLS callback array is outside a section")
        for index in range(_MAX_TLS_CALLBACKS + 1):
            slot_rva = callback_array_rva + index * 8
            if slot_rva > size_of_image - 8:
                raise ManualMapValidationError(
                    "TLS callback array is not null-terminated within SizeOfImage"
                )
            if _section_for_range(sections, slot_rva, 8) is not callback_array_section:
                raise ManualMapValidationError(
                    "TLS callback array is not null-terminated within its containing section"
                )
            callback_va = _buffer_u64(mapped, slot_rva, "TLS callback array entry")
            if not callback_va:
                break
            if index == _MAX_TLS_CALLBACKS:
                raise ManualMapValidationError(
                    f"TLS callback count exceeds the {_MAX_TLS_CALLBACKS}-callback limit"
                )
            callback_rva = _image_va_to_rva(
                callback_va,
                image_base,
                size_of_image,
                f"TLS callback {index + 1}",
            )
            callback_section = _section_for_rva(sections, callback_rva)
            if callback_section is None or not (
                callback_section.characteristics & IMAGE_SCN_MEM_EXECUTE
            ):
                raise ManualMapValidationError(
                    f"TLS callback {index + 1} is not in an executable section"
                )
            callback_rvas.append(callback_rva)
        else:  # pragma: no cover - the bounded loop always exits by return or exception
            raise ManualMapValidationError("TLS callback array validation did not terminate")

    return PETLSDirectory(
        directory_rva=rva,
        directory_size=size,
        start_raw_data_va=start_raw_data_va,
        end_raw_data_va=end_raw_data_va,
        address_of_index_va=address_of_index_va,
        address_of_callbacks_va=address_of_callbacks_va,
        callback_array_rva=callback_array_rva,
        callback_rvas=tuple(callback_rvas),
        size_of_zero_fill=size_of_zero_fill,
        characteristics=characteristics,
    )


def _parse_runtime_functions(
    mapped: bytes | bytearray,
    directory: tuple[int, int],
    size_of_image: int,
    sections: Sequence[PESection],
    machine: int,
) -> list[PERuntimeFunction]:
    rva, size = directory
    if not rva and not size:
        return []
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise ManualMapValidationError("unsupported: non-x64 exception directory is present")
    if rva % 4:
        raise ManualMapValidationError("x64 exception directory RVA is not DWORD-aligned")
    if size < 12 or size % 12:
        raise ManualMapValidationError(
            "x64 exception/unwind directory size is not a nonzero multiple of RUNTIME_FUNCTION"
        )
    _require_buffer_range(mapped, rva, size, "x64 exception directory")
    exception_section = _section_for_range(sections, rva, size)
    if exception_section is None or not (
        exception_section.characteristics & IMAGE_SCN_MEM_READ
    ):
        raise ManualMapValidationError(
            "x64 exception directory is not contained in one section"
        )
    count = size // 12
    if count > _MAX_RUNTIME_FUNCTIONS:
        raise ManualMapValidationError(
            f"RUNTIME_FUNCTION count exceeds the {_MAX_RUNTIME_FUNCTIONS}-entry limit"
        )

    entries: list[PERuntimeFunction] = []
    previous_end = 0
    for index in range(count):
        entry_rva = rva + index * 12
        begin_rva, end_rva, unwind_info_rva = struct.unpack_from("<III", mapped, entry_rva)
        label = f"RUNTIME_FUNCTION entry {index + 1}"
        if not begin_rva or end_rva <= begin_rva or end_rva > size_of_image:
            raise ManualMapValidationError(f"{label} has an invalid code RVA range")
        begin_section = _section_for_rva(sections, begin_rva)
        end_section = _section_for_rva(sections, end_rva - 1)
        if (
            begin_section is None
            or end_section is not begin_section
            or not (begin_section.characteristics & IMAGE_SCN_MEM_EXECUTE)
        ):
            raise ManualMapValidationError(
                f"{label} code range is not contained in one executable section"
            )
        if entries and begin_rva < previous_end:
            raise ManualMapValidationError(
                "RUNTIME_FUNCTION entries are not strictly sorted and non-overlapping"
            )
        if not unwind_info_rva or unwind_info_rva % 4:
            raise ManualMapValidationError(f"{label} has an invalid unwind-info RVA")
        _validate_unwind_info(
            mapped,
            unwind_info_rva,
            size_of_image,
            sections,
            label,
            end_rva - begin_rva,
        )
        entries.append(
            PERuntimeFunction(
                begin_rva=begin_rva,
                end_rva=end_rva,
                unwind_info_rva=unwind_info_rva,
            )
        )
        previous_end = end_rva
    return entries


def _validate_unwind_info(
    mapped: bytes | bytearray,
    unwind_rva: int,
    size_of_image: int,
    sections: Sequence[PESection],
    runtime_label: str,
    function_length: int,
    *,
    _visited: Optional[set[int]] = None,
    _depth: int = 0,
) -> None:
    if _depth > _MAX_UNWIND_CHAIN_DEPTH:
        raise ManualMapValidationError(
            f"{runtime_label} exceeds the chained-unwind depth limit"
        )
    visited = set() if _visited is None else _visited
    if unwind_rva in visited:
        raise ManualMapValidationError(f"{runtime_label} has a cyclic chained-unwind record")
    visited.add(unwind_rva)
    _require_buffer_range(mapped, unwind_rva, 4, f"{runtime_label} UNWIND_INFO header")
    unwind_section = _section_for_rva(sections, unwind_rva)
    if unwind_section is None or not (unwind_section.characteristics & IMAGE_SCN_MEM_READ):
        raise ManualMapValidationError(f"{runtime_label} UNWIND_INFO is outside a section")
    version_and_flags, prolog_size, code_count, frame = struct.unpack_from(
        "<BBBB", mapped, unwind_rva
    )
    version = version_and_flags & 0x07
    flags = version_and_flags >> 3
    if version != 1:
        raise ManualMapValidationError(
            f"{runtime_label} uses unsupported UNWIND_INFO version {version}"
        )
    if flags & ~0x07 or (flags & 0x04 and flags & 0x03):
        raise ManualMapValidationError(f"{runtime_label} has invalid UNWIND_INFO flags")
    if prolog_size > function_length:
        raise ManualMapValidationError(
            f"{runtime_label} UNWIND_INFO prolog exceeds its function range"
        )
    frame_register = frame & 0x0F
    frame_offset = frame >> 4
    if not frame_register and frame_offset:
        raise ManualMapValidationError(
            f"{runtime_label} has a frame offset without a frame register"
        )
    nonvolatile_registers = {3, 5, 6, 7, 12, 13, 14, 15}
    if frame_register and frame_register not in nonvolatile_registers:
        raise ManualMapValidationError(
            f"{runtime_label} frame register is not a nonvolatile x64 register"
        )

    code_bytes = code_count * 2
    codes_end = unwind_rva + 4 + code_bytes
    trailer_rva = (codes_end + 3) & ~3
    _require_buffer_range(
        mapped,
        unwind_rva,
        trailer_rva - unwind_rva,
        f"{runtime_label} unwind codes",
    )
    if _section_for_range(sections, unwind_rva, trailer_rva - unwind_rva) is not unwind_section:
        raise ManualMapValidationError(f"{runtime_label} UNWIND_INFO crosses a section boundary")
    slot = 0
    previous_code_offset = prolog_size + 1
    saw_set_frame_register = False
    while slot < code_count:
        code_rva = unwind_rva + 4 + slot * 2
        code_offset, operation_byte = struct.unpack_from("<BB", mapped, code_rva)
        operation = operation_byte & 0x0F
        operation_info = operation_byte >> 4
        if code_offset > prolog_size or code_offset > previous_code_offset:
            raise ManualMapValidationError(
                f"{runtime_label} unwind codes are not ordered within the prolog"
            )
        if operation == 1:
            if operation_info == 0:
                extra_slots = 1
            elif operation_info == 1:
                extra_slots = 2
            else:
                raise ManualMapValidationError(
                    f"{runtime_label} has invalid UWOP_ALLOC_LARGE metadata"
                )
        elif operation == 4:
            if operation_info not in nonvolatile_registers:
                raise ManualMapValidationError(
                    f"{runtime_label} UWOP_SAVE_NONVOL names a volatile register"
                )
            extra_slots = 1
        elif operation == 5:
            if operation_info not in nonvolatile_registers:
                raise ManualMapValidationError(
                    f"{runtime_label} UWOP_SAVE_NONVOL_FAR names a volatile register"
                )
            extra_slots = 2
        elif operation == 8:
            if operation_info < 6:
                raise ManualMapValidationError(
                    f"{runtime_label} UWOP_SAVE_XMM128 names a volatile register"
                )
            extra_slots = 1
        elif operation == 9:
            if operation_info < 6:
                raise ManualMapValidationError(
                    f"{runtime_label} UWOP_SAVE_XMM128_FAR names a volatile register"
                )
            extra_slots = 2
        elif operation == 0:
            if operation_info not in nonvolatile_registers:
                raise ManualMapValidationError(
                    f"{runtime_label} UWOP_PUSH_NONVOL names a volatile register"
                )
            extra_slots = 0
        elif operation == 2:
            extra_slots = 0
        elif operation == 3:
            if operation_info:
                raise ManualMapValidationError(
                    f"{runtime_label} has invalid UWOP_SET_FPREG metadata"
                )
            saw_set_frame_register = True
            extra_slots = 0
        elif operation == 10:
            if operation_info > 1:
                raise ManualMapValidationError(
                    f"{runtime_label} has invalid UWOP_PUSH_MACHFRAME metadata"
                )
            extra_slots = 0
        else:
            raise ManualMapValidationError(
                f"{runtime_label} uses reserved unwind operation {operation}"
            )
        if slot + extra_slots >= code_count:
            raise ManualMapValidationError(f"{runtime_label} has truncated unwind operation data")
        previous_code_offset = code_offset
        slot += 1 + extra_slots
    if bool(frame_register) != saw_set_frame_register:
        raise ManualMapValidationError(
            f"{runtime_label} frame-register metadata does not match its unwind codes"
        )

    if flags & 0x04:
        _require_buffer_range(mapped, trailer_rva, 12, f"{runtime_label} chained unwind entry")
        if _section_for_range(sections, trailer_rva, 12) is not unwind_section:
            raise ManualMapValidationError(
                f"{runtime_label} chained unwind entry crosses a section boundary"
            )
        chained_begin, chained_end, chained_unwind = struct.unpack_from(
            "<III", mapped, trailer_rva
        )
        if (
            not chained_begin
            or chained_end <= chained_begin
            or chained_end > size_of_image
            or not chained_unwind
            or chained_unwind % 4
        ):
            raise ManualMapValidationError(f"{runtime_label} has invalid chained unwind data")
        chained_begin_section = _section_for_rva(sections, chained_begin)
        chained_end_section = _section_for_rva(sections, chained_end - 1)
        chained_unwind_section = _section_for_range(sections, chained_unwind, 4)
        if (
            chained_begin_section is None
            or chained_end_section is not chained_begin_section
            or not (chained_begin_section.characteristics & IMAGE_SCN_MEM_EXECUTE)
            or chained_unwind_section is None
            or not (chained_unwind_section.characteristics & IMAGE_SCN_MEM_READ)
        ):
            raise ManualMapValidationError(
                f"{runtime_label} chained unwind data references invalid image ranges"
            )
        _validate_unwind_info(
            mapped,
            chained_unwind,
            size_of_image,
            sections,
            f"{runtime_label} chained entry",
            chained_end - chained_begin,
            _visited=visited,
            _depth=_depth + 1,
        )
    elif flags & 0x03:
        _require_buffer_range(mapped, trailer_rva, 4, f"{runtime_label} exception handler RVA")
        if _section_for_range(sections, trailer_rva, 4) is not unwind_section:
            raise ManualMapValidationError(
                f"{runtime_label} exception-handler field crosses a section boundary"
            )
        handler_rva = _buffer_u32(mapped, trailer_rva, "exception handler RVA")
        handler_section = _section_for_rva(sections, handler_rva)
        if handler_section is None or not (
            handler_section.characteristics & IMAGE_SCN_MEM_EXECUTE
        ):
            raise ManualMapValidationError(
                f"{runtime_label} exception handler is not in an executable section"
            )


def _image_va_to_rva(
    va: int,
    image_base: int,
    size_of_image: int,
    label: str,
    *,
    allow_image_end: bool = False,
) -> int:
    if va < image_base:
        raise ManualMapValidationError(f"{label} is below ImageBase")
    rva = va - image_base
    upper_bound = size_of_image if allow_image_end else size_of_image - 1
    if rva > upper_bound:
        raise ManualMapValidationError(f"{label} is outside SizeOfImage")
    return rva


def _parse_imports(
    mapped: bytes | bytearray,
    directory: tuple[int, int],
    pointer_size: int,
) -> list[PEImportModule]:
    rva, size = directory
    if not rva and not size:
        return []
    _require_buffer_range(mapped, rva, size, "import directory")
    modules: list[PEImportModule] = []
    cursor = rva
    end = rva + size
    total_symbols = 0
    terminated = False
    while cursor + 20 <= end:
        original_thunk, timestamp, forwarder_chain, name_rva, first_thunk = struct.unpack_from(
            "<IIIII", mapped, cursor
        )
        cursor += 20
        if not any((original_thunk, timestamp, forwarder_chain, name_rva, first_thunk)):
            terminated = True
            break
        if len(modules) >= _MAX_IMPORT_MODULES:
            raise ManualMapValidationError("import module count exceeds validation limit")
        if timestamp or forwarder_chain:
            raise ManualMapValidationError(
                "unsupported: bound import descriptor metadata is present"
            )
        if not name_rva or not first_thunk:
            raise ManualMapValidationError("import descriptor is missing Name or FirstThunk")
        module_name = _read_ascii(mapped, name_rva, "import module name", maximum=260)
        if any(character in module_name for character in ("/", "\\", ":")):
            raise ManualMapValidationError(
                f"unsupported: import module path is not a bare DLL name: {module_name!r}"
            )
        lookup_rva = original_thunk or first_thunk
        symbols: list[PEImportSymbol] = []
        index = 0
        ordinal_flag = 1 << (pointer_size * 8 - 1)
        pointer_mask = ordinal_flag - 1
        while True:
            thunk_rva = lookup_rva + index * pointer_size
            iat_rva = first_thunk + index * pointer_size
            _require_buffer_range(mapped, thunk_rva, pointer_size, "import lookup thunk")
            _require_buffer_range(mapped, iat_rva, pointer_size, "IAT thunk")
            value = (
                _buffer_u32(mapped, thunk_rva, "PE32 import thunk")
                if pointer_size == 4
                else _buffer_u64(mapped, thunk_rva, "PE32+ import thunk")
            )
            if value == 0:
                break
            total_symbols += 1
            if total_symbols > _MAX_IMPORT_SYMBOLS:
                raise ManualMapValidationError("import symbol count exceeds validation limit")
            if value & ordinal_flag:
                ordinal = value & 0xFFFF
                if not ordinal or value & pointer_mask != ordinal:
                    raise ManualMapValidationError("invalid import-by-ordinal thunk")
                symbols.append(PEImportSymbol(iat_rva=iat_rva, ordinal=ordinal))
            else:
                name_entry_rva = value & pointer_mask
                _require_buffer_range(mapped, name_entry_rva, 3, "IMAGE_IMPORT_BY_NAME")
                hint = _buffer_u16(mapped, name_entry_rva, "import hint")
                symbol_name = _read_ascii(
                    mapped,
                    name_entry_rva + 2,
                    "import symbol name",
                    maximum=_MAX_STRING,
                )
                symbols.append(
                    PEImportSymbol(
                        iat_rva=iat_rva,
                        name=symbol_name,
                        hint=hint,
                    )
                )
            index += 1
        modules.append(PEImportModule(name=module_name, symbols=tuple(symbols)))
    if not terminated:
        raise ManualMapValidationError("import descriptor table is not null-terminated")
    return modules


def _parse_delay_imports(
    mapped: bytes | bytearray,
    directory: tuple[int, int],
    pointer_size: int,
) -> list[PEDelayImportModule]:
    rva, size = directory
    if not rva and not size:
        return []
    if size < 32:
        raise ManualMapValidationError(
            "delay imports directory is too small for a descriptor and terminator"
        )
    _require_buffer_range(mapped, rva, size, "delay imports directory")
    modules: list[PEDelayImportModule] = []
    cursor = rva
    end = rva + size
    total_symbols = 0
    terminated = False
    while cursor + 32 <= end:
        (
            attributes,
            name_rva,
            module_handle_rva,
            iat_rva,
            name_table_rva,
            bound_iat_rva,
            unload_iat_rva,
            timestamp,
        ) = struct.unpack_from("<8I", mapped, cursor)
        cursor += 32
        if not any(
            (
                attributes,
                name_rva,
                module_handle_rva,
                iat_rva,
                name_table_rva,
                bound_iat_rva,
                unload_iat_rva,
                timestamp,
            )
        ):
            terminated = True
            if any(mapped[cursor:end]):
                raise ManualMapValidationError(
                    "delay imports directory has data after its null descriptor"
                )
            break
        if len(modules) >= _MAX_IMPORT_MODULES:
            raise ManualMapValidationError("delay import module count exceeds validation limit")
        if attributes != _DELAY_IMPORT_ATTRIBUTE_RVA:
            raise ManualMapValidationError(
                "unsupported: delay imports require an RVA-based descriptor with no reserved flags"
            )
        if not all((name_rva, module_handle_rva, iat_rva, name_table_rva)):
            raise ManualMapValidationError(
                "delay imports descriptor is missing Name, ModuleHandle, IAT, or INT"
            )
        if bound_iat_rva or timestamp:
            raise ManualMapValidationError(
                "unsupported: bound delay imports require loader timestamp validation"
            )
        if unload_iat_rva:
            raise ManualMapValidationError(
                "unsupported: unloadable delay imports can change dependency ownership at runtime"
            )

        module_name = _read_ascii(mapped, name_rva, "delay import module name", maximum=260)
        if any(character in module_name for character in ("/", "\\", ":")):
            raise ManualMapValidationError(
                f"unsupported: delay import module path is not a bare DLL name: {module_name!r}"
            )
        _require_buffer_range(
            mapped,
            module_handle_rva,
            pointer_size,
            "delay-import module handle slot",
        )

        symbols: list[PEImportSymbol] = []
        index = 0
        ordinal_flag = 1 << (pointer_size * 8 - 1)
        pointer_mask = ordinal_flag - 1
        while True:
            thunk_rva = name_table_rva + index * pointer_size
            slot_rva = iat_rva + index * pointer_size
            _require_buffer_range(mapped, thunk_rva, pointer_size, "delay import name thunk")
            _require_buffer_range(mapped, slot_rva, pointer_size, "delay IAT thunk")
            value = (
                _buffer_u32(mapped, thunk_rva, "PE32 delay import thunk")
                if pointer_size == 4
                else _buffer_u64(mapped, thunk_rva, "PE32+ delay import thunk")
            )
            if value == 0:
                iat_terminator = (
                    _buffer_u32(mapped, slot_rva, "PE32 delay IAT terminator")
                    if pointer_size == 4
                    else _buffer_u64(mapped, slot_rva, "PE32+ delay IAT terminator")
                )
                if iat_terminator:
                    raise ManualMapValidationError("delay IAT is not null-terminated")
                break
            total_symbols += 1
            if total_symbols > _MAX_IMPORT_SYMBOLS:
                raise ManualMapValidationError("delay import symbol count exceeds validation limit")
            if value & ordinal_flag:
                ordinal = value & 0xFFFF
                if not ordinal or value & pointer_mask != ordinal:
                    raise ManualMapValidationError("invalid delay import-by-ordinal thunk")
                symbols.append(PEImportSymbol(iat_rva=slot_rva, ordinal=ordinal))
            else:
                name_entry_rva = value & pointer_mask
                _require_buffer_range(mapped, name_entry_rva, 3, "delay IMAGE_IMPORT_BY_NAME")
                hint = _buffer_u16(mapped, name_entry_rva, "delay import hint")
                symbol_name = _read_ascii(
                    mapped,
                    name_entry_rva + 2,
                    "delay import symbol name",
                    maximum=_MAX_STRING,
                )
                symbols.append(
                    PEImportSymbol(
                        iat_rva=slot_rva,
                        name=symbol_name,
                        hint=hint,
                    )
                )
            index += 1
        if not symbols:
            raise ManualMapValidationError(
                f"delay imports descriptor for {module_name} contains no symbols"
            )
        modules.append(
            PEDelayImportModule(
                name=module_name,
                module_handle_rva=module_handle_rva,
                iat_rva=iat_rva,
                name_table_rva=name_table_rva,
                symbols=tuple(symbols),
            )
        )
    if not terminated:
        raise ManualMapValidationError("delay imports descriptor table is not null-terminated")
    return modules


def _validate_import_storage(
    imports: Sequence[PEImportModule],
    delay_imports: Sequence[PEDelayImportModule],
    pointer_size: int,
) -> None:
    ranges: list[tuple[int, int, str]] = []
    for module in imports:
        for symbol in module.symbols:
            ranges.append(
                (symbol.iat_rva, symbol.iat_rva + pointer_size, f"import {module.name} IAT")
            )
    for module in delay_imports:
        ranges.append(
            (
                module.module_handle_rva,
                module.module_handle_rva + pointer_size,
                f"delay import {module.name} module handle",
            )
        )
        for symbol in module.symbols:
            ranges.append(
                (
                    symbol.iat_rva,
                    symbol.iat_rva + pointer_size,
                    f"delay import {module.name} IAT",
                )
            )
    for start, _end, label in ranges:
        if start % pointer_size:
            raise ManualMapValidationError(f"{label} is not pointer-aligned")
    for previous, current in zip(sorted(ranges), sorted(ranges)[1:]):
        if current[0] < previous[1]:
            raise ManualMapValidationError(
                f"import storage overlaps between {previous[2]} and {current[2]}"
            )


def _parse_relocations(
    mapped: bytes | bytearray,
    directory: tuple[int, int],
    machine: int,
) -> list[PERelocation]:
    rva, size = directory
    if not rva and not size:
        return []
    _require_buffer_range(mapped, rva, size, "base-relocation directory")
    expected_type = (
        IMAGE_REL_BASED_HIGHLOW if machine == IMAGE_FILE_MACHINE_I386 else IMAGE_REL_BASED_DIR64
    )
    pointer_size = 4 if machine == IMAGE_FILE_MACHINE_I386 else 8
    cursor = rva
    end = rva + size
    relocations: list[PERelocation] = []
    while cursor < end:
        if end - cursor < 8:
            if all(value == 0 for value in mapped[cursor:end]):
                break
            raise ManualMapValidationError("truncated base-relocation block")
        page_rva, block_size = struct.unpack_from("<II", mapped, cursor)
        if not page_rva and not block_size:
            if any(mapped[cursor:end]):
                raise ManualMapValidationError("invalid zero base-relocation block")
            break
        if block_size < 8 or block_size % 2 or cursor + block_size > end:
            raise ManualMapValidationError("invalid base-relocation block size")
        for offset in range(cursor + 8, cursor + block_size, 2):
            entry = _buffer_u16(mapped, offset, "base-relocation entry")
            relocation_type = entry >> 12
            target_rva = page_rva + (entry & 0x0FFF)
            if relocation_type == IMAGE_REL_BASED_ABSOLUTE:
                continue
            if relocation_type != expected_type:
                raise ManualMapValidationError(
                    f"unsupported: relocation type {relocation_type} for machine 0x{machine:04x}"
                )
            _require_buffer_range(mapped, target_rva, pointer_size, "base-relocation target")
            relocations.append(PERelocation(rva=target_rva, type=relocation_type))
        cursor += block_size
    return relocations


def _build_page_protection_plan(
    image_size: int,
    header_size: int,
    sections: Sequence[PESection],
) -> list[dict[str, Any]]:
    page_count = (image_size + _PAGE_SIZE - 1) // _PAGE_SIZE
    rights = [0] * page_count
    for page in range((header_size + _PAGE_SIZE - 1) // _PAGE_SIZE):
        rights[page] |= 0x1  # read
    for section in sections:
        if not section.mapped_size:
            continue
        section_rights = 0
        if section.characteristics & IMAGE_SCN_MEM_READ:
            section_rights |= 0x1
        if section.characteristics & IMAGE_SCN_MEM_WRITE:
            section_rights |= 0x2
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE:
            section_rights |= 0x4
        first_page = section.virtual_address // _PAGE_SIZE
        last_page = (section.virtual_address + section.mapped_size - 1) // _PAGE_SIZE
        for page in range(first_page, last_page + 1):
            rights[page] |= section_rights
    if any((value & 0x2) and (value & 0x4) for value in rights):
        raise ManualMapValidationError(
            "unsupported: section layout would create a writable executable page"
        )
    ranges: list[dict[str, Any]] = []
    start_page = 0
    for page in range(1, page_count + 1):
        if page < page_count and rights[page] == rights[start_page]:
            continue
        ranges.append(
            {
                "rva": start_page * _PAGE_SIZE,
                "size": min(image_size, page * _PAGE_SIZE) - start_page * _PAGE_SIZE,
                "rights": rights[start_page],
            }
        )
        start_page = page
    return ranges


def _section_for_rva(sections: Sequence[PESection], rva: int) -> Optional[PESection]:
    for section in sections:
        if section.virtual_address <= rva < section.virtual_address + section.mapped_size:
            return section
    return None


def _section_for_range(
    sections: Sequence[PESection],
    rva: int,
    size: int,
) -> Optional[PESection]:
    if rva < 0 or size <= 0:
        return None
    end = rva + size
    for section in sections:
        section_end = section.virtual_address + section.mapped_size
        if section.virtual_address <= rva and end <= section_end:
            return section
    return None


def _overlap_issues(ranges: Sequence[tuple[int, int, str]], kind: str) -> list[str]:
    issues: list[str] = []
    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] < previous[1]:
            issues.append(
                f"sections {previous[2]} and {current[2]} have overlapping {kind} ranges"
            )
    return issues


def _read_ascii(
    data: bytes | bytearray,
    offset: int,
    label: str,
    *,
    maximum: int,
) -> str:
    _require_buffer_range(data, offset, 1, label)
    end_limit = min(len(data), offset + maximum + 1)
    end = data.find(b"\0", offset, end_limit)
    if end < 0:
        raise ManualMapValidationError(f"{label} is not null-terminated within {maximum} bytes")
    raw = bytes(data[offset:end])
    if not raw:
        raise ManualMapValidationError(f"{label} is empty")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ManualMapValidationError(f"{label} is not ASCII") from exc


def _u16(data: bytes, offset: int, label: str) -> int:
    _require_range(data, offset, 2, label)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int, label: str) -> int:
    _require_range(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int, label: str) -> int:
    _require_range(data, offset, 8, label)
    return struct.unpack_from("<Q", data, offset)[0]


def _buffer_u16(data: bytes | bytearray, offset: int, label: str) -> int:
    _require_buffer_range(data, offset, 2, label)
    return struct.unpack_from("<H", data, offset)[0]


def _buffer_u32(data: bytes | bytearray, offset: int, label: str) -> int:
    _require_buffer_range(data, offset, 4, label)
    return struct.unpack_from("<I", data, offset)[0]


def _buffer_u64(data: bytes | bytearray, offset: int, label: str) -> int:
    _require_buffer_range(data, offset, 8, label)
    return struct.unpack_from("<Q", data, offset)[0]


def _require_range(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ManualMapValidationError(f"{label} exceeds the PE file")


def _require_buffer_range(
    data: bytes | bytearray,
    offset: int,
    size: int,
    label: str,
) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ManualMapValidationError(f"{label} exceeds SizeOfImage")


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _deduplicate(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in items if item))


def _loader_coverage() -> dict[str, Any]:
    return {
        "status": "partial",
        "production_backend": "Win32ManualMapper",
        "supported": list(_LOADER_SUPPORTED_FEATURES),
        "dependency_gated": [],
        "fail_closed": list(_LOADER_FAIL_CLOSED_FEATURES),
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
