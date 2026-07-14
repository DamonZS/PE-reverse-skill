"""Generate architecture-locked DLL export-forwarding proxy projects.

The generator only reads a DLL that already lives in an explicit copy root and
creates a new project below that same root.  Forwarders are emitted through a
module-definition file; no generated C trampoline attempts to guess a calling
convention or function signature.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile
from typing import Any, Mapping


_MAX_INPUT_SIZE = 512 * 1024 * 1024
_MAX_SECTIONS = 96
_MAX_EXPORTS = 65_535
_MAX_EXPORT_NAME = 4_096
_IMAGE_FILE_DLL = 0x2000
_ARCHITECTURES = {
    (0x014C, 0x10B): ("x86", 32),
    (0x01C0, 0x10B): ("arm", 32),
    (0x01C4, 0x10B): ("arm", 32),
    (0x8664, 0x20B): ("x64", 64),
    (0xAA64, 0x20B): ("arm64", 64),
}
_ARCHITECTURE_ALIASES = {
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "win32": "x86",
    "x64": "x64",
    "x86_64": "x64",
    "x86-64": "x64",
    "amd64": "x64",
    "arm": "arm",
    "arm32": "arm",
    "arm64": "arm64",
    "aarch64": "arm64",
}
_DLL_STEM_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$")
_DEF_NAME_RE = re.compile(r"^[A-Za-z0-9_?$@.:-]+$")
_DEF_KEYWORDS = frozenset(
    {
        "BASE",
        "CODE",
        "CONSTANT",
        "DATA",
        "DESCRIPTION",
        "DIRECTIVE",
        "EXECUTE",
        "EXPORTS",
        "HEAPSIZE",
        "IMPORTS",
        "LIBRARY",
        "NAME",
        "NONAME",
        "PRIVATE",
        "READ",
        "SECTIONS",
        "SEGMENTS",
        "SHARED",
        "STACKSIZE",
        "VERSION",
        "WRITE",
    }
)
_FORWARDER_MODULE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_FORWARDER_TARGET_RE = re.compile(r"^(?:#[1-9][0-9]{0,4}|[A-Za-z0-9_?$@.:-]+)$")
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


class DllProxyGenerationError(ValueError):
    """Base error for rejected proxy inputs and projects."""


class MalformedPEError(DllProxyGenerationError):
    """Raised when PE layout or export metadata is malformed."""


class DuplicateExportError(MalformedPEError):
    """Raised when names or ordinal bindings are duplicated."""


class ArchitectureMismatchError(DllProxyGenerationError):
    """Raised when machine, optional-header format, and requested arch differ."""


class PathBoundaryError(DllProxyGenerationError):
    """Raised when an input or output escapes the declared copy root."""


@dataclass(frozen=True)
class PEExport:
    """One populated Export Address Table slot."""

    ordinal: int
    name: str | None
    target_rva: int
    forwarder: str | None
    address_table_index: int

    @property
    def noname(self) -> bool:
        return self.name is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "address_table_index": self.address_table_index,
            "forwarder": self.forwarder,
            "name": self.name,
            "noname": self.noname,
            "ordinal": self.ordinal,
            "target_rva": self.target_rva,
        }


@dataclass(frozen=True)
class PEExportTable:
    """Validated PE architecture and export-directory snapshot."""

    architecture: str
    bits: int
    machine: int
    optional_magic: int
    dll_name: str
    ordinal_base: int
    function_count: int
    name_count: int
    exports: tuple[PEExport, ...]
    hole_ordinals: tuple[int, ...]
    source_sha256: str
    file_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "bits": self.bits,
            "dll_name": self.dll_name,
            "exports": [item.to_dict() for item in self.exports],
            "file_size": self.file_size,
            "function_count": self.function_count,
            "hole_ordinals": list(self.hole_ordinals),
            "machine": self.machine,
            "machine_hex": f"0x{self.machine:04X}",
            "name_count": self.name_count,
            "optional_magic": self.optional_magic,
            "ordinal_base": self.ordinal_base,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class DllProxyProject:
    """Committed proxy-project result."""

    copy_dir: Path
    source_dll: Path
    project_dir: Path
    proxy_name: str
    backing_name: str
    export_table: PEExportTable
    artifacts: tuple[Path, ...]

    @property
    def architecture(self) -> str:
        return self.export_table.architecture

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "artifacts": [str(item) for item in self.artifacts],
            "backing_name": self.backing_name,
            "copy_dir": str(self.copy_dir),
            "export_count": len(self.export_table.exports),
            "project_dir": str(self.project_dir),
            "proxy_name": self.proxy_name,
            "source_dll": str(self.source_dll),
            "status": "generated",
        }


@dataclass(frozen=True)
class _Section:
    index: int
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass(frozen=True)
class _PEImage:
    data: bytes
    size_of_headers: int
    size_of_image: int
    sections: tuple[_Section, ...]

    def rva_to_offset(self, rva: int, size: int, *, label: str) -> int:
        if rva < 0 or size < 0 or rva + size > 0x1_0000_0000:
            raise MalformedPEError(f"{label} has an invalid RVA range")
        candidates: list[int] = []
        if rva < self.size_of_headers and rva + size <= self.size_of_headers:
            if rva + size <= len(self.data):
                candidates.append(rva)
        for section in self.sections:
            if section.virtual_address <= rva and rva + size <= section.virtual_end:
                relative = rva - section.virtual_address
                if relative + size <= section.raw_size and section.raw_offset + relative + size <= len(self.data):
                    candidates.append(section.raw_offset + relative)
        if len(candidates) > 1:
            raise MalformedPEError(f"{label} RVA 0x{rva:X} is mapped ambiguously")
        if not candidates:
            raise MalformedPEError(f"{label} RVA 0x{rva:X}+{size} is not file-backed")
        return candidates[0]

    def contiguous_rva_limit(self, rva: int, *, label: str) -> tuple[int, int]:
        offset = self.rva_to_offset(rva, 1, label=label)
        if rva < self.size_of_headers:
            return offset, min(self.size_of_headers, len(self.data)) - offset
        matches = [section for section in self.sections if section.virtual_address <= rva < section.virtual_end]
        if len(matches) != 1:
            raise MalformedPEError(f"{label} RVA 0x{rva:X} is mapped ambiguously")
        section = matches[0]
        relative = rva - section.virtual_address
        return offset, min(section.raw_size - relative, len(self.data) - offset)

    def validate_target_rva(self, rva: int, *, label: str) -> None:
        if rva <= 0 or rva >= self.size_of_image:
            raise MalformedPEError(f"{label} RVA 0x{rva:X} is outside SizeOfImage")
        matches = [section for section in self.sections if section.virtual_address <= rva < section.virtual_end]
        if len(matches) != 1:
            detail = "ambiguous" if matches else "not mapped by a section"
            raise MalformedPEError(f"{label} RVA 0x{rva:X} is {detail}")


def parse_pe_exports(
    path: str | Path,
    *,
    expected_architecture: str | None = None,
) -> PEExportTable:
    """Parse and strictly validate a PE32/PE32+ DLL export directory."""

    source = Path(path).resolve()
    if not source.is_file():
        raise DllProxyGenerationError(f"DLL does not exist or is not a regular file: {source}")
    data = _read_input(source)
    return _parse_pe_exports_bytes(
        data,
        source_label=source.name,
        expected_architecture=expected_architecture,
    )


def generate_dll_proxy_project(
    source_dll: str | Path,
    *,
    copy_dir: str | Path,
    project_dir: str | Path | None = None,
    expected_architecture: str | None = None,
    proxy_name: str | None = None,
) -> DllProxyProject:
    """Generate a C/CMake forwarding project wholly inside ``copy_dir``.

    ``source_dll`` must already be a copied DLL below ``copy_dir``.  The source
    is never changed; an exact backing copy is placed in the generated project.
    Existing project paths are rejected to avoid taking ownership of files from
    another process or user.
    """

    copy_root = Path(copy_dir).resolve()
    if not copy_root.is_dir():
        raise PathBoundaryError(f"copy directory does not exist: {copy_root}")
    source = Path(source_dll).resolve()
    _require_within(copy_root, source, label="source DLL", strict_descendant=False)
    if not source.is_file():
        raise DllProxyGenerationError(f"source DLL does not exist or is not a regular file: {source}")
    if source.suffix.casefold() != ".dll":
        raise DllProxyGenerationError("source DLL must have a .dll filename")

    selected_proxy_name = _validate_dll_filename(proxy_name or source.name, label="proxy name")
    proxy_stem = Path(selected_proxy_name).stem
    backing_name = f"{proxy_stem}_original.dll"
    backing_module = Path(backing_name).stem
    if selected_proxy_name.casefold() == backing_name.casefold():
        raise DllProxyGenerationError("proxy and backing DLL names must be distinct")

    if project_dir is None:
        project = copy_root / f"{proxy_stem}_proxy_project"
    else:
        supplied = Path(project_dir)
        project = supplied if supplied.is_absolute() else copy_root / supplied
    project = project.resolve()
    _require_within(copy_root, project, label="project directory", strict_descendant=True)
    if project.exists():
        raise DllProxyGenerationError(f"project directory already exists: {project}")

    source_data = _read_input(source)
    source_hash = _sha256(source_data)
    table = _parse_pe_exports_bytes(
        source_data,
        source_label=source.name,
        expected_architecture=expected_architecture,
    )
    if not table.exports:
        raise DllProxyGenerationError("source DLL has no populated exports to forward")

    forwarding = _forwarding_records(table, backing_module)
    definition = _render_definition(selected_proxy_name, forwarding)
    c_source = _render_c_source(table.architecture)
    cmake = _render_cmake(
        architecture=table.architecture,
        bits=table.bits,
        proxy_name=selected_proxy_name,
        backing_name=backing_name,
    )

    source_relative = _relative_path(copy_root, source)
    project_relative = _relative_path(copy_root, project)
    backing_relative = f"{project_relative}/backing/{backing_name}"
    core_files: dict[str, bytes] = {
        "CMakeLists.txt": cmake.encode("ascii"),
        "backing/" + backing_name: source_data,
        "proxy.c": c_source.encode("ascii"),
        "proxy.def": definition.encode("ascii"),
    }
    build_manifest = _build_manifest(
        table=table,
        source_relative=source_relative,
        project_relative=project_relative,
        proxy_name=selected_proxy_name,
        backing_name=backing_name,
        backing_relative=backing_relative,
        forwarding=forwarding,
        core_files=core_files,
    )
    validation_report = _validation_report(
        table=table,
        source_relative=source_relative,
        project_relative=project_relative,
        proxy_name=selected_proxy_name,
        backing_name=backing_name,
        forwarding=forwarding,
    )
    risk_report = _risk_report(table, forwarding)
    files = dict(core_files)
    files["build_manifest.json"] = _json_bytes(build_manifest)
    files["risk_report.json"] = _json_bytes(risk_report)
    files["validation_report.json"] = _json_bytes(validation_report)

    missing_parents = _missing_parent_paths(copy_root, project.parent)
    rollback = _rollback_metadata(
        source_relative=source_relative,
        source_hash=source_hash,
        project_relative=project_relative,
        files=files,
        missing_parents=missing_parents,
    )
    files["rollback.json"] = _json_bytes(rollback)

    _commit_project(
        copy_root=copy_root,
        source=source,
        expected_source_hash=source_hash,
        project=project,
        files=files,
        missing_parents=missing_parents,
    )
    artifacts = tuple((project / name).resolve() for name in sorted(files))
    return DllProxyProject(
        copy_dir=copy_root,
        source_dll=source,
        project_dir=project,
        proxy_name=selected_proxy_name,
        backing_name=backing_name,
        export_table=table,
        artifacts=artifacts,
    )


def generate_dll_proxy(*args: Any, **kwargs: Any) -> DllProxyProject:
    """Compatibility spelling for :func:`generate_dll_proxy_project`."""

    return generate_dll_proxy_project(*args, **kwargs)


def _parse_pe_exports_bytes(
    data: bytes,
    *,
    source_label: str,
    expected_architecture: str | None,
) -> PEExportTable:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise MalformedPEError("missing or truncated DOS MZ header")
    pe_offset = _u32(data, 0x3C, "DOS e_lfanew")
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise MalformedPEError("DOS e_lfanew does not locate a complete PE header")
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise MalformedPEError("invalid PE signature")

    machine, section_count, _, _, _, optional_size, characteristics = _unpack(
        data,
        "<HHIIIHH",
        pe_offset + 4,
        "COFF file header",
    )
    if not (characteristics & _IMAGE_FILE_DLL):
        raise MalformedPEError("PE image is not marked IMAGE_FILE_DLL")
    if section_count <= 0 or section_count > _MAX_SECTIONS:
        raise MalformedPEError(f"invalid PE section count: {section_count}")
    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data):
        raise MalformedPEError("optional header extends beyond the file")
    if optional_size < 2:
        raise MalformedPEError("optional header is truncated")
    optional_magic = _u16(data, optional_offset, "optional-header magic")
    architecture, bits = _architecture(machine, optional_magic, expected_architecture)
    directory_base = 96 if optional_magic == 0x10B else 112
    directory_count_offset = 92 if optional_magic == 0x10B else 108
    if optional_size < directory_base + 8:
        raise MalformedPEError("optional header does not contain an export data-directory slot")
    size_of_image = _u32(data, optional_offset + 56, "SizeOfImage")
    size_of_headers = _u32(data, optional_offset + 60, "SizeOfHeaders")
    if size_of_headers <= 0 or size_of_headers > len(data):
        raise MalformedPEError("SizeOfHeaders is zero or exceeds the file")
    if size_of_image < size_of_headers:
        raise MalformedPEError("SizeOfImage is smaller than SizeOfHeaders")
    directory_count = _u32(data, optional_offset + directory_count_offset, "NumberOfRvaAndSizes")
    if directory_count < 1:
        raise MalformedPEError("PE has no export data-directory slot")
    directory_capacity = (optional_size - directory_base) // 8
    if directory_count > directory_capacity:
        raise MalformedPEError(
            "NumberOfRvaAndSizes exceeds the optional-header data-directory capacity"
        )
    export_rva, export_size = _unpack(
        data,
        "<II",
        optional_offset + directory_base,
        "export data directory",
    )
    if not export_rva or export_size < 40:
        raise MalformedPEError("PE has no complete export directory")
    if export_rva + export_size > 0x1_0000_0000 or export_rva + export_size > size_of_image:
        raise MalformedPEError("export directory exceeds SizeOfImage")

    section_table = optional_end
    if section_table + (section_count * 40) > len(data):
        raise MalformedPEError("section table extends beyond the file")
    if section_table + (section_count * 40) > size_of_headers:
        raise MalformedPEError("section table extends beyond SizeOfHeaders")
    sections = _parse_sections(data, section_table, section_count, size_of_headers, size_of_image)
    image = _PEImage(
        data=data,
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        sections=sections,
    )
    export_offset = image.rva_to_offset(export_rva, 40, label="export directory")
    image.rva_to_offset(export_rva, export_size, label="export directory")
    (
        _,
        _,
        _,
        _,
        dll_name_rva,
        ordinal_base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        name_ordinals_rva,
    ) = _unpack(data, "<IIHHIIIIIII", export_offset, "IMAGE_EXPORT_DIRECTORY")
    if function_count > _MAX_EXPORTS:
        raise MalformedPEError(f"export function count exceeds {_MAX_EXPORTS}")
    if name_count > function_count:
        raise MalformedPEError("export name count exceeds function count")
    if ordinal_base > _MAX_EXPORTS or (
        function_count and ordinal_base + function_count - 1 > _MAX_EXPORTS
    ):
        raise MalformedPEError("export ordinal range exceeds 65535")
    dll_name = _read_ascii_rva(image, dll_name_rva, label="export DLL name")

    if function_count:
        if not functions_rva:
            raise MalformedPEError("export address table RVA is zero")
        functions_offset = image.rva_to_offset(
            functions_rva,
            function_count * 4,
            label="export address table",
        )
        function_rvas = tuple(
            _u32(data, functions_offset + index * 4, "export address table entry")
            for index in range(function_count)
        )
    else:
        function_rvas = ()

    names_by_index: dict[int, str] = {}
    if name_count:
        if not names_rva or not name_ordinals_rva:
            raise MalformedPEError("named exports have a zero name/ordinal table RVA")
        names_offset = image.rva_to_offset(
            names_rva,
            name_count * 4,
            label="export name pointer table",
        )
        ordinals_offset = image.rva_to_offset(
            name_ordinals_rva,
            name_count * 2,
            label="export name ordinal table",
        )
        observed_names: set[str] = set()
        previous_name: bytes | None = None
        for name_index in range(name_count):
            name_rva = _u32(data, names_offset + name_index * 4, "export name pointer")
            name = _read_ascii_rva(image, name_rva, label=f"export name {name_index}")
            encoded_name = name.encode("ascii")
            if name in observed_names:
                raise DuplicateExportError(f"duplicate export name: {name!r}")
            if previous_name is not None and encoded_name < previous_name:
                raise MalformedPEError("export name pointer table is not bytewise sorted")
            previous_name = encoded_name
            observed_names.add(name)
            address_index = _u16(
                data,
                ordinals_offset + name_index * 2,
                "export name ordinal entry",
            )
            if address_index >= function_count:
                raise MalformedPEError(
                    f"export name {name!r} references address-table index {address_index} outside {function_count}"
                )
            if address_index in names_by_index:
                existing = names_by_index[address_index]
                raise DuplicateExportError(
                    f"duplicate ordinal binding: {existing!r} and {name!r} reference ordinal "
                    f"{ordinal_base + address_index}"
                )
            names_by_index[address_index] = name

    exports: list[PEExport] = []
    holes: list[int] = []
    export_end = export_rva + export_size
    for address_index, target_rva in enumerate(function_rvas):
        ordinal = ordinal_base + address_index
        name = names_by_index.get(address_index)
        if target_rva == 0:
            if name is not None:
                raise MalformedPEError(f"named export {name!r} points to an empty address-table slot")
            holes.append(ordinal)
            continue
        forwarder: str | None = None
        if export_rva <= target_rva < export_end:
            forwarder = _read_ascii_rva(
                image,
                target_rva,
                label=f"forwarder for ordinal {ordinal}",
                rva_limit=export_end,
            )
            _validate_forwarder(forwarder, ordinal=ordinal)
        else:
            image.validate_target_rva(target_rva, label=f"export ordinal {ordinal}")
        exports.append(
            PEExport(
                ordinal=ordinal,
                name=name,
                target_rva=target_rva,
                forwarder=forwarder,
                address_table_index=address_index,
            )
        )
    if len(names_by_index) != name_count:
        raise MalformedPEError("named export table could not be represented uniquely")
    return PEExportTable(
        architecture=architecture,
        bits=bits,
        machine=machine,
        optional_magic=optional_magic,
        dll_name=dll_name,
        ordinal_base=ordinal_base,
        function_count=function_count,
        name_count=name_count,
        exports=tuple(exports),
        hole_ordinals=tuple(holes),
        source_sha256=_sha256(data),
        file_size=len(data),
    )


def _parse_sections(
    data: bytes,
    table_offset: int,
    count: int,
    size_of_headers: int,
    size_of_image: int,
) -> tuple[_Section, ...]:
    sections: list[_Section] = []
    for index in range(count):
        offset = table_offset + index * 40
        raw_name = data[offset : offset + 8].split(b"\x00", 1)[0]
        try:
            name = raw_name.decode("ascii") or f"section_{index}"
        except UnicodeDecodeError as exc:
            raise MalformedPEError(f"section {index} name is not ASCII") from exc
        virtual_size, virtual_address, raw_size, raw_offset = _unpack(
            data,
            "<IIII",
            offset + 8,
            f"section {index} layout",
        )
        if raw_size:
            if raw_offset < size_of_headers:
                raise MalformedPEError(f"section {name} raw data overlaps PE headers")
            if raw_offset + raw_size > len(data):
                raise MalformedPEError(f"section {name} raw data exceeds the file")
        if virtual_address + max(virtual_size, raw_size) > size_of_image:
            raise MalformedPEError(f"section {name} virtual range exceeds SizeOfImage")
        sections.append(
            _Section(
                index=index,
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
            )
        )
    raw_sections = sorted((item for item in sections if item.raw_size), key=lambda item: item.raw_offset)
    for left, right in zip(raw_sections, raw_sections[1:]):
        if left.raw_end > right.raw_offset:
            raise MalformedPEError(f"section raw ranges overlap: {left.name} and {right.name}")
    virtual_sections = sorted(
        (item for item in sections if max(item.virtual_size, item.raw_size)),
        key=lambda item: item.virtual_address,
    )
    for left, right in zip(virtual_sections, virtual_sections[1:]):
        if left.virtual_end > right.virtual_address:
            raise MalformedPEError(f"section virtual ranges overlap: {left.name} and {right.name}")
    return tuple(sections)


def _architecture(
    machine: int,
    optional_magic: int,
    expected_architecture: str | None,
) -> tuple[str, int]:
    format_name = {0x10B: "PE32", 0x20B: "PE32+"}.get(optional_magic)
    if format_name is None:
        raise ArchitectureMismatchError(
            f"unsupported optional-header magic 0x{optional_magic:04X}; expected PE32 or PE32+"
        )
    observed = _ARCHITECTURES.get((machine, optional_magic))
    if observed is None:
        machine_formats = {
            magic for observed_machine, magic in _ARCHITECTURES if observed_machine == machine
        }
        if machine_formats:
            raise ArchitectureMismatchError(
                f"machine 0x{machine:04X} is not valid for {format_name}; architecture is ambiguous"
            )
        raise ArchitectureMismatchError(
            f"unsupported machine 0x{machine:04X} for {format_name}; architecture cannot be selected"
        )
    architecture, bits = observed
    if expected_architecture is not None:
        expected = _normalize_architecture(expected_architecture)
        if expected != architecture:
            raise ArchitectureMismatchError(
                f"expected {expected} architecture but PE is {architecture} "
                f"(machine 0x{machine:04X}, {format_name})"
            )
    return architecture, bits


def _normalize_architecture(value: str) -> str:
    normalized = str(value).strip().casefold()
    try:
        return _ARCHITECTURE_ALIASES[normalized]
    except KeyError as exc:
        supported = ", ".join(sorted(set(_ARCHITECTURE_ALIASES.values())))
        raise ArchitectureMismatchError(
            f"unsupported expected architecture {value!r}; choose {supported}"
        ) from exc


def _read_ascii_rva(
    image: _PEImage,
    rva: int,
    *,
    label: str,
    rva_limit: int | None = None,
) -> str:
    if not rva:
        raise MalformedPEError(f"{label} RVA is zero")
    offset, available = image.contiguous_rva_limit(rva, label=label)
    if rva_limit is not None:
        if rva >= rva_limit:
            raise MalformedPEError(f"{label} starts outside its containing directory")
        available = min(available, rva_limit - rva)
    available = min(available, _MAX_EXPORT_NAME + 1)
    end = image.data.find(b"\x00", offset, offset + available)
    if end < 0:
        raise MalformedPEError(f"{label} is not NUL-terminated within {_MAX_EXPORT_NAME} bytes")
    raw = image.data[offset:end]
    if not raw:
        raise MalformedPEError(f"{label} is empty")
    if any(value < 0x20 or value > 0x7E for value in raw):
        raise MalformedPEError(f"{label} contains non-printable or non-ASCII bytes")
    return raw.decode("ascii")


def _validate_forwarder(value: str, *, ordinal: int) -> None:
    if "." not in value:
        raise MalformedPEError(f"forwarder for ordinal {ordinal} has no module separator")
    module, target = value.rsplit(".", 1)
    if not _FORWARDER_MODULE_RE.fullmatch(module) or not _FORWARDER_TARGET_RE.fullmatch(target):
        raise MalformedPEError(f"forwarder for ordinal {ordinal} has unsafe syntax: {value!r}")
    if target.startswith("#") and int(target[1:]) > _MAX_EXPORTS:
        raise MalformedPEError(f"forwarder for ordinal {ordinal} has an out-of-range target ordinal")


def _forwarding_records(
    table: PEExportTable,
    backing_module: str,
) -> list[dict[str, Any]]:
    named_exports = {item.name for item in table.exports if item.name is not None}
    aliases: set[str] = set()
    records: list[dict[str, Any]] = []
    for item in table.exports:
        if item.name is not None:
            if not _DEF_NAME_RE.fullmatch(item.name):
                raise DllProxyGenerationError(
                    f"export name {item.name!r} cannot be represented safely in a DEF file"
                )
            definition_name = item.name
            target_name = item.name
        else:
            definition_name = f"__proxy_ordinal_{item.ordinal}"
            while definition_name in named_exports or definition_name in aliases:
                definition_name = "_" + definition_name
            aliases.add(definition_name)
            target_name = f"#{item.ordinal}"
        records.append(
            {
                "definition_name": definition_name,
                "name": item.name,
                "noname": item.noname,
                "ordinal": item.ordinal,
                "proxy_forwarder": f"{backing_module}.{target_name}",
                "source_forwarder": item.forwarder,
            }
        )
    return records


def _render_definition(proxy_name: str, records: list[Mapping[str, Any]]) -> str:
    lines = [f'LIBRARY "{proxy_name}"', "EXPORTS"]
    for item in records:
        suffix = " NONAME" if item["noname"] else ""
        definition_name = str(item["definition_name"])
        keyword_name = definition_name.upper() in _DEF_KEYWORDS
        if keyword_name:
            definition_name = f'"{definition_name}"'
        target = item["proxy_forwarder"]
        if item["noname"] or keyword_name:
            # GNU ld treats an unquoted '#' as DEF syntax rather than as part
            # of an ordinal target, and tokenizes reserved export names even
            # after a module separator. MSVC accepts the quoted form.
            target = f'"{target}"'
        lines.append(
            f"    {definition_name}={target} @{item['ordinal']}{suffix}"
        )
    return "\n".join(lines) + "\n"


def _render_c_source(architecture: str) -> str:
    guard = {
        "x86": "DLL_PROXY_ARCH_X86",
        "x64": "DLL_PROXY_ARCH_X64",
        "arm": "DLL_PROXY_ARCH_ARM",
        "arm64": "DLL_PROXY_ARCH_ARM64",
    }[architecture]
    return f"""#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#if defined(_M_IX86) || defined(__i386__)
#define DLL_PROXY_ARCH_X86 1
#elif defined(_M_X64) || defined(__x86_64__)
#define DLL_PROXY_ARCH_X64 1
#elif defined(_M_ARM64) || defined(__aarch64__)
#define DLL_PROXY_ARCH_ARM64 1
#elif defined(_M_ARM) || defined(__arm__)
#define DLL_PROXY_ARCH_ARM 1
#else
#error Unsupported compiler target architecture
#endif

#if !defined({guard})
#error Compiler target does not match the source DLL architecture
#endif

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}}
"""


def _render_cmake(
    *,
    architecture: str,
    bits: int,
    proxy_name: str,
    backing_name: str,
) -> str:
    proxy_stem = Path(proxy_name).stem
    return f"""cmake_minimum_required(VERSION 3.20)
project(dll_export_proxy LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "This project must use a Windows-targeting toolchain")
endif()

set(DLL_PROXY_SOURCE_ROOT "${{CMAKE_CURRENT_SOURCE_DIR}}")
cmake_path(
    IS_PREFIX DLL_PROXY_SOURCE_ROOT
    "${{CMAKE_CURRENT_BINARY_DIR}}"
    NORMALIZE
    DLL_PROXY_BUILD_INSIDE)
if(NOT DLL_PROXY_BUILD_INSIDE)
    message(FATAL_ERROR "Build output must remain inside the generated proxy project")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL {bits // 8})
    message(FATAL_ERROR "Compiler pointer width does not match {architecture}")
endif()

add_library(dll_proxy SHARED proxy.c)
if(MSVC)
    target_link_options(dll_proxy PRIVATE "/DEF:${{CMAKE_CURRENT_SOURCE_DIR}}/proxy.def")
else()
    target_sources(dll_proxy PRIVATE proxy.def)
endif()
set_target_properties(dll_proxy PROPERTIES
    PREFIX ""
    OUTPUT_NAME "{proxy_stem}"
    RUNTIME_OUTPUT_DIRECTORY "${{CMAKE_CURRENT_BINARY_DIR}}"
    LIBRARY_OUTPUT_DIRECTORY "${{CMAKE_CURRENT_BINARY_DIR}}"
    ARCHIVE_OUTPUT_DIRECTORY "${{CMAKE_CURRENT_BINARY_DIR}}")
add_custom_command(TARGET dll_proxy POST_BUILD
    COMMAND "${{CMAKE_COMMAND}}" -E copy_if_different
        "${{CMAKE_CURRENT_SOURCE_DIR}}/backing/{backing_name}"
        "$<TARGET_FILE_DIR:dll_proxy>/{backing_name}"
    VERBATIM)
"""


def _build_manifest(
    *,
    table: PEExportTable,
    source_relative: str,
    project_relative: str,
    proxy_name: str,
    backing_name: str,
    backing_relative: str,
    forwarding: list[Mapping[str, Any]],
    core_files: Mapping[str, bytes],
) -> dict[str, Any]:
    return {
        "architecture": {
            "bits": table.bits,
            "machine": table.machine,
            "machine_hex": f"0x{table.machine:04X}",
            "name": table.architecture,
            "optional_magic": table.optional_magic,
        },
        "build": {
            "build_directory": "build",
            "build_system": "cmake",
            "commands": [
                {"argv": ["cmake", "-S", ".", "-B", "build"], "name": "configure"},
                {
                    "argv": ["cmake", "--build", "build", "--config", "Release"],
                    "name": "build",
                },
            ],
            "minimum_cmake_version": "3.20",
            "output_candidates": [
                f"build/{proxy_name}",
                f"build/Release/{proxy_name}",
            ],
            "output_scope": "project_directory_only",
        },
        "exports": [dict(item) for item in forwarding],
        "files": [
            {"path": name, "sha256": _sha256(payload), "size": len(payload)}
            for name, payload in sorted(core_files.items())
        ],
        "generator": {"name": "reverse_analyzer.dll_proxy", "version": 1},
        "project": {"path": project_relative},
        "proxy": {
            "backing_binary": backing_relative,
            "backing_name": backing_name,
            "output_name": proxy_name,
        },
        "schema_version": 1,
        "scope": "copy_directory_only",
        "source": {
            "dll_name": table.dll_name,
            "path": source_relative,
            "sha256": table.source_sha256,
            "size": table.file_size,
        },
    }


def _validation_report(
    *,
    table: PEExportTable,
    source_relative: str,
    project_relative: str,
    proxy_name: str,
    backing_name: str,
    forwarding: list[Mapping[str, Any]],
) -> dict[str, Any]:
    total = len(table.exports)
    named = sum(not item.noname for item in table.exports)
    noname = total - named
    source_forwarders = sum(item.forwarder is not None for item in table.exports)
    return {
        "architecture": {
            "bits": table.bits,
            "machine": table.machine,
            "name": table.architecture,
            "unique": True,
        },
        "checks": [
            {"name": "pe_headers", "status": "passed"},
            {"name": "export_directory", "status": "passed"},
            {"name": "duplicate_names", "status": "passed"},
            {"name": "duplicate_ordinals", "status": "passed"},
            {"name": "architecture_match", "status": "passed"},
            {"name": "copy_directory_confinement", "status": "passed"},
            {"name": "forwarding_coverage", "status": "passed"},
        ],
        "coverage": {
            "coverage_percent": round((len(forwarding) / total) * 100.0, 6) if total else 0.0,
            "forwarded_exports": len(forwarding),
            "named_exports": named,
            "noname_exports": noname,
            "source_forwarders": source_forwarders,
            "total_exports": total,
        },
        "preservation": {
            "calling_boundaries": True,
            "forwarder_mechanism": "PE loader direct forwarders",
            "names": True,
            "noname": True,
            "ordinals": True,
        },
        "project": {
            "backing_name": backing_name,
            "output_name": proxy_name,
            "path": project_relative,
        },
        "schema_version": 1,
        "source": {"path": source_relative, "sha256": table.source_sha256},
        "status": "passed",
    }


def _risk_report(
    table: PEExportTable,
    forwarding: list[Mapping[str, Any]],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = [
        {
            "category": "deployment",
            "id": "paired_dll_deployment",
            "message": "The proxy and renamed backing DLL must be deployed atomically in one directory.",
            "mitigation": "Verify both hashes from build_manifest.json before replacing a copied deployment.",
            "severity": "high",
        },
        {
            "category": "trust",
            "id": "unsigned_proxy_binary",
            "message": "A newly built proxy does not inherit the source DLL Authenticode signature.",
            "mitigation": "Sign and verify the built proxy under the deployment policy.",
            "severity": "high",
        },
        {
            "category": "abi",
            "id": "direct_loader_forwarders",
            "message": "Direct PE forwarders preserve calling boundaries without generated signature guesses.",
            "mitigation": "Do not replace DEF forwarders with C wrappers unless exact prototypes are proven.",
            "severity": "info",
        },
        {
            "category": "build",
            "id": "architecture_locked_build",
            "message": f"The generated project rejects compiler targets other than {table.architecture}.",
            "mitigation": "Keep the CMake and preprocessor architecture guards enabled.",
            "severity": "info",
        },
    ]
    noname_count = sum(bool(item["noname"]) for item in forwarding)
    if noname_count:
        findings.append(
            {
                "category": "compatibility",
                "evidence": {"count": noname_count},
                "id": "ordinal_only_exports",
                "message": "Ordinal-only exports require linker NONAME support and ordinal-preserving verification.",
                "mitigation": "Parse the built DLL export table before deployment.",
                "severity": "medium",
            }
        )
    source_forwarder_count = sum(item["source_forwarder"] is not None for item in forwarding)
    if source_forwarder_count:
        findings.append(
            {
                "category": "resolution",
                "evidence": {"count": source_forwarder_count},
                "id": "source_forwarder_chain",
                "message": "Some source exports already forward and will resolve through the backing DLL.",
                "mitigation": "Validate the final forwarding chain on the target Windows version.",
                "severity": "low",
            }
        )
    findings.sort(key=lambda item: (-_SEVERITY_ORDER[str(item["severity"])], str(item["id"])))
    highest = max((_SEVERITY_ORDER[str(item["severity"])] for item in findings), default=0)
    overall = next(name for name, value in _SEVERITY_ORDER.items() if value == highest)
    counts = {name: sum(item["severity"] == name for item in findings) for name in _SEVERITY_ORDER}
    return {
        "counts": counts,
        "findings": findings,
        "overall_risk": overall,
        "schema_version": 1,
        "status": "review_required" if highest >= _SEVERITY_ORDER["high"] else "ok",
    }


def _rollback_metadata(
    *,
    source_relative: str,
    source_hash: str,
    project_relative: str,
    files: Mapping[str, bytes],
    missing_parents: tuple[Path, ...],
) -> dict[str, Any]:
    generated_files = [
        {
            "path": f"{project_relative}/{name}",
            "sha256": _sha256(payload),
            "size": len(payload),
        }
        for name, payload in sorted(files.items())
    ]
    return {
        "actions": [
            {
                "action": "remove_project_if_generated_hashes_match",
                "path": project_relative,
            },
            {
                "action": "remove_empty_parent_directories",
                "paths": [item.as_posix() for item in reversed(missing_parents)],
            },
        ],
        "generated_files": generated_files,
        "original_modified": False,
        "project_directory": project_relative,
        "requires_hash_verification": True,
        "reversible": True,
        "schema_version": 1,
        "scope": "copy_directory_only",
        "self": {
            "action": "delete_last",
            "path": f"{project_relative}/rollback.json",
        },
        "source": {"path": source_relative, "sha256": source_hash},
        "status": "ready",
    }


def _commit_project(
    *,
    copy_root: Path,
    source: Path,
    expected_source_hash: str,
    project: Path,
    files: Mapping[str, bytes],
    missing_parents: tuple[Path, ...],
) -> None:
    created_parents: list[Path] = []
    staging: Path | None = None
    committed = False
    try:
        for relative in missing_parents:
            candidate = copy_root / relative
            candidate.mkdir(exist_ok=False)
            created_parents.append(candidate)
        _require_within(copy_root, project.parent.resolve(), label="project parent", strict_descendant=False)
        if project.exists():
            raise DllProxyGenerationError(f"project directory already exists: {project}")
        staging = Path(tempfile.mkdtemp(prefix=".dll-proxy-stage-", dir=project.parent))
        _require_within(copy_root, staging.resolve(), label="staging directory", strict_descendant=True)
        for relative_name, payload in sorted(files.items()):
            relative = Path(relative_name)
            if relative.is_absolute() or ".." in relative.parts:
                raise PathBoundaryError(f"generated artifact path is unsafe: {relative_name}")
            output = staging / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        if _sha256_file(source) != expected_source_hash:
            raise DllProxyGenerationError("source DLL changed while the proxy project was being generated")
        if project.exists():
            raise DllProxyGenerationError(f"project directory already exists: {project}")
        staging.rename(project)
        staging = None
        committed = True
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)
        if not committed:
            for path in reversed(created_parents):
                try:
                    path.rmdir()
                except OSError:
                    pass


def _missing_parent_paths(copy_root: Path, parent: Path) -> tuple[Path, ...]:
    missing: list[Path] = []
    cursor = parent
    while cursor != copy_root and not cursor.exists():
        missing.append(cursor.relative_to(copy_root))
        cursor = cursor.parent
    if not cursor.is_dir():
        raise PathBoundaryError(f"project parent is not a directory: {cursor}")
    return tuple(reversed(missing))


def _validate_dll_filename(value: str, *, label: str) -> str:
    if Path(value).name != value or not value.casefold().endswith(".dll"):
        raise DllProxyGenerationError(f"{label} must be a basename ending in .dll")
    stem = value[:-4]
    if not _DLL_STEM_RE.fullmatch(stem):
        raise DllProxyGenerationError(
            f"{label} stem must contain only ASCII letters, digits, underscore, and hyphen"
        )
    if stem.casefold() in _WINDOWS_RESERVED_STEMS:
        raise DllProxyGenerationError(f"{label} uses a reserved Windows device name")
    return stem + ".dll"


def _require_within(
    root: Path,
    candidate: Path,
    *,
    label: str,
    strict_descendant: bool,
) -> None:
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise PathBoundaryError(f"{label} must remain inside copy directory: {candidate}") from exc
    if strict_descendant and not relative.parts:
        raise PathBoundaryError(f"{label} must be a child of the copy directory")


def _relative_path(root: Path, value: Path) -> str:
    return value.relative_to(root).as_posix()


def _read_input(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DllProxyGenerationError(f"unable to stat DLL {path}: {exc}") from exc
    if size <= 0 or size > _MAX_INPUT_SIZE:
        raise DllProxyGenerationError(
            f"DLL size must be between 1 and {_MAX_INPUT_SIZE} bytes; observed {size}"
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DllProxyGenerationError(f"unable to read DLL {path}: {exc}") from exc
    if len(data) != size:
        raise DllProxyGenerationError("DLL size changed while it was being read")
    return data


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _unpack(data: bytes, format_string: str, offset: int, label: str) -> tuple[Any, ...]:
    size = struct.calcsize(format_string)
    if offset < 0 or offset + size > len(data):
        raise MalformedPEError(f"{label} extends beyond the file")
    return struct.unpack_from(format_string, data, offset)


def _u16(data: bytes, offset: int, label: str) -> int:
    return int(_unpack(data, "<H", offset, label)[0])


def _u32(data: bytes, offset: int, label: str) -> int:
    return int(_unpack(data, "<I", offset, label)[0])


__all__ = [
    "ArchitectureMismatchError",
    "DllProxyGenerationError",
    "DllProxyProject",
    "DuplicateExportError",
    "MalformedPEError",
    "PathBoundaryError",
    "PEExport",
    "PEExportTable",
    "generate_dll_proxy",
    "generate_dll_proxy_project",
    "parse_pe_exports",
]
