"""Verified patch planning for Android ARM ELF binaries.

The planner is intentionally dependency-free.  It parses the ELF structures
needed to prove that a byte range is file-backed by exactly one PT_LOAD
segment, records the original bytes, and revalidates that evidence before a
generic patch executor is allowed to consume the plan.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from typing import Any

from reverse_analyzer.tools.executor import ToolResult


ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
EM_ARM = 40
EM_AARCH64 = 183
ET_REL = 1
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
PN_XNUM = 0xFFFF
SHN_XINDEX = 0xFFFF

DT_NULL = 0
DT_PLTRELSZ = 2
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_JMPREL = 23
DT_ANDROID_REL = 0x6000000F
DT_ANDROID_RELSZ = 0x60000010
DT_ANDROID_RELA = 0x60000011
DT_ANDROID_RELASZ = 0x60000012

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_TABLE_ENTRIES = 1_000_000


class AndroidElfPatchError(ValueError):
    """Raised when an ELF image or patch plan cannot be proved safe to map."""


@dataclass(frozen=True, slots=True)
class ElfProgramHeader:
    """One parsed ELF program header."""

    index: int
    type: int
    offset: int
    virtual_address: int
    physical_address: int
    file_size: int
    memory_size: int
    flags: int
    alignment: int

    @property
    def readable(self) -> bool:
        return bool(self.flags & PF_R)

    @property
    def writable(self) -> bool:
        return bool(self.flags & PF_W)

    @property
    def executable(self) -> bool:
        return bool(self.flags & PF_X)

    @property
    def file_end(self) -> int:
        return self.offset + self.file_size

    @property
    def virtual_file_end(self) -> int:
        return self.virtual_address + self.file_size

    @property
    def virtual_memory_end(self) -> int:
        return self.virtual_address + self.memory_size

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "type": self.type,
            "offset": self.offset,
            "virtual_address": self.virtual_address,
            "file_size": self.file_size,
            "memory_size": self.memory_size,
            "flags": self.flags,
            "permissions": _permissions(self.flags),
            "alignment": self.alignment,
        }


@dataclass(frozen=True, slots=True)
class ElfSection:
    """The section fields required to decode relocation tables."""

    index: int
    name_offset: int
    type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True, slots=True)
class ElfRelocation:
    """A decoded relocation target with an optional file-backed mapping."""

    source: str
    index: int
    virtual_address: int
    file_offset: int | None
    size: int
    type: int
    symbol: int
    table_offset: int
    table_entry_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "index": self.index,
            "virtual_address": self.virtual_address,
            "file_offset": self.file_offset,
            "size": self.size,
            "type": self.type,
            "symbol": self.symbol,
            "table_offset": self.table_offset,
            "table_entry_size": self.table_entry_size,
        }


@dataclass(frozen=True, slots=True)
class AndroidElfImage:
    """Parsed ARM ELF image and strict PT_LOAD address mapper."""

    data: bytes
    bits: int
    elf_type: int
    machine: int
    architecture: str
    entrypoint: int
    flags: int
    header_size: int
    program_header_offset: int
    program_header_entry_size: int
    program_header_count: int
    section_header_offset: int
    section_header_entry_size: int
    section_header_count: int
    program_headers: tuple[ElfProgramHeader, ...]
    sections: tuple[ElfSection, ...]
    relocations: tuple[ElfRelocation, ...] = ()
    relocation_coverage: str = "full"
    relocation_notes: tuple[str, ...] = ()

    @property
    def load_segments(self) -> tuple[ElfProgramHeader, ...]:
        return tuple(item for item in self.program_headers if item.type == PT_LOAD)

    @property
    def supported_instruction_modes(self) -> tuple[str, ...]:
        return ("arm", "thumb") if self.architecture == "arm" else ("aarch64",)

    def virtual_address_to_file_offset(
        self,
        virtual_address: int,
        size: int = 1,
        *,
        instruction_mode: str | None = None,
    ) -> int:
        canonical = _canonical_virtual_address(
            self,
            _nonnegative_int(virtual_address, field="virtual_address"),
            instruction_mode=instruction_mode,
        )
        offset, _ = self._map_virtual_range(canonical, size)
        return offset

    def file_offset_to_virtual_address(self, offset: int, size: int = 1) -> int:
        virtual_address, _ = self._map_file_range(offset, size)
        return virtual_address

    def segment_for_virtual_range(
        self,
        virtual_address: int,
        size: int,
        *,
        instruction_mode: str | None = None,
    ) -> ElfProgramHeader:
        canonical = _canonical_virtual_address(
            self,
            _nonnegative_int(virtual_address, field="virtual_address"),
            instruction_mode=instruction_mode,
        )
        _, segment = self._map_virtual_range(canonical, size)
        return segment

    def segment_for_file_range(self, offset: int, size: int) -> ElfProgramHeader:
        _, segment = self._map_file_range(offset, size)
        return segment

    # Short aliases are useful to providers while keeping the public names
    # explicit in serialized evidence.
    def va_to_offset(
        self,
        virtual_address: int,
        size: int = 1,
        *,
        instruction_mode: str | None = None,
    ) -> int:
        return self.virtual_address_to_file_offset(
            virtual_address,
            size,
            instruction_mode=instruction_mode,
        )

    def offset_to_va(self, offset: int, size: int = 1) -> int:
        return self.file_offset_to_virtual_address(offset, size)

    def _map_virtual_range(self, virtual_address: int, size: int) -> tuple[int, ElfProgramHeader]:
        start, end = _checked_range(virtual_address, size, field="virtual address")
        candidates = [
            segment
            for segment in self.load_segments
            if segment.virtual_address <= start and end <= segment.virtual_file_end
        ]
        if not candidates:
            memory_hits = [
                segment
                for segment in self.load_segments
                if segment.virtual_address <= start < segment.virtual_memory_end
            ]
            if memory_hits:
                raise AndroidElfPatchError(
                    f"virtual range 0x{start:X}-0x{end:X} is not wholly file-backed by one PT_LOAD segment"
                )
            raise AndroidElfPatchError(
                f"virtual range 0x{start:X}-0x{end:X} is not mapped by a PT_LOAD segment"
            )
        if len(candidates) != 1:
            raise AndroidElfPatchError(
                f"virtual range 0x{start:X}-0x{end:X} has ambiguous PT_LOAD mappings"
            )
        segment = candidates[0]
        offset = segment.offset + (start - segment.virtual_address)
        if offset + size > len(self.data):
            raise AndroidElfPatchError("PT_LOAD mapping resolves outside the ELF file")
        return offset, segment

    def _map_file_range(self, offset: int, size: int) -> tuple[int, ElfProgramHeader]:
        start, end = _checked_range(offset, size, field="file offset")
        if end > len(self.data):
            raise AndroidElfPatchError(
                f"file range 0x{start:X}-0x{end:X} exceeds file size 0x{len(self.data):X}"
            )
        candidates = [
            segment
            for segment in self.load_segments
            if segment.offset <= start and end <= segment.file_end
        ]
        if not candidates:
            partial_hits = [
                segment
                for segment in self.load_segments
                if segment.offset <= start < segment.file_end
            ]
            if partial_hits:
                raise AndroidElfPatchError(
                    f"file range 0x{start:X}-0x{end:X} crosses a PT_LOAD segment boundary"
                )
            raise AndroidElfPatchError(
                f"file range 0x{start:X}-0x{end:X} is not mapped by a PT_LOAD segment"
            )
        if len(candidates) != 1:
            raise AndroidElfPatchError(
                f"file range 0x{start:X}-0x{end:X} has ambiguous PT_LOAD mappings"
            )
        segment = candidates[0]
        virtual_address = segment.virtual_address + (start - segment.offset)
        return virtual_address, segment


def parse_android_elf(source: str | Path | bytes | bytearray | memoryview) -> AndroidElfImage:
    """Parse one little-endian ARM/AArch64 ELF image.

    This is a structural parser, not a magic-byte detector: all referenced
    program/section tables and file-backed PT_LOAD ranges are bounds checked.
    """

    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        target = _require_file(source)
        data = target.read_bytes()
    return _parse_elf_bytes(data)


def plan_android_elf_patch(
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
    """Create a checked, layout-preserving Android ELF patch plan."""

    try:
        target = _require_file(path)
        data = target.read_bytes()
        image = _parse_elf_bytes(data)
        normalized = _merge_intent(
            intent,
            virtual_address=virtual_address,
            file_offset=file_offset,
            replacement=replacement,
            instruction_mode=instruction_mode,
            operation_id=operation_id,
        )
        operation = _operation_from_intent(data, image, normalized)
        target_identity = _target_summary(target, data, image)
        patched = bytearray(data)
        start = int(operation["offset"])
        replacement_bytes = bytes.fromhex(str(operation["replacement"]))
        patched[start : start + len(replacement_bytes)] = replacement_bytes
        rollback_plan = _rollback_plan(
            target,
            data,
            [operation],
            patched_sha256=_sha256(bytes(patched)),
            reversible=True,
            errors=[],
        )
        operation["rollback"] = dict(rollback_plan["operations"][0])
        plan = {
            "schema_version": 1,
            "target_sha256": _sha256(data),
            "strategy": "android_elf_inline_patch",
            "target": target_identity,
            "target_identity": target_identity,
            "architecture": image.architecture,
            "bits": image.bits,
            "operations": [operation],
            "rollback_plan": rollback_plan,
            "planner": {
                "name": "android_elf_patch_planner",
                "schema_version": 1,
                "explicit_intent": True,
                "layout_preserving": True,
                "operation_model": "checked_equal_length_byte_replacements",
                "address_mapping": "pt_load_file_backed",
            },
        }
        verification, risk_report, verified_rollback = _verify_payload(target, data, image, plan)
        plan["rollback_plan"] = verified_rollback
        operation["rollback"] = dict(verified_rollback["operations"][0])
        artifact_root = Path(out_dir).resolve()
        artifacts = _write_artifacts(
            artifact_root,
            plan=plan,
            verification=verification,
            risk_report=risk_report,
            rollback_plan=verified_rollback,
            include_plan=True,
            protected_paths={"target": target},
        )
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="android_elf_patch_plan",
            status=status,
            error=None if status == "ok" else "; ".join(verification["errors"]),
            data={
                "status": status,
                "valid": verification["valid"],
                "target_path": str(target),
                "architecture": image.architecture,
                "instruction_mode": operation["instruction_mode"],
                "overall_risk": risk_report["overall_risk"],
                "plan_path": str(artifact_root / "plan.json"),
                "verify_path": str(artifact_root / "verify.json"),
                "risk_report_path": str(artifact_root / "risk_report.json"),
                "rollback_plan_path": str(artifact_root / "rollback_plan.json"),
                "artifacts": artifacts,
            },
        )
    except (AndroidElfPatchError, OSError, TypeError, ValueError) as exc:
        return _failure("android_elf_patch_plan", path, exc)


def validate_android_elf_patch_plan(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
) -> ToolResult:
    """Validate a plan against the current target without writing artifacts."""

    try:
        target = _require_file(path)
        plan_payload, _ = _load_mapping(plan, label="Android ELF patch plan")
        data = target.read_bytes()
        image = _parse_elf_bytes(data)
        verification, risk_report, rollback_plan = _verify_payload(
            target,
            data,
            image,
            plan_payload,
        )
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="android_elf_patch_validate",
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
    except (AndroidElfPatchError, OSError, TypeError, ValueError) as exc:
        return _failure("android_elf_patch_validate", path, exc)


def verify_android_elf_patch(
    path: str | Path,
    *,
    plan: Mapping[str, Any] | str | Path,
    out_dir: str | Path | None = None,
) -> ToolResult:
    """Revalidate target identity, preimages, mapping, and rollback evidence."""

    try:
        target = _require_file(path)
        plan_input = Path(plan).resolve() if not isinstance(plan, Mapping) else None
        plan_payload, plan_parent = _load_mapping(plan, label="Android ELF patch plan")
        data = target.read_bytes()
        image = _parse_elf_bytes(data)
        verification, risk_report, rollback_plan = _verify_payload(
            target,
            data,
            image,
            plan_payload,
        )
        artifact_root = Path(out_dir).resolve() if out_dir is not None else plan_parent or target.parent / "patch"
        protected = {"target": target}
        if plan_input is not None:
            protected["plan_input"] = plan_input
        artifacts = _write_artifacts(
            artifact_root,
            plan=plan_payload,
            verification=verification,
            risk_report=risk_report,
            rollback_plan=rollback_plan,
            include_plan=False,
            protected_paths=protected,
        )
        status = "ok" if verification["valid"] else "failed"
        return ToolResult(
            tool="android_elf_patch_verify",
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
    except (AndroidElfPatchError, OSError, TypeError, ValueError) as exc:
        return _failure("android_elf_patch_verify", path, exc)


def _parse_elf_bytes(data: bytes) -> AndroidElfImage:
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise AndroidElfPatchError("target is not an ELF file")
    elf_class = data[4]
    if elf_class not in {ELFCLASS32, ELFCLASS64}:
        raise AndroidElfPatchError(f"unsupported ELF class {elf_class}")
    if data[5] != ELFDATA2LSB:
        raise AndroidElfPatchError("only little-endian ELF images are supported")
    if data[6] != 1:
        raise AndroidElfPatchError("unsupported ELF identification version")

    if elf_class == ELFCLASS32:
        bits = 32
        header_format = "<HHIIIIIHHHHHH"
        expected_header_size = 52
        expected_program_size = 32
        expected_section_size = 40
    else:
        bits = 64
        header_format = "<HHIQQQIHHHHHH"
        expected_header_size = 64
        expected_program_size = 56
        expected_section_size = 64
    if len(data) < expected_header_size:
        raise AndroidElfPatchError("ELF header is truncated")
    values = struct.unpack_from(header_format, data, 16)
    (
        elf_type,
        machine,
        version,
        entrypoint,
        program_offset,
        section_offset,
        flags,
        header_size,
        program_entry_size,
        program_count,
        section_entry_size,
        section_count,
        section_name_index,
    ) = values
    if version != 1:
        raise AndroidElfPatchError("unsupported ELF header version")
    if header_size < expected_header_size or header_size > len(data):
        raise AndroidElfPatchError("invalid ELF header size")
    if machine == EM_ARM and bits == 32:
        architecture = "arm"
    elif machine == EM_AARCH64 and bits == 64:
        architecture = "aarch64"
    elif machine in {EM_ARM, EM_AARCH64}:
        raise AndroidElfPatchError("ELF class does not match the ARM machine type")
    else:
        raise AndroidElfPatchError(f"unsupported ELF machine 0x{machine:X}; expected ARM or AArch64")

    section_zero: ElfSection | None = None
    needs_section_zero = (
        section_offset != 0
        and (section_count == 0 or program_count == PN_XNUM or section_name_index == SHN_XINDEX)
    )
    if needs_section_zero:
        if section_entry_size < expected_section_size:
            raise AndroidElfPatchError("ELF section header entry size is too small")
        _check_table_range(
            len(data),
            section_offset,
            section_entry_size,
            1,
            label="section header table",
        )
        section_zero = _parse_section(data, bits, section_offset, 0)
        if section_count == 0:
            section_count = section_zero.size
        if program_count == PN_XNUM:
            program_count = section_zero.info
        if section_name_index == SHN_XINDEX:
            section_name_index = section_zero.link

    if program_count:
        if program_entry_size < expected_program_size:
            raise AndroidElfPatchError("ELF program header entry size is too small")
        _check_table_range(
            len(data),
            program_offset,
            program_entry_size,
            program_count,
            label="program header table",
        )
    if section_count:
        if section_offset == 0:
            raise AndroidElfPatchError("ELF section count is nonzero but section table offset is zero")
        if section_entry_size < expected_section_size:
            raise AndroidElfPatchError("ELF section header entry size is too small")
        _check_table_range(
            len(data),
            section_offset,
            section_entry_size,
            section_count,
            label="section header table",
        )
    if section_name_index not in {0, SHN_XINDEX} and section_name_index >= section_count:
        raise AndroidElfPatchError("ELF section-name index is outside the section table")

    program_headers = tuple(
        _parse_program_header(data, bits, program_offset + index * program_entry_size, index)
        for index in range(program_count)
    )
    load_segments = [item for item in program_headers if item.type == PT_LOAD]
    if not load_segments:
        raise AndroidElfPatchError("ELF image has no PT_LOAD segments")
    for item in program_headers:
        if item.file_size and item.offset + item.file_size > len(data):
            raise AndroidElfPatchError(f"program header[{item.index}] exceeds the ELF file")
    for segment in load_segments:
        if segment.file_size > segment.memory_size:
            raise AndroidElfPatchError(f"PT_LOAD[{segment.index}] file size exceeds memory size")
        if segment.offset + segment.file_size > len(data):
            raise AndroidElfPatchError(f"PT_LOAD[{segment.index}] exceeds the ELF file")
        if segment.alignment not in {0, 1}:
            if segment.alignment & (segment.alignment - 1):
                raise AndroidElfPatchError(f"PT_LOAD[{segment.index}] alignment is not a power of two")
            if (segment.virtual_address - segment.offset) % segment.alignment:
                raise AndroidElfPatchError(
                    f"PT_LOAD[{segment.index}] virtual address and file offset are not congruent"
                )

    sections = tuple(
        _parse_section(data, bits, section_offset + index * section_entry_size, index)
        for index in range(section_count)
    )
    for section in sections:
        if section.type != SHT_NOBITS and section.offset + section.size > len(data):
            raise AndroidElfPatchError(f"section[{section.index}] exceeds the ELF file")

    image = AndroidElfImage(
        data=data,
        bits=bits,
        elf_type=elf_type,
        machine=machine,
        architecture=architecture,
        entrypoint=entrypoint,
        flags=flags,
        header_size=header_size,
        program_header_offset=program_offset,
        program_header_entry_size=program_entry_size,
        program_header_count=program_count,
        section_header_offset=section_offset,
        section_header_entry_size=section_entry_size,
        section_header_count=section_count,
        program_headers=program_headers,
        sections=sections,
    )
    section_relocations = _section_relocations(image)
    dynamic_relocations, coverage, notes = _dynamic_relocations(image)
    relocations = _dedupe_relocations([*section_relocations, *dynamic_relocations])
    return replace(
        image,
        relocations=tuple(relocations),
        relocation_coverage=coverage,
        relocation_notes=tuple(notes),
    )


def _parse_program_header(data: bytes, bits: int, offset: int, index: int) -> ElfProgramHeader:
    if bits == 32:
        values = struct.unpack_from("<IIIIIIII", data, offset)
        item_type, file_offset, virtual, physical, file_size, memory_size, flags, alignment = values
    else:
        values = struct.unpack_from("<IIQQQQQQ", data, offset)
        item_type, flags, file_offset, virtual, physical, file_size, memory_size, alignment = values
    return ElfProgramHeader(
        index=index,
        type=item_type,
        offset=file_offset,
        virtual_address=virtual,
        physical_address=physical,
        file_size=file_size,
        memory_size=memory_size,
        flags=flags,
        alignment=alignment,
    )


def _parse_section(data: bytes, bits: int, offset: int, index: int) -> ElfSection:
    if bits == 32:
        values = struct.unpack_from("<IIIIIIIIII", data, offset)
    else:
        values = struct.unpack_from("<IIQQQQIIQQ", data, offset)
    return ElfSection(index, *values)


def _section_relocations(image: AndroidElfImage) -> list[ElfRelocation]:
    result: list[ElfRelocation] = []
    for section in image.sections:
        if section.type not in {SHT_REL, SHT_RELA} or section.size == 0:
            continue
        with_addend = section.type == SHT_RELA
        minimum_size = _relocation_entry_size(image.bits, with_addend)
        entry_size = section.entry_size or minimum_size
        if entry_size < minimum_size or section.size % entry_size:
            raise AndroidElfPatchError(f"relocation section[{section.index}] has an invalid entry size")
        count = section.size // entry_size
        if count > _MAX_TABLE_ENTRIES:
            raise AndroidElfPatchError("relocation section exceeds the entry limit")
        for index in range(count):
            entry_offset = section.offset + index * entry_size
            target, info = _unpack_relocation(image.data, image.bits, entry_offset)
            relocation_type, symbol = _relocation_info(image.bits, info)
            if relocation_type == 0:
                continue
            width = _relocation_width(image.machine, relocation_type)
            virtual_address, file_offset = _relocation_target(
                image,
                target,
                width,
                target_section_index=section.info if image.elf_type == ET_REL else None,
            )
            result.append(
                ElfRelocation(
                    source=f"section:{section.index}",
                    index=index,
                    virtual_address=virtual_address,
                    file_offset=file_offset,
                    size=width,
                    type=relocation_type,
                    symbol=symbol,
                    table_offset=entry_offset,
                    table_entry_size=entry_size,
                )
            )
    return result


def _dynamic_relocations(
    image: AndroidElfImage,
) -> tuple[list[ElfRelocation], str, list[str]]:
    relocations: list[ElfRelocation] = []
    notes: list[str] = []
    coverage = "full"
    for dynamic in (item for item in image.program_headers if item.type == PT_DYNAMIC):
        word_size = 4 if image.bits == 32 else 8
        entry_size = word_size * 2
        if dynamic.file_size % entry_size:
            raise AndroidElfPatchError(f"PT_DYNAMIC[{dynamic.index}] has a truncated entry")
        tags: dict[int, int] = {}
        for index in range(dynamic.file_size // entry_size):
            offset = dynamic.offset + index * entry_size
            if image.bits == 32:
                tag, value = struct.unpack_from("<iI", image.data, offset)
            else:
                tag, value = struct.unpack_from("<qQ", image.data, offset)
            if tag == DT_NULL:
                break
            tags[int(tag)] = int(value)

        specs: list[tuple[str, int, int, int, bool]] = []
        if DT_REL in tags and DT_RELSZ in tags:
            specs.append(
                (
                    "dynamic:rel",
                    tags[DT_REL],
                    tags[DT_RELSZ],
                    tags.get(DT_RELENT, _relocation_entry_size(image.bits, False)),
                    False,
                )
            )
        if DT_RELA in tags and DT_RELASZ in tags:
            specs.append(
                (
                    "dynamic:rela",
                    tags[DT_RELA],
                    tags[DT_RELASZ],
                    tags.get(DT_RELAENT, _relocation_entry_size(image.bits, True)),
                    True,
                )
            )
        if DT_JMPREL in tags and DT_PLTRELSZ in tags:
            plt_kind = tags.get(DT_PLTREL)
            if plt_kind == DT_REL:
                with_addend = False
            elif plt_kind == DT_RELA:
                with_addend = True
            else:
                raise AndroidElfPatchError("DT_JMPREL has an unsupported DT_PLTREL encoding")
            specs.append(
                (
                    "dynamic:jmprel",
                    tags[DT_JMPREL],
                    tags[DT_PLTRELSZ],
                    _relocation_entry_size(image.bits, with_addend),
                    with_addend,
                )
            )
        for source, table_va, table_size, entry_size, with_addend in specs:
            if table_size == 0:
                continue
            minimum_size = _relocation_entry_size(image.bits, with_addend)
            if entry_size < minimum_size or table_size % entry_size:
                raise AndroidElfPatchError(f"{source} has an invalid entry size")
            count = table_size // entry_size
            if count > _MAX_TABLE_ENTRIES:
                raise AndroidElfPatchError(f"{source} exceeds the entry limit")
            table_offset = image.virtual_address_to_file_offset(table_va, table_size)
            for index in range(count):
                entry_offset = table_offset + index * entry_size
                target, info = _unpack_relocation(image.data, image.bits, entry_offset)
                relocation_type, symbol = _relocation_info(image.bits, info)
                if relocation_type == 0:
                    continue
                width = _relocation_width(image.machine, relocation_type)
                virtual_address, file_offset = _relocation_target(image, target, width)
                relocations.append(
                    ElfRelocation(
                        source=source,
                        index=index,
                        virtual_address=virtual_address,
                        file_offset=file_offset,
                        size=width,
                        type=relocation_type,
                        symbol=symbol,
                        table_offset=entry_offset,
                        table_entry_size=entry_size,
                    )
                )
        if DT_ANDROID_REL in tags or DT_ANDROID_RELA in tags:
            coverage = "partial"
            notes.append(
                "Android APS2 packed relocations are present; standard REL/RELA "
                "targets were decoded but packed targets remain opaque"
            )
        if (DT_ANDROID_REL in tags) != (DT_ANDROID_RELSZ in tags):
            raise AndroidElfPatchError("incomplete DT_ANDROID_REL relocation metadata")
        if (DT_ANDROID_RELA in tags) != (DT_ANDROID_RELASZ in tags):
            raise AndroidElfPatchError("incomplete DT_ANDROID_RELA relocation metadata")
    return relocations, coverage, list(dict.fromkeys(notes))


def _relocation_entry_size(bits: int, with_addend: bool) -> int:
    if bits == 32:
        return 12 if with_addend else 8
    return 24 if with_addend else 16


def _unpack_relocation(data: bytes, bits: int, offset: int) -> tuple[int, int]:
    return struct.unpack_from("<II" if bits == 32 else "<QQ", data, offset)


def _relocation_info(bits: int, info: int) -> tuple[int, int]:
    if bits == 32:
        return info & 0xFF, info >> 8
    return info & 0xFFFFFFFF, info >> 32


def _relocation_width(machine: int, relocation_type: int) -> int:
    if machine == EM_ARM:
        return {5: 2, 8: 1}.get(relocation_type, 4)
    return {
        257: 8,  # R_AARCH64_ABS64
        258: 4,  # R_AARCH64_ABS32
        259: 2,  # R_AARCH64_ABS16
        260: 8,  # R_AARCH64_PREL64
        261: 4,  # R_AARCH64_PREL32
        262: 2,  # R_AARCH64_PREL16
        1025: 8,  # R_AARCH64_GLOB_DAT
        1026: 8,  # R_AARCH64_JUMP_SLOT
        1027: 8,  # R_AARCH64_RELATIVE
        1032: 8,  # R_AARCH64_IRELATIVE
    }.get(relocation_type, 4)


def _relocation_target(
    image: AndroidElfImage,
    target: int,
    width: int,
    *,
    target_section_index: int | None = None,
) -> tuple[int, int | None]:
    if target_section_index is not None:
        if target_section_index >= len(image.sections):
            raise AndroidElfPatchError("relocation target section is outside the section table")
        section = image.sections[target_section_index]
        virtual_address = section.address + target
        if section.type == SHT_NOBITS or target + width > section.size:
            return virtual_address, None
        return virtual_address, section.offset + target
    virtual_address = target
    try:
        return virtual_address, image.virtual_address_to_file_offset(virtual_address, width)
    except AndroidElfPatchError:
        return virtual_address, None


def _dedupe_relocations(values: list[ElfRelocation]) -> list[ElfRelocation]:
    ordered = sorted(
        values,
        key=lambda item: (
            item.file_offset is None,
            item.file_offset if item.file_offset is not None else item.virtual_address,
            item.size,
            item.type,
            item.source,
            item.index,
        ),
    )
    result: list[ElfRelocation] = []
    seen: set[tuple[int, int | None, int, int, int]] = set()
    for item in ordered:
        key = (item.virtual_address, item.file_offset, item.size, item.type, item.symbol)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _merge_intent(
    intent: Mapping[str, Any] | None,
    *,
    virtual_address: int | str | None,
    file_offset: int | str | None,
    replacement: str | bytes | None,
    instruction_mode: str,
    operation_id: str | None,
) -> dict[str, Any]:
    result = dict(intent or {})
    if virtual_address is not None:
        result["virtual_address"] = virtual_address
    if file_offset is not None:
        result["file_offset"] = file_offset
    if replacement is not None:
        result["replacement"] = replacement
    if "instruction_mode" not in result and "mode" not in result:
        result["instruction_mode"] = instruction_mode
    if operation_id is not None:
        result["id"] = operation_id
    aliases = {
        "va": "virtual_address",
        "address": "virtual_address",
        "offset": "file_offset",
        "preimage": "expected",
    }
    for alias, canonical in aliases.items():
        if canonical not in result and alias in result:
            result[canonical] = result[alias]
    return result


def _operation_from_intent(
    data: bytes,
    image: AndroidElfImage,
    intent: Mapping[str, Any],
) -> dict[str, Any]:
    replacement = _hex_bytes(intent.get("replacement"), field="replacement")
    selectors = [name for name in ("virtual_address", "file_offset") if intent.get(name) is not None]
    if len(selectors) != 1:
        raise AndroidElfPatchError("provide exactly one selector: virtual_address or file_offset")
    requested_mode = str(intent.get("instruction_mode", intent.get("mode", "auto")))
    requested_address: int | None = None
    if selectors[0] == "virtual_address":
        requested_address = _nonnegative_int(intent["virtual_address"], field="virtual_address")
        mode = _instruction_mode(image, requested_mode, requested_address=requested_address)
        canonical_address = _canonical_virtual_address(
            image,
            requested_address,
            instruction_mode=mode,
        )
        file_offset_value, segment = image._map_virtual_range(canonical_address, len(replacement))
        virtual_address_value = canonical_address
    else:
        file_offset_value = _nonnegative_int(intent["file_offset"], field="file_offset")
        virtual_address_value, segment = image._map_file_range(file_offset_value, len(replacement))
        mode = _instruction_mode(
            image,
            requested_mode,
            requested_address=virtual_address_value,
        )
    _validate_instruction_alignment(
        image,
        mode,
        virtual_address_value,
        file_offset_value,
        len(replacement),
    )
    preimage = data[file_offset_value : file_offset_value + len(replacement)]
    if "expected" in intent and intent.get("expected") is not None:
        expected = _hex_bytes(intent.get("expected"), field="expected")
        if len(expected) != len(replacement):
            raise AndroidElfPatchError("expected preimage length must equal replacement length")
        if expected != preimage:
            raise AndroidElfPatchError("expected preimage does not match the current ELF bytes")
    operation_id = str(intent.get("id") or "android-elf-operation-1").strip()
    if not operation_id:
        raise AndroidElfPatchError("operation id must be non-empty")
    alignment = _mode_alignment(mode)
    return {
        "id": operation_id,
        "kind": "replace_offset",
        "role": str(intent.get("role") or "native_instruction_patch"),
        "offset": file_offset_value,
        "file_offset": file_offset_value,
        "virtual_address": virtual_address_value,
        "selector_virtual_address": requested_address,
        "expected": preimage.hex(),
        "preimage": preimage.hex(),
        "replacement": replacement.hex(),
        "size": len(replacement),
        "architecture": image.architecture,
        "effective_architecture": mode,
        "bits": image.bits,
        "instruction_mode": mode,
        "instruction_alignment": alignment,
        "thumb_address_bit": bool(requested_address is not None and requested_address & 1),
        "segment_index": segment.index,
        "segment_permissions": _permissions(segment.flags),
    }


def _verify_payload(
    target: Path,
    data: bytes,
    image: AndroidElfImage,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    errors: list[str] = []
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = [
        {
            "name": "elf_parse",
            "status": "passed",
            "details": {
                "bits": image.bits,
                "machine": f"0x{image.machine:X}",
                "architecture": image.architecture,
                "pt_load_count": len(image.load_segments),
            },
        }
    ]

    schema_valid = plan.get("schema_version") == 1
    if not schema_valid:
        errors.append("patch plan schema_version must be the supported integer 1")
    planner = plan.get("planner") if isinstance(plan.get("planner"), Mapping) else {}
    planner_valid = str(planner.get("name") or "") == "android_elf_patch_planner"
    if not planner_valid:
        errors.append("patch plan was not produced by android_elf_patch_planner")
    checks.append(
        {
            "name": "plan_schema",
            "status": "passed" if schema_valid and planner_valid else "failed",
            "schema_version": plan.get("schema_version"),
            "planner": planner.get("name"),
        }
    )

    observed_hash = _sha256(data)
    declared_hash = plan.get("target_sha256")
    hash_format_valid = _valid_sha256(declared_hash)
    hash_matches = hash_format_valid and str(declared_hash).casefold() == observed_hash
    if not hash_format_valid:
        errors.append("target_sha256 must be a 64-character hexadecimal SHA-256 digest")
    elif not hash_matches:
        errors.append("target_sha256 does not match the supplied target")
    checks.append(
        {
            "name": "target_hash",
            "status": "passed" if hash_matches else "failed",
            "expected": declared_hash,
            "observed": observed_hash,
        }
    )

    identity_errors = _target_identity_errors(plan, target, data, image)
    errors.extend(identity_errors)
    checks.append(
        {
            "name": "target_identity",
            "status": "failed" if identity_errors else "passed",
            "errors": identity_errors,
        }
    )

    resolved: list[dict[str, Any]] = []
    operation_errors: list[str] = []
    operations = plan.get("operations")
    if not isinstance(operations, list) or not operations:
        operation_errors.append("patch plan must contain a non-empty operations array")
    else:
        simulated = bytearray(data)
        for index, raw_operation in enumerate(operations):
            try:
                resolved_operation = _resolve_operation(
                    bytes(simulated),
                    image,
                    raw_operation,
                    index=index,
                    prior=resolved,
                )
                resolved.append(resolved_operation)
                start = resolved_operation["file_offset"]
                replacement = bytes.fromhex(resolved_operation["replacement_hex"])
                simulated[start : start + len(replacement)] = replacement
            except (AndroidElfPatchError, TypeError, ValueError) as exc:
                operation_errors.append(str(exc))
    errors.extend(operation_errors)
    checks.append(
        {
            "name": "operation_ranges",
            "status": "failed" if operation_errors else "passed",
            "operation_count": len(resolved),
            "errors": operation_errors,
        }
    )

    alignment_errors = [
        error
        for operation in resolved
        for error in _alignment_errors(
            image,
            str(operation["instruction_mode"]),
            int(operation["virtual_address"]),
            int(operation["file_offset"]),
            int(operation["size"]),
            operation_id=str(operation["id"]),
        )
    ]
    errors.extend(alignment_errors)
    checks.append(
        {
            "name": "instruction_alignment",
            "status": "failed" if alignment_errors else "passed",
            "errors": alignment_errors,
            "operations": [
                {
                    "id": item["id"],
                    "mode": item["instruction_mode"],
                    "alignment": item["instruction_alignment"],
                }
                for item in resolved
            ],
        }
    )

    for operation in resolved:
        _append_segment_findings(operation, findings)
        _append_layout_findings(operation, image, findings)
        _append_relocation_findings(operation, image, findings)
    relocation_findings = [item for item in findings if item["category"] == "relocation"]
    checks.append(
        {
            "name": "relocation_overlap",
            "status": "warning" if relocation_findings else "passed",
            "coverage": image.relocation_coverage,
            "intersection_count": sum(
                item["id"].startswith("relocation_target_intersection")
                for item in relocation_findings
            ),
            "finding_ids": [item["id"] for item in relocation_findings],
        }
    )
    if image.relocation_coverage != "full":
        warnings.extend(image.relocation_notes)

    planned_hash = None
    if resolved and not operation_errors:
        simulated = bytearray(data)
        for operation in resolved:
            start = int(operation["file_offset"])
            replacement = bytes.fromhex(str(operation["replacement_hex"]))
            simulated[start : start + len(replacement)] = replacement
        planned_hash = _sha256(bytes(simulated))
    rollback_plan = _rollback_plan(
        target,
        data,
        resolved,
        patched_sha256=planned_hash,
        reversible=not errors and bool(resolved) and planned_hash is not None,
        errors=errors,
    )
    declared_rollback_errors = _declared_rollback_errors(plan.get("rollback_plan"), rollback_plan)
    errors.extend(declared_rollback_errors)
    if declared_rollback_errors:
        rollback_plan = {**rollback_plan, "status": "unavailable", "reversible": False, "errors": _dedupe(errors)}
    checks.append(
        {
            "name": "rollback_recoverability",
            "status": "passed" if rollback_plan["reversible"] else "failed",
            "errors": declared_rollback_errors,
        }
    )

    risk_report = _risk_report(findings)
    verification = {
        "schema_version": 1,
        "status": "ok" if not errors else "failed",
        "valid": not errors,
        "target_path": str(target),
        "target_sha256": observed_hash,
        "planned_sha256": planned_hash,
        "format": "elf",
        "architecture": image.architecture,
        "bits": image.bits,
        "checks": checks,
        "operations": resolved,
        "errors": _dedupe(errors),
        "warnings": _dedupe(warnings),
        "overall_risk": risk_report["overall_risk"],
    }
    return verification, risk_report, rollback_plan


def _resolve_operation(
    data: bytes,
    image: AndroidElfImage,
    raw_operation: Any,
    *,
    index: int,
    prior: list[Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(raw_operation, Mapping):
        raise AndroidElfPatchError(f"operations[{index}] must be an object")
    operation = dict(raw_operation)
    operation_id = str(operation.get("id") or f"operation-{index + 1}")
    if str(operation.get("kind") or "").casefold() not in {
        "replace_offset",
        "replace_file_offset",
        "replace_bytes",
    }:
        raise AndroidElfPatchError(f"{operation_id}: unsupported Android ELF patch operation kind")
    offset = _nonnegative_int(
        operation.get("offset", operation.get("file_offset")),
        field=f"{operation_id}.offset",
    )
    expected = _hex_bytes(operation.get("expected", operation.get("preimage")), field=f"{operation_id}.expected")
    replacement = _hex_bytes(operation.get("replacement"), field=f"{operation_id}.replacement")
    if len(expected) != len(replacement):
        raise AndroidElfPatchError(f"{operation_id}: replacement length must equal expected length")
    mapped_va, segment = image._map_file_range(offset, len(replacement))
    declared_va = _nonnegative_int(
        operation.get("virtual_address"),
        field=f"{operation_id}.virtual_address",
    )
    if declared_va != mapped_va:
        raise AndroidElfPatchError(
            f"{operation_id}: virtual address does not match the PT_LOAD file-offset mapping"
        )
    architecture = str(operation.get("architecture") or "")
    if architecture != image.architecture:
        raise AndroidElfPatchError(f"{operation_id}: architecture does not match the target ELF")
    mode = _instruction_mode(
        image,
        str(operation.get("instruction_mode") or ""),
        requested_address=mapped_va,
    )
    _validate_instruction_alignment(image, mode, mapped_va, offset, len(replacement))
    for previous in prior:
        previous_start = int(previous["file_offset"])
        previous_end = previous_start + int(previous["size"])
        if _overlaps(offset, offset + len(replacement), previous_start, previous_end):
            raise AndroidElfPatchError(
                f"{operation_id}: patch range overlaps operation {previous['id']}"
            )
    observed = data[offset : offset + len(replacement)]
    if observed != expected:
        raise AndroidElfPatchError(f"{operation_id}: current preimage does not match expected bytes")
    return {
        "id": operation_id,
        "kind": "replace_offset",
        "role": str(operation.get("role") or "native_instruction_patch"),
        "file_offset": offset,
        "file_offset_hex": f"0x{offset:X}",
        "virtual_address": mapped_va,
        "virtual_address_hex": f"0x{mapped_va:X}",
        "size": len(replacement),
        "original_hex": observed.hex(),
        "expected_hex": expected.hex(),
        "replacement_hex": replacement.hex(),
        "architecture": image.architecture,
        "bits": image.bits,
        "instruction_mode": mode,
        "instruction_alignment": _mode_alignment(mode),
        "segment_index": segment.index,
        "segment_flags": segment.flags,
        "segment_permissions": _permissions(segment.flags),
        "segment_executable": segment.executable,
        "segment_writable": segment.writable,
        "segment_readable": segment.readable,
    }


def _instruction_mode(
    image: AndroidElfImage,
    requested: str,
    *,
    requested_address: int,
) -> str:
    normalized = requested.strip().casefold().replace("-", "")
    aliases = {"arm32": "arm", "thumb2": "thumb", "arm64": "aarch64"}
    normalized = aliases.get(normalized, normalized)
    if image.architecture == "aarch64":
        if normalized in {"", "auto", "aarch64"}:
            return "aarch64"
        raise AndroidElfPatchError("AArch64 ELF patches require instruction_mode=aarch64")
    if normalized in {"", "auto"}:
        if requested_address & 1:
            return "thumb"
        if image.entrypoint & 1 and requested_address == (image.entrypoint & ~1):
            return "thumb"
        return "arm"
    if normalized not in {"arm", "thumb"}:
        raise AndroidElfPatchError("ARM ELF patches require instruction_mode=arm or thumb")
    if normalized == "arm" and requested_address & 1:
        raise AndroidElfPatchError("an odd ARM virtual address carries Thumb state; use instruction_mode=thumb")
    return normalized


def _canonical_virtual_address(
    image: AndroidElfImage,
    virtual_address: int,
    *,
    instruction_mode: str | None,
) -> int:
    requested = instruction_mode or "auto"
    mode = _instruction_mode(image, requested, requested_address=virtual_address)
    if image.architecture == "arm" and mode == "thumb":
        return virtual_address & ~1
    return virtual_address


def _validate_instruction_alignment(
    image: AndroidElfImage,
    mode: str,
    virtual_address: int,
    file_offset: int,
    size: int,
) -> None:
    errors = _alignment_errors(
        image,
        mode,
        virtual_address,
        file_offset,
        size,
        operation_id="operation",
    )
    if errors:
        raise AndroidElfPatchError(errors[0].split(": ", 1)[-1])


def _alignment_errors(
    image: AndroidElfImage,
    mode: str,
    virtual_address: int,
    file_offset: int,
    size: int,
    *,
    operation_id: str,
) -> list[str]:
    if mode not in image.supported_instruction_modes:
        return [f"{operation_id}: instruction mode {mode!r} is incompatible with {image.architecture}"]
    alignment = _mode_alignment(mode)
    errors: list[str] = []
    if virtual_address % alignment:
        errors.append(
            f"{operation_id}: {mode} virtual address 0x{virtual_address:X} is not {alignment}-byte aligned"
        )
    if file_offset % alignment:
        errors.append(
            f"{operation_id}: {mode} file offset 0x{file_offset:X} is not {alignment}-byte aligned"
        )
    if size % alignment:
        errors.append(
            f"{operation_id}: {mode} replacement size {size} is not a multiple of {alignment}"
        )
    return errors


def _mode_alignment(mode: str) -> int:
    return 2 if mode == "thumb" else 4


def _append_segment_findings(
    operation: Mapping[str, Any],
    findings: list[dict[str, Any]],
) -> None:
    operation_id = str(operation["id"])
    evidence = {
        "segment_index": operation["segment_index"],
        "permissions": operation["segment_permissions"],
        "file_offset": operation["file_offset"],
        "virtual_address": operation["virtual_address"],
        "size": operation["size"],
    }
    if not operation["segment_executable"]:
        findings.append(
            _finding(
                f"segment_not_executable:{operation_id}",
                "high",
                "segment_permissions",
                "instruction patch targets a PT_LOAD segment without execute permission",
                operation_id,
                evidence,
            )
        )
    if not operation["segment_writable"]:
        findings.append(
            _finding(
                f"segment_not_writable:{operation_id}",
                "medium",
                "segment_permissions",
                "PT_LOAD segment is not writable; a runtime application would require a protection transition",
                operation_id,
                evidence,
            )
        )
    if operation["segment_executable"] and operation["segment_writable"]:
        findings.append(
            _finding(
                f"writable_executable_segment:{operation_id}",
                "high",
                "segment_permissions",
                "patch target is in a writable and executable PT_LOAD segment",
                operation_id,
                evidence,
            )
        )


def _append_layout_findings(
    operation: Mapping[str, Any],
    image: AndroidElfImage,
    findings: list[dict[str, Any]],
) -> None:
    start = int(operation["file_offset"])
    end = start + int(operation["size"])
    operation_id = str(operation["id"])
    ranges = [
        (0, image.header_size, "elf_header"),
        (
            image.program_header_offset,
            image.program_header_offset + image.program_header_entry_size * image.program_header_count,
            "program_header_table",
        ),
    ]
    if image.section_header_count:
        ranges.append(
            (
                image.section_header_offset,
                image.section_header_offset + image.section_header_entry_size * image.section_header_count,
                "section_header_table",
            )
        )
    for range_start, range_end, name in ranges:
        if range_end > range_start and _overlaps(start, end, range_start, range_end):
            findings.append(
                _finding(
                    f"elf_layout_intersection:{name}:{operation_id}",
                    "critical",
                    "elf_layout",
                    f"patch intersects the ELF {name.replace('_', ' ')}",
                    operation_id,
                    {"range_start": range_start, "range_end": range_end},
                )
            )
    canonical_entry = image.entrypoint & ~1 if image.architecture == "arm" else image.entrypoint
    patch_va = int(operation["virtual_address"])
    if patch_va <= canonical_entry < patch_va + int(operation["size"]):
        findings.append(
            _finding(
                f"entrypoint_intersection:{operation_id}",
                "high",
                "control_flow",
                "patch intersects the ELF entrypoint",
                operation_id,
                {"entrypoint": image.entrypoint, "canonical_entrypoint": canonical_entry},
            )
        )


def _append_relocation_findings(
    operation: Mapping[str, Any],
    image: AndroidElfImage,
    findings: list[dict[str, Any]],
) -> None:
    start = int(operation["file_offset"])
    end = start + int(operation["size"])
    operation_id = str(operation["id"])
    for relocation in image.relocations:
        if relocation.file_offset is None:
            continue
        if _overlaps(start, end, relocation.file_offset, relocation.file_offset + relocation.size):
            findings.append(
                _finding(
                    "relocation_target_intersection:"
                    f"{operation_id}:0x{relocation.virtual_address:X}:{relocation.type}",
                    "critical",
                    "relocation",
                    "patch intersects an ELF relocation target",
                    operation_id,
                    relocation.to_dict(),
                )
            )
        if _overlaps(
            start,
            end,
            relocation.table_offset,
            relocation.table_offset + relocation.table_entry_size,
        ):
            findings.append(
                _finding(
                    f"relocation_table_intersection:{operation_id}:0x{relocation.table_offset:X}",
                    "critical",
                    "relocation",
                    "patch intersects an ELF relocation table entry",
                    operation_id,
                    relocation.to_dict(),
                )
            )
    if image.relocation_coverage != "full":
        findings.append(
            _finding(
                f"relocation_coverage_partial:{operation_id}",
                "high",
                "relocation",
                "packed Android relocations prevent complete target-overlap proof",
                operation_id,
                {"coverage": image.relocation_coverage, "notes": list(image.relocation_notes)},
            )
        )


def _target_identity_errors(
    plan: Mapping[str, Any],
    target: Path,
    data: bytes,
    image: AndroidElfImage,
) -> list[str]:
    value = plan.get("target_identity", plan.get("target"))
    if not isinstance(value, Mapping):
        return ["target_identity must be an object"]
    errors: list[str] = []
    checks = {
        "format": "elf",
        "sha256": _sha256(data),
        "size": len(data),
        "bits": image.bits,
        "architecture": image.architecture,
        "machine": image.machine,
    }
    for name, expected in checks.items():
        observed = value.get(name)
        if name == "sha256" and isinstance(observed, str):
            matches = observed.casefold() == str(expected).casefold()
        else:
            matches = observed == expected
        if not matches:
            errors.append(f"target_identity.{name} does not match the supplied target")
    declared_path = value.get("path")
    if not isinstance(declared_path, str) or Path(declared_path).resolve() != target:
        errors.append("target_identity.path does not match the supplied target")
    return errors


def _declared_rollback_errors(declared: Any, computed: Mapping[str, Any]) -> list[str]:
    if not isinstance(declared, Mapping):
        return ["patch plan must contain rollback_plan evidence"]
    errors: list[str] = []
    for field in ("source_sha256", "patched_sha256"):
        left = declared.get(field)
        right = computed.get(field)
        if not isinstance(left, str) or not isinstance(right, str) or left.casefold() != right.casefold():
            errors.append(f"rollback_plan.{field} does not match the computed patch evidence")
    declared_operations = declared.get("operations")
    computed_operations = computed.get("operations")
    if declared_operations != computed_operations:
        errors.append("rollback_plan.operations do not match the computed rollback bytes")
    return errors


def _rollback_plan(
    target: Path,
    data: bytes,
    operations: list[Mapping[str, Any]],
    *,
    patched_sha256: str | None,
    reversible: bool,
    errors: list[str],
) -> dict[str, Any]:
    rollback_operations = [
        {
            "kind": "restore_bytes",
            "id": item["id"],
            "offset": item["file_offset"] if "file_offset" in item else item["offset"],
            "file_offset": item["file_offset"] if "file_offset" in item else item["offset"],
            "virtual_address": item["virtual_address"],
            "expected": item.get("replacement_hex", item.get("replacement")),
            "replacement": item.get("expected_hex", item.get("expected")),
            "original_hex": item.get("expected_hex", item.get("expected")),
            "patched_hex": item.get("replacement_hex", item.get("replacement")),
        }
        for item in operations
    ]
    return {
        "schema_version": 1,
        "status": "planned" if reversible else "unavailable",
        "reversible": bool(reversible),
        "strategy": "android_elf_inline_patch",
        "source_path": str(target),
        "source_sha256": _sha256(data),
        "patched_sha256": patched_sha256,
        "operations": rollback_operations,
        "requires_patched_copy": True,
        "errors": [] if reversible else _dedupe(errors),
    }


def _target_summary(target: Path, data: bytes, image: AndroidElfImage) -> dict[str, Any]:
    return {
        "kind": "sample",
        "path": str(target),
        "display_name": target.name,
        "format": "elf",
        "sha256": _sha256(data),
        "size": len(data),
        "bits": image.bits,
        "machine": image.machine,
        "machine_hex": f"0x{image.machine:X}",
        "architecture": image.architecture,
        "entrypoint": image.entrypoint,
        "supported_instruction_modes": list(image.supported_instruction_modes),
        "pt_load_segments": [item.to_dict() for item in image.load_segments],
        "relocation_count": len(image.relocations),
        "relocation_coverage": image.relocation_coverage,
    }


def _risk_report(findings: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(
        findings,
        key=lambda item: (
            -_SEVERITY_ORDER.get(str(item.get("severity")), 0),
            str(item.get("id")),
            str(item.get("operation_id")),
        ),
    )
    highest = max(
        (_SEVERITY_ORDER.get(str(item.get("severity")), 0) for item in ordered),
        default=0,
    )
    overall = next(name for name, value in _SEVERITY_ORDER.items() if value == highest)
    counts = {name: 0 for name in _SEVERITY_ORDER}
    for item in ordered:
        counts[str(item.get("severity") or "info")] += 1
    weights = {"info": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
    return {
        "schema_version": 1,
        "status": "ok",
        "overall_risk": overall,
        "risk_score": min(100, sum(counts[name] * weights[name] for name in counts)),
        "counts": counts,
        "findings": ordered,
    }


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


def _write_artifacts(
    out_dir: Path,
    *,
    plan: Mapping[str, Any],
    verification: Mapping[str, Any],
    risk_report: Mapping[str, Any],
    rollback_plan: Mapping[str, Any],
    include_plan: bool,
    protected_paths: Mapping[str, Path],
) -> list[dict[str, Any]]:
    values: list[tuple[str, Mapping[str, Any], str]] = []
    if include_plan:
        values.append(("plan.json", plan, "android-elf-patch-plan"))
    values.extend(
        [
            ("verify.json", verification, "android-elf-patch-verification"),
            ("risk_report.json", risk_report, "android-elf-patch-risk-report"),
            ("rollback_plan.json", rollback_plan, "android-elf-patch-rollback-plan"),
        ]
    )
    outputs = {name: (out_dir / name).resolve() for name, _, _ in values}
    _ensure_distinct_paths({**protected_paths, **{f"artifact:{name}": value for name, value in outputs.items()}})
    _write_json_bundle([(outputs[name], payload) for name, payload, _ in values])
    return [
        {"name": name, "path": str(outputs[name]), "kind": kind}
        for name, _, kind in values
    ]


def _load_mapping(
    value: Mapping[str, Any] | str | Path,
    *,
    label: str,
) -> tuple[dict[str, Any], Path | None]:
    if isinstance(value, Mapping):
        return dict(value), None
    source = Path(value).resolve()
    if not source.is_file():
        raise AndroidElfPatchError(f"{label} does not exist: {source}")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AndroidElfPatchError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise AndroidElfPatchError(f"{label} JSON must be an object")
    return dict(payload), source.parent


def _check_table_range(
    file_size: int,
    offset: int,
    entry_size: int,
    count: int,
    *,
    label: str,
) -> None:
    if count < 0 or count > _MAX_TABLE_ENTRIES:
        raise AndroidElfPatchError(f"{label} has an unreasonable entry count")
    if offset < 0 or entry_size < 0 or offset + entry_size * count > file_size:
        raise AndroidElfPatchError(f"{label} exceeds the ELF file")


def _checked_range(start: int, size: int, *, field: str) -> tuple[int, int]:
    normalized_start = _nonnegative_int(start, field=field)
    normalized_size = _positive_int(size, field=f"{field} size")
    return normalized_start, normalized_start + normalized_size


def _nonnegative_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise AndroidElfPatchError(f"{field} must be a non-negative integer")
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise AndroidElfPatchError(f"{field} must be a non-negative integer") from exc
    if not isinstance(value, int) or value < 0:
        raise AndroidElfPatchError(f"{field} must be a non-negative integer")
    return value


def _positive_int(value: Any, *, field: str) -> int:
    result = _nonnegative_int(value, field=field)
    if result == 0:
        raise AndroidElfPatchError(f"{field} must be positive")
    return result


def _hex_bytes(value: Any, *, field: str) -> bytes:
    if isinstance(value, bytes):
        result = value
    elif isinstance(value, str):
        compact = "".join(value.split())
        if compact.casefold().startswith("0x"):
            compact = compact[2:]
        if not compact or len(compact) % 2:
            raise AndroidElfPatchError(f"{field} must contain an even number of hexadecimal characters")
        try:
            result = bytes.fromhex(compact)
        except ValueError as exc:
            raise AndroidElfPatchError(f"{field} must be hexadecimal bytes") from exc
    else:
        raise AndroidElfPatchError(f"{field} must be bytes or a hexadecimal string")
    if not result:
        raise AndroidElfPatchError(f"{field} must not be empty")
    return result


def _permissions(flags: int) -> str:
    return "".join(("r" if flags & PF_R else "-", "w" if flags & PF_W else "-", "x" if flags & PF_X else "-"))


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and start_b < end_a


def _dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _require_file(path: str | Path) -> Path:
    target = Path(path).resolve()
    if not target.is_file():
        raise AndroidElfPatchError(f"target file does not exist: {target}")
    return target


def _ensure_distinct_paths(named_paths: Mapping[str, Path]) -> None:
    normalized = [(name, Path(path).resolve()) for name, path in named_paths.items()]
    for index, (left_name, left_path) in enumerate(normalized):
        for right_name, right_path in normalized[index + 1 :]:
            if left_path == right_path:
                raise AndroidElfPatchError(
                    f"path collision between {left_name} and {right_name}: {left_path}"
                )
            try:
                if left_path.exists() and right_path.exists() and os.path.samefile(left_path, right_path):
                    raise AndroidElfPatchError(
                        f"path collision between {left_name} and {right_name}: {left_path}"
                    )
            except OSError:
                pass


def _write_json_bundle(values: list[tuple[Path, Mapping[str, Any]]]) -> None:
    staged: list[tuple[Path, Path]] = []
    previous: dict[Path, bytes | None] = {}
    committed: list[Path] = []
    try:
        for output, payload in values:
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists() and not output.is_file():
                raise AndroidElfPatchError(f"artifact path is not a regular file: {output}")
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
                    _atomic_write(output, original)
            except OSError:
                pass
        raise
    finally:
        for temporary_path, _ in staged:
            temporary_path.unlink(missing_ok=True)


def _atomic_write(path: Path, payload: bytes) -> None:
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
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _failure(tool: str, path: str | Path, exc: Exception) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="failed",
        error=f"{type(exc).__name__}: {exc}",
        data={"status": "failed", "target": str(path), "artifacts": []},
    )


__all__ = [
    "AndroidElfImage",
    "AndroidElfPatchError",
    "ElfProgramHeader",
    "ElfRelocation",
    "parse_android_elf",
    "plan_android_elf_patch",
    "validate_android_elf_patch_plan",
    "verify_android_elf_patch",
]
