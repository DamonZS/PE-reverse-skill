"""Built-in local static-analysis tools.

These tools avoid network access and active exploitation. Optional reverse
engineering dependencies are imported lazily so missing packages degrade into
``unavailable`` results instead of import-time failures.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, Iterable, List

from .executor import ToolExecutor, ToolResult
from .ghidra import ghidra_check, ghidra_decompile, ghidra_install_guide

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))
SUSPICIOUS_SECTION_NAMES = {"upx0", "upx1", "aspack", ".aspack", ".adata", ".packed", "petite"}
PACKER_IMPORT_HINTS = {
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
}


def register_builtin_tools(executor: ToolExecutor | None = None) -> ToolExecutor:
    """Register all built-in static-analysis tools on an executor."""

    executor = executor or ToolExecutor()
    executor.register("file_info", file_info)
    executor.register("hash", hash_file)
    executor.register("strings_extract", strings_extract)
    executor.register("pe_header_scan", pe_header_scan)
    executor.register("section_entropy_scan", section_entropy_scan)
    executor.register("capstone_disassemble_stub", capstone_disassemble_stub)
    executor.register("packer_detect", packer_detect)
    executor.register("yara_scan_stub", yara_scan_stub)
    executor.register("external_command", external_command)
    executor.register("ghidra_check", ghidra_check)
    executor.register("ghidra_decompile", ghidra_decompile)
    executor.register("ghidra_install_guide", ghidra_install_guide)
    return executor


def file_info(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    st = p.stat()
    return {
        "path": str(p),
        "name": p.name,
        "size": st.st_size,
        "suffix": p.suffix,
        "is_file": p.is_file(),
    }


def hash_file(path: str | os.PathLike[str], algorithms: Iterable[str] = ("md5", "sha1", "sha256")) -> Dict[str, Any]:
    p = _require_file(path)
    hashers = {name: hashlib.new(name) for name in algorithms}
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            for h in hashers.values():
                h.update(chunk)
    return {"path": str(p), "hashes": {name: h.hexdigest() for name, h in hashers.items()}}


def strings_extract(path: str | os.PathLike[str], min_length: int = 4, limit: int = 1000) -> Dict[str, Any]:
    p = _require_file(path)
    data = p.read_bytes()
    ascii_strings = [m.group(0).decode("ascii", errors="replace") for m in PRINTABLE_RE.finditer(data)]
    utf16_strings = [m.group(0).decode("utf-16le", errors="ignore") for m in UTF16LE_RE.finditer(data)]
    strings = [s for s in ascii_strings + utf16_strings if len(s) >= min_length]
    return {"path": str(p), "count": len(strings), "strings": strings[:limit], "truncated": len(strings) > limit}


def pe_header_scan(path: str | os.PathLike[str]) -> ToolResult | Dict[str, Any]:
    p = _require_file(path)
    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return _unavailable("pe_header_scan", "pefile", exc)

    pe = pefile.PE(str(p), fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sections.append(
            {
                "name": name,
                "virtual_address": int(section.VirtualAddress),
                "virtual_size": int(section.Misc_VirtualSize),
                "raw_size": int(section.SizeOfRawData),
                "entropy": float(section.get_entropy()),
            }
        )
    imports = _extract_pe_imports(pe)
    return {
        "path": str(p),
        "machine": int(pe.FILE_HEADER.Machine),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "entry_point": int(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": int(pe.OPTIONAL_HEADER.ImageBase),
        "sections": sections,
        "imports": imports,
    }


def section_entropy_scan(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    data = p.read_bytes()
    sections = _fallback_sections(data)
    pe_sections = _try_pe_sections(p)
    if pe_sections:
        sections = pe_sections
    return {"path": str(p), "sections": sections, "max_entropy": max((s["entropy"] for s in sections), default=0.0)}


def capstone_disassemble_stub(
    path: str | os.PathLike[str],
    offset: int = 0,
    size: int = 64,
    arch: str = "x86",
    mode: str = "32",
) -> ToolResult | Dict[str, Any]:
    p = _require_file(path)
    try:
        import capstone  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool="capstone_disassemble_stub",
            status="unavailable",
            error=f"optional dependency capstone unavailable: {exc}",
            data={"path": str(p), "stub": True, "instructions": []},
        )

    arch_const = capstone.CS_ARCH_X86 if arch == "x86" else capstone.CS_ARCH_X86
    mode_const = capstone.CS_MODE_64 if str(mode) == "64" else capstone.CS_MODE_32
    md = capstone.Cs(arch_const, mode_const)
    blob = p.read_bytes()[offset : offset + size]
    instructions = [
        {"address": int(i.address + offset), "mnemonic": i.mnemonic, "op_str": i.op_str, "bytes": i.bytes.hex()}
        for i in md.disasm(blob, 0)
    ]
    return {"path": str(p), "offset": offset, "size": size, "instructions": instructions, "stub": False}


def packer_detect(path: str | os.PathLike[str]) -> Dict[str, Any]:
    p = _require_file(path)
    entropy = section_entropy_scan(p)["sections"]
    strings = strings_extract(p, limit=5000)["strings"]
    lower_strings = {s.lower() for s in strings}
    indicators: List[Dict[str, Any]] = []

    for section in entropy:
        name = str(section.get("name", "")).lower()
        value = float(section.get("entropy", 0.0))
        if name in SUSPICIOUS_SECTION_NAMES or name.startswith("upx"):
            indicators.append({"type": "section_name", "section": name, "reason": "known packer-like section name"})
        if value >= 7.2:
            indicators.append({"type": "high_entropy", "section": name, "entropy": round(value, 4)})

    for hint in PACKER_IMPORT_HINTS:
        if hint.lower() in lower_strings:
            indicators.append({"type": "import_or_string", "value": hint})

    score = min(100, len(indicators) * 25)
    return {
        "path": str(p),
        "packed_likely": score >= 50,
        "score": score,
        "indicators": indicators,
    }


def yara_scan_stub(path: str | os.PathLike[str], rules_path: str | os.PathLike[str] | None = None) -> ToolResult | Dict[str, Any]:
    p = _require_file(path)
    try:
        import yara  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return _unavailable("yara_scan_stub", "yara-python", exc, data={"path": str(p), "matches": []})

    if rules_path is None:
        return ToolResult(
            tool="yara_scan_stub",
            status="unavailable",
            error="rules_path is required when yara-python is installed",
            data={"path": str(p), "matches": []},
        )
    rules = yara.compile(filepath=str(rules_path))
    matches = rules.match(str(p))
    return {"path": str(p), "matches": [str(m) for m in matches]}


def external_command(
    command: List[str],
    allow_external: bool = False,
    timeout: float = 10.0,
    cwd: str | os.PathLike[str] | None = None,
) -> ToolResult | Dict[str, Any]:
    if not allow_external:
        return ToolResult(
            tool="external_command",
            status="unavailable",
            error="external commands are disabled by default; pass allow_external=True",
            data={"command": command},
        )
    if not command or not isinstance(command, list):
        raise ValueError("command must be a non-empty list")
    executable = shutil.which(command[0])
    if executable is None:
        raise FileNotFoundError(command[0])
    completed = subprocess.run(
        [executable, *command[1:]],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        shell=False,
        check=False,
    )
    return {
        "command": [executable, *command[1:]],
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _require_file(path: str | os.PathLike[str]) -> Path:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(str(p))
    return p


def _unavailable(tool: str, dependency: str, exc: BaseException, data: Dict[str, Any] | None = None) -> ToolResult:
    return ToolResult(
        tool=tool,
        status="unavailable",
        error=f"optional dependency {dependency} unavailable: {exc}",
        data=data or {},
    )


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _fallback_sections(data: bytes, chunk_size: int = 4096) -> List[Dict[str, Any]]:
    if not data:
        return [{"name": "whole_file", "offset": 0, "size": 0, "entropy": 0.0}]
    chunks = []
    for index, offset in enumerate(range(0, len(data), chunk_size)):
        chunk = data[offset : offset + chunk_size]
        chunks.append({"name": f"chunk_{index}", "offset": offset, "size": len(chunk), "entropy": _entropy(chunk)})
    return chunks


def _try_pe_sections(path: Path) -> List[Dict[str, Any]]:
    try:
        import pefile  # type: ignore[import-not-found]

        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return []
    sections = []
    for section in pe.sections:
        raw = section.get_data()
        sections.append(
            {
                "name": section.Name.rstrip(b"\x00").decode("utf-8", errors="replace"),
                "offset": int(section.PointerToRawData),
                "size": int(section.SizeOfRawData),
                "virtual_address": int(section.VirtualAddress),
                "entropy": _entropy(raw),
            }
        )
    return sections


def _extract_pe_imports(pe: Any) -> List[Dict[str, Any]]:
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("utf-8", errors="replace") if isinstance(entry.dll, bytes) else str(entry.dll)
        funcs = []
        for imp in entry.imports:
            funcs.append(
                {
                    "name": imp.name.decode("utf-8", errors="replace") if imp.name else None,
                    "ordinal": int(imp.ordinal) if imp.ordinal is not None else None,
                    "address": int(imp.address),
                }
            )
        imports.append({"dll": dll, "functions": funcs})
    return imports
