"""Read-only dynamic memory evidence helpers for Windows processes.

The functions in this module deliberately use only query/read Win32 APIs.  They
never allocate in, write to, suspend, inject into, or create threads in a target
process.  Their JSON artifacts are intended as bounded evidence, rather than as
full process dumps.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from .executor import ToolResult


SCHEMA_VERSION = 1
DEFAULT_MAX_BYTES = 64 * 1024
DEFAULT_REGION_SAMPLE_BYTES = 4096
# Keep a plan from turning a read-only evidence capture into an unbounded
# process walk or a multi-megabyte JSON artifact.  Callers may request smaller
# values; larger values are clamped and reported as truncated evidence.
DEFAULT_MAX_REGIONS = 512
MAX_SAMPLE_BYTES = 1024 * 1024
MAX_REGIONS = 4096

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
LIST_MODULES_ALL = 0x03
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

_READABLE_PROTECTIONS = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
_PROTECTION_NAMES = {
    0x01: "PAGE_NOACCESS", 0x02: "PAGE_READONLY", 0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY", 0x10: "PAGE_EXECUTE", 0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE", 0x80: "PAGE_EXECUTE_WRITECOPY",
}
_STATE_NAMES = {MEM_COMMIT: "MEM_COMMIT", MEM_FREE: "MEM_FREE", 0x2000: "MEM_RESERVE"}
_TYPE_NAMES = {0x01000000: "MEM_IMAGE", 0x02000000: "MEM_MAPPED", 0x04000000: "MEM_PRIVATE"}


class _MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", wintypes.LPVOID), ("SizeOfImage", wintypes.DWORD), ("EntryPoint", wintypes.LPVOID)]


class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", wintypes.LPVOID),
        ("AllocationBase", wintypes.LPVOID),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class _SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", wintypes.WORD), ("wReserved", wintypes.WORD),
        ("dwPageSize", wintypes.DWORD), ("lpMinimumApplicationAddress", wintypes.LPVOID),
        ("lpMaximumApplicationAddress", wintypes.LPVOID), ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", wintypes.DWORD), ("dwProcessorType", wintypes.DWORD),
        ("dwAllocationGranularity", wintypes.DWORD), ("wProcessorLevel", wintypes.WORD),
        ("wProcessorRevision", wintypes.WORD),
    ]


def memory_snapshot(
    path: str | Path | int,
    out_dir: str | Path,
    module_filter: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_regions: int = DEFAULT_MAX_REGIONS,
) -> ToolResult:
    """Collect bounded, read-only module and virtual-memory evidence.

    ``path`` may be a PID or an executable path/name.  On non-Windows hosts,
    and when access is denied, an ``unavailable`` result is returned instead of
    raising an exception.
    """

    try:
        if os.name != "nt":
            return _unavailable("memory_snapshot", "Windows read-only memory APIs are unavailable on this platform")
        if not _non_negative_int(max_bytes):
            return _failed("memory_snapshot", "max_bytes must be a non-negative integer")
        if not _non_negative_int(max_regions):
            return _failed("memory_snapshot", "max_regions must be a non-negative integer")

        requested_max_bytes = max_bytes
        requested_max_regions = max_regions
        max_bytes = min(max_bytes, MAX_SAMPLE_BYTES)
        max_regions = min(max_regions, MAX_REGIONS)
        limits_clamped = max_bytes != requested_max_bytes or max_regions != requested_max_regions

        pid = _resolve_pid(path)
        if pid is None:
            return _unavailable("memory_snapshot", f"target process not found: {path}")

        kernel32 = _kernel32()
        process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not process:
            error = ctypes.get_last_error()
            return _unavailable("memory_snapshot", f"unable to open pid {pid} for read-only inspection (Win32 error {error})", {"pid": pid})
        try:
            modules = _enumerate_modules(process)
            selected_modules = _filter_modules(modules, module_filter)
            selected_ranges = None if module_filter is None else [(item["base_address_int"], item["base_address_int"] + item["size"]) for item in selected_modules]
            regions, sampled_bytes, enumeration_truncated = _enumerate_regions(
                process,
                modules,
                selected_ranges,
                max_bytes,
                max_regions,
            )
        finally:
            kernel32.CloseHandle(process)

        snapshot = {
            "schema_version": SCHEMA_VERSION,
            "kind": "memory_snapshot",
            "source": {"pid": pid, "module_filter": module_filter},
            "modules": [_public_module(item) for item in selected_modules],
            "regions": regions,
            "truncated": limits_clamped or enumeration_truncated,
            "summary": {
                "module_count": len(selected_modules), "region_count": len(regions),
                "sampled_region_count": sum(1 for item in regions if "sample" in item),
                "sampled_bytes": sampled_bytes,
                "max_bytes": max_bytes,
                "max_regions": max_regions,
                "requested_max_bytes": requested_max_bytes,
                "requested_max_regions": requested_max_regions,
                "truncated": limits_clamped or enumeration_truncated,
            },
        }
        data, artifacts = _write_artifact(out_dir, f"memory_snapshot_{pid}.json", snapshot, "memory_snapshot")
        return ToolResult("memory_snapshot", "ok", data=data, metadata={"artifacts": artifacts})
    except OSError as exc:
        return _unavailable("memory_snapshot", str(exc))
    except Exception as exc:  # noqa: BLE001 - public tools never propagate operational failures
        return _failed("memory_snapshot", str(exc))


def memory_diff(
    before: str | Path | Mapping[str, Any],
    after: str | Path | Mapping[str, Any],
    out_dir: str | Path,
    artifact_name: str | None = None,
) -> ToolResult:
    """Diff two memory snapshot JSON documents or mappings by region identity."""

    try:
        before_snapshot = _load_snapshot(before)
        after_snapshot = _load_snapshot(after)
        before_regions = {_region_key(item): item for item in _regions(before_snapshot)}
        after_regions = {_region_key(item): item for item in _regions(after_snapshot)}
        added_keys = sorted(after_regions.keys() - before_regions.keys())
        removed_keys = sorted(before_regions.keys() - after_regions.keys())
        changed = []
        for key in sorted(before_regions.keys() & after_regions.keys()):
            changed_fields = _changed_fields(before_regions[key], after_regions[key])
            if changed_fields:
                changed.append({"region": key, "changed_fields": changed_fields, "before": before_regions[key], "after": after_regions[key]})
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "memory_diff",
            "added_regions": [after_regions[key] for key in added_keys],
            "removed_regions": [before_regions[key] for key in removed_keys],
            "changed_regions": changed,
            "summary": {
                "before_region_count": len(before_regions), "after_region_count": len(after_regions),
                "added_count": len(added_keys), "removed_count": len(removed_keys), "changed_count": len(changed),
            },
        }
        data, artifacts = _write_artifact(
            out_dir,
            _artifact_name(artifact_name, "memory_diff.json"),
            result,
            "memory_diff",
        )
        return ToolResult("memory_diff", "ok", data=data, metadata={"artifacts": artifacts})
    except Exception as exc:  # noqa: BLE001
        return _failed("memory_diff", str(exc))


def memory_address_map(
    path: str | Path,
    snapshot: str | Path | Mapping[str, Any],
    addresses: Iterable[int | str],
    out_dir: str | Path,
    artifact_name: str | None = None,
) -> ToolResult:
    """Map process addresses to loaded modules, RVAs, and PE sections when possible."""

    try:
        source = _load_snapshot(snapshot)
        modules = [_normalise_module(item) for item in source.get("modules", []) if isinstance(item, Mapping)]
        sections, pe_error = _pe_sections(path)
        mapped = [_map_address(item, modules, sections, path) for item in addresses]
        result = {
            "schema_version": SCHEMA_VERSION,
            "kind": "memory_address_map",
            "path": str(path),
            "addresses": mapped,
            "summary": {"address_count": len(mapped), "mapped_count": sum(1 for item in mapped if item["module"] is not None)},
            "pe_mapping": {"available": not bool(pe_error), "error": pe_error},
        }
        data, artifacts = _write_artifact(
            out_dir,
            _artifact_name(artifact_name, "memory_address_map.json"),
            result,
            "memory_address_map",
        )
        return ToolResult("memory_address_map", "ok", data=data, metadata={"artifacts": artifacts})
    except Exception as exc:  # noqa: BLE001
        return _failed("memory_address_map", str(exc))


def _resolve_pid(target: str | Path | int) -> int | None:
    if isinstance(target, int):
        return target if target > 0 else None
    value = str(target).strip()
    if value.isdigit():
        return int(value) if int(value) > 0 else None
    wanted = Path(value).name.lower()
    kernel32 = _kernel32()
    # TH32CS_SNAPPROCESS and PROCESSENTRY32W are used only to locate a process;
    # no target-process handle is opened here.
    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    handle = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        return None
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = kernel32.Process32FirstW(handle, ctypes.byref(entry))
        while more:
            if entry.szExeFile.lower() == wanted:
                return int(entry.th32ProcessID)
            more = kernel32.Process32NextW(handle, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(handle)
    return None


def _kernel32():
    """Return kernel32 with pointer-sized signatures configured for 64-bit hosts."""

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(_SYSTEM_INFO)]
    kernel32.GetSystemInfo.restype = None
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(_MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    return kernel32


def _enumerate_modules(process: int) -> list[dict[str, Any]]:
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    psapi.EnumProcessModulesEx.restype = wintypes.BOOL
    psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(_MODULEINFO), wintypes.DWORD]
    psapi.GetModuleInformation.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    count = 256
    while True:
        array = (wintypes.HMODULE * count)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModulesEx(process, array, ctypes.sizeof(array), ctypes.byref(needed), LIST_MODULES_ALL):
            raise OSError(f"EnumProcessModulesEx failed (Win32 error {ctypes.get_last_error()})")
        if needed.value <= ctypes.sizeof(array):
            break
        count = (needed.value // ctypes.sizeof(wintypes.HMODULE)) + 16
    modules = []
    for handle in array[: needed.value // ctypes.sizeof(wintypes.HMODULE)]:
        info = _MODULEINFO()
        if not psapi.GetModuleInformation(process, handle, ctypes.byref(info), ctypes.sizeof(info)):
            continue
        buffer = ctypes.create_unicode_buffer(32768)
        psapi.GetModuleFileNameExW(process, handle, buffer, len(buffer))
        base = int(info.lpBaseOfDll or 0)
        modules.append({"name": Path(buffer.value).name or f"module_{base:x}", "path": buffer.value or None, "base_address": _hex(base), "base_address_int": base, "size": int(info.SizeOfImage)})
    return sorted(modules, key=lambda item: item["base_address_int"])


def _enumerate_regions(
    process: int,
    modules: list[dict[str, Any]],
    selected_ranges: list[tuple[int, int]] | None,
    max_bytes: int,
    max_regions: int,
) -> tuple[list[dict[str, Any]], int, bool]:
    kernel32 = _kernel32()
    info = _SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(info))
    address = int(info.lpMinimumApplicationAddress or 0)
    maximum = int(info.lpMaximumApplicationAddress or 0)
    regions, remaining, truncated = [], max_bytes, False
    while address <= maximum:
        mbi = _MEMORY_BASIC_INFORMATION()
        queried = kernel32.VirtualQueryEx(process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not queried:
            break
        # Query one additional region before stopping so that ``truncated`` is
        # only set when there is known evidence left out of the artifact.
        if len(regions) >= max_regions:
            truncated = True
            break
        base = int(mbi.BaseAddress or address)
        size = int(mbi.RegionSize)
        if size <= 0:
            break
        module = _module_for_address(base, modules)
        region = {"base_address": _hex(base), "size": size, "state": _STATE_NAMES.get(int(mbi.State), _hex(int(mbi.State))), "protect": _protection_name(int(mbi.Protect)), "type": _TYPE_NAMES.get(int(mbi.Type), _hex(int(mbi.Type))), "allocation_base": _hex(int(mbi.AllocationBase or 0)), "module": module["name"] if module else None}
        in_scope = selected_ranges is None or any(base < end and base + size > start for start, end in selected_ranges)
        if in_scope and _readable_region(mbi):
            if remaining <= 0:
                truncated = True
            else:
                desired_size = min(size, DEFAULT_REGION_SAMPLE_BYTES)
                sample_size = min(desired_size, remaining)
                sample = _read_memory(process, base, sample_size)
                if sample:
                    region["sample"] = {"size": len(sample), "sha256": sha256(sample).hexdigest(), "hex": sample.hex()}
                    remaining -= len(sample)
                    # The requested byte budget, rather than the ordinary
                    # per-region sample size, cut this sample short.
                    if sample_size < desired_size and len(sample) == sample_size:
                        truncated = True
        regions.append(region)
        address = base + size
    return regions, max_bytes - remaining, truncated


def _read_memory(process: int, address: int, size: int) -> bytes:
    kernel32 = _kernel32()
    buffer = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(process, ctypes.c_void_p(address), buffer, size, ctypes.byref(read)):
        return b""
    return buffer.raw[: read.value]


def _readable_region(mbi: _MEMORY_BASIC_INFORMATION) -> bool:
    protection = int(mbi.Protect)
    return int(mbi.State) == MEM_COMMIT and not (protection & PAGE_GUARD) and (protection & 0xFF) in _READABLE_PROTECTIONS


def _filter_modules(modules: list[dict[str, Any]], module_filter: str | None) -> list[dict[str, Any]]:
    if not module_filter:
        return modules
    needle = str(module_filter).lower()
    return [item for item in modules if needle in item["name"].lower() or needle in (item["path"] or "").lower()]


def _module_for_address(address: int, modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    for module in modules:
        if module["base_address_int"] <= address < module["base_address_int"] + module["size"]:
            return module
    return None


def _public_module(module: Mapping[str, Any]) -> dict[str, Any]:
    return {"name": module["name"], "path": module.get("path"), "base_address": module["base_address"], "size": module["size"]}


def _load_snapshot(value: str | Path | Mapping[str, Any]) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        value = value.get("data", value)
        if not isinstance(value, Mapping):
            raise ValueError("snapshot mapping data must be an object")
        return value
    # Offline plans/snapshots are commonly authored with Windows PowerShell,
    # which may prefix JSON with a UTF-8 BOM.  Treat that as regular UTF-8.
    with Path(value).open("r", encoding="utf-8-sig") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, Mapping):
        raise ValueError("snapshot JSON must contain an object")
    return loaded.get("data", loaded) if isinstance(loaded.get("data", loaded), Mapping) else loaded


def _regions(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    values = snapshot.get("regions", [])
    if not isinstance(values, list):
        raise ValueError("snapshot regions must be a list")
    return [dict(item) for item in values if isinstance(item, Mapping)]


def _region_key(region: Mapping[str, Any]) -> str:
    address = _parse_address(region.get("base_address"))
    size = region.get("size")
    if address is None or not isinstance(size, int):
        raise ValueError("each region requires base_address and integer size")
    return _hex(address)


def _changed_fields(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[str]:
    keys = sorted(set(before) | set(after))
    return [key for key in keys if key != "base_address" and before.get(key) != after.get(key)]


def _normalise_module(module: Mapping[str, Any]) -> dict[str, Any]:
    base = _parse_address(module.get("base_address"))
    size = module.get("size")
    if base is None or not isinstance(size, int) or size < 0:
        raise ValueError("each module requires base_address and non-negative integer size")
    return {"name": str(module.get("name") or "unknown"), "path": module.get("path"), "base_address": _hex(base), "base_address_int": base, "size": size}


def _map_address(value: int | str, modules: list[dict[str, Any]], sections: list[dict[str, Any]], pe_path: str | Path) -> dict[str, Any]:
    address = _parse_address(value)
    original = str(value) if address is None else _hex(address)
    if address is None:
        return {"address": original, "module": None, "rva": None, "section": None, "file_offset": None, "error": "invalid address"}
    module = _module_for_address(address, modules)
    if not module:
        return {"address": _hex(address), "module": None, "rva": None, "section": None, "file_offset": None, "error": None}
    rva = address - module["base_address_int"]
    same_image = _same_image_path(module.get("path"), pe_path)
    section = next((item for item in sections if item["virtual_address"] <= rva < item["virtual_address"] + max(item["virtual_size"], item["raw_size"])), None) if same_image else None
    return {"address": _hex(address), "module": _public_module(module), "rva": _hex(rva), "section": section["name"] if section else None, "file_offset": section["raw_offset"] + (rva - section["virtual_address"]) if section and rva < section["virtual_address"] + section["raw_size"] else None, "error": None}


def _same_image_path(module_path: Any, pe_path: str | Path) -> bool:
    """Return whether a loaded module is provably the analyzed image path."""

    if not module_path:
        return False
    try:
        module_resolved = Path(str(module_path)).expanduser().resolve(strict=False)
        pe_resolved = Path(pe_path).expanduser().resolve(strict=False)
    except (OSError, ValueError, TypeError):
        return False
    # Loaded Windows image paths are case-insensitive.  Resolving first also
    # makes equivalent relative paths and symlinks compare as the same image.
    if str(module_resolved).casefold() == str(pe_resolved).casefold():
        return True
    try:
        return os.path.samefile(module_resolved, pe_resolved)
    except OSError:
        return False


def _pe_sections(path: str | Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        import pefile  # type: ignore[import-not-found]
        pe = pefile.PE(str(path), fast_load=True)
        sections = []
        for item in pe.sections:
            sections.append({"name": item.Name.rstrip(b"\\x00").decode("utf-8", "replace"), "virtual_address": int(item.VirtualAddress), "virtual_size": int(item.Misc_VirtualSize), "raw_offset": int(item.PointerToRawData), "raw_size": int(item.SizeOfRawData)})
        return sorted(sections, key=lambda item: item["virtual_address"]), None
    except Exception as exc:  # noqa: BLE001
        return [], f"PE section mapping unavailable: {exc}"


def _write_artifact(
    out_dir: str | Path,
    name: str,
    payload: Mapping[str, Any],
    kind: str,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Write an analyst-requested JSON evidence artifact and index it in data.

    This is the only filesystem write performed by these tools.  It writes to
    the caller-provided evidence directory; inspection of the target process
    itself remains strictly read-only.
    """

    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    artifact = directory / name
    artifacts = [_artifact(artifact, kind)]
    data = {**payload, "artifacts": artifacts}
    artifact.write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return data, artifacts


def _artifact_name(value: str | None, default: str) -> str:
    """Return a safe single-file artifact name, preserving legacy defaults."""

    if value is None:
        return default
    if not isinstance(value, str) or not value or Path(value).name != value:
        raise ValueError("artifact_name must be a non-empty filename")
    return value


def _artifact(path: Path, kind: str) -> dict[str, str]:
    return {"name": path.name, "path": str(path), "kind": kind}


def _unavailable(tool: str, error: str, data: Mapping[str, Any] | None = None) -> ToolResult:
    return ToolResult(tool, "unavailable", data=dict(data or {}), error=error)


def _failed(tool: str, error: str) -> ToolResult:
    return ToolResult(tool, "failed", data={}, error=error)


def _parse_address(value: Any) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str):
        try:
            parsed = int(value.strip(), 0)
            return parsed if parsed >= 0 else None
        except ValueError:
            return None
    return None


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _protection_name(value: int) -> str:
    base = value & 0xFF
    name = _PROTECTION_NAMES.get(base, _hex(base))
    return f"{name}|PAGE_GUARD" if value & PAGE_GUARD else name
