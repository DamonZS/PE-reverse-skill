"""Read-only DMA and physical-memory evidence provider.

The provider deliberately exposes no mutation primitive.  It can acquire
bounded evidence through the LeechCore Python API, a mounted MemProcFS VFS,
or an explicitly supplied offline physical-memory image adapter.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import re
import struct
import threading
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Optional, Protocol, Sequence

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)


_SCHEMA_VERSION = 1
_DEFAULT_MAX_READ_BYTES = 16 * 1024 * 1024
_MAX_SEGMENTS = 256
_MAX_METADATA_BYTES = 1024 * 1024
_PAGE_SIZE = 0x1000
_PHYSICAL_ADDRESS_MASK = 0x000F_FFFF_FFFF_F000
_MAX_U64 = (1 << 64) - 1
_SUPPORTED_ACTIONS = frozenset({"probe", "modules", "translate", "read", "snapshot"})
_ACTION_ALIASES = {
    "initialize": "probe",
    "resolve_target": "probe",
    "list_modules": "modules",
    "address_translate": "translate",
    "read_memory": "read",
}
_COMMON_PARAM_KEYS = {
    "pid",
    "dtb",
    "cr3",
    "allowlist",
    "allowed_ranges",
    "address_allowlist",
    "expected_name",
    "expected_image",
    "process_name",
    "image_name",
    "max_bytes",
    "device",
    "include_modules",
    "architecture",
}
_ACTION_PARAM_KEYS = {
    "probe": set(),
    "modules": set(),
    "translate": {"address"},
    "read": {"address", "size", "address_space", "artifact_name"},
    "snapshot": {"ranges", "artifact_name"},
}
_SEGMENT_KEYS = {"address", "size", "address_space", "label"}
_SAFE_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_HARDWARE_DEVICE_SCHEMES = frozenset({"fpga", "usb3380"})


class DMAMemoryError(RuntimeError):
    """Base error for a bounded read-only acquisition failure."""


class AddressTranslationError(DMAMemoryError):
    """Raised when an x86-64 page-table walk cannot resolve an address."""

    def __init__(self, message: str, *, walk: Optional[list[dict[str, Any]]] = None) -> None:
        super().__init__(message)
        self.walk = list(walk or [])


class DMAMemoryAdapter(Protocol):
    """Minimal read-only adapter surface consumed by :class:`DMAMemoryProvider`."""

    name: str
    dependency_available: bool
    unavailable_reason: Optional[str]
    hardware_backed: bool

    def open(self) -> None: ...

    def close(self) -> None: ...

    def resolve_target(
        self,
        pid: int,
        *,
        dtb: Optional[int] = None,
        expected_name: Optional[str] = None,
        expected_image: Optional[str] = None,
    ) -> Mapping[str, Any]: ...

    def read_physical(self, address: int, size: int) -> bytes: ...

    def list_modules(self, pid: int) -> Sequence[Mapping[str, Any]]: ...

    def describe(self) -> Mapping[str, Any]: ...


class UnavailableDMAMemoryAdapter:
    """Dependency gate used when no production read backend is usable."""

    name = "unavailable"
    dependency_available = False
    hardware_backed = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = str(reason)

    def open(self) -> None:
        raise DMAMemoryError(self.unavailable_reason)

    def close(self) -> None:
        return None

    def resolve_target(
        self,
        pid: int,
        *,
        dtb: Optional[int] = None,
        expected_name: Optional[str] = None,
        expected_image: Optional[str] = None,
    ) -> Mapping[str, Any]:
        del pid, dtb, expected_name, expected_image
        raise DMAMemoryError(self.unavailable_reason)

    def read_physical(self, address: int, size: int) -> bytes:
        del address, size
        raise DMAMemoryError(self.unavailable_reason)

    def list_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        del pid
        raise DMAMemoryError(self.unavailable_reason)

    def describe(self) -> Mapping[str, Any]:
        return {
            "adapter": self.name,
            "source_type": "unavailable",
            "dependency_available": False,
            "read_only": True,
            "hardware_backed": False,
            "hardware_acquisition_completed": False,
            "reason": self.unavailable_reason,
        }


class OfflinePhysicalMemoryAdapter:
    """Read a physical-memory image from an allowlisted offline path."""

    name = "offline_physical_image"
    hardware_backed = False

    def __init__(
        self,
        image_path: str | Path,
        *,
        targets: Optional[Mapping[int, Mapping[str, Any]]] = None,
        modules: Optional[Mapping[int, Sequence[Mapping[str, Any]]]] = None,
        allowed_root: Optional[str | Path] = None,
    ) -> None:
        self.image_path = Path(image_path).expanduser().resolve()
        self.allowed_root = (
            Path(allowed_root).expanduser().resolve()
            if allowed_root is not None
            else self.image_path.parent
        )
        _require_within(self.image_path, self.allowed_root, "offline image")
        self.targets = {
            int(pid): _json_mapping(value) for pid, value in (targets or {}).items()
        }
        self.modules = {
            int(pid): [_json_mapping(item) for item in values]
            for pid, values in (modules or {}).items()
        }
        self.dependency_available = self.image_path.is_file()
        self.unavailable_reason = (
            None if self.dependency_available else f"offline image does not exist: {self.image_path}"
        )
        self._stream: Any = None
        self.open_count = 0
        self.close_count = 0
        self._bytes_read = 0

    def open(self) -> None:
        if not self.dependency_available:
            raise DMAMemoryError(str(self.unavailable_reason))
        if self._stream is None:
            self._stream = self.image_path.open("rb")
            self.open_count += 1

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._stream = None
            self.close_count += 1

    def resolve_target(
        self,
        pid: int,
        *,
        dtb: Optional[int] = None,
        expected_name: Optional[str] = None,
        expected_image: Optional[str] = None,
    ) -> Mapping[str, Any]:
        record = dict(self.targets.get(pid) or {})
        if not record:
            raise DMAMemoryError(f"offline image has no target metadata for PID {pid}")
        resolved_pid = _coerce_int(record.get("pid"))
        if resolved_pid != pid:
            raise DMAMemoryError("offline target PID does not match the requested identity")
        resolved_dtb = _normalize_dtb(record.get("dtb"))
        requested_dtb = _normalize_dtb(dtb)
        if requested_dtb is not None and resolved_dtb != requested_dtb:
            raise DMAMemoryError("offline target DTB does not match the requested CR3")
        _verify_expected_identity(record, expected_name, expected_image)
        return _prune(
            {
                **record,
                "pid": pid,
                "dtb": resolved_dtb,
                "identity_verified": record.get("identity_verified") is True,
                "identity_source": "offline_fixture_metadata",
            }
        )

    def read_physical(self, address: int, size: int) -> bytes:
        _validate_physical_range(address, size)
        if self._stream is None:
            raise DMAMemoryError("offline image session is not open")
        self._stream.seek(address)
        data = self._stream.read(size)
        if len(data) != size:
            raise DMAMemoryError(
                f"offline image short read at 0x{address:x}: requested {size}, received {len(data)}"
            )
        self._bytes_read += len(data)
        return data

    def list_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        return [dict(item) for item in self.modules.get(pid, [])]

    def describe(self) -> Mapping[str, Any]:
        return {
            "adapter": self.name,
            "source_type": "offline_image",
            "source_path": str(self.image_path),
            "dependency_available": self.dependency_available,
            "read_only": True,
            "hardware_backed": False,
            "hardware_acquisition_completed": False,
            "bytes_read": self._bytes_read,
        }


class LeechCorePythonAdapter:
    """Narrow read-only boundary around the LeechCore Python API."""

    name = "leechcore_python"

    def __init__(
        self,
        *,
        device: str = "fpga",
        module: Any = None,
        test_double: Optional[bool] = None,
    ) -> None:
        device_text = str(device or "").strip()
        if not device_text or "\x00" in device_text or len(device_text) > 512:
            raise ValueError("LeechCore device must be a bounded non-empty string")
        self.device = device_text
        self._module = module
        self._module_injected = module is not None
        self._module_name: Optional[str] = None
        # An injected module is always a test boundary; it cannot self-attest as
        # the installed production dependency by setting test_double=False.
        self.test_double = bool(self._module_injected or test_double is True)
        self.dependency_available = module is not None or any(
            importlib.util.find_spec(name) is not None for name in ("leechcorepyc", "leechcore")
        )
        self.unavailable_reason = (
            None
            if self.dependency_available
            else "LeechCore Python dependency is not installed (leechcorepyc/leechcore)"
        )
        self.hardware_backed = bool(
            not self.test_double
            and _leechcore_device_scheme(self.device) in _HARDWARE_DEVICE_SCHEMES
        )
        self._handle: Any = None
        self._successful_reads = 0
        self._bytes_read = 0

    def open(self) -> None:
        if not self.dependency_available:
            raise DMAMemoryError(str(self.unavailable_reason))
        if self._handle is not None:
            return
        module = self._module
        if module is None:
            failures: list[str] = []
            for name in ("leechcorepyc", "leechcore"):
                try:
                    module = importlib.import_module(name)
                    self._module_name = name
                    break
                except ImportError as exc:
                    failures.append(f"{name}: {exc}")
            if module is None:
                raise DMAMemoryError("; ".join(failures) or "LeechCore import failed")
        factory = getattr(module, "LeechCore", None) or getattr(module, "create", None)
        if not callable(factory):
            raise DMAMemoryError("LeechCore dependency does not expose LeechCore/create")
        try:
            self._handle = factory(self.device)
        except TypeError:
            self._handle = factory(device=self.device)
        if self._handle is None:
            raise DMAMemoryError("LeechCore returned an empty device handle")

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        close = getattr(handle, "close", None)
        if callable(close):
            close()

    def read_physical(self, address: int, size: int) -> bytes:
        _validate_physical_range(address, size)
        if self._handle is None:
            raise DMAMemoryError("LeechCore session is not open")
        method = _first_callable(self._handle, ("read", "read_physical", "mem_read"))
        if method is None:
            raise DMAMemoryError("LeechCore handle does not expose a physical read method")
        data = _extract_bytes(method(address, size))
        if data is None or len(data) != size:
            received = len(data) if data is not None else 0
            raise DMAMemoryError(
                f"LeechCore short read at 0x{address:x}: requested {size}, received {received}"
            )
        self._successful_reads += 1
        self._bytes_read += len(data)
        return data

    def resolve_target(
        self,
        pid: int,
        *,
        dtb: Optional[int] = None,
        expected_name: Optional[str] = None,
        expected_image: Optional[str] = None,
    ) -> Mapping[str, Any]:
        if self._handle is None:
            raise DMAMemoryError("LeechCore session is not open")
        requested_dtb = _normalize_dtb(dtb)
        record: dict[str, Any] = {}
        resolver = _first_callable(self._handle, ("resolve_process", "get_process"))
        if resolver is not None:
            value = resolver(pid)
            if isinstance(value, Mapping):
                record = _json_mapping(value)
        observed_pid = _coerce_int(record.get("pid")) if record else None
        resolved_pid = observed_pid if observed_pid is not None else pid
        if resolved_pid != pid:
            raise DMAMemoryError("LeechCore target PID does not match the request")
        observed_dtb = (
            _normalize_dtb(record.get("dtb", record.get("cr3"))) if record else None
        )
        resolved_dtb = observed_dtb if observed_dtb is not None else requested_dtb
        if requested_dtb is not None and resolved_dtb != requested_dtb:
            raise DMAMemoryError("LeechCore target DTB does not match the requested CR3")
        if resolved_dtb is None:
            raise DMAMemoryError("LeechCore physical reads require an explicit target DTB/CR3")
        if record:
            _verify_expected_identity(record, expected_name, expected_image)
        independently_verified = bool(
            record
            and observed_pid == pid
            and observed_dtb is not None
            and observed_dtb == resolved_dtb
        )
        return _prune(
            {
                **record,
                "pid": pid,
                "dtb": resolved_dtb,
                "name": record.get("name") or expected_name,
                "image_path": record.get("image_path") or expected_image,
                "identity_verified": independently_verified,
                "identity_source": (
                    "leechcore_process_api" if independently_verified else "request_pid_dtb_binding"
                ),
            }
        )

    def list_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        if self._handle is None:
            raise DMAMemoryError("LeechCore session is not open")
        method = _first_callable(self._handle, ("list_modules", "modules"))
        if method is None:
            return []
        value = method(pid)
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
            raise DMAMemoryError("LeechCore module API returned an invalid value")
        return [_json_mapping(item) for item in value if isinstance(item, Mapping)]

    def describe(self) -> Mapping[str, Any]:
        completed = bool(self.hardware_backed and self._successful_reads)
        return {
            "adapter": self.name,
            "source_type": "leechcore_device",
            "device": self.device,
            "device_scheme": _leechcore_device_scheme(self.device),
            "module": self._module_name,
            "module_injected": self._module_injected,
            "dependency_available": self.dependency_available,
            "read_only": True,
            "test_double": self.test_double,
            "hardware_backed": self.hardware_backed,
            "hardware_acquisition_completed": completed,
            "successful_reads": self._successful_reads,
            "bytes_read": self._bytes_read,
        }


class MemProcFSVFSAdapter:
    """Read process, module, and memory files below a mounted MemProcFS root."""

    name = "memprocfs_vfs"
    hardware_backed = False

    _PHYSICAL_FILES = (
        "sys/memory/physmem.raw",
        "memory/physmem.raw",
        "physmem.raw",
        "memory.pmem",
    )

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.dependency_available = self.root.is_dir()
        self.unavailable_reason = (
            None if self.dependency_available else f"MemProcFS mount does not exist: {self.root}"
        )
        self._opened = False
        self._physical_path: Optional[Path] = None
        self._physical_stream: Any = None
        self._bytes_read = 0

    def open(self) -> None:
        if not self.dependency_available:
            raise DMAMemoryError(str(self.unavailable_reason))
        self._opened = True
        physical = self._first_file(self._PHYSICAL_FILES)
        if physical is not None:
            self._physical_path = physical
            self._physical_stream = physical.open("rb")

    def close(self) -> None:
        if self._physical_stream is not None:
            self._physical_stream.close()
        self._physical_stream = None
        self._physical_path = None
        self._opened = False

    def resolve_target(
        self,
        pid: int,
        *,
        dtb: Optional[int] = None,
        expected_name: Optional[str] = None,
        expected_image: Optional[str] = None,
    ) -> Mapping[str, Any]:
        self._require_open()
        process_dir = self._process_dir(pid)
        dtb_path = self._first_file(
            (
                f"pid/{pid}/win-dtb.txt",
                f"pid/{pid}/dtb.txt",
                f"pid/{pid}/map/dtb.txt",
                f"proc/{pid}/win-dtb.txt",
                f"proc/{pid}/dtb.txt",
            )
        )
        observed_dtb = _parse_dtb_text(self._read_text(dtb_path)) if dtb_path else None
        requested_dtb = _normalize_dtb(dtb)
        if requested_dtb is not None and observed_dtb is not None and requested_dtb != observed_dtb:
            raise DMAMemoryError("MemProcFS target DTB does not match the requested CR3")
        resolved_dtb = observed_dtb if observed_dtb is not None else requested_dtb

        name_path = self._first_file(
            (
                f"pid/{pid}/name.txt",
                f"pid/{pid}/win-name.txt",
                f"proc/{pid}/name.txt",
            )
        )
        name = self._read_text(name_path).strip().splitlines()[0] if name_path else None
        process_path = self._first_file(
            (
                f"pid/{pid}/win-process.txt",
                f"pid/{pid}/process.txt",
                f"proc/{pid}/process.txt",
            )
        )
        process_text = self._read_text(process_path) if process_path else ""
        image_path = _parse_process_image(process_text)
        record = {
            "pid": pid,
            "dtb": resolved_dtb,
            "name": name,
            "image_path": image_path,
        }
        _verify_expected_identity(record, expected_name, expected_image)
        identity_verified = bool(
            process_dir is not None
            and observed_dtb is not None
            and (expected_name is None or _identity_name_matches(name, expected_name))
            and (expected_image is None or _identity_image_matches(image_path, expected_image))
        )
        return _prune(
            {
                **record,
                "identity_verified": identity_verified,
                "identity_source": "memprocfs_vfs",
                "process_path": str(process_dir),
                "dtb_source_path": str(dtb_path) if dtb_path else None,
                "name_source_path": str(name_path) if name_path else None,
            }
        )

    def read_physical(self, address: int, size: int) -> bytes:
        _validate_physical_range(address, size)
        self._require_open()
        if self._physical_stream is None:
            raise DMAMemoryError("MemProcFS mount does not expose a read-only physical-memory file")
        self._physical_stream.seek(address)
        data = self._physical_stream.read(size)
        if len(data) != size:
            raise DMAMemoryError(
                f"MemProcFS physical-memory short read at 0x{address:x}: "
                f"requested {size}, received {len(data)}"
            )
        self._bytes_read += len(data)
        return data

    def read_virtual(self, pid: int, address: int, size: int) -> bytes:
        _validate_u64_range(address, size, "virtual memory")
        self._require_open()
        path = self._first_file(
            (
                f"pid/{pid}/mem/mem-v.dmp",
                f"pid/{pid}/mem.dmp",
                f"pid/{pid}/memory.vmem",
                f"proc/{pid}/mem/mem-v.dmp",
            )
        )
        if path is None:
            raise DMAMemoryError("MemProcFS mount does not expose a process memory file")
        with path.open("rb") as stream:
            stream.seek(address)
            data = stream.read(size)
        if len(data) != size:
            raise DMAMemoryError(
                f"MemProcFS process-memory short read at 0x{address:x}: "
                f"requested {size}, received {len(data)}"
            )
        self._bytes_read += len(data)
        return data

    def list_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        self._require_open()
        path = self._first_file(
            (
                f"pid/{pid}/map/module.txt",
                f"pid/{pid}/map/modules.txt",
                f"pid/{pid}/modules.txt",
                f"proc/{pid}/map/module.txt",
            )
        )
        if path is None:
            return []
        text = self._read_text(path)
        modules = _parse_module_text(text)
        for module in modules:
            module["source_path"] = str(path)
        return modules

    def describe(self) -> Mapping[str, Any]:
        return {
            "adapter": self.name,
            "source_type": "mounted_vfs",
            "mount_root": str(self.root),
            "physical_memory_path": str(self._physical_path) if self._physical_path else None,
            "dependency_available": self.dependency_available,
            "read_only": True,
            "hardware_backed": False,
            "hardware_acquisition_completed": False,
            "bytes_read": self._bytes_read,
        }

    def _require_open(self) -> None:
        if not self._opened:
            raise DMAMemoryError("MemProcFS VFS session is not open")

    def _process_dir(self, pid: int) -> Optional[Path]:
        for relative in (f"pid/{pid}", f"proc/{pid}"):
            candidate = self._safe_path(relative)
            if candidate.is_dir():
                return candidate
        raise DMAMemoryError(f"MemProcFS mount has no process directory for PID {pid}")

    def _first_file(self, relatives: Sequence[str]) -> Optional[Path]:
        for relative in relatives:
            candidate = self._safe_path(relative)
            if candidate.is_file():
                return candidate
        return None

    def _safe_path(self, relative: str) -> Path:
        windows = PureWindowsPath(relative)
        posix = PurePosixPath(relative)
        if (
            windows.is_absolute()
            or bool(windows.drive)
            or posix.is_absolute()
            or ".." in windows.parts
            or ".." in posix.parts
        ):
            raise DMAMemoryError("MemProcFS path must remain relative to the mount root")
        candidate = (self.root / Path(relative)).resolve()
        _require_within(candidate, self.root, "MemProcFS path")
        return candidate

    def _read_text(self, path: Path) -> str:
        size = path.stat().st_size
        if size > _MAX_METADATA_BYTES:
            raise DMAMemoryError(f"MemProcFS metadata file exceeds {_MAX_METADATA_BYTES} bytes: {path}")
        return path.read_text(encoding="utf-8", errors="replace")


class _ReadBudget:
    def __init__(self, adapter: Any, payload_limit: int, segment_count: int) -> None:
        self.adapter = adapter
        self.payload_limit = payload_limit
        pages = max(1, (payload_limit + _PAGE_SIZE - 1) // _PAGE_SIZE)
        self.device_limit = payload_limit + 32 * (pages + max(1, segment_count))
        self.device_bytes = 0
        self.payload_bytes = 0

    def read_physical(self, address: int, size: int, *, payload: bool) -> bytes:
        _validate_physical_range(address, size)
        if self.device_bytes + size > self.device_limit:
            raise DMAMemoryError("physical read budget exceeded")
        if payload and self.payload_bytes + size > self.payload_limit:
            raise DMAMemoryError("payload read budget exceeded")
        data = _adapter_read_physical(self.adapter, address, size)
        if len(data) != size:
            raise DMAMemoryError("adapter returned a short physical read")
        self.device_bytes += size
        if payload:
            self.payload_bytes += size
        return data


def translate_x64_virtual_address(
    adapter: Any,
    dtb: int,
    virtual_address: int,
    *,
    budget: Optional[_ReadBudget] = None,
) -> dict[str, Any]:
    """Translate one canonical x86-64 virtual address with page-walk evidence."""

    if not _is_canonical_x64(virtual_address):
        raise AddressTranslationError(f"virtual address is not canonical: 0x{virtual_address:x}")
    dtb_base = _normalize_dtb(dtb)
    if dtb_base is None:
        raise AddressTranslationError("DTB/CR3 must resolve to a non-zero page-aligned address")
    read_budget = budget or _ReadBudget(adapter, 64, 1)
    levels = (
        ("pml4", (virtual_address >> 39) & 0x1FF),
        ("pdpt", (virtual_address >> 30) & 0x1FF),
        ("pd", (virtual_address >> 21) & 0x1FF),
        ("pt", (virtual_address >> 12) & 0x1FF),
    )
    table = dtb_base
    walk: list[dict[str, Any]] = []
    for level, index in levels:
        entry_address = table + index * 8
        raw = read_budget.read_physical(entry_address, 8, payload=False)
        entry = struct.unpack("<Q", raw)[0]
        present = bool(entry & 1)
        large = bool(entry & (1 << 7)) and level in {"pdpt", "pd"}
        evidence = {
            "level": level,
            "index": index,
            "table_physical_address": table,
            "entry_physical_address": entry_address,
            "entry": entry,
            "entry_hex": f"0x{entry:016x}",
            "present": present,
            "writable": bool(entry & (1 << 1)),
            "user": bool(entry & (1 << 2)),
            "large_page": large,
            "no_execute": bool(entry & (1 << 63)),
        }
        walk.append(evidence)
        if not present:
            raise AddressTranslationError(
                f"{level} entry is not present for virtual address 0x{virtual_address:x}",
                walk=walk,
            )
        if level == "pdpt" and large:
            page_size = 1 << 30
            base = entry & 0x000F_FFFF_C000_0000
            physical = base + (virtual_address & (page_size - 1))
            evidence["resolved_page_base"] = base
            return _translation_payload(virtual_address, physical, page_size, dtb_base, walk)
        if level == "pd" and large:
            page_size = 1 << 21
            base = entry & 0x000F_FFFF_FFE0_0000
            physical = base + (virtual_address & (page_size - 1))
            evidence["resolved_page_base"] = base
            return _translation_payload(virtual_address, physical, page_size, dtb_base, walk)
        table = entry & _PHYSICAL_ADDRESS_MASK
        evidence["next_table_physical_address"] = table
        if not table:
            raise AddressTranslationError(f"{level} entry resolves to a zero table", walk=walk)
    physical = table + (virtual_address & (_PAGE_SIZE - 1))
    walk[-1]["resolved_page_base"] = table
    return _translation_payload(virtual_address, physical, _PAGE_SIZE, dtb_base, walk)


class DMAMemoryProvider:
    """Plan and collect bounded, read-only DMA/physical-memory evidence."""

    capability_name = "dma_memory"
    provider_name = "dma_memory_readonly"
    priority = 30

    def __init__(
        self,
        adapter: Optional[DMAMemoryAdapter] = None,
        *,
        device: str = "fpga",
        memprocfs_root: Optional[str | Path] = None,
        leechcore_module: Any = None,
        max_read_bytes: int = _DEFAULT_MAX_READ_BYTES,
        allowlist: Any = None,
        allowed_output_roots: Optional[Sequence[str | Path]] = None,
    ) -> None:
        self.device = str(device)
        self.max_read_bytes = max(1, int(max_read_bytes))
        configured, errors = _parse_allowlist(allowlist)
        if errors:
            raise ValueError("invalid provider allowlist: " + "; ".join(errors))
        self._configured_allowlist = configured
        self._allowed_output_roots = [
            Path(item).expanduser().resolve() for item in (allowed_output_roots or [])
        ]
        if adapter is not None:
            self._candidates: list[Any] = [adapter]
        else:
            self._candidates = [
                LeechCorePythonAdapter(device=self.device, module=leechcore_module)
            ]
            if memprocfs_root is not None:
                self._candidates.append(MemProcFSVFSAdapter(memprocfs_root))
        if not self._candidates:
            self._candidates = [UnavailableDMAMemoryAdapter("no DMA memory adapter configured")]
        self._sessions: dict[str, dict[str, Any]] = {}
        self._session_lock = threading.RLock()

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) in _SUPPORTED_ACTIONS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        action = _normalize_action(request.action)
        session_id = str(request.session_id or "dma-memory-session")
        parameters, parameter_errors = self._normalize_parameters(request, action)
        parameters["parameter_errors"] = parameter_errors
        target_payload = _target_payload(request.target)
        target_hash = _canonical_hash(target_payload)
        parameters["target_identity_sha256"] = target_hash
        precondition_payload = {
            "capability": request.capability,
            "provider": self.provider_name,
            "session_id": session_id,
            "action": action,
            "target_identity_sha256": target_hash,
            "parameters": {
                key: value for key, value in parameters.items() if key != "parameter_errors"
            },
        }
        precondition_hash = _canonical_hash(precondition_payload)
        backend_preflight = self._backend_preflight()
        before_snapshot = {
            "schema_version": _SCHEMA_VERSION,
            "capture_phase": "plan",
            "read_only": True,
            "side_effects": False,
            "target": target_payload,
            "target_identity_sha256": target_hash,
            "authorized_ranges": list(parameters.get("allowlist") or []),
            "backend_preflight": backend_preflight,
            "precondition_hash": precondition_hash,
        }
        rollback_plan = {
            "mode": "cleanup_session_resources",
            "supported": True,
            "mutations": False,
            "delete_collected_evidence": False,
            "resources": ["adapter_session", "in_memory_evidence_buffers"],
        }
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=parameters,
            steps=_plan_steps(action),
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "schema_version": _SCHEMA_VERSION,
                "provider": self.provider_name,
                "requested_action": request.action,
                "action": action,
                "read_only": True,
                "target_identity_sha256": target_hash,
                "precondition_hash": precondition_hash,
                "backend_priority": [str(item.get("adapter")) for item in backend_preflight],
                "hardware_acquisition_completed": False,
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        del context
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []

        def check(name: str, ok: bool, message: str, **details: Any) -> None:
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": "ok" if ok else "failed",
                        "message": message,
                        **details,
                    }
                )
            )
            if not ok:
                errors.append(message)

        identity_ok = plan.capability == self.capability_name and plan.provider == self.provider_name
        check(
            "provider_identity",
            identity_ok,
            "plan capability/provider identity does not match dma_memory provider",
        )
        action = _normalize_action(plan.action)
        check(
            "action_allowlist",
            action in _SUPPORTED_ACTIONS,
            f"unsupported dma_memory action: {plan.action}",
            allowed_actions=sorted(_SUPPORTED_ACTIONS),
        )
        parameter_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        check(
            "parameters",
            not parameter_errors,
            "; ".join(parameter_errors) if parameter_errors else "parameters are normalized",
        )
        target_payload = _target_payload(plan.target)
        actual_target_hash = _canonical_hash(target_payload)
        expected_target_hash = str(plan.parameters.get("target_identity_sha256") or "")
        check(
            "target_identity",
            bool(expected_target_hash and actual_target_hash == expected_target_hash),
            "target identity changed after planning",
            expected=expected_target_hash,
            actual=actual_target_hash,
        )
        pid = _coerce_int(plan.parameters.get("pid"))
        target_pid = _coerce_int(target_payload.get("pid"))
        check(
            "target_pid",
            bool(pid and pid > 0 and pid == target_pid),
            "target PID must be positive and match the planned target identity",
            pid=pid,
            target_pid=target_pid,
        )
        if action in {"translate", "read", "snapshot"}:
            segments = plan.parameters.get("segments") or []
            allowlist = plan.parameters.get("allowlist") or []
            allowlist_ok = bool(allowlist) and all(
                _range_allowed(
                    str(segment.get("address_space") or "virtual"),
                    _coerce_int(segment.get("address")),
                    _coerce_int(segment.get("size")),
                    allowlist,
                )
                for segment in segments
            )
            check(
                "address_allowlist",
                allowlist_ok,
                "every requested range must be fully contained in an explicit address allowlist",
                authorized_ranges=allowlist,
            )
            total = sum(int(_coerce_int(item.get("size")) or 0) for item in segments)
            effective_max = int(_coerce_int(plan.parameters.get("max_bytes")) or self.max_read_bytes)
            check(
                "max_bytes",
                bool(0 < total <= effective_max <= self.max_read_bytes),
                "requested bytes exceed the provider or request maximum",
                requested_bytes=total,
                request_max=effective_max,
                provider_max=self.max_read_bytes,
            )
        expected_precondition = _canonical_hash(
            {
                "capability": plan.capability,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "action": action,
                "target_identity_sha256": expected_target_hash,
                "parameters": {
                    key: value
                    for key, value in plan.parameters.items()
                    if key not in {"parameter_errors"}
                },
            }
        )
        check(
            "precondition_hash",
            bool(plan.precondition_hash and plan.precondition_hash == expected_precondition),
            "plan precondition hash does not match the authorized request",
        )
        backend_preflight = self._backend_preflight()
        available = [item for item in backend_preflight if item.get("dependency_available")]
        if available:
            checks.append(
                {
                    "name": "dependency",
                    "status": "ok",
                    "message": "a read-only DMA memory dependency is available",
                    "candidates": available,
                }
            )
        else:
            reasons = [
                str(item.get("reason") or f"{item.get('adapter')} unavailable")
                for item in backend_preflight
            ]
            message = "; ".join(reasons) or "no read-only DMA memory dependency is available"
            checks.append(
                {
                    "name": "dependency",
                    "status": _dependency_gate_status(backend_preflight),
                    "message": message,
                }
            )
            errors.append(message)
        return CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            warnings=_deduplicate(warnings),
            errors=_deduplicate(errors),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        del context
        validation = self.validate(plan)
        backend_preflight = self._backend_preflight()
        dependency_available = any(
            item.get("dependency_available") for item in backend_preflight
        )
        if not dependency_available:
            return self._result(
                plan,
                status=_dependency_gate_status(backend_preflight),
                validation=validation,
                after={"status": "unavailable", "side_effects": False},
                errors=list(validation.errors),
                adapter_description=(backend_preflight[0] if backend_preflight else None),
            )
        if not validation.ok:
            return self._result(
                plan,
                status="failed",
                validation=validation,
                after={"status": "blocked", "side_effects": False},
                errors=list(validation.errors),
            )
        with self._session_lock:
            if plan.session_id in self._sessions:
                return self._result(
                    plan,
                    status="failed",
                    validation=validation,
                    after={"status": "blocked", "side_effects": False},
                    errors=["session ID already has active DMA resources"],
                )
        adapter, attempts = self._open_adapter()
        if adapter is None:
            errors = [str(item.get("error")) for item in attempts if item.get("error")]
            return self._result(
                plan,
                status=_dependency_gate_status(attempts),
                validation=validation,
                after={
                    "status": "unavailable",
                    "adapter_attempts": attempts,
                    "side_effects": False,
                },
                errors=errors or ["all read-only DMA adapters failed to initialize"],
                adapter_description=(attempts[-1] if attempts else None),
            )

        session: dict[str, Any] = {"adapter": adapter, "buffers": {}, "collected": False}
        with self._session_lock:
            self._sessions[plan.session_id] = session
        action = _normalize_action(plan.action)
        pid = int(_coerce_int(plan.parameters.get("pid")) or 0)
        dtb = _normalize_dtb(plan.parameters.get("dtb"))
        expected_name = _optional_text(plan.parameters.get("expected_name"))
        expected_image = _optional_text(plan.parameters.get("expected_image"))
        artifacts: list[CapabilityArtifact] = []
        segments_evidence: list[dict[str, Any]] = []
        translations: list[dict[str, Any]] = []
        modules: list[dict[str, Any]] = []
        errors: list[str] = []
        status = "ok"
        target_info: dict[str, Any] = {}
        effective_max = int(_coerce_int(plan.parameters.get("max_bytes")) or self.max_read_bytes)
        budget = _ReadBudget(adapter, effective_max, len(plan.parameters.get("segments") or []))
        try:
            target_info = _json_mapping(
                _adapter_resolve_target(
                    adapter,
                    pid,
                    dtb=dtb,
                    expected_name=expected_name,
                    expected_image=expected_image,
                )
            )
            resolved_pid = _coerce_int(target_info.get("pid"))
            if resolved_pid != pid:
                raise DMAMemoryError("resolved PID does not match the planned target")
            if target_info.get("identity_verified") is not True:
                raise DMAMemoryError(
                    "adapter did not independently verify the target PID/DTB identity"
                )
            resolved_dtb = _normalize_dtb(target_info.get("dtb"))
            if dtb is not None and resolved_dtb != dtb:
                raise DMAMemoryError("resolved DTB does not match the planned target")
            dtb = resolved_dtb
            if action == "modules" or bool(plan.parameters.get("include_modules")):
                modules = [
                    _json_mapping(item) for item in _adapter_list_modules(adapter, pid)
                ]
            if action in {"translate", "read", "snapshot"}:
                for index, segment in enumerate(plan.parameters.get("segments") or []):
                    data, segment_evidence = self._read_segment(
                        adapter,
                        budget,
                        segment,
                        dtb=dtb,
                    )
                    segment_evidence["index"] = index
                    segments_evidence.append(segment_evidence)
                    translations.extend(segment_evidence.get("translations") or [])
                    if action in {"read", "snapshot"}:
                        artifact_path = _segment_artifact_path(
                            plan.session_id,
                            plan.parameters.get("artifact_name"),
                            index,
                            len(plan.parameters.get("segments") or []),
                        )
                        session["buffers"][artifact_path] = bytearray(data)
                        artifacts.append(
                            CapabilityArtifact(
                                path=artifact_path,
                                kind="memory-snapshot",
                                description=str(segment.get("label") or "bounded memory snapshot"),
                                metadata={
                                    "buffer_key": artifact_path,
                                    "address_space": segment_evidence["address_space"],
                                    "address": segment_evidence["address"],
                                    "size": len(data),
                                    "sha256": segment_evidence["sha256"],
                                    "read_only": True,
                                },
                            )
                        )
        except Exception as exc:
            status = "failed"
            errors.append(str(exc))
            if isinstance(exc, AddressTranslationError) and exc.walk:
                translations.append({"status": "failed", "walk": exc.walk, "error": str(exc)})

        adapter_description = _adapter_describe(adapter)
        artifacts.extend(_base_evidence_artifacts(plan.session_id))
        after = {
            "schema_version": _SCHEMA_VERSION,
            "capture_phase": "after",
            "status": status,
            "read_only": True,
            "side_effects": False,
            "target": target_info,
            "segments": segments_evidence,
            "translations": translations,
            "modules": modules,
            "module_manifest_sha256": _canonical_hash(modules) if modules else None,
            "payload_bytes": budget.payload_bytes,
            "device_bytes": budget.device_bytes,
            "device_read_limit": budget.device_limit,
            "adapter": adapter_description,
            "adapter_attempts": attempts,
        }
        result = self._result(
            plan,
            status=status,
            validation=validation,
            after=after,
            errors=errors,
            artifacts=artifacts,
            adapter_description=adapter_description,
        )
        return result

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        with self._session_lock:
            session = self._sessions.pop(result.session_id, None)
        close_errors: list[str] = []
        buffers_zeroed = False
        resources_released: list[str] = []
        if session is not None:
            for buffer in session.get("buffers", {}).values():
                if isinstance(buffer, bytearray):
                    buffer[:] = b"\x00" * len(buffer)
                    buffers_zeroed = True
            session.get("buffers", {}).clear()
            resources_released.append("in_memory_evidence_buffers")
            try:
                _adapter_close(session.get("adapter"))
                resources_released.append("adapter_session")
            except Exception as exc:
                close_errors.append(str(exc))
        status = "resources_released" if session is not None else "already_released"
        ok = not close_errors
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": status if ok else "cleanup_failed",
            "read_only": True,
            "restored": False,
            "mutations_reverted": False,
            "buffers_zeroed": buffers_zeroed,
            "resources_released": resources_released,
            "collected_evidence_preserved": True,
            "errors": close_errors,
        }
        result.rollback_plan.update(
            {
                "completed": ok,
                "status": details["status"],
                "restored": False,
                "details": details,
            }
        )
        result.report_section["rollback"] = details
        result.dashboard_trace.append(
            {
                "kind": "dma_memory_rollback",
                "session_id": result.session_id,
                "status": details["status"],
                "restored": False,
            }
        )
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=ok,
            restored=False,
            details=details,
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        root = Path(out_dir).expanduser().resolve()
        self._validate_output_root(root)
        root.mkdir(parents=True, exist_ok=True)
        with self._session_lock:
            session = self._sessions.get(result.session_id)
        artifacts = list(result.artifacts or [])
        entries: list[dict[str, Any]] = []

        for artifact in artifacts:
            if artifact.kind != "memory-snapshot":
                continue
            destination = _artifact_destination(root, artifact.path)
            buffer_key = str(artifact.metadata.get("buffer_key") or artifact.path)
            buffer = (session or {}).get("buffers", {}).get(buffer_key)
            if not isinstance(buffer, bytearray):
                raise DMAMemoryError(f"snapshot buffer is unavailable: {artifact.path}")
            encoded = bytes(buffer)
            _write_bytes(destination, encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update(
                {"materialized": True, "sha256": digest, "size": len(encoded)}
            )
            entries.append(self._manifest_entry(result, artifact, digest, len(encoded)))

        evidence_artifact = next(
            item for item in artifacts if item.kind == "dma-memory-evidence"
        )
        evidence_payload = {
            "schema_version": _SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "action": result.action,
            "read_only": True,
            "target": _target_payload(result.target),
            "before_snapshot": _json_mapping(result.before_snapshot),
            "after_snapshot": _json_mapping(result.after_snapshot),
            "rollback_plan": _json_mapping(result.rollback_plan),
            "provenance": _json_mapping(result.provenance),
            "artifacts": [item.to_dict() for item in artifacts if item.kind == "memory-snapshot"],
        }
        evidence_bytes = _json_bytes(evidence_payload)
        evidence_destination = _artifact_destination(root, evidence_artifact.path)
        _write_bytes(evidence_destination, evidence_bytes)
        evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
        evidence_artifact.metadata.update(
            {"materialized": True, "sha256": evidence_digest, "size": len(evidence_bytes)}
        )
        entries.append(
            self._manifest_entry(result, evidence_artifact, evidence_digest, len(evidence_bytes))
        )

        manifest_artifact = next(item for item in artifacts if item.kind == "evidence-manifest")
        manifest_payload = {
            "schema_version": _SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "read_only": True,
            "target_identity_sha256": result.provenance.get("target_identity_sha256"),
            "entries": entries,
        }
        manifest_bytes = _json_bytes(manifest_payload)
        manifest_destination = _artifact_destination(root, manifest_artifact.path)
        _write_bytes(manifest_destination, manifest_bytes)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_artifact.metadata.update(
            {"materialized": True, "sha256": manifest_digest, "size": len(manifest_bytes)}
        )
        entries.append(
            self._manifest_entry(result, manifest_artifact, manifest_digest, len(manifest_bytes))
        )

        if session is not None:
            session["collected"] = True
        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        result.report_section["artifacts"] = [item.to_dict() for item in artifacts]
        result.report_section["evidence_manifest_entries"] = entries
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=entries,
        )

    def _normalize_parameters(
        self,
        request: CapabilityRequest,
        action: str,
    ) -> tuple[dict[str, Any], list[str]]:
        raw = dict(request.params or {})
        errors: list[str] = []
        allowed_keys = _COMMON_PARAM_KEYS | _ACTION_PARAM_KEYS.get(action, set())
        unknown = sorted(str(key) for key in raw if key not in allowed_keys)
        if unknown:
            errors.append("unsupported parameters: " + ", ".join(unknown))
        target_payload = _target_payload(request.target)
        target_pid = _coerce_int(target_payload.get("pid"))
        parameter_pid = _coerce_int(raw.get("pid"))
        metadata = target_payload.get("metadata") if isinstance(target_payload.get("metadata"), Mapping) else {}
        metadata_pid = _coerce_int(metadata.get("pid"))
        supplied_pids = [item for item in (target_pid, parameter_pid, metadata_pid) if item is not None]
        pid = target_pid if target_pid is not None else parameter_pid
        if not pid or pid <= 0:
            errors.append("target PID is required and must be positive")
        if supplied_pids and any(item != supplied_pids[0] for item in supplied_pids):
            errors.append("PID values in target identity and parameters conflict")

        dtb_values = [
            value
            for value in (
                raw.get("dtb"),
                raw.get("cr3"),
                metadata.get("dtb"),
                metadata.get("cr3"),
            )
            if value is not None
        ]
        normalized_dtbs = [_normalize_dtb(value) for value in dtb_values]
        if any(item is None for item in normalized_dtbs):
            errors.append("DTB/CR3 must be a non-zero x86-64 physical address")
        valid_dtbs = [item for item in normalized_dtbs if item is not None]
        if valid_dtbs and any(item != valid_dtbs[0] for item in valid_dtbs):
            errors.append("DTB/CR3 values in target identity and parameters conflict")
        dtb = valid_dtbs[0] if valid_dtbs else None

        requested_allowlist_value = raw.get(
            "allowlist", raw.get("allowed_ranges", raw.get("address_allowlist"))
        )
        requested_allowlist, allowlist_errors = _parse_allowlist(requested_allowlist_value)
        errors.extend(allowlist_errors)
        if self._configured_allowlist and requested_allowlist:
            if not all(
                _range_allowed(
                    str(item["address_space"]),
                    int(item["start"]),
                    int(item["end"]) - int(item["start"]),
                    self._configured_allowlist,
                )
                for item in requested_allowlist
            ):
                errors.append("request allowlist exceeds the provider-configured allowlist")
            effective_allowlist = requested_allowlist
        else:
            effective_allowlist = requested_allowlist or list(self._configured_allowlist)

        requested_max = _coerce_int(raw.get("max_bytes"))
        if requested_max is None:
            effective_max = self.max_read_bytes
        elif requested_max <= 0 or requested_max > self.max_read_bytes:
            errors.append("max_bytes must be positive and no greater than the provider maximum")
            effective_max = self.max_read_bytes
        else:
            effective_max = requested_max

        artifact_name = _optional_text(raw.get("artifact_name"))
        if artifact_name is not None and not _valid_artifact_name(artifact_name):
            errors.append("artifact_name must be a safe basename without path components")
        if raw.get("device") is not None and str(raw.get("device")) != self.device:
            errors.append("requested device does not match the provider-configured device")
        expected_name = _optional_text(
            raw.get("expected_name")
            or raw.get("process_name")
            or metadata.get("process_name")
            or metadata.get("name")
            or (
                target_payload.get("display_name")
                if str(target_payload.get("display_name") or "").casefold()
                != f"pid:{pid}".casefold()
                else None
            )
        )
        expected_image = _optional_text(
            raw.get("expected_image")
            or raw.get("image_name")
            or metadata.get("image_path")
            or metadata.get("image_name")
        )
        architecture = str(raw.get("architecture") or "x86_64").strip().casefold()
        architecture = {
            "amd64": "x86_64",
            "x64": "x86_64",
            "x86-64": "x86_64",
        }.get(architecture, architecture)
        if architecture != "x86_64":
            errors.append("architecture must be x86_64 for DTB/CR3 page-table translation")

        segments, segment_errors = _normalize_segments(action, raw)
        errors.extend(segment_errors)
        total_bytes = sum(int(item.get("size") or 0) for item in segments)
        if action in {"translate", "read", "snapshot"} and not effective_allowlist:
            errors.append("an explicit address allowlist is required")
        if total_bytes > effective_max:
            errors.append("requested byte total exceeds max_bytes")
        return (
            _prune(
                {
                    "pid": pid,
                    "dtb": dtb,
                    "expected_name": expected_name,
                    "expected_image": expected_image,
                    "architecture": architecture,
                    "device": self.device,
                    "include_modules": bool(raw.get("include_modules", False)),
                    "max_bytes": effective_max,
                    "allowlist": effective_allowlist,
                    "segments": segments,
                    "artifact_name": artifact_name,
                    "requested_bytes": total_bytes,
                }
            ),
            _deduplicate(errors),
        )

    def _read_segment(
        self,
        adapter: Any,
        budget: _ReadBudget,
        segment: Mapping[str, Any],
        *,
        dtb: Optional[int],
    ) -> tuple[bytes, dict[str, Any]]:
        address_space = str(segment.get("address_space") or "virtual")
        address = int(_coerce_int(segment.get("address")) or 0)
        size = int(_coerce_int(segment.get("size")) or 0)
        if address_space == "physical":
            data = budget.read_physical(address, size, payload=True)
            translations: list[dict[str, Any]] = []
        else:
            if dtb is None:
                raise DMAMemoryError("virtual reads require a resolved target DTB/CR3")
            chunks: list[bytes] = []
            translations = []
            remaining = size
            cursor = address
            while remaining:
                translation = translate_x64_virtual_address(
                    adapter,
                    dtb,
                    cursor,
                    budget=budget,
                )
                page_size = int(translation["page_size"])
                offset = cursor & (page_size - 1)
                chunk_size = min(remaining, page_size - offset)
                if segment.get("translate_only"):
                    chunk_size = 0
                else:
                    chunks.append(
                        budget.read_physical(
                            int(translation["physical_address"]),
                            chunk_size,
                            payload=True,
                        )
                    )
                translation["virtual_size"] = chunk_size or 1
                translations.append(translation)
                if segment.get("translate_only"):
                    break
                cursor += chunk_size
                remaining -= chunk_size
            data = b"".join(chunks)
        evidence = {
            "label": segment.get("label"),
            "address_space": address_space,
            "address": address,
            "size": size if not segment.get("translate_only") else 0,
            "requested_size": size,
            "sha256": hashlib.sha256(data).hexdigest() if data else None,
            "translations": translations,
            "read_only": True,
        }
        return data, _prune(evidence)

    def _backend_preflight(self) -> list[dict[str, Any]]:
        return [_adapter_describe(item) for item in self._candidates]

    def _open_adapter(self) -> tuple[Optional[Any], list[dict[str, Any]]]:
        attempts: list[dict[str, Any]] = []
        for adapter in self._candidates:
            description = _adapter_describe(adapter)
            if not description.get("dependency_available"):
                attempts.append(
                    {
                        "adapter": description.get("adapter"),
                        "status": "unavailable",
                        "backend_class": description.get("backend_class"),
                        "error": description.get("reason") or getattr(adapter, "unavailable_reason", None),
                    }
                )
                continue
            try:
                _adapter_open(adapter)
                attempts.append(
                    {
                        "adapter": description.get("adapter"),
                        "status": "opened",
                        "read_only": True,
                        "backend_class": description.get("backend_class"),
                    }
                )
                return adapter, attempts
            except Exception as exc:
                try:
                    _adapter_close(adapter)
                except Exception:
                    pass
                attempts.append(
                    {
                        "adapter": description.get("adapter"),
                        "status": "failed",
                        "backend_class": description.get("backend_class"),
                        "error": str(exc),
                    }
                )
        return None, attempts

    def _result(
        self,
        plan: CapabilityPlan,
        *,
        status: str,
        validation: CapabilityValidation,
        after: Mapping[str, Any],
        errors: Sequence[str],
        artifacts: Optional[list[CapabilityArtifact]] = None,
        adapter_description: Optional[Mapping[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        adapter_payload = _json_mapping(adapter_description or {})
        backend_class = str(
            adapter_payload.get("backend_class") or "dependency-gated"
        )
        effective_status = (
            "test-double"
            if status == "ok" and backend_class == "test-double"
            else status
        )
        result_artifacts = list(artifacts or [])
        artifact_kinds = {item.kind for item in result_artifacts}
        result_artifacts.extend(
            item
            for item in _base_evidence_artifacts(plan.session_id)
            if item.kind not in artifact_kinds
        )
        provenance = {
            **_json_mapping(plan.provenance),
            "schema_version": _SCHEMA_VERSION,
            "read_only": True,
            "acquisition_mode": adapter_payload.get("source_type") or "unavailable",
            "adapter": adapter_payload,
            "backend_class": backend_class,
            "production_backend": backend_class.startswith("production-"),
            "offline_fixture": backend_class == "offline-fixture",
            "test_double": backend_class == "test-double",
            "dependency_gated": backend_class == "dependency-gated",
            "hardware_backed": backend_class == "production-hardware",
            "hardware_acquisition_completed": bool(
                status == "ok"
                and backend_class == "production-hardware"
                and _json_mapping(after.get("target")).get("identity_verified") is True
                and adapter_payload.get("hardware_acquisition_completed", False)
            ),
        }
        report = {
            "schema_version": _SCHEMA_VERSION,
            "title": "Read-only DMA / physical-memory evidence",
            "status": effective_status,
            "action": plan.action,
            "session_id": plan.session_id,
            "read_only": True,
            "target_identity": _target_payload(plan.target),
            "validation": validation.to_dict(),
            "before_snapshot": _json_mapping(plan.before_snapshot),
            "after_snapshot": _json_mapping(after),
            "errors": list(errors),
            "provenance": provenance,
        }
        result = CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=effective_status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_json_mapping(plan.before_snapshot),
            after_snapshot=_json_mapping(after),
            rollback_plan=dict(plan.rollback_plan),
            artifacts=result_artifacts,
            evidence_manifest_entries=[],
            report_section=report,
            dashboard_trace=[
                {
                    "kind": "dma_memory_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "session_id": plan.session_id,
                    "action": plan.action,
                    "status": effective_status,
                    "read_only": True,
                    "hardware_acquisition_completed": provenance[
                        "hardware_acquisition_completed"
                    ],
                }
            ],
            provenance=provenance,
        )
        return result

    def _manifest_entry(
        self,
        result: CapabilityExecutionResult,
        artifact: CapabilityArtifact,
        digest: str,
        size: int,
    ) -> dict[str, Any]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "description": artifact.description,
            "sha256": digest,
            "size": size,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "target_identity_sha256": result.provenance.get("target_identity_sha256"),
            "acquisition_mode": result.provenance.get("acquisition_mode"),
            "backend_class": result.provenance.get("backend_class"),
            "hardware_acquisition_completed": result.provenance.get(
                "hardware_acquisition_completed", False
            ),
            "read_only": True,
        }

    def _validate_output_root(self, root: Path) -> None:
        if self._allowed_output_roots and not any(
            root == allowed or allowed in root.parents for allowed in self._allowed_output_roots
        ):
            raise DMAMemoryError("artifact output directory is outside the configured roots")


def _normalize_segments(
    action: str,
    raw: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    if action == "translate":
        values: list[Any] = [
            {
                "address_space": "virtual",
                "address": raw.get("address"),
                "size": 1,
                "label": "address-translation",
                "translate_only": True,
            }
        ]
    elif action == "read":
        values = [
            {
                "address_space": raw.get("address_space", "virtual"),
                "address": raw.get("address"),
                "size": raw.get("size"),
                "label": "bounded-read",
            }
        ]
    elif action == "snapshot":
        supplied = raw.get("ranges")
        if not isinstance(supplied, Sequence) or isinstance(supplied, (str, bytes, bytearray)):
            return [], ["snapshot ranges must be a non-empty sequence"]
        values = list(supplied)
        if not values:
            errors.append("snapshot ranges must be non-empty")
    else:
        return [], errors
    if len(values) > _MAX_SEGMENTS:
        errors.append(f"snapshot range count exceeds {_MAX_SEGMENTS}")
        values = values[:_MAX_SEGMENTS]
    segments: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            errors.append(f"range {index} must be an object")
            continue
        unknown = sorted(str(key) for key in value if key not in _SEGMENT_KEYS and key != "translate_only")
        if unknown:
            errors.append(f"range {index} has unsupported keys: {', '.join(unknown)}")
        address_space = str(value.get("address_space") or "virtual").casefold()
        if action == "translate":
            address_space = "virtual"
        if address_space not in {"virtual", "physical"}:
            errors.append(f"range {index} address_space must be virtual or physical")
        address = _coerce_int(value.get("address"))
        size = _coerce_int(value.get("size"))
        if address is None or size is None or size <= 0:
            errors.append(f"range {index} requires a non-negative address and positive size")
            continue
        try:
            if address_space == "physical":
                _validate_physical_range(address, size)
            else:
                _validate_u64_range(address, size, "virtual memory")
                if not _is_canonical_x64(address) or not _is_canonical_x64(address + size - 1):
                    raise ValueError("virtual range is not canonical x86-64")
        except (ValueError, DMAMemoryError) as exc:
            errors.append(f"range {index}: {exc}")
            continue
        label = _optional_text(value.get("label")) or f"range-{index}"
        if len(label) > 128:
            errors.append(f"range {index} label exceeds 128 characters")
            label = label[:128]
        segments.append(
            {
                "address_space": address_space,
                "address": address,
                "size": size,
                "label": label,
                "translate_only": bool(value.get("translate_only", False)),
            }
        )
    return segments, errors


def _parse_allowlist(value: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if value in (None, "", [], {}):
        return [], []
    entries: list[tuple[str, Any]] = []
    errors: list[str] = []
    if isinstance(value, Mapping):
        if any(key in value for key in ("start", "end", "address", "size")):
            entries.append((str(value.get("address_space") or value.get("space") or "virtual"), value))
        else:
            unknown_spaces = [key for key in value if str(key).casefold() not in {"virtual", "physical"}]
            if unknown_spaces:
                errors.append("allowlist spaces must be virtual or physical")
            for space in ("virtual", "physical"):
                ranges = value.get(space) or value.get(space.upper()) or []
                if isinstance(ranges, Sequence) and not isinstance(ranges, (str, bytes, bytearray)):
                    entries.extend((space, item) for item in ranges)
                elif ranges:
                    errors.append(f"{space} allowlist must be a sequence")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if isinstance(item, Mapping):
                entries.append((str(item.get("address_space") or item.get("space") or "virtual"), item))
            else:
                entries.append(("virtual", item))
    else:
        return [], ["allowlist must be an object or sequence"]
    normalized: list[dict[str, Any]] = []
    for index, (space_value, item) in enumerate(entries):
        space = str(space_value).casefold()
        if space not in {"virtual", "physical"}:
            errors.append(f"allowlist range {index} has an invalid address space")
            continue
        if isinstance(item, Mapping):
            start = _coerce_int(item.get("start", item.get("address")))
            end = _coerce_int(item.get("end"))
            size = _coerce_int(item.get("size"))
            if end is None and start is not None and size is not None:
                end = start + size
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)) and len(item) == 2:
            start = _coerce_int(item[0])
            end = _coerce_int(item[1])
        else:
            errors.append(f"allowlist range {index} must contain start/end")
            continue
        if start is None or end is None or start < 0 or end <= start or end > _MAX_U64 + 1:
            errors.append(f"allowlist range {index} is invalid")
            continue
        if space == "physical" and end - 1 > _PHYSICAL_ADDRESS_MASK + 0xFFF:
            errors.append(f"allowlist range {index} exceeds the supported physical address width")
            continue
        if space == "virtual" and (
            not _is_canonical_x64(start) or not _is_canonical_x64(end - 1)
        ):
            errors.append(f"allowlist range {index} is not canonical x86-64")
            continue
        normalized.append({"address_space": space, "start": start, "end": end})
    normalized.sort(key=lambda item: (str(item["address_space"]), int(item["start"]), int(item["end"])))
    return normalized, errors


def _range_allowed(
    address_space: str,
    address: Optional[int],
    size: Optional[int],
    allowlist: Sequence[Mapping[str, Any]],
) -> bool:
    if address is None or size is None or size <= 0:
        return False
    end = address + size
    return any(
        str(item.get("address_space")) == address_space
        and int(item.get("start", -1)) <= address
        and end <= int(item.get("end", -1))
        for item in allowlist
    )


def _plan_steps(action: str) -> list[dict[str, Any]]:
    steps = [
        {"order": 1, "operation": "initialize_read_only_source", "mutating": False},
        {"order": 2, "operation": "resolve_pid_dtb_identity", "mutating": False},
    ]
    if action == "modules":
        steps.append({"order": 3, "operation": "read_module_metadata", "mutating": False})
    elif action in {"translate", "read", "snapshot"}:
        steps.append({"order": 3, "operation": "walk_x64_page_tables", "mutating": False})
        if action in {"read", "snapshot"}:
            steps.append({"order": 4, "operation": "bounded_snapshot", "mutating": False})
    steps.append(
        {"order": len(steps) + 1, "operation": "hash_and_manifest_evidence", "mutating": False}
    )
    return steps


def _translation_payload(
    virtual_address: int,
    physical_address: int,
    page_size: int,
    dtb: int,
    walk: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "status": "ok",
        "architecture": "x86_64",
        "method": "four_level_page_table_walk",
        "virtual_address": virtual_address,
        "physical_address": physical_address,
        "page_size": page_size,
        "dtb": dtb,
        "walk": walk,
        "walk_sha256": _canonical_hash(walk),
    }


def _adapter_open(adapter: Any) -> None:
    method = _first_callable(adapter, ("open", "initialize"))
    if method is None:
        raise DMAMemoryError("adapter does not expose open/initialize")
    method()


def _adapter_close(adapter: Any) -> None:
    if adapter is None:
        return
    method = _first_callable(adapter, ("close", "cleanup"))
    if method is not None:
        method()


def _adapter_read_physical(adapter: Any, address: int, size: int) -> bytes:
    method = _first_callable(adapter, ("read_physical", "read"))
    if method is None:
        raise DMAMemoryError("adapter does not expose a physical read method")
    data = _extract_bytes(method(address, size))
    if data is None:
        raise DMAMemoryError("adapter physical read did not return bytes")
    return data


def _adapter_resolve_target(
    adapter: Any,
    pid: int,
    **kwargs: Any,
) -> Mapping[str, Any]:
    method = _first_callable(adapter, ("resolve_target", "resolve_process"))
    if method is None:
        raise DMAMemoryError("adapter does not expose target resolution")
    value = method(pid, **kwargs)
    if not isinstance(value, Mapping):
        raise DMAMemoryError("adapter target resolution returned an invalid value")
    return value


def _adapter_list_modules(adapter: Any, pid: int) -> Sequence[Mapping[str, Any]]:
    method = _first_callable(adapter, ("list_modules", "modules"))
    if method is None:
        return []
    value = method(pid)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise DMAMemoryError("adapter module listing returned an invalid value")
    return [item for item in value if isinstance(item, Mapping)]


def _adapter_describe(adapter: Any) -> dict[str, Any]:
    method = getattr(adapter, "describe", None)
    if callable(method):
        try:
            value = method()
            payload = _json_mapping(value) if isinstance(value, Mapping) else {}
        except Exception as exc:
            payload = {"description_error": f"{type(exc).__name__}: {exc}"}
    else:
        payload = {}
    available = bool(
        payload.get(
            "dependency_available",
            getattr(adapter, "dependency_available", getattr(adapter, "available", True)),
        )
    )
    backend_class = _adapter_backend_class(adapter, available=available)
    hardware_backed = backend_class == "production-hardware"
    payload.update(
        {
            "adapter": payload.get("adapter") or getattr(adapter, "name", type(adapter).__name__),
            "dependency_available": available,
            "read_only": True,
            "backend_class": backend_class,
            "production_backend": backend_class.startswith("production-"),
            "offline_fixture": backend_class == "offline-fixture",
            "test_double": backend_class == "test-double",
            "dependency_gated": backend_class == "dependency-gated",
            "hardware_backed": hardware_backed,
            "hardware_acquisition_completed": bool(
                hardware_backed
                and payload.get("hardware_acquisition_completed", False)
            ),
        }
    )
    reason = payload.get("reason") or getattr(adapter, "unavailable_reason", None)
    if reason:
        payload["reason"] = str(reason)
    return _prune(payload)


def _adapter_backend_class(adapter: Any, *, available: bool) -> str:
    """Classify concrete adapters without trusting describe() attestation."""

    if type(adapter) is UnavailableDMAMemoryAdapter:
        return "dependency-gated"
    if type(adapter) is OfflinePhysicalMemoryAdapter:
        return "offline-fixture"
    if type(adapter) is LeechCorePythonAdapter:
        if not available:
            return "dependency-gated"
        if adapter.test_double:
            return "test-double"
        if adapter.hardware_backed:
            return "production-hardware"
        return "production-api"
    if type(adapter) is MemProcFSVFSAdapter:
        return "production-vfs" if available else "dependency-gated"
    return "test-double"


def _dependency_gate_status(descriptions: Sequence[Mapping[str, Any]]) -> str:
    classes = {str(item.get("backend_class") or "") for item in descriptions}
    if classes & {"dependency-gated", "production-hardware"}:
        return "dependency-gated"
    return "unavailable"


def _leechcore_device_scheme(device: str) -> str:
    match = re.fullmatch(
        r"([a-z0-9_-]+)(?:://[^\x00]*)?",
        str(device).strip().casefold(),
    )
    return match.group(1) if match else ""


def _extract_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, Mapping):
        for key in ("data", "bytes", "payload"):
            if key in value:
                return _extract_bytes(value[key])
    return None


def _first_callable(value: Any, names: Sequence[str]) -> Any:
    for name in names:
        method = getattr(value, name, None)
        if callable(method):
            return method
    return None


def _verify_expected_identity(
    record: Mapping[str, Any],
    expected_name: Optional[str],
    expected_image: Optional[str],
    *,
    allow_unverified: bool = False,
) -> None:
    actual_name = _optional_text(record.get("name") or record.get("process_name"))
    actual_image = _optional_text(
        record.get("image_path") or record.get("path") or record.get("image")
    )
    if expected_name and actual_name and not _identity_name_matches(actual_name, expected_name):
        raise DMAMemoryError("resolved process name does not match the target identity")
    if expected_image and actual_image and not _identity_image_matches(actual_image, expected_image):
        raise DMAMemoryError("resolved image path does not match the target identity")
    if not allow_unverified:
        if expected_name and not actual_name:
            raise DMAMemoryError("target process name could not be verified")
        if expected_image and not actual_image:
            raise DMAMemoryError("target image path could not be verified")


def _identity_name_matches(actual: Optional[str], expected: str) -> bool:
    if not actual:
        return False
    return PureWindowsPath(actual).name.casefold() == PureWindowsPath(expected).name.casefold()


def _identity_image_matches(actual: Optional[str], expected: str) -> bool:
    if not actual:
        return False
    actual_path = str(actual).replace("/", "\\").casefold()
    expected_path = str(expected).replace("/", "\\").casefold()
    return actual_path == expected_path or PureWindowsPath(actual_path).name == PureWindowsPath(expected_path).name


def _parse_dtb_text(text: str) -> Optional[int]:
    patterns = (
        r"(?i)(?:dtb|cr3)\s*[:=]?\s*(0x[0-9a-f]+|[0-9a-f]{4,16})",
        r"(?i)\b(0x[0-9a-f]+|[0-9a-f]{4,16})\b",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            token = match.group(1)
            try:
                value = int(token, 16)
            except ValueError:
                continue
            return _normalize_dtb(value)
    return None


def _parse_process_image(text: str) -> Optional[str]:
    for line in text.splitlines():
        match = re.match(r"(?i)\s*(?:image|path|image_path)\s*[:=]\s*(.+?)\s*$", line)
        if match:
            return match.group(1).strip()
    return None


def _parse_module_text(text: str) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.casefold().startswith("base "):
            continue
        parts = stripped.split(None, 3)
        if len(parts) < 3:
            continue
        base = _parse_hex_column(parts[0])
        size = _parse_hex_column(parts[1])
        if base is None or size is None:
            continue
        modules.append(
            _prune(
                {
                    "base_address": base,
                    "size": size,
                    "name": parts[2],
                    "path": parts[3] if len(parts) > 3 else None,
                }
            )
        )
    return modules


def _parse_hex_column(value: str) -> Optional[int]:
    token = value.strip().rstrip(",")
    try:
        return int(token, 16)
    except ValueError:
        return None


def _segment_artifact_path(
    session_id: str,
    artifact_name: Any,
    index: int,
    count: int,
) -> str:
    if artifact_name:
        name = str(artifact_name)
        path = Path(name)
        suffix = path.suffix or ".bin"
        stem = path.stem if path.suffix else path.name
        return f"{stem}-{index:03d}{suffix}" if count > 1 else f"{stem}{suffix}"
    return f"dma-memory-{_safe_segment(session_id)}-{index:03d}.bin"


def _base_evidence_artifacts(session_id: str) -> list[CapabilityArtifact]:
    safe_session = _safe_segment(session_id)
    return [
        CapabilityArtifact(
            path=f"dma-memory-{safe_session}-evidence.json",
            kind="dma-memory-evidence",
            description="Read-only DMA memory acquisition evidence",
        ),
        CapabilityArtifact(
            path=f"dma-memory-{safe_session}-manifest.json",
            kind="evidence-manifest",
            description="DMA memory evidence manifest",
        ),
    ]


def _artifact_destination(root: Path, artifact_path: str) -> Path:
    text = str(artifact_path or "").strip()
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text)
    if (
        not text
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.is_absolute()
        or ".." in windows.parts
        or ".." in posix.parts
    ):
        raise DMAMemoryError("artifact path must remain inside the collection directory")
    destination = (root / Path(text)).resolve()
    _require_within(destination, root, "artifact path")
    return destination


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = path.parent.resolve()
    _require_within(path.resolve(), resolved_parent, "artifact destination")
    path.write_bytes(data)


def _require_within(path: Path, root: Path, label: str) -> None:
    if path != root and root not in path.parents:
        raise ValueError(f"{label} escapes its configured root")


def _valid_artifact_name(value: str) -> bool:
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    return bool(
        _SAFE_ARTIFACT_NAME.fullmatch(value)
        and not windows.is_absolute()
        and not windows.drive
        and not posix.is_absolute()
        and len(windows.parts) == 1
        and len(posix.parts) == 1
        and value not in {".", ".."}
    )


def _normalize_action(value: Any) -> str:
    action = str(value or "").strip().casefold()
    return _ACTION_ALIASES.get(action, action)


def _normalize_dtb(value: Any) -> Optional[int]:
    parsed = _coerce_int(value)
    if parsed is None or parsed <= 0 or parsed > _MAX_U64:
        return None
    base = parsed & _PHYSICAL_ADDRESS_MASK
    return base if base else None


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16) if all(char in "0123456789abcdefABCDEF" for char in text) else None
        except ValueError:
            return None


def _validate_physical_range(address: int, size: int) -> None:
    _validate_u64_range(address, size, "physical memory")
    if address + size - 1 > _PHYSICAL_ADDRESS_MASK + 0xFFF:
        raise DMAMemoryError("physical memory range exceeds the supported address width")


def _validate_u64_range(address: int, size: int, label: str) -> None:
    if address < 0 or size <= 0 or address > _MAX_U64 or size > _MAX_U64:
        raise ValueError(f"{label} range must have a non-negative address and positive size")
    if address + size - 1 > _MAX_U64:
        raise ValueError(f"{label} range overflows 64-bit addressing")


def _is_canonical_x64(address: int) -> bool:
    if address < 0 or address > _MAX_U64:
        return False
    upper = address >> 48
    sign = (address >> 47) & 1
    return upper == (0xFFFF if sign else 0)


def _target_payload(target: Any) -> dict[str, Any]:
    method = getattr(target, "to_dict", None)
    if callable(method):
        value = method()
        if isinstance(value, Mapping):
            return _json_mapping(value)
    return _prune(
        {
            "kind": getattr(target, "kind", None),
            "path": getattr(target, "path", None),
            "pid": getattr(target, "pid", None),
            "sha256": getattr(target, "sha256", None),
            "display_name": getattr(target, "display_name", None),
            "metadata": getattr(target, "metadata", None),
        }
    )


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(_json_value(value), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _json_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _prune(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


def _safe_segment(value: Any) -> str:
    safe = "".join(
        char if char.isalnum() or char in "-_." else "_" for char in str(value or "session")
    ).strip(".")
    return safe[:96] or "session"


def _optional_text(value: Any) -> Optional[str]:
    text = str(value).strip() if value is not None else ""
    return text or None


def _deduplicate(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


# Compatibility spellings for callers that prefer title-cased acronyms.
DmaMemoryProvider = DMAMemoryProvider
LeechCoreAdapter = LeechCorePythonAdapter
MemProcFSAdapter = MemProcFSVFSAdapter
RawMemoryImageAdapter = OfflinePhysicalMemoryAdapter


__all__ = [
    "AddressTranslationError",
    "DMAMemoryAdapter",
    "DMAMemoryError",
    "DMAMemoryProvider",
    "DmaMemoryProvider",
    "LeechCoreAdapter",
    "LeechCorePythonAdapter",
    "MemProcFSAdapter",
    "MemProcFSVFSAdapter",
    "OfflinePhysicalMemoryAdapter",
    "RawMemoryImageAdapter",
    "UnavailableDMAMemoryAdapter",
    "translate_x64_virtual_address",
]
