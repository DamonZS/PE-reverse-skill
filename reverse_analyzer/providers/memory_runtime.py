"""Auditable Windows process-memory capability provider.

The provider keeps process mutation behind explicit plans and byte/protection
preconditions.  A backend can be injected for deterministic tests; the native
backend uses only documented Win32 APIs through :mod:`ctypes`.
"""

from __future__ import annotations

import ctypes
import hashlib
import inspect
import json
import math
import struct
import sys
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
from reverse_analyzer.providers.mock import MockCapabilityProvider
from reverse_analyzer.providers.memory_schema import (
    compile_memory_schema,
    decode_structure,
    describe_memory_layout,
    read_structure_field,
    resolve_structure_field,
    write_structure_field,
)


_AUDIT_SCHEMA_VERSION = 1
_DEFAULT_MAX_READ = 16 * 1024 * 1024
_DEFAULT_MAX_SCAN_BYTES = 256 * 1024 * 1024
_DEFAULT_SCAN_CHUNK = 1024 * 1024
_DEFAULT_MAX_RESULTS = 256
_DEFAULT_MAX_STRING_BYTES = 4096
_MAX_POINTER_CHAIN_DEPTH = 64

_MEM_COMMIT = 0x1000
_MEM_RESERVE = 0x2000
_MEM_PRIVATE = 0x20000
_MEM_RELEASE = 0x8000
_MEM_FREE = 0x10000

_WRITE_ACTIONS = {"write", "schema_write"}
_MUTATING_ACTIONS = {*_WRITE_ACTIONS, "protect", "alloc", "free"}
_STRUCTURED_READ_ACTIONS = {
    "typed_read",
    "string_read",
    "pointer_chain",
    "module_rva",
    "schema_read",
}
_ADDRESS_ACTIONS = {
    "read",
    "typed_read",
    "string_read",
    "pointer_chain",
    "schema_read",
    "schema_write",
    "write",
    "protect",
    "free",
}
_SUPPORTED_ACTIONS = {
    "probe",
    "regions",
    "modules",
    "read",
    *_WRITE_ACTIONS,
    "protect",
    "alloc",
    "free",
    "scan",
    *_STRUCTURED_READ_ACTIONS,
}
_ACTION_ALIASES = {
    "process_probe": "probe",
    "probe_process": "probe",
    "enumerate_regions": "regions",
    "list_regions": "regions",
    "region_enum": "regions",
    "enumerate_modules": "modules",
    "list_modules": "modules",
    "module_enum": "modules",
    "read_memory": "read",
    "read_typed": "typed_read",
    "typed_memory_read": "typed_read",
    "read_string": "string_read",
    "resolve_pointer_chain": "pointer_chain",
    "pointer_chain_resolve": "pointer_chain",
    "resolve_module_rva": "module_rva",
    "module_rva_resolve": "module_rva",
    "write_memory": "write",
    "write_typed": "write",
    "typed_memory_write": "write",
    "read_schema": "schema_read",
    "read_struct": "schema_read",
    "structured_read": "schema_read",
    "write_schema": "schema_write",
    "write_struct": "schema_write",
    "structured_write": "schema_write",
    "protect_memory": "protect",
    "virtual_protect": "protect",
    "allocate": "alloc",
    "allocate_memory": "alloc",
    "virtual_alloc": "alloc",
    "free_memory": "free",
    "virtual_free": "free",
    "aob_scan": "scan",
    "pattern_scan": "scan",
    "scan_pattern": "scan",
}

_TYPED_VALUE_FORMATS = {
    "int8": ("b", 1),
    "uint8": ("B", 1),
    "int16": ("h", 2),
    "uint16": ("H", 2),
    "int32": ("i", 4),
    "uint32": ("I", 4),
    "int64": ("q", 8),
    "uint64": ("Q", 8),
    "float32": ("f", 4),
    "float64": ("d", 8),
}
_TYPED_VALUE_ALIASES = {
    "float": "float32",
    "double": "float64",
    "i8": "int8",
    "u8": "uint8",
    "i16": "int16",
    "u16": "uint16",
    "i32": "int32",
    "u32": "uint32",
    "i64": "int64",
    "u64": "uint64",
}
_STRING_ENCODINGS = {
    "utf8": "utf-8",
    "utf-8": "utf-8",
    "utf16": "utf-16-le",
    "utf-16": "utf-16-le",
    "utf16le": "utf-16-le",
    "utf-16le": "utf-16-le",
    "utf-16-le": "utf-16-le",
    "utf16be": "utf-16-be",
    "utf-16be": "utf-16-be",
    "utf-16-be": "utf-16-be",
}

_PAGE_PROTECTIONS = {
    "PAGE_NOACCESS": 0x01,
    "PAGE_READONLY": 0x02,
    "PAGE_READWRITE": 0x04,
    "PAGE_WRITECOPY": 0x08,
    "PAGE_EXECUTE": 0x10,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
    "PAGE_EXECUTE_WRITECOPY": 0x80,
}
_PROTECTION_NAMES = {value: key for key, value in _PAGE_PROTECTIONS.items()}


class MemoryRuntimeBackendError(RuntimeError):
    """A backend failure carrying serializable operation details."""

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
        return _prune(
            {
                "type": type(self).__name__,
                "operation": self.operation,
                "message": self.message,
                "winerror": self.code,
                "details": self.details,
            }
        )


class MemoryRuntimeBackend(Protocol):
    """Backend surface accepted by :class:`MemoryRuntimeProvider`."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_process(self, pid: int) -> Mapping[str, Any]: ...

    def enumerate_regions(self, pid: int) -> Sequence[Mapping[str, Any]]: ...

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]: ...

    def read(self, pid: int, address: int, size: int) -> bytes: ...

    def write(
        self,
        pid: int,
        address: int,
        data: bytes,
        expected: bytes,
    ) -> Mapping[str, Any]: ...

    def protect(
        self,
        pid: int,
        address: int,
        size: int,
        protection: int,
    ) -> Mapping[str, Any]: ...

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        address: Optional[int] = None,
        allocation_type: int = 0x3000,
    ) -> Mapping[str, Any]: ...

    def free(
        self,
        pid: int,
        address: int,
        *,
        size: int = 0,
        free_type: int = 0x8000,
    ) -> Mapping[str, Any]: ...

    def scan(
        self,
        pid: int,
        pattern: bytes,
        *,
        mask: str,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_results: int = _DEFAULT_MAX_RESULTS,
        max_bytes: int = _DEFAULT_MAX_SCAN_BYTES,
        chunk_size: int = _DEFAULT_SCAN_CHUNK,
    ) -> Mapping[str, Any]: ...


class UnavailableMemoryRuntimeBackend:
    """No-op backend used when Win32 process APIs are not available."""

    name = "unavailable"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def _result(self, operation: str, **details: Any) -> dict[str, Any]:
        return _prune(
            {
                "ok": False,
                "status": "unavailable",
                "operation": operation,
                "reason": self.unavailable_reason,
                "side_effects": False,
                **details,
            }
        )

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        return self._result(
            "probe_process",
            pid=pid,
            exists=None,
            accessible=False,
        )

    def enumerate_regions(self, pid: int) -> Sequence[Mapping[str, Any]]:
        del pid
        return []

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        del pid
        return []

    def read(self, pid: int, address: int, size: int) -> bytes:
        del pid, address, size
        return b""

    def write(self, pid: int, address: int, data: bytes, expected: bytes) -> Mapping[str, Any]:
        del data, expected
        return self._result("write", pid=pid, address=address)

    def protect(self, pid: int, address: int, size: int, protection: int) -> Mapping[str, Any]:
        return self._result(
            "protect",
            pid=pid,
            address=address,
            size=size,
            protection=protection,
        )

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        address: Optional[int] = None,
        allocation_type: int = 0x3000,
    ) -> Mapping[str, Any]:
        return self._result(
            "alloc",
            pid=pid,
            address=address,
            size=size,
            protection=protection,
            allocation_type=allocation_type,
        )

    def free(
        self,
        pid: int,
        address: int,
        *,
        size: int = 0,
        free_type: int = 0x8000,
    ) -> Mapping[str, Any]:
        return self._result(
            "free",
            pid=pid,
            address=address,
            size=size,
            free_type=free_type,
        )

    def scan(
        self,
        pid: int,
        pattern: bytes,
        *,
        mask: str,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_results: int = _DEFAULT_MAX_RESULTS,
        max_bytes: int = _DEFAULT_MAX_SCAN_BYTES,
        chunk_size: int = _DEFAULT_SCAN_CHUNK,
    ) -> Mapping[str, Any]:
        del pattern, mask, start_address, end_address, max_results, max_bytes, chunk_size
        return self._result("scan", pid=pid, matches=[])

    # Compatibility names are useful for lightweight injected backends.
    list_regions = enumerate_regions
    list_modules = enumerate_modules
    read_memory = read
    write_memory = write
    protect_memory = protect
    allocate_memory = alloc
    free_memory = free
    aob_scan = scan


class WindowsMemoryRuntimeBackend:
    """Win32 process-memory backend implemented with ``ctypes``."""

    name = "windows_ctypes"

    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    MEM_FREE = 0x10000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    ERROR_NO_MORE_FILES = 18
    ERROR_INVALID_PARAMETER = 87
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self) -> None:
        self.available = sys.platform == "win32"
        self.unavailable_reason: Optional[str] = None
        self._kernel32: Any = None
        self._memory_info_type: Any = None
        self._system_info_type: Any = None
        self._module_entry_type: Any = None
        if not self.available:
            self.unavailable_reason = f"Windows process-memory APIs are unavailable on {sys.platform}"
            return
        try:
            self._configure_api()
        except Exception as exc:  # pragma: no cover - host API dependent
            self.available = False
            self.unavailable_reason = f"failed to initialize Win32 memory API bindings: {exc}"

    def _configure_api(self) -> None:  # pragma: no cover - exercised on Windows
        from ctypes import wintypes

        byte_pointer = ctypes.POINTER(ctypes.c_ubyte)

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", wintypes.LPVOID),
                ("AllocationBase", wintypes.LPVOID),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        class SYSTEM_INFO(ctypes.Structure):
            _fields_ = [
                ("wProcessorArchitecture", wintypes.WORD),
                ("wReserved", wintypes.WORD),
                ("dwPageSize", wintypes.DWORD),
                ("lpMinimumApplicationAddress", wintypes.LPVOID),
                ("lpMaximumApplicationAddress", wintypes.LPVOID),
                ("dwActiveProcessorMask", ctypes.c_size_t),
                ("dwNumberOfProcessors", wintypes.DWORD),
                ("dwProcessorType", wintypes.DWORD),
                ("dwAllocationGranularity", wintypes.DWORD),
                ("wProcessorLevel", wintypes.WORD),
                ("wProcessorRevision", wintypes.WORD),
            ]

        class MODULEENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD),
                ("modBaseAddr", byte_pointer),
                ("modBaseSize", wintypes.DWORD),
                ("hModule", wintypes.HANDLE),
                ("szModule", wintypes.WCHAR * 256),
                ("szExePath", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        size_t = ctypes.c_size_t
        void_pointer = ctypes.c_void_p

        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.GetSystemInfo.argtypes = [ctypes.POINTER(SYSTEM_INFO)]
        kernel32.GetSystemInfo.restype = None
        kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            size_t,
        ]
        kernel32.VirtualQueryEx.restype = size_t
        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            void_pointer,
            size_t,
            ctypes.POINTER(size_t),
        ]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL
        kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            void_pointer,
            size_t,
            ctypes.POINTER(size_t),
        ]
        kernel32.WriteProcessMemory.restype = wintypes.BOOL
        kernel32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.VirtualProtectEx.restype = wintypes.BOOL
        kernel32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.VirtualAllocEx.restype = void_pointer
        kernel32.VirtualFreeEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
            wintypes.DWORD,
        ]
        kernel32.VirtualFreeEx.restype = wintypes.BOOL
        kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, void_pointer, size_t]
        kernel32.FlushInstructionCache.restype = wintypes.BOOL
        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
        kernel32.Module32FirstW.restype = wintypes.BOOL
        kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
        kernel32.Module32NextW.restype = wintypes.BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

        self._kernel32 = kernel32
        self._memory_info_type = MEMORY_BASIC_INFORMATION
        self._system_info_type = SYSTEM_INFO
        self._module_entry_type = MODULEENTRY32W

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        if not self.available:
            return {
                "pid": pid,
                "exists": None,
                "accessible": False,
                "status": "unavailable",
                "reason": self.unavailable_reason,
            }
        access = self.PROCESS_QUERY_LIMITED_INFORMATION
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            code = ctypes.get_last_error()
            return {
                "pid": pid,
                "exists": False if code == self.ERROR_INVALID_PARAMETER else None,
                "accessible": False,
                "status": "failed",
                "required_access": access,
                "winerror": code,
                "error": ctypes.FormatError(code).strip(),
            }
        try:
            from ctypes import wintypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(buffer))
            path = None
            if self._kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
                path = buffer.value
            return {
                "pid": pid,
                "exists": True,
                "accessible": True,
                "status": "ok",
                "required_access": access,
                "image_path": path,
            }
        finally:
            self._kernel32.CloseHandle(handle)

    def enumerate_regions(self, pid: int) -> Sequence[Mapping[str, Any]]:
        self._require_available("VirtualQueryEx")
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ
        process = self._open_process(pid, access, "VirtualQueryEx")
        try:
            return self._enumerate_regions_handle(process)
        finally:
            self._kernel32.CloseHandle(process)

    def _enumerate_regions_handle(self, process: Any) -> list[dict[str, Any]]:
        info = self._system_info_type()
        self._kernel32.GetSystemInfo(ctypes.byref(info))
        address = _pointer_value(info.lpMinimumApplicationAddress)
        maximum = _pointer_value(info.lpMaximumApplicationAddress)
        regions: list[dict[str, Any]] = []
        while address <= maximum:
            mbi = self._memory_info_type()
            queried = self._kernel32.VirtualQueryEx(
                process,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not queried:
                break
            base = _pointer_value(mbi.BaseAddress) or address
            size = int(mbi.RegionSize)
            if size <= 0:
                break
            protection = int(mbi.Protect)
            state = int(mbi.State)
            regions.append(
                {
                    "base_address": base,
                    "allocation_base": _pointer_value(mbi.AllocationBase),
                    "allocation_protection": int(mbi.AllocationProtect),
                    "size": size,
                    "state": state,
                    "protection": protection,
                    "protection_name": _protection_name(protection),
                    "type": int(mbi.Type),
                    "committed": state == self.MEM_COMMIT,
                    "readable": _is_readable_protection(protection) and state == self.MEM_COMMIT,
                    "writable": _is_writable_protection(protection) and state == self.MEM_COMMIT,
                    "executable": _is_executable_protection(protection) and state == self.MEM_COMMIT,
                }
            )
            next_address = base + size
            if next_address <= address:
                break
            address = next_address
        return regions

    def enumerate_modules(self, pid: int) -> Sequence[Mapping[str, Any]]:
        self._require_available("CreateToolhelp32Snapshot")
        flags = self.TH32CS_SNAPMODULE | self.TH32CS_SNAPMODULE32
        snapshot = self._kernel32.CreateToolhelp32Snapshot(flags, pid)
        if _pointer_value(snapshot) == self.INVALID_HANDLE_VALUE:
            raise self._last_error("CreateToolhelp32Snapshot")
        modules: list[dict[str, Any]] = []
        try:
            entry = self._module_entry_type()
            entry.dwSize = ctypes.sizeof(entry)
            if not self._kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
                code = ctypes.get_last_error()
                if code == self.ERROR_NO_MORE_FILES:
                    return []
                raise self._last_error("Module32FirstW", code=code)
            while True:
                modules.append(
                    {
                        "name": str(entry.szModule),
                        "path": str(entry.szExePath),
                        "base_address": _pointer_value(entry.modBaseAddr),
                        "size": int(entry.modBaseSize),
                    }
                )
                entry.dwSize = ctypes.sizeof(entry)
                if not self._kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                    code = ctypes.get_last_error()
                    if code != self.ERROR_NO_MORE_FILES:
                        raise self._last_error("Module32NextW", code=code)
                    break
        finally:
            self._kernel32.CloseHandle(snapshot)
        return sorted(modules, key=lambda item: item["base_address"])

    def read(self, pid: int, address: int, size: int) -> bytes:
        self._require_available("ReadProcessMemory")
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ
        process = self._open_process(pid, access, "ReadProcessMemory")
        try:
            return self._read_handle(process, address, size, exact=True)
        finally:
            self._kernel32.CloseHandle(process)

    def write(self, pid: int, address: int, data: bytes, expected: bytes) -> Mapping[str, Any]:
        """Write only after an exact expected-byte check on the same handle."""

        self._require_available("WriteProcessMemory")
        access = (
            self.PROCESS_QUERY_INFORMATION
            | self.PROCESS_VM_READ
            | self.PROCESS_VM_WRITE
            | self.PROCESS_VM_OPERATION
        )
        process = self._open_process(pid, access, "WriteProcessMemory")
        try:
            before = self._read_handle(process, address, len(expected), exact=True)
            if before != expected:
                return {
                    "ok": False,
                    "status": "precondition_failed",
                    "operation": "WriteProcessMemory",
                    "pid": pid,
                    "address": address,
                    "expected_hex": expected.hex(),
                    "actual_hex": before.hex(),
                    "bytes_written": 0,
                    "side_effects": False,
                }
            written = ctypes.c_size_t(0)
            buffer = ctypes.create_string_buffer(data, len(data))
            ok = self._kernel32.WriteProcessMemory(
                process,
                ctypes.c_void_p(address),
                buffer,
                len(data),
                ctypes.byref(written),
            )
            if not ok or written.value != len(data):
                code = ctypes.get_last_error()
                return {
                    "ok": False,
                    "status": "failed",
                    "operation": "WriteProcessMemory",
                    "pid": pid,
                    "address": address,
                    "requested_bytes": len(data),
                    "bytes_written": int(written.value),
                    "winerror": code,
                    "error": ctypes.FormatError(code).strip() if code else "partial process-memory write",
                    "side_effects": bool(written.value),
                }
            self._kernel32.FlushInstructionCache(process, ctypes.c_void_p(address), len(data))
            after = self._read_handle(process, address, len(data), exact=True)
            verified = after == data
            return {
                "ok": verified,
                "status": "ok" if verified else "failed",
                "operation": "WriteProcessMemory",
                "pid": pid,
                "address": address,
                "requested_bytes": len(data),
                "bytes_written": int(written.value),
                "before_hex": before.hex(),
                "after_hex": after.hex(),
                "verified": verified,
                "side_effects": True,
                "error": None if verified else "post-write verification failed",
            }
        finally:
            self._kernel32.CloseHandle(process)

    def protect(self, pid: int, address: int, size: int, protection: int) -> Mapping[str, Any]:
        self._require_available("VirtualProtectEx")
        from ctypes import wintypes

        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_OPERATION
        process = self._open_process(pid, access, "VirtualProtectEx")
        try:
            old = wintypes.DWORD(0)
            ok = self._kernel32.VirtualProtectEx(
                process,
                ctypes.c_void_p(address),
                size,
                protection,
                ctypes.byref(old),
            )
            if not ok:
                raise self._last_error("VirtualProtectEx")
            return {
                "ok": True,
                "status": "ok",
                "operation": "VirtualProtectEx",
                "pid": pid,
                "address": address,
                "size": size,
                "old_protection": int(old.value),
                "new_protection": protection,
                "side_effects": int(old.value) != protection,
            }
        finally:
            self._kernel32.CloseHandle(process)

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        address: Optional[int] = None,
        allocation_type: int = MEM_COMMIT | MEM_RESERVE,
    ) -> Mapping[str, Any]:
        self._require_available("VirtualAllocEx")
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_OPERATION
        process = self._open_process(pid, access, "VirtualAllocEx")
        try:
            pointer = self._kernel32.VirtualAllocEx(
                process,
                ctypes.c_void_p(address) if address is not None else None,
                size,
                allocation_type,
                protection,
            )
            allocated = _pointer_value(pointer)
            if not allocated:
                raise self._last_error("VirtualAllocEx")
            return {
                "ok": True,
                "status": "ok",
                "operation": "VirtualAllocEx",
                "pid": pid,
                "address": allocated,
                "requested_address": address,
                "size": size,
                "protection": protection,
                "allocation_type": allocation_type,
                "side_effects": True,
            }
        finally:
            self._kernel32.CloseHandle(process)

    def free(
        self,
        pid: int,
        address: int,
        *,
        size: int = 0,
        free_type: int = MEM_RELEASE,
    ) -> Mapping[str, Any]:
        self._require_available("VirtualFreeEx")
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_OPERATION
        process = self._open_process(pid, access, "VirtualFreeEx")
        try:
            ok = self._kernel32.VirtualFreeEx(
                process,
                ctypes.c_void_p(address),
                size,
                free_type,
            )
            if not ok:
                raise self._last_error("VirtualFreeEx")
            return {
                "ok": True,
                "status": "ok",
                "operation": "VirtualFreeEx",
                "pid": pid,
                "address": address,
                "size": size,
                "free_type": free_type,
                "side_effects": True,
            }
        finally:
            self._kernel32.CloseHandle(process)

    def scan(
        self,
        pid: int,
        pattern: bytes,
        *,
        mask: str,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_results: int = _DEFAULT_MAX_RESULTS,
        max_bytes: int = _DEFAULT_MAX_SCAN_BYTES,
        chunk_size: int = _DEFAULT_SCAN_CHUNK,
    ) -> Mapping[str, Any]:
        self._require_available("ReadProcessMemory")
        if not pattern or len(mask) != len(pattern):
            raise ValueError("pattern and mask must be non-empty and have equal length")
        access = self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ
        process = self._open_process(pid, access, "AoB scan")
        matches: list[int] = []
        scanned = 0
        truncated = False
        try:
            regions = self._enumerate_regions_handle(process)
            for region in regions:
                if not region.get("readable"):
                    continue
                region_start = int(region["base_address"])
                region_end = region_start + int(region["size"])
                scan_start = max(region_start, start_address or region_start)
                scan_end = min(region_end, end_address if end_address is not None else region_end)
                if scan_start >= scan_end:
                    continue
                cursor = scan_start
                carry = b""
                while cursor < scan_end:
                    if scanned >= max_bytes or len(matches) >= max_results:
                        truncated = True
                        break
                    request_size = min(chunk_size, scan_end - cursor, max_bytes - scanned)
                    if request_size <= 0:
                        truncated = True
                        break
                    try:
                        block = self._read_handle(process, cursor, request_size, exact=False)
                    except MemoryRuntimeBackendError:
                        break
                    if not block:
                        break
                    combined = carry + block
                    combined_base = cursor - len(carry)
                    for offset in _pattern_offsets(combined, pattern, mask):
                        address = combined_base + offset
                        if address < scan_start or address + len(pattern) > scan_end:
                            continue
                        if not matches or address != matches[-1]:
                            matches.append(address)
                            if len(matches) >= max_results:
                                truncated = True
                                break
                    scanned += len(block)
                    cursor += len(block)
                    carry = combined[-(len(pattern) - 1) :] if len(pattern) > 1 else b""
                    if len(block) < request_size or len(matches) >= max_results:
                        break
                if truncated:
                    break
        finally:
            self._kernel32.CloseHandle(process)
        return {
            "ok": True,
            "status": "ok",
            "operation": "aob_scan",
            "pid": pid,
            "pattern_hex": pattern.hex(),
            "mask": mask,
            "matches": matches,
            "match_count": len(matches),
            "scanned_bytes": scanned,
            "truncated": truncated,
            "side_effects": False,
        }

    def _read_handle(self, process: Any, address: int, size: int, *, exact: bool) -> bytes:
        if size < 0:
            raise ValueError("size must be non-negative")
        if size == 0:
            return b""
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = self._kernel32.ReadProcessMemory(
            process,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(read),
        )
        if (not ok and read.value == 0) or (exact and read.value != size):
            raise self._last_error(
                "ReadProcessMemory",
                details={"address": address, "requested": size, "read": int(read.value)},
            )
        return buffer.raw[: read.value]

    def _open_process(self, pid: int, access: int, operation: str) -> Any:
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            raise self._last_error(operation, details={"pid": pid, "access": access})
        return handle

    def _last_error(
        self,
        operation: str,
        *,
        code: Optional[int] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> MemoryRuntimeBackendError:
        error_code = ctypes.get_last_error() if code is None else code
        return MemoryRuntimeBackendError(
            operation,
            ctypes.FormatError(error_code).strip() or "Win32 API call failed",
            code=error_code,
            details=details,
        )

    def _require_available(self, operation: str) -> None:
        if not self.available or self._kernel32 is None:
            raise MemoryRuntimeBackendError(
                operation,
                self.unavailable_reason or "Win32 process-memory APIs are unavailable",
            )

    list_regions = enumerate_regions
    list_modules = enumerate_modules
    read_memory = read
    write_memory = write
    protect_memory = protect
    allocate_memory = alloc
    free_memory = free
    aob_scan = scan


class MemoryRuntimeProvider:
    """Plan, validate, execute, roll back, and audit process-memory actions."""

    capability_name = "memory_runtime"
    provider_name = "windows_memory_runtime"
    priority = 10

    def __init__(
        self,
        backend: Optional[MemoryRuntimeBackend] = None,
        *,
        platform_name: Optional[str] = None,
        max_read_bytes: int = _DEFAULT_MAX_READ,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.max_read_bytes = max(1, int(max_read_bytes))
        if backend is not None:
            self.backend: MemoryRuntimeBackend = backend
        elif self.platform_name == "win32":
            self.backend = WindowsMemoryRuntimeBackend()
        else:
            self.backend = UnavailableMemoryRuntimeBackend(
                f"Windows process-memory APIs are unavailable on {self.platform_name}"
            )
        self._write_guard = threading.RLock()
        self._write_locked = False
        self._write_lock_details: dict[str, Any] = {}

    @property
    def write_locked(self) -> bool:
        """Whether a prior write failure has closed the write path."""

        return self._write_locked

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
        backend = self._select_backend(context)
        action = _normalize_action(request.action)
        session_id = request.session_id or "memory-runtime-session"
        raw_pid, pid, pid_conflict = _request_pid(request)
        parameters = _normalize_parameters(
            action,
            request.params,
            max_read_bytes=self.max_read_bytes,
        )
        parameters.update(
            {
                "pid": pid if pid is not None else raw_pid,
                "pid_conflict": pid_conflict,
                "requested_action": request.action,
            }
        )
        _resolve_planned_module_address(backend, action, parameters)
        before_snapshot = _capture_state(
            backend,
            action,
            parameters,
            max_capture_bytes=self.max_read_bytes,
        )
        if action == "free":
            allocation_size = _coerce_int(
                (before_snapshot.get("allocation") or {}).get("size")
            )
            if allocation_size and allocation_size > 0:
                parameters["size"] = allocation_size
        before_snapshot.update(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "plan",
                "platform": self.platform_name,
                "backend": _backend_info(backend, self.platform_name),
            }
        )
        precondition_hash = _state_precondition_hash(action, before_snapshot, parameters)
        before_snapshot["precondition_hash"] = precondition_hash
        rollback_plan = _initial_rollback_plan(action, parameters, before_snapshot)
        rollback_plan["precondition_hash"] = precondition_hash
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
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "backend": _backend_info(backend, self.platform_name),
                "platform": self.platform_name,
                "requested_action": request.action,
                "action": action,
                "pid": pid if pid is not None else raw_pid,
                "mutating": action in _MUTATING_ACTIONS,
                "precondition_hash": precondition_hash,
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        validation, _ = self._validate_plan(plan, context=context)
        return validation

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        action = _normalize_action(plan.action)
        validation, validated_snapshot = self._validate_plan(plan, context=context)
        before_snapshot = dict(validated_snapshot or plan.before_snapshot or {})
        before_snapshot.update(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "before",
                "precondition_hash": plan.precondition_hash,
            }
        )

        if not _backend_available(backend):
            reason = _backend_reason(backend)
            return self._result(
                plan,
                status="unavailable",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "status": "unavailable",
                    "reason": reason,
                },
                rollback_plan=_not_required_rollback(plan.rollback_plan, "unavailable", reason),
                operation={"status": "unavailable", "reason": reason, "side_effects": False},
                errors=[reason],
            )

        target_pid = _coerce_int(plan.parameters.get("pid"))
        if not target_pid or target_pid <= 0:
            reason = "target PID is unavailable"
            return self._result(
                plan,
                status="unavailable",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "status": "unavailable",
                    "reason": reason,
                },
                rollback_plan=_not_required_rollback(
                    plan.rollback_plan, "unavailable", reason
                ),
                operation={
                    "status": "unavailable",
                    "reason": reason,
                    "side_effects": False,
                },
                errors=[reason],
            )

        api_name = _ACTION_BACKEND_OPERATION.get(action)
        if action in _SUPPORTED_ACTIONS and not (
            api_name and _backend_method(backend, api_name, required=False)
        ):
            reason = f"backend does not implement the {api_name or action} operation"
            return self._result(
                plan,
                status="unavailable",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "status": "unavailable",
                    "reason": reason,
                },
                rollback_plan=_not_required_rollback(
                    plan.rollback_plan, "unavailable", reason
                ),
                operation={
                    "status": "unavailable",
                    "reason": reason,
                    "side_effects": False,
                },
                errors=[reason],
            )

        if action not in _SUPPORTED_ACTIONS or not validation.ok:
            reason = (
                f"unsupported memory_runtime action: {action or plan.action}"
                if action not in _SUPPORTED_ACTIONS
                else "execution was blocked by plan validation"
            )
            return self._result(
                plan,
                status="failed",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "status": "blocked",
                },
                rollback_plan=_not_required_rollback(plan.rollback_plan, "blocked", reason),
                operation={"status": "blocked", "reason": reason, "side_effects": False},
                errors=list(validation.errors) or [reason],
            )

        pid = int(_coerce_int(plan.parameters.get("pid")) or 0)
        operation: dict[str, Any]
        errors: list[Any] = []
        rollback_plan = dict(plan.rollback_plan or {})
        try:
            operation = self._execute_action(backend, action, pid, plan.parameters)
        except Exception as exc:  # backend failures stay in the audit result
            operation = {
                "ok": False,
                "status": "failed",
                "operation": action,
                "error": _exception_payload(exc),
                "side_effects": "unknown" if action in _MUTATING_ACTIONS else False,
            }

        after_snapshot = _capture_state(
            backend,
            action,
            plan.parameters,
            max_capture_bytes=self.max_read_bytes,
        )
        after_snapshot.update(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "after",
                "operation": operation,
            }
        )
        status, verification_errors = self._verify_execution(
            action,
            plan.parameters,
            before_snapshot,
            after_snapshot,
            operation,
        )
        errors.extend(verification_errors)
        if status != "ok" and operation.get("error"):
            errors.append(operation["error"])

        if action in _WRITE_ACTIONS and status != "ok":
            self._latch_write_failure(plan, operation, after_snapshot, errors)
        after_snapshot["side_effects"] = _side_effects_observed(
            action,
            before_snapshot,
            after_snapshot,
            operation,
        )
        rollback_plan = _completed_rollback_metadata(
            action,
            rollback_plan,
            plan.parameters,
            before_snapshot,
            after_snapshot,
            operation,
            status,
        )
        after_snapshot["postcondition_hash"] = _state_precondition_hash(
            action,
            after_snapshot,
            plan.parameters,
        )
        return self._result(
            plan,
            status=status,
            validation=validation,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            operation=operation,
            errors=errors,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        backend = self._select_backend(context)
        action = _normalize_action(result.action)
        rollback_plan = dict(result.rollback_plan or {})
        base_details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "action": action,
            "session_id": result.session_id,
            "session": {"id": result.session_id},
            "target": _target_payload(result.target),
            "precondition": {
                "hash": result.provenance.get("precondition_hash"),
            },
            "precondition_hash": result.provenance.get("precondition_hash"),
            "rollback": rollback_plan,
            "rollback_metadata": rollback_plan,
            "provenance": dict(result.provenance or {}),
        }
        if action not in _MUTATING_ACTIONS:
            details = {
                **base_details,
                "status": "not_required",
                "reason": "read-only action",
            }
            self._record_rollback(
                result,
                details,
                ok=True,
                restored=False,
                attempted=False,
            )
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details=details,
            )
        if not _backend_available(backend):
            details = {
                **base_details,
                "status": "unavailable",
                "reason": _backend_reason(backend),
            }
            self._record_rollback(
                result,
                details,
                ok=False,
                restored=False,
                attempted=False,
            )
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details=details,
            )
        if not rollback_plan.get("supported"):
            not_required = rollback_plan.get("mode") == "not_required"
            details = {
                **base_details,
                "status": "not_required" if not_required else "failed",
                "reason": rollback_plan.get("reason")
                or "rollback metadata is incomplete",
            }
            self._record_rollback(
                result,
                details,
                ok=not_required,
                restored=False,
                attempted=False,
            )
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=not_required,
                restored=False,
                details=details,
            )

        pid = _coerce_int(rollback_plan.get("pid"))
        before: dict[str, Any] = {}
        after: dict[str, Any] = {}
        operation: dict[str, Any]
        errors: list[Any] = []
        restored = False
        try:
            if not pid or pid <= 0:
                raise ValueError("rollback PID is invalid")
            if action in _WRITE_ACTIONS:
                address = _required_int(rollback_plan, "address")
                original = _hex_bytes(rollback_plan.get("before_hex"), "rollback before_hex")
                current = _backend_read(backend, pid, address, len(original))
                before = _bytes_snapshot(current, address=address)
                if current == original:
                    operation = {"ok": True, "status": "already_restored", "side_effects": False}
                else:
                    operation = _mapping_result(
                        _backend_write(backend, pid, address, original, current),
                        operation="write_rollback",
                    )
                restored_bytes = _backend_read(backend, pid, address, len(original))
                after = _bytes_snapshot(restored_bytes, address=address)
                restored = _operation_ok(operation) and restored_bytes == original
                if not restored:
                    self._latch_rollback_write_failure(result, operation, after)
            elif action == "protect":
                address = _required_int(rollback_plan, "address")
                size = _required_int(rollback_plan, "size")
                old_protection = _required_int(rollback_plan, "old_protection")
                before = _region_snapshot_for(backend, pid, address)
                operation = _mapping_result(
                    _backend_protect(backend, pid, address, size, old_protection),
                    operation="protect_rollback",
                )
                after = _region_snapshot_for(backend, pid, address)
                restored = _operation_ok(operation) and _region_protection(after) == old_protection
            elif action == "alloc":
                address = _required_int(rollback_plan, "address")
                before = _region_snapshot_for(backend, pid, address)
                operation = _mapping_result(
                    _backend_free(backend, pid, address, size=0, free_type=0x8000),
                    operation="alloc_rollback",
                )
                after = _region_snapshot_for(backend, pid, address)
                restored = _operation_ok(operation) and not after.get("present", False)
            else:
                address = _required_int(rollback_plan, "address")
                size = _required_int(rollback_plan, "size")
                protection = _required_int(rollback_plan, "protection")
                original = _hex_bytes(rollback_plan.get("before_hex"), "rollback before_hex")
                before = _region_snapshot_for(backend, pid, address)
                allocation = _mapping_result(
                    _backend_alloc(
                        backend,
                        pid,
                        size,
                        _PAGE_PROTECTIONS["PAGE_READWRITE"],
                        address=address,
                        allocation_type=0x3000,
                    ),
                    operation="free_rollback_alloc",
                )
                allocated_address = _operation_address(allocation)
                if not _operation_ok(allocation) or allocated_address != address:
                    operation = allocation
                else:
                    zeroes = _backend_read(backend, pid, address, len(original))
                    write_result = _mapping_result(
                        _backend_write(backend, pid, address, original, zeroes),
                        operation="free_rollback_write",
                    )
                    protect_result = _mapping_result(
                        _backend_protect(backend, pid, address, size, protection),
                        operation="free_rollback_protect",
                    )
                    operation = {
                        "ok": _operation_ok(write_result) and _operation_ok(protect_result),
                        "status": (
                            "ok"
                            if _operation_ok(write_result) and _operation_ok(protect_result)
                            else "failed"
                        ),
                        "allocation": allocation,
                        "write": write_result,
                        "protect": protect_result,
                        "side_effects": True,
                    }
                    if not _operation_ok(write_result):
                        self._latch_rollback_write_failure(result, write_result, {})
                restored_bytes = _backend_read(backend, pid, address, len(original))
                after = {
                    **_region_snapshot_for(backend, pid, address),
                    "memory": _bytes_snapshot(restored_bytes, address=address),
                }
                restored = (
                    _operation_ok(operation)
                    and restored_bytes == original
                    and _region_protection(after) == protection
                )
        except Exception as exc:
            operation = {
                "ok": False,
                "status": "failed",
                "error": _exception_payload(exc),
                "side_effects": "unknown",
            }
            errors.append(operation["error"])

        status = "ok" if restored else "failed"
        rollback_plan.update(
            {
                "completed": restored,
                "rollback_status": status,
                "rollback_operation": operation,
            }
        )
        result.rollback_plan = rollback_plan
        details = {
            **base_details,
            "status": status,
            "restored": restored,
            "before": before,
            "after": after,
            "operation": operation,
            "errors": errors,
            "write_locked": self._write_locked,
        }
        self._record_rollback(
            result,
            details,
            ok=restored,
            restored=restored,
            attempted=True,
        )
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=restored,
            restored=restored,
            details=_prune(details),
        )

    def _record_rollback(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        *,
        ok: bool,
        restored: bool,
        attempted: bool,
    ) -> None:
        payload = _prune(dict(details))
        status = str(payload.get("status") or ("ok" if ok else "failed"))
        result.rollback_plan.update(
            {
                "rollback_attempted": attempted,
                "rollback_status": status,
                "completed": ok,
                "restored": restored,
            }
        )
        result.after_snapshot["rollback"] = payload
        result.report_section["rollback"] = payload
        _sync_audit_report(result)
        result.dashboard_trace.append(
            {
                "kind": "memory_runtime_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "action": result.action,
                "session_id": result.session_id,
                "status": status,
                "restored": restored,
                "attempted": attempted,
            }
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        collection_root = Path(out_dir).expanduser().resolve()
        collection_root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or [])
        entries_by_path = {
            str(entry.get("path")): dict(entry)
            for entry in result.evidence_manifest_entries or []
            if entry.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        audit_payload = _memory_runtime_audit_payload(result)
        for artifact in artifacts:
            artifact.metadata.setdefault("collection_root", str(collection_root))
            destination = _artifact_destination(collection_root, artifact.path)
            entry = entries_by_path.get(
                artifact.path,
                {
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "path": artifact.path,
                    "kind": artifact.kind,
                    "tool": self.capability_name,
                    "provider": self.provider_name,
                    "status": result.status,
                    "role": "memory-runtime-audit",
                    "session_id": result.session_id,
                    "action": result.action,
                    "pid": result.target.pid,
                },
            )
            if artifact.kind == "memory-runtime-audit":
                destination.parent.mkdir(parents=True, exist_ok=True)
                encoded = (
                    json.dumps(
                        audit_payload,
                        indent=2,
                        sort_keys=True,
                        ensure_ascii=True,
                    )
                    + "\n"
                ).encode("utf-8")
                destination.write_bytes(encoded)
                digest = hashlib.sha256(encoded).hexdigest()
                artifact.metadata.update(
                    {
                        "materialized": True,
                        "sha256": digest,
                        "size": len(encoded),
                    }
                )
                entry.update(
                    {
                        "materialized": True,
                        "sha256": digest,
                        "size": len(encoded),
                    }
                )
            manifest_entries.append(entry)

        result.artifacts = artifacts
        result.evidence_manifest_entries = manifest_entries
        _sync_audit_report(result)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        backend = self._select_backend(context)
        action = _normalize_action(plan.action)
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

        check(
            "capability_identity",
            plan.capability == self.capability_name and plan.provider == self.provider_name,
            "plan capability/provider identity does not match memory_runtime provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        check(
            "supported_action",
            action in _SUPPORTED_ACTIONS,
            f"unsupported memory_runtime action: {action or plan.action}",
            action=action,
        )
        pid = _coerce_int(plan.parameters.get("pid"))
        planned_pid = _coerce_int((plan.before_snapshot.get("process") or {}).get("pid"))
        target_pid = _coerce_int(getattr(plan.target, "pid", None))
        pid_ok = bool(pid and pid > 0 and not plan.parameters.get("pid_conflict"))
        if planned_pid is not None:
            pid_ok = pid_ok and pid == planned_pid
        if target_pid is not None:
            pid_ok = pid_ok and pid == target_pid
        check(
            "target_pid",
            pid_ok,
            "target PID must be positive and match the planned target identity",
            pid=pid,
            planned_pid=planned_pid,
            target_pid=target_pid,
        )
        parse_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        check(
            "parameters",
            not parse_errors,
            "; ".join(parse_errors) if parse_errors else "action parameters are valid",
        )

        api_name = _ACTION_BACKEND_OPERATION.get(action)
        api_present = bool(api_name and _backend_method(backend, api_name, required=False))
        if api_present:
            check(
                "backend_api",
                True,
                "backend implements the requested operation",
                operation=api_name or action,
            )
        else:
            reason = f"backend does not implement the {api_name or action} operation"
            checks.append(
                {
                    "name": "backend_api",
                    "status": "unavailable",
                    "message": reason,
                    "operation": api_name or action,
                }
            )
            warnings.append(reason)

        if not _backend_available(backend):
            reason = _backend_reason(backend)
            checks.append(
                {
                    "name": "windows_backend",
                    "status": "unavailable",
                    "message": reason,
                    "platform": self.platform_name,
                }
            )
            warnings.append(reason)
            return (
                CapabilityValidation(
                    capability=plan.capability,
                    provider=plan.provider,
                    session_id=plan.session_id,
                    ok=not errors,
                    checks=checks,
                    warnings=warnings,
                    errors=_deduplicate(errors),
                ),
                dict(plan.before_snapshot or {}),
            )

        current: dict[str, Any] = {}
        if pid and pid > 0:
            current = _capture_state(
                backend,
                action,
                plan.parameters,
                max_capture_bytes=self.max_read_bytes,
            )
            probe = current.get("process") or {}
            process_ok = bool(probe.get("accessible") and probe.get("status") == "ok")
            check(
                "process_access",
                process_ok,
                "target process is not accessible",
                process=probe,
            )

        if _has_module_rva_spec(plan.parameters):
            planned_resolution = plan.parameters.get("module_resolution") or {}
            current_resolution = current.get("module_resolution") or {}
            resolution_ok = bool(
                planned_resolution.get("status") == "ok"
                and current_resolution.get("status") == "ok"
                and _module_resolution_identity(planned_resolution)
                == _module_resolution_identity(current_resolution)
                and _coerce_int(current_resolution.get("address_int"))
                == _coerce_int(plan.parameters.get("address"))
            )
            check(
                "module_rva_resolution",
                resolution_ok,
                "live module+RVA resolution does not match the planned address",
                planned=planned_resolution,
                current=current_resolution,
            )

        if action == "typed_read":
            memory = _snapshot_bytes(current.get("memory"))
            expected_size = _coerce_int(plan.parameters.get("size"))
            check(
                "typed_read_capture",
                memory is not None and len(memory) == expected_size,
                "typed read could not capture the complete scalar value",
                expected_size=expected_size,
                captured_size=len(memory) if memory is not None else None,
            )
        if action == "string_read":
            string_capture = current.get("string") or {}
            check(
                "string_read_capture",
                string_capture.get("status") == "ok",
                "string read could not capture a bounded string",
                string=string_capture,
            )
        if action == "pointer_chain":
            chain = current.get("pointer_chain") or {}
            check(
                "pointer_chain_resolution",
                chain.get("status") == "ok",
                "pointer chain could not be resolved",
                pointer_chain=chain,
            )
        if action == "schema_read":
            memory = _snapshot_bytes(current.get("memory"))
            expected_size = _coerce_int(plan.parameters.get("schema_size"))
            structured = current.get("structured_value") or {}
            check(
                "schema_read_capture",
                memory is not None
                and len(memory) == expected_size
                and structured.get("size") == expected_size,
                "structured read could not capture and decode the complete schema",
                expected_size=expected_size,
                captured_size=len(memory) if memory is not None else None,
            )

        if action == "write":
            expected = _parameter_bytes(plan.parameters, "expected_hex")
            replacement = _parameter_bytes(plan.parameters, "data_hex")
            current_bytes = _snapshot_bytes(current.get("memory"))
            check(
                "write_expected_bytes",
                bool(expected is not None and replacement),
                "write requires non-empty data and explicit expected bytes",
            )
            if expected is not None and current_bytes is not None:
                check(
                    "write_preimage",
                    current_bytes == expected,
                    "current bytes do not match the write expected-byte precondition",
                    expected_hex=expected.hex(),
                    actual_hex=current_bytes.hex(),
                )
            check(
                "write_fail_closed_latch",
                not self._write_locked,
                "write path is locked after a prior write failure",
                lock_details=self._write_lock_details,
            )
        if action == "schema_write":
            memory = _snapshot_bytes(current.get("memory"))
            expected_size = _coerce_int(plan.parameters.get("schema_size"))
            field = current.get("structured_field") or {}
            check(
                "schema_write_capture",
                memory is not None and len(memory) == expected_size,
                "schema write could not capture the complete structure",
                expected_size=expected_size,
                captured_size=len(memory) if memory is not None else None,
            )
            check(
                "schema_write_field_precondition",
                "value" in field
                and field.get("value") == plan.parameters.get("expected_field_value"),
                "current field value does not match the schema-write precondition",
                path=plan.parameters.get("field_path"),
                expected=plan.parameters.get("expected_field_value"),
                actual=field.get("value"),
            )
            check(
                "write_fail_closed_latch",
                not self._write_locked,
                "write path is locked after a prior write failure",
                lock_details=self._write_lock_details,
            )
        if action == "alloc":
            allocation_type = _coerce_int(plan.parameters.get("allocation_type"))
            check(
                "alloc_release_rollback",
                allocation_type == (_MEM_COMMIT | _MEM_RESERVE),
                "alloc requires MEM_COMMIT|MEM_RESERVE so rollback can release the allocation",
                allocation_type=allocation_type,
            )
            requested_address = _coerce_int(plan.parameters.get("address"))
            if requested_address is not None:
                check(
                    "alloc_target_available",
                    not bool(current.get("region")),
                    "requested allocation address is already allocated",
                    address=requested_address,
                    region=current.get("region"),
                )
        if action == "free":
            region = current.get("region") or {}
            allocation = current.get("allocation") or {}
            address = _coerce_int(plan.parameters.get("address"))
            allocation_base = _region_allocation_base(region)
            free_type = _coerce_int(plan.parameters.get("free_type"))
            free_size = _coerce_int(plan.parameters.get("free_size"))
            check(
                "free_release_mode",
                free_type == _MEM_RELEASE and free_size == 0,
                "free requires MEM_RELEASE with a zero VirtualFreeEx size",
                free_type=free_type,
                free_size=free_size,
            )
            check(
                "free_allocation_base",
                bool(region and address is not None and allocation_base == address),
                "free requires the exact allocation base so rollback metadata is complete",
                address=address,
                allocation_base=allocation_base,
            )
            allocation_size = _coerce_int(allocation.get("size"))
            check(
                "free_single_region_allocation",
                bool(allocation.get("recoverable")),
                "free only supports a readable committed private allocation represented by one region",
                allocation=allocation,
            )
            requested_size = _coerce_int(plan.parameters.get("requested_size"))
            check(
                "free_complete_size",
                bool(
                    allocation_size
                    and requested_size in (None, 0, allocation_size)
                    and _coerce_int(plan.parameters.get("size")) == allocation_size
                ),
                "free size must be zero, omitted, or equal to the complete allocation size",
                requested_size=requested_size,
                allocation_size=allocation_size,
            )
            check(
                "free_capture_limit",
                bool(allocation_size and allocation_size <= self.max_read_bytes),
                "free allocation exceeds the rollback capture limit",
                allocation_size=allocation_size,
                max_capture_bytes=self.max_read_bytes,
            )
            captured = _snapshot_bytes(current.get("memory"))
            check(
                "free_rollback_capture",
                captured is not None and len(captured) == allocation_size,
                "free requires a complete allocation byte snapshot for rollback",
                captured_size=len(captured) if captured is not None else None,
                allocation_size=allocation_size,
            )
        if action == "protect":
            region = current.get("region") or {}
            address = _coerce_int(plan.parameters.get("address"))
            size = _coerce_int(plan.parameters.get("size"))
            check(
                "protect_region",
                bool(region),
                "protect range does not start in a known memory region",
            )
            check(
                "protect_single_region_range",
                bool(
                    region
                    and address is not None
                    and size is not None
                    and _region_is_committed(region)
                    and _region_contains_range(region, address, size)
                ),
                "protect range must stay within one committed memory region",
                address=address,
                size=size,
                region=region,
            )
            expected_protection = _coerce_int(
                plan.parameters.get("expected_protection")
            )
            if expected_protection is not None:
                current_protection = _region_protection(region)
                check(
                    "protect_expected_protection",
                    current_protection == expected_protection,
                    "current page protection does not match expected_protection",
                    expected=expected_protection,
                    expected_name=_protection_name(expected_protection),
                    actual=current_protection,
                    actual_name=(
                        _protection_name(current_protection)
                        if current_protection is not None
                        else None
                    ),
                )

        if action in _MUTATING_ACTIONS:
            current_hash = _state_precondition_hash(action, current, plan.parameters)
            check(
                "precondition_hash",
                bool(plan.precondition_hash and current_hash == plan.precondition_hash),
                "live process state no longer matches the planned precondition hash",
                expected=plan.precondition_hash,
                actual=current_hash,
            )
        return (
            CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=warnings,
                errors=_deduplicate(errors),
            ),
            current,
        )

    def _execute_action(
        self,
        backend: MemoryRuntimeBackend,
        action: str,
        pid: int,
        parameters: Mapping[str, Any],
    ) -> dict[str, Any]:
        if action == "probe":
            return _mapping_result(_backend_probe(backend, pid), operation="probe_process")
        if action == "regions":
            regions = _backend_regions(backend, pid)
            return {
                "ok": True,
                "status": "ok",
                "operation": "enumerate_regions",
                "regions": regions,
                "region_count": len(regions),
                "side_effects": False,
            }
        if action == "schema_read":
            address = _required_int(parameters, "address")
            size = _required_int(parameters, "schema_size")
            data = _backend_read(backend, pid, address, size)
            if len(data) != size:
                raise MemoryRuntimeBackendError(
                    "schema_read",
                    "backend returned fewer bytes than the compiled schema requires",
                    details={"expected_size": size, "actual_size": len(data)},
                )
            schema = parameters.get("schema")
            if not isinstance(schema, Mapping):
                raise ValueError("compiled schema metadata is unavailable")
            operation = {
                "ok": True,
                "status": "ok",
                "operation": "schema_read",
                "address": address,
                "schema": parameters.get("schema_layout"),
                "structured_value": decode_structure(data, schema),
                "memory": _bytes_snapshot(data, address=address),
                "side_effects": False,
            }
            field_path = str(parameters.get("field_path") or "").strip()
            if field_path:
                operation["structured_field"] = {
                    "path": field_path,
                    "value": read_structure_field(data, schema, field_path),
                }
            return operation
        if action == "modules":
            modules = _backend_modules(backend, pid)
            return {
                "ok": True,
                "status": "ok",
                "operation": "enumerate_modules",
                "modules": modules,
                "module_count": len(modules),
                "side_effects": False,
            }
        if action == "module_rva":
            resolution = _resolve_module_rva(
                _backend_modules(backend, pid),
                str(parameters.get("module") or ""),
                parameters.get("rva"),
            )
            return {
                "ok": True,
                "status": "ok",
                "operation": "resolve_module_rva",
                "resolution": resolution,
                "address": resolution.get("address_int"),
                "side_effects": False,
            }
        if action == "read":
            address = _required_int(parameters, "address")
            size = _required_int(parameters, "size")
            data = _backend_read(backend, pid, address, size)
            return {
                "ok": len(data) == size,
                "status": "ok" if len(data) == size else "failed",
                "operation": "read",
                "memory": _bytes_snapshot(data, address=address),
                "side_effects": False,
            }
        if action == "typed_read":
            address = _required_int(parameters, "address")
            size = _required_int(parameters, "size")
            data = _backend_read(backend, pid, address, size)
            if len(data) != size:
                raise MemoryRuntimeBackendError(
                    "typed_read",
                    "backend returned fewer bytes than requested",
                    details={"expected_size": size, "actual_size": len(data)},
                )
            value = _decode_typed_value(
                data,
                str(parameters.get("value_type")),
                str(parameters.get("endian")),
            )
            return {
                "ok": True,
                "status": "ok",
                "operation": "typed_read",
                "address": address,
                "value_type": parameters.get("value_type"),
                "endian": parameters.get("endian"),
                "value": value,
                "memory": _bytes_snapshot(data, address=address),
                "side_effects": False,
            }
        if action == "string_read":
            result = _read_bounded_string(
                backend,
                pid,
                _required_int(parameters, "address"),
                str(parameters.get("encoding")),
                _required_int(parameters, "max_bytes"),
            )
            return {
                "ok": True,
                "status": "ok",
                "operation": "string_read",
                **result,
                "side_effects": False,
            }
        if action == "pointer_chain":
            result = _resolve_pointer_chain(
                backend,
                pid,
                _required_int(parameters, "address"),
                parameters.get("offsets") or [],
                _required_int(parameters, "pointer_size"),
                str(parameters.get("endian")),
            )
            return {
                "ok": True,
                "status": "ok",
                "operation": "pointer_chain",
                **result,
                "side_effects": False,
            }
        if action == "schema_write":
            with self._write_guard:
                if self._write_locked:
                    return {
                        "ok": False,
                        "status": "blocked",
                        "operation": "schema_write",
                        "reason": "write path is locked after a prior write failure",
                        "lock_details": dict(self._write_lock_details),
                        "side_effects": False,
                    }
                address = _required_int(parameters, "address")
                size = _required_int(parameters, "schema_size")
                current = _backend_read(backend, pid, address, size)
                if len(current) != size:
                    raise MemoryRuntimeBackendError(
                        "schema_write",
                        "backend returned fewer bytes than the compiled schema requires",
                        details={"expected_size": size, "actual_size": len(current)},
                    )
                schema = parameters.get("schema")
                if not isinstance(schema, Mapping):
                    raise ValueError("compiled schema metadata is unavailable")
                structured_write = write_structure_field(
                    current,
                    schema,
                    str(parameters.get("field_path") or ""),
                    parameters.get("field_value"),
                    expected=parameters.get("expected_field_value"),
                )
                replacement = structured_write.pop("data")
                result = _mapping_result(
                    _backend_write(backend, pid, address, replacement, current),
                    operation="schema_write",
                )
                result.update(
                    {
                        "schema": parameters.get("schema_layout"),
                        "structured_write": structured_write,
                        "memory": _bytes_snapshot(replacement, address=address),
                    }
                )
                return result
        if action == "write":
            with self._write_guard:
                if self._write_locked:
                    return {
                        "ok": False,
                        "status": "blocked",
                        "operation": "write",
                        "reason": "write path is locked after a prior write failure",
                        "lock_details": dict(self._write_lock_details),
                        "side_effects": False,
                    }
                address = _required_int(parameters, "address")
                data = _parameter_bytes(parameters, "data_hex") or b""
                expected = _parameter_bytes(parameters, "expected_hex") or b""
                result = _mapping_result(
                    _backend_write(backend, pid, address, data, expected),
                    operation="write",
                )
                if parameters.get("value_type"):
                    result["typed_write"] = _prune(
                        {
                            "value_type": parameters.get("value_type"),
                            "endian": parameters.get("endian"),
                            "value": parameters.get("value"),
                            "expected_original_value": parameters.get(
                                "expected_original_value"
                            ),
                        }
                    )
                return result
        if action == "protect":
            return _mapping_result(
                _backend_protect(
                    backend,
                    pid,
                    _required_int(parameters, "address"),
                    _required_int(parameters, "size"),
                    _required_int(parameters, "protection"),
                ),
                operation="protect",
            )
        if action == "alloc":
            return _mapping_result(
                _backend_alloc(
                    backend,
                    pid,
                    _required_int(parameters, "size"),
                    _required_int(parameters, "protection"),
                    address=_coerce_int(parameters.get("address")),
                    allocation_type=_required_int(parameters, "allocation_type"),
                ),
                operation="alloc",
            )
        if action == "free":
            return _mapping_result(
                _backend_free(
                    backend,
                    pid,
                    _required_int(parameters, "address"),
                    size=_coerce_int(parameters.get("free_size")) or 0,
                    free_type=_required_int(parameters, "free_type"),
                ),
                operation="free",
            )
        pattern = _parameter_bytes(parameters, "pattern_hex") or b""
        return _mapping_result(
            _backend_scan(
                backend,
                pid,
                pattern,
                mask=str(parameters.get("mask") or "x" * len(pattern)),
                start_address=_coerce_int(parameters.get("start_address")),
                end_address=_coerce_int(parameters.get("end_address")),
                max_results=_required_int(parameters, "max_results"),
                max_bytes=_required_int(parameters, "max_bytes"),
                chunk_size=_required_int(parameters, "chunk_size"),
            ),
            operation="scan",
        )

    def _verify_execution(
        self,
        action: str,
        parameters: Mapping[str, Any],
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        operation: Mapping[str, Any],
    ) -> tuple[str, list[Any]]:
        errors: list[Any] = []
        if not _operation_ok(operation):
            errors.append(operation.get("reason") or operation.get("error") or f"{action} backend failed")
            return "failed", errors
        if action == "write":
            wanted = _parameter_bytes(parameters, "data_hex")
            actual = _snapshot_bytes(after.get("memory"))
            if wanted is None or actual != wanted:
                errors.append("post-write byte verification failed")
        elif action == "schema_write":
            structured_write = operation.get("structured_write") or {}
            wanted_hex = str(structured_write.get("after_hex") or "")
            actual = _snapshot_bytes(after.get("memory"))
            if not wanted_hex or actual is None or actual.hex() != wanted_hex:
                errors.append("post-schema-write byte verification failed")
            field = after.get("structured_field") or {}
            if field.get("value") != parameters.get("field_value"):
                errors.append("post-schema-write field verification failed")
        elif action == "protect":
            wanted = _coerce_int(parameters.get("protection"))
            if _region_protection(after.get("region") or after) != wanted:
                errors.append("post-protect region verification failed")
        elif action == "alloc":
            address = _operation_address(operation)
            region = _find_region(after.get("regions") or [], address) if address else None
            if not address or region is None:
                errors.append("allocated address was not present in the post-operation region snapshot")
            requested_address = _coerce_int(parameters.get("address"))
            if requested_address is not None and address != requested_address:
                errors.append("allocated address does not match the requested fixed address")
            requested_size = _coerce_int(parameters.get("size"))
            if (
                address
                and region
                and requested_size
                and not _region_contains_range(region, address, requested_size)
            ):
                errors.append("allocated region is smaller than the requested allocation")
        elif action == "free":
            address = _coerce_int(parameters.get("address"))
            before_region = before.get("region") or {}
            after_region = after.get("region") or {}
            if address is None or not before_region or after_region:
                errors.append("freed allocation is still present in the post-operation region snapshot")
        elif action == "read":
            if len(_snapshot_bytes(after.get("memory")) or b"") != _coerce_int(parameters.get("size")):
                errors.append("read returned fewer bytes than requested")
        elif action == "typed_read":
            memory = operation.get("memory") or {}
            if len(_snapshot_bytes(memory) or b"") != _coerce_int(parameters.get("size")):
                errors.append("typed read returned fewer bytes than requested")
            if operation.get("value_type") != parameters.get("value_type"):
                errors.append("typed read value type does not match the plan")
        elif action == "schema_read":
            memory = operation.get("memory") or {}
            structured = operation.get("structured_value") or {}
            expected_size = _coerce_int(parameters.get("schema_size"))
            if len(_snapshot_bytes(memory) or b"") != expected_size:
                errors.append("structured read returned fewer bytes than required")
            if structured.get("size") != expected_size:
                errors.append("structured read decode does not match the compiled schema")
        elif action == "string_read":
            memory = operation.get("memory") or {}
            consumed = _coerce_int(operation.get("consumed_bytes"))
            max_bytes = _coerce_int(parameters.get("max_bytes"))
            if consumed is None or max_bytes is None or not 0 <= consumed <= max_bytes:
                errors.append("string read exceeded its bounded byte range")
            if len(_snapshot_bytes(memory) or b"") != consumed:
                errors.append("string read raw-byte evidence is incomplete")
        elif action == "pointer_chain":
            offsets = parameters.get("offsets") or []
            hops = operation.get("hops") or []
            if len(hops) != len(offsets) or _coerce_int(operation.get("final_address")) is None:
                errors.append("pointer chain result is incomplete")
        elif action == "module_rva":
            resolution = operation.get("resolution") or {}
            if (
                resolution.get("status") != "ok"
                or _module_resolution_identity(resolution)
                != _module_resolution_identity(parameters.get("module_resolution") or {})
            ):
                errors.append("module+RVA execution no longer matches the plan")
        return ("ok" if not errors else "failed"), errors

    def _latch_write_failure(
        self,
        plan: CapabilityPlan,
        operation: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        errors: Sequence[Any],
    ) -> None:
        with self._write_guard:
            self._write_locked = True
            self._write_lock_details = _prune(
                {
                    "session_id": plan.session_id,
                    "pid": plan.parameters.get("pid"),
                    "address": plan.parameters.get("address"),
                    "operation": dict(operation),
                    "after": dict(after_snapshot),
                    "errors": list(errors),
                }
            )

    def _latch_rollback_write_failure(
        self,
        result: CapabilityExecutionResult,
        operation: Mapping[str, Any],
        after: Mapping[str, Any],
    ) -> None:
        with self._write_guard:
            self._write_locked = True
            self._write_lock_details = _prune(
                {
                    "session_id": result.session_id,
                    "action": "rollback",
                    "operation": dict(operation),
                    "after": dict(after),
                }
            )

    def _result(
        self,
        plan: CapabilityPlan,
        *,
        status: str,
        validation: CapabilityValidation,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        operation: Mapping[str, Any],
        errors: Sequence[Any],
    ) -> CapabilityExecutionResult:
        target = _target_payload(plan.target)
        precondition = {
            "hash": plan.precondition_hash,
            "validation": {
                "ok": validation.ok,
                "check": next(
                    (
                        dict(item)
                        for item in validation.checks
                        if item.get("name") == "precondition_hash"
                    ),
                    None,
                ),
            },
        }
        provenance = {
            **dict(plan.provenance or {}),
            "precondition_hash": plan.precondition_hash,
            "backend": plan.provenance.get("backend"),
            "execution": {
                "status": status,
                "action": plan.action,
                "mutating": plan.action in _MUTATING_ACTIONS,
                "before_hash": _state_precondition_hash(
                    plan.action, before_snapshot, plan.parameters
                ),
                "after_hash": _state_precondition_hash(
                    plan.action, after_snapshot, plan.parameters
                ),
                "rollback_mode": rollback_plan.get("mode"),
            },
        }
        artifact = CapabilityArtifact(
            path=(
                f"memory_runtime/{_safe_segment(plan.session_id)}/"
                f"{_safe_segment(plan.action)}.json"
            ),
            kind="memory-runtime-audit",
            description=f"Process-memory audit for {plan.action}",
            metadata={
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "status": status,
                "action": plan.action,
                "session_id": plan.session_id,
                "target": target,
                "precondition_hash": plan.precondition_hash,
                "materialized": False,
            },
        )
        manifest = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": self.capability_name,
            "provider": self.provider_name,
            "status": status,
            "role": "memory-runtime-audit",
            "session_id": plan.session_id,
            "action": plan.action,
            "pid": plan.parameters.get("pid"),
            "target": target,
            "precondition_hash": plan.precondition_hash,
        }
        report = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "platform": self.platform_name,
            "action": plan.action,
            "session_id": plan.session_id,
            "session": {"id": plan.session_id},
            "target": target,
            "target_identity": target,
            "pid": plan.parameters.get("pid"),
            "mutating": plan.action in _MUTATING_ACTIONS,
            "precondition": precondition,
            "precondition_hash": plan.precondition_hash,
            "before": dict(before_snapshot),
            "after": dict(after_snapshot),
            "rollback": dict(rollback_plan),
            "before_snapshot": dict(before_snapshot),
            "after_snapshot": dict(after_snapshot),
            "rollback_plan": dict(rollback_plan),
            "provenance": provenance,
            "artifacts": [artifact.to_dict()],
            "evidence_manifest_entries": [dict(manifest)],
            "operation": dict(operation),
            "validation": {
                "ok": validation.ok,
                "checks": list(validation.checks),
                "warnings": list(validation.warnings),
                "errors": list(validation.errors),
            },
            "errors": list(errors),
            "write_fail_closed": {
                "locked": self._write_locked,
                "details": dict(self._write_lock_details),
            },
        }
        trace = {
            "kind": "memory_runtime_execution",
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "session_id": plan.session_id,
            "status": status,
            "pid": plan.parameters.get("pid"),
            "mutating": plan.action in _MUTATING_ACTIONS,
            "side_effects": after_snapshot.get("side_effects", False),
        }
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(before_snapshot),
            after_snapshot=dict(after_snapshot),
            rollback_plan=dict(rollback_plan),
            artifacts=[artifact],
            evidence_manifest_entries=[manifest],
            report_section=report,
            dashboard_trace=[trace],
            provenance=provenance,
        )

    def _select_backend(self, context: Optional[dict[str, Any]]) -> MemoryRuntimeBackend:
        if context:
            candidate = context.get("memory_runtime_backend")
            if candidate is not None:
                return candidate
        return self.backend


class MemoryRuntimeMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("memory_runtime")


_ACTION_BACKEND_OPERATION = {
    "probe": "probe",
    "regions": "regions",
    "modules": "modules",
    "read": "read",
    "typed_read": "read",
    "string_read": "read",
    "pointer_chain": "read",
    "schema_read": "read",
    "module_rva": "modules",
    "write": "write",
    "schema_write": "write",
    "protect": "protect",
    "alloc": "alloc",
    "free": "free",
    "scan": "scan",
}
_BACKEND_METHOD_NAMES = {
    "probe": ("probe_process", "probe"),
    "regions": ("enumerate_regions", "list_regions", "regions"),
    "modules": ("enumerate_modules", "list_modules", "modules"),
    "read": ("read", "read_memory"),
    "write": ("write", "write_memory"),
    "protect": ("protect", "protect_memory"),
    "alloc": ("alloc", "allocate", "allocate_memory"),
    "free": ("free", "free_memory"),
    "scan": ("scan", "aob_scan", "scan_pattern"),
}


def _normalize_action(value: Any) -> str:
    action = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ACTION_ALIASES.get(action, action)


def _request_pid(request: CapabilityRequest) -> tuple[Any, Optional[int], bool]:
    target_pid = getattr(request.target, "pid", None)
    parameter_pid = request.params.get("pid")
    raw = parameter_pid if parameter_pid is not None else target_pid
    pid = _coerce_int(raw)
    target_value = _coerce_int(target_pid)
    parameter_value = _coerce_int(parameter_pid)
    conflict = (
        target_pid is not None
        and parameter_pid is not None
        and target_value != parameter_value
    )
    return raw, pid, conflict


def _first_present(
    values: Mapping[str, Any], keys: Sequence[str]
) -> tuple[bool, Any]:
    for key in keys:
        if key in values:
            return True, values.get(key)
    return False, None


def _normalize_value_type(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("_t", "")
    normalized = _TYPED_VALUE_ALIASES.get(normalized, normalized)
    return normalized if normalized in _TYPED_VALUE_FORMATS else None


def _normalize_endian(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("_", "-")
    if normalized in {"little", "little-endian", "le", "<"}:
        return "little"
    if normalized in {"big", "big-endian", "be", ">"}:
        return "big"
    return None


def _normalize_string_encoding(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("_", "-")
    return _STRING_ENCODINGS.get(normalized)


def _parse_pointer_offsets(value: Any) -> tuple[list[int], Optional[str]]:
    if isinstance(value, str):
        items: Sequence[Any] = [
            item for item in value.replace(",", " ").split() if item
        ]
    elif isinstance(value, Sequence) and not isinstance(
        value, (bytes, bytearray, memoryview)
    ):
        items = value
    else:
        return [], "pointer chain offsets must be a non-empty sequence"
    if not items:
        return [], "pointer chain offsets must be a non-empty sequence"
    if len(items) > _MAX_POINTER_CHAIN_DEPTH:
        return [], f"pointer chain exceeds maximum depth ({_MAX_POINTER_CHAIN_DEPTH})"
    offsets: list[int] = []
    for index, item in enumerate(items):
        offset = _coerce_int(item)
        if offset is None:
            return [], f"pointer chain offset {index} must be an integer"
        offsets.append(offset)
    return offsets, None


def _pack_typed_value(value: Any, value_type: str, endian: str) -> bytes:
    normalized_type = _normalize_value_type(value_type)
    normalized_endian = _normalize_endian(endian)
    if normalized_type is None:
        raise ValueError(f"unsupported typed memory value: {value_type}")
    if normalized_endian is None:
        raise ValueError(f"unsupported byte order: {endian}")
    format_code, size = _TYPED_VALUE_FORMATS[normalized_type]
    if format_code in {"f", "d"}:
        if isinstance(value, bool):
            raise ValueError(f"{normalized_type} value must be numeric")
        try:
            normalized_value: int | float = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"{normalized_type} value must be numeric") from exc
        if not math.isfinite(normalized_value):
            raise ValueError(f"{normalized_type} value must be finite")
    else:
        normalized_value = _coerce_int(value)
        if normalized_value is None:
            raise ValueError(f"{normalized_type} value must be an integer")
        signed = format_code.islower()
        bits = size * 8
        minimum = -(1 << (bits - 1)) if signed else 0
        maximum = (1 << (bits - 1)) - 1 if signed else (1 << bits) - 1
        if not minimum <= normalized_value <= maximum:
            raise ValueError(
                f"{normalized_type} value must be between {minimum} and {maximum}"
            )
    prefix = "<" if normalized_endian == "little" else ">"
    try:
        return struct.pack(prefix + format_code, normalized_value)
    except (OverflowError, struct.error) as exc:
        raise ValueError(f"{normalized_type} value cannot be encoded") from exc


def _decode_typed_value(data: bytes, value_type: str, endian: str) -> int | float:
    normalized_type = _normalize_value_type(value_type)
    normalized_endian = _normalize_endian(endian)
    if normalized_type is None or normalized_endian is None:
        raise ValueError("typed memory metadata is invalid")
    format_code, size = _TYPED_VALUE_FORMATS[normalized_type]
    if len(data) != size:
        raise ValueError(
            f"{normalized_type} requires {size} bytes, received {len(data)}"
        )
    prefix = "<" if normalized_endian == "little" else ">"
    return struct.unpack(prefix + format_code, data)[0]


def _has_module_rva_spec(parameters: Mapping[str, Any]) -> bool:
    return bool(str(parameters.get("module") or "").strip()) and _coerce_int(
        parameters.get("rva")
    ) is not None


def _resolve_module_rva(
    modules: Sequence[Mapping[str, Any]], module: str, rva: Any
) -> dict[str, Any]:
    # Import lazily so the provider package does not pull in the complete tool
    # registry during provider discovery.
    from reverse_analyzer.tools.memory import resolve_module_rva

    return resolve_module_rva(modules, module, rva)


def _resolve_planned_module_address(
    backend: MemoryRuntimeBackend,
    action: str,
    parameters: dict[str, Any],
) -> None:
    if action not in _ADDRESS_ACTIONS | {"module_rva"} or not _has_module_rva_spec(
        parameters
    ):
        return
    if not _backend_available(backend):
        return
    pid = _coerce_int(parameters.get("pid"))
    if not pid or pid <= 0:
        return
    try:
        resolution = _resolve_module_rva(
            _backend_modules(backend, pid),
            str(parameters.get("module") or ""),
            parameters.get("rva"),
        )
        resolved_address = _coerce_int(resolution.get("address_int"))
        requested_address = _coerce_int(parameters.get("requested_address"))
        if resolved_address is None:
            raise ValueError("module+RVA resolver did not return an address")
        if requested_address is not None and requested_address != resolved_address:
            raise ValueError(
                "explicit address does not match the module+RVA resolved address"
            )
        parameters["address"] = resolved_address
        parameters["module_resolution"] = resolution
    except Exception as exc:
        errors = [str(item) for item in parameters.get("parameter_errors") or []]
        errors.append(f"module+RVA resolution failed: {exc}")
        parameters["parameter_errors"] = _deduplicate(errors)


def _module_resolution_identity(value: Mapping[str, Any]) -> tuple[Any, ...]:
    module = value.get("module") if isinstance(value.get("module"), Mapping) else {}
    path = str(module.get("path") or "").strip()
    path_identity = (
        str(PureWindowsPath(path)).replace("\\", "/").casefold() if path else None
    )
    return (
        value.get("status"),
        str(module.get("name") or "").casefold(),
        path_identity,
        _coerce_int(value.get("base_address_int", value.get("base_address"))),
        _coerce_int(module.get("size")),
        _coerce_int(value.get("rva_int", value.get("rva"))),
        _coerce_int(value.get("address_int", value.get("address"))),
    )


def _normalize_parameters(
    action: str,
    raw: Mapping[str, Any],
    *,
    max_read_bytes: int,
) -> dict[str, Any]:
    source = _json_mapping(raw)
    params = dict(source)
    errors: list[str] = []

    module_present, module_value = _first_present(
        source, ("module", "module_name", "module_path")
    )
    rva_present, rva_value = _first_present(source, ("rva",))
    module_spec_requested = module_present or rva_present or action == "module_rva"
    module_spec_valid = False
    if module_spec_requested:
        module_selector = str(module_value or "").strip()
        rva = _coerce_int(rva_value)
        if not module_selector:
            errors.append("module selector must be non-empty")
        if not rva_present or rva is None or rva < 0:
            errors.append("module RVA must be a non-negative integer")
        if module_selector and rva is not None and rva >= 0:
            params["module"] = module_selector
            params["rva"] = rva
            module_spec_valid = True

    address_present, address_value = _first_present(
        source, ("address", "base_address")
    )
    address = _coerce_int(address_value)
    size = _coerce_int(source.get("size", source.get("length")))
    if action in _ADDRESS_ACTIONS:
        if address_present and (address is None or address < 0):
            errors.append("address must be a non-negative integer")
        elif address is not None and address >= 0:
            params["address"] = address
            params["requested_address"] = address
        elif not module_spec_valid:
            errors.append("address or module+RVA must be provided")
    if action in {"read", "protect", "alloc"}:
        if size is None or size <= 0:
            errors.append("size must be a positive integer")
        elif size > max_read_bytes and action == "read":
            errors.append(f"read size exceeds max_read_bytes ({max_read_bytes})")
        else:
            params["size"] = size

    if action == "typed_read":
        value_type = _normalize_value_type(
            source.get("value_type", source.get("data_type", source.get("type")))
        )
        endian = _normalize_endian(source.get("endian", "little"))
        if value_type is None:
            errors.append(
                "value_type must be int8/uint8/int16/uint16/int32/uint32/"
                "int64/uint64/float/double"
            )
        else:
            params["value_type"] = value_type
            params["size"] = _TYPED_VALUE_FORMATS[value_type][1]
        if endian is None:
            errors.append("endian must be little or big")
        else:
            params["endian"] = endian

    if action == "string_read":
        encoding = _normalize_string_encoding(source.get("encoding", "utf-8"))
        raw_max_bytes = source.get(
            "max_bytes", source.get("size", source.get("length", _DEFAULT_MAX_STRING_BYTES))
        )
        max_bytes = _coerce_int(raw_max_bytes)
        if encoding is None:
            errors.append("encoding must be UTF-8, UTF-16, UTF-16-LE, or UTF-16-BE")
        else:
            params["encoding"] = encoding
        if max_bytes is None or max_bytes <= 0:
            errors.append("max_bytes must be a positive integer")
        elif max_bytes > max_read_bytes:
            errors.append(f"string max_bytes exceeds max_read_bytes ({max_read_bytes})")
            params["max_bytes"] = max_read_bytes
        elif encoding in {"utf-16-le", "utf-16-be"} and max_bytes % 2:
            errors.append("UTF-16 max_bytes must be a multiple of two")
            params["max_bytes"] = max_bytes
        else:
            params["max_bytes"] = max_bytes

    if action == "pointer_chain":
        offsets, offsets_error = _parse_pointer_offsets(source.get("offsets"))
        pointer_size = _coerce_int(source.get("pointer_size", ctypes.sizeof(ctypes.c_void_p)))
        endian = _normalize_endian(source.get("endian", "little"))
        if offsets_error:
            errors.append(offsets_error)
        else:
            params["offsets"] = offsets
        if pointer_size not in {4, 8}:
            errors.append("pointer_size must be 4 or 8 bytes")
        else:
            params["pointer_size"] = pointer_size
        if endian is None:
            errors.append("endian must be little or big")
        else:
            params["endian"] = endian

    if action in {"schema_read", "schema_write"}:
        raw_schema = source.get("schema", source.get("layout"))
        if not isinstance(raw_schema, Mapping):
            errors.append("schema must be a memory-layout object")
        else:
            schema = _json_mapping(raw_schema)
            if "endian" not in schema and source.get("endian") is not None:
                schema["endian"] = source.get("endian")
            try:
                layout = compile_memory_schema(schema, max_size=max_read_bytes)
                params["schema"] = schema
                params["schema_size"] = layout.size
                params["size"] = layout.size
                params["schema_layout"] = describe_memory_layout(layout)
                field_path = str(
                    source.get("field_path", source.get("path", "")) or ""
                ).strip()
                if field_path:
                    reference = resolve_structure_field(layout, field_path)
                    params["field_path"] = reference.path
                elif action == "schema_write":
                    errors.append("schema_write requires a non-empty field_path")
            except ValueError as exc:
                errors.append(str(exc))

        if action == "schema_write":
            value_present, field_value = _first_present(
                source, ("field_value", "value", "replacement_value")
            )
            expected_present, expected_value = _first_present(
                source,
                (
                    "expected_field_value",
                    "expected_value",
                    "expected_original_value",
                ),
            )
            if not value_present:
                errors.append("schema_write requires a replacement field value")
            else:
                params["field_value"] = _json_value(field_value)
            if not expected_present:
                errors.append("schema_write requires an expected field value")
            else:
                params["expected_field_value"] = _json_value(expected_value)

    if action == "write":
        value_type_present, value_type_value = _first_present(
            source, ("value_type", "data_type", "type")
        )
        value_type = _normalize_value_type(value_type_value) if value_type_present else None
        endian = _normalize_endian(source.get("endian", "little"))
        if value_type_present and value_type is None:
            errors.append(
                "value_type must be int8/uint8/int16/uint16/int32/uint32/"
                "int64/uint64/float/double"
            )
        if value_type_present and endian is None:
            errors.append("endian must be little or big")
        if value_type is not None and endian is not None:
            params["value_type"] = value_type
            params["endian"] = endian

        raw_data_present, raw_data = _first_present(
            source, ("data", "bytes", "replacement")
        )
        typed_data_present, typed_data = _first_present(
            source, ("value", "replacement_value")
        )
        data, data_error = (
            _parse_bytes_value(raw_data, allow_wildcards=False)
            if raw_data_present
            else (None, None)
        )
        typed_data_bytes: Optional[bytes] = None
        if typed_data_present:
            if value_type is None or endian is None:
                errors.append("typed write value requires a valid value_type and endian")
            else:
                try:
                    typed_data_bytes = _pack_typed_value(typed_data, value_type, endian)
                    params["value"] = _decode_typed_value(
                        typed_data_bytes, value_type, endian
                    )
                except ValueError as exc:
                    errors.append(str(exc))
        if data is not None and typed_data_bytes is not None and data != typed_data_bytes:
            errors.append("typed replacement value does not match write data bytes")
        if typed_data_bytes is not None:
            data = typed_data_bytes

        raw_expected_present, raw_expected = _first_present(
            source,
            (
                "expected",
                "expected_bytes",
                "expected_original_bytes",
                "original_bytes",
            ),
        )
        typed_expected_present, typed_expected = _first_present(
            source,
            ("expected_value", "expected_original_value", "original_value"),
        )
        expected, expected_error = (
            _parse_bytes_value(raw_expected, allow_wildcards=False)
            if raw_expected_present
            else (None, None)
        )
        typed_expected_bytes: Optional[bytes] = None
        if typed_expected_present:
            if value_type is None or endian is None:
                errors.append(
                    "typed expected original value requires a valid value_type and endian"
                )
            else:
                try:
                    typed_expected_bytes = _pack_typed_value(
                        typed_expected, value_type, endian
                    )
                    params["expected_original_value"] = _decode_typed_value(
                        typed_expected_bytes, value_type, endian
                    )
                except ValueError as exc:
                    errors.append(str(exc))
        if (
            expected is not None
            and typed_expected_bytes is not None
            and expected != typed_expected_bytes
        ):
            errors.append("typed expected value does not match expected original bytes")
        if typed_expected_bytes is not None:
            expected = typed_expected_bytes

        if data_error or not data:
            errors.append(data_error or "write data must be non-empty")
        if expected_error or expected is None:
            errors.append(expected_error or "write expected bytes are required")
        if data is not None and expected is not None and len(data) != len(expected):
            errors.append("write data and expected bytes must have equal length")
        if data is not None:
            params["data_hex"] = data.hex()
            params["size"] = len(data)
        if expected is not None:
            params["expected_hex"] = expected.hex()
        if value_type is not None and endian is not None:
            expected_size = _TYPED_VALUE_FORMATS[value_type][1]
            if data is not None and len(data) != expected_size:
                errors.append("typed write data size does not match value_type")
            if expected is not None and len(expected) != expected_size:
                errors.append("typed expected byte size does not match value_type")
            if data is not None and "value" not in params and len(data) == expected_size:
                params["value"] = _decode_typed_value(data, value_type, endian)
            if (
                expected is not None
                and "expected_original_value" not in params
                and len(expected) == expected_size
            ):
                params["expected_original_value"] = _decode_typed_value(
                    expected, value_type, endian
                )

    if action in {"protect", "alloc"}:
        default = _PAGE_PROTECTIONS["PAGE_READWRITE"] if action == "alloc" else None
        protection = _parse_protection(
            source.get("protection", source.get("new_protection", default))
        )
        if protection is None:
            errors.append("protection must be a Win32 PAGE_* name or integer")
        else:
            params["protection"] = protection
            params["protection_name"] = _protection_name(protection)

    if action == "protect" and "expected_protection" in source:
        expected_protection = _parse_protection(source.get("expected_protection"))
        if expected_protection is None:
            errors.append("expected_protection must be a Win32 PAGE_* name or integer")
        else:
            params["expected_protection"] = expected_protection
            params["expected_protection_name"] = _protection_name(
                expected_protection
            )

    if action == "alloc":
        requested_address = _coerce_int(source.get("address"))
        if source.get("address") is not None and requested_address is None:
            errors.append("allocation address must be an integer")
        params["address"] = requested_address
        raw_allocation_type = source.get(
            "allocation_type", _MEM_COMMIT | _MEM_RESERVE
        )
        allocation_type = _coerce_int(raw_allocation_type)
        if allocation_type is None or allocation_type <= 0:
            errors.append("allocation_type must be a positive integer")
        else:
            params["allocation_type"] = allocation_type

    if action == "free":
        raw_requested_size = source.get("size", source.get("length"))
        requested_size = _coerce_int(raw_requested_size)
        if raw_requested_size is not None and (
            requested_size is None or requested_size < 0
        ):
            errors.append("free size must be a non-negative integer")
        params["requested_size"] = requested_size
        params["size"] = requested_size

        raw_free_type = source.get("free_type", _MEM_RELEASE)
        free_type = _coerce_int(raw_free_type)
        if free_type is None or free_type <= 0:
            errors.append("free_type must be a positive integer")
        else:
            params["free_type"] = free_type

        raw_free_size = source.get("free_size", 0)
        free_size = _coerce_int(raw_free_size)
        if free_size is None or free_size < 0:
            errors.append("free_size must be a non-negative integer")
        else:
            params["free_size"] = free_size

    if action == "scan":
        pattern_value = source.get("pattern", source.get("aob", source.get("signature")))
        pattern, mask, pattern_error = _parse_pattern(pattern_value, source.get("mask"))
        if pattern_error:
            errors.append(pattern_error)
        if pattern is not None:
            params["pattern_hex"] = pattern.hex()
            params["mask"] = mask
            params["pattern"] = _display_pattern(pattern, mask)
        start = _coerce_int(source.get("start_address", source.get("start")))
        end = _coerce_int(source.get("end_address", source.get("end")))
        if source.get("start_address", source.get("start")) is not None and start is None:
            errors.append("scan start_address must be an integer")
        if source.get("end_address", source.get("end")) is not None and end is None:
            errors.append("scan end_address must be an integer")
        if start is not None and end is not None and end <= start:
            errors.append("scan end_address must be greater than start_address")
        params["start_address"] = start
        params["end_address"] = end
        params["max_results"] = _bounded_positive(
            source.get("max_results"), _DEFAULT_MAX_RESULTS, 100_000
        )
        params["max_bytes"] = _bounded_positive(
            source.get("max_bytes"), _DEFAULT_MAX_SCAN_BYTES, 4 * 1024 * 1024 * 1024
        )
        params["chunk_size"] = _bounded_positive(
            source.get("chunk_size"), _DEFAULT_SCAN_CHUNK, 16 * 1024 * 1024
        )

    params["parameter_errors"] = _deduplicate(errors)
    return params


def _capture_state(
    backend: MemoryRuntimeBackend,
    action: str,
    parameters: Mapping[str, Any],
    *,
    max_capture_bytes: int = _DEFAULT_MAX_READ,
) -> dict[str, Any]:
    pid = _coerce_int(parameters.get("pid"))
    snapshot: dict[str, Any] = {
        "action": action,
        "process": {
            "pid": pid if pid is not None else parameters.get("pid"),
            "status": "not_probed",
        },
    }
    if not _backend_available(backend):
        snapshot["process"] = {
            "pid": pid if pid is not None else parameters.get("pid"),
            "exists": None,
            "accessible": False,
            "status": "unavailable",
            "reason": _backend_reason(backend),
        }
        snapshot["status"] = "unavailable"
        return snapshot
    if not pid or pid <= 0:
        snapshot["status"] = "invalid_target"
        return snapshot
    errors: list[dict[str, Any]] = []
    try:
        snapshot["process"] = _json_mapping(_backend_probe(backend, pid))
    except Exception as exc:
        errors.append(_exception_payload(exc))
        snapshot["process"] = {
            "pid": pid,
            "accessible": False,
            "status": "failed",
            "error": _exception_payload(exc),
        }

    try:
        if action in {"regions", "protect", "alloc", "free", "scan"}:
            regions = _backend_regions(backend, pid)
            snapshot["regions"] = regions
            snapshot["region_count"] = len(regions)
            address = _coerce_int(parameters.get("address"))
            if address is not None:
                region = _find_region(regions, address)
                if region is not None:
                    snapshot["region"] = region
                if action == "free":
                    snapshot["allocation"] = _allocation_snapshot(regions, address)
        if action in {"modules", "module_rva"} or _has_module_rva_spec(parameters):
            modules = _backend_modules(backend, pid)
            snapshot["modules"] = modules
            snapshot["module_count"] = len(modules)
            if _has_module_rva_spec(parameters):
                try:
                    snapshot["module_resolution"] = _resolve_module_rva(
                        modules,
                        str(parameters.get("module") or ""),
                        parameters.get("rva"),
                    )
                except Exception as exc:
                    payload = _exception_payload(exc)
                    snapshot["module_resolution"] = {
                        "status": "failed",
                        "error": payload,
                    }
                    errors.append(payload)
        if action in {"read", "write", "typed_read", "schema_read", "schema_write"}:
            address = _coerce_int(parameters.get("address"))
            size = _coerce_int(parameters.get("size"))
            if action == "write":
                data = _parameter_bytes(parameters, "data_hex")
                size = len(data) if data is not None else size
            if address is not None and size is not None and size > 0:
                data = _backend_read(backend, pid, address, size)
                snapshot["memory"] = _bytes_snapshot(data, address=address)
                if parameters.get("value_type") and len(data) == size:
                    snapshot["typed_value"] = {
                        "value_type": parameters.get("value_type"),
                        "endian": parameters.get("endian"),
                        "value": _decode_typed_value(
                            data,
                            str(parameters.get("value_type")),
                            str(parameters.get("endian")),
                        ),
                    }
                if action in {"schema_read", "schema_write"} and len(data) == size:
                    schema = parameters.get("schema")
                    if isinstance(schema, Mapping):
                        snapshot["structured_value"] = decode_structure(data, schema)
                        field_path = str(parameters.get("field_path") or "").strip()
                        if field_path:
                            snapshot["structured_field"] = {
                                "path": field_path,
                                "value": read_structure_field(data, schema, field_path),
                            }
        elif action == "string_read":
            address = _coerce_int(parameters.get("address"))
            max_bytes = _coerce_int(parameters.get("max_bytes"))
            if address is not None and max_bytes is not None and max_bytes > 0:
                string_capture = _read_bounded_string(
                    backend,
                    pid,
                    address,
                    str(parameters.get("encoding")),
                    min(max_bytes, max_capture_bytes),
                )
                snapshot["string"] = {"status": "ok", **string_capture}
                snapshot["memory"] = string_capture["memory"]
        elif action == "pointer_chain":
            address = _coerce_int(parameters.get("address"))
            pointer_size = _coerce_int(parameters.get("pointer_size"))
            if address is not None and pointer_size in {4, 8}:
                snapshot["pointer_chain"] = {
                    "status": "ok",
                    **_resolve_pointer_chain(
                        backend,
                        pid,
                        address,
                        parameters.get("offsets") or [],
                        pointer_size,
                        str(parameters.get("endian")),
                    ),
                }
        elif action == "free":
            address = _coerce_int(parameters.get("address"))
            allocation = snapshot.get("allocation") or {}
            capture_size = _coerce_int(allocation.get("size"))
            capture_limit = max(1, int(max_capture_bytes))
            capture = {
                "address": address,
                "size": capture_size,
                "max_capture_bytes": capture_limit,
            }
            if not allocation.get("recoverable") or not capture_size:
                capture.update(
                    {
                        "status": "not_recoverable",
                        "reason": "allocation is not a single readable committed private region",
                    }
                )
            elif capture_size > capture_limit:
                capture.update(
                    {
                        "status": "blocked",
                        "reason": "allocation exceeds the rollback capture limit",
                    }
                )
            elif address is not None:
                data = _backend_read(backend, pid, address, capture_size)
                snapshot["memory"] = _bytes_snapshot(data, address=address)
                capture.update(
                    {
                        "status": "captured",
                        "captured_size": len(data),
                        "complete": len(data) == capture_size,
                    }
                )
            snapshot["memory_capture"] = capture
    except Exception as exc:
        errors.append(_exception_payload(exc))
    if errors:
        snapshot["errors"] = errors
        snapshot["status"] = "failed"
    else:
        snapshot["status"] = "ok"
    return snapshot


def _state_precondition_hash(
    action: str,
    snapshot: Mapping[str, Any],
    parameters: Mapping[str, Any],
) -> Optional[str]:
    memory = _snapshot_bytes(snapshot.get("memory"))
    if action in {
        "read",
        "write",
        "typed_read",
        "string_read",
        "schema_read",
        "schema_write",
    } and memory is not None:
        return hashlib.sha256(memory).hexdigest()
    if action == "pointer_chain":
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "address": parameters.get("address"),
                "offsets": parameters.get("offsets"),
                "pointer_size": parameters.get("pointer_size"),
                "endian": parameters.get("endian"),
                "pointer_chain": snapshot.get("pointer_chain"),
            }
        )
    if action == "module_rva":
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "module": parameters.get("module"),
                "rva": parameters.get("rva"),
                "module_resolution": snapshot.get("module_resolution"),
            }
        )
    if action == "free":
        allocation = snapshot.get("allocation") or {}
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "action": action,
                "address": parameters.get("address"),
                "size": parameters.get("size"),
                "allocation": {
                    "present": allocation.get("present", False),
                    "base_address": allocation.get("base_address"),
                    "allocation_base": allocation.get("allocation_base"),
                    "size": allocation.get("size"),
                    "region_count": allocation.get("region_count"),
                    "recoverable": allocation.get("recoverable", False),
                },
                "memory_sha256": (
                    hashlib.sha256(memory).hexdigest() if memory is not None else None
                ),
            }
        )
    if action == "protect":
        region = snapshot.get("region") or {}
        if not region:
            return None
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "address": parameters.get("address"),
                "size": parameters.get("size"),
                "region_base": _region_base(region),
                "region_size": _coerce_int(region.get("size")),
                "protection": _region_protection(region),
            }
        )
    if action == "alloc":
        requested_address = _coerce_int(parameters.get("address"))
        region = snapshot.get("region") or {}
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "action": action,
                "address": requested_address,
                "size": parameters.get("size"),
                "protection": parameters.get("protection"),
                "allocation_type": parameters.get("allocation_type"),
                "target_state": (
                    {
                        "occupied": True,
                        "base_address": _region_base(region),
                        "allocation_base": _region_allocation_base(region),
                        "size": _coerce_int(region.get("size")),
                        "state": _coerce_int(region.get("state")),
                        "protection": _region_protection(region),
                    }
                    if requested_address is not None and region
                    else {"occupied": False}
                    if requested_address is not None
                    else {"selection": "system"}
                ),
            }
        )
    if snapshot.get("status") == "unavailable":
        return _canonical_hash(
            {
                "pid": parameters.get("pid"),
                "action": action,
                "status": "unavailable",
            }
        )
    return _canonical_hash(
        {
            "pid": parameters.get("pid"),
            "action": action,
            "process": snapshot.get("process"),
            "regions": snapshot.get("regions"),
            "modules": snapshot.get("modules"),
        }
    )


def _initial_rollback_plan(
    action: str,
    parameters: Mapping[str, Any],
    before: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "action": action,
        "pid": parameters.get("pid"),
        "address": parameters.get("address"),
        "before": _rollback_before_summary(before),
        "after": {"status": "pending"},
    }
    if action in _WRITE_ACTIONS:
        memory = before.get("memory") or {}
        return {
            **base,
            "supported": bool(memory.get("hex")),
            "mode": "write_restore",
            "size": parameters.get("size"),
            "before_hex": memory.get("hex"),
            "before_sha256": memory.get("sha256"),
            "expected_after_hex": (
                parameters.get("data_hex")
                if action == "write"
                else None
            ),
        }
    if action == "protect":
        region = before.get("region") or {}
        return {
            **base,
            "supported": _region_protection(region) is not None,
            "mode": "protect_restore",
            "size": parameters.get("size"),
            "old_protection": _region_protection(region),
            "new_protection": parameters.get("protection"),
        }
    if action == "alloc":
        return {
            **base,
            "supported": True,
            "mode": "free_allocation",
            "size": parameters.get("size"),
            "protection": parameters.get("protection"),
            "address": None,
        }
    if action == "free":
        memory = before.get("memory") or {}
        region = before.get("region") or {}
        size = parameters.get("size")
        complete = bool(memory.get("hex")) and _coerce_int(memory.get("size")) == _coerce_int(size)
        return {
            **base,
            "supported": complete and _region_protection(region) is not None,
            "mode": "reallocate_restore",
            "size": size,
            "protection": _region_protection(region),
            "allocation_type": 0x3000,
            "before_hex": memory.get("hex"),
            "before_sha256": memory.get("sha256"),
        }
    return {
        **base,
        "supported": False,
        "mode": "not_required",
        "reason": "read-only action",
    }


def _completed_rollback_metadata(
    action: str,
    rollback: Mapping[str, Any],
    parameters: Mapping[str, Any],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    operation: Mapping[str, Any],
    status: str,
) -> dict[str, Any]:
    result = dict(rollback or {})
    result.update(
        {
            "before": _rollback_before_summary(before),
            "after": _rollback_before_summary(after),
            "operation_status": status,
        }
    )
    if action in _WRITE_ACTIONS:
        memory = after.get("memory") or {}
        result.update(
            {
                "supported": bool((before.get("memory") or {}).get("hex")),
                "after_hex": memory.get("hex"),
                "after_sha256": memory.get("sha256"),
            }
        )
    elif action == "protect":
        result["after_protection"] = _region_protection(after.get("region") or {})
    elif action == "alloc":
        result["address"] = _operation_address(operation)
        result["supported"] = status == "ok" and result["address"] is not None
    elif action == "free":
        result["supported"] = bool(result.get("before_hex") and result.get("protection") is not None)
    if action in _MUTATING_ACTIONS and status != "ok" and not after.get("side_effects"):
        result.update(
            {
                "supported": False,
                "mode": "not_required",
                "reason": "mutation was not observed",
            }
        )
    return result


def _not_required_rollback(
    rollback: Mapping[str, Any],
    status: str,
    reason: str,
) -> dict[str, Any]:
    result = dict(rollback or {})
    result.update(
        {
            "supported": False,
            "mode": "not_required",
            "status": status,
            "reason": reason,
        }
    )
    return result


def _plan_steps(action: str) -> list[dict[str, Any]]:
    steps = [
        {"step": "pin_target_pid", "status": "planned", "required": True},
        {"step": "probe_process", "status": "planned", "required": True},
    ]
    action_steps = {
        "probe": ["capture_process_identity"],
        "regions": ["enumerate_regions"],
        "modules": ["enumerate_modules"],
        "read": ["capture_before", "ReadProcessMemory", "capture_after"],
        "typed_read": [
            "capture_before",
            "ReadProcessMemory",
            "decode_typed_value",
            "capture_after",
        ],
        "schema_read": [
            "compile_schema",
            "capture_before",
            "ReadProcessMemory",
            "decode_structured_value",
            "capture_after",
        ],
        "schema_write": [
            "compile_schema",
            "capture_before",
            "verify_expected_field_value",
            "encode_field_preserving_unrelated_bytes",
            "WriteProcessMemory",
            "verify_structured_field",
            "record_write_restore",
        ],
        "string_read": [
            "capture_before",
            "bounded_string_read",
            "decode_string",
            "capture_after",
        ],
        "pointer_chain": [
            "capture_before",
            "resolve_pointer_chain",
            "record_pointer_hops",
            "capture_after",
        ],
        "module_rva": [
            "enumerate_modules",
            "match_module_identity",
            "validate_rva_bounds",
            "resolve_address",
        ],
        "write": [
            "capture_before",
            "verify_expected_bytes",
            "WriteProcessMemory",
            "verify_written_bytes",
            "record_write_restore",
        ],
        "protect": [
            "capture_before",
            "VirtualProtectEx",
            "verify_protection",
            "record_protection_restore",
        ],
        "alloc": [
            "capture_before",
            "VirtualAllocEx",
            "verify_allocation",
            "record_allocation_free",
        ],
        "free": [
            "capture_allocation_bytes",
            "VirtualFreeEx",
            "verify_release",
            "record_reallocation_restore",
        ],
        "scan": ["enumerate_regions", "bounded_aob_scan", "record_matches"],
    }
    return steps + [
        {"step": name, "status": "planned", "required": True}
        for name in action_steps.get(action, [])
    ]


def _backend_info(backend: Any, platform_name: str) -> dict[str, Any]:
    return {
        "name": str(getattr(backend, "name", type(backend).__name__)),
        "available": _backend_available(backend),
        "reason": None if _backend_available(backend) else _backend_reason(backend),
        "platform": platform_name,
    }


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", True))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "process-memory backend is unavailable"
    )


def _backend_method(backend: Any, operation: str, *, required: bool = True) -> Any:
    for name in _BACKEND_METHOD_NAMES.get(operation, (operation,)):
        method = getattr(backend, name, None)
        if callable(method):
            return method
    if required:
        raise MemoryRuntimeBackendError(operation, f"backend does not implement {operation}")
    return None


def _invoke(method: Any, *args: Any, **kwargs: Any) -> Any:
    """Pass optional keywords only when an injected backend accepts them."""

    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return method(*args, **kwargs)
    accepts_kwargs = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    )
    if accepts_kwargs:
        return method(*args, **kwargs)
    accepted = {key: value for key, value in kwargs.items() if key in signature.parameters}
    return method(*args, **accepted)


def _backend_probe(backend: Any, pid: int) -> Mapping[str, Any]:
    value = _invoke(_backend_method(backend, "probe"), pid)
    return value if isinstance(value, Mapping) else {"pid": pid, "status": "ok", "accessible": bool(value)}


def _backend_regions(backend: Any, pid: int) -> list[dict[str, Any]]:
    value = _invoke(_backend_method(backend, "regions"), pid)
    if isinstance(value, Mapping):
        value = value.get("regions") or []
    return [_normalize_region(item) for item in value or [] if isinstance(item, Mapping)]


def _backend_modules(backend: Any, pid: int) -> list[dict[str, Any]]:
    value = _invoke(_backend_method(backend, "modules"), pid)
    if isinstance(value, Mapping):
        value = value.get("modules") or []
    return [_json_mapping(item) for item in value or [] if isinstance(item, Mapping)]


def _backend_read(backend: Any, pid: int, address: int, size: int) -> bytes:
    value = _invoke(_backend_method(backend, "read"), pid, address, size)
    data = _extract_backend_bytes(value)
    if data is None:
        raise MemoryRuntimeBackendError("read", "backend did not return bytes")
    return data


def _read_bounded_string(
    backend: Any,
    pid: int,
    address: int,
    encoding: str,
    max_bytes: int,
) -> dict[str, Any]:
    normalized_encoding = _normalize_string_encoding(encoding)
    if normalized_encoding is None:
        raise ValueError(f"unsupported string encoding: {encoding}")
    unit_size = 1 if normalized_encoding == "utf-8" else 2
    if max_bytes <= 0 or (unit_size == 2 and max_bytes % 2):
        raise ValueError("string read bound is invalid for the selected encoding")
    raw = bytearray()
    terminator = b"\x00" * unit_size
    terminated = False
    for offset in range(0, max_bytes, unit_size):
        chunk = _backend_read(backend, pid, address + offset, unit_size)
        if len(chunk) != unit_size:
            raise MemoryRuntimeBackendError(
                "string_read",
                "backend returned an incomplete string code unit",
                details={
                    "address": address + offset,
                    "expected_size": unit_size,
                    "actual_size": len(chunk),
                },
            )
        raw.extend(chunk)
        if chunk == terminator:
            terminated = True
            break
    value_bytes = bytes(raw[:-unit_size] if terminated else raw)
    decode_error: Optional[str] = None
    try:
        value = value_bytes.decode(normalized_encoding, errors="strict")
    except UnicodeDecodeError as exc:
        decode_error = str(exc)
        value = value_bytes.decode(normalized_encoding, errors="replace")
    return _prune(
        {
            "address": address,
            "encoding": normalized_encoding,
            "value": value,
            "terminated": terminated,
            "consumed_bytes": len(raw),
            "decoded_bytes": len(value_bytes),
            "decode_status": "ok" if decode_error is None else "replacement",
            "decode_error": decode_error,
            "memory": _bytes_snapshot(bytes(raw), address=address),
            "value_memory": _bytes_snapshot(value_bytes, address=address),
        }
    )


def _resolve_pointer_chain(
    backend: Any,
    pid: int,
    base_address: int,
    offsets: Sequence[Any],
    pointer_size: int,
    endian: str,
) -> dict[str, Any]:
    normalized_endian = _normalize_endian(endian)
    if pointer_size not in {4, 8}:
        raise ValueError("pointer_size must be 4 or 8 bytes")
    if normalized_endian is None:
        raise ValueError("pointer-chain endian must be little or big")
    if not offsets or len(offsets) > _MAX_POINTER_CHAIN_DEPTH:
        raise ValueError(
            f"pointer chain must contain 1 through {_MAX_POINTER_CHAIN_DEPTH} offsets"
        )
    maximum_address = (1 << (pointer_size * 8)) - 1
    current = base_address
    hops: list[dict[str, Any]] = []
    for index, raw_offset in enumerate(offsets):
        offset = _coerce_int(raw_offset)
        if offset is None:
            raise ValueError(f"pointer chain offset {index} must be an integer")
        if not 0 <= current <= maximum_address:
            raise MemoryRuntimeBackendError(
                "pointer_chain",
                "pointer read address is outside the selected pointer width",
                details={"hop": index, "address": current, "hops": hops},
            )
        data = _backend_read(backend, pid, current, pointer_size)
        if len(data) != pointer_size:
            raise MemoryRuntimeBackendError(
                "pointer_chain",
                "backend returned an incomplete pointer",
                details={
                    "hop": index,
                    "address": current,
                    "expected_size": pointer_size,
                    "actual_size": len(data),
                    "hops": hops,
                },
            )
        pointer = int.from_bytes(data, byteorder=normalized_endian, signed=False)
        if pointer == 0:
            raise MemoryRuntimeBackendError(
                "pointer_chain",
                "null pointer encountered",
                details={"hop": index, "address": current, "hops": hops},
            )
        resolved = pointer + offset
        hop = {
            "index": index,
            "read_address": current,
            "read_address_hex": f"0x{current:x}",
            "memory": _bytes_snapshot(data, address=current),
            "pointer_value": pointer,
            "pointer_hex": f"0x{pointer:x}",
            "offset": offset,
            "resolved_address": resolved,
            "resolved_address_hex": f"0x{resolved:x}" if resolved >= 0 else None,
        }
        hops.append(_prune(hop))
        if not 0 <= resolved <= maximum_address:
            raise MemoryRuntimeBackendError(
                "pointer_chain",
                "resolved pointer address is outside the selected pointer width",
                details={"hop": index, "address": resolved, "hops": hops},
            )
        current = resolved
    return {
        "base_address": base_address,
        "base_address_hex": f"0x{base_address:x}",
        "pointer_size": pointer_size,
        "endian": normalized_endian,
        "offsets": list(offsets),
        "hops": hops,
        "depth": len(hops),
        "final_address": current,
        "final_address_hex": f"0x{current:x}",
    }


def _backend_write(
    backend: Any,
    pid: int,
    address: int,
    data: bytes,
    expected: bytes,
) -> Any:
    return _invoke(_backend_method(backend, "write"), pid, address, data, expected)


def _backend_protect(
    backend: Any,
    pid: int,
    address: int,
    size: int,
    protection: int,
) -> Any:
    return _invoke(_backend_method(backend, "protect"), pid, address, size, protection)


def _backend_alloc(
    backend: Any,
    pid: int,
    size: int,
    protection: int,
    *,
    address: Optional[int],
    allocation_type: int,
) -> Any:
    return _invoke(
        _backend_method(backend, "alloc"),
        pid,
        size,
        protection,
        address=address,
        allocation_type=allocation_type,
    )


def _backend_free(
    backend: Any,
    pid: int,
    address: int,
    *,
    size: int,
    free_type: int,
) -> Any:
    return _invoke(
        _backend_method(backend, "free"),
        pid,
        address,
        size=size,
        free_type=free_type,
    )


def _backend_scan(
    backend: Any,
    pid: int,
    pattern: bytes,
    *,
    mask: str,
    start_address: Optional[int],
    end_address: Optional[int],
    max_results: int,
    max_bytes: int,
    chunk_size: int,
) -> Any:
    return _invoke(
        _backend_method(backend, "scan"),
        pid,
        pattern,
        mask=mask,
        start_address=start_address,
        end_address=end_address,
        max_results=max_results,
        max_bytes=max_bytes,
        chunk_size=chunk_size,
    )


def _mapping_result(value: Any, *, operation: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = _json_mapping(value)
    elif isinstance(value, bool):
        result = {"ok": value, "status": "ok" if value else "failed"}
    elif isinstance(value, int):
        result = {"ok": value != 0, "status": "ok" if value else "failed", "address": value}
    elif value is None:
        result = {"ok": False, "status": "failed", "error": "backend returned no result"}
    else:
        result = {"ok": True, "status": "ok", "result": _json_value(value)}
    result.setdefault("operation", operation)
    result.setdefault("side_effects", operation in _MUTATING_ACTIONS and _operation_ok(result))
    return result


def _operation_ok(value: Mapping[str, Any]) -> bool:
    if "ok" in value:
        return bool(value.get("ok"))
    return str(value.get("status") or "").lower() in {"ok", "success", "succeeded", "already_restored"}


def _operation_address(value: Mapping[str, Any]) -> Optional[int]:
    return _coerce_int(
        value.get("address", value.get("base_address", value.get("allocated_address")))
    )


def _normalize_region(value: Mapping[str, Any]) -> dict[str, Any]:
    region = _json_mapping(value)
    base = _coerce_int(region.get("base_address", region.get("address")))
    allocation_base = _coerce_int(region.get("allocation_base"))
    protection = _coerce_int(region.get("protection", region.get("protect")))
    size = _coerce_int(region.get("size", region.get("region_size")))
    region.update(
        {
            "base_address": base,
            "allocation_base": allocation_base if allocation_base is not None else base,
            "size": size,
            "protection": protection,
        }
    )
    if protection is not None:
        region.setdefault("protection_name", _protection_name(protection))
    return region


def _find_region(
    regions: Sequence[Mapping[str, Any]],
    address: Optional[int],
    *,
    include_free: bool = False,
) -> Optional[dict[str, Any]]:
    if address is None:
        return None
    for item in regions:
        region = _normalize_region(item)
        if not include_free and not _region_is_allocated(region):
            continue
        base = _region_base(region)
        size = _coerce_int(region.get("size"))
        if base is not None and size is not None and base <= address < base + size:
            return region
    return None


def _allocation_snapshot(
    regions: Sequence[Mapping[str, Any]], address: int
) -> dict[str, Any]:
    target = _find_region(regions, address)
    if target is None:
        return {
            "present": False,
            "address": address,
            "region_count": 0,
            "recoverable": False,
        }

    allocation_base = _region_allocation_base(target)
    allocation_regions = sorted(
        (
            _normalize_region(item)
            for item in regions
            if _region_is_allocated(item)
            and _region_allocation_base(item) == allocation_base
        ),
        key=lambda item: _region_base(item) or 0,
    )
    single_region = len(allocation_regions) == 1
    exact_base = bool(
        allocation_base == address and _region_base(target) == address
    )
    committed = _region_is_committed(target)
    protection = _region_protection(target)
    readable = (
        bool(target.get("readable"))
        if "readable" in target
        else protection is None or _is_readable_protection(protection)
    )
    region_type = _coerce_int(target.get("type"))
    private = region_type is None or region_type == _MEM_PRIVATE
    size = _coerce_int(target.get("size")) if single_region else None
    recoverable = bool(
        exact_base
        and single_region
        and committed
        and readable
        and private
        and size
        and size > 0
    )
    return {
        "present": True,
        "address": address,
        "base_address": _region_base(target),
        "allocation_base": allocation_base,
        "size": size,
        "region_count": len(allocation_regions),
        "regions": allocation_regions,
        "single_region": single_region,
        "exact_base": exact_base,
        "committed": committed,
        "readable": readable,
        "private": private,
        "type": region_type,
        "recoverable": recoverable,
    }


def _region_snapshot_for(backend: Any, pid: int, address: int) -> dict[str, Any]:
    region = _find_region(_backend_regions(backend, pid), address)
    return {"present": region is not None, "region": region} if region else {"present": False}


def _region_base(region: Mapping[str, Any]) -> Optional[int]:
    return _coerce_int(region.get("base_address", region.get("address")))


def _region_allocation_base(region: Mapping[str, Any]) -> Optional[int]:
    return _coerce_int(region.get("allocation_base", region.get("base_address")))


def _region_protection(value: Mapping[str, Any]) -> Optional[int]:
    region = value.get("region") if isinstance(value.get("region"), Mapping) else value
    return _coerce_int(region.get("protection", region.get("protect"))) if isinstance(region, Mapping) else None


def _region_is_allocated(region: Mapping[str, Any]) -> bool:
    if region.get("allocated") is False:
        return False
    return _coerce_int(region.get("state")) != _MEM_FREE


def _region_is_committed(region: Mapping[str, Any]) -> bool:
    if "committed" in region:
        return bool(region.get("committed"))
    state = _coerce_int(region.get("state"))
    return state is None or state == _MEM_COMMIT


def _region_contains_range(
    region: Mapping[str, Any], address: int, size: int
) -> bool:
    base = _region_base(region)
    region_size = _coerce_int(region.get("size"))
    return bool(
        base is not None
        and region_size is not None
        and size > 0
        and base <= address
        and address + size <= base + region_size
    )


def _bytes_snapshot(data: bytes, *, address: Optional[int] = None) -> dict[str, Any]:
    return {
        "address": address,
        "size": len(data),
        "hex": data.hex(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _snapshot_bytes(value: Any) -> Optional[bytes]:
    if not isinstance(value, Mapping):
        return None
    try:
        return bytes.fromhex(str(value.get("hex") or ""))
    except ValueError:
        return None


def _parameter_bytes(parameters: Mapping[str, Any], key: str) -> Optional[bytes]:
    value = parameters.get(key)
    if value is None:
        return None
    try:
        return bytes.fromhex(str(value))
    except ValueError:
        return None


def _extract_backend_bytes(value: Any) -> Optional[bytes]:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, Mapping):
        for key in ("data", "bytes", "data_hex", "hex"):
            if key not in value:
                continue
            item = value[key]
            if isinstance(item, (bytes, bytearray, memoryview)):
                return bytes(item)
            parsed, error = _parse_bytes_value(item, allow_wildcards=False)
            if error is None:
                return parsed
    return None


def _parse_bytes_value(
    value: Any,
    *,
    allow_wildcards: bool,
) -> tuple[Optional[bytes], Optional[str]]:
    if value is None:
        return None, None
    if isinstance(value, bytes):
        return value, None
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value), None
    if isinstance(value, Sequence) and not isinstance(value, str):
        try:
            return bytes(int(item) for item in value), None
        except (TypeError, ValueError, OverflowError):
            return None, "byte sequence must contain integers from 0 through 255"
    text = str(value).strip()
    if not text:
        return b"", None
    compact = text.replace("0x", "").replace("0X", "")
    for separator in (" ", "-", ":", ",", "_", "\\x"):
        compact = compact.replace(separator, "")
    if allow_wildcards:
        compact = compact.replace("??", "00").replace("?", "0")
    if len(compact) % 2:
        return None, "hex byte input must contain an even number of digits"
    try:
        return bytes.fromhex(compact), None
    except ValueError:
        return None, "byte input must be bytes, integer octets, or hexadecimal text"


def _parse_pattern(value: Any, explicit_mask: Any) -> tuple[Optional[bytes], str, Optional[str]]:
    if value is None:
        return None, "", "scan pattern is required"
    if isinstance(value, (bytes, bytearray, memoryview)):
        pattern = bytes(value)
        mask = str(explicit_mask or "x" * len(pattern)).lower()
    elif isinstance(value, Sequence) and not isinstance(value, str):
        try:
            pattern = bytes(int(item) for item in value)
        except (TypeError, ValueError, OverflowError):
            return None, "", "scan pattern sequence contains an invalid byte"
        mask = str(explicit_mask or "x" * len(pattern)).lower()
    else:
        text = str(value).strip()
        tokens = text.replace(",", " ").replace("-", " ").split()
        if len(tokens) <= 1:
            compact = text.replace("0x", "").replace("0X", "").replace(" ", "")
            if len(compact) % 2:
                return None, "", "scan pattern must contain complete bytes"
            tokens = [compact[index : index + 2] for index in range(0, len(compact), 2)]
        octets: list[int] = []
        generated_mask: list[str] = []
        for token in tokens:
            normalized = token.strip().replace("0x", "").replace("0X", "")
            if normalized in {"?", "??", "**"}:
                octets.append(0)
                generated_mask.append("?")
                continue
            try:
                octets.append(int(normalized, 16))
            except ValueError:
                return None, "", f"invalid scan pattern byte: {token}"
            if not 0 <= octets[-1] <= 255:
                return None, "", f"invalid scan pattern byte: {token}"
            generated_mask.append("x")
        pattern = bytes(octets)
        mask = str(explicit_mask or "".join(generated_mask)).lower()
    mask = mask.replace("1", "x").replace("0", "?")
    if not pattern:
        return None, "", "scan pattern must be non-empty"
    if len(mask) != len(pattern) or any(item not in {"x", "?"} for item in mask):
        return None, "", "scan mask must contain one 'x' or '?' per pattern byte"
    return pattern, mask, None


def _display_pattern(pattern: bytes, mask: str) -> str:
    return " ".join(f"{byte:02X}" if mask[index] == "x" else "??" for index, byte in enumerate(pattern))


def _pattern_offsets(data: bytes, pattern: bytes, mask: str) -> list[int]:
    if not pattern or len(data) < len(pattern):
        return []
    if "?" not in mask:
        offsets: list[int] = []
        start = 0
        while True:
            index = data.find(pattern, start)
            if index < 0:
                return offsets
            offsets.append(index)
            start = index + 1
    return [
        offset
        for offset in range(0, len(data) - len(pattern) + 1)
        if all(mask[index] == "?" or data[offset + index] == byte for index, byte in enumerate(pattern))
    ]


def _parse_protection(value: Any) -> Optional[int]:
    if isinstance(value, str):
        normalized = value.strip().upper()
        if normalized in _PAGE_PROTECTIONS:
            return _PAGE_PROTECTIONS[normalized]
    parsed = _coerce_int(value)
    return parsed if parsed is not None and parsed > 0 else None


def _protection_name(value: int) -> str:
    base = value & 0xFF
    name = _PROTECTION_NAMES.get(base, f"0x{base:x}")
    suffixes = []
    if value & 0x100:
        suffixes.append("PAGE_GUARD")
    if value & 0x200:
        suffixes.append("PAGE_NOCACHE")
    if value & 0x400:
        suffixes.append("PAGE_WRITECOMBINE")
    return "|".join([name, *suffixes])


def _is_readable_protection(value: int) -> bool:
    return not value & 0x100 and (value & 0xFF) in {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}


def _is_writable_protection(value: int) -> bool:
    return not value & 0x100 and (value & 0xFF) in {0x04, 0x08, 0x40, 0x80}


def _is_executable_protection(value: int) -> bool:
    return not value & 0x100 and (value & 0xFF) in {0x10, 0x20, 0x40, 0x80}


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
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
            return int(text, 16) if all(item in "0123456789abcdefABCDEF" for item in text) else None
        except ValueError:
            return None


def _required_int(value: Mapping[str, Any], key: str) -> int:
    parsed = _coerce_int(value.get(key))
    if parsed is None:
        raise ValueError(f"{key} must be an integer")
    return parsed


def _bounded_positive(value: Any, default: int, maximum: int) -> int:
    parsed = _coerce_int(value)
    if parsed is None or parsed <= 0:
        return default
    return min(parsed, maximum)


def _hex_bytes(value: Any, name: str) -> bytes:
    try:
        result = bytes.fromhex(str(value or ""))
    except ValueError as exc:
        raise ValueError(f"{name} is invalid") from exc
    if not result:
        raise ValueError(f"{name} is empty")
    return result


def _pointer_value(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(ctypes.cast(value, ctypes.c_void_p).value or 0)
    except (TypeError, ValueError):
        return int(getattr(value, "value", 0) or 0)


def _canonical_hash(value: Any) -> str:
    payload = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _rollback_before_summary(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "process": snapshot.get("process"),
            "region": snapshot.get("region"),
            "memory": snapshot.get("memory"),
            "precondition_hash": snapshot.get("precondition_hash"),
        }
    )


def _side_effects_observed(
    action: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    operation: Mapping[str, Any],
) -> bool:
    if action not in _MUTATING_ACTIONS:
        return False
    explicit = operation.get("side_effects")
    if isinstance(explicit, bool) and explicit:
        return True
    if action in _WRITE_ACTIONS:
        return _snapshot_bytes(before.get("memory")) != _snapshot_bytes(after.get("memory"))
    if action == "protect":
        return _region_protection(before.get("region") or {}) != _region_protection(after.get("region") or {})
    if action == "alloc":
        return _operation_address(operation) is not None
    return bool(before.get("region")) and not bool(after.get("region"))


def _target_payload(target: Any) -> dict[str, Any]:
    to_dict = getattr(target, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return _json_mapping(payload)
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


def _memory_runtime_audit_payload(
    result: CapabilityExecutionResult,
) -> dict[str, Any]:
    precondition = result.report_section.get("precondition") or {
        "hash": result.provenance.get("precondition_hash")
    }
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
        "session_id": result.session_id,
        "session": {"id": result.session_id},
        "target": _target_payload(result.target),
        "target_identity": _target_payload(result.target),
        "precondition": _json_mapping(precondition),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before": _json_mapping(result.before_snapshot),
        "after": _json_mapping(result.after_snapshot),
        "rollback": _json_mapping(result.rollback_plan),
        "before_snapshot": _json_mapping(result.before_snapshot),
        "after_snapshot": _json_mapping(result.after_snapshot),
        "rollback_plan": _json_mapping(result.rollback_plan),
        "provenance": _json_mapping(result.provenance),
        "artifacts": [artifact.to_dict() for artifact in result.artifacts],
        "evidence_manifest_entries": [
            _json_mapping(entry) for entry in result.evidence_manifest_entries
        ],
        "dashboard_trace": [
            _json_mapping(item) for item in result.dashboard_trace
        ],
        "report": _json_mapping(result.report_section),
        "report_section": _json_mapping(result.report_section),
    }


def _artifact_destination(collection_root: Path, artifact_path: str) -> Path:
    text = str(artifact_path or "").strip()
    windows_path = PureWindowsPath(text)
    posix_path = PurePosixPath(text)
    relative = Path(text)
    if (
        not text
        or text in {".", ".."}
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or posix_path.is_absolute()
        or ".." in windows_path.parts
        or ".." in posix_path.parts
    ):
        raise ValueError("artifact path must stay inside the collection directory")
    destination = (collection_root / relative).resolve()
    if destination != collection_root and collection_root not in destination.parents:
        raise ValueError("artifact path escapes the collection directory")
    return destination


def _sync_audit_report(result: CapabilityExecutionResult) -> None:
    report = result.report_section
    target = _target_payload(result.target)
    report.update(
        {
            "session_id": result.session_id,
            "target_identity": target,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "before": _json_mapping(result.before_snapshot),
            "after": _json_mapping(result.after_snapshot),
            "before_snapshot": _json_mapping(result.before_snapshot),
            "after_snapshot": _json_mapping(result.after_snapshot),
            "rollback_plan": _json_mapping(result.rollback_plan),
            "provenance": _json_mapping(result.provenance),
            "artifacts": [artifact.to_dict() for artifact in result.artifacts],
            "evidence_manifest_entries": [
                _json_mapping(entry) for entry in result.evidence_manifest_entries
            ],
        }
    )
    session = report.setdefault("session", {})
    if isinstance(session, dict):
        session.setdefault("id", result.session_id)


def _exception_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, MemoryRuntimeBackendError):
        return exc.to_dict()
    return {"type": type(exc).__name__, "message": str(exc)}


def _safe_segment(value: Any) -> str:
    safe = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in str(value or "session")
    ).strip(".")
    return safe or "session"


def _deduplicate(items: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


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
