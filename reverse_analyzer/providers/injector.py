"""Controlled Windows DLL injection capability provider."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Optional, Protocol

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
from reverse_analyzer.providers.injector_manual_map import (
    Win32ManualMapper,
    inspect_manual_map_image,
)


_AUDIT_SCHEMA_VERSION = 1
_RISK_SCHEMA_VERSION = "1.0"
_DEFAULT_TIMEOUT_MS = 10_000
_MAX_TIMEOUT_MS = 120_000
_SHA256_LENGTH = 64

_LOAD_LIBRARY = "load_library"
_MANUAL_MAP = "manual_map"
_SUPPORTED_METHODS = {_LOAD_LIBRARY, _MANUAL_MAP}
_METHOD_ALIASES = {
    "inject": _LOAD_LIBRARY,
    "load_library": _LOAD_LIBRARY,
    "load_library_w": _LOAD_LIBRARY,
    "loadlibrary": _LOAD_LIBRARY,
    "loadlibraryw": _LOAD_LIBRARY,
    "remote_thread": _LOAD_LIBRARY,
    "create_remote_thread": _LOAD_LIBRARY,
    "manual_map": _MANUAL_MAP,
    "manualmap": _MANUAL_MAP,
}


class InjectorBackendError(RuntimeError):
    """A Win32 operation failure with serializable audit details."""

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


class InjectorBackend(Protocol):
    """Backend surface used by :class:`InjectorProvider` and fake tests."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_process(self, pid: int) -> Mapping[str, Any]: ...

    def list_modules(self, pid: int) -> list[Mapping[str, Any]]: ...

    def load_library(
        self,
        pid: int,
        dll_path: str,
        timeout_ms: int,
    ) -> Mapping[str, Any]: ...

    def rollback_load_library(
        self,
        pid: int,
        module_handle: Optional[int],
        remote_allocation: Optional[int],
        timeout_ms: int,
    ) -> Mapping[str, Any]: ...

    def release_remote_memory(
        self,
        pid: int,
        remote_allocation: int,
    ) -> Mapping[str, Any]: ...

    def manual_map(
        self,
        pid: int,
        dll_path: str,
        expected_sha256: str,
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]: ...

    def rollback_manual_map(
        self,
        pid: int,
        mapping: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]: ...


class UnavailableInjectorBackend:
    """Backend placeholder used when native Windows APIs cannot be loaded."""

    name = "unavailable"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        return {
            "pid": pid,
            "exists": None,
            "accessible": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
        }

    def list_modules(self, pid: int) -> list[Mapping[str, Any]]:
        del pid
        return []

    def load_library(self, pid: int, dll_path: str, timeout_ms: int) -> Mapping[str, Any]:
        del pid, dll_path, timeout_ms
        return {
            "ok": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
            "side_effects": False,
        }

    def rollback_load_library(
        self,
        pid: int,
        module_handle: Optional[int],
        remote_allocation: Optional[int],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        del pid, module_handle, remote_allocation, timeout_ms
        return {
            "ok": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
            "free_library_attempted": False,
            "memory_release_attempted": False,
        }

    def release_remote_memory(self, pid: int, remote_allocation: int) -> Mapping[str, Any]:
        del pid, remote_allocation
        return {
            "ok": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
        }

    def manual_map(
        self,
        pid: int,
        dll_path: str,
        expected_sha256: str,
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        del pid, dll_path, expected_sha256, expected_identity, timeout_ms
        return {
            "ok": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
            "side_effects": False,
        }

    def rollback_manual_map(
        self,
        pid: int,
        mapping: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        del pid, mapping, expected_identity, timeout_ms
        return {
            "ok": False,
            "status": "unavailable",
            "reason": self.unavailable_reason,
            "mapping_released": False,
            "release_verified": False,
        }


class WindowsInjectorBackend:
    """ctypes backend for controlled CreateRemoteThread/LoadLibraryW injection."""

    name = "windows_ctypes"

    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    REQUIRED_PROCESS_ACCESS = (
        PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )

    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    MEM_RELEASE = 0x8000
    PAGE_READWRITE = 0x04
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    WAIT_OBJECT_0 = 0x00000000
    WAIT_TIMEOUT = 0x00000102
    WAIT_FAILED = 0xFFFFFFFF
    ERROR_NO_MORE_FILES = 18
    ERROR_INVALID_PARAMETER = 87
    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x00000002
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x00000004

    def __init__(self) -> None:
        self.available = sys.platform == "win32"
        self.unavailable_reason: Optional[str] = None
        self._kernel32: Any = None
        self._module_entry_type: Any = None
        self._memory_basic_information_type: Any = None
        self._manual_mapper: Optional[Win32ManualMapper] = None
        if not self.available:
            self.unavailable_reason = f"Windows injection is unavailable on {sys.platform}"
            return
        try:
            self._configure_api()
            self._manual_mapper = Win32ManualMapper(self)
        except Exception as exc:  # pragma: no cover - depends on host Win32 setup
            self.available = False
            self.unavailable_reason = f"failed to initialize Win32 API bindings: {exc}"

    def _configure_api(self) -> None:  # pragma: no cover - exercised only on Windows
        from ctypes import wintypes

        byte_pointer = ctypes.POINTER(ctypes.c_ubyte)

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

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
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

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        size_t = ctypes.c_size_t
        void_pointer = ctypes.c_void_p

        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
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
        kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            void_pointer,
            size_t,
            ctypes.POINTER(size_t),
        ]
        kernel32.WriteProcessMemory.restype = wintypes.BOOL
        kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            void_pointer,
            size_t,
            ctypes.POINTER(size_t),
        ]
        kernel32.ReadProcessMemory.restype = wintypes.BOOL
        kernel32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.VirtualProtectEx.restype = wintypes.BOOL
        kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            ctypes.POINTER(MEMORY_BASIC_INFORMATION),
            size_t,
        ]
        kernel32.VirtualQueryEx.restype = size_t
        kernel32.FlushInstructionCache.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
        ]
        kernel32.FlushInstructionCache.restype = wintypes.BOOL
        kernel32.CreateRemoteThread.argtypes = [
            wintypes.HANDLE,
            void_pointer,
            size_t,
            void_pointer,
            void_pointer,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.CreateRemoteThread.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeThread.restype = wintypes.BOOL
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HANDLE
        kernel32.GetModuleHandleExW.argtypes = [
            wintypes.DWORD,
            void_pointer,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        kernel32.GetModuleHandleExW.restype = wintypes.BOOL
        kernel32.GetModuleFileNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        kernel32.GetModuleFileNameW.restype = wintypes.DWORD
        kernel32.GetProcAddress.argtypes = [wintypes.HANDLE, wintypes.LPCSTR]
        kernel32.GetProcAddress.restype = void_pointer
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
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        if hasattr(kernel32, "IsWow64Process2"):
            kernel32.IsWow64Process2.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.USHORT),
                ctypes.POINTER(wintypes.USHORT),
            ]
            kernel32.IsWow64Process2.restype = wintypes.BOOL
        kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
        kernel32.IsWow64Process.restype = wintypes.BOOL

        self._kernel32 = kernel32
        self._module_entry_type = MODULEENTRY32W
        self._memory_basic_information_type = MEMORY_BASIC_INFORMATION

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        if not self.available:
            return {
                "pid": pid,
                "exists": None,
                "accessible": False,
                "status": "unavailable",
                "reason": self.unavailable_reason,
            }
        handle = self._kernel32.OpenProcess(self.REQUIRED_PROCESS_ACCESS, False, pid)
        if handle:
            try:
                try:
                    identity = self._process_identity(handle, pid)
                    identity_status = "ok"
                    identity_error = None
                except Exception as exc:
                    identity = {"pid": pid}
                    identity_status = "failed"
                    identity_error = _exception_payload(exc)
                return {
                    **identity,
                    "pid": pid,
                    "exists": True,
                    "accessible": True,
                    "required_access": self.REQUIRED_PROCESS_ACCESS,
                    "status": "ok",
                    "identity_status": identity_status,
                    "identity_error": identity_error,
                }
            finally:
                self._kernel32.CloseHandle(handle)
        code = ctypes.get_last_error()
        return {
            "pid": pid,
            "exists": False if code == self.ERROR_INVALID_PARAMETER else None,
            "accessible": False,
            "required_access": self.REQUIRED_PROCESS_ACCESS,
            "status": "failed",
            "winerror": code,
            "error": ctypes.FormatError(code).strip(),
        }

    def list_modules(self, pid: int) -> list[Mapping[str, Any]]:
        self._require_available("CreateToolhelp32Snapshot")
        flags = self.TH32CS_SNAPMODULE | self.TH32CS_SNAPMODULE32
        snapshot = self._kernel32.CreateToolhelp32Snapshot(flags, pid)
        if _pointer_value(snapshot) == ctypes.c_void_p(-1).value:
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
        return modules

    def load_library(self, pid: int, dll_path: str, timeout_ms: int) -> Mapping[str, Any]:
        """Write a UTF-16 path and run LoadLibraryW in the target process."""

        self._require_available("LoadLibraryW")
        process: Any = None
        remote_allocation: Optional[int] = None
        thread_started = False
        wait_completed = False
        memory_released = False
        api_calls: list[dict[str, Any]] = []
        payload = (dll_path + "\0").encode("utf-16-le")

        try:
            process = self._open_process(pid)
            api_calls.append({"api": "OpenProcess", "status": "ok"})

            remote_pointer = self._kernel32.VirtualAllocEx(
                process,
                None,
                len(payload),
                self.MEM_RESERVE | self.MEM_COMMIT,
                self.PAGE_READWRITE,
            )
            remote_allocation = _pointer_value(remote_pointer)
            if not remote_allocation:
                raise self._last_error("VirtualAllocEx")
            api_calls.append(
                {
                    "api": "VirtualAllocEx",
                    "status": "ok",
                    "address": remote_allocation,
                    "size": len(payload),
                }
            )

            written = ctypes.c_size_t(0)
            buffer = ctypes.create_string_buffer(payload)
            write_ok = self._kernel32.WriteProcessMemory(
                process,
                ctypes.c_void_p(remote_allocation),
                ctypes.cast(buffer, ctypes.c_void_p),
                len(payload),
                ctypes.byref(written),
            )
            if not write_ok:
                raise self._last_error("WriteProcessMemory")
            if int(written.value) != len(payload):
                raise InjectorBackendError(
                    "WriteProcessMemory",
                    "partial write",
                    details={"expected": len(payload), "actual": int(written.value)},
                )
            api_calls.append(
                {
                    "api": "WriteProcessMemory",
                    "status": "ok",
                    "bytes_written": int(written.value),
                }
            )

            start_address, export_evidence = self._remote_export_address(
                pid,
                module_name="kernel32.dll",
                export_name="LoadLibraryW",
            )
            api_calls.append(
                {
                    "api": "GetProcAddress",
                    "status": "ok",
                    **export_evidence,
                }
            )
            thread_result = self._run_remote_thread(
                process,
                start_address=start_address,
                parameter=remote_allocation,
                timeout_ms=timeout_ms,
            )
            thread_started = True
            wait_completed = True
            api_calls.extend(thread_result["api_calls"])
            exit_code = int(thread_result["exit_code"])
            ok = exit_code != 0
            if not ok:
                memory_released = self._virtual_free(process, remote_allocation)
                api_calls.append(
                    {
                        "api": "VirtualFreeEx",
                        "status": "ok" if memory_released else "failed",
                        "reason": "LoadLibraryW returned NULL",
                    }
                )
            return {
                "ok": ok,
                "status": "ok" if ok else "failed",
                "method": _LOAD_LIBRARY,
                "pid": pid,
                "dll_path": dll_path,
                "payload_encoding": "utf-16-le",
                "payload_size": len(payload),
                "bytes_written": len(payload),
                "thread_id": thread_result["thread_id"],
                "thread_exit_code": exit_code,
                "remote_allocation": remote_allocation,
                "temporary_memory_retained": ok,
                "temporary_memory_released": memory_released,
                "safe_to_release": True,
                "api_calls": api_calls,
                "error": None if ok else "LoadLibraryW returned NULL",
            }
        except Exception as exc:  # pragma: no cover - native failure paths
            details = _exception_payload(exc)
            if isinstance(exc, InjectorBackendError):
                thread_started = thread_started or bool(exc.details.get("thread_started"))
                wait_completed = wait_completed or bool(exc.details.get("wait_completed"))
            safe_to_release = not thread_started or wait_completed
            if process and remote_allocation and safe_to_release:
                memory_released = self._virtual_free(process, remote_allocation)
                api_calls.append(
                    {
                        "api": "VirtualFreeEx",
                        "status": "ok" if memory_released else "failed",
                        "reason": "failure cleanup",
                    }
                )
            return {
                "ok": False,
                "status": "failed",
                "method": _LOAD_LIBRARY,
                "pid": pid,
                "dll_path": dll_path,
                "remote_allocation": remote_allocation,
                "temporary_memory_retained": bool(remote_allocation and not memory_released),
                "temporary_memory_released": memory_released,
                "safe_to_release": safe_to_release,
                "thread_started": thread_started,
                "wait_completed": wait_completed,
                "api_calls": api_calls,
                "error": details,
            }
        finally:
            if process:
                self._kernel32.CloseHandle(process)

    def rollback_load_library(
        self,
        pid: int,
        module_handle: Optional[int],
        remote_allocation: Optional[int],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        """Attempt FreeLibrary and always attempt temporary-memory release."""

        self._require_available("FreeLibrary")
        process: Any = None
        free_library_ok = False
        memory_released = remote_allocation is None
        errors: list[dict[str, Any]] = []
        api_calls: list[dict[str, Any]] = []
        try:
            process = self._open_process(pid)
            api_calls.append({"api": "OpenProcess", "status": "ok"})

            if module_handle:
                try:
                    start_address, export_evidence = self._remote_export_address(
                        pid,
                        module_name="kernel32.dll",
                        export_name="FreeLibrary",
                    )
                    api_calls.append(
                        {
                            "api": "GetProcAddress",
                            "status": "ok",
                            **export_evidence,
                        }
                    )
                    thread_result = self._run_remote_thread(
                        process,
                        start_address=start_address,
                        parameter=int(module_handle),
                        timeout_ms=timeout_ms,
                    )
                    api_calls.extend(thread_result["api_calls"])
                    free_library_ok = int(thread_result["exit_code"]) != 0
                    if not free_library_ok:
                        errors.append(
                            {
                                "operation": "FreeLibrary",
                                "message": "FreeLibrary returned FALSE",
                            }
                        )
                except Exception as exc:  # pragma: no cover - native failure paths
                    errors.append(_exception_payload(exc))
            else:
                errors.append(
                    {
                        "operation": "FreeLibrary",
                        "message": "module handle is unavailable",
                    }
                )

            if remote_allocation is not None:
                memory_released = self._virtual_free(process, int(remote_allocation))
                api_calls.append(
                    {
                        "api": "VirtualFreeEx",
                        "status": "ok" if memory_released else "failed",
                        "address": int(remote_allocation),
                    }
                )
                if not memory_released:
                    errors.append(
                        {
                            "operation": "VirtualFreeEx",
                            "message": "temporary remote memory was not released",
                            "winerror": ctypes.get_last_error(),
                        }
                    )
        except Exception as exc:  # pragma: no cover - native failure paths
            errors.append(_exception_payload(exc))
        finally:
            if process:
                self._kernel32.CloseHandle(process)

        ok = free_library_ok and memory_released
        return {
            "ok": ok,
            "status": "ok" if ok else "failed",
            "pid": pid,
            "module_handle": module_handle,
            "remote_allocation": remote_allocation,
            "free_library_attempted": module_handle is not None,
            "free_library_ok": free_library_ok,
            "memory_release_attempted": remote_allocation is not None,
            "memory_released": memory_released,
            "api_calls": api_calls,
            "errors": errors,
        }

    def release_remote_memory(self, pid: int, remote_allocation: int) -> Mapping[str, Any]:
        self._require_available("VirtualFreeEx")
        process: Any = None
        try:
            process = self._open_process(pid)
            released = self._virtual_free(process, remote_allocation)
            return {
                "ok": released,
                "status": "ok" if released else "failed",
                "pid": pid,
                "remote_allocation": remote_allocation,
                "memory_release_attempted": True,
                "memory_released": released,
                "winerror": None if released else ctypes.get_last_error(),
            }
        finally:
            if process:
                self._kernel32.CloseHandle(process)

    def manual_map(
        self,
        pid: int,
        dll_path: str,
        expected_sha256: str,
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        self._require_available("manual_map")
        if self._manual_mapper is None:
            raise InjectorBackendError("manual_map", "native manual mapper is unavailable")
        return self._manual_mapper.map_image(
            pid,
            dll_path,
            expected_sha256,
            expected_identity,
            timeout_ms,
        )

    def rollback_manual_map(
        self,
        pid: int,
        mapping: Mapping[str, Any],
        expected_identity: Mapping[str, Any],
        timeout_ms: int,
    ) -> Mapping[str, Any]:
        self._require_available("rollback_manual_map")
        if self._manual_mapper is None:
            raise InjectorBackendError(
                "rollback_manual_map",
                "native manual mapper is unavailable",
            )
        return self._manual_mapper.rollback_image(
            pid,
            mapping,
            expected_identity,
            timeout_ms,
        )

    def _open_process(self, pid: int) -> Any:
        handle = self._kernel32.OpenProcess(self.REQUIRED_PROCESS_ACCESS, False, pid)
        if not handle:
            raise self._last_error(
                "OpenProcess",
                details={"pid": pid, "required_access": self.REQUIRED_PROCESS_ACCESS},
            )
        return handle

    def _process_identity(self, process: Any, pid: int) -> dict[str, Any]:
        from ctypes import wintypes

        path_buffer = ctypes.create_unicode_buffer(32768)
        path_length = wintypes.DWORD(len(path_buffer))
        if not self._kernel32.QueryFullProcessImageNameW(
            process,
            0,
            path_buffer,
            ctypes.byref(path_length),
        ):
            raise self._last_error("QueryFullProcessImageNameW", details={"pid": pid})

        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not self._kernel32.GetProcessTimes(
            process,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise self._last_error("GetProcessTimes", details={"pid": pid})
        creation_time = (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

        process_machine = 0
        native_machine = 0
        if hasattr(self._kernel32, "IsWow64Process2"):
            process_value = wintypes.USHORT(0)
            native_value = wintypes.USHORT(0)
            if not self._kernel32.IsWow64Process2(
                process,
                ctypes.byref(process_value),
                ctypes.byref(native_value),
            ):
                raise self._last_error("IsWow64Process2", details={"pid": pid})
            process_machine = int(process_value.value)
            native_machine = int(native_value.value)
            machine = process_machine or native_machine
        else:
            wow64 = wintypes.BOOL(False)
            if not self._kernel32.IsWow64Process(process, ctypes.byref(wow64)):
                raise self._last_error("IsWow64Process", details={"pid": pid})
            if wow64.value:
                machine = 0x014C
                process_machine = machine
                native_machine = 0x8664
            else:
                machine = 0x8664 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x014C
                native_machine = machine
        architecture = {0x014C: "x86", 0x8664: "x64"}.get(machine, "unsupported")
        injector_machine = 0x8664 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0x014C
        return {
            "pid": pid,
            "creation_time_100ns": creation_time,
            "image_path": path_buffer.value,
            "machine": machine,
            "machine_hex": f"0x{machine:04x}",
            "architecture": architecture,
            "process_machine": process_machine,
            "native_machine": native_machine,
            "injector_machine": injector_machine,
            "injector_architecture": {
                0x014C: "x86",
                0x8664: "x64",
            }[injector_machine],
        }

    def _remote_export_address(
        self,
        pid: int,
        *,
        module_name: str,
        export_name: str,
    ) -> tuple[int, dict[str, Any]]:
        local_module = self._kernel32.GetModuleHandleW(module_name)
        if not local_module:
            raise self._last_error("GetModuleHandleW", details={"module": module_name})
        local_export = self._kernel32.GetProcAddress(local_module, export_name.encode("ascii"))
        if not local_export:
            raise self._last_error(
                "GetProcAddress",
                details={"module": module_name, "export": export_name},
            )

        local_base = _pointer_value(local_module)
        local_address = _pointer_value(local_export)
        owner_module = ctypes.c_void_p()
        owner_flags = (
            self.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            | self.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT
        )
        if not self._kernel32.GetModuleHandleExW(
            owner_flags,
            ctypes.c_void_p(local_address),
            ctypes.byref(owner_module),
        ):
            raise self._last_error(
                "GetModuleHandleExW",
                details={"export": export_name, "address": local_address},
            )
        owner_path_buffer = ctypes.create_unicode_buffer(32768)
        owner_path_length = self._kernel32.GetModuleFileNameW(
            owner_module,
            owner_path_buffer,
            len(owner_path_buffer),
        )
        if not owner_path_length:
            raise self._last_error(
                "GetModuleFileNameW",
                details={"export": export_name, "address": local_address},
            )
        owner_path = owner_path_buffer.value
        owner_name = _path_name(owner_path)
        owner_base = _pointer_value(owner_module)
        export_offset = local_address - owner_base
        remote_module = next(
            (
                module
                for module in self.list_modules(pid)
                if str(module.get("name") or "").casefold() == owner_name.casefold()
            ),
            None,
        )
        if remote_module is None or not _coerce_address(remote_module.get("base_address")):
            raise InjectorBackendError(
                "CreateToolhelp32Snapshot",
                f"{owner_name} is not present in target process",
                details={"pid": pid, "requested_module": module_name},
            )
        remote_base = int(_coerce_address(remote_module.get("base_address")) or 0)
        remote_address = remote_base + export_offset
        return remote_address, {
            "module": module_name,
            "export": export_name,
            "local_module_base": local_base,
            "export_owner_module": owner_name,
            "export_owner_path": owner_path,
            "local_export_owner_base": owner_base,
            "remote_module_base": remote_base,
            "export_offset": export_offset,
            "remote_export_address": remote_address,
        }

    def _run_remote_thread(
        self,
        process: Any,
        *,
        start_address: int,
        parameter: int,
        timeout_ms: int,
    ) -> dict[str, Any]:
        from ctypes import wintypes

        thread_id = wintypes.DWORD(0)
        thread = self._kernel32.CreateRemoteThread(
            process,
            None,
            0,
            ctypes.c_void_p(start_address),
            ctypes.c_void_p(parameter),
            0,
            ctypes.byref(thread_id),
        )
        if not thread:
            raise self._last_error("CreateRemoteThread")
        api_calls = [
            {
                "api": "CreateRemoteThread",
                "status": "ok",
                "thread_id": int(thread_id.value),
                "start_address": start_address,
            }
        ]
        try:
            wait_status = int(self._kernel32.WaitForSingleObject(thread, timeout_ms))
            if wait_status == self.WAIT_TIMEOUT:
                raise InjectorBackendError(
                    "WaitForSingleObject",
                    "remote thread timed out",
                    details={
                        "thread_started": True,
                        "wait_completed": False,
                        "wait_status": wait_status,
                        "timeout_ms": timeout_ms,
                    },
                )
            if wait_status == self.WAIT_FAILED:
                raise self._last_error(
                    "WaitForSingleObject",
                    details={
                        "thread_started": True,
                        "wait_completed": False,
                        "wait_status": wait_status,
                    },
                )
            if wait_status != self.WAIT_OBJECT_0:
                raise InjectorBackendError(
                    "WaitForSingleObject",
                    f"unexpected wait status 0x{wait_status:08x}",
                    details={
                        "thread_started": True,
                        "wait_completed": False,
                        "wait_status": wait_status,
                    },
                )
            api_calls.append(
                {
                    "api": "WaitForSingleObject",
                    "status": "ok",
                    "wait_status": wait_status,
                    "timeout_ms": timeout_ms,
                }
            )

            exit_code = wintypes.DWORD(0)
            if not self._kernel32.GetExitCodeThread(thread, ctypes.byref(exit_code)):
                raise self._last_error(
                    "GetExitCodeThread",
                    details={"thread_started": True, "wait_completed": True},
                )
            api_calls.append(
                {
                    "api": "GetExitCodeThread",
                    "status": "ok",
                    "exit_code": int(exit_code.value),
                }
            )
            return {
                "thread_id": int(thread_id.value),
                "exit_code": int(exit_code.value),
                "api_calls": api_calls,
            }
        finally:
            self._kernel32.CloseHandle(thread)

    def _virtual_free(self, process: Any, address: int) -> bool:
        return bool(
            self._kernel32.VirtualFreeEx(
                process,
                ctypes.c_void_p(address),
                0,
                self.MEM_RELEASE,
            )
        )

    def _last_error(
        self,
        operation: str,
        *,
        code: Optional[int] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> InjectorBackendError:
        error_code = ctypes.get_last_error() if code is None else code
        return InjectorBackendError(
            operation,
            ctypes.FormatError(error_code).strip() or f"Win32 error {error_code}",
            code=error_code,
            details=details,
        )

    def _require_available(self, operation: str) -> None:
        if not self.available:
            raise InjectorBackendError(
                operation,
                self.unavailable_reason or "Windows backend is unavailable",
            )


class InjectorProvider:
    """Plan, validate, execute, audit, and roll back controlled DLL injection."""

    capability_name = "injector"
    provider_name = "windows_controlled_injector"
    priority = 10

    def __init__(
        self,
        backend: Optional[InjectorBackend] = None,
        *,
        platform_name: Optional[str] = None,
        timeout_ms: int = _DEFAULT_TIMEOUT_MS,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.timeout_ms = _bounded_timeout(timeout_ms)
        if backend is not None:
            self.backend: InjectorBackend = backend
        elif self.platform_name == "win32":
            native_backend = WindowsInjectorBackend()
            self.backend = native_backend
        else:
            self.backend = UnavailableInjectorBackend(
                f"Windows injection is unavailable on {self.platform_name}"
            )

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _request_method(request) in _SUPPORTED_METHODS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        method = _request_method(request)
        session_id = request.session_id or "injector-session"
        raw_pid, pid, pid_conflict = _request_pid(request)
        declared_path = _request_dll_path(request)
        dll_path = _resolved_path(declared_path)
        dll_snapshot = _dll_snapshot(dll_path)
        manual_map_image = (
            inspect_manual_map_image(dll_path) if method == _MANUAL_MAP else None
        )
        declared_hash = _request_dll_hash(request, declared_path)
        requested_timeout = request.params.get("timeout_ms", self.timeout_ms)
        timeout_ms = _bounded_timeout(requested_timeout, default=self.timeout_ms)
        risk_assessment = _risk_assessment(method)
        backend_info = _backend_info(backend, platform_name=self.platform_name)

        parameters = {
            **_json_mapping(request.params),
            "method": method,
            "pid": pid if pid is not None else raw_pid,
            "pid_conflict": pid_conflict,
            "dll_path": dll_path,
            "declared_dll_path": declared_path,
            "dll_path_is_absolute": _is_absolute_path(declared_path),
            "expected_sha256": declared_hash or dll_snapshot.get("sha256"),
            "declared_sha256": declared_hash,
            "timeout_ms": timeout_ms,
            "requested_timeout_ms": _json_value(requested_timeout),
            "risk_schema_version": _RISK_SCHEMA_VERSION,
            "risk_assessment": risk_assessment,
            "manual_map_image": manual_map_image,
        }
        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "plan",
            "platform": self.platform_name,
            "backend": backend_info,
            "process": {
                "pid": pid if pid is not None else raw_pid,
                "status": "not_probed",
                "reason": "process access is checked during validation and execution",
            },
            "dll": dll_snapshot,
            "manual_map_image": manual_map_image,
            "modules": [],
            "module_evidence": {
                "status": "not_captured",
                "reason": "modules are captured immediately before execution",
            },
        }
        rollback_plan = _initial_rollback_plan(
            method=method,
            pid=pid,
            dll_path=dll_path,
            dll_sha256=dll_snapshot.get("sha256"),
        )
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=method,
            parameters=parameters,
            steps=_plan_steps(method),
            precondition_hash=dll_snapshot.get("sha256"),
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "backend": backend_info,
                "platform": self.platform_name,
                "method": method,
                "requested_action": request.action,
                "pid": pid if pid is not None else raw_pid,
                "dll_path": dll_path,
                "declared_dll_path": declared_path,
                "declared_sha256": declared_hash,
                "planned_sha256": dll_snapshot.get("sha256"),
                "risk_assessment": risk_assessment,
                "manual_map_image": manual_map_image,
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        validation, _, _ = self._validate_plan(plan, context=context)
        return validation

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        method = _normalize_method(plan.parameters.get("method") or plan.action)
        validation, process_probe, before_modules = self._validate_plan(plan, context=context)
        current_dll = _dll_snapshot(str(plan.parameters.get("dll_path") or ""))
        before_snapshot = _execution_snapshot(
            plan,
            process_probe=process_probe,
            dll_snapshot=current_dll,
            modules=before_modules,
            validation=validation,
        )

        if method not in _SUPPORTED_METHODS:
            reason = f"unsupported injector method: {method or plan.action}"
            return self._result(
                plan,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={"side_effects": False},
                rollback_plan=_non_execution_rollback_plan(
                    plan.rollback_plan,
                    status="failed",
                    reason=reason,
                ),
                validation=validation,
                operation={"status": "failed", "side_effects": False, "reason": reason},
                errors=[reason],
            )

        if not _backend_available(backend):
            reason = _backend_reason(backend)
            return self._result(
                plan,
                status="unavailable",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "modules": before_modules,
                },
                rollback_plan=_non_execution_rollback_plan(
                    plan.rollback_plan,
                    status="unavailable",
                    reason=reason,
                ),
                validation=validation,
                operation={
                    "method": method,
                    "status": "unavailable",
                    "reason": reason,
                    "side_effects": False,
                },
                errors=[reason],
            )

        if not validation.ok:
            return self._result(
                plan,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot={
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "side_effects": False,
                    "modules": before_modules,
                },
                rollback_plan=_non_execution_rollback_plan(
                    plan.rollback_plan,
                    status="blocked",
                    reason="execution was blocked by plan validation",
                ),
                validation=validation,
                operation={
                    "method": method,
                    "status": "blocked",
                    "side_effects": False,
                    "reason": "plan validation failed",
                },
                errors=list(validation.errors),
            )

        pid = _coerce_pid(plan.parameters.get("pid"))
        dll_path = str(plan.parameters.get("dll_path") or "")
        timeout_ms = _bounded_timeout(
            plan.parameters.get("timeout_ms"),
            default=self.timeout_ms,
        )
        if method == _MANUAL_MAP:
            expected_identity = _manual_map_target_identity(process_probe)
            try:
                operation = _json_mapping(
                    backend.manual_map(
                        int(pid),
                        dll_path,
                        str(plan.precondition_hash or ""),
                        expected_identity,
                        timeout_ms,
                    )
                )
            except Exception as exc:
                operation = {
                    "ok": False,
                    "status": "failed",
                    "method": method,
                    "side_effects": "unknown",
                    "error": _exception_payload(exc),
                }

            after_modules, modules_error = _capture_modules(backend, int(pid))
            after_dll = _dll_snapshot(dll_path)
            assessment = inspect_manual_map_image(dll_path)
            evidence_errors = _manual_map_evidence_errors(
                operation,
                assessment=assessment,
                expected_sha256=str(plan.precondition_hash or ""),
                expected_identity=expected_identity,
            )
            if modules_error:
                evidence_errors.append("unable to capture target modules after manual mapping")
            if _find_module(after_modules, dll_path) is not None:
                evidence_errors.append(
                    "manual-mapped DLL unexpectedly appeared in the loader module list"
                )
            if after_dll.get("sha256") != plan.precondition_hash:
                evidence_errors.append("DLL changed during execution")
            status = "ok" if bool(operation.get("ok")) and not evidence_errors else "failed"
            errors: list[Any] = list(evidence_errors)
            if not operation.get("ok"):
                errors.insert(0, operation.get("error") or "manual-map backend failed")

            rollback_metadata = (
                dict(operation.get("rollback"))
                if isinstance(operation.get("rollback"), Mapping)
                else {
                    "safe_to_unmap": operation.get("safe_to_unmap"),
                    "image_base": operation.get("image_base"),
                    "image_size": operation.get("image_size"),
                    "entry_point_address": operation.get("entry_point_address"),
                    "architecture": assessment.get("architecture"),
                    "attach_succeeded": False,
                    "dependencies": operation.get("dependencies") or [],
                    "target_identity": operation.get("target_identity") or expected_identity,
                }
            )
            mapping_retained = bool(operation.get("image_retained")) or bool(
                operation.get("ok")
                and _coerce_address(operation.get("image_base"))
                and rollback_metadata.get("safe_to_unmap")
            )
            rollback_dependencies = [
                dict(item)
                for item in rollback_metadata.get("dependencies", [])
                if isinstance(item, Mapping)
                and item.get("reference_added")
                and not item.get("released")
            ]
            dependencies_retained = bool(rollback_dependencies)
            rollback_metadata["dependencies"] = rollback_dependencies
            rollback_supported = (mapping_retained or dependencies_retained) and bool(
                rollback_metadata.get("safe_to_unmap")
            )
            rollback_plan = dict(plan.rollback_plan or {})
            rollback_plan.update(
                {
                    "supported": rollback_supported,
                    "mode": (
                        "manual_unmap"
                        if rollback_supported
                        else "blocked" if mapping_retained else "not_required"
                    ),
                    "status": "pending" if rollback_supported else "not_required",
                    "pid": pid,
                    "dll_path": dll_path,
                    "dll_sha256": plan.precondition_hash,
                    "mapping": rollback_metadata,
                    "target_identity": expected_identity,
                    "mapping_release_required": mapping_retained,
                    "dependency_release_required": dependencies_retained,
                    "release_verification_required": mapping_retained,
                }
            )
            after_snapshot = {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "after",
                "side_effects": operation.get("side_effects", mapping_retained),
                "dll": after_dll,
                "manual_map_image": assessment,
                "process": operation.get("target_identity"),
                "modules": after_modules,
                "module_snapshot_error": modules_error,
                "loader_visibility": {
                    "expected": "absent",
                    "present": _find_module(after_modules, dll_path) is not None,
                },
                "operation": operation,
            }
            return self._result(
                plan,
                status=status,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                validation=validation,
                operation=operation,
                errors=errors,
            )

        try:
            operation = _json_mapping(backend.load_library(int(pid), dll_path, timeout_ms))
        except Exception as exc:
            operation = {
                "ok": False,
                "status": "failed",
                "method": method,
                "side_effects": "unknown",
                "error": _exception_payload(exc),
            }

        after_modules, modules_error = _capture_modules(backend, int(pid))
        evidence = _module_evidence(before_modules, after_modules, dll_path)
        after_dll = _dll_snapshot(dll_path)
        evidence_ok = bool(evidence.get("observed_transition"))
        operation_ok = bool(operation.get("ok"))
        hash_unchanged = after_dll.get("sha256") == plan.precondition_hash
        status = "ok" if operation_ok and evidence_ok and hash_unchanged and not modules_error else "failed"

        errors: list[Any] = []
        if not operation_ok:
            errors.append(operation.get("error") or "LoadLibraryW backend failed")
        if modules_error:
            errors.append({"operation": "module_snapshot_after", "error": modules_error})
        if not evidence_ok:
            errors.append("target module was not observed in the post-execution module snapshot")
        if not hash_unchanged:
            errors.append("DLL changed during execution")

        remote_allocation = _coerce_address(operation.get("remote_allocation"))
        cleanup: Optional[dict[str, Any]] = None
        if status != "ok" and remote_allocation and not operation.get("temporary_memory_released"):
            if bool(operation.get("safe_to_release", True)):
                cleanup = self._release_remote_memory(backend, int(pid), remote_allocation)
                operation["failure_cleanup"] = cleanup

        loaded_module = evidence.get("loaded_module") or {}
        module_handle = _coerce_address(loaded_module.get("base_address"))
        if module_handle is None:
            module_handle = _coerce_address(operation.get("module_handle"))
        rollback_plan = dict(plan.rollback_plan or {})
        rollback_plan.update(
            {
                "supported": status == "ok",
                "mode": "remote_free_library" if status == "ok" else "failure_cleanup",
                "pid": pid,
                "dll_path": dll_path,
                "dll_sha256": plan.precondition_hash,
                "module_handle": module_handle,
                "remote_allocation": (
                    None
                    if operation.get("temporary_memory_released")
                    or bool(cleanup and cleanup.get("memory_released"))
                    else remote_allocation
                ),
                "free_library_required": status == "ok",
                "temporary_memory_release_required": bool(
                    remote_allocation
                    and not operation.get("temporary_memory_released")
                    and not bool(cleanup and cleanup.get("memory_released"))
                ),
            }
        )
        after_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "after",
            "side_effects": bool(operation.get("thread_id") or evidence_ok),
            "dll": after_dll,
            "modules": after_modules,
            "module_snapshot_error": modules_error,
            "module_evidence": evidence,
            "operation": operation,
        }
        return self._result(
            plan,
            status=status,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            validation=validation,
            operation=operation,
            errors=errors,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        backend = self._select_backend(context)
        method = _normalize_method(
            result.provenance.get("method")
            or result.report_section.get("method")
            or result.action
        )
        rollback_plan = dict(result.rollback_plan or {})
        if method == _MANUAL_MAP:
            pid = _coerce_pid(rollback_plan.get("pid") or result.target.pid)
            mapping = rollback_plan.get("mapping")
            expected_identity = rollback_plan.get("target_identity")
            if not rollback_plan.get("mapping_release_required"):
                details = {
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "status": "not_required",
                    "method": _MANUAL_MAP,
                    "reason": "manual-map execution retained no image allocation",
                    "mapping_release_attempted": False,
                    "mapping_released": True,
                    "release_verified": True,
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
            if pid is None:
                return self._rollback_failure(result, "manual-map rollback PID is invalid")
            if not isinstance(mapping, Mapping) or not isinstance(expected_identity, Mapping):
                return self._rollback_failure(
                    result,
                    "manual-map rollback metadata or target identity is missing",
                )
            if not rollback_plan.get("supported") or not mapping.get("safe_to_unmap"):
                return self._rollback_failure(
                    result,
                    "manual-map rollback is blocked because unmapping is not proven safe",
                    status="blocked",
                )
            if not _backend_available(backend):
                return self._rollback_failure(
                    result,
                    _backend_reason(backend),
                    status="unavailable",
                )
            rollback_method = getattr(backend, "rollback_manual_map", None)
            if not callable(rollback_method):
                return self._rollback_failure(
                    result,
                    "backend does not provide manual-map rollback",
                    status="unavailable",
                )
            timeout_ms = _bounded_timeout(
                result.provenance.get("timeout_ms") or self.timeout_ms,
                default=self.timeout_ms,
            )
            try:
                operation = _json_mapping(
                    rollback_method(
                        pid,
                        dict(mapping),
                        dict(expected_identity),
                        timeout_ms,
                    )
                )
            except Exception as exc:
                operation = {
                    "ok": False,
                    "status": "failed",
                    "mapping_release_attempted": False,
                    "mapping_released": False,
                    "release_verified": False,
                    "error": _exception_payload(exc),
                }
            detach = operation.get("detach")
            detach_ok = not isinstance(detach, Mapping) or bool(detach.get("completed"))
            dependencies_ok = bool(operation.get("dependencies_released", False))
            mapping_released = bool(operation.get("mapping_released"))
            release_verified = bool(operation.get("release_verified"))
            identity_verified = bool(operation.get("target_identity_verified"))
            ok = bool(
                operation.get("ok")
                and detach_ok
                and dependencies_ok
                and mapping_released
                and release_verified
                and identity_verified
            )
            details = {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "status": "ok" if ok else "failed",
                "method": _MANUAL_MAP,
                "pid": pid,
                "image_base": mapping.get("image_base"),
                "image_size": mapping.get("image_size"),
                "target_identity_verified": identity_verified,
                "detach_completed": detach_ok,
                "dependencies_released": dependencies_ok,
                "mapping_release_attempted": bool(
                    operation.get("mapping_release_attempted")
                ),
                "mapping_released": mapping_released,
                "release_verified": release_verified,
                "operation": operation,
            }
            result.rollback_plan.update(
                {
                    "mapping_released": mapping_released,
                    "release_verified": release_verified,
                    "dependencies_released": dependencies_ok,
                }
            )
            self._record_rollback(
                result,
                details,
                ok=ok,
                restored=ok,
                attempted=True,
            )
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=ok,
                restored=ok,
                details=_prune(details),
            )

        pid = _coerce_pid(rollback_plan.get("pid") or result.target.pid)
        module_handle = _coerce_address(rollback_plan.get("module_handle"))
        remote_allocation = _coerce_address(rollback_plan.get("remote_allocation"))
        dll_path = str(rollback_plan.get("dll_path") or result.report_section.get("dll_path") or "")
        timeout_ms = _bounded_timeout(
            result.provenance.get("timeout_ms") or self.timeout_ms,
            default=self.timeout_ms,
        )

        if result.status != "ok" and not remote_allocation:
            details = {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "status": "not_required",
                "method": method,
                "reason": "execution did not load a module or retain temporary memory",
                "free_library_attempted": False,
                "memory_release_attempted": False,
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

        if pid is None:
            return self._rollback_failure(result, "rollback PID is missing or invalid")
        if not _backend_available(backend):
            return self._rollback_failure(result, _backend_reason(backend), status="unavailable")

        before_modules, before_error = _capture_modules(backend, pid)
        if module_handle is None:
            module_handle = _coerce_address(
                (_find_module(before_modules, dll_path) or {}).get("base_address")
            )
        try:
            operation = _json_mapping(
                backend.rollback_load_library(
                    pid,
                    module_handle,
                    remote_allocation,
                    timeout_ms,
                )
            )
        except Exception as exc:
            operation = {
                "ok": False,
                "status": "failed",
                "free_library_attempted": module_handle is not None,
                "free_library_ok": False,
                "memory_release_attempted": remote_allocation is not None,
                "memory_released": False,
                "error": _exception_payload(exc),
            }
            if remote_allocation:
                operation["memory_fallback"] = self._release_remote_memory(
                    backend,
                    pid,
                    remote_allocation,
                )

        after_modules, after_error = _capture_modules(backend, pid)
        remaining_module = _find_module(after_modules, dll_path)
        module_absent = remaining_module is None and not after_error
        memory_required = remote_allocation is not None
        fallback = operation.get("memory_fallback")
        memory_released = (
            not memory_required
            or bool(operation.get("memory_released"))
            or bool(isinstance(fallback, Mapping) and fallback.get("memory_released"))
        )
        free_library_ok = bool(operation.get("free_library_ok"))
        restored = free_library_ok and module_absent
        ok = restored and memory_released
        details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": "ok" if ok else "failed",
            "method": method,
            "pid": pid,
            "dll_path": dll_path,
            "module_handle": module_handle,
            "remote_allocation": remote_allocation,
            "free_library_attempted": bool(operation.get("free_library_attempted")),
            "free_library_ok": free_library_ok,
            "memory_release_attempted": bool(operation.get("memory_release_attempted")),
            "memory_released": memory_released,
            "module_absent_after": module_absent,
            "before_modules": before_modules,
            "after_modules": after_modules,
            "before_snapshot_error": before_error,
            "after_snapshot_error": after_error,
            "operation": operation,
        }
        result.rollback_plan.update(
            {
                "free_library_ok": free_library_ok,
                "temporary_memory_released": memory_released,
                "module_absent_after": module_absent,
            }
        )
        self._record_rollback(
            result,
            details,
            ok=ok,
            restored=restored,
            attempted=True,
        )
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=ok,
            restored=restored,
            details=_prune(details),
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
        if not artifacts:
            artifacts.append(_audit_artifact(result.session_id, result.action, result.status))
        entries_by_path = {
            str(entry.get("path")): dict(entry)
            for entry in result.evidence_manifest_entries or []
            if entry.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        audit_payload = _injector_audit_payload(result)
        for artifact in artifacts:
            artifact.metadata.setdefault("collection_root", str(collection_root))
            destination = _artifact_destination(collection_root, artifact.path)
            entry = entries_by_path.get(
                artifact.path,
                _manifest_entry(
                    artifact,
                    status=result.status,
                    session_id=result.session_id,
                    method=result.action,
                    pid=result.target.pid,
                    dll_sha256=result.provenance.get("dll_sha256"),
                    target=result.target,
                ),
            )
            if artifact.kind == "injector-audit":
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
    ) -> tuple[CapabilityValidation, dict[str, Any], list[dict[str, Any]]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        method = _normalize_method(plan.parameters.get("method") or plan.action)

        method_ok = method in _SUPPORTED_METHODS
        checks.append(
            {
                "name": "injection_method",
                "status": "ok" if method_ok else "failed",
                "method": method,
                "supported_methods": sorted(_SUPPORTED_METHODS),
            }
        )
        if not method_ok:
            errors.append(f"unsupported injector method: {method or plan.action}")

        raw_pid = plan.parameters.get("pid")
        pid = _coerce_pid(raw_pid)
        planned_pid = _coerce_pid(plan.provenance.get("pid"))
        target_pid = _coerce_pid(plan.target.pid)
        pid_identity_ok = pid is not None and all(
            expected is None or expected == pid
            for expected in (planned_pid, target_pid)
        )
        pid_ok = (
            pid is not None
            and pid_identity_ok
            and not bool(plan.parameters.get("pid_conflict"))
        )
        checks.append(
            {
                "name": "target_pid",
                "status": "ok" if pid_ok else "failed",
                "pid": raw_pid,
                "planned_pid": planned_pid,
                "target_identity_pid": target_pid,
                "positive_integer": pid is not None,
                "matches_planned_identity": pid_identity_ok,
                "identity_conflict": bool(plan.parameters.get("pid_conflict")),
            }
        )
        if not pid_ok:
            errors.append("target PID must be a positive integer and identity sources must agree")

        declared_path = str(plan.parameters.get("declared_dll_path") or "")
        dll_path = str(plan.parameters.get("dll_path") or "")
        absolute_ok = bool(declared_path) and _is_absolute_path(declared_path)
        checks.append(
            {
                "name": "dll_absolute_path",
                "status": "ok" if absolute_ok else "failed",
                "declared_path": declared_path,
                "resolved_path": dll_path,
            }
        )
        if not absolute_ok:
            errors.append("DLL path must be absolute")

        planned_path = str(plan.provenance.get("dll_path") or "")
        path_identity_ok = bool(dll_path) and _same_path(dll_path, planned_path)
        checks.append(
            {
                "name": "dll_planned_path_identity",
                "status": "ok" if path_identity_ok else "failed",
                "expected": planned_path,
                "actual": dll_path,
            }
        )
        if not path_identity_ok:
            errors.append("DLL path does not match the planned path identity")

        snapshot = _dll_snapshot(dll_path)
        exists_ok = bool(snapshot.get("exists") and snapshot.get("is_file"))
        checks.append(
            {
                "name": "dll_file",
                "status": "ok" if exists_ok else "failed",
                "path": dll_path,
                "exists": snapshot.get("exists"),
                "is_file": snapshot.get("is_file"),
                "read_error": snapshot.get("read_error"),
            }
        )
        if not exists_ok:
            errors.append("DLL path must identify an existing regular file")

        mz_ok = bool(snapshot.get("readable") and snapshot.get("mz"))
        checks.append(
            {
                "name": "dll_mz_signature",
                "status": "ok" if mz_ok else "failed",
                "expected": "4d5a",
                "actual": snapshot.get("magic"),
                "readable": snapshot.get("readable"),
            }
        )
        if not mz_ok:
            errors.append("DLL must be readable and begin with an MZ signature")

        planned_hash = str(plan.precondition_hash or "").lower()
        current_hash = str(snapshot.get("sha256") or "").lower()
        planned_hash_ok = _valid_sha256(planned_hash) and current_hash == planned_hash
        checks.append(
            {
                "name": "dll_precondition_sha256",
                "status": "ok" if planned_hash_ok else "failed",
                "expected": plan.precondition_hash,
                "actual": snapshot.get("sha256"),
            }
        )
        if not planned_hash_ok:
            errors.append("DLL does not match the planned SHA-256 precondition")

        declared_hash = str(plan.parameters.get("declared_sha256") or "").lower()
        if declared_hash:
            declared_hash_ok = _valid_sha256(declared_hash) and current_hash == declared_hash
            checks.append(
                {
                    "name": "dll_declared_sha256",
                    "status": "ok" if declared_hash_ok else "failed",
                    "expected": declared_hash,
                    "actual": snapshot.get("sha256"),
                }
            )
            if not declared_hash_ok:
                errors.append("DLL does not match the declared SHA-256 identity")

        backend_available = _backend_available(backend)
        backend_details = _backend_info(backend, platform_name=self.platform_name)
        checks.append(
            {
                **backend_details,
                "name": "windows_backend",
                "status": "ok" if backend_available else "unavailable",
                "backend_name": backend_details.get("name"),
            }
        )
        if not backend_available:
            warnings.append(_backend_reason(backend))

        process_probe: dict[str, Any] = {
            "pid": pid if pid is not None else raw_pid,
            "exists": None,
            "accessible": False,
            "status": "not_checked",
        }
        modules: list[dict[str, Any]] = []
        if backend_available and pid is not None:
            process_probe = _probe_process(backend, pid)
            process_ok = bool(
                process_probe.get("accessible")
                and process_probe.get("exists") is not False
            )
            checks.append(
                {
                    "name": "target_process_access",
                    "status": "ok" if process_ok else "failed",
                    **process_probe,
                }
            )
            if not process_ok:
                errors.append("target PID does not identify an accessible process")
            else:
                modules, modules_error = _capture_modules(backend, pid)
                checks.append(
                    {
                        "name": "module_snapshot_before",
                        "status": "ok" if not modules_error else "failed",
                        "module_count": len(modules),
                        "error": modules_error,
                    }
                )
                if modules_error:
                    errors.append("unable to capture target modules before injection")
                already_loaded = _find_module(modules, dll_path)
                checks.append(
                    {
                        "name": "dll_not_already_loaded",
                        "status": "ok" if already_loaded is None else "failed",
                        "loaded_module": already_loaded,
                    }
                )
                if already_loaded is not None:
                    errors.append("DLL is already loaded in the target process")

        risk_assessment = plan.parameters.get("risk_assessment")
        risk_errors = _risk_schema_errors(risk_assessment, method=method)
        checks.append(
            {
                "name": "risk_assessment_schema",
                "status": "ok" if not risk_errors else "failed",
                "schema_version": (
                    risk_assessment.get("schema_version")
                    if isinstance(risk_assessment, Mapping)
                    else None
                ),
                "method": method,
                "errors": risk_errors,
            }
        )
        if risk_errors:
            errors.extend(f"risk schema: {item}" for item in risk_errors)

        if method == _MANUAL_MAP:
            assessment = inspect_manual_map_image(dll_path)
            planned_assessment = plan.provenance.get("manual_map_image")
            assessment_ok = bool(assessment.get("ok"))
            assessment_pinned = _manual_map_assessment_identity(assessment) == (
                _manual_map_assessment_identity(planned_assessment)
            )
            checks.append(
                {
                    "name": "manual_map_pe_loader_subset",
                    "status": "ok" if assessment_ok else "failed",
                    "assessment": assessment,
                    "unsupported_features": assessment.get("unsupported_features") or [],
                }
            )
            if not assessment_ok:
                errors.extend(
                    f"manual_map PE validation: {item}"
                    for item in assessment.get("errors", ["unsupported PE image"])
                )
            checks.append(
                {
                    "name": "manual_map_planned_image_identity",
                    "status": "ok" if assessment_pinned else "failed",
                    "expected": _manual_map_assessment_identity(planned_assessment),
                    "actual": _manual_map_assessment_identity(assessment),
                }
            )
            if not assessment_pinned:
                errors.append("manual-map PE assessment does not match the planned image")

            executor_available = callable(getattr(backend, "manual_map", None)) and callable(
                getattr(backend, "rollback_manual_map", None)
            )
            checks.append(
                {
                    "name": "manual_map_executor",
                    "status": (
                        "ok"
                        if backend_available and executor_available
                        else "unavailable"
                    ),
                    "implemented": executor_available,
                    "available": backend_available and executor_available,
                    "side_effects": False,
                    "reason": (
                        None
                        if backend_available and executor_available
                        else "backend does not provide manual-map execution and rollback"
                    ),
                }
            )
            if backend_available and not executor_available:
                errors.append("backend does not provide manual-map execution and rollback")

            target_identity = _manual_map_target_identity(process_probe)
            identity_missing = [
                field
                for field in ("pid", "creation_time_100ns", "image_path", "machine")
                if target_identity.get(field) in (None, "")
            ]
            identity_ok = not identity_missing
            checks.append(
                {
                    "name": "manual_map_target_identity",
                    "status": (
                        "ok" if identity_ok else "failed" if backend_available else "unavailable"
                    ),
                    "identity": target_identity,
                    "missing": identity_missing,
                }
            )
            if backend_available and pid is not None and not identity_ok:
                errors.append(
                    "manual_map requires target PID, creation time, image path, and machine identity"
                )

            pe_machine = _coerce_address(assessment.get("machine"))
            target_machine = _coerce_address(target_identity.get("machine"))
            architecture_ok = bool(
                assessment_ok
                and pe_machine
                and target_machine
                and pe_machine == target_machine
            )
            checks.append(
                {
                    "name": "manual_map_architecture_match",
                    "status": (
                        "ok"
                        if architecture_ok
                        else "failed" if backend_available else "unavailable"
                    ),
                    "pe_machine": pe_machine,
                    "pe_architecture": assessment.get("architecture"),
                    "target_machine": target_machine,
                    "target_architecture": target_identity.get("architecture"),
                }
            )
            if backend_available and pid is not None and assessment_ok and not architecture_ok:
                errors.append("manual-map PE architecture does not match the target process")

            injector_machine = _coerce_address(target_identity.get("injector_machine"))
            injector_architecture_ok = bool(
                not injector_machine
                or (
                    assessment_ok
                    and pe_machine
                    and pe_machine == injector_machine
                )
            )
            checks.append(
                {
                    "name": "manual_map_injector_architecture_match",
                    "status": (
                        "ok"
                        if injector_architecture_ok
                        else "failed" if backend_available else "unavailable"
                    ),
                    "pe_machine": pe_machine,
                    "pe_architecture": assessment.get("architecture"),
                    "injector_machine": injector_machine,
                    "injector_architecture": target_identity.get("injector_architecture"),
                    "strategy": "same-bitness local-export-owner RVA",
                }
            )
            if (
                backend_available
                and pid is not None
                and assessment_ok
                and not injector_architecture_ok
            ):
                errors.append(
                    "manual-map requires injector, DLL, and target to use the same architecture"
                )
            warnings.append(
                "manual_map has critical loader, visibility, and rollback risks; review risk_assessment"
            )
        elif method == _LOAD_LIBRARY:
            warnings.append(
                "LoadLibraryW injection writes target memory and creates a remote thread"
            )

        return (
            CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=_prune(checks),
                warnings=warnings,
                errors=_deduplicate(errors),
            ),
            process_probe,
            modules,
        )

    def _result(
        self,
        plan: CapabilityPlan,
        *,
        status: str,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        validation: CapabilityValidation,
        operation: Mapping[str, Any],
        errors: list[Any],
    ) -> CapabilityExecutionResult:
        method = _normalize_method(plan.parameters.get("method") or plan.action)
        pid = _coerce_pid(plan.parameters.get("pid"))
        dll_path = str(plan.parameters.get("dll_path") or "")
        artifact = _audit_artifact(plan.session_id, method, status)
        target_identity = _target_identity(plan.target)
        artifact.metadata.update(
            {
                "target_identity": target_identity,
                "precondition_hash": plan.precondition_hash,
            }
        )
        manifest = _manifest_entry(
            artifact,
            status=status,
            session_id=plan.session_id,
            method=method,
            pid=pid,
            dll_sha256=plan.precondition_hash,
            target=plan.target,
        )
        module_evidence = dict(after_snapshot.get("module_evidence") or {})
        provenance = _prune(
            {
                **_json_mapping(plan.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "precondition_hash": plan.precondition_hash,
                "method": method,
                "pid": pid,
                "dll_path": dll_path,
                "dll_sha256": plan.precondition_hash,
                "timeout_ms": plan.parameters.get("timeout_ms"),
                "validation_ok": validation.ok,
                "execution_status": status,
                "backend_operation": operation,
            }
        )
        report_section = _prune(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "status": status,
                "available": status != "unavailable",
                "provider": self.provider_name,
                "capability": self.capability_name,
                "action": plan.action,
                "method": method,
                "session_id": plan.session_id,
                "session": {"id": plan.session_id, "state": status},
                "target_identity": target_identity,
                "platform": self.platform_name,
                "backend": plan.provenance.get("backend"),
                "pid": pid,
                "dll_path": dll_path,
                "dll_sha256": plan.precondition_hash,
                "precondition_hash": plan.precondition_hash,
                "before_snapshot": dict(before_snapshot),
                "after_snapshot": dict(after_snapshot),
                "rollback_plan": dict(rollback_plan),
                "provenance": provenance,
                "artifacts": [artifact.to_dict()],
                "evidence_manifest_entries": [dict(manifest)],
                "validation": {
                    "ok": validation.ok,
                    "checks": validation.checks,
                    "warnings": validation.warnings,
                    "errors": validation.errors,
                },
                "operation": operation,
                "module_evidence": module_evidence,
                "rollback": rollback_plan,
                "risk_assessment": plan.parameters.get("risk_assessment"),
                "errors": errors,
            }
        )
        dashboard_trace = [
            _prune(
                {
                    "kind": "injector_execution",
                    "schema_version": _AUDIT_SCHEMA_VERSION,
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "action": plan.action,
                    "method": method,
                    "pid": pid,
                    "dll_path": dll_path,
                    "dll_sha256": plan.precondition_hash,
                    "platform": self.platform_name,
                    "backend": (
                        plan.provenance.get("backend", {}).get("name")
                        if isinstance(plan.provenance.get("backend"), Mapping)
                        else plan.provenance.get("backend")
                    ),
                    "status": status,
                    "validation_ok": validation.ok,
                    "module_transition_observed": module_evidence.get("observed_transition"),
                    "rollback_supported": rollback_plan.get("supported"),
                    "error_count": len([item for item in errors if item]),
                }
            )
        ]
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_prune(dict(before_snapshot)),
            after_snapshot=_prune(dict(after_snapshot)),
            rollback_plan=_prune(dict(rollback_plan)),
            artifacts=[artifact],
            evidence_manifest_entries=[manifest],
            report_section=report_section,
            dashboard_trace=dashboard_trace,
            provenance=provenance,
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
            _prune(
                {
                    "kind": "injector_rollback",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "session_id": result.session_id,
                    "method": result.provenance.get("method") or result.action,
                    "pid": result.target.pid,
                    "status": status,
                    "restored": restored,
                    "attempted": attempted,
                    "memory_released": payload.get("memory_released"),
                }
            )
        )

    def _rollback_failure(
        self,
        result: CapabilityExecutionResult,
        reason: str,
        *,
        status: str = "failed",
    ) -> CapabilityRollbackResult:
        details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "reason": reason,
            "session_id": result.session_id,
            "method": result.provenance.get("method") or result.action,
            "pid": result.target.pid,
            "free_library_attempted": False,
            "memory_release_attempted": False,
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

    def _select_backend(self, context: Optional[dict[str, Any]]) -> InjectorBackend:
        if context:
            candidate = context.get("injector_backend") or context.get("backend")
            if candidate is not None:
                return candidate
        return self.backend

    @staticmethod
    def _release_remote_memory(
        backend: InjectorBackend,
        pid: int,
        remote_allocation: int,
    ) -> dict[str, Any]:
        try:
            return _json_mapping(backend.release_remote_memory(pid, remote_allocation))
        except Exception as exc:
            return {
                "ok": False,
                "status": "failed",
                "memory_release_attempted": True,
                "memory_released": False,
                "error": _exception_payload(exc),
            }


class InjectorMockProvider(MockCapabilityProvider):
    """Retained deterministic provider for existing registry and offline tests."""

    def __init__(self) -> None:
        super().__init__("injector")


def _request_method(request: CapabilityRequest) -> str:
    explicit = request.params.get("method") or request.params.get("strategy")
    return _normalize_method(explicit or request.action)


def _normalize_method(value: Any) -> str:
    normalized = str(value or "").strip().casefold().replace("-", "_").replace(" ", "_")
    return _METHOD_ALIASES.get(normalized, normalized)


def _request_pid(request: CapabilityRequest) -> tuple[Any, Optional[int], bool]:
    target_pid = request.target.pid
    parameter_pid = request.params.get("pid")
    raw_pid = target_pid if target_pid is not None else parameter_pid
    target_value = _coerce_pid(target_pid)
    parameter_value = _coerce_pid(parameter_pid)
    conflict = (
        target_pid is not None
        and parameter_pid is not None
        and (target_value is None or parameter_value is None or target_value != parameter_value)
    )
    return raw_pid, _coerce_pid(raw_pid), conflict


def _request_dll_path(request: CapabilityRequest) -> str:
    value = (
        request.params.get("dll_path")
        or request.params.get("library_path")
        or request.target.path
        or ""
    )
    return str(value)


def _request_dll_hash(request: CapabilityRequest, declared_path: str) -> Optional[str]:
    value = (
        request.params.get("dll_sha256")
        or request.params.get("expected_sha256")
        or request.params.get("sha256")
    )
    if not value and request.target.path and _same_path(request.target.path, declared_path):
        value = request.target.sha256
    return str(value).strip().lower() if value else None


def _coerce_pid(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        pid = int(str(value), 10)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def _coerce_address(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        address = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return address if address > 0 else None


def _bounded_timeout(value: Any, *, default: int = _DEFAULT_TIMEOUT_MS) -> int:
    if isinstance(value, bool):
        return default
    try:
        timeout = int(value)
    except (TypeError, ValueError):
        return default
    return min(max(timeout, 1), _MAX_TIMEOUT_MS)


def _is_absolute_path(value: Any) -> bool:
    text = str(value or "")
    if not text:
        return False
    return Path(text).expanduser().is_absolute() or PureWindowsPath(text).is_absolute()


def _resolved_path(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    candidate = Path(text).expanduser()
    try:
        return str(candidate.resolve(strict=False))
    except OSError:
        return str(candidate.absolute())


def _dll_snapshot(path_value: str) -> dict[str, Any]:
    if not path_value:
        return {
            "path": "",
            "exists": False,
            "is_file": False,
            "readable": False,
            "mz": False,
        }
    path = Path(path_value)
    snapshot: dict[str, Any] = {
        "path": str(path),
        "absolute": _is_absolute_path(path_value),
        "exists": path.exists(),
        "is_file": path.is_file(),
        "readable": False,
        "mz": False,
    }
    if not snapshot["is_file"]:
        return snapshot

    digest = hashlib.sha256()
    magic = b""
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                if not magic:
                    magic = chunk[:2]
                digest.update(chunk)
        stat = path.stat()
        snapshot.update(
            {
                "readable": True,
                "size": stat.st_size,
                "magic": magic.hex(),
                "mz": magic == b"MZ",
                "sha256": digest.hexdigest(),
            }
        )
    except OSError as exc:
        snapshot["read_error"] = f"{type(exc).__name__}: {exc}"
    return snapshot


def _valid_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == _SHA256_LENGTH and all(character in "0123456789abcdef" for character in text.lower())


def _backend_available(backend: Any) -> bool:
    available = getattr(backend, "available", True)
    try:
        return bool(available() if callable(available) else available)
    except Exception:
        return False


def _backend_reason(backend: Any) -> str:
    reason = getattr(backend, "unavailable_reason", None)
    return str(reason or "Windows injection backend is unavailable")


def _backend_info(backend: Any, *, platform_name: str) -> dict[str, Any]:
    return {
        "name": str(getattr(backend, "name", type(backend).__name__)),
        "available": _backend_available(backend),
        "reason": None if _backend_available(backend) else _backend_reason(backend),
        "platform": platform_name,
    }


def _probe_process(backend: InjectorBackend, pid: int) -> dict[str, Any]:
    try:
        probe = backend.probe_process(pid)
        if isinstance(probe, Mapping):
            payload = _json_mapping(probe)
        else:
            payload = {
                "pid": pid,
                "exists": bool(probe),
                "accessible": bool(probe),
            }
        payload.setdefault("pid", pid)
        payload.setdefault("exists", payload.get("accessible"))
        payload.setdefault("accessible", bool(payload.get("exists")))
        payload.setdefault("status", "ok" if payload.get("accessible") else "failed")
        return payload
    except Exception as exc:
        return {
            "pid": pid,
            "exists": None,
            "accessible": False,
            "status": "failed",
            "error": _exception_payload(exc),
        }


def _capture_modules(
    backend: InjectorBackend,
    pid: int,
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    try:
        raw_modules = backend.list_modules(pid)
        modules = [_normalize_module(item) for item in raw_modules]
        modules.sort(
            key=lambda item: (
                str(item.get("path") or "").casefold(),
                int(item.get("base_address") or 0),
            )
        )
        return modules, None
    except Exception as exc:
        return [], _exception_payload(exc)


def _normalize_module(module: Mapping[str, Any]) -> dict[str, Any]:
    path = str(module.get("path") or module.get("image_path") or "")
    name = str(module.get("name") or module.get("module_name") or _path_name(path))
    return _prune(
        {
            **_json_mapping(module),
            "name": name,
            "path": path,
            "base_address": _coerce_address(
                module.get("base_address") or module.get("base") or module.get("handle")
            ),
            "size": module.get("size") or module.get("image_size"),
        }
    )


def _find_module(modules: list[Mapping[str, Any]], dll_path: str) -> Optional[dict[str, Any]]:
    expected = _path_identity(dll_path)
    if not expected:
        return None
    for module in modules:
        if _path_identity(module.get("path")) == expected:
            return dict(module)
    return None


def _module_evidence(
    before_modules: list[Mapping[str, Any]],
    after_modules: list[Mapping[str, Any]],
    dll_path: str,
) -> dict[str, Any]:
    before_by_key = {_module_key(item): dict(item) for item in before_modules}
    after_by_key = {_module_key(item): dict(item) for item in after_modules}
    added = [after_by_key[key] for key in sorted(after_by_key.keys() - before_by_key.keys())]
    removed = [before_by_key[key] for key in sorted(before_by_key.keys() - after_by_key.keys())]
    before_match = _find_module([dict(item) for item in before_modules], dll_path)
    after_match = _find_module([dict(item) for item in after_modules], dll_path)
    return {
        "expected_path": dll_path,
        "before_count": len(before_modules),
        "after_count": len(after_modules),
        "present_before": before_match is not None,
        "present_after": after_match is not None,
        "observed_transition": before_match is None and after_match is not None,
        "loaded_module": after_match,
        "added_modules": added,
        "removed_modules": removed,
    }


def _module_key(module: Mapping[str, Any]) -> str:
    path = _path_identity(module.get("path"))
    base = _coerce_address(module.get("base_address")) or 0
    return f"{path}|{base:x}"


def _path_identity(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return os.path.normpath(text).replace("/", "\\").casefold()


def _path_name(value: Any) -> str:
    return str(value or "").replace("/", "\\").rsplit("\\", 1)[-1]


def _same_path(left: Any, right: Any) -> bool:
    return bool(_path_identity(left)) and _path_identity(left) == _path_identity(right)


def _manual_map_target_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "pid": _coerce_pid(value.get("pid")),
            "creation_time_100ns": value.get("creation_time_100ns"),
            "image_path": value.get("image_path"),
            "machine": _coerce_address(value.get("machine")),
            "machine_hex": value.get("machine_hex"),
            "architecture": value.get("architecture"),
            "injector_machine": _coerce_address(value.get("injector_machine")),
            "injector_architecture": value.get("injector_architecture"),
        }
    )


def _manual_map_assessment_identity(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return _prune(
        {
            "ok": bool(value.get("ok")),
            "sha256": value.get("sha256"),
            "format": value.get("format"),
            "machine": _coerce_address(value.get("machine")),
            "architecture": value.get("architecture"),
            "image_base": _coerce_address(value.get("image_base")),
            "entry_point_rva": _coerce_address(value.get("entry_point_rva")) or 0,
            "size_of_image": value.get("size_of_image"),
            "section_count": value.get("section_count"),
            "import_module_count": value.get("import_module_count"),
            "import_symbol_count": value.get("import_symbol_count"),
            "delay_import_module_count": value.get("delay_import_module_count"),
            "delay_import_symbol_count": value.get("delay_import_symbol_count"),
            "relocation_count": value.get("relocation_count"),
            "protection_range_count": value.get("protection_range_count"),
            "unsupported_features": value.get("unsupported_features") or [],
            "errors": value.get("errors") or [],
            "loader_subset": value.get("loader_subset"),
        }
    )


def _same_process_identity(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    return bool(
        _coerce_pid(left.get("pid")) == _coerce_pid(right.get("pid"))
        and left.get("creation_time_100ns") == right.get("creation_time_100ns")
        and _same_path(left.get("image_path"), right.get("image_path"))
        and _coerce_address(left.get("machine")) == _coerce_address(right.get("machine"))
    )


def _manual_map_evidence_errors(
    operation: Mapping[str, Any],
    *,
    assessment: Mapping[str, Any],
    expected_sha256: str,
    expected_identity: Mapping[str, Any],
) -> list[str]:
    errors: list[str] = []
    if operation.get("method") != _MANUAL_MAP:
        errors.append("manual-map backend returned the wrong method identity")
    if str(operation.get("dll_sha256") or "").lower() != expected_sha256.lower():
        errors.append("manual-map backend did not prove the planned DLL SHA-256")
    if not operation.get("target_identity_verified") or not isinstance(
        operation.get("target_identity"), Mapping
    ):
        errors.append("manual-map backend did not verify target process identity")
    elif not _same_process_identity(expected_identity, operation["target_identity"]):
        errors.append("manual-map backend target identity differs from validation")

    image = operation.get("image")
    if not isinstance(image, Mapping):
        errors.append("manual-map backend omitted parsed PE image evidence")
    else:
        for field in ("machine", "architecture", "size_of_image", "entry_point_rva"):
            if image.get(field) != assessment.get(field):
                errors.append(f"manual-map PE evidence mismatch for {field}")
    if not _coerce_address(operation.get("image_base")):
        errors.append("manual-map backend omitted the mapped image base")
    if operation.get("image_size") != assessment.get("size_of_image"):
        errors.append("manual-map backend image size differs from validated SizeOfImage")

    headers_sections = operation.get("headers_sections")
    if not isinstance(headers_sections, Mapping) or not headers_sections.get("complete"):
        errors.append("manual-map header/section mapping evidence is incomplete")
    elif headers_sections.get("section_count") != assessment.get("section_count"):
        errors.append("manual-map section mapping count is incomplete")

    relocations = operation.get("relocations")
    if not isinstance(relocations, Mapping) or not relocations.get("complete"):
        errors.append("manual-map relocation evidence is incomplete")
    elif relocations.get("available_count") != assessment.get("relocation_count"):
        errors.append("manual-map relocation count differs from the validated PE")
    elif relocations.get("required") and (
        relocations.get("applied_count") != relocations.get("available_count")
    ):
        errors.append("manual-map did not apply every required relocation")

    imports = operation.get("imports")
    if not isinstance(imports, Mapping) or not imports.get("complete"):
        errors.append("manual-map import-resolution evidence is incomplete")
    elif imports.get("expected_count") != assessment.get("import_symbol_count"):
        errors.append("manual-map import count differs from the validated PE")
    elif imports.get("resolved_count") != imports.get("expected_count"):
        errors.append("manual-map did not resolve every import")

    delay_import_count = int(assessment.get("delay_import_symbol_count") or 0)
    delay_imports = operation.get("delay_imports")
    if delay_import_count:
        if not isinstance(delay_imports, Mapping) or not delay_imports.get("complete"):
            errors.append("manual-map delay-import resolution evidence is incomplete")
        else:
            if delay_imports.get("strategy") != "eager_target_context":
                errors.append("manual-map delay imports used an unvalidated binding strategy")
            if delay_imports.get("expected_count") != delay_import_count:
                errors.append("manual-map delay-import count differs from the validated PE")
            if delay_imports.get("resolved_count") != delay_import_count:
                errors.append("manual-map did not resolve every delay import")
            if delay_imports.get("module_handle_slots_written") != assessment.get(
                "delay_import_module_count"
            ):
                errors.append("manual-map did not initialize every delay-import module handle")
            if not delay_imports.get("readback_verified"):
                errors.append("manual-map did not verify remote delay-import storage")

    tls_callback_count = int(assessment.get("tls_callback_count") or 0)
    tls_callbacks = operation.get("tls_callbacks")
    if tls_callback_count:
        if not isinstance(tls_callbacks, Mapping) or not tls_callbacks.get("complete"):
            errors.append("manual-map TLS callback evidence is incomplete")
        else:
            if not tls_callbacks.get("directory_present") or not tls_callbacks.get(
                "required"
            ):
                errors.append("manual-map TLS callback requirement was not preserved")
            if tls_callbacks.get("callback_count") != tls_callback_count:
                errors.append("manual-map TLS callback count differs from the validated PE")
            if tls_callbacks.get("attach_completed_count") != tls_callback_count:
                errors.append("manual-map did not attach every TLS callback")
            callbacks = tls_callbacks.get("callbacks")
            if not isinstance(callbacks, list) or len(callbacks) != tls_callback_count:
                errors.append("manual-map TLS callback audit list is incomplete")
            elif not all(
                isinstance(item, Mapping) and item.get("attach_completed")
                for item in callbacks
            ):
                errors.append("manual-map TLS callback attach evidence is incomplete")

    runtime_function_count = int(assessment.get("runtime_function_count") or 0)
    exception_table = operation.get("exception_table")
    exception_assessment = assessment.get("exception_table")
    exception_directory_rva = (
        _coerce_address(exception_assessment.get("directory_rva"))
        if isinstance(exception_assessment, Mapping)
        else None
    )
    if runtime_function_count:
        if not isinstance(exception_table, Mapping) or not exception_table.get(
            "complete"
        ):
            errors.append("manual-map x64 exception-table evidence is incomplete")
        else:
            if not exception_table.get("required") or not exception_table.get(
                "registered"
            ):
                errors.append("manual-map did not register the x64 exception table")
            if exception_table.get("entry_count") != runtime_function_count:
                errors.append(
                    "manual-map exception-table count differs from the validated PE"
                )
            if _coerce_address(exception_table.get("table_rva")) != exception_directory_rva:
                errors.append("manual-map exception-table RVA differs from the validated PE")
            expected_table_address = (
                (_coerce_address(operation.get("image_base")) or 0)
                + (exception_directory_rva or 0)
            )
            if _coerce_address(exception_table.get("table_address")) != (
                expected_table_address or None
            ):
                errors.append("manual-map exception-table address is inconsistent")
            if _coerce_address(exception_table.get("base_address")) != _coerce_address(
                operation.get("image_base")
            ):
                errors.append("manual-map exception-table image base is inconsistent")
            if not exception_table.get("delete_resolved_before_registration"):
                errors.append(
                    "manual-map exception-table rollback function was not pre-resolved"
                )

    readback = operation.get("readback")
    if not isinstance(readback, Mapping) or not readback.get("complete"):
        errors.append("manual-map remote readback evidence is incomplete")
    elif not readback.get("mapped_sha256") or (
        readback.get("mapped_sha256") != readback.get("readback_sha256")
    ):
        errors.append("manual-map remote readback hash does not match mapped bytes")

    protections = operation.get("protections")
    if not isinstance(protections, Mapping) or not protections.get("complete"):
        errors.append("manual-map page-protection evidence is incomplete")
    else:
        if protections.get("writable_executable"):
            errors.append("manual-map backend left writable executable image pages")
        if protections.get("applied_count") != assessment.get("protection_range_count"):
            errors.append("manual-map did not apply every validated protection range")
        if not protections.get("instruction_cache_flushed"):
            errors.append("manual-map backend did not flush the target instruction cache")

    entrypoint = operation.get("entrypoint")
    entrypoint_required = bool(assessment.get("entry_point_rva"))
    if not isinstance(entrypoint, Mapping):
        errors.append("manual-map backend omitted entry-point evidence")
    elif bool(entrypoint.get("required")) != entrypoint_required:
        errors.append("manual-map entry-point requirement differs from the validated PE")
    elif entrypoint_required and not (
        entrypoint.get("called")
        and entrypoint.get("completed")
        and entrypoint.get("attach_returned")
    ):
        errors.append("manual-map DLL_PROCESS_ATTACH did not complete successfully")

    rollback = operation.get("rollback")
    if not isinstance(rollback, Mapping) or not (
        rollback.get("safe_to_unmap")
        and _coerce_address(rollback.get("image_base")) == _coerce_address(operation.get("image_base"))
        and rollback.get("image_size") == operation.get("image_size")
        and isinstance(rollback.get("dependencies"), list)
    ):
        errors.append("manual-map backend omitted complete rollback metadata")
    elif tls_callback_count:
        rollback_tls = rollback.get("tls_callbacks")
        if not isinstance(rollback_tls, list) or len(rollback_tls) != tls_callback_count:
            errors.append("manual-map rollback omitted attached TLS callbacks")
        elif not all(
            isinstance(item, Mapping) and item.get("attach_completed")
            for item in rollback_tls
        ):
            errors.append("manual-map rollback TLS callback state is incomplete")
    if runtime_function_count and isinstance(rollback, Mapping):
        rollback_function_table = rollback.get("function_table")
        if not isinstance(rollback_function_table, Mapping) or not rollback_function_table.get(
            "registered"
        ):
            errors.append("manual-map rollback omitted the registered exception table")
        else:
            if rollback_function_table.get("entry_count") != runtime_function_count:
                errors.append("manual-map rollback exception-table count is incomplete")
            if _coerce_address(rollback_function_table.get("table_rva")) != (
                exception_directory_rva
            ):
                errors.append("manual-map rollback exception-table RVA is inconsistent")
            if not _coerce_address(rollback_function_table.get("delete_function_address")):
                errors.append("manual-map rollback omitted RtlDeleteFunctionTable")
    return _deduplicate(errors)


def _execution_snapshot(
    plan: CapabilityPlan,
    *,
    process_probe: Mapping[str, Any],
    dll_snapshot: Mapping[str, Any],
    modules: list[Mapping[str, Any]],
    validation: CapabilityValidation,
) -> dict[str, Any]:
    dll_path = str(plan.parameters.get("dll_path") or "")
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capture_phase": "before",
        "platform": plan.provenance.get("platform"),
        "backend": plan.provenance.get("backend"),
        "process": dict(process_probe),
        "dll": dict(dll_snapshot),
        "manual_map_image": (
            inspect_manual_map_image(dll_path)
            if _normalize_method(plan.parameters.get("method") or plan.action) == _MANUAL_MAP
            else None
        ),
        "modules": [dict(item) for item in modules],
        "module_evidence": {
            "expected_path": dll_path,
            "module_count": len(modules),
            "present": _find_module([dict(item) for item in modules], dll_path) is not None,
        },
        "validation": {
            "ok": validation.ok,
            "errors": list(validation.errors),
            "warnings": list(validation.warnings),
        },
    }


def _initial_rollback_plan(
    *,
    method: str,
    pid: Optional[int],
    dll_path: str,
    dll_sha256: Any,
) -> dict[str, Any]:
    if method == _LOAD_LIBRARY:
        return {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "supported": True,
            "mode": "remote_free_library",
            "pid": pid,
            "dll_path": dll_path,
            "dll_sha256": dll_sha256,
            "module_handle": None,
            "remote_allocation": None,
            "free_library_required": True,
            "temporary_memory_release_required": True,
            "evidence_required": "module absent after FreeLibrary",
        }
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "supported": True,
        "mode": "manual_unmap",
        "pid": pid,
        "dll_path": dll_path,
        "dll_sha256": dll_sha256,
        "mapping": None,
        "mapping_release_required": True,
        "release_verification_required": True,
        "evidence_required": (
            "DllMain detach completion, image region MEM_FREE, and dependency references released"
        ),
        "risk_schema_version": _RISK_SCHEMA_VERSION,
    }


def _non_execution_rollback_plan(
    rollback_plan: Mapping[str, Any],
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    result = dict(rollback_plan or {})
    result.pop("evidence_required", None)
    result.update(
        {
            "supported": False,
            "mode": "not_required",
            "status": status,
            "reason": reason,
            "free_library_required": False,
            "temporary_memory_release_required": False,
        }
    )
    return result


def _plan_steps(method: str) -> list[dict[str, Any]]:
    common = [
        {"step": "validate_positive_pid", "status": "planned", "required": True},
        {"step": "validate_absolute_dll_path", "status": "planned", "required": True},
        {"step": "validate_mz_signature", "status": "planned", "required": True},
        {"step": "pin_dll_sha256", "status": "planned", "required": True},
        {"step": "probe_target_process_access", "status": "planned", "required": True},
        {"step": "capture_modules_before", "status": "planned", "required": True},
    ]
    if method == _MANUAL_MAP:
        return common + [
            {"step": "inspect_pe_architecture", "status": "planned", "required": True},
            {"step": "assess_manual_map_risks", "status": "planned", "required": True},
            {"step": "reject_tls_exception_load_config_and_unsupported_delay_modes", "status": "planned", "required": True},
            {"step": "reserve_remote_image", "status": "planned", "implemented": True},
            {"step": "copy_headers_and_sections", "status": "planned", "implemented": True},
            {"step": "apply_base_relocations", "status": "planned", "implemented": True},
            {"step": "resolve_imports_in_target", "status": "planned", "implemented": True},
            {"step": "eager_bind_delay_imports_in_target", "status": "planned", "implemented": True},
            {"step": "apply_section_protections", "status": "planned", "implemented": True},
            {"step": "invoke_dll_entry_point", "status": "planned", "implemented": True},
            {"step": "capture_manual_map_evidence", "status": "planned", "implemented": True},
            {"step": "rollback_manual_map", "status": "planned", "implemented": True},
        ]
    return common + [
        {"step": "OpenProcess", "status": "planned", "required": True},
        {"step": "VirtualAllocEx", "status": "planned", "required": True},
        {"step": "WriteProcessMemory", "status": "planned", "required": True},
        {"step": "resolve_remote_LoadLibraryW", "status": "planned", "required": True},
        {"step": "CreateRemoteThread", "status": "planned", "required": True},
        {"step": "wait_for_remote_thread", "status": "planned", "required": True},
        {"step": "capture_modules_after", "status": "planned", "required": True},
        {"step": "retain_temporary_path_for_rollback", "status": "planned", "required": True},
    ]


def _risk_assessment(method: str) -> dict[str, Any]:
    if method == _MANUAL_MAP:
        risks = [
            _risk(
                "architecture_compatibility",
                "loader_semantics",
                "critical",
                "high",
                "Wrong machine type or pointer width can corrupt the target process.",
                ["parse PE machine type", "verify target architecture", "reject mismatch"],
            ),
            _risk(
                "relocation_correctness",
                "loader_semantics",
                "critical",
                "high",
                "Incomplete relocation processing can write invalid absolute addresses.",
                ["validate relocation directory", "support every emitted relocation type"],
            ),
            _risk(
                "import_resolution",
                "loader_semantics",
                "critical",
                "high",
                "Imports, forwarded exports, API sets, and delay imports require target-side resolution.",
                [
                    "resolve imports in target context",
                    "eagerly bind validated RVA-based delay imports",
                    "validate every normal and delay IAT entry by remote readback",
                ],
            ),
            _risk(
                "tls_initialization",
                "runtime_initialization",
                "high",
                "medium",
                "Skipped TLS data or callbacks can leave the module partially initialized.",
                ["reject every image with a TLS directory before remote allocation"],
            ),
            _risk(
                "exception_metadata",
                "runtime_initialization",
                "high",
                "medium",
                "x64 exception and unwind metadata must be registered and later removed.",
                ["reject every image with an exception directory before remote allocation"],
            ),
            _risk(
                "section_protections",
                "memory_safety",
                "high",
                "high",
                "Incorrect final protections create writable executable memory or access faults.",
                ["derive protections per section", "enforce W^X", "flush instruction cache"],
            ),
            _risk(
                "loader_lock_and_entrypoint",
                "runtime_initialization",
                "critical",
                "medium",
                "DllMain execution outside loader semantics can deadlock or race process state.",
                ["define invocation context", "bound execution timeout", "capture exit evidence"],
            ),
            _risk(
                "module_visibility",
                "evidence",
                "high",
                "high",
                "A manually mapped image may not appear in standard module enumeration.",
                ["capture mapped ranges", "hash remote headers and sections", "record VAD evidence"],
            ),
            _risk(
                "rollback_integrity",
                "reversibility",
                "critical",
                "high",
                "Unmapping code while threads or callbacks remain active can crash the target.",
                ["track all allocations and registrations", "prove quiescence", "reverse in dependency order"],
            ),
        ]
        return {
            "schema_version": _RISK_SCHEMA_VERSION,
            "method": _MANUAL_MAP,
            "risk_level": "critical",
            "overall_severity": "critical",
            "score": 10,
            "execution": {
                "implemented": True,
                "available": True,
                "status": "guarded",
                "side_effects_allowed": True,
            },
            "assumptions": [
                "target process identity remains stable from validation through rollback",
                "DLL bytes remain pinned to the planned SHA-256",
                "injector and target architecture compatibility is proven before allocation",
            ],
            "required_inputs": [
                "absolute DLL path",
                "DLL SHA-256",
                "positive target PID",
                "target architecture",
                "PE data-directory inventory",
            ],
            "validation_requirements": [
                {"id": "absolute_path", "required": True},
                {"id": "mz_signature", "required": True},
                {"id": "sha256_precondition", "required": True},
                {"id": "process_access", "required": True},
                {"id": "architecture_match", "required": True},
                {"id": "relocation_coverage", "required": True},
                {"id": "import_coverage", "required": True},
                {"id": "delay_import_coverage", "required": True},
                {"id": "rollback_proof", "required": True},
            ],
            "risks": risks,
            "rollback": {
                "implemented": True,
                "required": True,
                "residual_risk": "critical",
                "required_evidence": [
                    "all remote allocations released",
                    "unsupported runtime-registration directories were absent",
                    "no executing thread references mapped image",
                ],
            },
            "acceptance": {
                "execution_allowed": True,
                "reason": (
                    "allowed only for the validated loader subset after every required check passes"
                ),
            },
        }

    return {
        "schema_version": _RISK_SCHEMA_VERSION,
        "method": _LOAD_LIBRARY,
        "risk_level": "high",
        "overall_severity": "high",
        "score": 8,
        "execution": {
            "implemented": True,
            "available": True,
            "status": "guarded",
            "side_effects_allowed": True,
        },
        "assumptions": [
            "target permits required process access",
            "remote kernel32 export offsets match the local system image",
        ],
        "required_inputs": ["absolute DLL path", "DLL SHA-256", "positive target PID"],
        "validation_requirements": [
            {"id": "absolute_path", "required": True},
            {"id": "mz_signature", "required": True},
            {"id": "sha256_precondition", "required": True},
            {"id": "process_access", "required": True},
            {"id": "before_after_module_evidence", "required": True},
        ],
        "risks": [
            _risk(
                "remote_process_mutation",
                "memory_safety",
                "high",
                "high",
                "The strategy writes memory and starts a thread in another process.",
                ["least required process access", "bounded wait", "fail-closed validation"],
            ),
            _risk(
                "module_identity",
                "evidence",
                "high",
                "medium",
                "A thread exit code alone is insufficient evidence of the loaded DLL identity.",
                ["absolute path", "SHA-256 pin", "before/after exact-path module evidence"],
            ),
            _risk(
                "rollback_refcount",
                "reversibility",
                "high",
                "medium",
                "FreeLibrary may not unload a module with additional references.",
                ["reject already-loaded DLL", "verify module absence after rollback"],
            ),
        ],
        "rollback": {
            "implemented": True,
            "required": True,
            "residual_risk": "medium",
            "required_evidence": ["FreeLibrary result", "module absence", "temporary memory release"],
        },
        "acceptance": {
            "execution_allowed": True,
            "reason": "allowed only after every required validation passes",
        },
    }


def _risk(
    risk_id: str,
    category: str,
    severity: str,
    likelihood: str,
    description: str,
    controls: list[str],
) -> dict[str, Any]:
    return {
        "id": risk_id,
        "category": category,
        "severity": severity,
        "likelihood": likelihood,
        "impact": severity,
        "description": description,
        "required_controls": controls,
        "validation_status": "required",
        "residual_risk": severity,
    }


def _risk_schema_errors(value: Any, *, method: str) -> list[str]:
    if not isinstance(value, Mapping):
        return ["risk_assessment must be an object"]
    errors: list[str] = []
    required = {
        "schema_version",
        "method",
        "risk_level",
        "overall_severity",
        "score",
        "execution",
        "validation_requirements",
        "risks",
        "rollback",
        "acceptance",
    }
    missing = sorted(required - set(value.keys()))
    if missing:
        errors.append(f"missing fields: {', '.join(missing)}")
    if value.get("schema_version") != _RISK_SCHEMA_VERSION:
        errors.append("unsupported schema_version")
    if _normalize_method(value.get("method")) != method:
        errors.append("method does not match plan")
    execution = value.get("execution")
    if not isinstance(execution, Mapping) or not {"implemented", "available", "status"} <= set(execution):
        errors.append("execution must include implemented, available, and status")
    risks = value.get("risks")
    if not isinstance(risks, list) or not risks:
        errors.append("risks must be a non-empty list")
    else:
        risk_fields = {
            "id",
            "category",
            "severity",
            "likelihood",
            "impact",
            "description",
            "required_controls",
            "validation_status",
            "residual_risk",
        }
        for index, risk in enumerate(risks):
            if not isinstance(risk, Mapping):
                errors.append(f"risks[{index}] must be an object")
                continue
            missing_risk = sorted(risk_fields - set(risk.keys()))
            if missing_risk:
                errors.append(f"risks[{index}] missing fields: {', '.join(missing_risk)}")
    requirements = value.get("validation_requirements")
    if not isinstance(requirements, list) or not requirements:
        errors.append("validation_requirements must be a non-empty list")
    return errors


def _audit_artifact(session_id: str, method: str, status: str) -> CapabilityArtifact:
    return CapabilityArtifact(
        path=f"injector/{_safe_segment(session_id)}/injection.json",
        kind="injector-audit",
        description=f"Controlled injector audit for {method}",
        metadata={
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "session_id": session_id,
            "method": method,
            "status": status,
            "materialized": False,
        },
    )


def _manifest_entry(
    artifact: CapabilityArtifact,
    *,
    status: str,
    session_id: str,
    method: str,
    pid: Optional[int],
    dll_sha256: Any,
    target: Any = None,
) -> dict[str, Any]:
    return _prune(
        {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": "injector",
            "provider": InjectorProvider.provider_name,
            "status": status,
            "role": "injection-audit",
            "session_id": session_id,
            "method": method,
            "pid": pid,
            "dll_sha256": dll_sha256,
            "precondition_hash": dll_sha256,
            "target_identity": _target_identity(target),
        }
    )


def _target_identity(target: Any) -> dict[str, Any]:
    if hasattr(target, "to_dict"):
        return _json_mapping(target.to_dict())
    if isinstance(target, Mapping):
        return _json_mapping(target)
    return _json_mapping(
        {
            "kind": getattr(target, "kind", None),
            "path": getattr(target, "path", None),
            "pid": getattr(target, "pid", None),
            "sha256": getattr(target, "sha256", None),
            "display_name": getattr(target, "display_name", None),
            "metadata": getattr(target, "metadata", None),
        }
    )


def _injector_audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
        "method": result.provenance.get("method") or result.action,
        "session_id": result.session_id,
        "target_identity": _target_identity(result.target),
        "precondition_hash": result.provenance.get("precondition_hash"),
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
    report.update(
        {
            "session_id": result.session_id,
            "target_identity": _target_identity(result.target),
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


def _safe_segment(value: Any) -> str:
    text = str(value or "session")
    safe = "".join(character if character.isalnum() or character in "-_." else "_" for character in text)
    safe = safe.strip(".")
    return safe or "session"


def _deduplicate(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))


def _exception_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, InjectorBackendError):
        return exc.to_dict()
    return {
        "type": type(exc).__name__,
        "message": str(exc),
    }


def _pointer_value(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    try:
        return int(ctypes.cast(value, ctypes.c_void_p).value or 0)
    except (TypeError, ValueError):
        return int(getattr(value, "value", 0) or 0)


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
