"""Verified Windows-native hook capability provider.

This provider is intentionally separate from the Frida hook runtime.  It owns
the native process-memory and debug-register lifecycle needed for reversible
program repair and bounded diagnostics.  Every mutating operation requires an
explicit expected preimage and fails closed when instruction relocation,
target identity, cleanup, or write verification cannot be established.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib
import json
import os
import re
import struct
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Optional, Protocol

from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
    TargetIdentity,
)
from reverse_analyzer.providers.hook_targets import (
    HookTargetResolutionError,
    resolve_common_hook_target,
)


_AUDIT_SCHEMA_VERSION = 1
_SUPPORTED_ACTIONS = {
    "vtable_pointer",
    "inline_trampoline",
    "hardware_breakpoint",
}
_ACTION_ALIASES = {
    "vtable": "vtable_pointer",
    "vtable_pointer": "vtable_pointer",
    "inline": "inline_trampoline",
    "inline_hook": "inline_trampoline",
    "inline_trampoline": "inline_trampoline",
    "hardware_breakpoint": "hardware_breakpoint",
    "hardware_breakpoint_trace": "hardware_breakpoint",
    "hw_breakpoint": "hardware_breakpoint",
}
_ARCH_ALIASES = {
    "x86": "x86",
    "i386": "x86",
    "i686": "x86",
    "32": "x86",
    "x64": "x64",
    "amd64": "x64",
    "x86_64": "x64",
    "64": "x64",
}
_POINTER_SIZES = {"x86": 4, "x64": 8}
_MAX_INLINE_CAPTURE = 64
_MAX_TRACE_MS = 60_000
_MAX_TRACE_EVENTS = 10_000

_PAGE_READWRITE = 0x04
_PAGE_EXECUTE_READ = 0x20
_PAGE_EXECUTE_READWRITE = 0x40
_MEM_COMMIT = 0x1000
_MEM_RESERVE = 0x2000
_MEM_RELEASE = 0x8000

_PROCESS_VM_OPERATION = 0x0008
_PROCESS_VM_READ = 0x0010
_PROCESS_VM_WRITE = 0x0020
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_THREAD_SUSPEND_RESUME = 0x0002
_THREAD_GET_CONTEXT = 0x0008
_THREAD_SET_CONTEXT = 0x0010
_THREAD_QUERY_INFORMATION = 0x0040
_THREAD_QUERY_LIMITED_INFORMATION = 0x0800

_IMAGE_FILE_MACHINE_UNKNOWN = 0x0000
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_CONTEXT_AMD64 = 0x00100000
_CONTEXT_CONTROL = _CONTEXT_AMD64 | 0x00000001
_CONTEXT_DEBUG_REGISTERS = _CONTEXT_AMD64 | 0x00000010
_STATUS_BREAKPOINT = 0x80000003
_STATUS_SINGLE_STEP = 0x80000004
_EXCEPTION_DEBUG_EVENT = 1
_DBG_CONTINUE = 0x00010002
_DBG_EXCEPTION_NOT_HANDLED = 0x80010001
_ERROR_SEM_TIMEOUT = 121

_SAFE_SESSION_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_CAPSTONE_DEFAULT = object()
_RESULT_IDENTITY_KEY = "native_hook_result_identity"
_IDENTITY_SCHEMA_VERSION = 1


class NativeHookBackendError(RuntimeError):
    """A Win32 backend failure with a stable operation label."""

    def __init__(self, operation: str, message: str, *, error_code: int = 0) -> None:
        super().__init__(message)
        self.operation = operation
        self.error_code = int(error_code)


class NativeHookBackend(Protocol):
    """Backend seam used by the provider and deterministic fake tests."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_process(self, pid: int) -> Mapping[str, Any]: ...

    def probe_thread(self, pid: int, thread_id: int) -> Mapping[str, Any]: ...

    def read(self, pid: int, address: int, size: int) -> bytes: ...

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]: ...

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]: ...

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        near: Optional[int] = None,
    ) -> Mapping[str, Any]: ...

    def free(self, pid: int, address: int) -> Mapping[str, Any]: ...

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]: ...

    def trace_hardware_breakpoint(
        self,
        pid: int,
        thread_id: int,
        address: int,
        access: str,
        size: int,
        duration_ms: int,
        max_events: int,
        *,
        slot: Optional[int] = None,
    ) -> Mapping[str, Any]: ...


class UnavailableNativeHookBackend:
    name = "windows_native_hook"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        return {
            "status": "unavailable",
            "pid": pid,
            "accessible": None,
            "reason": self.unavailable_reason,
        }

    def probe_thread(self, pid: int, thread_id: int) -> Mapping[str, Any]:
        return {
            "status": "unavailable",
            "pid": pid,
            "thread_id": thread_id,
            "accessible": None,
            "reason": self.unavailable_reason,
        }

    def _raise(self, operation: str) -> None:
        raise NativeHookBackendError(operation, self.unavailable_reason)

    def read(self, pid: int, address: int, size: int) -> bytes:
        del pid, address, size
        self._raise("ReadProcessMemory")

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]:
        del pid, address, data
        self._raise("WriteProcessMemory")

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]:
        del pid, address, size, protection
        self._raise("VirtualProtectEx")

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        near: Optional[int] = None,
    ) -> Mapping[str, Any]:
        del pid, size, protection, near
        self._raise("VirtualAllocEx")

    def free(self, pid: int, address: int) -> Mapping[str, Any]:
        del pid, address
        self._raise("VirtualFreeEx")

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        del pid, address, size
        self._raise("FlushInstructionCache")

    def trace_hardware_breakpoint(
        self,
        pid: int,
        thread_id: int,
        address: int,
        access: str,
        size: int,
        duration_ms: int,
        max_events: int,
        *,
        slot: Optional[int] = None,
    ) -> Mapping[str, Any]:
        del pid, thread_id, address, access, size, duration_ms, max_events, slot
        return {"status": "unavailable", "reason": self.unavailable_reason}


class _M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_ulonglong), ("High", ctypes.c_longlong)]


class _XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_ushort),
        ("StatusWord", ctypes.c_ushort),
        ("TagWord", ctypes.c_ubyte),
        ("Reserved1", ctypes.c_ubyte),
        ("ErrorOpcode", ctypes.c_ushort),
        ("ErrorOffset", ctypes.c_ulong),
        ("ErrorSelector", ctypes.c_ushort),
        ("Reserved2", ctypes.c_ushort),
        ("DataOffset", ctypes.c_ulong),
        ("DataSelector", ctypes.c_ushort),
        ("Reserved3", ctypes.c_ushort),
        ("MxCsr", ctypes.c_ulong),
        ("MxCsr_Mask", ctypes.c_ulong),
        ("FloatRegisters", _M128A * 8),
        ("XmmRegisters", _M128A * 16),
        ("Reserved4", ctypes.c_ubyte * 96),
    ]


class _CONTEXT64_UNION(ctypes.Union):
    _fields_ = [("FltSave", _XMM_SAVE_AREA32), ("Q", _M128A * 32)]


class _CONTEXT64(ctypes.Structure):
    _anonymous_ = ("DUMMYUNION",)
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong),
        ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort),
        ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort),
        ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
        ("DUMMYUNION", _CONTEXT64_UNION),
        ("VectorRegister", _M128A * 26),
        ("VectorControl", ctypes.c_ulonglong),
        ("DebugControl", ctypes.c_ulonglong),
        ("LastBranchToRip", ctypes.c_ulonglong),
        ("LastBranchFromRip", ctypes.c_ulonglong),
        ("LastExceptionToRip", ctypes.c_ulonglong),
        ("LastExceptionFromRip", ctypes.c_ulonglong),
    ]


_ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class _EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", ctypes.c_ulong),
        ("ExceptionFlags", ctypes.c_ulong),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", ctypes.c_ulong),
        ("ExceptionInformation", _ULONG_PTR * 15),
    ]


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", _EXCEPTION_RECORD),
        ("dwFirstChance", ctypes.c_ulong),
    ]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("Exception", _EXCEPTION_DEBUG_INFO), ("raw", ctypes.c_ubyte * 192)]


class _DEBUG_EVENT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("dwDebugEventCode", ctypes.c_ulong),
        ("dwProcessId", ctypes.c_ulong),
        ("dwThreadId", ctypes.c_ulong),
        ("u", _DEBUG_EVENT_UNION),
    ]


class WindowsNativeHookBackend:
    """ctypes adapter for process memory and bounded x64 debug-register traces."""

    name = "windows_native_hook"

    def __init__(self, kernel32: Any = None) -> None:
        self.available = sys.platform == "win32"
        self.unavailable_reason: Optional[str] = None
        self._kernel32: Any = kernel32
        if not self.available:
            self.unavailable_reason = f"Windows native hook APIs are unavailable on {sys.platform}"
            return
        try:
            self._kernel32 = self._kernel32 or ctypes.WinDLL(
                "kernel32", use_last_error=True
            )
            self._configure_api()
        except Exception as exc:  # noqa: BLE001 - platform boundary
            self.available = False
            self.unavailable_reason = f"Windows native hook API initialization failed: {exc}"

    def _configure_api(self) -> None:
        k32 = self._kernel32
        k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k32.OpenThread.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        k32.ReadProcessMemory.restype = wintypes.BOOL
        k32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        k32.WriteProcessMemory.restype = wintypes.BOOL
        k32.VirtualProtectEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        k32.VirtualProtectEx.restype = wintypes.BOOL
        k32.VirtualAllocEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        k32.VirtualAllocEx.restype = ctypes.c_void_p
        k32.VirtualFreeEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
            wintypes.DWORD,
        ]
        k32.VirtualFreeEx.restype = wintypes.BOOL
        k32.FlushInstructionCache.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        k32.FlushInstructionCache.restype = wintypes.BOOL
        k32.SuspendThread.argtypes = [wintypes.HANDLE]
        k32.SuspendThread.restype = wintypes.DWORD
        k32.ResumeThread.argtypes = [wintypes.HANDLE]
        k32.ResumeThread.restype = wintypes.DWORD
        k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(_CONTEXT64)]
        k32.GetThreadContext.restype = wintypes.BOOL
        k32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(_CONTEXT64)]
        k32.SetThreadContext.restype = wintypes.BOOL
        k32.DebugActiveProcess.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcess.restype = wintypes.BOOL
        k32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcessStop.restype = wintypes.BOOL
        k32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
        k32.DebugSetProcessKillOnExit.restype = wintypes.BOOL
        k32.WaitForDebugEvent.argtypes = [ctypes.POINTER(_DEBUG_EVENT), wintypes.DWORD]
        k32.WaitForDebugEvent.restype = wintypes.BOOL
        k32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
        k32.ContinueDebugEvent.restype = wintypes.BOOL

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        if not self.available:
            return UnavailableNativeHookBackend(
                self.unavailable_reason or "Windows APIs are unavailable"
            ).probe_process(pid)
        handle = None
        try:
            handle = self._open_process(
                pid,
                _PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_VM_READ,
                "probe_process",
            )
            return {
                "status": "ok",
                "pid": pid,
                "exists": True,
                "accessible": True,
                "image_path": self._query_image_path(handle),
                "creation_time": self._query_creation_time(handle),
                "architecture": self._process_architecture(handle),
            }
        except NativeHookBackendError as exc:
            return {
                "status": "failed",
                "pid": pid,
                "exists": None,
                "accessible": False,
                "error": _exception_payload(exc),
            }
        finally:
            self._close(handle)

    def probe_thread(self, pid: int, thread_id: int) -> Mapping[str, Any]:
        process = self.probe_process(pid)
        if process.get("status") != "ok":
            return {
                "status": process.get("status", "failed"),
                "pid": pid,
                "thread_id": thread_id,
                "accessible": False,
                "process": process,
            }
        handle = None
        try:
            handle = self._open_thread(
                thread_id,
                _THREAD_QUERY_LIMITED_INFORMATION
                | _THREAD_GET_CONTEXT
                | _THREAD_SET_CONTEXT
                | _THREAD_SUSPEND_RESUME,
                "probe_thread",
            )
            owner = None
            get_owner = getattr(self._kernel32, "GetProcessIdOfThread", None)
            if callable(get_owner):
                get_owner.argtypes = [wintypes.HANDLE]
                get_owner.restype = wintypes.DWORD
                owner = int(get_owner(handle))
            owner_matches = owner in (None, 0, pid)
            supported = (
                process.get("architecture") == "x64"
                and ctypes.sizeof(ctypes.c_void_p) == 8
            )
            return {
                "status": "ok" if owner_matches else "failed",
                "pid": pid,
                "thread_id": thread_id,
                "owner_pid": owner,
                "owner_matches": owner_matches,
                "accessible": owner_matches,
                "architecture": process.get("architecture"),
                "hardware_breakpoint_supported": supported,
                "reason": None
                if supported
                else "hardware breakpoint context is limited to same-bitness x64 targets",
            }
        except NativeHookBackendError as exc:
            return {
                "status": "failed",
                "pid": pid,
                "thread_id": thread_id,
                "accessible": False,
                "error": _exception_payload(exc),
            }
        finally:
            self._close(handle)

    def read(self, pid: int, address: int, size: int) -> bytes:
        if size <= 0:
            raise ValueError("read size must be positive")
        handle = self._open_process(
            pid, _PROCESS_VM_READ | _PROCESS_QUERY_INFORMATION, "ReadProcessMemory"
        )
        try:
            buffer = (ctypes.c_ubyte * size)()
            read_count = ctypes.c_size_t(0)
            ok = self._kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(read_count),
            )
            if not ok or read_count.value != size:
                self._raise_last_error(
                    "ReadProcessMemory",
                    f"read {read_count.value} of {size} bytes at 0x{address:x}",
                )
            return bytes(buffer)
        finally:
            self._close(handle)

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]:
        payload = bytes(data)
        if not payload:
            raise ValueError("write payload must not be empty")
        handle = self._open_process(
            pid,
            _PROCESS_VM_OPERATION | _PROCESS_VM_WRITE | _PROCESS_VM_READ,
            "WriteProcessMemory",
        )
        try:
            buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
            written = ctypes.c_size_t(0)
            ok = self._kernel32.WriteProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                len(payload),
                ctypes.byref(written),
            )
            if not ok or written.value != len(payload):
                self._raise_last_error(
                    "WriteProcessMemory",
                    f"wrote {written.value} of {len(payload)} bytes at 0x{address:x}",
                )
            return {
                "ok": True,
                "status": "ok",
                "address": address,
                "bytes_written": written.value,
            }
        finally:
            self._close(handle)

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]:
        handle = self._open_process(pid, _PROCESS_VM_OPERATION, "VirtualProtectEx")
        try:
            old = wintypes.DWORD(0)
            ok = self._kernel32.VirtualProtectEx(
                handle,
                ctypes.c_void_p(address),
                size,
                protection,
                ctypes.byref(old),
            )
            if not ok:
                self._raise_last_error(
                    "VirtualProtectEx", f"could not protect 0x{address:x}+0x{size:x}"
                )
            return {
                "ok": True,
                "status": "ok",
                "address": address,
                "size": size,
                "old_protection": int(old.value),
                "new_protection": int(protection),
            }
        finally:
            self._close(handle)

    def alloc(
        self,
        pid: int,
        size: int,
        protection: int,
        *,
        near: Optional[int] = None,
    ) -> Mapping[str, Any]:
        handle = self._open_process(pid, _PROCESS_VM_OPERATION, "VirtualAllocEx")
        try:
            hints: list[Optional[int]] = []
            if near is not None:
                base = near & ~0xFFFF
                for delta in (0x10000, -0x10000, 0x100000, -0x100000, 0x1000000, -0x1000000):
                    candidate = base + delta
                    if candidate > 0:
                        hints.append(candidate)
            hints.append(None)
            allocated = 0
            for hint in hints:
                pointer = self._kernel32.VirtualAllocEx(
                    handle,
                    ctypes.c_void_p(hint) if hint is not None else None,
                    size,
                    _MEM_COMMIT | _MEM_RESERVE,
                    protection,
                )
                allocated = int(pointer or 0)
                if allocated:
                    break
            if not allocated:
                self._raise_last_error("VirtualAllocEx", "remote allocation failed")
            return {
                "ok": True,
                "status": "ok",
                "address": allocated,
                "size": size,
                "protection": protection,
            }
        finally:
            self._close(handle)

    def free(self, pid: int, address: int) -> Mapping[str, Any]:
        handle = self._open_process(pid, _PROCESS_VM_OPERATION, "VirtualFreeEx")
        try:
            ok = self._kernel32.VirtualFreeEx(
                handle, ctypes.c_void_p(address), 0, _MEM_RELEASE
            )
            if not ok:
                self._raise_last_error(
                    "VirtualFreeEx", f"could not release allocation 0x{address:x}"
                )
            return {"ok": True, "status": "ok", "address": address, "released": True}
        finally:
            self._close(handle)

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        handle = self._open_process(
            pid, _PROCESS_QUERY_INFORMATION, "FlushInstructionCache"
        )
        try:
            ok = self._kernel32.FlushInstructionCache(
                handle, ctypes.c_void_p(address), size
            )
            if not ok:
                self._raise_last_error(
                    "FlushInstructionCache", f"flush failed at 0x{address:x}"
                )
            return {"ok": True, "status": "ok", "address": address, "size": size}
        finally:
            self._close(handle)

    def trace_hardware_breakpoint(
        self,
        pid: int,
        thread_id: int,
        address: int,
        access: str,
        size: int,
        duration_ms: int,
        max_events: int,
        *,
        slot: Optional[int] = None,
    ) -> Mapping[str, Any]:
        probe = self.probe_thread(pid, thread_id)
        if probe.get("status") != "ok":
            return {"status": "failed", "reason": "target thread is inaccessible", "probe": probe}
        if not probe.get("hardware_breakpoint_supported"):
            return {
                "status": "unavailable",
                "reason": probe.get("reason")
                or "hardware breakpoint context is unavailable for this target",
                "probe": probe,
                "installed": False,
                "restored": False,
                "debug_detached": False,
            }

        thread = None
        attached = False
        installed = False
        restored = False
        debug_detached = False
        selected_slot: Optional[int] = None
        original: dict[str, int] = {}
        events: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        initial_breakpoint_pending = True
        started = time.monotonic()
        try:
            thread = self._open_thread(
                thread_id,
                _THREAD_GET_CONTEXT
                | _THREAD_SET_CONTEXT
                | _THREAD_SUSPEND_RESUME
                | _THREAD_QUERY_INFORMATION,
                "OpenThread",
            )
            if not self._kernel32.DebugActiveProcess(pid):
                self._raise_last_error("DebugActiveProcess", f"could not attach to PID {pid}")
            attached = True
            if not self._kernel32.DebugSetProcessKillOnExit(False):
                self._raise_last_error(
                    "DebugSetProcessKillOnExit", "could not disable debugger kill-on-exit"
                )

            context = self._get_suspended_context(thread)
            original = _debug_registers(context)
            selected_slot = _select_debug_slot(int(context.Dr7), slot)
            _install_debug_register(
                context,
                selected_slot,
                address=address,
                access=access,
                size=size,
            )
            self._set_suspended_context(thread, context)
            installed = True

            deadline = started + (max(0, duration_ms) / 1000.0)
            while time.monotonic() <= deadline and len(events) < max_events:
                remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                event = _DEBUG_EVENT()
                wait_ms = min(50, remaining_ms) if remaining_ms else 0
                if not self._kernel32.WaitForDebugEvent(ctypes.byref(event), wait_ms):
                    code = ctypes.get_last_error()
                    if code in (0, _ERROR_SEM_TIMEOUT):
                        if remaining_ms <= 0:
                            break
                        continue
                    raise NativeHookBackendError(
                        "WaitForDebugEvent", _format_win_error(code), error_code=code
                    )

                continue_status = _DBG_CONTINUE
                try:
                    exception_code = None
                    if event.dwDebugEventCode == _EXCEPTION_DEBUG_EVENT:
                        exception_code = int(event.Exception.ExceptionRecord.ExceptionCode)
                        if (
                            exception_code == _STATUS_BREAKPOINT
                            and initial_breakpoint_pending
                        ):
                            initial_breakpoint_pending = False
                        elif (
                            exception_code == _STATUS_SINGLE_STEP
                            and int(event.dwThreadId) == thread_id
                        ):
                            event_context = self._get_context(thread)
                            slot_hit = bool(
                                selected_slot is not None
                                and int(event_context.Dr6) & (1 << selected_slot)
                            )
                            if slot_hit:
                                events.append(
                                    {
                                        "index": len(events),
                                        "event": "hardware_breakpoint",
                                        "pid": int(event.dwProcessId),
                                        "thread_id": int(event.dwThreadId),
                                        "exception_code": exception_code,
                                        "exception_address": int(
                                            event.Exception.ExceptionRecord.ExceptionAddress
                                            or 0
                                        ),
                                        "instruction_pointer": int(event_context.Rip),
                                        "dr6": int(event_context.Dr6),
                                        "slot": selected_slot,
                                        "watch_address": address,
                                        "access": access,
                                        "size": size,
                                        "elapsed_ms": int(
                                            (time.monotonic() - started) * 1000
                                        ),
                                    }
                                )
                            else:
                                continue_status = _DBG_EXCEPTION_NOT_HANDLED
                        else:
                            continue_status = _DBG_EXCEPTION_NOT_HANDLED
                finally:
                    if not self._kernel32.ContinueDebugEvent(
                        event.dwProcessId, event.dwThreadId, continue_status
                    ):
                        self._raise_last_error(
                            "ContinueDebugEvent", "could not continue debug event"
                        )
        except Exception as exc:  # noqa: BLE001 - converted to explicit trace failure
            errors.append(_exception_payload(exc))
        finally:
            if thread is not None and original:
                try:
                    current = self._get_suspended_context(thread)
                    _restore_debug_registers(current, original)
                    self._set_suspended_context(thread, current)
                    verified = self._get_suspended_context(thread)
                    restored = _debug_registers(verified) == original
                    if not restored:
                        errors.append(
                            {
                                "type": "RuntimeError",
                                "message": "debug-register restoration verification failed",
                                "operation": "restore_thread_context",
                            }
                        )
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))
            if attached:
                try:
                    debug_detached = bool(self._kernel32.DebugActiveProcessStop(pid))
                    if not debug_detached:
                        self._raise_last_error(
                            "DebugActiveProcessStop", f"could not detach from PID {pid}"
                        )
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))
            self._close(thread)

        status = "ok" if installed and restored and debug_detached and not errors else "failed"
        return {
            "status": status,
            "installed": installed,
            "restored": restored,
            "debug_detached": debug_detached,
            "slot": selected_slot,
            "events": events,
            "event_count": len(events),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "bounded": True,
            "original_context": original,
            "errors": errors,
        }

    def _open_process(self, pid: int, access: int, operation: str) -> Any:
        if not self.available:
            raise NativeHookBackendError(
                operation, self.unavailable_reason or "Windows APIs are unavailable"
            )
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            self._raise_last_error(operation, f"could not open PID {pid}")
        return handle

    def _open_thread(self, thread_id: int, access: int, operation: str) -> Any:
        if not self.available:
            raise NativeHookBackendError(
                operation, self.unavailable_reason or "Windows APIs are unavailable"
            )
        handle = self._kernel32.OpenThread(access, False, thread_id)
        if not handle:
            self._raise_last_error(operation, f"could not open thread {thread_id}")
        return handle

    def _close(self, handle: Any) -> None:
        if handle:
            self._kernel32.CloseHandle(handle)

    def _raise_last_error(self, operation: str, message: str) -> None:
        code = int(ctypes.get_last_error())
        detail = _format_win_error(code)
        raise NativeHookBackendError(
            operation, f"{message}: {detail}", error_code=code
        )

    def _query_image_path(self, handle: Any) -> Optional[str]:
        query = getattr(self._kernel32, "QueryFullProcessImageNameW", None)
        if not callable(query):
            return None
        query.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        query.restype = wintypes.BOOL
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not query(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value

    def _query_creation_time(self, handle: Any) -> Optional[int]:
        get_times = getattr(self._kernel32, "GetProcessTimes", None)
        if not callable(get_times):
            return None
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        if not get_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return None
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

    def _process_architecture(self, handle: Any) -> Optional[str]:
        is_wow64_2 = getattr(self._kernel32, "IsWow64Process2", None)
        if callable(is_wow64_2):
            process_machine = wintypes.USHORT(0)
            native_machine = wintypes.USHORT(0)
            if is_wow64_2(handle, ctypes.byref(process_machine), ctypes.byref(native_machine)):
                machine = (
                    int(native_machine.value)
                    if process_machine.value == _IMAGE_FILE_MACHINE_UNKNOWN
                    else int(process_machine.value)
                )
                if machine == _IMAGE_FILE_MACHINE_AMD64:
                    return "x64"
                if machine == _IMAGE_FILE_MACHINE_I386:
                    return "x86"
        is_wow64 = getattr(self._kernel32, "IsWow64Process", None)
        if callable(is_wow64):
            wow64 = wintypes.BOOL(False)
            if is_wow64(handle, ctypes.byref(wow64)):
                if wow64.value:
                    return "x86"
                return "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"
        return None

    def _get_context(self, thread: Any) -> _CONTEXT64:
        context = _CONTEXT64()
        context.ContextFlags = _CONTEXT_CONTROL | _CONTEXT_DEBUG_REGISTERS
        if not self._kernel32.GetThreadContext(thread, ctypes.byref(context)):
            self._raise_last_error("GetThreadContext", "could not read thread context")
        return context

    def _get_suspended_context(self, thread: Any) -> _CONTEXT64:
        suspended = self._kernel32.SuspendThread(thread)
        if suspended == 0xFFFFFFFF:
            self._raise_last_error("SuspendThread", "could not suspend target thread")
        try:
            return self._get_context(thread)
        finally:
            if self._kernel32.ResumeThread(thread) == 0xFFFFFFFF:
                self._raise_last_error("ResumeThread", "could not resume target thread")

    def _set_suspended_context(self, thread: Any, context: _CONTEXT64) -> None:
        suspended = self._kernel32.SuspendThread(thread)
        if suspended == 0xFFFFFFFF:
            self._raise_last_error("SuspendThread", "could not suspend target thread")
        try:
            context.ContextFlags = _CONTEXT_CONTROL | _CONTEXT_DEBUG_REGISTERS
            if not self._kernel32.SetThreadContext(thread, ctypes.byref(context)):
                self._raise_last_error("SetThreadContext", "could not write thread context")
        finally:
            if self._kernel32.ResumeThread(thread) == 0xFFFFFFFF:
                self._raise_last_error("ResumeThread", "could not resume target thread")


def _debug_registers(context: _CONTEXT64) -> dict[str, int]:
    return {
        "dr0": int(context.Dr0),
        "dr1": int(context.Dr1),
        "dr2": int(context.Dr2),
        "dr3": int(context.Dr3),
        "dr6": int(context.Dr6),
        "dr7": int(context.Dr7),
    }


def _restore_debug_registers(context: _CONTEXT64, values: Mapping[str, Any]) -> None:
    context.Dr0 = int(values["dr0"])
    context.Dr1 = int(values["dr1"])
    context.Dr2 = int(values["dr2"])
    context.Dr3 = int(values["dr3"])
    context.Dr6 = int(values["dr6"])
    context.Dr7 = int(values["dr7"])


def _select_debug_slot(dr7: int, requested: Optional[int]) -> int:
    candidates = [requested] if requested is not None else list(range(4))
    for slot in candidates:
        if slot is None or slot not in range(4):
            continue
        if ((dr7 >> (slot * 2)) & 0b11) == 0:
            return slot
    if requested is not None:
        raise RuntimeError(f"requested debug register DR{requested} is already enabled")
    raise RuntimeError("no unused hardware debug register is available")


def _install_debug_register(
    context: _CONTEXT64,
    slot: int,
    *,
    address: int,
    access: str,
    size: int,
) -> None:
    setattr(context, f"Dr{slot}", address)
    rw_bits = {"execute": 0b00, "write": 0b01, "readwrite": 0b11}[access]
    length_bits = {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}[size]
    enable_shift = slot * 2
    control_shift = 16 + slot * 4
    dr7 = int(context.Dr7)
    dr7 &= ~(0b11 << enable_shift)
    dr7 &= ~(0b1111 << control_shift)
    dr7 |= 0b01 << enable_shift
    dr7 |= rw_bits << control_shift
    dr7 |= length_bits << (control_shift + 2)
    context.Dr6 = 0
    context.Dr7 = dr7


def _format_win_error(code: int) -> str:
    if not code:
        return "unknown Win32 error"
    try:
        return ctypes.FormatError(code).strip() or f"Win32 error {code}"
    except Exception:  # noqa: BLE001
        return f"Win32 error {code}"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prune(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return {str(key): _json_value(item) for key, item in payload.items()}
    return {}


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _target_payload(target: TargetIdentity) -> dict[str, Any]:
    return {
        "kind": target.kind,
        "path": target.path,
        "pid": target.pid,
        "sha256": target.sha256,
        "display_name": target.display_name,
        "metadata": _json_mapping(target.metadata),
    }


def _normalize_action(value: Any) -> str:
    key = str(value or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(key, key)


def _normalize_architecture(value: Any) -> Optional[str]:
    key = str(value or "").strip().lower().replace("-", "_")
    return _ARCH_ALIASES.get(key)


def _coerce_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().replace("_", "")
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            try:
                return int(text, 16)
            except ValueError:
                return None
    return None


def _first_value(mapping: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _parse_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        try:
            return bytes(int(item) for item in value)
        except (TypeError, ValueError, OverflowError):
            return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        text = re.sub(r"[\s:_-]", "", text)
        if not text or len(text) % 2:
            return None
        try:
            return bytes.fromhex(text)
        except ValueError:
            return None
    return None


def _pointer_bytes(value: int, pointer_size: int) -> bytes:
    if value < 0 or value >= 1 << (pointer_size * 8):
        raise ValueError(f"pointer 0x{value:x} does not fit in {pointer_size * 8} bits")
    return value.to_bytes(pointer_size, byteorder="little", signed=False)


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", True))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "Windows native hook backend is unavailable"
    )


def _backend_info(backend: Any, platform_name: str) -> dict[str, Any]:
    return {
        "name": str(getattr(backend, "name", backend.__class__.__name__)),
        "available": _backend_available(backend),
        "unavailable_reason": getattr(backend, "unavailable_reason", None),
        "platform": platform_name,
    }


def _exception_payload(exc: BaseException) -> dict[str, Any]:
    payload = {"type": exc.__class__.__name__, "message": str(exc)}
    operation = getattr(exc, "operation", None)
    if operation:
        payload["operation"] = str(operation)
    error_code = _coerce_int(getattr(exc, "error_code", None))
    if error_code:
        payload["error_code"] = error_code
    return payload


def _operation_mapping(value: Any, *, operation: str) -> dict[str, Any]:
    if isinstance(value, Mapping):
        payload = _json_mapping(value)
    elif isinstance(value, bool):
        payload = {"ok": value, "status": "ok" if value else "failed"}
    elif isinstance(value, int):
        payload = {"ok": value > 0, "status": "ok" if value > 0 else "failed", "value": value}
    elif value is None:
        payload = {"ok": True, "status": "ok"}
    else:
        payload = {"ok": False, "status": "failed", "value": _json_value(value)}
    payload.setdefault("operation", operation)
    if "ok" not in payload:
        payload["ok"] = str(payload.get("status") or "").lower() in {
            "ok",
            "success",
            "succeeded",
            "already_restored",
        }
    payload.setdefault("status", "ok" if payload["ok"] else "failed")
    return payload


def _operation_ok(value: Any) -> bool:
    return bool(_operation_mapping(value, operation="operation").get("ok"))


def _process_identity(probe: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "pid": _coerce_int(probe.get("pid")),
            "image_path": probe.get("image_path"),
            "creation_time": probe.get("creation_time"),
            "architecture": _normalize_architecture(probe.get("architecture")),
        }
    )


def _process_identity_matches(
    planned: Mapping[str, Any], current: Mapping[str, Any]
) -> bool:
    planned_identity = _process_identity(planned)
    current_identity = _process_identity(current)
    for key, expected in planned_identity.items():
        actual = current_identity.get(key)
        if key == "image_path" and isinstance(expected, str) and isinstance(actual, str):
            if expected.casefold() != actual.casefold():
                return False
        elif actual != expected:
            return False
    return bool(planned_identity) and bool(current_identity)


def _plan_integrity_payload(plan: CapabilityPlan) -> dict[str, Any]:
    rollback_plan = _json_mapping(plan.rollback_plan)
    # The rollback record carries the digest for correlation, but the digest
    # cannot include itself.
    rollback_plan.pop("precondition_hash", None)
    return {
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "target": _target_payload(plan.target),
        "action": plan.action,
        "parameters": _json_mapping(plan.parameters),
        "before_snapshot": _json_mapping(plan.before_snapshot),
        "rollback_plan": rollback_plan,
    }


def _plan_precondition_hash(plan: CapabilityPlan) -> str:
    return _sha256_json(_plan_integrity_payload(plan))


def _hook_target_request(
    params: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    raw = params.get("target_resolution")
    if not isinstance(raw, Mapping):
        raise HookTargetResolutionError("target_resolution must be an object")
    nested = raw.get("specification")
    if nested is not None:
        if not isinstance(nested, Mapping):
            raise HookTargetResolutionError(
                "target_resolution.specification must be an object"
            )
        specification = _json_mapping(nested)
    else:
        specification = {
            str(key): _json_value(value)
            for key, value in raw.items()
            if str(key) != "modules"
        }
    if not specification:
        raise HookTargetResolutionError("target_resolution specification is empty")

    raw_modules = raw.get(
        "modules",
        params.get("target_modules", params.get("hook_modules", [])),
    )
    if raw_modules is None:
        raw_modules = []
    if not isinstance(raw_modules, Sequence) or isinstance(
        raw_modules, (str, bytes, bytearray)
    ):
        raise HookTargetResolutionError("target_resolution modules must be an array")
    modules: list[dict[str, Any]] = []
    for index, item in enumerate(raw_modules):
        if not isinstance(item, Mapping):
            raise HookTargetResolutionError(
                f"target_resolution modules[{index}] must be an object"
            )
        modules.append(_json_mapping(item))
    return specification, modules


def _bind_resolved_target(
    *,
    action: str,
    params: dict[str, Any],
    normalized: dict[str, Any],
) -> None:
    if "target_resolution" not in params:
        return
    errors = normalized.setdefault("parameter_errors", [])
    try:
        specification, modules = _hook_target_request(params)
        resolution = resolve_common_hook_target(specification, modules=modules)
    except (HookTargetResolutionError, OSError, TypeError, ValueError) as exc:
        errors.append(f"hook target resolution failed: {exc}")
        return

    request_payload = {
        "specification": specification,
        "modules": modules,
    }
    resolution_payload = resolution.to_dict()
    normalized["target_resolution_request"] = request_payload
    normalized["target_resolution"] = resolution_payload
    if not resolution.ok:
        detail = "; ".join(resolution.errors) or resolution.status
        errors.append(f"hook target resolution is not usable: {detail}")
        return

    source_architecture = _normalize_architecture(
        resolution_payload.get("source", {}).get("architecture")
    )
    requested_architecture = _normalize_architecture(
        _first_value(params, "architecture", "arch")
    )
    if source_architecture and requested_architecture:
        if source_architecture != requested_architecture:
            errors.append(
                "hook target architecture conflicts with the requested architecture"
            )
    elif source_architecture:
        params["architecture"] = source_architecture
        normalized["architecture"] = source_architecture

    def bind_address(
        canonical_key: str,
        resolved_value: Optional[int],
        *aliases: str,
    ) -> None:
        if not resolved_value or resolved_value <= 0:
            errors.append(
                f"hook target resolution did not prove {canonical_key}"
            )
            return
        supplied = _coerce_int(_first_value(params, canonical_key, *aliases))
        if supplied is not None and supplied != resolved_value:
            errors.append(
                f"resolved {canonical_key} conflicts with the caller-provided address"
            )
            return
        params[canonical_key] = resolved_value

    if action == "vtable_pointer":
        bind_address("slot_address", resolution.slot_address, "address")
        bind_address(
            "expected_original_pointer",
            resolution.address,
            "expected_original",
            "expected_pointer",
        )
    elif action == "inline_trampoline":
        bind_address("target_address", resolution.address, "address")
    elif action == "hardware_breakpoint":
        bind_address("address", resolution.address, "target_address")


def _resolve_planned_hook_target(plan: CapabilityPlan) -> dict[str, Any] | None:
    request = plan.parameters.get("target_resolution_request")
    planned = plan.parameters.get("target_resolution")
    if request is None and planned is None:
        return None
    if not isinstance(request, Mapping) or not isinstance(planned, Mapping):
        raise HookTargetResolutionError(
            "planned hook target resolution evidence is malformed"
        )
    specification = request.get("specification")
    modules = request.get("modules", [])
    if not isinstance(specification, Mapping):
        raise HookTargetResolutionError(
            "planned hook target specification is malformed"
        )
    if not isinstance(modules, Sequence) or isinstance(
        modules, (str, bytes, bytearray)
    ) or any(not isinstance(item, Mapping) for item in modules):
        raise HookTargetResolutionError("planned hook target modules are malformed")
    resolution = resolve_common_hook_target(
        specification,
        modules=[_json_mapping(item) for item in modules],
    )
    payload = _prune(resolution.to_dict())
    if not resolution.ok:
        detail = "; ".join(resolution.errors) or resolution.status
        raise HookTargetResolutionError(
            f"planned hook target no longer resolves: {detail}"
        )
    if _canonical_json(payload) != _canonical_json(planned):
        raise HookTargetResolutionError(
            "hook target resolution evidence changed after planning"
        )
    if payload.get("executable_range", {}).get("status") != "ok":
        raise HookTargetResolutionError(
            "hook target no longer has an executable-range proof"
        )
    return payload


def _minimum_jump_size(architecture: str) -> int:
    return 5 if architecture == "x86" else 14


def _relative_jump(source_address: int, destination: int) -> bytes:
    displacement = destination - (source_address + 5)
    if displacement < -(1 << 31) or displacement > (1 << 31) - 1:
        raise ValueError("x86 relative jump target is outside the signed 32-bit range")
    return b"\xE9" + struct.pack("<i", displacement)


def _absolute_x64_jump(destination: int) -> bytes:
    return b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", destination)


def _jump_bytes(source_address: int, destination: int, architecture: str) -> bytes:
    if architecture == "x86":
        return _relative_jump(source_address, destination)
    if architecture == "x64":
        return _absolute_x64_jump(destination)
    raise ValueError(f"unsupported architecture: {architecture}")


def _load_capstone(selected: Any) -> tuple[Any, Optional[str]]:
    if selected is not _CAPSTONE_DEFAULT:
        if selected is None:
            return None, "Capstone disassembler is unavailable"
        return selected, None
    try:
        return importlib.import_module("capstone"), None
    except Exception as exc:  # noqa: BLE001 - optional dependency boundary
        return None, f"Capstone disassembler is unavailable: {exc}"


def _analyze_inline_instructions(
    code: bytes,
    address: int,
    architecture: str,
    capstone_module: Any,
) -> dict[str, Any]:
    minimum = _minimum_jump_size(architecture)
    if capstone_module is None:
        return {
            "status": "unavailable",
            "safe": False,
            "minimum_size": minimum,
            "reason": "Capstone disassembler is unavailable",
        }
    if not code:
        return {
            "status": "failed",
            "safe": False,
            "minimum_size": minimum,
            "reason": "inline trampoline requires captured original bytes",
        }
    try:
        mode = (
            capstone_module.CS_MODE_32
            if architecture == "x86"
            else capstone_module.CS_MODE_64
        )
        disassembler = capstone_module.Cs(capstone_module.CS_ARCH_X86, mode)
        disassembler.detail = True
        instructions: list[dict[str, Any]] = []
        unsafe: list[dict[str, Any]] = []
        consumed = 0
        expected_address = address
        x86_const = getattr(capstone_module, "x86_const", None)
        op_mem = getattr(x86_const, "X86_OP_MEM", 3)
        rip_reg = getattr(x86_const, "X86_REG_RIP", -1)
        control_groups = {
            value
            for value in (
                getattr(capstone_module, "CS_GRP_JUMP", None),
                getattr(capstone_module, "CS_GRP_CALL", None),
                getattr(capstone_module, "CS_GRP_RET", None),
                getattr(capstone_module, "CS_GRP_INT", None),
                getattr(capstone_module, "CS_GRP_IRET", None),
                getattr(capstone_module, "CS_GRP_BRANCH_RELATIVE", None),
            )
            if value is not None
        }
        for instruction in disassembler.disasm(code, address):
            if int(instruction.address) != expected_address or int(instruction.size) <= 0:
                unsafe.append(
                    {
                        "address": int(instruction.address),
                        "reason": "non-contiguous instruction decode",
                    }
                )
                break
            reasons: list[str] = []
            groups = {int(group) for group in getattr(instruction, "groups", [])}
            if groups & control_groups:
                reasons.append("relative or control-flow instruction requires relocation")
            for operand in getattr(instruction, "operands", []):
                if getattr(operand, "type", None) != op_mem:
                    continue
                memory = getattr(operand, "mem", None)
                if memory is not None and getattr(memory, "base", None) == rip_reg:
                    reasons.append("RIP-relative memory operand requires relocation")
            item = {
                "address": int(instruction.address),
                "size": int(instruction.size),
                "bytes_hex": bytes(instruction.bytes).hex(),
                "mnemonic": str(instruction.mnemonic),
                "op_str": str(instruction.op_str),
            }
            instructions.append(item)
            for reason in dict.fromkeys(reasons):
                unsafe.append({**item, "reason": reason})
            consumed += int(instruction.size)
            expected_address += int(instruction.size)
            if consumed >= minimum:
                break

        if consumed < minimum:
            return {
                "status": "failed",
                "safe": False,
                "minimum_size": minimum,
                "overwrite_size": consumed,
                "instructions": instructions,
                "unsafe": unsafe,
                "reason": "Capstone could not decode complete instructions covering the jump",
            }
        selected = code[:consumed]
        return {
            "status": "ok" if not unsafe else "failed",
            "safe": not unsafe,
            "minimum_size": minimum,
            "overwrite_size": consumed,
            "original_hex": selected.hex(),
            "instructions": instructions,
            "unsafe": unsafe,
            "reason": None
            if not unsafe
            else "inline prologue contains instructions that are not safely relocatable",
        }
    except Exception as exc:  # noqa: BLE001 - disassembler failures are validation data
        return {
            "status": "failed",
            "safe": False,
            "minimum_size": minimum,
            "reason": f"Capstone disassembly failed: {exc}",
            "error": _exception_payload(exc),
        }


class NativeHookProvider:
    """Plan and execute reversible Windows-native hooks with explicit consent."""

    capability_name = "native_hook"
    provider_name = "windows_native_hook"
    priority = 10

    def __init__(
        self,
        backend: Optional[NativeHookBackend] = None,
        *,
        platform_name: Optional[str] = None,
        capstone_module: Any = _CAPSTONE_DEFAULT,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        if backend is not None:
            self.backend: NativeHookBackend = backend
        elif self.platform_name == "win32":
            self.backend = WindowsNativeHookBackend()
        else:
            self.backend = UnavailableNativeHookBackend(
                f"Windows native hook APIs are unavailable on {self.platform_name}"
            )
        self._capstone_option = capstone_module
        self._instance_id = uuid.uuid4().hex
        self._issued_plans: dict[str, str] = {}
        self._issued_results: dict[str, str] = {}

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
        session_id = str(request.session_id or "native-hook-session")
        params = _json_mapping(request.params)
        raw_pid = _first_value(params, "pid", "process_id")
        param_pid = _coerce_int(raw_pid)
        target_pid = _coerce_int(request.target.pid)
        pid_conflict = bool(param_pid and target_pid and param_pid != target_pid)
        pid = target_pid if target_pid is not None else param_pid
        authorized = (
            params.get("authorized") is True
            or params.get("user_authorized") is True
            or request.provenance.get("authorized") is True
        )
        authorization_source = (
            "params.authorized"
            if params.get("authorized") is True
            else "params.user_authorized"
            if params.get("user_authorized") is True
            else "provenance.authorized"
            if request.provenance.get("authorized") is True
            else "missing"
        )

        process_probe = self._probe_process(backend, pid)
        architecture = _normalize_architecture(
            _first_value(params, "architecture", "arch")
        ) or _normalize_architecture(process_probe.get("architecture"))
        normalized: dict[str, Any] = {
            "requested_action": request.action,
            "pid": pid if pid is not None else raw_pid,
            "pid_conflict": pid_conflict,
            "authorized": authorized,
            "authorization_source": authorization_source,
            "authorization_scope": params.get("authorization_scope")
            or params.get("reason")
            or "program repair/diagnostics",
            "architecture": architecture,
            "parameter_errors": [],
        }
        _bind_resolved_target(
            action=action,
            params=params,
            normalized=normalized,
        )
        architecture = _normalize_architecture(
            normalized.get("architecture")
        ) or _normalize_architecture(_first_value(params, "architecture", "arch"))
        normalized["architecture"] = architecture
        before_action: dict[str, Any] = {"status": "not_captured"}

        if action == "vtable_pointer":
            before_action = self._plan_vtable(
                backend, pid, architecture, params, normalized
            )
        elif action == "inline_trampoline":
            before_action = self._plan_inline(
                backend, pid, architecture, params, normalized
            )
        elif action == "hardware_breakpoint":
            before_action = self._plan_hardware_breakpoint(
                backend, pid, params, normalized
            )
        else:
            normalized["parameter_errors"].append(
                f"unsupported native_hook action: {action or request.action}"
            )

        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "plan",
            "target_identity": _target_payload(request.target),
            "process": process_probe,
            "process_identity": _process_identity(process_probe),
            "action": before_action,
            "hook_target_resolution": normalized.get("target_resolution"),
            "backend": _backend_info(backend, self.platform_name),
        }
        rollback_plan = self._initial_rollback_plan(action, pid, normalized)
        capability_plan = CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=_prune(normalized),
            steps=self._plan_steps(action),
            before_snapshot=_prune(before_snapshot),
            rollback_plan=_prune(rollback_plan),
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "provider_instance": self._instance_id,
                "backend": _backend_info(backend, self.platform_name),
                "requested_action": request.action,
                "action": action,
                "authorization_source": authorization_source,
                "target_identity": _target_payload(request.target),
                "process_identity": _process_identity(process_probe),
                "hook_target_resolution": normalized.get("target_resolution"),
                "hook_target_resolution_request": normalized.get(
                    "target_resolution_request"
                ),
                "native_win32": True,
                "frida": False,
            },
        )
        capability_plan.precondition_hash = _plan_precondition_hash(capability_plan)
        capability_plan.provenance["precondition_hash"] = capability_plan.precondition_hash
        capability_plan.rollback_plan["precondition_hash"] = capability_plan.precondition_hash
        self._issued_plans[capability_plan.precondition_hash] = _canonical_json(
            _plan_integrity_payload(capability_plan)
        )
        return capability_plan

    def _plan_vtable(
        self,
        backend: Any,
        pid: Optional[int],
        architecture: Optional[str],
        params: Mapping[str, Any],
        normalized: dict[str, Any],
    ) -> dict[str, Any]:
        errors = normalized["parameter_errors"]
        address = _coerce_int(_first_value(params, "slot_address", "address"))
        expected = _coerce_int(
            _first_value(
                params,
                "expected_original_pointer",
                "expected_original",
                "expected_pointer",
            )
        )
        replacement = _coerce_int(
            _first_value(params, "replacement_pointer", "replacement")
        )
        pointer_size = _POINTER_SIZES.get(architecture or "")
        normalized.update(
            {
                "slot_address": address,
                "expected_original_pointer": expected,
                "replacement_pointer": replacement,
                "pointer_size": pointer_size,
            }
        )
        if not address or address <= 0:
            errors.append("vtable_pointer requires a positive slot_address")
        if expected is None:
            errors.append("vtable_pointer requires expected_original_pointer")
        if replacement is None or replacement <= 0:
            errors.append("vtable_pointer requires a positive replacement_pointer")
        if pointer_size is None:
            errors.append("vtable_pointer requires an x86 or x64 target architecture")
        if pointer_size and expected is not None:
            try:
                _pointer_bytes(expected, pointer_size)
                _pointer_bytes(replacement or 0, pointer_size)
            except ValueError as exc:
                errors.append(str(exc))
        if not (_backend_available(backend) and pid and address and pointer_size):
            return {
                "status": "unavailable" if not _backend_available(backend) else "not_captured",
                "address": address,
                "size": pointer_size,
            }
        try:
            current = bytes(backend.read(pid, address, pointer_size))
            return {
                "status": "ok",
                "address": address,
                "size": pointer_size,
                "bytes_hex": current.hex(),
                "pointer": int.from_bytes(current, "little"),
                "matches_expected": expected is not None
                and current == _pointer_bytes(expected, pointer_size),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "failed",
                "address": address,
                "size": pointer_size,
                "error": _exception_payload(exc),
            }

    def _plan_inline(
        self,
        backend: Any,
        pid: Optional[int],
        architecture: Optional[str],
        params: Mapping[str, Any],
        normalized: dict[str, Any],
    ) -> dict[str, Any]:
        errors = normalized["parameter_errors"]
        address = _coerce_int(_first_value(params, "target_address", "address"))
        replacement = _coerce_int(
            _first_value(params, "replacement_pointer", "replacement_address", "replacement")
        )
        expected_value = _first_value(
            params, "expected_original_bytes", "expected_original_hex", "expected_original"
        )
        expected = _parse_bytes(expected_value)
        if expected_value is not None and expected is None:
            errors.append("expected_original_bytes must be a non-empty hexadecimal byte string")
        normalized.update(
            {
                "target_address": address,
                "replacement_pointer": replacement,
                "caller_expected_original_hex": expected.hex() if expected else None,
            }
        )
        if not address or address <= 0:
            errors.append("inline_trampoline requires a positive target_address")
        if not replacement or replacement <= 0:
            errors.append("inline_trampoline requires a positive replacement_pointer")
        if architecture not in _POINTER_SIZES:
            errors.append("inline_trampoline requires an x86 or x64 target architecture")
        if architecture and replacement:
            try:
                _pointer_bytes(replacement, _POINTER_SIZES[architecture])
                _jump_bytes(address or 0, replacement, architecture)
            except ValueError as exc:
                errors.append(str(exc))

        captured = expected or b""
        capture_error: Optional[dict[str, Any]] = None
        if _backend_available(backend) and pid and address:
            read_sizes = [len(expected)] if expected else [
                _MAX_INLINE_CAPTURE,
                48,
                32,
                24,
                16,
                _minimum_jump_size(architecture) if architecture in _POINTER_SIZES else 14,
            ]
            for size in dict.fromkeys(item for item in read_sizes if item > 0):
                try:
                    captured = bytes(backend.read(pid, address, size))
                    capture_error = None
                    break
                except Exception as exc:  # noqa: BLE001
                    capture_error = _exception_payload(exc)

        capstone_module, capstone_reason = _load_capstone(self._capstone_option)
        analysis = (
            _analyze_inline_instructions(captured, address or 0, architecture, capstone_module)
            if architecture in _POINTER_SIZES
            else {
                "status": "failed",
                "safe": False,
                "reason": "target architecture is unavailable",
            }
        )
        if capstone_reason and analysis.get("status") == "unavailable":
            analysis["reason"] = capstone_reason
        normalized["instruction_analysis"] = analysis
        if analysis.get("status") == "failed" and analysis.get("reason"):
            errors.append(str(analysis["reason"]))
        if expected and captured and captured != expected:
            errors.append(
                "inline target bytes do not match caller-provided expected original bytes"
            )
        selected_hex = analysis.get("original_hex")
        if selected_hex:
            normalized["expected_original_hex"] = selected_hex
            normalized["overwrite_size"] = analysis.get("overwrite_size")
            normalized["instruction_analysis"] = analysis
            if address and replacement and architecture:
                try:
                    jump = _jump_bytes(address, replacement, architecture)
                    overwrite_size = int(analysis["overwrite_size"])
                    normalized["patch_hex"] = (
                        jump + b"\x90" * (overwrite_size - len(jump))
                    ).hex()
                except (ValueError, TypeError) as exc:
                    errors.append(str(exc))
        return _prune(
            {
                "status": "failed"
                if capture_error
                else "unavailable"
                if not _backend_available(backend)
                else "ok",
                "address": address,
                "captured_hex": captured.hex() if captured else None,
                "caller_expected_hex": expected.hex() if expected else None,
                "matches_caller_expected": None
                if not expected or not captured
                else captured == expected,
                "analysis": analysis,
                "error": capture_error,
            }
        )

    def _plan_hardware_breakpoint(
        self,
        backend: Any,
        pid: Optional[int],
        params: Mapping[str, Any],
        normalized: dict[str, Any],
    ) -> dict[str, Any]:
        errors = normalized["parameter_errors"]
        thread_id = _coerce_int(_first_value(params, "thread_id", "tid"))
        address = _coerce_int(_first_value(params, "address", "target_address"))
        access = str(params.get("access") or "execute").strip().lower().replace("_", "")
        access = {"read/write": "readwrite", "read_write": "readwrite", "rw": "readwrite"}.get(
            access, access
        )
        size = _coerce_int(params.get("size"))
        duration_ms = _coerce_int(params.get("duration_ms"))
        max_events = _coerce_int(params.get("max_events"))
        slot_value = params.get("slot")
        slot = _coerce_int(slot_value) if slot_value is not None else None
        normalized.update(
            {
                "thread_id": thread_id,
                "address": address,
                "access": access,
                "size": size,
                "duration_ms": 250 if duration_ms is None else duration_ms,
                "max_events": 1000 if max_events is None else max_events,
                "slot": slot,
            }
        )
        if not thread_id or thread_id <= 0:
            errors.append("hardware_breakpoint requires a positive thread_id")
        if not address or address <= 0:
            errors.append("hardware_breakpoint requires a positive address")
        if access not in {"execute", "write", "readwrite"}:
            errors.append("hardware_breakpoint access must be execute, write, or readwrite")
        if size not in {1, 2, 4, 8}:
            errors.append("hardware_breakpoint size must be 1, 2, 4, or 8")
        if access == "execute" and size != 1:
            errors.append("execute hardware breakpoints require size 1")
        if normalized["duration_ms"] < 0 or normalized["duration_ms"] > _MAX_TRACE_MS:
            errors.append(f"duration_ms must be from 0 to {_MAX_TRACE_MS}")
        if normalized["max_events"] <= 0 or normalized["max_events"] > _MAX_TRACE_EVENTS:
            errors.append(f"max_events must be from 1 to {_MAX_TRACE_EVENTS}")
        if slot is not None and slot not in range(4):
            errors.append("hardware breakpoint slot must be DR0, DR1, DR2, or DR3")
        if not (_backend_available(backend) and pid and thread_id):
            return {
                "status": "unavailable" if not _backend_available(backend) else "not_probed",
                "thread_id": thread_id,
            }
        probe_method = getattr(backend, "probe_thread", None)
        if not callable(probe_method):
            return {
                "status": "unavailable",
                "thread_id": thread_id,
                "reason": "backend does not implement thread probing",
            }
        try:
            return _json_mapping(probe_method(pid, thread_id))
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "failed",
                "thread_id": thread_id,
                "error": _exception_payload(exc),
            }

    def _initial_rollback_plan(
        self, action: str, pid: Optional[int], parameters: Mapping[str, Any]
    ) -> dict[str, Any]:
        if action == "hardware_breakpoint":
            return {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "supported": True,
                "mode": "execute_cleanup",
                "pid": pid,
                "thread_id": parameters.get("thread_id"),
                "active": False,
                "completed": False,
                "restored": False,
                "cross_process_supported": False,
            }
        pointer_size = _coerce_int(parameters.get("pointer_size"))
        original_hex = parameters.get("expected_original_hex")
        patched_hex = parameters.get("patch_hex")
        if action == "vtable_pointer" and pointer_size:
            expected = _coerce_int(parameters.get("expected_original_pointer"))
            replacement = _coerce_int(parameters.get("replacement_pointer"))
            try:
                original_hex = _pointer_bytes(
                    expected, pointer_size  # type: ignore[arg-type]
                ).hex()
                patched_hex = _pointer_bytes(
                    replacement, pointer_size  # type: ignore[arg-type]
                ).hex()
            except (TypeError, ValueError):
                original_hex = None
                patched_hex = None
        return {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "supported": action in {"vtable_pointer", "inline_trampoline"},
            "mode": "restore_original_bytes",
            "pid": pid,
            "address": parameters.get("slot_address")
            if action == "vtable_pointer"
            else parameters.get("target_address"),
            "original_hex": original_hex,
            "patched_hex": patched_hex,
            "active": False,
            "completed": False,
            "restored": False,
        }

    @staticmethod
    def _plan_steps(action: str) -> list[dict[str, Any]]:
        if action == "vtable_pointer":
            labels = [
                "verify process identity and expected pointer",
                "make the vtable slot writable",
                "write and verify the replacement pointer",
                "restore page protection",
            ]
        elif action == "inline_trampoline":
            labels = [
                "verify process identity and Capstone instruction boundaries",
                "allocate and materialize the remote trampoline",
                "change target protection and install the jump",
                "flush instruction cache and verify both code regions",
            ]
        elif action == "hardware_breakpoint":
            labels = [
                "verify the target thread and debug-register parameters",
                "attach with the Windows Debug API and save thread context",
                "collect a bounded trace",
                "restore thread context and detach the debugger",
            ]
        else:
            labels = ["reject unsupported native hook action"]
        return [{"index": index + 1, "operation": label} for index, label in enumerate(labels)]

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        validation, _ = self._validate_plan(plan, context=context)
        return validation

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        current: dict[str, Any] = {}

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

        action = _normalize_action(plan.action)
        check(
            "capability_identity",
            plan.capability == self.capability_name and plan.provider == self.provider_name,
            "plan capability/provider identity does not match native_hook provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        check(
            "provider_instance",
            plan.provenance.get("provider_instance") == self._instance_id,
            "native hook plan was not issued by this provider instance",
            expected=self._instance_id,
            actual=plan.provenance.get("provider_instance"),
        )
        check(
            "session_id",
            bool(str(plan.session_id or "").strip()) and len(str(plan.session_id)) <= 256,
            "native hook session_id must be a non-empty string of at most 256 characters",
        )
        check(
            "supported_action",
            action in _SUPPORTED_ACTIONS and action == plan.action,
            f"unsupported or non-canonical native_hook action: {plan.action}",
        )
        check(
            "explicit_authorization",
            plan.parameters.get("authorized") is True,
            "native hook execution requires explicit authorized=True consent",
            authorization_source=plan.parameters.get("authorization_source"),
        )
        pid = _coerce_int(plan.parameters.get("pid"))
        target_pid = _coerce_int(plan.target.pid)
        check(
            "target_pid",
            bool(pid and pid > 0 and not plan.parameters.get("pid_conflict"))
            and (target_pid is None or target_pid == pid),
            "target PID must be positive, unambiguous, and match target identity",
            pid=pid,
            target_pid=target_pid,
        )
        parameter_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        check(
            "parameters",
            not parameter_errors,
            "; ".join(parameter_errors) if parameter_errors else "parameters are valid",
            errors=parameter_errors,
        )
        expected_hash = _plan_precondition_hash(plan)
        check(
            "plan_integrity",
            bool(plan.precondition_hash) and plan.precondition_hash == expected_hash,
            "native hook plan precondition hash does not match its immutable inputs",
            expected=expected_hash,
            actual=plan.precondition_hash,
        )
        check(
            "issued_plan",
            bool(plan.precondition_hash)
            and self._issued_plans.get(str(plan.precondition_hash))
            == _canonical_json(_plan_integrity_payload(plan)),
            "native hook plan identity was not issued by this provider instance",
        )

        if (
            plan.parameters.get("target_resolution_request") is not None
            or plan.parameters.get("target_resolution") is not None
        ):
            try:
                live_resolution = _resolve_planned_hook_target(plan)
                current["hook_target_resolution"] = live_resolution
                resolved_address = _coerce_int(live_resolution.get("address"))
                resolved_slot = _coerce_int(live_resolution.get("slot_address"))
                if action == "vtable_pointer":
                    binding_ok = (
                        resolved_slot == _coerce_int(plan.parameters.get("slot_address"))
                        and resolved_address
                        == _coerce_int(
                            plan.parameters.get("expected_original_pointer")
                        )
                    )
                elif action == "inline_trampoline":
                    binding_ok = resolved_address == _coerce_int(
                        plan.parameters.get("target_address")
                    )
                else:
                    binding_ok = resolved_address == _coerce_int(
                        plan.parameters.get("address")
                    )
                check(
                    "hook_target_resolution",
                    bool(binding_ok),
                    "hook target resolution remains reproducible and bound to the plan"
                    if binding_ok
                    else "resolved hook target is not bound to the planned address",
                    resolution=live_resolution,
                )
            except (HookTargetResolutionError, OSError, TypeError, ValueError) as exc:
                check(
                    "hook_target_resolution",
                    False,
                    f"hook target resolution validation failed: {exc}",
                )

        backend_info = _backend_info(backend, self.platform_name)
        if not _backend_available(backend):
            reason = _backend_reason(backend)
            checks.append(
                {
                    "name": "windows_backend",
                    "status": "unavailable",
                    "message": reason,
                    **backend_info,
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
                    warnings=list(dict.fromkeys(warnings)),
                    errors=list(dict.fromkeys(errors)),
                ),
                current,
            )
        checks.append(
            {
                "name": "windows_backend",
                "status": "ok",
                "message": "Windows native hook backend is available",
                **backend_info,
            }
        )

        if pid and pid > 0 and not errors:
            process = self._probe_process(backend, pid)
            current["process"] = process
            process_ok = process.get("status") == "ok" and process.get("accessible") is not False
            check(
                "process_access",
                process_ok,
                "target process is not accessible through the native backend",
                process=process,
            )
            planned_process = plan.before_snapshot.get("process") or {}
            identity_ok = process_ok and _process_identity_matches(planned_process, process)
            check(
                "process_identity",
                identity_ok,
                "target process identity changed after planning",
                planned=_process_identity(planned_process),
                current=_process_identity(process),
            )

        if not errors and pid:
            if action == "vtable_pointer":
                self._validate_vtable(plan, backend, pid, checks, errors, current)
            elif action == "inline_trampoline":
                self._validate_inline(plan, backend, pid, checks, warnings, errors, current)
            elif action == "hardware_breakpoint":
                self._validate_hardware(plan, backend, pid, checks, warnings, errors, current)

        return (
            CapabilityValidation(
                capability=plan.capability,
                provider=plan.provider,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=list(dict.fromkeys(warnings)),
                errors=list(dict.fromkeys(errors)),
            ),
            _prune(current),
        )

    def _validate_vtable(
        self,
        plan: CapabilityPlan,
        backend: Any,
        pid: int,
        checks: list[dict[str, Any]],
        errors: list[str],
        current: dict[str, Any],
    ) -> None:
        address = _coerce_int(plan.parameters.get("slot_address"))
        pointer_size = _coerce_int(plan.parameters.get("pointer_size"))
        expected = _coerce_int(plan.parameters.get("expected_original_pointer"))
        replacement = _coerce_int(plan.parameters.get("replacement_pointer"))
        try:
            expected_bytes = _pointer_bytes(expected, pointer_size)  # type: ignore[arg-type]
            replacement_bytes = _pointer_bytes(replacement, pointer_size)  # type: ignore[arg-type]
            live = bytes(backend.read(pid, address, pointer_size))  # type: ignore[arg-type]
            current["memory"] = {
                "address": address,
                "size": pointer_size,
                "bytes_hex": live.hex(),
                "pointer": int.from_bytes(live, "little"),
            }
            planned_hex = str((plan.before_snapshot.get("action") or {}).get("bytes_hex") or "")
            ok = live == expected_bytes and (not planned_hex or live.hex() == planned_hex)
            checks.append(
                {
                    "name": "vtable_preimage",
                    "status": "ok" if ok else "failed",
                    "message": "vtable slot matches the explicit expected original pointer"
                    if ok
                    else "vtable slot no longer matches the expected original pointer",
                    "expected_hex": expected_bytes.hex(),
                    "actual_hex": live.hex(),
                    "replacement_hex": replacement_bytes.hex(),
                }
            )
            if not ok:
                errors.append("vtable slot no longer matches the expected original pointer")
        except Exception as exc:  # noqa: BLE001
            message = f"vtable pointer validation failed: {exc}"
            checks.append(
                {
                    "name": "vtable_preimage",
                    "status": "failed",
                    "message": message,
                    "error": _exception_payload(exc),
                }
            )
            errors.append(message)

    def _validate_inline(
        self,
        plan: CapabilityPlan,
        backend: Any,
        pid: int,
        checks: list[dict[str, Any]],
        warnings: list[str],
        errors: list[str],
        current: dict[str, Any],
    ) -> None:
        architecture = _normalize_architecture(plan.parameters.get("architecture"))
        address = _coerce_int(plan.parameters.get("target_address"))
        replacement = _coerce_int(plan.parameters.get("replacement_pointer"))
        expected = _parse_bytes(plan.parameters.get("expected_original_hex"))
        capstone_module, capstone_reason = _load_capstone(self._capstone_option)
        if capstone_module is None:
            reason = capstone_reason or "Capstone disassembler is unavailable"
            checks.append(
                {"name": "capstone", "status": "unavailable", "message": reason}
            )
            warnings.append(reason)
            return
        try:
            if (
                architecture not in _POINTER_SIZES
                or not address
                or not replacement
                or not expected
            ):
                raise ValueError(
                    "inline trampoline plan is missing architecture, address, "
                    "replacement, or original bytes"
                )
            analysis = _analyze_inline_instructions(
                expected, address, architecture, capstone_module
            )
            analysis_ok = bool(
                analysis.get("safe")
                and analysis.get("status") == "ok"
                and analysis.get("original_hex") == expected.hex()
                and _coerce_int(analysis.get("overwrite_size")) == len(expected)
            )
            checks.append(
                {
                    "name": "capstone_instruction_boundaries",
                    "status": "ok" if analysis_ok else "failed",
                    "message": "Capstone verified complete position-independent instructions"
                    if analysis_ok
                    else str(analysis.get("reason") or "inline instruction analysis changed"),
                    "analysis": analysis,
                }
            )
            if not analysis_ok:
                errors.append(
                    str(analysis.get("reason") or "inline instruction analysis is unsafe")
                )
                return
            jump = _jump_bytes(address, replacement, architecture)
            expected_patch = (jump + b"\x90" * (len(expected) - len(jump))).hex()
            patch_ok = expected_patch == str(plan.parameters.get("patch_hex") or "")
            checks.append(
                {
                    "name": "inline_patch_encoding",
                    "status": "ok" if patch_ok else "failed",
                    "message": "inline jump encoding matches the planned bytes"
                    if patch_ok
                    else "inline jump encoding changed after planning",
                    "expected_hex": expected_patch,
                    "planned_hex": plan.parameters.get("patch_hex"),
                }
            )
            if not patch_ok:
                errors.append("inline jump encoding changed after planning")
                return
            live = bytes(backend.read(pid, address, len(expected)))
            current["memory"] = {
                "address": address,
                "size": len(expected),
                "bytes_hex": live.hex(),
            }
            preimage_ok = live == expected
            checks.append(
                {
                    "name": "inline_preimage",
                    "status": "ok" if preimage_ok else "failed",
                    "message": "inline target bytes match the planned prologue"
                    if preimage_ok
                    else "inline target bytes changed after planning",
                    "expected_hex": expected.hex(),
                    "actual_hex": live.hex(),
                }
            )
            if not preimage_ok:
                errors.append("inline target bytes changed after planning")
        except Exception as exc:  # noqa: BLE001
            message = f"inline trampoline validation failed: {exc}"
            checks.append(
                {
                    "name": "inline_validation",
                    "status": "failed",
                    "message": message,
                    "error": _exception_payload(exc),
                }
            )
            errors.append(message)

    def _validate_hardware(
        self,
        plan: CapabilityPlan,
        backend: Any,
        pid: int,
        checks: list[dict[str, Any]],
        warnings: list[str],
        errors: list[str],
        current: dict[str, Any],
    ) -> None:
        thread_id = _coerce_int(plan.parameters.get("thread_id"))
        trace_method = getattr(backend, "trace_hardware_breakpoint", None)
        if not callable(trace_method):
            reason = "backend does not implement Windows Debug API hardware-breakpoint tracing"
            checks.append(
                {"name": "hardware_breakpoint_api", "status": "unavailable", "message": reason}
            )
            warnings.append(reason)
            return
        probe_method = getattr(backend, "probe_thread", None)
        if not callable(probe_method) or not thread_id:
            errors.append("hardware breakpoint backend cannot verify the target thread")
            checks.append(
                {
                    "name": "thread_context",
                    "status": "failed",
                    "message": errors[-1],
                }
            )
            return
        try:
            probe = _json_mapping(probe_method(pid, thread_id))
            current["thread"] = probe
            accessible = probe.get("status") == "ok" and probe.get("accessible") is not False
            checks.append(
                {
                    "name": "thread_context",
                    "status": "ok" if accessible else "failed",
                    "message": "target thread context is accessible"
                    if accessible
                    else "target thread context is not accessible",
                    "probe": probe,
                }
            )
            if not accessible:
                errors.append("target thread context is not accessible")
            supported = probe.get("hardware_breakpoint_supported")
            if supported is False:
                reason = str(
                    probe.get("reason")
                    or "hardware breakpoint context is unavailable for this target"
                )
                checks.append(
                    {
                        "name": "hardware_breakpoint_context",
                        "status": "unavailable",
                        "message": reason,
                    }
                )
                warnings.append(reason)
            else:
                checks.append(
                    {
                        "name": "hardware_breakpoint_context",
                        "status": "ok",
                        "message": "backend reports a supported hardware-breakpoint context",
                    }
                )
        except Exception as exc:  # noqa: BLE001
            message = f"thread context probe failed: {exc}"
            checks.append(
                {
                    "name": "thread_context",
                    "status": "failed",
                    "message": message,
                    "error": _exception_payload(exc),
                }
            )
            errors.append(message)

    def _probe_process(self, backend: Any, pid: Optional[int]) -> dict[str, Any]:
        if not pid or pid <= 0:
            return {"status": "failed", "accessible": False, "pid": pid, "reason": "invalid PID"}
        if not _backend_available(backend):
            return {
                "status": "unavailable",
                "accessible": None,
                "pid": pid,
                "reason": _backend_reason(backend),
            }
        probe = getattr(backend, "probe_process", None)
        if not callable(probe):
            return {
                "status": "unavailable",
                "accessible": None,
                "pid": pid,
                "reason": "backend does not implement process probing",
            }
        try:
            return _json_mapping(probe(pid))
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "failed",
                "accessible": False,
                "pid": pid,
                "error": _exception_payload(exc),
            }

    def _select_backend(self, context: Optional[dict[str, Any]]) -> NativeHookBackend:
        if isinstance(context, Mapping) and context.get("native_hook_backend") is not None:
            return context["native_hook_backend"]
        return self.backend

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        validation, current = self._validate_plan(plan, context=context)
        before_snapshot = _execution_before_snapshot(plan, validation, current)

        if not validation.ok:
            errors = list(validation.errors) or ["native hook validation failed"]
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="blocked",
                reason="execution was blocked by plan validation",
            )
            return self._build_execution_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                action_snapshot={"status": "blocked", "errors": errors},
                rollback_plan=rollback_plan,
                errors=errors,
                operations=[],
                events=[],
            )

        unavailable = _validation_unavailable_reason(validation)
        if unavailable:
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="unavailable",
                reason=unavailable,
            )
            return self._build_execution_result(
                plan,
                validation=validation,
                status="unavailable",
                before_snapshot=before_snapshot,
                action_snapshot={"status": "unavailable", "reason": unavailable},
                rollback_plan=rollback_plan,
                errors=[unavailable],
                operations=[],
                events=[],
            )

        try:
            if plan.action == "vtable_pointer":
                outcome = self._execute_vtable(plan, backend)
            elif plan.action == "inline_trampoline":
                outcome = self._execute_inline(plan, backend)
            elif plan.action == "hardware_breakpoint":
                outcome = self._execute_hardware_breakpoint(plan, backend)
            else:
                raise ValueError(f"unsupported native hook action: {plan.action}")
        except Exception as exc:  # noqa: BLE001 - provider boundary
            error = _exception_payload(exc)
            outcome = {
                "status": "failed",
                "action_snapshot": {"status": "failed", "error": error},
                "rollback_plan": _inactive_rollback_plan(
                    plan.rollback_plan,
                    status="failed",
                    reason="execution failed before native state could be established",
                ),
                "errors": [error],
                "operations": [],
                "events": [],
            }

        return self._build_execution_result(
            plan,
            validation=validation,
            status=str(outcome.get("status") or "failed"),
            before_snapshot=before_snapshot,
            action_snapshot=_json_mapping(outcome.get("action_snapshot")),
            rollback_plan=_json_mapping(outcome.get("rollback_plan")),
            errors=list(outcome.get("errors") or []),
            operations=list(outcome.get("operations") or []),
            events=list(outcome.get("events") or []),
        )

    def _execute_vtable(self, plan: CapabilityPlan, backend: Any) -> dict[str, Any]:
        pid = int(plan.parameters["pid"])
        address = int(plan.parameters["slot_address"])
        pointer_size = int(plan.parameters["pointer_size"])
        original = _pointer_bytes(
            int(plan.parameters["expected_original_pointer"]), pointer_size
        )
        patched = _pointer_bytes(
            int(plan.parameters["replacement_pointer"]), pointer_size
        )
        operations: list[dict[str, Any]] = []
        errors: list[Any] = []
        write_attempted = False
        protection_changed = False
        protection_restored = True
        old_protection: Optional[int] = None

        try:
            live = bytes(backend.read(pid, address, pointer_size))
            operations.append(_memory_observation("read_preimage", address, live))
            if live != original:
                raise RuntimeError("vtable preimage changed immediately before execution")

            protected = _checked_operation(
                backend.protect(pid, address, pointer_size, _PAGE_READWRITE),
                operation="VirtualProtectEx(vtable,writable)",
            )
            operations.append(protected)
            old_protection = _coerce_int(protected.get("old_protection"))
            if old_protection is None:
                raise RuntimeError("VirtualProtectEx did not report the original protection")
            protection_changed = True
            protection_restored = False

            locked_live = bytes(backend.read(pid, address, pointer_size))
            operations.append(
                _memory_observation("read_locked_preimage", address, locked_live)
            )
            if locked_live != original:
                raise RuntimeError("vtable preimage changed after page protection update")

            write_attempted = True
            written = _checked_operation(
                backend.write(pid, address, patched),
                operation="WriteProcessMemory(vtable)",
            )
            operations.append(written)
            verified = bytes(backend.read(pid, address, pointer_size))
            operations.append(_memory_observation("verify_vtable_write", address, verified))
            if verified != patched:
                raise RuntimeError("vtable write verification failed")

            restored_protection = _checked_operation(
                backend.protect(pid, address, pointer_size, old_protection),
                operation="VirtualProtectEx(vtable,restore)",
            )
            operations.append(restored_protection)
            protection_changed = False
            protection_restored = True
        except Exception as exc:  # noqa: BLE001 - compensated below
            errors.append(_exception_payload(exc))
        finally:
            if protection_changed and old_protection is not None:
                try:
                    restored_protection = _checked_operation(
                        backend.protect(pid, address, pointer_size, old_protection),
                        operation="VirtualProtectEx(vtable,finally_restore)",
                    )
                    operations.append(restored_protection)
                    protection_changed = False
                    protection_restored = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))

        live_after = _safe_read(backend, pid, address, pointer_size)
        if errors and write_attempted and (
            live_after != original or not protection_restored
        ):
            compensation = _restore_memory_region(
                backend,
                pid=pid,
                address=address,
                original=original,
                expected_current=patched,
                executable=False,
                final_protection=old_protection,
                allow_unknown_current=True,
            )
            operations.extend(compensation["operations"])
            errors.extend(compensation["errors"])
            protection_restored = bool(compensation["protection_restored"])
            live_after = _safe_read(backend, pid, address, pointer_size)

        state_original = live_after == original
        state_patched = live_after == patched
        rollback_plan = _json_mapping(plan.rollback_plan)
        rollback_plan.update(
            {
                "pid": pid,
                "address": address,
                "size": pointer_size,
                "original_hex": original.hex(),
                "patched_hex": patched.hex(),
                "old_protection": old_protection,
                "provider_instance": self._instance_id,
                "active": bool(state_patched or not state_original),
                "completed": bool(state_original and errors and protection_restored),
                "restored": bool(state_original and errors and write_attempted),
                "status": (
                    "ready"
                    if state_patched
                    else "compensated"
                    if errors and state_original and protection_restored
                    else "failed"
                    if errors
                    else "ready"
                ),
                "idempotent": True,
                "cross_process_supported": False,
            }
        )
        status = "ok" if not errors and state_patched and protection_restored else "failed"
        if status == "ok":
            rollback_plan.update(
                {"active": True, "completed": False, "restored": False, "status": "ready"}
            )
        return {
            "status": status,
            "action_snapshot": {
                "status": status,
                "kind": "vtable_pointer",
                "address": address,
                "size": pointer_size,
                "before_hex": original.hex(),
                "after_hex": live_after.hex() if live_after is not None else None,
                "expected_after_hex": patched.hex(),
                "write_verified": live_after == patched,
                "protection_restored": protection_restored,
            },
            "rollback_plan": rollback_plan,
            "errors": errors,
            "operations": operations,
            "events": [],
        }

    def _execute_inline(self, plan: CapabilityPlan, backend: Any) -> dict[str, Any]:
        pid = int(plan.parameters["pid"])
        architecture = str(plan.parameters["architecture"])
        target_address = int(plan.parameters["target_address"])
        original = bytes.fromhex(str(plan.parameters["expected_original_hex"]))
        patch = bytes.fromhex(str(plan.parameters["patch_hex"]))
        operations: list[dict[str, Any]] = []
        errors: list[Any] = []
        allocation_address: Optional[int] = None
        allocation_size = len(original) + _minimum_jump_size(architecture)
        allocation_released = False
        target_write_attempted = False
        target_protection_changed = False
        target_protection_restored = True
        old_target_protection: Optional[int] = None
        trampoline = b""

        try:
            live = bytes(backend.read(pid, target_address, len(original)))
            operations.append(_memory_observation("read_inline_preimage", target_address, live))
            if live != original:
                raise RuntimeError("inline target changed immediately before execution")

            allocation = _checked_operation(
                backend.alloc(
                    pid,
                    allocation_size,
                    _PAGE_READWRITE,
                    near=target_address,
                ),
                operation="VirtualAllocEx(trampoline)",
            )
            operations.append(allocation)
            allocation_address = _coerce_int(allocation.get("address"))
            if not allocation_address or allocation_address <= 0:
                raise RuntimeError("VirtualAllocEx did not return a trampoline address")

            jump_back = _jump_bytes(
                allocation_address + len(original),
                target_address + len(original),
                architecture,
            )
            trampoline = original + jump_back
            if len(trampoline) > allocation_size:
                raise RuntimeError("trampoline encoding exceeds the remote allocation")

            trampoline_write = _checked_operation(
                backend.write(pid, allocation_address, trampoline),
                operation="WriteProcessMemory(trampoline)",
            )
            operations.append(trampoline_write)
            trampoline_live = bytes(
                backend.read(pid, allocation_address, len(trampoline))
            )
            operations.append(
                _memory_observation(
                    "verify_trampoline_write", allocation_address, trampoline_live
                )
            )
            if trampoline_live != trampoline:
                raise RuntimeError("trampoline write verification failed")

            trampoline_protect = _checked_operation(
                backend.protect(
                    pid,
                    allocation_address,
                    allocation_size,
                    _PAGE_EXECUTE_READ,
                ),
                operation="VirtualProtectEx(trampoline,executable)",
            )
            operations.append(trampoline_protect)
            trampoline_flush = _checked_operation(
                backend.flush_instruction_cache(
                    pid, allocation_address, len(trampoline)
                ),
                operation="FlushInstructionCache(trampoline)",
            )
            operations.append(trampoline_flush)
            trampoline_verified = bytes(
                backend.read(pid, allocation_address, len(trampoline))
            )
            if trampoline_verified != trampoline:
                raise RuntimeError("trampoline changed after protection or cache flush")

            target_protect = _checked_operation(
                backend.protect(
                    pid,
                    target_address,
                    len(original),
                    _PAGE_EXECUTE_READWRITE,
                ),
                operation="VirtualProtectEx(inline,writable)",
            )
            operations.append(target_protect)
            old_target_protection = _coerce_int(target_protect.get("old_protection"))
            if old_target_protection is None:
                raise RuntimeError("VirtualProtectEx did not report target protection")
            target_protection_changed = True
            target_protection_restored = False

            locked_live = bytes(backend.read(pid, target_address, len(original)))
            operations.append(
                _memory_observation(
                    "read_locked_inline_preimage", target_address, locked_live
                )
            )
            if locked_live != original:
                raise RuntimeError("inline target changed after page protection update")

            target_write_attempted = True
            target_write = _checked_operation(
                backend.write(pid, target_address, patch),
                operation="WriteProcessMemory(inline_target)",
            )
            operations.append(target_write)
            target_verified = bytes(backend.read(pid, target_address, len(patch)))
            operations.append(
                _memory_observation("verify_inline_write", target_address, target_verified)
            )
            if target_verified != patch:
                raise RuntimeError("inline target write verification failed")
            target_flush = _checked_operation(
                backend.flush_instruction_cache(pid, target_address, len(patch)),
                operation="FlushInstructionCache(inline_target)",
            )
            operations.append(target_flush)

            target_restore = _checked_operation(
                backend.protect(
                    pid,
                    target_address,
                    len(original),
                    old_target_protection,
                ),
                operation="VirtualProtectEx(inline,restore)",
            )
            operations.append(target_restore)
            target_protection_changed = False
            target_protection_restored = True
        except Exception as exc:  # noqa: BLE001 - compensated below
            errors.append(_exception_payload(exc))
        finally:
            if target_protection_changed and old_target_protection is not None:
                try:
                    target_restore = _checked_operation(
                        backend.protect(
                            pid,
                            target_address,
                            len(original),
                            old_target_protection,
                        ),
                        operation="VirtualProtectEx(inline,finally_restore)",
                    )
                    operations.append(target_restore)
                    target_protection_changed = False
                    target_protection_restored = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))

        target_live = _safe_read(backend, pid, target_address, len(original))
        if errors and target_write_attempted and (
            target_live != original or not target_protection_restored
        ):
            compensation = _restore_memory_region(
                backend,
                pid=pid,
                address=target_address,
                original=original,
                expected_current=patch,
                executable=True,
                final_protection=old_target_protection,
                allow_unknown_current=True,
            )
            operations.extend(compensation["operations"])
            errors.extend(compensation["errors"])
            target_protection_restored = bool(compensation["protection_restored"])
            target_live = _safe_read(backend, pid, target_address, len(original))

        target_original = target_live == original
        target_patched = target_live == patch
        if errors and allocation_address and target_original and target_protection_restored:
            try:
                released = _checked_operation(
                    backend.free(pid, allocation_address),
                    operation="VirtualFreeEx(trampoline_compensation)",
                )
                operations.append(released)
                allocation_released = bool(released.get("released", True))
                if not allocation_released:
                    raise RuntimeError("trampoline allocation release was not confirmed")
            except Exception as exc:  # noqa: BLE001
                errors.append(_exception_payload(exc))

        rollback_plan = _json_mapping(plan.rollback_plan)
        allocation_active = bool(allocation_address and not allocation_released)
        residual_state = not target_original or allocation_active
        rollback_plan.update(
            {
                "pid": pid,
                "address": target_address,
                "size": len(original),
                "original_hex": original.hex(),
                "patched_hex": patch.hex(),
                "old_protection": old_target_protection,
                "trampoline_address": allocation_address,
                "trampoline_size": allocation_size,
                "trampoline_hex": trampoline.hex() if trampoline else None,
                "allocation_active": allocation_active,
                "allocation_released": allocation_released,
                "provider_instance": self._instance_id,
                "active": residual_state,
                "completed": bool(errors and not residual_state and target_protection_restored),
                "restored": bool(errors and target_original and target_write_attempted),
                "status": (
                    "ready"
                    if target_patched or allocation_active
                    else "compensated"
                    if errors and target_original and target_protection_restored
                    else "failed"
                    if errors
                    else "ready"
                ),
                "idempotent": True,
                "cross_process_supported": False,
            }
        )
        status = (
            "ok"
            if not errors
            and target_patched
            and target_protection_restored
            and allocation_active
            else "failed"
        )
        if status == "ok":
            rollback_plan.update(
                {"active": True, "completed": False, "restored": False, "status": "ready"}
            )
        return {
            "status": status,
            "action_snapshot": {
                "status": status,
                "kind": "inline_trampoline",
                "architecture": architecture,
                "target_address": target_address,
                "overwrite_size": len(original),
                "before_hex": original.hex(),
                "after_hex": target_live.hex() if target_live is not None else None,
                "expected_after_hex": patch.hex(),
                "write_verified": target_live == patch,
                "protection_restored": target_protection_restored,
                "trampoline": {
                    "address": allocation_address,
                    "size": allocation_size,
                    "used_size": len(trampoline),
                    "bytes_hex": trampoline.hex() if trampoline else None,
                    "verified": bool(trampoline and allocation_active),
                    "allocation_active": allocation_active,
                },
            },
            "rollback_plan": rollback_plan,
            "errors": errors,
            "operations": operations,
            "events": [],
        }

    def _execute_hardware_breakpoint(
        self, plan: CapabilityPlan, backend: Any
    ) -> dict[str, Any]:
        parameters = plan.parameters
        operations: list[dict[str, Any]] = []
        errors: list[Any] = []
        try:
            raw_trace = backend.trace_hardware_breakpoint(
                int(parameters["pid"]),
                int(parameters["thread_id"]),
                int(parameters["address"]),
                str(parameters["access"]),
                int(parameters["size"]),
                int(parameters["duration_ms"]),
                int(parameters["max_events"]),
                slot=_coerce_int(parameters.get("slot")),
            )
            trace = _json_mapping(raw_trace)
        except Exception as exc:  # noqa: BLE001
            trace = {"status": "failed", "errors": [_exception_payload(exc)]}

        operations.append({"operation": "hardware_breakpoint_trace", **trace})
        raw_events = trace.get("events")
        events = (
            [
                _json_mapping(item)
                for item in raw_events
                if isinstance(item, Mapping)
            ]
            if isinstance(raw_events, Sequence)
            and not isinstance(raw_events, (str, bytes, bytearray))
            else []
        )
        status_value = str(trace.get("status") or "failed").lower()
        cleanup_complete = (
            trace.get("restored") is True and trace.get("debug_detached") is True
        )
        success = (
            status_value == "ok"
            and trace.get("installed") is True
            and cleanup_complete
            and trace.get("bounded") is True
            and len(events) <= int(parameters["max_events"])
        )
        if status_value == "unavailable":
            status = "unavailable"
            reason = str(trace.get("reason") or "hardware breakpoint tracing is unavailable")
            errors.append(reason)
        elif success:
            status = "ok"
        else:
            status = "failed"
            errors.extend(list(trace.get("errors") or []))
            errors.append(
                "hardware breakpoint trace did not prove installation, bounded capture, "
                "context restoration, and debugger detach"
            )

        rollback_plan = _json_mapping(plan.rollback_plan)
        rollback_plan.update(
            {
                "provider_instance": self._instance_id,
                "status": (
                    "completed"
                    if success
                    else "not_required"
                    if status == "unavailable" and not trace.get("installed")
                    else "cleanup_failed"
                ),
                "active": bool(trace.get("installed") and not cleanup_complete),
                "completed": bool(
                    success or (status == "unavailable" and not trace.get("installed"))
                ),
                "restored": bool(trace.get("restored")),
                "debug_detached": bool(trace.get("debug_detached")),
                "installed": bool(trace.get("installed")),
                "slot": trace.get("slot"),
                "idempotent": True,
                "cross_process_supported": False,
                "cleanup": {
                    "restored": bool(trace.get("restored")),
                    "debug_detached": bool(trace.get("debug_detached")),
                    "errors": list(trace.get("errors") or []),
                },
            }
        )
        return {
            "status": status,
            "action_snapshot": {
                "status": status,
                "kind": "hardware_breakpoint",
                "thread_id": parameters.get("thread_id"),
                "address": parameters.get("address"),
                "access": parameters.get("access"),
                "size": parameters.get("size"),
                "duration_ms": trace.get("duration_ms"),
                "event_count": len(events),
                "events": events,
                "trace": trace,
                "cleanup_complete": cleanup_complete,
            },
            "rollback_plan": rollback_plan,
            "errors": errors,
            "operations": operations,
            "events": events,
        }

    def _build_execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before_snapshot: Mapping[str, Any],
        action_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        errors: Sequence[Any],
        operations: Sequence[Any],
        events: Sequence[Any],
    ) -> CapabilityExecutionResult:
        completed_at = _utc_now()
        lifecycle_events = [
            {
                "kind": "plan",
                "ts": completed_at,
                "message": "native hook plan created",
                "action": plan.action,
            },
            {
                "kind": "validate",
                "ts": completed_at,
                "message": "native hook plan validated",
                "ok": validation.ok,
                "warning_count": len(validation.warnings),
                "error_count": len(validation.errors),
            },
            {
                "kind": "execute",
                "ts": completed_at,
                "message": "native hook execution completed",
                "status": status,
            },
        ]
        target_resolution = plan.parameters.get("target_resolution")
        artifact_specs = _session_artifact_specs(
            plan.session_id,
            include_target_resolution=isinstance(target_resolution, Mapping),
        )
        artifacts = [
            CapabilityArtifact(
                path=spec["path"],
                kind=spec["kind"],
                description=spec["description"],
                metadata={"materialized": False, "session_id": plan.session_id},
            )
            for spec in artifact_specs
        ]
        evidence_entries = [
            _artifact_manifest_entry(item, status=status) for item in artifacts
        ]
        normalized_errors = [_json_value(item) for item in errors]
        normalized_operations = [_json_value(item) for item in operations]
        normalized_trace_events = [_json_value(item) for item in events]
        after_snapshot = _prune(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "execute",
                "captured_at": completed_at,
                "target_identity": _target_payload(plan.target),
                "process_identity": plan.provenance.get("process_identity"),
                "status": status,
                "action": _json_mapping(action_snapshot),
                "operations": normalized_operations,
                "errors": normalized_errors,
                "trace_events": normalized_trace_events,
                "trace_event_count": len(normalized_trace_events),
            }
        )
        final_rollback_plan = _json_mapping(rollback_plan)
        final_rollback_plan.setdefault("supported", False)
        final_rollback_plan.setdefault("precondition_hash", plan.precondition_hash)
        report_section = _prune(
            {
                "capability": self.capability_name,
                "provider": self.provider_name,
                "action": plan.action,
                "status": status,
                "session_id": plan.session_id,
                "target_identity": _target_payload(plan.target),
                "native_win32": True,
                "frida": False,
                "rollback_supported": bool(final_rollback_plan.get("supported")),
                "rollback_status": final_rollback_plan.get("status"),
                "operation_count": len(normalized_operations),
                "trace_event_count": len(normalized_trace_events),
                "hook_target_resolution": _json_mapping(target_resolution),
                "errors": normalized_errors,
            }
        )
        dashboard_trace = [
            _prune(
                {
                    "kind": "native_hook_execution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "action": plan.action,
                    "status": status,
                    "session_id": plan.session_id,
                    "pid": plan.parameters.get("pid"),
                    "operation_count": len(normalized_operations),
                    "trace_event_count": len(normalized_trace_events),
                    "rollback_status": final_rollback_plan.get("status"),
                    "hook_target": _json_mapping(target_resolution),
                }
            )
        ]
        result = CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_json_mapping(before_snapshot),
            after_snapshot=after_snapshot,
            rollback_plan=final_rollback_plan,
            artifacts=artifacts,
            evidence_manifest_entries=evidence_entries,
            report_section=report_section,
            dashboard_trace=dashboard_trace,
            provenance=_prune(
                {
                    **_json_mapping(plan.provenance),
                    "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                    "provider_instance": self._instance_id,
                    "precondition_hash": plan.precondition_hash,
                    "target_identity": _target_payload(plan.target),
                    "plan": plan.to_dict(),
                    "validation": validation.to_dict(),
                    "lifecycle_events": lifecycle_events,
                    "native_win32": True,
                    "frida": False,
                }
            ),
        )
        self._issue_result_identity(result)
        return result

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        self._require_owned_result(result)
        backend = self._select_backend(context)
        rollback_plan = _json_mapping(result.rollback_plan)

        if result.action == "hardware_breakpoint":
            complete = (
                rollback_plan.get("completed") is True
                and rollback_plan.get("restored") is True
                and rollback_plan.get("debug_detached") is True
                and rollback_plan.get("active") is not True
            )
            if complete:
                return CapabilityRollbackResult(
                    capability=self.capability_name,
                    provider=self.provider_name,
                    session_id=result.session_id,
                    ok=True,
                    restored=True,
                    details={
                        "status": "already_completed",
                        "mode": "execute_cleanup",
                        "cleanup": _json_mapping(rollback_plan.get("cleanup")),
                    },
                )
            if rollback_plan.get("active") is not True:
                return CapabilityRollbackResult(
                    capability=self.capability_name,
                    provider=self.provider_name,
                    session_id=result.session_id,
                    ok=True,
                    restored=False,
                    details={
                        "status": "not_required",
                        "reason": "no installed hardware breakpoint remains",
                    },
                )
            return self._record_rollback_result(
                result,
                ok=False,
                restored=False,
                status="failed",
                details={
                    "mode": "execute_cleanup",
                    "error": (
                        "hardware-breakpoint cleanup was not proven during execution; "
                        "the backend exposes no reliable out-of-band context recovery"
                    ),
                },
            )

        if result.action not in {"vtable_pointer", "inline_trampoline"}:
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details={"status": "failed", "error": "unsupported rollback action"},
            )

        if (
            rollback_plan.get("completed") is True
            and rollback_plan.get("restored") is True
            and rollback_plan.get("active") is not True
        ):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=True,
                details={"status": "already_completed"},
            )
        if rollback_plan.get("active") is not True:
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=bool(rollback_plan.get("restored")),
                details={
                    "status": "not_required",
                    "reason": "execution left no active native hook state",
                },
            )
        if not _backend_available(backend):
            return self._record_rollback_result(
                result,
                ok=False,
                restored=False,
                status="unavailable",
                details={"error": _backend_reason(backend)},
            )

        pid = _coerce_int(rollback_plan.get("pid"))
        address = _coerce_int(rollback_plan.get("address"))
        original = _parse_bytes(rollback_plan.get("original_hex"))
        patched = _parse_bytes(rollback_plan.get("patched_hex"))
        if not pid or not address or not original or not patched or len(original) != len(patched):
            return self._record_rollback_result(
                result,
                ok=False,
                restored=False,
                status="failed",
                details={"error": "rollback metadata is incomplete or inconsistent"},
            )

        process = self._probe_process(backend, pid)
        planned_process = _planned_process_snapshot(result)
        if process.get("status") != "ok" or not _process_identity_matches(
            planned_process, process
        ):
            return self._record_rollback_result(
                result,
                ok=False,
                restored=False,
                status="failed",
                details={
                    "error": "target process identity changed; refusing rollback",
                    "planned_process_identity": _process_identity(planned_process),
                    "current_process_identity": _process_identity(process),
                },
            )

        operations: list[dict[str, Any]] = []
        errors: list[Any] = []
        live = _safe_read(backend, pid, address, len(original))
        if live not in {original, patched}:
            return self._record_rollback_result(
                result,
                ok=False,
                restored=False,
                status="failed",
                details={
                    "error": "hook target no longer matches original or patched bytes",
                    "address": address,
                    "expected_original_hex": original.hex(),
                    "expected_patched_hex": patched.hex(),
                    "actual_hex": live.hex() if live is not None else None,
                },
            )

        protection_restored = True
        if live == patched:
            restored_region = _restore_memory_region(
                backend,
                pid=pid,
                address=address,
                original=original,
                expected_current=patched,
                executable=result.action == "inline_trampoline",
                final_protection=_coerce_int(rollback_plan.get("old_protection")),
                allow_unknown_current=False,
            )
            operations.extend(restored_region["operations"])
            errors.extend(restored_region["errors"])
            protection_restored = bool(restored_region["protection_restored"])

        target_live = _safe_read(backend, pid, address, len(original))
        target_restored = target_live == original and protection_restored
        allocation_released = not bool(rollback_plan.get("allocation_active"))
        if result.action == "inline_trampoline" and target_restored:
            trampoline_address = _coerce_int(rollback_plan.get("trampoline_address"))
            trampoline = _parse_bytes(rollback_plan.get("trampoline_hex"))
            if rollback_plan.get("allocation_active"):
                if not trampoline_address or not trampoline:
                    errors.append(
                        {
                            "type": "ValueError",
                            "message": "inline rollback allocation metadata is incomplete",
                        }
                    )
                else:
                    trampoline_live = _safe_read(
                        backend, pid, trampoline_address, len(trampoline)
                    )
                    operations.append(
                        _memory_observation(
                            "verify_trampoline_before_free",
                            trampoline_address,
                            trampoline_live or b"",
                        )
                    )
                    if trampoline_live != trampoline:
                        errors.append(
                            {
                                "type": "RuntimeError",
                                "message": (
                                    "trampoline allocation changed; refusing to free an "
                                    "unverified remote region"
                                ),
                            }
                        )
                    else:
                        try:
                            released = _checked_operation(
                                backend.free(pid, trampoline_address),
                                operation="VirtualFreeEx(trampoline_rollback)",
                            )
                            operations.append(released)
                            allocation_released = released.get("released") is True
                            if not allocation_released:
                                raise RuntimeError(
                                    "trampoline allocation release was not confirmed"
                                )
                        except Exception as exc:  # noqa: BLE001
                            errors.append(_exception_payload(exc))

        complete = target_restored and allocation_released and not errors
        details = {
            "pid": pid,
            "address": address,
            "target_restored": target_restored,
            "actual_hex": target_live.hex() if target_live is not None else None,
            "protection_restored": protection_restored,
            "allocation_released": allocation_released,
            "operations": operations,
            "errors": errors,
        }
        return self._record_rollback_result(
            result,
            ok=complete,
            restored=complete,
            status="ok" if complete else "failed",
            details=details,
        )

    def _record_rollback_result(
        self,
        result: CapabilityExecutionResult,
        *,
        ok: bool,
        restored: bool,
        status: str,
        details: Mapping[str, Any],
    ) -> CapabilityRollbackResult:
        recorded_at = _utc_now()
        result.rollback_plan.update(
            {
                "status": "completed" if ok else status,
                "active": False if ok else bool(result.rollback_plan.get("active")),
                "completed": ok,
                "restored": restored,
                "allocation_active": False
                if ok and result.action == "inline_trampoline"
                else result.rollback_plan.get("allocation_active"),
                "allocation_released": True
                if ok and result.action == "inline_trampoline"
                else result.rollback_plan.get("allocation_released"),
                "rollback_at": recorded_at,
                "rollback_details": _json_mapping(details),
            }
        )
        result.after_snapshot["rollback"] = {
            "status": status,
            "ok": ok,
            "restored": restored,
            "captured_at": recorded_at,
            **_json_mapping(details),
        }
        result.report_section["rollback_status"] = status
        result.report_section["restored"] = restored
        result.dashboard_trace.append(
            {
                "kind": "native_hook_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "action": result.action,
                "status": status,
                "restored": restored,
                "session_id": result.session_id,
            }
        )
        lifecycle = result.provenance.setdefault("lifecycle_events", [])
        if isinstance(lifecycle, list):
            lifecycle.append(
                {
                    "kind": "rollback",
                    "ts": recorded_at,
                    "message": "native hook rollback completed",
                    "status": status,
                    "restored": restored,
                }
            )
        self._issue_result_identity(result)
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=ok,
            restored=restored,
            details={"status": status, **_json_mapping(details)},
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        del context
        self._require_owned_result(result)
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        target_resolution = result.provenance.get("hook_target_resolution")
        if not isinstance(target_resolution, Mapping):
            plan_payload = result.provenance.get("plan")
            if isinstance(plan_payload, Mapping):
                parameters = plan_payload.get("parameters")
                if isinstance(parameters, Mapping):
                    candidate = parameters.get("target_resolution")
                    if isinstance(candidate, Mapping):
                        target_resolution = candidate
        include_target_resolution = isinstance(target_resolution, Mapping)
        specs = _session_artifact_specs(
            result.session_id,
            include_target_resolution=include_target_resolution,
        )
        paths = {
            spec["kind"]: _resolve_artifact_path(root, spec["path"])
            for spec in specs
        }
        evidence_entries = [
            {
                "path": spec["path"],
                "kind": spec["kind"],
                "description": spec["description"],
                "status": result.status,
                "session_id": result.session_id,
            }
            for spec in specs
        ]
        result.evidence_manifest_entries = evidence_entries
        lifecycle_events = _normalized_lifecycle_events(result)
        audit_payload = _capability_audit_payload(result, lifecycle_events)
        event_payload = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "lifecycle_events": lifecycle_events,
            "trace_events": list(result.after_snapshot.get("trace_events") or []),
        }

        audit_meta = _atomic_write_json(paths["native-hook-audit"], audit_payload)
        event_meta = _atomic_write_json(paths["native-hook-events"], event_payload)
        metadata_by_kind = {
            "native-hook-audit": audit_meta,
            "native-hook-events": event_meta,
        }
        if include_target_resolution:
            metadata_by_kind["native-hook-target-resolution"] = _atomic_write_json(
                paths["native-hook-target-resolution"],
                _json_mapping(target_resolution),
            )
        materialized_entries = [
            {
                **entry,
                "sha256": metadata_by_kind[entry["kind"]]["sha256"],
                "size": metadata_by_kind[entry["kind"]]["size"],
            }
            for entry in evidence_entries
            if entry["kind"] != "native-hook-manifest"
        ]
        manifest_payload = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "generated_at": _utc_now(),
            "artifacts": materialized_entries,
        }
        manifest_meta = _atomic_write_json(
            paths["native-hook-manifest"], manifest_payload
        )
        metadata_by_kind["native-hook-manifest"] = manifest_meta
        result.artifacts = [
            CapabilityArtifact(
                path=spec["path"],
                kind=spec["kind"],
                description=spec["description"],
                metadata={
                    "materialized": True,
                    "session_id": result.session_id,
                    **metadata_by_kind[spec["kind"]],
                },
            )
            for spec in specs
        ]
        result.evidence_manifest_entries = [
            {
                **entry,
                "sha256": metadata_by_kind[entry["kind"]]["sha256"],
                "size": metadata_by_kind[entry["kind"]]["size"],
            }
            for entry in evidence_entries
        ]
        result.report_section["artifact_count"] = len(result.artifacts)
        result.report_section["artifacts_materialized"] = True
        self._issue_result_identity(result)
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=list(result.artifacts),
            manifest_entries=list(result.evidence_manifest_entries),
        )

    def _issue_result_identity(self, result: CapabilityExecutionResult) -> None:
        old_identity = (
            result.provenance.get(_RESULT_IDENTITY_KEY)
            if isinstance(result.provenance, Mapping)
            else None
        )
        if isinstance(old_identity, Mapping):
            self._issued_results.pop(str(old_identity.get("digest") or ""), None)
        payload = _result_identity_payload(result)
        canonical = _canonical_json(payload)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self._issued_results[digest] = canonical
        result.provenance[_RESULT_IDENTITY_KEY] = {
            "schema_version": _IDENTITY_SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "provider_instance": self._instance_id,
            "session_id": result.session_id,
            "action": result.action,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "digest": digest,
        }

    def _require_owned_result(self, result: CapabilityExecutionResult) -> None:
        if result.capability != self.capability_name or result.provider != self.provider_name:
            raise ValueError("capability result does not belong to native_hook provider")
        supplied = (
            result.provenance.get(_RESULT_IDENTITY_KEY)
            if isinstance(result.provenance, Mapping)
            else None
        )
        if not isinstance(supplied, Mapping):
            raise ValueError("native_hook result identity is missing")
        if supplied.get("provider_instance") != self._instance_id:
            raise ValueError("native_hook result was not issued by this provider instance")
        payload = _result_identity_payload(result)
        canonical = _canonical_json(payload)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        expected = {
            "schema_version": _IDENTITY_SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "provider_instance": self._instance_id,
            "session_id": result.session_id,
            "action": result.action,
            "precondition_hash": result.provenance.get("precondition_hash"),
            "digest": digest,
        }
        if _canonical_json(dict(supplied)) != _canonical_json(expected):
            raise ValueError("native_hook result identity does not match result contents")
        if self._issued_results.get(digest) != canonical:
            raise ValueError("native_hook result was not issued by this provider instance")
        precondition_hash = str(result.provenance.get("precondition_hash") or "")
        if precondition_hash not in self._issued_plans:
            raise ValueError("native_hook result references an unknown plan identity")


def _execution_before_snapshot(
    plan: CapabilityPlan,
    validation: CapabilityValidation,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    return _prune(
        {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "execute_validation",
            "captured_at": _utc_now(),
            "target_identity": _target_payload(plan.target),
            "planned": _json_mapping(plan.before_snapshot),
            "current": _json_mapping(current),
            "validation": validation.to_dict(),
        }
    )


def _inactive_rollback_plan(
    value: Mapping[str, Any], *, status: str, reason: str
) -> dict[str, Any]:
    rollback_plan = _json_mapping(value)
    rollback_plan.setdefault("supported", False)
    rollback_plan.update(
        {
            "status": status,
            "active": False,
            "completed": True,
            "restored": False,
            "reason": reason,
        }
    )
    return rollback_plan


def _validation_unavailable_reason(
    validation: CapabilityValidation,
) -> Optional[str]:
    reasons = [
        str(check.get("message") or "native hook dependency is unavailable")
        for check in validation.checks
        if str(check.get("status") or "").lower() == "unavailable"
    ]
    return "; ".join(dict.fromkeys(reasons)) or None


def _memory_observation(operation: str, address: int, data: bytes) -> dict[str, Any]:
    return {
        "operation": operation,
        "ok": True,
        "status": "ok",
        "address": address,
        "size": len(data),
        "bytes_hex": bytes(data).hex(),
    }


def _checked_operation(value: Any, *, operation: str) -> dict[str, Any]:
    payload = _operation_mapping(value, operation=operation)
    if not payload.get("ok"):
        reason = payload.get("error") or payload.get("reason") or payload.get("message")
        raise NativeHookBackendError(
            operation,
            str(reason or f"{operation} did not report success"),
            error_code=_coerce_int(payload.get("error_code")) or 0,
        )
    return payload


def _safe_read(
    backend: Any, pid: int, address: int, size: int
) -> Optional[bytes]:
    try:
        data = bytes(backend.read(pid, address, size))
    except Exception:  # noqa: BLE001 - observation helper
        return None
    return data if len(data) == size else None


def _restore_memory_region(
    backend: Any,
    *,
    pid: int,
    address: int,
    original: bytes,
    expected_current: bytes,
    executable: bool,
    final_protection: Optional[int],
    allow_unknown_current: bool,
) -> dict[str, Any]:
    operations: list[dict[str, Any]] = []
    errors: list[Any] = []
    protection_changed = False
    protection_restored = True
    captured_protection: Optional[int] = None
    current = _safe_read(backend, pid, address, len(original))
    if current == original:
        return {
            "operations": operations,
            "errors": errors,
            "restored": True,
            "protection_restored": True,
            "current": current,
        }
    if current != expected_current and not allow_unknown_current:
        return {
            "operations": operations,
            "errors": [
                {
                    "type": "RuntimeError",
                    "message": "memory changed before rollback; refusing to overwrite it",
                    "actual_hex": current.hex() if current is not None else None,
                }
            ],
            "restored": False,
            "protection_restored": True,
            "current": current,
        }

    try:
        protected = _checked_operation(
            backend.protect(
                pid,
                address,
                len(original),
                _PAGE_EXECUTE_READWRITE if executable else _PAGE_READWRITE,
            ),
            operation="VirtualProtectEx(rollback,writable)",
        )
        operations.append(protected)
        captured_protection = _coerce_int(protected.get("old_protection"))
        if captured_protection is None:
            raise RuntimeError("rollback page protection did not report its prior value")
        protection_changed = True
        protection_restored = False
        locked = _safe_read(backend, pid, address, len(original))
        operations.append(
            _memory_observation("read_rollback_preimage", address, locked or b"")
        )
        if locked != expected_current and not allow_unknown_current:
            raise RuntimeError("memory changed after rollback page protection update")
        written = _checked_operation(
            backend.write(pid, address, original),
            operation="WriteProcessMemory(rollback)",
        )
        operations.append(written)
        verified = _safe_read(backend, pid, address, len(original))
        operations.append(
            _memory_observation("verify_rollback_write", address, verified or b"")
        )
        if verified != original:
            raise RuntimeError("rollback write verification failed")
        if executable:
            operations.append(
                _checked_operation(
                    backend.flush_instruction_cache(pid, address, len(original)),
                    operation="FlushInstructionCache(rollback)",
                )
            )
    except Exception as exc:  # noqa: BLE001 - protection restored below
        errors.append(_exception_payload(exc))
    finally:
        if protection_changed:
            restore_to = final_protection
            if restore_to is None:
                restore_to = captured_protection
            if restore_to is not None:
                try:
                    operations.append(
                        _checked_operation(
                            backend.protect(pid, address, len(original), restore_to),
                            operation="VirtualProtectEx(rollback,restore)",
                        )
                    )
                    protection_changed = False
                    protection_restored = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))

    current = _safe_read(backend, pid, address, len(original))
    return {
        "operations": operations,
        "errors": errors,
        "restored": current == original,
        "protection_restored": protection_restored and not protection_changed,
        "current": current,
    }


def _planned_process_snapshot(result: CapabilityExecutionResult) -> dict[str, Any]:
    plan = result.provenance.get("plan")
    if isinstance(plan, Mapping):
        before = plan.get("before_snapshot")
        if isinstance(before, Mapping) and isinstance(before.get("process"), Mapping):
            return _json_mapping(before["process"])
    planned = result.before_snapshot.get("planned")
    if isinstance(planned, Mapping) and isinstance(planned.get("process"), Mapping):
        return _json_mapping(planned["process"])
    return {}


def _safe_session_segment(session_id: str) -> str:
    raw = str(session_id or "native-hook-session")
    cleaned = _SAFE_SESSION_RE.sub("_", raw).strip("._-")
    if not cleaned:
        cleaned = "session"
    cleaned = cleaned[:96]
    if cleaned != raw:
        suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        cleaned = f"{cleaned}-{suffix}"
    return cleaned


def _session_artifact_specs(
    session_id: str,
    *,
    include_target_resolution: bool = False,
) -> list[dict[str, str]]:
    base = PurePosixPath("native_hook") / _safe_session_segment(session_id)
    specs = [
        {
            "path": str(base / "audit.json"),
            "kind": "native-hook-audit",
            "description": "Native hook lifecycle audit record",
        },
        {
            "path": str(base / "events.json"),
            "kind": "native-hook-events",
            "description": "Native hook lifecycle and bounded trace events",
        },
    ]
    if include_target_resolution:
        specs.append(
            {
                "path": str(base / "hook-targets" / "resolution.json"),
                "kind": "native-hook-target-resolution",
                "description": "Verified native hook target resolution evidence",
            }
        )
    specs.append(
        {
            "path": str(base / "manifest.json"),
            "kind": "native-hook-manifest",
            "description": "Native hook session artifact manifest",
        }
    )
    return specs


def _resolve_artifact_path(root: Path, relative_path: str) -> Path:
    posix = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise ValueError(f"unsafe native_hook artifact path: {relative_path}")
    candidate = root.joinpath(*posix.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"native_hook artifact path escapes output root: {relative_path}"
        ) from exc
    return candidate


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            _json_value(payload),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(encoded)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "size": len(encoded),
    }


def _artifact_manifest_entry(
    artifact: CapabilityArtifact, *, status: str
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "description": artifact.description,
        "status": status,
        "metadata": _json_mapping(artifact.metadata),
    }


def _normalized_lifecycle_events(
    result: CapabilityExecutionResult,
) -> list[dict[str, Any]]:
    raw_events = result.provenance.get("lifecycle_events")
    events = [
        _json_mapping(item)
        for item in raw_events or []
        if isinstance(item, Mapping)
    ]
    required = ("plan", "validate", "execute")
    kinds = [str(item.get("kind") or "") for item in events]
    if any(kind not in kinds for kind in required):
        raise ValueError("native_hook lifecycle events are incomplete")
    for item in events:
        if not item.get("ts") or not item.get("message"):
            raise ValueError("native_hook lifecycle event lacks timestamp or message")
    return events


def _capability_audit_payload(
    result: CapabilityExecutionResult,
    lifecycle_events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    provenance = _json_mapping(result.provenance)
    provenance.pop(_RESULT_IDENTITY_KEY, None)
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "session_id": result.session_id,
        "capability": result.capability,
        "provider": result.provider,
        "target_identity": _target_payload(result.target),
        "action": result.action,
        "status": result.status,
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before_snapshot": _json_mapping(result.before_snapshot),
        "after_snapshot": _json_mapping(result.after_snapshot),
        "rollback_plan": _json_mapping(result.rollback_plan),
        "provenance": provenance,
        "evidence_manifest_entries": [
            _json_mapping(item) for item in result.evidence_manifest_entries
        ],
        "report_section": _json_mapping(result.report_section),
        "dashboard_trace": [
            _json_mapping(item) for item in result.dashboard_trace
        ],
        "events": [_json_mapping(item) for item in lifecycle_events],
    }


def _result_identity_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    payload = result.to_dict()
    provenance = _json_mapping(payload.get("provenance"))
    provenance.pop(_RESULT_IDENTITY_KEY, None)
    payload["provenance"] = provenance
    return _json_mapping(payload)
