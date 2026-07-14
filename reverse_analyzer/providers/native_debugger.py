"""Bounded Windows native debugger capability provider.

The production backend in this module is a direct ctypes adapter for the
Windows debugging APIs.  It never falls back to a simulator.  Tests may inject
an explicit backend object into NativeDebuggerProvider, but dependency and
architecture failures remain first-class unavailable results.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import re
import struct
import sys
import time
import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass, field
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


_AUDIT_SCHEMA_VERSION = 1
_IDENTITY_SCHEMA_VERSION = 1
_RESULT_IDENTITY_KEY = "native_debugger_result_identity"
_SUPPORTED_ACTIONS = {"attach_trace", "software_breakpoint_trace"}
_ACTION_ALIASES = {
    "attach": "attach_trace",
    "attach_trace": "attach_trace",
    "trace": "attach_trace",
    "breakpoint": "software_breakpoint_trace",
    "software_breakpoint": "software_breakpoint_trace",
    "software_breakpoint_trace": "software_breakpoint_trace",
}

_DEFAULT_DURATION_MS = 1_000
_MAX_DURATION_MS = 60_000
_DEFAULT_MAX_EVENTS = 256
_MAX_EVENTS = 10_000
_DEFAULT_POLL_INTERVAL_MS = 50
_MAX_DEBUG_STRING_BYTES = 64 * 1024
_DEFAULT_MAX_STACK_FRAMES = 32
_MAX_STACK_FRAMES = 128
_MAX_FRAME_POINTER_DELTA = 16 * 1024 * 1024

_PROCESS_VM_OPERATION = 0x0008
_PROCESS_VM_READ = 0x0010
_PROCESS_VM_WRITE = 0x0020
_PROCESS_QUERY_INFORMATION = 0x0400
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_THREAD_SUSPEND_RESUME = 0x0002
_THREAD_GET_CONTEXT = 0x0008
_THREAD_SET_CONTEXT = 0x0010
_THREAD_QUERY_INFORMATION = 0x0040

_PAGE_EXECUTE_READWRITE = 0x40
_ERROR_SEM_TIMEOUT = 121
_ERROR_INVALID_PARAMETER = 87
_STILL_ACTIVE = 259
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_EXCEPTION_DEBUG_EVENT = 1
_CREATE_THREAD_DEBUG_EVENT = 2
_CREATE_PROCESS_DEBUG_EVENT = 3
_EXIT_THREAD_DEBUG_EVENT = 4
_EXIT_PROCESS_DEBUG_EVENT = 5
_LOAD_DLL_DEBUG_EVENT = 6
_UNLOAD_DLL_DEBUG_EVENT = 7
_OUTPUT_DEBUG_STRING_EVENT = 8
_RIP_EVENT = 9

_EXCEPTION_BREAKPOINT = 0x80000003
_EXCEPTION_SINGLE_STEP = 0x80000004
_DBG_CONTINUE = 0x00010002
_DBG_EXCEPTION_NOT_HANDLED = 0x80010001

_IMAGE_FILE_MACHINE_UNKNOWN = 0x0000
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_IMAGE_FILE_MACHINE_ARM64 = 0xAA64

_CONTEXT_I386 = 0x00010000
_CONTEXT_I386_CONTROL = _CONTEXT_I386 | 0x00000001
_CONTEXT_I386_INTEGER = _CONTEXT_I386 | 0x00000002
_CONTEXT_AMD64 = 0x00100000
_CONTEXT_AMD64_CONTROL = _CONTEXT_AMD64 | 0x00000001
_CONTEXT_AMD64_INTEGER = _CONTEXT_AMD64 | 0x00000002
_TRAP_FLAG = 0x100

_SAFE_SESSION_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class NativeDebuggerBackendError(RuntimeError):
    """A Win32 backend failure with a stable operation and error code."""

    def __init__(self, operation: str, message: str, *, error_code: int = 0) -> None:
        super().__init__(message)
        self.operation = operation
        self.error_code = int(error_code)


@dataclass
class NativeDebugEvent:
    """Decoded DEBUG_EVENT plus handles that must be released by the debugger."""

    code: int
    pid: int
    thread_id: int
    payload: dict[str, Any]
    resources: tuple[int, ...] = field(default_factory=tuple)


class NativeDebuggerBackend(Protocol):
    """Backend seam used by the provider and explicit test doubles."""

    name: str
    available: bool
    unavailable_reason: Optional[str]
    production: bool

    def probe_process(self, pid: int) -> Mapping[str, Any]: ...

    def read(self, pid: int, address: int, size: int) -> bytes: ...

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]: ...

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]: ...

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]: ...

    def attach(self, pid: int) -> Mapping[str, Any]: ...

    def set_kill_on_exit(self, kill: bool) -> Mapping[str, Any]: ...

    def wait_for_debug_event(self, timeout_ms: int) -> Optional[NativeDebugEvent]: ...

    def continue_debug_event(
        self, pid: int, thread_id: int, continue_status: int
    ) -> Mapping[str, Any]: ...

    def detach(self, pid: int) -> Mapping[str, Any]: ...

    def release_event(self, event: NativeDebugEvent) -> None: ...

    def capture_thread_context(
        self, thread_id: int, architecture: str, *, suspend: bool = False
    ) -> Mapping[str, Any]: ...

    def update_thread_context(
        self,
        thread_id: int,
        architecture: str,
        *,
        instruction_pointer: Optional[int] = None,
        trap_flag: Optional[bool] = None,
        suspend: bool = False,
    ) -> Mapping[str, Any]: ...


class UnavailableNativeDebuggerBackend:
    """Dependency gate used outside Windows or after Win32 initialization fails."""

    name = "windows_native_debugger"
    available = False
    production = True

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        return {
            "status": "unavailable",
            "accessible": None,
            "pid": pid,
            "reason": self.unavailable_reason,
        }

    def _raise(self, operation: str) -> None:
        raise NativeDebuggerBackendError(operation, self.unavailable_reason)

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

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        del pid, address, size
        self._raise("FlushInstructionCache")

    def attach(self, pid: int) -> Mapping[str, Any]:
        del pid
        self._raise("DebugActiveProcess")

    def set_kill_on_exit(self, kill: bool) -> Mapping[str, Any]:
        del kill
        self._raise("DebugSetProcessKillOnExit")

    def wait_for_debug_event(self, timeout_ms: int) -> Optional[NativeDebugEvent]:
        del timeout_ms
        self._raise("WaitForDebugEvent")

    def continue_debug_event(
        self, pid: int, thread_id: int, continue_status: int
    ) -> Mapping[str, Any]:
        del pid, thread_id, continue_status
        self._raise("ContinueDebugEvent")

    def detach(self, pid: int) -> Mapping[str, Any]:
        del pid
        self._raise("DebugActiveProcessStop")

    def release_event(self, event: NativeDebugEvent) -> None:
        del event

    def capture_thread_context(
        self, thread_id: int, architecture: str, *, suspend: bool = False
    ) -> Mapping[str, Any]:
        del thread_id, architecture, suspend
        self._raise("GetThreadContext")

    def update_thread_context(
        self,
        thread_id: int,
        architecture: str,
        *,
        instruction_pointer: Optional[int] = None,
        trap_flag: Optional[bool] = None,
        suspend: bool = False,
    ) -> Mapping[str, Any]:
        del thread_id, architecture, instruction_pointer, trap_flag, suspend
        self._raise("SetThreadContext")


class _M128A(ctypes.Structure):
    _fields_ = [("Low", ctypes.c_uint64), ("High", ctypes.c_int64)]


class _XMM_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint16),
        ("StatusWord", ctypes.c_uint16),
        ("TagWord", ctypes.c_uint8),
        ("Reserved1", ctypes.c_uint8),
        ("ErrorOpcode", ctypes.c_uint16),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint16),
        ("Reserved2", ctypes.c_uint16),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint16),
        ("Reserved3", ctypes.c_uint16),
        ("MxCsr", ctypes.c_uint32),
        ("MxCsr_Mask", ctypes.c_uint32),
        ("FloatRegisters", _M128A * 8),
        ("XmmRegisters", _M128A * 16),
        ("Reserved4", ctypes.c_uint8 * 96),
    ]


class _CONTEXT64_UNION(ctypes.Union):
    _fields_ = [("FltSave", _XMM_SAVE_AREA32), ("Q", _M128A * 32)]


class _CONTEXT64(ctypes.Structure):
    _anonymous_ = ("DUMMYUNION",)
    _fields_ = [
        ("P1Home", ctypes.c_uint64),
        ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64),
        ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64),
        ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32),
        ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16),
        ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16),
        ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16),
        ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64),
        ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64),
        ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64),
        ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64),
        ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64),
        ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64),
        ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64),
        ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64),
        ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64),
        ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64),
        ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64),
        ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("DUMMYUNION", _CONTEXT64_UNION),
        ("VectorRegister", _M128A * 26),
        ("VectorControl", ctypes.c_uint64),
        ("DebugControl", ctypes.c_uint64),
        ("LastBranchToRip", ctypes.c_uint64),
        ("LastBranchFromRip", ctypes.c_uint64),
        ("LastExceptionToRip", ctypes.c_uint64),
        ("LastExceptionFromRip", ctypes.c_uint64),
    ]


class _FLOATING_SAVE_AREA32(ctypes.Structure):
    _fields_ = [
        ("ControlWord", ctypes.c_uint32),
        ("StatusWord", ctypes.c_uint32),
        ("TagWord", ctypes.c_uint32),
        ("ErrorOffset", ctypes.c_uint32),
        ("ErrorSelector", ctypes.c_uint32),
        ("DataOffset", ctypes.c_uint32),
        ("DataSelector", ctypes.c_uint32),
        ("RegisterArea", ctypes.c_uint8 * 80),
        ("Cr0NpxState", ctypes.c_uint32),
    ]


class _CONTEXT32(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint32),
        ("Dr1", ctypes.c_uint32),
        ("Dr2", ctypes.c_uint32),
        ("Dr3", ctypes.c_uint32),
        ("Dr6", ctypes.c_uint32),
        ("Dr7", ctypes.c_uint32),
        ("FloatSave", _FLOATING_SAVE_AREA32),
        ("SegGs", ctypes.c_uint32),
        ("SegFs", ctypes.c_uint32),
        ("SegEs", ctypes.c_uint32),
        ("SegDs", ctypes.c_uint32),
        ("Edi", ctypes.c_uint32),
        ("Esi", ctypes.c_uint32),
        ("Ebx", ctypes.c_uint32),
        ("Edx", ctypes.c_uint32),
        ("Ecx", ctypes.c_uint32),
        ("Eax", ctypes.c_uint32),
        ("Ebp", ctypes.c_uint32),
        ("Eip", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint32),
        ("EFlags", ctypes.c_uint32),
        ("Esp", ctypes.c_uint32),
        ("SegSs", ctypes.c_uint32),
        ("ExtendedRegisters", ctypes.c_uint8 * 512),
    ]


_ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32


class _EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", _ULONG_PTR * 15),
    ]


class _EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", _EXCEPTION_RECORD),
        ("dwFirstChance", wintypes.DWORD),
    ]


class _CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class _CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class _EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class _LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class _UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class _OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class _RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", wintypes.DWORD), ("dwType", wintypes.DWORD)]


class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", _EXCEPTION_DEBUG_INFO),
        ("CreateThread", _CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", _CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", _EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", _EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", _LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", _UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", _OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", _RIP_INFO),
    ]


class _DEBUG_EVENT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", _DEBUG_EVENT_UNION),
    ]


class WindowsNativeDebuggerBackend:
    """Direct ctypes adapter for the Windows native debugging APIs."""

    name = "windows_native_debugger"
    production = True

    def __init__(self, kernel32: Any = None, *, platform_name: Optional[str] = None) -> None:
        self.platform_name = platform_name or sys.platform
        self.available = self.platform_name == "win32"
        self.unavailable_reason: Optional[str] = None
        self._kernel32 = kernel32
        if not self.available:
            self.unavailable_reason = (
                f"Windows native debugger APIs are unavailable on {self.platform_name}"
            )
            return
        try:
            self._kernel32 = self._kernel32 or ctypes.WinDLL(
                "kernel32", use_last_error=True
            )
            self._configure_api()
        except Exception as exc:  # noqa: BLE001 - platform boundary
            self.available = False
            self.unavailable_reason = (
                f"Windows native debugger API initialization failed: {exc}"
            )

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
        k32.FlushInstructionCache.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        k32.FlushInstructionCache.restype = wintypes.BOOL
        k32.DebugActiveProcess.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcess.restype = wintypes.BOOL
        k32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
        k32.DebugActiveProcessStop.restype = wintypes.BOOL
        k32.DebugSetProcessKillOnExit.argtypes = [wintypes.BOOL]
        k32.DebugSetProcessKillOnExit.restype = wintypes.BOOL
        k32.WaitForDebugEvent.argtypes = [
            ctypes.POINTER(_DEBUG_EVENT),
            wintypes.DWORD,
        ]
        k32.WaitForDebugEvent.restype = wintypes.BOOL
        k32.ContinueDebugEvent.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        k32.ContinueDebugEvent.restype = wintypes.BOOL
        k32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        k32.GetThreadContext.restype = wintypes.BOOL
        k32.SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        k32.SetThreadContext.restype = wintypes.BOOL
        k32.SuspendThread.argtypes = [wintypes.HANDLE]
        k32.SuspendThread.restype = wintypes.DWORD
        k32.ResumeThread.argtypes = [wintypes.HANDLE]
        k32.ResumeThread.restype = wintypes.DWORD
        k32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        k32.GetProcessTimes.restype = wintypes.BOOL
        query_image = getattr(k32, "QueryFullProcessImageNameW", None)
        if callable(query_image):
            query_image.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            query_image.restype = wintypes.BOOL
        wow64_2 = getattr(k32, "IsWow64Process2", None)
        if callable(wow64_2):
            wow64_2.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.USHORT),
                ctypes.POINTER(wintypes.USHORT),
            ]
            wow64_2.restype = wintypes.BOOL
        wow64 = getattr(k32, "IsWow64Process", None)
        if callable(wow64):
            wow64.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
            wow64.restype = wintypes.BOOL
        final_path = getattr(k32, "GetFinalPathNameByHandleW", None)
        if callable(final_path):
            final_path.argtypes = [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            final_path.restype = wintypes.DWORD

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        handle = None
        try:
            handle = self._open_process(
                pid,
                _PROCESS_QUERY_LIMITED_INFORMATION | _PROCESS_VM_READ,
                "probe_process",
            )
            architecture = self._query_architecture(handle)
            return {
                "status": "ok",
                "accessible": True,
                "exists": True,
                "pid": pid,
                "image_path": self._query_image_path(handle),
                "creation_time": self._query_creation_time(handle),
                **architecture,
            }
        except NativeDebuggerBackendError as exc:
            return {
                "status": "failed",
                "accessible": False,
                "exists": None,
                "pid": pid,
                "error": _exception_payload(exc),
            }
        finally:
            self._close(handle)

    def read(self, pid: int, address: int, size: int) -> bytes:
        if size <= 0:
            raise ValueError("read size must be positive")
        handle = self._open_process(
            pid,
            _PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ,
            "ReadProcessMemory",
        )
        try:
            buffer = (ctypes.c_ubyte * size)()
            count = ctypes.c_size_t(0)
            if not self._kernel32.ReadProcessMemory(
                handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(count),
            ) or count.value != size:
                self._raise_last_error(
                    "ReadProcessMemory",
                    f"read {count.value} of {size} bytes at 0x{address:x}",
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
            source = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
            count = ctypes.c_size_t(0)
            if not self._kernel32.WriteProcessMemory(
                handle,
                ctypes.c_void_p(address),
                source,
                len(payload),
                ctypes.byref(count),
            ) or count.value != len(payload):
                self._raise_last_error(
                    "WriteProcessMemory",
                    f"wrote {count.value} of {len(payload)} bytes at 0x{address:x}",
                )
            return {
                "ok": True,
                "status": "ok",
                "operation": "WriteProcessMemory",
                "address": address,
                "bytes_written": int(count.value),
            }
        finally:
            self._close(handle)

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]:
        handle = self._open_process(
            pid,
            _PROCESS_VM_OPERATION | _PROCESS_QUERY_INFORMATION,
            "VirtualProtectEx",
        )
        try:
            old = wintypes.DWORD(0)
            if not self._kernel32.VirtualProtectEx(
                handle,
                ctypes.c_void_p(address),
                size,
                protection,
                ctypes.byref(old),
            ):
                self._raise_last_error(
                    "VirtualProtectEx", f"could not protect 0x{address:x}"
                )
            return {
                "ok": True,
                "status": "ok",
                "operation": "VirtualProtectEx",
                "address": address,
                "size": size,
                "old_protection": int(old.value),
                "new_protection": int(protection),
            }
        finally:
            self._close(handle)

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        handle = self._open_process(
            pid,
            _PROCESS_QUERY_INFORMATION,
            "FlushInstructionCache",
        )
        try:
            if not self._kernel32.FlushInstructionCache(
                handle, ctypes.c_void_p(address), size
            ):
                self._raise_last_error(
                    "FlushInstructionCache", f"could not flush 0x{address:x}"
                )
            return {
                "ok": True,
                "status": "ok",
                "operation": "FlushInstructionCache",
                "address": address,
                "size": size,
            }
        finally:
            self._close(handle)

    def attach(self, pid: int) -> Mapping[str, Any]:
        if not self._kernel32.DebugActiveProcess(pid):
            self._raise_last_error("DebugActiveProcess", f"could not attach to PID {pid}")
        return {
            "ok": True,
            "status": "ok",
            "operation": "DebugActiveProcess",
            "pid": pid,
        }

    def set_kill_on_exit(self, kill: bool) -> Mapping[str, Any]:
        if not self._kernel32.DebugSetProcessKillOnExit(bool(kill)):
            self._raise_last_error(
                "DebugSetProcessKillOnExit", "could not set debugger exit policy"
            )
        return {
            "ok": True,
            "status": "ok",
            "operation": "DebugSetProcessKillOnExit",
            "kill_on_exit": bool(kill),
        }

    def wait_for_debug_event(self, timeout_ms: int) -> Optional[NativeDebugEvent]:
        event = _DEBUG_EVENT()
        ctypes.set_last_error(0)
        if not self._kernel32.WaitForDebugEvent(
            ctypes.byref(event), max(0, int(timeout_ms))
        ):
            error_code = int(ctypes.get_last_error())
            if error_code == _ERROR_SEM_TIMEOUT:
                return None
            self._raise_last_error(
                "WaitForDebugEvent", "could not retrieve a debug event"
            )
        try:
            return self._decode_event(event)
        except Exception as exc:  # noqa: BLE001 - acquired events must be continued
            return NativeDebugEvent(
                code=int(event.dwDebugEventCode),
                pid=int(event.dwProcessId),
                thread_id=int(event.dwThreadId),
                payload={
                    "kind": _event_kind_for_code(int(event.dwDebugEventCode)),
                    "debug_event_code": int(event.dwDebugEventCode),
                    "decode_error": _exception_payload(exc),
                },
                resources=self._raw_event_resources(event),
            )

    def continue_debug_event(
        self, pid: int, thread_id: int, continue_status: int
    ) -> Mapping[str, Any]:
        if not self._kernel32.ContinueDebugEvent(pid, thread_id, continue_status):
            self._raise_last_error(
                "ContinueDebugEvent",
                f"could not continue PID {pid} thread {thread_id}",
            )
        return {
            "ok": True,
            "status": "ok",
            "operation": "ContinueDebugEvent",
            "pid": pid,
            "thread_id": thread_id,
            "continue_status": int(continue_status),
        }

    def detach(self, pid: int) -> Mapping[str, Any]:
        if not self._kernel32.DebugActiveProcessStop(pid):
            self._raise_last_error(
                "DebugActiveProcessStop", f"could not detach from PID {pid}"
            )
        return {
            "ok": True,
            "status": "ok",
            "operation": "DebugActiveProcessStop",
            "pid": pid,
        }

    def release_event(self, event: NativeDebugEvent) -> None:
        for handle in dict.fromkeys(event.resources):
            self._close(handle)

    def capture_thread_context(
        self, thread_id: int, architecture: str, *, suspend: bool = False
    ) -> Mapping[str, Any]:
        return self._with_thread_context(
            thread_id, architecture, suspend=suspend, updates=None
        )["before"]

    def update_thread_context(
        self,
        thread_id: int,
        architecture: str,
        *,
        instruction_pointer: Optional[int] = None,
        trap_flag: Optional[bool] = None,
        suspend: bool = False,
    ) -> Mapping[str, Any]:
        return self._with_thread_context(
            thread_id,
            architecture,
            suspend=suspend,
            updates={
                "instruction_pointer": instruction_pointer,
                "trap_flag": trap_flag,
            },
        )

    def _with_thread_context(
        self,
        thread_id: int,
        architecture: str,
        *,
        suspend: bool,
        updates: Optional[Mapping[str, Any]],
    ) -> dict[str, Any]:
        if architecture not in {"x86", "x64"}:
            raise NativeDebuggerBackendError(
                "GetThreadContext", f"unsupported context architecture: {architecture}"
            )
        debugger_arch = _debugger_architecture()
        if architecture != debugger_arch:
            raise NativeDebuggerBackendError(
                "GetThreadContext",
                f"{debugger_arch} debugger cannot use native context APIs for {architecture} target",
            )
        handle = self._open_thread(
            thread_id,
            _THREAD_GET_CONTEXT
            | _THREAD_SET_CONTEXT
            | _THREAD_SUSPEND_RESUME
            | _THREAD_QUERY_INFORMATION,
            "OpenThread(context)",
        )
        suspended = False
        try:
            if suspend:
                previous = int(self._kernel32.SuspendThread(handle))
                if previous == 0xFFFFFFFF:
                    self._raise_last_error(
                        "SuspendThread", f"could not suspend thread {thread_id}"
                    )
                suspended = True
            context: Any
            if architecture == "x64":
                context = _CONTEXT64()
                context.ContextFlags = _CONTEXT_AMD64_CONTROL | _CONTEXT_AMD64_INTEGER
            else:
                context = _CONTEXT32()
                context.ContextFlags = _CONTEXT_I386_CONTROL | _CONTEXT_I386_INTEGER
            if not self._kernel32.GetThreadContext(handle, ctypes.byref(context)):
                self._raise_last_error(
                    "GetThreadContext", f"could not read thread {thread_id} context"
                )
            before = _context_summary(context, architecture, thread_id)
            if updates is not None:
                instruction_pointer = updates.get("instruction_pointer")
                trap_flag = updates.get("trap_flag")
                if instruction_pointer is not None:
                    if architecture == "x64":
                        context.Rip = int(instruction_pointer)
                    else:
                        context.Eip = int(instruction_pointer)
                if trap_flag is not None:
                    flags = int(context.EFlags)
                    context.EFlags = (
                        flags | _TRAP_FLAG if bool(trap_flag) else flags & ~_TRAP_FLAG
                    )
                if not self._kernel32.SetThreadContext(handle, ctypes.byref(context)):
                    self._raise_last_error(
                        "SetThreadContext", f"could not update thread {thread_id} context"
                    )
            after = _context_summary(context, architecture, thread_id)
            return {"ok": True, "status": "ok", "before": before, "after": after}
        finally:
            if suspended:
                if int(self._kernel32.ResumeThread(handle)) == 0xFFFFFFFF:
                    self._close(handle)
                    self._raise_last_error(
                        "ResumeThread", f"could not resume thread {thread_id}"
                    )
            self._close(handle)

    def _decode_event(self, event: _DEBUG_EVENT) -> NativeDebugEvent:
        code = int(event.dwDebugEventCode)
        pid = int(event.dwProcessId)
        thread_id = int(event.dwThreadId)
        resources: list[int] = []
        payload: dict[str, Any]
        if code == _EXCEPTION_DEBUG_EVENT:
            record = event.Exception.ExceptionRecord
            count = min(int(record.NumberParameters), 15)
            payload = {
                "kind": "exception",
                "exception_code": int(record.ExceptionCode),
                "exception_code_hex": f"0x{int(record.ExceptionCode):08x}",
                "exception_flags": int(record.ExceptionFlags),
                "exception_address": _pointer_value(record.ExceptionAddress),
                "first_chance": bool(event.Exception.dwFirstChance),
                "information": [
                    int(record.ExceptionInformation[index]) for index in range(count)
                ],
            }
        elif code == _CREATE_THREAD_DEBUG_EVENT:
            info = event.CreateThread
            resources.extend(_valid_handles(info.hThread))
            payload = {
                "kind": "thread_create",
                "start_address": _pointer_value(info.lpStartAddress),
                "thread_local_base": _pointer_value(info.lpThreadLocalBase),
            }
        elif code == _CREATE_PROCESS_DEBUG_EVENT:
            info = event.CreateProcessInfo
            resources.extend(_valid_handles(info.hFile, info.hProcess, info.hThread))
            payload = {
                "kind": "process_create",
                "base_address": _pointer_value(info.lpBaseOfImage),
                "start_address": _pointer_value(info.lpStartAddress),
                "thread_local_base": _pointer_value(info.lpThreadLocalBase),
                "image_path": self._file_path_from_handle(info.hFile),
            }
        elif code == _EXIT_THREAD_DEBUG_EVENT:
            payload = {
                "kind": "thread_exit",
                "exit_code": int(event.ExitThread.dwExitCode),
            }
        elif code == _EXIT_PROCESS_DEBUG_EVENT:
            payload = {
                "kind": "process_exit",
                "exit_code": int(event.ExitProcess.dwExitCode),
            }
        elif code == _LOAD_DLL_DEBUG_EVENT:
            info = event.LoadDll
            resources.extend(_valid_handles(info.hFile))
            payload = {
                "kind": "module_load",
                "base_address": _pointer_value(info.lpBaseOfDll),
                "image_path": self._file_path_from_handle(info.hFile),
            }
        elif code == _UNLOAD_DLL_DEBUG_EVENT:
            payload = {
                "kind": "module_unload",
                "base_address": _pointer_value(event.UnloadDll.lpBaseOfDll),
            }
        elif code == _OUTPUT_DEBUG_STRING_EVENT:
            info = event.DebugString
            payload = {
                "kind": "debug_string",
                **self._read_debug_string(
                    pid,
                    _pointer_value(info.lpDebugStringData),
                    int(info.nDebugStringLength),
                    bool(info.fUnicode),
                ),
            }
        elif code == _RIP_EVENT:
            payload = {
                "kind": "rip",
                "error_code": int(event.RipInfo.dwError),
                "error_type": int(event.RipInfo.dwType),
            }
        else:
            payload = {"kind": "unknown", "debug_event_code": code}
        return NativeDebugEvent(
            code=code,
            pid=pid,
            thread_id=thread_id,
            payload=_prune(payload),
            resources=tuple(resources),
        )

    def _raw_event_resources(self, event: _DEBUG_EVENT) -> tuple[int, ...]:
        try:
            code = int(event.dwDebugEventCode)
            if code == _CREATE_THREAD_DEBUG_EVENT:
                return tuple(_valid_handles(event.CreateThread.hThread))
            if code == _CREATE_PROCESS_DEBUG_EVENT:
                info = event.CreateProcessInfo
                return tuple(_valid_handles(info.hFile, info.hProcess, info.hThread))
            if code == _LOAD_DLL_DEBUG_EVENT:
                return tuple(_valid_handles(event.LoadDll.hFile))
        except Exception:  # noqa: BLE001 - best-effort handle recovery
            return ()
        return ()

    def _read_debug_string(
        self, pid: int, address: int, length: int, unicode_text: bool
    ) -> dict[str, Any]:
        if not address or length <= 0:
            return {"text": "", "unicode": unicode_text, "length": length}
        byte_count = length * (2 if unicode_text else 1)
        byte_count = min(byte_count, _MAX_DEBUG_STRING_BYTES)
        try:
            raw = self.read(pid, address, byte_count)
            encoding = "utf-16-le" if unicode_text else "mbcs"
            text = raw.decode(encoding, errors="replace").rstrip("\x00")
            return {
                "text": text,
                "unicode": unicode_text,
                "length": length,
                "truncated": byte_count < length * (2 if unicode_text else 1),
            }
        except Exception as exc:  # noqa: BLE001 - event must still be continued
            return {
                "text": None,
                "unicode": unicode_text,
                "length": length,
                "decode_error": _exception_payload(exc),
            }

    def _file_path_from_handle(self, handle: Any) -> Optional[str]:
        value = _pointer_value(handle)
        if not value:
            return None
        function = getattr(self._kernel32, "GetFinalPathNameByHandleW", None)
        if not callable(function):
            return None
        size = 32768
        buffer = ctypes.create_unicode_buffer(size)
        length = int(function(handle, buffer, size, 0))
        if length <= 0 or length >= size:
            return None
        path = buffer.value
        return path[4:] if path.startswith("\\\\?\\") else path

    def _query_image_path(self, handle: Any) -> Optional[str]:
        function = getattr(self._kernel32, "QueryFullProcessImageNameW", None)
        if not callable(function):
            return None
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not function(handle, 0, buffer, ctypes.byref(size)):
            return None
        return buffer.value

    def _query_creation_time(self, handle: Any) -> Optional[int]:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel_time = wintypes.FILETIME()
        user_time = wintypes.FILETIME()
        if not self._kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            return None
        return (int(creation.dwHighDateTime) << 32) | int(creation.dwLowDateTime)

    def _query_architecture(self, handle: Any) -> dict[str, Any]:
        debugger_arch = _debugger_architecture()
        process_machine: Optional[int] = None
        native_machine: Optional[int] = None
        wow64 = False
        function = getattr(self._kernel32, "IsWow64Process2", None)
        if callable(function):
            process_value = wintypes.USHORT(0)
            native_value = wintypes.USHORT(0)
            if function(handle, ctypes.byref(process_value), ctypes.byref(native_value)):
                process_machine = int(process_value.value)
                native_machine = int(native_value.value)
                wow64 = process_machine != _IMAGE_FILE_MACHINE_UNKNOWN
        if process_machine is None:
            legacy = getattr(self._kernel32, "IsWow64Process", None)
            if callable(legacy):
                value = wintypes.BOOL(False)
                if legacy(handle, ctypes.byref(value)):
                    wow64 = bool(value.value)
            if wow64:
                architecture = "x86"
            else:
                architecture = debugger_arch
        else:
            effective = native_machine if process_machine == 0 else process_machine
            architecture = {
                _IMAGE_FILE_MACHINE_I386: "x86",
                _IMAGE_FILE_MACHINE_AMD64: "x64",
                _IMAGE_FILE_MACHINE_ARM64: "arm64",
            }.get(int(effective or 0), "unknown")
        context_supported = architecture == debugger_arch and architecture in {"x86", "x64"}
        reason = None
        if not context_supported:
            if wow64 and debugger_arch == "x64" and architecture == "x86":
                reason = (
                    "WOW64 thread context is not supported by this provider; "
                    "use a same-bitness x86 debugger"
                )
            else:
                reason = (
                    f"same-bitness x86/x64 debugging is required "
                    f"(debugger={debugger_arch}, target={architecture})"
                )
        return {
            "architecture": architecture,
            "debugger_architecture": debugger_arch,
            "wow64": wow64,
            "process_machine": process_machine,
            "native_machine": native_machine,
            "context_supported": context_supported,
            "context_api": "GetThreadContext" if context_supported else None,
            "architecture_reason": reason,
        }

    def _open_process(self, pid: int, access: int, operation: str) -> Any:
        if not self.available:
            raise NativeDebuggerBackendError(
                operation,
                self.unavailable_reason or "Windows native debugger is unavailable",
            )
        handle = self._kernel32.OpenProcess(access, False, pid)
        if not handle:
            self._raise_last_error(operation, f"could not open PID {pid}")
        return handle

    def _open_thread(self, thread_id: int, access: int, operation: str) -> Any:
        if not self.available:
            raise NativeDebuggerBackendError(
                operation,
                self.unavailable_reason or "Windows native debugger is unavailable",
            )
        handle = self._kernel32.OpenThread(access, False, thread_id)
        if not handle:
            self._raise_last_error(operation, f"could not open thread {thread_id}")
        return handle

    def _close(self, handle: Any) -> None:
        if handle:
            self._kernel32.CloseHandle(handle)

    def _raise_last_error(self, operation: str, message: str) -> None:
        error_code = int(ctypes.get_last_error())
        try:
            detail = ctypes.FormatError(error_code).strip()
        except Exception:  # noqa: BLE001
            detail = f"WinError {error_code}"
        raise NativeDebuggerBackendError(
            operation,
            f"{message}: {detail or f'WinError {error_code}'}",
            error_code=error_code,
        )


class NativeDebuggerProvider:
    """Plan and run bounded, reversible Windows debugger sessions."""

    capability_name = "native_debugger"
    provider_name = "windows_native_debugger"
    priority = 10

    def __init__(
        self,
        backend: Optional[NativeDebuggerBackend] = None,
        *,
        platform_name: Optional[str] = None,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        if backend is not None:
            self.backend: NativeDebuggerBackend = backend
        elif self.platform_name == "win32":
            self.backend = WindowsNativeDebuggerBackend(
                platform_name=self.platform_name
            )
        else:
            self.backend = UnavailableNativeDebuggerBackend(
                f"Windows native debugger APIs are unavailable on {self.platform_name}"
            )
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
        params = _json_mapping(request.params)
        errors: list[str] = []
        target_pid = _coerce_int(request.target.pid)
        param_pid = _coerce_int(_first_value(params, "pid", "process_id"))
        pid_conflict = bool(target_pid and param_pid and target_pid != param_pid)
        pid = target_pid if target_pid is not None else param_pid
        if not pid or pid <= 0:
            errors.append("native debugger requires a positive target PID")
        if pid_conflict:
            errors.append("target PID conflicts with params.pid")
        if pid == os.getpid():
            errors.append("native debugger cannot attach to its own process")

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

        duration_ms = _duration_ms(params, errors)
        max_events = _bounded_integer(
            params.get("max_events"),
            default=_DEFAULT_MAX_EVENTS,
            minimum=1,
            maximum=_MAX_EVENTS,
            name="max_events",
            errors=errors,
        )
        poll_interval_ms = _bounded_integer(
            params.get("poll_interval_ms"),
            default=_DEFAULT_POLL_INTERVAL_MS,
            minimum=1,
            maximum=1_000,
            name="poll_interval_ms",
            errors=errors,
        )
        max_stack_frames = _bounded_integer(
            params.get("max_stack_frames"),
            default=_DEFAULT_MAX_STACK_FRAMES,
            minimum=1,
            maximum=_MAX_STACK_FRAMES,
            name="max_stack_frames",
            errors=errors,
        )
        requested_creation_time = _first_value(
            params,
            "creation_time",
            "process_creation_time",
            "expected_creation_time",
        )
        expected_creation_time = _coerce_int(requested_creation_time)
        if requested_creation_time is not None and expected_creation_time is None:
            errors.append("expected process creation time must be an integer")
        if expected_creation_time is None:
            metadata_creation_time = _first_value(
                _json_mapping(request.target.metadata),
                "creation_time",
                "process_creation_time",
            )
            expected_creation_time = _coerce_int(metadata_creation_time)
            if metadata_creation_time is not None and expected_creation_time is None:
                errors.append("target creation-time identity must be an integer")

        process_probe = self._probe_process(backend, pid)
        requested_architecture_value = _first_value(params, "architecture", "arch")
        requested_architecture = _normalize_architecture(requested_architecture_value)
        if requested_architecture_value is not None and requested_architecture is None:
            errors.append("architecture must be x86, x64, or arm64")
        architecture = _normalize_architecture(process_probe.get("architecture"))
        if requested_architecture and architecture and requested_architecture != architecture:
            errors.append(
                "requested architecture does not match the probed target architecture"
            )

        normalized: dict[str, Any] = {
            "requested_action": request.action,
            "pid": pid,
            "pid_conflict": pid_conflict,
            "authorized": authorized,
            "authorization_source": authorization_source,
            "authorization_scope": params.get("authorization_scope")
            or params.get("reason")
            or "authorized native debugging",
            "duration_ms": duration_ms,
            "max_events": max_events,
            "poll_interval_ms": poll_interval_ms,
            "max_stack_frames": max_stack_frames,
            "requested_architecture": requested_architecture,
            "architecture": architecture,
            "expected_creation_time": expected_creation_time,
            "parameter_errors": errors,
        }

        breakpoint_snapshot: dict[str, Any] = {"status": "not_applicable"}
        if action == "software_breakpoint_trace":
            address = _coerce_int(
                _first_value(params, "address", "breakpoint_address", "target_address")
            )
            expected_byte = _parse_expected_byte(
                _first_value(
                    params,
                    "expected_original_byte",
                    "expected_byte",
                    "expected_original",
                )
            )
            rearm = _coerce_bool(params.get("rearm"), default=True)
            max_hits = _bounded_integer(
                params.get("max_breakpoint_hits"),
                default=max_events,
                minimum=1,
                maximum=_MAX_EVENTS,
                name="max_breakpoint_hits",
                errors=errors,
            )
            normalized.update(
                {
                    "address": address,
                    "expected_original_byte": expected_byte,
                    "expected_original_hex": (
                        f"{expected_byte:02x}" if expected_byte is not None else None
                    ),
                    "rearm": rearm,
                    "max_breakpoint_hits": max_hits,
                }
            )
            if not address or address <= 0:
                errors.append(
                    "software_breakpoint_trace requires a positive breakpoint address"
                )
            if expected_byte is None:
                errors.append(
                    "software_breakpoint_trace requires one explicit expected_original_byte"
                )
            if _backend_available(backend) and pid and address:
                try:
                    current = bytes(backend.read(pid, address, 1))
                    breakpoint_snapshot = {
                        "status": "ok",
                        "address": address,
                        "bytes_hex": current.hex(),
                        "expected_hex": (
                            f"{expected_byte:02x}"
                            if expected_byte is not None
                            else None
                        ),
                        "matches_expected": (
                            expected_byte is not None
                            and current == bytes([expected_byte])
                        ),
                    }
                except Exception as exc:  # noqa: BLE001 - captured precondition
                    breakpoint_snapshot = {
                        "status": "failed",
                        "address": address,
                        "error": _exception_payload(exc),
                    }
        elif action != "attach_trace":
            errors.append(
                f"unsupported native_debugger action: {action or request.action}"
            )

        before_snapshot = _prune(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "plan",
                "captured_at": _utc_now(),
                "target_identity": _target_payload(request.target),
                "process": process_probe,
                "process_identity": _process_identity(process_probe),
                "breakpoint": breakpoint_snapshot,
                "architecture_boundary": _architecture_boundary(process_probe),
                "backend": _backend_info(backend, self.platform_name),
            }
        )
        rollback_plan = {
            "supported": True,
            "status": "planned",
            "active": False,
            "completed": False,
            "pid": pid,
            "detach": True,
            "clear_trap_flag": action == "software_breakpoint_trace",
            "restore_original_byte": action == "software_breakpoint_trace",
            "address": normalized.get("address"),
            "original_byte_hex": normalized.get("expected_original_hex"),
        }
        steps = [
            {
                "name": "verify_target_identity",
                "description": "Re-probe PID and creation time immediately before attach",
            },
            {
                "name": "attach",
                "description": "Call DebugActiveProcess and disable kill-on-debugger-exit",
            },
        ]
        if action == "software_breakpoint_trace":
            steps.append(
                {
                    "name": "install_breakpoint",
                    "description": (
                        "Verify the expected byte, write 0xCC, and flush the instruction cache"
                    ),
                }
            )
        steps.extend(
            [
                {
                    "name": "trace",
                    "description": "Normalize and continue a bounded set of debug events",
                },
                {
                    "name": "cleanup",
                    "description": "Restore byte/context state and call DebugActiveProcessStop",
                },
            ]
        )
        plan = CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=str(request.session_id or "native-debugger-session"),
            target=request.target,
            action=action,
            parameters=_prune(normalized),
            steps=steps,
            before_snapshot=before_snapshot,
            rollback_plan=_prune(rollback_plan),
            provenance=_prune(
                {
                    **_json_mapping(request.provenance),
                    "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                    "provider": self.provider_name,
                    "provider_instance": self._instance_id,
                    "backend": _backend_info(backend, self.platform_name),
                    "authorization_source": authorization_source,
                    "target_identity": _target_payload(request.target),
                    "process_identity": _process_identity(process_probe),
                    "native_win32": True,
                    "debug_api": [
                        "DebugActiveProcess",
                        "WaitForDebugEvent",
                        "ContinueDebugEvent",
                        "DebugActiveProcessStop",
                    ],
                    "simulated": False,
                }
            ),
        )
        plan.precondition_hash = _plan_precondition_hash(plan)
        plan.provenance["precondition_hash"] = plan.precondition_hash
        plan.rollback_plan["precondition_hash"] = plan.precondition_hash
        self._issued_plans[plan.precondition_hash] = _canonical_json(
            _plan_integrity_payload(plan)
        )
        return plan

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
        errors: list[str] = []
        warnings: list[str] = []
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
            plan.capability == self.capability_name
            and plan.provider == self.provider_name,
            "plan capability/provider identity does not match native_debugger provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        check(
            "provider_instance",
            plan.provenance.get("provider_instance") == self._instance_id,
            "native debugger plan was not issued by this provider instance",
        )
        check(
            "session_id",
            bool(str(plan.session_id or "").strip())
            and len(str(plan.session_id)) <= 256,
            "native debugger session_id must be non-empty and at most 256 characters",
        )
        check(
            "supported_action",
            action in _SUPPORTED_ACTIONS and action == plan.action,
            f"unsupported or non-canonical native_debugger action: {plan.action}",
        )
        check(
            "explicit_authorization",
            plan.parameters.get("authorized") is True,
            "native debugger execution requires explicit authorized=True consent",
            authorization_source=plan.parameters.get("authorization_source"),
        )
        pid = _coerce_int(plan.parameters.get("pid"))
        target_pid = _coerce_int(plan.target.pid)
        check(
            "target_pid",
            bool(pid and pid > 0 and pid != os.getpid())
            and not bool(plan.parameters.get("pid_conflict"))
            and (target_pid is None or target_pid == pid),
            "target PID must be positive, unambiguous, non-self, and match target identity",
            pid=pid,
            target_pid=target_pid,
        )
        parameter_errors = [
            str(item) for item in plan.parameters.get("parameter_errors") or []
        ]
        check(
            "parameters",
            not parameter_errors,
            "; ".join(parameter_errors) if parameter_errors else "parameters are valid",
            errors=parameter_errors,
        )
        check(
            "duration_bound",
            1 <= (_coerce_int(plan.parameters.get("duration_ms")) or 0) <= _MAX_DURATION_MS,
            f"duration_ms must be between 1 and {_MAX_DURATION_MS}",
        )
        check(
            "event_bound",
            1 <= (_coerce_int(plan.parameters.get("max_events")) or 0) <= _MAX_EVENTS,
            f"max_events must be between 1 and {_MAX_EVENTS}",
        )
        check(
            "stack_frame_bound",
            1
            <= (_coerce_int(plan.parameters.get("max_stack_frames")) or 0)
            <= _MAX_STACK_FRAMES,
            f"max_stack_frames must be between 1 and {_MAX_STACK_FRAMES}",
        )
        expected_hash = _plan_precondition_hash(plan)
        check(
            "plan_integrity",
            bool(plan.precondition_hash) and plan.precondition_hash == expected_hash,
            "native debugger plan precondition hash does not match immutable inputs",
            expected=expected_hash,
            actual=plan.precondition_hash,
        )
        check(
            "issued_plan",
            bool(plan.precondition_hash)
            and self._issued_plans.get(str(plan.precondition_hash))
            == _canonical_json(_plan_integrity_payload(plan)),
            "native debugger plan identity was not issued by this provider instance",
        )

        if not _backend_available(backend):
            reason = _backend_reason(backend)
            checks.append(
                {
                    "name": "windows_backend",
                    "status": "unavailable",
                    "message": reason,
                    **_backend_info(backend, self.platform_name),
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
                "message": "Windows native debugger backend is available",
                **_backend_info(backend, self.platform_name),
            }
        )

        if pid and pid > 0 and not errors:
            process = self._probe_process(backend, pid)
            current["process"] = process
            process_ok = (
                process.get("status") == "ok"
                and process.get("accessible") is not False
            )
            check(
                "process_access",
                process_ok,
                "target process is not accessible through the native debugger backend",
                process=process,
            )
            planned_process = _json_mapping(plan.before_snapshot.get("process"))
            identity_ok = process_ok and _process_identity_matches(
                planned_process, process
            )
            check(
                "process_identity",
                identity_ok,
                "target PID or creation-time identity changed after planning",
                planned=_process_identity(planned_process),
                current=_process_identity(process),
            )
            expected_creation_time = _coerce_int(
                plan.parameters.get("expected_creation_time")
            )
            if expected_creation_time is not None:
                check(
                    "requested_creation_time",
                    _coerce_int(process.get("creation_time"))
                    == expected_creation_time,
                    "target creation time does not match the explicitly requested identity",
                    expected=expected_creation_time,
                    actual=process.get("creation_time"),
                )
            support_ok, support_reason = _architecture_support(process)
            if support_ok:
                checks.append(
                    {
                        "name": "architecture_boundary",
                        "status": "ok",
                        "message": "target uses a supported same-bitness x86/x64 context",
                        **_architecture_boundary(process),
                    }
                )
            else:
                checks.append(
                    {
                        "name": "architecture_boundary",
                        "status": "unavailable",
                        "message": support_reason,
                        **_architecture_boundary(process),
                    }
                )
                warnings.append(support_reason)

            requested_arch = _normalize_architecture(
                plan.parameters.get("requested_architecture")
            )
            actual_arch = _normalize_architecture(process.get("architecture"))
            if requested_arch:
                check(
                    "requested_architecture",
                    requested_arch == actual_arch,
                    "requested architecture does not match the live target architecture",
                    requested=requested_arch,
                    actual=actual_arch,
                )

        if not errors and pid and action == "software_breakpoint_trace":
            address = _coerce_int(plan.parameters.get("address"))
            expected_byte = _coerce_int(
                plan.parameters.get("expected_original_byte")
            )
            try:
                if not address or expected_byte is None or not 0 <= expected_byte <= 0xFF:
                    raise ValueError("breakpoint address or expected byte is invalid")
                live = bytes(backend.read(pid, address, 1))
                current["breakpoint"] = {
                    "address": address,
                    "bytes_hex": live.hex(),
                    "expected_hex": f"{expected_byte:02x}",
                }
                planned_hex = str(
                    (_json_mapping(plan.before_snapshot.get("breakpoint"))).get(
                        "bytes_hex"
                    )
                    or ""
                )
                byte_ok = live == bytes([expected_byte]) and (
                    not planned_hex or live.hex() == planned_hex
                )
                check(
                    "breakpoint_preimage",
                    byte_ok,
                    "breakpoint address matches the explicit expected original byte"
                    if byte_ok
                    else "breakpoint address does not match the expected original byte",
                    expected_hex=f"{expected_byte:02x}",
                    actual_hex=live.hex(),
                )
            except Exception as exc:  # noqa: BLE001
                message = f"breakpoint preimage validation failed: {exc}"
                checks.append(
                    {
                        "name": "breakpoint_preimage",
                        "status": "failed",
                        "message": message,
                        "error": _exception_payload(exc),
                    }
                )
                errors.append(message)

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

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        validation, current = self._validate_plan(plan, context=context)
        before_snapshot = _prune(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "execute_validation",
                "captured_at": _utc_now(),
                "target_identity": _target_payload(plan.target),
                "planned": plan.before_snapshot,
                "current": current,
                "validation": validation.to_dict(),
            }
        )
        if not validation.ok:
            return self._build_result(
                plan,
                validation=validation,
                status="failed",
                before_snapshot=before_snapshot,
                outcome={
                    "termination_reason": "validation_failed",
                    "events": [],
                    "operations": [],
                    "context_summaries": [],
                    "errors": list(validation.errors),
                    "cleanup_errors": [],
                    "continuation_count": 0,
                    "all_events_continued": True,
                    "debug_detached": True,
                    "byte_restored": True,
                },
                rollback_plan=_inactive_rollback_plan(
                    plan.rollback_plan,
                    status="blocked",
                    reason="execution was blocked by plan validation",
                ),
            )

        unavailable = _validation_unavailable_reason(validation)
        if unavailable:
            return self._build_result(
                plan,
                validation=validation,
                status="unavailable",
                before_snapshot=before_snapshot,
                outcome={
                    "termination_reason": "dependency_unavailable",
                    "events": [],
                    "operations": [],
                    "context_summaries": [],
                    "errors": [unavailable],
                    "cleanup_errors": [],
                    "continuation_count": 0,
                    "all_events_continued": True,
                    "debug_detached": True,
                    "byte_restored": True,
                },
                rollback_plan=_inactive_rollback_plan(
                    plan.rollback_plan,
                    status="unavailable",
                    reason=unavailable,
                ),
            )

        try:
            outcome = self._run_trace(plan, backend)
        except Exception as exc:  # noqa: BLE001 - provider boundary
            outcome = {
                "termination_reason": "provider_error",
                "events": [],
                "operations": [],
                "context_summaries": [],
                "errors": [_exception_payload(exc)],
                "cleanup_errors": [],
                "continuation_count": 0,
                "all_events_continued": False,
                "debug_detached": False,
                "byte_restored": plan.action != "software_breakpoint_trace",
                "elapsed_ms": 0,
            }
        cleanup_ok = bool(
            outcome.get("debug_detached")
            and outcome.get("byte_restored")
            and outcome.get("all_events_continued")
            and not outcome.get("cleanup_errors")
        )
        status = "ok" if not outcome.get("errors") and cleanup_ok else "failed"
        rollback_plan = {
            **_json_mapping(plan.rollback_plan),
            "supported": True,
            "status": "completed" if cleanup_ok else "cleanup_failed",
            "active": not cleanup_ok,
            "completed": cleanup_ok,
            "restored": cleanup_ok,
            "debug_attached": not bool(outcome.get("debug_detached")),
            "debug_detached": bool(outcome.get("debug_detached")),
            "byte_restored": bool(outcome.get("byte_restored")),
            "pending_single_step_thread_id": outcome.get(
                "pending_single_step_thread_id"
            ),
            "cleanup_errors": list(outcome.get("cleanup_errors") or []),
        }
        return self._build_result(
            plan,
            validation=validation,
            status=status,
            before_snapshot=before_snapshot,
            outcome=outcome,
            rollback_plan=rollback_plan,
        )

    def _run_trace(self, plan: CapabilityPlan, backend: Any) -> dict[str, Any]:
        pid = int(plan.parameters["pid"])
        architecture = str(plan.parameters["architecture"])
        duration_ms = int(plan.parameters["duration_ms"])
        max_events = int(plan.parameters["max_events"])
        poll_interval_ms = int(plan.parameters["poll_interval_ms"])
        max_stack_frames = int(plan.parameters["max_stack_frames"])
        breakpoint_mode = plan.action == "software_breakpoint_trace"
        address = _coerce_int(plan.parameters.get("address"))
        expected_byte_value = _coerce_int(
            plan.parameters.get("expected_original_byte")
        )
        original_byte = (
            bytes([expected_byte_value])
            if expected_byte_value is not None and 0 <= expected_byte_value <= 0xFF
            else b""
        )
        rearm = bool(plan.parameters.get("rearm", True))
        max_hits = int(plan.parameters.get("max_breakpoint_hits") or max_events)

        events: list[dict[str, Any]] = []
        operations: list[dict[str, Any]] = []
        contexts: list[dict[str, Any]] = []
        modules: dict[int, dict[str, Any]] = {}
        threads: dict[int, dict[str, Any]] = {}
        exceptions: list[dict[str, Any]] = []
        call_stacks: list[dict[str, Any]] = []
        crash_evidence: list[dict[str, Any]] = []
        errors: list[Any] = []
        cleanup_errors: list[Any] = []
        attached = False
        process_exited = False
        breakpoint_active = False
        byte_restored = not breakpoint_mode
        pending_thread_id: Optional[int] = None
        continuation_count = 0
        all_events_continued = True
        hit_count = 0
        rearm_count = 0
        initial_breakpoint_seen = False
        termination_reason = "duration"
        started = time.monotonic()
        deadline = started + duration_ms / 1000.0

        try:
            attach_result = backend.attach(pid)
            attached = True
            operations.append(_checked_operation(attach_result, "DebugActiveProcess"))
            operations.append(
                _checked_operation(
                    backend.set_kill_on_exit(False), "DebugSetProcessKillOnExit"
                )
            )
            if breakpoint_mode:
                if not address or not original_byte:
                    raise RuntimeError("validated breakpoint state is incomplete")
                try:
                    self._change_breakpoint_byte(
                        backend,
                        pid=pid,
                        address=address,
                        expected=original_byte,
                        replacement=b"\xcc",
                        operation="install",
                        operations=operations,
                    )
                    breakpoint_active = True
                    byte_restored = False
                except Exception:
                    try:
                        byte_restored = self._restore_original_byte(
                            backend,
                            pid=pid,
                            address=address,
                            original=original_byte,
                            operations=operations,
                        )
                    except Exception as cleanup_exc:  # noqa: BLE001
                        cleanup_errors.append(_exception_payload(cleanup_exc))
                    raise

            # The requested duration is the event-capture window. Attaching a
            # debugger and installing a breakpoint can be delayed by host
            # scanners, so setup time must not consume that window.
            deadline = time.monotonic() + duration_ms / 1000.0

            while True:
                if len(events) >= max_events:
                    termination_reason = "max_events"
                    break
                now = time.monotonic()
                if now >= deadline:
                    termination_reason = "duration"
                    break
                timeout_ms = max(
                    1,
                    min(
                        poll_interval_ms,
                        int(max(0.001, deadline - now) * 1000),
                    ),
                )
                try:
                    raw_event = backend.wait_for_debug_event(timeout_ms)
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))
                    termination_reason = "wait_error"
                    break
                if raw_event is None:
                    continue

                event = _coerce_debug_event(raw_event)
                normalized = {
                    "index": len(events),
                    "timestamp": _utc_now(),
                    "elapsed_ms": int((time.monotonic() - started) * 1000),
                    "debug_event_code": event.code,
                    "pid": event.pid,
                    "thread_id": event.thread_id,
                    **_json_mapping(event.payload),
                }
                events.append(_prune(normalized))
                continue_status = _DBG_CONTINUE
                processing_error: Optional[dict[str, Any]] = None

                try:
                    _update_debug_inventory(normalized, modules, threads)
                    if normalized.get("kind") == "process_exit":
                        process_exited = True
                        termination_reason = "process_exit"
                    elif normalized.get("kind") == "exception":
                        exception_code = _coerce_int(
                            normalized.get("exception_code")
                        )
                        exception_address = _coerce_int(
                            normalized.get("exception_address")
                        )
                        is_target_breakpoint = bool(
                            breakpoint_mode
                            and breakpoint_active
                            and exception_code == _EXCEPTION_BREAKPOINT
                            and address
                            and exception_address == address
                        )
                        is_pending_single_step = bool(
                            exception_code == _EXCEPTION_SINGLE_STEP
                            and pending_thread_id == event.thread_id
                        )
                        if is_target_breakpoint:
                            hit_count += 1
                            self._change_breakpoint_byte(
                                backend,
                                pid=pid,
                                address=int(address),
                                expected=b"\xcc",
                                replacement=original_byte,
                                operation="breakpoint_hit_restore",
                                operations=operations,
                            )
                            breakpoint_active = False
                            byte_restored = True
                            should_rearm = bool(
                                rearm
                                and hit_count < max_hits
                                and len(events) < max_events
                                and time.monotonic() < deadline
                            )
                            updated = _backend_update_context(
                                backend,
                                event.thread_id,
                                architecture,
                                instruction_pointer=int(address),
                                trap_flag=should_rearm,
                                suspend=False,
                            )
                            summary = {
                                "reason": "software_breakpoint_hit",
                                "event_index": normalized["index"],
                                **_json_mapping(updated),
                            }
                            contexts.append(_prune(summary))
                            normalized["classification"] = "software_breakpoint_hit"
                            normalized["breakpoint_hit"] = hit_count
                            normalized["context"] = _prune(summary)
                            pending_thread_id = (
                                event.thread_id if should_rearm else None
                            )
                            continue_status = _DBG_CONTINUE
                        elif is_pending_single_step:
                            updated = _backend_update_context(
                                backend,
                                event.thread_id,
                                architecture,
                                trap_flag=False,
                                suspend=False,
                            )
                            summary = {
                                "reason": "software_breakpoint_single_step",
                                "event_index": normalized["index"],
                                **_json_mapping(updated),
                            }
                            contexts.append(_prune(summary))
                            normalized["classification"] = "single_step_rearm"
                            normalized["context"] = _prune(summary)
                            pending_thread_id = None
                            if (
                                rearm
                                and hit_count < max_hits
                                and len(events) < max_events
                                and time.monotonic() < deadline
                            ):
                                self._change_breakpoint_byte(
                                    backend,
                                    pid=pid,
                                    address=int(address),
                                    expected=original_byte,
                                    replacement=b"\xcc",
                                    operation="rearm",
                                    operations=operations,
                                )
                                breakpoint_active = True
                                byte_restored = False
                                rearm_count += 1
                            continue_status = _DBG_CONTINUE
                        else:
                            try:
                                context_summary = _backend_capture_context(
                                    backend,
                                    event.thread_id,
                                    architecture,
                                    suspend=False,
                                )
                                summary = {
                                    "reason": "exception_observation",
                                    "event_index": normalized["index"],
                                    **_json_mapping(context_summary),
                                }
                                contexts.append(_prune(summary))
                                normalized["context"] = _prune(summary)
                                stack = _capture_bounded_call_stack(
                                    backend,
                                    pid=pid,
                                    architecture=architecture,
                                    context_summary=summary,
                                    modules=modules,
                                    max_frames=max_stack_frames,
                                    event_index=int(normalized["index"]),
                                    thread_id=event.thread_id,
                                )
                                call_stacks.append(stack)
                                normalized["call_stack"] = stack
                            except Exception as context_exc:  # noqa: BLE001
                                normalized["context_error"] = _exception_payload(
                                    context_exc
                                )
                            if (
                                exception_code == _EXCEPTION_BREAKPOINT
                                and not initial_breakpoint_seen
                            ):
                                initial_breakpoint_seen = True
                                normalized["classification"] = (
                                    "debugger_initial_breakpoint"
                                )
                                continue_status = _DBG_CONTINUE
                            else:
                                normalized["classification"] = (
                                    "exception_not_handled"
                                )
                                continue_status = _DBG_EXCEPTION_NOT_HANDLED
                        exception_evidence = _exception_evidence(normalized)
                        exceptions.append(exception_evidence)
                        if exception_evidence.get("crash_candidate"):
                            crash = {
                                **exception_evidence,
                                "call_stack": normalized.get("call_stack"),
                                "process_identity": plan.provenance.get(
                                    "process_identity"
                                ),
                            }
                            crash_evidence.append(_prune(crash))
                except Exception as exc:  # noqa: BLE001 - event is continued below
                    processing_error = _exception_payload(exc)
                    normalized["processing_error"] = processing_error
                    errors.append(processing_error)
                    termination_reason = "event_processing_error"
                    if normalized.get("kind") == "exception":
                        continue_status = _DBG_EXCEPTION_NOT_HANDLED
                finally:
                    continuation_error: Optional[dict[str, Any]] = None
                    try:
                        operation = _checked_operation(
                            backend.continue_debug_event(
                                event.pid, event.thread_id, continue_status
                            ),
                            "ContinueDebugEvent",
                        )
                        operations.append(operation)
                        continuation_count += 1
                        normalized["continued"] = True
                        normalized["continue_status"] = continue_status
                    except Exception as exc:  # noqa: BLE001
                        continuation_error = _exception_payload(exc)
                        errors.append(continuation_error)
                        normalized["continued"] = False
                        normalized["continue_error"] = continuation_error
                        all_events_continued = False
                        termination_reason = "continue_error"
                    finally:
                        try:
                            _backend_release_event(backend, raw_event)
                        except Exception as exc:  # noqa: BLE001
                            release_error = _exception_payload(exc)
                            cleanup_errors.append(release_error)
                            normalized["release_error"] = release_error
                    events[-1] = _prune(normalized)
                if process_exited or processing_error or continuation_error:
                    break
        except Exception as exc:  # noqa: BLE001 - cleanup is mandatory
            errors.append(_exception_payload(exc))
            termination_reason = "execution_error"
        finally:
            if pending_thread_id is not None and not process_exited:
                try:
                    cleared = _backend_update_context(
                        backend,
                        pending_thread_id,
                        architecture,
                        trap_flag=False,
                        suspend=True,
                    )
                    contexts.append(
                        _prune(
                            {
                                "reason": "cleanup_clear_trap_flag",
                                **_json_mapping(cleared),
                            }
                        )
                    )
                    pending_thread_id = None
                except Exception as exc:  # noqa: BLE001
                    cleanup_errors.append(_exception_payload(exc))

            if breakpoint_mode:
                if process_exited:
                    breakpoint_active = False
                    byte_restored = True
                elif address and original_byte:
                    try:
                        byte_restored = self._restore_original_byte(
                            backend,
                            pid=pid,
                            address=address,
                            original=original_byte,
                            operations=operations,
                        )
                        breakpoint_active = False
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append(_exception_payload(exc))
                        byte_restored = False

            debug_detached = not attached
            if attached:
                if process_exited:
                    debug_detached = True
                    attached = False
                else:
                    try:
                        operations.append(
                            _checked_operation(
                                backend.detach(pid), "DebugActiveProcessStop"
                            )
                        )
                        debug_detached = True
                        attached = False
                    except Exception as exc:  # noqa: BLE001
                        cleanup_errors.append(_exception_payload(exc))
                        debug_detached = False

        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "termination_reason": termination_reason,
            "requested_duration_ms": duration_ms,
            "elapsed_ms": elapsed_ms,
            "max_events": max_events,
            "event_count": len(events),
            "events": events,
            "event_counts": dict(
                sorted(Counter(str(item.get("kind") or "unknown") for item in events).items())
            ),
            "operations": operations,
            "context_summaries": contexts,
            "module_inventory": _finalize_module_inventory(modules),
            "thread_inventory": _finalize_thread_inventory(threads),
            "exceptions": exceptions,
            "call_stacks": call_stacks,
            "crash_evidence": crash_evidence,
            "errors": errors,
            "cleanup_errors": cleanup_errors,
            "continuation_count": continuation_count,
            "all_events_continued": all_events_continued
            and continuation_count == len(events),
            "debug_detached": debug_detached,
            "process_exited": process_exited,
            "breakpoint_installed": breakpoint_mode,
            "breakpoint_active": breakpoint_active,
            "breakpoint_hit_count": hit_count,
            "breakpoint_rearm_count": rearm_count,
            "byte_restored": byte_restored,
            "pending_single_step_thread_id": pending_thread_id,
            "bounded": True,
        }

    def _change_breakpoint_byte(
        self,
        backend: Any,
        *,
        pid: int,
        address: int,
        expected: bytes,
        replacement: bytes,
        operation: str,
        operations: list[dict[str, Any]],
    ) -> None:
        current = bytes(backend.read(pid, address, 1))
        operations.append(
            _memory_observation(f"{operation}_preimage", address, current)
        )
        if current != expected:
            raise RuntimeError(
                f"{operation} expected byte {expected.hex()} at 0x{address:x}, "
                f"found {current.hex()}"
            )
        protected = _checked_operation(
            backend.protect(pid, address, 1, _PAGE_EXECUTE_READWRITE),
            f"VirtualProtectEx({operation},writable)",
        )
        operations.append(protected)
        old_protection = _coerce_int(protected.get("old_protection"))
        if old_protection is None:
            raise RuntimeError("VirtualProtectEx did not report original protection")
        protection_restored = False
        try:
            locked = bytes(backend.read(pid, address, 1))
            operations.append(
                _memory_observation(f"{operation}_locked_preimage", address, locked)
            )
            if locked != expected:
                raise RuntimeError(
                    f"{operation} preimage changed after VirtualProtectEx"
                )
            operations.append(
                _checked_operation(
                    backend.write(pid, address, replacement),
                    f"WriteProcessMemory({operation})",
                )
            )
            verified = bytes(backend.read(pid, address, 1))
            operations.append(
                _memory_observation(f"{operation}_verify", address, verified)
            )
            if verified != replacement:
                raise RuntimeError(f"{operation} write verification failed")
            operations.append(
                _checked_operation(
                    backend.flush_instruction_cache(pid, address, 1),
                    f"FlushInstructionCache({operation})",
                )
            )
        finally:
            restored = _checked_operation(
                backend.protect(pid, address, 1, old_protection),
                f"VirtualProtectEx({operation},restore)",
            )
            operations.append(restored)
            protection_restored = True
        if not protection_restored:
            raise RuntimeError(f"{operation} page protection was not restored")

    def _restore_original_byte(
        self,
        backend: Any,
        *,
        pid: int,
        address: int,
        original: bytes,
        operations: list[dict[str, Any]],
    ) -> bool:
        current = bytes(backend.read(pid, address, 1))
        operations.append(_memory_observation("cleanup_preimage", address, current))
        if current == original:
            return True
        if current != b"\xcc":
            raise RuntimeError(
                "breakpoint byte changed to an unknown value; refusing cleanup overwrite"
            )
        self._change_breakpoint_byte(
            backend,
            pid=pid,
            address=address,
            expected=b"\xcc",
            replacement=original,
            operation="cleanup_restore",
            operations=operations,
        )
        return bytes(backend.read(pid, address, 1)) == original

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        self._require_owned_result(result)
        rollback_plan = _json_mapping(result.rollback_plan)
        if rollback_plan.get("completed") is True and not rollback_plan.get("active"):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=True,
                restored=True,
                details={
                    "status": "already_completed",
                    "debug_detached": rollback_plan.get("debug_detached", True),
                    "byte_restored": rollback_plan.get("byte_restored", True),
                },
            )

        backend = self._select_backend(context)
        pid = _coerce_int(rollback_plan.get("pid"))
        errors: list[Any] = []
        operations: list[dict[str, Any]] = []
        byte_restored = bool(rollback_plan.get("byte_restored"))
        debug_detached = bool(rollback_plan.get("debug_detached"))
        pending_thread_id = _coerce_int(
            rollback_plan.get("pending_single_step_thread_id")
        )
        architecture = _normalize_architecture(
            _result_plan_parameters(result).get("architecture")
        )

        process = self._probe_process(backend, pid)
        planned_process = _planned_process_snapshot(result)
        process_identity_ok = bool(
            process.get("status") == "ok"
            and _process_identity_matches(planned_process, process)
        )
        needs_live_cleanup = bool(
            not debug_detached
            or pending_thread_id is not None
            or (
                result.action == "software_breakpoint_trace"
                and not byte_restored
            )
        )
        if needs_live_cleanup and not process_identity_ok:
            errors.append(
                {
                    "type": "RuntimeError",
                    "message": "target process identity changed before rollback",
                    "planned": _process_identity(planned_process),
                    "current": _process_identity(process),
                }
            )
        else:
            if pending_thread_id and architecture:
                try:
                    operation = _backend_update_context(
                        backend,
                        pending_thread_id,
                        architecture,
                        trap_flag=False,
                        suspend=True,
                    )
                    operations.append(_json_mapping(operation))
                    pending_thread_id = None
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))

            if result.action == "software_breakpoint_trace" and pid:
                parameters = _result_plan_parameters(result)
                address = _coerce_int(parameters.get("address"))
                expected_byte = _coerce_int(
                    parameters.get("expected_original_byte")
                )
                if address and expected_byte is not None:
                    try:
                        byte_restored = self._restore_original_byte(
                            backend,
                            pid=pid,
                            address=address,
                            original=bytes([expected_byte]),
                            operations=operations,
                        )
                    except Exception as exc:  # noqa: BLE001
                        errors.append(_exception_payload(exc))
                        byte_restored = False

            if not debug_detached and pid:
                try:
                    operations.append(
                        _checked_operation(
                            backend.detach(pid), "DebugActiveProcessStop(rollback)"
                        )
                    )
                    debug_detached = True
                except Exception as exc:  # noqa: BLE001
                    errors.append(_exception_payload(exc))

        restored = bool(
            not errors
            and byte_restored
            and debug_detached
            and pending_thread_id is None
        )
        status = "completed" if restored else "failed"
        result.rollback_plan.update(
            {
                "status": status,
                "active": not restored,
                "completed": restored,
                "restored": restored,
                "byte_restored": byte_restored,
                "debug_detached": debug_detached,
                "debug_attached": not debug_detached,
                "pending_single_step_thread_id": pending_thread_id,
                "rollback_errors": errors,
                "rollback_operations": operations,
            }
        )
        result.report_section["rollback_status"] = status
        result.report_section["restored"] = restored
        recorded_at = _utc_now()
        result.dashboard_trace.append(
            {
                "kind": "native_debugger_rollback",
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
                    "message": "native debugger rollback completed",
                    "status": status,
                    "restored": restored,
                }
            )
        self._issue_result_identity(result)
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=restored,
            restored=restored,
            details={
                "status": status,
                "byte_restored": byte_restored,
                "debug_detached": debug_detached,
                "errors": errors,
                "operations": operations,
            },
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
        specs = _session_artifact_specs(result.session_id)
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
            "termination_reason": result.after_snapshot.get("termination_reason"),
            "lifecycle_events": lifecycle_events,
            "debug_events": list(result.after_snapshot.get("events") or []),
            "context_summaries": list(
                result.after_snapshot.get("context_summaries") or []
            ),
        }
        diagnostics_payload = {
            "schema_version": 1,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "module_inventory": list(
                result.after_snapshot.get("module_inventory") or []
            ),
            "thread_inventory": list(
                result.after_snapshot.get("thread_inventory") or []
            ),
            "exceptions": list(result.after_snapshot.get("exceptions") or []),
            "call_stacks": list(result.after_snapshot.get("call_stacks") or []),
            "crash_evidence": list(
                result.after_snapshot.get("crash_evidence") or []
            ),
        }
        audit_meta = _atomic_write_json(
            paths["native-debugger-audit"], audit_payload
        )
        events_meta = _atomic_write_json(
            paths["native-debugger-events"], event_payload
        )
        diagnostics_meta = _atomic_write_json(
            paths["native-debugger-diagnostics"], diagnostics_payload
        )
        manifest_payload = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "generated_at": _utc_now(),
            "artifacts": [
                {
                    **entry,
                    "sha256": metadata["sha256"],
                    "size": metadata["size"],
                }
                for entry, metadata in (
                    (evidence_entries[0], audit_meta),
                    (evidence_entries[1], events_meta),
                    (evidence_entries[2], diagnostics_meta),
                )
            ],
        }
        manifest_meta = _atomic_write_json(
            paths["native-debugger-manifest"], manifest_payload
        )
        metadata_by_kind = {
            "native-debugger-audit": audit_meta,
            "native-debugger-events": events_meta,
            "native-debugger-diagnostics": diagnostics_meta,
            "native-debugger-manifest": manifest_meta,
        }
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

    def _build_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before_snapshot: Mapping[str, Any],
        outcome: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
    ) -> CapabilityExecutionResult:
        completed_at = _utc_now()
        lifecycle_events = [
            {
                "kind": "plan",
                "ts": completed_at,
                "message": "native debugger plan created",
                "action": plan.action,
            },
            {
                "kind": "validate",
                "ts": completed_at,
                "message": "native debugger plan validated",
                "ok": validation.ok,
                "warning_count": len(validation.warnings),
                "error_count": len(validation.errors),
            },
            {
                "kind": "execute",
                "ts": completed_at,
                "message": "native debugger execution completed",
                "status": status,
            },
        ]
        specs = _session_artifact_specs(plan.session_id)
        artifacts = [
            CapabilityArtifact(
                path=spec["path"],
                kind=spec["kind"],
                description=spec["description"],
                metadata={"materialized": False, "session_id": plan.session_id},
            )
            for spec in specs
        ]
        evidence_entries = [
            _artifact_manifest_entry(item, status=status) for item in artifacts
        ]
        events = [_json_mapping(item) for item in outcome.get("events") or []]
        contexts = [
            _json_mapping(item) for item in outcome.get("context_summaries") or []
        ]
        operations = [_json_mapping(item) for item in outcome.get("operations") or []]
        module_inventory = [
            _json_mapping(item) for item in outcome.get("module_inventory") or []
        ]
        thread_inventory = [
            _json_mapping(item) for item in outcome.get("thread_inventory") or []
        ]
        exceptions = [
            _json_mapping(item) for item in outcome.get("exceptions") or []
        ]
        call_stacks = [
            _json_mapping(item) for item in outcome.get("call_stacks") or []
        ]
        crash_evidence = [
            _json_mapping(item) for item in outcome.get("crash_evidence") or []
        ]
        normalized_errors = [_json_value(item) for item in outcome.get("errors") or []]
        cleanup_errors = [
            _json_value(item) for item in outcome.get("cleanup_errors") or []
        ]
        after_snapshot = _prune(
            {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "execute",
                "captured_at": completed_at,
                "target_identity": _target_payload(plan.target),
                "process_identity": plan.provenance.get("process_identity"),
                "status": status,
                "termination_reason": outcome.get("termination_reason"),
                "requested_duration_ms": outcome.get("requested_duration_ms"),
                "elapsed_ms": outcome.get("elapsed_ms", 0),
                "max_events": outcome.get("max_events", plan.parameters.get("max_events")),
                "event_count": len(events),
                "event_counts": outcome.get("event_counts") or {},
                "events": events,
                "context_summaries": contexts,
                "module_inventory": module_inventory,
                "thread_inventory": thread_inventory,
                "exceptions": exceptions,
                "call_stacks": call_stacks,
                "crash_evidence": crash_evidence,
                "operations": operations,
                "errors": normalized_errors,
                "cleanup_errors": cleanup_errors,
                "continuation_count": outcome.get("continuation_count", 0),
                "all_events_continued": outcome.get("all_events_continued", False),
                "debug_detached": outcome.get("debug_detached", False),
                "process_exited": outcome.get("process_exited", False),
                "breakpoint": {
                    "installed": outcome.get("breakpoint_installed", False),
                    "active": outcome.get("breakpoint_active", False),
                    "hit_count": outcome.get("breakpoint_hit_count", 0),
                    "rearm_count": outcome.get("breakpoint_rearm_count", 0),
                    "byte_restored": outcome.get("byte_restored", False),
                    "pending_single_step_thread_id": outcome.get(
                        "pending_single_step_thread_id"
                    ),
                },
                "bounded": outcome.get("bounded", True),
            }
        )
        final_rollback_plan = _json_mapping(rollback_plan)
        final_rollback_plan.setdefault("supported", True)
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
                "simulated": False,
                "termination_reason": outcome.get("termination_reason"),
                "event_count": len(events),
                "event_counts": outcome.get("event_counts") or {},
                "breakpoint_hit_count": outcome.get("breakpoint_hit_count", 0),
                "context_summary_count": len(contexts),
                "module_count": len(module_inventory),
                "thread_count": len(thread_inventory),
                "exception_count": len(exceptions),
                "call_stack_count": len(call_stacks),
                "crash_detected": bool(crash_evidence),
                "continuation_count": outcome.get("continuation_count", 0),
                "all_events_continued": outcome.get("all_events_continued", False),
                "debug_detached": outcome.get("debug_detached", False),
                "byte_restored": outcome.get("byte_restored", False),
                "rollback_supported": bool(final_rollback_plan.get("supported")),
                "rollback_status": final_rollback_plan.get("status"),
                "errors": normalized_errors,
                "cleanup_errors": cleanup_errors,
            }
        )
        dashboard_trace = [
            {
                "kind": "native_debugger_execution",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "action": plan.action,
                "status": status,
                "session_id": plan.session_id,
                "pid": plan.parameters.get("pid"),
                "termination_reason": outcome.get("termination_reason"),
                "event_count": len(events),
                "breakpoint_hit_count": outcome.get("breakpoint_hit_count", 0),
                "exception_count": len(exceptions),
                "crash_detected": bool(crash_evidence),
                "debug_detached": outcome.get("debug_detached", False),
                "byte_restored": outcome.get("byte_restored", False),
            }
        ]
        dashboard_trace.extend(
            {
                "kind": "native_debugger_event",
                "session_id": plan.session_id,
                "event_index": item.get("index"),
                "event_kind": item.get("kind"),
                "thread_id": item.get("thread_id"),
                "exception_code": item.get("exception_code"),
                "classification": item.get("classification"),
            }
            for item in events[:64]
            if item.get("kind") in {"exception", "process_exit", "debug_string"}
        )
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
            dashboard_trace=[_prune(item) for item in dashboard_trace],
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
                    "simulated": False,
                }
            ),
        )
        self._issue_result_identity(result)
        return result

    def _probe_process(self, backend: Any, pid: Optional[int]) -> dict[str, Any]:
        if not pid or pid <= 0:
            return {
                "status": "failed",
                "accessible": False,
                "pid": pid,
                "reason": "invalid PID",
            }
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

    def _select_backend(self, context: Optional[dict[str, Any]]) -> NativeDebuggerBackend:
        if (
            isinstance(context, Mapping)
            and context.get("native_debugger_backend") is not None
        ):
            return context["native_debugger_backend"]
        return self.backend

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
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            raise ValueError(
                "capability result does not belong to native_debugger provider"
            )
        supplied = (
            result.provenance.get(_RESULT_IDENTITY_KEY)
            if isinstance(result.provenance, Mapping)
            else None
        )
        if not isinstance(supplied, Mapping):
            raise ValueError("native_debugger result identity is missing")
        if supplied.get("provider_instance") != self._instance_id:
            raise ValueError(
                "native_debugger result was not issued by this provider instance"
            )
        canonical = _canonical_json(_result_identity_payload(result))
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
            raise ValueError("native_debugger result identity does not match contents")
        if self._issued_results.get(digest) != canonical:
            raise ValueError(
                "native_debugger result was not issued by this provider instance"
            )
        if str(result.provenance.get("precondition_hash") or "") not in self._issued_plans:
            raise ValueError("native_debugger result references an unknown plan")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _debugger_architecture() -> str:
    machine = platform.machine().strip().lower().replace("-", "_")
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    return "x64" if struct.calcsize("P") == 8 else "x86"


def _pointer_value(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    raw = getattr(value, "value", value)
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


def _valid_handles(*values: Any) -> list[int]:
    return [
        value
        for value in (_pointer_value(item) for item in values)
        if value and value != _INVALID_HANDLE_VALUE
    ]


def _context_summary(context: Any, architecture: str, thread_id: int) -> dict[str, Any]:
    if architecture == "x64":
        registers = {
            "rax": int(context.Rax),
            "rbx": int(context.Rbx),
            "rcx": int(context.Rcx),
            "rdx": int(context.Rdx),
            "rsi": int(context.Rsi),
            "rdi": int(context.Rdi),
            "r8": int(context.R8),
            "r9": int(context.R9),
            "r10": int(context.R10),
            "r11": int(context.R11),
            "r12": int(context.R12),
            "r13": int(context.R13),
            "r14": int(context.R14),
            "r15": int(context.R15),
        }
        instruction_pointer = int(context.Rip)
        stack_pointer = int(context.Rsp)
        frame_pointer = int(context.Rbp)
    else:
        registers = {
            "eax": int(context.Eax),
            "ebx": int(context.Ebx),
            "ecx": int(context.Ecx),
            "edx": int(context.Edx),
            "esi": int(context.Esi),
            "edi": int(context.Edi),
        }
        instruction_pointer = int(context.Eip)
        stack_pointer = int(context.Esp)
        frame_pointer = int(context.Ebp)
    flags = int(context.EFlags)
    return {
        "thread_id": int(thread_id),
        "architecture": architecture,
        "instruction_pointer": instruction_pointer,
        "stack_pointer": stack_pointer,
        "frame_pointer": frame_pointer,
        "flags": flags,
        "trap_flag": bool(flags & _TRAP_FLAG),
        "registers": registers,
    }


def _normalize_action(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(normalized, normalized)


def _normalize_architecture(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "x86": "x86",
        "i386": "x86",
        "i686": "x86",
        "32": "x86",
        "x64": "x64",
        "amd64": "x64",
        "x86_64": "x64",
        "64": "x64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    return aliases.get(normalized)


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return None


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return default


def _first_value(values: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in values and values[name] not in (None, ""):
            return values[name]
    return None


def _bounded_integer(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    name: str,
    errors: list[str],
) -> int:
    if value is None:
        return default
    parsed = _coerce_int(value)
    if parsed is None or not minimum <= parsed <= maximum:
        errors.append(f"{name} must be between {minimum} and {maximum}")
        return default
    return parsed


def _duration_ms(params: Mapping[str, Any], errors: list[str]) -> int:
    if params.get("duration_ms") is not None:
        return _bounded_integer(
            params.get("duration_ms"),
            default=_DEFAULT_DURATION_MS,
            minimum=1,
            maximum=_MAX_DURATION_MS,
            name="duration_ms",
            errors=errors,
        )
    if params.get("duration") is not None:
        try:
            duration = float(params["duration"])
            milliseconds = int(duration * 1000)
        except (TypeError, ValueError, OverflowError):
            errors.append("duration must be a positive number of seconds")
            return _DEFAULT_DURATION_MS
        if not 1 <= milliseconds <= _MAX_DURATION_MS:
            errors.append(
                f"duration must resolve to between 1 and {_MAX_DURATION_MS} milliseconds"
            )
            return _DEFAULT_DURATION_MS
        return milliseconds
    return _DEFAULT_DURATION_MS


def _parse_expected_byte(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (bytes, bytearray)):
        return int(value[0]) if len(value) == 1 else None
    if isinstance(value, int):
        return value if 0 <= value <= 0xFF else None
    text = str(value).strip().lower().replace(" ", "")
    if text.startswith("\\x"):
        text = text[2:]
    try:
        parsed = int(text, 16) if not text.startswith("0x") else int(text, 0)
    except ValueError:
        return None
    return parsed if 0 <= parsed <= 0xFF else None


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", False))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "Windows native debugger backend is unavailable"
    )


def _backend_info(backend: Any, platform_name: str) -> dict[str, Any]:
    return {
        "name": str(getattr(backend, "name", type(backend).__name__)),
        "available": _backend_available(backend),
        "reason": None if _backend_available(backend) else _backend_reason(backend),
        "platform": platform_name,
        "production": bool(getattr(backend, "production", False)),
        "simulated": False,
    }


def _architecture_boundary(process: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target_architecture": _normalize_architecture(process.get("architecture"))
        or process.get("architecture"),
        "debugger_architecture": _normalize_architecture(
            process.get("debugger_architecture")
        )
        or process.get("debugger_architecture")
        or _debugger_architecture(),
        "wow64": bool(process.get("wow64", False)),
        "context_supported": process.get("context_supported"),
        "context_api": process.get("context_api"),
        "reason": process.get("architecture_reason"),
    }


def _architecture_support(process: Mapping[str, Any]) -> tuple[bool, str]:
    target = _normalize_architecture(process.get("architecture"))
    debugger = (
        _normalize_architecture(process.get("debugger_architecture"))
        or _debugger_architecture()
    )
    wow64 = bool(process.get("wow64", False))
    supported = bool(
        target in {"x86", "x64"}
        and target == debugger
        and process.get("context_supported") is not False
    )
    if supported:
        return True, "same-bitness native thread context is supported"
    explicit_reason = str(process.get("architecture_reason") or "").strip()
    if explicit_reason:
        return False, explicit_reason
    if wow64 and debugger == "x64" and target == "x86":
        return (
            False,
            "WOW64 targets are not supported by the x64 context implementation; "
            "use a same-bitness x86 debugger",
        )
    return (
        False,
        f"same-bitness x86/x64 debugging is required (debugger={debugger}, target={target})",
    )


def _process_identity(process: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "pid": _coerce_int(process.get("pid")),
            "creation_time": _coerce_int(process.get("creation_time")),
            "image_path": process.get("image_path"),
            "architecture": process.get("architecture"),
            "wow64": process.get("wow64"),
        }
    )


def _normalized_path(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    return os.path.normcase(os.path.normpath(text))


def _process_identity_matches(
    planned: Mapping[str, Any], current: Mapping[str, Any]
) -> bool:
    planned_pid = _coerce_int(planned.get("pid"))
    current_pid = _coerce_int(current.get("pid"))
    planned_creation = _coerce_int(planned.get("creation_time"))
    current_creation = _coerce_int(current.get("creation_time"))
    if not planned_pid or planned_pid != current_pid:
        return False
    if planned_creation is None or current_creation is None:
        return False
    if planned_creation != current_creation:
        return False
    planned_path = _normalized_path(planned.get("image_path"))
    current_path = _normalized_path(current.get("image_path"))
    if planned_path and current_path and planned_path != current_path:
        return False
    planned_arch = _normalize_architecture(planned.get("architecture"))
    current_arch = _normalize_architecture(current.get("architecture"))
    if planned_arch and current_arch and planned_arch != current_arch:
        return False
    return True


def _target_payload(target: TargetIdentity) -> dict[str, Any]:
    to_dict = getattr(target, "to_dict", None)
    if callable(to_dict):
        return _json_mapping(to_dict())
    return _prune(
        {
            "kind": target.kind,
            "path": target.path,
            "pid": target.pid,
            "sha256": target.sha256,
            "display_name": target.display_name,
            "metadata": target.metadata,
        }
    )


def _plan_integrity_payload(plan: CapabilityPlan) -> dict[str, Any]:
    rollback_plan = _json_mapping(plan.rollback_plan)
    rollback_plan.pop("precondition_hash", None)
    provenance = _json_mapping(plan.provenance)
    provenance.pop("precondition_hash", None)
    return {
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "target": _target_payload(plan.target),
        "action": plan.action,
        "parameters": _json_mapping(plan.parameters),
        "steps": [_json_mapping(item) for item in plan.steps],
        "before_snapshot": _json_mapping(plan.before_snapshot),
        "rollback_plan": rollback_plan,
        "provenance": provenance,
    }


def _plan_precondition_hash(plan: CapabilityPlan) -> str:
    payload = _canonical_json(_plan_integrity_payload(plan)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validation_unavailable_reason(
    validation: CapabilityValidation,
) -> Optional[str]:
    reasons = [
        str(check.get("message") or "native debugger dependency is unavailable")
        for check in validation.checks
        if str(check.get("status") or "").lower() == "unavailable"
    ]
    return "; ".join(dict.fromkeys(reasons)) or None


def _inactive_rollback_plan(
    value: Mapping[str, Any], *, status: str, reason: str
) -> dict[str, Any]:
    rollback_plan = _json_mapping(value)
    rollback_plan.update(
        {
            "supported": True,
            "status": status,
            "active": False,
            "completed": True,
            "restored": True,
            "byte_restored": True,
            "debug_detached": True,
            "debug_attached": False,
            "reason": reason,
        }
    )
    return rollback_plan


def _event_kind_for_code(code: int) -> str:
    return {
        _EXCEPTION_DEBUG_EVENT: "exception",
        _CREATE_THREAD_DEBUG_EVENT: "thread_create",
        _CREATE_PROCESS_DEBUG_EVENT: "process_create",
        _EXIT_THREAD_DEBUG_EVENT: "thread_exit",
        _EXIT_PROCESS_DEBUG_EVENT: "process_exit",
        _LOAD_DLL_DEBUG_EVENT: "module_load",
        _UNLOAD_DLL_DEBUG_EVENT: "module_unload",
        _OUTPUT_DEBUG_STRING_EVENT: "debug_string",
        _RIP_EVENT: "rip",
    }.get(code, "unknown")


def _coerce_debug_event(value: Any) -> NativeDebugEvent:
    if isinstance(value, NativeDebugEvent):
        return value
    if isinstance(value, Mapping):
        mapping = _json_mapping(value)
        code = _coerce_int(
            _first_value(mapping, "code", "debug_event_code", "event_code")
        ) or 0
        pid = _coerce_int(_first_value(mapping, "pid", "process_id")) or 0
        thread_id = _coerce_int(
            _first_value(mapping, "thread_id", "tid")
        ) or 0
        payload = _json_mapping(mapping.get("payload"))
        for key, item in mapping.items():
            if key not in {
                "code",
                "debug_event_code",
                "event_code",
                "pid",
                "process_id",
                "thread_id",
                "tid",
                "payload",
                "resources",
            }:
                payload.setdefault(key, item)
        payload.setdefault("kind", _event_kind_for_code(code))
        resources = tuple(
            item
            for item in (_coerce_int(entry) for entry in mapping.get("resources") or [])
            if item
        )
        return NativeDebugEvent(code, pid, thread_id, payload, resources)
    code = _coerce_int(getattr(value, "code", None)) or 0
    pid = _coerce_int(getattr(value, "pid", None)) or 0
    thread_id = _coerce_int(getattr(value, "thread_id", None)) or 0
    payload = _json_mapping(getattr(value, "payload", None))
    payload.setdefault("kind", _event_kind_for_code(code))
    return NativeDebugEvent(code, pid, thread_id, payload)


def _backend_release_event(backend: Any, event: Any) -> None:
    release = getattr(backend, "release_event", None)
    if callable(release):
        release(event)


def _backend_capture_context(
    backend: Any,
    thread_id: int,
    architecture: str,
    *,
    suspend: bool,
) -> dict[str, Any]:
    capture = getattr(backend, "capture_thread_context", None)
    if callable(capture):
        return _json_mapping(
            capture(thread_id, architecture, suspend=suspend)
        )
    capture = getattr(backend, "get_thread_context", None)
    if callable(capture):
        return _json_mapping(
            capture(thread_id, architecture=architecture, suspend=suspend)
        )
    raise NativeDebuggerBackendError(
        "GetThreadContext", "backend does not implement context capture"
    )


def _backend_update_context(
    backend: Any,
    thread_id: int,
    architecture: str,
    *,
    instruction_pointer: Optional[int] = None,
    trap_flag: Optional[bool] = None,
    suspend: bool,
) -> dict[str, Any]:
    update = getattr(backend, "update_thread_context", None)
    if callable(update):
        return _json_mapping(
            update(
                thread_id,
                architecture,
                instruction_pointer=instruction_pointer,
                trap_flag=trap_flag,
                suspend=suspend,
            )
        )
    update = getattr(backend, "set_thread_context", None)
    if callable(update):
        return _json_mapping(
            update(
                thread_id,
                architecture=architecture,
                instruction_pointer=instruction_pointer,
                trap_flag=trap_flag,
                suspend=suspend,
            )
        )
    raise NativeDebuggerBackendError(
        "SetThreadContext", "backend does not implement context updates"
    )


def _update_debug_inventory(
    event: Mapping[str, Any],
    modules: dict[int, dict[str, Any]],
    threads: dict[int, dict[str, Any]],
) -> None:
    kind = str(event.get("kind") or "unknown")
    event_index = _coerce_int(event.get("index")) or 0
    timestamp = event.get("timestamp")
    thread_id = _coerce_int(event.get("thread_id"))
    if kind in {"process_create", "thread_create"} and thread_id:
        threads[thread_id] = _prune(
            {
                "thread_id": thread_id,
                "status": "active",
                "created_event_index": event_index,
                "created_at": timestamp,
                "start_address": event.get("start_address"),
                "thread_local_base": event.get("thread_local_base"),
                "is_initial_thread": kind == "process_create",
            }
        )
    elif kind == "thread_exit" and thread_id:
        item = threads.setdefault(
            thread_id,
            {
                "thread_id": thread_id,
                "created_event_index": None,
            },
        )
        item.update(
            _prune(
                {
                    "status": "exited",
                    "exit_code": event.get("exit_code"),
                    "exited_event_index": event_index,
                    "exited_at": timestamp,
                }
            )
        )

    if kind in {"process_create", "module_load"}:
        base = _coerce_int(event.get("base_address"))
        if base:
            modules[base] = _prune(
                {
                    "base_address": base,
                    "base_address_hex": f"0x{base:x}",
                    "image_path": event.get("image_path"),
                    "status": "loaded",
                    "loaded_event_index": event_index,
                    "loaded_at": timestamp,
                    "is_main_image": kind == "process_create",
                }
            )
    elif kind == "module_unload":
        base = _coerce_int(event.get("base_address"))
        if base:
            item = modules.setdefault(
                base,
                {
                    "base_address": base,
                    "base_address_hex": f"0x{base:x}",
                    "loaded_event_index": None,
                },
            )
            item.update(
                _prune(
                    {
                        "status": "unloaded",
                        "unloaded_event_index": event_index,
                        "unloaded_at": timestamp,
                    }
                )
            )


def _finalize_module_inventory(
    modules: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    ordered = sorted((int(base), _json_mapping(item)) for base, item in modules.items())
    result: list[dict[str, Any]] = []
    for index, (base, item) in enumerate(ordered):
        next_base = ordered[index + 1][0] if index + 1 < len(ordered) else None
        result.append(
            _prune(
                {
                    **item,
                    "base_address": base,
                    "base_address_hex": f"0x{base:x}",
                    "observed_upper_bound": next_base,
                }
            )
        )
    return result


def _finalize_thread_inventory(
    threads: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        _prune({**_json_mapping(item), "thread_id": int(thread_id)})
        for thread_id, item in sorted(threads.items())
    ]


def _context_after_summary(context_summary: Mapping[str, Any]) -> dict[str, Any]:
    after = context_summary.get("after")
    if isinstance(after, Mapping):
        return _json_mapping(after)
    before = context_summary.get("before")
    if isinstance(before, Mapping):
        return _json_mapping(before)
    return _json_mapping(context_summary)


def _resolve_module_for_address(
    address: int, modules: Mapping[int, Mapping[str, Any]]
) -> Optional[dict[str, Any]]:
    candidates = [int(base) for base in modules if int(base) <= address]
    if not candidates:
        return None
    base = max(candidates)
    item = _json_mapping(modules[base])
    return _prune(
        {
            "base_address": base,
            "image_path": item.get("image_path"),
            "rva": address - base,
        }
    )


def _capture_bounded_call_stack(
    backend: Any,
    *,
    pid: int,
    architecture: str,
    context_summary: Mapping[str, Any],
    modules: Mapping[int, Mapping[str, Any]],
    max_frames: int,
    event_index: int,
    thread_id: int,
) -> dict[str, Any]:
    context = _context_after_summary(context_summary)
    instruction_pointer = _coerce_int(context.get("instruction_pointer"))
    frame_pointer = _coerce_int(context.get("frame_pointer"))
    pointer_size = 8 if architecture == "x64" else 4
    frames: list[dict[str, Any]] = []
    if instruction_pointer:
        frames.append(
            _prune(
                {
                    "index": 0,
                    "address": instruction_pointer,
                    "address_hex": f"0x{instruction_pointer:x}",
                    "source": "thread_context",
                    "module": _resolve_module_for_address(
                        instruction_pointer, modules
                    ),
                }
            )
        )
    termination_reason = "frame_pointer_unavailable"
    current = frame_pointer
    visited: set[int] = set()
    while current and len(frames) < max_frames:
        if current in visited:
            termination_reason = "frame_pointer_cycle"
            break
        visited.add(current)
        try:
            pair = bytes(backend.read(pid, current, pointer_size * 2))
        except Exception as exc:  # noqa: BLE001 - diagnostic capture is best effort
            termination_reason = "stack_read_failed"
            return _prune(
                {
                    "schema_version": 1,
                    "event_index": event_index,
                    "thread_id": thread_id,
                    "architecture": architecture,
                    "capture_method": "bounded_frame_pointer_walk",
                    "frames": frames,
                    "complete": False,
                    "termination_reason": termination_reason,
                    "error": _exception_payload(exc),
                }
            )
        if len(pair) != pointer_size * 2:
            termination_reason = "short_stack_read"
            break
        next_frame = int.from_bytes(pair[:pointer_size], "little")
        return_address = int.from_bytes(pair[pointer_size:], "little")
        if return_address:
            frames.append(
                _prune(
                    {
                        "index": len(frames),
                        "address": return_address,
                        "address_hex": f"0x{return_address:x}",
                        "frame_pointer": current,
                        "source": "frame_pointer",
                        "module": _resolve_module_for_address(
                            return_address, modules
                        ),
                    }
                )
            )
        if not next_frame:
            termination_reason = "end_of_chain"
            break
        if next_frame <= current or next_frame - current > _MAX_FRAME_POINTER_DELTA:
            termination_reason = "invalid_frame_pointer_progression"
            break
        current = next_frame
    else:
        termination_reason = "max_frames" if current else "end_of_chain"
    return _prune(
        {
            "schema_version": 1,
            "event_index": event_index,
            "thread_id": thread_id,
            "architecture": architecture,
            "capture_method": "bounded_frame_pointer_walk",
            "frames": frames,
            "complete": termination_reason == "end_of_chain",
            "termination_reason": termination_reason,
        }
    )


def _exception_evidence(event: Mapping[str, Any]) -> dict[str, Any]:
    code = _coerce_int(event.get("exception_code")) or 0
    first_chance = event.get("first_chance") is not False
    classification = str(event.get("classification") or "exception")
    crash_candidate = bool(
        not first_chance
        and classification not in {
            "debugger_initial_breakpoint",
            "software_breakpoint_hit",
            "single_step_rearm",
        }
    )
    return _prune(
        {
            "schema_version": 1,
            "event_index": event.get("index"),
            "thread_id": event.get("thread_id"),
            "exception_code": code,
            "exception_code_hex": event.get("exception_code_hex")
            or f"0x{code:08x}",
            "exception_address": event.get("exception_address"),
            "first_chance": first_chance,
            "classification": classification,
            "information": event.get("information"),
            "crash_candidate": crash_candidate,
        }
    )


def _checked_operation(value: Any, operation: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NativeDebuggerBackendError(
            operation, f"{operation} did not return an operation mapping"
        )
    payload = _json_mapping(value)
    if payload.get("ok") is not True and str(payload.get("status")) != "ok":
        reason = (
            payload.get("reason")
            or payload.get("message")
            or payload.get("error")
            or f"{operation} did not report success"
        )
        raise NativeDebuggerBackendError(
            operation,
            str(reason),
            error_code=_coerce_int(payload.get("error_code")) or 0,
        )
    payload.setdefault("operation", operation)
    payload.setdefault("ok", True)
    payload.setdefault("status", "ok")
    return payload


def _memory_observation(operation: str, address: int, data: bytes) -> dict[str, Any]:
    return {
        "operation": operation,
        "ok": True,
        "status": "ok",
        "address": address,
        "size": len(data),
        "bytes_hex": bytes(data).hex(),
    }


def _result_plan_parameters(result: CapabilityExecutionResult) -> dict[str, Any]:
    plan = result.provenance.get("plan")
    if isinstance(plan, Mapping):
        return _json_mapping(plan.get("parameters"))
    return {}


def _planned_process_snapshot(result: CapabilityExecutionResult) -> dict[str, Any]:
    plan = result.provenance.get("plan")
    if isinstance(plan, Mapping):
        before = plan.get("before_snapshot")
        if isinstance(before, Mapping):
            return _json_mapping(before.get("process"))
    planned = result.before_snapshot.get("planned")
    if isinstance(planned, Mapping):
        return _json_mapping(planned.get("process"))
    return {}


def _safe_session_segment(session_id: str) -> str:
    raw = str(session_id or "native-debugger-session")
    cleaned = _SAFE_SESSION_RE.sub("_", raw).strip("._-")
    if not cleaned:
        cleaned = "session"
    cleaned = cleaned[:96]
    if cleaned != raw:
        suffix = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        cleaned = f"{cleaned}-{suffix}"
    return cleaned


def _session_artifact_specs(session_id: str) -> list[dict[str, str]]:
    base = PurePosixPath("native_debugger") / _safe_session_segment(session_id)
    return [
        {
            "path": str(base / "audit.json"),
            "kind": "native-debugger-audit",
            "description": "Native debugger lifecycle audit record",
        },
        {
            "path": str(base / "events.json"),
            "kind": "native-debugger-events",
            "description": "Bounded normalized debug events and context summaries",
        },
        {
            "path": str(base / "diagnostics.json"),
            "kind": "native-debugger-diagnostics",
            "description": (
                "Module, thread, exception, call-stack, and crash evidence"
            ),
        },
        {
            "path": str(base / "manifest.json"),
            "kind": "native-debugger-manifest",
            "description": "Native debugger artifact manifest",
        },
    ]


def _resolve_artifact_path(root: Path, relative_path: str) -> Path:
    posix = PurePosixPath(relative_path)
    windows = PureWindowsPath(relative_path)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise ValueError(f"unsafe native_debugger artifact path: {relative_path}")
    candidate = root.joinpath(*posix.parts).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"native_debugger artifact path escapes output root: {relative_path}"
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
    events = [
        _json_mapping(item)
        for item in result.provenance.get("lifecycle_events") or []
        if isinstance(item, Mapping)
    ]
    kinds = [str(item.get("kind") or "") for item in events]
    if any(required not in kinds for required in ("plan", "validate", "execute")):
        raise ValueError("native_debugger lifecycle events are incomplete")
    for item in events:
        if not item.get("ts") or not item.get("message"):
            raise ValueError("native_debugger lifecycle event lacks timestamp or message")
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
    payload = _json_mapping(result.to_dict())
    provenance = _json_mapping(payload.get("provenance"))
    provenance.pop(_RESULT_IDENTITY_KEY, None)
    payload["provenance"] = provenance
    return payload


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {
            str(key): _json_value(item)
            for key, item in value.items()
        }
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return _json_mapping(payload)
    return {}


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    if value is None or isinstance(value, (str, int, float, bool)):
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
    if isinstance(value, tuple):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


def _exception_payload(exc: BaseException) -> dict[str, Any]:
    payload = {
        "type": type(exc).__name__,
        "message": str(exc),
    }
    operation = getattr(exc, "operation", None)
    error_code = _coerce_int(getattr(exc, "error_code", None))
    if operation:
        payload["operation"] = str(operation)
    if error_code:
        payload["error_code"] = error_code
    return payload


__all__ = [
    "NativeDebugEvent",
    "NativeDebuggerBackend",
    "NativeDebuggerBackendError",
    "NativeDebuggerProvider",
    "UnavailableNativeDebuggerBackend",
    "WindowsNativeDebuggerBackend",
]
