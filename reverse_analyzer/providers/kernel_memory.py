"""Bounded, auditable client for the signed lab kernel-memory driver.

The production backend talks to a versioned METHOD_BUFFERED IOCTL contract
through CreateFileW/DeviceIoControl/CloseHandle.  Only protocol version,
process identity query, bounded user-memory read, and compare-before-write are
exposed.  A deterministic backend can be injected by tests, but such runs are
reported as ``test-double`` rather than production success.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
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


AUDIT_SCHEMA_VERSION = 1
PROTOCOL_VERSION = 1
REQUEST_MAGIC = 0x51524D4B  # KMRQ
RESPONSE_MAGIC = 0x53524D4B  # KMRS
VERSION_MAGIC = 0x56444D4B  # KMDV

OP_VERSION = 1
OP_QUERY_PROCESS = 2
OP_READ = 3
OP_WRITE = 4

DEFAULT_DEVICE_PATH = r"\\.\ReverseAnalyzerKernelMemory"
DEFAULT_ALLOWED_DEVICE_PATHS = (DEFAULT_DEVICE_PATH,)
HARD_MAX_READ_BYTES = 64 * 1024
HARD_MAX_WRITE_BYTES = 4 * 1024
MIN_USER_ADDRESS = 0x10000
MAX_USER_ADDRESS = 0x00007FFFFFFFFFFF

FILE_DEVICE_UNKNOWN = 0x22
METHOD_BUFFERED = 0
FILE_READ_DATA = 0x0001
FILE_WRITE_DATA = 0x0002


def _ctl_code(device_type: int, function: int, method: int, access: int) -> int:
    return (
        (int(device_type) << 16)
        | (int(access) << 14)
        | (int(function) << 2)
        | int(method)
    )


IOCTL_KM_VERSION = _ctl_code(
    FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA
)
IOCTL_KM_QUERY_PROCESS = _ctl_code(
    FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA
)
IOCTL_KM_READ = _ctl_code(
    FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA
)
IOCTL_KM_WRITE = _ctl_code(
    FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA
)
ALLOWED_IOCTL_CODES = frozenset(
    {
        IOCTL_KM_VERSION,
        IOCTL_KM_QUERY_PROCESS,
        IOCTL_KM_READ,
        IOCTL_KM_WRITE,
    }
)

_OPERATION_IOCTL = {
    OP_VERSION: IOCTL_KM_VERSION,
    OP_QUERY_PROCESS: IOCTL_KM_QUERY_PROCESS,
    OP_READ: IOCTL_KM_READ,
    OP_WRITE: IOCTL_KM_WRITE,
}
_ACTION_OPERATION = {
    "version": OP_VERSION,
    "query": OP_QUERY_PROCESS,
    "read": OP_READ,
    "write": OP_WRITE,
}
_ACTION_ALIASES = {
    "get_version": "version",
    "driver_version": "version",
    "query_process": "query",
    "process_query": "query",
    "read_memory": "read",
    "write_memory": "write",
}
_SUPPORTED_ACTIONS = frozenset(_ACTION_OPERATION)

_REQUEST_STRUCT = struct.Struct("<IHHIIIIQQQIIII16s")
_RESPONSE_STRUCT = struct.Struct("<IHHIIiIQQQIIII16s")
_VERSION_STRUCT = struct.Struct("<IHHHHIII")


class KernelMemoryProtocolError(ValueError):
    """A malformed or incompatible kernel-memory protocol message."""


class KernelMemoryBackendError(RuntimeError):
    """A backend failure with a stable operation and availability status."""

    def __init__(
        self,
        operation: str,
        message: str,
        *,
        status: str = "failed",
        code: Optional[int] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(f"{operation}: {message}")
        self.operation = operation
        self.message = message
        self.status = status
        self.code = code
        self.details = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        return _prune(
            {
                "type": type(self).__name__,
                "operation": self.operation,
                "message": self.message,
                "status": self.status,
                "code": self.code,
                "details": self.details,
            }
        )


@dataclass(frozen=True)
class KernelMemoryRequest:
    """One fixed-layout protocol request plus an optional bounded payload."""

    operation: int
    pid: int = 0
    process_creation_time: int = 0
    address: int = 0
    length: int = 0
    expected: bytes = b""
    data: bytes = b""
    flags: int = 0
    session_nonce: int = 0
    request_id: bytes = field(default_factory=lambda: uuid.uuid4().bytes)
    version: int = PROTOCOL_VERSION

    def pack(self) -> bytes:
        expected = bytes(self.expected)
        data = bytes(self.data)
        request_id = bytes(self.request_id)
        if len(request_id) != 16:
            raise KernelMemoryProtocolError("request_id must contain exactly 16 bytes")
        if self.operation not in _OPERATION_IOCTL:
            raise KernelMemoryProtocolError("operation is not allowlisted")
        if self.version != PROTOCOL_VERSION:
            raise KernelMemoryProtocolError("request protocol version is unsupported")
        if self.flags != 0:
            raise KernelMemoryProtocolError("request flags must be zero for protocol v1")
        _require_uint("pid", self.pid, 32)
        _require_uint("process_creation_time", self.process_creation_time, 64)
        _require_uint("address", self.address, 64)
        _require_uint("length", self.length, 32)
        _require_uint("session_nonce", self.session_nonce, 64)
        if self.session_nonce == 0:
            raise KernelMemoryProtocolError("session_nonce must be non-zero")
        if request_id == b"\x00" * 16:
            raise KernelMemoryProtocolError("request_id must be non-zero")
        if self.operation == OP_VERSION:
            if any((self.pid, self.process_creation_time, self.address, self.length)):
                raise KernelMemoryProtocolError(
                    "version request identity, address, and length fields must be zero"
                )
        elif self.operation == OP_QUERY_PROCESS:
            _require_process_identity(self.pid, self.process_creation_time)
            if self.address or self.length:
                raise KernelMemoryProtocolError(
                    "query request address and length fields must be zero"
                )
        elif self.operation == OP_READ:
            _require_process_identity(self.pid, self.process_creation_time)
            if not _valid_user_range(self.address, self.length, HARD_MAX_READ_BYTES):
                raise KernelMemoryProtocolError(
                    "read request exceeds the bounded user-memory range"
                )
        elif self.operation == OP_WRITE:
            _require_process_identity(self.pid, self.process_creation_time)
            if not _valid_user_range(self.address, self.length, HARD_MAX_WRITE_BYTES):
                raise KernelMemoryProtocolError(
                    "write request exceeds the bounded user-memory range"
                )
            if not self.length or len(expected) != self.length or len(data) != self.length:
                raise KernelMemoryProtocolError(
                    "write payload must contain length bytes of expected and replacement data"
                )
        if self.operation != OP_WRITE and (expected or data):
            raise KernelMemoryProtocolError("only write requests may carry payload data")
        payload = expected + data
        total_size = _REQUEST_STRUCT.size + len(payload)
        header = _REQUEST_STRUCT.pack(
            REQUEST_MAGIC,
            self.version,
            _REQUEST_STRUCT.size,
            total_size,
            self.operation,
            self.flags,
            self.pid,
            self.process_creation_time,
            self.address,
            self.session_nonce,
            self.length,
            len(expected),
            len(data),
            0,
            request_id,
        )
        return header + payload

    @classmethod
    def unpack(cls, encoded: bytes) -> "KernelMemoryRequest":
        raw = bytes(encoded)
        if len(raw) < _REQUEST_STRUCT.size:
            raise KernelMemoryProtocolError("request is shorter than its fixed header")
        values = _REQUEST_STRUCT.unpack_from(raw)
        (
            magic,
            version,
            header_size,
            total_size,
            operation,
            flags,
            pid,
            creation_time,
            address,
            session_nonce,
            length,
            expected_length,
            data_length,
            reserved,
            request_id,
        ) = values
        if magic != REQUEST_MAGIC:
            raise KernelMemoryProtocolError("request magic does not match")
        if version != PROTOCOL_VERSION:
            raise KernelMemoryProtocolError("request protocol version does not match")
        if header_size != _REQUEST_STRUCT.size:
            raise KernelMemoryProtocolError("request header size does not match")
        if total_size != len(raw):
            raise KernelMemoryProtocolError("request total size does not match buffer length")
        if flags != 0 or reserved != 0:
            raise KernelMemoryProtocolError("request contains unsupported flags or reserved data")
        payload = raw[header_size:]
        if len(payload) != expected_length + data_length:
            raise KernelMemoryProtocolError("request payload lengths do not match")
        expected = payload[:expected_length]
        data = payload[expected_length:]
        request = cls(
            operation=operation,
            pid=pid,
            process_creation_time=creation_time,
            address=address,
            length=length,
            expected=expected,
            data=data,
            flags=flags,
            session_nonce=session_nonce,
            request_id=request_id,
            version=version,
        )
        request.pack()
        return request


@dataclass(frozen=True)
class KernelMemoryResponse:
    """One fixed-layout protocol response and its validated data payload."""

    operation: int
    status: int
    pid: int = 0
    process_creation_time: int = 0
    address: int = 0
    requested_length: int = 0
    bytes_transferred: int = 0
    data: bytes = b""
    flags: int = 0
    session_nonce: int = 0
    request_id: bytes = b"\x00" * 16
    version: int = PROTOCOL_VERSION

    def pack(self) -> bytes:
        data = bytes(self.data)
        request_id = bytes(self.request_id)
        if len(request_id) != 16:
            raise KernelMemoryProtocolError("response request_id must contain 16 bytes")
        if self.operation not in _OPERATION_IOCTL:
            raise KernelMemoryProtocolError("response operation is not allowlisted")
        if self.version != PROTOCOL_VERSION:
            raise KernelMemoryProtocolError("response protocol version is unsupported")
        if self.flags != 0:
            raise KernelMemoryProtocolError("response flags must be zero for protocol v1")
        _validate_response_shape(self)
        total_size = _RESPONSE_STRUCT.size + len(data)
        return _RESPONSE_STRUCT.pack(
            RESPONSE_MAGIC,
            self.version,
            _RESPONSE_STRUCT.size,
            total_size,
            self.operation,
            int(self.status),
            self.pid,
            self.process_creation_time,
            self.address,
            self.session_nonce,
            self.requested_length,
            self.bytes_transferred,
            len(data),
            self.flags,
            request_id,
        ) + data

    @classmethod
    def unpack(
        cls,
        encoded: bytes,
        *,
        expected_request: Optional[KernelMemoryRequest] = None,
    ) -> "KernelMemoryResponse":
        raw = bytes(encoded)
        if len(raw) < _RESPONSE_STRUCT.size:
            raise KernelMemoryProtocolError("response is shorter than its fixed header")
        values = _RESPONSE_STRUCT.unpack_from(raw)
        (
            magic,
            version,
            header_size,
            total_size,
            operation,
            status,
            pid,
            creation_time,
            address,
            session_nonce,
            requested_length,
            bytes_transferred,
            data_length,
            flags,
            request_id,
        ) = values
        if magic != RESPONSE_MAGIC:
            raise KernelMemoryProtocolError("response magic does not match")
        if version != PROTOCOL_VERSION:
            raise KernelMemoryProtocolError("response protocol version does not match")
        if header_size != _RESPONSE_STRUCT.size:
            raise KernelMemoryProtocolError("response header size does not match")
        if total_size != len(raw):
            raise KernelMemoryProtocolError("response total size does not match buffer length")
        if data_length != len(raw) - header_size:
            raise KernelMemoryProtocolError("response data length does not match")
        if flags != 0:
            raise KernelMemoryProtocolError("response contains unsupported flags")
        response = cls(
            operation=operation,
            status=status,
            pid=pid,
            process_creation_time=creation_time,
            address=address,
            requested_length=requested_length,
            bytes_transferred=bytes_transferred,
            data=raw[header_size:],
            flags=flags,
            session_nonce=session_nonce,
            request_id=request_id,
            version=version,
        )
        _validate_response_shape(response)
        if expected_request is not None:
            if response.operation != expected_request.operation:
                raise KernelMemoryProtocolError("response operation does not match request")
            if response.request_id != expected_request.request_id:
                raise KernelMemoryProtocolError("response request_id does not match request")
            if response.session_nonce != expected_request.session_nonce:
                raise KernelMemoryProtocolError("response session nonce does not match request")
            if response.pid != expected_request.pid:
                raise KernelMemoryProtocolError("response PID does not match request")
            if response.process_creation_time != expected_request.process_creation_time:
                raise KernelMemoryProtocolError(
                    "response process creation identity does not match request"
                )
            if response.address != expected_request.address:
                raise KernelMemoryProtocolError("response address does not match request")
            if response.requested_length != expected_request.length:
                raise KernelMemoryProtocolError("response requested length does not match request")
        return response


@dataclass(frozen=True)
class KernelMemoryVersionInfo:
    struct_version: int = 1
    protocol_min: int = PROTOCOL_VERSION
    protocol_max: int = PROTOCOL_VERSION
    max_read_bytes: int = HARD_MAX_READ_BYTES
    max_write_bytes: int = HARD_MAX_WRITE_BYTES
    operation_mask: int = 0x0F

    def pack(self) -> bytes:
        return _VERSION_STRUCT.pack(
            VERSION_MAGIC,
            self.struct_version,
            _VERSION_STRUCT.size,
            self.protocol_min,
            self.protocol_max,
            self.max_read_bytes,
            self.max_write_bytes,
            self.operation_mask,
        )

    @classmethod
    def unpack(cls, encoded: bytes) -> "KernelMemoryVersionInfo":
        raw = bytes(encoded)
        if len(raw) != _VERSION_STRUCT.size:
            raise KernelMemoryProtocolError("version payload size does not match")
        values = _VERSION_STRUCT.unpack(raw)
        magic, struct_version, size, protocol_min, protocol_max, max_read, max_write, mask = values
        if magic != VERSION_MAGIC or size != _VERSION_STRUCT.size or struct_version != 1:
            raise KernelMemoryProtocolError("version payload header is incompatible")
        if not (protocol_min <= PROTOCOL_VERSION <= protocol_max):
            raise KernelMemoryProtocolError("driver does not support client protocol version")
        if not (0 < max_read <= HARD_MAX_READ_BYTES):
            raise KernelMemoryProtocolError("driver advertised an invalid maximum read size")
        if not (0 < max_write <= HARD_MAX_WRITE_BYTES):
            raise KernelMemoryProtocolError("driver advertised an invalid maximum write size")
        required_mask = sum(1 << (operation - 1) for operation in _OPERATION_IOCTL)
        if mask & required_mask != required_mask:
            raise KernelMemoryProtocolError("driver operation mask is incomplete")
        return cls(
            struct_version=struct_version,
            protocol_min=protocol_min,
            protocol_max=protocol_max,
            max_read_bytes=max_read,
            max_write_bytes=max_write,
            operation_mask=mask,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "struct_version": self.struct_version,
            "protocol_min": self.protocol_min,
            "protocol_max": self.protocol_max,
            "max_read_bytes": self.max_read_bytes,
            "max_write_bytes": self.max_write_bytes,
            "operation_mask": self.operation_mask,
        }


class KernelMemoryBackend(Protocol):
    name: str
    available: bool
    availability_status: str
    unavailable_reason: Optional[str]
    test_double: bool

    def describe(self) -> Mapping[str, Any]: ...

    def get_version(self) -> Mapping[str, Any]: ...

    def query_process(self, pid: int, process_creation_time: int) -> Mapping[str, Any]: ...

    def read(self, pid: int, process_creation_time: int, address: int, size: int) -> bytes: ...

    def write(
        self,
        pid: int,
        process_creation_time: int,
        address: int,
        expected: bytes,
        data: bytes,
    ) -> Mapping[str, Any]: ...


class UnavailableKernelMemoryBackend:
    """Backend used when the host API or signed driver dependency is absent."""

    name = "unavailable_kernel_memory_driver"
    available = False
    test_double = False

    def __init__(self, reason: str, *, status: str = "unavailable") -> None:
        if status not in {"unavailable", "dependency-gated"}:
            raise ValueError("unavailable backend status must be unavailable or dependency-gated")
        self.availability_status = status
        self.unavailable_reason = str(reason)

    def describe(self) -> Mapping[str, Any]:
        return {
            "name": self.name,
            "available": False,
            "status": self.availability_status,
            "reason": self.unavailable_reason,
            "test_double": False,
        }

    def _raise(self, operation: str) -> None:
        raise KernelMemoryBackendError(
            operation,
            self.unavailable_reason,
            status=self.availability_status,
        )

    def get_version(self) -> Mapping[str, Any]:
        self._raise("version")

    def query_process(self, pid: int, process_creation_time: int) -> Mapping[str, Any]:
        del pid, process_creation_time
        self._raise("query_process")

    def read(self, pid: int, process_creation_time: int, address: int, size: int) -> bytes:
        del pid, process_creation_time, address, size
        self._raise("read")

    def write(
        self,
        pid: int,
        process_creation_time: int,
        address: int,
        expected: bytes,
        data: bytes,
    ) -> Mapping[str, Any]:
        del pid, process_creation_time, address, expected, data
        self._raise("write")


class WindowsKernelMemoryBackend:
    """Production Win32 transport for the allowlisted kernel driver device."""

    name = "windows_device_io_control"
    test_double = False

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(
        self,
        device_path: str = DEFAULT_DEVICE_PATH,
        *,
        allowed_device_paths: Sequence[str] = DEFAULT_ALLOWED_DEVICE_PATHS,
        platform_name: Optional[str] = None,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.device_path = str(device_path)
        self.allowed_device_paths = tuple(str(item) for item in allowed_device_paths)
        fixed_allowlist = {item.casefold() for item in DEFAULT_ALLOWED_DEVICE_PATHS}
        configured_allowlist = {
            item.casefold() for item in self.allowed_device_paths
        }
        if not configured_allowlist or not configured_allowlist.issubset(fixed_allowlist):
            raise ValueError("kernel-memory device allowlist cannot be expanded")
        if self.device_path.casefold() not in configured_allowlist:
            raise ValueError("kernel-memory device path is not allowlisted")
        self.available = False
        self.availability_status = "unavailable"
        self.unavailable_reason: Optional[str] = None
        self._kernel32: Any = None
        if self.platform_name != "win32":
            self.unavailable_reason = (
                f"CreateFileW/DeviceIoControl are unavailable on {self.platform_name}"
            )
            return
        try:
            self._configure_api()
        except Exception as exc:  # pragma: no cover - host API dependent
            self.unavailable_reason = f"failed to initialize Win32 driver transport: {exc}"
            return
        self.available = True
        self.availability_status = "available"

    def _configure_api(self) -> None:  # pragma: no cover - Windows binding setup
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32 = kernel32

    def describe(self) -> Mapping[str, Any]:
        return _prune(
            {
                "name": self.name,
                "available": self.available,
                "status": self.availability_status,
                "reason": self.unavailable_reason,
                "platform": self.platform_name,
                "device_path": self.device_path,
                "allowed_device_paths": list(self.allowed_device_paths),
                "allowed_ioctls": sorted(ALLOWED_IOCTL_CODES),
                "test_double": False,
            }
        )

    def _ensure_api(self, operation: str) -> None:
        if not self.available or self._kernel32 is None:
            raise KernelMemoryBackendError(
                operation,
                self.unavailable_reason or "Win32 driver transport is unavailable",
                status="unavailable",
            )

    def _transact(
        self,
        ioctl: int,
        request: KernelMemoryRequest,
        *,
        output_capacity: int,
    ) -> KernelMemoryResponse:
        self._ensure_api("DeviceIoControl")
        if ioctl not in ALLOWED_IOCTL_CODES or _OPERATION_IOCTL.get(request.operation) != ioctl:
            raise KernelMemoryBackendError(
                "DeviceIoControl",
                "IOCTL is not allowlisted for this protocol operation",
            )
        if self.device_path.casefold() not in {
            item.casefold() for item in self.allowed_device_paths
        }:
            raise KernelMemoryBackendError("CreateFileW", "device path is not allowlisted")
        encoded = request.pack()
        if output_capacity < _RESPONSE_STRUCT.size:
            raise KernelMemoryBackendError("DeviceIoControl", "output capacity is too small")
        kernel32 = self._kernel32
        handle = kernel32.CreateFileW(
            self.device_path,
            self.GENERIC_READ | self.GENERIC_WRITE,
            0,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if not handle or handle == self.INVALID_HANDLE_VALUE:
            code = ctypes.get_last_error()
            raise KernelMemoryBackendError(
                "CreateFileW",
                os.strerror(code) if code else "failed to open kernel-memory device",
                status="dependency-gated",
                code=code,
                details={"device_path": self.device_path},
            )
        try:
            input_buffer = ctypes.create_string_buffer(encoded, len(encoded))
            output_buffer = ctypes.create_string_buffer(output_capacity)
            returned = ctypes.c_ulong(0)
            ok = kernel32.DeviceIoControl(
                handle,
                ioctl,
                input_buffer,
                len(encoded),
                output_buffer,
                output_capacity,
                ctypes.byref(returned),
                None,
            )
            if not ok:
                code = ctypes.get_last_error()
                status = "dependency-gated" if code in {1, 2, 3, 5, 50, 1060, 1168} else "failed"
                raise KernelMemoryBackendError(
                    "DeviceIoControl",
                    os.strerror(code) if code else "driver transaction failed",
                    status=status,
                    code=code,
                    details={"ioctl": ioctl, "operation": request.operation},
                )
            returned_size = int(returned.value)
            if not (_RESPONSE_STRUCT.size <= returned_size <= output_capacity):
                raise KernelMemoryBackendError(
                    "DeviceIoControl",
                    "driver returned an invalid response length",
                    details={"returned": returned_size, "capacity": output_capacity},
                )
            try:
                return KernelMemoryResponse.unpack(
                    output_buffer.raw[:returned_size], expected_request=request
                )
            except KernelMemoryProtocolError as exc:
                raise KernelMemoryBackendError(
                    "protocol",
                    str(exc),
                    status="dependency-gated",
                    details={"ioctl": ioctl},
                ) from exc
        finally:
            kernel32.CloseHandle(handle)

    @staticmethod
    def _require_success(response: KernelMemoryResponse, operation: str) -> None:
        if response.status != 0:
            raise KernelMemoryBackendError(
                operation,
                "driver rejected the request",
                code=response.status & 0xFFFFFFFF,
                details={
                    "pid": response.pid,
                    "address": response.address,
                    "bytes_transferred": response.bytes_transferred,
                },
            )

    def get_version(self) -> Mapping[str, Any]:
        request = KernelMemoryRequest(operation=OP_VERSION, session_nonce=_nonce())
        response = self._transact(
            IOCTL_KM_VERSION,
            request,
            output_capacity=_RESPONSE_STRUCT.size + _VERSION_STRUCT.size,
        )
        self._require_success(response, "version")
        info = KernelMemoryVersionInfo.unpack(response.data)
        return {
            "status": "ok",
            "protocol_version": response.version,
            **info.to_dict(),
            "driver_backed": True,
        }

    def query_process(self, pid: int, process_creation_time: int) -> Mapping[str, Any]:
        _require_backend_identity("query_process", pid, process_creation_time)
        request = KernelMemoryRequest(
            operation=OP_QUERY_PROCESS,
            pid=pid,
            process_creation_time=process_creation_time,
            session_nonce=_nonce(),
        )
        response = self._transact(
            IOCTL_KM_QUERY_PROCESS,
            request,
            output_capacity=_RESPONSE_STRUCT.size,
        )
        self._require_success(response, "query_process")
        if response.process_creation_time != process_creation_time:
            raise KernelMemoryBackendError(
                "query_process", "driver returned a different process creation identity"
            )
        return {
            "status": "ok",
            "pid": response.pid,
            "process_creation_time": response.process_creation_time,
            "identity_verified": True,
            "driver_backed": True,
        }

    def read(self, pid: int, process_creation_time: int, address: int, size: int) -> bytes:
        _require_backend_identity("read", pid, process_creation_time)
        _require_backend_user_range(
            "read", address, size, HARD_MAX_READ_BYTES
        )
        request = KernelMemoryRequest(
            operation=OP_READ,
            pid=pid,
            process_creation_time=process_creation_time,
            address=address,
            length=size,
            session_nonce=_nonce(),
        )
        response = self._transact(
            IOCTL_KM_READ,
            request,
            output_capacity=_RESPONSE_STRUCT.size + size,
        )
        self._require_success(response, "read")
        if response.process_creation_time != process_creation_time:
            raise KernelMemoryBackendError("read", "process creation identity drifted")
        if response.bytes_transferred != size or len(response.data) != size:
            raise KernelMemoryBackendError(
                "read",
                "driver returned a short or oversized read",
                details={
                    "requested": size,
                    "bytes_transferred": response.bytes_transferred,
                    "data_length": len(response.data),
                },
            )
        return response.data

    def write(
        self,
        pid: int,
        process_creation_time: int,
        address: int,
        expected: bytes,
        data: bytes,
    ) -> Mapping[str, Any]:
        _require_backend_identity("write", pid, process_creation_time)
        try:
            expected = bytes(expected)
            data = bytes(data)
        except (TypeError, ValueError, OverflowError) as exc:
            raise KernelMemoryBackendError(
                "write", "expected and replacement must be byte sequences"
            ) from exc
        if (
            not data
            or len(expected) != len(data)
        ):
            raise KernelMemoryBackendError(
                "write",
                "expected and replacement must be equal non-zero bounded user-memory bytes",
            )
        _require_backend_user_range(
            "write", address, len(data), HARD_MAX_WRITE_BYTES
        )
        request = KernelMemoryRequest(
            operation=OP_WRITE,
            pid=pid,
            process_creation_time=process_creation_time,
            address=address,
            length=len(data),
            expected=expected,
            data=data,
            session_nonce=_nonce(),
        )
        response = self._transact(
            IOCTL_KM_WRITE,
            request,
            output_capacity=_RESPONSE_STRUCT.size + len(data),
        )
        self._require_success(response, "write")
        if response.process_creation_time != process_creation_time:
            raise KernelMemoryBackendError("write", "process creation identity drifted")
        if response.bytes_transferred != len(data) or response.data != bytes(data):
            raise KernelMemoryBackendError(
                "write",
                "driver write response did not prove the complete postimage",
                details={
                    "requested": len(data),
                    "bytes_transferred": response.bytes_transferred,
                    "after_hex": response.data.hex(),
                },
            )
        return {
            "status": "ok",
            "bytes_transferred": response.bytes_transferred,
            "after_hex": response.data.hex(),
            "driver_backed": True,
        }


class KernelDriverMemoryProvider:
    """CapabilityProvider for bounded kernel-assisted process memory access."""

    capability_name = "kernel_driver_memory_runtime"
    provider_name = "windows_kernel_memory_driver"
    priority = 30

    def __init__(
        self,
        backend: Optional[KernelMemoryBackend] = None,
        *,
        platform_name: Optional[str] = None,
        device_path: str = DEFAULT_DEVICE_PATH,
        max_read_bytes: int = HARD_MAX_READ_BYTES,
        max_write_bytes: int = HARD_MAX_WRITE_BYTES,
    ) -> None:
        self.platform_name = platform_name or sys.platform
        self.max_read_bytes = min(HARD_MAX_READ_BYTES, max(1, int(max_read_bytes)))
        self.max_write_bytes = min(HARD_MAX_WRITE_BYTES, max(1, int(max_write_bytes)))
        if backend is not None:
            self.backend = backend
        elif self.platform_name == "win32":
            self.backend = WindowsKernelMemoryBackend(
                device_path=device_path, platform_name=self.platform_name
            )
        else:
            self.backend = UnavailableKernelMemoryBackend(
                f"signed Windows kernel-memory driver is unavailable on {self.platform_name}",
                status="unavailable",
            )

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
        parameters = _normalize_parameters(
            request,
            action,
            max_read_bytes=self.max_read_bytes,
            max_write_bytes=self.max_write_bytes,
        )
        before = _capture_live(backend, action, parameters)
        before.update(
            {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "capture_phase": "plan",
                "backend": _backend_description(backend),
            }
        )
        precondition_hash = _precondition_hash(action, parameters, before)
        before["precondition_hash"] = precondition_hash
        rollback_plan = _initial_rollback(action, parameters, before)
        rollback_plan["precondition_hash"] = precondition_hash
        planned_at = _utc_now()
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=request.session_id or f"kernel-memory-{uuid.uuid4().hex[:12]}",
            target=request.target,
            action=action,
            parameters=parameters,
            steps=_plan_steps(action),
            precondition_hash=precondition_hash,
            before_snapshot=before,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": AUDIT_SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "provider": self.provider_name,
                "backend": _backend_description(backend),
                "requested_action": request.action,
                "action": action,
                "planned_at": planned_at,
                "precondition_hash": precondition_hash,
                "test_double": _is_test_double_backend(backend),
                "production_backend": _is_production_backend(backend),
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
        validation, current = self._validate_plan(plan, context=context)
        before = dict(current or plan.before_snapshot or {})
        before.update(
            {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "capture_phase": "before",
                "precondition_hash": plan.precondition_hash,
            }
        )
        gate_status = _snapshot_gate_status(before)
        if gate_status:
            reason = str((before.get("error") or {}).get("message") or before.get("reason") or "kernel driver dependency is unavailable")
            return self._build_result(
                plan,
                validation,
                status=gate_status,
                before=before,
                after={
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": gate_status,
                    "side_effects": False,
                    "reason": reason,
                },
                rollback=_not_required_rollback(plan.rollback_plan, gate_status, reason),
                operation={"status": gate_status, "side_effects": False, "reason": reason},
                errors=[reason],
                backend=backend,
            )
        if not validation.ok or plan.action not in _SUPPORTED_ACTIONS:
            reason = "execution was blocked by fail-closed plan validation"
            return self._build_result(
                plan,
                validation,
                status="failed",
                before=before,
                after={
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": "blocked",
                    "side_effects": False,
                },
                rollback=_not_required_rollback(plan.rollback_plan, "blocked", reason),
                operation={"status": "blocked", "side_effects": False, "reason": reason},
                errors=list(validation.errors) or [reason],
                backend=backend,
            )

        action = plan.action
        operation: dict[str, Any]
        errors: list[Any] = []
        rollback = dict(plan.rollback_plan or {})
        after = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "capture_phase": "after",
            "status": "ok",
            "side_effects": False,
        }
        operation_status = "ok"
        if action in {"version", "query", "read"}:
            operation = {
                "status": "ok",
                "action": action,
                "side_effects": False,
            }
            for key in ("version", "process", "memory"):
                if key in before:
                    after[key] = _json_value(before[key])
        else:
            operation, after, rollback, errors = self._execute_write(
                backend, plan, before
            )
            operation_status = str(operation.get("status") or "failed")

        if action != "write":
            rollback = _not_required_rollback(
                rollback, "not_required", "read-only operation"
            )
        success = operation_status == "ok"
        if success:
            status = "ok" if _is_production_backend(backend) else "test-double"
        elif operation_status in {"dependency-gated", "unavailable"}:
            status = operation_status
        else:
            status = "failed"
        after["postcondition_hash"] = _postcondition_hash(action, plan.parameters, after)
        return self._build_result(
            plan,
            validation,
            status=status,
            before=before,
            after=after,
            rollback=rollback,
            operation=operation,
            errors=errors,
            backend=backend,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        backend = self._select_backend(context)
        rollback = result.rollback_plan
        base = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "session_id": result.session_id,
            "action": result.action,
            "target_identity": _target_payload(result.target),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "driver_backed": _is_production_backend(backend),
            "test_double": _is_test_double_backend(backend),
        }
        if result.action != "write" or not rollback.get("active"):
            details = {
                **base,
                "status": "not_required",
                "reason": rollback.get("status") or rollback.get("reason") or "no active write",
            }
            self._record_rollback(result, details, ok=True, restored=False)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details=details,
            )

        pid = _coerce_int(rollback.get("pid"))
        creation = _coerce_int(rollback.get("process_creation_time"))
        address = _coerce_int(rollback.get("address"))
        size = _coerce_int(rollback.get("size"))
        original = _hex_bytes(rollback.get("before_hex"))
        expected_current = _hex_bytes(rollback.get("expected_current_hex"))
        expected_after = _hex_bytes(rollback.get("expected_after_hex"))
        allowed_ranges = rollback.get("allowed_ranges") or []
        recorded_before = _snapshot_bytes(result.before_snapshot.get("memory"))
        recorded_after = _snapshot_bytes(result.after_snapshot.get("memory"))
        target_identity = _target_payload(result.target)
        target_pid = _coerce_int(target_identity.get("pid"))
        target_metadata = target_identity.get("metadata")
        target_creation = _first_int(
            target_metadata if isinstance(target_metadata, Mapping) else {},
            "process_creation_time",
            "creation_time_100ns",
            "creation_time",
        )
        metadata_valid = bool(
            pid
            and creation
            and address is not None
            and original
            and expected_current
            and expected_after == expected_current
            and size == len(original) == len(expected_current)
            and recorded_before == original
            and recorded_after == expected_current
            and rollback.get("before_sha256")
            == hashlib.sha256(original).hexdigest()
            and rollback.get("after_sha256")
            == hashlib.sha256(expected_current).hexdigest()
            and _valid_user_range(address, size, self.max_write_bytes)
            and _range_is_allowlisted(address, size, allowed_ranges)
            and (target_pid is None or target_pid == pid)
            and (target_creation is None or target_creation == creation)
            and rollback.get("precondition_hash")
            == result.provenance.get("precondition_hash")
        )
        if not metadata_valid:
            details = {**base, "status": "failed", "reason": "rollback metadata is incomplete"}
            self._record_rollback(result, details, ok=False, restored=False)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details=details,
            )
        try:
            version = _json_mapping(backend.get_version())
            _validate_version_mapping(version)
            process = _json_mapping(backend.query_process(pid, creation))
            if (
                _coerce_int(process.get("pid")) != pid
                or _coerce_int(process.get("process_creation_time")) != creation
                or process.get("identity_verified") is not True
            ):
                raise KernelMemoryBackendError("rollback", "process creation identity drifted")
            current = bytes(backend.read(pid, creation, address, len(original)))
            if len(current) != len(original):
                raise KernelMemoryBackendError("rollback", "rollback preimage read was incomplete")
            if current == original:
                restored = True
                operation = {"status": "already_restored", "bytes_transferred": 0}
            elif current != expected_current:
                details = {
                    **base,
                    "status": "failed",
                    "reason": "live bytes no longer match the rollback expected-current precondition",
                    "expected_current_sha256": hashlib.sha256(expected_current).hexdigest(),
                    "actual_sha256": hashlib.sha256(current).hexdigest(),
                    "process": _json_mapping(process),
                    "version": _json_mapping(version),
                }
                self._record_rollback(result, details, ok=False, restored=False)
                return CapabilityRollbackResult(
                    capability=result.capability,
                    provider=result.provider,
                    session_id=result.session_id,
                    ok=False,
                    restored=False,
                    details=details,
                )
            else:
                operation = _json_mapping(
                    backend.write(pid, creation, address, current, original)
                )
                verified = bytes(backend.read(pid, creation, address, len(original)))
                restored = verified == original
                if not restored:
                    raise KernelMemoryBackendError("rollback", "write-back verification failed")
            details = {
                **base,
                "status": "restored"
                if _is_production_backend(backend)
                else "test-double-restored",
                "operation": operation,
                "restored_sha256": hashlib.sha256(original).hexdigest(),
                "process": _json_mapping(process),
                "version": _json_mapping(version),
            }
            rollback.update(
                {
                    "active": False,
                    "completed": True,
                    "restored": True,
                    "status": details["status"],
                }
            )
            self._record_rollback(result, details, ok=True, restored=True)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=True,
                details=details,
            )
        except Exception as exc:
            payload = _exception_payload(exc)
            details = {
                **base,
                "status": payload.get("status") or "failed",
                "reason": payload.get("message") or str(exc),
                "error": payload,
            }
            self._record_rollback(result, details, ok=False, restored=False)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
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
        root.mkdir(parents=True, exist_ok=True)
        prefix = f"kernel_memory/{_safe_segment(result.session_id)}"
        action = _safe_segment(result.action)
        audit = CapabilityArtifact(
            path=f"{prefix}/{action}-audit.json",
            kind="kernel-memory-audit",
            description="Kernel-memory capability audit record",
            metadata={"materialized": False},
        )
        rollback_metadata = CapabilityArtifact(
            path=f"{prefix}/{action}-rollback.json",
            kind="kernel-memory-rollback-metadata",
            description="Compare-and-restore rollback metadata",
            metadata={"materialized": False},
        )
        provenance = CapabilityArtifact(
            path=f"{prefix}/{action}-provenance.json",
            kind="kernel-memory-provenance",
            description="Kernel-memory plan, validation, and execution provenance",
            metadata={"materialized": False},
        )
        dashboard_trace = CapabilityArtifact(
            path=f"{prefix}/{action}-dashboard-trace.json",
            kind="kernel-memory-dashboard-trace",
            description="Dashboard-ready kernel-memory execution trace",
            metadata={"materialized": False},
        )
        artifacts: list[CapabilityArtifact] = [
            audit,
            rollback_metadata,
            provenance,
            dashboard_trace,
        ]
        json_specs: list[tuple[CapabilityArtifact, bytes]] = [
            (
                rollback_metadata,
                _json_bytes(
                    {
                        "schema_version": AUDIT_SCHEMA_VERSION,
                        "session_id": result.session_id,
                        "target_identity": _target_payload(result.target),
                        "precondition_hash": result.provenance.get(
                            "precondition_hash"
                        ),
                        "rollback_plan": result.rollback_plan,
                    }
                ),
            ),
            (provenance, _json_bytes(result.provenance)),
            (
                dashboard_trace,
                _json_bytes(
                    {
                        "schema_version": AUDIT_SCHEMA_VERSION,
                        "session_id": result.session_id,
                        "trace": result.dashboard_trace,
                    }
                ),
            ),
        ]
        snapshot_specs: list[tuple[CapabilityArtifact, bytes]] = []
        for phase, snapshot in (
            ("before", result.before_snapshot),
            ("after", result.after_snapshot),
        ):
            data = _snapshot_bytes(snapshot.get("memory"))
            if data is None:
                continue
            artifact = CapabilityArtifact(
                path=f"{prefix}/{action}-{phase}.bin",
                kind=f"kernel-memory-{phase}-snapshot",
                description=f"Exact {phase} memory bytes",
                metadata={"materialized": False, "size": len(data)},
            )
            artifacts.append(artifact)
            snapshot_specs.append((artifact, data))

        entries = [self._manifest_entry(result, item) for item in artifacts]
        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        _sync_result_report(result)

        for artifact, data in json_specs:
            destination = _artifact_destination(root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            _materialize_metadata(artifact, data)
            _update_manifest_entry(entries, artifact)

        for artifact, data in snapshot_specs:
            destination = _artifact_destination(root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            _materialize_metadata(artifact, data)
            _update_manifest_entry(entries, artifact)

        audit_payload = _audit_payload(result)
        audit_bytes = _json_bytes(audit_payload)
        audit_path = _artifact_destination(root, audit.path)
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        audit_path.write_bytes(audit_bytes)
        _materialize_metadata(audit, audit_bytes)
        _update_manifest_entry(entries, audit)

        manifest_payload = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "target_identity": _target_payload(result.target),
            "entries": entries,
            "provenance": _json_mapping(result.provenance),
        }
        manifest_bytes = _json_bytes(manifest_payload)
        manifest = CapabilityArtifact(
            path=f"{prefix}/evidence-manifest.json",
            kind="evidence-manifest",
            description="Kernel-memory evidence manifest",
            metadata={},
        )
        manifest_path = _artifact_destination(root, manifest.path)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest_bytes)
        _materialize_metadata(manifest, manifest_bytes)
        artifacts.append(manifest)

        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        _sync_result_report(result)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=entries,
        )

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
            "plan capability/provider identity does not match kernel-memory provider",
        )
        check(
            "supported_action",
            action in _SUPPORTED_ACTIONS,
            f"unsupported kernel-memory action: {action or plan.action}",
        )
        parse_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        check(
            "parameters",
            not parse_errors,
            "; ".join(parse_errors) if parse_errors else "parameters are valid",
        )
        if action != "version":
            pid = _coerce_int(plan.parameters.get("pid"))
            creation = _coerce_int(plan.parameters.get("process_creation_time"))
            target_pid = _coerce_int(getattr(plan.target, "pid", None))
            check(
                "target_identity",
                bool(
                    pid
                    and pid > 0
                    and creation
                    and creation > 0
                    and not plan.parameters.get("pid_conflict")
                    and not plan.parameters.get("creation_time_conflict")
                    and (target_pid is None or target_pid == pid)
                ),
                "PID and process creation identity must be positive, stable, and consistent",
                pid=pid,
                process_creation_time=creation,
                target_pid=target_pid,
            )
        if action in {"read", "write"}:
            address = _coerce_int(plan.parameters.get("address"))
            size = _coerce_int(plan.parameters.get("size"))
            limit = self.max_write_bytes if action == "write" else self.max_read_bytes
            check(
                "bounded_user_range",
                _valid_user_range(address, size, limit),
                "address and length must stay within the bounded user-mode range",
                address=address,
                size=size,
                limit=limit,
            )
            check(
                "address_allowlist",
                _range_is_allowlisted(
                    address, size, plan.parameters.get("allowed_ranges") or []
                ),
                "memory range is not covered by an explicit address allowlist",
            )
        if action == "write":
            expected = _hex_bytes(plan.parameters.get("expected_hex"))
            replacement = _hex_bytes(plan.parameters.get("data_hex"))
            size = _coerce_int(plan.parameters.get("size"))
            check(
                "write_authorization",
                plan.parameters.get("authorized") is True,
                "write requires authorized=true",
            )
            check(
                "write_payload",
                bool(
                    expected
                    and replacement
                    and len(expected) == len(replacement) == size
                ),
                "write requires equal non-empty expected and replacement bytes",
            )

        current = _capture_live(backend, action, plan.parameters)
        current.update(
            {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "capture_phase": "validate",
                "backend": _backend_description(backend),
            }
        )
        gate_status = _snapshot_gate_status(current)
        if gate_status:
            reason = str((current.get("error") or {}).get("message") or current.get("reason") or "kernel driver dependency is unavailable")
            checks.append(
                {
                    "name": "driver_dependency",
                    "status": gate_status,
                    "message": reason,
                }
            )
            warnings.append(reason)
            errors.append(reason)
            return (
                CapabilityValidation(
                    capability=plan.capability,
                    provider=plan.provider,
                    session_id=plan.session_id,
                    ok=False,
                    checks=checks,
                    warnings=_deduplicate(warnings),
                    errors=_deduplicate(errors),
                ),
                current,
            )
        checks.append(
            {
                "name": "driver_dependency",
                "status": "ok",
                "message": "signed driver and protocol are available",
                "version": current.get("version"),
            }
        )
        if _is_test_double_backend(backend):
            warnings.append("execution backend is a test double and cannot prove production capability")
            checks.append(
                {
                    "name": "production_backend",
                    "status": "test-double",
                    "message": warnings[-1],
                }
            )
        elif _is_production_backend(backend):
            checks.append(
                {
                    "name": "production_backend",
                    "status": "ok",
                    "message": "production DeviceIoControl backend is active",
                }
            )
        else:
            checks.append(
                {
                    "name": "production_backend",
                    "status": "dependency-gated",
                    "message": "the fixed production DeviceIoControl backend is not active",
                }
            )
        if action != "version":
            process = current.get("process") or {}
            check(
                "live_process_identity",
                bool(
                    process.get("identity_verified")
                    and _coerce_int(process.get("pid")) == _coerce_int(plan.parameters.get("pid"))
                    and _coerce_int(process.get("process_creation_time"))
                    == _coerce_int(plan.parameters.get("process_creation_time"))
                ),
                "live PID/create-time identity does not match the plan",
                process=process,
            )
        if action in {"read", "write"}:
            current_bytes = _snapshot_bytes(current.get("memory"))
            size = _coerce_int(plan.parameters.get("size"))
            check(
                "complete_before_snapshot",
                current_bytes is not None and len(current_bytes) == size,
                "driver did not return the exact requested before snapshot",
                captured_size=len(current_bytes) if current_bytes is not None else None,
                requested_size=size,
            )
            if action == "write":
                expected = _hex_bytes(plan.parameters.get("expected_hex"))
                check(
                    "expected_original_bytes",
                    current_bytes is not None and current_bytes == expected,
                    "live bytes do not match the explicit expected-original precondition",
                    expected_sha256=hashlib.sha256(expected or b"").hexdigest(),
                    actual_sha256=hashlib.sha256(current_bytes or b"").hexdigest(),
                )
        current_hash = _precondition_hash(action, plan.parameters, current)
        check(
            "precondition_hash",
            bool(plan.precondition_hash and current_hash == plan.precondition_hash),
            "live driver/process/memory state no longer matches the planned precondition",
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
                warnings=_deduplicate(warnings),
                errors=_deduplicate(errors),
            ),
            current,
        )

    def _execute_write(
        self,
        backend: KernelMemoryBackend,
        plan: CapabilityPlan,
        before: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[Any]]:
        pid = int(_coerce_int(plan.parameters.get("pid")) or 0)
        creation = int(_coerce_int(plan.parameters.get("process_creation_time")) or 0)
        address = int(_coerce_int(plan.parameters.get("address")) or 0)
        expected = _hex_bytes(plan.parameters.get("expected_hex")) or b""
        replacement = _hex_bytes(plan.parameters.get("data_hex")) or b""
        original = _snapshot_bytes(before.get("memory")) or expected
        errors: list[Any] = []
        operation: dict[str, Any]
        final_bytes = original
        try:
            write_result = _json_mapping(
                backend.write(pid, creation, address, expected, replacement)
            )
            final_bytes = bytes(backend.read(pid, creation, address, len(replacement)))
            if len(final_bytes) != len(replacement):
                raise KernelMemoryBackendError("write", "write-back read returned the wrong length")
            if final_bytes != replacement:
                raise KernelMemoryBackendError("write", "write-back bytes do not match replacement")
            transferred = _coerce_int(write_result.get("bytes_transferred"))
            if transferred != len(replacement):
                raise KernelMemoryBackendError("write", "driver did not report a complete write")
            operation = {
                "status": "ok",
                "action": "write",
                "bytes_transferred": transferred,
                "driver_response": write_result,
                "write_verified": True,
                "side_effects": True,
            }
            rollback = dict(plan.rollback_plan or {})
            rollback.update(
                {
                    "supported": True,
                    "active": True,
                    "status": "pending",
                    "expected_current_hex": final_bytes.hex(),
                    "after_sha256": hashlib.sha256(final_bytes).hexdigest(),
                }
            )
            return (
                operation,
                {
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": "ok",
                    "side_effects": True,
                    "memory": _bytes_snapshot(final_bytes, address),
                    "write_verified": True,
                },
                rollback,
                errors,
            )
        except Exception as exc:
            error = _exception_payload(exc)
            errors.append(error)
            compensation, final_bytes = _compensate_write(
                backend,
                pid=pid,
                creation_time=creation,
                address=address,
                original=original,
                intended=replacement,
            )
            final_state_complete = len(final_bytes) == len(original)
            side_effects = final_state_complete and final_bytes != original
            state_unknown = not final_state_complete
            operation_status = str(error.get("status") or "failed")
            if operation_status not in {"dependency-gated", "unavailable"}:
                operation_status = "failed"
            operation = {
                "status": operation_status,
                "action": "write",
                "error": error,
                "write_verified": False,
                "compensation": compensation,
                "side_effects": side_effects,
                "state_unknown": state_unknown,
            }
            rollback = dict(plan.rollback_plan or {})
            if compensation.get("restored"):
                rollback.update(
                    {
                        "supported": False,
                        "active": False,
                        "status": "compensated",
                        "reason": "failed write was restored immediately",
                    }
                )
            elif side_effects and compensation.get("attributable"):
                rollback.update(
                    {
                        "supported": True,
                        "active": True,
                        "status": "compensation_failed",
                        "expected_current_hex": final_bytes.hex(),
                    }
                )
            elif side_effects or state_unknown:
                rollback.update(
                    {
                        "supported": False,
                        "active": False,
                        "mode": "manual_review",
                        "status": "state_conflict" if side_effects else "state_unknown",
                        "reason": (
                            "live bytes are not attributable to this write; "
                            "automatic rollback is disabled"
                        ),
                    }
                )
            else:
                rollback = _not_required_rollback(
                    rollback, "not_required", "write mutation was not observed"
                )
            return (
                operation,
                {
                    "schema_version": AUDIT_SCHEMA_VERSION,
                    "capture_phase": "after",
                    "status": operation_status,
                    "side_effects": side_effects,
                    "state_unknown": state_unknown,
                    "memory": _bytes_snapshot(final_bytes, address),
                    "write_verified": False,
                    "compensation": compensation,
                },
                rollback,
                errors,
            )

    def _build_result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        *,
        status: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        rollback: Mapping[str, Any],
        operation: Mapping[str, Any],
        errors: Sequence[Any],
        backend: KernelMemoryBackend,
    ) -> CapabilityExecutionResult:
        backend_description = _backend_description(backend)
        test_double = _is_test_double_backend(backend)
        target = _target_payload(plan.target)
        executed_at = _utc_now()
        events = [
            {
                "kind": "plan",
                "ts": plan.provenance.get("planned_at") or executed_at,
                "message": "kernel-memory plan created",
            },
            {
                "kind": "validate",
                "ts": executed_at,
                "message": "kernel-memory plan validated",
                "ok": validation.ok,
            },
            {
                "kind": "execute",
                "ts": executed_at,
                "message": f"kernel-memory execution finished with status {status}",
            },
        ]
        real_driver = bool(
            status == "ok"
            and _is_production_backend(backend)
            and operation.get("status") == "ok"
        )
        provenance = {
            **_json_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "execution": {
                "status": status,
                "executed_at": executed_at,
                "real_driver_completed": real_driver,
                "test_double": test_double,
                "backend": backend_description,
            },
        }
        artifact = CapabilityArtifact(
            path=(
                f"kernel_memory/{_safe_segment(plan.session_id)}/"
                f"{_safe_segment(plan.action)}-audit.json"
            ),
            kind="kernel-memory-audit",
            description="Kernel-memory capability audit record",
            metadata={"materialized": False, "status": status},
        )
        manifest_entry = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": self.capability_name,
            "provider": self.provider_name,
            "session_id": plan.session_id,
            "action": plan.action,
            "status": status,
            "target_identity": target,
            "precondition_hash": plan.precondition_hash,
        }
        report = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "status": status,
            "action": plan.action,
            "session_id": plan.session_id,
            "target_identity": target,
            "precondition_hash": plan.precondition_hash,
            "before_snapshot": _json_mapping(before),
            "after_snapshot": _json_mapping(after),
            "rollback_plan": _json_mapping(rollback),
            "provenance": provenance,
            "backend": backend_description,
            "operation": _json_mapping(operation),
            "validation": validation.to_dict(),
            "evidence_manifest_entries": [manifest_entry],
            "artifacts": [artifact.to_dict()],
            "events": events,
            "errors": [_json_value(item) for item in errors],
        }
        trace = {
            "kind": "kernel_memory_execution",
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": plan.session_id,
            "action": plan.action,
            "status": status,
            "pid": plan.parameters.get("pid"),
            "side_effects": bool(after.get("side_effects")),
            "real_driver_completed": real_driver,
        }
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(before),
            after_snapshot=dict(after),
            rollback_plan=dict(rollback),
            artifacts=[artifact],
            evidence_manifest_entries=[manifest_entry],
            report_section=report,
            dashboard_trace=[trace],
            provenance=provenance,
        )

    def _record_rollback(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        *,
        ok: bool,
        restored: bool,
    ) -> None:
        payload = _json_mapping(details)
        result.after_snapshot["rollback"] = payload
        result.report_section["rollback"] = payload
        result.dashboard_trace.append(
            {
                "kind": "kernel_memory_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "action": result.action,
                "status": payload.get("status"),
                "ok": ok,
                "restored": restored,
            }
        )
        result.report_section.setdefault("events", []).append(
            {
                "kind": "rollback",
                "ts": _utc_now(),
                "message": f"kernel-memory rollback finished with status {payload.get('status')}",
            }
        )
        _sync_result_report(result)

    def _manifest_entry(
        self,
        result: CapabilityExecutionResult,
        artifact: CapabilityArtifact,
    ) -> dict[str, Any]:
        return {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": self.capability_name,
            "provider": self.provider_name,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "target_identity": _target_payload(result.target),
            "precondition_hash": result.provenance.get("precondition_hash"),
        }

    def _select_backend(self, context: Optional[dict[str, Any]]) -> KernelMemoryBackend:
        if context and context.get("kernel_memory_backend") is not None:
            return context["kernel_memory_backend"]
        return self.backend


KernelMemoryProvider = KernelDriverMemoryProvider


def _normalize_action(value: Any) -> str:
    action = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _ACTION_ALIASES.get(action, action)


def _normalize_parameters(
    request: CapabilityRequest,
    action: str,
    *,
    max_read_bytes: int,
    max_write_bytes: int,
) -> dict[str, Any]:
    params = dict(request.params or {})
    errors: list[str] = []
    target_pid = _coerce_int(getattr(request.target, "pid", None))
    parameter_pid = _coerce_int(params.get("pid"))
    pid = parameter_pid if parameter_pid is not None else target_pid
    pid_conflict = (
        target_pid is not None
        and parameter_pid is not None
        and target_pid != parameter_pid
    )
    metadata = getattr(request.target, "metadata", {}) or {}
    target_creation = _first_int(
        metadata,
        "process_creation_time",
        "creation_time_100ns",
        "creation_time",
    )
    parameter_creation = _first_int(
        params,
        "process_creation_time",
        "creation_time_100ns",
        "creation_time",
    )
    creation = parameter_creation if parameter_creation is not None else target_creation
    creation_conflict = (
        target_creation is not None
        and parameter_creation is not None
        and target_creation != parameter_creation
    )
    normalized: dict[str, Any] = {
        "requested_action": request.action,
        "pid": pid,
        "pid_conflict": pid_conflict,
        "process_creation_time": creation,
        "creation_time_conflict": creation_conflict,
        "authorized": params.get("authorized") is True,
    }
    if action not in _SUPPORTED_ACTIONS:
        errors.append(f"unsupported action: {action or request.action}")
    if action != "version":
        if pid is None or pid <= 0 or pid > 0xFFFFFFFF:
            errors.append("PID must be between 1 and 0xffffffff")
        if creation is None or creation <= 0 or creation > 0xFFFFFFFFFFFFFFFF:
            errors.append("process creation time identity must be a positive uint64")
        if pid_conflict:
            errors.append("target PID conflicts with parameter PID")
        if creation_conflict:
            errors.append("target process creation identity conflicts with parameters")
    if action in {"read", "write"}:
        address = _coerce_int(params.get("address"))
        normalized["address"] = address
        raw_ranges = params.get("allowed_ranges", params.get("address_allowlist"))
        ranges, range_errors = _normalize_ranges(raw_ranges)
        normalized["allowed_ranges"] = ranges
        errors.extend(range_errors)
        if action == "read":
            size = _coerce_int(params.get("size", params.get("length")))
            normalized["size"] = size
            if not _valid_user_range(address, size, max_read_bytes):
                errors.append("read range exceeds the configured bounded user-memory limit")
        else:
            expected = _parse_bytes(
                params.get(
                    "expected_original_bytes",
                    params.get("expected", params.get("expected_hex")),
                )
            )
            data = _parse_bytes(
                params.get("data", params.get("replacement", params.get("data_hex")))
            )
            if expected is None:
                errors.append("write requires explicit expected original bytes")
                expected = b""
            if data is None:
                errors.append("write requires replacement bytes")
                data = b""
            normalized.update(
                {
                    "size": len(data),
                    "expected_hex": expected.hex(),
                    "expected_sha256": hashlib.sha256(expected).hexdigest(),
                    "data_hex": data.hex(),
                    "data_sha256": hashlib.sha256(data).hexdigest(),
                }
            )
            if not data or len(expected) != len(data):
                errors.append("write expected and replacement bytes must be equal non-zero lengths")
            if not _valid_user_range(address, len(data), max_write_bytes):
                errors.append("write range exceeds the configured bounded user-memory limit")
            if params.get("authorized") is not True:
                errors.append("write requires authorized=true")
        if not _range_is_allowlisted(
            normalized.get("address"), normalized.get("size"), ranges
        ):
            errors.append("requested memory range is outside the explicit allowlist")
    normalized["parameter_errors"] = _deduplicate(errors)
    return normalized


def _normalize_ranges(value: Any) -> tuple[list[dict[str, int]], list[str]]:
    ranges: list[dict[str, int]] = []
    errors: list[str] = []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return [], ["allowed_ranges must be an explicit sequence"]
    for index, item in enumerate(value):
        start: Optional[int]
        end: Optional[int]
        if isinstance(item, Mapping):
            start = _coerce_int(item.get("start"))
            if item.get("end_exclusive") is not None:
                end = _coerce_int(item.get("end_exclusive"))
            elif item.get("end") is not None:
                end = _coerce_int(item.get("end"))
            else:
                size = _coerce_int(item.get("size"))
                end = start + size if start is not None and size is not None else None
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)) and len(item) == 2:
            start = _coerce_int(item[0])
            end = _coerce_int(item[1])
        else:
            errors.append(f"allowed_ranges[{index}] has an invalid shape")
            continue
        if not _valid_user_range(start, (end - start) if start is not None and end is not None else None, MAX_USER_ADDRESS):
            errors.append(f"allowed_ranges[{index}] is not a valid user-mode interval")
            continue
        ranges.append({"start": int(start), "end_exclusive": int(end)})
    ranges.sort(key=lambda item: (item["start"], item["end_exclusive"]))
    return ranges, errors


def _capture_live(
    backend: KernelMemoryBackend,
    action: str,
    parameters: Mapping[str, Any],
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {"status": "ok"}
    try:
        version = _json_mapping(backend.get_version())
        _validate_version_mapping(version)
        snapshot["version"] = version
        if action == "version":
            return snapshot
        pid = _required_int(parameters, "pid")
        creation = _required_int(parameters, "process_creation_time")
        process = _json_mapping(backend.query_process(pid, creation))
        if (
            _coerce_int(process.get("pid")) != pid
            or _coerce_int(process.get("process_creation_time")) != creation
            or process.get("identity_verified") is not True
        ):
            raise KernelMemoryBackendError(
                "query_process", "backend did not prove the requested PID/create-time identity"
            )
        snapshot["process"] = process
        if action in {"read", "write"}:
            address = _required_int(parameters, "address")
            size = _required_int(parameters, "size")
            data = bytes(backend.read(pid, creation, address, size))
            if len(data) != size:
                raise KernelMemoryBackendError(
                    "read",
                    "backend returned a non-exact memory length",
                    details={"expected": size, "actual": len(data)},
                )
            snapshot["memory"] = _bytes_snapshot(data, address)
        return snapshot
    except Exception as exc:
        payload = _exception_payload(exc)
        status = str(payload.get("status") or "failed")
        snapshot.update({"status": status, "error": payload})
        return snapshot


def _validate_version_mapping(version: Mapping[str, Any]) -> None:
    protocol_version = _coerce_int(version.get("protocol_version"))
    struct_version = _coerce_int(version.get("struct_version"))
    protocol_min = _coerce_int(version.get("protocol_min"))
    protocol_max = _coerce_int(version.get("protocol_max"))
    max_read = _coerce_int(version.get("max_read_bytes"))
    max_write = _coerce_int(version.get("max_write_bytes"))
    operation_mask = _coerce_int(version.get("operation_mask"))
    required_mask = sum(1 << (operation - 1) for operation in _OPERATION_IOCTL)
    if not (
        version.get("status") == "ok"
        and protocol_version == PROTOCOL_VERSION
        and struct_version == 1
        and protocol_min is not None
        and protocol_max is not None
        and protocol_min <= PROTOCOL_VERSION <= protocol_max
        and max_read is not None
        and 0 < max_read <= HARD_MAX_READ_BYTES
        and max_write is not None
        and 0 < max_write <= HARD_MAX_WRITE_BYTES
        and operation_mask is not None
        and operation_mask & required_mask == required_mask
    ):
        raise KernelMemoryBackendError(
            "version",
            "backend version response is missing or incompatible",
            status="dependency-gated",
        )


def _initial_rollback(
    action: str,
    parameters: Mapping[str, Any],
    before: Mapping[str, Any],
) -> dict[str, Any]:
    base = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "action": action,
        "pid": parameters.get("pid"),
        "process_creation_time": parameters.get("process_creation_time"),
        "address": parameters.get("address"),
        "active": False,
    }
    if action == "write":
        data = _snapshot_bytes(before.get("memory"))
        return {
            **base,
            "supported": bool(data),
            "mode": "compare_restore",
            "size": parameters.get("size"),
            "allowed_ranges": _json_value(parameters.get("allowed_ranges") or []),
            "before_hex": data.hex() if data is not None else None,
            "before_sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
            "expected_after_hex": parameters.get("data_hex"),
            "status": "planned",
        }
    return {
        **base,
        "supported": False,
        "mode": "not_required",
        "status": "not_required",
        "reason": "read-only operation",
    }


def _not_required_rollback(
    rollback: Mapping[str, Any], status: str, reason: str
) -> dict[str, Any]:
    return {
        **dict(rollback or {}),
        "supported": False,
        "active": False,
        "mode": "not_required",
        "status": status,
        "reason": reason,
    }


def _compensate_write(
    backend: KernelMemoryBackend,
    *,
    pid: int,
    creation_time: int,
    address: int,
    original: bytes,
    intended: bytes,
) -> tuple[dict[str, Any], bytes]:
    try:
        current = bytes(backend.read(pid, creation_time, address, len(original)))
        if len(current) != len(original):
            return (
                {"attempted": False, "restored": False, "reason": "short compensation read"},
                current,
            )
        if current == original:
            return (
                {
                    "attempted": False,
                    "restored": True,
                    "attributable": False,
                    "status": "already_original",
                },
                current,
            )
        if current != intended:
            return (
                {
                    "attempted": False,
                    "restored": False,
                    "attributable": False,
                    "status": "state_conflict",
                    "reason": "live bytes do not match the intended write postimage",
                    "actual_sha256": hashlib.sha256(current).hexdigest(),
                    "intended_sha256": hashlib.sha256(intended).hexdigest(),
                },
                current,
            )
        response = _json_mapping(
            backend.write(pid, creation_time, address, current, original)
        )
        verified = bytes(backend.read(pid, creation_time, address, len(original)))
        restored = verified == original
        return (
            {
                "attempted": True,
                "restored": restored,
                "attributable": True,
                "status": "restored" if restored else "failed",
                "response": response,
                "before_compensation_sha256": hashlib.sha256(current).hexdigest(),
                "after_compensation_sha256": hashlib.sha256(verified).hexdigest(),
            },
            verified,
        )
    except Exception as exc:
        try:
            current = bytes(backend.read(pid, creation_time, address, len(original)))
        except Exception:
            current = b""
        return (
            {
                "attempted": True,
                "restored": False,
                "attributable": False,
                "status": "failed",
                "error": _exception_payload(exc),
            },
            current,
        )


def _precondition_hash(
    action: str,
    parameters: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> str:
    memory = snapshot.get("memory") or {}
    process = snapshot.get("process") or {}
    version = snapshot.get("version") or {}
    return _canonical_hash(
        {
            "action": action,
            "pid": parameters.get("pid"),
            "process_creation_time": parameters.get("process_creation_time"),
            "address": parameters.get("address"),
            "size": parameters.get("size"),
            "allowed_ranges": parameters.get("allowed_ranges"),
            "expected_sha256": parameters.get("expected_sha256"),
            "data_sha256": parameters.get("data_sha256"),
            "protocol": {
                "protocol_min": version.get("protocol_min"),
                "protocol_max": version.get("protocol_max"),
                "max_read_bytes": version.get("max_read_bytes"),
                "max_write_bytes": version.get("max_write_bytes"),
                "operation_mask": version.get("operation_mask"),
            },
            "process": {
                "pid": process.get("pid"),
                "process_creation_time": process.get("process_creation_time"),
                "identity_verified": process.get("identity_verified"),
            },
            "memory_sha256": memory.get("sha256"),
            "snapshot_status": snapshot.get("status"),
        }
    )


def _postcondition_hash(
    action: str,
    parameters: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> str:
    memory = snapshot.get("memory") or {}
    return _canonical_hash(
        {
            "action": action,
            "pid": parameters.get("pid"),
            "process_creation_time": parameters.get("process_creation_time"),
            "address": parameters.get("address"),
            "size": parameters.get("size"),
            "status": snapshot.get("status"),
            "memory_sha256": memory.get("sha256"),
            "side_effects": snapshot.get("side_effects"),
        }
    )


def _plan_steps(action: str) -> list[dict[str, Any]]:
    names = ["verify_driver_protocol"]
    if action != "version":
        names.append("pin_pid_and_process_creation_identity")
    if action in {"read", "write"}:
        names.extend(["validate_user_range_allowlist", "capture_before_snapshot"])
    if action == "read":
        names.extend(["bounded_driver_read", "verify_exact_return_length"])
    elif action == "write":
        names.extend(
            [
                "verify_expected_original_bytes",
                "bounded_compare_before_write",
                "write_back_read_verification",
                "prepare_compare_restore_rollback",
            ]
        )
    elif action == "query":
        names.append("query_allowlisted_process_identity")
    else:
        names.append("query_driver_version")
    names.extend(["record_provenance", "collect_evidence_manifest"])
    return [
        {"step": name, "status": "planned", "required": True} for name in names
    ]


def _snapshot_gate_status(snapshot: Mapping[str, Any]) -> Optional[str]:
    status = str(snapshot.get("status") or "")
    if status in {"dependency-gated", "unavailable"}:
        return status
    return None


def _backend_description(backend: Any) -> dict[str, Any]:
    describe = getattr(backend, "describe", None)
    if callable(describe):
        try:
            payload = describe()
            if isinstance(payload, Mapping):
                description = _json_mapping(payload)
            else:
                description = {}
        except Exception as exc:
            description = {
                "name": getattr(backend, "name", type(backend).__name__),
                "error": str(exc),
            }
    else:
        description = {}
    production = _is_production_backend(backend)
    test_double = _is_test_double_backend(backend)
    if production:
        backend_class = "production-driver"
    elif test_double:
        backend_class = "test-double"
    else:
        backend_class = "dependency-gated-driver"
    description.update(
        {
            "name": description.get("name")
            or getattr(backend, "name", type(backend).__name__),
            "available": bool(getattr(backend, "available", False)),
            "status": description.get("status")
            or getattr(backend, "availability_status", None),
            "reason": description.get("reason")
            or getattr(backend, "unavailable_reason", None),
            "backend_class": backend_class,
            "production_backend": production,
            "test_double": test_double,
        }
    )
    return _prune(description)


def _is_production_backend(backend: Any) -> bool:
    """Only the fixed concrete Win32 transport can attest production completion."""

    return bool(
        type(backend) is WindowsKernelMemoryBackend
        and backend.platform_name == "win32"
        and backend.available
        and backend.device_path.casefold() == DEFAULT_DEVICE_PATH.casefold()
        and getattr(backend, "test_double", True) is False
    )


def _is_test_double_backend(backend: Any) -> bool:
    if type(backend) is WindowsKernelMemoryBackend or isinstance(
        backend, UnavailableKernelMemoryBackend
    ):
        return False
    return not _is_production_backend(backend)


def _bytes_snapshot(data: bytes, address: Optional[int]) -> dict[str, Any]:
    raw = bytes(data)
    return {
        "address": address,
        "size": len(raw),
        "hex": raw.hex(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _snapshot_bytes(value: Any) -> Optional[bytes]:
    if not isinstance(value, Mapping):
        return None
    return _hex_bytes(value.get("hex"))


def _valid_user_range(
    address: Optional[int], size: Optional[int], limit: int
) -> bool:
    if address is None or size is None or size <= 0 or size > limit:
        return False
    if address < MIN_USER_ADDRESS or address > MAX_USER_ADDRESS:
        return False
    end = address + size
    return end > address and end - 1 <= MAX_USER_ADDRESS


def _require_uint(name: str, value: Any, bits: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise KernelMemoryProtocolError(f"{name} must be an unsigned {bits}-bit integer")
    if value < 0 or value > (1 << bits) - 1:
        raise KernelMemoryProtocolError(f"{name} is outside the unsigned {bits}-bit range")
    return value


def _require_process_identity(pid: int, process_creation_time: int) -> None:
    if pid <= 0 or process_creation_time <= 0:
        raise KernelMemoryProtocolError(
            "PID and process creation identity must both be non-zero"
        )


def _require_backend_identity(
    operation: str, pid: Any, process_creation_time: Any
) -> None:
    try:
        _require_uint("pid", pid, 32)
        _require_uint("process_creation_time", process_creation_time, 64)
        _require_process_identity(pid, process_creation_time)
    except KernelMemoryProtocolError as exc:
        raise KernelMemoryBackendError(operation, str(exc)) from exc


def _require_backend_user_range(
    operation: str, address: Any, size: Any, limit: int
) -> None:
    try:
        _require_uint("address", address, 64)
        _require_uint("size", size, 32)
    except KernelMemoryProtocolError as exc:
        raise KernelMemoryBackendError(operation, str(exc)) from exc
    if not _valid_user_range(address, size, limit):
        raise KernelMemoryBackendError(
            operation, "requested range exceeds the bounded user-memory limit"
        )


def _validate_response_shape(response: KernelMemoryResponse) -> None:
    if response.operation not in _OPERATION_IOCTL:
        raise KernelMemoryProtocolError("response operation is not allowlisted")
    _require_uint("response pid", response.pid, 32)
    _require_uint(
        "response process_creation_time", response.process_creation_time, 64
    )
    _require_uint("response address", response.address, 64)
    _require_uint("response requested_length", response.requested_length, 32)
    _require_uint("response bytes_transferred", response.bytes_transferred, 32)
    _require_uint("response session_nonce", response.session_nonce, 64)
    if response.session_nonce == 0:
        raise KernelMemoryProtocolError("response session nonce must be non-zero")
    if bytes(response.request_id) == b"\x00" * 16:
        raise KernelMemoryProtocolError("response request_id must be non-zero")
    if isinstance(response.status, bool) or not isinstance(response.status, int):
        raise KernelMemoryProtocolError("response status must be a signed 32-bit integer")
    if not -(1 << 31) <= response.status < (1 << 31):
        raise KernelMemoryProtocolError("response status is outside the signed 32-bit range")
    data = bytes(response.data)
    if response.status != 0:
        if response.bytes_transferred != 0 or data:
            raise KernelMemoryProtocolError(
                "failed response must not claim transferred bytes or return data"
            )
        return
    if response.operation == OP_VERSION:
        if any(
            (
                response.pid,
                response.process_creation_time,
                response.address,
                response.requested_length,
            )
        ) or response.bytes_transferred != _VERSION_STRUCT.size or len(data) != _VERSION_STRUCT.size:
            raise KernelMemoryProtocolError("successful version response has an invalid shape")
    elif response.operation == OP_QUERY_PROCESS:
        _require_process_identity(response.pid, response.process_creation_time)
        if (
            response.address
            or response.requested_length
            or response.bytes_transferred
            or data
        ):
            raise KernelMemoryProtocolError("successful query response has an invalid shape")
    elif response.operation in {OP_READ, OP_WRITE}:
        _require_process_identity(response.pid, response.process_creation_time)
        limit = HARD_MAX_READ_BYTES if response.operation == OP_READ else HARD_MAX_WRITE_BYTES
        if (
            not _valid_user_range(response.address, response.requested_length, limit)
            or response.bytes_transferred != response.requested_length
            or len(data) != response.requested_length
        ):
            raise KernelMemoryProtocolError(
                "successful memory response has an invalid bounded payload shape"
            )


def _range_is_allowlisted(
    address: Optional[int],
    size: Optional[int],
    ranges: Sequence[Mapping[str, Any]],
) -> bool:
    if address is None or size is None or size <= 0:
        return False
    end = address + size
    for item in ranges:
        start = _coerce_int(item.get("start"))
        allowed_end = _coerce_int(item.get("end_exclusive"))
        if start is not None and allowed_end is not None and start <= address and end <= allowed_end:
            return True
    return False


def _parse_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, Sequence) and not isinstance(value, str):
        try:
            return bytes(int(item) for item in value)
        except (TypeError, ValueError, OverflowError):
            return None
    text = str(value).strip().replace("0x", "").replace(" ", "").replace("_", "")
    if not text or len(text) % 2:
        return None
    try:
        return bytes.fromhex(text)
    except ValueError:
        return None


def _hex_bytes(value: Any) -> Optional[bytes]:
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    try:
        return bytes.fromhex(str(value).strip())
    except ValueError:
        return None


def _first_int(mapping: Mapping[str, Any], *keys: str) -> Optional[int]:
    for key in keys:
        if key in mapping and mapping.get(key) is not None:
            return _coerce_int(mapping.get(key))
    return None


def _coerce_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _required_int(mapping: Mapping[str, Any], key: str) -> int:
    value = _coerce_int(mapping.get(key))
    if value is None:
        raise ValueError(f"{key} is required")
    return value


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        _json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _nonce() -> int:
    value = uuid.uuid4().int & 0xFFFFFFFFFFFFFFFF
    return value or 1


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    report = _json_mapping(result.report_section)
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
        "session_id": result.session_id,
        "target_identity": _target_payload(result.target),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "before_snapshot": _json_mapping(result.before_snapshot),
        "after_snapshot": _json_mapping(result.after_snapshot),
        "rollback_plan": _json_mapping(result.rollback_plan),
        "provenance": _json_mapping(result.provenance),
        "evidence_manifest_entries": [
            _json_mapping(item) for item in result.evidence_manifest_entries
        ],
        "report_section": report,
        "dashboard_trace": [
            _json_mapping(item) for item in result.dashboard_trace
        ],
        "events": [_json_mapping(item) for item in report.get("events") or []],
    }


def _sync_result_report(result: CapabilityExecutionResult) -> None:
    result.report_section.update(
        {
            "status": result.status,
            "before_snapshot": _json_mapping(result.before_snapshot),
            "after_snapshot": _json_mapping(result.after_snapshot),
            "rollback_plan": _json_mapping(result.rollback_plan),
            "provenance": _json_mapping(result.provenance),
            "artifacts": [item.to_dict() for item in result.artifacts],
            "evidence_manifest_entries": [
                _json_mapping(item) for item in result.evidence_manifest_entries
            ],
        }
    )


def _artifact_destination(root: Path, artifact_path: str) -> Path:
    text = str(artifact_path or "").strip()
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text)
    if (
        not text
        or text in {".", ".."}
        or windows.is_absolute()
        or bool(windows.drive)
        or posix.is_absolute()
        or ".." in windows.parts
        or ".." in posix.parts
    ):
        raise ValueError("artifact path must stay inside the collection directory")
    destination = (root / Path(text)).resolve()
    if destination != root and root not in destination.parents:
        raise ValueError("artifact path escapes the collection directory")
    return destination


def _safe_segment(value: Any) -> str:
    text = "".join(
        character if character.isalnum() or character in "-_." else "_"
        for character in str(value or "session")
    ).strip(".")
    return text or "session"


def _materialize_metadata(artifact: CapabilityArtifact, data: bytes) -> None:
    artifact.metadata.update(
        {
            "materialized": True,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    )


def _update_manifest_entry(
    entries: list[dict[str, Any]], artifact: CapabilityArtifact
) -> None:
    for entry in entries:
        if entry.get("path") == artifact.path:
            entry.update(
                {
                    "materialized": True,
                    "size": artifact.metadata.get("size"),
                    "sha256": artifact.metadata.get("sha256"),
                }
            )
            return


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(_json_value(value), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def _exception_payload(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, KernelMemoryBackendError):
        return exc.to_dict()
    if isinstance(exc, KernelMemoryProtocolError):
        return {
            "type": type(exc).__name__,
            "operation": "protocol",
            "message": str(exc),
            "status": "dependency-gated",
        }
    return {
        "type": type(exc).__name__,
        "message": str(exc),
        "status": "failed",
    }


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


def _deduplicate(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


__all__ = [
    "ALLOWED_IOCTL_CODES",
    "DEFAULT_ALLOWED_DEVICE_PATHS",
    "DEFAULT_DEVICE_PATH",
    "HARD_MAX_READ_BYTES",
    "HARD_MAX_WRITE_BYTES",
    "IOCTL_KM_QUERY_PROCESS",
    "IOCTL_KM_READ",
    "IOCTL_KM_VERSION",
    "IOCTL_KM_WRITE",
    "KernelDriverMemoryProvider",
    "KernelMemoryBackendError",
    "KernelMemoryProtocolError",
    "KernelMemoryProvider",
    "KernelMemoryRequest",
    "KernelMemoryResponse",
    "KernelMemoryVersionInfo",
    "UnavailableKernelMemoryBackend",
    "WindowsKernelMemoryBackend",
]
