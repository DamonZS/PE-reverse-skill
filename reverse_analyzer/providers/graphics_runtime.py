"""Passive, bounded graphics-present evidence for local Windows processes.

The production backend launches a configured PresentMon executable as a local
subprocess and parses the capture it writes.  This module never injects code,
installs hooks, renders an overlay, or sends input to the target process.

Swap-chain values reported by PresentMon are retained as opaque correlation
identifiers.  In particular, this provider does not manufacture a code address
for ``IDXGISwapChain::Present`` or any other COM vtable method.  OpenGL and
Vulkan targets can additionally be supported by read-only PE export evidence.
Offline records contain RVAs only; live loader records are explicitly scoped to
the analyzer's current process and never claim an address in the target PID.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import json
import math
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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


_SCHEMA_VERSION = 1
_CAPABILITY = "graphics_present_runtime"
_PROVIDER = "windows_presentmon"
_ACTION = "capture"
_ACTION_ALIASES = {
    "capture": _ACTION,
    "capture_present": _ACTION,
    "collect": _ACTION,
    "present": _ACTION,
    "trace": _ACTION,
    "trace_present": _ACTION,
}

_DEFAULT_DURATION_MS = 2_000
_MIN_DURATION_MS = 100
_MAX_DURATION_MS = 30_000
_DEFAULT_TIMEOUT_GRACE_MS = 5_000
_MAX_TIMEOUT_MS = 45_000
_DEFAULT_MAX_EVENTS = 100_000
_MAX_EVENTS = 500_000
_DEFAULT_MAX_CAPTURE_BYTES = 64 * 1024 * 1024
_MAX_CAPTURE_BYTES = 256 * 1024 * 1024
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_MAX_FIELD_LENGTH = 4_096
_MAX_MODULES = 32
_MAX_EXPORTS = 131_072
_MAX_PID = 0xFFFFFFFF

NATIVE_BRIDGE_PROTOCOL = "reverse-analyzer.native-bridge"
NATIVE_BRIDGE_PROTOCOL_VERSION = 1
_DEFAULT_BRIDGE_TIMEOUT_MS = 5_000
_MAX_BRIDGE_TIMEOUT_MS = 60_000
_MAX_BRIDGE_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_BRIDGE_RESPONSE_BYTES = 16 * 1024 * 1024
_GRAPHICS_BRIDGE_ENV_VARS = (
    "REVERSE_ANALYZER_GRAPHICS_BRIDGE",
    "RA_GRAPHICS_BRIDGE",
)
_GRAPHICS_PRESENT_BACKENDS = ("d3d11", "d3d12", "opengl", "vulkan")

_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_PRESENTMON_BASENAME_RE = re.compile(
    r"^presentmon(?:[-_.a-z0-9]*)?(?:\.exe)?$", re.IGNORECASE
)
_CONTROL_PARAMETER_TOKENS = (
    "click",
    "controller",
    "hook",
    "inject",
    "input",
    "keyboard",
    "mouse",
    "overlay",
    "patch",
    "render",
    "script",
)
_ALLOWED_PARAMETER_KEYS = {
    "api_filter",
    "bridge_args",
    "bridge_executable",
    "bridge_path",
    "bridge_timeout_ms",
    "capture_format",
    "duration_ms",
    "max_events",
    "module_paths",
    "modules",
    "pid",
    "presentmon_path",
    "timeout_ms",
}

_PASSIVE_POLICY = {
    "mode": "external_etw_observation",
    "read_only": True,
    "target_process_mutation": False,
    "code_injection": False,
    "hook_installation": False,
    "overlay_rendering": False,
    "input_automation": False,
}

_KEY_ALIASES = {
    "pid": ("processid", "processidentifier", "pid"),
    "application": (
        "application",
        "applicationname",
        "executable",
        "process",
        "processname",
    ),
    "api": ("api", "graphicsapi", "presentruntime", "runtime"),
    "swap_chain": (
        "swapchain",
        "swapchainaddress",
        "swapchainid",
        "swapchainidentifier",
    ),
    "timestamp_s": (
        "cpustarttime",
        "timeinseconds",
        "timestamp",
        "timestamps",
        "time",
    ),
    "frame_time_ms": (
        "frametime",
        "frametimems",
        "msbetweenpresents",
        "msbetweenpresent",
    ),
    "present_api_ms": ("msinpresentapi", "presentapims"),
    "render_complete_ms": ("msuntilrendercomplete", "rendercompletems"),
    "display_latency_ms": ("displaylatency", "displaylatencyms"),
    "displayed_time_ms": ("displayedtime", "displayedtimems"),
    "gpu_time_ms": ("gputime", "gputimems"),
    "cpu_busy_ms": ("cpubusy", "cpubusyms"),
    "present_mode": ("presentmode", "mode"),
    "sync_interval": ("syncinterval",),
    "present_flags": ("presentflags", "flags"),
    "dropped": ("dropped", "isdropped"),
    "lifecycle": ("event", "eventname", "eventtype", "lifecycle", "state"),
}

_KNOWN_API_NAMES = {
    "d3d9": "D3D9",
    "direct3d9": "D3D9",
    "d3d10": "D3D10",
    "direct3d10": "D3D10",
    "d3d11": "D3D11",
    "direct3d11": "D3D11",
    "d3d12": "D3D12",
    "direct3d12": "D3D12",
    "dxgi": "DXGI",
    "opengl": "OpenGL",
    "wgl": "OpenGL",
    "vulkan": "Vulkan",
}


class PresentMonParseError(ValueError):
    """Raised when capture bytes cannot be trusted as PresentMon events."""


class PresentMonRunnerError(RuntimeError):
    """Raised for invalid or failed runner operations."""


@dataclass(frozen=True)
class PresentMonCaptureResult:
    """Result of one bounded local subprocess capture."""

    status: str
    output: str = ""
    output_format: str = "unknown"
    command: tuple[str, ...] = ()
    returncode: Optional[int] = None
    timed_out: bool = False
    process_cleanup: dict[str, Any] = field(default_factory=dict)
    stdout: str = ""
    stderr: str = ""
    started_at: str = ""
    ended_at: str = ""
    elapsed_ms: float = 0.0
    output_sha256: Optional[str] = None
    output_size: int = 0
    local_subprocess: bool = False
    presentmon_identity_verified: bool = False
    error: Optional[str] = None
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, include_output: bool = False) -> dict[str, Any]:
        payload = {
            "status": self.status,
            "output_format": self.output_format,
            "command": list(self.command),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "process_cleanup": _json_safe(self.process_cleanup),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_ms": self.elapsed_ms,
            "output_sha256": self.output_sha256,
            "output_size": self.output_size,
            "local_subprocess": self.local_subprocess,
            "presentmon_identity_verified": self.presentmon_identity_verified,
            "error": self.error,
            "provenance": _json_safe(self.provenance),
        }
        if include_output:
            payload["output"] = self.output
        return _prune(payload)


class GraphicsCaptureRunner(Protocol):
    """Runner boundary; injected implementations are test doubles only."""

    name: str
    test_double: bool
    available: bool
    unavailable_reason: Optional[str]

    def probe(self) -> Mapping[str, Any]: ...

    def capture(
        self,
        *,
        pid: int,
        duration_ms: int,
        timeout_ms: int,
        capture_format: str,
    ) -> PresentMonCaptureResult: ...


class _WindowsKillOnCloseJob:
    """Best-effort Windows job object used to contain PresentMon descendants."""

    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JobObjectExtendedLimitInformation = 9

    def __init__(self) -> None:
        self.handle: Optional[int] = None
        self.assigned = False
        self.error: Optional[str] = None

    def assign(self, process: subprocess.Popen[Any]) -> bool:
        if sys.platform != "win32":
            return False
        try:
            from ctypes import wintypes

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("ReadOperationCount", ctypes.c_ulonglong),
                    ("WriteOperationCount", ctypes.c_ulonglong),
                    ("OtherOperationCount", ctypes.c_ulonglong),
                    ("ReadTransferCount", ctypes.c_ulonglong),
                    ("WriteTransferCount", ctypes.c_ulonglong),
                    ("OtherTransferCount", ctypes.c_ulonglong),
                ]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
            ]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.AssignProcessToJobObject.argtypes = [
                wintypes.HANDLE,
                wintypes.HANDLE,
            ]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            self.handle = int(handle)
            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = (
                self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            if not kernel32.SetInformationJobObject(
                handle,
                self.JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ):
                raise OSError(
                    ctypes.get_last_error(), "SetInformationJobObject failed"
                )
            if not kernel32.AssignProcessToJobObject(handle, int(process._handle)):
                raise OSError(
                    ctypes.get_last_error(), "AssignProcessToJobObject failed"
                )
            self.assigned = True
            return True
        except Exception as exc:  # pragma: no cover - host policy dependent
            self.error = str(exc)
            self.close()
            return False

    def close(self) -> None:
        if not self.handle:
            return
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CloseHandle(ctypes.c_void_p(self.handle))
        finally:
            self.handle = None


@dataclass(frozen=True)
class NativeBridgeCallResult:
    """Auditable outcome of one local JSON bridge subprocess invocation."""

    status: str
    operation: str
    request: dict[str, Any]
    response: dict[str, Any] = field(default_factory=dict)
    command: tuple[str, ...] = ()
    returncode: Optional[int] = None
    timed_out: bool = False
    started_at: str = ""
    ended_at: str = ""
    elapsed_ms: float = 0.0
    stdout_sha256: Optional[str] = None
    stdout_size: int = 0
    stderr: str = ""
    error: Optional[str] = None
    process_cleanup: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in {"ok", "partial", "stopped"}

    def to_dict(self, *, include_payloads: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": NATIVE_BRIDGE_PROTOCOL_VERSION,
            "protocol": NATIVE_BRIDGE_PROTOCOL,
            "status": self.status,
            "operation": self.operation,
            "command": list(self.command),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "elapsed_ms": self.elapsed_ms,
            "stdout_sha256": self.stdout_sha256,
            "stdout_size": self.stdout_size,
            "stderr": self.stderr,
            "error": self.error,
            "process_cleanup": _json_safe(self.process_cleanup),
            "request_sha256": _sha256_bridge_json(self.request),
            "response_sha256": (
                _sha256_bridge_json(self.response) if self.response else None
            ),
        }
        if include_payloads:
            payload["request"] = _json_safe(self.request)
            payload["response"] = _json_safe(self.response)
        return _prune(payload)


class LocalJsonBridgeAdapter:
    """Strict shell-free adapter for a versioned local native bridge protocol.

    One JSON object is written to stdin and exactly one JSON object is expected
    on stdout.  Executable discovery alone never establishes availability: a
    successful protocol probe with ``native_bridge=true`` is required.
    """

    def __init__(
        self,
        capability: str,
        executable: str | os.PathLike[str] | None = None,
        *,
        args: Sequence[str] = (),
        env_vars: str | Sequence[str] | None = None,
        timeout_ms: int = _DEFAULT_BRIDGE_TIMEOUT_MS,
        max_response_bytes: int = _MAX_BRIDGE_RESPONSE_BYTES,
    ) -> None:
        self.capability = str(capability or "").strip()
        if not self.capability or len(self.capability) > 128:
            raise ValueError("native bridge capability must contain 1-128 characters")
        self.timeout_ms = _bridge_bounded_int(
            timeout_ms,
            "bridge timeout_ms",
            minimum=100,
            maximum=_MAX_BRIDGE_TIMEOUT_MS,
        )
        self.max_response_bytes = _bridge_bounded_int(
            max_response_bytes,
            "bridge max_response_bytes",
            minimum=1_024,
            maximum=_MAX_BRIDGE_RESPONSE_BYTES,
        )
        if isinstance(args, (str, bytes, bytearray)):
            raise ValueError("native bridge args must be a sequence of arguments")
        self.args = tuple(_bridge_arg(item) for item in args)
        if len(self.args) > 32:
            raise ValueError("native bridge accepts at most 32 fixed arguments")
        if env_vars is None:
            names: tuple[str, ...] = ()
        elif isinstance(env_vars, str):
            names = (env_vars,)
        else:
            names = tuple(str(item) for item in env_vars)
        self.env_vars = tuple(item for item in names if item)
        configured = executable
        source = "explicit" if executable is not None else None
        if configured is None:
            for name in self.env_vars:
                value = os.environ.get(name)
                if value and value.strip():
                    configured = value
                    source = f"environment:{name}"
                    break
        self.configured = configured is not None
        self.configuration_source = source or "none"
        self.executable: Optional[Path] = None
        self.unavailable_reason: Optional[str] = None
        if configured is None:
            names_text = ", ".join(self.env_vars) or "an explicit executable"
            self.unavailable_reason = (
                f"native bridge is not configured; set {names_text}"
            )
        else:
            try:
                candidate = _resolve_bridge_executable(configured)
                if not candidate.is_file():
                    raise ValueError(f"native bridge executable does not exist: {candidate}")
                if os.name != "nt" and not os.access(candidate, os.X_OK):
                    raise ValueError(f"native bridge executable is not executable: {candidate}")
                self.executable = candidate
            except (OSError, TypeError, ValueError) as exc:
                self.unavailable_reason = str(exc)

    @property
    def available(self) -> bool:
        return self.executable is not None and self.unavailable_reason is None

    def describe(self) -> dict[str, Any]:
        identity: dict[str, Any] = {
            "adapter": "local_json_subprocess",
            "protocol": NATIVE_BRIDGE_PROTOCOL,
            "protocol_version": NATIVE_BRIDGE_PROTOCOL_VERSION,
            "capability": self.capability,
            "configured": self.configured,
            "configuration_source": self.configuration_source,
            "available": self.available,
            "executable": str(self.executable) if self.executable else None,
            "args": list(self.args),
            "timeout_ms": self.timeout_ms,
            "shell": False,
            "unavailable_reason": self.unavailable_reason,
        }
        if self.executable is not None:
            try:
                stat = self.executable.stat()
                identity["executable_identity"] = {
                    "path": str(self.executable),
                    "size": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": _sha256_bridge_file(self.executable),
                }
            except OSError as exc:
                identity["available"] = False
                identity["unavailable_reason"] = str(exc)
        return _prune(identity)

    def probe(
        self,
        *,
        required_operations: Sequence[str] = (),
        required_backends: Sequence[str] = (),
    ) -> NativeBridgeCallResult:
        call = self.invoke(
            "probe",
            {
                "required_operations": [str(item) for item in required_operations],
                "required_backends": [str(item) for item in required_backends],
            },
            session_id="dependency-probe",
        )
        if not call.ok:
            return call
        response_payload = _mapping(call.response.get("result"))
        operations = _bridge_string_set(
            response_payload.get(
                "operations",
                response_payload.get("capabilities", call.response.get("operations")),
            )
        )
        backends = {
            _bridge_backend_name(item)
            for item in _bridge_string_set(
                response_payload.get("backends", call.response.get("backends"))
            )
        }
        missing_operations = sorted(
            {str(item) for item in required_operations} - operations
        )
        missing_backends = sorted(
            {_bridge_backend_name(item) for item in required_backends} - backends
        )
        if not missing_operations and not missing_backends:
            return call
        reasons: list[str] = []
        if missing_operations:
            reasons.append("missing operations: " + ", ".join(missing_operations))
        if missing_backends:
            reasons.append("missing backends: " + ", ".join(missing_backends))
        return NativeBridgeCallResult(
            **{
                **call.__dict__,
                "status": "unavailable",
                "error": "native bridge dependency probe failed: " + "; ".join(reasons),
            }
        )

    def invoke(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        session_id: str,
        timeout_ms: Optional[int] = None,
    ) -> NativeBridgeCallResult:
        normalized_operation = _bridge_operation(operation)
        normalized_session = str(session_id or "").strip()
        if not normalized_session or len(normalized_session) > 256 or "\x00" in normalized_session:
            raise ValueError("native bridge session_id is invalid")
        request = {
            "protocol": NATIVE_BRIDGE_PROTOCOL,
            "protocol_version": NATIVE_BRIDGE_PROTOCOL_VERSION,
            "capability": self.capability,
            "operation": normalized_operation,
            "request_id": uuid.uuid4().hex,
            "session_id": normalized_session,
            "payload": _bridge_json_value(payload),
        }
        request_bytes = _bridge_json_bytes(request)
        if len(request_bytes) > _MAX_BRIDGE_REQUEST_BYTES:
            raise ValueError(
                f"native bridge request exceeds {_MAX_BRIDGE_REQUEST_BYTES} bytes"
            )
        started_at = _utc_now()
        started_ns = time.perf_counter_ns()
        if not self.available or self.executable is None:
            ended_ns = time.perf_counter_ns()
            return NativeBridgeCallResult(
                status="unavailable",
                operation=normalized_operation,
                request=request,
                started_at=started_at,
                ended_at=_utc_now(),
                elapsed_ms=_elapsed_ms(started_ns, ended_ns),
                error=self.unavailable_reason or "native bridge is unavailable",
                process_cleanup={"not_started": True, "process_exited": True},
            )
        invocation_timeout = _bridge_bounded_int(
            self.timeout_ms if timeout_ms is None else timeout_ms,
            "bridge invocation timeout_ms",
            minimum=100,
            maximum=_MAX_BRIDGE_TIMEOUT_MS,
        )
        command = (str(self.executable), *self.args)
        process: Optional[subprocess.Popen[bytes]] = None
        job = _WindowsKillOnCloseJob()
        cleanup: dict[str, Any] = {}
        stdout = b""
        stderr = b""
        try:
            popen_kwargs: dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "shell": False,
            }
            if sys.platform == "win32":
                popen_kwargs["creationflags"] = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            else:
                popen_kwargs["start_new_session"] = True
            process = subprocess.Popen(list(command), **popen_kwargs)
            job.assign(process)
            try:
                stdout, stderr = process.communicate(
                    input=request_bytes,
                    timeout=invocation_timeout / 1000.0,
                )
                cleanup = {
                    "attempted": False,
                    "process_exited": process.poll() is not None,
                    "returncode": process.returncode,
                    "job_assigned": job.assigned,
                    "job_error": job.error,
                }
                job.close()
            except subprocess.TimeoutExpired as exc:
                stdout = _capture_bytes(exc.output)
                stderr = _capture_bytes(exc.stderr)
                cleanup = _terminate_process_tree(process, job=job)
                try:
                    drained_stdout, drained_stderr = process.communicate(timeout=1.0)
                    stdout += drained_stdout or b""
                    stderr += drained_stderr or b""
                except subprocess.TimeoutExpired:
                    pass
                ended_ns = time.perf_counter_ns()
                return NativeBridgeCallResult(
                    status="failed",
                    operation=normalized_operation,
                    request=request,
                    command=command,
                    returncode=process.poll(),
                    timed_out=True,
                    started_at=started_at,
                    ended_at=_utc_now(),
                    elapsed_ms=_elapsed_ms(started_ns, ended_ns),
                    stdout_sha256=hashlib.sha256(stdout).hexdigest() if stdout else None,
                    stdout_size=len(stdout),
                    stderr=_bridge_decode_diagnostic(stderr),
                    error=f"native bridge timed out after {invocation_timeout} ms",
                    process_cleanup=cleanup,
                )
        except (OSError, ValueError) as exc:
            if process is not None and process.poll() is None:
                cleanup = _terminate_process_tree(process, job=job)
            else:
                job.close()
                cleanup = {"not_started": process is None, "process_exited": True}
            ended_ns = time.perf_counter_ns()
            return NativeBridgeCallResult(
                status="failed",
                operation=normalized_operation,
                request=request,
                command=command,
                returncode=process.poll() if process is not None else None,
                started_at=started_at,
                ended_at=_utc_now(),
                elapsed_ms=_elapsed_ms(started_ns, ended_ns),
                stderr=_bridge_decode_diagnostic(stderr),
                error=f"native bridge launch failed: {exc}",
                process_cleanup=cleanup,
            )

        ended_ns = time.perf_counter_ns()
        returncode = process.returncode if process is not None else None
        stdout_hash = hashlib.sha256(stdout).hexdigest() if stdout else None
        common = {
            "operation": normalized_operation,
            "request": request,
            "command": command,
            "returncode": returncode,
            "started_at": started_at,
            "ended_at": _utc_now(),
            "elapsed_ms": _elapsed_ms(started_ns, ended_ns),
            "stdout_sha256": stdout_hash,
            "stdout_size": len(stdout),
            "stderr": _bridge_decode_diagnostic(stderr),
            "process_cleanup": cleanup,
        }
        if returncode != 0:
            return NativeBridgeCallResult(
                status="failed",
                error=f"native bridge exited with code {returncode}",
                **common,
            )
        if len(stdout) > self.max_response_bytes:
            return NativeBridgeCallResult(
                status="failed",
                error=(
                    "native bridge stdout exceeds "
                    f"{self.max_response_bytes} bytes"
                ),
                **common,
            )
        try:
            response = _parse_bridge_response(
                stdout,
                request=request,
                maximum=self.max_response_bytes,
            )
        except ValueError as exc:
            return NativeBridgeCallResult(
                status="failed",
                error=f"native bridge protocol validation failed: {exc}",
                **common,
            )
        return NativeBridgeCallResult(
            status=str(response["status"]),
            response=response,
            error=_bridge_response_error(response),
            **common,
        )


# Public compatibility name for callers that prefer a client-oriented label.
NativeBridgeClient = LocalJsonBridgeAdapter


class PresentMonRunner:
    """Run a configured PresentMon executable with a bounded local capture."""

    name = "presentmon_local_subprocess"
    test_double = False

    def __init__(
        self,
        executable: Optional[str | os.PathLike[str]] = None,
        *,
        base_args: Sequence[str] = (),
        option_prefix: str = "--",
        environment: Optional[Mapping[str, str]] = None,
        max_output_bytes: int = _DEFAULT_MAX_CAPTURE_BYTES,
        require_presentmon_identity: bool = True,
    ) -> None:
        configured = executable or os.environ.get("PRESENTMON_PATH")
        self.configuration_source = (
            "constructor"
            if executable is not None
            else "PRESENTMON_PATH"
            if os.environ.get("PRESENTMON_PATH")
            else "PATH"
        )
        self.executable = _resolve_executable(configured)
        if self.executable is None and configured is None:
            self.executable = _resolve_executable("PresentMon.exe")
            if self.executable is None:
                self.executable = _resolve_executable("PresentMon")
        self.base_args = tuple(_validate_fixed_arg(item) for item in base_args)
        if option_prefix not in {"-", "--"}:
            raise ValueError("PresentMon option_prefix must be '-' or '--'")
        self.option_prefix = option_prefix
        self.environment = (
            {str(key): str(value) for key, value in environment.items()}
            if environment is not None
            else None
        )
        self.max_output_bytes = _bounded_configuration(
            max_output_bytes,
            default=_DEFAULT_MAX_CAPTURE_BYTES,
            maximum=_MAX_CAPTURE_BYTES,
        )
        self.require_presentmon_identity = bool(require_presentmon_identity)
        self.presentmon_identity = _inspect_presentmon_identity(self.executable)
        self.presentmon_identity_verified = bool(
            self.presentmon_identity.get("verified")
        )
        self.available = bool(
            self.executable
            and self.executable.is_file()
            and (
                self.presentmon_identity_verified
                or not self.require_presentmon_identity
            )
        )
        if self.executable is None:
            self.unavailable_reason = "PresentMon executable was not configured or found"
        elif not self.executable.is_file():
            self.unavailable_reason = (
                f"configured PresentMon executable is not a file: {self.executable}"
            )
        elif self.require_presentmon_identity and not self.presentmon_identity_verified:
            self.unavailable_reason = (
                "configured executable lacks verifiable PresentMon filename/version "
                f"identity: {self.executable.name}"
            )
        else:
            self.unavailable_reason = None

    def probe(self) -> Mapping[str, Any]:
        identity: dict[str, Any] = {}
        if self.executable and self.executable.is_file():
            identity = _file_identity(self.executable, include_sha256=True)
        return _prune(
            {
                "status": "ok" if self.available else "unavailable",
                "name": self.name,
                "available": self.available,
                "unavailable_reason": self.unavailable_reason,
                "configuration_source": self.configuration_source,
                "executable": str(self.executable) if self.executable else None,
                "executable_identity": identity,
                "presentmon_identity_verified": self.presentmon_identity_verified,
                "presentmon_identity": self.presentmon_identity,
                "require_presentmon_identity": self.require_presentmon_identity,
                "transport": "local_subprocess",
                "shell": False,
                "bounded": True,
            }
        )

    def capture(
        self,
        *,
        pid: int,
        duration_ms: int,
        timeout_ms: int,
        capture_format: str = "auto",
    ) -> PresentMonCaptureResult:
        pid = _required_positive_int(pid, "pid", maximum=_MAX_PID)
        duration_ms = _required_positive_int(
            duration_ms, "duration_ms", maximum=_MAX_DURATION_MS
        )
        timeout_ms = _required_positive_int(
            timeout_ms, "timeout_ms", maximum=_MAX_TIMEOUT_MS
        )
        if timeout_ms <= duration_ms:
            raise PresentMonRunnerError("timeout_ms must exceed duration_ms")
        if capture_format not in {"auto", "csv", "json"}:
            raise PresentMonRunnerError(
                "capture_format must be one of: auto, csv, json"
            )
        if not self.available or self.executable is None:
            raise PresentMonRunnerError(
                self.unavailable_reason or "PresentMon is unavailable"
            )

        started_at = _utc_now()
        started_ns = time.perf_counter_ns()
        suffix = ".json" if capture_format == "json" else ".csv"
        with tempfile.TemporaryDirectory(prefix="reverse-analyzer-presentmon-") as tmp:
            root = Path(tmp)
            output_path = root / f"capture{suffix}"
            stdout_path = root / "stdout.log"
            stderr_path = root / "stderr.log"
            command = self._build_command(
                pid=pid,
                duration_ms=duration_ms,
                output_path=output_path,
            )
            process: Optional[subprocess.Popen[Any]] = None
            job = _WindowsKillOnCloseJob()
            timed_out = False
            returncode: Optional[int] = None
            cleanup: dict[str, Any] = {
                "launch_attempted": True,
                "launched": False,
                "attempted": False,
                "process_exited": False,
                "wait_completed": False,
                "cleanup_required": False,
                "tree_containment": "not_available",
            }
            launch_error: Optional[str] = None

            try:
                with stdout_path.open("wb") as stdout_handle, stderr_path.open(
                    "wb"
                ) as stderr_handle:
                    popen_kwargs: dict[str, Any] = {
                        "stdin": subprocess.DEVNULL,
                        "stdout": stdout_handle,
                        "stderr": stderr_handle,
                        "shell": False,
                        "env": self.environment,
                    }
                    if sys.platform == "win32":
                        popen_kwargs["creationflags"] = (
                            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                        )
                    else:
                        popen_kwargs["start_new_session"] = True
                    process = subprocess.Popen(command, **popen_kwargs)
                    cleanup.update(
                        {
                            "launched": True,
                            "process_id": process.pid,
                        }
                    )
                    assigned = job.assign(process)
                    cleanup["tree_containment"] = (
                        "windows_job_object" if assigned else "process_group"
                    )
                    cleanup["job_assigned"] = assigned
                    if job.error:
                        cleanup["job_error"] = job.error
                    try:
                        returncode = process.wait(timeout=timeout_ms / 1000.0)
                        cleanup["wait_completed"] = True
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        cleanup["cleanup_required"] = True
                        cleanup.update(_terminate_process_tree(process, job=job))
                        returncode = process.poll()
            except OSError as exc:
                launch_error = f"failed to launch PresentMon: {exc}"
            finally:
                if process is not None and process.poll() is None:
                    cleanup["cleanup_required"] = True
                    cleanup.update(_terminate_process_tree(process, job=job))
                    returncode = process.poll()
                else:
                    job.close()
                    if process is not None:
                        cleanup.update(
                            {
                                "process_exited": process.poll() is not None,
                                "returncode": process.poll(),
                            }
                        )
                if process is not None and process.poll() is not None:
                    cleanup["wait_completed"] = True

            stdout, stdout_truncated = _read_text_bounded(
                stdout_path, _MAX_DIAGNOSTIC_BYTES
            )
            stderr, stderr_truncated = _read_text_bounded(
                stderr_path, _MAX_DIAGNOSTIC_BYTES
            )
            if stdout_truncated:
                cleanup["stdout_truncated"] = True
            if stderr_truncated:
                cleanup["stderr_truncated"] = True

            output = ""
            output_error: Optional[str] = None
            if output_path.is_file():
                try:
                    output = _read_capture_text(
                        output_path, maximum=self.max_output_bytes
                    )
                except Exception as exc:
                    output_error = str(exc)
            elif _looks_like_capture(stdout):
                output = stdout
                cleanup["capture_source"] = "stdout"
            else:
                output_error = "PresentMon did not produce a capture output file"

            ended_at = _utc_now()
            elapsed_ms = _elapsed_ms(started_ns, time.perf_counter_ns())
            output_bytes = output.encode("utf-8") if output else b""
            actual_format = _detect_capture_format(output) if output else "unknown"
            error = launch_error or output_error
            if timed_out:
                status = "timeout"
                error = f"PresentMon exceeded the {timeout_ms} ms timeout"
            elif launch_error:
                status = "unavailable"
            elif returncode not in (0, None):
                status = "failed"
                error = error or f"PresentMon exited with code {returncode}"
            elif error:
                status = "failed"
            elif not output.strip():
                status = "failed"
                error = "PresentMon capture output was empty"
            else:
                status = "ok"

            return PresentMonCaptureResult(
                status=status,
                output=output,
                output_format=actual_format,
                command=tuple(command),
                returncode=returncode,
                timed_out=timed_out,
                process_cleanup=_json_safe(cleanup),
                stdout=stdout,
                stderr=stderr,
                started_at=started_at,
                ended_at=ended_at,
                elapsed_ms=elapsed_ms,
                output_sha256=(
                    hashlib.sha256(output_bytes).hexdigest()
                    if output_bytes
                    else None
                ),
                output_size=len(output_bytes),
                local_subprocess=process is not None,
                presentmon_identity_verified=self.presentmon_identity_verified,
                error=error,
                provenance={
                    "runner": self.name,
                    "transport": "local_subprocess",
                    "shell": False,
                    "pid": pid,
                    "requested_duration_ms": duration_ms,
                    "timeout_ms": timeout_ms,
                    "configured_capture_format": capture_format,
                    "executable": str(self.executable),
                    "executable_identity": _file_identity(
                        self.executable, include_sha256=True
                    ),
                    "presentmon_identity_verified": self.presentmon_identity_verified,
                    "presentmon_identity": self.presentmon_identity,
                    "identity_basis": "basename_version_resource_plus_file_sha256",
                    "process_lifecycle": {
                        "launched": cleanup.get("launched", False),
                        "process_id": cleanup.get("process_id"),
                        "wait_completed": cleanup.get("wait_completed", False),
                        "cleanup_required": cleanup.get("cleanup_required", False),
                        "process_exited": cleanup.get("process_exited", False),
                        "returncode": returncode,
                        "timed_out": timed_out,
                    },
                },
            )

    def _build_command(
        self,
        *,
        pid: int,
        duration_ms: int,
        output_path: Path,
    ) -> list[str]:
        assert self.executable is not None
        timed_seconds = max(1, int(math.ceil(duration_ms / 1000.0)))
        option = lambda name: f"{self.option_prefix}{name}"
        return [
            str(self.executable),
            *self.base_args,
            option("process_id"),
            str(pid),
            option("timed"),
            str(timed_seconds),
            option("terminate_after_timed"),
            option("output_file"),
            str(output_path),
        ]


def parse_presentmon_csv(
    data: str | bytes,
    *,
    expected_pid: Optional[int] = None,
    max_events: int = _DEFAULT_MAX_EVENTS,
) -> list[dict[str, Any]]:
    """Parse a strict PresentMon CSV capture into normalized frame events."""

    text = _capture_text(data)
    max_events = _parse_event_limit(max_events)
    lines = text.splitlines()
    while lines and (not lines[0].strip() or lines[0].lstrip().startswith("#")):
        lines.pop(0)
    if not lines:
        raise PresentMonParseError("PresentMon CSV is empty")
    if any("\x00" in line for line in lines):
        raise PresentMonParseError("PresentMon CSV contains NUL bytes")

    reader = csv.reader(io.StringIO("\n".join(lines), newline=""), strict=True)
    try:
        header = next(reader)
    except (StopIteration, csv.Error) as exc:
        raise PresentMonParseError(f"unable to read PresentMon CSV header: {exc}") from exc
    if not header or any(not str(item).strip() for item in header):
        raise PresentMonParseError("PresentMon CSV header contains an empty column")
    if any(len(str(item)) > _MAX_FIELD_LENGTH for item in header):
        raise PresentMonParseError("PresentMon CSV header contains an oversized field")
    normalized_header = [_canonical_key(item) for item in header]
    if len(set(normalized_header)) != len(normalized_header):
        raise PresentMonParseError("PresentMon CSV header contains duplicate columns")
    _validate_required_columns(normalized_header)

    events: list[dict[str, Any]] = []
    csv_index = 1
    while True:
        try:
            values = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            raise PresentMonParseError(
                f"unable to read PresentMon CSV row {csv_index + 1}: {exc}"
            ) from exc
        csv_index += 1
        if not values or all(not str(item).strip() for item in values):
            continue
        if len(values) != len(header):
            raise PresentMonParseError(
                f"PresentMon CSV row {csv_index} has {len(values)} fields; "
                f"expected {len(header)}"
            )
        if any(len(item) > _MAX_FIELD_LENGTH for item in values):
            raise PresentMonParseError(
                f"PresentMon CSV row {csv_index} contains an oversized field"
            )
        row = dict(zip(header, values))
        event = _normalize_present_event(
            row,
            event_index=len(events),
            source_format="csv",
            source_row=csv_index,
        )
        events.append(event)
        if len(events) > max_events:
            raise PresentMonParseError(
                f"PresentMon capture exceeds max_events={max_events}"
            )
    if not events:
        raise PresentMonParseError("PresentMon CSV contains no events")
    if expected_pid is not None:
        pid = _required_positive_int(expected_pid, "expected_pid", maximum=_MAX_PID)
        events = [event for event in events if event["pid"] == pid]
    return events


def parse_presentmon_json(
    data: str | bytes,
    *,
    expected_pid: Optional[int] = None,
    max_events: int = _DEFAULT_MAX_EVENTS,
) -> list[dict[str, Any]]:
    """Parse a JSON array, ``{"events": [...]}``, or JSON-lines capture."""

    text = _capture_text(data)
    max_events = _parse_event_limit(max_events)
    if not text.strip():
        raise PresentMonParseError("PresentMon JSON is empty")

    def reject_constant(value: str) -> Any:
        raise PresentMonParseError(f"non-finite JSON number is not allowed: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PresentMonParseError(f"duplicate JSON object key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            text,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
        if isinstance(payload, list):
            raw_events = payload
        elif isinstance(payload, Mapping):
            raw_events = payload.get("events")
            if not isinstance(raw_events, list):
                raise PresentMonParseError(
                    "PresentMon JSON object must contain an events array"
                )
        else:
            raise PresentMonParseError(
                "PresentMon JSON must be an array or an object with events"
            )
    except PresentMonParseError:
        raise
    except json.JSONDecodeError:
        raw_events = []
        for line_index, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(
                    line,
                    parse_constant=reject_constant,
                    object_pairs_hook=unique_object,
                )
            except (json.JSONDecodeError, PresentMonParseError) as exc:
                raise PresentMonParseError(
                    f"invalid PresentMon JSON line {line_index}: {exc}"
                ) from exc
            raw_events.append(item)

    if not raw_events:
        raise PresentMonParseError("PresentMon JSON contains no events")
    if len(raw_events) > max_events:
        raise PresentMonParseError(
            f"PresentMon capture exceeds max_events={max_events}"
        )

    events: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_events):
        if not isinstance(raw, Mapping):
            raise PresentMonParseError(
                f"PresentMon JSON event {index} must be an object"
            )
        events.append(
            _normalize_present_event(
                raw,
                event_index=index,
                source_format="json",
                source_row=index,
            )
        )
    if expected_pid is not None:
        pid = _required_positive_int(expected_pid, "expected_pid", maximum=_MAX_PID)
        events = [event for event in events if event["pid"] == pid]
    return events


def parse_presentmon_events(
    data: str | bytes,
    *,
    format_hint: str = "auto",
    expected_pid: Optional[int] = None,
    max_events: int = _DEFAULT_MAX_EVENTS,
) -> list[dict[str, Any]]:
    """Parse PresentMon CSV or JSON using an explicit or content-based format."""

    if format_hint not in {"auto", "csv", "json"}:
        raise PresentMonParseError("format_hint must be one of: auto, csv, json")
    text = _capture_text(data)
    selected = _detect_capture_format(text) if format_hint == "auto" else format_hint
    if selected == "json":
        return parse_presentmon_json(
            text, expected_pid=expected_pid, max_events=max_events
        )
    if selected == "csv":
        return parse_presentmon_csv(
            text, expected_pid=expected_pid, max_events=max_events
        )
    raise PresentMonParseError("unable to determine PresentMon capture format")


class PresentMonEventParser:
    """Object wrapper for callers that prefer a configured parser."""

    def __init__(self, *, max_events: int = _DEFAULT_MAX_EVENTS) -> None:
        self.max_events = _parse_event_limit(max_events)

    def parse(
        self,
        data: str | bytes,
        *,
        format_hint: str = "auto",
        expected_pid: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        return parse_presentmon_events(
            data,
            format_hint=format_hint,
            expected_pid=expected_pid,
            max_events=self.max_events,
        )


def correlate_present_events(
    events: Sequence[Mapping[str, Any]],
    *,
    expected_pid: Optional[int] = None,
    api_filter: Sequence[str] = (),
) -> dict[str, Any]:
    """Correlate frames by PID, API, and opaque swap-chain identity."""

    pid = (
        _required_positive_int(expected_pid, "expected_pid", maximum=_MAX_PID)
        if expected_pid is not None
        else None
    )
    allowed_apis = {_normalize_api(item) for item in api_filter}
    selected: list[dict[str, Any]] = []
    excluded = 0
    for raw in events:
        event = dict(raw)
        event_pid = _strict_int(event.get("pid"), "event pid", minimum=1)
        event_api = _normalize_api(event.get("api"))
        if pid is not None and event_pid != pid:
            excluded += 1
            continue
        if allowed_apis and event_api not in allowed_apis:
            excluded += 1
            continue
        event["pid"] = event_pid
        event["api"] = event_api
        selected.append(event)

    streams: dict[tuple[int, str, str], list[dict[str, Any]]] = {}
    for event in selected:
        opaque_id = str(event.get("swap_chain_id") or "unreported")
        key = (int(event["pid"]), str(event["api"]), opaque_id)
        streams.setdefault(key, []).append(event)

    stream_records: list[dict[str, Any]] = []
    lifecycle_warnings: list[str] = []
    for (stream_pid, api, opaque_id), stream_events in streams.items():
        states = [str(item.get("lifecycle") or "present") for item in stream_events]
        explicit_states = [state for state in states if state != "present"]
        created_indexes = [i for i, state in enumerate(states) if state == "created"]
        destroyed_indexes = [i for i, state in enumerate(states) if state == "destroyed"]
        complete = bool(
            created_indexes
            and destroyed_indexes
            and created_indexes[0] < destroyed_indexes[-1]
        )
        if destroyed_indexes and any(
            state == "present" for state in states[destroyed_indexes[0] + 1 :]
        ):
            lifecycle_warnings.append(
                f"present event observed after destroy for {stream_pid}/{api}/{opaque_id}"
            )
        timestamps = [
            float(item["timestamp_s"])
            for item in stream_events
            if item.get("timestamp_s") is not None
        ]
        stream_records.append(
            _prune(
                {
                    "pid": stream_pid,
                    "api": api,
                    "swap_chain_id": (
                        None if opaque_id == "unreported" else opaque_id
                    ),
                    "swap_chain_identity_kind": "opaque_presentmon_identifier",
                    "event_count": len(stream_events),
                    "first_event_index": stream_events[0].get("event_index"),
                    "last_event_index": stream_events[-1].get("event_index"),
                    "first_timestamp_s": timestamps[0] if timestamps else None,
                    "last_timestamp_s": timestamps[-1] if timestamps else None,
                    "observed_states": _deduplicate(states),
                    "explicit_lifecycle_observed": bool(explicit_states),
                    "lifecycle_complete": complete,
                    "lifecycle_claim": (
                        "explicit_create_destroy_observed"
                        if complete
                        else "present_observation_only"
                    ),
                }
            )
        )

    frame_times = [
        float(item["frame_time_ms"])
        for item in selected
        if item.get("frame_time_ms") is not None
    ]
    dropped_count = sum(1 for item in selected if item.get("dropped") is True)
    frame_summary = _frame_summary(frame_times, event_count=len(selected))
    frame_summary["dropped_count"] = dropped_count
    return {
        "event_count": len(selected),
        "excluded_event_count": excluded,
        "events": selected,
        "apis": sorted({str(item["api"]) for item in selected}),
        "swap_chain_count": len(streams),
        "streams": stream_records,
        "frames": frame_summary,
        "warnings": lifecycle_warnings,
    }


def inspect_pe_exports(
    path: str | os.PathLike[str],
    required_exports: Sequence[str] = (),
    *,
    any_of_exports: Sequence[str] = (),
    max_exports: int = _MAX_EXPORTS,
) -> dict[str, Any]:
    """Read one real PE export table and report export RVAs without loading it."""

    requested = _normalize_export_names(required_exports, "required_exports")
    any_of = _normalize_export_names(any_of_exports, "any_of_exports")
    max_exports = _required_positive_int(
        max_exports, "max_exports", maximum=_MAX_EXPORTS
    )
    try:
        module_path = Path(path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return {
            "status": "failed",
            "path": str(path),
            "read_only": True,
            "loaded": False,
            "runtime_address": None,
            "error": f"PE module path is unavailable: {exc}",
        }
    if not module_path.is_file():
        return {
            "status": "failed",
            "path": str(module_path),
            "read_only": True,
            "loaded": False,
            "runtime_address": None,
            "error": "PE module path is not a file",
        }

    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001 - dependency gate
        return {
            "status": "unavailable",
            "path": str(module_path),
            "read_only": True,
            "loaded": False,
            "runtime_address": None,
            "dependency": "pefile",
            "error": f"optional dependency pefile unavailable: {exc}",
        }

    identity = _file_identity(module_path, include_sha256=True)
    pe: Any = None
    try:
        pe = pefile.PE(str(module_path), fast_load=True)
        directory_id = pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_EXPORT")
        if directory_id is not None:
            pe.parse_data_directories(directories=[directory_id])
        symbols: list[dict[str, Any]] = []
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        raw_symbols = list(getattr(directory, "symbols", []) or [])
        if len(raw_symbols) > max_exports:
            raise PresentMonParseError(
                f"PE export count exceeds max_exports={max_exports}"
            )
        for symbol in raw_symbols:
            name = _decode_export_name(getattr(symbol, "name", None))
            forwarder = _decode_export_name(getattr(symbol, "forwarder", None))
            rva = _optional_nonnegative_int(getattr(symbol, "address", None))
            symbol_record = _prune(
                {
                    "name": name,
                    "ordinal": _optional_nonnegative_int(
                        getattr(symbol, "ordinal", None)
                    ),
                    "rva": rva,
                    "forwarder": forwarder,
                    "address_kind": "pe_export_rva",
                }
            )
            symbol_record["runtime_address"] = None
            symbols.append(symbol_record)

        by_name = {
            str(item["name"]): item for item in symbols if item.get("name")
        }
        matched_required = [name for name in requested if name in by_name]
        missing_required = [name for name in requested if name not in by_name]
        matched_any = [name for name in any_of if name in by_name]
        requirements_met = not missing_required and (not any_of or bool(matched_any))
        selected_names = set(matched_required + matched_any)
        selected_exports = [
            dict(by_name[name]) for name in sorted(selected_names) if name in by_name
        ]
        machine = _optional_nonnegative_int(
            getattr(getattr(pe, "FILE_HEADER", None), "Machine", None)
        )
        status = "ok" if requirements_met else "failed"
        error = None
        if missing_required:
            error = "required exports missing: " + ", ".join(missing_required)
        elif any_of and not matched_any:
            error = "none of the alternative exports were found: " + ", ".join(
                any_of
            )
        result = _prune(
            {
                "status": status,
                "path": str(module_path),
                "identity": identity,
                "parser": "pefile",
                "parser_version": str(getattr(pefile, "__version__", "unknown")),
                "read_only": True,
                "loaded": False,
                "machine": machine,
                "export_count": len(symbols),
                "required_exports": requested,
                "any_of_exports": any_of,
                "matched_required_exports": matched_required,
                "matched_alternative_exports": matched_any,
                "missing_required_exports": missing_required,
                "requirements_met": requirements_met,
                "selected_exports": selected_exports,
                "exports": symbols,
                "address_semantics": "relative_virtual_address_only",
                "error": error,
            }
        )
        for export in result.get("exports", []):
            export["runtime_address"] = None
        for export in result.get("selected_exports", []):
            export["runtime_address"] = None
        result["runtime_address"] = None
        return result
    except Exception as exc:  # noqa: BLE001 - malformed PE becomes evidence
        return {
            "status": "failed",
            "path": str(module_path),
            "identity": identity,
            "parser": "pefile",
            "read_only": True,
            "loaded": False,
            "runtime_address": None,
            "error": f"unable to parse PE exports: {exc}",
        }
    finally:
        close = getattr(pe, "close", None)
        if callable(close):
            close()


def inspect_pe_module_exports(
    path: str | os.PathLike[str],
    required_exports: Sequence[str] = (),
    *,
    any_of_exports: Sequence[str] = (),
    max_exports: int = _MAX_EXPORTS,
) -> dict[str, Any]:
    """Compatibility name for :func:`inspect_pe_exports`."""

    return inspect_pe_exports(
        path,
        required_exports,
        any_of_exports=any_of_exports,
        max_exports=max_exports,
    )


def inspect_live_system_present_exports(
    targets: Sequence[str] = (
        "gdi_swap_buffers",
        "opengl_swap_buffers",
        "vulkan_present",
    ),
) -> dict[str, Any]:
    """Resolve real system present exports in this analyzer process.

    The returned virtual addresses are proven with the Windows loader and
    ``VirtualQuery``.  They are valid only in ``os.getpid()`` and are never
    represented as addresses in the requested target process.
    """

    requested = _normalize_export_names(targets, "targets")
    allowed = {
        "gdi_swap_buffers",
        "opengl_swap_buffers",
        "vulkan_present",
    }
    unknown = [item for item in requested if item not in allowed]
    if unknown:
        raise ValueError("unknown live present export target: " + ", ".join(unknown))
    if os.name != "nt" or sys.platform != "win32":
        return {
            "status": "unavailable",
            "address_scope": "analyzer_current_process_only",
            "observed_pid": os.getpid(),
            "target_pid_address_claim": False,
            "reason": "live system export resolution requires Windows",
            "targets": [],
        }

    try:
        from reverse_analyzer.providers.hook_targets import (
            resolve_live_common_hook_target,
        )
    except Exception as exc:  # noqa: BLE001 - dependency boundary becomes evidence
        return {
            "status": "unavailable",
            "address_scope": "analyzer_current_process_only",
            "observed_pid": os.getpid(),
            "target_pid_address_claim": False,
            "reason": f"live hook-target resolver is unavailable: {exc}",
            "targets": [],
        }

    records: list[dict[str, Any]] = []
    for target in requested:
        try:
            resolution = resolve_live_common_hook_target(
                target,
                load_if_missing=True,
            ).to_dict()
        except Exception as exc:  # noqa: BLE001 - one optional DLL must not hide others
            resolution = {
                "status": "unavailable",
                "target": target,
                "production_ready": False,
                "errors": [str(exc)],
            }
        record = _json_safe(resolution)
        record.update(
            {
                "address_scope": "analyzer_current_process_only",
                "observed_pid": os.getpid(),
                "target_pid_address_claim": False,
            }
        )
        records.append(record)

    proven = [
        item
        for item in records
        if item.get("status") == "ok"
        and item.get("production_ready") is True
        and isinstance(item.get("address"), int)
        and item.get("address", 0) > 0
        and _mapping(item.get("executable_range")).get("executable") is True
    ]
    if len(proven) == len(records):
        status = "ok"
    elif proven:
        status = "partial"
    else:
        status = "unavailable"
    return {
        "status": status,
        "address_scope": "analyzer_current_process_only",
        "observed_pid": os.getpid(),
        "target_pid_address_claim": False,
        "requested_targets": requested,
        "proven_target_count": len(proven),
        "targets": records,
        "dependency_gates": [
            {
                "target": item.get("target"),
                "status": item.get("status"),
                "reason": (
                    "; ".join(str(value) for value in item.get("errors") or [])
                    or "; ".join(str(value) for value in item.get("warnings") or [])
                    or "system export was not proven"
                ),
            }
            for item in records
            if item not in proven
        ],
    }


def _production_capture_failures(
    runner: GraphicsCaptureRunner,
    outcome: PresentMonCaptureResult,
) -> list[str]:
    failures: list[str] = []
    if type(runner) is not PresentMonRunner:
        failures.append("runner is not the exact internal PresentMonRunner type")
        return failures
    if outcome.status != "ok":
        failures.append(f"capture status is {outcome.status}")
    if not outcome.local_subprocess:
        failures.append("capture was not produced by a launched local subprocess")
    if not outcome.presentmon_identity_verified:
        failures.append("PresentMon filename/version-resource identity was not verified")
    if outcome.returncode != 0:
        failures.append("PresentMon did not exit successfully")
    cleanup = _mapping(outcome.process_cleanup)
    for key in ("launched", "wait_completed", "process_exited"):
        if cleanup.get(key) is not True:
            failures.append(f"process lifecycle did not confirm {key}")
    if outcome.timed_out:
        failures.append("PresentMon capture timed out")
    if not outcome.output or outcome.output_size <= 0 or not outcome.output_sha256:
        failures.append("capture output bytes were not hash-bound")
    elif hashlib.sha256(outcome.output.encode("utf-8")).hexdigest() != outcome.output_sha256:
        failures.append("capture output hash does not match the returned bytes")

    executable = runner.executable
    command_path = outcome.command[0] if outcome.command else None
    if executable is None or not executable.is_file():
        failures.append("configured PresentMon executable is no longer available")
    elif command_path is None:
        failures.append("capture command does not identify the launched executable")
    else:
        try:
            if Path(command_path).resolve() != executable.resolve():
                failures.append("capture command executable differs from the runner")
        except (OSError, RuntimeError):
            failures.append("capture command executable could not be revalidated")
        expected_identity = _file_identity(executable, include_sha256=True)
        observed_identity = _mapping(
            _mapping(outcome.provenance).get("executable_identity")
        )
        if observed_identity.get("sha256") != expected_identity.get("sha256"):
            failures.append("PresentMon executable hash changed across capture")

    provenance = _mapping(outcome.provenance)
    if provenance.get("runner") != PresentMonRunner.name:
        failures.append("capture provenance does not name the production runner")
    if provenance.get("transport") != "local_subprocess":
        failures.append("capture provenance transport is not local_subprocess")
    if provenance.get("shell") is not False:
        failures.append("capture provenance does not prove shell=False")
    lifecycle = _mapping(provenance.get("process_lifecycle"))
    if lifecycle.get("process_id") != cleanup.get("process_id"):
        failures.append("capture lifecycle PID evidence is inconsistent")
    return _deduplicate(failures)


class GraphicsRuntimeProvider:
    """Collect bounded passive present evidence from one explicit PID."""

    capability_name = _CAPABILITY
    provider_name = _PROVIDER
    priority = 10
    supported_actions = (_ACTION,)

    def __init__(
        self,
        runner: Optional[GraphicsCaptureRunner] = None,
        *,
        presentmon_path: Optional[str | os.PathLike[str]] = None,
        bridge_executable: Optional[str | os.PathLike[str]] = None,
        bridge_args: Sequence[str] = (),
        bridge_timeout_ms: int = _DEFAULT_BRIDGE_TIMEOUT_MS,
        platform_name: Optional[str] = None,
        max_capture_bytes: int = _DEFAULT_MAX_CAPTURE_BYTES,
    ) -> None:
        if (
            runner is not None
            and type(runner) is not PresentMonRunner
            and getattr(runner, "test_double", None) is not True
        ):
            raise ValueError(
                "injected graphics runner must declare test_double=True"
            )
        self.platform_name = platform_name or sys.platform
        self.max_capture_bytes = _bounded_configuration(
            max_capture_bytes,
            default=_DEFAULT_MAX_CAPTURE_BYTES,
            maximum=_MAX_CAPTURE_BYTES,
        )
        self._runner_explicit = runner is not None
        self._live_export_evidence: Optional[dict[str, Any]] = None
        self.runner: GraphicsCaptureRunner = runner or PresentMonRunner(
            presentmon_path,
            max_output_bytes=self.max_capture_bytes,
        )
        self.bridge = LocalJsonBridgeAdapter(
            self.capability_name,
            bridge_executable,
            args=bridge_args,
            env_vars=_GRAPHICS_BRIDGE_ENV_VARS,
            timeout_ms=bridge_timeout_ms,
        )

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) == _ACTION
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        action = _normalize_action(request.action)
        parameters, target = _normalize_request_parameters(request, self.runner)
        bridge, bridge_errors = self._bridge_for_request(request.params)
        parameters["parameter_errors"] = _deduplicate(
            [*parameters.get("parameter_errors", []), *bridge_errors]
        )
        parameters["execution_adapter"] = (
            "native_bridge" if bridge.configured else "presentmon"
        )
        parameters["native_bridge"] = bridge.describe()
        session_id = str(request.session_id or "graphics-present-session")
        precondition_hash = _plan_fingerprint(action, target, parameters)
        before = {
            "schema_version": _SCHEMA_VERSION,
            "capture_phase": "planned",
            "pid": parameters.get("pid"),
            "execution_adapter": parameters.get("execution_adapter"),
            "native_bridge": parameters.get("native_bridge"),
            "capture_bounds": {
                "duration_ms": parameters.get("duration_ms"),
                "timeout_ms": parameters.get("timeout_ms"),
                "max_events": parameters.get("max_events"),
                "max_capture_bytes": self.max_capture_bytes,
            },
            "declared_modules": [
                _module_declaration(item)
                for item in parameters.get("modules", [])
            ],
            "passive_policy": dict(_PASSIVE_POLICY),
            "precondition_hash": precondition_hash,
            "side_effects": False,
        }
        rollback_plan = _read_only_rollback_plan(precondition_hash)
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=target,
            action=action,
            parameters=parameters,
            steps=[
                {
                    "name": "validate_passive_capture",
                    "operation": "reject control, hook, injection, and overlay inputs",
                    "read_only": True,
                },
                {
                    "name": "probe_native_bridge",
                    "operation": "verify versioned local JSON bridge when configured",
                    "read_only": True,
                    "required_backends": list(_GRAPHICS_PRESENT_BACKENDS),
                },
                {
                    "name": "probe_presentmon",
                    "operation": "verify configured local PresentMon executable when selected",
                    "read_only": True,
                },
                {
                    "name": "inspect_declared_pe_exports",
                    "operation": "read PE export tables without loading modules",
                    "read_only": True,
                },
                {
                    "name": "inspect_live_system_exports",
                    "operation": "resolve analyzer-process system exports with GetProcAddress",
                    "read_only": True,
                    "address_scope": "analyzer_current_process_only",
                },
                {
                    "name": "capture_present_events",
                    "operation": "run bounded external PresentMon capture",
                    "read_only": True,
                },
                {
                    "name": "correlate_frame_lifecycle",
                    "operation": "correlate PID, API, and opaque swap-chain identifiers",
                    "read_only": True,
                },
                {
                    "name": "collect_evidence",
                    "operation": "materialize audit, events, and manifest JSON",
                    "read_only": True,
                },
            ],
            precondition_hash=precondition_hash,
            before_snapshot=before,
            rollback_plan=rollback_plan,
            provenance={
                **_mapping(request.provenance),
                "schema_version": _SCHEMA_VERSION,
                "provider": self.provider_name,
                "platform": self.platform_name,
                "requested_action": request.action,
                "action": action,
                "passive_policy": dict(_PASSIVE_POLICY),
                "parser": {
                    "formats": ["csv", "json", "jsonl"],
                    "strict": True,
                    "schema_version": _SCHEMA_VERSION,
                },
                "execution_adapter": parameters["execution_adapter"],
                "native_bridge": parameters["native_bridge"],
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
        validation, state = self._validate_plan(plan, context=context)
        if state["unavailable_reasons"]:
            reason = "; ".join(state["unavailable_reasons"])
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                capture={"status": "unavailable", "reason": reason},
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )
        if not validation.ok:
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture={
                    "status": "blocked",
                    "reason": "execution was blocked by validation",
                },
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=list(validation.errors),
                warnings=list(validation.warnings),
            )

        if state.get("execution_adapter") == "native_bridge":
            return self._execute_native_bridge(
                plan,
                validation=validation,
                state=state,
            )

        runner = state["runner"]
        try:
            outcome = runner.capture(
                pid=int(plan.parameters["pid"]),
                duration_ms=int(plan.parameters["duration_ms"]),
                timeout_ms=int(plan.parameters["timeout_ms"]),
                capture_format=str(plan.parameters["capture_format"]),
            )
        except Exception as exc:  # noqa: BLE001 - runner boundary becomes evidence
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture={
                    "status": "failed",
                    "reason": f"PresentMon runner failed: {exc}",
                    "process_cleanup": {"process_exited": True, "not_started": True},
                },
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[f"PresentMon runner failed: {exc}"],
                warnings=list(validation.warnings),
            )

        if not isinstance(outcome, PresentMonCaptureResult):
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture={
                    "status": "failed",
                    "reason": "runner returned an invalid capture result type",
                },
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=["runner returned an invalid capture result type"],
                warnings=list(validation.warnings),
            )

        capture = outcome.to_dict()
        production_failures = _production_capture_failures(runner, outcome)
        production_evidence = not production_failures
        capture["production_evidence"] = production_evidence
        capture["production_evidence_failures"] = production_failures
        if not production_evidence and outcome.status == "ok":
            reason = (
                "non-production runner output cannot establish successful "
                "graphics-present evidence"
            )
            capture["status"] = "unavailable"
            capture["reason"] = reason
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                capture=capture,
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )

        if outcome.status != "ok":
            reason = outcome.error or f"PresentMon capture status is {outcome.status}"
            status = "unavailable" if outcome.status == "unavailable" else "failed"
            return self._execution_result(
                plan,
                validation=validation,
                status=status,
                capture=capture,
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )
        if not outcome.process_cleanup.get("process_exited", False):
            reason = "PresentMon process cleanup could not be confirmed"
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture=capture,
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )

        try:
            events = parse_presentmon_events(
                outcome.output,
                format_hint=str(plan.parameters["capture_format"]),
                max_events=int(plan.parameters["max_events"]),
            )
            correlation = correlate_present_events(
                events,
                expected_pid=int(plan.parameters["pid"]),
                api_filter=list(plan.parameters.get("api_filter") or []),
            )
        except PresentMonParseError as exc:
            reason = f"PresentMon event parsing failed: {exc}"
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture=capture,
                correlation=_empty_correlation(),
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )

        if not correlation["event_count"]:
            reason = "PresentMon captured no events matching the requested PID/API"
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                capture=capture,
                correlation=correlation,
                modules=state["modules"],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )

        present_targets, target_gaps = _build_present_targets(
            correlation, state["modules"]
        )
        warnings = _deduplicate(
            [*validation.warnings, *correlation.get("warnings", []), *target_gaps]
        )
        status = "partial" if target_gaps else "ok"
        return self._execution_result(
            plan,
            validation=validation,
            status=status,
            capture=capture,
            correlation=correlation,
            modules=state["modules"],
            present_targets=present_targets,
            errors=[],
            warnings=warnings,
        )

    def _execute_native_bridge(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        state: Mapping[str, Any],
    ) -> CapabilityExecutionResult:
        bridge = state.get("bridge")
        if not isinstance(bridge, LocalJsonBridgeAdapter):
            reason = "validated native graphics bridge is unavailable"
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                capture={"status": "unavailable", "reason": reason},
                correlation=_empty_correlation(),
                modules=state.get("modules") or [],
                present_targets=[],
                errors=[reason],
                warnings=list(validation.warnings),
            )
        payload = {
            "target": plan.target.to_dict(),
            "pid": plan.parameters.get("pid"),
            "duration_ms": plan.parameters.get("duration_ms"),
            "max_events": plan.parameters.get("max_events"),
            "backends": _requested_graphics_backends(
                plan.parameters.get("api_filter")
            ),
            "passive_only": True,
            "read_only": True,
        }
        call = bridge.invoke(
            "observe_present",
            payload,
            session_id=plan.session_id,
            timeout_ms=int(plan.parameters.get("timeout_ms") or bridge.timeout_ms),
        )
        capture = {
            "status": call.status,
            "output_format": "native_bridge_json",
            "output_sha256": call.stdout_sha256,
            "output_size": call.stdout_size,
            "local_subprocess": bool(call.command),
            "native_bridge_verified": call.ok,
            "production_evidence": call.ok,
            "production_evidence_failures": [] if call.ok else [call.error],
            "process_cleanup": call.process_cleanup,
            "bridge": call.to_dict(include_payloads=True),
            "error": call.error,
        }
        bridge_result = _mapping(call.response.get("result"))
        if not call.ok:
            reason = call.error or f"native graphics bridge status is {call.status}"
            status = "unavailable" if call.status == "unavailable" else "failed"
            return self._record_native_bridge_session(
                self._execution_result(
                    plan,
                    validation=validation,
                    status=status,
                    capture=capture,
                    correlation=_empty_correlation(),
                    modules=state.get("modules") or [],
                    present_targets=[],
                    errors=[reason],
                    warnings=list(validation.warnings),
                ),
                bridge,
                bridge_result,
            )
        raw_events = bridge_result.get("events")
        if (
            not isinstance(raw_events, list)
            or len(raw_events) > int(plan.parameters.get("max_events") or 0)
            or any(not isinstance(item, Mapping) for item in raw_events)
        ):
            reason = "native graphics bridge result.events is missing or invalid"
            capture.update({"status": "failed", "production_evidence": False})
            return self._record_native_bridge_session(
                self._execution_result(
                    plan,
                    validation=validation,
                    status="failed",
                    capture=capture,
                    correlation=_empty_correlation(),
                    modules=state.get("modules") or [],
                    present_targets=[],
                    errors=[reason],
                    warnings=list(validation.warnings),
                ),
                bridge,
                bridge_result,
            )
        try:
            events = parse_presentmon_json(
                json.dumps(raw_events, allow_nan=False),
                max_events=int(plan.parameters["max_events"]),
            )
            correlation = correlate_present_events(
                events,
                expected_pid=int(plan.parameters["pid"]),
                api_filter=list(plan.parameters.get("api_filter") or []),
            )
        except (PresentMonParseError, TypeError, ValueError) as exc:
            reason = f"native graphics bridge event validation failed: {exc}"
            capture.update({"status": "failed", "production_evidence": False})
            return self._record_native_bridge_session(
                self._execution_result(
                    plan,
                    validation=validation,
                    status="failed",
                    capture=capture,
                    correlation=_empty_correlation(),
                    modules=state.get("modules") or [],
                    present_targets=[],
                    errors=[reason],
                    warnings=list(validation.warnings),
                ),
                bridge,
                bridge_result,
            )
        if not correlation.get("event_count"):
            reason = "native graphics bridge produced no matching present events"
            return self._record_native_bridge_session(
                self._execution_result(
                    plan,
                    validation=validation,
                    status="failed",
                    capture=capture,
                    correlation=correlation,
                    modules=state.get("modules") or [],
                    present_targets=[],
                    errors=[reason],
                    warnings=list(validation.warnings),
                ),
                bridge,
                bridge_result,
            )
        observed_backends = {
            _bridge_backend_name(item) for item in correlation.get("apis") or []
        }
        missing_backends = sorted(
            set(_requested_graphics_backends(plan.parameters.get("api_filter")))
            - observed_backends
        )
        present_targets, target_gaps = _build_present_targets(
            correlation,
            state.get("modules") or [],
        )
        warnings = [
            *validation.warnings,
            *correlation.get("warnings", []),
            *target_gaps,
        ]
        if missing_backends:
            warnings.append(
                "capture did not observe requested backends: "
                + ", ".join(missing_backends)
            )
        status = "partial" if target_gaps or missing_backends else "ok"
        result = self._execution_result(
            plan,
            validation=validation,
            status=status,
            capture=capture,
            correlation=correlation,
            modules=state.get("modules") or [],
            present_targets=present_targets,
            errors=[],
            warnings=_deduplicate(warnings),
        )
        return self._record_native_bridge_session(result, bridge, bridge_result)

    def _record_native_bridge_session(
        self,
        result: CapabilityExecutionResult,
        bridge: LocalJsonBridgeAdapter,
        bridge_result: Mapping[str, Any],
    ) -> CapabilityExecutionResult:
        planned_bridge = _mapping(
            _mapping(
                _mapping(result.provenance.get("plan")).get("parameters")
            ).get("native_bridge")
        )
        bridge_descriptor = planned_bridge or bridge.describe()
        session_active = bridge_result.get("session_active") is True
        stop_token_present = (
            "stop_token" in bridge_result
            and bridge_result.get("stop_token") is not None
        )
        stop_required = bool(
            session_active
            or bridge_result.get("stop_required") is True
            or stop_token_present
        )
        result.rollback_plan.update(
            {
                "native_bridge": True,
                "session_active": session_active,
                "stop_required": stop_required,
                "stop_token": (
                    bridge_result.get("stop_token") if stop_required else None
                ),
                "bridge": bridge_descriptor,
                "completed": not stop_required,
            }
        )
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.after_snapshot["bridge_session"] = {
            "active": session_active,
            "stop_required": stop_required,
            "stop_token_present": stop_token_present,
        }
        _sync_report(result)
        return result

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=str(result.session_id or ""),
                ok=False,
                restored=False,
                details={
                    "status": "failed",
                    "reason": "execution result does not belong to this provider",
                },
            )
        bridge_session = _mapping(result.after_snapshot.get("bridge_session"))
        stop_token_marked = bool(
            (
                "stop_token" in result.rollback_plan
                and result.rollback_plan.get("stop_token") is not None
            )
            or bridge_session.get("stop_token_present") is True
        )
        if bool(
            result.rollback_plan.get("session_active") is True
            or result.rollback_plan.get("stop_required") is True
            or bridge_session.get("active") is True
            or bridge_session.get("stop_required") is True
            or stop_token_marked
        ):
            return self._rollback_native_bridge_session(result, context=context)

        capture = _mapping(result.report_section.get("capture"))
        cleanup = _mapping(capture.get("process_cleanup"))
        cleanup_confirmed = bool(
            cleanup.get("process_exited")
            or cleanup.get("not_started")
            or capture.get("status") in {"blocked", "unavailable"}
        )
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "not_required" if cleanup_confirmed else "failed",
            "reason": (
                "graphics-present capture is read-only and its subprocess is closed"
                if cleanup_confirmed
                else "capture subprocess cleanup was not confirmed"
            ),
            "read_only": True,
            "side_effects": False,
            "attempted": False,
            "restored": False,
            "process_cleanup_confirmed": cleanup_confirmed,
        }
        result.rollback_plan.update(
            {
                "supported": False,
                "mode": "not_required",
                "completed": cleanup_confirmed,
                "rollback_status": details["status"],
                "restored": False,
            }
        )
        result.after_snapshot["rollback"] = dict(details)
        result.report_section["rollback"] = dict(details)
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "graphics_present_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "status": details["status"],
                "read_only": True,
            }
        )
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=cleanup_confirmed,
            restored=False,
            details=details,
        )

    def _rollback_native_bridge_session(
        self,
        result: CapabilityExecutionResult,
        *,
        context: Optional[dict[str, Any]],
    ) -> CapabilityRollbackResult:
        bridge_session = _mapping(result.after_snapshot.get("bridge_session"))
        stop_token = result.rollback_plan.get("stop_token")
        stop_token_present = bool(
            (
                "stop_token" in result.rollback_plan
                and stop_token is not None
            )
            or bridge_session.get("stop_token_present") is True
        )
        session_active_before = bool(
            result.rollback_plan.get("session_active") is True
            or bridge_session.get("active") is True
        )
        stop_call: Optional[NativeBridgeCallResult] = None
        stop_error: Optional[str] = None
        attempted = False
        bridge_identity_verified = False
        try:
            bridge = self._select_rollback_bridge(
                _mapping(result.rollback_plan.get("bridge")),
                context,
            )
            bridge_identity_verified = True
            attempted = True
            candidate = bridge.invoke(
                "stop",
                {
                    "stop_token": stop_token,
                    "session_active": session_active_before,
                    "stop_required": True,
                    "reason": "rollback",
                },
                session_id=result.session_id,
                timeout_ms=bridge.timeout_ms,
            )
            if not isinstance(candidate, NativeBridgeCallResult):
                stop_error = "native graphics bridge returned an invalid stop result type"
            else:
                stop_call = candidate
        except Exception as exc:  # noqa: BLE001 - rollback boundary becomes evidence
            stop_error = f"native graphics bridge stop failed: {exc}"

        stop_response = (
            _mapping(stop_call.response.get("result")) if stop_call else {}
        )
        stop_cleanup = _mapping(stop_call.process_cleanup) if stop_call else {}
        stop_process_closed = bool(stop_cleanup.get("process_exited"))
        stop_attested = bool(
            stop_call
            and (
                stop_call.status == "stopped"
                or stop_response.get("stopped") is True
                or stop_response.get("session_active") is False
            )
            and stop_response.get("session_active") is not True
            and stop_response.get("stop_required") is not True
        )
        stop_verified = bool(
            stop_call and stop_call.ok and stop_process_closed and stop_attested
        )
        if stop_verified:
            reason = "native graphics bridge confirmed that the session stopped"
        elif stop_error:
            reason = stop_error
        elif stop_call and stop_call.error:
            reason = stop_call.error
        elif stop_call and not stop_process_closed:
            reason = "native graphics bridge stop subprocess cleanup was not confirmed"
        else:
            reason = "native graphics bridge did not attest that the session stopped"

        session_active_after = not stop_verified
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "completed" if stop_verified else "failed",
            "reason": reason,
            "read_only": True,
            "side_effects": False,
            "attempted": attempted,
            "restored": False,
            "bridge_identity_verified": bridge_identity_verified,
            "process_cleanup_confirmed": stop_process_closed,
            "stop_token_present": stop_token_present,
            "stop_verified": stop_verified,
            "session_active_before": session_active_before,
            "session_active_after": session_active_after,
            "native_bridge_stop": (
                stop_call.to_dict(include_payloads=True) if stop_call else {}
            ),
        }
        result.rollback_plan.update(
            {
                "supported": True,
                "mode": "native_bridge_stop",
                "rollback_attempted": attempted,
                "rollback_status": details["status"],
                "completed": stop_verified,
                "restored": False,
                "session_active": session_active_after,
                "stop_required": not stop_verified,
                "stop_token": None if stop_verified else stop_token,
                "stop_verified": stop_verified,
            }
        )
        result.after_snapshot["bridge_session"] = {
            **bridge_session,
            "active": session_active_after,
            "stop_required": not stop_verified,
            "stop_token_present": stop_token_present and not stop_verified,
            "stop_verified": stop_verified,
        }
        result.after_snapshot["rollback"] = dict(details)
        result.report_section["rollback"] = dict(details)
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "graphics_present_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "status": details["status"],
                "read_only": True,
                "mode": "native_bridge_stop",
                "stop_verified": stop_verified,
            }
        )
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=stop_verified,
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
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            raise ValueError("execution result does not belong to graphics provider")
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or _artifacts(result.session_id, result.status))
        expected_kinds = {
            "graphics-runtime-audit",
            "graphics-present-events",
            "graphics-runtime-manifest",
        }
        if {artifact.kind for artifact in artifacts} != expected_kinds:
            raise ValueError("graphics runtime artifact set is incomplete or unsupported")

        entries_by_path = {
            str(item.get("path")): dict(item)
            for item in result.evidence_manifest_entries or []
            if item.get("path")
        }
        materialized: dict[str, dict[str, Any]] = {}
        for artifact in artifacts:
            if artifact.kind == "graphics-runtime-manifest":
                continue
            payload = (
                _audit_payload(result)
                if artifact.kind == "graphics-runtime-audit"
                else _events_payload(result)
            )
            encoded = _json_bytes(payload)
            destination = _artifact_destination(root, artifact.path)
            _atomic_write(destination, encoded)
            materialized[artifact.path] = {
                "path": artifact.path,
                "kind": artifact.kind,
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size": len(encoded),
                "materialized": True,
            }

        manifest_artifact = next(
            item for item in artifacts if item.kind == "graphics-runtime-manifest"
        )
        manifest_payload = {
            "schema_version": _SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": result.status,
            "target_identity": result.target.to_dict(),
            "artifacts": [
                materialized.get(
                    artifact.path,
                    {
                        "path": artifact.path,
                        "kind": artifact.kind,
                        "materialized": True,
                        "self_hash_omitted": True,
                    },
                )
                for artifact in artifacts
            ],
            "provenance": {
                "precondition_hash": result.provenance.get("precondition_hash"),
                "capture_output_sha256": _mapping(
                    result.report_section.get("capture")
                ).get("output_sha256"),
            },
        }
        manifest_encoded = _json_bytes(manifest_payload)
        manifest_destination = _artifact_destination(root, manifest_artifact.path)
        _atomic_write(manifest_destination, manifest_encoded)
        materialized[manifest_artifact.path] = {
            "path": manifest_artifact.path,
            "kind": manifest_artifact.kind,
            "sha256": hashlib.sha256(manifest_encoded).hexdigest(),
            "size": len(manifest_encoded),
            "materialized": True,
        }

        manifest_entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            record = materialized[artifact.path]
            artifact.metadata.update(
                {
                    "collection_root": str(root),
                    "materialized": True,
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
            )
            entry = entries_by_path.get(
                artifact.path, _manifest_entry(result, artifact)
            )
            entry.update(
                {
                    "materialized": True,
                    "sha256": record["sha256"],
                    "size": record["size"],
                }
            )
            manifest_entries.append(entry)
        result.artifacts = artifacts
        result.evidence_manifest_entries = manifest_entries
        _sync_report(result)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _bridge_for_request(
        self,
        raw_parameters: Mapping[str, Any],
    ) -> tuple[LocalJsonBridgeAdapter, list[str]]:
        """Resolve a request-level bridge without weakening provider defaults."""

        source = dict(raw_parameters or {})
        bridge_keys = {
            "bridge_args",
            "bridge_executable",
            "bridge_path",
            "bridge_timeout_ms",
        }
        if not bridge_keys.intersection(source):
            return self.bridge, []

        errors: list[str] = []
        executable: Optional[Path] = None
        supplied_paths: list[tuple[str, Path]] = []
        for name in ("bridge_executable", "bridge_path"):
            if name not in source or source.get(name) is None:
                continue
            try:
                supplied_paths.append(
                    (name, _resolve_bridge_executable(source.get(name)))
                )
            except (OSError, TypeError, ValueError) as exc:
                errors.append(f"{name}: {exc}")
        if supplied_paths:
            executable = supplied_paths[0][1]
            if any(path != executable for _, path in supplied_paths[1:]):
                errors.append(
                    "bridge_executable and bridge_path must identify the same executable"
                )
        elif not errors and self.bridge.executable is not None:
            executable = self.bridge.executable

        raw_args = source.get("bridge_args", ())
        args: tuple[str, ...] = ()
        if isinstance(raw_args, (str, bytes, bytearray)) or not isinstance(
            raw_args, Sequence
        ):
            errors.append("bridge_args must be a sequence of argument strings")
        else:
            parsed_args: list[str] = []
            for index, value in enumerate(raw_args):
                try:
                    parsed_args.append(_bridge_arg(value))
                except ValueError as exc:
                    errors.append(f"bridge_args[{index}]: {exc}")
            if len(parsed_args) > 32:
                errors.append("bridge_args accepts at most 32 fixed arguments")
                parsed_args = parsed_args[:32]
            args = tuple(parsed_args)

        timeout_ms = self.bridge.timeout_ms
        if "bridge_timeout_ms" in source:
            try:
                timeout_ms = _bridge_bounded_int(
                    source.get("bridge_timeout_ms"),
                    "bridge_timeout_ms",
                    minimum=100,
                    maximum=_MAX_BRIDGE_TIMEOUT_MS,
                )
            except ValueError as exc:
                errors.append(str(exc))

        if errors:
            return LocalJsonBridgeAdapter(self.capability_name), _deduplicate(errors)

        bridge = LocalJsonBridgeAdapter(
            self.capability_name,
            executable,
            args=args,
            env_vars=() if executable is not None else _GRAPHICS_BRIDGE_ENV_VARS,
            timeout_ms=timeout_ms,
        )
        if args and not bridge.configured:
            errors.append("bridge_args requires a configured native bridge executable")
        return bridge, _deduplicate(errors)

    def _select_bridge(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]],
    ) -> LocalJsonBridgeAdapter:
        override = (context or {}).get("graphics_runtime_bridge")
        if override is not None:
            if type(override) is not LocalJsonBridgeAdapter:
                raise ValueError(
                    "graphics_runtime_bridge must be an exact LocalJsonBridgeAdapter"
                )
            return override

        planned = _mapping(plan.parameters.get("native_bridge"))
        planned_executable = planned.get("executable")
        current = self.bridge.describe()
        if planned_executable and _bridge_descriptors_match(planned, current):
            return self.bridge
        if planned_executable:
            return LocalJsonBridgeAdapter(
                self.capability_name,
                planned_executable,
                args=tuple(planned.get("args") or ()),
                env_vars=(),
                timeout_ms=int(planned.get("timeout_ms") or self.bridge.timeout_ms),
            )
        return self.bridge

    def _select_rollback_bridge(
        self,
        descriptor: Mapping[str, Any],
        context: Optional[dict[str, Any]],
    ) -> LocalJsonBridgeAdapter:
        planned = _mapping(descriptor)
        override = (context or {}).get("graphics_runtime_bridge")
        if override is not None:
            if type(override) is not LocalJsonBridgeAdapter:
                raise ValueError(
                    "graphics_runtime_bridge must be an exact LocalJsonBridgeAdapter"
                )
            bridge = override
        elif _bridge_descriptors_match(planned, self.bridge.describe()):
            bridge = self.bridge
        else:
            executable = planned.get("executable")
            args = planned.get("args") if "args" in planned else ()
            timeout_ms = planned.get("timeout_ms")
            if not executable:
                raise ValueError("planned native bridge executable is missing")
            if (
                isinstance(args, (str, bytes, bytearray))
                or not isinstance(args, Sequence)
            ):
                raise ValueError("planned native bridge args are invalid")
            if type(timeout_ms) is not int:
                raise ValueError("planned native bridge timeout_ms is invalid")
            bridge = LocalJsonBridgeAdapter(
                self.capability_name,
                executable,
                args=tuple(args),
                env_vars=(),
                timeout_ms=timeout_ms,
            )

        if not _bridge_descriptors_match(planned, bridge.describe()):
            raise ValueError(
                "native graphics bridge command or executable identity changed "
                "before rollback"
            )
        return bridge

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        unavailable_reasons: list[str] = []

        def add_check(
            name: str,
            ok: bool,
            message: str,
            *,
            unavailable: bool = False,
            warning: bool = False,
            **details: Any,
        ) -> None:
            if ok:
                status = "ok"
            elif warning:
                status = "warning"
            elif unavailable:
                status = "unavailable"
            else:
                status = "failed"
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": status,
                        "message": message,
                        **details,
                    }
                )
            )
            if not ok:
                if unavailable:
                    warnings.append(message)
                    unavailable_reasons.append(message)
                elif warning:
                    warnings.append(message)
                else:
                    errors.append(message)

        add_check(
            "capability_identity",
            plan.capability == self.capability_name
            and plan.provider == self.provider_name,
            "plan capability/provider identity does not match graphics provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        action = _normalize_action(plan.action)
        add_check(
            "supported_action",
            action == _ACTION,
            f"unsupported graphics-present action: {plan.action}",
            action=action,
        )
        pid = _optional_positive_int(plan.parameters.get("pid"))
        target_pid = _optional_positive_int(getattr(plan.target, "pid", None))
        add_check(
            "target_pid",
            bool(pid and target_pid == pid),
            "target PID must be positive and match the planned target identity",
            pid=pid,
            target_pid=target_pid,
        )
        parameter_errors = [
            str(item) for item in plan.parameters.get("parameter_errors") or []
        ]
        add_check(
            "input_schema",
            not parameter_errors,
            (
                "graphics-present parameters are valid"
                if not parameter_errors
                else "; ".join(parameter_errors)
            ),
            parameter_errors=parameter_errors,
        )
        add_check(
            "passive_policy",
            bool(plan.parameters.get("passive_only"))
            and not plan.parameters.get("rejected_control_keys"),
            "graphics-present capture accepts passive observation only",
            policy=_PASSIVE_POLICY,
            rejected_control_keys=plan.parameters.get("rejected_control_keys"),
        )
        current_hash = _plan_fingerprint(action, plan.target, plan.parameters)
        precondition_hash_ok = bool(
            plan.precondition_hash and current_hash == plan.precondition_hash
        )
        add_check(
            "precondition_hash",
            precondition_hash_ok,
            "graphics-present plan parameters no longer match the precondition hash",
            expected=plan.precondition_hash,
            actual=current_hash,
        )
        execution_adapter = str(
            plan.parameters.get("execution_adapter") or "presentmon"
        )
        bridge_selected = execution_adapter == "native_bridge"
        bridge_context_error: Optional[str] = None
        try:
            bridge = self._select_bridge(plan, context)
        except (TypeError, ValueError) as exc:
            bridge = self.bridge
            bridge_context_error = str(exc)
        add_check(
            "native_bridge_context",
            bridge_context_error is None,
            bridge_context_error or "native bridge selection is bound to the plan",
        )
        platform_ok = self.platform_name == "win32" or bridge_selected
        add_check(
            "windows_platform",
            platform_ok,
            (
                "native bridge owns platform-specific graphics observation"
                if bridge_selected
                else "Windows PresentMon production path is available"
                if platform_ok
                else f"PresentMon production capture is unavailable on {self.platform_name}"
            ),
            unavailable=not platform_ok,
            platform=self.platform_name,
        )

        required_backends = _requested_graphics_backends(
            plan.parameters.get("api_filter")
        )
        bridge_probe: Optional[NativeBridgeCallResult] = None
        if bridge_selected:
            bridge_description = bridge.describe()
            planned_identity = _mapping(
                _mapping(plan.parameters.get("native_bridge")).get(
                    "executable_identity"
                )
            )
            identity_unavailable = bool(
                not bridge_description.get("available") and not planned_identity
            )
            identity_ok = bool(planned_identity) and _bridge_descriptors_match(
                _mapping(plan.parameters.get("native_bridge")),
                bridge_description,
            )
            add_check(
                "native_bridge_identity",
                identity_ok,
                (
                    "native graphics bridge command and executable identity are unchanged"
                    if identity_ok
                    else str(
                        bridge_description.get("unavailable_reason")
                        or "native graphics bridge is unavailable"
                    )
                    if identity_unavailable
                    else (
                        "native graphics bridge command or executable identity "
                        "changed after planning"
                    )
                ),
                unavailable=identity_unavailable,
                bridge=bridge_description,
            )
            static_bridge_valid = bool(
                precondition_hash_ok
                and bridge_context_error is None
                and identity_ok
                and not errors
                and not unavailable_reasons
            )
            if static_bridge_valid:
                bridge_probe = bridge.probe(
                    required_operations=("observe_present", "stop"),
                    required_backends=required_backends,
                )
                bridge_available = bridge_probe.ok
                bridge_reason = (
                    bridge_probe.error or "native graphics bridge is unavailable"
                )
                add_check(
                    "native_bridge_dependency",
                    bridge_available,
                    (
                        "native graphics bridge protocol and backend capabilities verified"
                        if bridge_available
                        else bridge_reason
                    ),
                    unavailable=not bridge_available,
                    probe=bridge_probe.to_dict(include_payloads=True),
                    required_backends=required_backends,
                )
            else:
                dependency_unavailable = bool(unavailable_reasons and not errors)
                add_check(
                    "native_bridge_dependency",
                    False,
                    (
                        "native graphics bridge probe was not run because the "
                        "configured dependency is unavailable"
                        if dependency_unavailable
                        else "native graphics bridge probe was blocked by static plan validation"
                    ),
                    unavailable=dependency_unavailable,
                    probe={},
                    required_backends=required_backends,
                )
        else:
            add_check(
                "native_bridge_dependency",
                True,
                "native bridge was not selected; PresentMon adapter is planned",
                selected=False,
            )

        runner = self._select_runner(plan, context)
        runner_api_ok = callable(getattr(runner, "probe", None)) and callable(
            getattr(runner, "capture", None)
        )
        add_check(
            "runner_api",
            runner_api_ok or bridge_selected,
            (
                "PresentMon runner is not selected"
                if bridge_selected
                else "graphics runner must implement probe and capture"
            ),
            unavailable=not runner_api_ok and not bridge_selected,
        )
        probe: dict[str, Any] = {}
        if runner_api_ok and not bridge_selected:
            try:
                probe = _mapping(runner.probe())
            except Exception as exc:  # noqa: BLE001 - dependency probe boundary
                probe = {
                    "status": "unavailable",
                    "available": False,
                    "unavailable_reason": str(exc),
                }
        runner_available = bool(
            probe.get("available", getattr(runner, "available", False))
        )
        reason = str(
            probe.get("unavailable_reason")
            or getattr(runner, "unavailable_reason", "")
            or "PresentMon runner is unavailable"
        )
        add_check(
            "presentmon_dependency",
            runner_available or bridge_selected,
            (
                "PresentMon is not selected because native bridge is planned"
                if bridge_selected
                else "configured PresentMon executable is available"
                if runner_available
                else reason
            ),
            unavailable=not runner_available and not bridge_selected,
            probe=probe,
        )
        production_runner = type(runner) is PresentMonRunner
        runner_policy_ok = production_runner or getattr(
            runner, "test_double", None
        ) is True
        add_check(
            "runner_boundary",
            runner_policy_ok,
            (
                "runner is the internal production type"
                if production_runner
                else "injected runner is explicitly marked test_double"
                if runner_policy_ok
                else "injected graphics runner must declare test_double=True"
            ),
        )
        add_check(
            "production_runner",
            production_runner or bridge_selected,
            (
                "production native bridge local-subprocess adapter selected"
                if bridge_selected
                else "production PresentMon local-subprocess runner selected"
                if production_runner
                else "non-production runner can exercise errors but cannot establish success"
            ),
            warning=not production_runner and not bridge_selected,
        )

        process = (
            {
                "status": "ok",
                "pid": pid,
                "identity_owner": "native_bridge",
                "reason": "target process validation is delegated to the probed native bridge",
            }
            if bridge_selected
            else _probe_windows_process(pid, self.platform_name)
        )
        process_ok = process.get("status") == "ok"
        add_check(
            "target_process",
            process_ok,
            (
                "target process identity is readable"
                if process_ok
                else str(process.get("reason") or "target process is unavailable")
            ),
            unavailable=bool(
                platform_ok and pid and process.get("status") == "unavailable"
            ),
            process=process,
        )

        if self._live_export_evidence is None:
            self._live_export_evidence = inspect_live_system_present_exports()
        live_exports = dict(self._live_export_evidence)
        live_export_ok = live_exports.get("status") in {"ok", "partial"}
        add_check(
            "live_system_present_exports",
            live_export_ok,
            (
                "real analyzer-process system export addresses were verified"
                if live_export_ok
                else str(
                    live_exports.get("reason")
                    or "no live system present export address was verified"
                )
            ),
            warning=not live_export_ok,
            evidence=live_exports,
        )

        module_results: list[dict[str, Any]] = []
        for spec in plan.parameters.get("modules") or []:
            inspection = inspect_pe_exports(
                spec["path"],
                spec.get("required_exports") or [],
                any_of_exports=spec.get("any_of_exports") or [],
            )
            compact = _compact_module_inspection(inspection)
            compact["api"] = spec.get("api")
            compact["declared_for_pid"] = pid
            compact["loaded_in_target_verified"] = False
            module_results.append(compact)
            status = str(inspection.get("status") or "failed")
            module_reason = str(
                inspection.get("error")
                or f"PE export inspection status is {status}"
            )
            add_check(
                f"pe_exports_{len(module_results) - 1}",
                status == "ok",
                (
                    f"PE exports verified for {spec['path']}"
                    if status == "ok"
                    else module_reason
                ),
                unavailable=status == "unavailable",
                module=compact,
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
            {
                "runner": runner,
                "runner_probe": probe,
                "bridge": bridge,
                "bridge_probe": bridge_probe,
                "execution_adapter": execution_adapter,
                "process": process,
                "modules": module_results,
                "live_system_exports": live_exports,
                "unavailable_reasons": _deduplicate(unavailable_reasons),
            },
        )

    def _select_runner(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]],
    ) -> GraphicsCaptureRunner:
        if context and context.get("graphics_runtime_runner") is not None:
            return context["graphics_runtime_runner"]
        requested = plan.parameters.get("presentmon_path")
        if self._runner_explicit or not requested:
            return self.runner
        current = getattr(self.runner, "executable", None)
        if current and str(Path(current).resolve()) == str(Path(requested).resolve()):
            return self.runner
        return PresentMonRunner(
            str(requested), max_output_bytes=self.max_capture_bytes
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        capture: Mapping[str, Any],
        correlation: Mapping[str, Any],
        modules: Sequence[Mapping[str, Any]],
        present_targets: Sequence[Mapping[str, Any]],
        errors: Sequence[str],
        warnings: Sequence[str],
    ) -> CapabilityExecutionResult:
        events = [dict(item) for item in correlation.get("events") or []]
        live_system_exports = next(
            (
                dict(item.get("evidence") or {})
                for item in validation.checks
                if item.get("name") == "live_system_present_exports"
            ),
            {},
        )
        artifacts = _artifacts(plan.session_id, status)
        manifest_entries = [
            _planned_manifest_entry(plan, artifact) for artifact in artifacts
        ]
        before = dict(plan.before_snapshot or {})
        after = {
            "schema_version": _SCHEMA_VERSION,
            "capture_phase": "after",
            "status": status,
            "pid": plan.parameters.get("pid"),
            "passive_policy": dict(_PASSIVE_POLICY),
            "capture": _json_safe(capture),
            "frame_summary": _json_safe(correlation.get("frames") or {}),
            "event_count": int(correlation.get("event_count") or 0),
            "excluded_event_count": int(
                correlation.get("excluded_event_count") or 0
            ),
            "apis": list(correlation.get("apis") or []),
            "swap_chain_count": int(correlation.get("swap_chain_count") or 0),
            "lifecycle": [dict(item) for item in correlation.get("streams") or []],
            "present_targets": [dict(item) for item in present_targets],
            "module_export_verification": [dict(item) for item in modules],
            "live_system_export_verification": live_system_exports,
            "side_effects": False,
        }
        rollback_plan = _read_only_rollback_plan(plan.precondition_hash)
        rollback_plan["completed"] = bool(
            _mapping(capture.get("process_cleanup")).get("process_exited")
            or capture.get("status") in {"blocked", "unavailable"}
        )
        provenance = {
            **_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "capture": _prune(
                {
                    "output_sha256": capture.get("output_sha256"),
                    "output_size": capture.get("output_size"),
                    "output_format": capture.get("output_format"),
                    "command": capture.get("command"),
                    "started_at": capture.get("started_at"),
                    "ended_at": capture.get("ended_at"),
                    "local_subprocess": capture.get("local_subprocess"),
                    "presentmon_identity_verified": capture.get(
                        "presentmon_identity_verified"
                    ),
                    "production_evidence": capture.get("production_evidence"),
                    "provenance": capture.get("provenance"),
                }
            ),
            "module_evidence": [dict(item) for item in modules],
            "live_system_export_evidence": live_system_exports,
            "passive_policy": dict(_PASSIVE_POLICY),
        }
        report = {
            "schema_version": _SCHEMA_VERSION,
            "capability": plan.capability,
            "provider": plan.provider,
            "action": plan.action,
            "status": status,
            "session_id": plan.session_id,
            "target_identity": plan.target.to_dict(),
            "precondition_hash": plan.precondition_hash,
            "before_snapshot": before,
            "after_snapshot": after,
            "rollback_plan": rollback_plan,
            "provenance": provenance,
            "artifacts": [artifact.to_dict() for artifact in artifacts],
            "evidence_manifest_entries": manifest_entries,
            "validation": validation.to_dict(),
            "capture": _json_safe(capture),
            "frames": _json_safe(correlation.get("frames") or {}),
            "lifecycle": [dict(item) for item in correlation.get("streams") or []],
            "present_targets": [dict(item) for item in present_targets],
            "module_export_verification": [dict(item) for item in modules],
            "live_system_export_verification": live_system_exports,
            "events": events,
            "errors": list(errors),
            "warnings": _deduplicate(warnings),
            "passive_policy": dict(_PASSIVE_POLICY),
        }
        dashboard_trace = [
            {
                "kind": "graphics_present_capture",
                "capability": plan.capability,
                "provider": plan.provider,
                "action": plan.action,
                "session_id": plan.session_id,
                "status": status,
                "pid": plan.parameters.get("pid"),
                "event_count": len(events),
                "api_count": len(correlation.get("apis") or []),
                "swap_chain_count": int(correlation.get("swap_chain_count") or 0),
                "production_evidence": bool(capture.get("production_evidence")),
                "side_effects": False,
            }
        ]
        report["dashboard_trace"] = dashboard_trace
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=before,
            after_snapshot=after,
            rollback_plan=rollback_plan,
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=report,
            dashboard_trace=dashboard_trace,
            provenance=provenance,
        )


def _normalize_request_parameters(
    request: CapabilityRequest,
    runner: GraphicsCaptureRunner,
) -> tuple[dict[str, Any], TargetIdentity]:
    source = dict(request.params or {})
    errors: list[str] = []
    unknown = sorted(str(key) for key in source if key not in _ALLOWED_PARAMETER_KEYS)
    rejected_control = sorted(
        key
        for key in unknown
        if any(token in key.lower() for token in _CONTROL_PARAMETER_TOKENS)
    )
    if unknown:
        errors.append("unsupported parameters: " + ", ".join(unknown))

    target_pid = _optional_positive_int(getattr(request.target, "pid", None))
    param_pid = _optional_positive_int(source.get("pid"))
    if source.get("pid") is not None and param_pid is None:
        errors.append("pid must be a positive integer")
    if target_pid and param_pid and target_pid != param_pid:
        errors.append("params.pid must match target.pid")
    pid = target_pid or param_pid
    if pid is None:
        errors.append("an explicit positive target PID is required")

    duration_ms = _parameter_int(
        source.get("duration_ms"),
        name="duration_ms",
        default=_DEFAULT_DURATION_MS,
        minimum=_MIN_DURATION_MS,
        maximum=_MAX_DURATION_MS,
        errors=errors,
    )
    timeout_default = min(
        _MAX_TIMEOUT_MS, duration_ms + _DEFAULT_TIMEOUT_GRACE_MS
    )
    timeout_ms = _parameter_int(
        source.get("timeout_ms"),
        name="timeout_ms",
        default=timeout_default,
        minimum=_MIN_DURATION_MS + 1,
        maximum=_MAX_TIMEOUT_MS,
        errors=errors,
    )
    if timeout_ms <= duration_ms:
        errors.append("timeout_ms must exceed duration_ms")
    max_events = _parameter_int(
        source.get("max_events"),
        name="max_events",
        default=_DEFAULT_MAX_EVENTS,
        minimum=1,
        maximum=_MAX_EVENTS,
        errors=errors,
    )

    capture_format = str(source.get("capture_format") or "auto").strip().lower()
    if capture_format not in {"auto", "csv", "json"}:
        errors.append("capture_format must be one of: auto, csv, json")
        capture_format = "auto"
    api_filter = _normalize_api_filter(source.get("api_filter"), errors)

    raw_modules = source.get("modules")
    if source.get("module_paths") is not None:
        if raw_modules is not None:
            errors.append("use only one of modules or module_paths")
        else:
            raw_modules = source.get("module_paths")
    modules = _normalize_module_specs(raw_modules, errors)

    presentmon_path = source.get("presentmon_path")
    if presentmon_path is None:
        configured = getattr(runner, "executable", None)
        presentmon_path = str(configured) if configured else None
    elif not isinstance(presentmon_path, (str, os.PathLike)):
        errors.append("presentmon_path must be a filesystem path")
        presentmon_path = None
    else:
        text = os.fspath(presentmon_path)
        if not text.strip() or "\x00" in text:
            errors.append("presentmon_path must be a non-empty path without NUL")
            presentmon_path = None
        else:
            presentmon_path = str(Path(text).expanduser().resolve())

    target = TargetIdentity(
        kind=request.target.kind or "process",
        path=request.target.path,
        pid=pid,
        sha256=request.target.sha256,
        display_name=request.target.display_name,
        metadata=dict(request.target.metadata or {}),
    )
    return (
        {
            "pid": pid,
            "duration_ms": duration_ms,
            "timeout_ms": timeout_ms,
            "max_events": max_events,
            "capture_format": capture_format,
            "api_filter": api_filter,
            "modules": modules,
            "presentmon_path": presentmon_path,
            "parameter_errors": _deduplicate(errors),
            "rejected_control_keys": rejected_control,
            "passive_only": True,
        },
        target,
    )


def _normalize_module_specs(
    value: Any,
    errors: list[str],
) -> list[dict[str, Any]]:
    if value in (None, [], {}):
        return []
    raw_items: list[Any]
    if isinstance(value, Mapping):
        if "path" in value:
            raw_items = [value]
        else:
            raw_items = [
                {"api": key, "path": path} for key, path in value.items()
            ]
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        raw_items = list(value)
    else:
        raw_items = [value]
    if len(raw_items) > _MAX_MODULES:
        errors.append(f"modules exceeds the {_MAX_MODULES} item limit")
        raw_items = raw_items[:_MAX_MODULES]

    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_items):
        if isinstance(raw, (str, os.PathLike)):
            item = {"path": os.fspath(raw)}
        elif isinstance(raw, Mapping):
            item = dict(raw)
        else:
            errors.append(f"modules[{index}] must be a path or mapping")
            continue
        unknown = sorted(
            str(key)
            for key in item
            if key not in {"api", "any_of_exports", "path", "required_exports"}
        )
        if unknown:
            errors.append(
                f"modules[{index}] has unsupported keys: " + ", ".join(unknown)
            )
        raw_path = item.get("path")
        if not isinstance(raw_path, (str, os.PathLike)) or not os.fspath(
            raw_path
        ).strip():
            errors.append(f"modules[{index}].path must be a non-empty path")
            continue
        if "\x00" in os.fspath(raw_path):
            errors.append(f"modules[{index}].path contains NUL")
            continue
        path = str(Path(raw_path).expanduser().resolve())
        api = _normalize_api(item.get("api") or _infer_module_api(path))
        required = _module_export_list(
            item.get("required_exports"), f"modules[{index}].required_exports", errors
        )
        any_of = _module_export_list(
            item.get("any_of_exports"), f"modules[{index}].any_of_exports", errors
        )
        if not required and not any_of:
            if api == "OpenGL":
                any_of = ["SwapBuffers", "wglSwapBuffers"]
            elif api == "Vulkan":
                required = ["vkQueuePresentKHR"]
        key = (api, os.path.normcase(path))
        if key in seen:
            errors.append(f"duplicate module declaration for {api}: {path}")
            continue
        seen.add(key)
        normalized.append(
            {
                "path": path,
                "api": api,
                "required_exports": required,
                "any_of_exports": any_of,
                "read_only": True,
            }
        )
    return normalized


def _module_export_list(value: Any, name: str, errors: list[str]) -> list[str]:
    if value in (None, "", []):
        return []
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray)):
        errors.append(f"{name} must be a string or sequence of strings")
        return []
    try:
        return _normalize_export_names(values, name)
    except ValueError as exc:
        errors.append(str(exc))
        return []


def _normalize_api_filter(value: Any, errors: list[str]) -> list[str]:
    if value in (None, "", []):
        return []
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, Sequence) or isinstance(values, (bytes, bytearray)):
        errors.append("api_filter must be a string or sequence of strings")
        return []
    if len(values) > 16:
        errors.append("api_filter exceeds the 16 item limit")
        values = values[:16]
    result: list[str] = []
    for item in values:
        try:
            result.append(_normalize_api(item))
        except PresentMonParseError as exc:
            errors.append(f"invalid api_filter: {exc}")
    return _deduplicate(result)


def _requested_graphics_backends(api_filter: Any) -> list[str]:
    """Translate normalized API filters into native-bridge backend names.

    DXGI does not identify the Direct3D generation, so a bridge selected for a
    DXGI capture must declare both supported swap-chain implementations.  D3D9
    and D3D10 remain explicit backend requirements; the current bridge contract
    does not advertise them, which makes dependency validation fail closed.
    """

    if not api_filter:
        return list(_GRAPHICS_PRESENT_BACKENDS)
    values = [api_filter] if isinstance(api_filter, str) else list(api_filter)
    requested: list[str] = []
    for value in values:
        api = _normalize_api(value)
        if api == "DXGI":
            backends = ("d3d11", "d3d12")
        else:
            backends = (_bridge_backend_name(api),)
        for backend in backends:
            if backend and backend not in requested:
                requested.append(backend)
    return requested


def _build_present_targets(
    correlation: Mapping[str, Any],
    modules: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    targets: list[dict[str, Any]] = []
    gaps: list[str] = []
    by_api: dict[str, list[Mapping[str, Any]]] = {}
    for module in modules:
        by_api.setdefault(str(module.get("api") or "Unknown"), []).append(module)

    for api in correlation.get("apis") or []:
        streams = [
            dict(item)
            for item in correlation.get("streams") or []
            if item.get("api") == api
        ]
        base = {
            "api": api,
            "source": "PresentMon",
            "observed": True,
            "swap_chains": [item.get("swap_chain_id") for item in streams],
            "swap_chain_identity_kind": "opaque_presentmon_identifier",
            "runtime_address": None,
        }
        if api in {"DXGI", "D3D10", "D3D11", "D3D12"}:
            targets.append(
                {
                    **base,
                    "kind": "com_vtable_method",
                    "interface": "IDXGISwapChain",
                    "method": "Present",
                    "verification": "present_events_observed",
                    "address_resolution": "intentionally_not_inferred",
                    "reason": (
                        "DXGI Present is a runtime COM vtable method; PE exports "
                        "cannot prove a process-specific method address"
                    ),
                }
            )
            continue
        if api == "D3D9":
            targets.append(
                {
                    **base,
                    "kind": "com_vtable_method",
                    "interface": "IDirect3DDevice9",
                    "method": "Present",
                    "verification": "present_events_observed",
                    "address_resolution": "intentionally_not_inferred",
                }
            )
            continue
        if api in {"OpenGL", "Vulkan"}:
            candidates = [
                item
                for item in by_api.get(api, [])
                if item.get("status") == "ok"
                and item.get("requirements_met", True)
                and item.get("selected_exports")
            ]
            if candidates:
                selected = candidates[0]
                selected_exports = list(selected.get("selected_exports") or [])
                matched_symbol = next(
                    (
                        str(item.get("name"))
                        for item in selected_exports
                        if item.get("name")
                    ),
                    "vkQueuePresentKHR" if api == "Vulkan" else "SwapBuffers",
                )
                targets.append(
                    {
                        **base,
                        "kind": "pe_export",
                        "symbol": matched_symbol,
                        "verification": "pe_export_rva_verified",
                        "module": selected.get("path"),
                        "module_sha256": _mapping(
                            selected.get("identity")
                        ).get("sha256"),
                        "exports": selected.get("selected_exports"),
                        "address_semantics": "relative_virtual_address_only",
                        "runtime_address": None,
                    }
                )
            else:
                reason = f"{api} events lack a verified present export module"
                gaps.append(reason)
                targets.append(
                    {
                        **base,
                        "kind": "pe_export",
                        "symbol": (
                            "vkQueuePresentKHR" if api == "Vulkan" else "SwapBuffers"
                        ),
                        "verification": "unavailable",
                        "reason": reason,
                    }
                )
            continue
        reason = f"no present-target verification rule exists for API {api}"
        gaps.append(reason)
        targets.append(
            {
                **base,
                "kind": "unknown",
                "verification": "unavailable",
                "reason": reason,
            }
        )
    return targets, gaps


def _compact_module_inspection(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    exports = list(result.pop("exports", []) or [])
    result["export_name_sample"] = [
        item.get("name") for item in exports[:32] if item.get("name")
    ]
    result["exports_truncated_in_audit"] = len(exports) > 32
    return _prune(result)


def _probe_windows_process(pid: Optional[int], platform_name: str) -> dict[str, Any]:
    if platform_name != "win32":
        return {
            "status": "unavailable",
            "pid": pid,
            "reason": f"Windows process APIs are unavailable on {platform_name}",
            "read_only": True,
        }
    if pid is None:
        return {
            "status": "failed",
            "pid": None,
            "reason": "target PID is invalid",
            "read_only": True,
        }
    try:
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            return {
                "status": "unavailable" if error == 5 else "failed",
                "pid": pid,
                "reason": f"OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed ({error})",
                "win32_error": error,
                "read_only": True,
            }
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            image_path = None
            if kernel32.QueryFullProcessImageNameW(
                handle, 0, buffer, ctypes.byref(size)
            ):
                image_path = buffer.value
            return _prune(
                {
                    "status": "ok",
                    "pid": pid,
                    "image_path": image_path,
                    "read_access": "query_limited_information",
                    "read_only": True,
                }
            )
        finally:
            kernel32.CloseHandle(handle)
    except Exception as exc:  # pragma: no cover - host API dependent
        return {
            "status": "unavailable",
            "pid": pid,
            "reason": f"unable to query target process: {exc}",
            "read_only": True,
        }


def _normalize_present_event(
    raw: Mapping[str, Any],
    *,
    event_index: int,
    source_format: str,
    source_row: int,
) -> dict[str, Any]:
    _validate_json_event_shape(raw)
    canonical: dict[str, Any] = {}
    for key, item in raw.items():
        canonical_key = _canonical_key(key)
        if not canonical_key:
            raise PresentMonParseError(
                f"event {event_index} contains an empty normalized field name"
            )
        if canonical_key in canonical:
            raise PresentMonParseError(
                f"event {event_index} contains duplicate normalized field "
                f"{canonical_key}"
            )
        canonical[canonical_key] = item

    def value(name: str) -> Any:
        for alias in _KEY_ALIASES[name]:
            if alias in canonical:
                return canonical[alias]
        return None

    pid = _strict_int(value("pid"), "ProcessID", minimum=1, maximum=_MAX_PID)
    api = _normalize_api(value("api"))
    timestamp = _optional_float(value("timestamp_s"), "timestamp", minimum=0.0)
    frame_time = _optional_float(
        value("frame_time_ms"), "frame time", minimum=0.0
    )
    if timestamp is None and frame_time is None:
        raise PresentMonParseError(
            f"event {event_index} must contain a timestamp or frame duration"
        )
    application = _optional_text(value("application"), "application", maximum=512)
    swap_chain = _normalize_swap_chain(value("swap_chain"))
    lifecycle = _normalize_lifecycle(value("lifecycle"))
    event = {
        "event_index": event_index,
        "pid": pid,
        "application": application,
        "api": api,
        "swap_chain_id": swap_chain,
        "swap_chain_identity_kind": "opaque_presentmon_identifier",
        "lifecycle": lifecycle,
        "timestamp_s": timestamp,
        "frame_time_ms": frame_time,
        "present_api_ms": _optional_float(
            value("present_api_ms"), "present API duration", minimum=0.0
        ),
        "render_complete_ms": _optional_float(
            value("render_complete_ms"), "render completion duration", minimum=0.0
        ),
        "display_latency_ms": _optional_float(
            value("display_latency_ms"), "display latency", minimum=0.0
        ),
        "displayed_time_ms": _optional_float(
            value("displayed_time_ms"), "displayed time", minimum=0.0
        ),
        "gpu_time_ms": _optional_float(
            value("gpu_time_ms"), "GPU time", minimum=0.0
        ),
        "cpu_busy_ms": _optional_float(
            value("cpu_busy_ms"), "CPU busy time", minimum=0.0
        ),
        "present_mode": _optional_text(
            value("present_mode"), "present mode", maximum=128
        ),
        "sync_interval": _optional_int(value("sync_interval"), "sync interval"),
        "present_flags": _optional_text(
            value("present_flags"), "present flags", maximum=128
        ),
        "dropped": _optional_bool(value("dropped"), "dropped"),
        "source": {
            "format": source_format,
            "row": source_row,
        },
        "source_fields": _json_safe(dict(raw)),
    }
    return _prune(event)


def _validate_required_columns(header: Sequence[str]) -> None:
    values = set(header)
    if not values.intersection(_KEY_ALIASES["pid"]):
        raise PresentMonParseError("PresentMon CSV is missing a ProcessID column")
    if not values.intersection(_KEY_ALIASES["api"]):
        raise PresentMonParseError("PresentMon CSV is missing a Runtime/API column")
    timing = set(_KEY_ALIASES["timestamp_s"] + _KEY_ALIASES["frame_time_ms"])
    if not values.intersection(timing):
        raise PresentMonParseError(
            "PresentMon CSV is missing timestamp and frame-duration columns"
        )


def _normalize_api(value: Any) -> str:
    text = _required_text(value, "graphics API", maximum=64)
    token = re.sub(r"[^a-z0-9]+", "", text.lower())
    return _KNOWN_API_NAMES.get(token, text.strip())


def _normalize_swap_chain(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise PresentMonParseError("swap-chain identity must not be boolean")
    if isinstance(value, int):
        if value < 0:
            raise PresentMonParseError("swap-chain identity must not be negative")
        return f"0x{value:x}"
    text = _required_text(value, "swap-chain identity", maximum=128)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
        return f"0x{int(text, 16):x}"
    return text


def _normalize_lifecycle(value: Any) -> str:
    if value in (None, ""):
        return "present"
    text = _required_text(value, "lifecycle", maximum=128).lower()
    if "resize" in text or "recreate" in text:
        return "resized"
    if "create" in text or "initial" in text:
        return "created"
    if "destroy" in text or "release" in text or "close" in text:
        return "destroyed"
    if "present" in text or "display" in text:
        return "present"
    return re.sub(r"[^a-z0-9_.-]+", "_", text).strip("_") or "unknown"


def _frame_summary(values: Sequence[float], *, event_count: int) -> dict[str, Any]:
    if not values:
        return {
            "event_count": event_count,
            "timed_frame_count": 0,
            "timing_status": "unreported",
        }
    ordered = sorted(values)
    average = statistics.fmean(ordered)
    p95_index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * 0.95) - 1))
    return {
        "event_count": event_count,
        "timed_frame_count": len(ordered),
        "timing_status": "observed",
        "minimum_ms": ordered[0],
        "maximum_ms": ordered[-1],
        "average_ms": average,
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[p95_index],
        "estimated_fps": 1000.0 / average if average > 0 else None,
    }


def _terminate_process_tree(
    process: subprocess.Popen[Any],
    *,
    job: _WindowsKillOnCloseJob,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "attempted": True,
        "process_exited": process.poll() is not None,
        "actions": [],
        "errors": [],
    }
    if process.poll() is not None:
        job.close()
        details["returncode"] = process.poll()
        return details
    if job.assigned:
        job.close()
        details["actions"].append("close_kill_on_close_job")
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            pass
    elif sys.platform != "win32":
        try:
            os.killpg(process.pid, signal.SIGTERM)
            details["actions"].append("sigterm_process_group")
            process.wait(timeout=0.75)
        except (OSError, subprocess.TimeoutExpired) as exc:
            details["errors"].append(str(exc))
    if process.poll() is None:
        try:
            process.terminate()
            details["actions"].append("terminate")
            process.wait(timeout=0.75)
        except (OSError, subprocess.TimeoutExpired) as exc:
            details["errors"].append(str(exc))
    if process.poll() is None:
        try:
            process.kill()
            details["actions"].append("kill")
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired) as exc:
            details["errors"].append(str(exc))
    job.close()
    details["process_exited"] = process.poll() is not None
    details["returncode"] = process.poll()
    return details


def _artifacts(session_id: str, status: str) -> list[CapabilityArtifact]:
    segment = _safe_segment(session_id)
    root = f"graphics-runtime/{segment}"
    return [
        CapabilityArtifact(
            path=f"{root}/audit.json",
            kind="graphics-runtime-audit",
            description="Passive graphics-present capability audit",
            metadata={"schema_version": _SCHEMA_VERSION, "status": status},
        ),
        CapabilityArtifact(
            path=f"{root}/events.json",
            kind="graphics-present-events",
            description="Normalized PresentMon frame and lifecycle events",
            metadata={"schema_version": _SCHEMA_VERSION, "status": status},
        ),
        CapabilityArtifact(
            path=f"{root}/manifest.json",
            kind="graphics-runtime-manifest",
            description="Graphics-present evidence artifact manifest",
            metadata={"schema_version": _SCHEMA_VERSION, "status": status},
        ),
    ]


def _planned_manifest_entry(
    plan: CapabilityPlan, artifact: CapabilityArtifact
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "materialized": False,
    }


def _manifest_entry(
    result: CapabilityExecutionResult, artifact: CapabilityArtifact
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "materialized": False,
    }


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "action": result.action,
        "status": result.status,
        "target_identity": result.target.to_dict(),
        "before_snapshot": result.before_snapshot,
        "after_snapshot": result.after_snapshot,
        "rollback_plan": result.rollback_plan,
        "provenance": result.provenance,
        "evidence_manifest_entries": result.evidence_manifest_entries,
        "report_section": result.report_section,
        "dashboard_trace": result.dashboard_trace,
    }


def _events_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "status": result.status,
        "target_identity": result.target.to_dict(),
        "capture": result.report_section.get("capture"),
        "frames": result.report_section.get("frames"),
        "lifecycle": result.report_section.get("lifecycle"),
        "present_targets": result.report_section.get("present_targets"),
        "events": result.report_section.get("events"),
        "provenance": {
            "precondition_hash": result.provenance.get("precondition_hash"),
            "capture": result.provenance.get("capture"),
        },
    }


def _sync_report(result: CapabilityExecutionResult) -> None:
    result.report_section.update(
        {
            "status": result.status,
            "target_identity": result.target.to_dict(),
            "before_snapshot": result.before_snapshot,
            "after_snapshot": result.after_snapshot,
            "rollback_plan": result.rollback_plan,
            "provenance": result.provenance,
            "artifacts": [item.to_dict() for item in result.artifacts],
            "evidence_manifest_entries": result.evidence_manifest_entries,
            "dashboard_trace": result.dashboard_trace,
        }
    )


def _read_only_rollback_plan(precondition_hash: Optional[str]) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "supported": False,
        "mode": "not_required",
        "reason": "passive graphics-present capture does not mutate the target",
        "completed": False,
        "restored": False,
        "target_state_modified": False,
        "precondition_hash": precondition_hash,
    }


def _empty_correlation() -> dict[str, Any]:
    return {
        "event_count": 0,
        "excluded_event_count": 0,
        "events": [],
        "apis": [],
        "swap_chain_count": 0,
        "streams": [],
        "frames": {
            "event_count": 0,
            "timed_frame_count": 0,
            "timing_status": "unavailable",
        },
        "warnings": [],
    }


def _plan_fingerprint(
    action: str, target: TargetIdentity, parameters: Mapping[str, Any]
) -> str:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "capability": _CAPABILITY,
        "provider": _PROVIDER,
        "action": action,
        "target": target.to_dict(),
        "parameters": _json_safe(parameters),
        "passive_policy": _PASSIVE_POLICY,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _module_declaration(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "path": value.get("path"),
        "api": value.get("api"),
        "required_exports": list(value.get("required_exports") or []),
        "any_of_exports": list(value.get("any_of_exports") or []),
        "read_only": True,
    }


def _artifact_destination(root: Path, relative_path: str) -> Path:
    path = Path(str(relative_path))
    if path.is_absolute():
        raise ValueError("artifact path must be relative to the collection directory")
    destination = (root / path).resolve()
    try:
        destination.relative_to(root)
    except ValueError as exc:
        raise ValueError("artifact path escapes the collection directory") from exc
    return destination


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(_json_safe(value), indent=2, sort_keys=True, ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def _bridge_descriptors_match(
    expected: Mapping[str, Any],
    observed: Mapping[str, Any],
) -> bool:
    expected_args = expected.get("args") if "args" in expected else ()
    observed_args = observed.get("args") if "args" in observed else ()
    if (
        isinstance(expected_args, (str, bytes, bytearray))
        or not isinstance(expected_args, Sequence)
        or isinstance(observed_args, (str, bytes, bytearray))
        or not isinstance(observed_args, Sequence)
    ):
        return False
    expected_timeout = expected.get("timeout_ms")
    observed_timeout = observed.get("timeout_ms")
    if type(expected_timeout) is not int or type(observed_timeout) is not int:
        return False
    expected_identity = _mapping(expected.get("executable_identity"))
    observed_identity = _mapping(observed.get("executable_identity"))
    return bool(
        expected.get("executable")
        and expected.get("executable") == observed.get("executable")
        and list(expected_args) == list(observed_args)
        and expected_timeout == observed_timeout
        and expected_identity.get("path")
        and expected_identity.get("path") == observed_identity.get("path")
        and expected_identity.get("sha256")
        and expected_identity.get("sha256") == observed_identity.get("sha256")
    )


def _bridge_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                _bridge_json_value(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"native bridge payload is not strict JSON: {exc}") from exc


def _bridge_json_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 32:
        raise ValueError("native bridge JSON nesting exceeds 32 levels")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value) > _MAX_FIELD_LENGTH * 16:
            raise ValueError("native bridge JSON string exceeds the length limit")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("native bridge JSON numbers must be finite")
        return value
    if isinstance(value, os.PathLike):
        return _bridge_json_value(os.fspath(value), depth=depth + 1)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if name in normalized:
                raise ValueError(f"native bridge JSON has a duplicate key: {name}")
            normalized[name] = _bridge_json_value(item, depth=depth + 1)
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [_bridge_json_value(item, depth=depth + 1) for item in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _bridge_json_value(to_dict(), depth=depth + 1)
    raise ValueError(
        f"native bridge JSON value has unsupported type {type(value).__name__}"
    )


def _parse_bridge_response(
    data: bytes,
    *,
    request: Mapping[str, Any],
    maximum: int,
) -> dict[str, Any]:
    if not data:
        raise ValueError("stdout is empty")
    if len(data) > maximum:
        raise ValueError(f"stdout exceeds {maximum} bytes")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("stdout is not valid UTF-8") from exc

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"response contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=strict_object,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"response contains non-finite number {token}")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"stdout must contain exactly one strict JSON object: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ValueError("response root must be an object")
    response = _bridge_json_value(decoded)
    expected = {
        "protocol": request.get("protocol"),
        "protocol_version": request.get("protocol_version"),
        "capability": request.get("capability"),
        "operation": request.get("operation"),
        "request_id": request.get("request_id"),
        "session_id": request.get("session_id"),
    }
    for name, value in expected.items():
        if response.get(name) != value:
            raise ValueError(
                f"response {name} does not match request: "
                f"expected {value!r}, got {response.get(name)!r}"
            )
    if (
        isinstance(response.get("protocol_version"), bool)
        or response.get("protocol_version") != NATIVE_BRIDGE_PROTOCOL_VERSION
    ):
        raise ValueError("response protocol_version is unsupported")
    bridge = _mapping(response.get("bridge"))
    if response.get("native_bridge") is not True and bridge.get("native") is not True:
        raise ValueError("response does not attest native_bridge=true")
    status = str(response.get("status") or "").strip().casefold()
    if status not in {"ok", "partial", "stopped", "unavailable", "failed"}:
        raise ValueError(f"response status is unsupported: {status!r}")
    response["status"] = status
    if status in {"ok", "partial", "stopped"} and not isinstance(
        response.get("result"), Mapping
    ):
        raise ValueError("successful response must contain an object result")
    errors = response.get("errors", [])
    if not isinstance(errors, list) or any(not isinstance(item, str) for item in errors):
        raise ValueError("response errors must be an array of strings")
    return response


def _bridge_response_error(response: Mapping[str, Any]) -> Optional[str]:
    if str(response.get("status")) in {"ok", "partial", "stopped"}:
        return None
    message = response.get("error")
    if isinstance(message, str) and message.strip():
        return message.strip()
    errors = response.get("errors")
    if isinstance(errors, list) and errors:
        return "; ".join(str(item) for item in errors)
    return f"native bridge reported {response.get('status') or 'failed'}"


def _resolve_bridge_executable(value: Any) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError("native bridge executable must be a filesystem path")
    text = os.fspath(value).strip()
    if not text or "\x00" in text:
        raise ValueError("native bridge executable path is empty or contains NUL")
    candidate = Path(text).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        return candidate.resolve()
    located = shutil.which(text)
    if located:
        return Path(located).resolve()
    return candidate.resolve()


def _bridge_arg(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("native bridge arguments must be non-empty strings without NUL")
    if len(value) > _MAX_FIELD_LENGTH:
        raise ValueError("native bridge argument exceeds the length limit")
    return value


def _bridge_operation(value: Any) -> str:
    operation = str(value or "").strip().casefold().replace("-", "_")
    if not operation or len(operation) > 64 or not re.fullmatch(
        r"[a-z][a-z0-9_]*", operation
    ):
        raise ValueError("native bridge operation is invalid")
    return operation


def _bridge_bounded_int(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bridge_string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        values: Sequence[Any] = [value]
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        values = value
    else:
        return set()
    return {str(item).strip().casefold() for item in values if str(item).strip()}


def _bridge_backend_name(value: Any) -> str:
    name = str(value or "").strip().casefold().replace("-", "").replace("_", "")
    aliases = {
        "d3d11": "d3d11",
        "direct3d11": "d3d11",
        "dx11": "d3d11",
        "d3d12": "d3d12",
        "direct3d12": "d3d12",
        "dx12": "d3d12",
        "opengl": "opengl",
        "opengl3": "opengl",
        "gl": "opengl",
        "vulkan": "vulkan",
        "vk": "vulkan",
    }
    return aliases.get(name, name)


def _bridge_decode_diagnostic(value: bytes) -> str:
    if not value:
        return ""
    data = value[:_MAX_DIAGNOSTIC_BYTES]
    suffix = "\n[truncated]" if len(value) > len(data) else ""
    return data.decode("utf-8", errors="replace") + suffix


def _capture_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return bytes(value)


def _sha256_bridge_json(value: Any) -> str:
    return hashlib.sha256(_bridge_json_bytes(value)).hexdigest()


def _sha256_bridge_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_executable(value: Any) -> Optional[Path]:
    if value is None:
        return None
    if not isinstance(value, (str, os.PathLike)):
        raise ValueError("PresentMon executable must be a filesystem path")
    text = os.fspath(value).strip()
    if not text or "\x00" in text:
        raise ValueError("PresentMon executable path is empty or contains NUL")
    candidate = Path(text).expanduser()
    if candidate.is_absolute() or candidate.parent != Path("."):
        try:
            return candidate.resolve()
        except OSError:
            return candidate.absolute()
    located = shutil.which(text)
    return Path(located).resolve() if located else candidate.resolve()


def _validate_fixed_arg(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("PresentMon base arguments must be non-empty strings without NUL")
    if len(value) > _MAX_FIELD_LENGTH:
        raise ValueError("PresentMon base argument exceeds the length limit")
    return value


def _read_capture_text(path: Path, *, maximum: int) -> str:
    size = path.stat().st_size
    if size > maximum:
        raise PresentMonRunnerError(
            f"PresentMon output exceeds the {maximum} byte capture limit"
        )
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise PresentMonRunnerError("PresentMon output is not valid UTF-8") from exc


def _read_text_bounded(path: Path, maximum: int) -> tuple[str, bool]:
    if not path.is_file():
        return "", False
    with path.open("rb") as handle:
        data = handle.read(maximum + 1)
    truncated = len(data) > maximum
    data = data[:maximum]
    return data.decode("utf-8", errors="replace"), truncated


def _capture_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        if len(value) > _MAX_CAPTURE_BYTES:
            raise PresentMonParseError("capture exceeds the parser byte limit")
        try:
            text = value.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise PresentMonParseError("capture is not valid UTF-8") from exc
    elif isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_CAPTURE_BYTES:
            raise PresentMonParseError("capture exceeds the parser byte limit")
        text = value.lstrip("\ufeff")
    else:
        raise PresentMonParseError("capture must be text or bytes")
    if "\x00" in text:
        raise PresentMonParseError("capture contains NUL bytes")
    return text


def _looks_like_capture(value: str) -> bool:
    text = value.lstrip()
    if not text:
        return False
    if text[0] in "[{":
        return True
    first = text.splitlines()[0]
    keys = {_canonical_key(item) for item in first.split(",")}
    return bool(keys.intersection(_KEY_ALIASES["pid"]))


def _detect_capture_format(value: str) -> str:
    text = value.lstrip("\ufeff \t\r\n")
    if not text:
        return "unknown"
    if text[0] in "[{":
        return "json"
    return "csv" if "," in text.splitlines()[0] else "unknown"


def _canonical_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value).strip().lower())


def _inspect_presentmon_identity(path: Optional[Path]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "verified": False,
        "path": str(path) if path else None,
        "filename_match": bool(
            path and _PRESENTMON_BASENAME_RE.fullmatch(path.name)
        ),
        "identity_basis": "windows_version_resource",
    }
    if path is None or not path.is_file():
        result.update(
            status="unavailable",
            reason="PresentMon executable file is unavailable",
        )
        return result
    if os.name != "nt" or sys.platform != "win32":
        result.update(
            status="unavailable",
            reason="PresentMon version-resource identity requires Windows",
        )
        return result
    try:
        from ctypes import wintypes

        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        version.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        version.GetFileVersionInfoW.restype = wintypes.BOOL
        version.VerQueryValueW.argtypes = [
            wintypes.LPCVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        version.VerQueryValueW.restype = wintypes.BOOL

        ignored = wintypes.DWORD(0)
        size = int(version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored)))
        if size <= 0:
            raise OSError(ctypes.get_last_error(), "version resource is unavailable")
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, buffer):
            raise ctypes.WinError(ctypes.get_last_error())

        def query(block: str) -> Optional[str]:
            address = ctypes.c_void_p()
            length = wintypes.UINT(0)
            if not version.VerQueryValueW(
                buffer,
                block,
                ctypes.byref(address),
                ctypes.byref(length),
            ):
                return None
            if not address.value or length.value <= 1:
                return None
            return ctypes.wstring_at(address.value, length.value).rstrip("\x00")

        translation_address = ctypes.c_void_p()
        translation_length = wintypes.UINT(0)
        translations: list[str] = []
        if version.VerQueryValueW(
            buffer,
            r"\VarFileInfo\Translation",
            ctypes.byref(translation_address),
            ctypes.byref(translation_length),
        ) and translation_address.value:
            words = ctypes.cast(
                translation_address,
                ctypes.POINTER(ctypes.c_ushort),
            )
            word_count = int(translation_length.value) // 2
            for index in range(0, word_count - 1, 2):
                translations.append(f"{words[index]:04x}{words[index + 1]:04x}")
        if not translations:
            translations.append("040904b0")

        fields: dict[str, str] = {}
        for field_name in (
            "ProductName",
            "FileDescription",
            "OriginalFilename",
            "CompanyName",
            "ProductVersion",
        ):
            for translation in translations:
                value = query(
                    f"\\StringFileInfo\\{translation}\\{field_name}"
                )
                if value:
                    fields[field_name] = value
                    break
        description = " ".join(
            fields.get(name, "")
            for name in ("ProductName", "FileDescription", "OriginalFilename")
        ).casefold()
        marker_match = "presentmon" in description
        verified = bool(result["filename_match"] and marker_match)
        result.update(
            {
                "status": "ok" if verified else "failed",
                "verified": verified,
                "version_fields": fields,
                "version_marker_match": marker_match,
                "reason": None
                if verified
                else "filename and version resource do not both identify PresentMon",
            }
        )
    except Exception as exc:  # noqa: BLE001 - identity failure is evidence
        result.update(
            status="unavailable",
            reason=f"unable to inspect PresentMon version resource: {exc}",
        )
    return _prune(result)


def _file_identity(path: Path, *, include_sha256: bool) -> dict[str, Any]:
    stat = path.stat()
    payload = {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }
    if include_sha256:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        payload["sha256"] = digest.hexdigest()
    return payload


def _normalize_export_names(value: Sequence[str], name: str) -> list[str]:
    if isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be a sequence of export names")
    if len(value) > 128:
        raise ValueError(f"{name} exceeds the 128 item limit")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{name} must contain only strings")
        text = item.strip()
        if not text or len(text) > 512 or "\x00" in text or any(
            ord(char) < 32 for char in text
        ):
            raise ValueError(f"{name} contains an invalid export name")
        result.append(text)
    return _deduplicate(result)


def _decode_export_name(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("ascii", errors="replace")
    return str(value)


def _validate_json_event_shape(value: Any, *, depth: int = 0) -> None:
    if depth > 6:
        raise PresentMonParseError("event JSON nesting exceeds the depth limit")
    if isinstance(value, str):
        if len(value) > _MAX_FIELD_LENGTH or "\x00" in value:
            raise PresentMonParseError("event contains an invalid or oversized string")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        if len(value) > 256:
            raise PresentMonParseError("event object contains too many fields")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256 or "\x00" in key:
                raise PresentMonParseError("event contains an invalid field name")
            _validate_json_event_shape(item, depth=depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if len(value) > 256:
            raise PresentMonParseError("event array contains too many values")
        for item in value:
            _validate_json_event_shape(item, depth=depth + 1)
        return
    raise PresentMonParseError("event contains a non-JSON value")


def _strict_int(
    value: Any,
    name: str,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    if isinstance(value, bool) or value in (None, ""):
        raise PresentMonParseError(f"{name} must be an integer")
    if isinstance(value, float) and not value.is_integer():
        raise PresentMonParseError(f"{name} must be an integer")
    try:
        parsed = int(str(value).strip(), 10) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PresentMonParseError(f"{name} must be an integer") from exc
    if minimum is not None and parsed < minimum:
        raise PresentMonParseError(f"{name} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise PresentMonParseError(f"{name} must be at most {maximum}")
    return parsed


def _optional_int(value: Any, name: str) -> Optional[int]:
    if value in (None, ""):
        return None
    return _strict_int(value, name)


def _optional_float(
    value: Any,
    name: str,
    *,
    minimum: Optional[float] = None,
) -> Optional[float]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise PresentMonParseError(f"{name} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise PresentMonParseError(f"{name} must be numeric") from exc
    if not math.isfinite(parsed):
        raise PresentMonParseError(f"{name} must be finite")
    if minimum is not None and parsed < minimum:
        raise PresentMonParseError(f"{name} must be at least {minimum}")
    return parsed


def _optional_bool(value: Any, name: str) -> Optional[bool]:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"0", "false", "no"}:
        return False
    if text in {"1", "true", "yes"}:
        return True
    raise PresentMonParseError(f"{name} must be boolean")


def _required_text(value: Any, name: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        if value is None:
            raise PresentMonParseError(f"{name} must be a non-empty string")
        value = str(value)
    text = value.strip()
    if not text or len(text) > maximum or "\x00" in text or any(
        ord(char) < 32 for char in text
    ):
        raise PresentMonParseError(f"{name} is invalid or exceeds its length limit")
    return text


def _optional_text(value: Any, name: str, *, maximum: int) -> Optional[str]:
    if value in (None, ""):
        return None
    return _required_text(value, name, maximum=maximum)


def _required_positive_int(value: Any, name: str, *, maximum: int) -> int:
    try:
        parsed = _strict_int(value, name, minimum=1, maximum=maximum)
    except PresentMonParseError as exc:
        raise PresentMonRunnerError(str(exc)) from exc
    return parsed


def _optional_positive_int(value: Any) -> Optional[int]:
    try:
        return _strict_int(value, "value", minimum=1, maximum=_MAX_PID)
    except PresentMonParseError:
        return None


def _optional_nonnegative_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return parsed if parsed >= 0 else None


def _parameter_int(
    value: Any,
    *,
    name: str,
    default: int,
    minimum: int,
    maximum: int,
    errors: list[str],
) -> int:
    if value is None:
        return default
    try:
        return _strict_int(value, name, minimum=minimum, maximum=maximum)
    except PresentMonParseError as exc:
        errors.append(str(exc))
        return default


def _parse_event_limit(value: Any) -> int:
    try:
        return _strict_int(value, "max_events", minimum=1, maximum=_MAX_EVENTS)
    except PresentMonParseError:
        raise


def _bounded_configuration(value: Any, *, default: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return parsed if 0 < parsed <= maximum else default


def _infer_module_api(path: str) -> str:
    name = Path(path).name.lower()
    if "vulkan" in name:
        return "Vulkan"
    if "opengl" in name or name in {"gdi32.dll", "gdi32full.dll"}:
        return "OpenGL"
    if "d3d9" in name:
        return "D3D9"
    if "dxgi" in name:
        return "DXGI"
    return "Unknown"


def _normalize_action(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(text, text)


def _safe_segment(value: Any) -> str:
    text = _SAFE_SEGMENT_RE.sub("-", str(value or "session")).strip(".-")
    return (text or "session")[:128]


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > 12:
        return "<depth-limit>"
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_safe(item, depth=depth + 1) for item in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _json_safe(to_dict(), depth=depth + 1)
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


def _deduplicate(values: Sequence[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(_json_safe(value), sort_keys=True, ensure_ascii=True)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _elapsed_ms(start_ns: int, end_ns: int) -> float:
    return max(0.0, (end_ns - start_ns) / 1_000_000.0)
