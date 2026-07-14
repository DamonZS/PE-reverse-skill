"""Auditable in-process Dear ImGui renderer project provider.

The provider generates a host-driven DLL project.  It deliberately does not
inject the DLL, resolve a Present address, or write a hook.  A caller must
supply an already-proven DXGI Present vtable resolution; its canonical hash is
bound into the generated plugin and all capability audit records.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tempfile
import threading
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
_CAPABILITY = "imgui_renderer_runtime"
_CAPABILITY_ALIASES = frozenset({_CAPABILITY, "imgui_renderer"})
_PROVIDER = "dear_imgui_inprocess_renderer"
_SUPPORTED_BACKENDS = frozenset({"d3d11", "d3d12", "opengl3", "vulkan"})
_IMPLEMENTED_BACKENDS = frozenset({"d3d11"})
_SUPPORTED_ARCHITECTURES = frozenset({"x86", "x64"})
_PLUGIN_NAME = "reverse_analyzer_imgui_renderer.dll"
_GENERATED_PROJECT_PATHS = (
    "CMakeLists.txt",
    "include/ra_imgui_renderer.h",
    "src/ra_imgui_build_config.h",
    "src/ra_imgui_renderer.cpp",
    "src/ra_imgui_renderer.def",
)
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_BYTES = 32 * 1024 * 1024
_MAX_PLUGIN_BYTES = 128 * 1024 * 1024
_MIN_TIMEOUT_SECONDS = 5
_MAX_TIMEOUT_SECONDS = 900
_DEFAULT_TIMEOUT_SECONDS = 180
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._-]+")

IMGUI_HOST_SCHEMA_VERSION = 1
IMGUI_HOST_LIFECYCLE_VERSION = 1
IMGUI_HOST_BRIDGE_PROTOCOL = "reverse-analyzer.native-bridge"
IMGUI_HOST_BRIDGE_PROTOCOL_VERSION = 1
IMGUI_HOST_BACKENDS = ("d3d11", "d3d12", "opengl", "vulkan")
IMGUI_HOST_LIFECYCLE = (
    "resolve_target",
    "install_hook",
    "renderer_init",
    "frame_evidence",
    "resize",
    "device_lost",
    "device_restore",
    "shutdown",
    "unload",
)
_HOST_TIMEOUT_MIN_MS = 100
_HOST_TIMEOUT_MAX_MS = 120_000
_HOST_RESULT_FLAGS = {
    "resolve_target": "target_resolved",
    "install_hook": "hook_installed",
    "renderer_init": "renderer_initialized",
    "frame_evidence": "frame_observed",
    "resize": "resize_observed",
    "device_lost": "device_lost",
    "device_restore": "device_restored",
    "shutdown": "renderer_shutdown",
    "unload": "module_unloaded",
}

REQUIRED_IMGUI_FILES = (
    "LICENSE.txt",
    "imconfig.h",
    "imgui.h",
    "imgui.cpp",
    "imgui_draw.cpp",
    "imgui_internal.h",
    "imgui_tables.cpp",
    "imgui_widgets.cpp",
    "imstb_rectpack.h",
    "imstb_textedit.h",
    "imstb_truetype.h",
    "backends/imgui_impl_dx11.h",
    "backends/imgui_impl_dx11.cpp",
    "backends/imgui_impl_win32.h",
    "backends/imgui_impl_win32.cpp",
)

EXPECTED_PLUGIN_EXPORTS = (
    "RAImGuiRenderer_AbiVersion",
    "RAImGuiRenderer_AfterResizeBuffers",
    "RAImGuiRenderer_BackendName",
    "RAImGuiRenderer_BeforeResizeBuffers",
    "RAImGuiRenderer_BindingHash",
    "RAImGuiRenderer_GetLastError",
    "RAImGuiRenderer_GetState",
    "RAImGuiRenderer_Initialize",
    "RAImGuiRenderer_NewFrame",
    "RAImGuiRenderer_OnDeviceRemoved",
    "RAImGuiRenderer_OnDeviceRestored",
    "RAImGuiRenderer_RenderDrawData",
    "RAImGuiRenderer_SetInputCapture",
    "RAImGuiRenderer_Shutdown",
    "RAImGuiRenderer_WndProcHandler",
)

_ALLOWED_PARAMETER_KEYS = frozenset(
    {
        "arch",
        "architecture",
        "backend",
        "build",
        "build_enabled",
        "build_timeout_seconds",
        "cmake_path",
        "compile",
        "cxx_compiler",
        "hook_target_resolution",
        "hook_target_resolution_artifact_sha256",
        "hook_target_resolution_path",
        "hook_target_resolution_sha256",
        "imgui_path",
        "imgui_root",
        "input_capture",
        "install_wndproc",
        "present_target",
        "resolution_hash",
        "target_resolution",
    }
)

_FORBIDDEN_IMPORT_MODULE_TOKENS = ("detours", "minhook", "frida")
_FORBIDDEN_IMPORT_SYMBOLS = frozenset(
    {
        "CreateRemoteThread",
        "NtWriteVirtualMemory",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
    }
)


class ImGuiRendererError(ValueError):
    """Base error for rejected renderer plans, projects, and binaries."""


class ImGuiPathBoundaryError(ImGuiRendererError):
    """Raised when an input or artifact path crosses an ownership boundary."""


class RendererPluginValidationError(ImGuiRendererError):
    """Raised when a built DLL does not satisfy the renderer ABI contract."""


class ImGuiHostContractError(ImGuiRendererError):
    """Raised when a host bridge violates the bound lifecycle contract."""


class ImGuiHostBridge(Protocol):
    test_double: bool

    def probe(
        self,
        *,
        required_operations: Sequence[str] = (),
        required_backends: Sequence[str] = (),
    ) -> Any: ...

    def invoke(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        session_id: str,
        timeout_ms: Optional[int] = None,
    ) -> Any: ...


class ImGuiHostOrchestrator:
    """Execute and attest an ImGui host lifecycle through a strict bridge."""

    def __init__(
        self,
        bridge: ImGuiHostBridge,
        *,
        target: TargetIdentity,
        session_id: str,
        precondition_hash: str,
        backend: str,
        timeout_ms: int = 5_000,
    ) -> None:
        if not callable(getattr(bridge, "probe", None)) or not callable(
            getattr(bridge, "invoke", None)
        ):
            raise ImGuiHostContractError("host bridge must implement probe and invoke")
        if target.kind != "process" or type(target.pid) is not int or target.pid <= 0:
            raise ImGuiHostContractError("host target must be a process with a positive PID")
        self.bridge = bridge
        self.target = target
        self.session_id = _normalize_session_id(session_id)
        if not isinstance(precondition_hash, str) or not _HEX_SHA256_RE.fullmatch(
            precondition_hash
        ):
            raise ImGuiHostContractError("precondition_hash must be lowercase SHA-256")
        self.precondition_hash = precondition_hash
        self.backend = _normalize_host_backend(backend)
        self.timeout_ms = _host_bounded_timeout(timeout_ms)
        self.target_identity_hash = _sha256_json(target.to_dict())

    def plan(self) -> dict[str, Any]:
        body = {
            "schema_version": IMGUI_HOST_SCHEMA_VERSION,
            "lifecycle_version": IMGUI_HOST_LIFECYCLE_VERSION,
            "session_id": self.session_id,
            "target_identity": self.target.to_dict(),
            "target_identity_hash": self.target_identity_hash,
            "precondition_hash": self.precondition_hash,
            "backend": self.backend,
            "timeout_ms": self.timeout_ms,
            "operations": list(IMGUI_HOST_LIFECYCLE),
        }
        return {**body, "plan_hash": _sha256_json(body)}

    def validate(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        _validate_host_plan(plan, self.plan())
        probe = self.bridge.probe(
            required_operations=IMGUI_HOST_LIFECYCLE,
            required_backends=(self.backend,),
        )
        if not getattr(probe, "ok", False):
            return {
                "ok": False,
                "status": "unavailable",
                "dependency_gated": True,
                "error": str(getattr(probe, "error", None) or "host bridge probe failed"),
                "probe": _host_call_dict(probe),
            }
        return {
            "ok": True,
            "status": "ok",
            "dependency_gated": False,
            "probe": _host_call_dict(probe),
        }

    def execute(self, plan: Mapping[str, Any]) -> dict[str, Any]:
        validation = self.validate(plan)
        if not validation["ok"]:
            return {
                "status": "unavailable",
                "validation": validation,
                "lifecycle": [],
                "evidence_class": "none",
                "live_verified": False,
            }
        lifecycle: list[dict[str, Any]] = []
        try:
            for sequence, operation in enumerate(IMGUI_HOST_LIFECYCLE, start=1):
                call = self.bridge.invoke(
                    operation,
                    {
                        "schema_version": IMGUI_HOST_SCHEMA_VERSION,
                        "lifecycle_version": IMGUI_HOST_LIFECYCLE_VERSION,
                        "sequence": sequence,
                        "target_identity": self.target.to_dict(),
                        "target_identity_hash": self.target_identity_hash,
                        "precondition_hash": self.precondition_hash,
                        "backend": self.backend,
                    },
                    session_id=self.session_id,
                    timeout_ms=self.timeout_ms,
                )
                lifecycle.append(self._validate_call(call, operation, sequence))
        except Exception as exc:
            partial = {
                "status": "failed",
                "error": str(exc),
                "validation": validation,
                "lifecycle": lifecycle,
                "evidence_class": _host_evidence_class(lifecycle),
                "live_verified": False,
            }
            partial["rollback"] = self.rollback(partial)
            return partial
        evidence_class = _host_evidence_class(lifecycle)
        return {
            "status": "ok",
            "validation": validation,
            "lifecycle": lifecycle,
            "evidence_class": evidence_class,
            "live_verified": evidence_class == "live_host_proof",
        }

    def rollback(self, execution: Mapping[str, Any]) -> dict[str, Any]:
        completed = {
            str(item.get("operation"))
            for item in execution.get("lifecycle", [])
            if isinstance(item, Mapping)
        }
        calls: list[dict[str, Any]] = []
        errors: list[str] = []
        for operation in ("shutdown", "unload"):
            if operation in completed:
                continue
            sequence = len(completed) + 1
            try:
                call = self.bridge.invoke(
                    operation,
                    {
                        "schema_version": IMGUI_HOST_SCHEMA_VERSION,
                        "lifecycle_version": IMGUI_HOST_LIFECYCLE_VERSION,
                        "sequence": sequence,
                        "target_identity_hash": self.target_identity_hash,
                        "precondition_hash": self.precondition_hash,
                        "backend": self.backend,
                        "rollback": True,
                    },
                    session_id=self.session_id,
                    timeout_ms=self.timeout_ms,
                )
                calls.append(self._validate_call(call, operation, sequence))
                completed.add(operation)
            except Exception as exc:
                errors.append(f"{operation}: {exc}")
        return {
            "ok": not errors,
            "status": "completed" if not errors else "failed",
            "calls": calls,
            "errors": errors,
            "live_verified": False,
        }

    def collect_artifacts(self, execution: Mapping[str, Any]) -> dict[str, Any]:
        lifecycle = [dict(item) for item in execution.get("lifecycle", []) if isinstance(item, Mapping)]
        frames = [item for item in lifecycle if item.get("operation") == "frame_evidence"]
        hooks = [item for item in lifecycle if item.get("operation") == "install_hook"]
        evidence_class = _host_evidence_class(lifecycle)
        return {
            "frame": {"evidence_class": evidence_class, "events": frames},
            "hook": {"evidence_class": evidence_class, "events": hooks},
            "lifecycle": {"evidence_class": evidence_class, "events": lifecycle},
            "provenance": {
                "schema_version": IMGUI_HOST_SCHEMA_VERSION,
                "lifecycle_version": IMGUI_HOST_LIFECYCLE_VERSION,
                "session_id": self.session_id,
                "target_identity_hash": self.target_identity_hash,
                "precondition_hash": self.precondition_hash,
                "backend": self.backend,
                "evidence_class": evidence_class,
                "live_verified": evidence_class == "live_host_proof",
            },
        }

    def _validate_call(self, call: Any, operation: str, sequence: int) -> dict[str, Any]:
        if getattr(call, "timed_out", False):
            raise ImGuiHostContractError(f"{operation} timed out")
        if not getattr(call, "ok", False):
            raise ImGuiHostContractError(
                f"{operation} failed: {getattr(call, 'error', None) or 'bridge failure'}"
            )
        response = getattr(call, "response", None)
        if not isinstance(response, Mapping):
            raise ImGuiHostContractError(f"{operation} response must be an object")
        result = _validate_host_response(
            response,
            operation=operation,
            sequence=sequence,
            session_id=self.session_id,
            target_identity_hash=self.target_identity_hash,
            precondition_hash=self.precondition_hash,
            backend=self.backend,
            test_double=getattr(self.bridge, "test_double", False) is True,
        )
        return {"operation": operation, **result, "bridge_call": _host_call_dict(call)}


class _ProductionBuildError(ImGuiRendererError):
    def __init__(self, message: str, evidence: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.evidence = _json_mapping(evidence)


class ImGuiBuildRunner(Protocol):
    """Test-only build boundary.

    Injected runners must set ``test_double = True``.  Their output is useful
    for boundary tests but can never establish a production-success result.
    """

    name: str
    test_double: bool

    def build(
        self,
        project_dir: Path,
        *,
        build_dir: Path,
        architecture: str,
        imgui_root: Path,
        timeout_seconds: int,
    ) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class RendererPluginInspection:
    architecture: str
    bits: int
    machine: int
    exports: tuple[str, ...]
    imports: dict[str, tuple[str, ...]]
    sha256: str
    file_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "architecture": self.architecture,
            "bits": self.bits,
            "machine": self.machine,
            "machine_hex": f"0x{self.machine:04X}",
            "exports": list(self.exports),
            "imports": {
                name: list(symbols) for name, symbols in sorted(self.imports.items())
            },
            "sha256": self.sha256,
            "file_size": self.file_size,
        }


@dataclass
class _ExecutionAssets:
    files: dict[str, bytes]
    project_hash: Optional[str]
    plugin_inspection: Optional[dict[str, Any]] = None
    bindings: dict[str, Any] = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)


@dataclass(frozen=True)
class _PESection:
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    @property
    def virtual_extent(self) -> int:
        return max(self.virtual_size, self.raw_size)


class _PEView:
    def __init__(self, data: bytes) -> None:
        if len(data) < 0x100 or data[:2] != b"MZ":
            raise RendererPluginValidationError("plugin is not a valid DOS/PE image")
        pe_offset = _unpack_from("<I", data, 0x3C, "DOS e_lfanew")[0]
        if pe_offset < 0x40 or pe_offset + 24 > len(data):
            raise RendererPluginValidationError("plugin has an invalid PE header offset")
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            raise RendererPluginValidationError("plugin does not contain a PE signature")
        (
            self.machine,
            section_count,
            _timestamp,
            _symbols,
            _symbol_count,
            optional_size,
            characteristics,
        ) = _unpack_from("<HHIIIHH", data, pe_offset + 4, "COFF header")
        if not characteristics & 0x2000:
            raise RendererPluginValidationError("PE image is not marked as a DLL")
        if section_count <= 0 or section_count > 96:
            raise RendererPluginValidationError("PE section count is outside the supported range")
        optional_offset = pe_offset + 24
        if optional_size < 96 or optional_offset + optional_size > len(data):
            raise RendererPluginValidationError("PE optional header is truncated")
        magic = _unpack_from("<H", data, optional_offset, "optional-header magic")[0]
        machine_map = {
            (0x014C, 0x10B): ("x86", 32, 96, 92),
            (0x8664, 0x20B): ("x64", 64, 112, 108),
        }
        identity = machine_map.get((self.machine, magic))
        if identity is None:
            raise RendererPluginValidationError(
                "plugin machine and optional-header architecture are unsupported or inconsistent"
            )
        self.architecture, self.bits, directory_offset, directory_count_offset = identity
        directory_count = _unpack_from(
            "<I", data, optional_offset + directory_count_offset, "data-directory count"
        )[0]
        directory_capacity = (optional_size - directory_offset) // 8
        if directory_count > directory_capacity:
            raise RendererPluginValidationError("PE data-directory count exceeds the optional header")
        self.size_of_headers = _unpack_from(
            "<I", data, optional_offset + 60, "SizeOfHeaders"
        )[0]
        self.directories: list[tuple[int, int]] = []
        for index in range(min(directory_count, 16)):
            self.directories.append(
                _unpack_from(
                    "<II",
                    data,
                    optional_offset + directory_offset + index * 8,
                    f"data directory {index}",
                )
            )
        section_offset = optional_offset + optional_size
        if section_offset + section_count * 40 > len(data):
            raise RendererPluginValidationError("PE section table is truncated")
        sections: list[_PESection] = []
        for index in range(section_count):
            offset = section_offset + index * 40
            virtual_size, virtual_address, raw_size, raw_offset = _unpack_from(
                "<IIII", data, offset + 8, f"section {index}"
            )
            if raw_size and (raw_offset > len(data) or raw_size > len(data) - raw_offset):
                raise RendererPluginValidationError(f"PE section {index} raw range is invalid")
            sections.append(
                _PESection(
                    virtual_address=virtual_address,
                    virtual_size=virtual_size,
                    raw_offset=raw_offset,
                    raw_size=raw_size,
                )
            )
        self.data = data
        self.sections = tuple(sections)

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def rva_to_offset(self, rva: int, size: int, label: str) -> int:
        if rva < 0 or size < 0:
            raise RendererPluginValidationError(f"{label} has a negative RVA or size")
        candidates: list[int] = []
        if rva < self.size_of_headers and rva + size <= min(self.size_of_headers, len(self.data)):
            candidates.append(rva)
        for section in self.sections:
            if (
                section.virtual_address <= rva
                and rva + size <= section.virtual_address + section.virtual_extent
            ):
                relative = rva - section.virtual_address
                if relative + size <= section.raw_size:
                    candidates.append(section.raw_offset + relative)
        if len(set(candidates)) != 1:
            detail = "ambiguous" if candidates else "not file-backed"
            raise RendererPluginValidationError(f"{label} RVA is {detail}")
        return candidates[0]

    def c_string(self, rva: int, label: str, maximum: int = 4096) -> str:
        offset = self.rva_to_offset(rva, 1, label)
        limit = min(len(self.data), offset + maximum)
        terminator = self.data.find(b"\x00", offset, limit)
        if terminator < 0:
            raise RendererPluginValidationError(f"{label} is not NUL terminated")
        try:
            return self.data[offset:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise RendererPluginValidationError(f"{label} is not ASCII") from exc


class ImGuiRendererProvider:
    """Generate and optionally build a D3D11 Dear ImGui renderer plugin."""

    capability_name = _CAPABILITY
    provider_name = _PROVIDER
    priority = 10
    supported_actions = ("generate", "build")

    def __init__(
        self,
        build_runner: Optional[ImGuiBuildRunner] = None,
        *,
        cmake_path: str | os.PathLike[str] | None = None,
        cxx_compiler: str | os.PathLike[str] | None = None,
        platform_name: Optional[str] = None,
        build_timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if build_runner is not None and getattr(build_runner, "test_double", None) is not True:
            raise ValueError("injected imgui build_runner must declare test_double=True")
        self.build_runner = build_runner
        self.cmake_path = str(cmake_path) if cmake_path is not None else None
        self.cxx_compiler = str(cxx_compiler) if cxx_compiler is not None else None
        self.platform_name = str(platform_name or os.sys.platform)
        self.build_timeout_seconds = _bounded_int(
            build_timeout_seconds,
            name="build_timeout_seconds",
            minimum=_MIN_TIMEOUT_SECONDS,
            maximum=_MAX_TIMEOUT_SECONDS,
        )
        self._assets: dict[
            int, tuple[CapabilityExecutionResult, _ExecutionAssets]
        ] = {}
        self._assets_lock = threading.RLock()

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        try:
            action = _normalize_action(request.action, request.params)
        except (TypeError, ValueError):
            return False
        return request.capability in _CAPABILITY_ALIASES and action in self.supported_actions

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        del context
        if request.capability not in _CAPABILITY_ALIASES:
            raise ValueError(f"unsupported ImGui renderer capability: {request.capability!r}")
        action = _normalize_action(request.action, request.params)
        if action not in self.supported_actions:
            raise ValueError(f"unsupported ImGui renderer action: {request.action!r}")
        session_id = _normalize_session_id(request.session_id)
        parameters, target = self._prepare_parameters(request, action=action)
        precondition_hash = _plan_precondition_hash(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            action=action,
            target=target,
            parameters=parameters,
        )
        target_hash = str(parameters.get("target_identity_hash") or "")
        resolution_hash = str(parameters.get("hook_target_resolution_hash") or "")
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=target,
            action=action,
            parameters=parameters,
            steps=[
                {
                    "step": "verify_present_target_evidence",
                    "status": "planned",
                    "writes_hook": False,
                    "resolves_address": False,
                },
                {"step": "verify_official_imgui_checkout", "status": "planned"},
                {"step": "generate_deterministic_plugin_project", "status": "planned"},
                {
                    "step": "optional_cmake_mingw_build",
                    "status": "planned" if parameters.get("build_requested") else "not_requested",
                },
                {
                    "step": "verify_pe_architecture_exports_imports",
                    "status": "planned" if parameters.get("build_requested") else "not_requested",
                },
                {"step": "collect_hashed_artifacts", "status": "planned"},
            ],
            precondition_hash=precondition_hash,
            before_snapshot={
                "schema_version": _SCHEMA_VERSION,
                "status": "planned",
                "session_id": session_id,
                "target_identity_hash": target_hash,
                "hook_target_resolution_hash": resolution_hash,
                "plugin_sha256": None,
                "target_process_modified": False,
                "hook_write_performed": False,
                "injection_performed": False,
            },
            rollback_plan={
                "schema_version": _SCHEMA_VERSION,
                "supported": True,
                "mode": "discard_provider_owned_build_workspace",
                "completed": False,
                "idempotent": True,
                "restore_original_wndproc": "plugin_shutdown_contract",
                "release_com_references": "plugin_shutdown_contract",
                "hook_rollback_owner": "host_hook_provider",
                "target_state_modified": False,
                "hook_write_performed": False,
                "injection_performed": False,
            },
            provenance={
                **_json_mapping(request.provenance),
                "schema_version": _SCHEMA_VERSION,
                "provider": self.provider_name,
                "session_id": session_id,
                "target_identity_hash": target_hash,
                "hook_target_resolution_hash": resolution_hash,
                "hook_target_resolution_artifact_sha256": parameters.get(
                    "hook_target_resolution_artifact_sha256"
                ),
                "hook_target_resolution_source": parameters.get(
                    "hook_target_resolution_source"
                ),
                "imgui_checkout_hash": _mapping(parameters.get("imgui_checkout")).get(
                    "checkout_hash"
                ),
                "host_responsibilities": _host_responsibilities(),
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
        validation, runtime = self._validate_plan(plan, context=context)
        errors = list(validation.errors)
        warnings = list(validation.warnings)
        build_requested = bool(plan.parameters.get("build_requested"))
        generated_files: dict[str, bytes] = {}
        project_hash: Optional[str] = None
        plugin_inspection: Optional[dict[str, Any]] = None
        build_evidence: dict[str, Any] = {
            "status": "not_requested" if not build_requested else "pending",
            "requested": build_requested,
            "production": False,
            "dependency_gated": False,
            "commands": [],
        }

        if not validation.ok:
            status = "failed"
        else:
            generated_files, project_hash = _render_project_files(plan)
            unavailable_reasons = list(runtime["unavailable_reasons"])
            if not build_requested:
                if unavailable_reasons:
                    status = "unavailable"
                    build_evidence.update(
                        {
                            "status": "dependency_gated",
                            "dependency_gated": True,
                            "reasons": unavailable_reasons,
                        }
                    )
                else:
                    status = "ok"
                    build_evidence.update(
                        {
                            "status": "not_requested",
                            "production": False,
                            "project_generated": True,
                        }
                    )
            elif unavailable_reasons:
                status = "unavailable"
                build_evidence.update(
                    {
                        "status": "dependency_gated",
                        "dependency_gated": True,
                        "reasons": unavailable_reasons,
                    }
                )
            elif runtime.get("test_runner") is not None:
                test_outcome = self._run_test_double_build(
                    runtime["test_runner"],
                    plan,
                    generated_files,
                )
                build_evidence.update(test_outcome)
                build_evidence["production"] = False
                build_evidence["dependency_gated"] = True
                status = "unavailable" if test_outcome.get("status") != "failed" else "failed"
                message = "test-double build runner cannot establish production success"
                if message not in errors:
                    errors.append(message)
            else:
                try:
                    plugin_bytes, production_evidence = self._run_production_build(
                        plan,
                        generated_files,
                        runtime,
                    )
                    generated_files[f"bin/{_PLUGIN_NAME}"] = plugin_bytes
                    plugin_inspection = dict(production_evidence["plugin"])
                    build_evidence.update(production_evidence)
                    build_evidence["status"] = "ok"
                    build_evidence["production"] = True
                    status = "ok"
                except _ProductionBuildError as exc:
                    status = "failed"
                    message = f"production renderer build failed: {exc}"
                    errors.append(message)
                    build_evidence.update(exc.evidence)
                    build_evidence.update(
                        {
                            "status": "failed",
                            "production": False,
                            "error": message,
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - build boundary becomes evidence
                    status = "failed"
                    message = f"production renderer build failed: {exc}"
                    errors.append(message)
                    build_evidence.update(
                        {
                            "status": "failed",
                            "production": False,
                            "error": message,
                        }
                    )

        metadata = _execution_metadata(
            plan,
            validation=validation,
            status=status,
            project_hash=project_hash,
            generated_files=generated_files,
            build_evidence=build_evidence,
            plugin_inspection=plugin_inspection,
            errors=errors,
            warnings=warnings,
        )
        metadata_bytes = _json_bytes(metadata)
        generated_files["renderer-metadata.json"] = metadata_bytes
        asset_key = _asset_key(plan.session_id, plan.precondition_hash)
        artifacts = _result_artifacts(
            plan.session_id,
            status=status,
            generated_files=generated_files,
        )
        manifest_entries = [_planned_manifest_entry(plan, item, status) for item in artifacts]
        rollback_plan = dict(plan.rollback_plan)
        rollback_plan.update(
            {
                "completed": True,
                "active": False,
                "asset_key": asset_key,
                "temporary_build_workspace_removed": True,
            }
        )
        plugin_sha256 = _mapping(plugin_inspection).get("sha256")
        after_snapshot = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "project_generated": bool(project_hash),
            "project_hash": project_hash,
            "generated_file_hashes": _file_hash_manifest(generated_files),
            "build": _json_value(build_evidence),
            "plugin": _json_mapping(plugin_inspection),
            "plugin_sha256": plugin_sha256,
            "target_identity_hash": plan.parameters.get("target_identity_hash"),
            "hook_target_resolution_hash": plan.parameters.get(
                "hook_target_resolution_hash"
            ),
            "hook_target_resolution_artifact_sha256": plan.parameters.get(
                "hook_target_resolution_artifact_sha256"
            ),
            "target_process_modified": False,
            "hook_write_performed": False,
            "injection_performed": False,
            "temporary_build_workspace_removed": True,
        }
        provenance = {
            **_json_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "target_identity_hash": plan.parameters.get("target_identity_hash"),
            "hook_target_resolution_hash": plan.parameters.get(
                "hook_target_resolution_hash"
            ),
            "hook_target_resolution": _json_mapping(
                plan.parameters.get("hook_target_resolution")
            ),
            "hook_target_resolution_artifact_sha256": plan.parameters.get(
                "hook_target_resolution_artifact_sha256"
            ),
            "hook_target_resolution_source": plan.parameters.get(
                "hook_target_resolution_source"
            ),
            "plugin_sha256": plugin_sha256,
            "project_hash": project_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "build": _json_value(build_evidence),
            "host_responsibilities": _host_responsibilities(),
        }
        report = {
            "schema_version": _SCHEMA_VERSION,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": plan.session_id,
            "action": plan.action,
            "status": status,
            "target_identity": plan.target.to_dict(),
            "target_identity_hash": plan.parameters.get("target_identity_hash"),
            "precondition_hash": plan.precondition_hash,
            "hook_target_resolution_hash": plan.parameters.get(
                "hook_target_resolution_hash"
            ),
            "hook_target_resolution_artifact_sha256": plan.parameters.get(
                "hook_target_resolution_artifact_sha256"
            ),
            "hook_target_resolution_source": plan.parameters.get(
                "hook_target_resolution_source"
            ),
            "plugin_sha256": plugin_sha256,
            "backend": plan.parameters.get("backend"),
            "architecture": plan.parameters.get("architecture"),
            "project_hash": project_hash,
            "lifecycle_contract": _lifecycle_contract(),
            "host_responsibilities": _host_responsibilities(),
            "build": _json_value(build_evidence),
            "plugin": _json_mapping(plugin_inspection),
            "validation": validation.to_dict(),
            "before_snapshot": dict(plan.before_snapshot),
            "after_snapshot": after_snapshot,
            "rollback_plan": rollback_plan,
            "artifacts": [item.to_dict() for item in artifacts],
            "evidence_manifest_entries": manifest_entries,
            "errors": _dedupe(errors),
            "warnings": _dedupe(warnings),
            "provenance": provenance,
        }
        dashboard_trace = [
            {
                "kind": "imgui_renderer_project",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": plan.session_id,
                "action": plan.action,
                "status": status,
                "backend": plan.parameters.get("backend"),
                "architecture": plan.parameters.get("architecture"),
                "production_build": bool(build_evidence.get("production")),
                "plugin_sha256": plugin_sha256,
                "hook_write_performed": False,
                "injection_performed": False,
            }
        ]
        report["dashboard_trace"] = dashboard_trace
        result = CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=dict(plan.before_snapshot),
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            artifacts=artifacts,
            evidence_manifest_entries=manifest_entries,
            report_section=report,
            dashboard_trace=dashboard_trace,
            provenance=provenance,
        )
        assets = _ExecutionAssets(
            files=dict(generated_files),
            project_hash=project_hash,
            plugin_inspection=plugin_inspection,
            bindings=_collection_bindings(result),
        )
        with self._assets_lock:
            self._assets[id(result)] = (result, assets)
        return result

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        if result.capability != self.capability_name or result.provider != self.provider_name:
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
        already_completed = bool(result.rollback_plan.get("completed"))
        result.rollback_plan.update(
            {
                "completed": True,
                "active": False,
                "target_state_modified": False,
                "hook_write_performed": False,
                "injection_performed": False,
            }
        )
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "already_completed" if already_completed else "completed",
            "completed": True,
            "idempotent": True,
            "restored": False,
            "target_state_modified": False,
            "hook_write_performed": False,
            "injection_performed": False,
            "temporary_build_workspace_removed": True,
            "plugin_runtime_shutdown_owner": "host",
            "host_must_call": "RAImGuiRenderer_Shutdown before unloading the DLL",
            "hook_rollback_owner": "host_hook_provider",
        }
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.report_section["rollback"] = details
        result.dashboard_trace.append(
            {
                "kind": "imgui_renderer_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": details["status"],
                "target_state_modified": False,
            }
        )
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=True,
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
        if result.capability != self.capability_name or result.provider != self.provider_name:
            raise ValueError("execution result does not belong to ImGui renderer provider")
        root = _strict_collection_root(out_dir)
        with self._assets_lock:
            asset_entry = self._assets.get(id(result))
        if asset_entry is None or asset_entry[0] is not result:
            raise ValueError("renderer execution assets are unavailable for collection")
        assets = asset_entry[1]

        artifacts = list(result.artifacts)
        destinations: dict[str, Path] = {}
        for artifact in artifacts:
            destinations[artifact.path] = _artifact_destination(root, artifact.path)
        if len(destinations) != len(artifacts):
            raise ValueError("renderer artifact set contains duplicate paths")
        manifest_artifacts = [item for item in artifacts if item.kind == "imgui-renderer-manifest"]
        if len(manifest_artifacts) != 1:
            raise ValueError("renderer artifact set must contain exactly one manifest")
        audit_artifacts = [item for item in artifacts if item.kind == "imgui-renderer-audit"]
        if len(audit_artifacts) != 1:
            raise ValueError("renderer artifact set must contain exactly one audit record")
        manifest_artifact = manifest_artifacts[0]
        base_prefix = _artifact_prefix(result.session_id)
        expected_paths = {
            *(f"{base_prefix}/{relative}" for relative in assets.files),
            f"{base_prefix}/renderer-audit.json",
            f"{base_prefix}/artifact-manifest.json",
        }
        if set(destinations) != expected_paths:
            raise ValueError("renderer artifact set no longer matches the executed project")
        expected_kinds = {
            item.path: item.kind
            for item in _result_artifacts(
                result.session_id,
                status=result.status,
                generated_files=assets.files,
            )
        }
        actual_kinds = {item.path: item.kind for item in artifacts}
        if actual_kinds != expected_kinds:
            raise ValueError("renderer artifact roles changed before collection")

        if _collection_bindings(result) != assets.bindings:
            raise ValueError("renderer execution bindings changed before collection")

        for artifact in artifacts:
            if artifact.kind in {"imgui-renderer-audit", "imgui-renderer-manifest"}:
                continue
            relative = _project_relative_path(base_prefix, artifact.path)
            encoded = assets.files.get(relative)
            if encoded is None:
                raise ValueError(f"renderer artifact content is unavailable: {artifact.path}")
            actual_hash = hashlib.sha256(encoded).hexdigest()
            if artifact.metadata.get("sha256") != actual_hash:
                raise ValueError(f"renderer artifact hash changed before collection: {artifact.path}")
            if artifact.metadata.get("size") != len(encoded):
                raise ValueError(f"renderer artifact size changed before collection: {artifact.path}")

        target_hash = result.provenance.get("target_identity_hash")
        if target_hash != _sha256_json(result.target.to_dict()):
            raise ValueError("renderer target identity hash changed before collection")
        architecture = str(assets.bindings.get("architecture") or "")
        target_errors = _validate_planned_target(result.target, architecture)
        if target_errors:
            raise ValueError(
                "renderer target changed before collection: " + "; ".join(target_errors)
            )
        resolution = _mapping(result.provenance.get("hook_target_resolution"))
        resolution_hash = result.provenance.get("hook_target_resolution_hash")
        if resolution and resolution_hash != _sha256_json(resolution):
            raise ValueError("renderer hook target resolution hash changed before collection")
        if not resolution and resolution_hash is not None:
            raise ValueError("renderer result records a resolution hash without evidence")
        resolution_errors = _validate_present_resolution(
            resolution,
            architecture,
            str(assets.bindings.get("backend") or ""),
        )
        resolution_errors.extend(
            _revalidate_resolution_artifact(
                {
                    "hook_target_resolution": resolution,
                    "hook_target_resolution_hash": resolution_hash,
                    "hook_target_resolution_artifact_sha256": result.provenance.get(
                        "hook_target_resolution_artifact_sha256"
                    ),
                    "hook_target_resolution_source": result.provenance.get(
                        "hook_target_resolution_source"
                    ),
                }
            )
        )
        if resolution_errors:
            raise ValueError(
                "renderer hook target evidence changed before collection: "
                + "; ".join(_dedupe(resolution_errors))
            )

        recorded_project_hash = result.provenance.get("project_hash")
        if recorded_project_hash != assets.project_hash:
            raise ValueError("renderer project hash changed before collection")
        if assets.project_hash is not None:
            project_files = {
                relative: assets.files[relative]
                for relative in _GENERATED_PROJECT_PATHS
                if relative in assets.files
            }
            if set(project_files) != set(_GENERATED_PROJECT_PATHS):
                raise ValueError("renderer project source set is incomplete")
            if _sha256_json(_file_hash_manifest(project_files)) != assets.project_hash:
                raise ValueError("renderer project content changed before collection")

        plugin_relative = f"bin/{_PLUGIN_NAME}"
        plugin_bytes = assets.files.get(plugin_relative)
        recorded_plugin_hash = result.provenance.get("plugin_sha256")
        if plugin_bytes is None:
            if recorded_plugin_hash is not None:
                raise ValueError("renderer result records a plugin hash without plugin bytes")
        else:
            actual_plugin_hash = hashlib.sha256(plugin_bytes).hexdigest()
            if recorded_plugin_hash != actual_plugin_hash:
                raise ValueError("renderer plugin hash changed before collection")
            if result.after_snapshot.get("plugin_sha256") != actual_plugin_hash:
                raise ValueError("renderer after-snapshot plugin hash is inconsistent")

        with assets.lock:
            for artifact in artifacts:
                if artifact is manifest_artifact or artifact is audit_artifacts[0]:
                    continue
                relative = _project_relative_path(base_prefix, artifact.path)
                if relative not in assets.files:
                    raise ValueError(
                        f"renderer artifact content is unavailable: {artifact.path}"
                    )
            materialized: dict[str, dict[str, Any]] = {}
            for artifact in artifacts:
                if artifact is manifest_artifact:
                    continue
                relative = _project_relative_path(base_prefix, artifact.path)
                if artifact.kind == "imgui-renderer-audit":
                    encoded = _json_bytes(_audit_payload(result))
                else:
                    encoded = assets.files.get(relative)
                    if encoded is None:
                        raise ValueError(f"renderer artifact content is unavailable: {artifact.path}")
                _atomic_write(destinations[artifact.path], encoded)
                materialized[artifact.path] = {
                    "path": artifact.path,
                    "kind": artifact.kind,
                    "status": result.status,
                    "materialized": True,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                    "size": len(encoded),
                }

            manifest_payload = {
                "schema_version": _SCHEMA_VERSION,
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "status": result.status,
                "target_identity": result.target.to_dict(),
                "target_identity_hash": result.provenance.get("target_identity_hash"),
                "precondition_hash": result.provenance.get("precondition_hash"),
                "hook_target_resolution_hash": result.provenance.get(
                    "hook_target_resolution_hash"
                ),
                "hook_target_resolution_artifact_sha256": result.provenance.get(
                    "hook_target_resolution_artifact_sha256"
                ),
                "plugin_sha256": result.provenance.get("plugin_sha256"),
                "project_hash": result.provenance.get("project_hash"),
                "artifacts": [
                    materialized[item.path]
                    for item in artifacts
                    if item is not manifest_artifact
                ],
                "manifest": {
                    "path": manifest_artifact.path,
                    "kind": manifest_artifact.kind,
                    "sha256": None,
                    "self_hash_excluded": True,
                },
            }
            manifest_bytes = _json_bytes(manifest_payload)
            _atomic_write(destinations[manifest_artifact.path], manifest_bytes)
            materialized[manifest_artifact.path] = {
                "path": manifest_artifact.path,
                "kind": manifest_artifact.kind,
                "status": result.status,
                "materialized": True,
                "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "size": len(manifest_bytes),
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
            entry = _manifest_entry(result, artifact)
            entry.update(record)
            manifest_entries.append(entry)
        result.artifacts = artifacts
        result.evidence_manifest_entries = manifest_entries
        result.report_section["artifacts"] = [item.to_dict() for item in artifacts]
        result.report_section["evidence_manifest_entries"] = manifest_entries
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _prepare_parameters(
        self,
        request: CapabilityRequest,
        *,
        action: str,
    ) -> tuple[dict[str, Any], TargetIdentity]:
        source = _json_mapping(request.params)
        errors: list[str] = []
        unknown = sorted(str(key) for key in source if str(key) not in _ALLOWED_PARAMETER_KEYS)
        if unknown:
            errors.append("unsupported ImGui renderer parameters: " + ", ".join(unknown))

        architecture = _normalize_architecture(source.get("architecture", source.get("arch")))
        if architecture is None:
            errors.append("architecture must be explicitly x86 or x64")
            architecture = "unknown"
        backend = _normalize_backend(source.get("backend", "d3d11"))
        if backend is None:
            errors.append("backend must be one of: d3d11, d3d12, opengl3, vulkan")
            backend = "unknown"
        try:
            build_requested = _strict_bool(
                source.get(
                    "build",
                    source.get("build_enabled", source.get("compile", action == "build")),
                ),
                name="build",
            )
        except ValueError as exc:
            errors.append(str(exc))
            build_requested = action == "build"
        if action == "build":
            build_requested = True
        try:
            install_wndproc = _strict_bool(
                source.get("install_wndproc", False), name="install_wndproc"
            )
            input_capture = _strict_bool(
                source.get("input_capture", False), name="input_capture"
            )
        except ValueError as exc:
            errors.append(str(exc))
            install_wndproc = False
            input_capture = False
        if input_capture and not install_wndproc:
            errors.append("input_capture requires install_wndproc=true")
        try:
            timeout_seconds = _bounded_int(
                source.get("build_timeout_seconds", self.build_timeout_seconds),
                name="build_timeout_seconds",
                minimum=_MIN_TIMEOUT_SECONDS,
                maximum=_MAX_TIMEOUT_SECONDS,
            )
        except ValueError as exc:
            errors.append(str(exc))
            timeout_seconds = self.build_timeout_seconds

        target, target_errors = _normalize_target(request.target, architecture)
        errors.extend(target_errors)
        target_hash = _sha256_json(target.to_dict())
        resolution, resolution_meta, resolution_errors = _load_resolution_evidence(source)
        errors.extend(resolution_errors)
        if resolution:
            errors.extend(_validate_present_resolution(resolution, architecture, backend))
        try:
            resolution_hash = _sha256_json(resolution) if resolution else None
        except (TypeError, ValueError):
            errors.append("hook target resolution must contain finite JSON values")
            resolution = {}
            resolution_hash = None
        supplied_resolution_hash = resolution_meta.get("expected_resolution_sha256")
        if supplied_resolution_hash and resolution_hash != supplied_resolution_hash:
            errors.append("hook target resolution hash does not match supplied evidence")

        imgui_value = source.get("imgui_root", source.get("imgui_path"))
        imgui_checkout = _inspect_imgui_checkout(imgui_value)
        cmake_value = source.get("cmake_path", self.cmake_path)
        cxx_value = source.get("cxx_compiler", self.cxx_compiler)
        toolchain = _probe_toolchain(
            cmake_value,
            cxx_value,
            architecture=architecture,
            requested=build_requested,
        )
        parameters = {
            "schema_version": _SCHEMA_VERSION,
            "architecture": architecture,
            "backend": backend,
            "build_requested": build_requested,
            "build_timeout_seconds": timeout_seconds,
            "install_wndproc": install_wndproc,
            "input_capture": input_capture,
            "target_identity_hash": target_hash,
            "hook_target_resolution": resolution,
            "hook_target_resolution_hash": resolution_hash,
            "hook_target_resolution_artifact_sha256": resolution_meta.get(
                "artifact_sha256"
            ),
            "hook_target_resolution_source": resolution_meta.get("source"),
            "imgui_checkout": imgui_checkout,
            "toolchain": toolchain,
            "parameter_errors": _dedupe(errors),
            "plugin_name": _PLUGIN_NAME,
            "implemented_backends": sorted(_IMPLEMENTED_BACKENDS),
            "host_responsibilities": _host_responsibilities(),
            "lifecycle_contract": _lifecycle_contract(),
        }
        return parameters, target

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []
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
            elif unavailable:
                status = "unavailable"
                unavailable_reasons.append(message)
                warnings.append(message)
            elif warning:
                status = "warning"
                warnings.append(message)
            else:
                status = "failed"
                errors.append(message)
            checks.append(
                {
                    "name": name,
                    "status": status,
                    "ok": ok,
                    "message": message,
                    **_json_mapping(details),
                }
            )

        add_check(
            "provider_identity",
            plan.capability == self.capability_name and plan.provider == self.provider_name,
            "plan capability/provider does not belong to ImGui renderer provider",
            capability=plan.capability,
            provider=plan.provider,
        )
        add_check(
            "supported_action",
            plan.action in self.supported_actions,
            f"unsupported ImGui renderer action: {plan.action}",
        )
        parameter_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        add_check(
            "parameter_schema",
            not parameter_errors,
            "renderer parameters are valid" if not parameter_errors else "; ".join(parameter_errors),
            parameter_errors=parameter_errors,
        )
        architecture = str(plan.parameters.get("architecture") or "")
        target_errors = _validate_planned_target(plan.target, architecture)
        add_check(
            "target_identity",
            not target_errors,
            "target identity is architecture-bound" if not target_errors else "; ".join(target_errors),
            target_identity_hash=plan.parameters.get("target_identity_hash"),
        )
        resolution = _mapping(plan.parameters.get("hook_target_resolution"))
        resolution_errors = _validate_present_resolution(
            resolution,
            architecture,
            str(plan.parameters.get("backend") or ""),
        )
        resolution_artifact_errors = _revalidate_resolution_artifact(plan.parameters)
        add_check(
            "present_target_artifact",
            not resolution_artifact_errors,
            (
                "Present target evidence source and raw artifact hash are unchanged"
                if not resolution_artifact_errors
                else "; ".join(resolution_artifact_errors)
            ),
            source=plan.parameters.get("hook_target_resolution_source"),
            artifact_sha256=plan.parameters.get(
                "hook_target_resolution_artifact_sha256"
            ),
        )
        actual_resolution_hash = _sha256_json(resolution) if resolution else None
        planned_resolution_hash = plan.parameters.get("hook_target_resolution_hash")
        if actual_resolution_hash != planned_resolution_hash:
            resolution_errors.append("planned hook target resolution hash changed")
        add_check(
            "present_target_evidence",
            bool(resolution) and not resolution_errors,
            (
                "proven DXGI Present vtable evidence is bound to the plan"
                if resolution and not resolution_errors
                else "; ".join(resolution_errors or ["Present target evidence is required"])
            ),
            resolution_hash=planned_resolution_hash,
            method=resolution.get("method"),
            slot_address=resolution.get("slot_address"),
        )
        current_precondition = _plan_precondition_hash(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            action=plan.action,
            target=plan.target,
            parameters=plan.parameters,
        )
        add_check(
            "precondition_hash",
            bool(plan.precondition_hash and current_precondition == plan.precondition_hash),
            "renderer plan no longer matches its precondition hash",
            expected=plan.precondition_hash,
            actual=current_precondition,
        )

        test_runner = self._select_test_runner(context)
        build_requested = bool(plan.parameters.get("build_requested"))
        checkout = _mapping(plan.parameters.get("imgui_checkout"))
        checkout_status = str(checkout.get("status") or "unavailable")
        checkout_reason = str(checkout.get("reason") or "Dear ImGui checkout is unavailable")
        current_checkout = _inspect_imgui_checkout(checkout.get("root"))
        if checkout_status == "ok" and current_checkout.get("status") == "ok":
            if current_checkout.get("checkout_hash") != checkout.get("checkout_hash"):
                checkout_status = "failed"
                checkout_reason = "Dear ImGui checkout changed after planning"
        elif checkout_status == "ok":
            checkout_status = str(current_checkout.get("status") or "failed")
            checkout_reason = str(
                current_checkout.get("reason") or "Dear ImGui checkout is no longer usable"
            )
        add_check(
            "official_imgui_sources",
            checkout_status == "ok",
            "Dear ImGui source manifest, hashes, and API markers verified"
            if checkout_status == "ok"
            else checkout_reason,
            unavailable=checkout_status == "unavailable",
            checkout=_json_value(current_checkout if checkout_status == "ok" else checkout),
        )
        repository_origin = _mapping(current_checkout.get("repository_origin"))
        origin_status = str(repository_origin.get("status") or "unavailable")
        origin_required = build_requested and test_runner is None
        origin_ok = origin_status == "ok"
        origin_reason = str(
            repository_origin.get("reason")
            or "Dear ImGui upstream Git origin is not attested"
        )
        add_check(
            "official_imgui_origin",
            origin_ok,
            (
                "Dear ImGui Git origin and commit identify github.com/ocornut/imgui"
                if origin_ok
                else origin_reason
            ),
            unavailable=origin_required and origin_status == "unavailable",
            warning=not origin_required and not origin_ok,
            required_for_production_build=origin_required,
            repository_origin=repository_origin,
        )

        backend = str(plan.parameters.get("backend") or "")
        backend_known = backend in _SUPPORTED_BACKENDS
        backend_implemented = backend in _IMPLEMENTED_BACKENDS
        add_check(
            "backend_adapter",
            backend_known and backend_implemented,
            (
                f"{backend} renderer adapter is implemented"
                if backend_implemented
                else f"{backend or 'unknown'} renderer adapter is dependency-gated for future implementation"
            ),
            unavailable=backend_known and not backend_implemented,
        )

        runner_valid = test_runner is None or getattr(test_runner, "test_double", None) is True
        add_check(
            "build_runner_policy",
            runner_valid,
            (
                "internal production build path selected"
                if test_runner is None
                else "injected build runner is marked test_double and cannot establish production success"
            ),
            warning=test_runner is not None and runner_valid,
        )
        toolchain = _mapping(plan.parameters.get("toolchain"))
        current_toolchain = _probe_toolchain(
            _mapping(toolchain.get("cmake")).get("path"),
            _mapping(toolchain.get("cxx_compiler")).get("path"),
            build_program_value=_mapping(toolchain.get("build_program")).get("path"),
            architecture=architecture,
            requested=build_requested,
        )
        for key, check_name, label in (
            ("cmake", "cmake_dependency", "CMake"),
            ("cxx_compiler", "mingw_dependency", "MinGW C++ compiler"),
            ("build_program", "mingw_make_dependency", "MinGW make program"),
        ):
            planned = _mapping(toolchain.get(key))
            current = _mapping(current_toolchain.get(key))
            required = build_requested and test_runner is None
            planned_status = str(planned.get("status") or "unavailable")
            status = str(current.get("status") or planned.get("status") or "unavailable")
            reason = str(current.get("reason") or planned.get("reason") or f"{label} unavailable")
            if (
                planned_status == "ok"
                and status == "ok"
                and planned.get("sha256") != current.get("sha256")
            ):
                status = "failed"
                reason = f"{label} binary changed after planning"
            elif required and planned_status != "ok" and status == "ok":
                status = "failed"
                reason = f"{label} became available after planning; create a new plan"
            add_check(
                check_name,
                not required or status == "ok",
                f"{label} verified" if status == "ok" else reason,
                unavailable=required and status == "unavailable",
                warning=not required and status != "ok",
                dependency=current or planned,
                required=required,
            )

        return (
            CapabilityValidation(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=plan.session_id,
                ok=not errors,
                checks=checks,
                warnings=_dedupe(warnings),
                errors=_dedupe(errors),
            ),
            {
                "test_runner": test_runner,
                "toolchain": current_toolchain,
                "imgui_checkout": current_checkout,
                "unavailable_reasons": _dedupe(unavailable_reasons),
            },
        )

    def _select_test_runner(
        self,
        context: Optional[dict[str, Any]],
    ) -> Optional[ImGuiBuildRunner]:
        candidate = None
        if context:
            candidate = context.get("imgui_renderer_build_runner")
            if candidate is None:
                candidate = context.get("build_runner")
        if candidate is None:
            candidate = self.build_runner
        if candidate is not None and getattr(candidate, "test_double", None) is not True:
            return candidate
        return candidate

    def _run_test_double_build(
        self,
        runner: ImGuiBuildRunner,
        plan: CapabilityPlan,
        files: Mapping[str, bytes],
    ) -> dict[str, Any]:
        if getattr(runner, "test_double", None) is not True:
            return {
                "status": "failed",
                "runner": str(getattr(runner, "name", type(runner).__name__)),
                "error": "injected build runner is not marked test_double",
            }
        checkout_root = Path(str(_mapping(plan.parameters.get("imgui_checkout")).get("root")))
        try:
            with tempfile.TemporaryDirectory(prefix="ra-imgui-test-double-") as temporary:
                root = Path(temporary).resolve()
                project = root / "project"
                build = root / "build"
                _materialize_project(project, files)
                raw = runner.build(
                    project,
                    build_dir=build,
                    architecture=str(plan.parameters.get("architecture")),
                    imgui_root=checkout_root,
                    timeout_seconds=int(plan.parameters.get("build_timeout_seconds")),
                )
                outcome = _json_mapping(raw)
        except Exception as exc:  # noqa: BLE001 - explicit test boundary
            return {
                "status": "failed",
                "runner": str(getattr(runner, "name", type(runner).__name__)),
                "test_double": True,
                "error": str(exc),
            }
        return {
            "status": (
                "failed"
                if str(outcome.get("status") or "").strip().casefold()
                in {"error", "failed", "failure"}
                else "test_double"
            ),
            "runner": str(getattr(runner, "name", type(runner).__name__)),
            "test_double": True,
            "reported_outcome": outcome,
            "production": False,
            "dependency_gated": True,
        }

    def _run_production_build(
        self,
        plan: CapabilityPlan,
        files: Mapping[str, bytes],
        runtime: Mapping[str, Any],
    ) -> tuple[bytes, dict[str, Any]]:
        if runtime.get("test_runner") is not None:
            raise ImGuiRendererError("production build cannot use an injected runner")
        checkout_state = _mapping(runtime.get("imgui_checkout"))
        repository_origin = _mapping(checkout_state.get("repository_origin"))
        if repository_origin.get("status") != "ok":
            raise ImGuiRendererError(
                "production build requires an attested github.com/ocornut/imgui Git origin"
            )
        expected_files, expected_project_hash = _render_project_files(plan)
        if dict(files) != expected_files:
            raise ImGuiRendererError(
                "generated renderer project changed before the production build"
            )
        toolchain = _mapping(runtime.get("toolchain"))
        commands: list[dict[str, Any]] = []
        try:
            cmake = Path(str(_mapping(toolchain.get("cmake")).get("path"))).resolve()
            cxx = Path(str(_mapping(toolchain.get("cxx_compiler")).get("path"))).resolve()
            build_program = Path(
                str(_mapping(toolchain.get("build_program")).get("path"))
            ).resolve()
            imgui_root = Path(
                str(_mapping(runtime.get("imgui_checkout")).get("root"))
            ).resolve()
            architecture = str(plan.parameters.get("architecture"))
            timeout = int(plan.parameters.get("build_timeout_seconds"))
            with tempfile.TemporaryDirectory(prefix="ra-imgui-production-") as temporary:
                root = Path(temporary).resolve()
                project = root / "project"
                build = root / "build"
                _materialize_project(project, files)
                configure = [
                    str(cmake),
                    "-S",
                    str(project),
                    "-B",
                    str(build),
                    "-G",
                    "MinGW Makefiles",
                    "-DCMAKE_BUILD_TYPE=Release",
                    f"-DCMAKE_CXX_COMPILER={cxx}",
                    f"-DCMAKE_MAKE_PROGRAM={build_program}",
                    f"-DIMGUI_ROOT={imgui_root}",
                    f"-DRA_IMGUI_ARCHITECTURE={architecture}",
                ]
                build_command = [
                    str(cmake),
                    "--build",
                    str(build),
                    "--config",
                    "Release",
                    "--target",
                    "reverse_analyzer_imgui_renderer",
                    "--parallel",
                    "1",
                ]
                environment = _build_environment(cxx)
                for phase, command in (("configure", configure), ("build", build_command)):
                    record = _normalize_ephemeral_build_record(
                        _run_command(
                            command,
                            cwd=project,
                            timeout_seconds=timeout,
                            environment=environment,
                        ),
                        workspace=root,
                        project=project,
                        build=build,
                    )
                    record["phase"] = phase
                    commands.append(record)
                    if record["returncode"] != 0:
                        raise ImGuiRendererError(
                            f"CMake {phase} exited with code {record['returncode']}: "
                            f"{record.get('stderr') or record.get('stdout') or 'no diagnostic output'}"
                        )
                plugin_path = (build / "bin" / _PLUGIN_NAME).resolve()
                _require_within(build, plugin_path, label="built plugin")
                if not plugin_path.is_file():
                    raise ImGuiRendererError(
                        f"CMake did not produce the expected DLL: {plugin_path}"
                    )
                if plugin_path.stat().st_size > _MAX_PLUGIN_BYTES:
                    raise ImGuiRendererError("built renderer DLL exceeds the size limit")
                plugin_bytes = plugin_path.read_bytes()
                inspection = inspect_renderer_plugin_bytes(
                    plugin_bytes,
                    expected_architecture=architecture,
                    expected_exports=EXPECTED_PLUGIN_EXPORTS,
                    binding_hashes=(
                        str(plan.parameters.get("target_identity_hash")),
                        str(plan.parameters.get("hook_target_resolution_hash")),
                        str(plan.precondition_hash),
                    ),
                )
        except Exception as exc:  # noqa: BLE001 - preserve the complete build audit
            raise _ProductionBuildError(
                str(exc),
                {
                    "status": "failed",
                    "production": False,
                    "dependency_gated": False,
                    "runner": "internal_cmake_mingw_subprocess",
                    "shell": False,
                    "commands": commands,
                    "toolchain": toolchain,
                    "audit_path_placeholders": _build_audit_path_placeholders(),
                    "temporary_workspace_removed": True,
                },
            ) from exc
        return plugin_bytes, {
            "status": "ok",
            "production": True,
            "dependency_gated": False,
            "runner": "internal_cmake_mingw_subprocess",
            "shell": False,
            "commands": commands,
            "toolchain": toolchain,
            "audit_path_placeholders": _build_audit_path_placeholders(),
            "generated_project_sha256": expected_project_hash,
            "imgui_repository_origin": repository_origin,
            "plugin": inspection.to_dict(),
            "temporary_workspace_removed": True,
        }


def required_imgui_sources() -> tuple[str, ...]:
    """Return the immutable official-source checklist used by the provider."""

    return REQUIRED_IMGUI_FILES


def inspect_renderer_plugin(
    path: str | os.PathLike[str],
    *,
    expected_architecture: str,
    expected_exports: Sequence[str] = EXPECTED_PLUGIN_EXPORTS,
    binding_hashes: Sequence[str] = (),
) -> RendererPluginInspection:
    source = _strict_absolute_path(path, label="renderer plugin", must_exist=True, kind="file")
    if source.stat().st_size > _MAX_PLUGIN_BYTES:
        raise RendererPluginValidationError("renderer plugin exceeds the size limit")
    return inspect_renderer_plugin_bytes(
        source.read_bytes(),
        expected_architecture=expected_architecture,
        expected_exports=expected_exports,
        binding_hashes=binding_hashes,
    )


def inspect_renderer_plugin_bytes(
    data: bytes,
    *,
    expected_architecture: str,
    expected_exports: Sequence[str] = EXPECTED_PLUGIN_EXPORTS,
    binding_hashes: Sequence[str] = (),
) -> RendererPluginInspection:
    if not isinstance(data, bytes) or not data:
        raise RendererPluginValidationError("renderer plugin bytes are empty")
    if len(data) > _MAX_PLUGIN_BYTES:
        raise RendererPluginValidationError("renderer plugin exceeds the size limit")
    view = _PEView(data)
    normalized_architecture = _normalize_architecture(expected_architecture)
    if normalized_architecture is None:
        raise RendererPluginValidationError("expected plugin architecture must be x86 or x64")
    if view.architecture != normalized_architecture:
        raise RendererPluginValidationError(
            f"renderer plugin architecture is {view.architecture}; expected {normalized_architecture}"
        )
    exports = _parse_pe_export_names(view)
    expected = tuple(sorted(set(str(item) for item in expected_exports)))
    if exports != expected:
        missing = sorted(set(expected) - set(exports))
        unexpected = sorted(set(exports) - set(expected))
        raise RendererPluginValidationError(
            "renderer plugin exports do not match the C ABI contract; "
            f"missing={missing}, unexpected={unexpected}"
        )
    imports = _parse_pe_imports(view)
    imported_modules = {name.casefold() for name in imports}
    for required in ("kernel32.dll", "user32.dll"):
        if required not in imported_modules:
            raise RendererPluginValidationError(
                f"renderer plugin import table is missing {required}"
            )
    for module in imported_modules:
        if any(token in module for token in _FORBIDDEN_IMPORT_MODULE_TOKENS):
            raise RendererPluginValidationError(
                f"renderer plugin imports forbidden hook module {module}"
            )
    imported_symbols = {symbol for symbols in imports.values() for symbol in symbols}
    forbidden = sorted(imported_symbols & _FORBIDDEN_IMPORT_SYMBOLS)
    if forbidden:
        raise RendererPluginValidationError(
            "renderer plugin imports process-injection primitives: " + ", ".join(forbidden)
        )
    for value in binding_hashes:
        digest = str(value or "").strip().lower()
        if not _HEX_SHA256_RE.fullmatch(digest):
            raise RendererPluginValidationError("plugin binding hash is missing or malformed")
        if digest.encode("ascii") not in data:
            raise RendererPluginValidationError(
                "renderer plugin does not embed all plan/evidence binding hashes"
            )
    return RendererPluginInspection(
        architecture=view.architecture,
        bits=view.bits,
        machine=view.machine,
        exports=exports,
        imports=imports,
        sha256=hashlib.sha256(data).hexdigest(),
        file_size=len(data),
    )


def _prepare_resolution_mapping(value: Any) -> tuple[dict[str, Any], Optional[str]]:
    if not isinstance(value, Mapping):
        raise ImGuiRendererError("hook target resolution evidence must be an object")
    raw = _json_mapping(value)
    nested = raw.get("resolution")
    if nested is not None:
        if not isinstance(nested, Mapping):
            raise ImGuiRendererError("hook target resolution wrapper contains a non-object resolution")
        expected = raw.get("resolution_hash", raw.get("sha256"))
        return _json_mapping(nested), _normalize_optional_sha256(expected)
    expected = raw.pop("resolution_hash", None)
    return raw, _normalize_optional_sha256(expected)


def _load_resolution_evidence(
    params: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    errors: list[str] = []
    aliases = [
        key
        for key in ("hook_target_resolution", "present_target", "target_resolution")
        if params.get(key) is not None
    ]
    path_value = params.get("hook_target_resolution_path")
    if len(aliases) > 1 or (aliases and path_value is not None):
        return {}, {}, ["provide exactly one Present target evidence source"]
    expected_resolution = None
    expected_artifact = None
    try:
        generic_hash = _normalize_optional_sha256(
            params.get("hook_target_resolution_sha256")
        )
        expected_resolution = _normalize_optional_sha256(params.get("resolution_hash"))
        expected_artifact = _normalize_optional_sha256(
            params.get("hook_target_resolution_artifact_sha256")
        )
    except ValueError as exc:
        errors.append(str(exc))
        generic_hash = None
    if aliases:
        try:
            resolution, wrapped_expected = _prepare_resolution_mapping(params[aliases[0]])
            if expected_artifact:
                errors.append(
                    "hook_target_resolution_artifact_sha256 is only valid with a path source"
                )
            inline_expected = expected_resolution or generic_hash
            if expected_resolution and generic_hash and expected_resolution != generic_hash:
                errors.append("conflicting canonical hook target resolution hashes were supplied")
            if inline_expected and wrapped_expected and inline_expected != wrapped_expected:
                errors.append("conflicting hook target resolution hashes were supplied")
            expected_resolution = inline_expected or wrapped_expected
            return (
                resolution,
                {
                    "source": "inline",
                    "expected_resolution_sha256": expected_resolution,
                },
                errors,
            )
        except (ImGuiRendererError, TypeError, ValueError) as exc:
            errors.append(str(exc))
            return (
                {},
                {
                    "source": "inline",
                    "expected_resolution_sha256": expected_resolution or generic_hash,
                },
                errors,
            )
    if path_value is not None:
        try:
            path = _strict_absolute_path(
                path_value,
                label="hook target resolution artifact",
                must_exist=True,
                kind="file",
            )
            size = path.stat().st_size
            if size <= 0 or size > _MAX_JSON_BYTES:
                raise ImGuiRendererError("hook target resolution artifact size is invalid")
            encoded = path.read_bytes()
            artifact_sha = hashlib.sha256(encoded).hexdigest()
            if expected_artifact and generic_hash and expected_artifact != generic_hash:
                errors.append("conflicting hook target resolution artifact hashes were supplied")
            expected_artifact = expected_artifact or generic_hash
            if expected_artifact and expected_artifact != artifact_sha:
                errors.append("hook target resolution artifact SHA-256 does not match")
            payload = _strict_json_object(encoded, label="hook target resolution artifact")
            resolution, wrapped_expected = _prepare_resolution_mapping(payload)
            if expected_resolution and wrapped_expected and expected_resolution != wrapped_expected:
                errors.append("conflicting hook target resolution hashes were supplied")
            expected_resolution = expected_resolution or wrapped_expected
            return (
                resolution,
                {
                    "source": str(path),
                    "artifact_sha256": artifact_sha,
                    "expected_artifact_sha256": expected_artifact,
                    "expected_resolution_sha256": expected_resolution,
                },
                errors,
            )
        except (OSError, ImGuiRendererError, TypeError, ValueError) as exc:
            errors.append(str(exc))
            return (
                {},
                {
                    "source": str(path_value),
                    "expected_artifact_sha256": expected_artifact or generic_hash,
                    "expected_resolution_sha256": expected_resolution,
                },
                errors,
            )
    errors.append("proven DXGI Present target resolution evidence is required")
    return (
        {},
        {
            "source": None,
            "expected_resolution_sha256": expected_resolution or generic_hash,
        },
        errors,
    )


def _revalidate_resolution_artifact(parameters: Mapping[str, Any]) -> list[str]:
    source = parameters.get("hook_target_resolution_source")
    artifact_sha = parameters.get("hook_target_resolution_artifact_sha256")
    planned_resolution = _mapping(parameters.get("hook_target_resolution"))
    if source == "inline":
        return [] if artifact_sha is None else ["inline Present evidence records a raw artifact hash"]
    if source in (None, ""):
        return ["Present target evidence source is missing"]
    errors: list[str] = []
    try:
        expected_artifact_sha = _normalize_optional_sha256(artifact_sha)
        if expected_artifact_sha is None:
            raise ImGuiRendererError("path-based Present evidence lacks its raw artifact hash")
        path = _strict_absolute_path(
            source,
            label="hook target resolution artifact",
            must_exist=True,
            kind="file",
        )
        size = path.stat().st_size
        if size <= 0 or size > _MAX_JSON_BYTES:
            raise ImGuiRendererError("hook target resolution artifact size is invalid")
        encoded = path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != expected_artifact_sha:
            errors.append("hook target resolution artifact changed after planning")
        payload = _strict_json_object(encoded, label="hook target resolution artifact")
        current_resolution, wrapped_expected = _prepare_resolution_mapping(payload)
        current_hash = _sha256_json(current_resolution)
        if wrapped_expected and wrapped_expected != current_hash:
            errors.append("hook target resolution wrapper hash no longer matches")
        if current_hash != _sha256_json(planned_resolution):
            errors.append("hook target resolution artifact content changed after planning")
    except (OSError, ImGuiRendererError, TypeError, ValueError) as exc:
        errors.append(str(exc))
    return _dedupe(errors)


def _validate_present_resolution(
    resolution: Mapping[str, Any],
    architecture: str,
    backend: str,
) -> list[str]:
    errors: list[str] = []
    if not resolution:
        return ["Present target resolution evidence is required"]
    if resolution.get("schema_version") != _SCHEMA_VERSION:
        errors.append("Present target resolution schema_version must be 1")
    if str(resolution.get("status") or "").casefold() != "ok":
        errors.append("Present target resolution status must be ok")
    method = str(resolution.get("method") or "").casefold().replace("-", "_")
    if method not in {"vtable_slot", "com_vtable", "vtable"}:
        errors.append("Present target resolution must prove a COM vtable slot")
    symbol = str(resolution.get("symbol") or "").casefold()
    target = str(resolution.get("target") or "").casefold()
    if symbol != "present":
        errors.append("hook target evidence must identify IDXGISwapChain::Present")
    if target != "dxgi_present":
        errors.append("hook target evidence must identify the dxgi_present target")
    api = str(resolution.get("api") or "").casefold()
    if backend == "d3d11" and api not in {
        "direct3d",
        "dxgi",
        "d3d11",
        "direct3d11",
    }:
        errors.append("D3D11 renderer requires DXGI/D3D11 Present evidence")
    module = str(resolution.get("module") or "").replace("\\", "/").rsplit("/", 1)[-1]
    if backend == "d3d11" and module.casefold() != "dxgi.dll":
        errors.append("D3D11 Present evidence must resolve inside dxgi.dll")
    try:
        method_address = _positive_int(resolution.get("address"), "resolution.address")
        slot_address = _positive_int(resolution.get("slot_address"), "resolution.slot_address")
        pointer_limit = (1 << (32 if architecture == "x86" else 64)) - 1
        if method_address > pointer_limit or slot_address > pointer_limit:
            errors.append("Present evidence address exceeds the requested pointer width")
    except ValueError as exc:
        errors.append(str(exc))
        method_address = 0
        slot_address = 0
    source = _mapping(resolution.get("source"))
    if str(source.get("kind") or "") != "vtable_snapshot":
        errors.append("Present evidence source.kind must be vtable_snapshot")
    interface = str(source.get("interface") or "").casefold()
    if interface != "idxgiswapchain":
        errors.append("Present evidence source.interface must be IDXGISwapChain")
    source_architecture = _normalize_architecture(source.get("architecture"))
    if source_architecture is None or source_architecture != architecture:
        errors.append("Present evidence architecture does not match the requested plugin")
    try:
        pointer_size = _positive_int(source.get("pointer_size"), "source.pointer_size")
        expected_pointer_size = 4 if architecture == "x86" else 8
        if pointer_size != expected_pointer_size:
            errors.append("Present evidence pointer size does not match architecture")
        vtable_address = _positive_int(source.get("vtable_address"), "source.vtable_address")
        vtable_index = _non_negative_int(source.get("vtable_index"), "source.vtable_index")
        if backend == "d3d11" and vtable_index != 8:
            errors.append("IDXGISwapChain::Present must use vtable slot 8")
        pointer_limit = (1 << (expected_pointer_size * 8)) - 1
        if vtable_address > pointer_limit:
            errors.append("Present vtable address exceeds the evidence pointer width")
        if slot_address and slot_address != vtable_address + vtable_index * pointer_size:
            errors.append("Present slot address is inconsistent with the supplied vtable snapshot")
    except ValueError as exc:
        errors.append(str(exc))
    module_path_value = source.get("module_path")
    module_hash_value = source.get("module_sha256")
    if module_path_value is not None or module_hash_value is not None:
        try:
            if module_path_value is None or module_hash_value is None:
                raise ImGuiRendererError(
                    "Present module_path and module_sha256 must be supplied together"
                )
            module_path = _strict_absolute_path(
                module_path_value,
                label="Present evidence module",
                must_exist=True,
                kind="file",
            )
            module_size = module_path.stat().st_size
            if module_size <= 0 or module_size > _MAX_SOURCE_BYTES:
                raise ImGuiRendererError("Present evidence module has an invalid file size")
            expected_module_hash = _normalize_optional_sha256(module_hash_value)
            if module_path.name.casefold() != "dxgi.dll":
                errors.append("Present evidence module path must name dxgi.dll")
            if expected_module_hash != _sha256_file(module_path):
                errors.append("Present evidence module SHA-256 no longer matches")
        except (OSError, ImGuiRendererError, ValueError) as exc:
            errors.append(str(exc))
    proof = _mapping(resolution.get("executable_range"))
    if proof.get("status") != "ok" or proof.get("executable") is not True:
        errors.append("Present method lacks an executable-range proof")
    try:
        range_start = _positive_int(proof.get("range_start"), "executable_range.range_start")
        range_end = _positive_int(proof.get("range_end"), "executable_range.range_end")
        proof_address = _positive_int(proof.get("address"), "executable_range.address")
        proof_size = _positive_int(proof.get("size"), "executable_range.size")
        if (
            not (range_start <= method_address < range_end)
            or proof_address != method_address
            or proof_address + proof_size > range_end
        ):
            errors.append("Present address is outside or inconsistent with its executable proof")
    except ValueError as exc:
        errors.append(str(exc))
    confidence = resolution.get("confidence")
    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0.0 < float(confidence) <= 1.0
    ):
        errors.append("Present target resolution confidence must be in the range (0, 1]")
    ambiguity = _mapping(resolution.get("ambiguity"))
    if ambiguity.get("ambiguous") is not False:
        errors.append("Present target resolution is ambiguous")
    candidate_count = ambiguity.get("candidate_count")
    try:
        if _positive_int(candidate_count, "ambiguity.candidate_count") != 1:
            errors.append("Present target resolution must contain exactly one candidate")
    except ValueError as exc:
        errors.append(str(exc))
    if resolution.get("errors"):
        errors.append("Present target resolution contains resolver errors")
    return _dedupe(errors)


def _normalize_target(
    target: TargetIdentity,
    architecture: str,
) -> tuple[TargetIdentity, list[str]]:
    errors: list[str] = []
    if not isinstance(target, TargetIdentity):
        raise TypeError("renderer request target must be TargetIdentity")
    if target.kind != "process":
        errors.append("renderer target kind must be process")
    if isinstance(target.pid, bool) or not isinstance(target.pid, int) or target.pid <= 0:
        errors.append("renderer target PID must be a positive integer")
    supplied_sha = None
    try:
        supplied_sha = _normalize_optional_sha256(target.sha256)
    except ValueError as exc:
        errors.append(str(exc))
    normalized_path: Optional[str] = None
    observed_sha: Optional[str] = None
    metadata = _json_mapping(target.metadata)
    declared_architecture = _normalize_architecture(metadata.get("architecture"))
    if metadata.get("architecture") is not None and declared_architecture is None:
        errors.append("target metadata architecture must be x86 or x64")
    if declared_architecture and declared_architecture != architecture:
        errors.append("target metadata architecture conflicts with renderer architecture")
    if target.path:
        try:
            path = _strict_absolute_path(target.path, label="target executable", must_exist=True, kind="file")
            normalized_path = str(path)
            observed_sha = _sha256_file(path)
            if supplied_sha and supplied_sha != observed_sha:
                errors.append("target executable SHA-256 does not match TargetIdentity")
            observed_architecture = _inspect_pe_architecture(path.read_bytes())
            if observed_architecture != architecture:
                errors.append(
                    f"target executable architecture is {observed_architecture}; expected {architecture}"
                )
            metadata["verified_architecture"] = observed_architecture
        except (OSError, ImGuiRendererError, RendererPluginValidationError) as exc:
            errors.append(str(exc))
    metadata["architecture"] = architecture
    normalized = TargetIdentity(
        kind="process",
        path=normalized_path,
        pid=target.pid,
        sha256=observed_sha or supplied_sha,
        display_name=target.display_name,
        metadata=metadata,
    )
    return normalized, _dedupe(errors)


def _validate_planned_target(target: TargetIdentity, architecture: str) -> list[str]:
    errors: list[str] = []
    if target.kind != "process":
        errors.append("planned target kind is not process")
    if isinstance(target.pid, bool) or not isinstance(target.pid, int) or target.pid <= 0:
        errors.append("planned target PID is invalid")
    declared = _normalize_architecture(_mapping(target.metadata).get("architecture"))
    if declared != architecture:
        errors.append("planned target architecture no longer matches")
    if target.path:
        try:
            path = _strict_absolute_path(target.path, label="target executable", must_exist=True, kind="file")
            digest = _sha256_file(path)
            if target.sha256 != digest:
                errors.append("target executable changed after planning")
            observed = _inspect_pe_architecture(path.read_bytes())
            if observed != architecture:
                errors.append("target executable architecture changed after planning")
        except (OSError, ImGuiRendererError, RendererPluginValidationError) as exc:
            errors.append(str(exc))
    return _dedupe(errors)


def _inspect_imgui_checkout(value: Any) -> dict[str, Any]:
    if value in (None, ""):
        return {
            "status": "unavailable",
            "root": None,
            "reason": "official Dear ImGui checkout was not provided",
            "required_files": list(REQUIRED_IMGUI_FILES),
        }
    try:
        root = _strict_absolute_path(
            value,
            label="Dear ImGui checkout",
            must_exist=True,
            kind="directory",
        )
    except (OSError, ImGuiRendererError) as exc:
        message = str(exc)
        status = "unavailable" if "does not exist" in message else "failed"
        return {
            "status": status,
            "root": str(value),
            "reason": message,
            "required_files": list(REQUIRED_IMGUI_FILES),
        }
    files: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    try:
        for relative in REQUIRED_IMGUI_FILES:
            candidate = (root / Path(*PurePosixPath(relative).parts)).resolve()
            _require_within(root, candidate, label=f"Dear ImGui source {relative}")
            if not candidate.is_file():
                missing.append(relative)
                continue
            size = candidate.stat().st_size
            if size <= 0 or size > _MAX_SOURCE_BYTES:
                raise ImGuiRendererError(
                    f"Dear ImGui source {relative} has an invalid file size"
                )
            files[relative] = {
                "sha256": _sha256_file(candidate),
                "size": size,
            }
        if missing:
            return {
                "status": "unavailable",
                "root": str(root),
                "reason": "official Dear ImGui checkout is missing required files: "
                + ", ".join(missing),
                "missing_files": missing,
                "required_files": list(REQUIRED_IMGUI_FILES),
                "files": files,
            }
        marker_checks = {
            "LICENSE.txt": b"MIT License",
            "imgui.h": b"IMGUI_VERSION",
            "imgui.cpp": b"Dear ImGui",
            "backends/imgui_impl_win32.cpp": b"ImGui_ImplWin32_Init",
            "backends/imgui_impl_dx11.cpp": b"ImGui_ImplDX11_Init",
        }
        for relative, marker in marker_checks.items():
            candidate = root / Path(*PurePosixPath(relative).parts)
            if marker not in candidate.read_bytes():
                raise ImGuiRendererError(
                    f"Dear ImGui source {relative} lacks its official API marker"
                )
    except (OSError, ImGuiRendererError) as exc:
        return {
            "status": "failed",
            "root": str(root),
            "reason": str(exc),
            "required_files": list(REQUIRED_IMGUI_FILES),
            "files": files,
        }
    checkout_hash = _sha256_json({name: files[name] for name in sorted(files)})
    repository_origin = _inspect_imgui_repository_origin(root)
    return {
        "status": "ok",
        "root": str(root),
        "checkout_hash": checkout_hash,
        "required_files": list(REQUIRED_IMGUI_FILES),
        "files": files,
        "api_markers_verified": True,
        "repository_origin": repository_origin,
        "official_origin_attested": repository_origin.get("status") == "ok",
        "source_authenticity": (
            "upstream_git_origin_attested"
            if repository_origin.get("status") == "ok"
            else "unattested_source_manifest"
        ),
    }


def _inspect_imgui_repository_origin(root: Path) -> dict[str, Any]:
    git_metadata = root / ".git"
    if not git_metadata.exists():
        return {
            "status": "unavailable",
            "reason": "Dear ImGui source directory is not a Git checkout",
            "attestation_kind": "local_git_configuration",
        }
    git = shutil.which("git.exe") or shutil.which("git")
    if not git:
        return {
            "status": "unavailable",
            "reason": "Git is unavailable for Dear ImGui origin attestation",
            "attestation_kind": "local_git_configuration",
        }

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )

    def run(*arguments: str) -> str:
        completed = subprocess.run(
            [git, "-C", str(root), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            check=False,
            timeout=10,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if completed.returncode != 0:
            raise ImGuiRendererError(
                completed.stderr.strip()
                or completed.stdout.strip()
                or f"git {' '.join(arguments)} failed"
            )
        return completed.stdout.strip()

    try:
        top_level = Path(run("rev-parse", "--show-toplevel")).resolve()
        commit = run("rev-parse", "HEAD").casefold()
        origin_url = run("remote", "get-url", "origin")
        if top_level != root.resolve():
            raise ImGuiRendererError(
                "Dear ImGui root is not the Git checkout top-level directory"
            )
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
            raise ImGuiRendererError("Dear ImGui Git commit is malformed")
        normalized_origin = origin_url.strip().casefold().rstrip("/")
        upstream_match = bool(
            re.search(
                r"github\.com(?::|/)ocornut/imgui(?:\.git)?$",
                normalized_origin,
            )
        )
        if not upstream_match:
            raise ImGuiRendererError(
                "Dear ImGui origin does not name github.com/ocornut/imgui"
            )
        return {
            "status": "ok",
            "attestation_kind": "local_git_configuration",
            "origin_url": origin_url,
            "upstream": "github.com/ocornut/imgui",
            "upstream_match": True,
            "commit": commit,
            "checkout_top_level": str(top_level),
            "network_verified": False,
        }
    except (OSError, subprocess.SubprocessError, ImGuiRendererError) as exc:
        return {
            "status": "failed",
            "reason": str(exc),
            "attestation_kind": "local_git_configuration",
        }


def _probe_toolchain(
    cmake_value: Any,
    cxx_value: Any,
    *,
    build_program_value: Any = None,
    architecture: str,
    requested: bool,
) -> dict[str, Any]:
    cmake = _probe_executable(
        cmake_value,
        candidates=("cmake.exe", "cmake"),
        label="CMake",
        version_args=("--version",),
        marker="cmake version",
    )
    compiler_candidates = (
        ("i686-w64-mingw32-g++.exe", "i686-w64-mingw32-g++", "g++.exe", "g++")
        if architecture == "x86"
        else (
            "x86_64-w64-mingw32-g++.exe",
            "x86_64-w64-mingw32-g++",
            "g++.exe",
            "g++",
        )
    )
    cxx = _probe_executable(
        cxx_value,
        candidates=compiler_candidates,
        label="MinGW C++ compiler",
        version_args=("-dumpmachine",),
        marker="mingw",
    )
    if cxx.get("status") == "ok":
        machine = str(cxx.get("version_output") or "").strip().casefold()
        arch_ok = (
            architecture == "x64" and ("x86_64" in machine or "amd64" in machine)
        ) or (architecture == "x86" and re.search(r"(^|[-_])i[3-6]86($|[-_])", machine))
        if not arch_ok:
            cxx = {
                **cxx,
                "status": "failed",
                "reason": f"MinGW target {machine or 'unknown'} does not match {architecture}",
            }
    make_value: Any = build_program_value
    if make_value in (None, "") and cxx.get("status") == "ok" and cxx.get("path"):
        adjacent_make = Path(str(cxx["path"])).parent / "mingw32-make.exe"
        if adjacent_make.is_file():
            make_value = adjacent_make
    build_program = _probe_executable(
        make_value,
        candidates=("mingw32-make.exe", "mingw32-make"),
        label="MinGW make program",
        version_args=("--version",),
        marker="GNU Make",
    )
    return {
        "requested": requested,
        "generator": "MinGW Makefiles",
        "cmake": cmake,
        "cxx_compiler": cxx,
        "build_program": build_program,
    }


def _probe_executable(
    value: Any,
    *,
    candidates: Sequence[str],
    label: str,
    version_args: Sequence[str],
    marker: str,
) -> dict[str, Any]:
    try:
        if value not in (None, ""):
            path = _strict_absolute_path(value, label=label, must_exist=True, kind="file")
            source = "explicit"
        else:
            discovered = next((shutil.which(name) for name in candidates if shutil.which(name)), None)
            if not discovered:
                return {
                    "status": "unavailable",
                    "path": None,
                    "reason": f"{label} executable was not provided or found on PATH",
                }
            path = Path(discovered).resolve()
            source = "PATH"
        completed = subprocess.run(
            [str(path), *version_args],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        output = (completed.stdout or completed.stderr or "").strip()[:4096]
        if completed.returncode != 0 or marker.casefold() not in output.casefold():
            return {
                "status": "failed",
                "path": str(path),
                "reason": f"{label} identity probe failed",
                "returncode": completed.returncode,
                "version_output": output,
                "sha256": _sha256_file(path),
            }
        return {
            "status": "ok",
            "path": str(path),
            "source": source,
            "sha256": _sha256_file(path),
            "size": path.stat().st_size,
            "version_output": output,
        }
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "path": str(value) if value is not None else None,
            "reason": f"{label} executable does not exist",
        }
    except (OSError, subprocess.SubprocessError, ImGuiRendererError) as exc:
        message = str(exc)
        unavailable = "does not exist" in message
        return {
            "status": "unavailable" if unavailable else "failed",
            "path": str(value) if value is not None else None,
            "reason": f"{label} probe failed: {message}",
        }


def _render_project_files(plan: CapabilityPlan) -> tuple[dict[str, bytes], str]:
    target_hash = str(plan.parameters.get("target_identity_hash") or "")
    resolution_hash = str(plan.parameters.get("hook_target_resolution_hash") or "")
    precondition_hash = str(plan.precondition_hash or "")
    for name, value in (
        ("target identity", target_hash),
        ("hook target resolution", resolution_hash),
        ("precondition", precondition_hash),
    ):
        if not _HEX_SHA256_RE.fullmatch(value):
            raise ImGuiRendererError(f"{name} hash is missing or malformed")
    files = {
        "CMakeLists.txt": _CMAKE_TEMPLATE.encode("ascii"),
        "include/ra_imgui_renderer.h": _HEADER_TEMPLATE.encode("ascii"),
        "src/ra_imgui_renderer.def": _DEF_TEMPLATE.encode("ascii"),
        "src/ra_imgui_build_config.h": _BUILD_CONFIG_TEMPLATE.replace(
            "@TARGET_IDENTITY_HASH@", target_hash
        )
        .replace("@HOOK_TARGET_RESOLUTION_HASH@", resolution_hash)
        .replace("@PRECONDITION_HASH@", precondition_hash)
        .encode("ascii"),
        "src/ra_imgui_renderer.cpp": _SOURCE_TEMPLATE.encode("ascii"),
    }
    project_hash = _sha256_json(_file_hash_manifest(files))
    return files, project_hash


def _execution_metadata(
    plan: CapabilityPlan,
    *,
    validation: CapabilityValidation,
    status: str,
    project_hash: Optional[str],
    generated_files: Mapping[str, bytes],
    build_evidence: Mapping[str, Any],
    plugin_inspection: Optional[Mapping[str, Any]],
    errors: Sequence[str],
    warnings: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": plan.capability,
        "provider": plan.provider,
        "session_id": plan.session_id,
        "action": plan.action,
        "status": status,
        "backend": plan.parameters.get("backend"),
        "implemented_backends": sorted(_IMPLEMENTED_BACKENDS),
        "extension_backends": sorted(_SUPPORTED_BACKENDS - _IMPLEMENTED_BACKENDS),
        "architecture": plan.parameters.get("architecture"),
        "target_identity": plan.target.to_dict(),
        "target_identity_hash": plan.parameters.get("target_identity_hash"),
        "precondition_hash": plan.precondition_hash,
        "hook_target_resolution": plan.parameters.get("hook_target_resolution"),
        "hook_target_resolution_hash": plan.parameters.get(
            "hook_target_resolution_hash"
        ),
        "hook_target_resolution_artifact_sha256": plan.parameters.get(
            "hook_target_resolution_artifact_sha256"
        ),
        "hook_target_resolution_source": plan.parameters.get(
            "hook_target_resolution_source"
        ),
        "imgui_checkout": plan.parameters.get("imgui_checkout"),
        "project_hash": project_hash,
        "generated_file_hashes": _file_hash_manifest(generated_files),
        "build": _json_value(build_evidence),
        "plugin": _json_mapping(plugin_inspection),
        "lifecycle_contract": _lifecycle_contract(),
        "host_responsibilities": _host_responsibilities(),
        "validation": validation.to_dict(),
        "errors": _dedupe(errors),
        "warnings": _dedupe(warnings),
        "deterministic": True,
        "timestamps_embedded": False,
    }


def _normalize_host_backend(value: Any) -> str:
    backend = str(value or "").strip().casefold().replace("_", "").replace("-", "")
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
    normalized = aliases.get(backend)
    if normalized not in IMGUI_HOST_BACKENDS:
        raise ImGuiHostContractError(
            "host backend must be one of d3d11, d3d12, opengl, vulkan"
        )
    return normalized


def _host_bounded_timeout(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ImGuiHostContractError("host timeout_ms must be an integer")
    if value < _HOST_TIMEOUT_MIN_MS or value > _HOST_TIMEOUT_MAX_MS:
        raise ImGuiHostContractError(
            f"host timeout_ms must be between {_HOST_TIMEOUT_MIN_MS} and {_HOST_TIMEOUT_MAX_MS}"
        )
    return value


def _validate_host_plan(observed: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if not isinstance(observed, Mapping):
        raise ImGuiHostContractError("host plan must be an object")
    if set(observed) != set(expected):
        raise ImGuiHostContractError("host plan schema contains missing or unknown fields")
    if type(observed.get("schema_version")) is not int or observed.get("schema_version") != IMGUI_HOST_SCHEMA_VERSION:
        raise ImGuiHostContractError("host plan schema_version is unsupported")
    if type(observed.get("lifecycle_version")) is not int or observed.get("lifecycle_version") != IMGUI_HOST_LIFECYCLE_VERSION:
        raise ImGuiHostContractError("host plan lifecycle_version is unsupported")
    for name in expected:
        if observed.get(name) != expected.get(name):
            raise ImGuiHostContractError(f"host plan {name} changed after planning")


def _validate_host_response(
    response: Mapping[str, Any],
    *,
    operation: str,
    sequence: int,
    session_id: str,
    target_identity_hash: str,
    precondition_hash: str,
    backend: str,
    test_double: bool,
) -> dict[str, Any]:
    allowed_envelope = {
        "protocol",
        "protocol_version",
        "capability",
        "operation",
        "request_id",
        "session_id",
        "status",
        "native_bridge",
        "bridge",
        "result",
        "errors",
    }
    required_envelope = {
        "protocol",
        "protocol_version",
        "capability",
        "operation",
        "request_id",
        "session_id",
        "status",
        "result",
        "errors",
    }
    if set(response) - allowed_envelope or not required_envelope.issubset(response):
        raise ImGuiHostContractError("host response envelope contains unknown fields")
    if (
        response.get("protocol") != IMGUI_HOST_BRIDGE_PROTOCOL
        or type(response.get("protocol_version")) is not int
        or response.get("protocol_version") != IMGUI_HOST_BRIDGE_PROTOCOL_VERSION
        or response.get("capability") != _CAPABILITY
        or not isinstance(response.get("request_id"), str)
        or not response.get("request_id")
    ):
        raise ImGuiHostContractError("host response bridge protocol/version is invalid")
    if response.get("operation") != operation or response.get("session_id") != session_id:
        raise ImGuiHostContractError("host response operation/session does not match request")
    if response.get("status") not in {"ok", "stopped"}:
        raise ImGuiHostContractError("host response status is not successful")
    errors = response.get("errors")
    if not isinstance(errors, list) or any(not isinstance(item, str) for item in errors):
        raise ImGuiHostContractError("host response errors must be an array of strings")
    if response.get("native_bridge") is not True and _mapping(response.get("bridge")).get("native") is not True:
        raise ImGuiHostContractError("host response must attest native_bridge=true")
    result = response.get("result")
    if not isinstance(result, Mapping):
        raise ImGuiHostContractError("host response result must be an object")
    required = {
        "schema_version",
        "lifecycle_version",
        "sequence",
        "operation",
        "session_id",
        "target_identity_hash",
        "precondition_hash",
        "backend",
        "evidence_class",
        "proof",
        _HOST_RESULT_FLAGS[operation],
    }
    allowed = required | {"hook_id", "frame_id", "width", "height", "reason"}
    if set(result) != required and (set(result) - allowed or not required.issubset(result)):
        raise ImGuiHostContractError(f"{operation} result does not match the lifecycle schema")
    expected = {
        "schema_version": IMGUI_HOST_SCHEMA_VERSION,
        "lifecycle_version": IMGUI_HOST_LIFECYCLE_VERSION,
        "sequence": sequence,
        "operation": operation,
        "session_id": session_id,
        "target_identity_hash": target_identity_hash,
        "precondition_hash": precondition_hash,
        "backend": backend,
    }
    for version_name in ("schema_version", "lifecycle_version", "sequence"):
        if type(result.get(version_name)) is not int:
            raise ImGuiHostContractError(f"{operation} result {version_name} must be an integer")
    for name, value in expected.items():
        if result.get(name) != value:
            raise ImGuiHostContractError(f"{operation} result {name} does not match the plan")
    if result.get(_HOST_RESULT_FLAGS[operation]) is not True:
        raise ImGuiHostContractError(f"{operation} did not attest {_HOST_RESULT_FLAGS[operation]}=true")
    evidence_class = result.get("evidence_class")
    if evidence_class not in {"synthetic_fixture", "live_host_proof"}:
        raise ImGuiHostContractError(f"{operation} evidence_class is unsupported")
    proof = result.get("proof")
    if not isinstance(proof, Mapping):
        raise ImGuiHostContractError(f"{operation} proof must be an object")
    if evidence_class == "live_host_proof":
        if test_double:
            raise ImGuiHostContractError("test-double evidence cannot establish live host proof")
        if proof.get("source") != "native_host_bridge" or proof.get("observed") is not True:
            raise ImGuiHostContractError("live host proof lacks native observation attestation")
        if not isinstance(proof.get("observed_at"), str) or not proof.get("observed_at"):
            raise ImGuiHostContractError("live host proof lacks observed_at")
    elif proof.get("fixture") is not True or proof.get("live_verified") is not False:
        raise ImGuiHostContractError("synthetic fixture proof must explicitly deny live verification")
    normalized = dict(result)
    normalized["proof"] = dict(proof)
    normalized["live_verified"] = evidence_class == "live_host_proof"
    return normalized


def _host_evidence_class(lifecycle: Sequence[Mapping[str, Any]]) -> str:
    if not lifecycle:
        return "none"
    classes = {str(item.get("evidence_class") or "") for item in lifecycle}
    if classes == {"live_host_proof"} and len(lifecycle) == len(IMGUI_HOST_LIFECYCLE):
        return "live_host_proof"
    return "synthetic_fixture"


def _host_call_dict(call: Any) -> dict[str, Any]:
    to_dict = getattr(call, "to_dict", None)
    if callable(to_dict):
        return _json_mapping(to_dict(include_payloads=True))
    return {
        "status": getattr(call, "status", "unknown"),
        "operation": getattr(call, "operation", None),
        "timed_out": bool(getattr(call, "timed_out", False)),
        "error": getattr(call, "error", None),
    }


def _lifecycle_contract() -> list[dict[str, Any]]:
    return [
        {
            "phase": "dll_attach",
            "contract": "DisableThreadLibraryCalls only; no hook, thread, ImGui, WndProc, or COM work",
        },
        {
            "phase": "initialize",
            "contract": "explicit HWND/device/context, COM AddRef, private ImGui context, Win32 and DX11 backends",
        },
        {
            "phase": "frame",
            "contract": "DX11 NewFrame, Win32 NewFrame, ImGui NewFrame, ImGui Render, RenderDrawData",
        },
        {
            "phase": "input",
            "contract": "optional owned WndProc subclass and explicit input-capture toggle",
        },
        {
            "phase": "resize",
            "contract": "InvalidateDeviceObjects before ResizeBuffers and CreateDeviceObjects after success",
        },
        {
            "phase": "device_removed_reset",
            "contract": "release stale D3D11 references and reinitialize backend with explicitly restored device/context",
        },
        {
            "phase": "threading",
            "contract": "serialize lifecycle, frame, resize, device, and WndProc calls with one recursive mutex",
        },
        {
            "phase": "shutdown",
            "contract": "mutex-serialized and idempotent; retry failed owned-WndProc restoration, stop backends, destroy context, release COM",
        },
    ]


def _host_responsibilities() -> dict[str, Any]:
    return {
        "resolve_present_target": True,
        "install_present_hook": True,
        "invoke_renderer_exports": True,
        "call_before_resize_buffers": True,
        "call_after_resize_buffers": True,
        "call_device_removed_restored": True,
        "call_shutdown_before_unload": True,
        "quiesce_renderer_calls_before_unload": True,
        "inject_or_load_plugin": True,
        "plugin_resolves_addresses": False,
        "plugin_writes_hooks": False,
        "provider_injects": False,
        "provider_writes_hooks": False,
    }


def _result_artifacts(
    session_id: str,
    *,
    status: str,
    generated_files: Mapping[str, bytes],
) -> list[CapabilityArtifact]:
    prefix = _artifact_prefix(session_id)
    artifacts: list[CapabilityArtifact] = []
    kind_by_name = {
        "CMakeLists.txt": "imgui-renderer-cmake",
        "include/ra_imgui_renderer.h": "imgui-renderer-c-abi",
        "src/ra_imgui_build_config.h": "imgui-renderer-build-binding",
        "src/ra_imgui_renderer.cpp": "imgui-renderer-source",
        "src/ra_imgui_renderer.def": "imgui-renderer-definition",
        "renderer-metadata.json": "imgui-renderer-metadata",
        f"bin/{_PLUGIN_NAME}": "imgui-renderer-plugin",
    }
    for relative in sorted(generated_files):
        artifacts.append(
            CapabilityArtifact(
                path=f"{prefix}/{relative}",
                kind=kind_by_name.get(relative, "imgui-renderer-project-file"),
                description=f"Dear ImGui renderer project artifact: {relative}",
                metadata={
                    "schema_version": _SCHEMA_VERSION,
                    "status": status,
                    "materialized": False,
                    "sha256": hashlib.sha256(generated_files[relative]).hexdigest(),
                    "size": len(generated_files[relative]),
                },
            )
        )
    artifacts.extend(
        [
            CapabilityArtifact(
                path=f"{prefix}/renderer-audit.json",
                kind="imgui-renderer-audit",
                description="Renderer plan, lifecycle, build, and provenance audit record",
                metadata={"schema_version": _SCHEMA_VERSION, "status": status, "materialized": False},
            ),
            CapabilityArtifact(
                path=f"{prefix}/artifact-manifest.json",
                kind="imgui-renderer-manifest",
                description="Hashed ImGui renderer artifact manifest",
                metadata={"schema_version": _SCHEMA_VERSION, "status": status, "materialized": False},
            ),
        ]
    )
    return artifacts


def _planned_manifest_entry(
    plan: CapabilityPlan,
    artifact: CapabilityArtifact,
    status: str,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "status": status,
        "session_id": plan.session_id,
        "target_identity": plan.target.to_dict(),
        "target_identity_hash": plan.parameters.get("target_identity_hash"),
        "precondition_hash": plan.precondition_hash,
        "hook_target_resolution_hash": plan.parameters.get(
            "hook_target_resolution_hash"
        ),
        "hook_target_resolution_artifact_sha256": plan.parameters.get(
            "hook_target_resolution_artifact_sha256"
        ),
        "materialized": False,
    }


def _manifest_entry(
    result: CapabilityExecutionResult,
    artifact: CapabilityArtifact,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "status": result.status,
        "session_id": result.session_id,
        "target_identity": result.target.to_dict(),
        "target_identity_hash": result.provenance.get("target_identity_hash"),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "hook_target_resolution_hash": result.provenance.get(
            "hook_target_resolution_hash"
        ),
        "hook_target_resolution_artifact_sha256": result.provenance.get(
            "hook_target_resolution_artifact_sha256"
        ),
        "plugin_sha256": result.provenance.get("plugin_sha256"),
    }


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    report_section = _json_mapping(result.report_section)
    stable_artifacts: list[dict[str, Any]] = []
    stable_manifest_entries: list[dict[str, Any]] = []
    for artifact in result.artifacts:
        record = artifact.to_dict()
        metadata = _mapping(record.get("metadata"))
        metadata.pop("collection_root", None)
        metadata["materialized"] = False
        if artifact.kind in {"imgui-renderer-audit", "imgui-renderer-manifest"}:
            metadata.pop("sha256", None)
            metadata.pop("size", None)
        record["metadata"] = metadata
        stable_artifacts.append(record)
        entry = _manifest_entry(result, artifact)
        entry["materialized"] = False
        stable_manifest_entries.append(entry)
    report_section["artifacts"] = stable_artifacts
    report_section["evidence_manifest_entries"] = stable_manifest_entries
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "action": result.action,
        "status": result.status,
        "target_identity": result.target.to_dict(),
        "target_identity_hash": result.provenance.get("target_identity_hash"),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "hook_target_resolution_hash": result.provenance.get(
            "hook_target_resolution_hash"
        ),
        "hook_target_resolution_artifact_sha256": result.provenance.get(
            "hook_target_resolution_artifact_sha256"
        ),
        "plugin_sha256": result.provenance.get("plugin_sha256"),
        "before_snapshot": result.before_snapshot,
        "after_snapshot": result.after_snapshot,
        "rollback_plan": result.rollback_plan,
        "lifecycle_contract": _lifecycle_contract(),
        "host_responsibilities": _host_responsibilities(),
        "report_section": report_section,
        "provenance": result.provenance,
    }


def _collection_bindings(result: CapabilityExecutionResult) -> dict[str, Any]:
    return _json_mapping(
        {
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "architecture": result.report_section.get("architecture"),
            "backend": result.report_section.get("backend"),
            "target_identity": result.target.to_dict(),
            "target_identity_hash": result.provenance.get("target_identity_hash"),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "hook_target_resolution": result.provenance.get("hook_target_resolution"),
            "hook_target_resolution_hash": result.provenance.get(
                "hook_target_resolution_hash"
            ),
            "hook_target_resolution_artifact_sha256": result.provenance.get(
                "hook_target_resolution_artifact_sha256"
            ),
            "hook_target_resolution_source": result.provenance.get(
                "hook_target_resolution_source"
            ),
            "project_hash": result.provenance.get("project_hash"),
            "plugin_sha256": result.provenance.get("plugin_sha256"),
        }
    )


def _parse_pe_export_names(view: _PEView) -> tuple[str, ...]:
    rva, size = view.directory(0)
    if not rva or size < 40:
        raise RendererPluginValidationError("renderer plugin has no PE export directory")
    offset = view.rva_to_offset(rva, 40, "export directory")
    values = _unpack_from("<IIHHIIIIIII", view.data, offset, "export directory")
    function_count = values[6]
    name_count = values[7]
    names_rva = values[9]
    ordinals_rva = values[10]
    if function_count <= 0 or function_count > 65535 or name_count > function_count:
        raise RendererPluginValidationError("renderer plugin export counts are invalid")
    names_offset = view.rva_to_offset(names_rva, name_count * 4, "export name table")
    ordinals_offset = view.rva_to_offset(ordinals_rva, name_count * 2, "export ordinal table")
    names: list[str] = []
    ordinals: set[int] = set()
    for index in range(name_count):
        name_rva = _unpack_from(
            "<I", view.data, names_offset + index * 4, f"export name RVA {index}"
        )[0]
        ordinal = _unpack_from(
            "<H", view.data, ordinals_offset + index * 2, f"export ordinal {index}"
        )[0]
        if ordinal >= function_count or ordinal in ordinals:
            raise RendererPluginValidationError("renderer plugin export ordinals are invalid")
        ordinals.add(ordinal)
        names.append(view.c_string(name_rva, f"export name {index}"))
    if len(set(names)) != len(names):
        raise RendererPluginValidationError("renderer plugin contains duplicate export names")
    if name_count != function_count:
        raise RendererPluginValidationError("renderer plugin contains unexpected ordinal-only exports")
    return tuple(sorted(names))


def _parse_pe_imports(view: _PEView) -> dict[str, tuple[str, ...]]:
    rva, size = view.directory(1)
    if not rva or size < 20:
        raise RendererPluginValidationError("renderer plugin has no PE import directory")
    imports: dict[str, tuple[str, ...]] = {}
    descriptor_rva = rva
    for descriptor_index in range(4096):
        offset = view.rva_to_offset(descriptor_rva, 20, f"import descriptor {descriptor_index}")
        original_thunk, timestamp, forwarder, name_rva, first_thunk = _unpack_from(
            "<IIIII", view.data, offset, f"import descriptor {descriptor_index}"
        )
        if not any((original_thunk, timestamp, forwarder, name_rva, first_thunk)):
            break
        module = view.c_string(name_rva, f"import module {descriptor_index}")
        if not module or module.casefold() in {name.casefold() for name in imports}:
            raise RendererPluginValidationError("renderer plugin import modules are empty or duplicated")
        thunk_rva = original_thunk or first_thunk
        symbols: list[str] = []
        width = 8 if view.bits == 64 else 4
        ordinal_mask = 1 << (view.bits - 1)
        for symbol_index in range(65536):
            thunk_offset = view.rva_to_offset(
                thunk_rva + symbol_index * width,
                width,
                f"import thunk {descriptor_index}:{symbol_index}",
            )
            value = _unpack_from(
                "<Q" if width == 8 else "<I",
                view.data,
                thunk_offset,
                f"import thunk {descriptor_index}:{symbol_index}",
            )[0]
            if value == 0:
                break
            if value & ordinal_mask:
                symbols.append(f"#{value & 0xFFFF}")
            else:
                name_offset = view.rva_to_offset(
                    value,
                    3,
                    f"import-by-name {descriptor_index}:{symbol_index}",
                )
                name = view.c_string(
                    value + 2,
                    f"import symbol {descriptor_index}:{symbol_index}",
                )
                if not name:
                    raise RendererPluginValidationError("renderer plugin contains an empty import name")
                if name_offset < 0:  # pragma: no cover - keeps the validated offset live
                    raise RendererPluginValidationError("invalid import name offset")
                symbols.append(name)
        else:
            raise RendererPluginValidationError("renderer plugin import thunk count exceeds the limit")
        imports[module] = tuple(sorted(set(symbols)))
        descriptor_rva += 20
    else:
        raise RendererPluginValidationError("renderer plugin import descriptor count exceeds the limit")
    if not imports:
        raise RendererPluginValidationError("renderer plugin import table is empty")
    return dict(sorted(imports.items(), key=lambda item: item[0].casefold()))


def _inspect_pe_architecture(data: bytes) -> str:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise RendererPluginValidationError("target executable is not a PE image")
    pe_offset = _unpack_from("<I", data, 0x3C, "target DOS e_lfanew")[0]
    if pe_offset + 26 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise RendererPluginValidationError("target executable has an invalid PE header")
    machine = _unpack_from("<H", data, pe_offset + 4, "target machine")[0]
    optional_size = _unpack_from("<H", data, pe_offset + 20, "target optional size")[0]
    if pe_offset + 24 + optional_size > len(data):
        raise RendererPluginValidationError("target executable optional header is truncated")
    magic = _unpack_from("<H", data, pe_offset + 24, "target optional magic")[0]
    identity = {(0x014C, 0x10B): "x86", (0x8664, 0x20B): "x64"}.get((machine, magic))
    if identity is None:
        raise RendererPluginValidationError("target executable architecture is unsupported or inconsistent")
    return identity


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            env=dict(environment),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr
        return {
            "command": [str(item) for item in command],
            "cwd_role": "ephemeral_project",
            "shell": False,
            "returncode": None,
            "timed_out": True,
            "timeout_seconds": timeout_seconds,
            "stdout": (stdout or "")[-32768:],
            "stderr": (stderr or "")[-32768:],
        }
    return {
        "command": [str(item) for item in command],
        "cwd_role": "ephemeral_project",
        "shell": False,
        "returncode": completed.returncode,
        "timed_out": False,
        "stdout": (completed.stdout or "")[-32768:],
        "stderr": (completed.stderr or "")[-32768:],
    }


def _normalize_ephemeral_build_record(
    record: Mapping[str, Any],
    *,
    workspace: Path,
    project: Path,
    build: Path,
) -> dict[str, Any]:
    replacements = (
        (project, "<ephemeral-project>"),
        (build, "<ephemeral-build>"),
        (workspace, "<ephemeral-workspace>"),
    )

    def normalize(value: Any) -> Any:
        if isinstance(value, str):
            result = value
            for source, replacement in replacements:
                variants = {
                    str(source),
                    str(source).replace("\\", "/"),
                    str(source).replace("/", "\\"),
                }
                for variant in sorted(variants, key=len, reverse=True):
                    result = re.sub(
                        re.escape(variant),
                        lambda _match, token=replacement: token,
                        result,
                        flags=re.IGNORECASE,
                    )
            return result
        if isinstance(value, Mapping):
            return {str(key): normalize(item) for key, item in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            return [normalize(item) for item in value]
        return value

    return _json_mapping(normalize(record))


def _build_audit_path_placeholders() -> dict[str, str]:
    return {
        "<ephemeral-build>": "provider-owned temporary CMake build directory",
        "<ephemeral-project>": "provider-owned temporary generated project directory",
        "<ephemeral-workspace>": "provider-owned temporary build workspace",
    }


def _build_environment(cxx: Path) -> dict[str, str]:
    environment = dict(os.environ)
    compiler_dir = str(cxx.parent)
    existing_path = environment.get("PATH", "")
    environment["PATH"] = compiler_dir + (os.pathsep + existing_path if existing_path else "")
    environment["SOURCE_DATE_EPOCH"] = "1"
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return environment


def _materialize_project(root: Path, files: Mapping[str, bytes]) -> None:
    root = root.resolve()
    if root.exists():
        raise ImGuiPathBoundaryError(f"project directory already exists: {root}")
    root.mkdir(parents=True, exist_ok=False)
    destinations = {
        relative: _artifact_destination(root, relative) for relative in files
    }
    for relative in sorted(files):
        _atomic_write(destinations[relative], files[relative])


def _plan_precondition_hash(
    *,
    capability: str,
    provider: str,
    session_id: str,
    action: str,
    target: TargetIdentity,
    parameters: Mapping[str, Any],
) -> str:
    return _sha256_json(
        {
            "schema_version": _SCHEMA_VERSION,
            "capability": capability,
            "provider": provider,
            "session_id": session_id,
            "action": action,
            "target": target.to_dict(),
            "parameters": _json_value(parameters),
        }
    )


def _file_hash_manifest(files: Mapping[str, bytes]) -> dict[str, dict[str, Any]]:
    return {
        relative: {
            "sha256": hashlib.sha256(files[relative]).hexdigest(),
            "size": len(files[relative]),
        }
        for relative in sorted(files)
    }


def _normalize_action(action: Any, params: Mapping[str, Any]) -> str:
    value = str(action or "generate").strip().casefold().replace("-", "_")
    aliases = {
        "generate": "generate",
        "prepare": "generate",
        "create_project": "generate",
        "build": "build",
        "compile": "build",
    }
    normalized = aliases.get(value)
    if normalized is None:
        raise ValueError(f"unsupported ImGui renderer action: {action!r}")
    if normalized == "generate":
        build_value = params.get("build", params.get("build_enabled", params.get("compile")))
        if build_value is True:
            return "build"
    return normalized


def _normalize_backend(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().casefold().replace("-", "").replace("_", "")
    aliases = {
        "d3d11": "d3d11",
        "direct3d11": "d3d11",
        "dx11": "d3d11",
        "d3d12": "d3d12",
        "direct3d12": "d3d12",
        "dx12": "d3d12",
        "opengl": "opengl3",
        "opengl3": "opengl3",
        "gl3": "opengl3",
        "vulkan": "vulkan",
        "vk": "vulkan",
    }
    return aliases.get(normalized)


def _normalize_architecture(value: Any) -> Optional[str]:
    normalized = str(value or "").strip().casefold().replace("-", "_")
    aliases = {
        "x86": "x86",
        "i386": "x86",
        "i686": "x86",
        "win32": "x86",
        "x64": "x64",
        "amd64": "x64",
        "x86_64": "x64",
    }
    return aliases.get(normalized)


def _normalize_session_id(value: Any) -> str:
    session = str(value or "imgui-renderer-session").strip()
    if not session or len(session) > 128 or "\x00" in session:
        raise ValueError("renderer session_id is empty, oversized, or contains NUL")
    return session


def _safe_segment(value: str) -> str:
    result = _SAFE_SEGMENT_RE.sub("-", str(value)).strip(".-")
    return (result or "imgui-renderer-session")[:96]


def _artifact_prefix(session_id: str) -> str:
    identity_suffix = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]
    return f"imgui-renderer/{_safe_segment(session_id)}-{identity_suffix}"


def _asset_key(session_id: str, precondition_hash: Optional[str]) -> str:
    return f"{session_id}:{precondition_hash or 'missing'}"


def _project_relative_path(prefix: str, artifact_path: str) -> str:
    expected = prefix + "/"
    if not artifact_path.startswith(expected):
        raise ValueError("renderer artifact path does not belong to the planned project")
    return artifact_path[len(expected) :]


def _strict_collection_root(value: Any) -> Path:
    root = _strict_absolute_path(
        value,
        label="collection directory",
        must_exist=False,
        kind="directory",
    )
    if root.exists() and not root.is_dir():
        raise ImGuiPathBoundaryError("collection directory exists and is not a directory")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _artifact_destination(root: Path, relative_path: str) -> Path:
    text = str(relative_path)
    pure = PurePosixPath(text.replace("\\", "/"))
    if (
        not text
        or "\x00" in text
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
        or any(_unsafe_windows_path_segment(part) for part in pure.parts)
    ):
        raise ImGuiPathBoundaryError("artifact path must remain relative to the collection directory")
    destination = (root / Path(*pure.parts)).resolve()
    _require_within(root, destination, label="artifact path")
    return destination


def _strict_absolute_path(
    value: Any,
    *,
    label: str,
    must_exist: bool,
    kind: str,
) -> Path:
    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise ImGuiRendererError(f"{label} must be a filesystem path") from exc
    if not isinstance(text, str) or not text.strip() or "\x00" in text:
        raise ImGuiRendererError(f"{label} path is empty or contains NUL")
    supplied = Path(text).expanduser()
    if not supplied.is_absolute():
        raise ImGuiPathBoundaryError(f"{label} path must be absolute")
    anchor = supplied.anchor
    if anchor.casefold().startswith(("\\\\?\\", "\\\\.\\")):
        raise ImGuiPathBoundaryError(f"{label} path cannot use a Windows device namespace")
    lexical_parts = supplied.parts[1:] if anchor and supplied.parts else supplied.parts
    if any(
        part in {"", ".", ".."} or _unsafe_windows_path_segment(part)
        for part in lexical_parts
    ):
        raise ImGuiPathBoundaryError(f"{label} path contains an unsafe segment")
    path = supplied.resolve()
    if must_exist and not path.exists():
        raise FileNotFoundError(f"{label} does not exist: {path}")
    if path.exists() and kind == "file" and not path.is_file():
        raise ImGuiRendererError(f"{label} is not a regular file: {path}")
    if path.exists() and kind == "directory" and not path.is_dir():
        raise ImGuiRendererError(f"{label} is not a directory: {path}")
    return path


def _require_within(root: Path, candidate: Path, *, label: str) -> None:
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve()
    if resolved_candidate == resolved_root or resolved_root in resolved_candidate.parents:
        return
    raise ImGuiPathBoundaryError(f"{label} escapes its declared directory")


def _atomic_write(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _unsafe_windows_path_segment(value: str) -> bool:
    if not value or ":" in value or value.rstrip(" .") != value:
        return True
    reserved = {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
    return value.split(".", 1)[0].casefold() in reserved


def _strict_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImGuiRendererError(f"{label} is not valid UTF-8") from exc

    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ImGuiRendererError(f"{label} contains duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        payload = json.loads(text, object_pairs_hook=pairs)
    except json.JSONDecodeError as exc:
        raise ImGuiRendererError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ImGuiRendererError(f"{label} must contain a JSON object")
    return _json_mapping(payload)


def _normalize_optional_sha256(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    digest = str(value).strip().casefold()
    if not _HEX_SHA256_RE.fullmatch(digest):
        raise ValueError("SHA-256 value must contain exactly 64 lowercase hexadecimal digits")
    return digest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            _json_value(value),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _json_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    raise TypeError(f"value is not JSON serializable: {type(value).__name__}")


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _strict_bool(value: Any, *, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{name} must be a boolean")


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _positive_int(value: Any, name: str) -> int:
    result = _integer(value, name)
    if result <= 0:
        raise ValueError(f"{name} must be positive")
    return result


def _non_negative_int(value: Any, name: str) -> int:
    result = _integer(value, name)
    if result < 0:
        raise ValueError(f"{name} must be non-negative")
    return result


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
    raise ValueError(f"{name} must be an integer")


def _unpack_from(format_string: str, data: bytes, offset: int, label: str) -> tuple[Any, ...]:
    size = struct.calcsize(format_string)
    if offset < 0 or offset + size > len(data):
        raise RendererPluginValidationError(f"{label} is outside the PE image")
    return struct.unpack_from(format_string, data, offset)


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


_CMAKE_TEMPLATE = r'''cmake_minimum_required(VERSION 3.20)
project(reverse_analyzer_imgui_renderer LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "The renderer plugin targets Win32 only")
endif()
if(NOT DEFINED IMGUI_ROOT OR NOT IS_DIRECTORY "${IMGUI_ROOT}")
  message(FATAL_ERROR "IMGUI_ROOT must name an official Dear ImGui checkout")
endif()
if(NOT RA_IMGUI_ARCHITECTURE MATCHES "^(x86|x64)$")
  message(FATAL_ERROR "RA_IMGUI_ARCHITECTURE must be x86 or x64")
endif()
if(NOT MINGW)
  message(FATAL_ERROR "The production renderer build requires MinGW")
endif()
if(RA_IMGUI_ARCHITECTURE STREQUAL "x64" AND NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Compiler pointer width does not match x64")
endif()
if(RA_IMGUI_ARCHITECTURE STREQUAL "x86" AND NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "Compiler pointer width does not match x86")
endif()

set(RA_IMGUI_REQUIRED_FILES
  LICENSE.txt
  imconfig.h
  imgui.h
  imgui.cpp
  imgui_draw.cpp
  imgui_internal.h
  imgui_tables.cpp
  imgui_widgets.cpp
  imstb_rectpack.h
  imstb_textedit.h
  imstb_truetype.h
  backends/imgui_impl_win32.h
  backends/imgui_impl_win32.cpp
  backends/imgui_impl_dx11.h
  backends/imgui_impl_dx11.cpp
)
foreach(relative_path IN LISTS RA_IMGUI_REQUIRED_FILES)
  if(NOT EXISTS "${IMGUI_ROOT}/${relative_path}")
    message(FATAL_ERROR "Missing official Dear ImGui source: ${relative_path}")
  endif()
endforeach()

add_library(reverse_analyzer_imgui_renderer SHARED
  src/ra_imgui_renderer.cpp
  src/ra_imgui_renderer.def
  "${IMGUI_ROOT}/imgui.cpp"
  "${IMGUI_ROOT}/imgui_draw.cpp"
  "${IMGUI_ROOT}/imgui_tables.cpp"
  "${IMGUI_ROOT}/imgui_widgets.cpp"
  "${IMGUI_ROOT}/backends/imgui_impl_win32.cpp"
  "${IMGUI_ROOT}/backends/imgui_impl_dx11.cpp"
)
target_compile_features(reverse_analyzer_imgui_renderer PRIVATE cxx_std_17)
target_compile_definitions(reverse_analyzer_imgui_renderer PRIVATE
  RA_IMGUI_RENDERER_BUILD
  UNICODE
  _UNICODE
  WIN32_LEAN_AND_MEAN
  NOMINMAX
)
target_include_directories(reverse_analyzer_imgui_renderer PRIVATE
  include
  src
  "${IMGUI_ROOT}"
  "${IMGUI_ROOT}/backends"
)
target_link_libraries(reverse_analyzer_imgui_renderer PRIVATE
  d3d11
  d3dcompiler
  dxgi
  dwmapi
  imm32
  user32
)
if(MINGW)
  target_link_options(reverse_analyzer_imgui_renderer PRIVATE
    "-static-libgcc"
    "-static-libstdc++"
    "-Wl,--no-insert-timestamp"
    "-Wl,--exclude-all-symbols"
  )
endif()
set_target_properties(reverse_analyzer_imgui_renderer PROPERTIES
  PREFIX ""
  OUTPUT_NAME "reverse_analyzer_imgui_renderer"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
'''


_HEADER_TEMPLATE = r'''#pragma once

#include <windows.h>
#include <d3d11.h>
#include <stdint.h>

#if defined(RA_IMGUI_RENDERER_BUILD)
#define RA_IMGUI_API __declspec(dllexport)
#else
#define RA_IMGUI_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum RAImGuiRendererState {
    RA_IMGUI_STATE_UNINITIALIZED = 0,
    RA_IMGUI_STATE_READY = 1,
    RA_IMGUI_STATE_RESIZE_INVALIDATED = 2,
    RA_IMGUI_STATE_DEVICE_LOST = 3,
    RA_IMGUI_STATE_SHUTDOWN = 4,
    RA_IMGUI_STATE_SHUTDOWN_PENDING = 5
};

enum RAImGuiGraphicsApi {
    RA_IMGUI_API_D3D11 = 1,
    RA_IMGUI_API_D3D12 = 2,
    RA_IMGUI_API_OPENGL3 = 3,
    RA_IMGUI_API_VULKAN = 4
};

typedef struct RAImGuiRendererConfig {
    uint32_t struct_size;
    BOOL install_wndproc;
    BOOL capture_input;
} RAImGuiRendererConfig;

RA_IMGUI_API uint32_t RAImGuiRenderer_AbiVersion(void);
RA_IMGUI_API const char* RAImGuiRenderer_BackendName(void);
RA_IMGUI_API const char* RAImGuiRenderer_BindingHash(void);
RA_IMGUI_API int RAImGuiRenderer_GetState(void);
RA_IMGUI_API const char* RAImGuiRenderer_GetLastError(void);
RA_IMGUI_API BOOL RAImGuiRenderer_Initialize(
    HWND hwnd,
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    const RAImGuiRendererConfig* config);
RA_IMGUI_API BOOL RAImGuiRenderer_NewFrame(void);
RA_IMGUI_API BOOL RAImGuiRenderer_RenderDrawData(void);
RA_IMGUI_API LRESULT RAImGuiRenderer_WndProcHandler(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);
RA_IMGUI_API BOOL RAImGuiRenderer_SetInputCapture(BOOL enabled);
RA_IMGUI_API BOOL RAImGuiRenderer_BeforeResizeBuffers(void);
RA_IMGUI_API BOOL RAImGuiRenderer_AfterResizeBuffers(void);
RA_IMGUI_API void RAImGuiRenderer_OnDeviceRemoved(HRESULT reason);
RA_IMGUI_API BOOL RAImGuiRenderer_OnDeviceRestored(
    ID3D11Device* device, ID3D11DeviceContext* context);
RA_IMGUI_API BOOL RAImGuiRenderer_Shutdown(void);

#ifdef __cplusplus
}
#endif
'''


_BUILD_CONFIG_TEMPLATE = r'''#pragma once

#define RA_IMGUI_TARGET_IDENTITY_HASH "@TARGET_IDENTITY_HASH@"
#define RA_IMGUI_HOOK_TARGET_RESOLUTION_HASH "@HOOK_TARGET_RESOLUTION_HASH@"
#define RA_IMGUI_PRECONDITION_HASH "@PRECONDITION_HASH@"
#define RA_IMGUI_BINDING_HASH \
    RA_IMGUI_TARGET_IDENTITY_HASH ":" \
    RA_IMGUI_HOOK_TARGET_RESOLUTION_HASH ":" \
    RA_IMGUI_PRECONDITION_HASH
'''


_DEF_TEMPLATE = r'''LIBRARY "reverse_analyzer_imgui_renderer.dll"
EXPORTS
    RAImGuiRenderer_AbiVersion
    RAImGuiRenderer_AfterResizeBuffers
    RAImGuiRenderer_BackendName
    RAImGuiRenderer_BeforeResizeBuffers
    RAImGuiRenderer_BindingHash
    RAImGuiRenderer_GetLastError
    RAImGuiRenderer_GetState
    RAImGuiRenderer_Initialize
    RAImGuiRenderer_NewFrame
    RAImGuiRenderer_OnDeviceRemoved
    RAImGuiRenderer_OnDeviceRestored
    RAImGuiRenderer_RenderDrawData
    RAImGuiRenderer_SetInputCapture
    RAImGuiRenderer_Shutdown
    RAImGuiRenderer_WndProcHandler
'''


_SOURCE_TEMPLATE = r'''#include "ra_imgui_renderer.h"
#include "ra_imgui_build_config.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <cstring>
#include <memory>
#include <mutex>
#include <new>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

namespace {

struct RendererBackendInitialization {
    RAImGuiGraphicsApi api;
    void* device;
    void* context;
};

class RendererBackend {
public:
    virtual ~RendererBackend() = default;
    virtual RAImGuiGraphicsApi GraphicsApi() const = 0;
    virtual bool Initialize(const RendererBackendInitialization& initialization) = 0;
    virtual void NewFrame() = 0;
    virtual void Render(ImDrawData* draw_data) = 0;
    virtual void InvalidateDeviceObjects() = 0;
    virtual bool RecreateDeviceObjects() = 0;
    virtual void Shutdown() = 0;
};

class D3D11RendererBackend final : public RendererBackend {
public:
    RAImGuiGraphicsApi GraphicsApi() const override {
        return RA_IMGUI_API_D3D11;
    }

    bool Initialize(const RendererBackendInitialization& initialization) override {
        if (initialized_ || initialization.api != RA_IMGUI_API_D3D11 ||
            initialization.device == nullptr || initialization.context == nullptr) {
            return false;
        }
        auto* device = static_cast<ID3D11Device*>(initialization.device);
        auto* context = static_cast<ID3D11DeviceContext*>(initialization.context);
        initialized_ = ImGui_ImplDX11_Init(device, context);
        return initialized_;
    }

    void NewFrame() override {
        ImGui_ImplDX11_NewFrame();
    }

    void Render(ImDrawData* draw_data) override {
        ImGui_ImplDX11_RenderDrawData(draw_data);
    }

    void InvalidateDeviceObjects() override {
        if (initialized_) {
            ImGui_ImplDX11_InvalidateDeviceObjects();
        }
    }

    bool RecreateDeviceObjects() override {
        return initialized_ && ImGui_ImplDX11_CreateDeviceObjects();
    }

    void Shutdown() override {
        if (initialized_) {
            ImGui_ImplDX11_Shutdown();
            initialized_ = false;
        }
    }

private:
    bool initialized_ = false;
};

struct RendererState {
    std::recursive_mutex mutex;
    RAImGuiRendererState state = RA_IMGUI_STATE_UNINITIALIZED;
    HWND hwnd = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    ImGuiContext* imgui_context = nullptr;
    std::unique_ptr<RendererBackend> backend;
    WNDPROC original_wndproc = nullptr;
    bool win32_initialized = false;
    bool wndproc_installed = false;
    bool capture_input = false;
    bool frame_started = false;
    HRESULT device_removed_reason = S_OK;
    char last_error[512] = {};
};

RendererState g_renderer;

template <typename T>
void ReleaseCom(T*& value) {
    if (value != nullptr) {
        value->Release();
        value = nullptr;
    }
}

void SetErrorLocked(const char* message) noexcept {
    const char* value = message != nullptr ? message : "unknown renderer error";
    std::strncpy(g_renderer.last_error, value, sizeof(g_renderer.last_error) - 1);
    g_renderer.last_error[sizeof(g_renderer.last_error) - 1] = '\0';
}

void ClearErrorLocked() noexcept {
    g_renderer.last_error[0] = '\0';
}

void SetCurrentContextLocked() {
    if (g_renderer.imgui_context != nullptr) {
        ImGui::SetCurrentContext(g_renderer.imgui_context);
    }
}

void CancelFrameLocked() {
    if (g_renderer.frame_started && g_renderer.imgui_context != nullptr) {
        SetCurrentContextLocked();
        ImGui::EndFrame();
    }
    g_renderer.frame_started = false;
}

bool IsMouseMessage(UINT message) {
    return (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST) ||
           message == WM_NCMOUSEMOVE || message == WM_NCLBUTTONDOWN ||
           message == WM_NCLBUTTONUP || message == WM_NCRBUTTONDOWN ||
           message == WM_NCRBUTTONUP;
}

bool IsKeyboardMessage(UINT message) {
    return (message >= WM_KEYFIRST && message <= WM_KEYLAST) ||
           message == WM_CHAR || message == WM_SYSCHAR;
}

LRESULT ProcessWndProcLocked(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (hwnd != g_renderer.hwnd || !g_renderer.win32_initialized ||
        g_renderer.imgui_context == nullptr) {
        return 0;
    }
    SetCurrentContextLocked();
    const LRESULT backend_handled =
        ImGui_ImplWin32_WndProcHandler(hwnd, message, wparam, lparam);
    if (!g_renderer.capture_input) {
        return 0;
    }
    const ImGuiIO& io = ImGui::GetIO();
    const bool consume =
        (IsMouseMessage(message) && io.WantCaptureMouse) ||
        (IsKeyboardMessage(message) && (io.WantCaptureKeyboard || io.WantTextInput));
    return consume ? (backend_handled != 0 ? backend_handled : 1) : 0;
}

LRESULT CALLBACK RendererWndProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    WNDPROC original = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
        const LRESULT handled = ProcessWndProcLocked(hwnd, message, wparam, lparam);
        if (handled != 0) {
            return handled;
        }
        original = g_renderer.original_wndproc;
    }
    return original != nullptr
        ? CallWindowProcW(original, hwnd, message, wparam, lparam)
        : DefWindowProcW(hwnd, message, wparam, lparam);
}

bool InstallWndProcLocked() {
    SetLastError(ERROR_SUCCESS);
    const LONG_PTR previous = SetWindowLongPtrW(
        g_renderer.hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(&RendererWndProc));
    if (previous == 0 && GetLastError() != ERROR_SUCCESS) {
        SetErrorLocked("SetWindowLongPtrW failed while installing the ImGui WndProc");
        return false;
    }
    g_renderer.original_wndproc = reinterpret_cast<WNDPROC>(previous);
    g_renderer.wndproc_installed = true;
    return true;
}

bool RestoreWndProcLocked() {
    if (!g_renderer.wndproc_installed) {
        return true;
    }
    if (!IsWindow(g_renderer.hwnd)) {
        g_renderer.wndproc_installed = false;
        g_renderer.original_wndproc = nullptr;
        return true;
    }
    SetLastError(ERROR_SUCCESS);
    const LONG_PTR current = GetWindowLongPtrW(g_renderer.hwnd, GWLP_WNDPROC);
    if (current == 0 && GetLastError() != ERROR_SUCCESS) {
        SetErrorLocked("GetWindowLongPtrW failed while checking ImGui WndProc ownership");
        return false;
    }
    if (current != reinterpret_cast<LONG_PTR>(&RendererWndProc)) {
        SetErrorLocked("ImGui WndProc is followed by another subclass; restoration is pending");
        return false;
    }
    SetLastError(ERROR_SUCCESS);
    const LONG_PTR previous = SetWindowLongPtrW(
        g_renderer.hwnd,
        GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(g_renderer.original_wndproc));
    if (previous == 0 && GetLastError() != ERROR_SUCCESS) {
        SetErrorLocked("SetWindowLongPtrW failed while restoring the original WndProc");
        return false;
    }
    g_renderer.wndproc_installed = false;
    g_renderer.original_wndproc = nullptr;
    return true;
}

void ReleaseGraphicsReferencesLocked() {
    ReleaseCom(g_renderer.context);
    ReleaseCom(g_renderer.device);
}

bool DeviceAndContextMatchLocked(
    ID3D11Device* device, ID3D11DeviceContext* context) {
    ID3D11Device* context_device = nullptr;
    context->GetDevice(&context_device);
    const bool matches = context_device == device;
    ReleaseCom(context_device);
    if (!matches) {
        SetErrorLocked("ID3D11DeviceContext belongs to a different D3D11 device");
    }
    return matches;
}

bool InitializationInputsAreValidLocked(
    HWND hwnd, ID3D11Device* device, ID3D11DeviceContext* context) {
    if (hwnd == nullptr || device == nullptr || context == nullptr) {
        SetErrorLocked("Initialize requires non-null HWND, ID3D11Device, and ID3D11DeviceContext");
        return false;
    }
    DWORD window_process_id = 0;
    if (!IsWindow(hwnd) || GetWindowThreadProcessId(hwnd, &window_process_id) == 0 ||
        window_process_id != GetCurrentProcessId()) {
        SetErrorLocked("Initialize requires an HWND owned by the current process");
        return false;
    }
    return DeviceAndContextMatchLocked(device, context);
}

void ResetStateLocked(RAImGuiRendererState final_state) {
    g_renderer.hwnd = nullptr;
    g_renderer.capture_input = false;
    g_renderer.frame_started = false;
    g_renderer.device_removed_reason = S_OK;
    g_renderer.state = final_state;
}

bool ShutdownLocked(RAImGuiRendererState final_state) {
    const bool wndproc_restored = RestoreWndProcLocked();
    SetCurrentContextLocked();
    CancelFrameLocked();
    if (g_renderer.backend != nullptr) {
        g_renderer.backend->Shutdown();
        g_renderer.backend.reset();
    }
    if (g_renderer.win32_initialized) {
        ImGui_ImplWin32_Shutdown();
        g_renderer.win32_initialized = false;
    }
    if (g_renderer.imgui_context != nullptr) {
        ImGui::DestroyContext(g_renderer.imgui_context);
        g_renderer.imgui_context = nullptr;
    }
    ReleaseGraphicsReferencesLocked();
    if (wndproc_restored) {
        ResetStateLocked(final_state);
    } else {
        // Keep HWND/WndProc ownership so a later idempotent Shutdown can retry.
        g_renderer.capture_input = false;
        g_renderer.device_removed_reason = S_OK;
        g_renderer.state = RA_IMGUI_STATE_SHUTDOWN_PENDING;
    }
    return wndproc_restored;
}

void DeviceRemovedLocked(HRESULT reason) {
    if (g_renderer.state != RA_IMGUI_STATE_READY &&
        g_renderer.state != RA_IMGUI_STATE_RESIZE_INVALIDATED) {
        return;
    }
    SetCurrentContextLocked();
    CancelFrameLocked();
    if (g_renderer.backend != nullptr) {
        g_renderer.backend->InvalidateDeviceObjects();
        g_renderer.backend->Shutdown();
    }
    ReleaseGraphicsReferencesLocked();
    g_renderer.frame_started = false;
    g_renderer.device_removed_reason = reason;
    g_renderer.state = RA_IMGUI_STATE_DEVICE_LOST;
    SetErrorLocked("D3D11 device was removed or reset; call OnDeviceRestored explicitly");
}

}  // namespace

extern "C" uint32_t RAImGuiRenderer_AbiVersion(void) {
    return 1U;
}

extern "C" const char* RAImGuiRenderer_BackendName(void) {
    return "d3d11";
}

extern "C" const char* RAImGuiRenderer_BindingHash(void) {
    return RA_IMGUI_BINDING_HASH;
}

extern "C" int RAImGuiRenderer_GetState(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    return static_cast<int>(g_renderer.state);
}

extern "C" const char* RAImGuiRenderer_GetLastError(void) {
    thread_local char error_snapshot[512] = {};
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    std::strncpy(error_snapshot, g_renderer.last_error, sizeof(error_snapshot) - 1);
    error_snapshot[sizeof(error_snapshot) - 1] = '\0';
    return error_snapshot;
}

extern "C" BOOL RAImGuiRenderer_Initialize(
    HWND hwnd,
    ID3D11Device* device,
    ID3D11DeviceContext* context,
    const RAImGuiRendererConfig* config) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (!InitializationInputsAreValidLocked(hwnd, device, context)) {
        return FALSE;
    }
    if (config != nullptr && config->struct_size < sizeof(RAImGuiRendererConfig)) {
        SetErrorLocked("renderer config has an incompatible struct_size");
        return FALSE;
    }
    if (g_renderer.state == RA_IMGUI_STATE_READY) {
        return g_renderer.hwnd == hwnd && g_renderer.device == device &&
               g_renderer.context == context ? TRUE : FALSE;
    }
    if (g_renderer.state != RA_IMGUI_STATE_UNINITIALIZED &&
        g_renderer.state != RA_IMGUI_STATE_SHUTDOWN) {
        SetErrorLocked("renderer must be shut down before reinitialization");
        return FALSE;
    }

    ClearErrorLocked();
    g_renderer.hwnd = hwnd;
    g_renderer.device = device;
    g_renderer.context = context;
    g_renderer.device->AddRef();
    g_renderer.context->AddRef();
    IMGUI_CHECKVERSION();
    g_renderer.imgui_context = ImGui::CreateContext();
    if (g_renderer.imgui_context == nullptr) {
        SetErrorLocked("ImGui::CreateContext failed");
        ShutdownLocked(RA_IMGUI_STATE_UNINITIALIZED);
        return FALSE;
    }
    SetCurrentContextLocked();
    ImGui::StyleColorsDark();
    if (!ImGui_ImplWin32_Init(hwnd)) {
        SetErrorLocked("ImGui_ImplWin32_Init failed");
        ShutdownLocked(RA_IMGUI_STATE_UNINITIALIZED);
        return FALSE;
    }
    g_renderer.win32_initialized = true;
    g_renderer.backend.reset(new (std::nothrow) D3D11RendererBackend());
    if (g_renderer.backend == nullptr) {
        SetErrorLocked("unable to allocate the D3D11 renderer backend");
        ShutdownLocked(RA_IMGUI_STATE_UNINITIALIZED);
        return FALSE;
    }
    const RendererBackendInitialization backend_initialization = {
        RA_IMGUI_API_D3D11, device, context};
    if (!g_renderer.backend->Initialize(backend_initialization)) {
        SetErrorLocked("ImGui_ImplDX11_Init failed");
        ShutdownLocked(RA_IMGUI_STATE_UNINITIALIZED);
        return FALSE;
    }
    g_renderer.capture_input = config != nullptr && config->capture_input != FALSE;
    if (config != nullptr && config->install_wndproc != FALSE && !InstallWndProcLocked()) {
        ShutdownLocked(RA_IMGUI_STATE_UNINITIALIZED);
        return FALSE;
    }
    g_renderer.state = RA_IMGUI_STATE_READY;
    return TRUE;
}

extern "C" BOOL RAImGuiRenderer_NewFrame(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state != RA_IMGUI_STATE_READY || g_renderer.backend == nullptr) {
        SetErrorLocked("NewFrame requires a ready renderer");
        return FALSE;
    }
    if (g_renderer.frame_started) {
        SetErrorLocked("NewFrame cannot begin before the prior frame is rendered");
        return FALSE;
    }
    const HRESULT removal_reason = g_renderer.device->GetDeviceRemovedReason();
    if (FAILED(removal_reason)) {
        DeviceRemovedLocked(removal_reason);
        return FALSE;
    }
    SetCurrentContextLocked();
    g_renderer.backend->NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    g_renderer.frame_started = true;
    return TRUE;
}

extern "C" BOOL RAImGuiRenderer_RenderDrawData(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state != RA_IMGUI_STATE_READY || !g_renderer.frame_started ||
        g_renderer.backend == nullptr) {
        SetErrorLocked("RenderDrawData requires a successful NewFrame");
        return FALSE;
    }
    SetCurrentContextLocked();
    ImGui::Render();
    g_renderer.backend->Render(ImGui::GetDrawData());
    g_renderer.frame_started = false;
    return TRUE;
}

extern "C" LRESULT RAImGuiRenderer_WndProcHandler(
    HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    return ProcessWndProcLocked(hwnd, message, wparam, lparam);
}

extern "C" BOOL RAImGuiRenderer_SetInputCapture(BOOL enabled) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (!g_renderer.win32_initialized) {
        SetErrorLocked("input capture requires an initialized Win32 backend");
        return FALSE;
    }
    g_renderer.capture_input = enabled != FALSE;
    return TRUE;
}

extern "C" BOOL RAImGuiRenderer_BeforeResizeBuffers(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state != RA_IMGUI_STATE_READY || g_renderer.backend == nullptr) {
        SetErrorLocked("BeforeResizeBuffers requires a ready renderer");
        return FALSE;
    }
    SetCurrentContextLocked();
    CancelFrameLocked();
    g_renderer.backend->InvalidateDeviceObjects();
    g_renderer.state = RA_IMGUI_STATE_RESIZE_INVALIDATED;
    return TRUE;
}

extern "C" BOOL RAImGuiRenderer_AfterResizeBuffers(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state != RA_IMGUI_STATE_RESIZE_INVALIDATED ||
        g_renderer.backend == nullptr) {
        SetErrorLocked("AfterResizeBuffers requires prior invalidation");
        return FALSE;
    }
    SetCurrentContextLocked();
    if (!g_renderer.backend->RecreateDeviceObjects()) {
        SetErrorLocked("ImGui_ImplDX11_CreateDeviceObjects failed after ResizeBuffers");
        return FALSE;
    }
    g_renderer.state = RA_IMGUI_STATE_READY;
    return TRUE;
}

extern "C" void RAImGuiRenderer_OnDeviceRemoved(HRESULT reason) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    DeviceRemovedLocked(reason);
}

extern "C" BOOL RAImGuiRenderer_OnDeviceRestored(
    ID3D11Device* device, ID3D11DeviceContext* context) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state != RA_IMGUI_STATE_DEVICE_LOST || device == nullptr ||
        context == nullptr || g_renderer.backend == nullptr) {
        SetErrorLocked("OnDeviceRestored requires device-lost state and non-null D3D11 objects");
        return FALSE;
    }
    if (!DeviceAndContextMatchLocked(device, context)) {
        return FALSE;
    }
    device->AddRef();
    context->AddRef();
    g_renderer.device = device;
    g_renderer.context = context;
    SetCurrentContextLocked();
    const RendererBackendInitialization backend_initialization = {
        RA_IMGUI_API_D3D11, device, context};
    if (!g_renderer.backend->Initialize(backend_initialization)) {
        ReleaseGraphicsReferencesLocked();
        SetErrorLocked("ImGui_ImplDX11_Init failed while restoring the device");
        return FALSE;
    }
    g_renderer.device_removed_reason = S_OK;
    g_renderer.state = RA_IMGUI_STATE_READY;
    ClearErrorLocked();
    return TRUE;
}

extern "C" BOOL RAImGuiRenderer_Shutdown(void) {
    std::lock_guard<std::recursive_mutex> lock(g_renderer.mutex);
    if (g_renderer.state == RA_IMGUI_STATE_UNINITIALIZED ||
        g_renderer.state == RA_IMGUI_STATE_SHUTDOWN) {
        g_renderer.state = RA_IMGUI_STATE_SHUTDOWN;
        return TRUE;
    }
    return ShutdownLocked(RA_IMGUI_STATE_SHUTDOWN) ? TRUE : FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}
'''


__all__ = [
    "EXPECTED_PLUGIN_EXPORTS",
    "ImGuiBuildRunner",
    "ImGuiHostContractError",
    "ImGuiHostOrchestrator",
    "ImGuiPathBoundaryError",
    "ImGuiRendererError",
    "ImGuiRendererProvider",
    "IMGUI_HOST_BRIDGE_PROTOCOL",
    "IMGUI_HOST_BRIDGE_PROTOCOL_VERSION",
    "IMGUI_HOST_LIFECYCLE",
    "REQUIRED_IMGUI_FILES",
    "RendererPluginInspection",
    "RendererPluginValidationError",
    "inspect_renderer_plugin",
    "inspect_renderer_plugin_bytes",
    "required_imgui_sources",
]
