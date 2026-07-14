"""Auditable hardware-identity snapshot and virtualization capability.

The built-in Windows transport is intentionally read-only and gathers identity
data through documented Windows APIs.  Identity changes are only delegated to
an explicitly configured transport that supplies a durable rollback receipt.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import threading
import uuid
from collections.abc import Mapping, Sequence
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


_SCHEMA_VERSION = "hardware-identity-capability/v1"
_HELPER_PROTOCOL_VERSION = 1
_MAX_HELPER_OUTPUT = 4 * 1024 * 1024
_SUPPORTED_ACTIONS = {"snapshot", "virtualize"}
_ACTION_ALIASES = {
    "capture": "snapshot",
    "inspect": "snapshot",
    "read": "snapshot",
    "apply": "virtualize",
    "change": "virtualize",
}
_SURFACES = ("machine_guid", "smbios", "volumes", "network_adapters")
_COMMON_PARAMETERS = {"surfaces"}
_VIRTUALIZE_PARAMETERS = {"changes", "change_id", "reason"}


class HardwareIdentityError(RuntimeError):
    """Base error for the hardware-identity provider."""


class HardwareIdentityUnavailable(HardwareIdentityError):
    """Raised when a required platform dependency or permission is missing."""


class HardwareIdentityTransport(Protocol):
    """Boundary implemented by real snapshot or virtualization transports."""

    name: str
    available: bool
    unavailable_reason: Optional[str]
    supports_mutation: bool

    def describe(self) -> Mapping[str, Any]: ...

    def snapshot(
        self,
        target: TargetIdentity,
        surfaces: Sequence[str],
    ) -> Mapping[str, Any]: ...

    def apply(
        self,
        target: TargetIdentity,
        changes: Mapping[str, Any],
        *,
        session_id: str,
        precondition_hash: str,
        change_id: str,
    ) -> Mapping[str, Any]: ...

    def rollback(
        self,
        target: TargetIdentity,
        receipt: Mapping[str, Any],
        *,
        session_id: str,
    ) -> Mapping[str, Any]: ...


class WindowsHardwareIdentityTransport:
    """Read public Windows identity surfaces without modifying the host."""

    name = "windows-public-identity"
    supports_mutation = False

    def __init__(
        self,
        *,
        platform_name: Optional[str] = None,
        volume_roots: Optional[Sequence[str]] = None,
    ) -> None:
        self.platform_name = str(platform_name or sys.platform).casefold()
        self.available = self.platform_name.startswith("win")
        self.unavailable_reason = (
            None
            if self.available
            else "Windows hardware identity APIs are unavailable on this platform"
        )
        self._volume_roots = tuple(volume_roots or ())

    def describe(self) -> Mapping[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "supports_snapshot": True,
            "supports_mutation": False,
            "platform": self.platform_name,
            "query_surfaces": list(_SURFACES),
            "production_transport": True,
        }

    def snapshot(
        self,
        target: TargetIdentity,
        surfaces: Sequence[str],
    ) -> Mapping[str, Any]:
        del target
        if not self.available:
            raise HardwareIdentityUnavailable(str(self.unavailable_reason))
        readers = {
            "machine_guid": self._read_machine_guid,
            "smbios": self._read_smbios,
            "volumes": self._read_volumes,
            "network_adapters": self._read_network_adapters,
        }
        identity: dict[str, Any] = {}
        surface_status: dict[str, dict[str, Any]] = {}
        for surface in surfaces:
            reader = readers[surface]
            try:
                value = reader()
                identity[surface] = value
                surface_status[surface] = {
                    "status": "ok",
                    "item_count": len(value) if isinstance(value, list) else 1,
                }
            except (OSError, PermissionError, HardwareIdentityError) as exc:
                surface_status[surface] = {
                    "status": "unavailable",
                    "reason": str(exc),
                }
            except Exception as exc:
                surface_status[surface] = {
                    "status": "failed",
                    "reason": f"{type(exc).__name__}: {exc}",
                }
        if not identity:
            reasons = "; ".join(
                str(item.get("reason") or name)
                for name, item in surface_status.items()
            )
            raise HardwareIdentityUnavailable(
                reasons or "no Windows hardware identity surface could be queried"
            )
        return {
            "identity": identity,
            "surface_status": surface_status,
            "source": "documented Windows public query APIs",
        }

    def apply(
        self,
        target: TargetIdentity,
        changes: Mapping[str, Any],
        *,
        session_id: str,
        precondition_hash: str,
        change_id: str,
    ) -> Mapping[str, Any]:
        del target, changes, session_id, precondition_hash, change_id
        raise HardwareIdentityUnavailable(
            "the built-in Windows transport is read-only; configure an explicit "
            "virtualization transport"
        )

    def rollback(
        self,
        target: TargetIdentity,
        receipt: Mapping[str, Any],
        *,
        session_id: str,
    ) -> Mapping[str, Any]:
        del target, receipt, session_id
        raise HardwareIdentityUnavailable(
            "the built-in Windows transport has no mutation to roll back"
        )

    @staticmethod
    def _read_machine_guid() -> str:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            access,
        ) as key:
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
        value = str(value).strip()
        if not value:
            raise HardwareIdentityUnavailable("MachineGuid is empty")
        return value

    @staticmethod
    def _read_smbios() -> Mapping[str, Any]:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_table = kernel32.GetSystemFirmwareTable
        get_table.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32]
        get_table.restype = ctypes.c_uint32
        provider = int.from_bytes(b"RSMB", "big")
        size = int(get_table(provider, 0, None, 0))
        if size <= 8:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size)
        written = int(get_table(provider, 0, buffer, size))
        if written != size:
            raise HardwareIdentityError(
                f"GetSystemFirmwareTable returned {written} bytes, expected {size}"
            )
        raw = bytes(buffer.raw[:written])
        return _parse_raw_smbios(raw)

    def _read_volumes(self) -> list[dict[str, Any]]:
        roots = list(self._volume_roots)
        if not roots:
            system_drive = str(os.environ.get("SystemDrive") or "C:")
            roots.append(system_drive.rstrip("\\/") + "\\")
        values = [self._read_volume(root) for root in sorted(set(roots), key=str.casefold)]
        return values

    @staticmethod
    def _read_volume(root: str) -> dict[str, Any]:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_info = kernel32.GetVolumeInformationW
        get_info.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        get_info.restype = ctypes.c_int
        label = ctypes.create_unicode_buffer(261)
        filesystem = ctypes.create_unicode_buffer(261)
        serial = ctypes.c_uint32()
        maximum_component = ctypes.c_uint32()
        flags = ctypes.c_uint32()
        ok = get_info(
            root,
            label,
            len(label),
            ctypes.byref(serial),
            ctypes.byref(maximum_component),
            ctypes.byref(flags),
            filesystem,
            len(filesystem),
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "root": root,
            "serial_number": f"{serial.value:08X}",
            "label": label.value,
            "file_system": filesystem.value,
            "file_system_flags": int(flags.value),
        }

    @staticmethod
    def _read_network_adapters() -> list[dict[str, Any]]:
        from ctypes import wintypes

        class AdapterAddresses(ctypes.Structure):
            pass

        adapter_pointer = ctypes.POINTER(AdapterAddresses)
        AdapterAddresses._fields_ = [
            ("Length", wintypes.ULONG),
            ("IfIndex", wintypes.DWORD),
            ("Next", adapter_pointer),
            ("AdapterName", ctypes.c_char_p),
            ("FirstUnicastAddress", ctypes.c_void_p),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.c_void_p),
            ("DnsSuffix", ctypes.c_wchar_p),
            ("Description", ctypes.c_wchar_p),
            ("FriendlyName", ctypes.c_wchar_p),
            ("PhysicalAddress", ctypes.c_ubyte * 8),
            ("PhysicalAddressLength", wintypes.DWORD),
            ("Flags", wintypes.DWORD),
            ("Mtu", wintypes.DWORD),
            ("IfType", wintypes.DWORD),
            ("OperStatus", ctypes.c_int),
            ("Ipv6IfIndex", wintypes.DWORD),
            ("ZoneIndices", wintypes.DWORD * 16),
            ("FirstPrefix", ctypes.c_void_p),
        ]
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        get_adapters = iphlpapi.GetAdaptersAddresses
        get_adapters.argtypes = [
            wintypes.ULONG,
            wintypes.ULONG,
            ctypes.c_void_p,
            adapter_pointer,
            ctypes.POINTER(wintypes.ULONG),
        ]
        get_adapters.restype = wintypes.ULONG
        size = wintypes.ULONG(15 * 1024)
        af_unspec = 0
        error_buffer_overflow = 111
        error_success = 0
        for _ in range(3):
            buffer = ctypes.create_string_buffer(size.value)
            result = int(
                get_adapters(
                    af_unspec,
                    0,
                    None,
                    ctypes.cast(buffer, adapter_pointer),
                    ctypes.byref(size),
                )
            )
            if result == error_success:
                break
            if result != error_buffer_overflow:
                raise OSError(result, "GetAdaptersAddresses failed")
        else:
            raise HardwareIdentityError("GetAdaptersAddresses buffer size did not stabilize")

        adapters: list[dict[str, Any]] = []
        current = ctypes.cast(buffer, adapter_pointer)
        visited: set[int] = set()
        while bool(current):
            address = int(ctypes.addressof(current.contents))
            if address in visited:
                raise HardwareIdentityError("GetAdaptersAddresses returned a cyclic list")
            visited.add(address)
            item = current.contents
            physical_length = min(int(item.PhysicalAddressLength), 8)
            physical = bytes(item.PhysicalAddress[:physical_length])
            adapters.append(
                {
                    "adapter_name": _decode_bytes(item.AdapterName),
                    "friendly_name": item.FriendlyName or "",
                    "description": item.Description or "",
                    "physical_address": "-".join(f"{part:02X}" for part in physical),
                    "if_index": int(item.IfIndex),
                    "ipv6_if_index": int(item.Ipv6IfIndex),
                    "if_type": int(item.IfType),
                    "oper_status": int(item.OperStatus),
                    "mtu": int(item.Mtu),
                }
            )
            current = item.Next
        adapters.sort(
            key=lambda item: (
                str(item.get("adapter_name") or "").casefold(),
                int(item.get("if_index") or 0),
            )
        )
        return adapters


class ExternalHardwareIdentityTransport:
    """Execute a versioned, allowlisted JSON helper transport.

    The helper receives exactly one JSON request on stdin and returns exactly
    one JSON response on stdout.  No shell is involved, and a mandatory SHA-256
    pin binds the provider to a reviewed helper binary.
    """

    name = "external-hardware-identity-helper"
    supports_mutation = True

    def __init__(
        self,
        executable: str | Path,
        *,
        expected_sha256: Optional[str] = None,
        timeout_seconds: float = 30.0,
        platform_name: Optional[str] = None,
    ) -> None:
        self.executable = Path(executable).expanduser().resolve()
        self.expected_sha256 = str(expected_sha256 or "").casefold() or None
        self.timeout_seconds = max(1.0, min(float(timeout_seconds), 300.0))
        self.platform_name = str(platform_name or sys.platform).casefold()
        self.available = False
        self.unavailable_reason: Optional[str] = None
        self._refresh_availability()

    def _refresh_availability(self) -> None:
        reasons: list[str] = []
        if not self.platform_name.startswith("win"):
            reasons.append("the hardware identity helper transport requires Windows")
        if not self.executable.is_file():
            reasons.append(f"helper executable is unavailable: {self.executable}")
        if not self.expected_sha256:
            reasons.append("a reviewed helper executable SHA-256 pin is required")
        elif (
            len(self.expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.expected_sha256)
        ):
            reasons.append("expected helper SHA-256 pin is invalid")
        elif self.executable.is_file():
            actual = _sha256_file(self.executable)
            if actual != self.expected_sha256:
                reasons.append("helper executable SHA-256 does not match the configured pin")
        self.available = not reasons
        self.unavailable_reason = "; ".join(reasons) or None

    def describe(self) -> Mapping[str, Any]:
        self._refresh_availability()
        return {
            "name": self.name,
            "available": self.available,
            "unavailable_reason": self.unavailable_reason,
            "supports_snapshot": True,
            "supports_mutation": True,
            "helper_path": str(self.executable),
            "helper_sha256": (
                _sha256_file(self.executable) if self.executable.is_file() else None
            ),
            "expected_sha256": self.expected_sha256,
            "protocol_version": _HELPER_PROTOCOL_VERSION,
            "production_transport": True,
        }

    def snapshot(
        self,
        target: TargetIdentity,
        surfaces: Sequence[str],
    ) -> Mapping[str, Any]:
        response = self._invoke(
            "snapshot",
            {"target": _target_payload(target), "surfaces": list(surfaces)},
        )
        snapshot = response.get("snapshot")
        if not isinstance(snapshot, Mapping) or not snapshot:
            raise HardwareIdentityError("helper snapshot response is missing snapshot data")
        return dict(snapshot)

    def apply(
        self,
        target: TargetIdentity,
        changes: Mapping[str, Any],
        *,
        session_id: str,
        precondition_hash: str,
        change_id: str,
    ) -> Mapping[str, Any]:
        response = self._invoke(
            "apply",
            {
                "target": _target_payload(target),
                "changes": _json_value(changes),
                "session_id": session_id,
                "precondition_hash": precondition_hash,
                "change_id": change_id,
            },
        )
        receipt = response.get("receipt")
        if not isinstance(receipt, Mapping) or not receipt:
            raise HardwareIdentityError("helper apply response is missing a rollback receipt")
        return dict(receipt)

    def rollback(
        self,
        target: TargetIdentity,
        receipt: Mapping[str, Any],
        *,
        session_id: str,
    ) -> Mapping[str, Any]:
        return self._invoke(
            "rollback",
            {
                "target": _target_payload(target),
                "receipt": _json_value(receipt),
                "session_id": session_id,
            },
        )

    def _invoke(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._refresh_availability()
        if not self.available:
            raise HardwareIdentityUnavailable(str(self.unavailable_reason))
        request = {
            "protocol_version": _HELPER_PROTOCOL_VERSION,
            "operation": operation,
            **dict(payload),
        }
        try:
            completed = subprocess.run(
                [str(self.executable)],
                input=json.dumps(request, sort_keys=True),
                text=True,
                encoding="utf-8",
                errors="strict",
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HardwareIdentityUnavailable(f"hardware identity helper failed: {exc}") from exc
        stdout = completed.stdout or ""
        if len(stdout.encode("utf-8")) > _MAX_HELPER_OUTPUT:
            raise HardwareIdentityError("hardware identity helper output exceeds the limit")
        try:
            response = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise HardwareIdentityError("hardware identity helper returned invalid JSON") from exc
        if not isinstance(response, Mapping):
            raise HardwareIdentityError("hardware identity helper response must be an object")
        if int(response.get("protocol_version") or 0) != _HELPER_PROTOCOL_VERSION:
            raise HardwareIdentityError("hardware identity helper protocol version mismatch")
        status = str(response.get("status") or "failed").casefold()
        if status in {"unavailable", "dependency-gated"}:
            raise HardwareIdentityUnavailable(
                str(response.get("error") or "hardware identity helper is unavailable")
            )
        if completed.returncode != 0 or status != "ok":
            raise HardwareIdentityError(
                str(
                    response.get("error")
                    or completed.stderr
                    or f"helper exited with code {completed.returncode}"
                )
            )
        return dict(response)


class HardwareIdentityProvider:
    """Capability provider for real snapshots and transport-backed changes."""

    capability_name = "hardware_identity_virtualization"
    provider_name = "hardware_identity_audited"
    priority = 30

    def __init__(
        self,
        transport: Optional[HardwareIdentityTransport] = None,
        *,
        allowed_output_roots: Optional[Sequence[str | Path]] = None,
    ) -> None:
        self.transport = transport or WindowsHardwareIdentityTransport()
        self._allowed_output_roots = [
            Path(item).expanduser().resolve() for item in (allowed_output_roots or [])
        ]
        self._sessions: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

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
        session_id = str(request.session_id or "hardware-identity-session")
        parameters, parameter_errors = _normalize_parameters(request.params, action)
        parameters["parameter_errors"] = parameter_errors
        target_payload = _target_payload(request.target)
        target_hash = _canonical_hash(target_payload)
        before = self._capture(request.target, parameters["surfaces"], phase="plan")
        identity_hash = str(before.get("identity_sha256") or "")
        parameters["target_identity_sha256"] = target_hash
        parameters["planned_identity_sha256"] = identity_hash
        transport = _transport_description(self.transport)
        transport_hash = _canonical_hash(transport)
        parameters["transport_identity_sha256"] = transport_hash
        precondition_hash = _precondition_hash(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            action=action,
            target_hash=target_hash,
            identity_hash=identity_hash,
            transport_hash=transport_hash,
            surfaces=parameters["surfaces"],
            changes=parameters.get("changes") or {},
            change_id=str(parameters.get("change_id") or ""),
        )
        before["precondition_hash"] = precondition_hash
        mutation = action == "virtualize"
        production_transport = bool(transport.get("production_transport"))
        rollback_plan = {
            "supported": bool(mutation and _transport_mutation_supported(self.transport)),
            "mode": "transport_receipt" if mutation else "not_required_read_only",
            "required": mutation,
            "completed": not mutation,
            "precondition_hash": precondition_hash,
            "before_identity_sha256": identity_hash,
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
            before_snapshot=before,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "schema_version": _SCHEMA_VERSION,
                "provider": self.provider_name,
                "transport": transport,
                "backend_class": transport.get("backend_class"),
                "target_identity_sha256": target_hash,
                "planned_identity_sha256": identity_hash,
                "precondition_hash": precondition_hash,
                "mutation_delegated_to_transport": mutation,
                "production_transport": production_transport,
                "mocked": not production_transport,
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

        def check(
            name: str,
            ok: bool,
            message: str,
            *,
            unavailable: bool = False,
            **details: Any,
        ) -> None:
            status = "ok" if ok else ("unavailable" if unavailable else "failed")
            checks.append(
                _prune({"name": name, "status": status, "message": message, **details})
            )
            if not ok:
                errors.append(message)

        check(
            "provider_identity",
            plan.capability == self.capability_name and plan.provider == self.provider_name,
            "plan capability/provider identity does not match this provider",
        )
        action = _normalize_action(plan.action)
        check(
            "action_allowlist",
            action in _SUPPORTED_ACTIONS,
            f"unsupported hardware identity action: {plan.action}",
            allowed_actions=sorted(_SUPPORTED_ACTIONS),
        )
        parameter_errors = [str(item) for item in plan.parameters.get("parameter_errors") or []]
        check(
            "parameters",
            not parameter_errors,
            "; ".join(parameter_errors) if parameter_errors else "parameters are normalized",
        )
        target_payload = _target_payload(plan.target)
        target_hash = _canonical_hash(target_payload)
        expected_target_hash = str(plan.parameters.get("target_identity_sha256") or "")
        check(
            "target_identity",
            bool(expected_target_hash and target_hash == expected_target_hash),
            "target identity changed after planning",
            expected=expected_target_hash,
            actual=target_hash,
        )
        target_anchored = any(
            target_payload.get(key) not in (None, "")
            for key in ("path", "pid", "sha256", "display_name")
        )
        check(
            "target_anchor",
            target_anchored,
            "target identity must include path, pid, sha256, or display_name",
        )
        transport = _transport_description(self.transport)
        transport_available = bool(transport.get("available"))
        current_transport_hash = _canonical_hash(transport)
        expected_transport_hash = str(
            plan.parameters.get("transport_identity_sha256") or ""
        )
        check(
            "transport_dependency",
            transport_available,
            str(
                transport.get("unavailable_reason")
                or "hardware identity transport is available"
            ),
            unavailable=not transport_available,
            transport=transport,
        )
        check(
            "transport_identity",
            bool(
                expected_transport_hash
                and current_transport_hash == expected_transport_hash
            ),
            "hardware identity transport changed after planning",
            expected=expected_transport_hash,
            actual=current_transport_hash,
        )
        if action == "virtualize":
            mutation_supported = _transport_mutation_supported(self.transport)
            check(
                "mutation_transport",
                mutation_supported,
                (
                    "explicit mutation transport is configured"
                    if mutation_supported
                    else "an explicit rollback-capable mutation transport is required"
                ),
                unavailable=not mutation_supported,
            )
            planned_identity = _json_mapping(plan.before_snapshot.get("identity"))
            planned_surface_status = _json_mapping(
                plan.before_snapshot.get("surface_status")
            )
            changed_surfaces = sorted(
                str(item) for item in _json_mapping(plan.parameters.get("changes"))
            )
            measurable = all(
                surface in planned_identity
                and (
                    surface not in planned_surface_status
                    or _json_mapping(planned_surface_status.get(surface)).get("status")
                    == "ok"
                )
                for surface in changed_surfaces
            )
            check(
                "change_surface_precondition",
                bool(changed_surfaces and measurable),
                "every changed identity surface must be measurable in the before snapshot",
                changed_surfaces=changed_surfaces,
            )
        expected_precondition = _precondition_hash(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            action=action,
            target_hash=expected_target_hash,
            identity_hash=str(plan.parameters.get("planned_identity_sha256") or ""),
            transport_hash=expected_transport_hash,
            surfaces=list(plan.parameters.get("surfaces") or []),
            changes=_json_mapping(plan.parameters.get("changes")),
            change_id=str(plan.parameters.get("change_id") or ""),
        )
        check(
            "plan_integrity",
            bool(plan.precondition_hash and plan.precondition_hash == expected_precondition),
            "plan precondition hash does not match the authorized request",
        )
        if transport_available:
            current = self._capture(
                plan.target,
                list(plan.parameters.get("surfaces") or []),
                phase="validate",
            )
            current_hash = str(current.get("identity_sha256") or "")
            planned_hash = str(plan.parameters.get("planned_identity_sha256") or "")
            capture_available = current.get("status") not in {"unavailable", "failed"}
            check(
                "identity_snapshot",
                capture_available,
                str(current.get("error") or "hardware identity snapshot is available"),
                unavailable=not capture_available,
                surface_status=current.get("surface_status"),
            )
            check(
                "precondition_state",
                bool(capture_available and planned_hash and current_hash == planned_hash),
                "hardware identity changed after planning",
                expected=planned_hash,
                actual=current_hash,
            )
            if current.get("status") == "partial":
                warnings.append("one or more hardware identity surfaces are unavailable")
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
        if not validation.ok:
            unavailable = any(
                item.get("status") == "unavailable" for item in validation.checks
            )
            return self._result(
                plan,
                validation,
                status="unavailable" if unavailable else "failed",
                before=_json_mapping(plan.before_snapshot),
                after={
                    "schema_version": _SCHEMA_VERSION,
                    "capture_phase": "execute",
                    "status": "blocked",
                    "side_effects": False,
                    "errors": list(validation.errors),
                },
                errors=list(validation.errors),
            )

        surfaces = list(plan.parameters.get("surfaces") or [])
        before = self._capture(plan.target, surfaces, phase="execute-before")
        planned_hash = str(plan.parameters.get("planned_identity_sha256") or "")
        if str(before.get("identity_sha256") or "") != planned_hash:
            return self._result(
                plan,
                validation,
                status="failed",
                before=before,
                after={
                    "schema_version": _SCHEMA_VERSION,
                    "capture_phase": "execute",
                    "status": "blocked",
                    "side_effects": False,
                    "error": "hardware identity changed immediately before execution",
                },
                errors=["hardware identity changed immediately before execution"],
            )
        if plan.action == "snapshot":
            after = dict(before)
            after["capture_phase"] = "after"
            status = "partial" if after.get("status") == "partial" else "ok"
            rollback_plan = {
                **dict(plan.rollback_plan),
                "supported": False,
                "completed": True,
                "status": "not_required_read_only",
            }
            return self._result(
                plan,
                validation,
                status=status,
                before=before,
                after=after,
                rollback_plan=rollback_plan,
                warnings=list(validation.warnings),
            )

        receipt: dict[str, Any] = {}
        changes = _json_mapping(plan.parameters.get("changes"))
        try:
            receipt = _json_mapping(
                self.transport.apply(
                    plan.target,
                    changes,
                    session_id=plan.session_id,
                    precondition_hash=str(plan.precondition_hash or ""),
                    change_id=str(plan.parameters.get("change_id") or ""),
                )
            )
            if not receipt:
                raise HardwareIdentityError("mutation transport returned no rollback receipt")
            after = self._capture(plan.target, surfaces, phase="after")
            if after.get("status") in {"unavailable", "failed"}:
                raise HardwareIdentityError("post-change identity snapshot is unavailable")
            if not _changes_match(_json_mapping(after.get("identity")), changes):
                raise HardwareIdentityError(
                    "post-change snapshot does not match the requested virtualization values"
                )
        except Exception as exc:
            rollback_details: dict[str, Any] = {}
            if receipt:
                rollback_details = self._attempt_rollback(
                    target=plan.target,
                    session_id=plan.session_id,
                    receipt=receipt,
                    before_identity_hash=planned_hash,
                    surfaces=surfaces,
                )
            after = self._capture(plan.target, surfaces, phase="failed-after")
            status = (
                "unavailable"
                if isinstance(exc, (HardwareIdentityUnavailable, PermissionError))
                else "failed"
            )
            rollback_plan = {
                **dict(plan.rollback_plan),
                "receipt": receipt,
                "completed": bool(rollback_details.get("ok")),
                "status": rollback_details.get("status") or "not_completed",
                "details": rollback_details,
            }
            return self._result(
                plan,
                validation,
                status=status,
                before=before,
                after=after,
                rollback_plan=rollback_plan,
                errors=[str(exc)],
            )

        rollback_plan = {
            **dict(plan.rollback_plan),
            "supported": True,
            "completed": False,
            "status": "pending",
            "receipt": receipt,
            "before_identity_sha256": planned_hash,
            "after_identity_sha256": after.get("identity_sha256"),
        }
        with self._lock:
            self._sessions[plan.session_id] = {
                "target": plan.target,
                "receipt": receipt,
                "surfaces": surfaces,
                "before_identity_sha256": planned_hash,
                "after_identity_sha256": after.get("identity_sha256"),
                "rolled_back": False,
            }
        return self._result(
            plan,
            validation,
            status="ok",
            before=before,
            after=after,
            rollback_plan=rollback_plan,
            warnings=list(validation.warnings),
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        if result.action != "virtualize":
            details = {"status": "not_required_read_only", "restored": False}
            result.rollback_plan.update({"completed": True, **details})
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details=details,
            )
        with self._lock:
            state = dict(self._sessions.get(result.session_id) or {})
        receipt = _json_mapping(state.get("receipt") or result.rollback_plan.get("receipt"))
        surfaces = list(state.get("surfaces") or result.before_snapshot.get("surfaces") or _SURFACES)
        before_hash = str(
            state.get("before_identity_sha256")
            or result.rollback_plan.get("before_identity_sha256")
            or result.before_snapshot.get("identity_sha256")
            or ""
        )
        after_hash = str(
            state.get("after_identity_sha256")
            or result.rollback_plan.get("after_identity_sha256")
            or result.after_snapshot.get("identity_sha256")
            or ""
        )
        if not receipt:
            details = {"status": "rollback_receipt_unavailable", "restored": False}
            return self._rollback_result(result, ok=False, restored=False, details=details)
        current = self._capture(result.target, surfaces, phase="rollback-before")
        current_hash = str(current.get("identity_sha256") or "")
        if current_hash and current_hash == before_hash:
            details = {
                "status": "already_restored",
                "restored": False,
                "identity_sha256": current_hash,
            }
            with self._lock:
                self._sessions.pop(result.session_id, None)
            return self._rollback_result(result, ok=True, restored=False, details=details)
        if not current_hash or current_hash != after_hash:
            details = {
                "status": "precondition_drift",
                "restored": False,
                "expected_after_identity_sha256": after_hash,
                "actual_identity_sha256": current_hash,
            }
            return self._rollback_result(result, ok=False, restored=False, details=details)
        details = self._attempt_rollback(
            target=result.target,
            session_id=result.session_id,
            receipt=receipt,
            before_identity_hash=before_hash,
            surfaces=surfaces,
        )
        ok = bool(details.get("ok"))
        with self._lock:
            if ok:
                self._sessions.pop(result.session_id, None)
        return self._rollback_result(
            result,
            ok=ok,
            restored=bool(details.get("restored")),
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
        payloads = {
            "hardware-identity-before": result.before_snapshot,
            "hardware-identity-after": result.after_snapshot,
            "hardware-identity-rollback": result.rollback_plan,
            "hardware-identity-provenance": result.provenance,
        }
        entries: list[dict[str, Any]] = []
        manifest_artifact = next(
            item for item in result.artifacts if item.kind == "evidence-manifest"
        )
        for artifact in result.artifacts:
            if artifact.kind == "evidence-manifest":
                continue
            if artifact.kind == "hardware-identity-audit":
                result.evidence_manifest_entries = list(entries)
                payload = _audit_payload(result)
            else:
                payload = payloads.get(artifact.kind)
            if payload is None:
                raise HardwareIdentityError(f"unsupported artifact kind: {artifact.kind}")
            encoded = _json_bytes(payload)
            destination = _artifact_destination(root, artifact.path)
            _atomic_write(destination, encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update(
                {"materialized": True, "sha256": digest, "size": len(encoded)}
            )
            entries.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "path": artifact.path,
                    "kind": artifact.kind,
                    "description": artifact.description,
                    "sha256": digest,
                    "size": len(encoded),
                    "capability": result.capability,
                    "provider": result.provider,
                    "session_id": result.session_id,
                    "action": result.action,
                    "status": result.status,
                    "target_identity_sha256": result.provenance.get(
                        "target_identity_sha256"
                    ),
                    "precondition_hash": result.provenance.get("precondition_hash"),
                    "backend_class": _json_mapping(
                        result.provenance.get("transport")
                    ).get("backend_class"),
                }
            )

        manifest_payload = {
            "schema_version": _SCHEMA_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "target_identity_sha256": result.provenance.get(
                "target_identity_sha256"
            ),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "entries": entries,
            "provenance": _json_mapping(result.provenance),
        }
        manifest_bytes = _json_bytes(manifest_payload)
        manifest_destination = _artifact_destination(root, manifest_artifact.path)
        _atomic_write(manifest_destination, manifest_bytes)
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_artifact.metadata.update(
            {
                "materialized": True,
                "sha256": manifest_digest,
                "size": len(manifest_bytes),
            }
        )
        manifest_entry = {
            "schema_version": _SCHEMA_VERSION,
            "path": manifest_artifact.path,
            "kind": manifest_artifact.kind,
            "description": manifest_artifact.description,
            "sha256": manifest_digest,
            "size": len(manifest_bytes),
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "action": result.action,
            "status": result.status,
            "target_identity_sha256": result.provenance.get(
                "target_identity_sha256"
            ),
            "precondition_hash": result.provenance.get("precondition_hash"),
            "backend_class": _json_mapping(result.provenance.get("transport")).get(
                "backend_class"
            ),
        }
        all_entries = [*entries, manifest_entry]
        result.evidence_manifest_entries = all_entries
        result.report_section["artifacts"] = [item.to_dict() for item in result.artifacts]
        result.report_section["evidence_manifest_entries"] = all_entries
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=list(result.artifacts),
            manifest_entries=all_entries,
        )

    def _capture(
        self,
        target: TargetIdentity,
        surfaces: Sequence[str],
        *,
        phase: str,
    ) -> dict[str, Any]:
        base = {
            "schema_version": _SCHEMA_VERSION,
            "capture_phase": phase,
            "captured_at": _utc_now(),
            "target_identity": _target_payload(target),
            "surfaces": list(surfaces),
            "transport": _transport_description(self.transport),
            "side_effects": False,
        }
        try:
            raw = _json_mapping(self.transport.snapshot(target, surfaces))
            identity = _json_mapping(raw.get("identity"))
            if not identity:
                identity = {
                    key: value
                    for key, value in raw.items()
                    if key not in {"surface_status", "source", "status", "captured_at"}
                }
            if not identity:
                raise HardwareIdentityUnavailable("transport returned an empty identity snapshot")
            surface_status = _json_mapping(raw.get("surface_status"))
            unavailable = [
                name
                for name, item in surface_status.items()
                if isinstance(item, Mapping) and item.get("status") != "ok"
            ]
            return {
                **base,
                "status": "partial" if unavailable else "ok",
                "identity": identity,
                "identity_sha256": _identity_hash(identity),
                "surface_status": surface_status,
                "source": raw.get("source"),
            }
        except (HardwareIdentityUnavailable, PermissionError, OSError) as exc:
            return {
                **base,
                "status": "unavailable",
                "error": str(exc),
                "identity": {},
                "identity_sha256": None,
            }
        except Exception as exc:
            return {
                **base,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "identity": {},
                "identity_sha256": None,
            }

    def _attempt_rollback(
        self,
        *,
        target: TargetIdentity,
        session_id: str,
        receipt: Mapping[str, Any],
        before_identity_hash: str,
        surfaces: Sequence[str],
    ) -> dict[str, Any]:
        try:
            transport_result = _json_mapping(
                self.transport.rollback(
                    target,
                    receipt,
                    session_id=session_id,
                )
            )
            snapshot = self._capture(target, surfaces, phase="rollback-after")
            actual_hash = str(snapshot.get("identity_sha256") or "")
            restored = bool(actual_hash and actual_hash == before_identity_hash)
            return {
                "ok": restored,
                "status": "restored" if restored else "verification_failed",
                "restored": restored,
                "transport_result": transport_result,
                "snapshot": snapshot,
                "expected_identity_sha256": before_identity_hash,
                "actual_identity_sha256": actual_hash,
            }
        except Exception as exc:
            return {
                "ok": False,
                "status": "rollback_failed",
                "restored": False,
                "error": str(exc),
            }

    def _rollback_result(
        self,
        result: CapabilityExecutionResult,
        *,
        ok: bool,
        restored: bool,
        details: Mapping[str, Any],
    ) -> CapabilityRollbackResult:
        result.rollback_plan.update(
            {
                "completed": ok,
                "status": details.get("status"),
                "restored": restored,
                "details": _json_mapping(details),
            }
        )
        result.report_section["rollback_plan"] = _json_mapping(result.rollback_plan)
        result.report_section["rollback"] = _json_mapping(details)
        result.dashboard_trace.append(
            {
                "kind": "hardware_identity_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "session_id": result.session_id,
                "status": details.get("status"),
                "restored": restored,
            }
        )
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=ok,
            restored=restored,
            details=_json_mapping(details),
        )

    def _result(
        self,
        plan: CapabilityPlan,
        validation: CapabilityValidation,
        *,
        status: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        rollback_plan: Optional[Mapping[str, Any]] = None,
        errors: Optional[Sequence[str]] = None,
        warnings: Optional[Sequence[str]] = None,
    ) -> CapabilityExecutionResult:
        artifacts = _artifacts(plan.session_id)
        planned_entries = [
            {
                "schema_version": _SCHEMA_VERSION,
                "path": item.path,
                "kind": item.kind,
                "description": item.description,
                "capability": plan.capability,
                "provider": plan.provider,
                "session_id": plan.session_id,
                "action": plan.action,
                "status": "planned",
            }
            for item in artifacts
        ]
        transport = _transport_description(self.transport)
        production_transport = bool(transport.get("production_transport"))
        effective_status = (
            "mocked" if status == "ok" and not production_transport else status
        )
        provenance = {
            **_json_mapping(plan.provenance),
            "schema_version": _SCHEMA_VERSION,
            "precondition_hash": plan.precondition_hash,
            "transport": transport,
            "backend_class": transport.get("backend_class"),
            "mutation_delegated_to_transport": plan.action == "virtualize",
            "production_transport": production_transport,
            "mocked": not production_transport,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
        }
        report = {
            "schema_version": _SCHEMA_VERSION,
            "title": "Hardware identity virtualization",
            "capability": plan.capability,
            "provider": plan.provider,
            "session_id": plan.session_id,
            "action": plan.action,
            "status": effective_status,
            "target_identity": _target_payload(plan.target),
            "validation": validation.to_dict(),
            "before_snapshot": _json_mapping(before),
            "after_snapshot": _json_mapping(after),
            "rollback_plan": _json_mapping(rollback_plan or plan.rollback_plan),
            "errors": list(errors or []),
            "warnings": list(warnings or []),
            "provenance": provenance,
        }
        return CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=effective_status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_json_mapping(before),
            after_snapshot=_json_mapping(after),
            rollback_plan=_json_mapping(rollback_plan or plan.rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=planned_entries,
            report_section=report,
            dashboard_trace=[
                {
                    "kind": "hardware_identity_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "session_id": plan.session_id,
                    "action": plan.action,
                    "status": effective_status,
                    "transport": transport.get("name"),
                    "mutation": plan.action == "virtualize",
                }
            ],
            provenance=provenance,
        )

    def _validate_output_root(self, root: Path) -> None:
        if self._allowed_output_roots and not any(
            root == allowed or allowed in root.parents for allowed in self._allowed_output_roots
        ):
            raise HardwareIdentityError(
                "artifact output directory is outside the configured roots"
            )


def _normalize_parameters(
    values: Optional[Mapping[str, Any]],
    action: str,
) -> tuple[dict[str, Any], list[str]]:
    raw = dict(values or {})
    errors: list[str] = []
    allowed = set(_COMMON_PARAMETERS)
    if action == "virtualize":
        allowed.update(_VIRTUALIZE_PARAMETERS)
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        errors.append("unsupported parameters: " + ", ".join(unknown))
    surfaces_value = raw.get("surfaces") or list(_SURFACES)
    if isinstance(surfaces_value, str):
        surfaces_value = [surfaces_value]
    if not isinstance(surfaces_value, Sequence):
        errors.append("surfaces must be a sequence")
        surfaces: list[str] = list(_SURFACES)
    else:
        surfaces = []
        for item in surfaces_value:
            surface = str(item).strip().casefold()
            if surface not in _SURFACES:
                errors.append(f"unsupported identity surface: {item}")
            elif surface not in surfaces:
                surfaces.append(surface)
        if not surfaces:
            errors.append("at least one identity surface is required")
    result: dict[str, Any] = {"surfaces": surfaces}
    if action == "virtualize":
        changes = _json_mapping(raw.get("changes"))
        if not changes:
            errors.append("virtualize requires a non-empty changes mapping")
        change_keys = set(changes)
        unknown_changes = sorted(change_keys - set(_SURFACES))
        if unknown_changes:
            errors.append("unsupported identity changes: " + ", ".join(unknown_changes))
        if changes and not _bounded_json(changes):
            errors.append("changes exceed the bounded JSON transport schema")
        change_id = str(raw.get("change_id") or "").strip()
        if not change_id:
            errors.append("virtualize requires a non-empty change_id")
        elif len(change_id) > 128:
            errors.append("change_id exceeds 128 characters")
        reason = str(raw.get("reason") or "").strip()
        if len(reason) > 1024:
            errors.append("reason exceeds 1024 characters")
        result.update(
            {"changes": changes, "change_id": change_id, "reason": reason}
        )
        for key in changes:
            if key not in surfaces:
                surfaces.append(key)
    return result, _deduplicate(errors)


def _plan_steps(action: str) -> list[dict[str, Any]]:
    steps = [
        {"step": "capture_before_snapshot", "side_effects": False},
        {"step": "validate_target_and_precondition", "side_effects": False},
    ]
    if action == "virtualize":
        steps.extend(
            [
                {"step": "delegate_to_explicit_transport", "side_effects": True},
                {"step": "capture_after_snapshot", "side_effects": False},
                {"step": "verify_requested_identity", "side_effects": False},
                {"step": "persist_rollback_receipt", "side_effects": False},
            ]
        )
    else:
        steps.append({"step": "persist_snapshot_evidence", "side_effects": False})
    return steps


def _precondition_hash(
    *,
    capability: str,
    provider: str,
    session_id: str,
    action: str,
    target_hash: str,
    identity_hash: str,
    transport_hash: str,
    surfaces: Sequence[str],
    changes: Mapping[str, Any],
    change_id: str,
) -> str:
    return _canonical_hash(
        {
            "capability": capability,
            "provider": provider,
            "session_id": session_id,
            "action": action,
            "target_identity_sha256": target_hash,
            "before_identity_sha256": identity_hash,
            "transport_identity_sha256": transport_hash,
            "surfaces": list(surfaces),
            "changes": _json_value(changes),
            "change_id": change_id,
        }
    )


def _identity_hash(identity: Mapping[str, Any]) -> str:
    stable = _stable_identity(identity)
    return _canonical_hash(stable)


def _stable_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    value = _json_mapping(identity)
    volumes = []
    for item in value.get("volumes") or []:
        if isinstance(item, Mapping):
            volumes.append(
                {
                    key: item.get(key)
                    for key in ("root", "serial_number", "file_system")
                    if item.get(key) is not None
                }
            )
    adapters = []
    for item in value.get("network_adapters") or []:
        if isinstance(item, Mapping):
            adapters.append(
                {
                    key: item.get(key)
                    for key in (
                        "adapter_name",
                        "physical_address",
                        "if_index",
                        "ipv6_if_index",
                        "if_type",
                    )
                    if item.get(key) is not None
                }
            )
    if "volumes" in value:
        value["volumes"] = sorted(volumes, key=_canonical_json)
    if "network_adapters" in value:
        value["network_adapters"] = sorted(adapters, key=_canonical_json)
    return value


def _changes_match(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    for key, expected_value in expected.items():
        if key not in actual or not _value_contains(actual[key], expected_value):
            return False
    return True


def _value_contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and _value_contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return False
        return all(_value_contains(left, right) for left, right in zip(actual, expected))
    return actual == expected


def _artifacts(session_id: str) -> list[CapabilityArtifact]:
    base = f"hardware_identity/{_safe_segment(session_id)}"
    return [
        CapabilityArtifact(
            path=f"{base}/before_snapshot.json",
            kind="hardware-identity-before",
            description="Hardware identity snapshot captured before execution",
        ),
        CapabilityArtifact(
            path=f"{base}/after_snapshot.json",
            kind="hardware-identity-after",
            description="Hardware identity snapshot captured after execution",
        ),
        CapabilityArtifact(
            path=f"{base}/rollback_plan.json",
            kind="hardware-identity-rollback",
            description="Rollback plan and transport receipt",
        ),
        CapabilityArtifact(
            path=f"{base}/provenance.json",
            kind="hardware-identity-provenance",
            description="Hardware identity plan, validation, and transport provenance",
        ),
        CapabilityArtifact(
            path=f"{base}/session.json",
            kind="hardware-identity-audit",
            description="Auditable hardware identity capability session",
        ),
        CapabilityArtifact(
            path=f"{base}/evidence-manifest.json",
            kind="evidence-manifest",
            description="Hardware identity evidence manifest",
        ),
    ]


def _audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    created_at = _utc_now()
    return {
        "schema_version": _SCHEMA_VERSION,
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
        "provenance": _json_mapping(result.provenance),
        "evidence_manifest_entries": list(result.evidence_manifest_entries or []),
        "report_section": _json_mapping(result.report_section),
        "dashboard_trace": list(result.dashboard_trace or []),
        "events": [
            {
                "kind": "plan",
                "ts": created_at,
                "message": "hardware identity capability plan created",
            },
            {
                "kind": "validate",
                "ts": created_at,
                "message": "hardware identity capability plan validated",
            },
            {
                "kind": "execute",
                "ts": created_at,
                "message": "hardware identity capability execution completed",
            },
        ],
    }


def _parse_raw_smbios(raw: bytes) -> dict[str, Any]:
    if len(raw) < 8:
        raise HardwareIdentityError("RawSMBIOSData header is truncated")
    table_length = int.from_bytes(raw[4:8], "little")
    table = raw[8 : 8 + table_length]
    if table_length <= 0 or len(table) != table_length:
        raise HardwareIdentityError("RawSMBIOSData table length is invalid")
    structures: dict[str, Any] = {}
    offset = 0
    structure_count = 0
    while offset + 4 <= len(table):
        structure_type = table[offset]
        length = table[offset + 1]
        if length < 4 or offset + length > len(table):
            break
        formatted = table[offset : offset + length]
        strings_start = offset + length
        end = strings_start
        while end + 1 < len(table) and table[end : end + 2] != b"\x00\x00":
            end += 1
        if end + 1 >= len(table):
            break
        strings = [
            item.decode("utf-8", errors="replace")
            for item in table[strings_start:end].split(b"\x00")
            if item
        ]
        structure_count += 1
        if structure_type == 0 and length >= 9:
            structures["bios"] = {
                "vendor": _smbios_string(strings, formatted[4]),
                "version": _smbios_string(strings, formatted[5]),
                "release_date": _smbios_string(strings, formatted[8]),
            }
        elif structure_type == 1 and length >= 8:
            system: dict[str, Any] = {
                "manufacturer": _smbios_string(strings, formatted[4]),
                "product_name": _smbios_string(strings, formatted[5]),
                "version": _smbios_string(strings, formatted[6]),
                "serial_number": _smbios_string(strings, formatted[7]),
            }
            if length >= 24:
                uuid_bytes = bytes(formatted[8:24])
                if uuid_bytes not in {b"\x00" * 16, b"\xff" * 16}:
                    system["uuid"] = str(uuid.UUID(bytes_le=uuid_bytes))
            structures["system"] = _prune(system)
        elif structure_type == 2 and length >= 9:
            structures["baseboard"] = _prune(
                {
                    "manufacturer": _smbios_string(strings, formatted[4]),
                    "product": _smbios_string(strings, formatted[5]),
                    "version": _smbios_string(strings, formatted[6]),
                    "serial_number": _smbios_string(strings, formatted[7]),
                    "asset_tag": _smbios_string(strings, formatted[8]),
                }
            )
        elif structure_type == 3 and length >= 9:
            structures["chassis"] = _prune(
                {
                    "manufacturer": _smbios_string(strings, formatted[4]),
                    "type": int(formatted[5] & 0x7F),
                    "version": _smbios_string(strings, formatted[6]),
                    "serial_number": _smbios_string(strings, formatted[7]),
                    "asset_tag": _smbios_string(strings, formatted[8]),
                }
            )
        offset = end + 2
        if structure_type == 127:
            break
    return {
        "smbios_version": f"{raw[1]}.{raw[2]}",
        "dmi_revision": int(raw[3]),
        "table_length": table_length,
        "structure_count": structure_count,
        "table_sha256": hashlib.sha256(table).hexdigest(),
        **structures,
    }


def _smbios_string(strings: Sequence[str], index: int) -> Optional[str]:
    if index <= 0 or index > len(strings):
        return None
    return strings[index - 1]


def _transport_description(transport: Any) -> dict[str, Any]:
    try:
        description = _json_mapping(transport.describe())
    except Exception as exc:
        description = {
            "name": getattr(transport, "name", type(transport).__name__),
            "available": False,
            "unavailable_reason": f"transport describe failed: {exc}",
        }
    description.setdefault("name", getattr(transport, "name", type(transport).__name__))
    description.setdefault("available", bool(getattr(transport, "available", False)))
    description.setdefault(
        "supports_mutation", bool(getattr(transport, "supports_mutation", False))
    )
    backend_class = _transport_backend_class(transport)
    description.update(
        {
            "backend_class": backend_class,
            "production_transport": backend_class.startswith("production-"),
            "test_double": backend_class == "test-double",
            "dependency_gated": backend_class == "dependency-gated",
        }
    )
    return description


def _transport_backend_class(transport: Any) -> str:
    """Classify concrete transports; describe() cannot self-attest production."""

    if type(transport) is WindowsHardwareIdentityTransport:
        if transport.available and transport.platform_name == "win32":
            return "production-readonly"
        return "dependency-gated"
    if type(transport) is ExternalHardwareIdentityTransport:
        if (
            transport.available
            and transport.platform_name == "win32"
            and transport.expected_sha256
            and transport.executable.is_file()
            and _sha256_file(transport.executable) == transport.expected_sha256
        ):
            return "production-helper"
        return "dependency-gated"
    return "test-double"


def _transport_mutation_supported(transport: Any) -> bool:
    description = _transport_description(transport)
    return bool(description.get("available") and description.get("supports_mutation"))


def _target_payload(target: Any) -> dict[str, Any]:
    if isinstance(target, TargetIdentity):
        return target.to_dict()
    return _json_mapping(target)


def _normalize_action(value: Any) -> str:
    action = str(value or "snapshot").strip().casefold().replace("-", "_")
    return _ACTION_ALIASES.get(action, action)


def _safe_segment(value: Any) -> str:
    raw = str(value or "session")
    safe = "".join(character if character.isalnum() or character in "-_." else "_" for character in raw)
    return safe[:128] or "session"


def _artifact_destination(root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise HardwareIdentityError("artifact path escapes the collection root")
    destination = (root / candidate).resolve()
    if destination != root and root not in destination.parents:
        raise HardwareIdentityError("artifact path escapes the collection root")
    return destination


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_bytes(value: Optional[bytes]) -> str:
    return value.decode("utf-8", errors="replace") if value else ""


def _bounded_json(value: Any, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, str):
        return len(value) <= 4096
    if isinstance(value, Mapping):
        return len(value) <= 128 and all(
            isinstance(key, str)
            and len(key) <= 128
            and _bounded_json(item, depth=depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return len(value) <= 1024 and all(
            _bounded_json(item, depth=depth + 1) for item in value
        )
    return False


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
    if isinstance(value, (list, tuple, set)):
        return [_json_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            _json_value(value),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _prune(item)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


def _deduplicate(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in values if str(item)))


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "ExternalHardwareIdentityTransport",
    "HardwareIdentityError",
    "HardwareIdentityProvider",
    "HardwareIdentityTransport",
    "HardwareIdentityUnavailable",
    "WindowsHardwareIdentityTransport",
]
