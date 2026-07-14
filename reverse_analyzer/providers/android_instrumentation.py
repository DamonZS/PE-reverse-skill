"""Frida-backed Android instrumentation capability provider.

The Frida binding is optional and imported only when the production backend is
constructed.  Plans remain deterministic without Frida, while execution
reports a real ``unavailable`` result instead of pretending that a device or
target was instrumented.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
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
_SCRIPT_SCHEMA_VERSION = 1
_DEFAULT_TIMEOUT_MS = 1_000
_MAX_TIMEOUT_MS = 300_000
_DEFAULT_DEVICE_TIMEOUT_MS = 5_000
_MAX_DEVICE_TIMEOUT_MS = 60_000
_DEFAULT_MAX_MESSAGES = 1_000
_MAX_MESSAGES = 10_000
_MAX_HOOKS = 64
_MAX_NATIVE_ARGUMENTS = 32
_MAX_SPAWN_ARGUMENTS = 64
_MAX_SCRIPT_BYTES = 2 * 1024 * 1024
_MAX_BINARY_MESSAGE_BYTES = 64 * 1024

_ATTACH = "attach"
_SPAWN = "spawn"
_MODE_ALIASES = {
    "attach": _ATTACH,
    "hook": _ATTACH,
    "instrument": _ATTACH,
    "trace": _ATTACH,
    "spawn": _SPAWN,
    "launch": _SPAWN,
    "run": _SPAWN,
}
_DEVICE_TYPES = {"usb", "local", "remote"}
_JAVA_HOOK = "java"
_NATIVE_HOOK = "native"
_HOOK_KIND_ALIASES = {
    "java": _JAVA_HOOK,
    "java_method": _JAVA_HOOK,
    "java-method": _JAVA_HOOK,
    "native": _NATIVE_HOOK,
    "native_export": _NATIVE_HOOK,
    "native-export": _NATIVE_HOOK,
}

_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*$")
_JAVA_CLASS_RE = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$"
)
_JAVA_METHOD_RE = re.compile(r"^(?:\$init|[A-Za-z_$][A-Za-z0-9_$]*)$")
_JAVA_TYPE_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*(?:\[\])*$")
_MODULE_RE = re.compile(r"^[A-Za-z0-9_.+\-]{1,260}$")
_EXPORT_RE = re.compile(r"^[A-Za-z_?$@#][A-Za-z0-9_?$@#.\-]{0,255}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:+@/\-]{1,128}$")
_NATIVE_ARGUMENT_TYPES = {
    "pointer",
    "utf8",
    "utf16",
    "int32",
    "uint32",
    "int64",
    "uint64",
    "hex",
    "bool",
}
_RUNTIME_ERROR_EVENTS = {
    "error",
    "hook_error",
    "hook-error",
    "script_error",
    "script-error",
}


class AndroidInstrumentationBackend(Protocol):
    """Backend surface used by the provider and device-free tests."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def select_device(self, options: Mapping[str, Any]) -> Any: ...

    def describe_device(self, device: Any) -> Mapping[str, Any]: ...

    def probe_target(
        self,
        device: Any,
        target: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def spawn(
        self,
        device: Any,
        package: str,
        options: Mapping[str, Any],
    ) -> int: ...

    def attach(self, device: Any, target: Any) -> Any: ...

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable[..., None],
    ) -> Any: ...

    def load_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...

    def resume(self, device: Any, pid: int) -> Optional[Mapping[str, Any]]: ...

    def wait(self, timeout_ms: int) -> None: ...

    def unload_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...

    def detach(self, session: Any) -> Optional[Mapping[str, Any]]: ...

    def describe_session(self, session: Any) -> Mapping[str, Any]: ...


class UnavailableAndroidInstrumentationBackend:
    """Backend used when the optional Frida Python binding cannot be loaded."""

    name = "frida"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def _raise(self) -> None:
        raise RuntimeError(self.unavailable_reason)

    def select_device(self, options: Mapping[str, Any]) -> Any:
        del options
        self._raise()

    def describe_device(self, device: Any) -> Mapping[str, Any]:
        del device
        self._raise()

    def probe_target(
        self,
        device: Any,
        target: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del device, target, options
        self._raise()

    def spawn(
        self,
        device: Any,
        package: str,
        options: Mapping[str, Any],
    ) -> int:
        del device, package, options
        self._raise()

    def attach(self, device: Any, target: Any) -> Any:
        del device, target
        self._raise()

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable[..., None],
    ) -> Any:
        del session, source, on_message
        self._raise()

    def load_script(self, script: Any) -> Optional[Mapping[str, Any]]:
        del script
        self._raise()

    def resume(self, device: Any, pid: int) -> Optional[Mapping[str, Any]]:
        del device, pid
        self._raise()

    def wait(self, timeout_ms: int) -> None:
        del timeout_ms
        self._raise()

    def unload_script(self, script: Any) -> Optional[Mapping[str, Any]]:
        del script
        self._raise()

    def detach(self, session: Any) -> Optional[Mapping[str, Any]]:
        del session
        self._raise()

    def describe_session(self, session: Any) -> Mapping[str, Any]:
        del session
        self._raise()


class FridaAndroidInstrumentationBackend:
    """Thin production adapter around Frida's Android device APIs."""

    name = "frida"

    def __init__(self, frida_module: Any = None) -> None:
        self._frida = frida_module
        self.available = False
        self.unavailable_reason: Optional[str] = None
        self.version: Optional[str] = None
        if self._frida is None:
            try:
                self._frida = importlib.import_module("frida")
            except Exception as exc:  # noqa: BLE001 - optional dependency boundary
                self.unavailable_reason = (
                    f"Frida Python binding is unavailable: {exc}"
                )
                return
        self.available = True
        self.version = str(getattr(self._frida, "__version__", "") or "") or None

    def select_device(self, options: Mapping[str, Any]) -> Any:
        self._require_available()
        device_type = str(options.get("device_type") or "usb")
        timeout_seconds = max(
            0.0,
            float(options.get("device_timeout_ms") or 0) / 1000.0,
        )
        device_id = str(options.get("device_id") or "").strip()

        manager = self._frida.get_device_manager()
        if device_id:
            return _call_with_optional_timeout(
                manager.get_device,
                device_id,
                timeout_seconds=timeout_seconds,
            )
        if device_type == "local":
            return self._frida.get_local_device()
        if device_type == "usb":
            return _call_with_optional_timeout(
                self._frida.get_usb_device,
                timeout_seconds=timeout_seconds,
            )
        if device_type == "remote":
            address = str(options.get("remote_address") or "").strip()
            if not address:
                raise ValueError("remote_address is required for a remote Frida device")
            return manager.add_remote_device(address)
        raise ValueError(f"unsupported Frida device type: {device_type}")

    def describe_device(self, device: Any) -> Mapping[str, Any]:
        return _prune(
            {
                "id": getattr(device, "id", None),
                "name": getattr(device, "name", None),
                "type": getattr(device, "type", None),
            }
        )

    def probe_target(
        self,
        device: Any,
        target: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        mode = str(options.get("mode") or _ATTACH)
        target_type = str(target.get("target_type") or "")
        package = str(target.get("package") or "").strip()
        process = str(target.get("process") or "").strip()
        pid = _positive_int(target.get("pid"))

        processes = list(device.enumerate_processes())
        process_match = None
        if pid is not None:
            process_match = next(
                (
                    item
                    for item in processes
                    if _positive_int(getattr(item, "pid", None)) == pid
                ),
                None,
            )
        else:
            name = process or package
            if name:
                process_match = next(
                    (
                        item
                        for item in processes
                        if str(getattr(item, "name", "") or "") == name
                    ),
                    None,
                )

        applications: list[Any] = []
        application_match = None
        if package:
            applications = list(device.enumerate_applications())
            application_match = next(
                (
                    item
                    for item in applications
                    if str(getattr(item, "identifier", "") or "") == package
                ),
                None,
            )
            app_pid = _positive_int(getattr(application_match, "pid", None))
            if process_match is None and app_pid is not None:
                process_match = next(
                    (
                        item
                        for item in processes
                        if _positive_int(getattr(item, "pid", None)) == app_pid
                    ),
                    application_match,
                )

        if mode == _SPAWN:
            exists = application_match is not None
        else:
            exists = process_match is not None
        resolved_pid = _positive_int(getattr(process_match, "pid", None))
        return _prune(
            {
                "status": "ok" if exists else "failed",
                "exists": exists,
                "accessible": exists,
                "running": process_match is not None,
                "mode": mode,
                "target_type": target_type,
                "package": package or None,
                "process": process or None,
                "pid": pid,
                "resolved_pid": resolved_pid,
                "resolved_name": (
                    getattr(process_match, "name", None)
                    if process_match is not None
                    else getattr(application_match, "name", None)
                ),
                "application_count": len(applications),
                "process_count": len(processes),
                "reason": None if exists else "Android package or process was not found",
            }
        )

    def spawn(
        self,
        device: Any,
        package: str,
        options: Mapping[str, Any],
    ) -> int:
        argv = [package, *[str(item) for item in options.get("spawn_argv", [])]]
        return int(device.spawn(argv))

    def attach(self, device: Any, target: Any) -> Any:
        return device.attach(target)

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable[..., None],
    ) -> Any:
        script = session.create_script(source)
        script.on("message", on_message)
        return script

    def load_script(self, script: Any) -> Mapping[str, Any]:
        script.load()
        return {"ok": True, "loaded": True}

    def resume(self, device: Any, pid: int) -> Mapping[str, Any]:
        device.resume(pid)
        return {"ok": True, "resumed": True, "pid": pid}

    def wait(self, timeout_ms: int) -> None:
        time.sleep(max(0, timeout_ms) / 1000.0)

    def unload_script(self, script: Any) -> Mapping[str, Any]:
        script.unload()
        return {"ok": True, "unloaded": True}

    def detach(self, session: Any) -> Mapping[str, Any]:
        session.detach()
        return {"ok": True, "detached": True}

    def describe_session(self, session: Any) -> Mapping[str, Any]:
        return _prune(
            {
                "pid": getattr(session, "pid", None),
                "persist_timeout": getattr(session, "persist_timeout", None),
            }
        )

    def _require_available(self) -> None:
        if not self.available:
            raise RuntimeError(self.unavailable_reason or "Frida is unavailable")


# Public aliases kept concise for callers that inject or inspect this backend.
FridaAndroidBackend = FridaAndroidInstrumentationBackend
AndroidFridaBackend = FridaAndroidInstrumentationBackend


class AndroidInstrumentationProvider:
    """Execute bounded Android Java/native hooks and close all Frida handles."""

    capability_name = "android_instrumentation"
    provider_name = "frida_android_instrumentation"
    priority = 10

    def __init__(
        self,
        backend: Optional[AndroidInstrumentationBackend] = None,
        *,
        timeout_ms: int = _DEFAULT_TIMEOUT_MS,
        device_timeout_ms: int = _DEFAULT_DEVICE_TIMEOUT_MS,
        max_messages: int = _DEFAULT_MAX_MESSAGES,
    ) -> None:
        self.backend: AndroidInstrumentationBackend = (
            backend if backend is not None else FridaAndroidInstrumentationBackend()
        )
        self.timeout_ms = _bounded_int(
            timeout_ms,
            minimum=0,
            maximum=_MAX_TIMEOUT_MS,
            default=_DEFAULT_TIMEOUT_MS,
        )
        self.device_timeout_ms = _bounded_int(
            device_timeout_ms,
            minimum=0,
            maximum=_MAX_DEVICE_TIMEOUT_MS,
            default=_DEFAULT_DEVICE_TIMEOUT_MS,
        )
        self.max_messages = _bounded_int(
            max_messages,
            minimum=1,
            maximum=_MAX_MESSAGES,
            default=_DEFAULT_MAX_MESSAGES,
        )

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _request_mode(request) in {_ATTACH, _SPAWN}
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        session_id = str(request.session_id or "android-instrumentation-session")
        mode = _request_mode(request)
        device = _device_config(
            request.params,
            default_timeout_ms=self.device_timeout_ms,
        )
        runtime_target = _runtime_target(request, mode)
        target_identity = _target_identity(request.target, runtime_target)
        timeout_requested = request.params.get(
            "timeout_ms",
            request.params.get("duration_ms", self.timeout_ms),
        )
        max_messages_requested = request.params.get(
            "max_messages",
            request.params.get("max_events", self.max_messages),
        )
        timeout_ms = _normalized_int(timeout_requested)
        max_messages = _normalized_int(max_messages_requested)
        spawn_argv = _normalize_spawn_argv(
            request.params.get("spawn_argv", request.params.get("target_args", []))
        )
        script = _prepare_script(request.params, context=context, session_id=session_id)

        integrity_payload = {
            "mode": mode,
            "device": device,
            "target": runtime_target,
            "target_identity": target_identity,
            "timeout_ms": timeout_ms,
            "max_messages": max_messages,
            "spawn_argv": spawn_argv,
            "script": _script_integrity_descriptor(script),
        }
        precondition_hash = _sha256_json(integrity_payload)
        backend_info = _backend_info(backend)
        parameters = {
            "requested_action": request.action,
            "mode": mode,
            "device": device,
            "device_type": device.get("device_type"),
            "device_id": device.get("device_id"),
            "remote_address": device.get("remote_address"),
            "device_timeout_ms": device.get("device_timeout_ms"),
            "target": runtime_target,
            "target_type": runtime_target.get("target_type"),
            "package": runtime_target.get("package"),
            "process": runtime_target.get("process"),
            "pid": runtime_target.get("pid"),
            "planned_target_identity": target_identity,
            "timeout_ms": timeout_ms,
            "requested_timeout_ms": _json_value(timeout_requested),
            "max_messages": max_messages,
            "requested_max_messages": _json_value(max_messages_requested),
            "spawn_argv": spawn_argv,
            "script": script,
            "script_source": script.get("source"),
            "script_path": script.get("path"),
            "script_sha256": script.get("sha256"),
            "hook_specs": script.get("hooks", []),
            "script_schema_version": _SCRIPT_SCHEMA_VERSION,
            "backend": backend_info,
        }
        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "plan",
            "session": {
                "id": session_id,
                "state": "planned",
                "attached": False,
                "script_loaded": False,
                "spawned": False,
                "resumed": False,
            },
            "device": device,
            "target_identity": target_identity,
            "runtime_target": runtime_target,
            "script": _public_script_descriptor(script),
            "messages": [],
            "backend": backend_info,
        }
        rollback_plan = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "supported": True,
            "mode": "execute_cleanup",
            "session_id": session_id,
            "active": False,
            "resume_required": False,
            "unload_required": False,
            "detach_required": False,
            "completed": False,
            "idempotent": True,
            "cross_process_supported": False,
            "order": ["resume_spawn", "unload_script", "detach_session"],
        }
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=mode,
            parameters=parameters,
            steps=_plan_steps(mode, script.get("source")),
            precondition_hash=precondition_hash,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "script_schema_version": _SCRIPT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "backend": backend_info,
                "requested_action": request.action,
                "mode": mode,
                "device": device,
                "target_identity": target_identity,
                "script_source": script.get("source"),
                "script_path": script.get("path"),
                "script_sha256": script.get("sha256"),
                "hook_specification_sha256": (
                    _sha256_json(script.get("hooks", []))
                    if script.get("source") == "generated"
                    else None
                ),
                "controlled_script": script.get("source") == "generated",
                "explicit_local_script": script.get("source") == "local_file",
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
        validation, runtime, source = self._validate_plan(plan, context=context)
        backend_info = _backend_info(backend)
        target_identity = _target_identity(
            plan.target,
            _json_mapping(plan.parameters.get("target")),
        )
        public_script = _public_script_descriptor(
            _json_mapping(plan.parameters.get("script"))
        )
        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "before",
            "session": {
                "id": plan.session_id,
                "state": "inactive",
                "attached": False,
                "script_loaded": False,
                "spawned": False,
                "resumed": False,
            },
            "device": _json_mapping(runtime.get("device_identity")),
            "device_request": _json_mapping(plan.parameters.get("device")),
            "target_identity": target_identity,
            "runtime_target": _json_mapping(plan.parameters.get("target")),
            "target_probe": _json_mapping(runtime.get("target_probe")),
            "script": public_script,
            "messages": [],
            "backend": backend_info,
            "validation": validation.to_dict(),
        }

        availability = str(runtime.get("availability") or "ok")
        if availability == "unavailable":
            reason = str(runtime.get("reason") or _backend_reason(backend))
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="unavailable",
                reason=reason,
            )
            after_snapshot = _inactive_after_snapshot(
                plan,
                target_identity=target_identity,
                device=_json_mapping(runtime.get("device_identity")),
                state="unavailable",
                rollback_plan=rollback_plan,
                reason=reason,
            )
            return self._execution_result(
                plan,
                status="unavailable",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                messages=[],
                errors=[reason],
                session=after_snapshot["session"],
                device=_json_mapping(runtime.get("device_identity")),
            )

        if not validation.ok or source is None:
            errors: list[Any] = list(validation.errors)
            if source is None and not errors:
                errors.append("instrumentation script could not be loaded or generated")
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="blocked",
                reason="execution was blocked by plan validation",
            )
            after_snapshot = _inactive_after_snapshot(
                plan,
                target_identity=target_identity,
                device=_json_mapping(runtime.get("device_identity")),
                state="blocked",
                rollback_plan=rollback_plan,
                reason="execution was blocked by plan validation",
            )
            return self._execution_result(
                plan,
                status="failed",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                messages=[],
                errors=errors,
                session=after_snapshot["session"],
                device=_json_mapping(runtime.get("device_identity")),
            )

        device_handle = runtime.get("device_handle")
        if device_handle is None:
            reason = "Frida backend returned no Android device handle"
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="unavailable",
                reason=reason,
            )
            after_snapshot = _inactive_after_snapshot(
                plan,
                target_identity=target_identity,
                device=_json_mapping(runtime.get("device_identity")),
                state="unavailable",
                rollback_plan=rollback_plan,
                reason=reason,
            )
            return self._execution_result(
                plan,
                status="unavailable",
                validation=validation,
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                messages=[],
                errors=[reason],
                session=after_snapshot["session"],
                device=_json_mapping(runtime.get("device_identity")),
            )

        max_messages = int(plan.parameters["max_messages"])
        timeout_ms = int(plan.parameters["timeout_ms"])
        messages: list[dict[str, Any]] = []
        dropped_messages = [0]

        def on_message(message: Any, data: Any = None) -> None:
            event = _normalize_message(message, data)
            if len(messages) < max_messages:
                messages.append(event)
            else:
                dropped_messages[0] += 1

        mode = str(plan.parameters.get("mode") or plan.action)
        target = _json_mapping(plan.parameters.get("target"))
        options = _runtime_options(plan)
        target_probe = _json_mapping(runtime.get("target_probe"))
        session_handle: Any = None
        script_handle: Any = None
        spawned_pid: Optional[int] = None
        resumed = False
        script_loaded = False
        session_identity: dict[str, Any] = {}
        errors = []
        try:
            if mode == _SPAWN:
                package = str(target.get("package") or "")
                spawned_pid = _positive_int(backend.spawn(device_handle, package, options))
                if spawned_pid is None:
                    raise RuntimeError("Frida backend returned an invalid spawned pid")
                attach_target: Any = spawned_pid
            else:
                attach_target = (
                    _positive_int(target_probe.get("resolved_pid"))
                    or _positive_int(target.get("pid"))
                    or target.get("process")
                    or target.get("package")
                )
                if attach_target in (None, ""):
                    raise RuntimeError("Android attach target could not be resolved")

            session_handle = backend.attach(device_handle, attach_target)
            if session_handle is None:
                raise RuntimeError("Frida backend returned no attached session handle")
            session_identity = _describe_backend_session(backend, session_handle)
            script_handle = backend.create_script(session_handle, source, on_message)
            if script_handle is None:
                raise RuntimeError("Frida backend returned no script handle")
            load_result = backend.load_script(script_handle)
            if not _backend_operation_ok(load_result):
                raise RuntimeError(
                    f"Frida script load failed: {_json_value(load_result)}"
                )
            script_loaded = True
            if spawned_pid is not None:
                resume_result = backend.resume(device_handle, spawned_pid)
                if not _backend_operation_ok(resume_result):
                    raise RuntimeError(
                        f"Frida spawned process resume failed: {_json_value(resume_result)}"
                    )
                resumed = True
            backend.wait(timeout_ms)
        except Exception as exc:  # noqa: BLE001 - backend failure is audit evidence
            errors.append(_exception_payload(exc))
        finally:
            cleanup = _cleanup_runtime(
                backend,
                device_handle=device_handle,
                spawned_pid=spawned_pid,
                resumed=resumed,
                script_handle=script_handle,
                session_handle=session_handle,
            )

        resumed = resumed or bool(cleanup.get("resumed"))
        runtime_errors = [
            item
            for item in messages
            if str(item.get("event") or item.get("message_type") or "").lower()
            in _RUNTIME_ERROR_EVENTS
        ]
        errors.extend(runtime_errors)
        if not cleanup.get("ok"):
            errors.append(
                {
                    "phase": "cleanup",
                    "message": "Android instrumentation cleanup did not complete",
                    "details": _json_mapping(cleanup),
                }
            )

        status = "ok" if not errors and cleanup.get("ok") else "failed"
        cleanup_ok = bool(cleanup.get("ok"))
        session_payload = {
            "id": plan.session_id,
            **session_identity,
            "state": "closed" if cleanup_ok else "cleanup_failed",
            "mode": mode,
            "pid": spawned_pid or target_probe.get("resolved_pid") or target.get("pid"),
            "attached": session_handle is not None and not cleanup.get("detached"),
            "script_loaded": (
                script_loaded
                and not cleanup.get("unloaded")
                and not cleanup.get("detached")
            ),
            "spawned": spawned_pid is not None,
            "resumed": resumed,
            "bounded_capture": True,
            "execution_succeeded": status == "ok",
        }
        rollback_plan = _completed_cleanup_plan(
            plan.rollback_plan,
            session_id=plan.session_id,
            cleanup=cleanup,
            execution_status=status,
        )
        after_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "after",
            "session": session_payload,
            "device": _json_mapping(runtime.get("device_identity")),
            "target_identity": target_identity,
            "runtime_target": target,
            "target_probe": target_probe,
            "script": public_script,
            "messages": messages,
            "message_count": len(messages),
            "dropped_message_count": dropped_messages[0],
            "script_sha256": _sha256_text(source),
            "cleanup": cleanup,
            "rollback": rollback_plan,
        }
        return self._execution_result(
            plan,
            status=status,
            validation=validation,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            messages=messages,
            errors=errors,
            session=session_payload,
            device=_json_mapping(runtime.get("device_identity")),
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        completed = bool(result.rollback_plan.get("completed"))
        if completed:
            status = "already_completed"
            reason = (
                "bounded Android instrumentation cleanup completed before execute "
                "returned; no Frida handles were persisted"
            )
        else:
            status = "failed"
            reason = (
                "Android instrumentation cleanup was incomplete and Frida handles "
                "were not persisted; cross-process rollback is unsupported"
            )
        details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "session_id": result.session_id,
            "idempotent": True,
            "cross_process_supported": False,
            "resume_attempted": False,
            "unload_attempted": False,
            "detach_attempted": False,
            "completed": completed,
            "reason": reason,
        }
        result.rollback_plan.update(
            {
                "active": False,
                "resume_required": False,
                "unload_required": False,
                "detach_required": False,
                "last_rollback_request": details,
            }
        )
        result.after_snapshot["rollback"] = _json_mapping(result.rollback_plan)
        result.report_section["rollback"] = _json_mapping(result.rollback_plan)
        result.report_section["rollback_plan"] = _json_mapping(result.rollback_plan)
        history = result.report_section.setdefault("rollback_history", [])
        if isinstance(history, list):
            history.append(details)
        result.dashboard_trace.append(
            {
                "kind": "android_instrumentation_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": status,
                "completed": completed,
            }
        )
        for artifact in result.artifacts:
            if artifact.kind == "android-instrumentation-rollback":
                artifact.metadata["rollback_status"] = status
                artifact.metadata["rollback_completed"] = completed
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=completed,
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
        collection_root = Path(out_dir).expanduser().resolve()
        collection_root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or _result_artifacts(result.session_id))
        entries_by_path = {
            str(item.get("path")): dict(item)
            for item in result.evidence_manifest_entries or []
            if item.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        payloads = _artifact_payloads(result)
        for artifact in artifacts:
            payload = payloads.get(artifact.kind)
            if payload is None:
                continue
            destination = _artifact_destination(collection_root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            encoded = (
                json.dumps(
                    payload,
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
                    "collection_root": str(collection_root),
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                }
            )
            entry = entries_by_path.get(
                artifact.path,
                _manifest_entry(
                    artifact,
                    status=result.status,
                    session_id=result.session_id,
                    target=result.target,
                    precondition_hash=result.provenance.get("precondition_hash"),
                ),
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
        _sync_report(result)
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
    ) -> tuple[CapabilityValidation, dict[str, Any], Optional[str]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []
        runtime: dict[str, Any] = {
            "availability": "ok",
            "target_probe": {
                "status": "not_probed",
                "reason": "static validation has not completed",
            },
        }

        def check(
            name: str,
            ok: bool,
            *,
            error: Optional[str] = None,
            status: Optional[str] = None,
            **details: Any,
        ) -> None:
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": status or ("ok" if ok else "failed"),
                        **details,
                    }
                )
            )
            if not ok and error:
                errors.append(error)

        check(
            "capability",
            plan.capability == self.capability_name,
            error=f"plan capability must be {self.capability_name}",
            actual=plan.capability,
        )
        check(
            "provider",
            plan.provider == self.provider_name,
            error=f"plan provider must be {self.provider_name}",
            actual=plan.provider,
        )
        check(
            "session_id",
            bool(plan.session_id) and len(str(plan.session_id)) <= 256,
            error="session_id must be a non-empty string of at most 256 characters",
        )

        mode = str(plan.parameters.get("mode") or plan.action or "")
        check(
            "mode",
            mode in {_ATTACH, _SPAWN} and plan.action == mode,
            error=f"unsupported or inconsistent Android instrumentation mode: {mode}",
            mode=mode,
            action=plan.action,
        )

        device = _json_mapping(plan.parameters.get("device"))
        device_errors = _device_errors(device)
        check(
            "device_config",
            not device_errors,
            error="; ".join(device_errors) if device_errors else None,
            device=device,
            errors=device_errors,
        )

        target = _json_mapping(plan.parameters.get("target"))
        target_errors = _runtime_target_errors(target, mode)
        target_identity = _target_identity(plan.target, target)
        planned_target_identity = _json_mapping(
            plan.parameters.get("planned_target_identity")
        )
        target_matches = target_identity == planned_target_identity
        check(
            "target_identity",
            not target_errors and target_matches,
            error=(
                "; ".join(target_errors)
                if target_errors
                else "target identity changed after planning"
                if not target_matches
                else None
            ),
            target=target_identity,
            runtime_target=target,
            matches_planned_identity=target_matches,
        )

        timeout_ms = plan.parameters.get("timeout_ms")
        max_messages = plan.parameters.get("max_messages")
        spawn_argv = plan.parameters.get("spawn_argv")
        timeout_ok = _integer_in_range(timeout_ms, 0, _MAX_TIMEOUT_MS)
        max_messages_ok = _integer_in_range(max_messages, 1, _MAX_MESSAGES)
        spawn_argv_ok = _valid_spawn_argv(spawn_argv)
        check(
            "timeout_ms",
            timeout_ok,
            error=f"timeout_ms must be an integer from 0 to {_MAX_TIMEOUT_MS}",
            actual=timeout_ms,
        )
        check(
            "max_messages",
            max_messages_ok,
            error=f"max_messages must be an integer from 1 to {_MAX_MESSAGES}",
            actual=max_messages,
        )
        check(
            "spawn_argv",
            spawn_argv_ok,
            error=(
                f"spawn_argv must contain at most {_MAX_SPAWN_ARGUMENTS} strings "
                "without NUL characters"
            ),
        )

        script = _json_mapping(plan.parameters.get("script"))
        source, script_errors = _validate_and_load_script(
            script,
            session_id=plan.session_id,
            max_messages=max_messages if isinstance(max_messages, int) else 1,
        )
        check(
            "instrumentation_script",
            not script_errors and source is not None,
            error="; ".join(script_errors) if script_errors else None,
            source=script.get("source"),
            path=script.get("path"),
            sha256=script.get("sha256"),
            errors=script_errors,
        )
        if script.get("source") == "generated":
            checks.append(
                {
                    "name": "restricted_hook_specification",
                    "status": "ok" if not script_errors else "failed",
                    "hook_count": len(script.get("hooks") or []),
                }
            )
        elif script.get("source") == "local_file":
            checks.append(
                {
                    "name": "explicit_local_script",
                    "status": "ok" if not script_errors else "failed",
                    "path": script.get("path"),
                    "sha256": script.get("sha256"),
                }
            )

        integrity_payload = {
            "mode": mode,
            "device": device,
            "target": target,
            "target_identity": target_identity,
            "timeout_ms": timeout_ms,
            "max_messages": max_messages,
            "spawn_argv": spawn_argv,
            "script": _script_integrity_descriptor(script),
        }
        expected_precondition = _sha256_json(integrity_payload)
        integrity_ok = (
            bool(plan.precondition_hash)
            and plan.precondition_hash == expected_precondition
        )
        check(
            "plan_integrity",
            integrity_ok,
            error=(
                "Android instrumentation precondition hash does not match its "
                "target, device, script, or runtime options"
            ),
            expected=expected_precondition,
            actual=plan.precondition_hash,
        )

        backend_info = _backend_info(backend)
        backend_available = _backend_available(backend)
        checks.append(
            {
                **backend_info,
                "name": "frida_backend",
                "status": "ok" if backend_available else "unavailable",
                "backend_name": backend_info.get("name"),
            }
        )
        if not backend_available:
            reason = _backend_reason(backend)
            warnings.append(reason)
            runtime.update(
                {
                    "availability": "unavailable",
                    "reason": reason,
                    "target_probe": {
                        "status": "unavailable",
                        "reason": reason,
                    },
                }
            )
            checks.append(
                {"name": "android_device", "status": "unavailable", "reason": reason}
            )
            checks.append(
                {"name": "target_probe", "status": "unavailable", "reason": reason}
            )
        elif errors:
            runtime["target_probe"] = {
                "status": "skipped",
                "reason": "static plan validation failed before device selection",
            }
            checks.append(
                {
                    "name": "android_device",
                    "status": "skipped",
                    "reason": runtime["target_probe"]["reason"],
                }
            )
            checks.append(
                {
                    "name": "target_probe",
                    "status": "skipped",
                    "reason": runtime["target_probe"]["reason"],
                }
            )
        else:
            try:
                device_handle = backend.select_device(device)
                if device_handle is None:
                    raise RuntimeError("Frida backend returned no Android device")
                device_identity = _describe_backend_device(backend, device_handle)
                runtime.update(
                    {
                        "device_handle": device_handle,
                        "device_identity": device_identity,
                    }
                )
                checks.append(
                    {
                        "name": "android_device",
                        "status": "ok",
                        "request": device,
                        "device": device_identity,
                    }
                )
            except Exception as exc:  # noqa: BLE001 - device absence is evidence
                reason = f"Android Frida device is unavailable: {exc}"
                warnings.append(reason)
                runtime.update(
                    {
                        "availability": "unavailable",
                        "reason": reason,
                        "target_probe": {
                            "status": "unavailable",
                            "reason": reason,
                            "error": _exception_payload(exc),
                        },
                    }
                )
                checks.append(
                    {
                        "name": "android_device",
                        "status": "unavailable",
                        "reason": reason,
                    }
                )
                checks.append(
                    {
                        "name": "target_probe",
                        "status": "unavailable",
                        "reason": reason,
                    }
                )
            else:
                try:
                    target_probe = _json_mapping(
                        backend.probe_target(device_handle, target, _runtime_options(plan))
                    )
                except Exception as exc:  # noqa: BLE001 - probe failure is evidence
                    target_probe = {
                        "status": "failed",
                        "exists": False,
                        "accessible": False,
                        "error": _exception_payload(exc),
                    }
                runtime["target_probe"] = target_probe
                target_ok = (
                    target_probe.get("status") == "ok"
                    and target_probe.get("exists") is not False
                    and target_probe.get("accessible") is not False
                )
                check(
                    "target_probe",
                    target_ok,
                    error=(
                        "Android package or process does not exist or is not accessible"
                    ),
                    probe=target_probe,
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
            runtime,
            source,
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        status: str,
        validation: CapabilityValidation,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        messages: list[dict[str, Any]],
        errors: list[Any],
        session: Mapping[str, Any],
        device: Mapping[str, Any],
    ) -> CapabilityExecutionResult:
        target_identity = _target_identity(
            plan.target,
            _json_mapping(plan.parameters.get("target")),
        )
        artifacts = _result_artifacts(plan.session_id)
        for artifact in artifacts:
            artifact.metadata.update(
                {
                    "target_identity": target_identity,
                    "precondition_hash": plan.precondition_hash,
                    "session_state": session.get("state"),
                    "rollback_completed": bool(rollback_plan.get("completed")),
                    "cross_process_rollback_supported": False,
                }
            )
        manifests = [
            _manifest_entry(
                artifact,
                status=status,
                session_id=plan.session_id,
                target=plan.target,
                precondition_hash=plan.precondition_hash,
            )
            for artifact in artifacts
        ]
        script = _json_mapping(plan.parameters.get("script"))
        provenance = {
            **_json_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "script_source": script.get("source"),
            "script_path": script.get("path"),
            "script_sha256": script.get("sha256"),
            "hook_specification_sha256": (
                _sha256_json(script.get("hooks", []))
                if script.get("source") == "generated"
                else None
            ),
            "message_count": len(messages),
            "controlled_script": script.get("source") == "generated",
            "explicit_local_script": script.get("source") == "local_file",
            "device": _json_mapping(device),
        }
        report_section = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "session_id": plan.session_id,
            "params": _json_mapping(plan.parameters),
            "session": _json_mapping(session),
            "device": _json_mapping(device),
            "target_identity": target_identity,
            "runtime_target": _json_mapping(plan.parameters.get("target")),
            "precondition_hash": plan.precondition_hash,
            "script": _public_script_descriptor(script),
            "hook_specification": list(script.get("hooks") or []),
            "messages": messages,
            "events": messages,
            "before": _json_mapping(before_snapshot),
            "after": _json_mapping(after_snapshot),
            "rollback": _json_mapping(rollback_plan),
            "before_snapshot": _json_mapping(before_snapshot),
            "after_snapshot": _json_mapping(after_snapshot),
            "rollback_plan": _json_mapping(rollback_plan),
            "provenance": provenance,
            "artifacts": [item.to_dict() for item in artifacts],
            "evidence_manifest_entries": manifests,
            "validation": validation.to_dict(),
            "errors": [_json_value(item) for item in errors],
        }
        return CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_json_mapping(before_snapshot),
            after_snapshot=_json_mapping(after_snapshot),
            rollback_plan=_json_mapping(rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=manifests,
            report_section=report_section,
            dashboard_trace=[
                {
                    "kind": "android_instrumentation_execution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "session_id": plan.session_id,
                    "mode": plan.action,
                    "status": status,
                    "message_count": len(messages),
                    "target": target_identity,
                    "device": _json_mapping(device),
                }
            ],
            provenance=provenance,
        )

    def _select_backend(
        self,
        context: Optional[dict[str, Any]],
    ) -> AndroidInstrumentationBackend:
        if isinstance(context, Mapping):
            for key in (
                "android_instrumentation_backend",
                "frida_android_backend",
            ):
                backend = context.get(key)
                if backend is not None:
                    return backend
        return self.backend


def render_android_instrumentation_script(
    hooks: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    *,
    session_id: str = "android-instrumentation",
    max_messages: int = _DEFAULT_MAX_MESSAGES,
) -> str:
    """Render a deterministic Frida script from validated Java/native hooks."""

    if isinstance(hooks, Mapping):
        raw_hooks: Any = hooks.get("hooks", [hooks])
    else:
        raw_hooks = hooks
    normalized = _normalize_hook_specs(raw_hooks)
    errors = _hook_specification_errors(normalized)
    if errors:
        raise ValueError("; ".join(errors))
    if not _integer_in_range(max_messages, 1, _MAX_MESSAGES):
        raise ValueError(f"max_messages must be between 1 and {_MAX_MESSAGES}")
    payload = json.dumps(
        {
            "schema_version": _SCRIPT_SCHEMA_VERSION,
            "session_id": str(session_id),
            "max_messages": int(max_messages),
            "hooks": normalized,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return f"""'use strict';
const SPEC = {payload};
let emitted = 0;

function emit(payload) {{
  if (emitted >= SPEC.max_messages) return;
  emitted += 1;
  payload.session_id = SPEC.session_id;
  payload.sequence = emitted;
  send(payload);
}}

function safeValue(value, typeName) {{
  try {{
    if (typeName === 'utf8') return value.isNull() ? null : value.readUtf8String(4096);
    if (typeName === 'utf16') return value.isNull() ? null : value.readUtf16String(2048);
    if (typeName === 'int32') return value.toInt32();
    if (typeName === 'uint32') return value.toUInt32();
    if (typeName === 'bool') return !value.isNull();
    return value === null || value === undefined ? null : value.toString();
  }} catch (error) {{
    return {{error: String(error)}};
  }}
}}

function installJava(spec) {{
  Java.perform(function () {{
    try {{
      const klass = Java.use(spec.class_name);
      const method = klass[spec.method_name];
      const overloads = spec.overload.length > 0
        ? [method.overload.apply(method, spec.overload)]
        : method.overloads;
      overloads.forEach(function (implementation) {{
        implementation.implementation = function () {{
          const args = Array.prototype.slice.call(arguments);
          const captured = spec.capture_args ? args.map(function (item) {{
            try {{ return String(item); }} catch (error) {{ return '<unreadable>'; }}
          }}) : [];
          const retval = implementation.apply(this, args);
          emit({{
            event: 'java_call',
            hook_kind: 'java',
            label: spec.label,
            class_name: spec.class_name,
            method_name: spec.method_name,
            arguments: captured,
            return_value: spec.capture_return ? String(retval) : null
          }});
          return retval;
        }};
      }});
      emit({{
        event: 'hook_installed',
        hook_kind: 'java',
        label: spec.label,
        class_name: spec.class_name,
        method_name: spec.method_name,
        overload_count: overloads.length
      }});
    }} catch (error) {{
      emit({{event: 'hook_error', hook_kind: 'java', label: spec.label, error: String(error)}});
    }}
  }});
}}

function installNative(spec) {{
  try {{
    let address = null;
    if (spec.address !== null && spec.address !== undefined) address = ptr(spec.address);
    else if (spec.export_name !== null && spec.export_name !== undefined) address = Module.findExportByName(spec.module, spec.export_name);
    else {{
      const base = Module.findBaseAddress(spec.module);
      if (base !== null) address = base.add(spec.offset);
    }}
    if (address === null) throw new Error('native hook address was not found');
    Interceptor.attach(address, {{
      onEnter(args) {{
        this.captured = spec.capture_args ? spec.arguments.map(function (argument) {{
          return {{name: argument.name, index: argument.index, value: safeValue(args[argument.index], argument.type)}};
        }}) : [];
      }},
      onLeave(retval) {{
        emit({{
          event: 'native_call',
          hook_kind: 'native',
          label: spec.label,
          module: spec.module,
          export_name: spec.export_name,
          address: address.toString(),
          arguments: this.captured || [],
          return_value: spec.capture_return ? retval.toString() : null
        }});
      }}
    }});
    emit({{
      event: 'hook_installed',
      hook_kind: 'native',
      label: spec.label,
      module: spec.module,
      export_name: spec.export_name,
      address: address.toString()
    }});
  }} catch (error) {{
    emit({{event: 'hook_error', hook_kind: 'native', label: spec.label, error: String(error)}});
  }}
}}

setImmediate(function () {{
  SPEC.hooks.forEach(function (hook) {{
    if (hook.kind === 'java') installJava(hook);
    else installNative(hook);
  }});
}});
"""


# Backwards-friendly concise name for callers that only need script rendering.
render_android_hook_script = render_android_instrumentation_script


def _request_mode(request: CapabilityRequest) -> str:
    requested = request.params.get("mode", request.action)
    return _MODE_ALIASES.get(str(requested or "").strip().lower(), str(requested or "").strip().lower())


def _device_config(
    params: Mapping[str, Any],
    *,
    default_timeout_ms: int,
) -> dict[str, Any]:
    raw_device = params.get("device", params.get("device_type", "usb"))
    if isinstance(raw_device, Mapping):
        device_type = raw_device.get("type", raw_device.get("device_type", "usb"))
        device_id = raw_device.get("id", raw_device.get("device_id"))
        remote_address = raw_device.get(
            "address",
            raw_device.get("remote_address", raw_device.get("host")),
        )
        timeout = raw_device.get(
            "timeout_ms",
            raw_device.get("device_timeout_ms", params.get("device_timeout_ms", default_timeout_ms)),
        )
    else:
        device_type = raw_device
        device_id = params.get("device_id")
        remote_address = params.get("remote_address", params.get("remote_host"))
        timeout = params.get("device_timeout_ms", default_timeout_ms)
    return _prune(
        {
            "device_type": str(device_type or "usb").strip().lower(),
            "device_id": _optional_text(device_id),
            "remote_address": _optional_text(remote_address),
            "device_timeout_ms": _normalized_int(timeout),
        }
    )


def _device_errors(device: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    device_type = str(device.get("device_type") or "")
    if device_type not in _DEVICE_TYPES:
        errors.append(f"device_type must be one of {sorted(_DEVICE_TYPES)}")
    if device_type == "remote" and not str(device.get("remote_address") or "").strip():
        errors.append("remote_address is required for a remote Frida device")
    address = str(device.get("remote_address") or "")
    if address and ("\x00" in address or len(address) > 512):
        errors.append("remote_address must be at most 512 characters without NUL")
    device_id = str(device.get("device_id") or "")
    if device_id and ("\x00" in device_id or len(device_id) > 256):
        errors.append("device_id must be at most 256 characters without NUL")
    if not _integer_in_range(
        device.get("device_timeout_ms"),
        0,
        _MAX_DEVICE_TIMEOUT_MS,
    ):
        errors.append(
            f"device_timeout_ms must be an integer from 0 to {_MAX_DEVICE_TIMEOUT_MS}"
        )
    return errors


def _runtime_target(request: CapabilityRequest, mode: str) -> dict[str, Any]:
    metadata = _json_mapping(request.target.metadata)
    params = request.params
    pid = _positive_int(params.get("pid")) or _positive_int(request.target.pid)
    package = _first_text(
        params.get("package"),
        params.get("package_name"),
        metadata.get("package"),
        metadata.get("package_name"),
    )
    process = _first_text(
        params.get("process"),
        params.get("process_name"),
        metadata.get("process"),
        metadata.get("process_name"),
    )
    kind = str(request.target.kind or "").strip().lower()
    display_name = _optional_text(request.target.display_name)
    path = _optional_text(request.target.path)
    if kind in {"android_package", "package", "application", "app"}:
        package = package or display_name
        if not package and path and not path.lower().endswith(".apk"):
            package = path
    elif kind in {"process", "android_process"}:
        process = process or display_name
    elif mode == _SPAWN:
        package = package or display_name
    elif pid is None:
        process = process or display_name or package

    if mode == _SPAWN or package and not process and pid is None:
        target_type = "package"
    else:
        target_type = "process"
    return _prune(
        {
            "target_type": target_type,
            "package": package,
            "process": process,
            "pid": pid,
        }
    )


def _runtime_target_errors(target: Mapping[str, Any], mode: str) -> list[str]:
    errors: list[str] = []
    target_type = str(target.get("target_type") or "")
    package = str(target.get("package") or "")
    process = str(target.get("process") or "")
    pid = target.get("pid")
    if target_type not in {"package", "process"}:
        errors.append("target_type must be package or process")
    if package and not _PACKAGE_RE.fullmatch(package):
        errors.append("package must be a valid Android application identifier")
    if process and (len(process) > 256 or "\x00" in process):
        errors.append("process must be at most 256 characters without NUL")
    if pid is not None and _positive_int(pid) is None:
        errors.append("pid must be a positive integer")
    if mode == _SPAWN and not package:
        errors.append("spawn mode requires an Android package target")
    if mode == _ATTACH and pid is None and not process and not package:
        errors.append("attach mode requires a package, process name, or pid")
    return errors


def _target_identity(
    target: TargetIdentity,
    runtime_target: Mapping[str, Any],
) -> dict[str, Any]:
    payload = target.to_dict()
    metadata = _json_mapping(payload.get("metadata"))
    metadata.update(
        {
            key: runtime_target.get(key)
            for key in ("target_type", "package", "process")
            if runtime_target.get(key) not in (None, "")
        }
    )
    payload["kind"] = str(target.kind or runtime_target.get("target_type") or "android_target")
    if target.pid is None and runtime_target.get("pid") is not None:
        payload["pid"] = runtime_target.get("pid")
    if not payload.get("display_name"):
        payload["display_name"] = (
            runtime_target.get("package") or runtime_target.get("process")
        )
    payload["metadata"] = metadata
    payload.update(
        {
            key: runtime_target.get(key)
            for key in ("target_type", "package", "process")
            if runtime_target.get(key) not in (None, "")
        }
    )
    return _prune(payload)


def _prepare_script(
    params: Mapping[str, Any],
    *,
    context: Optional[Mapping[str, Any]],
    session_id: str,
) -> dict[str, Any]:
    forbidden_inline_fields = {"javascript", "script", "script_source", "source"}
    custom_script_supplied = any(
        key in params for key in forbidden_inline_fields
    )
    custom_script_error = (
        "inline JavaScript is not accepted; use structured hook specifications "
        "or an explicit local script_path"
    )
    raw_path = _first_text(
        params.get("script_path"),
        params.get("script_file"),
        params.get("local_script"),
    )
    raw_hooks = _raw_hook_specs(params)
    if raw_path:
        descriptor: dict[str, Any] = {
            "source": "local_file",
            "requested_path": raw_path,
            "hooks": [],
        }
        descriptor_errors: list[str] = []
        if custom_script_supplied:
            descriptor_errors.append(custom_script_error)
        if raw_hooks:
            descriptor_errors.append(
                "script_path and structured hook specifications are mutually exclusive"
            )
        try:
            path = _resolve_local_script_path(raw_path, context)
            descriptor["path"] = str(path)
            source = _read_local_script(path)
            descriptor.update(
                {
                    "sha256": _sha256_text(source),
                    "size": len(source.encode("utf-8")),
                }
            )
        except (OSError, ValueError, UnicodeError) as exc:
            descriptor["path"] = str(
                _resolve_local_script_path(raw_path, context, require_local=False)
            )
            descriptor_errors.append(str(exc))
        if descriptor_errors:
            descriptor["error"] = "; ".join(_deduplicate(descriptor_errors))
        return descriptor

    hooks = _normalize_hook_specs(raw_hooks)
    descriptor = {
        "source": "generated",
        "hooks": hooks,
        "path": None,
    }
    errors = []
    if custom_script_supplied:
        errors.append(custom_script_error)
    errors.extend(_hook_specification_errors(hooks))
    if errors:
        descriptor["error"] = "; ".join(errors)
        return descriptor
    try:
        source = render_android_instrumentation_script(
            hooks,
            session_id=session_id,
            max_messages=_bounded_int(
                params.get("max_messages", params.get("max_events", _DEFAULT_MAX_MESSAGES)),
                minimum=1,
                maximum=_MAX_MESSAGES,
                default=_DEFAULT_MAX_MESSAGES,
            ),
        )
    except ValueError as exc:
        descriptor["error"] = str(exc)
        return descriptor
    descriptor.update(
        {
            "sha256": _sha256_text(source),
            "size": len(source.encode("utf-8")),
        }
    )
    return descriptor


def _raw_hook_specs(params: Mapping[str, Any]) -> list[Any]:
    result: list[Any] = []
    hooks = params.get("hooks", params.get("hook_specs", params.get("hook_spec")))
    if isinstance(hooks, Mapping) and isinstance(hooks.get("hooks"), Sequence):
        hooks = hooks.get("hooks")
    if isinstance(hooks, Mapping):
        result.append(hooks)
    elif isinstance(hooks, Sequence) and not isinstance(hooks, (str, bytes, bytearray)):
        result.extend(hooks)
    for key, kind in (("java_hooks", _JAVA_HOOK), ("native_hooks", _NATIVE_HOOK)):
        values = params.get(key)
        if isinstance(values, Mapping):
            values = [values]
        if isinstance(values, Sequence) and not isinstance(values, (str, bytes, bytearray)):
            for item in values:
                if isinstance(item, Mapping):
                    result.append({"kind": kind, **dict(item)})
                else:
                    result.append(item)
    if not result and any(key in params for key in ("kind", "type", "class", "class_name", "module")):
        result.append(params)
    return result


def _normalize_hook_specs(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            normalized.append(
                {
                    "kind": "invalid",
                    "label": f"hook-{index}",
                    "invalid_value": _json_value(item),
                }
            )
            continue
        kind = _HOOK_KIND_ALIASES.get(
            str(item.get("kind", item.get("type", ""))).strip().lower(),
            str(item.get("kind", item.get("type", ""))).strip().lower(),
        )
        if not kind:
            kind = _JAVA_HOOK if item.get("class") or item.get("class_name") else _NATIVE_HOOK
        label = _optional_text(item.get("label")) or f"{kind}-hook-{index}"
        if kind == _JAVA_HOOK:
            allowed = {
                "kind", "type", "class", "class_name", "method", "method_name",
                "overload", "argument_types", "args", "capture_args",
                "capture_return", "label",
            }
            overload = item.get("overload", item.get("argument_types", item.get("args", [])))
            if not isinstance(overload, Sequence) or isinstance(overload, (str, bytes, bytearray)):
                overload = [overload] if overload not in (None, "") else []
            hook = _prune(
                {
                    "kind": kind,
                    "label": label,
                    "class_name": _optional_text(item.get("class_name", item.get("class"))),
                    "method_name": _optional_text(item.get("method_name", item.get("method"))),
                    "capture_args": _normalize_bool(item.get("capture_args", True)),
                    "capture_return": _normalize_bool(item.get("capture_return", True)),
                    "unknown_fields": sorted(set(item) - allowed),
                }
            )
            hook["overload"] = [str(entry).strip() for entry in overload]
            normalized.append(hook)
        elif kind == _NATIVE_HOOK:
            allowed = {
                "kind", "type", "module", "module_name", "export", "export_name",
                "name", "function", "address", "offset", "arguments", "args",
                "capture_args", "capture_return", "label",
            }
            arguments = _normalize_native_arguments(item.get("arguments", item.get("args", [])))
            hook = _prune(
                {
                    "kind": kind,
                    "label": label,
                    "module": _optional_text(item.get("module", item.get("module_name"))),
                    "export_name": _optional_text(
                        item.get("export_name", item.get("export", item.get("function", item.get("name"))))
                    ),
                    "address": _normalize_address(item.get("address")),
                    "offset": _normalize_offset(item.get("offset")),
                    "capture_args": _normalize_bool(item.get("capture_args", True)),
                    "capture_return": _normalize_bool(item.get("capture_return", True)),
                    "unknown_fields": sorted(set(item) - allowed),
                }
            )
            hook["arguments"] = arguments
            normalized.append(hook)
        else:
            normalized.append(
                {
                    "kind": kind or "invalid",
                    "label": label,
                    "unknown_fields": sorted(set(item) - {"kind", "type", "label"}),
                }
            )
    return normalized


def _normalize_native_arguments(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        value = list(range(max(0, value)))
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return value
    result: list[dict[str, Any]] = []
    for position, item in enumerate(value):
        if isinstance(item, Mapping):
            index = _normalized_int(item.get("index", position))
            name = _optional_text(item.get("name")) or f"arg{position}"
            argument_type = str(item.get("type") or "pointer").strip().lower()
        else:
            index = _normalized_int(item)
            name = f"arg{position}"
            argument_type = "pointer"
        result.append(
            {
                "name": name,
                "index": index,
                "type": argument_type,
            }
        )
    return result


def _hook_specification_errors(hooks: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(hooks, Sequence) or isinstance(hooks, (str, bytes, bytearray)):
        return ["hooks must be a sequence"]
    if not hooks:
        return ["at least one Java or native hook specification is required"]
    if len(hooks) > _MAX_HOOKS:
        errors.append(f"at most {_MAX_HOOKS} hook specifications are allowed")
    for index, hook in enumerate(hooks):
        if not isinstance(hook, Mapping):
            errors.append(f"hooks[{index}] must be a mapping")
            continue
        prefix = f"hooks[{index}]"
        kind = str(hook.get("kind") or "")
        label = str(hook.get("label") or "")
        unknown = list(hook.get("unknown_fields") or [])
        if unknown:
            errors.append(f"{prefix} contains unsupported fields: {', '.join(unknown)}")
        if not _LABEL_RE.fullmatch(label):
            errors.append(f"{prefix}.label is invalid")
        if kind == _JAVA_HOOK:
            class_name = str(hook.get("class_name") or "")
            method_name = str(hook.get("method_name") or "")
            overload = hook.get("overload")
            if not _JAVA_CLASS_RE.fullmatch(class_name):
                errors.append(f"{prefix}.class_name is invalid")
            if not _JAVA_METHOD_RE.fullmatch(method_name):
                errors.append(f"{prefix}.method_name is invalid")
            if not isinstance(overload, list) or any(
                not isinstance(item, str) or not _JAVA_TYPE_RE.fullmatch(item)
                for item in overload or []
            ):
                errors.append(f"{prefix}.overload must contain valid Java type names")
            for key in ("capture_args", "capture_return"):
                if not isinstance(hook.get(key), bool):
                    errors.append(f"{prefix}.{key} must be a boolean")
        elif kind == _NATIVE_HOOK:
            module = hook.get("module")
            export_name = hook.get("export_name")
            address = hook.get("address")
            offset = hook.get("offset")
            if module is not None and not _MODULE_RE.fullmatch(str(module)):
                errors.append(f"{prefix}.module is invalid")
            if export_name is not None and not _EXPORT_RE.fullmatch(str(export_name)):
                errors.append(f"{prefix}.export_name is invalid")
            selectors = sum(
                value is not None for value in (export_name, address, offset)
            )
            if selectors != 1:
                errors.append(
                    f"{prefix} requires exactly one export_name, address, or offset"
                )
            if export_name is not None and module is None:
                errors.append(f"{prefix}.module is required with export_name")
            if offset is not None and module is None:
                errors.append(f"{prefix}.module is required with offset")
            if address is not None and _positive_int(_parse_address(address)) is None:
                errors.append(f"{prefix}.address must be a positive address")
            if offset is not None and _parse_offset(offset) is None:
                errors.append(f"{prefix}.offset must be a non-negative integer")
            arguments = hook.get("arguments")
            errors.extend(_native_argument_errors(arguments, prefix=prefix))
            for key in ("capture_args", "capture_return"):
                if not isinstance(hook.get(key), bool):
                    errors.append(f"{prefix}.{key} must be a boolean")
        else:
            errors.append(f"{prefix}.kind must be java or native")
    return errors


def _native_argument_errors(value: Any, *, prefix: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{prefix}.arguments must be a list"]
    errors: list[str] = []
    if len(value) > _MAX_NATIVE_ARGUMENTS:
        errors.append(
            f"{prefix}.arguments may contain at most {_MAX_NATIVE_ARGUMENTS} entries"
        )
    seen: set[int] = set()
    for position, item in enumerate(value):
        item_prefix = f"{prefix}.arguments[{position}]"
        if not isinstance(item, Mapping):
            errors.append(f"{item_prefix} must be a mapping")
            continue
        index = item.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < _MAX_NATIVE_ARGUMENTS:
            errors.append(f"{item_prefix}.index is out of range")
        elif index in seen:
            errors.append(f"{item_prefix}.index is duplicated")
        else:
            seen.add(index)
        name = str(item.get("name") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name):
            errors.append(f"{item_prefix}.name is invalid")
        if str(item.get("type") or "") not in _NATIVE_ARGUMENT_TYPES:
            errors.append(f"{item_prefix}.type is unsupported")
    return errors


def _validate_and_load_script(
    script: Mapping[str, Any],
    *,
    session_id: str,
    max_messages: int,
) -> tuple[Optional[str], list[str]]:
    errors: list[str] = []
    if script.get("error"):
        errors.append(str(script.get("error")))
    source_kind = str(script.get("source") or "")
    source: Optional[str] = None
    if source_kind == "generated":
        hooks = script.get("hooks")
        errors.extend(_hook_specification_errors(hooks))
        if not errors:
            try:
                source = render_android_instrumentation_script(
                    hooks,
                    session_id=session_id,
                    max_messages=max_messages,
                )
            except ValueError as exc:
                errors.append(str(exc))
    elif source_kind == "local_file":
        path_value = str(script.get("path") or "")
        if not path_value:
            errors.append("local script path is missing")
        else:
            try:
                path = Path(path_value)
                if not path.is_absolute():
                    raise ValueError("planned local script path must be absolute")
                source = _read_local_script(path)
            except (OSError, ValueError, UnicodeError) as exc:
                errors.append(str(exc))
    else:
        errors.append("script source must be generated or local_file")

    actual_hash = _sha256_text(source) if source is not None else None
    if source is not None and actual_hash != script.get("sha256"):
        errors.append("instrumentation script changed after planning")
    if source is not None and len(source.encode("utf-8")) != script.get("size"):
        errors.append("instrumentation script size changed after planning")
    return source, _deduplicate(errors)


def _resolve_local_script_path(
    value: str,
    context: Optional[Mapping[str, Any]],
    *,
    require_local: bool = True,
) -> Path:
    text = str(value).strip()
    if require_local and (
        "://" in text or text.lower().startswith(("data:", "javascript:"))
    ):
        raise ValueError("script_path must reference a local file")
    path = Path(text).expanduser()
    if not path.is_absolute():
        root_value: Any = None
        if isinstance(context, Mapping):
            root_value = context.get("script_root", context.get("workspace_root"))
        root = Path(str(root_value)).expanduser() if root_value else Path.cwd()
        path = root / path
    return path.resolve()


def _read_local_script(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"local Frida script does not exist: {path}")
    size = path.stat().st_size
    if size > _MAX_SCRIPT_BYTES:
        raise ValueError(
            f"local Frida script exceeds the {_MAX_SCRIPT_BYTES}-byte limit"
        )
    return path.read_text(encoding="utf-8-sig")


def _public_script_descriptor(script: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "source": script.get("source"),
            "path": script.get("path"),
            "requested_path": script.get("requested_path"),
            "sha256": script.get("sha256"),
            "size": script.get("size"),
            "hook_count": len(script.get("hooks") or []),
            "hooks": list(script.get("hooks") or []),
            "error": script.get("error"),
        }
    )


def _script_integrity_descriptor(script: Mapping[str, Any]) -> dict[str, Any]:
    return _prune(
        {
            "source": script.get("source"),
            "path": script.get("path"),
            "sha256": script.get("sha256"),
            "size": script.get("size"),
            "hooks": script.get("hooks"),
            "error": script.get("error"),
        }
    )


def _runtime_options(plan: CapabilityPlan) -> dict[str, Any]:
    device = _json_mapping(plan.parameters.get("device"))
    return {
        **device,
        "mode": plan.parameters.get("mode"),
        "timeout_ms": plan.parameters.get("timeout_ms"),
        "max_messages": plan.parameters.get("max_messages"),
        "spawn_argv": list(plan.parameters.get("spawn_argv") or []),
    }


def _cleanup_runtime(
    backend: AndroidInstrumentationBackend,
    *,
    device_handle: Any,
    spawned_pid: Optional[int],
    resumed: bool,
    script_handle: Any,
    session_handle: Any,
) -> dict[str, Any]:
    cleanup: dict[str, Any] = {
        "resume_attempted": False,
        "resume_required": spawned_pid is not None,
        "resume_completed": resumed or spawned_pid is None,
        "resumed": resumed,
        "unload_attempted": False,
        "unloaded": script_handle is None,
        "detach_attempted": False,
        "detached": session_handle is None,
        "errors": [],
    }
    if spawned_pid is not None and not resumed:
        cleanup["resume_attempted"] = True
        try:
            result = backend.resume(device_handle, spawned_pid)
            cleanup["resumed"] = _backend_operation_ok(result)
            cleanup["resume_completed"] = cleanup["resumed"]
            cleanup["resume_result"] = _json_value(result)
            if not cleanup["resumed"]:
                cleanup["errors"].append(
                    {"phase": "resume", "message": "backend did not confirm resume"}
                )
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            cleanup["errors"].append(
                {"phase": "resume", **_exception_payload(exc)}
            )
    if script_handle is not None:
        cleanup["unload_attempted"] = True
        try:
            result = backend.unload_script(script_handle)
            cleanup["unloaded"] = _backend_operation_ok(result)
            cleanup["unload_result"] = _json_value(result)
            if not cleanup["unloaded"]:
                cleanup["errors"].append(
                    {"phase": "unload", "message": "backend did not confirm unload"}
                )
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            cleanup["errors"].append(
                {"phase": "unload", **_exception_payload(exc)}
            )
    if session_handle is not None:
        cleanup["detach_attempted"] = True
        try:
            result = backend.detach(session_handle)
            cleanup["detached"] = _backend_operation_ok(result)
            cleanup["detach_result"] = _json_value(result)
            if not cleanup["detached"]:
                cleanup["errors"].append(
                    {"phase": "detach", "message": "backend did not confirm detach"}
                )
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            cleanup["errors"].append(
                {"phase": "detach", **_exception_payload(exc)}
            )
    cleanup["ok"] = bool(
        cleanup["resume_completed"]
        and cleanup["unloaded"]
        and cleanup["detached"]
        and not cleanup["errors"]
    )
    return _prune(cleanup)


def _inactive_rollback_plan(
    rollback_plan: Mapping[str, Any],
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    return {
        **_json_mapping(rollback_plan),
        "supported": True,
        "active": False,
        "resume_required": False,
        "unload_required": False,
        "detach_required": False,
        "completed": True,
        "status": status,
        "idempotent": True,
        "cross_process_supported": False,
        "reason": reason,
        "cleanup": {
            "ok": True,
            "resumed": True,
            "unloaded": True,
            "detached": True,
            "not_started": True,
        },
    }


def _completed_cleanup_plan(
    rollback_plan: Mapping[str, Any],
    *,
    session_id: str,
    cleanup: Mapping[str, Any],
    execution_status: str,
) -> dict[str, Any]:
    completed = bool(cleanup.get("ok"))
    return {
        **_json_mapping(rollback_plan),
        "supported": True,
        "mode": "execute_cleanup",
        "session_id": session_id,
        "active": False,
        "resume_required": False,
        "unload_required": False,
        "detach_required": False,
        "completed": completed,
        "status": "completed" if completed else "cleanup_failed",
        "execution_status": execution_status,
        "idempotent": True,
        "cross_process_supported": False,
        "cleanup": _json_mapping(cleanup),
    }


def _inactive_after_snapshot(
    plan: CapabilityPlan,
    *,
    target_identity: Mapping[str, Any],
    device: Mapping[str, Any],
    state: str,
    rollback_plan: Mapping[str, Any],
    reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capture_phase": "after",
        "session": {
            "id": plan.session_id,
            "state": state,
            "attached": False,
            "script_loaded": False,
            "spawned": False,
            "resumed": False,
        },
        "device": _json_mapping(device),
        "target_identity": _json_mapping(target_identity),
        "runtime_target": _json_mapping(plan.parameters.get("target")),
        "messages": [],
        "message_count": 0,
        "rollback": _json_mapping(rollback_plan),
        "reason": reason,
    }


def _normalize_message(message: Any, data: Any = None) -> dict[str, Any]:
    if isinstance(message, Mapping):
        message_type = str(message.get("type") or "message")
        payload = message.get("payload")
        if isinstance(payload, Mapping):
            event = dict(payload)
        else:
            event = {"payload": _json_value(payload)}
        event.setdefault("message_type", message_type)
        if message_type == "error":
            event.setdefault("event", "script_error")
            for key in ("description", "stack", "fileName", "lineNumber", "columnNumber"):
                if message.get(key) not in (None, ""):
                    event[key] = _json_value(message.get(key))
    else:
        event = {"message_type": "message", "payload": _json_value(message)}
    event.setdefault("event", "message")
    event["captured_at"] = _utc_now()
    if data is not None:
        event["data"] = _binary_message(data)
    return _prune(_json_mapping(event))


def _binary_message(value: Any) -> dict[str, Any]:
    try:
        encoded = bytes(value)
    except Exception:
        return {"value": _json_value(value)}
    retained = encoded[:_MAX_BINARY_MESSAGE_BYTES]
    return {
        "encoding": "base64",
        "value": base64.b64encode(retained).decode("ascii"),
        "size": len(encoded),
        "retained_size": len(retained),
        "truncated": len(retained) != len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _result_artifacts(session_id: str) -> list[CapabilityArtifact]:
    segment = _safe_segment(session_id)
    root = f"android_instrumentation/{segment}"
    return [
        CapabilityArtifact(
            path=f"{root}/audit.json",
            kind="android-instrumentation-audit",
            description="Android instrumentation lifecycle audit",
        ),
        CapabilityArtifact(
            path=f"{root}/events.json",
            kind="android-instrumentation-events",
            description="Messages emitted by the bounded Frida script",
        ),
        CapabilityArtifact(
            path=f"{root}/rollback.json",
            kind="android-instrumentation-rollback",
            description="Script unload, spawn resume, and session detach evidence",
        ),
    ]


def _artifact_payloads(result: CapabilityExecutionResult) -> dict[str, dict[str, Any]]:
    report = _json_mapping(result.report_section)
    common = {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "status": result.status,
        "action": result.action,
        "target_identity": report.get("target_identity") or result.target.to_dict(),
        "precondition_hash": result.provenance.get("precondition_hash"),
    }
    return {
        "android-instrumentation-audit": {
            **common,
            "device": report.get("device", {}),
            "runtime_target": report.get("runtime_target", {}),
            "script": report.get("script", {}),
            "before_snapshot": _json_mapping(result.before_snapshot),
            "after_snapshot": _json_mapping(result.after_snapshot),
            "rollback_plan": _json_mapping(result.rollback_plan),
            "provenance": _json_mapping(result.provenance),
            "validation": report.get("validation", {}),
            "messages": list(report.get("messages") or []),
            "errors": list(report.get("errors") or []),
        },
        "android-instrumentation-events": {
            **common,
            "message_count": len(report.get("messages") or []),
            "dropped_message_count": result.after_snapshot.get(
                "dropped_message_count", 0
            ),
            "events": list(report.get("messages") or []),
        },
        "android-instrumentation-rollback": {
            **common,
            "rollback_plan": _json_mapping(result.rollback_plan),
            "rollback_history": list(report.get("rollback_history") or []),
            "cleanup": _json_mapping(result.rollback_plan.get("cleanup")),
        },
    }


def _manifest_entry(
    artifact: CapabilityArtifact,
    *,
    status: str,
    session_id: str,
    target: TargetIdentity,
    precondition_hash: Any,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": artifact.kind,
        "description": artifact.description,
        "status": status,
        "session_id": session_id,
        "target_identity": target.to_dict(),
        "precondition_hash": precondition_hash,
        "materialized": False,
    }


def _artifact_destination(collection_root: Path, artifact_path: str) -> Path:
    posix = PurePosixPath(str(artifact_path).replace("\\", "/"))
    windows = PureWindowsPath(str(artifact_path))
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or ".." in posix.parts
        or ".." in windows.parts
    ):
        raise ValueError("artifact path must stay within the collection directory")
    destination = collection_root.joinpath(*posix.parts).resolve()
    try:
        destination.relative_to(collection_root)
    except ValueError as exc:
        raise ValueError(
            "artifact path must stay within the collection directory"
        ) from exc
    return destination


def _sync_report(result: CapabilityExecutionResult) -> None:
    result.report_section["after"] = _json_mapping(result.after_snapshot)
    result.report_section["after_snapshot"] = _json_mapping(result.after_snapshot)
    result.report_section["rollback"] = _json_mapping(result.rollback_plan)
    result.report_section["rollback_plan"] = _json_mapping(result.rollback_plan)
    result.report_section["provenance"] = _json_mapping(result.provenance)
    result.report_section["artifacts"] = [item.to_dict() for item in result.artifacts]
    result.report_section["evidence_manifest_entries"] = [
        dict(item) for item in result.evidence_manifest_entries
    ]


def _plan_steps(mode: str, script_source: Any) -> list[dict[str, Any]]:
    steps = [
        {"order": 1, "action": "select_device"},
        {"order": 2, "action": "probe_target"},
    ]
    next_order = 3
    if mode == _SPAWN:
        steps.append({"order": next_order, "action": "spawn_package"})
        next_order += 1
    steps.extend(
        [
            {"order": next_order, "action": "attach_session"},
            {
                "order": next_order + 1,
                "action": (
                    "load_local_script"
                    if script_source == "local_file"
                    else "generate_restricted_script"
                ),
            },
            {"order": next_order + 2, "action": "load_script"},
        ]
    )
    if mode == _SPAWN:
        steps.append({"order": next_order + 3, "action": "resume_spawn"})
        next_order += 1
    steps.extend(
        [
            {"order": next_order + 3, "action": "collect_messages"},
            {"order": next_order + 4, "action": "unload_script"},
            {"order": next_order + 5, "action": "detach_session"},
        ]
    )
    return steps


def _normalize_spawn_argv(value: Any) -> Any:
    if value in (None, ""):
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return value
    return [str(item) for item in value]


def _valid_spawn_argv(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= _MAX_SPAWN_ARGUMENTS
        and all(isinstance(item, str) and "\x00" not in item for item in value)
    )


def _backend_info(backend: Any) -> dict[str, Any]:
    return _prune(
        {
            "name": str(getattr(backend, "name", type(backend).__name__)),
            "available": _backend_available(backend),
            "version": getattr(backend, "version", None),
            "unavailable_reason": getattr(backend, "unavailable_reason", None),
        }
    )


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", True))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "Frida Android instrumentation backend is unavailable"
    )


def _backend_operation_ok(result: Any) -> bool:
    if result is None:
        return True
    if isinstance(result, bool):
        return result
    if isinstance(result, Mapping):
        return result.get("ok") is not False and result.get("status") not in {
            "failed",
            "error",
        }
    return True


def _describe_backend_device(backend: Any, device: Any) -> dict[str, Any]:
    describe = getattr(backend, "describe_device", None)
    if callable(describe):
        try:
            return _json_mapping(describe(device))
        except Exception as exc:  # noqa: BLE001 - description is non-critical
            return {"description_error": _exception_payload(exc)}
    return {"backend": str(getattr(backend, "name", type(backend).__name__))}


def _describe_backend_session(backend: Any, session: Any) -> dict[str, Any]:
    describe = getattr(backend, "describe_session", None)
    if callable(describe):
        try:
            return _json_mapping(describe(session))
        except Exception as exc:  # noqa: BLE001 - description is non-critical
            return {"description_error": _exception_payload(exc)}
    return {}


def _call_with_optional_timeout(
    function: Callable[..., Any],
    *args: Any,
    timeout_seconds: float,
) -> Any:
    try:
        return function(*args, timeout=timeout_seconds)
    except TypeError:
        return function(*args)


def _normalize_address(value: Any) -> Any:
    parsed = _parse_address(value)
    return f"0x{parsed:x}" if parsed is not None else value


def _normalize_offset(value: Any) -> Any:
    parsed = _parse_offset(value)
    return parsed if parsed is not None else value


def _parse_address(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _parse_offset(value: Any) -> Optional[int]:
    parsed = _parse_address(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _normalize_bool(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return value


def _normalized_int(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            return value
    return value


def _bounded_int(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    default: int,
) -> int:
    normalized = _normalized_int(value)
    if not isinstance(normalized, int) or isinstance(normalized, bool):
        return default
    return min(maximum, max(minimum, normalized))


def _integer_in_range(value: Any, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _positive_int(value: Any) -> Optional[int]:
    normalized = _normalized_int(value)
    if isinstance(normalized, int) and not isinstance(normalized, bool) and normalized > 0:
        return normalized
    return None


def _first_text(*values: Any) -> Optional[str]:
    for value in values:
        text = _optional_text(value)
        if text:
            return text
    return None


def _optional_text(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    return str(value).strip() or None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_segment(value: Any) -> str:
    segment = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "session")).strip(".-")
    return segment[:128] or "session"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _exception_payload(exc: Exception) -> dict[str, Any]:
    return {"type": type(exc).__name__, "message": str(exc)}


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, Mapping):
            return _json_mapping(payload)
    return {}


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return {
            "encoding": "base64",
            "value": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _json_value(to_dict())
    return str(value)


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


def _deduplicate(items: list[str]) -> list[str]:
    return list(dict.fromkeys(str(item) for item in items if str(item)))


__all__ = [
    "AndroidFridaBackend",
    "AndroidInstrumentationBackend",
    "AndroidInstrumentationProvider",
    "FridaAndroidBackend",
    "FridaAndroidInstrumentationBackend",
    "UnavailableAndroidInstrumentationBackend",
    "render_android_hook_script",
    "render_android_instrumentation_script",
]
