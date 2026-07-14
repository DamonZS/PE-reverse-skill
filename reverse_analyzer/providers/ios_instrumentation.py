"""Bounded Frida-backed iOS runtime evidence provider.

Only structured Objective-C and native hook specifications are accepted.  The
provider never accepts caller supplied JavaScript and always closes Frida
handles before returning (with an in-process retry retained for failed cleanup).
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import re
import sys
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


_AUDIT_VERSION = 1
_SCRIPT_VERSION = 1
_DEFAULT_DURATION_MS = 1_000
_MAX_DURATION_MS = 300_000
_DEFAULT_DEVICE_TIMEOUT_MS = 5_000
_MAX_DEVICE_TIMEOUT_MS = 60_000
_DEFAULT_MAX_EVENTS = 1_000
_MAX_EVENTS = 10_000
_DEFAULT_MAX_STRING = 256
_MAX_STRING = 4_096
_DEFAULT_MAX_BYTES = 256
_MAX_BYTES = 4_096
_MAX_HOOKS = 64
_MAX_ARGUMENTS = 32
_MAX_SPAWN_ARGUMENTS = 64

_ACTIONS = {"attach", "spawn", "trace"}
_ACTION_ALIASES = {"launch": "spawn", "run": "spawn", "hook": "attach"}
_DEVICE_TYPES = {"usb", "local", "remote", "explicit"}
_OBJC = "objc"
_NATIVE = "native"
_HOOK_ALIASES = {
    "objc": _OBJC,
    "objective-c": _OBJC,
    "objective_c": _OBJC,
    "objc_method": _OBJC,
    "native": _NATIVE,
    "native_export": _NATIVE,
}
_BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$")
_CLASS_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_.$]{0,255}$")
_SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)*:?$")
_MODULE_RE = re.compile(r"^[A-Za-z0-9_.+@-]{1,255}$")
_EXPORT_RE = re.compile(r"^[A-Za-z_?$@][A-Za-z0-9_?$@#.:+\-]{0,255}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:+@/\-]{1,128}$")
_ARG_TYPES = {"pointer", "objc", "utf8", "utf16", "int32", "uint32", "hex", "bool", "bytes"}
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|authorization|cookie|credential|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_RUNTIME_ERROR_EVENTS = {"error", "hook_error", "script_error"}


class IOSInstrumentationBackend(Protocol):
    name: str
    available: bool
    unavailable_reason: Optional[str]

    def select_device(self, options: Mapping[str, Any]) -> Any: ...
    def describe_device(self, device: Any) -> Mapping[str, Any]: ...
    def probe_target(self, device: Any, target: Mapping[str, Any], options: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def spawn(self, device: Any, bundle_id: str, options: Mapping[str, Any]) -> int: ...
    def attach(self, device: Any, target: Any) -> Any: ...
    def create_script(self, session: Any, source: str, on_message: Callable[..., None]) -> Any: ...
    def load_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...
    def resume(self, device: Any, pid: int) -> Optional[Mapping[str, Any]]: ...
    def wait(self, timeout_ms: int) -> None: ...
    def unload_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...
    def detach(self, session: Any) -> Optional[Mapping[str, Any]]: ...
    def kill(self, device: Any, pid: int) -> Optional[Mapping[str, Any]]: ...
    def describe_session(self, session: Any) -> Mapping[str, Any]: ...


class UnavailableIOSInstrumentationBackend:
    name = "frida"
    available = False
    test_double = False
    real_device_parity = False
    execution_assurance = "dependency_gated"

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def _raise(self) -> None:
        raise RuntimeError(self.unavailable_reason)

    def select_device(self, options: Mapping[str, Any]) -> Any:
        del options
        self._raise()

    def __getattr__(self, _name: str) -> Callable[..., Any]:
        return lambda *_args, **_kwargs: self._raise()


class FridaIOSInstrumentationBackend:
    """Production adapter for the optional Frida Python binding."""

    name = "frida"

    def __init__(self, frida_module: Any = None, *, platform_name: Optional[str] = None) -> None:
        self._binding_source = "injected" if frida_module is not None else "imported"
        self._frida = frida_module
        self.host_platform = str(platform_name or sys.platform)
        self.available = False
        self.unavailable_reason: Optional[str] = None
        self.version: Optional[str] = None
        self.test_double = True
        self.real_device_parity = False
        self.execution_assurance = "simulation"
        if self._frida is None:
            try:
                self._frida = importlib.import_module("frida")
            except Exception as exc:  # noqa: BLE001 - optional dependency boundary
                self.unavailable_reason = f"Frida Python binding is unavailable: {exc}"
                return
        if self.host_platform != "darwin":
            self.unavailable_reason = (
                f"iOS Frida instrumentation is unavailable on non-Darwin host {self.host_platform!r}"
            )
            return
        self.available = True
        self.version = str(getattr(self._frida, "__version__", "") or "") or None
        production = self._binding_source == "imported" and not bool(
            getattr(self._frida, "test_double", False)
        )
        self.test_double = not production
        self.real_device_parity = production
        self.execution_assurance = "production" if production else "simulation"

    def _require_available(self) -> None:
        if not self.available:
            raise RuntimeError(self.unavailable_reason or "Frida iOS backend is unavailable")

    def select_device(self, options: Mapping[str, Any]) -> Any:
        self._require_available()
        device_type = str(options.get("device_type") or "usb")
        timeout = max(0.0, float(options.get("device_timeout_ms") or 0) / 1000.0)
        device_id = str(options.get("device_id") or "").strip()
        manager = self._frida.get_device_manager()
        if device_type == "explicit" or device_id:
            if not device_id:
                raise ValueError("device_id is required for an explicit Frida device")
            return _call_timeout(manager.get_device, device_id, timeout_seconds=timeout)
        if device_type == "usb":
            return _call_timeout(self._frida.get_usb_device, timeout_seconds=timeout)
        if device_type == "local":
            return self._frida.get_local_device()
        if device_type == "remote":
            address = str(options.get("remote_address") or "").strip()
            if not address:
                raise ValueError("remote_address is required for a remote Frida device")
            return manager.add_remote_device(address)
        raise ValueError(f"unsupported Frida device type: {device_type}")

    def describe_device(self, device: Any) -> Mapping[str, Any]:
        return _prune({
            "id": getattr(device, "id", None),
            "name": getattr(device, "name", None),
            "type": getattr(device, "type", None),
        })

    def probe_target(self, device: Any, target: Mapping[str, Any], options: Mapping[str, Any]) -> Mapping[str, Any]:
        processes = list(device.enumerate_processes())
        pid = _positive_int(target.get("pid"))
        process_name = _text(target.get("process_name"))
        bundle_id = _text(target.get("bundle_id"))
        process = next(
            (
                item for item in processes
                if (pid is not None and _positive_int(getattr(item, "pid", None)) == pid)
                or (pid is None and process_name and str(getattr(item, "name", "")) == process_name)
            ),
            None,
        )
        applications: list[Any] = []
        application = None
        if bundle_id:
            applications = list(device.enumerate_applications())
            application = next(
                (item for item in applications if str(getattr(item, "identifier", "")) == bundle_id),
                None,
            )
            app_pid = _positive_int(getattr(application, "pid", None))
            if process is None and app_pid is not None:
                process = next(
                    (item for item in processes if _positive_int(getattr(item, "pid", None)) == app_pid),
                    application,
                )
        action = str(options.get("action") or "attach")
        exists = application is not None if action == "spawn" else process is not None
        return _prune({
            "status": "ok" if exists else "failed",
            "exists": exists,
            "accessible": exists,
            "running": process is not None,
            "bundle_id": bundle_id,
            "process_name": process_name,
            "pid": pid,
            "resolved_pid": _positive_int(getattr(process, "pid", None)),
            "resolved_name": getattr(process, "name", None) or getattr(application, "name", None),
            "process_count": len(processes),
            "application_count": len(applications),
            "reason": None if exists else "iOS bundle or process was not found",
        })

    def spawn(self, device: Any, bundle_id: str, options: Mapping[str, Any]) -> int:
        argv = [bundle_id, *[str(item) for item in options.get("spawn_argv", [])]]
        return int(device.spawn(argv))

    def attach(self, device: Any, target: Any) -> Any:
        return device.attach(target)

    def create_script(self, session: Any, source: str, on_message: Callable[..., None]) -> Any:
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

    def kill(self, device: Any, pid: int) -> Mapping[str, Any]:
        device.kill(pid)
        return {"ok": True, "killed": True, "pid": pid}

    def describe_session(self, session: Any) -> Mapping[str, Any]:
        return _prune({"pid": getattr(session, "pid", None)})


FridaIOSBackend = FridaIOSInstrumentationBackend
IOSFridaBackend = FridaIOSInstrumentationBackend


class IOSInstrumentationProvider:
    capability_name = "ios_instrumentation"
    provider_name = "frida_ios_instrumentation"
    priority = 10

    def __init__(
        self,
        backend: Optional[IOSInstrumentationBackend] = None,
        *,
        duration_ms: int = _DEFAULT_DURATION_MS,
        device_timeout_ms: int = _DEFAULT_DEVICE_TIMEOUT_MS,
        max_events: int = _DEFAULT_MAX_EVENTS,
        max_string_length: int = _DEFAULT_MAX_STRING,
        max_byte_length: int = _DEFAULT_MAX_BYTES,
    ) -> None:
        self.backend: IOSInstrumentationBackend = backend or FridaIOSInstrumentationBackend()
        self.duration_ms = _bounded(duration_ms, 0, _MAX_DURATION_MS, _DEFAULT_DURATION_MS)
        self.device_timeout_ms = _bounded(device_timeout_ms, 0, _MAX_DEVICE_TIMEOUT_MS, _DEFAULT_DEVICE_TIMEOUT_MS)
        self.max_events = _bounded(max_events, 1, _MAX_EVENTS, _DEFAULT_MAX_EVENTS)
        self.max_string_length = _bounded(max_string_length, 1, _MAX_STRING, _DEFAULT_MAX_STRING)
        self.max_byte_length = _bounded(max_byte_length, 1, _MAX_BYTES, _DEFAULT_MAX_BYTES)
        self._active_runs: dict[str, dict[str, Any]] = {}

    def supports(self, request: CapabilityRequest, context: Optional[dict[str, Any]] = None) -> bool:
        del context
        return request.capability == self.capability_name and _request_action(request) in _ACTIONS

    def plan(self, request: CapabilityRequest, context: Optional[dict[str, Any]] = None) -> CapabilityPlan:
        backend = self._select_backend(context)
        session_id = str(request.session_id or "ios-instrumentation-session")
        action = _request_action(request)
        device = _device_config(request.params, self.device_timeout_ms)
        runtime_target = _runtime_target(request, action)
        identity = _target_identity(request.target, runtime_target)
        duration = _normalized_int(request.params.get("duration_ms", request.params.get("timeout_ms", self.duration_ms)))
        max_events = _normalized_int(request.params.get("max_events", request.params.get("max_messages", self.max_events)))
        max_string = _normalized_int(request.params.get("max_string_length", request.params.get("max_string_bytes", self.max_string_length)))
        max_bytes = _normalized_int(request.params.get("max_byte_length", request.params.get("max_bytes", self.max_byte_length)))
        spawn_argv = _normalize_argv(request.params.get("spawn_argv", request.params.get("target_args", [])))
        hooks = _normalize_hooks(_raw_hooks(request.params))
        script_errors = _caller_script_errors(request.params) + _hook_errors(hooks)
        source: Optional[str] = None
        if not script_errors:
            try:
                source = render_ios_instrumentation_script(
                    hooks,
                    session_id=session_id,
                    max_events=max_events,
                    duration_ms=duration,
                    max_string_length=max_string,
                    max_byte_length=max_bytes,
                )
            except ValueError as exc:
                script_errors.append(str(exc))
        script = _prune({
            "source": "generated",
            "controlled": True,
            "hooks": hooks,
            "sha256": _sha256_text(source) if source is not None else None,
            "size": len(source.encode("utf-8")) if source is not None else None,
            "error": "; ".join(_dedupe(script_errors)) if script_errors else None,
        })
        integrity = {
            "action": action,
            "device": device,
            "target": runtime_target,
            "target_identity": identity,
            "duration_ms": duration,
            "max_events": max_events,
            "max_string_length": max_string,
            "max_byte_length": max_bytes,
            "spawn_argv": spawn_argv,
            "script": script,
        }
        precondition_hash = _sha256_json(integrity)
        backend_info = _backend_info(backend)
        assurance = str(backend_info["execution_assurance"])
        lifecycle = [_lifecycle("plan", "completed")]
        parameters = {
            **integrity,
            "requested_action": request.action,
            "device_type": device.get("device_type"),
            "device_id": device.get("device_id"),
            "remote_address": device.get("remote_address"),
            "target_type": runtime_target.get("target_type"),
            "bundle_id": runtime_target.get("bundle_id"),
            "process_name": runtime_target.get("process_name"),
            "pid": runtime_target.get("pid"),
            "hook_specs": hooks,
            "backend": backend_info,
        }
        rollback_plan = {
            "schema_version": _AUDIT_VERSION,
            "supported": True,
            "mode": "runtime_cleanup",
            "session_id": session_id,
            "active": False,
            "completed": False,
            "idempotent": True,
            "order": ["resume_spawn", "unload_script", "detach_session", "kill_spawn_if_required"],
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
            before_snapshot={
                "schema_version": _AUDIT_VERSION,
                "capture_phase": "plan",
                "session": {"id": session_id, "state": "planned", "spawned": False, "attached": False},
                "device": device,
                "target_identity": identity,
                "runtime_target": runtime_target,
                "script": _public_script(script),
                "lifecycle": lifecycle,
                "backend": backend_info,
            },
            rollback_plan=rollback_plan,
            provenance=_redact({
                **_mapping(request.provenance),
                "audit_schema_version": _AUDIT_VERSION,
                "script_schema_version": _SCRIPT_VERSION,
                "provider": self.provider_name,
                "backend": backend_info,
                "target_identity": identity,
                "controlled_script": True,
                "caller_supplied_script_allowed": False,
                "observation_scope": "bounded_runtime_calls_only",
                "execution_assurance": assurance,
                "production_evidence": False,
                "real_device_parity": assurance == "production",
            }),
        )

    def validate(self, plan: CapabilityPlan, context: Optional[dict[str, Any]] = None) -> CapabilityValidation:
        validation, _, _ = self._validate_plan(plan, context)
        return validation

    def execute(self, plan: CapabilityPlan, context: Optional[dict[str, Any]] = None) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        validation, runtime, source = self._validate_plan(plan, context)
        identity = _target_identity(plan.target, _mapping(plan.parameters.get("target")))
        lifecycle = list(plan.before_snapshot.get("lifecycle") or [])
        lifecycle.append(_lifecycle("validate", "ok" if validation.ok else "failed"))
        before = {
            "schema_version": _AUDIT_VERSION,
            "capture_phase": "before",
            "session": {"id": plan.session_id, "state": "inactive", "spawned": False, "attached": False},
            "device": _mapping(runtime.get("device_identity")),
            "device_request": _mapping(plan.parameters.get("device")),
            "target_identity": identity,
            "runtime_target": _mapping(plan.parameters.get("target")),
            "target_probe": _mapping(runtime.get("target_probe")),
            "script": _public_script(_mapping(plan.parameters.get("script"))),
            "validation": validation.to_dict(),
            "lifecycle": lifecycle,
        }
        if runtime.get("availability") == "unavailable":
            reason = str(runtime.get("reason") or _backend_reason(backend))
            return self._inactive_result(plan, validation, before, identity, "unavailable", reason)
        if not validation.ok or source is None:
            reason = "; ".join(validation.errors) or "controlled script generation failed"
            return self._inactive_result(plan, validation, before, identity, "failed", reason)

        device = runtime.get("device_handle")
        target = _mapping(plan.parameters.get("target"))
        probe = _mapping(runtime.get("target_probe"))
        max_events = int(plan.parameters["max_events"])
        max_string = int(plan.parameters["max_string_length"])
        max_bytes = int(plan.parameters["max_byte_length"])
        events: list[dict[str, Any]] = []
        dropped = [0]

        def on_message(message: Any, data: Any = None) -> None:
            event = _normalize_message(message, data, max_string=max_string, max_bytes=max_bytes)
            if len(events) < max_events:
                events.append(event)
            else:
                dropped[0] += 1

        spawned_pid: Optional[int] = None
        session_handle: Any = None
        script_handle: Any = None
        resumed = False
        loaded = False
        errors: list[Any] = []
        session_identity: dict[str, Any] = {}
        try:
            if plan.action == "spawn":
                lifecycle.append(_lifecycle("spawn", "started"))
                spawned_pid = _positive_int(backend.spawn(device, str(target.get("bundle_id") or ""), _runtime_options(plan)))
                if spawned_pid is None:
                    raise RuntimeError("Frida returned an invalid spawned pid")
                lifecycle.append(_lifecycle("spawn", "completed", pid=spawned_pid))
                attach_target: Any = spawned_pid
            else:
                attach_target = probe.get("resolved_pid") or target.get("pid") or target.get("process_name") or target.get("bundle_id")
                if attach_target in (None, ""):
                    raise RuntimeError("iOS attach target could not be resolved")
            lifecycle.append(_lifecycle("attach", "started"))
            session_handle = backend.attach(device, attach_target)
            if session_handle is None:
                raise RuntimeError("Frida returned no session handle")
            session_identity = _describe_session(backend, session_handle)
            lifecycle.append(_lifecycle("attach", "completed"))
            script_handle = backend.create_script(session_handle, source, on_message)
            if script_handle is None:
                raise RuntimeError("Frida returned no script handle")
            if not _operation_ok(backend.load_script(script_handle)):
                raise RuntimeError("Frida script load failed")
            loaded = True
            lifecycle.append(_lifecycle("load_script", "completed"))
            if spawned_pid is not None:
                if not _operation_ok(backend.resume(device, spawned_pid)):
                    raise RuntimeError("Frida spawned process resume failed")
                resumed = True
                lifecycle.append(_lifecycle("resume", "completed", pid=spawned_pid))
            backend.wait(int(plan.parameters["duration_ms"]))
            lifecycle.append(_lifecycle("capture", "completed", event_count=len(events)))
        except Exception as exc:  # noqa: BLE001 - backend failure becomes evidence
            errors.append(_exception(exc))
            lifecycle.append(_lifecycle("execute", "failed", error=str(exc)))
        cleanup = _cleanup_runtime(
            backend,
            device=device,
            spawned_pid=spawned_pid,
            resumed=resumed,
            script=script_handle,
            session=session_handle,
            force_kill=bool(errors),
        )
        lifecycle.extend(cleanup.pop("lifecycle", []))
        if not cleanup.get("ok"):
            errors.append({"phase": "cleanup", "details": cleanup})
        runtime_errors = [event for event in events if str(event.get("event") or "").lower() in _RUNTIME_ERROR_EVENTS]
        errors.extend(runtime_errors)
        status = "ok" if not errors and cleanup.get("ok") else "failed"
        if not cleanup.get("ok"):
            self._active_runs[plan.session_id] = {
                "backend": backend,
                "device": device,
                "spawned_pid": None if cleanup.get("killed") else spawned_pid,
                "resumed": bool(cleanup.get("resumed")),
                "script": None if cleanup.get("unloaded") else script_handle,
                "session": None if cleanup.get("detached") else session_handle,
            }
        else:
            self._active_runs.pop(plan.session_id, None)
        rollback = _completed_rollback(plan.rollback_plan, cleanup, status)
        session_payload = {
            "id": plan.session_id,
            **session_identity,
            "state": "closed" if cleanup.get("ok") else "cleanup_failed",
            "action": plan.action,
            "pid": spawned_pid or probe.get("resolved_pid") or target.get("pid"),
            "spawned": spawned_pid is not None,
            "resumed": bool(resumed or cleanup.get("resumed")),
            "attached": session_handle is not None and not cleanup.get("detached"),
            "script_loaded": loaded and not cleanup.get("unloaded"),
            "bounded_capture": True,
        }
        after = {
            "schema_version": _AUDIT_VERSION,
            "capture_phase": "after",
            "session": session_payload,
            "device": _mapping(runtime.get("device_identity")),
            "target_identity": identity,
            "runtime_target": target,
            "target_probe": probe,
            "events": events,
            "event_count": len(events),
            "dropped_event_count": dropped[0],
            "cleanup": cleanup,
            "rollback": rollback,
            "lifecycle": lifecycle,
        }
        return self._result(plan, validation, status, before, after, rollback, events, errors)

    def rollback(self, result: CapabilityExecutionResult, context: Optional[dict[str, Any]] = None) -> CapabilityRollbackResult:
        del context
        active = self._active_runs.pop(result.session_id, None)
        if active:
            cleanup = _cleanup_runtime(
                active["backend"],
                device=active["device"],
                spawned_pid=active.get("spawned_pid"),
                resumed=bool(active.get("resumed")),
                script=active.get("script"),
                session=active.get("session"),
                force_kill=True,
            )
            lifecycle = cleanup.pop("lifecycle", [])
            ok = bool(cleanup.get("ok"))
            status = "completed" if ok else "cleanup_failed"
            if not ok:
                self._active_runs[result.session_id] = active
        elif result.rollback_plan.get("completed"):
            cleanup = _mapping(result.rollback_plan.get("cleanup"))
            lifecycle = [_lifecycle("rollback", "already_completed")]
            ok = True
            status = "already_completed"
        else:
            cleanup = {}
            lifecycle = [_lifecycle("rollback", "failed")]
            ok = False
            status = "handles_unavailable"
        details = {
            "schema_version": _AUDIT_VERSION,
            "status": status,
            "session_id": result.session_id,
            "idempotent": True,
            "completed": ok,
            "cleanup": cleanup,
        }
        result.rollback_plan.update({"active": not ok, "completed": ok, "status": status, "last_rollback_request": details})
        result.after_snapshot["rollback"] = _mapping(result.rollback_plan)
        result.after_snapshot.setdefault("lifecycle", []).extend(lifecycle)
        result.report_section.setdefault("rollback_history", []).append(details)
        result.dashboard_trace.append({
            "kind": "ios_instrumentation_rollback",
            "capability": self.capability_name,
            "provider": self.provider_name,
            "session_id": result.session_id,
            "status": status,
        })
        _sync_report(result)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=ok,
            restored=False,
            details=details,
        )

    def collect_artifacts(self, result: CapabilityExecutionResult, out_dir: str, context: Optional[dict[str, Any]] = None) -> CapabilityArtifactBundle:
        del context
        root = Path(out_dir).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or _result_artifacts(result.session_id))
        old_entries = {str(item.get("path")): dict(item) for item in result.evidence_manifest_entries if item.get("path")}
        payloads = _artifact_payloads(result)
        entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            payload = payloads.get(artifact.kind)
            if payload is None:
                continue
            destination = _artifact_destination(root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            encoded = (json.dumps(_redact(payload), indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8")
            destination.write_bytes(encoded)
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update({"materialized": True, "sha256": digest, "size": len(encoded), "collection_root": str(root)})
            entry = old_entries.get(artifact.path) or _manifest_entry(artifact, result)
            entry.update({"materialized": True, "sha256": digest, "size": len(encoded)})
            entries.append(entry)
        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        _sync_report(result)
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=entries,
        )

    def _validate_plan(self, plan: CapabilityPlan, context: Optional[dict[str, Any]]) -> tuple[CapabilityValidation, dict[str, Any], Optional[str]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []

        def check(name: str, ok: bool, error: Optional[str] = None, **details: Any) -> None:
            checks.append(_prune({"name": name, "status": "ok" if ok else "failed", **details}))
            if not ok and error:
                errors.append(error)

        check("capability", plan.capability == self.capability_name, f"plan capability must be {self.capability_name}")
        check("provider", plan.provider == self.provider_name, f"plan provider must be {self.provider_name}")
        check("session_id", isinstance(plan.session_id, str) and 0 < len(plan.session_id) <= 256, "session_id must contain 1-256 characters")
        action = str(plan.parameters.get("action") or plan.action or "")
        check("action", action in _ACTIONS and action == plan.action, f"unsupported or inconsistent iOS instrumentation action: {action}")
        device = _mapping(plan.parameters.get("device"))
        device_errors = _device_errors(device)
        check("device_config", not device_errors, "; ".join(device_errors), device=device)
        target = _mapping(plan.parameters.get("target"))
        target_errors = _target_errors(target, action)
        planned_identity = _mapping(plan.parameters.get("target_identity"))
        current_identity = _target_identity(plan.target, target)
        check("target_identity", not target_errors and planned_identity == current_identity, "; ".join(target_errors) or "target identity changed after planning", target=current_identity)
        limits = (
            ("duration_ms", 0, _MAX_DURATION_MS),
            ("max_events", 1, _MAX_EVENTS),
            ("max_string_length", 1, _MAX_STRING),
            ("max_byte_length", 1, _MAX_BYTES),
        )
        for name, minimum, maximum in limits:
            value = plan.parameters.get(name)
            check(name, _int_range(value, minimum, maximum), f"{name} must be an integer from {minimum} to {maximum}", actual=value)
        argv = plan.parameters.get("spawn_argv")
        check("spawn_argv", _valid_argv(argv), f"spawn_argv must contain at most {_MAX_SPAWN_ARGUMENTS} strings without NUL")
        script = _mapping(plan.parameters.get("script"))
        source, script_errors = _render_planned_script(plan, script)
        check("controlled_script", not script_errors and source is not None, "; ".join(script_errors), hook_count=len(script.get("hooks") or []))
        integrity = {
            "action": action,
            "device": device,
            "target": target,
            "target_identity": current_identity,
            "duration_ms": plan.parameters.get("duration_ms"),
            "max_events": plan.parameters.get("max_events"),
            "max_string_length": plan.parameters.get("max_string_length"),
            "max_byte_length": plan.parameters.get("max_byte_length"),
            "spawn_argv": argv,
            "script": script,
        }
        expected_hash = _sha256_json(integrity)
        check("plan_integrity", bool(plan.precondition_hash) and plan.precondition_hash == expected_hash, "iOS instrumentation precondition hash mismatch")
        runtime: dict[str, Any] = {"availability": "ok", "target_probe": {"status": "not_probed"}}
        backend_info = _backend_info(backend)
        available = bool(getattr(backend, "available", True))
        checks.append({**backend_info, "name": "frida_backend", "status": "ok" if available else "unavailable"})
        if not available:
            reason = _backend_reason(backend)
            warnings.append(reason)
            runtime.update({"availability": "unavailable", "reason": reason, "target_probe": {"status": "unavailable", "reason": reason}})
            checks.extend([
                {"name": "ios_device", "status": "unavailable", "reason": reason},
                {"name": "target_probe", "status": "unavailable", "reason": reason},
            ])
        elif errors:
            checks.extend([
                {"name": "ios_device", "status": "skipped"},
                {"name": "target_probe", "status": "skipped"},
            ])
        else:
            try:
                device_handle = backend.select_device(device)
                if device_handle is None:
                    raise RuntimeError("Frida returned no iOS device")
                runtime.update({"device_handle": device_handle, "device_identity": _describe_device(backend, device_handle)})
                checks.append({"name": "ios_device", "status": "ok", "device": runtime["device_identity"]})
            except Exception as exc:  # noqa: BLE001 - absence is an unavailable gate
                reason = f"iOS Frida device is unavailable: {exc}"
                warnings.append(reason)
                runtime.update({"availability": "unavailable", "reason": reason, "target_probe": {"status": "unavailable", "reason": reason}})
                checks.extend([
                    {"name": "ios_device", "status": "unavailable", "reason": reason},
                    {"name": "target_probe", "status": "unavailable", "reason": reason},
                ])
            else:
                try:
                    probe = _mapping(backend.probe_target(device_handle, target, _runtime_options(plan)))
                except Exception as exc:  # noqa: BLE001
                    probe = {"status": "failed", "exists": False, "accessible": False, "error": _exception(exc)}
                runtime["target_probe"] = probe
                target_ok = probe.get("status") == "ok" and probe.get("exists") is not False and probe.get("accessible") is not False
                check("target_probe", target_ok, "iOS bundle or process does not exist or is not accessible", probe=probe)
        validation = CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            warnings=_dedupe(warnings),
            errors=_dedupe(errors),
        )
        return validation, runtime, source

    def _inactive_result(self, plan: CapabilityPlan, validation: CapabilityValidation, before: Mapping[str, Any], identity: Mapping[str, Any], status: str, reason: str) -> CapabilityExecutionResult:
        rollback = _inactive_rollback(plan.rollback_plan, status, reason)
        lifecycle = list(before.get("lifecycle") or [])
        lifecycle.append(_lifecycle("execute", status, reason=reason))
        after = {
            "schema_version": _AUDIT_VERSION,
            "capture_phase": "after",
            "session": {"id": plan.session_id, "state": status, "spawned": False, "attached": False, "script_loaded": False},
            "target_identity": _mapping(identity),
            "runtime_target": _mapping(plan.parameters.get("target")),
            "events": [],
            "event_count": 0,
            "cleanup": rollback["cleanup"],
            "rollback": rollback,
            "lifecycle": lifecycle,
            "reason": reason,
        }
        return self._result(plan, validation, status, before, after, rollback, [], [reason])

    def _result(self, plan: CapabilityPlan, validation: CapabilityValidation, status: str, before: Mapping[str, Any], after: Mapping[str, Any], rollback: Mapping[str, Any], events: list[dict[str, Any]], errors: list[Any]) -> CapabilityExecutionResult:
        artifacts = _result_artifacts(plan.session_id)
        backend_check = next(
            (item for item in validation.checks if item.get("name") == "frida_backend"),
            {},
        )
        assurance = str(backend_check.get("execution_assurance") or "simulation")
        production_evidence = status == "ok" and assurance == "production"
        provenance = _redact({
            **_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "event_count": len(events),
            "execution_assurance": assurance,
            "production_evidence": production_evidence,
            "real_device_parity": assurance == "production",
        })
        result = CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_mapping(before),
            after_snapshot=_mapping(after),
            rollback_plan=_mapping(rollback),
            artifacts=artifacts,
            evidence_manifest_entries=[],
            report_section={},
            dashboard_trace=[{
                "kind": "ios_instrumentation_execution",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": plan.session_id,
                "status": status,
                "action": plan.action,
                "target": _target_identity(plan.target, _mapping(plan.parameters.get("target"))),
                "device": _mapping(after.get("device")),
                "event_count": len(events),
                "execution_assurance": assurance,
                "production_evidence": production_evidence,
            }],
            provenance=provenance,
        )
        result.evidence_manifest_entries = [_manifest_entry(item, result) for item in artifacts]
        result.report_section = {
            "schema_version": _AUDIT_VERSION,
            "capability": result.capability,
            "provider": result.provider,
            "session_id": result.session_id,
            "status": status,
            "action": plan.action,
            "target_identity": _target_identity(plan.target, _mapping(plan.parameters.get("target"))),
            "device": _mapping(after.get("device")),
            "runtime_target": _mapping(plan.parameters.get("target")),
            "precondition_hash": plan.precondition_hash,
            "script": _public_script(_mapping(plan.parameters.get("script"))),
            "hook_specification": list(_mapping(plan.parameters.get("script")).get("hooks") or []),
            "events": events,
            "lifecycle": list(after.get("lifecycle") or []),
            "before_snapshot": result.before_snapshot,
            "after_snapshot": result.after_snapshot,
            "rollback_plan": result.rollback_plan,
            "provenance": provenance,
            "validation": validation.to_dict(),
            "execution_assurance": assurance,
            "production_evidence": production_evidence,
            "errors": [_json_value(item) for item in errors],
            "artifacts": [item.to_dict() for item in artifacts],
            "evidence_manifest_entries": result.evidence_manifest_entries,
        }
        return result

    def _select_backend(self, context: Optional[dict[str, Any]]) -> IOSInstrumentationBackend:
        if isinstance(context, Mapping):
            for key in ("ios_instrumentation_backend", "frida_ios_backend"):
                if context.get(key) is not None:
                    return context[key]
        return self.backend


def render_ios_instrumentation_script(
    hooks: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    *,
    session_id: str = "ios-instrumentation",
    max_events: int = _DEFAULT_MAX_EVENTS,
    duration_ms: int = _DEFAULT_DURATION_MS,
    max_string_length: int = _DEFAULT_MAX_STRING,
    max_byte_length: int = _DEFAULT_MAX_BYTES,
) -> str:
    """Generate the finite Frida program used by production execution."""

    raw: Any = hooks.get("hooks", [hooks]) if isinstance(hooks, Mapping) else hooks
    normalized = _normalize_hooks(raw)
    errors = _hook_errors(normalized)
    for name, value, minimum, maximum in (
        ("max_events", max_events, 1, _MAX_EVENTS),
        ("duration_ms", duration_ms, 0, _MAX_DURATION_MS),
        ("max_string_length", max_string_length, 1, _MAX_STRING),
        ("max_byte_length", max_byte_length, 1, _MAX_BYTES),
    ):
        if not _int_range(value, minimum, maximum):
            errors.append(f"{name} must be an integer from {minimum} to {maximum}")
    if errors:
        raise ValueError("; ".join(_dedupe(errors)))
    spec = json.dumps({
        "schema_version": _SCRIPT_VERSION,
        "session_id": str(session_id),
        "max_events": int(max_events),
        "duration_ms": int(duration_ms),
        "max_string_length": int(max_string_length),
        "max_byte_length": int(max_byte_length),
        "hooks": normalized,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"""'use strict';
const SPEC = {spec};
const STARTED_AT = Date.now();
let emitted = 0;

function emit(event) {{
  if (emitted >= SPEC.max_events || Date.now() - STARTED_AT > SPEC.duration_ms) return;
  emitted += 1;
  event.session_id = SPEC.session_id;
  event.sequence = emitted;
  event.thread_id = event.thread_id || Process.getCurrentThreadId();
  event.timestamp_ms = Date.now();
  event.timestamp = new Date(event.timestamp_ms).toISOString();
  send(event);
}}

function textSummary(value) {{
  const text = String(value);
  return {{text: text.slice(0, SPEC.max_string_length), length: text.length, truncated: text.length > SPEC.max_string_length}};
}}

function pointerSummary(value) {{
  const result = {{address: value === null || value === undefined ? null : value.toString()}};
  try {{
    if (ObjC.available && value && !value.isNull()) {{
      const object = new ObjC.Object(value);
      result.class_name = object.$className;
      result.description = textSummary(object.toString());
    }}
  }} catch (_error) {{}}
  return result;
}}

function valueSummary(value, typeName) {{
  try {{
    if (typeName === 'utf8') return value.isNull() ? null : textSummary(value.readUtf8String(SPEC.max_string_length + 1));
    if (typeName === 'utf16') return value.isNull() ? null : textSummary(value.readUtf16String(SPEC.max_string_length + 1));
    if (typeName === 'int32') return {{value: value.toInt32()}};
    if (typeName === 'uint32') return {{value: value.toUInt32()}};
    if (typeName === 'bool') return {{value: !value.isNull()}};
    if (typeName === 'bytes') {{
      const data = value.isNull() ? null : value.readByteArray(SPEC.max_byte_length);
      if (data === null) return null;
      const bytes = new Uint8Array(data);
      return {{hex: Array.prototype.map.call(bytes, x => x.toString(16).padStart(2, '0')).join(''), retained_length: bytes.length, bounded: true}};
    }}
    if (typeName === 'objc') return pointerSummary(value);
    return pointerSummary(value);
  }} catch (error) {{ return {{error: textSummary(error)}}; }}
}}

function installObjC(hook) {{
  try {{
    if (!ObjC.available) throw new Error('Objective-C runtime is unavailable');
    const klass = ObjC.classes[hook.class_name];
    if (!klass) throw new Error('Objective-C class was not found');
    const methodKey = (hook.method_type === 'class' ? '+ ' : '- ') + hook.selector;
    const method = klass[methodKey];
    if (!method) throw new Error('Objective-C selector was not found');
    Interceptor.attach(method.implementation, {{
      onEnter(args) {{
        this.thread_id = Process.getCurrentThreadId();
        this.arguments = [];
        if (hook.capture_args) for (let i = 0; i < hook.argument_count; i++) this.arguments.push({{index: i, value: pointerSummary(args[i + 2])}});
      }},
      onLeave(retval) {{
        emit({{event: 'objc_call', hook_kind: 'objc', label: hook.label, class_name: hook.class_name, selector: hook.selector, thread_id: this.thread_id, arguments: this.arguments || [], return_value: hook.capture_return ? pointerSummary(retval) : null}});
      }}
    }});
    emit({{event: 'hook_installed', hook_kind: 'objc', label: hook.label, class_name: hook.class_name, selector: hook.selector}});
  }} catch (error) {{ emit({{event: 'hook_error', hook_kind: 'objc', label: hook.label, error: textSummary(error)}}); }}
}}

function installNative(hook) {{
  try {{
    let address = null;
    if (hook.export_name !== undefined) address = Module.findExportByName(hook.module, hook.export_name);
    else {{ const base = Module.findBaseAddress(hook.module); if (base !== null) address = base.add(hook.offset); }}
    if (address === null) throw new Error('native export/offset was not found');
    Interceptor.attach(address, {{
      onEnter(args) {{
        this.thread_id = Process.getCurrentThreadId();
        this.arguments = hook.capture_args ? hook.arguments.map(arg => ({{name: arg.name, index: arg.index, value: valueSummary(args[arg.index], arg.type)}})) : [];
      }},
      onLeave(retval) {{
        emit({{event: 'native_call', hook_kind: 'native', label: hook.label, module: hook.module, export_name: hook.export_name, offset: hook.offset, address: address.toString(), thread_id: this.thread_id, arguments: this.arguments || [], return_value: hook.capture_return ? pointerSummary(retval) : null}});
      }}
    }});
    emit({{event: 'hook_installed', hook_kind: 'native', label: hook.label, module: hook.module, export_name: hook.export_name, offset: hook.offset, address: address.toString()}});
  }} catch (error) {{ emit({{event: 'hook_error', hook_kind: 'native', label: hook.label, error: textSummary(error)}}); }}
}}

setImmediate(function () {{ SPEC.hooks.forEach(hook => hook.kind === 'objc' ? installObjC(hook) : installNative(hook)); }});
"""


render_ios_hook_script = render_ios_instrumentation_script


def _request_action(request: CapabilityRequest) -> str:
    raw = str(request.params.get("mode", request.params.get("action", request.action)) or "").strip().lower()
    return _ACTION_ALIASES.get(raw, raw)


def _device_config(params: Mapping[str, Any], default_timeout: int) -> dict[str, Any]:
    raw = params.get("device", params.get("device_type", "usb"))
    if isinstance(raw, Mapping):
        device_type = raw.get("type", raw.get("device_type", "usb"))
        device_id = raw.get("id", raw.get("device_id"))
        address = raw.get("address", raw.get("remote_address"))
        timeout = raw.get("timeout_ms", raw.get("device_timeout_ms", params.get("device_timeout_ms", default_timeout)))
    else:
        device_type = raw
        device_id = params.get("device_id")
        address = params.get("remote_address", params.get("remote_host"))
        timeout = params.get("device_timeout_ms", default_timeout)
    return _prune({
        "device_type": str(device_type or "usb").strip().lower(),
        "device_id": _text(device_id),
        "remote_address": _text(address),
        "device_timeout_ms": _normalized_int(timeout),
    })


def _device_errors(device: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    kind = str(device.get("device_type") or "")
    if kind not in _DEVICE_TYPES:
        errors.append(f"device_type must be one of {sorted(_DEVICE_TYPES)}")
    if kind == "remote" and not _text(device.get("remote_address")):
        errors.append("remote_address is required for a remote Frida device")
    if kind == "explicit" and not _text(device.get("device_id")):
        errors.append("device_id is required for an explicit Frida device")
    for name, maximum in (("device_id", 256), ("remote_address", 512)):
        value = str(device.get(name) or "")
        if value and (len(value) > maximum or "\x00" in value):
            errors.append(f"{name} must be at most {maximum} characters without NUL")
    if not _int_range(device.get("device_timeout_ms"), 0, _MAX_DEVICE_TIMEOUT_MS):
        errors.append(f"device_timeout_ms must be an integer from 0 to {_MAX_DEVICE_TIMEOUT_MS}")
    return errors


def _runtime_target(request: CapabilityRequest, action: str) -> dict[str, Any]:
    params = request.params
    metadata = _mapping(request.target.metadata)
    pid = _positive_int(params.get("pid")) or _positive_int(request.target.pid)
    bundle = _first_text(params.get("bundle_id"), params.get("bundle"), metadata.get("bundle_id"))
    process = _first_text(params.get("process_name"), params.get("process"), metadata.get("process_name"))
    kind = str(request.target.kind or "").lower()
    display = _text(request.target.display_name)
    if kind in {"ios_bundle", "bundle", "bundle_id", "application", "app"}:
        bundle = bundle or display
    elif kind in {"process", "ios_process"}:
        process = process or display
    elif action == "spawn":
        bundle = bundle or display
    elif pid is None:
        process = process or display or bundle
    target_type = "pid" if pid is not None else "bundle" if action == "spawn" or bundle and not process else "process"
    return _prune({"target_type": target_type, "bundle_id": bundle, "process_name": process, "pid": pid})


def _target_errors(target: Mapping[str, Any], action: str) -> list[str]:
    errors: list[str] = []
    bundle = _text(target.get("bundle_id"))
    process = _text(target.get("process_name"))
    pid = target.get("pid")
    if bundle and not _BUNDLE_RE.fullmatch(bundle):
        errors.append("bundle_id must be a valid iOS bundle identifier")
    if process and (len(process) > 256 or "\x00" in process):
        errors.append("process_name must be at most 256 characters without NUL")
    if pid is not None and _positive_int(pid) is None:
        errors.append("pid must be a positive integer")
    if action == "spawn" and not bundle:
        errors.append("spawn requires an iOS bundle_id target")
    if action in {"attach", "trace"} and pid is None and not process and not bundle:
        errors.append(f"{action} requires a bundle id, process name, or pid")
    return errors


def _target_identity(target: TargetIdentity, runtime: Mapping[str, Any]) -> dict[str, Any]:
    payload = target.to_dict()
    metadata = _mapping(payload.get("metadata"))
    metadata.update({key: runtime.get(key) for key in ("target_type", "bundle_id", "process_name") if runtime.get(key) not in (None, "")})
    payload["metadata"] = metadata
    if payload.get("pid") is None and runtime.get("pid") is not None:
        payload["pid"] = runtime.get("pid")
    if not payload.get("display_name"):
        payload["display_name"] = runtime.get("bundle_id") or runtime.get("process_name") or str(runtime.get("pid") or "")
    payload.update({key: runtime.get(key) for key in ("target_type", "bundle_id", "process_name") if runtime.get(key) not in (None, "")})
    return _prune(payload)


def _caller_script_errors(params: Mapping[str, Any]) -> list[str]:
    forbidden = {"javascript", "script", "source", "script_source", "script_path", "script_file", "local_script"}
    return ["caller-supplied Frida JavaScript is not accepted; use structured bounded hooks"] if any(key in params for key in forbidden) else []


def _raw_hooks(params: Mapping[str, Any]) -> Any:
    hooks = params.get("hooks", params.get("hook_specs", params.get("hook_spec", [])))
    result: list[Any] = []
    if isinstance(hooks, Mapping):
        result.extend(hooks.get("hooks", [hooks]) if isinstance(hooks.get("hooks"), Sequence) else [hooks])
    elif isinstance(hooks, Sequence) and not isinstance(hooks, (str, bytes, bytearray)):
        result.extend(hooks)
    for key, kind in (("objc_hooks", _OBJC), ("objective_c_hooks", _OBJC), ("native_hooks", _NATIVE)):
        value = params.get(key)
        if isinstance(value, Mapping):
            value = [value]
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            result.extend({"kind": kind, **dict(item)} if isinstance(item, Mapping) else item for item in value)
    return result


def _normalize_hooks(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            result.append({"kind": "invalid", "label": f"hook-{index}"})
            continue
        raw_kind = str(item.get("kind", item.get("type", ""))).strip().lower()
        kind = _HOOK_ALIASES.get(raw_kind, raw_kind or (_OBJC if item.get("selector") else _NATIVE))
        label = _text(item.get("label")) or f"{kind}-hook-{index}"
        if kind == _OBJC:
            allowed = {"kind", "type", "class", "class_name", "selector", "method", "method_type", "class_method", "argument_count", "capture_args", "capture_return", "label"}
            selector = _text(item.get("selector", item.get("method")))
            method_type = str(item.get("method_type") or ("class" if item.get("class_method") is True else "instance")).lower()
            result.append(_prune({
                "kind": kind,
                "label": label,
                "class_name": _text(item.get("class_name", item.get("class"))),
                "selector": selector,
                "method_type": method_type,
                "argument_count": selector.count(":") if selector else 0,
                "capture_args": _bool(item.get("capture_args", True)),
                "capture_return": _bool(item.get("capture_return", True)),
                "unknown_fields": sorted(set(item) - allowed),
            }))
        elif kind == _NATIVE:
            allowed = {"kind", "type", "module", "module_name", "export", "export_name", "function", "name", "offset", "arguments", "args", "capture_args", "capture_return", "label"}
            args = _normalize_arguments(item.get("arguments", item.get("args", [])))
            hook = _prune({
                "kind": kind,
                "label": label,
                "module": _text(item.get("module", item.get("module_name"))),
                "export_name": _text(item.get("export_name", item.get("export", item.get("function", item.get("name"))))),
                "offset": _normalize_offset(item.get("offset")),
                "capture_args": _bool(item.get("capture_args", True)),
                "capture_return": _bool(item.get("capture_return", True)),
                "unknown_fields": sorted(set(item) - allowed),
            })
            hook["arguments"] = args
            result.append(hook)
        else:
            result.append({"kind": kind or "invalid", "label": label})
    return result


def _normalize_arguments(value: Any) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        value = list(range(max(0, value)))
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return value
    result = []
    for position, item in enumerate(value):
        if isinstance(item, Mapping):
            index = _normalized_int(item.get("index", position))
            name = _text(item.get("name")) or f"arg{position}"
            kind = str(item.get("type") or "pointer").lower()
        else:
            index = _normalized_int(item)
            name = f"arg{position}"
            kind = "pointer"
        result.append({"name": name, "index": index, "type": kind})
    return result


def _hook_errors(hooks: Any) -> list[str]:
    if not isinstance(hooks, Sequence) or isinstance(hooks, (str, bytes, bytearray)):
        return ["hooks must be a sequence"]
    if not hooks:
        return ["at least one Objective-C or native hook is required"]
    errors: list[str] = []
    if len(hooks) > _MAX_HOOKS:
        errors.append(f"at most {_MAX_HOOKS} hooks are allowed")
    for index, hook in enumerate(hooks):
        prefix = f"hooks[{index}]"
        if not isinstance(hook, Mapping):
            errors.append(f"{prefix} must be a mapping")
            continue
        if hook.get("unknown_fields"):
            errors.append(f"{prefix} contains unsupported fields: {', '.join(hook['unknown_fields'])}")
        if not _LABEL_RE.fullmatch(str(hook.get("label") or "")):
            errors.append(f"{prefix}.label is invalid")
        kind = hook.get("kind")
        if kind == _OBJC:
            if not _CLASS_RE.fullmatch(str(hook.get("class_name") or "")):
                errors.append(f"{prefix}.class_name is invalid")
            selector = str(hook.get("selector") or "")
            if not _SELECTOR_RE.fullmatch(selector):
                errors.append(f"{prefix}.selector is invalid")
            if selector.count(":") > _MAX_ARGUMENTS:
                errors.append(f"{prefix}.selector exceeds {_MAX_ARGUMENTS} arguments")
            if hook.get("method_type") not in {"instance", "class"}:
                errors.append(f"{prefix}.method_type must be instance or class")
        elif kind == _NATIVE:
            if not _MODULE_RE.fullmatch(str(hook.get("module") or "")):
                errors.append(f"{prefix}.module is invalid")
            export = hook.get("export_name")
            offset = hook.get("offset")
            if sum(item is not None for item in (export, offset)) != 1:
                errors.append(f"{prefix} requires exactly one export_name or offset")
            if export is not None and not _EXPORT_RE.fullmatch(str(export)):
                errors.append(f"{prefix}.export_name is invalid")
            if offset is not None and (_parse_offset(offset) is None or _parse_offset(offset) > 0x7FFFFFFF):
                errors.append(f"{prefix}.offset must be a non-negative integer at most 0x7fffffff")
            args = hook.get("arguments")
            if not isinstance(args, list) or len(args) > _MAX_ARGUMENTS:
                errors.append(f"{prefix}.arguments must be a list of at most {_MAX_ARGUMENTS} entries")
            else:
                seen: set[int] = set()
                for position, arg in enumerate(args):
                    if not isinstance(arg, Mapping):
                        errors.append(f"{prefix}.arguments[{position}] must be a mapping")
                        continue
                    arg_index = arg.get("index")
                    if not isinstance(arg_index, int) or isinstance(arg_index, bool) or not 0 <= arg_index < _MAX_ARGUMENTS or arg_index in seen:
                        errors.append(f"{prefix}.arguments[{position}].index is invalid or duplicated")
                    else:
                        seen.add(arg_index)
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", str(arg.get("name") or "")):
                        errors.append(f"{prefix}.arguments[{position}].name is invalid")
                    if arg.get("type") not in _ARG_TYPES:
                        errors.append(f"{prefix}.arguments[{position}].type is unsupported")
        else:
            errors.append(f"{prefix}.kind must be objc or native")
        for key in ("capture_args", "capture_return"):
            if not isinstance(hook.get(key), bool):
                errors.append(f"{prefix}.{key} must be a boolean")
    return errors


def _render_planned_script(plan: CapabilityPlan, script: Mapping[str, Any]) -> tuple[Optional[str], list[str]]:
    errors = [str(script.get("error"))] if script.get("error") else []
    if script.get("source") != "generated" or script.get("controlled") is not True:
        errors.append("only provider-generated controlled scripts are accepted")
    source: Optional[str] = None
    if not errors:
        try:
            source = render_ios_instrumentation_script(
                script.get("hooks") or [],
                session_id=plan.session_id,
                max_events=plan.parameters.get("max_events"),
                duration_ms=plan.parameters.get("duration_ms"),
                max_string_length=plan.parameters.get("max_string_length"),
                max_byte_length=plan.parameters.get("max_byte_length"),
            )
        except ValueError as exc:
            errors.append(str(exc))
    if source is not None and _sha256_text(source) != script.get("sha256"):
        errors.append("controlled instrumentation script changed after planning")
    if source is not None and len(source.encode("utf-8")) != script.get("size"):
        errors.append("controlled instrumentation script size changed after planning")
    return source, _dedupe(errors)


def _cleanup_runtime(backend: Any, *, device: Any, spawned_pid: Optional[int], resumed: bool, script: Any, session: Any, force_kill: bool) -> dict[str, Any]:
    cleanup: dict[str, Any] = {
        "resume_attempted": False,
        "resume_completed": resumed or spawned_pid is None,
        "resumed": resumed,
        "unload_attempted": False,
        "unloaded": script is None,
        "detach_attempted": False,
        "detached": session is None,
        "kill_attempted": False,
        "kill_required": False,
        "killed": False,
        "errors": [],
        "lifecycle": [],
    }
    if spawned_pid is not None and not resumed:
        cleanup["resume_attempted"] = True
        try:
            cleanup["resumed"] = _operation_ok(backend.resume(device, spawned_pid))
            cleanup["resume_completed"] = cleanup["resumed"]
            cleanup["lifecycle"].append(_lifecycle("cleanup_resume", "completed" if cleanup["resumed"] else "failed"))
            if not cleanup["resumed"]:
                cleanup["errors"].append({"phase": "resume", "message": "backend did not confirm resume"})
        except Exception as exc:  # noqa: BLE001
            cleanup["errors"].append({"phase": "resume", **_exception(exc)})
    if script is not None:
        cleanup["unload_attempted"] = True
        try:
            cleanup["unloaded"] = _operation_ok(backend.unload_script(script))
            cleanup["lifecycle"].append(_lifecycle("unload_script", "completed" if cleanup["unloaded"] else "failed"))
            if not cleanup["unloaded"]:
                cleanup["errors"].append({"phase": "unload", "message": "backend did not confirm unload"})
        except Exception as exc:  # noqa: BLE001
            cleanup["errors"].append({"phase": "unload", **_exception(exc)})
    if session is not None:
        cleanup["detach_attempted"] = True
        try:
            cleanup["detached"] = _operation_ok(backend.detach(session))
            cleanup["lifecycle"].append(_lifecycle("detach", "completed" if cleanup["detached"] else "failed"))
            if not cleanup["detached"]:
                cleanup["errors"].append({"phase": "detach", "message": "backend did not confirm detach"})
        except Exception as exc:  # noqa: BLE001
            cleanup["errors"].append({"phase": "detach", **_exception(exc)})
    cleanup["kill_required"] = bool(spawned_pid is not None and (force_kill or not cleanup["unloaded"] or not cleanup["detached"]))
    if cleanup["kill_required"]:
        cleanup["kill_attempted"] = True
        try:
            cleanup["killed"] = _operation_ok(backend.kill(device, int(spawned_pid)))
            cleanup["lifecycle"].append(_lifecycle("kill_spawn", "completed" if cleanup["killed"] else "failed", pid=spawned_pid))
            if not cleanup["killed"]:
                cleanup["errors"].append({"phase": "kill", "message": "backend did not confirm kill"})
        except Exception as exc:  # noqa: BLE001
            cleanup["errors"].append({"phase": "kill", **_exception(exc)})
    cleanup["ok"] = bool(
        cleanup["resume_completed"]
        and cleanup["unloaded"]
        and cleanup["detached"]
        and (not cleanup["kill_required"] or cleanup["killed"])
        and not cleanup["errors"]
    )
    return cleanup


def _inactive_rollback(base: Mapping[str, Any], status: str, reason: str) -> dict[str, Any]:
    return {**_mapping(base), "supported": True, "active": False, "completed": True, "status": status, "reason": reason, "cleanup": {"ok": True, "not_started": True, "unloaded": True, "detached": True}}


def _completed_rollback(base: Mapping[str, Any], cleanup: Mapping[str, Any], execution_status: str) -> dict[str, Any]:
    completed = bool(cleanup.get("ok"))
    return {**_mapping(base), "supported": True, "active": not completed, "completed": completed, "status": "completed" if completed else "cleanup_failed", "execution_status": execution_status, "cleanup": _mapping(cleanup)}


def _normalize_message(message: Any, data: Any, *, max_string: int, max_bytes: int) -> dict[str, Any]:
    if isinstance(message, Mapping):
        payload = message.get("payload")
        event = dict(payload) if isinstance(payload, Mapping) else {"payload": payload}
        event.setdefault("message_type", str(message.get("type") or "message"))
        if message.get("type") == "error":
            event.setdefault("event", "script_error")
            event["description"] = message.get("description")
            event["stack"] = message.get("stack")
    else:
        event = {"event": "message", "payload": message, "message_type": "message"}
    event.setdefault("event", "message")
    event["captured_at"] = _utc_now()
    if data is not None:
        try:
            raw = bytes(data)
            retained = raw[:max_bytes]
            event["data"] = {"encoding": "base64", "value": base64.b64encode(retained).decode("ascii"), "size": len(raw), "retained_size": len(retained), "truncated": len(raw) != len(retained), "sha256": hashlib.sha256(raw).hexdigest()}
        except Exception:
            event["data"] = {"value": str(data)[:max_string]}
    return _redact(event, max_string=max_string)


def _result_artifacts(session_id: str) -> list[CapabilityArtifact]:
    root = f"ios_instrumentation/{_safe_segment(session_id)}"
    return [
        CapabilityArtifact(f"{root}/audit.json", "ios-instrumentation-audit", "iOS instrumentation lifecycle audit"),
        CapabilityArtifact(f"{root}/events.json", "ios-instrumentation-events", "Bounded Objective-C/native call events"),
        CapabilityArtifact(f"{root}/rollback.json", "ios-instrumentation-rollback", "Frida unload, detach, resume, and kill cleanup evidence"),
    ]


def _artifact_payloads(result: CapabilityExecutionResult) -> dict[str, dict[str, Any]]:
    report = _mapping(result.report_section)
    common = {"schema_version": _AUDIT_VERSION, "capability": result.capability, "provider": result.provider, "session_id": result.session_id, "status": result.status, "action": result.action, "target_identity": report.get("target_identity") or result.target.to_dict(), "device": report.get("device", {}), "precondition_hash": result.provenance.get("precondition_hash")}
    return {
        "ios-instrumentation-audit": {**common, "before_snapshot": result.before_snapshot, "after_snapshot": result.after_snapshot, "rollback_plan": result.rollback_plan, "provenance": result.provenance, "validation": report.get("validation", {}), "lifecycle": report.get("lifecycle", []), "errors": report.get("errors", [])},
        "ios-instrumentation-events": {**common, "event_count": len(report.get("events") or []), "dropped_event_count": result.after_snapshot.get("dropped_event_count", 0), "events": report.get("events", [])},
        "ios-instrumentation-rollback": {**common, "rollback_plan": result.rollback_plan, "rollback_history": report.get("rollback_history", []), "cleanup": result.rollback_plan.get("cleanup", {})},
    }


def _manifest_entry(artifact: CapabilityArtifact, result: CapabilityExecutionResult) -> dict[str, Any]:
    return {"path": artifact.path, "kind": artifact.kind, "role": artifact.kind, "description": artifact.description, "status": result.status, "session_id": result.session_id, "target_identity": result.target.to_dict(), "precondition_hash": result.provenance.get("precondition_hash"), "materialized": False}


def _artifact_destination(root: Path, path: str) -> Path:
    posix = PurePosixPath(str(path).replace("\\", "/"))
    windows = PureWindowsPath(str(path))
    if posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts or ".." in windows.parts:
        raise ValueError("artifact path must stay within the collection directory")
    destination = root.joinpath(*posix.parts).resolve()
    destination.relative_to(root)
    return destination


def _sync_report(result: CapabilityExecutionResult) -> None:
    result.report_section["after_snapshot"] = _mapping(result.after_snapshot)
    result.report_section["rollback_plan"] = _mapping(result.rollback_plan)
    result.report_section["provenance"] = _mapping(result.provenance)
    result.report_section["artifacts"] = [item.to_dict() for item in result.artifacts]
    result.report_section["evidence_manifest_entries"] = [dict(item) for item in result.evidence_manifest_entries]


def _plan_steps(action: str) -> list[dict[str, Any]]:
    names = ["select_device", "probe_target"]
    if action == "spawn":
        names.append("spawn_bundle")
    names.extend(["attach_session", "generate_controlled_script", "load_script"])
    if action == "spawn":
        names.append("resume_spawn")
    names.extend(["collect_bounded_events", "unload_script", "detach_session", "kill_spawn_if_required"])
    return [{"order": index + 1, "action": name} for index, name in enumerate(names)]


def _runtime_options(plan: CapabilityPlan) -> dict[str, Any]:
    return {**_mapping(plan.parameters.get("device")), "action": plan.action, "duration_ms": plan.parameters.get("duration_ms"), "max_events": plan.parameters.get("max_events"), "spawn_argv": list(plan.parameters.get("spawn_argv") or [])}


def _public_script(script: Mapping[str, Any]) -> dict[str, Any]:
    return _prune({"source": script.get("source"), "controlled": script.get("controlled"), "sha256": script.get("sha256"), "size": script.get("size"), "hook_count": len(script.get("hooks") or []), "hooks": list(script.get("hooks") or []), "error": script.get("error")})


def _backend_info(backend: Any) -> dict[str, Any]:
    assurance = _backend_assurance(backend)
    return _prune({"name": str(getattr(backend, "name", type(backend).__name__)), "available": bool(getattr(backend, "available", True)), "version": getattr(backend, "version", None), "host_platform": getattr(backend, "host_platform", None), "unavailable_reason": getattr(backend, "unavailable_reason", None), "test_double": assurance == "simulation", "real_device_parity": assurance == "production", "execution_assurance": assurance, "production_evidence": False})


def _backend_assurance(backend: Any) -> str:
    if not bool(getattr(backend, "available", True)):
        return "dependency_gated"
    production = (
        type(backend) is FridaIOSInstrumentationBackend
        and getattr(backend, "host_platform", None) == "darwin"
        and getattr(backend, "_binding_source", None) == "imported"
        and not bool(getattr(getattr(backend, "_frida", None), "test_double", False))
    )
    return "production" if production else "simulation"


def _backend_reason(backend: Any) -> str:
    return str(getattr(backend, "unavailable_reason", None) or "Frida iOS instrumentation backend is unavailable")


def _describe_device(backend: Any, device: Any) -> dict[str, Any]:
    try:
        return _mapping(backend.describe_device(device))
    except Exception as exc:  # noqa: BLE001
        return {"description_error": _exception(exc)}


def _describe_session(backend: Any, session: Any) -> dict[str, Any]:
    try:
        return _mapping(backend.describe_session(session))
    except Exception as exc:  # noqa: BLE001
        return {"description_error": _exception(exc)}


def _operation_ok(result: Any) -> bool:
    if result is None:
        return True
    if isinstance(result, bool):
        return result
    return not isinstance(result, Mapping) or (result.get("ok") is not False and result.get("status") not in {"failed", "error"})


def _call_timeout(function: Callable[..., Any], *args: Any, timeout_seconds: float) -> Any:
    try:
        return function(*args, timeout=timeout_seconds)
    except TypeError:
        return function(*args)


def _normalize_argv(value: Any) -> Any:
    if value in (None, ""):
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return value
    return [str(item) for item in value]


def _valid_argv(value: Any) -> bool:
    return isinstance(value, list) and len(value) <= _MAX_SPAWN_ARGUMENTS and all(isinstance(item, str) and "\x00" not in item for item in value)


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


def _int_range(value: Any, minimum: int, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _bounded(value: Any, minimum: int, maximum: int, default: int) -> int:
    value = _normalized_int(value)
    return min(maximum, max(minimum, value)) if isinstance(value, int) and not isinstance(value, bool) else default


def _positive_int(value: Any) -> Optional[int]:
    value = _normalized_int(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _normalize_offset(value: Any) -> Any:
    parsed = _parse_offset(value)
    return parsed if parsed is not None else value


def _parse_offset(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        parsed = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _bool(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "yes", "1", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "no", "0", "off"}:
        return False
    return value


def _first_text(*values: Any) -> Optional[str]:
    return next((text for value in values if (text := _text(value))), None)


def _text(value: Any) -> Optional[str]:
    return str(value).strip() or None if value not in (None, "") else None


def _sha256_text(value: Optional[str]) -> Optional[str]:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value is not None else None


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(_json_value(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


def _safe_segment(value: Any) -> str:
    return (re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "session")).strip(".-")[:128] or "session")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _lifecycle(phase: str, status: str, **details: Any) -> dict[str, Any]:
    return _prune({"phase": phase, "status": status, "ts": _utc_now(), **details})


def _exception(exc: Exception) -> dict[str, Any]:
    return {"type": type(exc).__name__, "message": str(exc)}


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    to_dict = getattr(value, "to_dict", None)
    return _mapping(to_dict()) if callable(to_dict) else {}


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return {"encoding": "base64", "value": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Path):
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    to_dict = getattr(value, "to_dict", None)
    return _json_value(to_dict()) if callable(to_dict) else str(value)


def _redact(value: Any, *, max_string: int = 4_096, _depth: int = 0) -> Any:
    if _depth > 12:
        return "<depth-limited>"
    if isinstance(value, Mapping):
        return {
            str(key): (
                "<redacted>"
                if _SENSITIVE_KEY_RE.search(str(key))
                else item
                if str(key).lower() == "sha256" and isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{64}", item)
                else _redact(item, max_string=max_string, _depth=_depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redact(item, max_string=max_string, _depth=_depth + 1) for item in list(value)[:256]]
    if isinstance(value, str):
        return value[:max_string] + ("<truncated>" if len(value) > max_string else "")
    return _json_value(value)


def _prune(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _prune(item) for key, item in value.items() if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [_prune(item) for item in value if item not in (None, "", [], {})]
    return value


def _dedupe(values: Sequence[Any]) -> list[str]:
    return list(dict.fromkeys(str(value) for value in values if str(value)))


__all__ = [
    "FridaIOSBackend",
    "FridaIOSInstrumentationBackend",
    "IOSFridaBackend",
    "IOSInstrumentationBackend",
    "IOSInstrumentationProvider",
    "UnavailableIOSInstrumentationBackend",
    "render_ios_hook_script",
    "render_ios_instrumentation_script",
]
