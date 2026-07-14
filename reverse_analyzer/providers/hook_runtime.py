"""Controlled Frida-backed runtime hook capability provider.

The Frida Python binding is optional.  Planning and validation remain usable
without it, while execution returns a structured ``unavailable`` result.
Only data-driven hook specifications are accepted; callers cannot provide
arbitrary JavaScript.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
from reverse_analyzer.providers.mock import MockCapabilityProvider


_AUDIT_SCHEMA_VERSION = 1
_SCRIPT_SCHEMA_VERSION = 1
_DEFAULT_DURATION_MS = 250
_MAX_DURATION_MS = 60_000
_DEFAULT_MAX_EVENTS = 1_000
_MAX_EVENTS = 10_000
_MAX_ARGUMENTS = 32
_MAX_ARGUMENT_LENGTH = 4_096
_MAX_TARGET_ARGUMENTS = 64

_API_HOOK = "api_hook"
_INLINE_HOOK = "inline_hook"
_BREAKPOINT_TRACE = "breakpoint_trace"
_SUPPORTED_HOOK_TYPES = {_API_HOOK, _INLINE_HOOK, _BREAKPOINT_TRACE}
_HOOK_TYPE_ALIASES = {
    "api": _API_HOOK,
    "api_hook": _API_HOOK,
    "inline": _INLINE_HOOK,
    "inline_hook": _INLINE_HOOK,
    "breakpoint": _BREAKPOINT_TRACE,
    "breakpoint_trace": _BREAKPOINT_TRACE,
}
_TRACE_ALIASES = {"hook_trace", "trace"}

_MODULE_RE = re.compile(r"^[A-Za-z0-9_.+-]{1,260}$")
_EXPORT_RE = re.compile(r"^[A-Za-z_?$@#][A-Za-z0-9_?$@#.-]{0,255}$")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.:+@-]{1,128}$")
_ARGUMENT_TYPE_ALIASES = {
    "pointer": "pointer",
    "ptr": "pointer",
    "utf8": "utf8",
    "ansi": "utf8",
    "string": "utf8",
    "utf16": "utf16",
    "wide": "utf16",
    "wstring": "utf16",
    "int32": "int32",
    "i32": "int32",
    "uint32": "uint32",
    "u32": "uint32",
    "int64": "int64",
    "i64": "int64",
    "uint64": "uint64",
    "u64": "uint64",
    "hex": "hex",
    "bool": "bool",
    "bytes": "bytes",
    "buffer": "bytes",
}
_RUNTIME_ERROR_EVENTS = {
    "hook_error",
    "hook-error",
    "hook_missing",
    "hook-missing",
    "script_error",
    "script-error",
}


class HookRuntimeBackend(Protocol):
    """Backend surface used by :class:`HookRuntimeProvider` and fake tests."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def attach(self, target: TargetIdentity, options: Mapping[str, Any]) -> Any: ...

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable[..., None],
    ) -> Any: ...

    def load_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...

    def wait(self, duration_ms: int) -> None: ...

    def unload_script(self, script: Any) -> Optional[Mapping[str, Any]]: ...

    def detach(self, session: Any) -> Optional[Mapping[str, Any]]: ...

    def describe_session(self, session: Any) -> Mapping[str, Any]: ...


class UnavailableHookRuntimeBackend:
    """Non-throwing backend used when the optional Frida binding is absent."""

    name = "frida"
    available = False

    def __init__(self, reason: str) -> None:
        self.unavailable_reason = reason

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del options
        return {
            "status": "unavailable",
            "accessible": None,
            "target": _target_identity(target),
            "reason": self.unavailable_reason,
        }

    def _raise(self) -> None:
        raise RuntimeError(self.unavailable_reason)

    def attach(self, target: TargetIdentity, options: Mapping[str, Any]) -> Any:
        del target, options
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

    def wait(self, duration_ms: int) -> None:
        del duration_ms
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


@dataclass
class _FridaSession:
    device: Any
    session: Any
    mode: str
    pid: int
    spawned: bool
    kill_on_detach: bool
    resumed: bool = False


@dataclass
class _FridaScript:
    runtime: _FridaSession
    script: Any


class FridaHookBackend:
    """Thin adapter around the optional Frida Python binding."""

    name = "frida"

    def __init__(self, frida_module: Any = None) -> None:
        self._frida: Any = frida_module
        self.available = False
        self.unavailable_reason: Optional[str] = None
        self.version: Optional[str] = None
        if self._frida is None:
            try:
                self._frida = importlib.import_module("frida")
            except Exception as exc:  # noqa: BLE001 - optional dependency boundary
                self.unavailable_reason = f"Frida Python binding is unavailable: {exc}"
                return
        self.available = True
        self.version = str(getattr(self._frida, "__version__", "") or "") or None

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del options
        if not self.available:
            return UnavailableHookRuntimeBackend(
                self.unavailable_reason or "Frida is unavailable"
            ).probe_target(target, {})

        pid = _positive_int(target.pid)
        path = str(target.path or "").strip()
        try:
            device = self._frida.get_local_device()
            if pid is not None:
                processes = device.enumerate_processes()
                process = next(
                    (item for item in processes if int(getattr(item, "pid", 0)) == pid),
                    None,
                )
                return {
                    "status": "ok" if process is not None else "failed",
                    "accessible": process is not None,
                    "exists": process is not None,
                    "mode": "attach",
                    "pid": pid,
                    "name": getattr(process, "name", None) if process is not None else None,
                }

            sample = Path(path)
            exists = sample.is_file()
            return {
                "status": "ok" if exists else "failed",
                "accessible": exists,
                "exists": exists,
                "mode": "spawn",
                "path": str(sample),
            }
        except Exception as exc:  # noqa: BLE001 - Frida device errors are backend data
            return {
                "status": "failed",
                "accessible": False,
                "mode": "attach" if pid is not None else "spawn",
                "pid": pid,
                "path": path or None,
                "error": _exception_payload(exc),
            }

    def attach(self, target: TargetIdentity, options: Mapping[str, Any]) -> _FridaSession:
        self._require_available()
        device = self._frida.get_local_device()
        pid = _positive_int(target.pid)
        if pid is not None:
            session = device.attach(pid)
            return _FridaSession(
                device=device,
                session=session,
                mode="attach",
                pid=pid,
                spawned=False,
                kill_on_detach=False,
                resumed=True,
            )

        path = str(target.path or "")
        argv = [path, *[str(item) for item in options.get("target_args", [])]]
        spawned_pid = int(device.spawn(argv))
        try:
            session = device.attach(spawned_pid)
        except Exception:
            try:
                device.kill(spawned_pid)
            except Exception:
                pass
            raise
        return _FridaSession(
            device=device,
            session=session,
            mode="spawn",
            pid=spawned_pid,
            spawned=True,
            kill_on_detach=bool(options.get("kill_spawned_on_rollback", False)),
        )

    def create_script(
        self,
        session: _FridaSession,
        source: str,
        on_message: Callable[..., None],
    ) -> _FridaScript:
        script = session.session.create_script(source)
        script.on("message", on_message)
        return _FridaScript(runtime=session, script=script)

    def load_script(self, script: _FridaScript) -> Mapping[str, Any]:
        script.script.load()
        runtime = script.runtime
        if runtime.spawned and not runtime.resumed:
            runtime.device.resume(runtime.pid)
            runtime.resumed = True
        return {"ok": True, "loaded": True, "resumed": runtime.resumed}

    def wait(self, duration_ms: int) -> None:
        time.sleep(max(0, duration_ms) / 1000.0)

    def unload_script(self, script: _FridaScript) -> Mapping[str, Any]:
        if _frida_object_flag(script.script, "is_destroyed"):
            return {
                "ok": True,
                "unloaded": True,
                "already_destroyed": True,
                "target_detached": _frida_object_flag(
                    script.runtime.session, "is_detached"
                ),
            }
        try:
            script.script.unload()
        except Exception:
            # Frida destroys scripts when the target exits.  That is the desired
            # terminal state even though an explicit unload is no longer valid.
            if not (
                _frida_object_flag(script.script, "is_destroyed")
                or _frida_object_flag(script.runtime.session, "is_detached")
            ):
                raise
            return {
                "ok": True,
                "unloaded": True,
                "already_destroyed": True,
                "target_detached": True,
            }
        return {"ok": True, "unloaded": True, "already_destroyed": False}

    def detach(self, session: _FridaSession) -> Mapping[str, Any]:
        already_detached = _frida_object_flag(session.session, "is_detached")
        if not already_detached:
            session.session.detach()
        killed = False
        already_exited = False
        if session.spawned and session.kill_on_detach:
            try:
                session.device.kill(session.pid)
                killed = True
            except Exception as exc:
                process_not_found = getattr(self._frida, "ProcessNotFoundError", None)
                if not (
                    isinstance(process_not_found, type)
                    and isinstance(exc, process_not_found)
                ):
                    raise
                already_exited = True
        return {
            "ok": True,
            "detached": True,
            "already_detached": already_detached,
            "spawned_process_killed": killed,
            "spawned_process_already_exited": already_exited,
        }

    def describe_session(self, session: _FridaSession) -> Mapping[str, Any]:
        return {
            "backend": self.name,
            "mode": session.mode,
            "pid": session.pid,
            "spawned": session.spawned,
            "resumed": session.resumed,
            "detached": _frida_object_flag(session.session, "is_detached"),
        }

    def _require_available(self) -> None:
        if not self.available:
            raise RuntimeError(self.unavailable_reason or "Frida is unavailable")


# A concise public alias for callers that inject or inspect the backend directly.
FridaBackend = FridaHookBackend


class HookRuntimeProvider:
    """Run bounded hook captures that are closed before execution returns.

    The provider deliberately does not expose a durable active-session contract.
    Frida handles cannot survive the short-lived CLI process, so every execution
    unloads its script and detaches in-process.  ``rollback`` is consequently an
    idempotent audit operation for completed cleanup, never a claim that persisted
    handles can be recovered in another process.
    """

    capability_name = "hook_runtime"
    provider_name = "frida_hook_runtime"
    priority = 10

    def __init__(
        self,
        backend: Optional[HookRuntimeBackend] = None,
        *,
        duration_ms: int = _DEFAULT_DURATION_MS,
        max_events: int = _DEFAULT_MAX_EVENTS,
    ) -> None:
        self.backend: HookRuntimeBackend = backend if backend is not None else FridaHookBackend()
        self.duration_ms = _bounded_int(
            duration_ms,
            minimum=0,
            maximum=_MAX_DURATION_MS,
            default=_DEFAULT_DURATION_MS,
        )
        self.max_events = _bounded_int(
            max_events,
            minimum=1,
            maximum=_MAX_EVENTS,
            default=_DEFAULT_MAX_EVENTS,
        )

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        hook_type = _request_hook_type(request)
        return request.capability == self.capability_name and hook_type in _SUPPORTED_HOOK_TYPES

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        hook_type = _request_hook_type(request)
        session_id = str(request.session_id or "hook-runtime-session")
        hook_specification = _request_hook_specification(request, hook_type)
        target_identity = _target_identity(request.target)

        requested_duration = request.params.get("duration_ms", self.duration_ms)
        duration_ms = _normalized_int(requested_duration)
        requested_max_events = request.params.get("max_events", self.max_events)
        max_events = _normalized_int(requested_max_events)
        target_args = _normalize_target_args(request.params.get("target_args", []))
        kill_spawned = _normalize_bool(
            request.params.get("kill_spawned_on_rollback", False)
        )
        options = {
            "duration_ms": duration_ms,
            "max_events": max_events,
            "target_args": target_args,
            "kill_spawned_on_rollback": kill_spawned,
        }
        fingerprint = _plan_fingerprint(
            target_identity,
            hook_specification,
            options,
        )

        script_sha256: Optional[str] = None
        spec_errors = _hook_specification_errors(hook_specification)
        if not spec_errors and _valid_runtime_options(options):
            source = render_frida_hook_script(
                hook_specification,
                session_id=session_id,
                max_events=int(max_events),
            )
            script_sha256 = _sha256_text(source)

        backend_info = _backend_info(backend)
        parameters = {
            "requested_action": request.action,
            "hook_type": hook_type,
            "hook_specification": hook_specification,
            "planned_target_identity": target_identity,
            "duration_ms": duration_ms,
            "requested_duration_ms": _json_value(requested_duration),
            "max_events": max_events,
            "requested_max_events": _json_value(requested_max_events),
            "target_args": target_args,
            "kill_spawned_on_rollback": kill_spawned,
            "script_schema_version": _SCRIPT_SCHEMA_VERSION,
            "script_sha256": script_sha256,
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
            },
            "target_identity": target_identity,
            "hook_specification": hook_specification,
            "events": [],
            "backend": backend_info,
        }
        rollback_plan = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "supported": True,
            "mode": "execute_cleanup",
            "session_id": session_id,
            "active": False,
            "unload_required": False,
            "detach_required": False,
            "completed": False,
            "idempotent": True,
            "executable": False,
            "cross_process_supported": False,
            "order": ["unload_script", "detach_session"],
        }
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=hook_type,
            parameters=parameters,
            steps=_plan_steps(hook_type),
            precondition_hash=fingerprint,
            before_snapshot=before_snapshot,
            rollback_plan=rollback_plan,
            provenance={
                **_json_mapping(request.provenance),
                "audit_schema_version": _AUDIT_SCHEMA_VERSION,
                "script_schema_version": _SCRIPT_SCHEMA_VERSION,
                "provider": self.provider_name,
                "backend": backend_info,
                "requested_action": request.action,
                "hook_type": hook_type,
                "target_identity": target_identity,
                "hook_specification_sha256": _sha256_json(hook_specification),
                "script_sha256": script_sha256,
                "controlled_script": True,
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
        validation, target_probe, source = self._validate_plan(plan, context=context)
        hook_specification = _json_mapping(plan.parameters.get("hook_specification"))
        backend_info = _backend_info(backend)
        before_snapshot = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "capture_phase": "before",
            "session": {
                "id": plan.session_id,
                "state": "inactive",
                "attached": False,
                "script_loaded": False,
            },
            "target_identity": _target_identity(plan.target),
            "hook_specification": hook_specification,
            "events": [],
            "backend": backend_info,
            "target_probe": target_probe,
            "validation": validation.to_dict(),
        }

        if not validation.ok or source is None:
            errors = list(validation.errors)
            if source is None and not errors:
                errors.append("controlled Frida script could not be generated")
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="blocked",
                reason="execution was blocked by plan validation",
            )
            after_snapshot = {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "after",
                "session": {
                    "id": plan.session_id,
                    "state": "blocked",
                    "attached": False,
                    "script_loaded": False,
                },
                "target_identity": _target_identity(plan.target),
                "hook_specification": hook_specification,
                "events": [],
                "event_count": 0,
                "rollback": rollback_plan,
            }
            return self._execution_result(
                plan,
                status="failed",
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                validation=validation,
                events=[],
                session=after_snapshot["session"],
                errors=errors,
            )

        if not _backend_available(backend):
            reason = _backend_reason(backend)
            rollback_plan = _inactive_rollback_plan(
                plan.rollback_plan,
                status="unavailable",
                reason=reason,
            )
            after_snapshot = {
                "schema_version": _AUDIT_SCHEMA_VERSION,
                "capture_phase": "after",
                "session": {
                    "id": plan.session_id,
                    "state": "unavailable",
                    "attached": False,
                    "script_loaded": False,
                },
                "target_identity": _target_identity(plan.target),
                "hook_specification": hook_specification,
                "events": [],
                "event_count": 0,
                "rollback": rollback_plan,
                "reason": reason,
            }
            return self._execution_result(
                plan,
                status="unavailable",
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
                rollback_plan=rollback_plan,
                validation=validation,
                events=[],
                session=after_snapshot["session"],
                errors=[reason],
            )

        max_events = int(plan.parameters["max_events"])
        duration_ms = int(plan.parameters["duration_ms"])
        events: list[dict[str, Any]] = []
        dropped_events = [0]

        def on_message(message: Any, data: Any = None) -> None:
            event = _normalize_event(message, data)
            if len(events) < max_events:
                events.append(event)
            else:
                dropped_events[0] += 1

        session_handle: Any = None
        script_handle: Any = None
        session_identity: dict[str, Any] = {}
        errors: list[Any] = []
        cleanup: Optional[dict[str, Any]] = None
        options = _runtime_options(plan)
        try:
            session_handle = backend.attach(plan.target, options)
            if session_handle is None:
                raise RuntimeError("Frida backend returned no attached session handle")
            session_identity = _describe_backend_session(backend, session_handle)
            script_handle = backend.create_script(session_handle, source, on_message)
            if script_handle is None:
                raise RuntimeError("Frida backend returned no script handle")
            load_result = backend.load_script(script_handle)
            if not _backend_operation_ok(load_result):
                raise RuntimeError(f"Frida script load failed: {_json_value(load_result)}")
            backend.wait(duration_ms)
        except Exception as exc:  # noqa: BLE001 - backend failure becomes audit evidence
            errors.append(_exception_payload(exc))
        finally:
            if session_handle is not None:
                # Spawn sessions transition to resumed during load_script().  Refresh
                # the snapshot before cleanup so the audit reflects what ran.
                session_identity = _describe_backend_session(backend, session_handle)
            cleanup = _cleanup_runtime(
                backend,
                script_handle=script_handle,
                session_handle=session_handle,
            )
            if session_handle is not None:
                session_identity.update(
                    _describe_backend_session(backend, session_handle)
                )

        runtime_errors = [
            event for event in events if str(event.get("event") or "") in _RUNTIME_ERROR_EVENTS
        ]
        if runtime_errors:
            errors.extend(runtime_errors)

        cleanup_ok = bool(cleanup.get("ok"))
        if not cleanup_ok:
            errors.append(
                {
                    "phase": "cleanup",
                    "message": "bounded hook session cleanup did not complete",
                    "details": _json_mapping(cleanup),
                }
            )

        status = "ok" if not errors and cleanup_ok else "failed"
        session_state = "closed" if cleanup_ok else "cleanup_failed"
        detached = bool(cleanup.get("detached"))
        unloaded = bool(cleanup.get("unloaded"))
        session_payload = {
            "id": plan.session_id,
            **session_identity,
            "state": session_state,
            "attached": session_handle is not None and not detached,
            "script_loaded": (
                script_handle is not None and not unloaded and not detached
            ),
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
            "target_identity": _target_identity(plan.target),
            "hook_specification": hook_specification,
            "events": events,
            "event_count": len(events),
            "dropped_event_count": dropped_events[0],
            "script_sha256": _sha256_text(source),
            "rollback": rollback_plan,
            "cleanup": cleanup,
        }
        return self._execution_result(
            plan,
            status=status,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            validation=validation,
            events=events,
            session=session_payload,
            errors=errors,
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
                "bounded hook session cleanup completed before execute returned; "
                "no runtime handles were persisted"
            )
        else:
            status = "failed"
            reason = (
                "bounded hook session cleanup was incomplete and runtime handles "
                "were not persisted; cross-process rollback is unsupported"
            )
        details = {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "status": status,
            "session_id": result.session_id,
            "idempotent": True,
            "cross_process_supported": False,
            "unload_attempted": False,
            "detach_attempted": False,
            "completed": completed,
            "reason": reason,
        }
        self._record_rollback(result, details, ok=completed)
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
        artifacts = list(result.artifacts or [])
        if not artifacts:
            artifacts.append(_audit_artifact(result.session_id, result.action, result.status))
        entries_by_path = {
            str(entry.get("path")): dict(entry)
            for entry in result.evidence_manifest_entries or []
            if entry.get("path")
        }
        manifest_entries: list[dict[str, Any]] = []
        audit_payload = _hook_runtime_audit_payload(result)
        for artifact in artifacts:
            artifact.metadata.setdefault("collection_root", str(collection_root))
            destination = _artifact_destination(collection_root, artifact.path)
            entry = entries_by_path.get(
                artifact.path,
                _manifest_entry(
                    artifact,
                    status=result.status,
                    session_id=result.session_id,
                    hook_type=result.action,
                    target=result.target,
                    precondition_hash=result.provenance.get("precondition_hash"),
                ),
            )
            if artifact.kind == "hook-runtime-audit":
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
    ) -> tuple[CapabilityValidation, dict[str, Any], Optional[str]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        warnings: list[str] = []
        errors: list[str] = []

        def check(name: str, ok: bool, *, error: Optional[str] = None, **details: Any) -> None:
            checks.append(
                _prune(
                    {
                        "name": name,
                        "status": "ok" if ok else "failed",
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

        hook_specification = _json_mapping(plan.parameters.get("hook_specification"))
        hook_type = str(hook_specification.get("type") or plan.action or "")
        parameter_hook_type = plan.parameters.get("hook_type")
        hook_type_ok = (
            hook_type in _SUPPORTED_HOOK_TYPES
            and plan.action == hook_type
            and parameter_hook_type == hook_type
        )
        check(
            "hook_type",
            hook_type_ok,
            error=f"unsupported or inconsistent hook type: {hook_type}",
            hook_type=hook_type,
            plan_action=plan.action,
            parameter_hook_type=parameter_hook_type,
        )

        spec_errors = _hook_specification_errors(hook_specification)
        check(
            "hook_specification",
            not spec_errors,
            error="; ".join(spec_errors) if spec_errors else None,
            errors=spec_errors,
        )
        module_ok, export_ok, address_ok, arguments_ok = _hook_field_statuses(
            hook_specification
        )
        checks.extend(
            [
                {"name": "module", "status": module_ok},
                {"name": "export", "status": export_ok},
                {"name": "address", "status": address_ok},
                {"name": "arguments", "status": arguments_ok},
            ]
        )

        target_identity = _target_identity(plan.target)
        planned_target = _json_mapping(plan.parameters.get("planned_target_identity"))
        target_errors = _target_errors(plan.target)
        target_matches = target_identity == planned_target
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
            matches_planned_identity=target_matches,
        )

        options = _runtime_options(plan)
        duration_ok = _integer_in_range(
            options.get("duration_ms"), 0, _MAX_DURATION_MS
        )
        max_events_ok = _integer_in_range(options.get("max_events"), 1, _MAX_EVENTS)
        target_args_ok = _valid_target_args(options.get("target_args"))
        kill_spawned_ok = isinstance(options.get("kill_spawned_on_rollback"), bool)
        check(
            "duration_ms",
            duration_ok,
            error=f"duration_ms must be an integer from 0 to {_MAX_DURATION_MS}",
            actual=options.get("duration_ms"),
        )
        check(
            "max_events",
            max_events_ok,
            error=f"max_events must be an integer from 1 to {_MAX_EVENTS}",
            actual=options.get("max_events"),
        )
        check(
            "target_args",
            target_args_ok,
            error=(
                f"target_args must contain at most {_MAX_TARGET_ARGUMENTS} strings "
                f"without NUL characters"
            ),
        )
        check(
            "kill_spawned_on_rollback",
            kill_spawned_ok,
            error="kill_spawned_on_rollback must be a boolean",
        )

        expected_fingerprint = _plan_fingerprint(
            target_identity,
            hook_specification,
            options,
        )
        integrity_ok = bool(plan.precondition_hash) and plan.precondition_hash == expected_fingerprint
        check(
            "plan_integrity",
            integrity_ok,
            error="hook plan precondition hash does not match its target, specification, or params",
            expected=expected_fingerprint,
            actual=plan.precondition_hash,
        )

        source: Optional[str] = None
        generation_prerequisites = (
            not spec_errors
            and hook_type_ok
            and duration_ok
            and max_events_ok
            and bool(plan.session_id)
        )
        if generation_prerequisites:
            try:
                source = render_frida_hook_script(
                    hook_specification,
                    session_id=plan.session_id,
                    max_events=int(options["max_events"]),
                )
            except ValueError as exc:
                errors.append(str(exc))
        expected_script_hash = plan.parameters.get("script_sha256")
        script_hash = _sha256_text(source) if source is not None else None
        script_ok = source is not None and expected_script_hash == script_hash
        check(
            "controlled_script",
            script_ok,
            error=(
                "controlled Frida script hash is missing or does not match the generated script"
                if generation_prerequisites
                else None
            ),
            controlled=True,
            expected_sha256=expected_script_hash,
            actual_sha256=script_hash,
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
        target_probe: dict[str, Any] = {
            "status": "not_probed",
            "reason": "plan validation failed before target probing",
        }
        if not backend_available:
            reason = _backend_reason(backend)
            warnings.append(reason)
            target_probe = {
                "status": "unavailable",
                "accessible": None,
                "reason": reason,
            }
            checks.append(
                {
                    "name": "target_probe",
                    "status": "unavailable",
                    "reason": reason,
                }
            )
        elif errors:
            target_probe = {
                "status": "skipped",
                "reason": "data-only plan validation failed before target probing",
            }
            checks.append(
                {
                    "name": "target_probe",
                    "status": "skipped",
                    "reason": target_probe["reason"],
                }
            )
        else:
            probe = getattr(backend, "probe_target", None)
            if callable(probe):
                try:
                    target_probe = _json_mapping(probe(plan.target, options))
                except Exception as exc:  # noqa: BLE001 - backend probe is evidence
                    target_probe = {
                        "status": "failed",
                        "accessible": False,
                        "error": _exception_payload(exc),
                    }
                accessible = target_probe.get("accessible") is not False
                exists = target_probe.get("exists") is not False
                probe_ok = accessible and exists and target_probe.get("status") != "failed"
                check(
                    "target_probe",
                    probe_ok,
                    error="Frida backend could not access the target",
                    probe=target_probe,
                )
            else:
                target_probe = {
                    "status": "skipped",
                    "reason": "backend does not implement probe_target",
                }
                checks.append(
                    {
                        "name": "target_probe",
                        "status": "skipped",
                        "reason": target_probe["reason"],
                    }
                )
                warnings.append(target_probe["reason"])

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
            target_probe,
            source,
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        status: str,
        before_snapshot: Mapping[str, Any],
        after_snapshot: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        validation: CapabilityValidation,
        events: list[dict[str, Any]],
        session: Mapping[str, Any],
        errors: list[Any],
    ) -> CapabilityExecutionResult:
        hook_specification = _json_mapping(plan.parameters.get("hook_specification"))
        target_identity = _target_identity(plan.target)
        artifact = _audit_artifact(plan.session_id, plan.action, status)
        artifact.metadata.update(
            {
                "target_identity": target_identity,
                "precondition_hash": plan.precondition_hash,
                "session_state": session.get("state"),
                "rollback_completed": bool(rollback_plan.get("completed")),
                "cross_process_rollback_supported": False,
            }
        )
        manifest = _manifest_entry(
            artifact,
            status=status,
            session_id=plan.session_id,
            hook_type=plan.action,
            target=plan.target,
            precondition_hash=plan.precondition_hash,
        )
        provenance = {
            **_json_mapping(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "script_sha256": plan.parameters.get("script_sha256"),
            "hook_specification_sha256": _sha256_json(hook_specification),
            "event_count": len(events),
            "controlled_script": True,
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
            "target_identity": target_identity,
            "precondition_hash": plan.precondition_hash,
            "hook_specification": hook_specification,
            "events": [_json_mapping(item) for item in events],
            "before": _json_mapping(before_snapshot),
            "after": _json_mapping(after_snapshot),
            "rollback": _json_mapping(rollback_plan),
            "before_snapshot": _json_mapping(before_snapshot),
            "after_snapshot": _json_mapping(after_snapshot),
            "rollback_plan": _json_mapping(rollback_plan),
            "provenance": provenance,
            "artifacts": [artifact.to_dict()],
            "evidence_manifest_entries": [dict(manifest)],
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
            artifacts=[artifact],
            evidence_manifest_entries=[manifest],
            report_section=report_section,
            dashboard_trace=[
                {
                    "kind": "hook_runtime_execution",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "session_id": plan.session_id,
                    "hook_type": plan.action,
                    "status": status,
                    "event_count": len(events),
                    "target": target_identity,
                }
            ],
            provenance=provenance,
        )

    def _record_rollback(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        *,
        ok: bool,
    ) -> None:
        result.rollback_plan.update(
            {
                "active": False,
                "unload_required": False,
                "detach_required": False,
                "idempotent": True,
                "cross_process_supported": False,
                "last_rollback_request": _json_mapping(details),
            }
        )
        result.after_snapshot["rollback"] = _json_mapping(result.rollback_plan)
        result.report_section["rollback"] = _json_mapping(result.rollback_plan)
        sessions = [
            result.after_snapshot.setdefault("session", {}),
            result.report_section.setdefault("session", {}),
        ]
        for session in sessions:
            if not isinstance(session, dict):
                continue
            if (
                result.rollback_plan.get("completed")
                and result.rollback_plan.get("mode") == "execute_cleanup"
            ):
                session.update(
                    {
                        "state": "closed",
                        "attached": False,
                        "script_loaded": False,
                    }
                )
        result.dashboard_trace.append(
            {
                "kind": "hook_runtime_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": str(details.get("status") or ("ok" if ok else "failed")),
                "idempotent": True,
                "cross_process_supported": False,
            }
        )
        _sync_audit_report(result)

    def _select_backend(
        self,
        context: Optional[dict[str, Any]],
    ) -> HookRuntimeBackend:
        if isinstance(context, Mapping):
            backend = context.get("hook_runtime_backend")
            if backend is not None:
                return backend
        return self.backend


class HookRuntimeMockProvider(MockCapabilityProvider):
    def __init__(self) -> None:
        super().__init__("hook_runtime")


def render_frida_hook_script(
    hook_specification: Mapping[str, Any],
    *,
    session_id: str = "hook-runtime-session",
    max_events: int = _DEFAULT_MAX_EVENTS,
) -> str:
    """Render a fixed Frida agent after strict data-only validation."""

    specification = _json_mapping(hook_specification)
    errors = _hook_specification_errors(specification)
    if errors:
        raise ValueError("invalid hook specification: " + "; ".join(errors))
    if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
        raise ValueError("invalid hook session_id")
    if not _integer_in_range(max_events, 1, _MAX_EVENTS):
        raise ValueError(f"max_events must be from 1 to {_MAX_EVENTS}")

    spec_json = json.dumps(specification, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    session_json = json.dumps(session_id, ensure_ascii=True)
    template = r"""'use strict';

const SPEC = __SPEC_JSON__;
const SESSION_ID = __SESSION_JSON__;
const MAX_EVENTS = __MAX_EVENTS__;
let emittedEvents = 0;

function emit(event, details) {
  if (emittedEvents >= MAX_EVENTS) return;
  emittedEvents += 1;
  const payload = Object.assign({
    event: event,
    session_id: SESSION_ID,
    hook_type: SPEC.type
  }, details || {});
  send(payload);
}

function safePointer(value) {
  try { return ptr(value).toString(); } catch (error) { return String(value); }
}

function safeString(value, encoding, maxLength) {
  try {
    const pointerValue = ptr(value);
    if (pointerValue.isNull()) return null;
    if (encoding === 'utf16') return pointerValue.readUtf16String(maxLength);
    return pointerValue.readUtf8String(maxLength);
  } catch (error) {
    return { pointer: safePointer(value), error: String(error) };
  }
}

function safeBytes(value, maxLength) {
  try {
    const pointerValue = ptr(value);
    if (pointerValue.isNull()) return null;
    const bytes = new Uint8Array(pointerValue.readByteArray(maxLength));
    let hex = '';
    for (let index = 0; index < bytes.length; index += 1) {
      hex += ('0' + bytes[index].toString(16)).slice(-2);
    }
    return { pointer: pointerValue.toString(), length: bytes.length, hex: hex };
  } catch (error) {
    return { pointer: safePointer(value), error: String(error) };
  }
}

function readArgument(specification, args) {
  const value = args[specification.index];
  const kind = specification.type;
  if (kind === 'utf8' || kind === 'utf16') {
    return safeString(value, kind, specification.max_length);
  }
  if (kind === 'bytes') return safeBytes(value, specification.max_length);
  if (kind === 'int32') {
    try { return ptr(value).toInt32(); } catch (error) { return safePointer(value); }
  }
  if (kind === 'uint32') {
    try { return ptr(value).toUInt32(); } catch (error) { return safePointer(value); }
  }
  if (kind === 'int64') {
    try { return ptr(value).toInt64().toString(); } catch (error) { return safePointer(value); }
  }
  if (kind === 'uint64') {
    try { return ptr(value).toUInt64().toString(); } catch (error) { return safePointer(value); }
  }
  if (kind === 'bool') {
    try { return !ptr(value).isNull(); } catch (error) { return false; }
  }
  return safePointer(value);
}

function readArguments(args) {
  const captured = {};
  (SPEC.arguments || []).forEach(function (argument) {
    captured[argument.name] = readArgument(argument, args);
  });
  return captured;
}

function contextSnapshot(context) {
  const captured = {};
  if (context === undefined || context === null) return captured;
  Object.keys(context).slice(0, 64).forEach(function (name) {
    captured[name] = safePointer(context[name]);
  });
  return captured;
}

function resolveTarget() {
  let target = null;
  if (SPEC.type === 'api_hook') {
    const loadedModule = Process.findModuleByName(SPEC.module);
    if (loadedModule === null) throw new Error('module is not loaded: ' + SPEC.module);
    if (typeof loadedModule.findExportByName === 'function') {
      target = loadedModule.findExportByName(SPEC.export);
    } else if (typeof Module.findExportByName === 'function') {
      target = Module.findExportByName(SPEC.module, SPEC.export);
    } else if (typeof loadedModule.getExportByName === 'function') {
      try { target = loadedModule.getExportByName(SPEC.export); } catch (error) { target = null; }
    }
    if (target === null) throw new Error('export is not available: ' + SPEC.export);
  } else {
    target = ptr(SPEC.address);
  }
  const range = Process.findRangeByAddress(target);
  if (range === null) throw new Error('hook address is not mapped: ' + target);
  if (range.protection.indexOf('x') === -1) {
    throw new Error('hook address is not executable: ' + target);
  }
  return target;
}

try {
  const target = resolveTarget();
  const listener = Interceptor.attach(target, {
    onEnter(args) {
      const capturedArguments = readArguments(args);
      this.capturedArguments = capturedArguments;
      emit(SPEC.type === 'breakpoint_trace' ? 'breakpoint_hit' : 'hook_call', {
        address: target.toString(),
        module: SPEC.module || null,
        export: SPEC.export || null,
        label: SPEC.label || null,
        thread_id: Process.getCurrentThreadId(),
        arguments: capturedArguments,
        context: SPEC.type === 'breakpoint_trace' ? contextSnapshot(this.context) : undefined
      });
    },
    onLeave(returnValue) {
      if (!SPEC.capture_return) return;
      emit('hook_return', {
        address: target.toString(),
        module: SPEC.module || null,
        export: SPEC.export || null,
        label: SPEC.label || null,
        thread_id: Process.getCurrentThreadId(),
        return_value: safePointer(returnValue),
        arguments: this.capturedArguments || {}
      });
    }
  });
  emit('hook_installed', {
    address: target.toString(),
    module: SPEC.module || null,
    export: SPEC.export || null,
    label: SPEC.label || null
  });
  emit('hook_ready', { listener_active: listener !== null });
} catch (error) {
  emit('hook_error', { message: String(error), stack: error.stack || null });
}
"""
    return (
        template.replace("__SPEC_JSON__", spec_json)
        .replace("__SESSION_JSON__", session_json)
        .replace("__MAX_EVENTS__", str(max_events))
    )


def _request_hook_type(request: CapabilityRequest) -> str:
    nested = request.params.get("hook_specification") or request.params.get("hook") or {}
    explicit: Any = None
    if isinstance(nested, Mapping):
        explicit = nested.get("type") or nested.get("hook_type")
    explicit = request.params.get("hook_type") or request.params.get("type") or explicit
    if explicit:
        normalized = _normalize_hook_type(explicit)
        if normalized not in _TRACE_ALIASES:
            return normalized
    else:
        normalized = str(request.action or "").strip().lower().replace("-", "_")

    if normalized in _TRACE_ALIASES:
        module = _first_value(request.params, nested, "module", "module_name")
        export = _first_value(
            request.params,
            nested,
            "export",
            "export_name",
            "symbol",
            "function",
        )
        address = _first_value(request.params, nested, "address")
        if module is not None or export is not None:
            return _API_HOOK
        if address is not None:
            return _BREAKPOINT_TRACE
        return _BREAKPOINT_TRACE
    return _normalize_hook_type(normalized)


def _normalize_hook_type(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return _HOOK_TYPE_ALIASES.get(normalized, normalized)


def _request_hook_specification(
    request: CapabilityRequest,
    hook_type: str,
) -> dict[str, Any]:
    nested_value = request.params.get("hook_specification") or request.params.get("hook") or {}
    nested = dict(nested_value) if isinstance(nested_value, Mapping) else {}
    module = _first_value(request.params, nested, "module", "module_name")
    export = _first_value(
        request.params,
        nested,
        "export",
        "export_name",
        "symbol",
        "function",
    )
    address = _first_value(request.params, nested, "address")
    arguments = _first_value(request.params, nested, "arguments", "args")
    capture_return = _first_value(request.params, nested, "capture_return")
    label = _first_value(request.params, nested, "label")

    known_nested_fields = {
        "type",
        "hook_type",
        "module",
        "module_name",
        "export",
        "export_name",
        "symbol",
        "function",
        "address",
        "arguments",
        "args",
        "capture_return",
        "label",
    }
    forbidden_fields = {"javascript", "script", "script_source", "source"}
    custom_script_supplied = any(
        key in request.params or key in nested for key in forbidden_fields
    )
    unknown_fields = sorted(str(key) for key in nested if key not in known_nested_fields)
    specification = {
        "schema_version": _SCRIPT_SCHEMA_VERSION,
        "type": hook_type,
        "arguments": _normalize_arguments(arguments),
        "capture_return": _normalize_bool(
            False if capture_return is None else capture_return
        ),
    }
    optional_values = {
        "module": _normalize_optional_text(module),
        "export": _normalize_optional_text(export),
        "address": _normalize_address(address),
        "label": _normalize_optional_text(label),
    }
    specification.update(
        {key: value for key, value in optional_values.items() if value is not None}
    )
    if custom_script_supplied:
        specification["custom_script_supplied"] = True
    if unknown_fields:
        specification["unknown_fields"] = unknown_fields
    return specification


def _hook_specification_errors(specification: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    hook_type = specification.get("type")
    module = specification.get("module")
    export = specification.get("export")
    address = specification.get("address")
    forbidden_fields = {"javascript", "script", "script_source", "source"}
    allowed_fields = {
        "schema_version",
        "type",
        "module",
        "export",
        "address",
        "arguments",
        "capture_return",
        "label",
        "custom_script_supplied",
        "unknown_fields",
    }

    if specification.get("schema_version") != _SCRIPT_SCHEMA_VERSION:
        errors.append("unsupported hook specification schema_version")
    if hook_type not in _SUPPORTED_HOOK_TYPES:
        errors.append(f"unsupported hook type: {hook_type}")
    if specification.get("custom_script_supplied") or any(
        field in specification for field in forbidden_fields
    ):
        errors.append("custom JavaScript is not accepted; use a data-only hook specification")
    declared_unknown_fields = specification.get("unknown_fields")
    if isinstance(declared_unknown_fields, (list, tuple, set)):
        unknown_fields = list(declared_unknown_fields)
    elif declared_unknown_fields:
        unknown_fields = [str(declared_unknown_fields)]
    else:
        unknown_fields = []
    unknown_fields.extend(
        str(field)
        for field in specification
        if field not in allowed_fields and field not in forbidden_fields
    )
    if unknown_fields:
        errors.append(
            "unknown hook specification fields: "
            + ", ".join(sorted(set(map(str, unknown_fields))))
        )

    if hook_type == _API_HOOK:
        if not isinstance(module, str) or not _MODULE_RE.fullmatch(module):
            errors.append("api_hook module must be a loaded module name without path separators")
        if not isinstance(export, str) or not _EXPORT_RE.fullmatch(export):
            errors.append("api_hook export must be a valid native export name")
        if address is not None:
            errors.append("api_hook address must be omitted; the export is resolved by Frida")
    elif hook_type in {_INLINE_HOOK, _BREAKPOINT_TRACE}:
        if module is not None and (
            not isinstance(module, str) or not _MODULE_RE.fullmatch(module)
        ):
            errors.append("module must be a module name without path separators")
        if export is not None:
            errors.append(f"{hook_type} export must be omitted when an address is used")
        if _parse_address(address) is None:
            errors.append(f"{hook_type} address must be a positive 64-bit integer or hex string")

    arguments = specification.get("arguments", [])
    errors.extend(_argument_errors(arguments))
    if not isinstance(specification.get("capture_return"), bool):
        errors.append("capture_return must be a boolean")
    label = specification.get("label")
    if label is not None and (
        not isinstance(label, str) or not _LABEL_RE.fullmatch(label)
    ):
        errors.append("label contains unsupported characters or is too long")
    return _deduplicate(errors)


def _hook_field_statuses(specification: Mapping[str, Any]) -> tuple[str, str, str, str]:
    hook_type = specification.get("type")
    module = specification.get("module")
    export = specification.get("export")
    address = specification.get("address")
    if hook_type == _API_HOOK:
        module_status = "ok" if isinstance(module, str) and _MODULE_RE.fullmatch(module) else "failed"
        export_status = "ok" if isinstance(export, str) and _EXPORT_RE.fullmatch(export) else "failed"
        address_status = "not_applicable" if address is None else "failed"
    else:
        module_status = (
            "not_applicable"
            if module is None
            else "ok"
            if isinstance(module, str) and _MODULE_RE.fullmatch(module)
            else "failed"
        )
        export_status = "not_applicable" if export is None else "failed"
        address_status = "ok" if _parse_address(address) is not None else "failed"
    arguments_status = "ok" if not _argument_errors(specification.get("arguments", [])) else "failed"
    return module_status, export_status, address_status, arguments_status


def _normalize_arguments(value: Any) -> Any:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        return _json_value(value)
    normalized: list[Any] = []
    for position, item in enumerate(value):
        if not isinstance(item, Mapping):
            normalized.append(_json_value(item))
            continue
        raw_type = str(item.get("type") or "pointer").strip().lower()
        argument_type = _ARGUMENT_TYPE_ALIASES.get(raw_type, raw_type)
        index = _normalized_int(item.get("index", position))
        name = item.get("name")
        if name is None and isinstance(index, int):
            name = f"arg{index}"
        max_length = item.get("max_length", item.get("max_len"))
        if max_length is None and argument_type in {"utf8", "utf16", "bytes"}:
            max_length = 256
        unknown_fields = sorted(
            str(key)
            for key in item
            if key not in {"name", "index", "type", "max_length", "max_len"}
        )
        normalized.append(
            _prune(
                {
                    "name": _normalize_optional_text(name),
                    "index": index,
                    "type": argument_type,
                    "max_length": _normalized_int(max_length) if max_length is not None else None,
                    "unknown_fields": unknown_fields,
                }
            )
        )
    return normalized


def _argument_errors(arguments: Any) -> list[str]:
    if not isinstance(arguments, list):
        return ["arguments must be a list of data-only argument specifications"]
    if len(arguments) > _MAX_ARGUMENTS:
        return [f"arguments may contain at most {_MAX_ARGUMENTS} entries"]

    errors: list[str] = []
    names: set[str] = set()
    for position, item in enumerate(arguments):
        prefix = f"arguments[{position}]"
        if not isinstance(item, Mapping):
            errors.append(f"{prefix} must be an object")
            continue
        name = item.get("name")
        index = item.get("index")
        argument_type = item.get("type")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
            errors.append(f"{prefix}.name is invalid")
        elif name in names:
            errors.append(f"{prefix}.name is duplicated")
        else:
            names.add(name)
        if not _integer_in_range(index, 0, _MAX_ARGUMENTS - 1):
            errors.append(f"{prefix}.index must be from 0 to {_MAX_ARGUMENTS - 1}")
        if argument_type not in set(_ARGUMENT_TYPE_ALIASES.values()):
            errors.append(f"{prefix}.type is unsupported")
        if argument_type in {"utf8", "utf16", "bytes"}:
            if not _integer_in_range(item.get("max_length"), 1, _MAX_ARGUMENT_LENGTH):
                errors.append(
                    f"{prefix}.max_length must be from 1 to {_MAX_ARGUMENT_LENGTH}"
                )
        elif item.get("max_length") is not None:
            errors.append(f"{prefix}.max_length is only valid for strings and bytes")
        if item.get("unknown_fields"):
            errors.append(f"{prefix} contains unknown fields")
    return errors


def _target_errors(target: TargetIdentity) -> list[str]:
    pid = _positive_int(target.pid)
    path = str(target.path or "").strip()
    if pid is None and not path:
        return ["target identity requires a positive pid or an executable path"]
    if target.pid is not None and pid is None:
        return ["target pid must be a positive integer"]
    if pid is None and path:
        if "\x00" in path or len(path) > 4_096:
            return ["target path is invalid"]
        if not _is_absolute_path(path):
            return ["spawn target path must be absolute"]
    return []


def _plan_steps(hook_type: str) -> list[dict[str, Any]]:
    resolve_step = (
        "resolve_module_export" if hook_type == _API_HOOK else "validate_executable_address"
    )
    return [
        {"step": "validate_target_identity", "status": "planned", "required": True},
        {"step": "validate_hook_specification", "status": "planned", "required": True},
        {"step": resolve_step, "status": "planned", "required": True},
        {"step": "generate_controlled_frida_script", "status": "planned", "required": True},
        {"step": "attach_target", "status": "planned", "required": True},
        {"step": "load_script", "status": "planned", "required": True},
        {"step": "collect_events", "status": "planned", "required": True},
        {"step": "unload_script", "status": "planned", "required": True},
        {"step": "detach_session", "status": "planned", "required": True},
        {"step": "close_bounded_session", "status": "planned", "required": True},
    ]


def _cleanup_runtime(
    backend: HookRuntimeBackend,
    *,
    script_handle: Any,
    session_handle: Any,
) -> dict[str, Any]:
    unload_attempted = script_handle is not None
    detach_attempted = session_handle is not None
    unloaded = not unload_attempted
    detached = not detach_attempted
    unload_result: Any = None
    detach_result: Any = None
    errors: list[dict[str, Any]] = []

    if unload_attempted:
        try:
            unload_result = backend.unload_script(script_handle)
            unloaded = _backend_operation_ok(unload_result)
            if not unloaded:
                errors.append(
                    {"operation": "unload_script", "result": _json_value(unload_result)}
                )
        except Exception as exc:  # noqa: BLE001 - detach still must run
            errors.append({"operation": "unload_script", "error": _exception_payload(exc)})

    if detach_attempted:
        try:
            detach_result = backend.detach(session_handle)
            detached = _backend_operation_ok(detach_result)
            if not detached:
                errors.append(
                    {"operation": "detach_session", "result": _json_value(detach_result)}
                )
        except Exception as exc:  # noqa: BLE001 - rollback reports both attempts
            errors.append({"operation": "detach_session", "error": _exception_payload(exc)})

    return _prune(
        {
            "ok": unloaded and detached,
            "unload_attempted": unload_attempted,
            "unloaded": unloaded,
            "unload_result": _json_value(unload_result),
            "detach_attempted": detach_attempted,
            "detached": detached,
            "detach_result": _json_value(detach_result),
            "errors": errors,
        }
    )


def _normalize_event(message: Any, data: Any = None) -> dict[str, Any]:
    if isinstance(message, Mapping):
        message_type = message.get("type")
        if message_type == "send":
            payload = message.get("payload")
            if isinstance(payload, Mapping):
                event = _json_mapping(payload)
            else:
                event = {"event": "message", "payload": _json_value(payload)}
            event.setdefault("message_type", "send")
        elif message_type == "error":
            event = {
                "event": "script_error",
                "message_type": "error",
                "description": message.get("description"),
                "stack": message.get("stack"),
                "file_name": message.get("fileName"),
                "line_number": message.get("lineNumber"),
            }
        else:
            event = _json_mapping(message)
            event.setdefault("event", str(message_type or "message"))
    else:
        event = {"event": "message", "payload": _json_value(message)}
    if data is not None:
        if isinstance(data, (bytes, bytearray)):
            event["data_hex"] = bytes(data).hex()
        else:
            event["data"] = _json_value(data)
    return _prune(event)


def _runtime_options(plan: CapabilityPlan) -> dict[str, Any]:
    return {
        "duration_ms": plan.parameters.get("duration_ms"),
        "max_events": plan.parameters.get("max_events"),
        "target_args": _json_value(plan.parameters.get("target_args", [])),
        "kill_spawned_on_rollback": plan.parameters.get("kill_spawned_on_rollback"),
    }


def _valid_runtime_options(options: Mapping[str, Any]) -> bool:
    return (
        _integer_in_range(options.get("duration_ms"), 0, _MAX_DURATION_MS)
        and _integer_in_range(options.get("max_events"), 1, _MAX_EVENTS)
        and _valid_target_args(options.get("target_args"))
        and isinstance(options.get("kill_spawned_on_rollback"), bool)
    )


def _normalize_target_args(value: Any) -> Any:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        return _json_value(value)
    return [_json_value(item) for item in value]


def _valid_target_args(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= _MAX_TARGET_ARGUMENTS
        and all(
            isinstance(item, str)
            and "\x00" not in item
            and len(item) <= _MAX_ARGUMENT_LENGTH
            for item in value
        )
    )


def _plan_fingerprint(
    target_identity: Mapping[str, Any],
    hook_specification: Mapping[str, Any],
    options: Mapping[str, Any],
) -> str:
    return _sha256_json(
        {
            "target_identity": _json_mapping(target_identity),
            "hook_specification": _json_mapping(hook_specification),
            "options": _json_mapping(options),
        }
    )


def _target_identity(target: TargetIdentity) -> dict[str, Any]:
    if hasattr(target, "to_dict"):
        return _json_mapping(target.to_dict())
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


def _backend_info(backend: Any) -> dict[str, Any]:
    return _prune(
        {
            "name": str(getattr(backend, "name", type(backend).__name__)),
            "available": _backend_available(backend),
            "version": getattr(backend, "version", None),
            "unavailable_reason": getattr(backend, "unavailable_reason", None),
        }
    )


def _frida_object_flag(value: Any, name: str) -> bool:
    try:
        return bool(getattr(value, name, False))
    except Exception:
        return False


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", False))


def _backend_reason(backend: Any) -> str:
    return str(
        getattr(backend, "unavailable_reason", None)
        or "Frida hook runtime backend is unavailable"
    )


def _backend_operation_ok(result: Any) -> bool:
    if result is None:
        return True
    if isinstance(result, Mapping):
        if result.get("ok") is False:
            return False
        return str(result.get("status") or "").lower() not in {"failed", "error"}
    return bool(result)


def _describe_backend_session(backend: Any, session: Any) -> dict[str, Any]:
    describe = getattr(backend, "describe_session", None)
    if callable(describe):
        try:
            return _json_mapping(describe(session))
        except Exception as exc:  # noqa: BLE001 - description is best effort
            return {"backend": _backend_info(backend), "description_error": _exception_payload(exc)}
    return {"backend": _backend_info(backend)}


def _inactive_rollback_plan(
    rollback_plan: Mapping[str, Any],
    *,
    status: str,
    reason: str,
) -> dict[str, Any]:
    payload = _json_mapping(rollback_plan)
    payload.update(
        {
            "supported": True,
            "mode": "not_required",
            "status": status,
            "reason": reason,
            "active": False,
            "unload_required": False,
            "detach_required": False,
            "completed": True,
            "idempotent": True,
            "executable": False,
            "cross_process_supported": False,
        }
    )
    return payload


def _completed_cleanup_plan(
    rollback_plan: Mapping[str, Any],
    *,
    session_id: str,
    cleanup: Mapping[str, Any],
    execution_status: str,
) -> dict[str, Any]:
    payload = _json_mapping(rollback_plan)
    cleanup_payload = _json_mapping(cleanup)
    completed = bool(cleanup_payload.get("ok"))
    payload.update(
        {
            "supported": True,
            "mode": "execute_cleanup",
            "status": "completed" if completed else "cleanup_failed",
            "reason": (
                "bounded hook session was unloaded and detached before execute returned"
                if completed
                else "bounded hook session cleanup was attempted before execute returned but did not complete"
            ),
            "session_id": session_id,
            "active": False,
            "unload_required": False,
            "detach_required": False,
            "completed": completed,
            "idempotent": True,
            "executable": False,
            "cross_process_supported": False,
            "execution_status": execution_status,
            "cleanup_attempted": bool(cleanup_payload.get("unload_attempted"))
            or bool(cleanup_payload.get("detach_attempted")),
            "unloaded": bool(cleanup_payload.get("unloaded")),
            "detached": bool(cleanup_payload.get("detached")),
            "cleanup": cleanup_payload,
        }
    )
    return payload


def _audit_artifact(session_id: str, hook_type: str, status: str) -> CapabilityArtifact:
    return CapabilityArtifact(
        path=f"hook_runtime/{_safe_segment(session_id)}/hook_runtime.json",
        kind="hook-runtime-audit",
        description=f"Controlled Frida hook audit for {hook_type}",
        metadata={
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "session_id": session_id,
            "hook_type": hook_type,
            "status": status,
            "materialized": False,
        },
    )


def _manifest_entry(
    artifact: CapabilityArtifact,
    *,
    status: str,
    session_id: str,
    hook_type: str,
    target: TargetIdentity,
    precondition_hash: Any = None,
) -> dict[str, Any]:
    return _prune(
        {
            "schema_version": _AUDIT_SCHEMA_VERSION,
            "path": artifact.path,
            "kind": artifact.kind,
            "tool": "hook_runtime",
            "provider": HookRuntimeProvider.provider_name,
            "status": status,
            "role": "hook-runtime-audit",
            "session_id": session_id,
            "hook_type": hook_type,
            "precondition_hash": precondition_hash,
            "target_identity": _target_identity(target),
        }
    )


def _hook_runtime_audit_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": _AUDIT_SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "status": result.status,
        "action": result.action,
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
            "dashboard_trace": [
                _json_mapping(item) for item in result.dashboard_trace
            ],
        }
    )
    session = report.setdefault("session", {})
    if isinstance(session, dict):
        session.setdefault("id", result.session_id)


def _first_value(primary: Mapping[str, Any], secondary: Any, *keys: str) -> Any:
    for source in (primary, secondary if isinstance(secondary, Mapping) else {}):
        for key in keys:
            if key in source:
                return source[key]
    return None


def _normalize_optional_text(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        return _json_value(value)
    return value.strip()


def _normalize_address(value: Any) -> Any:
    if value is None:
        return None
    parsed = _parse_address(value)
    return f"0x{parsed:x}" if parsed is not None else _json_value(value)


def _parse_address(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]+", value.strip()):
        text = value.strip()
        parsed = int(text, 16)
    else:
        return None
    return parsed if 0 < parsed <= 0xFFFFFFFFFFFFFFFF else None


def _normalize_bool(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return _json_value(value)


def _normalized_int(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[+-]?\d+", value.strip()):
        return int(value.strip(), 10)
    return _json_value(value)


def _bounded_int(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    default: int,
) -> int:
    normalized = _normalized_int(value)
    if isinstance(normalized, int) and not isinstance(normalized, bool):
        return min(maximum, max(minimum, normalized))
    return default


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


def _is_absolute_path(value: str) -> bool:
    return PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    payload = json.dumps(
        _json_value(value),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_text(payload)


def _safe_segment(value: Any) -> str:
    text = str(value or "session")
    safe = "".join(character if character.isalnum() or character in "-_." else "_" for character in text)
    return safe.strip(".") or "session"


def _exception_payload(exc: Exception) -> dict[str, Any]:
    return {"type": type(exc).__name__, "message": str(exc)}


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
    if hasattr(value, "to_dict"):
        return _json_value(value.to_dict())
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


def _deduplicate(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))
