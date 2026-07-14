from __future__ import annotations

import ctypes
import hashlib
import json
import os
import queue
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Optional

from reverse_analyzer.core.capabilities.audit_contract import (
    validate_capability_audit_record,
)
from reverse_analyzer.core.capabilities.models import (
    CapabilityRequest,
    TargetIdentity,
)
from reverse_analyzer.providers.native_debugger import (
    NativeDebugEvent,
    NativeDebuggerProvider,
    WindowsNativeDebuggerBackend,
    _DBG_CONTINUE,
    _DBG_EXCEPTION_NOT_HANDLED,
    _CONTEXT32,
    _CONTEXT64,
    _CREATE_PROCESS_DEBUG_EVENT,
    _CREATE_THREAD_DEBUG_EVENT,
    _DEBUG_EVENT,
    _EXCEPTION_BREAKPOINT,
    _EXCEPTION_DEBUG_EVENT,
    _EXCEPTION_SINGLE_STEP,
    _EXIT_PROCESS_DEBUG_EVENT,
    _LOAD_DLL_DEBUG_EVENT,
    _OUTPUT_DEBUG_STRING_EVENT,
    _resolve_artifact_path,
)


_PID = 4242
_ADDRESS = 0x140001000
_ARCHITECTURE = "x64" if struct.calcsize("P") == 8 else "x86"


class FaultInjectingBackend:
    """Deterministic backend used only to exercise provider failure paths."""

    name = "test_fault_injecting_native_debugger"
    available = True
    unavailable_reason: Optional[str] = None
    production = False

    def __init__(
        self,
        *,
        events: Optional[list[NativeDebugEvent | Mapping[str, Any]]] = None,
        architecture: str = _ARCHITECTURE,
        debugger_architecture: str = _ARCHITECTURE,
        wow64: bool = False,
        context_supported: bool = True,
        attach_delay_ms: int = 0,
    ) -> None:
        self.events = list(events or [])
        self.calls: list[tuple[Any, ...]] = []
        self.released: list[Any] = []
        self.failures: dict[str, int] = {}
        self.memory: dict[int, int] = {}
        self.protection = 0x20
        self.attached = False
        self.attach_delay_ms = max(0, int(attach_delay_ms))
        self.process = {
            "status": "ok",
            "accessible": True,
            "exists": True,
            "pid": _PID,
            "creation_time": 133713371337,
            "image_path": r"C:\fixtures\debug-child.exe",
            "architecture": architecture,
            "debugger_architecture": debugger_architecture,
            "wow64": wow64,
            "context_supported": context_supported,
            "context_api": "GetThreadContext" if context_supported else None,
            "architecture_reason": (
                None
                if context_supported
                else "WOW64 thread context is unavailable in this debugger"
            ),
        }
        self.map(_ADDRESS, b"\x90")
        pointer_size = 8 if architecture == "x64" else 4
        frame_return_base = _ADDRESS if pointer_size == 8 else 0x401000
        self.map(
            0x100100,
            (0x100120).to_bytes(pointer_size, "little")
            + (frame_return_base + 0x30).to_bytes(pointer_size, "little"),
        )
        self.map(
            0x100120,
            (0).to_bytes(pointer_size, "little")
            + (frame_return_base + 0x50).to_bytes(pointer_size, "little"),
        )

    def map(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def fail(self, operation: str, count: int = 1) -> None:
        self.failures[operation] = self.failures.get(operation, 0) + count

    def _maybe_fail(self, operation: str) -> None:
        remaining = self.failures.get(operation, 0)
        if remaining:
            self.failures[operation] = remaining - 1
            raise RuntimeError(f"injected {operation} failure")

    def probe_process(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("probe", pid))
        self._maybe_fail("probe")
        return {**self.process, "pid": pid}

    def read(self, pid: int, address: int, size: int) -> bytes:
        self.calls.append(("read", pid, address, size))
        self._maybe_fail("read")
        return bytes(self.memory[address + offset] for offset in range(size))

    def write(self, pid: int, address: int, data: bytes) -> Mapping[str, Any]:
        payload = bytes(data)
        self.calls.append(("write", pid, address, payload))
        self._maybe_fail("write")
        self.map(address, payload)
        return {
            "ok": True,
            "status": "ok",
            "operation": "WriteProcessMemory",
            "bytes_written": len(payload),
        }

    def protect(
        self, pid: int, address: int, size: int, protection: int
    ) -> Mapping[str, Any]:
        self.calls.append(("protect", pid, address, size, protection))
        self._maybe_fail("protect")
        old = self.protection
        self.protection = protection
        return {
            "ok": True,
            "status": "ok",
            "operation": "VirtualProtectEx",
            "old_protection": old,
            "new_protection": protection,
        }

    def flush_instruction_cache(
        self, pid: int, address: int, size: int
    ) -> Mapping[str, Any]:
        self.calls.append(("flush", pid, address, size))
        self._maybe_fail("flush")
        return {
            "ok": True,
            "status": "ok",
            "operation": "FlushInstructionCache",
        }

    def attach(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("attach", pid))
        self._maybe_fail("attach")
        if self.attach_delay_ms:
            time.sleep(self.attach_delay_ms / 1000.0)
        self.attached = True
        return {"ok": True, "status": "ok", "operation": "DebugActiveProcess"}

    def set_kill_on_exit(self, kill: bool) -> Mapping[str, Any]:
        self.calls.append(("kill_on_exit", kill))
        self._maybe_fail("kill_on_exit")
        return {
            "ok": True,
            "status": "ok",
            "operation": "DebugSetProcessKillOnExit",
        }

    def wait_for_debug_event(self, timeout_ms: int) -> Optional[NativeDebugEvent]:
        self.calls.append(("wait", timeout_ms))
        self._maybe_fail("wait")
        if self.events:
            return self.events.pop(0)  # type: ignore[return-value]
        time.sleep(max(0, timeout_ms) / 1000.0)
        return None

    def continue_debug_event(
        self, pid: int, thread_id: int, continue_status: int
    ) -> Mapping[str, Any]:
        self.calls.append(("continue", pid, thread_id, continue_status))
        self._maybe_fail("continue")
        return {
            "ok": True,
            "status": "ok",
            "operation": "ContinueDebugEvent",
        }

    def detach(self, pid: int) -> Mapping[str, Any]:
        self.calls.append(("detach", pid))
        self._maybe_fail("detach")
        self.attached = False
        return {
            "ok": True,
            "status": "ok",
            "operation": "DebugActiveProcessStop",
        }

    def release_event(self, event: NativeDebugEvent) -> None:
        self.calls.append(("release", event))
        self.released.append(event)
        self._maybe_fail("release")

    def capture_thread_context(
        self, thread_id: int, architecture: str, *, suspend: bool = False
    ) -> Mapping[str, Any]:
        self.calls.append(("capture_context", thread_id, architecture, suspend))
        self._maybe_fail("capture_context")
        return {
            "thread_id": thread_id,
            "architecture": architecture,
            "instruction_pointer": _ADDRESS + 1,
            "stack_pointer": 0x100000,
            "frame_pointer": 0x100100,
            "flags": 0x202,
            "trap_flag": False,
            "registers": {"ax": 1},
        }

    def update_thread_context(
        self,
        thread_id: int,
        architecture: str,
        *,
        instruction_pointer: Optional[int] = None,
        trap_flag: Optional[bool] = None,
        suspend: bool = False,
    ) -> Mapping[str, Any]:
        self.calls.append(
            (
                "update_context",
                thread_id,
                architecture,
                instruction_pointer,
                trap_flag,
                suspend,
            )
        )
        self._maybe_fail("update_context")
        before = {
            "thread_id": thread_id,
            "architecture": architecture,
            "instruction_pointer": _ADDRESS + 1,
            "flags": 0x202,
            "trap_flag": False,
        }
        after = {
            **before,
            "instruction_pointer": (
                instruction_pointer
                if instruction_pointer is not None
                else before["instruction_pointer"]
            ),
            "trap_flag": bool(trap_flag) if trap_flag is not None else False,
        }
        return {"ok": True, "status": "ok", "before": before, "after": after}


def _event(
    code: int,
    kind: str,
    *,
    thread_id: int = 77,
    **payload: Any,
) -> NativeDebugEvent:
    return NativeDebugEvent(
        code=code,
        pid=_PID,
        thread_id=thread_id,
        payload={"kind": kind, **payload},
    )


def _request(
    action: str = "attach_trace",
    *,
    session_id: str = "native-debugger-test",
    pid: int = _PID,
    **params: Any,
) -> CapabilityRequest:
    values = {
        "authorized": True,
        "duration_ms": 20,
        "max_events": 1,
        "poll_interval_ms": 2,
        **params,
    }
    if action == "software_breakpoint_trace":
        values.setdefault("address", _ADDRESS)
        values.setdefault("expected_original_byte", "90")
    return CapabilityRequest(
        capability="native_debugger",
        action=action,
        target=TargetIdentity(
            kind="process",
            pid=pid,
            display_name="authorized-debug-child.exe",
        ),
        params=values,
        session_id=session_id,
        provenance={"request_source": "unit-test"},
    )


class NativeDebuggerProviderTests(unittest.TestCase):
    def test_authorization_blocks_attach_and_memory_mutation(self) -> None:
        backend = FaultInjectingBackend()
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(_request(authorized=False))

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertFalse(any(call[0] == "attach" for call in backend.calls))
        self.assertFalse(any(call[0] == "write" for call in backend.calls))

    def test_pid_creation_time_change_fails_closed_before_attach(self) -> None:
        backend = FaultInjectingBackend()
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(_request())
        backend.process["creation_time"] += 1

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        identity_check = next(
            item
            for item in result.provenance["validation"]["checks"]
            if item["name"] == "process_identity"
        )
        self.assertEqual(identity_check["status"], "failed")
        self.assertFalse(any(call[0] == "attach" for call in backend.calls))

    def test_explicit_creation_time_is_part_of_identity(self) -> None:
        backend = FaultInjectingBackend()
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(
            _request(expected_creation_time=backend.process["creation_time"] + 1)
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertIn(
            "creation time",
            " ".join(result.provenance["validation"]["errors"]).lower(),
        )
        self.assertFalse(any(call[0] == "attach" for call in backend.calls))

    def test_duration_timeout_is_bounded_and_detaches(self) -> None:
        backend = FaultInjectingBackend()
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        started = time.monotonic()

        result = provider.execute(
            provider.plan(_request(duration_ms=8, max_events=8, poll_interval_ms=2))
        )

        elapsed = time.monotonic() - started
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.after_snapshot["termination_reason"], "duration")
        self.assertEqual(result.after_snapshot["event_count"], 0)
        self.assertLess(elapsed, 0.5)
        self.assertTrue(result.after_snapshot["debug_detached"])
        self.assertEqual(len([call for call in backend.calls if call[0] == "detach"]), 1)

    def test_capture_duration_starts_after_attach_and_breakpoint_setup(self) -> None:
        backend = FaultInjectingBackend(
            attach_delay_ms=20,
            events=[
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_BREAKPOINT,
                    exception_address=_ADDRESS,
                    first_chance=True,
                )
            ],
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(
            provider.plan(
                _request(
                    "software_breakpoint_trace",
                    duration_ms=5,
                    max_events=1,
                    rearm=False,
                )
            )
        )

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.after_snapshot["breakpoint"]["hit_count"], 1)
        self.assertTrue(result.after_snapshot["breakpoint"]["byte_restored"])

    def test_event_limit_continues_every_acquired_event(self) -> None:
        backend = FaultInjectingBackend(
            events=[
                _event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000),
                _event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x2000),
                _event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x3000),
            ]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(provider.plan(_request(max_events=2)))

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.after_snapshot["termination_reason"], "max_events")
        self.assertEqual(result.after_snapshot["event_count"], 2)
        continuations = [call for call in backend.calls if call[0] == "continue"]
        self.assertEqual(len(continuations), 2)
        self.assertTrue(all(call[3] == _DBG_CONTINUE for call in continuations))
        self.assertEqual(len(backend.released), 2)

    def test_expected_original_byte_mismatch_blocks_attach(self) -> None:
        backend = FaultInjectingBackend()
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(_request("software_breakpoint_trace"))
        backend.map(_ADDRESS, b"\x91")

        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(_PID, _ADDRESS, 1), b"\x91")
        self.assertFalse(any(call[0] == "attach" for call in backend.calls))
        self.assertFalse(any(call[0] == "write" for call in backend.calls))

    def test_breakpoint_hit_single_step_rearm_and_final_restore(self) -> None:
        backend = FaultInjectingBackend(
            events=[
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_BREAKPOINT,
                    exception_address=_ADDRESS + 0x500,
                    first_chance=True,
                ),
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_BREAKPOINT,
                    exception_address=_ADDRESS,
                    first_chance=True,
                ),
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_SINGLE_STEP,
                    exception_address=_ADDRESS + 1,
                    first_chance=True,
                ),
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_BREAKPOINT,
                    exception_address=_ADDRESS,
                    first_chance=True,
                ),
            ]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(
            _request(
                "software_breakpoint_trace",
                max_events=4,
                max_breakpoint_hits=2,
                rearm=True,
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(result.after_snapshot["breakpoint"]["hit_count"], 2)
        self.assertEqual(result.after_snapshot["breakpoint"]["rearm_count"], 1)
        self.assertTrue(result.after_snapshot["breakpoint"]["byte_restored"])
        self.assertEqual(backend.read(_PID, _ADDRESS, 1), b"\x90")
        updates = [call for call in backend.calls if call[0] == "update_context"]
        self.assertIn(("update_context", 77, _ARCHITECTURE, _ADDRESS, True, False), updates)
        self.assertIn(("update_context", 77, _ARCHITECTURE, None, False, False), updates)
        self.assertIn(("update_context", 77, _ARCHITECTURE, _ADDRESS, False, False), updates)
        self.assertEqual(
            [call[3] for call in backend.calls if call[0] == "continue"],
            [_DBG_CONTINUE] * 4,
        )

    def test_processing_error_still_continues_restores_and_detaches(self) -> None:
        backend = FaultInjectingBackend(
            events=[
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    exception_code=_EXCEPTION_BREAKPOINT,
                    exception_address=_ADDRESS,
                    first_chance=True,
                )
            ]
        )
        backend.fail("update_context")
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(
            provider.plan(_request("software_breakpoint_trace", rearm=True))
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.read(_PID, _ADDRESS, 1), b"\x90")
        self.assertTrue(result.after_snapshot["debug_detached"])
        continuation = next(call for call in backend.calls if call[0] == "continue")
        self.assertEqual(continuation[3], _DBG_EXCEPTION_NOT_HANDLED)
        self.assertEqual(len(backend.released), 1)

    def test_wait_failure_after_install_restores_byte_and_detaches(self) -> None:
        backend = FaultInjectingBackend()
        backend.fail("wait")
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(
            provider.plan(_request("software_breakpoint_trace", max_events=3))
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.after_snapshot["termination_reason"], "wait_error")
        self.assertEqual(backend.read(_PID, _ADDRESS, 1), b"\x90")
        self.assertTrue(result.after_snapshot["breakpoint"]["byte_restored"])
        self.assertTrue(result.after_snapshot["debug_detached"])

    def test_continue_failure_releases_event_and_detaches(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        backend.fail("continue")
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(provider.plan(_request()))

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.after_snapshot["all_events_continued"])
        self.assertEqual(len([call for call in backend.calls if call[0] == "continue"]), 1)
        self.assertEqual(len(backend.released), 1)
        self.assertTrue(result.after_snapshot["debug_detached"])

    def test_detach_failure_is_retried_by_idempotent_rollback(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        backend.fail("detach")
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        result = provider.execute(provider.plan(_request()))

        self.assertEqual(result.status, "failed")
        self.assertTrue(result.rollback_plan["active"])
        self.assertFalse(result.rollback_plan["debug_detached"])

        rollback = provider.rollback(result)
        second = provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        self.assertEqual(second.details["status"], "already_completed")
        self.assertEqual(len([call for call in backend.calls if call[0] == "detach"]), 2)

    def test_rollback_refuses_reused_pid_identity(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        backend.fail("detach")
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        result = provider.execute(provider.plan(_request()))
        self.assertTrue(result.rollback_plan["active"])

        backend.process["creation_time"] += 1
        rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertIn("identity changed", json.dumps(rollback.details))
        self.assertEqual(len([call for call in backend.calls if call[0] == "detach"]), 1)

    def test_successful_cleanup_makes_rollback_idempotent(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        result = provider.execute(provider.plan(_request()))

        first = provider.rollback(result)
        second = provider.rollback(result)

        self.assertTrue(first.ok)
        self.assertEqual(first.details["status"], "already_completed")
        self.assertEqual(second.details["status"], "already_completed")
        self.assertEqual(len([call for call in backend.calls if call[0] == "detach"]), 1)

    def test_unavailable_dependency_and_wow64_boundary_are_not_success(self) -> None:
        unavailable = NativeDebuggerProvider(platform_name="linux")
        unavailable_result = unavailable.execute(unavailable.plan(_request()))
        self.assertEqual(unavailable_result.status, "unavailable")
        self.assertFalse(unavailable_result.provenance["simulated"])
        self.assertTrue(unavailable_result.provenance["backend"]["production"])

        wow64_backend = FaultInjectingBackend(
            architecture="x86",
            debugger_architecture="x64",
            wow64=True,
            context_supported=False,
        )
        wow64 = NativeDebuggerProvider(wow64_backend, platform_name="win32")
        wow64_result = wow64.execute(wow64.plan(_request()))
        self.assertEqual(wow64_result.status, "unavailable")
        self.assertFalse(any(call[0] == "attach" for call in wow64_backend.calls))
        self.assertIn("WOW64", " ".join(wow64_result.provenance["validation"]["warnings"]))

    def test_artifacts_are_confined_hashed_and_audit_contract_valid(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        result = provider.execute(
            provider.plan(_request(session_id=r"..\..\outside/session"))
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            bundle = provider.collect_artifacts(result, str(root))

            self.assertEqual(len(bundle.artifacts), 4)
            entries = {item["path"]: item for item in bundle.manifest_entries}
            for artifact in bundle.artifacts:
                materialized = (root / Path(artifact.path)).resolve()
                materialized.relative_to(root)
                data = materialized.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                self.assertEqual(artifact.metadata["sha256"], digest)
                self.assertEqual(artifact.metadata["size"], len(data))
                self.assertEqual(entries[artifact.path]["sha256"], digest)
                self.assertNotIn("outside", materialized.relative_to(root).parts[:1])

            audit_artifact = next(
                item
                for item in bundle.artifacts
                if item.kind == "native-debugger-audit"
            )
            audit = json.loads(
                (root / audit_artifact.path).read_text(encoding="utf-8")
            )
            contract = validate_capability_audit_record(audit)
            self.assertTrue(contract.ok, contract.errors)
            self.assertEqual(audit["target_identity"]["pid"], _PID)
            self.assertIn("events", audit["after_snapshot"])
            self.assertTrue(audit["report_section"]["native_win32"])
            self.assertTrue(audit["dashboard_trace"])

            diagnostics_artifact = next(
                item
                for item in bundle.artifacts
                if item.kind == "native-debugger-diagnostics"
            )
            diagnostics = json.loads(
                (root / diagnostics_artifact.path).read_text(encoding="utf-8")
            )
            self.assertIn("module_inventory", diagnostics)
            self.assertIn("thread_inventory", diagnostics)
            self.assertIn("crash_evidence", diagnostics)

            with self.assertRaisesRegex(ValueError, "unsafe|escapes"):
                _resolve_artifact_path(root, "../escape.json")
            with self.assertRaisesRegex(ValueError, "unsafe|escapes"):
                _resolve_artifact_path(root, r"C:\escape.json")

    def test_tampered_plan_and_result_fail_closed(self) -> None:
        backend = FaultInjectingBackend(
            events=[_event(_LOAD_DLL_DEBUG_EVENT, "module_load", base_address=0x1000)]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")
        plan = provider.plan(_request())
        plan.parameters["max_events"] = 999

        self.assertFalse(provider.validate(plan).ok)
        self.assertEqual(provider.execute(plan).status, "failed")
        self.assertFalse(any(call[0] == "attach" for call in backend.calls))

        clean = provider.execute(provider.plan(_request()))
        clean.report_section["status"] = "tampered"
        with self.assertRaisesRegex(ValueError, "identity"):
            provider.rollback(clean)

    def test_normalizes_runtime_inventory_stack_and_crash_evidence(self) -> None:
        backend = FaultInjectingBackend(
            events=[
                _event(
                    _CREATE_PROCESS_DEBUG_EVENT,
                    "process_create",
                    thread_id=10,
                    base_address=0x140000000,
                    start_address=_ADDRESS,
                    image_path=r"C:\fixtures\debug-child.exe",
                ),
                _event(
                    _LOAD_DLL_DEBUG_EVENT,
                    "module_load",
                    thread_id=10,
                    base_address=0x7FF800000000,
                    image_path=r"C:\Windows\System32\kernel32.dll",
                ),
                _event(
                    _CREATE_THREAD_DEBUG_EVENT,
                    "thread_create",
                    thread_id=77,
                    start_address=_ADDRESS + 0x20,
                ),
                _event(
                    _EXCEPTION_DEBUG_EVENT,
                    "exception",
                    thread_id=77,
                    exception_code=0xC0000005,
                    exception_address=_ADDRESS + 1,
                    first_chance=False,
                    information=[0, 0xDEADBEEF],
                ),
                _event(4, "thread_exit", thread_id=77, exit_code=0xC0000005),
                _event(7, "module_unload", thread_id=10, base_address=0x7FF800000000),
                _event(5, "process_exit", thread_id=10, exit_code=0xC0000005),
            ]
        )
        provider = NativeDebuggerProvider(backend, platform_name="win32")

        result = provider.execute(
            provider.plan(_request(max_events=7, max_stack_frames=8))
        )

        self.assertEqual(result.status, "ok", result.report_section)
        self.assertEqual(result.report_section["module_count"], 2)
        self.assertEqual(result.report_section["thread_count"], 2)
        self.assertEqual(result.report_section["exception_count"], 1)
        self.assertTrue(result.report_section["crash_detected"])
        modules = result.after_snapshot["module_inventory"]
        self.assertEqual(modules[0]["base_address"], 0x140000000)
        self.assertEqual(modules[1]["status"], "unloaded")
        threads = {item["thread_id"]: item for item in result.after_snapshot["thread_inventory"]}
        self.assertTrue(threads[10]["is_initial_thread"])
        self.assertEqual(threads[77]["status"], "exited")
        stack = result.after_snapshot["call_stacks"][0]
        self.assertEqual(stack["termination_reason"], "end_of_chain")
        self.assertGreaterEqual(len(stack["frames"]), 3)
        self.assertEqual(result.after_snapshot["crash_evidence"][0]["exception_code"], 0xC0000005)


@unittest.skipUnless(sys.platform == "win32", "Windows native debugger ABI")
class NativeDebuggerWin32AbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = WindowsNativeDebuggerBackend()
        if not cls.backend.available:
            raise unittest.SkipTest(
                cls.backend.unavailable_reason or "Win32 APIs unavailable"
            )

    def test_native_structure_sizes_and_event_decoding(self) -> None:
        self.assertEqual(ctypes.sizeof(_CONTEXT32), 716)
        self.assertEqual(ctypes.sizeof(_CONTEXT64), 1232)
        self.assertEqual(
            ctypes.sizeof(_DEBUG_EVENT),
            176 if ctypes.sizeof(ctypes.c_void_p) == 8 else 96,
        )

        process = _DEBUG_EVENT()
        process.dwDebugEventCode = _CREATE_PROCESS_DEBUG_EVENT
        process.dwProcessId = _PID
        process.dwThreadId = 10
        process.CreateProcessInfo.lpBaseOfImage = 0x140000000
        process.CreateProcessInfo.lpStartAddress = 0x140001000

        thread = _DEBUG_EVENT()
        thread.dwDebugEventCode = _CREATE_THREAD_DEBUG_EVENT
        thread.dwProcessId = _PID
        thread.dwThreadId = 11
        thread.CreateThread.lpStartAddress = 0x140002000

        module = _DEBUG_EVENT()
        module.dwDebugEventCode = _LOAD_DLL_DEBUG_EVENT
        module.dwProcessId = _PID
        module.dwThreadId = 10
        module.LoadDll.lpBaseOfDll = 0x7FF800000000

        exception = _DEBUG_EVENT()
        exception.dwDebugEventCode = _EXCEPTION_DEBUG_EVENT
        exception.dwProcessId = _PID
        exception.dwThreadId = 10
        exception.Exception.ExceptionRecord.ExceptionCode = _EXCEPTION_BREAKPOINT
        exception.Exception.ExceptionRecord.ExceptionAddress = _ADDRESS
        exception.Exception.dwFirstChance = 1

        debug_text = "native debugger fixture\0".encode("utf-16-le")
        debug_string = _DEBUG_EVENT()
        debug_string.dwDebugEventCode = _OUTPUT_DEBUG_STRING_EVENT
        debug_string.dwProcessId = _PID
        debug_string.dwThreadId = 10
        debug_string.DebugString.lpDebugStringData = 0x12340000
        debug_string.DebugString.fUnicode = 1
        debug_string.DebugString.nDebugStringLength = len(debug_text) // 2

        process_exit = _DEBUG_EVENT()
        process_exit.dwDebugEventCode = _EXIT_PROCESS_DEBUG_EVENT
        process_exit.dwProcessId = _PID
        process_exit.dwThreadId = 10
        process_exit.ExitProcess.dwExitCode = 7

        original_read = self.backend.read
        self.backend.read = lambda pid, address, size: debug_text[:size]
        try:
            decoded = [
                self.backend._decode_event(event)
                for event in (
                    process,
                    thread,
                    module,
                    exception,
                    debug_string,
                    process_exit,
                )
            ]
        finally:
            self.backend.read = original_read

        self.assertEqual(
            [event.payload["kind"] for event in decoded],
            [
                "process_create",
                "thread_create",
                "module_load",
                "exception",
                "debug_string",
                "process_exit",
            ],
        )
        self.assertEqual(decoded[0].payload["base_address"], 0x140000000)
        self.assertEqual(decoded[1].payload["start_address"], 0x140002000)
        self.assertEqual(decoded[2].payload["base_address"], 0x7FF800000000)
        self.assertEqual(decoded[3].payload["exception_address"], _ADDRESS)
        self.assertTrue(decoded[3].payload["first_chance"])
        self.assertEqual(decoded[4].payload["text"], "native debugger fixture")
        self.assertEqual(decoded[5].payload["exit_code"], 7)


@unittest.skipUnless(sys.platform == "win32", "Windows native debugger E2E")
class NativeDebuggerWindowsE2ETests(unittest.TestCase):
    _temporary: tempfile.TemporaryDirectory[str]
    _fixture: Path

    @classmethod
    def setUpClass(cls) -> None:
        backend = WindowsNativeDebuggerBackend()
        if not backend.available:
            raise unittest.SkipTest(backend.unavailable_reason or "Win32 APIs unavailable")
        gcc = shutil.which("gcc")
        if not gcc:
            raise unittest.SkipTest("gcc is unavailable")

        # The freshly linked executable can remain briefly locked by host
        # scanners after the child and all Popen handles have been closed.
        cls._temporary = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(cls._temporary.name)
        source = root / "native_debugger_fixture.c"
        cls._fixture = root / "native_debugger_fixture.exe"
        source.write_text(
            """
#include <windows.h>
#include <stdio.h>

__declspec(noinline) int debug_target(void) {
    volatile int result = 42;
    return result;
}

int main(void) {
    printf("%lu %p\\n", (unsigned long)GetCurrentProcessId(), (void *)&debug_target);
    fflush(stdout);
    Sleep(500);
    for (;;) {
        volatile int value = debug_target();
        (void)value;
        Sleep(1);
    }
}
""".lstrip(),
            encoding="ascii",
        )
        compiled = subprocess.run(
            [
                gcc,
                "-O0",
                "-g",
                "-fno-omit-frame-pointer",
                str(source),
                "-o",
                str(cls._fixture),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if compiled.returncode != 0 or not cls._fixture.is_file():
            cls._temporary.cleanup()
            raise unittest.SkipTest(f"gcc fixture compilation failed: {compiled.stderr}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def _start_fixture(self) -> tuple[subprocess.Popen[str], int, int]:
        child = subprocess.Popen(
            [str(self._fixture)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert child.stdout is not None
        ready: queue.Queue[str | BaseException] = queue.Queue(maxsize=1)

        def read_banner() -> None:
            try:
                ready.put(child.stdout.readline())
            except BaseException as exc:  # noqa: BLE001 - test fixture boundary
                ready.put(exc)

        reader = threading.Thread(target=read_banner, daemon=True)
        reader.start()
        try:
            banner = ready.get(timeout=5)
        except queue.Empty:
            if child.poll() is None:
                child.kill()
            reader.join(timeout=2)
            child.communicate(timeout=5)
            self.skipTest("controlled fixture startup timed out")
        if isinstance(banner, BaseException):
            if child.poll() is None:
                child.kill()
            reader.join(timeout=2)
            child.communicate(timeout=5)
            self.skipTest(f"controlled fixture stdout failed: {banner}")
        line = banner.strip()
        if not line:
            if child.poll() is None:
                child.kill()
            reader.join(timeout=2)
            _, stderr = child.communicate(timeout=5)
            self.skipTest(f"controlled fixture did not start: {stderr}")
        pid_text, address_text = line.split()
        return child, int(pid_text), int(address_text, 16)

    def _stop_fixture(self, child: subprocess.Popen[str]) -> None:
        if child.poll() is None:
            child.terminate()
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.communicate(timeout=5)
        if child.stdout is not None:
            child.stdout.close()
        if child.stderr is not None:
            child.stderr.close()
        process_handle = getattr(child, "_handle", None)
        if process_handle is not None and hasattr(process_handle, "Close"):
            process_handle.Close()
            child._handle = None
        self.assertIsNotNone(child.returncode, "native debugger fixture did not exit")

    def _retain_acceptance_artifacts(
        self,
        provider: NativeDebuggerProvider,
        result: Any,
        *,
        pid: int,
    ) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            return
        root = Path(configured).expanduser().resolve()
        provider.collect_artifacts(result, str(root))

        evidence = root / "native-debugger"
        evidence.mkdir(parents=True, exist_ok=True)
        fixture_sha256 = hashlib.sha256(self._fixture.read_bytes()).hexdigest()
        (evidence / "target-identity.json").write_text(
            json.dumps(
                {
                    "kind": "controlled_child_process",
                    "pid": pid,
                    "path": str(self._fixture.resolve()),
                    "sha256": fixture_sha256,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        breakpoint = result.after_snapshot.get("breakpoint") or {}
        (evidence / "rollback.json").write_text(
            json.dumps(
                {
                    "status": "ok",
                    "verified": True,
                    "debug_detached": bool(result.after_snapshot.get("debug_detached")),
                    "byte_restored": bool(
                        breakpoint.get("byte_restored", result.action == "attach_trace")
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        proof_path = evidence / "execution-proof.json"
        proof = {
            "status": "ok",
            "provider": result.provider,
            "evidence_class": "live_host_proof",
            "executed_tests": 0,
            "skipped_tests": 0,
            "live_operations": 0,
            "actions": [],
        }
        if proof_path.is_file():
            previous = json.loads(proof_path.read_text(encoding="utf-8"))
            if isinstance(previous, Mapping):
                proof.update(previous)
        proof["executed_tests"] = int(proof.get("executed_tests") or 0) + 1
        proof["live_operations"] = int(proof.get("live_operations") or 0) + max(
            1, int(result.after_snapshot.get("event_count") or 0)
        )
        proof["actions"] = [*list(proof.get("actions") or []), result.action]
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")

    def _skip_environment_attach_denial(self, result: Any) -> None:
        if result.status == "unavailable":
            self.skipTest(json.dumps(result.report_section, sort_keys=True))
        errors = list(result.after_snapshot.get("errors") or []) + list(
            result.after_snapshot.get("cleanup_errors") or []
        )
        for error in errors:
            if not isinstance(error, Mapping):
                continue
            operation = str(error.get("operation") or "")
            code = int(error.get("error_code") or 0)
            message = str(error.get("message") or "").lower()
            if operation in {"DebugActiveProcess", "DebugActiveProcessStop"} and (
                code in {5, 50, 87, 1314} or "access is denied" in message
            ):
                self.skipTest(f"native debugger attach/detach denied by environment: {error}")

    def _real_request(
        self,
        pid: int,
        action: str,
        *,
        address: Optional[int] = None,
        expected_byte: Optional[int] = None,
    ) -> CapabilityRequest:
        params: dict[str, Any] = {
            "authorized": True,
            "architecture": _ARCHITECTURE,
            "duration_ms": 750,
            "max_events": 512,
            "poll_interval_ms": 10,
        }
        if action == "software_breakpoint_trace":
            params.update(
                {
                    "address": address,
                    "expected_original_byte": expected_byte,
                    # Full-suite host load can delay the controlled child well
                    # beyond the normal sub-second cadence. Keep the finite
                    # bound while leaving enough time to observe a real hit.
                    "duration_ms": 5_000,
                    "max_breakpoint_hits": 1,
                    "rearm": False,
                }
            )
        return CapabilityRequest(
            capability="native_debugger",
            action=action,
            target=TargetIdentity(
                kind="process",
                pid=pid,
                display_name="gcc-native-debugger-fixture.exe",
            ),
            params=params,
            session_id=f"native-debugger-e2e-{action}",
            provenance={"request_source": "windows-e2e"},
        )

    def test_real_attach_trace_round_trip(self) -> None:
        child, pid, _ = self._start_fixture()
        result = None
        try:
            provider = NativeDebuggerProvider(
                WindowsNativeDebuggerBackend(), platform_name="win32"
            )
            result = provider.execute(
                provider.plan(self._real_request(pid, "attach_trace"))
            )
            self._skip_environment_attach_denial(result)

            self.assertEqual(result.status, "ok", result.report_section)
            self.assertGreater(result.after_snapshot["event_count"], 0)
            self.assertTrue(result.after_snapshot["all_events_continued"])
            self.assertTrue(result.after_snapshot["debug_detached"])
            self.assertIsNone(child.poll())
        finally:
            self._stop_fixture(child)
        if result is not None:
            self._retain_acceptance_artifacts(provider, result, pid=pid)

    def test_real_software_breakpoint_round_trip(self) -> None:
        child, pid, address = self._start_fixture()
        result = None
        try:
            backend = WindowsNativeDebuggerBackend()
            original = backend.read(pid, address, 1)
            provider = NativeDebuggerProvider(backend, platform_name="win32")
            request = self._real_request(
                pid,
                "software_breakpoint_trace",
                address=address,
                expected_byte=original[0],
            )
            result = provider.execute(provider.plan(request))
            self._skip_environment_attach_denial(result)

            self.assertEqual(result.status, "ok", result.report_section)
            self.assertGreaterEqual(result.after_snapshot["breakpoint"]["hit_count"], 1)
            self.assertTrue(result.after_snapshot["breakpoint"]["byte_restored"])
            self.assertEqual(backend.read(pid, address, 1), original)
            self.assertTrue(result.after_snapshot["all_events_continued"])
            self.assertTrue(result.after_snapshot["debug_detached"])
            self.assertIsNone(child.poll())
        finally:
            self._stop_fixture(child)
        if result is not None:
            self._retain_acceptance_artifacts(provider, result, pid=pid)


if __name__ == "__main__":
    unittest.main()
