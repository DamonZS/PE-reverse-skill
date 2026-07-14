"""Contract tests using recording fakes; they do not provide real-device parity."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Optional
from unittest.mock import patch

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers.ios_instrumentation import (
    FridaIOSInstrumentationBackend,
    IOSInstrumentationProvider,
    render_ios_instrumentation_script,
)


class RecordingScript:
    def __init__(self, owner: "RecordingFrida") -> None:
        self.owner = owner
        self.callback: Optional[Callable[..., None]] = None

    def on(self, signal: str, callback: Callable[..., None]) -> None:
        self.owner.calls.append(("script.on", signal))
        self.callback = callback

    def load(self) -> None:
        self.owner.calls.append(("script.load",))
        if self.owner.load_error is not None:
            raise self.owner.load_error
        assert self.callback is not None
        for message, data in self.owner.messages:
            self.callback(message, data)

    def unload(self) -> None:
        self.owner.calls.append(("script.unload",))
        if self.owner.unload_failures:
            self.owner.unload_failures -= 1
            raise RuntimeError("recorded unload failure")


class RecordingSession:
    def __init__(self, owner: "RecordingFrida", pid: int) -> None:
        self.owner = owner
        self.pid = pid

    def create_script(self, source: str) -> RecordingScript:
        self.owner.calls.append(("session.create_script",))
        self.owner.source = source
        self.owner.script = RecordingScript(self.owner)
        return self.owner.script

    def detach(self) -> None:
        self.owner.calls.append(("session.detach",))


class RecordingDevice:
    id = "ios-recording-device"
    name = "Recording iPhone"
    type = "usb"

    def __init__(self, owner: "RecordingFrida") -> None:
        self.owner = owner

    def enumerate_processes(self) -> list[Any]:
        self.owner.calls.append(("device.enumerate_processes",))
        return [SimpleNamespace(pid=4242, name="ExampleApp")]

    def enumerate_applications(self) -> list[Any]:
        self.owner.calls.append(("device.enumerate_applications",))
        return [SimpleNamespace(pid=4242, name="Example App", identifier="com.example.app")]

    def spawn(self, argv: list[str]) -> int:
        self.owner.calls.append(("device.spawn", list(argv)))
        return 7331

    def attach(self, target: Any) -> RecordingSession:
        self.owner.calls.append(("device.attach", target))
        return RecordingSession(self.owner, int(target) if isinstance(target, int) else 4242)

    def resume(self, pid: int) -> None:
        self.owner.calls.append(("device.resume", pid))

    def kill(self, pid: int) -> None:
        self.owner.calls.append(("device.kill", pid))


class RecordingDeviceManager:
    def __init__(self, owner: "RecordingFrida") -> None:
        self.owner = owner

    def get_device(self, device_id: str, timeout: float = 0.0) -> RecordingDevice:
        self.owner.calls.append(("manager.get_device", device_id, timeout))
        return self.owner.device

    def add_remote_device(self, address: str) -> RecordingDevice:
        self.owner.calls.append(("manager.add_remote_device", address))
        return self.owner.device


class RecordingFrida:
    """Call recorder only; it deliberately does not claim device/runtime parity."""

    __version__ = "recording-test"
    test_double = True
    real_device_parity = False

    def __init__(
        self,
        *,
        messages: Optional[list[tuple[Any, Any]]] = None,
        load_error: Optional[Exception] = None,
        unload_failures: int = 0,
        device_error: Optional[Exception] = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.messages = messages or []
        self.load_error = load_error
        self.unload_failures = unload_failures
        self.device_error = device_error
        self.source: Optional[str] = None
        self.script: Optional[RecordingScript] = None
        self.device = RecordingDevice(self)
        self.manager = RecordingDeviceManager(self)

    def get_device_manager(self) -> RecordingDeviceManager:
        self.calls.append(("frida.get_device_manager",))
        return self.manager

    def get_usb_device(self, timeout: float = 0.0) -> RecordingDevice:
        self.calls.append(("frida.get_usb_device", timeout))
        if self.device_error is not None:
            raise self.device_error
        return self.device

    def get_local_device(self) -> RecordingDevice:
        self.calls.append(("frida.get_local_device",))
        return self.device


class IOSInstrumentationProviderTests(unittest.TestCase):
    @staticmethod
    def _hooks() -> list[dict[str, Any]]:
        return [
            {
                "kind": "objc",
                "class": "ExampleController",
                "selector": "viewDidAppear:",
                "label": "view-entry",
            },
            {
                "kind": "native",
                "module": "TargetKit",
                "export": "target_entry",
                "arguments": [{"index": 0, "name": "context", "type": "pointer"}],
                "label": "native-entry",
            },
        ]

    def _request(
        self,
        action: str = "spawn",
        *,
        target: Optional[TargetIdentity] = None,
        params: Optional[Mapping[str, Any]] = None,
        hooks: Optional[list[dict[str, Any]]] = None,
    ) -> CapabilityRequest:
        values: dict[str, Any] = {
            "mode": action,
            "device": "usb",
            "duration_ms": 0,
            "max_events": 2,
            "max_string_length": 32,
            "max_byte_length": 2,
            "hooks": self._hooks() if hooks is None else hooks,
        }
        values.update(dict(params or {}))
        return CapabilityRequest(
            capability="ios_instrumentation",
            action=action,
            target=target or TargetIdentity(kind="ios_bundle", display_name="com.example.app"),
            params=values,
            session_id=f"ios-{action}-test",
            provenance={"source": "recording-fake", "api_token": "provenance-secret"},
        )

    @staticmethod
    def _backend(frida: RecordingFrida) -> FridaIOSInstrumentationBackend:
        return FridaIOSInstrumentationBackend(frida, platform_name="darwin")

    def test_production_spawn_script_events_cleanup_artifacts_and_audit(self) -> None:
        frida = RecordingFrida(
            messages=[
                ({"type": "send", "payload": {"event": "native_call", "thread_id": 7, "token": "event-secret"}}, b"abcd"),
                ({"type": "send", "payload": {"event": "objc_call", "thread_id": 8}}, None),
                ({"type": "send", "payload": {"event": "native_call", "thread_id": 9}}, None),
            ]
        )
        provider = IOSInstrumentationProvider(backend=self._backend(frida), duration_ms=0)
        plan = provider.plan(self._request())
        self.assertTrue(provider.validate(plan).ok)
        self.assertFalse(plan.provenance["real_device_parity"])
        self.assertEqual(plan.provenance["execution_assurance"], "simulation")
        self.assertFalse(plan.provenance["production_evidence"])
        frida.calls.clear()

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.provenance["execution_assurance"], "simulation")
        self.assertFalse(result.provenance["production_evidence"])
        self.assertFalse(result.report_section["production_evidence"])
        names = [call[0] for call in frida.calls]
        for required in (
            "frida.get_usb_device",
            "device.spawn",
            "device.attach",
            "session.create_script",
            "script.load",
            "device.resume",
            "script.unload",
            "session.detach",
        ):
            self.assertIn(required, names)
        self.assertLess(names.index("device.spawn"), names.index("device.resume"))
        self.assertLess(names.index("script.load"), names.index("device.resume"))
        self.assertNotIn("device.kill", names)
        self.assertEqual(frida.calls[names.index("device.spawn")][1], ["com.example.app"])
        self.assertIn("Interceptor.attach", frida.source or "")
        self.assertIn("Process.getCurrentThreadId", frida.source or "")
        self.assertIn("emitted >= SPEC.max_events", frida.source or "")
        spec_line = next(line for line in (frida.source or "").splitlines() if line.startswith("const SPEC = "))
        spec = json.loads(spec_line.removeprefix("const SPEC = ")[:-1])
        self.assertEqual((spec["max_events"], spec["duration_ms"], spec["max_string_length"], spec["max_byte_length"]), (2, 0, 32, 2))
        self.assertEqual(result.after_snapshot["event_count"], 2)
        self.assertEqual(result.after_snapshot["dropped_event_count"], 1)
        self.assertEqual(result.report_section["events"][0]["token"], "<redacted>")
        self.assertEqual(result.report_section["events"][0]["data"]["retained_size"], 2)
        self.assertEqual(result.report_section["events"][0]["data"]["sha256"], hashlib.sha256(b"abcd").hexdigest())
        self.assertTrue(result.rollback_plan["completed"])
        self.assertEqual(provider.rollback(result).details["status"], "already_completed")

        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            self.assertEqual(len(bundle.artifacts), 3)
            materialized = "".join((Path(out_dir) / item.path).read_text(encoding="utf-8") for item in bundle.artifacts)
            self.assertNotIn("event-secret", materialized)
            self.assertNotIn("provenance-secret", materialized)
            self.assertTrue(all(entry["materialized"] for entry in bundle.manifest_entries))

        record = CapabilityAuditBuilder().build_record(plan=plan, validation=provider.validate(plan), result=result)
        self.assertTrue(validate_capability_audit_record(record).ok)

    def test_injected_frida_binding_cannot_claim_production_evidence(self) -> None:
        frida = RecordingFrida()
        frida.test_double = False
        frida.real_device_parity = True
        backend = FridaIOSInstrumentationBackend(frida, platform_name="darwin")
        provider = IOSInstrumentationProvider(backend=backend, duration_ms=0)

        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(result.status, "ok")
        self.assertFalse(backend.real_device_parity)
        self.assertTrue(backend.test_double)
        self.assertEqual(result.provenance["execution_assurance"], "simulation")
        self.assertFalse(result.provenance["production_evidence"])

    def test_attach_and_trace_never_spawn_resume_or_kill(self) -> None:
        cases = [
            ("attach", TargetIdentity(kind="process", pid=4242, display_name="ExampleApp"), {"device": "local"}),
            ("trace", TargetIdentity(kind="ios_process", display_name="ExampleApp"), {"device": {"type": "remote", "address": "127.0.0.1:27042"}}),
        ]
        for action, target, params in cases:
            with self.subTest(action=action):
                frida = RecordingFrida()
                provider = IOSInstrumentationProvider(backend=self._backend(frida), duration_ms=0)
                result = provider.execute(provider.plan(self._request(action, target=target, params=params)))
                self.assertEqual(result.status, "ok")
                names = [call[0] for call in frida.calls]
                self.assertNotIn("device.spawn", names)
                self.assertNotIn("device.resume", names)
                self.assertNotIn("device.kill", names)
                self.assertIn("device.attach", names)

    def test_device_selection_and_dependency_gates(self) -> None:
        frida = RecordingFrida()
        backend = self._backend(frida)
        for options in (
            {"device_type": "usb", "device_timeout_ms": 10},
            {"device_type": "local", "device_timeout_ms": 10},
            {"device_type": "remote", "remote_address": "127.0.0.1:27042", "device_timeout_ms": 10},
            {"device_type": "explicit", "device_id": "device-1", "device_timeout_ms": 10},
        ):
            self.assertIs(backend.select_device(options), frida.device)

        with patch("reverse_analyzer.providers.ios_instrumentation.importlib.import_module", side_effect=ModuleNotFoundError("frida")):
            missing = FridaIOSInstrumentationBackend(platform_name="darwin")
        non_darwin = FridaIOSInstrumentationBackend(RecordingFrida(), platform_name="win32")
        unavailable_device = self._backend(RecordingFrida(device_error=RuntimeError("no USB device")))
        for gated in (missing, non_darwin, unavailable_device):
            with self.subTest(reason=getattr(gated, "unavailable_reason", None)):
                provider = IOSInstrumentationProvider(backend=gated, duration_ms=0)
                result = provider.execute(provider.plan(self._request()))
                self.assertEqual(result.status, "unavailable")
                self.assertNotEqual(result.status, "ok")
                self.assertTrue(result.rollback_plan["completed"])

    def test_validation_rejects_raw_scripts_invalid_hooks_and_limits(self) -> None:
        cases = [
            ({"script_source": "send('unbounded')"}, self._hooks(), "caller-supplied"),
            ({}, [{"kind": "objc", "class": "Example", "selector": "bad selector"}], "selector"),
            ({}, [{"kind": "native", "module": "bad module", "export": "entry"}], "module"),
            ({}, [{"kind": "native", "module": "TargetKit", "export": "bad export!"}], "export_name"),
            ({}, [{"kind": "native", "module": "TargetKit", "offset": -1}], "offset"),
            ({"max_events": 10001}, self._hooks(), "max_events"),
            ({}, [self._hooks()[0]] * 65, "at most 64 hooks"),
        ]
        provider = IOSInstrumentationProvider(backend=self._backend(RecordingFrida()), duration_ms=0)
        for params, hooks, expected in cases:
            with self.subTest(expected=expected):
                validation = provider.validate(provider.plan(self._request(params=params, hooks=hooks)))
                self.assertFalse(validation.ok)
                self.assertIn(expected, " ".join(validation.errors))

        with self.assertRaises(ValueError):
            render_ios_instrumentation_script(self._hooks(), max_byte_length=4097)

    def test_load_failure_resumes_unloads_detaches_kills_and_rollback_retries(self) -> None:
        frida = RecordingFrida(load_error=RuntimeError("recorded load failure"), unload_failures=1)
        provider = IOSInstrumentationProvider(backend=self._backend(frida), duration_ms=0)

        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(result.status, "failed")
        names = [call[0] for call in frida.calls]
        self.assertLess(names.index("script.load"), names.index("device.resume"))
        self.assertLess(names.index("device.resume"), names.index("script.unload"))
        self.assertLess(names.index("script.unload"), names.index("session.detach"))
        self.assertLess(names.index("session.detach"), names.index("device.kill"))
        self.assertFalse(result.rollback_plan["completed"])

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertEqual(rollback.details["status"], "completed")
        self.assertEqual([call[0] for call in frida.calls].count("script.unload"), 2)


if __name__ == "__main__":
    unittest.main()
