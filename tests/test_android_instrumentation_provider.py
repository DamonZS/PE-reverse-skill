import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import (
    CapabilityRequest,
    TargetIdentity,
    validate_capability_audit_record,
)
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.providers.android_instrumentation import (
    AndroidInstrumentationProvider,
    FridaAndroidInstrumentationBackend,
    render_android_instrumentation_script,
)


class FakeAndroidInstrumentationBackend:
    name = "fake-frida-android"
    available = True
    unavailable_reason = None
    version = "test-1"

    def __init__(
        self,
        *,
        probe_result: Optional[Mapping[str, Any]] = None,
        device_error: Optional[Exception] = None,
        emitted_messages: Optional[list[tuple[Any, Any]]] = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.device_error = device_error
        self.probe_result = dict(
            probe_result
            or {
                "status": "ok",
                "exists": True,
                "accessible": True,
                "running": True,
                "resolved_pid": 4242,
                "resolved_name": "com.example.app",
            }
        )
        self.emitted_messages = emitted_messages or [
            (
                {
                    "type": "send",
                    "payload": {
                        "event": "hook_installed",
                        "hook_kind": "java",
                        "label": "activity-entry",
                    },
                },
                None,
            )
        ]
        self.source: Optional[str] = None
        self.specification: dict[str, Any] = {}
        self._on_message: Optional[Callable[..., None]] = None

    def select_device(self, options: Mapping[str, Any]) -> str:
        self.calls.append(("select_device", dict(options)))
        if self.device_error is not None:
            raise self.device_error
        return "fake-device-handle"

    def describe_device(self, device: Any) -> Mapping[str, Any]:
        return {
            "id": "usb-test-device",
            "name": "Android Test Device",
            "type": "usb",
            "handle": str(device),
        }

    def probe_target(
        self,
        device: Any,
        target: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls.append(
            ("probe_target", device, dict(target), dict(options))
        )
        return dict(self.probe_result)

    def spawn(
        self,
        device: Any,
        package: str,
        options: Mapping[str, Any],
    ) -> int:
        self.calls.append(("spawn", device, package, dict(options)))
        return 7331

    def attach(self, device: Any, target: Any) -> str:
        self.calls.append(("attach", device, target))
        return "fake-session-handle"

    def create_script(
        self,
        session: Any,
        source: str,
        on_message: Callable[..., None],
    ) -> str:
        self.calls.append(("create_script", session))
        self.source = source
        self._on_message = on_message
        spec_line = next(
            line for line in source.splitlines() if line.startswith("const SPEC = ")
        )
        self.specification = json.loads(
            spec_line.removeprefix("const SPEC = ")[:-1]
        )
        return "fake-script-handle"

    def load_script(self, script: Any) -> Mapping[str, Any]:
        self.calls.append(("load_script", script))
        assert self._on_message is not None
        for message, data in self.emitted_messages:
            self._on_message(message, data)
        return {"ok": True, "loaded": True}

    def resume(self, device: Any, pid: int) -> Mapping[str, Any]:
        self.calls.append(("resume", device, pid))
        return {"ok": True, "resumed": True, "pid": pid}

    def wait(self, timeout_ms: int) -> None:
        self.calls.append(("wait", timeout_ms))

    def unload_script(self, script: Any) -> Mapping[str, Any]:
        self.calls.append(("unload_script", script))
        return {"ok": True, "unloaded": True}

    def detach(self, session: Any) -> Mapping[str, Any]:
        self.calls.append(("detach", session))
        return {"ok": True, "detached": True}

    def describe_session(self, session: Any) -> Mapping[str, Any]:
        return {"handle": str(session), "pid": 7331}

    def call_names(self) -> list[str]:
        return [str(call[0]) for call in self.calls]


class FakeFridaDeviceManager:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def get_device(self, device_id: str, timeout: float = 0.0) -> str:
        self.calls.append(("get_device", device_id, timeout))
        return f"device:{device_id}"

    def add_remote_device(self, address: str) -> str:
        self.calls.append(("add_remote_device", address))
        return f"remote:{address}"


class FakeFridaModule:
    __version__ = "99.0-test"

    def __init__(self) -> None:
        self.manager = FakeFridaDeviceManager()
        self.calls: list[tuple[Any, ...]] = []

    def get_device_manager(self) -> FakeFridaDeviceManager:
        return self.manager

    def get_usb_device(self, timeout: float = 0.0) -> str:
        self.calls.append(("get_usb_device", timeout))
        return "usb-device"

    def get_local_device(self) -> str:
        self.calls.append(("get_local_device",))
        return "local-device"


class AndroidInstrumentationProviderTests(unittest.TestCase):
    @staticmethod
    def _java_hook() -> dict[str, Any]:
        return {
            "kind": "java",
            "class": "com.example.MainActivity",
            "method": "onCreate",
            "overload": [],
            "label": "activity-entry",
        }

    @staticmethod
    def _native_hook() -> dict[str, Any]:
        return {
            "kind": "native",
            "module": "libtarget.so",
            "export": "target_entry",
            "arguments": [],
            "label": "native-entry",
        }

    def _request(
        self,
        *,
        mode: str = "spawn",
        target: Optional[TargetIdentity] = None,
        device: Any = "usb",
        hooks: Optional[list[dict[str, Any]]] = None,
        params: Optional[Mapping[str, Any]] = None,
        session_id: str = "android-instrumentation-test",
    ) -> CapabilityRequest:
        if target is None:
            target = TargetIdentity(
                kind="android_package",
                display_name="com.example.app",
            )
        request_params: dict[str, Any] = {
            "mode": mode,
            "device": device,
            "timeout_ms": 0,
            "max_messages": 8,
        }
        if hooks is not None:
            request_params["hooks"] = hooks
        elif not params or not any(
            key in params for key in ("script_path", "script_file", "local_script")
        ):
            request_params["hooks"] = [self._java_hook()]
        request_params.update(dict(params or {}))
        return CapabilityRequest(
            capability="android_instrumentation",
            action=mode,
            target=target,
            params=request_params,
            session_id=session_id,
            provenance={"source": "test_android_instrumentation_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    def test_usb_spawn_lifecycle_messages_rollback_artifacts_and_audit(self) -> None:
        backend = FakeAndroidInstrumentationBackend(
            emitted_messages=[
                (
                    {
                        "type": "send",
                        "payload": {
                            "event": "hook_installed",
                            "hook_kind": "java",
                            "label": "activity-entry",
                        },
                    },
                    b"\x00\x01",
                ),
                (
                    {
                        "type": "send",
                        "payload": {
                            "event": "native_call",
                            "hook_kind": "native",
                            "label": "native-entry",
                        },
                    },
                    None,
                ),
            ]
        )
        provider = AndroidInstrumentationProvider(backend=backend, timeout_ms=0)
        request = self._request(hooks=[self._java_hook(), self._native_hook()])

        self.assertTrue(provider.supports(request))
        plan = provider.plan(request)
        validation = provider.validate(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(plan.action, "spawn")
        self.assertEqual(plan.parameters["device_type"], "usb")
        self.assertEqual(plan.parameters["target_type"], "package")
        self.assertEqual(plan.parameters["package"], "com.example.app")
        self.assertEqual(plan.parameters["hook_specs"][0]["overload"], [])
        self.assertEqual(plan.parameters["hook_specs"][1]["arguments"], [])
        self.assertEqual(len(plan.precondition_hash or ""), 64)
        self.assertEqual(
            plan.provenance["target_identity"]["package"], "com.example.app"
        )
        backend.calls.clear()

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(
            backend.call_names(),
            [
                "select_device",
                "probe_target",
                "spawn",
                "attach",
                "create_script",
                "load_script",
                "resume",
                "wait",
                "unload_script",
                "detach",
            ],
        )
        self.assertEqual(backend.calls[2][2], "com.example.app")
        self.assertEqual(backend.calls[3][2], 7331)
        self.assertEqual(backend.calls[6][2], 7331)
        self.assertIn("Java.perform", backend.source or "")
        self.assertIn("Interceptor.attach", backend.source or "")
        self.assertEqual(len(result.report_section["messages"]), 2)
        self.assertEqual(
            result.report_section["messages"][0]["data"]["sha256"],
            hashlib.sha256(b"\x00\x01").hexdigest(),
        )
        self.assertEqual(result.after_snapshot["session"]["state"], "closed")
        self.assertTrue(result.after_snapshot["session"]["resumed"])
        self.assertTrue(result.rollback_plan["completed"])
        self.assertEqual(result.rollback_plan["status"], "completed")
        self.assertEqual(
            result.provenance["precondition_hash"], plan.precondition_hash
        )

        calls_after_execute = list(backend.calls)
        first_rollback = provider.rollback(result)
        second_rollback = provider.rollback(result)
        self.assertTrue(first_rollback.ok, first_rollback.details)
        self.assertTrue(second_rollback.ok, second_rollback.details)
        self.assertEqual(first_rollback.details["status"], "already_completed")
        self.assertEqual(backend.calls, calls_after_execute)

        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            self.assertEqual(len(bundle.artifacts), 3)
            self.assertEqual(
                {artifact.kind for artifact in bundle.artifacts},
                {
                    "android-instrumentation-audit",
                    "android-instrumentation-events",
                    "android-instrumentation-rollback",
                },
            )
            entries = {entry["path"]: entry for entry in bundle.manifest_entries}
            for artifact in bundle.artifacts:
                artifact_path = Path(out_dir) / artifact.path
                encoded = artifact_path.read_bytes()
                digest = hashlib.sha256(encoded).hexdigest()
                self.assertEqual(artifact.metadata["sha256"], digest)
                self.assertEqual(entries[artifact.path]["sha256"], digest)
                self.assertEqual(entries[artifact.path]["size"], len(encoded))
                self.assertTrue(entries[artifact.path]["materialized"])
                json.loads(encoded)

        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_remote_process_attach_does_not_spawn_or_resume(self) -> None:
        backend = FakeAndroidInstrumentationBackend(
            probe_result={
                "status": "ok",
                "exists": True,
                "accessible": True,
                "running": True,
                "resolved_pid": 5151,
                "resolved_name": "com.example.app:worker",
            }
        )
        provider = AndroidInstrumentationProvider(backend=backend)
        request = self._request(
            mode="attach",
            target=TargetIdentity(
                kind="process",
                pid=5151,
                display_name="com.example.app:worker",
            ),
            device={"type": "remote", "address": "127.0.0.1:27042"},
        )

        plan = provider.plan(request)
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(plan.parameters["device_type"], "remote")
        self.assertEqual(plan.parameters["remote_address"], "127.0.0.1:27042")
        self.assertEqual(
            backend.call_names(),
            [
                "select_device",
                "probe_target",
                "attach",
                "create_script",
                "load_script",
                "wait",
                "unload_script",
                "detach",
            ],
        )
        self.assertEqual(backend.calls[2][2], 5151)
        self.assertNotIn("spawn", backend.call_names())
        self.assertNotIn("resume", backend.call_names())
        self.assertFalse(result.after_snapshot["session"]["resumed"])
        self.assertFalse(result.rollback_plan["cleanup"]["resume_required"])
        self.assertTrue(result.rollback_plan["cleanup"]["resume_completed"])

    def test_renderer_preserves_empty_overloads_and_native_arguments(self) -> None:
        source = render_android_instrumentation_script(
            [
                self._java_hook(),
                {
                    "kind": "native",
                    "module": "libtarget.so",
                    "offset": 32,
                    "arguments": [],
                    "label": "offset-entry",
                },
            ],
            session_id="renderer-test",
            max_messages=4,
        )
        spec_line = next(
            line for line in source.splitlines() if line.startswith("const SPEC = ")
        )
        specification = json.loads(
            spec_line.removeprefix("const SPEC = ")[:-1]
        )

        self.assertEqual(specification["hooks"][0]["overload"], [])
        self.assertEqual(specification["hooks"][1]["arguments"], [])
        self.assertEqual(specification["hooks"][1]["offset"], 32)
        self.assertIn("spec.address !== undefined", source)
        self.assertIn("spec.export_name !== undefined", source)

        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            render_android_instrumentation_script(
                [{**self._java_hook(), "javascript": "send('not allowed')"}]
            )

    def test_local_script_path_is_loaded_and_integrity_checked_again(self) -> None:
        backend = FakeAndroidInstrumentationBackend()
        provider = AndroidInstrumentationProvider(backend=backend)
        with tempfile.TemporaryDirectory() as tmp:
            script_path = Path(tmp) / "bounded-hook.js"
            original = "send({event: 'ready'});\n"
            script_path.write_text(original, encoding="utf-8")
            request = self._request(
                mode="attach",
                target=TargetIdentity(
                    kind="process",
                    pid=4242,
                    display_name="com.example.app",
                ),
                params={"script_path": str(script_path)},
            )
            plan = provider.plan(request)
            validation = provider.validate(plan)

            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(plan.parameters["script_source"], "local_file")
            self.assertEqual(plan.parameters["script_path"], str(script_path.resolve()))
            self.assertEqual(
                plan.parameters["script_sha256"],
                hashlib.sha256(original.encode("utf-8")).hexdigest(),
            )

            backend.calls.clear()
            script_path.write_text("send({event: 'changed'});\n", encoding="utf-8")
            changed_validation = provider.validate(plan)
            changed_result = provider.execute(plan)

            self.assertFalse(changed_validation.ok)
            self.assertTrue(
                any(
                    "instrumentation script changed after planning" in error
                    for error in changed_validation.errors
                ),
                changed_validation.errors,
            )
            self.assertEqual(changed_result.status, "failed")
            self.assertEqual(backend.calls, [])

    def test_inline_javascript_is_rejected_before_backend_access(self) -> None:
        backend = FakeAndroidInstrumentationBackend()
        provider = AndroidInstrumentationProvider(backend=backend)
        plan = provider.plan(
            self._request(
                hooks=[self._java_hook()],
                params={"script": "send({event: 'caller-controlled'});"},
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertTrue(
            any("inline JavaScript is not accepted" in error for error in validation.errors),
            validation.errors,
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.calls, [])

    def test_target_not_found_is_failed_without_attach(self) -> None:
        backend = FakeAndroidInstrumentationBackend(
            probe_result={
                "status": "failed",
                "exists": False,
                "accessible": False,
                "reason": "package was not found",
            }
        )
        provider = AndroidInstrumentationProvider(backend=backend)
        plan = provider.plan(self._request())

        validation = provider.validate(plan)
        backend.calls.clear()
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.call_names(), ["select_device", "probe_target"])
        self.assertNotIn("attach", backend.call_names())
        self.assertEqual(
            self._checks(validation)["target_probe"]["status"], "failed"
        )

    def test_device_not_found_is_unavailable_without_target_probe(self) -> None:
        backend = FakeAndroidInstrumentationBackend(
            device_error=RuntimeError("USB device not found")
        )
        provider = AndroidInstrumentationProvider(backend=backend)
        plan = provider.plan(self._request())

        validation = provider.validate(plan)
        backend.calls.clear()
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertTrue(
            any("USB device not found" in warning for warning in validation.warnings)
        )
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(backend.call_names(), ["select_device"])
        self.assertEqual(
            self._checks(validation)["android_device"]["status"], "unavailable"
        )

    def test_missing_frida_dependency_remains_unavailable(self) -> None:
        with patch(
            "reverse_analyzer.providers.android_instrumentation.importlib.import_module",
            side_effect=ModuleNotFoundError("No module named 'frida'"),
        ):
            provider = AndroidInstrumentationProvider()

        plan = provider.plan(self._request())
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertTrue(validation.warnings)
        self.assertFalse(provider.backend.available)
        self.assertEqual(
            self._checks(validation)["frida_backend"]["status"], "unavailable"
        )
        self.assertEqual(result.status, "unavailable")
        self.assertIn("No module named 'frida'", result.report_section["errors"][0])

    def test_production_backend_selects_usb_local_remote_and_device_id(self) -> None:
        frida = FakeFridaModule()
        backend = FridaAndroidInstrumentationBackend(frida_module=frida)

        self.assertEqual(
            backend.select_device(
                {"device_type": "usb", "device_timeout_ms": 2500}
            ),
            "usb-device",
        )
        self.assertEqual(
            backend.select_device(
                {"device_type": "local", "device_timeout_ms": 2500}
            ),
            "local-device",
        )
        self.assertEqual(
            backend.select_device(
                {
                    "device_type": "remote",
                    "remote_address": "127.0.0.1:27042",
                    "device_timeout_ms": 2500,
                }
            ),
            "remote:127.0.0.1:27042",
        )
        self.assertEqual(
            backend.select_device(
                {
                    "device_type": "usb",
                    "device_id": "device-123",
                    "device_timeout_ms": 2500,
                }
            ),
            "device:device-123",
        )
        self.assertEqual(frida.calls[0], ("get_usb_device", 2.5))
        self.assertEqual(frida.calls[1], ("get_local_device",))
        self.assertIn(
            ("add_remote_device", "127.0.0.1:27042"), frida.manager.calls
        )
        self.assertIn(("get_device", "device-123", 2.5), frida.manager.calls)

    def test_default_registry_registers_production_adapter(self) -> None:
        registry = build_default_registry()

        provider = registry.resolve("android_instrumentation")
        self.assertIsInstance(provider, AndroidInstrumentationProvider)
        self.assertEqual(provider.provider_name, "frida_android_instrumentation")


if __name__ == "__main__":
    unittest.main()
