import hashlib
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import time
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
from reverse_analyzer.providers.hook_runtime import (
    FridaHookBackend,
    HookRuntimeMockProvider,
    HookRuntimeProvider,
    render_frida_hook_script,
)


_RUN_FRIDA_HOOK_RUNTIME_SMOKE = os.environ.get("RUN_FRIDA_HOOK_RUNTIME_SMOKE") == "1"
_FRIDA_HOOK_TARGET = Path(__file__).parent / "fixtures" / "frida_hook_target.py"


class FakeHookRuntimeBackend:
    name = "fake-frida"
    available = True
    unavailable_reason = None
    version = "test-1"

    def __init__(
        self,
        *,
        wait_error: Optional[Exception] = None,
        unload_error: Optional[Exception] = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.source: Optional[str] = None
        self.specification: dict[str, Any] = {}
        self._on_message: Optional[Callable[..., None]] = None
        self.wait_error = wait_error
        self.unload_error = unload_error

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls.append(("probe_target", target.pid, dict(options)))
        return {
            "status": "ok",
            "accessible": True,
            "exists": True,
            "pid": target.pid,
        }

    def attach(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> str:
        self.calls.append(("attach", target.pid, dict(options)))
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
        self.specification = json.loads(spec_line.removeprefix("const SPEC = ")[:-1])
        return "fake-script-handle"

    def load_script(self, script: Any) -> Mapping[str, Any]:
        self.calls.append(("load_script", script))
        assert self._on_message is not None
        hook_type = self.specification["type"]
        self._on_message(
            {
                "type": "send",
                "payload": {
                    "event": "hook_installed",
                    "hook_type": hook_type,
                    "address": self.specification.get("address", "0x70001000"),
                },
            },
            None,
        )
        self._on_message(
            {
                "type": "send",
                "payload": {
                    "event": (
                        "breakpoint_hit"
                        if hook_type == "breakpoint_trace"
                        else "hook_call"
                    ),
                    "hook_type": hook_type,
                    "sequence": 1,
                },
            },
            None,
        )
        return {"ok": True, "loaded": True}

    def wait(self, duration_ms: int) -> None:
        self.calls.append(("wait", duration_ms))
        if self.wait_error is not None:
            raise self.wait_error

    def unload_script(self, script: Any) -> Mapping[str, Any]:
        self.calls.append(("unload_script", script))
        if self.unload_error is not None:
            raise self.unload_error
        return {"ok": True, "unloaded": True}

    def detach(self, session: Any) -> Mapping[str, Any]:
        self.calls.append(("detach", session))
        return {"ok": True, "detached": True}

    def describe_session(self, session: Any) -> Mapping[str, Any]:
        return {
            "backend": self.name,
            "handle": session,
            "mode": "attach",
            "pid": 4242,
        }

    def call_names(self) -> list[str]:
        return [str(call[0]) for call in self.calls]


class HookRuntimeProviderTests(unittest.TestCase):
    _REPORT_AUDIT_FIELDS = {
        "session_id",
        "target_identity",
        "precondition_hash",
        "before_snapshot",
        "after_snapshot",
        "rollback_plan",
        "provenance",
        "artifacts",
        "evidence_manifest_entries",
    }

    def _request(
        self,
        action: str,
        params: Mapping[str, Any],
        *,
        session_id: str = "hook-runtime-test",
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="hook_runtime",
            action=action,
            target=TargetIdentity(
                kind="process",
                pid=4242,
                display_name="target.exe",
            ),
            params=dict(params),
            session_id=session_id,
            provenance={"source": "test_hook_runtime_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    def _assert_audit_contract(self, plan: Any, validation: Any, result: Any) -> None:
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def _live_backend_and_profile(self) -> tuple[FridaHookBackend, dict[str, Any]]:
        backend = FridaHookBackend()
        if not backend.available:
            self.skipTest(backend.unavailable_reason or "Frida Python binding unavailable")
        try:
            backend._frida.get_local_device()
        except Exception as exc:  # noqa: BLE001 - smoke-test availability boundary
            self.skipTest(f"local Frida device unavailable: {type(exc).__name__}: {exc}")

        try:
            completed = subprocess.run(
                [sys.executable, str(_FRIDA_HOOK_TARGET), "--describe"],
                capture_output=True,
                check=False,
                text=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            self.fail("Frida hook target description timed out")
        if completed.returncode == 2:
            self.skipTest(completed.stdout.strip() or "platform is unsupported")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        profile = json.loads(completed.stdout.strip())
        self.assertEqual(profile["event"], "description")
        return backend, profile

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()

    def _start_live_target(
        self,
        *,
        duration: str = "30",
    ) -> tuple[subprocess.Popen[str], dict[str, Any]]:
        process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(_FRIDA_HOOK_TARGET),
                "--duration",
                duration,
                "--interval",
                "0.005",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._stop_process, process)
        assert process.stdout is not None
        output: queue.Queue[Any] = queue.Queue(maxsize=1)

        def read_ready_line() -> None:
            try:
                output.put(process.stdout.readline())
            except BaseException as exc:  # noqa: BLE001 - forwarded to the test thread
                output.put(exc)

        threading.Thread(target=read_ready_line, daemon=True).start()
        try:
            line = output.get(timeout=5)
        except queue.Empty:
            self._stop_process(process)
            self.fail("Frida hook target readiness timed out")
        if isinstance(line, BaseException):
            raise line
        if not line:
            process.wait(timeout=5)
            stderr = process.stderr.read() if process.stderr is not None else ""
            self.fail(f"Frida hook target exited before readiness: {stderr}")
        identity = json.loads(line)
        self.assertEqual(identity["event"], "ready")
        self.assertEqual(identity["pid"], process.pid)
        return process, identity

    def _live_request(
        self,
        target: TargetIdentity,
        profile: Mapping[str, Any],
        *,
        session_id: str,
        target_args: Optional[list[str]] = None,
        kill_spawned: bool = False,
        duration_ms: int = 1_000,
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="hook_runtime",
            action="api_hook",
            target=target,
            params={
                "module": profile["module"],
                "export": profile["export"],
                "arguments": [],
                "capture_return": False,
                "label": "local-python-smoke",
                "duration_ms": duration_ms,
                "max_events": 64,
                "target_args": target_args or [],
                "kill_spawned_on_rollback": kill_spawned,
            },
            session_id=session_id,
            provenance={"source": "frida_hook_runtime_live_smoke"},
        )

    def _assert_live_result(
        self,
        provider: HookRuntimeProvider,
        plan: Any,
        validation: Any,
        result: Any,
        *,
        mode: str,
        expected_pid: Optional[int] = None,
    ) -> None:
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(result.status, "ok", json.dumps(result.report_section["errors"]))
        session = result.report_section["session"]
        self.assertEqual(session["backend"], "frida")
        self.assertEqual(session["mode"], mode)
        self.assertGreater(session["pid"], 0)
        if expected_pid is not None:
            self.assertEqual(session["pid"], expected_pid)
        self.assertEqual(session["state"], "closed")
        self.assertFalse(session["attached"])
        self.assertFalse(session["script_loaded"])
        self.assertTrue(session["detached"])

        hook_calls = [
            event
            for event in result.report_section["events"]
            if event.get("event") == "hook_call"
        ]
        self.assertTrue(hook_calls, result.report_section["events"])
        self.assertTrue(all(event.get("message_type") == "send" for event in hook_calls))
        self.assertTrue(
            all(event.get("session_id") == plan.session_id for event in hook_calls)
        )

        cleanup = result.after_snapshot["cleanup"]
        self.assertTrue(cleanup["ok"], cleanup)
        self.assertTrue(cleanup["unloaded"], cleanup)
        self.assertTrue(cleanup["detached"], cleanup)
        self.assertTrue(result.rollback_plan["completed"])
        self.assertEqual(result.rollback_plan["status"], "completed")
        self._assert_audit_contract(plan, validation, result)

        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            self.assertEqual(len(bundle.artifacts), 1)
            artifact = bundle.artifacts[0]
            self.assertEqual(artifact.kind, "hook-runtime-audit")
            artifact_path = Path(out_dir) / artifact.path
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["session_id"], plan.session_id)
            self.assertEqual(payload["precondition_hash"], plan.precondition_hash)
            self.assertEqual(
                payload["report_section"]["session"]["pid"], session["pid"]
            )
            self.assertTrue(
                any(
                    event.get("event") == "hook_call"
                    for event in payload["report_section"]["events"]
                )
            )
            self.assertTrue(artifact.metadata["materialized"])
            self.assertEqual(
                artifact.metadata["sha256"], hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            )

    def test_all_hook_types_execute_rollback_and_collect_artifacts(self) -> None:
        cases = {
            "api_hook": {
                "module": "kernel32.dll",
                "export": "CreateFileW",
                "arguments": [
                    {
                        "name": "path",
                        "index": 0,
                        "type": "utf16",
                        "max_length": 128,
                    }
                ],
                "capture_return": True,
                "label": "file-open",
            },
            "inline_hook": {
                "address": "0x401000",
                "arguments": [{"name": "flags", "index": 0, "type": "uint32"}],
                "capture_return": True,
                "label": "inline-entry",
            },
            "breakpoint_trace": {
                "address": 0x402000,
                "arguments": [],
                "capture_return": False,
                "label": "trace-point",
            },
        }

        for hook_type, hook_params in cases.items():
            with self.subTest(hook_type=hook_type):
                backend = FakeHookRuntimeBackend()
                provider = HookRuntimeProvider(backend=backend, duration_ms=0)
                request = self._request(
                    hook_type,
                    {
                        **hook_params,
                        "duration_ms": 0,
                        "max_events": 8,
                        "target_args": [],
                        "kill_spawned_on_rollback": False,
                    },
                    session_id=f"session-{hook_type}",
                )

                self.assertTrue(provider.supports(request))
                plan = provider.plan(request)
                validation = provider.validate(plan)

                self.assertEqual(plan.action, hook_type)
                self.assertEqual(plan.parameters["hook_type"], hook_type)
                self.assertEqual(
                    plan.parameters["hook_specification"]["type"], hook_type
                )
                self.assertEqual(
                    plan.parameters["hook_specification"]["arguments"],
                    hook_params["arguments"],
                )
                self.assertIsNotNone(plan.parameters["script_sha256"])
                self.assertTrue(validation.ok, validation.errors)
                self.assertEqual(
                    self._checks(validation)["controlled_script"]["status"], "ok"
                )

                result = provider.execute(plan)

                self.assertEqual(result.status, "ok")
                self.assertEqual(result.report_section["session"]["state"], "closed")
                self.assertFalse(result.report_section["session"]["attached"])
                self.assertFalse(result.report_section["session"]["script_loaded"])
                self.assertEqual(result.report_section["target_identity"]["pid"], 4242)
                self.assertEqual(
                    result.report_section["hook_specification"]["type"], hook_type
                )
                self.assertEqual(len(result.report_section["events"]), 2)
                self.assertFalse(result.rollback_plan["active"])
                self.assertTrue(result.rollback_plan["completed"])
                self.assertTrue(result.rollback_plan["idempotent"])
                self.assertFalse(result.rollback_plan["cross_process_supported"])
                self.assertEqual(result.rollback_plan["status"], "completed")
                self.assertTrue(result.rollback_plan["cleanup"]["unloaded"])
                self.assertTrue(result.rollback_plan["cleanup"]["detached"])
                self.assertTrue(result.provenance["controlled_script"])
                self.assertTrue(
                    {
                        "params",
                        "session",
                        "target_identity",
                        "hook_specification",
                        "events",
                        "before",
                        "after",
                        "rollback",
                        "provenance",
                    }
                    <= set(result.report_section)
                )
                self.assertTrue(
                    self._REPORT_AUDIT_FIELDS <= set(result.report_section)
                )
                self.assertEqual(result.artifacts[0].kind, "hook-runtime-audit")
                self.assertIn("Interceptor.attach", backend.source or "")
                names = backend.call_names()
                self.assertLess(names.index("wait"), names.index("unload_script"))
                self.assertLess(names.index("unload_script"), names.index("detach"))
                self._assert_audit_contract(plan, validation, result)
                json.dumps(result.to_dict(), sort_keys=True)

                calls_after_execute = list(backend.calls)
                rollback = provider.rollback(result)
                repeated = provider.rollback(result)

                self.assertTrue(rollback.ok, rollback.details)
                self.assertFalse(rollback.restored)
                self.assertEqual(rollback.details["status"], "already_completed")
                self.assertTrue(repeated.ok, repeated.details)
                self.assertFalse(repeated.restored)
                self.assertEqual(repeated.details["status"], "already_completed")
                self.assertEqual(backend.calls, calls_after_execute)
                self.assertEqual(result.report_section["session"]["state"], "closed")
                self.assertEqual(result.after_snapshot["session"]["state"], "closed")
                self.assertEqual(
                    result.report_section["after"]["rollback"]["status"], "completed"
                )
                self.assertEqual(
                    result.report_section["after_snapshot"], result.after_snapshot
                )
                self.assertEqual(
                    result.report_section["rollback_plan"], result.rollback_plan
                )
                self.assertEqual(
                    result.dashboard_trace[-1]["kind"], "hook_runtime_rollback"
                )
                with tempfile.TemporaryDirectory() as out_dir:
                    bundle = provider.collect_artifacts(result, out_dir)
                    artifact_path = Path(out_dir) / bundle.artifacts[0].path
                    encoded = artifact_path.read_bytes()
                    payload = json.loads(encoded)
                    digest = hashlib.sha256(encoded).hexdigest()
                    self.assertEqual(payload["session_id"], result.session_id)
                    self.assertEqual(payload["target_identity"]["pid"], 4242)
                    self.assertEqual(
                        payload["after_snapshot"]["session"]["state"], "closed"
                    )
                    self.assertTrue(payload["rollback_plan"]["completed"])
                    self.assertFalse(
                        payload["rollback_plan"]["cross_process_supported"]
                    )
                    self.assertEqual(
                        payload["precondition_hash"], plan.precondition_hash
                    )
                    self.assertEqual(
                        bundle.artifacts[0].metadata["session_state"], "closed"
                    )
                    self.assertTrue(bundle.artifacts[0].metadata["materialized"])
                    self.assertEqual(bundle.artifacts[0].metadata["sha256"], digest)
                    self.assertEqual(bundle.artifacts[0].metadata["size"], len(encoded))
                    self.assertEqual(bundle.manifest_entries[0]["sha256"], digest)
                    self.assertEqual(bundle.manifest_entries[0]["size"], len(encoded))
                    self.assertEqual(
                        bundle.manifest_entries[0]["target_identity"]["pid"], 4242
                    )
                    self.assertEqual(
                        bundle.manifest_entries[0]["precondition_hash"],
                        plan.precondition_hash,
                    )
                self.assertEqual(bundle.provider, provider.provider_name)
                self.assertEqual(bundle.artifacts[0].kind, "hook-runtime-audit")
                self.assertEqual(
                    bundle.manifest_entries[0]["role"], "hook-runtime-audit"
                )

    def test_hook_trace_and_trace_aliases_infer_data_contract(self) -> None:
        cases = [
            (
                "hook-trace",
                {"module": "user32.dll", "export": "MessageBoxW"},
                "api_hook",
            ),
            ("trace", {"address": "0x500000"}, "breakpoint_trace"),
            (
                "install",
                {
                    "hook_type": "hook-trace",
                    "module": "ntdll.dll",
                    "export": "NtClose",
                },
                "api_hook",
            ),
        ]

        for action, params, expected in cases:
            with self.subTest(action=action, params=params):
                provider = HookRuntimeProvider(backend=FakeHookRuntimeBackend())
                request = self._request(action, params)
                self.assertTrue(provider.supports(request))
                plan = provider.plan(request)
                self.assertEqual(plan.action, expected)
                self.assertEqual(plan.parameters["hook_type"], expected)

    def test_invalid_module_export_address_and_arguments_never_reach_backend(self) -> None:
        cases = [
            ("api_hook", {"module": "C:/Windows/kernel32.dll", "export": "CreateFileW"}),
            ("api_hook", {"module": "kernel32.dll", "export": "bad export"}),
            ("inline_hook", {"address": "0x0"}),
            (
                "breakpoint_trace",
                {
                    "address": "0x401000",
                    "arguments": [
                        {"name": "bad-name!", "index": 0, "type": "utf8", "max_length": 0}
                    ],
                },
            ),
        ]

        for action, params in cases:
            with self.subTest(action=action, params=params):
                backend = FakeHookRuntimeBackend()
                provider = HookRuntimeProvider(backend=backend)
                plan = provider.plan(self._request(action, params))

                validation = provider.validate(plan)
                result = provider.execute(plan)

                self.assertFalse(validation.ok)
                self.assertEqual(result.status, "failed")
                self.assertEqual(backend.calls, [])
                self.assertEqual(
                    self._checks(validation)["target_probe"]["status"], "skipped"
                )
                self._assert_audit_contract(plan, validation, result)

    def test_collect_artifacts_rejects_paths_outside_collection_root(self) -> None:
        provider = HookRuntimeProvider(backend=FakeHookRuntimeBackend(), duration_ms=0)
        result = provider.execute(
            provider.plan(
                self._request(
                    "api_hook",
                    {"module": "kernel32.dll", "export": "CreateFileW"},
                )
            )
        )
        result.artifacts[0].path = "../escaped-hook-audit.json"

        with tempfile.TemporaryDirectory() as tmp:
            collection_root = Path(tmp) / "artifacts"
            with self.assertRaisesRegex(ValueError, "collection directory"):
                provider.collect_artifacts(result, str(collection_root))
            self.assertFalse((Path(tmp) / "escaped-hook-audit.json").exists())

    def test_custom_javascript_is_rejected_by_plan_and_renderer(self) -> None:
        backend = FakeHookRuntimeBackend()
        provider = HookRuntimeProvider(backend=backend)
        plan = provider.plan(
            self._request(
                "api_hook",
                {
                    "module": "kernel32.dll",
                    "export": "CreateFileW",
                    "script": "send('caller-controlled')",
                },
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertIn("custom JavaScript", " ".join(validation.errors))
        self.assertEqual(result.status, "failed")
        self.assertEqual(backend.calls, [])
        with self.assertRaisesRegex(ValueError, "custom JavaScript"):
            render_frida_hook_script(
                {
                    "schema_version": 1,
                    "type": "api_hook",
                    "module": "kernel32.dll",
                    "export": "CreateFileW",
                    "arguments": [],
                    "capture_return": False,
                    "script": "send('caller-controlled')",
                }
            )

    def test_missing_frida_dependency_is_gracefully_unavailable(self) -> None:
        with patch(
            "reverse_analyzer.providers.hook_runtime.importlib.import_module",
            side_effect=ModuleNotFoundError("No module named 'frida'"),
        ):
            backend = FridaHookBackend()
        provider = HookRuntimeProvider(backend=backend)
        plan = provider.plan(
            self._request(
                "hook-trace",
                {"address": "0x401000", "duration_ms": 0},
                session_id="frida-unavailable",
            )
        )

        validation = provider.validate(plan)
        result = provider.execute(plan)
        rollback = provider.rollback(result)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(
            self._checks(validation)["frida_backend"]["status"], "unavailable"
        )
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.report_section["session"]["state"], "unavailable")
        self.assertFalse(result.report_section["session"]["attached"])
        self.assertFalse(result.report_section["session"]["script_loaded"])
        self.assertFalse(result.rollback_plan["active"])
        self.assertTrue(result.rollback_plan["completed"])
        self.assertIn("Frida Python binding is unavailable", " ".join(validation.warnings))
        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        self._assert_audit_contract(plan, validation, result)

    def test_frida_backend_cleanup_accepts_already_destroyed_runtime(self) -> None:
        backend = FridaHookBackend(frida_module=SimpleNamespace(__version__="test"))
        unload_calls: list[str] = []
        detach_calls: list[str] = []
        native_session = SimpleNamespace(
            is_detached=True,
            detach=lambda: detach_calls.append("detach"),
        )
        runtime = SimpleNamespace(
            device=SimpleNamespace(),
            session=native_session,
            mode="attach",
            pid=4242,
            spawned=False,
            kill_on_detach=False,
            resumed=True,
        )
        native_script = SimpleNamespace(
            is_destroyed=True,
            unload=lambda: unload_calls.append("unload"),
        )
        script = SimpleNamespace(runtime=runtime, script=native_script)

        unload = backend.unload_script(script)
        detach = backend.detach(runtime)

        self.assertTrue(unload["ok"])
        self.assertTrue(unload["unloaded"])
        self.assertTrue(unload["already_destroyed"])
        self.assertTrue(unload["target_detached"])
        self.assertEqual(unload_calls, [])
        self.assertTrue(detach["ok"])
        self.assertTrue(detach["already_detached"])
        self.assertEqual(detach_calls, [])

    def test_execute_best_effort_cleanup_after_wait_error(self) -> None:
        backend = FakeHookRuntimeBackend(wait_error=RuntimeError("fake wait failure"))
        provider = HookRuntimeProvider(backend=backend, duration_ms=0)
        result = provider.execute(
            provider.plan(
                self._request(
                    "breakpoint_trace",
                    {"address": "0x401000", "duration_ms": 0},
                )
            )
        )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["session"]["state"], "closed")
        self.assertFalse(result.report_section["session"]["attached"])
        self.assertFalse(result.report_section["session"]["script_loaded"])
        self.assertTrue(result.rollback_plan["completed"])
        self.assertTrue(result.rollback_plan["cleanup"]["unloaded"])
        self.assertTrue(result.rollback_plan["cleanup"]["detached"])
        self.assertIn("fake wait failure", json.dumps(result.report_section["errors"]))
        names = backend.call_names()
        self.assertLess(names.index("wait"), names.index("unload_script"))
        self.assertLess(names.index("unload_script"), names.index("detach"))

        calls_after_execute = list(backend.calls)
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "already_completed")
        self.assertEqual(backend.calls, calls_after_execute)

    def test_spawn_session_audit_refreshes_resumed_state_after_script_load(self) -> None:
        class SpawnBackend(FakeHookRuntimeBackend):
            def __init__(self) -> None:
                super().__init__()
                self.resumed = False

            def load_script(self, script: Any) -> Mapping[str, Any]:
                result = super().load_script(script)
                self.resumed = True
                return {**result, "resumed": True}

            def describe_session(self, session: Any) -> Mapping[str, Any]:
                return {
                    "backend": self.name,
                    "handle": session,
                    "mode": "spawn",
                    "pid": 5151,
                    "spawned": True,
                    "resumed": self.resumed,
                }

        backend = SpawnBackend()
        provider = HookRuntimeProvider(backend=backend, duration_ms=0)
        request = CapabilityRequest(
            capability="hook_runtime",
            action="api_hook",
            target=TargetIdentity(
                kind="executable",
                path=str(Path(sys.executable).resolve()),
            ),
            params={
                "module": "kernel32.dll",
                "export": "GetCurrentProcessId",
                "duration_ms": 0,
            },
            session_id="spawn-session-refresh",
        )

        result = provider.execute(provider.plan(request))

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.report_section["session"]["mode"], "spawn")
        self.assertTrue(result.report_section["session"]["resumed"])

    def test_execute_reports_incomplete_cleanup_without_persisted_rollback(self) -> None:
        backend = FakeHookRuntimeBackend(unload_error=RuntimeError("fake unload failure"))
        provider = HookRuntimeProvider(backend=backend, duration_ms=0)
        result = provider.execute(
            provider.plan(
                self._request(
                    "breakpoint_trace",
                    {"address": "0x401000", "duration_ms": 0},
                )
            )
        )

        calls_after_execute = list(backend.calls)
        rollback = provider.rollback(result)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["session"]["state"], "cleanup_failed")
        self.assertFalse(result.rollback_plan["active"])
        self.assertFalse(result.rollback_plan["completed"])
        self.assertFalse(result.rollback_plan["cross_process_supported"])
        self.assertEqual(result.rollback_plan["status"], "cleanup_failed")
        self.assertTrue(result.rollback_plan["cleanup"]["unload_attempted"])
        self.assertFalse(result.rollback_plan["cleanup"]["unloaded"])
        self.assertTrue(result.rollback_plan["cleanup"]["detach_attempted"])
        self.assertTrue(result.rollback_plan["cleanup"]["detached"])
        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "failed")
        self.assertFalse(rollback.details["cross_process_supported"])
        self.assertIn("not persisted", rollback.details["reason"])
        self.assertEqual(backend.calls, calls_after_execute)
        names = backend.call_names()
        self.assertLess(names.index("unload_script"), names.index("detach"))

    def test_rollback_is_idempotent_after_bounded_capture_closes(self) -> None:
        backend = FakeHookRuntimeBackend()
        provider = HookRuntimeProvider(backend=backend, duration_ms=0)
        result = provider.execute(
            provider.plan(
                self._request(
                    "api_hook",
                    {
                        "module": "kernel32.dll",
                        "export": "CreateFileW",
                        "duration_ms": 0,
                    },
                )
            )
        )
        calls_after_execute = list(backend.calls)

        first = provider.rollback(result)
        second = provider.rollback(result)

        self.assertTrue(first.ok)
        self.assertTrue(second.ok)
        self.assertFalse(first.restored)
        self.assertFalse(second.restored)
        self.assertEqual(first.details["status"], "already_completed")
        self.assertEqual(second.details["status"], "already_completed")
        self.assertEqual(backend.calls, calls_after_execute)
        self.assertEqual(result.after_snapshot["session"]["state"], "closed")
        self.assertTrue(result.rollback_plan["completed"])
        self.assertTrue(result.rollback_plan["idempotent"])

    @unittest.skipUnless(
        _RUN_FRIDA_HOOK_RUNTIME_SMOKE,
        "set RUN_FRIDA_HOOK_RUNTIME_SMOKE=1 to run the live Frida smoke tests",
    )
    def test_live_frida_attaches_to_harmless_local_python_process(self) -> None:
        backend, described_profile = self._live_backend_and_profile()
        process, target_profile = self._start_live_target()
        self.assertEqual(target_profile["module"], described_profile["module"])
        self.assertEqual(target_profile["export"], described_profile["export"])

        target = TargetIdentity(
            kind="process",
            pid=process.pid,
            display_name=Path(sys.executable).name,
        )
        provider = HookRuntimeProvider(backend=backend)
        request = self._live_request(
            target,
            target_profile,
            session_id=f"frida-live-attach-{os.getpid()}-{time.time_ns()}",
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertEqual(result.report_section["target_identity"]["pid"], process.pid)
        self._assert_live_result(
            provider,
            plan,
            validation,
            result,
            mode="attach",
            expected_pid=process.pid,
        )
        self.assertIsNone(process.poll(), "detach unexpectedly terminated attach target")
        self._stop_process(process)
        self.assertIsNotNone(process.poll())

    @unittest.skipUnless(
        _RUN_FRIDA_HOOK_RUNTIME_SMOKE,
        "set RUN_FRIDA_HOOK_RUNTIME_SMOKE=1 to run the live Frida smoke tests",
    )
    def test_live_frida_cleans_up_when_attach_target_exits(self) -> None:
        backend, described_profile = self._live_backend_and_profile()
        process, target_profile = self._start_live_target(duration="2")
        self.assertEqual(target_profile["module"], described_profile["module"])
        self.assertEqual(target_profile["export"], described_profile["export"])

        target = TargetIdentity(kind="process", pid=process.pid)
        provider = HookRuntimeProvider(backend=backend)
        request = self._live_request(
            target,
            target_profile,
            session_id=f"frida-live-target-exit-{os.getpid()}-{time.time_ns()}",
            duration_ms=3_000,
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        process.wait(timeout=5)
        self._assert_live_result(
            provider,
            plan,
            validation,
            result,
            mode="attach",
            expected_pid=process.pid,
        )
        self.assertTrue(result.report_section["session"]["detached"])
        self.assertTrue(
            result.after_snapshot["cleanup"]["unload_result"]["already_destroyed"]
        )
        self.assertTrue(
            result.after_snapshot["cleanup"]["detach_result"]["already_detached"]
        )

    @unittest.skipUnless(
        _RUN_FRIDA_HOOK_RUNTIME_SMOKE,
        "set RUN_FRIDA_HOOK_RUNTIME_SMOKE=1 to run the live Frida smoke tests",
    )
    def test_live_frida_spawns_and_cleans_harmless_local_python_process(self) -> None:
        backend, profile = self._live_backend_and_profile()
        executable = str(Path(sys.executable).resolve())
        target = TargetIdentity(
            kind="executable",
            path=executable,
            display_name=Path(executable).name,
        )
        provider = HookRuntimeProvider(backend=backend)
        request = self._live_request(
            target,
            profile,
            session_id=f"frida-live-spawn-{os.getpid()}-{time.time_ns()}",
            target_args=[
                "-u",
                str(_FRIDA_HOOK_TARGET),
                "--quiet",
                "--duration",
                "30",
                "--interval",
                "0.005",
            ],
            kill_spawned=True,
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)
        spawned_pid = result.report_section.get("session", {}).get("pid")

        try:
            self.assertEqual(result.report_section["target_identity"]["path"], executable)
            self._assert_live_result(
                provider,
                plan,
                validation,
                result,
                mode="spawn",
            )
            self.assertTrue(result.report_section["session"]["spawned"])
            self.assertTrue(result.report_section["session"]["resumed"])
            self.assertTrue(
                result.after_snapshot["cleanup"]["detach_result"][
                    "spawned_process_killed"
                ]
            )

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                probe = backend.probe_target(
                    TargetIdentity(kind="process", pid=spawned_pid), {}
                )
                if probe.get("accessible") is False:
                    break
                time.sleep(0.05)
            self.assertFalse(probe.get("accessible"), probe)
        finally:
            if isinstance(spawned_pid, int) and spawned_pid > 0:
                try:
                    backend._frida.get_local_device().kill(spawned_pid)
                except Exception:
                    pass

    def test_mock_provider_is_retained(self) -> None:
        provider = HookRuntimeMockProvider()
        request = self._request("trace", {"address": "0x401000"})

        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertEqual(provider.provider_name, "mock")
        self.assertTrue(validation.ok)
        self.assertEqual(result.status, "mocked")


if __name__ == "__main__":
    unittest.main()
