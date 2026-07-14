from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import (
    CapabilityRequest,
    TargetIdentity,
)
from reverse_analyzer.providers import graphics_runtime as graphics
from reverse_analyzer.providers.graphics_runtime import (
    GraphicsRuntimeProvider,
    PresentMonCaptureResult,
    PresentMonEventParser,
    PresentMonParseError,
    PresentMonRunner,
    PresentMonRunnerError,
    correlate_present_events,
    inspect_live_system_present_exports,
    inspect_pe_exports,
    parse_presentmon_csv,
    parse_presentmon_events,
    parse_presentmon_json,
)
from tests._graphics_acceptance import (
    acceptance_context,
    assert_non_synthetic,
    json_bytes,
    manifest_entry,
    required_pid,
    target_identity as acceptance_target_identity,
    write_bundle,
)


CSV_CAPTURE = """\
ProcessID,Application,PresentRuntime,SwapChainAddress,CPUStartTime,FrameTime,Dropped,Event
4321,game.exe,DXGI,0xABC,1.000,16.0,0,SwapChainCreated
4321,game.exe,DXGI,0xABC,1.016,17.0,1,Present
4321,game.exe,DXGI,0xABC,1.033,18.0,0,SwapChainRecreated
4321,game.exe,DXGI,0xABC,1.051,19.0,0,SwapChainDestroyed
9999,other.exe,Vulkan,opaque-vk,2.000,20.0,0,Present
"""


def _gdi32_path() -> Path | None:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return None
    path = Path(system_root) / "System32" / "gdi32.dll"
    return path if path.is_file() else None


def _vulkan_loader_path() -> Path | None:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        return None
    path = Path(system_root) / "System32" / "vulkan-1.dll"
    return path if path.is_file() else None


class PresentMonParserTests(unittest.TestCase):
    def test_csv_parser_correlates_pid_api_swap_chain_and_lifecycle(self) -> None:
        events = parse_presentmon_csv(CSV_CAPTURE)

        self.assertEqual(len(events), 5)
        self.assertEqual(events[0]["swap_chain_id"], "0xabc")
        self.assertEqual(events[0]["lifecycle"], "created")
        self.assertEqual(events[2]["lifecycle"], "resized")
        self.assertEqual(events[3]["lifecycle"], "destroyed")
        self.assertEqual(events[0]["source"]["format"], "csv")

        correlated = correlate_present_events(
            events,
            expected_pid=4321,
            api_filter=["dxgi"],
        )
        self.assertEqual(correlated["event_count"], 4)
        self.assertEqual(correlated["excluded_event_count"], 1)
        self.assertEqual(correlated["apis"], ["DXGI"])
        self.assertEqual(correlated["swap_chain_count"], 1)
        self.assertEqual(correlated["frames"]["dropped_count"], 1)
        self.assertEqual(correlated["frames"]["average_ms"], 17.5)
        stream = correlated["streams"][0]
        self.assertEqual(
            stream["observed_states"],
            ["created", "present", "resized", "destroyed"],
        )
        self.assertTrue(stream["explicit_lifecycle_observed"])
        self.assertTrue(stream["lifecycle_complete"])
        self.assertEqual(
            stream["lifecycle_claim"], "explicit_create_destroy_observed"
        )

    def test_json_array_object_and_json_lines_are_normalized(self) -> None:
        raw_events = [
            {
                "ProcessID": 77,
                "Application": "json.exe",
                "Runtime": "OpenGL",
                "SwapChain": 4660,
                "CPUStartTime": 3.5,
                "FrameTime": 8.25,
            },
            {
                "ProcessID": 78,
                "Runtime": "Vulkan",
                "SwapChain": "queue-1",
                "FrameTime": 9.5,
            },
        ]
        array_events = parse_presentmon_json(json.dumps(raw_events))
        object_events = parse_presentmon_json(json.dumps({"events": raw_events}))
        json_lines = "\n".join(json.dumps(item) for item in raw_events)
        line_events = parse_presentmon_events(json_lines)

        self.assertEqual(array_events, object_events)
        self.assertEqual(line_events, array_events)
        self.assertEqual(array_events[0]["swap_chain_id"], "0x1234")
        self.assertEqual(array_events[0]["api"], "OpenGL")
        self.assertEqual(array_events[1]["api"], "Vulkan")
        self.assertEqual(
            parse_presentmon_json(json.dumps(raw_events), expected_pid=77),
            [array_events[0]],
        )

        parser = PresentMonEventParser(max_events=1)
        with self.assertRaisesRegex(PresentMonParseError, "max_events"):
            parser.parse(json_lines)

    def test_malformed_csv_is_rejected_strictly(self) -> None:
        malformed = {
            "duplicate header": (
                "ProcessID,process_id,Runtime,CPUStartTime\n1,1,DXGI,1.0\n"
            ),
            "missing pid": "Runtime,CPUStartTime\nDXGI,1.0\n",
            "missing api": "ProcessID,CPUStartTime\n1,1.0\n",
            "missing timing": "ProcessID,Runtime\n1,DXGI\n",
            "field count": (
                "ProcessID,Runtime,CPUStartTime\n1,DXGI,1.0,unexpected\n"
            ),
            "non-finite": "ProcessID,Runtime,FrameTime\n1,DXGI,NaN\n",
            "nul": "ProcessID,Runtime,FrameTime\n1,DXGI,1.0\x00\n",
            "oversized row field": (
                "ProcessID,Application,Runtime,FrameTime\n"
                f"1,{'x' * 5000},DXGI,1.0\n"
            ),
            "oversized header field": (
                f"ProcessID,Runtime,{'x' * 5000}\n1,DXGI,1.0\n"
            ),
            "malformed quoting": (
                'ProcessID,Runtime,CPUStartTime\n1,DXGI,"1.0\n'
            ),
        }
        for name, payload in malformed.items():
            with self.subTest(name=name):
                with self.assertRaises(PresentMonParseError):
                    parse_presentmon_csv(payload)

    def test_malformed_json_is_rejected_strictly(self) -> None:
        malformed = {
            "boolean pid": (
                '[{"ProcessID":true,"Runtime":"DXGI","FrameTime":1.0}]'
            ),
            "non-finite": (
                '[{"ProcessID":1,"Runtime":"DXGI","FrameTime":NaN}]'
            ),
            "duplicate key": (
                '[{"ProcessID":1,"ProcessID":2,"Runtime":"DXGI",'
                '"FrameTime":1.0}]'
            ),
            "normalized duplicate key": (
                '[{"ProcessID":1,"process_id":2,"Runtime":"DXGI",'
                '"FrameTime":1.0}]'
            ),
            "missing timing": '[{"ProcessID":1,"Runtime":"DXGI"}]',
            "missing api": '[{"ProcessID":1,"FrameTime":1.0}]',
            "not an event object": "[1]",
            "malformed jsonl": (
                '{"ProcessID":1,"Runtime":"DXGI","FrameTime":1.0}\n{bad'
            ),
        }
        for name, payload in malformed.items():
            with self.subTest(name=name):
                with self.assertRaises(PresentMonParseError):
                    parse_presentmon_json(payload)

    def test_dxgi_target_is_observed_without_a_fabricated_com_address(self) -> None:
        correlation = correlate_present_events(
            parse_presentmon_csv(CSV_CAPTURE),
            expected_pid=4321,
            api_filter=["DXGI"],
        )
        targets, gaps = graphics._build_present_targets(correlation, [])

        self.assertEqual(gaps, [])
        self.assertEqual(len(targets), 1)
        target = targets[0]
        self.assertEqual(target["kind"], "com_vtable_method")
        self.assertEqual(target["interface"], "IDXGISwapChain")
        self.assertEqual(target["method"], "Present")
        self.assertEqual(target["address_resolution"], "intentionally_not_inferred")
        self.assertIsNone(target["runtime_address"])
        self.assertNotIn("address", target)


class PresentMonRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _runner(self, source: str, *base_args: str) -> PresentMonRunner:
        script = self.root / f"fixture-{len(list(self.root.glob('fixture-*.py')))}.py"
        script.write_text(source, encoding="utf-8")
        return PresentMonRunner(
            sys.executable,
            base_args=(str(script), *base_args),
            max_output_bytes=64 * 1024,
            require_presentmon_identity=False,
        )

    def test_real_local_subprocess_writes_and_parses_csv_capture(self) -> None:
        runner = self._runner(
            """
import pathlib
import sys

args = sys.argv[1:]
pid = args[args.index("--process_id") + 1]
output = pathlib.Path(args[args.index("--output_file") + 1])
output.write_text(
    "ProcessID,Application,PresentRuntime,SwapChainAddress,CPUStartTime,FrameTime\\n"
    + pid + ",fixture.exe,DXGI,0xCAFE,10.0,16.67\\n",
    encoding="utf-8",
)
""".lstrip()
        )

        outcome = runner.capture(
            pid=os.getpid(),
            duration_ms=100,
            timeout_ms=2_000,
            capture_format="csv",
        )

        self.assertEqual(outcome.status, "ok", outcome.error)
        self.assertTrue(outcome.local_subprocess)
        self.assertFalse(outcome.presentmon_identity_verified)
        self.assertTrue(outcome.process_cleanup["process_exited"])
        self.assertTrue(outcome.process_cleanup["launched"])
        self.assertTrue(outcome.process_cleanup["wait_completed"])
        self.assertEqual(outcome.process_cleanup["process_id"], outcome.provenance["process_lifecycle"]["process_id"])
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(outcome.output_format, "csv")
        self.assertEqual(
            outcome.output_sha256,
            hashlib.sha256(outcome.output.encode("utf-8")).hexdigest(),
        )
        self.assertEqual(outcome.provenance["transport"], "local_subprocess")
        self.assertFalse(outcome.provenance["shell"])
        events = parse_presentmon_events(
            outcome.output,
            format_hint=outcome.output_format,
            expected_pid=os.getpid(),
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["swap_chain_id"], "0xcafe")

    def test_real_timeout_child_is_terminated_and_reaped(self) -> None:
        marker = self.root / "child-pid.txt"
        runner = self._runner(
            """
import os
import pathlib
import sys
import time

pathlib.Path(sys.argv[1]).write_text(str(os.getpid()), encoding="ascii")
time.sleep(30)
""".lstrip(),
            str(marker),
        )

        outcome = runner.capture(
            pid=os.getpid(),
            duration_ms=100,
            timeout_ms=750,
            capture_format="csv",
        )

        self.assertTrue(marker.is_file())
        self.assertEqual(outcome.status, "timeout")
        self.assertTrue(outcome.timed_out)
        self.assertTrue(outcome.local_subprocess)
        self.assertTrue(outcome.process_cleanup["attempted"])
        self.assertTrue(outcome.process_cleanup["process_exited"])
        self.assertIsNotNone(outcome.returncode)
        self.assertLess(outcome.elapsed_ms, 5_000)

    def test_runner_rejects_invalid_capture_bounds_before_launch(self) -> None:
        runner = self._runner("raise SystemExit(99)\n")
        with self.assertRaisesRegex(PresentMonRunnerError, "exceed"):
            runner.capture(
                pid=os.getpid(),
                duration_ms=500,
                timeout_ms=500,
                capture_format="csv",
            )
        with self.assertRaisesRegex(PresentMonRunnerError, "capture_format"):
            runner.capture(
                pid=os.getpid(),
                duration_ms=100,
                timeout_ms=500,
                capture_format="xml",
            )


class PeExportEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "requires real Win32 loader evidence")
    def test_live_gdi_swapbuffers_has_current_process_address_proof(self) -> None:
        evidence = inspect_live_system_present_exports(("gdi_swap_buffers",))

        self.assertEqual(evidence["status"], "ok", evidence)
        self.assertEqual(evidence["observed_pid"], os.getpid())
        self.assertEqual(evidence["address_scope"], "analyzer_current_process_only")
        self.assertFalse(evidence["target_pid_address_claim"])
        target = evidence["targets"][0]
        self.assertEqual(target["status"], "ok", target)
        self.assertTrue(target["production_ready"])
        self.assertGreater(target["address"], 0)
        self.assertTrue(target["executable_range"]["executable"])
        self.assertEqual(target["source"]["loader_resolution"]["api"], "GetProcAddress")
        self.assertEqual(len(target["source"]["sha256"]), 64)

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows PE module")
    def test_real_gdi32_swapbuffers_export_has_rva_only(self) -> None:
        path = _gdi32_path()
        if path is None:
            self.skipTest("gdi32.dll is unavailable")
        if importlib.util.find_spec("pefile") is None:
            self.skipTest("optional dependency pefile is unavailable")

        inspection = inspect_pe_exports(
            path,
            any_of_exports=["SwapBuffers", "wglSwapBuffers"],
        )

        self.assertEqual(inspection["status"], "ok", inspection.get("error"))
        self.assertTrue(inspection["read_only"])
        self.assertFalse(inspection["loaded"])
        self.assertTrue(inspection["requirements_met"])
        self.assertEqual(inspection["address_semantics"], "relative_virtual_address_only")
        self.assertIn("runtime_address", inspection)
        self.assertIsNone(inspection["runtime_address"])
        self.assertEqual(len(inspection["identity"]["sha256"]), 64)
        selected = inspection["selected_exports"]
        self.assertTrue(selected)
        self.assertIn(selected[0]["name"], {"SwapBuffers", "wglSwapBuffers"})
        self.assertIsInstance(selected[0]["rva"], int)
        self.assertEqual(selected[0]["address_kind"], "pe_export_rva")
        self.assertIn("runtime_address", selected[0])
        self.assertIsNone(selected[0]["runtime_address"])

        event = parse_presentmon_csv(
            "ProcessID,Runtime,FrameTime\n4321,OpenGL,16.0\n"
        )
        correlation = correlate_present_events(event, expected_pid=4321)
        module = dict(inspection)
        module["api"] = "OpenGL"
        targets, gaps = graphics._build_present_targets(correlation, [module])
        self.assertEqual(gaps, [])
        self.assertEqual(targets[0]["verification"], "pe_export_rva_verified")
        self.assertEqual(targets[0]["symbol"], selected[0]["name"])
        self.assertIsNone(targets[0]["runtime_address"])

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows PE module")
    def test_real_vulkan_loader_queue_present_export_has_rva_only(self) -> None:
        path = _vulkan_loader_path()
        if path is None:
            self.skipTest("vulkan-1.dll is unavailable")
        if importlib.util.find_spec("pefile") is None:
            self.skipTest("optional dependency pefile is unavailable")

        inspection = inspect_pe_exports(path, ["vkQueuePresentKHR"])

        self.assertEqual(inspection["status"], "ok", inspection.get("error"))
        self.assertEqual(
            inspection["matched_required_exports"], ["vkQueuePresentKHR"]
        )
        selected = inspection["selected_exports"]
        self.assertEqual(selected[0]["name"], "vkQueuePresentKHR")
        self.assertIsInstance(selected[0]["rva"], int)
        self.assertIsNone(selected[0]["runtime_address"])

        events = parse_presentmon_csv(
            "ProcessID,Runtime,FrameTime\n4321,Vulkan,16.0\n"
        )
        correlation = correlate_present_events(events, expected_pid=4321)
        module = dict(inspection)
        module["api"] = "Vulkan"
        targets, gaps = graphics._build_present_targets(correlation, [module])
        self.assertEqual(gaps, [])
        self.assertEqual(targets[0]["symbol"], "vkQueuePresentKHR")
        self.assertEqual(targets[0]["verification"], "pe_export_rva_verified")
        self.assertIsNone(targets[0]["runtime_address"])

    @unittest.skipUnless(sys.platform == "win32", "requires a real Windows PE module")
    def test_missing_pefile_is_reported_as_unavailable(self) -> None:
        path = _gdi32_path()
        if path is None:
            self.skipTest("gdi32.dll is unavailable")

        with mock.patch.dict(sys.modules, {"pefile": None}):
            inspection = inspect_pe_exports(path, any_of_exports=["SwapBuffers"])

        self.assertEqual(inspection["status"], "unavailable")
        self.assertEqual(inspection["dependency"], "pefile")
        self.assertTrue(inspection["read_only"])
        self.assertFalse(inspection["loaded"])
        self.assertIsNone(inspection["runtime_address"])

    def test_malformed_pe_is_failed_without_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "malformed.dll"
            path.write_bytes(b"MZ" + b"not-a-valid-pe" * 8)
            inspection = inspect_pe_exports(path, ["SwapBuffers"])

        if inspection["status"] == "unavailable":
            self.skipTest("optional dependency pefile is unavailable")
        self.assertEqual(inspection["status"], "failed")
        self.assertTrue(inspection["read_only"])
        self.assertFalse(inspection["loaded"])
        self.assertIsNone(inspection["runtime_address"])
        self.assertIn("unable to parse PE exports", inspection["error"])


class RaisingBoundaryRunner:
    """Test-only runner for failure boundaries; never production evidence."""

    name = "raising_boundary_runner"
    test_double = True
    available = True
    unavailable_reason = None

    def __init__(self) -> None:
        self.capture_calls = 0

    def probe(self) -> Mapping[str, Any]:
        return {"status": "ok", "available": True, "name": self.name}

    def capture(self, **_: Any) -> PresentMonCaptureResult:
        self.capture_calls += 1
        raise RuntimeError("boundary failure")


class SuccessfulBoundaryRunner(RaisingBoundaryRunner):
    """Produces valid-looking bytes that must still be dependency-gated."""

    name = "successful_boundary_runner"

    def capture(self, **kwargs: Any) -> PresentMonCaptureResult:
        self.capture_calls += 1
        pid = int(kwargs["pid"])
        output = (
            "ProcessID,Runtime,FrameTime\n"
            f"{pid},DXGI,16.0\n"
        )
        return PresentMonCaptureResult(
            status="ok",
            output=output,
            output_format="csv",
            process_cleanup={"process_exited": True},
            local_subprocess=True,
            presentmon_identity_verified=True,
        )


class UnmarkedBoundaryRunner(RaisingBoundaryRunner):
    test_double = False


class SpoofedPresentMonSubclass(PresentMonRunner):
    name = PresentMonRunner.name
    test_double = True

    def __init__(self) -> None:
        self.available = True
        self.unavailable_reason = None
        self.capture_calls = 0

    def probe(self) -> Mapping[str, Any]:
        return {"status": "ok", "available": True, "name": self.name}

    def capture(self, **kwargs: Any) -> PresentMonCaptureResult:
        self.capture_calls += 1
        return SuccessfulBoundaryRunner().capture(**kwargs)


class GraphicsBridgeBackendMappingTests(unittest.TestCase):
    def test_empty_filter_requests_every_supported_native_backend(self) -> None:
        self.assertEqual(
            graphics._requested_graphics_backends([]),
            ["d3d11", "d3d12", "opengl", "vulkan"],
        )

    def test_dxgi_expands_and_deduplicates_in_stable_order(self) -> None:
        self.assertEqual(
            graphics._requested_graphics_backends(
                ["DXGI", "OpenGL", "D3D11", "Vulkan", "DXGI"]
            ),
            ["d3d11", "d3d12", "opengl", "vulkan"],
        )

    def test_unsupported_direct3d_generations_remain_explicit(self) -> None:
        self.assertEqual(
            graphics._requested_graphics_backends(["D3D9", "D3D10"]),
            ["d3d9", "d3d10"],
        )


class GraphicsNativeBridgeSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _request(
        self,
        *,
        params: dict[str, Any] | None = None,
    ) -> CapabilityRequest:
        values: dict[str, Any] = {
            "duration_ms": 100,
            "timeout_ms": 1_000,
            "max_events": 100,
            "capture_format": "json",
            "api_filter": ["D3D11"],
        }
        values.update(params or {})
        return CapabilityRequest(
            capability="graphics_present_runtime",
            action="capture",
            target=TargetIdentity(
                kind="process",
                pid=os.getpid(),
                display_name="test-runner.exe",
            ),
            params=values,
            session_id="graphics/native-bridge-safety",
            provenance={"source": "test_graphics_runtime_provider"},
        )

    def _bridge_call(
        self,
        operation: str,
        *,
        status: str,
        result: Mapping[str, Any],
    ) -> graphics.NativeBridgeCallResult:
        return graphics.NativeBridgeCallResult(
            status=status,
            operation=operation,
            request={"operation": operation},
            response={"status": status, "result": dict(result)},
            command=(str(Path(sys.executable).resolve()),),
            returncode=0,
            process_cleanup={"process_exited": True, "returncode": 0},
        )

    def test_plan_args_and_timeout_are_part_of_bridge_reuse_identity(self) -> None:
        executable = str(Path(sys.executable).resolve())
        provider = GraphicsRuntimeProvider(
            bridge_executable=executable,
            bridge_args=("--provider-default",),
            bridge_timeout_ms=5_000,
            platform_name="win32",
        )
        plan = provider.plan(
            self._request(
                params={
                    "bridge_executable": executable,
                    "bridge_args": ["--planned-command"],
                    "bridge_timeout_ms": 1_500,
                }
            )
        )

        selected = provider._select_bridge(plan, None)

        self.assertIsNot(selected, provider.bridge)
        self.assertEqual(selected.args, ("--planned-command",))
        self.assertEqual(selected.timeout_ms, 1_500)

    def test_changed_bridge_hash_blocks_probe_in_validate_and_execute(self) -> None:
        executable = self.root / "graphics-bridge.exe"
        executable.write_bytes(b"planned-bridge-image")
        executable.chmod(executable.stat().st_mode | 0o111)
        provider = GraphicsRuntimeProvider(
            bridge_executable=executable,
            platform_name="win32",
        )
        plan = provider.plan(self._request())
        executable.write_bytes(b"changed-bridge-image")

        with mock.patch.object(
            graphics.LocalJsonBridgeAdapter,
            "probe",
            autospec=True,
            side_effect=AssertionError("probe ran before static identity validation"),
        ) as probe:
            validation = provider.validate(plan)
            result = provider.execute(plan)

        probe.assert_not_called()
        checks = {item["name"]: item for item in validation.checks}
        self.assertFalse(validation.ok)
        self.assertEqual(checks["native_bridge_identity"]["status"], "failed")
        self.assertEqual(result.status, "failed")

    def test_rollback_stops_and_records_active_native_bridge_session(self) -> None:
        provider = GraphicsRuntimeProvider(
            bridge_executable=Path(sys.executable).resolve(),
            platform_name="win32",
        )
        plan = provider.plan(self._request())
        operations: list[tuple[str, dict[str, Any]]] = []

        def invoke(
            operation: str,
            payload: Mapping[str, Any],
            *,
            session_id: str,
            timeout_ms: int | None = None,
        ) -> graphics.NativeBridgeCallResult:
            del session_id, timeout_ms
            operations.append((operation, dict(payload)))
            if operation == "observe_present":
                return self._bridge_call(
                    operation,
                    status="ok",
                    result={
                        "events": [
                            {
                                "ProcessID": os.getpid(),
                                "Runtime": "D3D11",
                                "FrameTime": 16.0,
                            }
                        ],
                        "session_active": True,
                        "stop_required": True,
                        "stop_token": "stop-token-123",
                    },
                )
            return self._bridge_call(
                operation,
                status="stopped",
                result={
                    "session_active": False,
                    "stop_required": False,
                    "stopped": True,
                },
            )

        probe_call = self._bridge_call(
            "probe",
            status="ok",
            result={"operations": ["observe_present", "stop"]},
        )
        with (
            mock.patch.object(provider.bridge, "probe", return_value=probe_call),
            mock.patch.object(provider.bridge, "invoke", side_effect=invoke),
        ):
            result = provider.execute(plan)
            rollback = provider.rollback(result)

        self.assertTrue(result.rollback_plan["completed"])
        self.assertFalse(result.rollback_plan["stop_required"])
        self.assertEqual([item[0] for item in operations], ["observe_present", "stop"])
        self.assertEqual(operations[1][1]["stop_token"], "stop-token-123")
        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(rollback.details["stop_verified"])
        self.assertEqual(
            rollback.details["native_bridge_stop"]["status"],
            "stopped",
        )
        self.assertFalse(result.after_snapshot["bridge_session"]["active"])
        self.assertEqual(
            result.report_section["rollback"]["native_bridge_stop"]["operation"],
            "stop",
        )

    def test_rollback_rejects_unverified_stop_after_invalid_bridge_events(self) -> None:
        provider = GraphicsRuntimeProvider(
            bridge_executable=Path(sys.executable).resolve(),
            platform_name="win32",
        )
        plan = provider.plan(self._request())

        def invoke(
            operation: str,
            payload: Mapping[str, Any],
            *,
            session_id: str,
            timeout_ms: int | None = None,
        ) -> graphics.NativeBridgeCallResult:
            del payload, session_id, timeout_ms
            if operation == "observe_present":
                return self._bridge_call(
                    operation,
                    status="ok",
                    result={
                        "events": "invalid-event-payload",
                        "session_active": True,
                        "stop_token": "unverified-stop-token",
                    },
                )
            return self._bridge_call(
                operation,
                status="ok",
                result={"accepted": True},
            )

        probe_call = self._bridge_call(
            "probe",
            status="ok",
            result={"operations": ["observe_present", "stop"]},
        )
        with (
            mock.patch.object(provider.bridge, "probe", return_value=probe_call),
            mock.patch.object(provider.bridge, "invoke", side_effect=invoke),
        ):
            result = provider.execute(plan)
            rollback = provider.rollback(result)

        self.assertFalse(rollback.ok)
        self.assertFalse(rollback.details["stop_verified"])
        self.assertEqual(
            rollback.details["native_bridge_stop"]["status"],
            "ok",
        )
        self.assertFalse(result.rollback_plan["completed"])
        self.assertTrue(result.after_snapshot["bridge_session"]["active"])


@unittest.skipUnless(sys.platform == "win32", "provider production path is Windows-only")
class GraphicsRuntimeProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _request(
        self,
        *,
        params: dict[str, Any] | None = None,
        action: str = "capture",
        session_id: str = "graphics/test-session",
    ) -> CapabilityRequest:
        values: dict[str, Any] = {
            "duration_ms": 100,
            "timeout_ms": 1_000,
            "max_events": 100,
            "capture_format": "csv",
        }
        values.update(params or {})
        return CapabilityRequest(
            capability="graphics_present_runtime",
            action=action,
            target=TargetIdentity(
                kind="process",
                pid=os.getpid(),
                display_name="test-runner.exe",
            ),
            params=values,
            session_id=session_id,
            provenance={"source": "test_graphics_runtime_provider"},
        )

    def test_missing_presentmon_is_dependency_gated_unavailable(self) -> None:
        missing = self.root / "missing" / "PresentMon.exe"
        provider = GraphicsRuntimeProvider(
            presentmon_path=missing,
            platform_name="win32",
        )
        request = self._request(params={"presentmon_path": str(missing)})
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        checks = {item["name"]: item for item in validation.checks}
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(checks["presentmon_dependency"]["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.report_section["capture"]["status"], "unavailable")
        self.assertFalse(result.report_section["passive_policy"]["target_process_mutation"])
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(result.dashboard_trace[0]["production_evidence"], False)

        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_passive_input_validation_blocks_runner_execution(self) -> None:
        runner = RaisingBoundaryRunner()
        provider = GraphicsRuntimeProvider(runner=runner, platform_name="win32")
        plan = provider.plan(
            self._request(params={"overlay": True, "keyboard_input": "space"})
        )
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(
            plan.parameters["rejected_control_keys"],
            ["keyboard_input", "overlay"],
        )
        self.assertEqual(runner.capture_calls, 0)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["capture"]["status"], "blocked")

    def test_fake_runner_exception_is_captured_as_failed_boundary(self) -> None:
        runner = RaisingBoundaryRunner()
        provider = GraphicsRuntimeProvider(runner=runner, platform_name="win32")
        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(runner.capture_calls, 1)
        self.assertEqual(result.status, "failed")
        self.assertIn("boundary failure", result.report_section["errors"][0])
        self.assertTrue(
            result.report_section["capture"]["process_cleanup"]["not_started"]
        )

    def test_fake_success_cannot_be_counted_as_production_success(self) -> None:
        runner = SuccessfulBoundaryRunner()
        provider = GraphicsRuntimeProvider(runner=runner, platform_name="win32")
        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(runner.capture_calls, 1)
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.report_section["capture"]["production_evidence"])
        self.assertIn("non-production runner", result.report_section["errors"][0])
        self.assertEqual(result.report_section["events"], [])

    def test_runner_boundary_rejects_unmarked_and_presentmon_subclass_spoofs(self) -> None:
        with self.assertRaisesRegex(ValueError, "test_double=True"):
            GraphicsRuntimeProvider(
                runner=UnmarkedBoundaryRunner(),
                platform_name="win32",
            )

        runner = SpoofedPresentMonSubclass()
        provider = GraphicsRuntimeProvider(runner=runner, platform_name="win32")
        result = provider.execute(provider.plan(self._request()))
        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.report_section["capture"]["production_evidence"])
        self.assertIn(
            "exact internal PresentMonRunner type",
            "; ".join(result.report_section["capture"]["production_evidence_failures"]),
        )

    def test_read_only_rollback_and_three_artifacts_are_materialized(self) -> None:
        missing = self.root / "PresentMon.exe"
        provider = GraphicsRuntimeProvider(
            presentmon_path=missing,
            platform_name="win32",
        )
        plan = provider.plan(
            self._request(
                params={"presentmon_path": str(missing)},
                session_id="artifact/session",
            )
        )
        result = provider.execute(plan)
        rollback = provider.rollback(result)

        self.assertTrue(rollback.ok)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "not_required")
        self.assertFalse(result.rollback_plan["supported"])
        self.assertEqual(result.dashboard_trace[-1]["kind"], "graphics_present_rollback")

        collection_root = self.root / "collected"
        bundle = provider.collect_artifacts(result, str(collection_root))
        self.assertEqual(len(bundle.artifacts), 3)
        self.assertEqual(len(bundle.manifest_entries), 3)
        self.assertEqual(
            {item.kind for item in bundle.artifacts},
            {
                "graphics-runtime-audit",
                "graphics-present-events",
                "graphics-runtime-manifest",
            },
        )
        for artifact in bundle.artifacts:
            destination = collection_root / artifact.path
            self.assertTrue(destination.is_file())
            self.assertEqual(
                artifact.metadata["sha256"],
                hashlib.sha256(destination.read_bytes()).hexdigest(),
            )
            self.assertTrue(artifact.metadata["materialized"])

        manifest_artifact = next(
            item
            for item in bundle.artifacts
            if item.kind == "graphics-runtime-manifest"
        )
        manifest = json.loads(
            (collection_root / manifest_artifact.path).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "unavailable")
        self.assertEqual(len(manifest["artifacts"]), 3)
        self.assertTrue(all(item["materialized"] for item in manifest["artifacts"]))
        self.assertTrue(
            all(item["path"].startswith("graphics-runtime/artifact-session/")
                for item in manifest["artifacts"])
        )

    def test_artifact_collection_rejects_path_escape(self) -> None:
        missing = self.root / "PresentMon.exe"
        provider = GraphicsRuntimeProvider(
            presentmon_path=missing,
            platform_name="win32",
        )
        plan = provider.plan(
            self._request(params={"presentmon_path": str(missing)})
        )
        result = provider.execute(plan)
        result.artifacts[0].path = "../outside.json"

        with self.assertRaisesRegex(ValueError, "escapes"):
            provider.collect_artifacts(result, str(self.root / "escape-root"))

    def test_supports_only_the_graphics_present_capability_and_aliases(self) -> None:
        provider = GraphicsRuntimeProvider(
            presentmon_path=self.root / "PresentMon.exe",
            platform_name="win32",
        )
        self.assertTrue(provider.supports(self._request(action="present")))
        self.assertTrue(provider.supports(self._request(action="capture_present")))
        request = self._request()
        request.capability = "render_overlay"
        self.assertFalse(provider.supports(request))

    def test_request_bridge_configuration_is_hash_bound_into_plan(self) -> None:
        provider = GraphicsRuntimeProvider(platform_name="win32")
        executable = str(Path(sys.executable).resolve())
        plan = provider.plan(
            self._request(
                params={
                    "bridge_executable": executable,
                    "bridge_path": executable,
                    "bridge_args": ["-B", "bridge-fixture.py"],
                    "bridge_timeout_ms": 1_500,
                }
            )
        )

        self.assertEqual(plan.parameters["execution_adapter"], "native_bridge")
        self.assertEqual(plan.parameters["parameter_errors"], [])
        bridge = plan.parameters["native_bridge"]
        self.assertEqual(bridge["executable"], executable)
        self.assertEqual(bridge["args"], ["-B", "bridge-fixture.py"])
        self.assertEqual(bridge["timeout_ms"], 1_500)
        self.assertEqual(
            bridge["executable_identity"]["sha256"],
            hashlib.sha256(Path(executable).read_bytes()).hexdigest(),
        )

    def test_invalid_bridge_args_and_context_fail_closed(self) -> None:
        provider = GraphicsRuntimeProvider(platform_name="win32")
        plan = provider.plan(
            self._request(
                params={
                    "bridge_executable": sys.executable,
                    "bridge_args": "--not-a-sequence",
                }
            )
        )
        self.assertIn(
            "bridge_args must be a sequence of argument strings",
            plan.parameters["parameter_errors"],
        )
        self.assertFalse(provider.validate(plan).ok)

        ordinary_plan = provider.plan(self._request())
        validation = provider.validate(
            ordinary_plan,
            context={"graphics_runtime_bridge": object()},
        )
        checks = {item["name"]: item for item in validation.checks}
        self.assertFalse(validation.ok)
        self.assertEqual(checks["native_bridge_context"]["status"], "failed")
        self.assertIn("exact LocalJsonBridgeAdapter", validation.errors[0])


@unittest.skipUnless(sys.platform == "win32", "live graphics acceptance requires Windows")
class GraphicsRuntimeAcceptanceTests(unittest.TestCase):
    def _target(self, pid: int) -> TargetIdentity:
        identity = acceptance_target_identity(pid)
        return TargetIdentity(
            kind=str(identity["kind"]),
            pid=int(identity["pid"]),
            display_name=str(identity["display_name"]),
        )

    def _request(
        self,
        *,
        pid: int,
        session_id: str,
        capture_format: str,
        api_filter: list[str],
    ) -> CapabilityRequest:
        return CapabilityRequest(
            capability="graphics_present_runtime",
            action="capture",
            target=self._target(pid),
            params={
                "duration_ms": 2_000,
                "timeout_ms": 15_000,
                "max_events": 20_000,
                "capture_format": capture_format,
                "api_filter": api_filter,
            },
            session_id=session_id,
            provenance={
                "source": "p4-graphics-acceptance",
                "evidence_class": "live_host_proof",
            },
        )

    @staticmethod
    def _collected_json(root: Path, bundle: Any, kind: str) -> dict[str, Any]:
        artifact = next(item for item in bundle.artifacts if item.kind == kind)
        payload = json.loads((root / artifact.path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise AssertionError(f"collected {kind} artifact is not an object")
        assert_non_synthetic(payload)
        return payload

    def test_presentmon_live_acceptance_artifacts(self) -> None:
        context = acceptance_context("p4-presentmon-live")
        if context is None:
            self.skipTest("p4-presentmon-live acceptance context is not active")
        pid = required_pid()

        # The PresentMon fixture must not silently select a configured bridge.
        with mock.patch.dict(
            os.environ,
            {
                "REVERSE_ANALYZER_GRAPHICS_BRIDGE": "",
                "RA_GRAPHICS_BRIDGE": "",
            },
        ):
            provider = GraphicsRuntimeProvider(platform_name="win32")
            self.assertIs(type(provider.runner), PresentMonRunner)
            self.assertIs(provider.runner.test_double, False)
            request = self._request(
                pid=pid,
                session_id=context.session_id,
                capture_format="csv",
                api_filter=[],
            )
            plan = provider.plan(request)
            self.assertEqual(plan.parameters["execution_adapter"], "presentmon")
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.to_dict())
            result = provider.execute(plan)
            self.assertIn(result.status, {"ok", "partial"}, result.report_section)

            capture = dict(result.report_section.get("capture") or {})
            self.assertIs(capture.get("production_evidence"), True, capture)
            self.assertIs(capture.get("presentmon_identity_verified"), True, capture)
            self.assertIs(capture.get("local_subprocess"), True, capture)
            cleanup = dict(capture.get("process_cleanup") or {})
            self.assertIs(cleanup.get("process_exited"), True, cleanup)
            events = list(result.report_section.get("events") or [])
            self.assertGreater(len(events), 0)
            self.assertTrue(all(int(item.get("pid") or 0) == pid for item in events))

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok, rollback.details)
            self.assertTrue(rollback.details["process_cleanup_confirmed"])
            with tempfile.TemporaryDirectory() as temporary:
                collected_root = Path(temporary).resolve()
                bundle = provider.collect_artifacts(result, str(collected_root))
                audit = self._collected_json(
                    collected_root, bundle, "graphics-runtime-audit"
                )

        target_payload = request.target.to_dict()
        event_text = "".join(
            json.dumps(item, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
            for item in events
        )
        target_encoded = json_bytes(target_payload)
        audit_encoded = json_bytes(audit)
        event_encoded = event_text.encode("utf-8")
        manifest = {
            "schema_version": 1,
            "status": "ok",
            "fixture_id": context.fixture_id,
            "session_id": context.session_id,
            "artifacts": [
                manifest_entry("graphics/target-identity.json", target_encoded, "target-identity"),
                manifest_entry("graphics/present-events.jsonl", event_encoded, "present-events"),
                manifest_entry("graphics/audit.json", audit_encoded, "graphics-runtime-audit"),
            ],
        }
        execution_proof = {
            "status": "ok",
            "provider": result.provider,
            "evidence_class": "live_host_proof",
            "executed_tests": 1,
            "skipped_tests": 0,
            "live_operations": 1,
            "actions": ["presentmon_capture"],
            "event_count": len(events),
        }
        write_bundle(
            context,
            {
                "graphics/target-identity.json": target_payload,
                "graphics/present-events.jsonl": event_text,
                "graphics/audit.json": audit,
                "graphics/evidence-manifest.json": manifest,
                "graphics/execution-proof.json": execution_proof,
            },
        )

    def test_native_bridge_live_acceptance_artifacts(self) -> None:
        context = acceptance_context("p4-native-graphics-bridge")
        if context is None:
            self.skipTest("p4-native-graphics-bridge acceptance context is not active")
        pid = required_pid()
        bridge_path = str(
            os.environ.get("REVERSE_ANALYZER_GRAPHICS_BRIDGE") or ""
        ).strip()
        if not bridge_path:
            self.skipTest("REVERSE_ANALYZER_GRAPHICS_BRIDGE is not configured")

        provider = GraphicsRuntimeProvider(
            bridge_executable=bridge_path,
            platform_name="win32",
        )
        request = self._request(
            pid=pid,
            session_id=context.session_id,
            capture_format="json",
            api_filter=["D3D11"],
        )
        plan = provider.plan(request)
        self.assertEqual(plan.parameters["execution_adapter"], "native_bridge")
        validation = provider.validate(plan)
        self.assertTrue(validation.ok, validation.to_dict())
        result = provider.execute(plan)
        self.assertIn(result.status, {"ok", "partial"}, result.report_section)

        capture = dict(result.report_section.get("capture") or {})
        self.assertIs(capture.get("native_bridge_verified"), True, capture)
        self.assertIs(capture.get("production_evidence"), True, capture)
        events = list(result.report_section.get("events") or [])
        self.assertGreater(len(events), 0)
        self.assertTrue(all(int(item.get("pid") or 0) == pid for item in events))
        bridge_call = dict(capture.get("bridge") or {})
        bridge_request = dict(bridge_call.get("request") or {})
        bridge_response = dict(bridge_call.get("response") or {})
        self.assertTrue(bridge_request)
        self.assertTrue(bridge_response)
        self.assertIs(bridge_response.get("native_bridge"), True)
        self.assertIs(
            dict(bridge_call.get("process_cleanup") or {}).get("process_exited"),
            True,
        )

        active_before = bool(
            dict(result.after_snapshot.get("bridge_session") or {}).get("active")
        )
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        active_after = bool(
            dict(result.after_snapshot.get("bridge_session") or {}).get("active")
        )
        self.assertFalse(active_after)
        if active_before:
            self.assertIs(rollback.details.get("stop_verified"), True, rollback.details)
        else:
            self.assertTrue(
                rollback.details.get("process_cleanup_confirmed"), rollback.details
            )
        with tempfile.TemporaryDirectory() as temporary:
            bundle = provider.collect_artifacts(result, temporary)
            self.assertEqual(len(bundle.artifacts), 3)

        stop_proof = {
            "status": "completed",
            "verified": True,
            "rollback_verified": True,
            "cleanup_verified": True,
            "session_active_before": active_before,
            "session_active_after": active_after,
            "stop_required": active_before,
            "stop_verified": bool(rollback.details.get("stop_verified"))
            if active_before
            else True,
            "details": rollback.details,
        }
        execution_proof = {
            "status": "ok",
            "provider": result.provider,
            "evidence_class": "live_host_proof",
            "executed_tests": 1,
            "skipped_tests": 0,
            "live_operations": 2 if active_before else 1,
            "actions": ["observe_present", *( ["stop"] if active_before else [])],
            "event_count": len(events),
        }
        for payload in (
            bridge_request,
            bridge_response,
            stop_proof,
            execution_proof,
        ):
            assert_non_synthetic(payload)
        write_bundle(
            context,
            {
                "graphics/target-identity.json": request.target.to_dict(),
                "graphics/bridge-request.json": bridge_request,
                "graphics/bridge-response.json": bridge_response,
                "graphics/stop-proof.json": stop_proof,
                "graphics/execution-proof.json": execution_proof,
            },
        )


if __name__ == "__main__":
    unittest.main()
