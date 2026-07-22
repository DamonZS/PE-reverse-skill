import importlib.util
import json
import os
from queue import Empty, Queue
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

from reverse_analyzer.gui.windows_uia import (
    WINDOWS_UIA_BACKEND,
    WindowsUIAAdapter,
    probe_windows_uia,
)
from tests._graphics_acceptance import acceptance_context, write_bundle


LIVE_SMOKE_ENV = "REVERSE_ANALYZER_RUN_WINDOWS_UIA_LIVE"


class FakeRect:
    def __init__(self, left: int, top: int, right: int, bottom: int) -> None:
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class FakeElement:
    def __init__(
        self,
        automation_id: str,
        name: str,
        control_type: int,
        bounds: FakeRect,
        *,
        process_id: int = 321,
        native_window_handle: int = 0,
        enabled: bool = True,
        offscreen: bool = False,
        children: list["FakeElement"] | None = None,
    ) -> None:
        self.CurrentAutomationId = automation_id
        self.CurrentName = name
        self.CurrentControlType = control_type
        self.CurrentBoundingRectangle = bounds
        self.CurrentIsEnabled = enabled
        self.CurrentIsOffscreen = offscreen
        self.CurrentProcessId = process_id
        self.CurrentNativeWindowHandle = native_window_handle
        self.children = list(children or [])
        self.parent: FakeElement | None = None
        for child in self.children:
            child.parent = self


class FakeElementArray:
    def __init__(self, elements: list[FakeElement]) -> None:
        self._elements = elements
        self.Length = len(elements)

    def GetElement(self, index: int) -> FakeElement:
        return self._elements[index]


class FakeDesktopRoot:
    def __init__(self, windows: list[FakeElement]) -> None:
        self.windows = windows
        self.find_all_calls: list[tuple[int, object]] = []

    def FindAll(self, scope: int, condition: object) -> FakeElementArray:
        self.find_all_calls.append((scope, condition))
        return FakeElementArray(self.windows)


class FakeWalker:
    def GetFirstChildElement(self, element: FakeElement) -> FakeElement | None:
        return element.children[0] if element.children else None

    def GetNextSiblingElement(self, element: FakeElement) -> FakeElement | None:
        if element.parent is None:
            return None
        siblings = element.parent.children
        index = siblings.index(element) + 1
        return siblings[index] if index < len(siblings) else None


class FakeAutomation:
    def __init__(self, windows: list[FakeElement]) -> None:
        self.desktop = FakeDesktopRoot(windows)
        self.ControlViewWalker = FakeWalker()
        self.conditions: list[tuple[int, int]] = []
        self.handles = {
            element.CurrentNativeWindowHandle: element
            for element in windows
            if element.CurrentNativeWindowHandle
        }
        self.element_from_handle_calls: list[int] = []

    def GetRootElement(self) -> FakeDesktopRoot:
        return self.desktop

    def CreatePropertyCondition(self, property_id: int, value: int) -> tuple[int, int]:
        condition = (property_id, value)
        self.conditions.append(condition)
        return condition

    def ElementFromHandle(self, handle: int) -> FakeElement | None:
        self.element_from_handle_calls.append(handle)
        return self.handles.get(handle)


class FakeUIAutomationClient:
    TreeScope_Children = 2
    UIA_ProcessIdPropertyId = 30_002
    UIA_ButtonControlTypeId = 50_000
    UIA_EditControlTypeId = 50_004
    UIA_TextControlTypeId = 50_020
    UIA_WindowControlTypeId = 50_032


class FakeBackend:
    def __init__(self, automation: FakeAutomation) -> None:
        self.automation = automation
        self.uia = FakeUIAutomationClient
        self.dependency = {
            "name": "comtypes",
            "required": True,
            "status": "available",
            "version": "fixture",
        }
        self.closed = False

    def close(self) -> None:
        self.closed = True


def fake_tree(*, process_id: int = 321, handle: int = 1001) -> tuple[FakeElement, FakeAutomation]:
    label = FakeElement(
        "statusText",
        "Ready",
        FakeUIAutomationClient.UIA_TextControlTypeId,
        FakeRect(20, 100, 220, 120),
        process_id=process_id,
    )
    editor = FakeElement(
        "editor",
        "Document",
        FakeUIAutomationClient.UIA_EditControlTypeId,
        FakeRect(20, 70, 620, 430),
        process_id=process_id,
        children=[label],
    )
    save = FakeElement(
        "saveButton",
        "Save",
        FakeUIAutomationClient.UIA_ButtonControlTypeId,
        FakeRect(20, 30, 100, 58),
        process_id=process_id,
    )
    window = FakeElement(
        "mainWindow",
        "Fixture Editor",
        FakeUIAutomationClient.UIA_WindowControlTypeId,
        FakeRect(10, 10, 650, 460),
        process_id=process_id,
        native_window_handle=handle,
        children=[save, editor],
    )
    return window, FakeAutomation([window])


class WindowsUIAAdapterTests(unittest.TestCase):
    def test_missing_comtypes_is_explicitly_unavailable(self) -> None:
        def missing_dependency() -> object:
            raise ModuleNotFoundError("No module named 'comtypes'", name="comtypes")

        result = probe_windows_uia(
            321,
            platform_name="win32",
            backend_loader=missing_dependency,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["backend"], WINDOWS_UIA_BACKEND)
        self.assertEqual(result["dependency"]["name"], "comtypes")
        self.assertEqual(result["dependency"]["status"], "missing")
        self.assertEqual(result["error"]["code"], "dependency_missing")
        self.assertEqual(result["windows"], [])
        self.assertNotEqual(result["status"], "ok")

    def test_non_windows_gate_does_not_attempt_dependency_load(self) -> None:
        called = False

        def should_not_load() -> object:
            nonlocal called
            called = True
            raise AssertionError("dependency loader must not run")

        result = probe_windows_uia(
            321,
            platform_name="linux",
            backend_loader=should_not_load,
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"]["code"], "platform_unavailable")
        self.assertEqual(result["dependency"]["status"], "not_checked")
        self.assertFalse(called)

    def test_fake_com_pid_tree_normalizes_accessibility_properties(self) -> None:
        _window, automation = fake_tree()
        backend = FakeBackend(automation)

        result = probe_windows_uia(
            321,
            platform_name="win32",
            backend_loader=lambda: backend,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["window_count"], 1)
        self.assertEqual(result["node_count"], 4)
        self.assertEqual(result["control_count"], 3)
        self.assertEqual(automation.conditions, [(30_002, 321)])
        self.assertEqual(automation.desktop.find_all_calls[0][0], 2)
        window = result["windows"][0]
        self.assertEqual(window["automation_id"], "mainWindow")
        self.assertEqual(window["control_type"], "Window")
        self.assertEqual(
            window["bounds"],
            {"left": 10, "top": 10, "width": 640, "height": 450},
        )
        save = window["children"][0]
        self.assertEqual(save["name"], "Save")
        self.assertEqual(save["control_type"], "Button")
        self.assertTrue(save["enabled"])
        self.assertFalse(save["offscreen"])
        self.assertEqual(window["children"][1]["children"][0]["name"], "Ready")
        self.assertEqual(result["provider"]["api"], "UIAutomationClient")
        self.assertEqual(result["dependency"]["version"], "fixture")
        self.assertFalse(result["provenance"]["target_executed"])
        self.assertTrue(backend.closed)

    def test_fake_com_window_handle_roots_tree_and_checks_pid(self) -> None:
        _window, automation = fake_tree(process_id=987, handle=4321)
        backend = FakeBackend(automation)

        result = probe_windows_uia(
            window_handle=4321,
            platform_name="nt",
            backend_loader=lambda: backend,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["target"], {"process_id": 987, "window_handle": 4321})
        self.assertEqual(automation.element_from_handle_calls, [4321])

        _other_window, mismatch_automation = fake_tree(process_id=987, handle=4321)
        mismatch = probe_windows_uia(
            321,
            window_handle=4321,
            platform_name="win32",
            backend_loader=lambda: FakeBackend(mismatch_automation),
        )
        self.assertEqual(mismatch["status"], "failed")
        self.assertEqual(mismatch["error"]["code"], "target_mismatch")
        self.assertEqual(mismatch["node_count"], 0)

    def test_depth_and_node_limits_truncate_without_exceeding_bounds(self) -> None:
        _window, depth_automation = fake_tree()
        depth_result = probe_windows_uia(
            321,
            max_depth=1,
            max_nodes=20,
            platform_name="win32",
            backend_loader=lambda: FakeBackend(depth_automation),
        )

        self.assertEqual(depth_result["status"], "ok")
        self.assertEqual(depth_result["node_count"], 3)
        self.assertTrue(depth_result["truncated"])
        self.assertIn("max_depth", depth_result["truncation_reasons"])
        self.assertEqual(depth_result["windows"][0]["children"][1]["children"], [])

        _window, node_automation = fake_tree()
        node_result = probe_windows_uia(
            321,
            max_depth=10,
            max_nodes=2,
            platform_name="win32",
            backend_loader=lambda: FakeBackend(node_automation),
        )

        self.assertEqual(node_result["status"], "ok")
        self.assertEqual(node_result["node_count"], 2)
        self.assertTrue(node_result["truncated"])
        self.assertIn("max_nodes", node_result["truncation_reasons"])

    def test_empty_provider_tree_is_failed_not_ok(self) -> None:
        backend = FakeBackend(FakeAutomation([]))

        result = probe_windows_uia(
            321,
            platform_name="win32",
            backend_loader=lambda: backend,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "empty_tree")
        self.assertEqual(result["window_count"], 0)
        self.assertEqual(result["node_count"], 0)
        self.assertTrue(backend.closed)

    def test_timeout_bounds_caller_wait_and_reports_real_com_limit(self) -> None:
        release = threading.Event()
        _window, automation = fake_tree()

        def blocked_loader() -> FakeBackend:
            release.wait(timeout=0.5)
            return FakeBackend(automation)

        started = time.monotonic()
        result = WindowsUIAAdapter(
            timeout_seconds=0.02,
            backend_loader=blocked_loader,
        ).probe(321, platform_name="win32")
        elapsed = time.monotonic() - started
        release.set()

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "timeout")
        self.assertTrue(result["truncated"])
        self.assertLess(elapsed, 0.2)
        limitations = " ".join(result["coverage"]["limitations"])
        self.assertIn("cannot be forcibly cancelled", limitations)

    def test_invalid_target_and_limits_are_rejected_before_com(self) -> None:
        result = probe_windows_uia(platform_name="win32", backend_loader=lambda: object())
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"]["code"], "target_required")

        with self.assertRaises(ValueError):
            WindowsUIAAdapter(max_depth=65)
        with self.assertRaises(ValueError):
            WindowsUIAAdapter(max_nodes=0)
        with self.assertRaises(ValueError):
            WindowsUIAAdapter(timeout_seconds=61)

    @unittest.skipUnless(
        sys.platform == "win32" and os.environ.get(LIVE_SMOKE_ENV) == "1",
        f"set {LIVE_SMOKE_ENV}=1 on an interactive Windows desktop",
    )
    def test_optional_live_windows_uia_smoke(self) -> None:
        if importlib.util.find_spec("comtypes") is None:
            self.skipTest("comtypes is not installed")
        if importlib.util.find_spec("tkinter") is None:
            self.skipTest("tkinter is not installed")

        fixture_script = """
import json
import os
import tkinter

window = tkinter.Tk()
window.title("Reverse Analyzer UIA Smoke")
tkinter.Button(window, text="Inspect me", name="inspect_button").pack()
window.update_idletasks()
window.after(
    0,
    lambda: print(
        json.dumps({"process_id": os.getpid(), "window_handle": int(window.winfo_id())}),
        flush=True,
    ),
)
window.mainloop()
"""
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        fixture = subprocess.Popen(  # noqa: S603 - fixed interpreter and fixture source.
            [sys.executable, "-u", "-c", fixture_script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creationflags,
        )
        assert fixture.stdout is not None
        startup_lines: Queue[str] = Queue(maxsize=1)
        reader = threading.Thread(
            target=lambda: startup_lines.put(fixture.stdout.readline()),
            daemon=True,
        )
        reader.start()
        target: dict[str, object] = {}
        handle_result: dict[str, object] = {}
        pid_result: dict[str, object] = {}
        cleanup = {"status": "pending", "terminated": False, "exit_code": None}
        try:
            try:
                startup_line = startup_lines.get(timeout=5)
            except Empty as exc:
                raise AssertionError("live UI fixture did not report its target within 5 seconds") from exc
            if not startup_line:
                assert fixture.stderr is not None
                raise AssertionError(f"live UI fixture exited early: {fixture.stderr.read()}")
            target = json.loads(startup_line)
            handle_result = probe_windows_uia(
                int(target["process_id"]),
                window_handle=int(target["window_handle"]),
                timeout_seconds=10,
            )
            pid_result = probe_windows_uia(
                int(target["process_id"]),
                timeout_seconds=10,
            )
        finally:
            fixture.terminate()
            try:
                fixture.wait(timeout=2)
            except subprocess.TimeoutExpired:
                fixture.kill()
                fixture.wait(timeout=2)
            cleanup = {
                "status": "stopped",
                "terminated": fixture.poll() is not None,
                "exit_code": fixture.returncode,
            }
            reader.join(timeout=1)
            fixture.stdout.close()
            assert fixture.stderr is not None
            fixture.stderr.close()

        for result in (handle_result, pid_result):
            self.assertIn(result["status"], {"ok", "partial"}, result)
            self.assertGreaterEqual(result["window_count"], 1)
            self.assertGreater(result["node_count"], 0)
            self.assertEqual(result["provider"]["api"], "UIAutomationClient")

        context = acceptance_context("p7-windows-uia-live")
        if context is not None:
            pid = int(target["process_id"])
            target_identity = {
                "kind": "live-child-process",
                "pid": pid,
                "path": Path(sys.executable).name,
                "display_name": "Reverse Analyzer UIA Smoke",
                "window_handle": int(target["window_handle"]),
            }
            audit = {
                "schema_version": 1,
                "status": "ok",
                "capability": "windows_uia_runtime",
                "session_id": context.session_id,
                "target_identity": target_identity,
                "provider": {
                    "name": WINDOWS_UIA_BACKEND,
                    "api": "UIAutomationClient",
                    "transport": "comtypes",
                },
                "operations": [
                    {"kind": "window_handle_traversal", "result": handle_result},
                    {"kind": "process_id_traversal", "result": pid_result},
                ],
                "cleanup": cleanup,
                "provenance": {
                    "evidence_class": "live_host_proof",
                    "fixture_id": context.fixture_id,
                },
            }
            write_bundle(
                context,
                {
                    "gui-uia/target-identity.json": target_identity,
                    "gui-uia/runtime-tree-audit.json": audit,
                    "gui-uia/fixture-cleanup.json": cleanup,
                    "gui-uia/execution-proof.json": {
                        "schema_version": 1,
                        "status": "ok",
                        "provider": "windows-uia-comtypes",
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 2,
                        "target_pid": pid,
                        "target_hwnd": int(target["window_handle"]),
                        "session_id": context.session_id,
                        "cleanup_verified": cleanup["terminated"],
                    },
                },
            )


if __name__ == "__main__":
    unittest.main()
