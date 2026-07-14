from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.providers.render_overlay import (
    RenderOverlayProvider,
    WindowsGDIOverlayBackend,
)


@dataclass
class _FakeOverlaySession:
    overlay_hwnd: int
    target_window: dict[str, Any]
    closed: bool = False
    created_gdi_objects: int = 0
    deleted_gdi_objects: int = 0


class FakeRenderOverlayBackend:
    name = "fake-windows-gdi"
    available = True
    unavailable_reason = None

    def __init__(
        self,
        *,
        probe: Optional[Mapping[str, Any]] = None,
        destroy_failures: int = 0,
        draw_error: Optional[Exception] = None,
    ) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.destroy_failures = destroy_failures
        self.draw_error = draw_error
        self.frame_index = 0
        self.session: Optional[_FakeOverlaySession] = None
        self._probe = dict(
            probe
            or {
                "status": "ok",
                "interactive_desktop": True,
                "exists": True,
                "visible": True,
                "owner_pid_matches": True,
                "pid": 4242,
                "hwnd": 0x1234,
                "title": "Fixture Window",
                "class_name": "FixtureWindowClass",
                "client_rect": {
                    "left": 0,
                    "top": 0,
                    "right": 800,
                    "bottom": 600,
                    "width": 800,
                    "height": 600,
                    "screen_x": 100,
                    "screen_y": 200,
                },
            }
        )

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls.append(("probe_target", target.pid, dict(options)))
        return dict(self._probe)

    def create_overlay(
        self,
        target_window: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> _FakeOverlaySession:
        self.calls.append(("create_overlay", dict(target_window), dict(options)))
        self.session = _FakeOverlaySession(
            overlay_hwnd=0x9001,
            target_window=dict(target_window),
        )
        return self.session

    def draw_frame(
        self,
        session: _FakeOverlaySession,
        primitives: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        self.calls.append(("draw_frame", session.overlay_hwnd, list(primitives)))
        if self.draw_error is not None:
            raise self.draw_error
        self.frame_index += 1
        session.created_gdi_objects += len(primitives)
        session.deleted_gdi_objects += len(primitives)
        identity = dict(session.target_window)
        identity["client_rect"] = {
            **dict(identity["client_rect"]),
            "screen_x": 100 + self.frame_index,
        }
        return {
            "window_identity": identity,
            "overlay_hwnd": session.overlay_hwnd,
            "primitive_count": len(primitives),
            "resources": {
                "created_gdi_objects": session.created_gdi_objects,
                "deleted_gdi_objects": session.deleted_gdi_objects,
                "live_gdi_objects": 0,
            },
        }

    def wait(self, session: _FakeOverlaySession, duration_ms: int) -> None:
        self.calls.append(("wait", session.overlay_hwnd, duration_ms))

    def destroy_overlay(self, session: _FakeOverlaySession) -> Mapping[str, Any]:
        self.calls.append(("destroy_overlay", session.overlay_hwnd))
        if self.destroy_failures:
            self.destroy_failures -= 1
            return {
                "ok": False,
                "window_destroyed": False,
                "resources_released": False,
                "error": "synthetic cleanup failure",
            }
        already_closed = session.closed
        session.closed = True
        return {
            "ok": True,
            "already_closed": already_closed,
            "window_destroyed": True,
            "resources_released": True,
            "released_memory_dc": True,
            "released_bitmap": True,
            "live_gdi_objects": 0,
        }

    def describe_overlay(self, session: _FakeOverlaySession) -> Mapping[str, Any]:
        return {
            "overlay_hwnd": session.overlay_hwnd,
            "target_hwnd": session.target_window["hwnd"],
            "target_pid": session.target_window["pid"],
            "closed": session.closed,
        }

    def call_names(self) -> list[str]:
        return [str(item[0]) for item in self.calls]


class RenderOverlayProviderTests(unittest.TestCase):
    def _request(
        self,
        *,
        params: Optional[Mapping[str, Any]] = None,
        target: Optional[TargetIdentity] = None,
        action: str = "render",
        session_id: str = "overlay-test",
    ) -> CapabilityRequest:
        values: dict[str, Any] = {
            "hwnd": "0x1234",
            "duration_ms": 25,
            "frame_interval_ms": 16,
            "primitives": [
                {
                    "type": "line",
                    "x1": 10,
                    "y1": 20,
                    "x2": 100,
                    "y2": 120,
                    "color": "#FF0000",
                    "width": 2,
                },
                {
                    "type": "rect",
                    "x": 30,
                    "y": 40,
                    "width": 120,
                    "height": 80,
                    "color": [0, 255, 0],
                    "stroke_width": 3,
                    "filled": False,
                },
                {
                    "type": "circle",
                    "x": 250,
                    "y": 200,
                    "radius": 35,
                    "color": "#0000FF",
                    "stroke_width": 2,
                    "filled": True,
                },
                {
                    "type": "text",
                    "x": 60,
                    "y": 70,
                    "text": "diagnostic",
                    "color": "#FFFFFF",
                    "font_size": 18,
                },
            ],
        }
        values.update(params or {})
        return CapabilityRequest(
            capability="render_overlay_runtime",
            action=action,
            target=target
            or TargetIdentity(
                kind="process",
                pid=4242,
                display_name="fixture.exe",
                metadata={"hwnd": 0x1234},
            ),
            params=values,
            session_id=session_id,
            provenance={"source": "test_render_overlay_provider"},
        )

    @staticmethod
    def _checks(validation: Any) -> dict[str, dict[str, Any]]:
        return {item["name"]: item for item in validation.checks}

    def test_fake_backend_lifecycle_artifact_and_idempotent_rollback(self) -> None:
        backend = FakeRenderOverlayBackend()
        provider = RenderOverlayProvider(backend=backend)
        request = self._request()

        self.assertTrue(provider.supports(request))
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(plan.action, "render")
        self.assertEqual(
            [item["type"] for item in plan.parameters["primitives"]],
            ["line", "rect", "circle", "text"],
        )
        self.assertEqual(plan.parameters["primitives"][1]["color"], "#00FF00")
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.after_snapshot["frame_count"], 2)
        self.assertEqual(len(result.after_snapshot["frames"]), 2)
        self.assertEqual(
            result.after_snapshot["frames"][1]["window_identity"]["client_rect"]["screen_x"],
            102,
        )
        self.assertEqual(result.after_snapshot["timing"]["requested_duration_ms"], 25)
        self.assertTrue(result.after_snapshot["resource_cleanup"]["ok"])
        self.assertEqual(result.after_snapshot["session"]["state"], "closed")
        self.assertTrue(result.rollback_plan["completed"])
        self.assertFalse(result.rollback_plan["active"])
        self.assertEqual(result.report_section["renderer"]["api"], "Win32 GDI")
        self.assertEqual(result.report_section["renderer"]["integration"], "external_layered_window")
        self.assertEqual(result.artifacts[0].kind, "render-overlay-audit")

        names = backend.call_names()
        self.assertLess(names.index("create_overlay"), names.index("draw_frame"))
        self.assertLess(names.index("draw_frame"), names.index("destroy_overlay"))
        self.assertEqual(names.count("draw_frame"), 2)
        self.assertEqual(names.count("wait"), 2)
        self.assertEqual(names.count("destroy_overlay"), 1)

        calls_after_execute = list(backend.calls)
        rollback = provider.rollback(result)
        repeated = provider.rollback(result)
        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(repeated.ok, repeated.details)
        self.assertFalse(rollback.restored)
        self.assertEqual(rollback.details["status"], "already_completed")
        self.assertEqual(backend.calls, calls_after_execute)

        audit = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(audit)
        self.assertTrue(contract.ok, contract.errors)
        json.dumps(result.to_dict(), sort_keys=True)

        with tempfile.TemporaryDirectory() as out_dir:
            bundle = provider.collect_artifacts(result, out_dir)
            artifact_path = Path(out_dir) / bundle.artifacts[0].path
            encoded = artifact_path.read_bytes()
            payload = json.loads(encoded)
            digest = hashlib.sha256(encoded).hexdigest()

        self.assertEqual(payload["session_id"], "overlay-test")
        self.assertEqual(payload["frame_count"], 2)
        self.assertEqual(payload["window_identity"]["hwnd"], 0x1234)
        self.assertEqual(payload["timing"]["requested_duration_ms"], 25)
        self.assertTrue(payload["resource_cleanup"]["resources_released"])
        self.assertEqual(bundle.artifacts[0].metadata["sha256"], digest)
        self.assertEqual(bundle.manifest_entries[0]["sha256"], digest)

    def test_invalid_commands_never_probe_or_create_a_window(self) -> None:
        cases = [
            {"primitives": [{"type": "line", "x1": 0, "y1": 0, "x2": 1, "y2": 1}]},
            {
                "primitives": [
                    {
                        "type": "rect",
                        "x": 0,
                        "y": 0,
                        "width": 10,
                        "height": 10,
                        "color": "#FFFFFF",
                        "script": "not-allowed",
                    }
                ]
            },
            {
                "primitives": [
                    {
                        "type": "circle",
                        "x": 5,
                        "y": 5,
                        "radius": 0,
                        "color": "#FFFFFF",
                    }
                ]
            },
            {
                "primitives": [
                    {
                        "type": "text",
                        "x": 1,
                        "y": 1,
                        "text": "line one\nline two",
                        "color": "#FFFFFF",
                    }
                ]
            },
            {"duration_ms": 30_001},
            {"frame_interval_ms": 1},
            {"input_automation": {"click": [1, 2]}},
            {
                "primitives": [
                    {
                        "type": "line",
                        "x1": True,
                        "y1": 0,
                        "x2": 1,
                        "y2": 1,
                        "color": "#FFFFFF",
                    }
                ]
            },
        ]

        for index, params in enumerate(cases):
            with self.subTest(index=index):
                backend = FakeRenderOverlayBackend()
                provider = RenderOverlayProvider(backend=backend)
                plan = provider.plan(self._request(params=params))

                validation = provider.validate(plan)
                result = provider.execute(plan)

                self.assertFalse(validation.ok)
                self.assertEqual(result.status, "failed")
                self.assertEqual(backend.calls, [])
                self.assertIn("command_schema", self._checks(validation))

    def test_target_window_checks_fail_closed(self) -> None:
        cases = [
            (
                {
                    "status": "failed",
                    "interactive_desktop": True,
                    "exists": False,
                    "visible": False,
                    "reason": "target window does not exist",
                },
                "target window does not exist",
            ),
            (
                {
                    "status": "ok",
                    "interactive_desktop": True,
                    "exists": True,
                    "visible": True,
                    "owner_pid_matches": False,
                    "pid": 9999,
                    "hwnd": 0x1234,
                    "client_rect": {"width": 800, "height": 600},
                },
                "ownership",
            ),
            (
                {
                    "status": "ok",
                    "interactive_desktop": True,
                    "exists": True,
                    "visible": False,
                    "owner_pid_matches": True,
                    "pid": 4242,
                    "hwnd": 0x1234,
                    "client_rect": {"width": 800, "height": 600},
                },
                "visible",
            ),
            (
                {
                    "status": "ok",
                    "interactive_desktop": True,
                    "exists": True,
                    "visible": True,
                    "owner_pid_matches": True,
                    "pid": 4242,
                    "hwnd": 0x1234,
                    "client_rect": {"width": 0, "height": 0},
                },
                "client rect",
            ),
        ]

        for probe, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                backend = FakeRenderOverlayBackend(probe=probe)
                provider = RenderOverlayProvider(backend=backend)
                plan = provider.plan(self._request())
                validation = provider.validate(plan)
                result = provider.execute(plan)

                self.assertFalse(validation.ok)
                self.assertIn(expected_error, " ".join(validation.errors).lower())
                self.assertEqual(result.status, "failed")
                self.assertNotIn("create_overlay", backend.call_names())

    def test_unavailable_platform_or_desktop_is_reported_without_simulation(self) -> None:
        non_windows = WindowsGDIOverlayBackend(platform_name="linux")
        provider = RenderOverlayProvider(backend=non_windows)
        plan = provider.plan(self._request(params={"duration_ms": 0}))
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(self._checks(validation)["backend"]["status"], "unavailable")
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.after_snapshot["session"]["state"], "unavailable")
        self.assertTrue(result.rollback_plan["completed"])

        desktop_backend = FakeRenderOverlayBackend(
            probe={
                "status": "unavailable",
                "interactive_desktop": False,
                "reason": "no interactive desktop is available",
            }
        )
        desktop_provider = RenderOverlayProvider(backend=desktop_backend)
        desktop_plan = desktop_provider.plan(self._request(params={"duration_ms": 0}))
        desktop_validation = desktop_provider.validate(desktop_plan)
        desktop_result = desktop_provider.execute(desktop_plan)

        self.assertTrue(desktop_validation.ok, desktop_validation.errors)
        self.assertEqual(desktop_result.status, "unavailable")
        self.assertNotIn("create_overlay", desktop_backend.call_names())

    def test_failed_execute_cleanup_is_retried_once_by_rollback(self) -> None:
        backend = FakeRenderOverlayBackend(destroy_failures=1)
        provider = RenderOverlayProvider(backend=backend)
        plan = provider.plan(self._request(params={"duration_ms": 0}))
        result = provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertTrue(result.rollback_plan["active"])
        self.assertFalse(result.rollback_plan["completed"])
        self.assertEqual(backend.call_names().count("destroy_overlay"), 1)

        rollback = provider.rollback(result)
        repeated = provider.rollback(result)

        self.assertTrue(rollback.ok, rollback.details)
        self.assertTrue(repeated.ok, repeated.details)
        self.assertEqual(rollback.details["status"], "completed")
        self.assertEqual(repeated.details["status"], "already_completed")
        self.assertEqual(backend.call_names().count("destroy_overlay"), 2)
        self.assertTrue(result.rollback_plan["completed"])
        self.assertFalse(result.rollback_plan["active"])
        self.assertEqual(result.after_snapshot["session"]["state"], "closed")

    def test_draw_failure_still_releases_overlay_resources(self) -> None:
        backend = FakeRenderOverlayBackend(draw_error=RuntimeError("draw failed"))
        provider = RenderOverlayProvider(backend=backend)
        result = provider.execute(
            provider.plan(self._request(params={"duration_ms": 0}))
        )

        self.assertEqual(result.status, "failed")
        self.assertIn("draw failed", json.dumps(result.report_section))
        self.assertEqual(backend.call_names().count("destroy_overlay"), 1)
        self.assertTrue(result.rollback_plan["completed"])

    def test_collect_artifacts_rejects_escape_paths(self) -> None:
        provider = RenderOverlayProvider(backend=FakeRenderOverlayBackend())
        result = provider.execute(
            provider.plan(self._request(params={"duration_ms": 0}))
        )
        result.artifacts[0].path = "../escaped-overlay.json"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "artifacts"
            with self.assertRaisesRegex(ValueError, "collection directory"):
                provider.collect_artifacts(result, str(root))
            self.assertFalse((Path(tmp) / "escaped-overlay.json").exists())

    def test_default_registry_contains_real_render_overlay_provider(self) -> None:
        registry = build_default_registry()
        self.assertEqual(
            registry.list_providers("render_overlay_runtime"),
            ["windows_gdi_overlay"],
        )
        self.assertIsInstance(
            registry.resolve("render_overlay_runtime"),
            RenderOverlayProvider,
        )


@unittest.skipUnless(
    sys.platform == "win32" and os.environ.get("RUN_RENDER_OVERLAY_SMOKE") == "1",
    "set RUN_RENDER_OVERLAY_SMOKE=1 on an interactive Windows desktop",
)
class WindowsRenderOverlaySmokeTests(unittest.TestCase):
    def test_real_layered_window_draw_and_cleanup(self) -> None:  # pragma: no cover - gated
        from ctypes import wintypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD,
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HWND,
            wintypes.HMENU,
            wintypes.HINSTANCE,
            wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.UpdateWindow.argtypes = [wintypes.HWND]
        user32.UpdateWindow.restype = wintypes.BOOL
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetCurrentProcessId.restype = wintypes.DWORD

        style = 0x80000000 | 0x00C00000 | 0x00080000 | 0x10000000
        hwnd = user32.CreateWindowExW(
            0x00000080,
            "STATIC",
            "reverse-analyzer-overlay-smoke-target",
            style,
            80,
            80,
            480,
            320,
            None,
            None,
            kernel32.GetModuleHandleW(None),
            None,
        )
        self.assertTrue(hwnd, ctypes.get_last_error())
        try:
            user32.ShowWindow(hwnd, 5)
            user32.UpdateWindow(hwnd)
            pid = int(kernel32.GetCurrentProcessId())
            backend = WindowsGDIOverlayBackend()
            if not backend.available:
                self.skipTest(backend.unavailable_reason or "Win32 GDI backend unavailable")
            provider = RenderOverlayProvider(backend=backend)
            request = CapabilityRequest(
                capability="render_overlay_runtime",
                action="render",
                target=TargetIdentity(kind="window", pid=pid, display_name="smoke-target"),
                params={
                    "hwnd": int(hwnd),
                    "duration_ms": 80,
                    "frame_interval_ms": 20,
                    "primitives": [
                        {
                            "type": "line",
                            "x1": 20,
                            "y1": 160,
                            "x2": 260,
                            "y2": 160,
                            "color": "#FF4040",
                            "width": 2,
                        },
                        {
                            "type": "rect",
                            "x": 20,
                            "y": 20,
                            "width": 120,
                            "height": 80,
                            "color": "#00FF00",
                            "stroke_width": 2,
                            "filled": False,
                        },
                        {
                            "type": "circle",
                            "x": 220,
                            "y": 80,
                            "radius": 30,
                            "color": "#40A0FF",
                            "stroke_width": 2,
                            "filled": False,
                        },
                        {
                            "type": "text",
                            "x": 30,
                            "y": 40,
                            "text": "overlay smoke",
                            "color": "#FFFFFF",
                            "font_size": 16,
                        },
                    ],
                },
                session_id="windows-overlay-smoke",
            )
            plan = provider.plan(request)
            validation = provider.validate(plan)
            if any("interactive desktop" in item.lower() for item in validation.warnings):
                self.skipTest("no interactive desktop")
            self.assertTrue(validation.ok, validation.errors)

            result = provider.execute(plan)

            self.assertEqual(result.status, "ok", result.report_section)
            self.assertGreaterEqual(result.after_snapshot["frame_count"], 1)
            cleanup = result.after_snapshot["resource_cleanup"]
            self.assertTrue(cleanup["ok"])
            self.assertTrue(cleanup["window_destroyed"])
            self.assertTrue(cleanup["resources_released"])
            self.assertFalse(cleanup["memory_dc_active"])
            self.assertFalse(cleanup["bitmap_active"])
            self.assertEqual(cleanup["live_gdi_objects"], 0)
            self.assertTrue(provider.rollback(result).ok)
        finally:
            user32.DestroyWindow(hwnd)
