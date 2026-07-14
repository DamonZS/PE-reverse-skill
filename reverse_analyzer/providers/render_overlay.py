"""Bounded external Win32 GDI diagnostic overlay capability provider.

The renderer creates a separate click-through layered window over one explicit
target HWND, or over the visible top-level window resolved from one explicit
PID.  It is intentionally data-driven: callers can submit only bounded GDI
primitives, never executable drawing callbacks, input commands, or target
selection logic.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
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


_SCHEMA_VERSION = 1
_ACTION = "render"
_ACTION_ALIASES = {
    "render": _ACTION,
    "overlay": _ACTION,
    "render_overlay": _ACTION,
    "show_overlay": _ACTION,
    "display": _ACTION,
}
_DEFAULT_DURATION_MS = 1_000
_MAX_DURATION_MS = 30_000
_DEFAULT_FRAME_INTERVAL_MS = 33
_MIN_FRAME_INTERVAL_MS = 16
_MAX_FRAME_INTERVAL_MS = 1_000
_MAX_PRIMITIVES = 256
_MAX_COORDINATE = 32_767
_MAX_PEN_WIDTH = 32
_MAX_FONT_SIZE = 96
_MAX_TEXT_LENGTH = 512
_MAX_FRAMES = 2_048
_MAX_PID = 0xFFFFFFFF
_TRANSPARENCY_COLOR = "#010203"
_TRANSPARENCY_RGB = (1, 2, 3)
_SAFE_SEGMENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_ALLOWED_PARAMETER_KEYS = {
    "commands",
    "duration_ms",
    "frame_interval_ms",
    "hwnd",
    "pid",
    "primitives",
}
_RENDERER_IDENTITY = {
    "api": "Win32 GDI",
    "integration": "external_layered_window",
    "window_style": "transparent_topmost_click_through",
    "bounded_primitives": True,
    "input_automation": False,
    "target_logic": False,
}


class RenderOverlayBackend(Protocol):
    """Backend surface used by the provider and deterministic fake tests."""

    name: str
    available: bool
    unavailable_reason: Optional[str]

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def create_overlay(
        self,
        target_window: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> Any: ...

    def draw_frame(
        self,
        session: Any,
        primitives: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]: ...

    def wait(self, session: Any, duration_ms: int) -> None: ...

    def destroy_overlay(self, session: Any) -> Mapping[str, Any]: ...

    def describe_overlay(self, session: Any) -> Mapping[str, Any]: ...


@dataclass
class _Win32OverlaySession:
    target_pid: int
    target_hwnd: int
    overlay_hwnd: int = 0
    width: int = 0
    height: int = 0
    memory_dc: int = 0
    bitmap: int = 0
    old_bitmap: int = 0
    closed: bool = False
    counted_active: bool = False
    class_registered: bool = False
    created_gdi_objects: int = 0
    deleted_gdi_objects: int = 0
    frames_drawn: int = 0


class WindowsGDIOverlayBackend:
    """Real local Win32 layered-window renderer implemented with ``ctypes``."""

    name = "windows_ctypes_gdi"

    WS_POPUP = 0x80000000
    WS_EX_TOPMOST = 0x00000008
    WS_EX_TRANSPARENT = 0x00000020
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_LAYERED = 0x00080000
    WS_EX_NOACTIVATE = 0x08000000
    LWA_COLORKEY = 0x00000001
    SW_SHOWNOACTIVATE = 4
    SWP_NOACTIVATE = 0x0010
    SWP_SHOWWINDOW = 0x0040
    GW_OWNER = 4
    WM_PAINT = 0x000F
    WM_ERASEBKGND = 0x0014
    WM_NCHITTEST = 0x0084
    WM_MOUSEACTIVATE = 0x0021
    HTTRANSPARENT = -1
    MA_NOACTIVATE = 3
    PM_REMOVE = 0x0001
    UOI_FLAGS = 1
    WSF_VISIBLE = 0x0001
    DESKTOP_READOBJECTS = 0x0001
    DESKTOP_SWITCHDESKTOP = 0x0100
    PS_SOLID = 0
    NULL_BRUSH = 5
    TRANSPARENT = 1
    SRCCOPY = 0x00CC0020
    DEFAULT_CHARSET = 1
    OUT_DEFAULT_PRECIS = 0
    CLIP_DEFAULT_PRECIS = 0
    ANTIALIASED_QUALITY = 4
    DEFAULT_PITCH = 0
    FF_DONTCARE = 0

    def __init__(self, *, platform_name: Optional[str] = None) -> None:
        self.platform_name = platform_name or sys.platform
        self.available = self.platform_name == "win32"
        self.unavailable_reason: Optional[str] = None
        self._user32: Any = None
        self._gdi32: Any = None
        self._kernel32: Any = None
        self._window_class_type: Any = None
        self._paint_struct_type: Any = None
        self._user_object_flags_type: Any = None
        self._enum_windows_proc_type: Any = None
        self._wndproc_type: Any = None
        self._wndproc: Any = None
        self._class_atom = 0
        self._class_name = f"ReverseAnalyzerGDIOverlay_{os.getpid()}_{id(self):x}"
        self._active_windows = 0
        self._class_lock = threading.RLock()
        if not self.available:
            self.unavailable_reason = (
                f"Win32 GDI overlay APIs are unavailable on {self.platform_name}"
            )
            return
        try:
            self._configure_api()
        except Exception as exc:  # pragma: no cover - host API dependent
            self.available = False
            self.unavailable_reason = (
                f"failed to initialize Win32 GDI overlay bindings: {exc}"
            )

    def probe_target(
        self,
        target: TargetIdentity,
        options: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if not self.available:
            return {
                "status": "unavailable",
                "interactive_desktop": False,
                "reason": self.unavailable_reason or "Win32 GDI is unavailable",
            }

        desktop = self._probe_interactive_desktop()
        if not desktop.get("available"):
            return {
                "status": "unavailable",
                "interactive_desktop": False,
                "desktop": desktop,
                "reason": str(
                    desktop.get("reason") or "no interactive desktop is available"
                ),
            }

        requested_pid = _positive_pid(options.get("pid")) or _positive_pid(target.pid)
        requested_hwnd = _positive_handle(options.get("hwnd"))
        resolution = "explicit_hwnd"
        if requested_hwnd is None and requested_pid is not None:
            requested_hwnd = self._resolve_pid_window(requested_pid)
            resolution = "explicit_pid_visible_top_level_window"
        if requested_hwnd is None:
            return {
                "status": "failed",
                "interactive_desktop": True,
                "desktop": desktop,
                "exists": False,
                "reason": (
                    "target PID has no visible top-level window with a non-empty client rect"
                    if requested_pid is not None
                    else "target PID or HWND is required"
                ),
            }

        identity = self._window_identity(requested_hwnd, requested_pid)
        identity.update(
            {
                "interactive_desktop": True,
                "desktop": desktop,
                "resolution": resolution,
            }
        )
        return identity

    def create_overlay(
        self,
        target_window: Mapping[str, Any],
        options: Mapping[str, Any],
    ) -> _Win32OverlaySession:
        del options
        self._require_available()
        target_hwnd = _positive_handle(target_window.get("hwnd"))
        target_pid = _positive_pid(target_window.get("pid"))
        if target_hwnd is None or target_pid is None:
            raise RuntimeError("validated target window identity is incomplete")
        current = self._window_identity(target_hwnd, target_pid)
        if current.get("status") != "ok":
            raise RuntimeError(
                str(current.get("reason") or "target window changed before overlay creation")
            )

        session = _Win32OverlaySession(
            target_pid=target_pid,
            target_hwnd=target_hwnd,
        )
        try:
            self._register_window_class()
            session.class_registered = True
            rect = _json_mapping(current.get("client_rect"))
            x = int(rect["screen_x"])
            y = int(rect["screen_y"])
            width = int(rect["width"])
            height = int(rect["height"])
            ex_style = (
                self.WS_EX_LAYERED
                | self.WS_EX_TRANSPARENT
                | self.WS_EX_TOPMOST
                | self.WS_EX_TOOLWINDOW
                | self.WS_EX_NOACTIVATE
            )
            instance = self._kernel32.GetModuleHandleW(None)
            hwnd = self._user32.CreateWindowExW(
                ex_style,
                self._class_name,
                "Reverse Analyzer Diagnostic Overlay",
                self.WS_POPUP,
                x,
                y,
                width,
                height,
                None,
                None,
                instance,
                None,
            )
            if not hwnd:
                self._raise_last_error("CreateWindowExW")
            session.overlay_hwnd = int(hwnd)
            session.counted_active = True
            with self._class_lock:
                self._active_windows += 1

            color_key = self._color_ref(_TRANSPARENCY_RGB)
            if not self._user32.SetLayeredWindowAttributes(
                session.overlay_hwnd,
                color_key,
                255,
                self.LWA_COLORKEY,
            ):
                self._raise_last_error("SetLayeredWindowAttributes")
            if not self._user32.SetWindowPos(
                session.overlay_hwnd,
                ctypes.c_void_p(-1),
                x,
                y,
                width,
                height,
                self.SWP_NOACTIVATE | self.SWP_SHOWWINDOW,
            ):
                self._raise_last_error("SetWindowPos")
            self._user32.ShowWindow(session.overlay_hwnd, self.SW_SHOWNOACTIVATE)
            return session
        except Exception:
            self.destroy_overlay(session)
            raise

    def draw_frame(
        self,
        session: _Win32OverlaySession,
        primitives: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        self._require_available()
        if session.closed or not session.overlay_hwnd:
            raise RuntimeError("overlay window is already closed")
        identity = self._window_identity(session.target_hwnd, session.target_pid)
        if identity.get("status") != "ok":
            raise RuntimeError(
                str(identity.get("reason") or "target window is no longer renderable")
            )
        rect = _json_mapping(identity.get("client_rect"))
        width = int(rect["width"])
        height = int(rect["height"])
        if not self._user32.SetWindowPos(
            session.overlay_hwnd,
            ctypes.c_void_p(-1),
            int(rect["screen_x"]),
            int(rect["screen_y"]),
            width,
            height,
            self.SWP_NOACTIVATE | self.SWP_SHOWWINDOW,
        ):
            self._raise_last_error("SetWindowPos")

        self._ensure_backbuffer(session, width, height)
        window_dc = self._user32.GetDC(session.overlay_hwnd)
        if not window_dc:
            self._raise_last_error("GetDC")
        try:
            self._clear_backbuffer(session)
            for primitive in primitives:
                self._draw_primitive(session, primitive)
            if not self._gdi32.BitBlt(
                window_dc,
                0,
                0,
                width,
                height,
                session.memory_dc,
                0,
                0,
                self.SRCCOPY,
            ):
                self._raise_last_error("BitBlt")
        finally:
            self._user32.ReleaseDC(session.overlay_hwnd, window_dc)
        self._pump_messages(session)
        session.frames_drawn += 1
        return {
            "window_identity": identity,
            "overlay_hwnd": session.overlay_hwnd,
            "primitive_count": len(primitives),
            "resources": self._resource_snapshot(session),
        }

    def wait(self, session: _Win32OverlaySession, duration_ms: int) -> None:
        remaining = max(0, int(duration_ms))
        while remaining > 0:
            self._pump_messages(session)
            chunk = min(remaining, 10)
            time.sleep(chunk / 1000.0)
            remaining -= chunk
        self._pump_messages(session)

    def destroy_overlay(self, session: _Win32OverlaySession) -> Mapping[str, Any]:
        if session.closed:
            return {
                "ok": True,
                "already_closed": True,
                "window_destroyed": True,
                "resources_released": True,
                **self._resource_snapshot(session),
            }

        errors: list[str] = []
        backing = self._release_backbuffer(session)
        errors.extend(backing["errors"])

        window_destroyed = not bool(session.overlay_hwnd)
        if session.overlay_hwnd:
            if not self._user32.IsWindow(session.overlay_hwnd):
                window_destroyed = True
            elif self._user32.DestroyWindow(session.overlay_hwnd):
                window_destroyed = True
            else:
                errors.append(self._last_error_message("DestroyWindow"))
            if window_destroyed:
                session.overlay_hwnd = 0

        if window_destroyed and session.counted_active:
            with self._class_lock:
                self._active_windows = max(0, self._active_windows - 1)
            session.counted_active = False

        class_released = True
        if window_destroyed and session.class_registered:
            class_released, class_error = self._unregister_window_class_if_unused()
            if class_error:
                errors.append(class_error)
            if class_released:
                session.class_registered = False

        resources_released = bool(backing["ok"] and window_destroyed and class_released)
        session.closed = resources_released
        return {
            "ok": resources_released and not errors,
            "already_closed": False,
            "window_destroyed": window_destroyed,
            "resources_released": resources_released,
            "released_memory_dc": backing["released_memory_dc"],
            "released_bitmap": backing["released_bitmap"],
            "window_class_released": class_released,
            "errors": errors,
            **self._resource_snapshot(session),
        }

    def describe_overlay(self, session: _Win32OverlaySession) -> Mapping[str, Any]:
        return {
            "overlay_hwnd": session.overlay_hwnd or None,
            "target_hwnd": session.target_hwnd,
            "target_pid": session.target_pid,
            "width": session.width,
            "height": session.height,
            "frames_drawn": session.frames_drawn,
            "closed": session.closed,
            "resources": self._resource_snapshot(session),
        }

    def _configure_api(self) -> None:  # pragma: no cover - exercised on Windows
        from ctypes import wintypes

        lresult = ctypes.c_ssize_t
        wparam = ctypes.c_size_t
        lparam = ctypes.c_ssize_t
        wndproc = ctypes.WINFUNCTYPE(lresult, wintypes.HWND, wintypes.UINT, wparam, lparam)
        enumproc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, lparam)

        class WNDCLASSW(ctypes.Structure):
            _fields_ = [
                ("style", wintypes.UINT),
                ("lpfnWndProc", wndproc),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HANDLE),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HANDLE),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
            ]

        class PAINTSTRUCT(ctypes.Structure):
            _fields_ = [
                ("hdc", wintypes.HDC),
                ("fErase", wintypes.BOOL),
                ("rcPaint", wintypes.RECT),
                ("fRestore", wintypes.BOOL),
                ("fIncUpdate", wintypes.BOOL),
                ("rgbReserved", ctypes.c_byte * 32),
            ]

        class USEROBJECTFLAGS(ctypes.Structure):
            _fields_ = [
                ("fInherit", wintypes.BOOL),
                ("fReserved", wintypes.BOOL),
                ("dwFlags", wintypes.DWORD),
            ]

        self._window_class_type = WNDCLASSW
        self._paint_struct_type = PAINTSTRUCT
        self._user_object_flags_type = USEROBJECTFLAGS
        self._enum_windows_proc_type = enumproc
        self._wndproc_type = wndproc
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        user32 = self._user32
        gdi32 = self._gdi32
        kernel32 = self._kernel32
        handle = wintypes.HANDLE

        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetCurrentThreadId.argtypes = []
        kernel32.GetCurrentThreadId.restype = wintypes.DWORD

        user32.IsWindow.argtypes = [wintypes.HWND]
        user32.IsWindow.restype = wintypes.BOOL
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.GetWindowThreadProcessId.argtypes = [
            wintypes.HWND,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        user32.GetClientRect.restype = wintypes.BOOL
        user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
        user32.ClientToScreen.restype = wintypes.BOOL
        user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetWindow.restype = wintypes.HWND
        user32.EnumWindows.argtypes = [enumproc, lparam]
        user32.EnumWindows.restype = wintypes.BOOL
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = ctypes.c_int
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetWindowTextW.restype = ctypes.c_int
        user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
        user32.GetClassNameW.restype = ctypes.c_int
        user32.GetProcessWindowStation.argtypes = []
        user32.GetProcessWindowStation.restype = handle
        user32.GetUserObjectInformationW.argtypes = [
            handle,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        user32.GetUserObjectInformationW.restype = wintypes.BOOL
        user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        user32.OpenInputDesktop.restype = handle
        user32.CloseDesktop.argtypes = [handle]
        user32.CloseDesktop.restype = wintypes.BOOL
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = wintypes.WORD
        user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        user32.UnregisterClassW.restype = wintypes.BOOL
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
        user32.SetLayeredWindowAttributes.argtypes = [
            wintypes.HWND,
            wintypes.DWORD,
            ctypes.c_ubyte,
            wintypes.DWORD,
        ]
        user32.SetLayeredWindowAttributes.restype = wintypes.BOOL
        user32.SetWindowPos.argtypes = [
            wintypes.HWND,
            wintypes.HWND,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.UINT,
        ]
        user32.SetWindowPos.restype = wintypes.BOOL
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wparam, lparam]
        user32.DefWindowProcW.restype = lresult
        user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
        user32.BeginPaint.restype = wintypes.HDC
        user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
        user32.EndPaint.restype = wintypes.BOOL
        user32.PeekMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG),
            wintypes.HWND,
            wintypes.UINT,
            wintypes.UINT,
            wintypes.UINT,
        ]
        user32.PeekMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = lresult
        user32.GetDC.argtypes = [wintypes.HWND]
        user32.GetDC.restype = wintypes.HDC
        user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
        user32.ReleaseDC.restype = ctypes.c_int
        user32.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), handle]
        user32.FillRect.restype = ctypes.c_int

        gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
        gdi32.CreateCompatibleDC.restype = wintypes.HDC
        gdi32.DeleteDC.argtypes = [wintypes.HDC]
        gdi32.DeleteDC.restype = wintypes.BOOL
        gdi32.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
        gdi32.CreateCompatibleBitmap.restype = handle
        gdi32.SelectObject.argtypes = [wintypes.HDC, handle]
        gdi32.SelectObject.restype = handle
        gdi32.DeleteObject.argtypes = [handle]
        gdi32.DeleteObject.restype = wintypes.BOOL
        gdi32.CreateSolidBrush.argtypes = [wintypes.DWORD]
        gdi32.CreateSolidBrush.restype = handle
        gdi32.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, wintypes.DWORD]
        gdi32.CreatePen.restype = handle
        gdi32.GetStockObject.argtypes = [ctypes.c_int]
        gdi32.GetStockObject.restype = handle
        gdi32.MoveToEx.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.POINTER(wintypes.POINT),
        ]
        gdi32.MoveToEx.restype = wintypes.BOOL
        gdi32.LineTo.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
        gdi32.LineTo.restype = wintypes.BOOL
        gdi32.Rectangle.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        ]
        gdi32.Rectangle.restype = wintypes.BOOL
        gdi32.Ellipse.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
        ]
        gdi32.Ellipse.restype = wintypes.BOOL
        gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
        gdi32.SetBkMode.restype = ctypes.c_int
        gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.DWORD]
        gdi32.SetTextColor.restype = wintypes.DWORD
        gdi32.TextOutW.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.LPCWSTR,
            ctypes.c_int,
        ]
        gdi32.TextOutW.restype = wintypes.BOOL
        gdi32.CreateFontW.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        gdi32.CreateFontW.restype = handle
        gdi32.BitBlt.argtypes = [
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.HDC,
            ctypes.c_int,
            ctypes.c_int,
            wintypes.DWORD,
        ]
        gdi32.BitBlt.restype = wintypes.BOOL

        @wndproc
        def overlay_wndproc(hwnd: Any, message: int, w_param: int, l_param: int) -> int:
            if message == self.WM_NCHITTEST:
                return self.HTTRANSPARENT
            if message == self.WM_MOUSEACTIVATE:
                return self.MA_NOACTIVATE
            if message == self.WM_ERASEBKGND:
                return 1
            if message == self.WM_PAINT:
                paint = PAINTSTRUCT()
                user32.BeginPaint(hwnd, ctypes.byref(paint))
                user32.EndPaint(hwnd, ctypes.byref(paint))
                return 0
            return int(user32.DefWindowProcW(hwnd, message, w_param, l_param))

        self._wndproc = overlay_wndproc

    def _probe_interactive_desktop(self) -> dict[str, Any]:
        station = self._user32.GetProcessWindowStation()
        if not station:
            return {
                "available": False,
                "reason": self._last_error_message("GetProcessWindowStation"),
            }
        flags = self._user_object_flags_type()
        needed = ctypes.c_ulong(0)
        if not self._user32.GetUserObjectInformationW(
            station,
            self.UOI_FLAGS,
            ctypes.byref(flags),
            ctypes.sizeof(flags),
            ctypes.byref(needed),
        ):
            return {
                "available": False,
                "reason": self._last_error_message("GetUserObjectInformationW"),
            }
        if not flags.dwFlags & self.WSF_VISIBLE:
            return {
                "available": False,
                "window_station_visible": False,
                "reason": "process window station is not visible",
            }
        desktop = self._user32.OpenInputDesktop(
            0,
            False,
            self.DESKTOP_READOBJECTS | self.DESKTOP_SWITCHDESKTOP,
        )
        if not desktop:
            return {
                "available": False,
                "window_station_visible": True,
                "reason": self._last_error_message("OpenInputDesktop"),
            }
        self._user32.CloseDesktop(desktop)
        return {
            "available": True,
            "window_station_visible": True,
            "input_desktop_opened": True,
        }

    def _resolve_pid_window(self, pid: int) -> Optional[int]:
        candidates: list[tuple[int, int]] = []

        @self._enum_windows_proc_type
        def visitor(hwnd: Any, l_param: int) -> bool:
            del l_param
            try:
                owner_pid = ctypes.c_ulong(0)
                self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
                if int(owner_pid.value) != pid:
                    return True
                if not self._user32.IsWindowVisible(hwnd):
                    return True
                if self._user32.GetWindow(hwnd, self.GW_OWNER):
                    return True
                rect = self._window_client_rect(int(hwnd))
                if rect is None:
                    return True
                candidates.append((int(rect["width"]) * int(rect["height"]), int(hwnd)))
            except Exception:
                return True
            return True

        self._user32.EnumWindows(visitor, 0)
        if not candidates:
            return None
        candidates.sort(key=lambda item: (-item[0], item[1]))
        return candidates[0][1]

    def _window_identity(
        self,
        hwnd: int,
        expected_pid: Optional[int],
    ) -> dict[str, Any]:
        if not self._user32.IsWindow(hwnd):
            return {
                "status": "failed",
                "exists": False,
                "visible": False,
                "hwnd": hwnd,
                "reason": "target window does not exist",
            }
        owner_pid = ctypes.c_ulong(0)
        thread_id = int(
            self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
        )
        actual_pid = int(owner_pid.value)
        ownership_ok = expected_pid is None or expected_pid == actual_pid
        if not ownership_ok:
            return {
                "status": "failed",
                "exists": True,
                "visible": bool(self._user32.IsWindowVisible(hwnd)),
                "owner_pid_matches": False,
                "expected_pid": expected_pid,
                "pid": actual_pid,
                "hwnd": hwnd,
                "thread_id": thread_id,
                "reason": "target HWND ownership does not match the declared PID",
            }
        visible = bool(self._user32.IsWindowVisible(hwnd))
        if not visible:
            return {
                "status": "failed",
                "exists": True,
                "visible": False,
                "owner_pid_matches": True,
                "pid": actual_pid,
                "hwnd": hwnd,
                "thread_id": thread_id,
                "reason": "target window is not visible",
            }
        rect = self._window_client_rect(hwnd)
        if rect is None or int(rect["width"]) <= 0 or int(rect["height"]) <= 0:
            return {
                "status": "failed",
                "exists": True,
                "visible": True,
                "owner_pid_matches": True,
                "pid": actual_pid,
                "hwnd": hwnd,
                "thread_id": thread_id,
                "client_rect": rect or {},
                "reason": "target window client rect is empty or unavailable",
            }
        return {
            "status": "ok",
            "exists": True,
            "visible": True,
            "owner_pid_matches": True,
            "pid": actual_pid,
            "hwnd": hwnd,
            "thread_id": thread_id,
            "title": self._window_text(hwnd),
            "class_name": self._window_class_name(hwnd),
            "client_rect": rect,
        }

    def _window_client_rect(self, hwnd: int) -> Optional[dict[str, int]]:
        from ctypes import wintypes

        rect = wintypes.RECT()
        if not self._user32.GetClientRect(hwnd, ctypes.byref(rect)):
            return None
        point = wintypes.POINT(rect.left, rect.top)
        if not self._user32.ClientToScreen(hwnd, ctypes.byref(point)):
            return None
        width = int(rect.right - rect.left)
        height = int(rect.bottom - rect.top)
        return {
            "left": int(rect.left),
            "top": int(rect.top),
            "right": int(rect.right),
            "bottom": int(rect.bottom),
            "width": width,
            "height": height,
            "screen_x": int(point.x),
            "screen_y": int(point.y),
        }

    def _window_text(self, hwnd: int) -> str:
        length = min(max(0, int(self._user32.GetWindowTextLengthW(hwnd))), 4_096)
        buffer = ctypes.create_unicode_buffer(length + 1)
        self._user32.GetWindowTextW(hwnd, buffer, len(buffer))
        return str(buffer.value)

    def _window_class_name(self, hwnd: int) -> str:
        buffer = ctypes.create_unicode_buffer(256)
        self._user32.GetClassNameW(hwnd, buffer, len(buffer))
        return str(buffer.value)

    def _register_window_class(self) -> None:
        with self._class_lock:
            if self._class_atom:
                return
            instance = self._kernel32.GetModuleHandleW(None)
            window_class = self._window_class_type()
            window_class.style = 0
            window_class.lpfnWndProc = self._wndproc
            window_class.cbClsExtra = 0
            window_class.cbWndExtra = 0
            window_class.hInstance = instance
            window_class.hIcon = None
            window_class.hCursor = None
            window_class.hbrBackground = None
            window_class.lpszMenuName = None
            window_class.lpszClassName = self._class_name
            atom = self._user32.RegisterClassW(ctypes.byref(window_class))
            if not atom:
                self._raise_last_error("RegisterClassW")
            self._class_atom = int(atom)

    def _unregister_window_class_if_unused(self) -> tuple[bool, Optional[str]]:
        with self._class_lock:
            if self._active_windows:
                return True, None
            if not self._class_atom:
                return True, None
            instance = self._kernel32.GetModuleHandleW(None)
            if not self._user32.UnregisterClassW(self._class_name, instance):
                return False, self._last_error_message("UnregisterClassW")
            self._class_atom = 0
            return True, None

    def _ensure_backbuffer(
        self,
        session: _Win32OverlaySession,
        width: int,
        height: int,
    ) -> None:
        if (
            session.memory_dc
            and session.bitmap
            and session.width == width
            and session.height == height
        ):
            return
        released = self._release_backbuffer(session)
        if not released["ok"]:
            raise RuntimeError("failed to release resized GDI backbuffer")
        window_dc = self._user32.GetDC(session.overlay_hwnd)
        if not window_dc:
            self._raise_last_error("GetDC")
        memory_dc = 0
        bitmap = 0
        try:
            memory_dc = self._gdi32.CreateCompatibleDC(window_dc)
            if not memory_dc:
                self._raise_last_error("CreateCompatibleDC")
            bitmap = self._gdi32.CreateCompatibleBitmap(window_dc, width, height)
            if not bitmap:
                self._raise_last_error("CreateCompatibleBitmap")
            old_bitmap = self._gdi32.SelectObject(memory_dc, bitmap)
            if not old_bitmap:
                self._raise_last_error("SelectObject")
            session.memory_dc = int(memory_dc)
            session.bitmap = int(bitmap)
            session.old_bitmap = int(old_bitmap)
            session.width = width
            session.height = height
            session.created_gdi_objects += 1
            memory_dc = 0
            bitmap = 0
        finally:
            if bitmap:
                self._gdi32.DeleteObject(bitmap)
            if memory_dc:
                self._gdi32.DeleteDC(memory_dc)
            self._user32.ReleaseDC(session.overlay_hwnd, window_dc)

    def _release_backbuffer(self, session: _Win32OverlaySession) -> dict[str, Any]:
        errors: list[str] = []
        released_bitmap = not bool(session.bitmap)
        released_memory_dc = not bool(session.memory_dc)
        if session.memory_dc and session.bitmap:
            if session.old_bitmap:
                self._gdi32.SelectObject(session.memory_dc, session.old_bitmap)
            if self._gdi32.DeleteObject(session.bitmap):
                released_bitmap = True
                session.deleted_gdi_objects += 1
                session.bitmap = 0
                session.old_bitmap = 0
            else:
                errors.append(self._last_error_message("DeleteObject(bitmap)"))
        if session.memory_dc and released_bitmap:
            if self._gdi32.DeleteDC(session.memory_dc):
                released_memory_dc = True
                session.memory_dc = 0
            else:
                errors.append(self._last_error_message("DeleteDC"))
        if released_bitmap and released_memory_dc:
            session.width = 0
            session.height = 0
        return {
            "ok": released_bitmap and released_memory_dc and not errors,
            "released_bitmap": released_bitmap,
            "released_memory_dc": released_memory_dc,
            "errors": errors,
        }

    def _clear_backbuffer(self, session: _Win32OverlaySession) -> None:
        from ctypes import wintypes

        brush = self._gdi32.CreateSolidBrush(self._color_ref(_TRANSPARENCY_RGB))
        if not brush:
            self._raise_last_error("CreateSolidBrush")
        session.created_gdi_objects += 1
        try:
            rect = wintypes.RECT(0, 0, session.width, session.height)
            if not self._user32.FillRect(session.memory_dc, ctypes.byref(rect), brush):
                self._raise_last_error("FillRect")
        finally:
            self._delete_tracked_object(session, brush, "background brush")

    def _draw_primitive(
        self,
        session: _Win32OverlaySession,
        primitive: Mapping[str, Any],
    ) -> None:
        kind = str(primitive["type"])
        color = self._color_ref(_rgb_from_color(str(primitive["color"])))
        if kind == "line":
            pen = self._create_pen(session, int(primitive["width"]), color)
            old_pen = self._gdi32.SelectObject(session.memory_dc, pen)
            try:
                if not self._gdi32.MoveToEx(
                    session.memory_dc,
                    int(primitive["x1"]),
                    int(primitive["y1"]),
                    None,
                ) or not self._gdi32.LineTo(
                    session.memory_dc,
                    int(primitive["x2"]),
                    int(primitive["y2"]),
                ):
                    self._raise_last_error("GDI line drawing")
            finally:
                self._gdi32.SelectObject(session.memory_dc, old_pen)
                self._delete_tracked_object(session, pen, "line pen")
            return

        if kind in {"rect", "circle"}:
            pen = self._create_pen(session, int(primitive["stroke_width"]), color)
            brush = (
                self._create_brush(session, color)
                if bool(primitive["filled"])
                else self._gdi32.GetStockObject(self.NULL_BRUSH)
            )
            old_pen = self._gdi32.SelectObject(session.memory_dc, pen)
            old_brush = self._gdi32.SelectObject(session.memory_dc, brush)
            try:
                if kind == "rect":
                    ok = self._gdi32.Rectangle(
                        session.memory_dc,
                        int(primitive["x"]),
                        int(primitive["y"]),
                        int(primitive["x"]) + int(primitive["width"]),
                        int(primitive["y"]) + int(primitive["height"]),
                    )
                else:
                    radius = int(primitive["radius"])
                    ok = self._gdi32.Ellipse(
                        session.memory_dc,
                        int(primitive["x"]) - radius,
                        int(primitive["y"]) - radius,
                        int(primitive["x"]) + radius,
                        int(primitive["y"]) + radius,
                    )
                if not ok:
                    self._raise_last_error(f"GDI {kind} drawing")
            finally:
                self._gdi32.SelectObject(session.memory_dc, old_brush)
                self._gdi32.SelectObject(session.memory_dc, old_pen)
                if bool(primitive["filled"]):
                    self._delete_tracked_object(session, brush, f"{kind} brush")
                self._delete_tracked_object(session, pen, f"{kind} pen")
            return

        text = str(primitive["text"])
        font = self._gdi32.CreateFontW(
            -int(primitive["font_size"]),
            0,
            0,
            0,
            400,
            False,
            False,
            False,
            self.DEFAULT_CHARSET,
            self.OUT_DEFAULT_PRECIS,
            self.CLIP_DEFAULT_PRECIS,
            self.ANTIALIASED_QUALITY,
            self.DEFAULT_PITCH | self.FF_DONTCARE,
            "Segoe UI",
        )
        if not font:
            self._raise_last_error("CreateFontW")
        session.created_gdi_objects += 1
        old_font = self._gdi32.SelectObject(session.memory_dc, font)
        try:
            self._gdi32.SetBkMode(session.memory_dc, self.TRANSPARENT)
            self._gdi32.SetTextColor(session.memory_dc, color)
            if not self._gdi32.TextOutW(
                session.memory_dc,
                int(primitive["x"]),
                int(primitive["y"]),
                text,
                len(text),
            ):
                self._raise_last_error("TextOutW")
        finally:
            self._gdi32.SelectObject(session.memory_dc, old_font)
            self._delete_tracked_object(session, font, "text font")

    def _create_pen(
        self,
        session: _Win32OverlaySession,
        width: int,
        color: int,
    ) -> int:
        pen = self._gdi32.CreatePen(self.PS_SOLID, width, color)
        if not pen:
            self._raise_last_error("CreatePen")
        session.created_gdi_objects += 1
        return int(pen)

    def _create_brush(self, session: _Win32OverlaySession, color: int) -> int:
        brush = self._gdi32.CreateSolidBrush(color)
        if not brush:
            self._raise_last_error("CreateSolidBrush")
        session.created_gdi_objects += 1
        return int(brush)

    def _delete_tracked_object(
        self,
        session: _Win32OverlaySession,
        handle: int,
        description: str,
    ) -> None:
        if not self._gdi32.DeleteObject(handle):
            raise RuntimeError(self._last_error_message(f"DeleteObject({description})"))
        session.deleted_gdi_objects += 1

    def _pump_messages(self, session: _Win32OverlaySession) -> None:
        if not session.overlay_hwnd:
            return
        from ctypes import wintypes

        message = wintypes.MSG()
        while self._user32.PeekMessageW(
            ctypes.byref(message),
            session.overlay_hwnd,
            0,
            0,
            self.PM_REMOVE,
        ):
            self._user32.TranslateMessage(ctypes.byref(message))
            self._user32.DispatchMessageW(ctypes.byref(message))

    @staticmethod
    def _color_ref(rgb: tuple[int, int, int]) -> int:
        red, green, blue = rgb
        return red | (green << 8) | (blue << 16)

    @staticmethod
    def _resource_snapshot(session: _Win32OverlaySession) -> dict[str, Any]:
        live = max(0, session.created_gdi_objects - session.deleted_gdi_objects)
        return {
            "created_gdi_objects": session.created_gdi_objects,
            "deleted_gdi_objects": session.deleted_gdi_objects,
            "live_gdi_objects": live,
            "memory_dc_active": bool(session.memory_dc),
            "bitmap_active": bool(session.bitmap),
        }

    def _require_available(self) -> None:
        if not self.available:
            raise RuntimeError(self.unavailable_reason or "Win32 GDI is unavailable")

    @staticmethod
    def _last_error_message(operation: str) -> str:
        error = ctypes.get_last_error()
        detail = ctypes.FormatError(error).strip() if error else "unknown Win32 error"
        return f"{operation} failed ({error}): {detail}"

    def _raise_last_error(self, operation: str) -> None:
        raise OSError(self._last_error_message(operation))


@dataclass
class _ActiveOverlay:
    backend: RenderOverlayBackend
    session: Any


class RenderOverlayProvider:
    """Render bounded diagnostics in a temporary external Win32 GDI window."""

    capability_name = "render_overlay_runtime"
    provider_name = "windows_gdi_overlay"
    priority = 10
    supported_actions = (_ACTION,)

    def __init__(
        self,
        backend: Optional[RenderOverlayBackend] = None,
        *,
        duration_ms: int = _DEFAULT_DURATION_MS,
        frame_interval_ms: int = _DEFAULT_FRAME_INTERVAL_MS,
    ) -> None:
        self.backend: RenderOverlayBackend = (
            backend if backend is not None else WindowsGDIOverlayBackend()
        )
        self.duration_ms = _bounded_default(
            duration_ms,
            minimum=0,
            maximum=_MAX_DURATION_MS,
            default=_DEFAULT_DURATION_MS,
        )
        self.frame_interval_ms = _bounded_default(
            frame_interval_ms,
            minimum=_MIN_FRAME_INTERVAL_MS,
            maximum=_MAX_FRAME_INTERVAL_MS,
            default=_DEFAULT_FRAME_INTERVAL_MS,
        )
        self._active: dict[str, _ActiveOverlay] = {}
        self._active_lock = threading.RLock()

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) == _ACTION
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        action = _normalize_action(request.action)
        if action != _ACTION:
            raise ValueError(f"unsupported render overlay action: {request.action!r}")
        backend = self._select_backend(context)
        session_id = str(request.session_id or "render-overlay-session")
        parameters, planned_target = self._prepare_parameters(request, backend)
        fingerprint = _plan_fingerprint(action, planned_target, parameters)
        declared_window = {
            "pid": parameters.get("pid"),
            "hwnd": parameters.get("hwnd"),
            "resolution": (
                "explicit_hwnd"
                if parameters.get("hwnd") is not None
                else "explicit_pid_visible_top_level_window"
            ),
        }
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=planned_target,
            action=action,
            parameters=parameters,
            steps=[
                {"step": "validate_bounded_primitives", "status": "planned"},
                {"step": "verify_interactive_desktop", "status": "planned"},
                {"step": "verify_window_identity", "status": "planned"},
                {"step": "render_external_gdi_overlay", "status": "planned"},
                {"step": "destroy_window_and_gdi_resources", "status": "planned"},
                {"step": "collect_frame_timing_evidence", "status": "planned"},
            ],
            precondition_hash=fingerprint,
            before_snapshot={
                "schema_version": _SCHEMA_VERSION,
                "session_state": "planned",
                "declared_window_identity": _prune(declared_window),
                "primitive_count": len(parameters.get("primitives") or []),
                "renderer": dict(_RENDERER_IDENTITY),
                "side_effects": False,
            },
            rollback_plan={
                "schema_version": _SCHEMA_VERSION,
                "supported": True,
                "mode": "destroy_external_overlay_and_release_gdi_resources",
                "active": False,
                "completed": False,
                "idempotent": True,
                "target_state_modified": False,
            },
            provenance={
                **_json_mapping(request.provenance),
                "provider": self.provider_name,
                "backend": _backend_info(backend),
                "renderer": dict(_RENDERER_IDENTITY),
                "command_schema_version": _SCHEMA_VERSION,
                "declared_window_identity": _prune(declared_window),
            },
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        validation, _ = self._validate_plan(plan, context=context)
        return validation

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        validation, target_probe = self._validate_plan(plan, context=context)
        backend_info = _backend_info(backend)
        probe_status = str(target_probe.get("status") or "")
        if not _backend_available(backend) or probe_status == "unavailable":
            reason = str(
                target_probe.get("reason")
                or backend_info.get("unavailable_reason")
                or "Win32 GDI overlay backend is unavailable"
            )
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                target_probe=target_probe,
                frames=[],
                timing=_empty_timing(plan),
                cleanup=_inactive_cleanup(reason),
                session={
                    "id": plan.session_id,
                    "state": "unavailable",
                    "active": False,
                    "overlay_hwnd": None,
                },
                errors=[reason],
            )
        if not validation.ok:
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                target_probe=target_probe,
                frames=[],
                timing=_empty_timing(plan),
                cleanup=_inactive_cleanup("execution was blocked by validation"),
                session={
                    "id": plan.session_id,
                    "state": "failed",
                    "active": False,
                    "overlay_hwnd": None,
                },
                errors=list(validation.errors),
            )

        primitives = [dict(item) for item in plan.parameters["primitives"]]
        duration_ms = int(plan.parameters["duration_ms"])
        frame_interval_ms = int(plan.parameters["frame_interval_ms"])
        frames: list[dict[str, Any]] = []
        errors: list[Any] = []
        session: Any = None
        cleanup = _inactive_cleanup("overlay was not created")
        runtime_key: Optional[str] = None
        started_utc = _utc_now()
        started_ns = time.perf_counter_ns()
        scheduled_elapsed_ms = 0
        session_description: dict[str, Any] = {}
        try:
            session = backend.create_overlay(target_probe, _runtime_options(plan))
            if session is None:
                raise RuntimeError("overlay backend returned no session handle")
            runtime_key = f"{plan.session_id}:{id(session):x}"
            session_description = _json_mapping(backend.describe_overlay(session))
            remaining_ms = duration_ms
            while True:
                frame_started_ns = time.perf_counter_ns()
                frame_result = _json_mapping(backend.draw_frame(session, primitives))
                if not frame_result:
                    raise RuntimeError("overlay backend returned an empty frame result")
                frame_ended_ns = time.perf_counter_ns()
                frames.append(
                    _prune(
                        {
                            "index": len(frames),
                            "scheduled_elapsed_ms": scheduled_elapsed_ms,
                            "started_offset_ms": _elapsed_ms(started_ns, frame_started_ns),
                            "draw_duration_ms": _elapsed_ms(
                                frame_started_ns,
                                frame_ended_ns,
                            ),
                            "window_identity": _json_mapping(
                                frame_result.get("window_identity")
                            ),
                            "overlay_hwnd": frame_result.get("overlay_hwnd"),
                            "primitive_count": frame_result.get(
                                "primitive_count",
                                len(primitives),
                            ),
                            "resources": _json_mapping(frame_result.get("resources")),
                        }
                    )
                )
                if len(frames) >= _MAX_FRAMES:
                    if remaining_ms > 0:
                        raise RuntimeError("overlay frame bound was exceeded")
                    break
                if remaining_ms <= 0:
                    break
                wait_ms = min(frame_interval_ms, remaining_ms)
                backend.wait(session, wait_ms)
                remaining_ms -= wait_ms
                scheduled_elapsed_ms += wait_ms
                if remaining_ms <= 0:
                    break
        except Exception as exc:  # noqa: BLE001 - backend failures become evidence
            errors.append(_exception_payload(exc, phase="render"))
        finally:
            if session is not None:
                cleanup = _destroy_overlay(backend, session)
                if not cleanup.get("ok"):
                    errors.append(
                        {
                            "phase": "cleanup",
                            "message": "overlay resources were not fully released",
                            "details": cleanup,
                        }
                    )
                    assert runtime_key is not None
                    with self._active_lock:
                        self._active[runtime_key] = _ActiveOverlay(backend, session)

        ended_ns = time.perf_counter_ns()
        timing = {
            "started_at": started_utc,
            "ended_at": _utc_now(),
            "requested_duration_ms": duration_ms,
            "frame_interval_ms": frame_interval_ms,
            "scheduled_elapsed_ms": scheduled_elapsed_ms,
            "actual_duration_ms": _elapsed_ms(started_ns, ended_ns),
            "frame_count": len(frames),
        }
        status = "ok" if not errors and cleanup.get("ok") else "failed"
        session_state = "closed" if cleanup.get("ok") else "cleanup_failed"
        session_payload = {
            "id": plan.session_id,
            **session_description,
            "state": session_state,
            "active": not bool(cleanup.get("ok")),
            "bounded_duration": True,
            "runtime_key": runtime_key if not cleanup.get("ok") else None,
        }
        return self._execution_result(
            plan,
            validation=validation,
            status=status,
            target_probe=target_probe,
            frames=frames,
            timing=timing,
            cleanup=cleanup,
            session=session_payload,
            errors=errors,
            runtime_key=runtime_key if not cleanup.get("ok") else None,
        )

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        del context
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=str(result.session_id or ""),
                ok=False,
                restored=False,
                details={
                    "status": "failed",
                    "reason": "execution result does not belong to this provider",
                },
            )

        runtime_key = str(result.rollback_plan.get("runtime_key") or "")
        with self._active_lock:
            active = self._active.get(runtime_key) if runtime_key else None
        if active is None:
            completed = bool(result.rollback_plan.get("completed"))
            details = {
                "schema_version": _SCHEMA_VERSION,
                "status": "already_completed" if completed else "failed",
                "completed": completed,
                "idempotent": True,
                "target_state_modified": False,
                "resources_released": completed,
                "reason": (
                    "overlay window and GDI resources were already released"
                    if completed
                    else "no live overlay session is available for cleanup"
                ),
            }
            self._record_rollback(result, details, ok=completed)
            return CapabilityRollbackResult(
                capability=self.capability_name,
                provider=self.provider_name,
                session_id=result.session_id,
                ok=completed,
                restored=False,
                details=details,
            )

        cleanup = _destroy_overlay(active.backend, active.session)
        ok = bool(cleanup.get("ok"))
        if ok:
            with self._active_lock:
                self._active.pop(runtime_key, None)
        details = {
            "schema_version": _SCHEMA_VERSION,
            "status": "completed" if ok else "failed",
            "completed": ok,
            "idempotent": True,
            "target_state_modified": False,
            "resources_released": bool(cleanup.get("resources_released")),
            "cleanup": cleanup,
        }
        self._record_rollback(result, details, ok=ok)
        return CapabilityRollbackResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            ok=ok,
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
        if (
            result.capability != self.capability_name
            or result.provider != self.provider_name
        ):
            raise ValueError("execution result does not belong to render overlay provider")
        collection_root = Path(out_dir).expanduser().resolve()
        collection_root.mkdir(parents=True, exist_ok=True)
        artifacts = list(result.artifacts or [])
        if not artifacts:
            artifacts.append(_audit_artifact(result.session_id, result.status))
        entries_by_path = {
            str(item.get("path")): dict(item)
            for item in result.evidence_manifest_entries or []
            if item.get("path")
        }
        payload = _artifact_payload(result)
        encoded = (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        manifest_entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            destination = _artifact_destination(collection_root, artifact.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(f".{destination.name}.tmp")
            temporary.write_bytes(encoded)
            os.replace(temporary, destination)
            digest = hashlib.sha256(encoded).hexdigest()
            artifact.metadata.update(
                {
                    "collection_root": str(collection_root),
                    "materialized": True,
                    "sha256": digest,
                    "size": len(encoded),
                    "frame_count": len(result.after_snapshot.get("frames") or []),
                    "resources_released": bool(
                        result.after_snapshot.get("resource_cleanup", {}).get(
                            "resources_released"
                        )
                    ),
                }
            )
            entry = entries_by_path.get(
                artifact.path,
                _manifest_entry(result, artifact),
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
        result.report_section["artifacts"] = [item.to_dict() for item in artifacts]
        result.report_section["evidence_manifest_entries"] = list(manifest_entries)
        return CapabilityArtifactBundle(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=manifest_entries,
        )

    def _prepare_parameters(
        self,
        request: CapabilityRequest,
        backend: RenderOverlayBackend,
    ) -> tuple[dict[str, Any], TargetIdentity]:
        params = _json_mapping(request.params)
        errors: list[str] = []
        unknown = sorted(set(params) - _ALLOWED_PARAMETER_KEYS)
        if unknown:
            errors.append("unsupported overlay parameters: " + ", ".join(unknown))

        target_pid, pid_errors = _declared_pid(request.target, params)
        target_hwnd, hwnd_errors = _declared_hwnd(request.target, params)
        errors.extend(pid_errors)
        errors.extend(hwnd_errors)
        if target_pid is None and target_hwnd is None:
            errors.append("target PID or HWND is required")

        if "primitives" in params and "commands" in params:
            errors.append("provide primitives or commands, not both")
        raw_primitives = params.get("primitives", params.get("commands"))
        primitives, primitive_errors = _normalize_primitives(raw_primitives)
        errors.extend(primitive_errors)

        duration_ms, duration_error = _bounded_parameter(
            params.get("duration_ms", self.duration_ms),
            "duration_ms",
            minimum=0,
            maximum=_MAX_DURATION_MS,
        )
        if duration_error:
            errors.append(duration_error)
        frame_interval_ms, interval_error = _bounded_parameter(
            params.get("frame_interval_ms", self.frame_interval_ms),
            "frame_interval_ms",
            minimum=_MIN_FRAME_INTERVAL_MS,
            maximum=_MAX_FRAME_INTERVAL_MS,
        )
        if interval_error:
            errors.append(interval_error)

        target_metadata = _json_mapping(request.target.metadata)
        if target_hwnd is not None:
            target_metadata["hwnd"] = target_hwnd
        planned_target = TargetIdentity(
            kind=str(request.target.kind or "window"),
            path=request.target.path,
            pid=target_pid,
            sha256=request.target.sha256,
            display_name=(
                request.target.display_name
                or (f"HWND 0x{target_hwnd:X}" if target_hwnd is not None else None)
            ),
            metadata=target_metadata,
        )
        parameters = {
            "schema_version": _SCHEMA_VERSION,
            "pid": target_pid,
            "hwnd": target_hwnd,
            "duration_ms": duration_ms,
            "frame_interval_ms": frame_interval_ms,
            "primitives": primitives,
            "primitive_count": len(primitives),
            "command_errors": _dedupe(errors),
            "backend": _backend_info(backend),
            "renderer": dict(_RENDERER_IDENTITY),
        }
        return parameters, planned_target

    def _validate_plan(
        self,
        plan: CapabilityPlan,
        *,
        context: Optional[dict[str, Any]],
    ) -> tuple[CapabilityValidation, dict[str, Any]]:
        backend = self._select_backend(context)
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []

        schema_errors = _plan_schema_errors(plan, self.capability_name, self.provider_name)
        checks.append(
            {
                "name": "command_schema",
                "status": "ok" if not schema_errors else "failed",
                "primitive_count": len(plan.parameters.get("primitives") or []),
                "errors": list(schema_errors),
            }
        )
        errors.extend(schema_errors)

        backend_info = _backend_info(backend)
        backend_available = _backend_available(backend)
        checks.append(
            {
                **backend_info,
                "name": "backend",
                "status": "ok" if backend_available else "unavailable",
            }
        )
        if not backend_available:
            reason = str(
                backend_info.get("unavailable_reason")
                or "Win32 GDI overlay backend is unavailable"
            )
            warnings.append(reason)
            target_probe = {
                "status": "unavailable",
                "interactive_desktop": False,
                "reason": reason,
            }
            checks.append({"name": "target_window", **target_probe})
            return self._validation(plan, checks, warnings, errors), target_probe

        if schema_errors:
            target_probe = {
                "status": "skipped",
                "reason": "target probing skipped because command validation failed",
            }
            checks.append({"name": "target_window", **target_probe})
            return self._validation(plan, checks, warnings, errors), target_probe

        try:
            target_probe = _json_mapping(
                backend.probe_target(plan.target, _runtime_options(plan))
            )
        except Exception as exc:  # noqa: BLE001 - backend probe becomes validation data
            target_probe = {
                "status": "failed",
                "reason": str(exc),
                "error": _exception_payload(exc, phase="probe_target"),
            }

        probe_errors = _target_probe_errors(plan, target_probe)
        probe_status = str(target_probe.get("status") or "failed")
        if probe_status == "unavailable":
            warnings.append(
                str(target_probe.get("reason") or "no interactive desktop is available")
            )
        else:
            errors.extend(probe_errors)
        check_status = (
            "unavailable"
            if probe_status == "unavailable"
            else "ok"
            if not probe_errors and probe_status == "ok"
            else "failed"
        )
        checks.append(
            {
                "name": "target_window",
                "status": check_status,
                **{key: value for key, value in target_probe.items() if key != "status"},
                "errors": probe_errors,
            }
        )

        if probe_status == "ok" and not probe_errors:
            bounds_errors = _primitive_bounds_errors(
                plan.parameters["primitives"],
                _json_mapping(target_probe.get("client_rect")),
            )
            checks.append(
                {
                    "name": "primitive_bounds",
                    "status": "ok" if not bounds_errors else "failed",
                    "errors": bounds_errors,
                }
            )
            errors.extend(bounds_errors)
        else:
            checks.append(
                {
                    "name": "primitive_bounds",
                    "status": "skipped",
                    "reason": "validated client rect is unavailable",
                }
            )
        return self._validation(plan, checks, warnings, errors), target_probe

    def _validation(
        self,
        plan: CapabilityPlan,
        checks: list[dict[str, Any]],
        warnings: list[str],
        errors: list[str],
    ) -> CapabilityValidation:
        return CapabilityValidation(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=str(plan.session_id or ""),
            ok=not errors,
            checks=checks,
            warnings=_dedupe(warnings),
            errors=_dedupe(errors),
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        target_probe: Mapping[str, Any],
        frames: list[dict[str, Any]],
        timing: Mapping[str, Any],
        cleanup: Mapping[str, Any],
        session: Mapping[str, Any],
        errors: Sequence[Any],
        runtime_key: Optional[str] = None,
    ) -> CapabilityExecutionResult:
        completed = bool(cleanup.get("ok"))
        rollback_plan = {
            **_json_mapping(plan.rollback_plan),
            "active": not completed,
            "completed": completed,
            "status": "completed" if completed else "pending",
            "runtime_key": runtime_key,
            "cleanup": _json_mapping(cleanup),
        }
        window_identity = (
            _json_mapping(frames[-1].get("window_identity"))
            if frames
            else _json_mapping(target_probe)
        )
        before_snapshot = {
            **_json_mapping(plan.before_snapshot),
            "session_state": "validated" if validation.ok else "validation_failed",
            "validation": validation.to_dict(),
            "window_identity": _json_mapping(target_probe),
        }
        after_snapshot = {
            "schema_version": _SCHEMA_VERSION,
            "session": _prune(dict(session)),
            "window_identity": window_identity,
            "frames": list(frames),
            "frame_count": len(frames),
            "timing": dict(timing),
            "resource_cleanup": _json_mapping(cleanup),
            "rollback": rollback_plan,
            "errors": [_json_value(item) for item in errors],
            "target_state_modified": False,
        }
        artifact = _audit_artifact(plan.session_id, status)
        manifest_entry = {
            "path": artifact.path,
            "kind": artifact.kind,
            "role": "render-overlay-audit",
            "status": status,
            "session_id": plan.session_id,
            "target_identity": plan.target.to_dict(),
            "window_identity": window_identity,
            "precondition_hash": plan.precondition_hash,
            "frame_count": len(frames),
            "materialized": False,
        }
        provenance = {
            **_json_mapping(plan.provenance),
            "plan": plan.to_dict(),
            "validation": validation.to_dict(),
            "precondition_hash": plan.precondition_hash,
            "renderer": dict(_RENDERER_IDENTITY),
        }
        report_section = {
            "capability": self.capability_name,
            "provider": self.provider_name,
            "action": plan.action,
            "status": status,
            "session_id": plan.session_id,
            "target_identity": plan.target.to_dict(),
            "precondition_hash": plan.precondition_hash,
            "renderer": dict(_RENDERER_IDENTITY),
            "primitives": [dict(item) for item in plan.parameters.get("primitives") or []],
            "window_identity": window_identity,
            "frames": list(frames),
            "timing": dict(timing),
            "resource_cleanup": _json_mapping(cleanup),
            "errors": [_json_value(item) for item in errors],
            "before_snapshot": before_snapshot,
            "after_snapshot": after_snapshot,
            "rollback_plan": rollback_plan,
            "provenance": provenance,
            "artifacts": [artifact.to_dict()],
            "evidence_manifest_entries": [manifest_entry],
        }
        return CapabilityExecutionResult(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            rollback_plan=rollback_plan,
            artifacts=[artifact],
            evidence_manifest_entries=[manifest_entry],
            report_section=report_section,
            dashboard_trace=[
                {
                    "kind": "render_overlay_runtime",
                    "capability": self.capability_name,
                    "provider": self.provider_name,
                    "session_id": plan.session_id,
                    "status": status,
                    "frame_count": len(frames),
                    "window_identity": window_identity,
                    "resources_released": bool(cleanup.get("resources_released")),
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
        cleanup = _json_mapping(details.get("cleanup"))
        result.rollback_plan.update(
            {
                "active": not ok,
                "completed": ok,
                "status": "completed" if ok else "failed",
                "cleanup": cleanup or result.rollback_plan.get("cleanup", {}),
            }
        )
        if ok:
            result.rollback_plan.pop("runtime_key", None)
            result.after_snapshot["session"]["state"] = "closed"
            result.after_snapshot["session"]["active"] = False
            result.after_snapshot["session"].pop("runtime_key", None)
            if cleanup:
                result.after_snapshot["resource_cleanup"] = cleanup
        result.after_snapshot["rollback"] = dict(result.rollback_plan)
        result.report_section["after_snapshot"] = result.after_snapshot
        result.report_section["resource_cleanup"] = result.after_snapshot.get(
            "resource_cleanup",
            {},
        )
        result.report_section["rollback_plan"] = dict(result.rollback_plan)
        result.dashboard_trace.append(
            {
                "kind": "render_overlay_rollback",
                "capability": self.capability_name,
                "provider": self.provider_name,
                "session_id": result.session_id,
                "status": str(details.get("status") or "failed"),
                "resources_released": bool(details.get("resources_released")),
            }
        )

    def _select_backend(
        self,
        context: Optional[dict[str, Any]],
    ) -> RenderOverlayBackend:
        if isinstance(context, Mapping):
            candidate = context.get("render_overlay_backend")
            if candidate is not None:
                return candidate
        return self.backend


def _normalize_action(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    return _ACTION_ALIASES.get(normalized, normalized)


def _declared_pid(
    target: TargetIdentity,
    params: Mapping[str, Any],
) -> tuple[Optional[int], list[str]]:
    errors: list[str] = []
    target_pid = _positive_pid(target.pid)
    if target.pid is not None and target_pid is None:
        errors.append("target PID must be a positive 32-bit integer")
    param_pid = _positive_pid(params.get("pid"))
    if params.get("pid") is not None and param_pid is None:
        errors.append("params.pid must be a positive 32-bit integer")
    if target_pid is not None and param_pid is not None and target_pid != param_pid:
        errors.append("target.pid and params.pid must match")
    return target_pid or param_pid, errors


def _declared_hwnd(
    target: TargetIdentity,
    params: Mapping[str, Any],
) -> tuple[Optional[int], list[str]]:
    errors: list[str] = []
    metadata = _json_mapping(target.metadata)
    metadata_value = metadata.get("hwnd")
    metadata_hwnd = _positive_handle(metadata_value)
    if metadata_value is not None and metadata_hwnd is None:
        errors.append("target.metadata.hwnd must be a positive window handle")
    parameter_value = params.get("hwnd")
    parameter_hwnd = _positive_handle(parameter_value)
    if parameter_value is not None and parameter_hwnd is None:
        errors.append("params.hwnd must be a positive window handle")
    if (
        metadata_hwnd is not None
        and parameter_hwnd is not None
        and metadata_hwnd != parameter_hwnd
    ):
        errors.append("target.metadata.hwnd and params.hwnd must match")
    return parameter_hwnd or metadata_hwnd, errors


def _normalize_primitives(value: Any) -> tuple[list[dict[str, Any]], list[str]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return [], ["primitives must be a non-empty sequence"]
    if not value:
        return [], ["primitives must not be empty"]
    if len(value) > _MAX_PRIMITIVES:
        return [], [f"primitive count must not exceed {_MAX_PRIMITIVES}"]
    normalized: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            errors.append(f"primitives[{index}] must be a mapping")
            continue
        primitive, item_errors = _normalize_primitive(item)
        errors.extend(f"primitives[{index}]: {message}" for message in item_errors)
        if not item_errors:
            normalized.append(primitive)
    return normalized, errors


def _normalize_primitive(
    primitive: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    kind = str(primitive.get("type") or "").strip().lower()
    if kind not in {"line", "rect", "circle", "text"}:
        return {}, ["type must be line, rect, circle, or text"]
    allowed = {
        "line": {"type", "x1", "y1", "x2", "y2", "color", "width", "stroke_width"},
        "rect": {"type", "x", "y", "width", "height", "color", "stroke_width", "filled"},
        "circle": {
            "type",
            "x",
            "y",
            "cx",
            "cy",
            "center_x",
            "center_y",
            "radius",
            "color",
            "stroke_width",
            "filled",
        },
        "text": {"type", "x", "y", "text", "color", "font_size"},
    }[kind]
    errors: list[str] = []
    unknown = sorted(set(primitive) - allowed)
    if unknown:
        errors.append("unsupported fields: " + ", ".join(str(item) for item in unknown))
    color, color_error = _normalize_color(primitive.get("color"))
    if color_error:
        errors.append(color_error)

    if kind == "line":
        values = {
            key: _coordinate(primitive.get(key), key, errors)
            for key in ("x1", "y1", "x2", "y2")
        }
        width_value = primitive.get("width", primitive.get("stroke_width", 1))
        if "width" in primitive and "stroke_width" in primitive:
            if primitive["width"] != primitive["stroke_width"]:
                errors.append("width and stroke_width must match when both are provided")
        width = _bounded_int_value(width_value, "width", 1, _MAX_PEN_WIDTH, errors)
        return {"type": kind, **values, "color": color, "width": width}, errors

    if kind == "rect":
        x = _coordinate(primitive.get("x"), "x", errors)
        y = _coordinate(primitive.get("y"), "y", errors)
        width = _bounded_int_value(
            primitive.get("width"),
            "width",
            1,
            _MAX_COORDINATE,
            errors,
        )
        height = _bounded_int_value(
            primitive.get("height"),
            "height",
            1,
            _MAX_COORDINATE,
            errors,
        )
        stroke_width = _bounded_int_value(
            primitive.get("stroke_width", 1),
            "stroke_width",
            1,
            _MAX_PEN_WIDTH,
            errors,
        )
        filled = _boolean(primitive.get("filled", False), "filled", errors)
        return {
            "type": kind,
            "x": x,
            "y": y,
            "width": width,
            "height": height,
            "color": color,
            "stroke_width": stroke_width,
            "filled": filled,
        }, errors

    if kind == "circle":
        x = _coordinate_alias(primitive, ("x", "cx", "center_x"), "x", errors)
        y = _coordinate_alias(primitive, ("y", "cy", "center_y"), "y", errors)
        radius = _bounded_int_value(
            primitive.get("radius"),
            "radius",
            1,
            _MAX_COORDINATE,
            errors,
        )
        stroke_width = _bounded_int_value(
            primitive.get("stroke_width", 1),
            "stroke_width",
            1,
            _MAX_PEN_WIDTH,
            errors,
        )
        filled = _boolean(primitive.get("filled", False), "filled", errors)
        return {
            "type": kind,
            "x": x,
            "y": y,
            "radius": radius,
            "color": color,
            "stroke_width": stroke_width,
            "filled": filled,
        }, errors

    x = _coordinate(primitive.get("x"), "x", errors)
    y = _coordinate(primitive.get("y"), "y", errors)
    text_value = primitive.get("text")
    if not isinstance(text_value, str) or not text_value:
        errors.append("text must be a non-empty string")
        text_value = ""
    elif len(text_value) > _MAX_TEXT_LENGTH:
        errors.append(f"text length must not exceed {_MAX_TEXT_LENGTH}")
    elif any(character in text_value for character in ("\x00", "\r", "\n")):
        errors.append("text must not contain NUL or line-break characters")
    font_size = _bounded_int_value(
        primitive.get("font_size", 16),
        "font_size",
        6,
        _MAX_FONT_SIZE,
        errors,
    )
    return {
        "type": kind,
        "x": x,
        "y": y,
        "text": text_value,
        "color": color,
        "font_size": font_size,
    }, errors


def _normalize_color(value: Any) -> tuple[str, Optional[str]]:
    if isinstance(value, str):
        text = value.strip().upper()
        if re.fullmatch(r"#[0-9A-F]{6}", text):
            if text == _TRANSPARENCY_COLOR:
                return text, f"color {_TRANSPARENCY_COLOR} is reserved for transparency"
            return text, None
        return "#000000", "color must use #RRGGBB or a three-byte RGB sequence"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) == 3 and all(_is_int(item) and 0 <= int(item) <= 255 for item in value):
            color = "#" + "".join(f"{int(item):02X}" for item in value)
            if color == _TRANSPARENCY_COLOR:
                return color, f"color {_TRANSPARENCY_COLOR} is reserved for transparency"
            return color, None
    return "#000000", "color must use #RRGGBB or a three-byte RGB sequence"


def _coordinate(value: Any, name: str, errors: list[str]) -> int:
    return _bounded_int_value(
        value,
        name,
        -_MAX_COORDINATE,
        _MAX_COORDINATE,
        errors,
    )


def _coordinate_alias(
    primitive: Mapping[str, Any],
    keys: tuple[str, ...],
    canonical: str,
    errors: list[str],
) -> int:
    supplied = [(key, primitive[key]) for key in keys if key in primitive]
    if not supplied:
        errors.append(f"{canonical} is required")
        return 0
    values = {json.dumps(_json_value(value), sort_keys=True) for _, value in supplied}
    if len(values) > 1:
        errors.append(f"{', '.join(keys)} aliases must match")
    return _coordinate(supplied[0][1], canonical, errors)


def _bounded_int_value(
    value: Any,
    name: str,
    minimum: int,
    maximum: int,
    errors: list[str],
) -> int:
    if not _is_int(value):
        errors.append(f"{name} must be an integer")
        return minimum
    integer = int(value)
    if integer < minimum or integer > maximum:
        errors.append(f"{name} must be between {minimum} and {maximum}")
    return integer


def _boolean(value: Any, name: str, errors: list[str]) -> bool:
    if not isinstance(value, bool):
        errors.append(f"{name} must be a boolean")
        return False
    return value


def _plan_schema_errors(
    plan: CapabilityPlan,
    capability_name: str,
    provider_name: str,
) -> list[str]:
    errors: list[str] = []
    if plan.capability != capability_name:
        errors.append(f"plan capability must be {capability_name}")
    if plan.provider != provider_name:
        errors.append(f"plan provider must be {provider_name}")
    if plan.action != _ACTION:
        errors.append("plan action must be render")
    if not str(plan.session_id or "").strip():
        errors.append("plan session_id must be non-empty")
    command_errors = plan.parameters.get("command_errors")
    if not isinstance(command_errors, list):
        errors.append("plan command_errors must be a list")
    else:
        errors.extend(str(item) for item in command_errors if str(item))
    primitives, primitive_errors = _normalize_primitives(plan.parameters.get("primitives"))
    errors.extend(primitive_errors)
    if not primitive_errors and primitives != plan.parameters.get("primitives"):
        errors.append("plan primitives are not in canonical form")
    duration, duration_error = _bounded_parameter(
        plan.parameters.get("duration_ms"),
        "duration_ms",
        minimum=0,
        maximum=_MAX_DURATION_MS,
    )
    interval, interval_error = _bounded_parameter(
        plan.parameters.get("frame_interval_ms"),
        "frame_interval_ms",
        minimum=_MIN_FRAME_INTERVAL_MS,
        maximum=_MAX_FRAME_INTERVAL_MS,
    )
    del duration, interval
    if duration_error:
        errors.append(duration_error)
    if interval_error:
        errors.append(interval_error)
    pid = _positive_pid(plan.parameters.get("pid"))
    hwnd = _positive_handle(plan.parameters.get("hwnd"))
    if pid is None and hwnd is None:
        errors.append("plan target PID or HWND is required")
    expected = _plan_fingerprint(plan.action, plan.target, plan.parameters)
    if not plan.precondition_hash or plan.precondition_hash != expected:
        errors.append("plan precondition hash does not match the bounded overlay command")
    return _dedupe(errors)


def _target_probe_errors(
    plan: CapabilityPlan,
    probe: Mapping[str, Any],
) -> list[str]:
    status = str(probe.get("status") or "failed")
    if status == "unavailable":
        return []
    errors: list[str] = []
    if status != "ok":
        errors.append(str(probe.get("reason") or "target window validation failed"))
        return errors
    if not bool(probe.get("interactive_desktop")):
        errors.append("no interactive desktop is available")
    if not bool(probe.get("exists")):
        errors.append("target window does not exist")
    if not bool(probe.get("visible")):
        errors.append("target window is not visible")
    if not bool(probe.get("owner_pid_matches")):
        errors.append("target HWND ownership does not match the declared PID")
    actual_pid = _positive_pid(probe.get("pid"))
    actual_hwnd = _positive_handle(probe.get("hwnd"))
    expected_pid = _positive_pid(plan.parameters.get("pid"))
    expected_hwnd = _positive_handle(plan.parameters.get("hwnd"))
    if actual_pid is None:
        errors.append("target window owner PID is unavailable")
    elif expected_pid is not None and actual_pid != expected_pid:
        errors.append("target window ownership PID differs from the plan")
    if actual_hwnd is None:
        errors.append("target HWND is unavailable")
    elif expected_hwnd is not None and actual_hwnd != expected_hwnd:
        errors.append("resolved target HWND differs from the plan")
    rect = _json_mapping(probe.get("client_rect"))
    width = rect.get("width")
    height = rect.get("height")
    if not _is_int(width) or not _is_int(height) or int(width) <= 0 or int(height) <= 0:
        errors.append("target window client rect must have positive width and height")
    return _dedupe(errors)


def _primitive_bounds_errors(
    primitives: Sequence[Mapping[str, Any]],
    rect: Mapping[str, Any],
) -> list[str]:
    width = int(rect.get("width") or 0)
    height = int(rect.get("height") or 0)
    errors: list[str] = []
    for index, primitive in enumerate(primitives):
        kind = str(primitive["type"])
        if kind == "line":
            points = (
                (int(primitive["x1"]), int(primitive["y1"])),
                (int(primitive["x2"]), int(primitive["y2"])),
            )
            if any(x < 0 or y < 0 or x >= width or y >= height for x, y in points):
                errors.append(f"primitives[{index}] line coordinates exceed the client rect")
        elif kind == "rect":
            x = int(primitive["x"])
            y = int(primitive["y"])
            right = x + int(primitive["width"])
            bottom = y + int(primitive["height"])
            if x < 0 or y < 0 or right > width or bottom > height:
                errors.append(f"primitives[{index}] rectangle exceeds the client rect")
        elif kind == "circle":
            x = int(primitive["x"])
            y = int(primitive["y"])
            radius = int(primitive["radius"])
            if x - radius < 0 or y - radius < 0 or x + radius > width or y + radius > height:
                errors.append(f"primitives[{index}] circle exceeds the client rect")
        else:
            x = int(primitive["x"])
            y = int(primitive["y"])
            if x < 0 or y < 0 or x >= width or y >= height:
                errors.append(f"primitives[{index}] text origin exceeds the client rect")
    return errors


def _plan_fingerprint(
    action: str,
    target: TargetIdentity,
    parameters: Mapping[str, Any],
) -> str:
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "action": action,
        "target": target.to_dict(),
        "pid": parameters.get("pid"),
        "hwnd": parameters.get("hwnd"),
        "duration_ms": parameters.get("duration_ms"),
        "frame_interval_ms": parameters.get("frame_interval_ms"),
        "primitives": parameters.get("primitives"),
        "command_errors": parameters.get("command_errors"),
        "renderer": parameters.get("renderer"),
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _runtime_options(plan: CapabilityPlan) -> dict[str, Any]:
    return {
        "pid": plan.parameters.get("pid"),
        "hwnd": plan.parameters.get("hwnd"),
        "duration_ms": plan.parameters.get("duration_ms"),
        "frame_interval_ms": plan.parameters.get("frame_interval_ms"),
        "renderer": dict(_RENDERER_IDENTITY),
    }


def _backend_info(backend: Any) -> dict[str, Any]:
    available = _backend_available(backend)
    return _prune(
        {
            "name": str(getattr(backend, "name", type(backend).__name__)),
            "available": available,
            "unavailable_reason": (
                None
                if available
                else str(
                    getattr(backend, "unavailable_reason", None)
                    or "backend reported unavailable"
                )
            ),
        }
    )


def _backend_available(backend: Any) -> bool:
    return bool(getattr(backend, "available", False))


def _destroy_overlay(backend: RenderOverlayBackend, session: Any) -> dict[str, Any]:
    try:
        payload = _json_mapping(backend.destroy_overlay(session))
        if not payload:
            return {
                "ok": False,
                "resources_released": False,
                "error": "overlay backend returned an empty cleanup result",
            }
        payload.setdefault("resources_released", bool(payload.get("ok")))
        return payload
    except Exception as exc:  # noqa: BLE001 - cleanup failure becomes evidence
        return {
            "ok": False,
            "resources_released": False,
            "error": _exception_payload(exc, phase="cleanup"),
        }


def _inactive_cleanup(reason: str) -> dict[str, Any]:
    return {
        "ok": True,
        "not_required": True,
        "window_destroyed": False,
        "resources_released": True,
        "reason": reason,
    }


def _empty_timing(plan: CapabilityPlan) -> dict[str, Any]:
    return {
        "started_at": _utc_now(),
        "ended_at": _utc_now(),
        "requested_duration_ms": plan.parameters.get("duration_ms"),
        "frame_interval_ms": plan.parameters.get("frame_interval_ms"),
        "scheduled_elapsed_ms": 0,
        "actual_duration_ms": 0.0,
        "frame_count": 0,
    }


def _audit_artifact(session_id: str, status: str) -> CapabilityArtifact:
    safe_session = _safe_segment(session_id or "render-overlay-session")
    return CapabilityArtifact(
        path=f"render-overlay/{safe_session}/render-overlay-audit.json",
        kind="render-overlay-audit",
        description="External Win32 GDI overlay frame, timing, window, and cleanup evidence",
        metadata={
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "materialized": False,
        },
    )


def _manifest_entry(
    result: CapabilityExecutionResult,
    artifact: CapabilityArtifact,
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "role": "render-overlay-audit",
        "status": result.status,
        "session_id": result.session_id,
        "target_identity": result.target.to_dict(),
        "window_identity": _json_mapping(result.after_snapshot.get("window_identity")),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "frame_count": len(result.after_snapshot.get("frames") or []),
        "materialized": False,
    }


def _artifact_payload(result: CapabilityExecutionResult) -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "capability": result.capability,
        "provider": result.provider,
        "session_id": result.session_id,
        "action": result.action,
        "status": result.status,
        "target_identity": result.target.to_dict(),
        "precondition_hash": result.provenance.get("precondition_hash"),
        "renderer": dict(_RENDERER_IDENTITY),
        "primitives": list(result.report_section.get("primitives") or []),
        "window_identity": _json_mapping(result.after_snapshot.get("window_identity")),
        "frames": list(result.after_snapshot.get("frames") or []),
        "frame_count": len(result.after_snapshot.get("frames") or []),
        "timing": _json_mapping(result.after_snapshot.get("timing")),
        "resource_cleanup": _json_mapping(
            result.after_snapshot.get("resource_cleanup")
        ),
        "before_snapshot": _json_mapping(result.before_snapshot),
        "after_snapshot": _json_mapping(result.after_snapshot),
        "rollback_plan": _json_mapping(result.rollback_plan),
        "provenance": _json_mapping(result.provenance),
        "evidence_manifest_entries": list(result.evidence_manifest_entries or []),
    }


def _artifact_destination(collection_root: Path, artifact_path: str) -> Path:
    relative = Path(str(artifact_path))
    if relative.is_absolute() or relative.drive:
        raise ValueError("artifact path must be relative to the collection directory")
    destination = (collection_root / relative).resolve()
    if destination != collection_root and collection_root not in destination.parents:
        raise ValueError("artifact path escapes the collection directory")
    return destination


def _safe_segment(value: str) -> str:
    segment = _SAFE_SEGMENT_RE.sub("-", str(value)).strip(".-")
    return segment[:128] or "render-overlay-session"


def _bounded_parameter(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> tuple[Optional[int], Optional[str]]:
    if not _is_int(value):
        return None, f"{name} must be an integer"
    integer = int(value)
    if integer < minimum or integer > maximum:
        return None, f"{name} must be between {minimum} and {maximum}"
    return integer, None


def _bounded_default(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    default: int,
) -> int:
    normalized, error = _bounded_parameter(
        value,
        "value",
        minimum=minimum,
        maximum=maximum,
    )
    return default if error or normalized is None else normalized


def _positive_pid(value: Any) -> Optional[int]:
    if not _is_int(value):
        return None
    integer = int(value)
    return integer if 0 < integer <= _MAX_PID else None


def _positive_handle(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        integer = value
    elif isinstance(value, str):
        text = value.strip().lower()
        try:
            integer = int(text, 16 if text.startswith("0x") else 10)
        except ValueError:
            return None
    else:
        return None
    max_handle = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8)) - 1
    return integer if 0 < integer <= max_handle else None


def _rgb_from_color(value: str) -> tuple[int, int, int]:
    return int(value[1:3], 16), int(value[3:5], 16), int(value[5:7], 16)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _json_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    return {}


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _json_value(to_dict())
    return str(value)[:1_024]


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


def _dedupe(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value)
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def _exception_payload(exc: BaseException, *, phase: str) -> dict[str, Any]:
    return {
        "phase": phase,
        "type": type(exc).__name__,
        "message": str(exc),
    }


def _elapsed_ms(started_ns: int, ended_ns: int) -> float:
    return round(max(0, ended_ns - started_ns) / 1_000_000.0, 3)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = [
    "RenderOverlayBackend",
    "RenderOverlayProvider",
    "WindowsGDIOverlayBackend",
]
