"""Harmless local process used by the gated Frida hook runtime smoke tests."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable


def _target_api() -> tuple[str, str, Callable[[], Any]]:
    if sys.platform == "win32":
        library = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        function = library.GetCurrentProcessId
        function.argtypes = []
        function.restype = ctypes.c_ulong
        return "kernel32.dll", "GetCurrentProcessId", function

    if sys.platform.startswith("linux"):
        module = ctypes.util.find_library("c") or "libc.so.6"
        library = ctypes.CDLL(module)
        function = library.getpid
        function.argtypes = []
        function.restype = ctypes.c_int
        return Path(module).name, "getpid", function

    if sys.platform == "darwin":
        module = ctypes.util.find_library("c") or "/usr/lib/libSystem.B.dylib"
        library = ctypes.CDLL(module)
        function = library.getpid
        function.argtypes = []
        function.restype = ctypes.c_int
        return Path(module).name, "getpid", function

    raise RuntimeError(f"unsupported smoke-test platform: {sys.platform}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--interval", type=float, default=0.005)
    args = parser.parse_args()

    try:
        module, export, function = _target_api()
    except RuntimeError as exc:
        print(json.dumps({"event": "unsupported", "reason": str(exc)}), flush=True)
        return 2

    identity = {
        "event": "description" if args.describe else "ready",
        "pid": os.getpid(),
        "module": module,
        "export": export,
        "platform": sys.platform,
    }
    if not args.quiet or args.describe:
        print(json.dumps(identity, sort_keys=True), flush=True)
    if args.describe:
        return 0

    deadline = time.monotonic() + max(0.0, args.duration)
    interval = max(0.001, args.interval)
    while time.monotonic() < deadline:
        function()
        time.sleep(interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
