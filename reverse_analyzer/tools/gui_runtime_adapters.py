"""Bounded adapters for live GUI accessibility providers.

The adapters in this module only inspect an already-running process or device.
They never launch the analyzed artifact.  Command runners are injectable so
parsing and execution boundaries can be tested without invoking host tools.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, Iterable, Mapping, Sequence
from xml.etree import ElementTree


WINDOWS_UIA_BACKEND = "windows-uia-powershell"
ANDROID_UIAUTOMATOR_BACKEND = "android-uiautomator"
IOS_ACCESSIBILITY_BACKEND = "ios-accessibility-provider"

DEFAULT_PROVIDER_TIMEOUT_SECONDS = 20.0
MAX_PROVIDER_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_WINDOWS = 100
MAX_CONTROLS = 2_000
MAX_TEXT_CHARS = 4_096
IOS_PROVIDER_ENV = "REVERSE_ANALYZER_IOS_UI_PROVIDER"

ExecutableFinder = Callable[[str], str | None]
CommandRunner = Callable[..., Any]


@dataclass(frozen=True, slots=True)
class CommandOutput:
    """Captured output from an injected or local provider command."""

    returncode: int
    stdout: str
    stderr: str


class CommandBoundaryError(RuntimeError):
    """Base class for failures enforced by the bounded command runner."""


class CommandTimeoutError(CommandBoundaryError):
    """The provider command exceeded its execution deadline."""


class CommandOutputLimitError(CommandBoundaryError):
    """The provider command exceeded its combined output allowance."""


class RuntimeProviderError(RuntimeError):
    """Base error carrying structured provider-attempt metadata."""

    status = "failed"

    def __init__(
        self,
        reason: str,
        *,
        backend: str,
        provenance: Mapping[str, Any] | None = None,
    ) -> None:
        self.backend = backend
        self.reason = _limit_text(reason, 1_000)
        self.provenance = dict(provenance or {})
        super().__init__(self.reason)

    def as_attempt(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "status": self.status,
            "reason": self.reason,
            "provenance": dict(self.provenance),
        }


class RuntimeProviderUnavailable(RuntimeProviderError):
    """The host does not expose the requested provider."""

    status = "unavailable"


class RuntimeProviderExecutionError(RuntimeProviderError):
    """A discovered provider command failed while collecting evidence."""


class RuntimeProviderParseError(RuntimeProviderError):
    """Provider output was empty, malformed, or outside the accepted schema."""


def run_bounded_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
) -> CommandOutput:
    """Run an argv-only command while bounding time and captured output.

    stdout and stderr are drained concurrently so a noisy provider cannot
    deadlock on a full pipe.  Once their combined byte count crosses the limit,
    the process is killed and no additional output is retained.
    """

    argv = _validate_command(command)
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be a positive finite number")
    if not isinstance(max_output_bytes, int) or max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be a positive integer")

    creationflags = 0
    if os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    process = subprocess.Popen(  # noqa: S603 - argv is explicit and shell=False.
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creationflags,
    )
    assert process.stdout is not None
    assert process.stderr is not None

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    output_size = 0
    output_lock = threading.Lock()
    overflow = threading.Event()

    def drain(stream: Any, sink: list[bytes]) -> None:
        nonlocal output_size
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                with output_lock:
                    remaining = max(0, max_output_bytes - output_size)
                    if remaining:
                        sink.append(chunk[:remaining])
                    output_size += len(chunk)
                    exceeded = output_size > max_output_bytes
                if exceeded:
                    overflow.set()
                    _kill_process(process)
        except (OSError, ValueError):
            return

    readers = [
        threading.Thread(target=drain, args=(process.stdout, stdout_chunks), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_chunks), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process(process)
        process.wait()
    finally:
        for reader in readers:
            reader.join(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
        for reader in readers:
            reader.join(timeout=0.2)

    if overflow.is_set():
        raise CommandOutputLimitError(f"provider output exceeded {max_output_bytes} bytes")
    if timed_out:
        raise CommandTimeoutError(f"provider command exceeded {timeout:g} seconds")

    return CommandOutput(
        returncode=int(process.returncode or 0),
        stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
    )


def probe_windows_uia(
    process_id: int,
    *,
    runner: CommandRunner = run_bounded_command,
    timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
    platform_name: str | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> Dict[str, Any]:
    """Collect a process UI tree through PowerShell and .NET UIAutomation."""

    backend = WINDOWS_UIA_BACKEND
    host_platform = platform_name or os.name
    if host_platform != "nt":
        raise RuntimeProviderUnavailable(
            "Windows UI Automation is only available on Windows",
            backend=backend,
            provenance={"host_platform": host_platform, "target_executed": False},
        )
    try:
        pid = int(process_id)
    except (TypeError, ValueError) as exc:
        raise RuntimeProviderUnavailable(
            "Windows UI Automation requires a positive attached process id",
            backend=backend,
            provenance={"target_executed": False},
        ) from exc
    if pid <= 0:
        raise RuntimeProviderUnavailable(
            "Windows UI Automation requires a positive attached process id",
            backend=backend,
            provenance={"process_id": pid, "target_executed": False},
        )

    powershell = _first_executable(("powershell.exe", "powershell", "pwsh"), executable_finder)
    provenance = {
        "provider": "System.Windows.Automation",
        "transport": "PowerShell encoded command",
        "source": "live attached process",
        "process_id": pid,
        "target_executed": False,
    }
    if not powershell:
        raise RuntimeProviderUnavailable(
            "PowerShell was not found; .NET UIAutomation provider cannot be loaded",
            backend=backend,
            provenance=provenance,
        )
    provenance["executable"] = str(powershell)

    script = _WINDOWS_UIA_SCRIPT.replace("__PROCESS_ID__", str(pid))
    script = script.replace("__MAX_WINDOWS__", str(MAX_WINDOWS))
    script = script.replace("__MAX_CONTROLS__", str(MAX_CONTROLS))
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
    output = _run_provider_command(
        command,
        backend=backend,
        provenance=provenance,
        operation="UIAutomation hierarchy dump",
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    try:
        tree = parse_windows_uia_json(output.stdout, max_output_bytes=max_output_bytes)
    except RuntimeProviderError as exc:
        exc.provenance.update(provenance)
        raise

    return {
        "status": "ok",
        "backend": backend,
        "coverage": {
            "scope": "attached-process",
            "hierarchy": "UI Automation top-level windows and descendants",
            "properties": [
                "automation_id",
                "control_type",
                "name",
                "bounds",
                "enabled",
                "offscreen",
                "class_name",
                "framework_id",
                "native_window_handle",
            ],
            "limits": {"windows": MAX_WINDOWS, "controls": MAX_CONTROLS},
            "truncated": bool(tree.get("truncated")),
        },
        "reason": "PowerShell/.NET UIAutomation provider completed for the attached process.",
        "provenance": provenance,
        **tree,
    }


def parse_windows_uia_json(
    payload: str | bytes,
    *,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
) -> Dict[str, Any]:
    """Strictly parse and normalize PowerShell UIAutomation JSON output."""

    backend = WINDOWS_UIA_BACKEND
    text = _bounded_payload(payload, max_output_bytes=max_output_bytes, backend=backend)
    value = _load_json_object(text, backend=backend)
    if "windows" not in value:
        raise RuntimeProviderParseError(
            "UIAutomation JSON is missing the windows collection",
            backend=backend,
        )
    return _normalize_window_collection(value, backend=backend)


def probe_android_uiautomator(
    *,
    adb_path: str | os.PathLike[str] | None = None,
    android_serial: str | None = None,
    runner: CommandRunner = run_bounded_command,
    timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
    executable_finder: ExecutableFinder = shutil.which,
) -> Dict[str, Any]:
    """Dump the current hierarchy from an already-connected Android target."""

    backend = ANDROID_UIAUTOMATOR_BACKEND
    requested_adb = os.fspath(adb_path) if adb_path else "adb"
    executable = _resolve_executable(requested_adb, executable_finder)
    provenance = {
        "provider": "Android uiautomator",
        "transport": "adb shell dump and exec-out cat",
        "source": "connected device current hierarchy",
        "android_serial": str(android_serial) if android_serial else None,
        "target_executed": False,
    }
    if not executable:
        raise RuntimeProviderUnavailable(
            f"adb not found: {_limit_text(requested_adb, 256)}",
            backend=backend,
            provenance=provenance,
        )
    provenance["executable"] = str(executable)

    prefix = [str(executable)]
    if android_serial:
        prefix.extend(["-s", _limit_text(str(android_serial), 256)])
    remote_path = "/sdcard/reverse_analyzer_uiautomator.xml"
    _run_provider_command(
        [*prefix, "shell", "uiautomator", "dump", remote_path],
        backend=backend,
        provenance=provenance,
        operation="uiautomator dump",
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    pulled = _run_provider_command(
        [*prefix, "exec-out", "cat", remote_path],
        backend=backend,
        provenance=provenance,
        operation="uiautomator XML read",
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    try:
        tree = parse_android_uiautomator_xml(pulled.stdout, max_output_bytes=max_output_bytes)
    except RuntimeProviderError as exc:
        exc.provenance.update(provenance)
        raise

    return {
        "status": "ok",
        "backend": backend,
        "coverage": {
            "scope": "connected-device-current-hierarchy",
            "hierarchy": "uiautomator XML nodes",
            "properties": [
                "automation_id",
                "control_type",
                "name",
                "bounds",
                "enabled",
                "offscreen",
                "resource_id",
                "content_description",
                "clickable",
            ],
            "limits": {"windows": 1, "controls": MAX_CONTROLS},
            "truncated": bool(tree.get("truncated")),
        },
        "reason": "Android uiautomator returned the connected device's current hierarchy.",
        "provenance": provenance,
        **tree,
    }


def parse_android_uiautomator_xml(
    payload: str | bytes,
    *,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
) -> Dict[str, Any]:
    """Strictly parse and normalize an injected uiautomator XML fixture."""

    backend = ANDROID_UIAUTOMATOR_BACKEND
    text = _bounded_payload(payload, max_output_bytes=max_output_bytes, backend=backend)
    raw_xml = _extract_xml(text, markers=("<?xml", "<hierarchy"), backend=backend)
    root = _parse_xml(raw_xml, backend=backend)
    if _local_tag(root.tag).lower() != "hierarchy":
        raise RuntimeProviderParseError(
            "uiautomator XML root must be hierarchy",
            backend=backend,
        )

    controls: list[Dict[str, Any]] = []
    truncated = False
    for node in root.iter():
        if _local_tag(node.tag).lower() != "node":
            continue
        if len(controls) >= MAX_CONTROLS:
            truncated = True
            break
        attributes = node.attrib
        class_name = _optional_text(attributes.get("class"))
        resource_id = _optional_text(attributes.get("resource-id"))
        text_value = _optional_text(attributes.get("text"))
        description = _optional_text(attributes.get("content-desc"))
        visible = _optional_bool(attributes.get("visible-to-user"))
        controls.append(
            {
                "automation_id": resource_id,
                "control_type": class_name,
                "name": text_value or description,
                "bounds": _android_bounds(attributes.get("bounds")),
                "enabled": _optional_bool(attributes.get("enabled")),
                "offscreen": (not visible) if visible is not None else None,
                "class_name": class_name,
                "resource_id": resource_id,
                "text": text_value,
                "content_description": description,
                "clickable": _optional_bool(attributes.get("clickable")),
            }
        )
    package = next(
        (str(item["resource_id"]).split(":", 1)[0] for item in controls if item.get("resource_id")),
        None,
    )
    return {
        "window_count": 1,
        "control_count": len(controls),
        "windows": [
            {
                "title": package or "Android UI hierarchy",
                "name": package or "Android UI hierarchy",
                "automation_id": None,
                "control_type": "hierarchy",
                "bounds": None,
                "enabled": None,
                "offscreen": None,
                "controls": controls,
                "control_count": len(controls),
            }
        ],
        "truncated": truncated,
        "raw_xml": raw_xml,
    }


def probe_ios_accessibility(
    *,
    provider_command: Sequence[str | os.PathLike[str]] | str | None = None,
    runner: CommandRunner = run_bounded_command,
    timeout_seconds: float = DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
    platform_name: str | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> Dict[str, Any]:
    """Run a configured macOS XCUITest/accessibility hierarchy provider.

    The command must print normalized JSON with a ``windows`` list, Appium page
    source JSON (``{"value": "<xml>..."}``), or XCUITest-style XML.  Merely
    having ``xcrun`` installed is not treated as a successful hierarchy probe.
    """

    backend = IOS_ACCESSIBILITY_BACKEND
    host_platform = platform_name or sys.platform
    if host_platform != "darwin":
        raise RuntimeProviderUnavailable(
            "iOS accessibility probing is only available on macOS",
            backend=backend,
            provenance={"host_platform": host_platform, "target_executed": False},
        )

    command_value: Sequence[str | os.PathLike[str]] | str | None = provider_command
    command_source = "argument"
    if command_value is None:
        command_value = os.environ.get(IOS_PROVIDER_ENV)
        command_source = f"environment:{IOS_PROVIDER_ENV}"
    if not command_value:
        xcrun = executable_finder("xcrun")
        reason = (
            "xcrun is available, but no accessibility hierarchy provider command was configured"
            if xcrun
            else "xcrun and an iOS accessibility hierarchy provider command are unavailable"
        )
        raise RuntimeProviderUnavailable(
            reason,
            backend=backend,
            provenance={
                "host_platform": host_platform,
                "xcrun": str(xcrun) if xcrun else None,
                "target_executed": False,
            },
        )

    try:
        command = _provider_command(command_value)
    except (TypeError, ValueError) as exc:
        raise RuntimeProviderUnavailable(
            f"invalid iOS provider command: {_limit_text(str(exc), 500)}",
            backend=backend,
            provenance={"command_source": command_source, "target_executed": False},
        ) from exc
    executable = _resolve_executable(command[0], executable_finder)
    provenance = {
        "provider": "configured iOS accessibility/XCUITest provider",
        "transport": "bounded argv command",
        "source": "already-running simulator or device session",
        "command_source": command_source,
        "target_executed": False,
    }
    if not executable:
        raise RuntimeProviderUnavailable(
            f"iOS provider executable not found: {_limit_text(command[0], 256)}",
            backend=backend,
            provenance=provenance,
        )
    command[0] = str(executable)
    provenance["executable"] = str(executable)
    production_runner = runner is run_bounded_command
    provenance.update(
        {
            "production_runner": production_runner,
            "provider_process_executed": production_runner,
            "execution_assurance": "production" if production_runner else "simulation",
            "production_evidence": production_runner,
        }
    )

    output = _run_provider_command(
        command,
        backend=backend,
        provenance=provenance,
        operation="iOS accessibility hierarchy dump",
        runner=runner,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
    )
    try:
        tree = parse_ios_accessibility_output(output.stdout, max_output_bytes=max_output_bytes)
    except RuntimeProviderError as exc:
        exc.provenance.update(provenance)
        raise

    return {
        "status": "ok" if production_runner else "simulated",
        "backend": backend,
        "coverage": {
            "scope": "configured-provider-current-hierarchy",
            "hierarchy": "XCUITest/Appium accessibility elements",
            "properties": ["automation_id", "control_type", "name", "bounds", "enabled", "offscreen"],
            "limits": {"windows": MAX_WINDOWS, "controls": MAX_CONTROLS},
            "truncated": bool(tree.get("truncated")),
        },
        "reason": (
            "Configured iOS accessibility provider returned a parseable current hierarchy."
            if production_runner
            else "Injected runner output was parsed as simulation evidence only."
        ),
        "provenance": provenance,
        **tree,
    }


def parse_ios_accessibility_output(
    payload: str | bytes,
    *,
    max_output_bytes: int = MAX_PROVIDER_OUTPUT_BYTES,
) -> Dict[str, Any]:
    """Parse normalized JSON or XCUITest/Appium XML without guessing success."""

    backend = IOS_ACCESSIBILITY_BACKEND
    text = _bounded_payload(payload, max_output_bytes=max_output_bytes, backend=backend)
    stripped = text.lstrip("\ufeff\r\n\t ")
    if stripped.startswith("{"):
        value = _load_json_object(stripped, backend=backend)
        page_source = value.get("value")
        if isinstance(page_source, str):
            return _parse_ios_xml(page_source, backend=backend, max_output_bytes=max_output_bytes)
        if "windows" not in value:
            raise RuntimeProviderParseError(
                "iOS provider JSON must contain windows or an XML value",
                backend=backend,
            )
        return _normalize_window_collection(value, backend=backend)
    return _parse_ios_xml(stripped, backend=backend, max_output_bytes=max_output_bytes)


def _parse_ios_xml(text: str, *, backend: str, max_output_bytes: int) -> Dict[str, Any]:
    bounded = _bounded_payload(text, max_output_bytes=max_output_bytes, backend=backend)
    raw_xml = _extract_xml(
        bounded,
        markers=("<?xml", "<AppiumAUT", "<XCUIElementType", "<Application", "<Window"),
        backend=backend,
    )
    root = _parse_xml(raw_xml, backend=backend)
    elements = list(root.iter())
    windows = [element for element in elements if _ios_element_kind(element) == "window"]
    if not windows:
        windows = [element for element in elements if _ios_element_kind(element) == "application"]
    if not windows:
        raise RuntimeProviderParseError(
            "iOS provider XML contains no application or window accessibility element",
            backend=backend,
        )

    normalized_windows: list[Dict[str, Any]] = []
    total_controls = 0
    truncated = len(windows) > MAX_WINDOWS
    for window_element in windows[:MAX_WINDOWS]:
        window = _normalize_ios_xml_element(window_element)
        controls: list[Dict[str, Any]] = []
        for child in window_element.iter():
            if child is window_element:
                continue
            if total_controls >= MAX_CONTROLS:
                truncated = True
                break
            controls.append(_normalize_ios_xml_element(child))
            total_controls += 1
        window["title"] = window.get("name")
        window["controls"] = controls
        window["control_count"] = len(controls)
        normalized_windows.append(window)
        if total_controls >= MAX_CONTROLS:
            break
    return {
        "window_count": len(normalized_windows),
        "control_count": total_controls,
        "windows": normalized_windows,
        "truncated": truncated,
        "raw_xml": raw_xml,
    }


def _run_provider_command(
    command: Sequence[str],
    *,
    backend: str,
    provenance: Mapping[str, Any],
    operation: str,
    runner: CommandRunner,
    timeout_seconds: float,
    max_output_bytes: int,
) -> CommandOutput:
    try:
        raw = runner(
            list(command),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
    except (CommandTimeoutError, subprocess.TimeoutExpired) as exc:
        raise RuntimeProviderExecutionError(
            f"{operation} timed out after {timeout_seconds:g} seconds",
            backend=backend,
            provenance=provenance,
        ) from exc
    except CommandOutputLimitError as exc:
        raise RuntimeProviderExecutionError(
            f"{operation} exceeded the {max_output_bytes}-byte output limit",
            backend=backend,
            provenance=provenance,
        ) from exc
    except RuntimeProviderError:
        raise
    except OSError as exc:
        raise RuntimeProviderUnavailable(
            f"unable to start {operation}: {type(exc).__name__}: {_limit_text(str(exc), 500)}",
            backend=backend,
            provenance=provenance,
        ) from exc
    except Exception as exc:
        raise RuntimeProviderExecutionError(
            f"{operation} runner failed: {type(exc).__name__}: {_limit_text(str(exc), 500)}",
            backend=backend,
            provenance=provenance,
        ) from exc

    output = _coerce_command_output(raw, backend=backend, max_output_bytes=max_output_bytes)
    if output.returncode != 0:
        detail = _limit_text((output.stderr or output.stdout or "no provider error output").strip(), 1_000)
        raise RuntimeProviderExecutionError(
            f"{operation} exited with code {output.returncode}: {detail}",
            backend=backend,
            provenance=provenance,
        )
    if not output.stdout.strip():
        raise RuntimeProviderParseError(
            f"{operation} returned empty output",
            backend=backend,
            provenance=provenance,
        )
    return output


def _coerce_command_output(raw: Any, *, backend: str, max_output_bytes: int) -> CommandOutput:
    try:
        returncode = int(raw.returncode)
        stdout = _decode_output(raw.stdout)
        stderr = _decode_output(raw.stderr)
    except (AttributeError, TypeError, ValueError) as exc:
        raise RuntimeProviderExecutionError(
            "provider runner returned an invalid command result",
            backend=backend,
        ) from exc
    _ensure_combined_output_limit(stdout, stderr, max_output_bytes=max_output_bytes, backend=backend)
    return CommandOutput(returncode=returncode, stdout=stdout, stderr=stderr)


def _ensure_combined_output_limit(
    stdout: str,
    stderr: str,
    *,
    max_output_bytes: int,
    backend: str,
) -> None:
    if len(stdout) + len(stderr) > max_output_bytes:
        raise RuntimeProviderExecutionError(
            f"provider output exceeded the {max_output_bytes}-byte output limit",
            backend=backend,
        )
    size = len(stdout.encode("utf-8", errors="replace")) + len(stderr.encode("utf-8", errors="replace"))
    if size > max_output_bytes:
        raise RuntimeProviderExecutionError(
            f"provider output exceeded the {max_output_bytes}-byte output limit",
            backend=backend,
        )


def _normalize_window_collection(value: Mapping[str, Any], *, backend: str) -> Dict[str, Any]:
    raw_windows = value.get("windows")
    if raw_windows is None:
        raw_windows = []
    if not isinstance(raw_windows, list):
        raise RuntimeProviderParseError("provider windows value must be a list", backend=backend)

    normalized_windows: list[Dict[str, Any]] = []
    total_controls = 0
    truncated = bool(value.get("truncated")) or len(raw_windows) > MAX_WINDOWS
    for raw_window in raw_windows[:MAX_WINDOWS]:
        if not isinstance(raw_window, Mapping):
            raise RuntimeProviderParseError("provider window entries must be objects", backend=backend)
        window = _normalize_element(raw_window)
        window["title"] = _optional_text(raw_window.get("title")) or window.get("name")
        controls: list[Dict[str, Any]] = []
        raw_controls = raw_window.get("controls")
        if raw_controls is None:
            raw_controls = raw_window.get("children") or []
        if not isinstance(raw_controls, list):
            raise RuntimeProviderParseError("provider controls value must be a list", backend=backend)
        for raw_control in _iter_control_mappings(raw_controls, backend=backend):
            if total_controls >= MAX_CONTROLS:
                truncated = True
                break
            controls.append(_normalize_element(raw_control))
            total_controls += 1
        window["controls"] = controls
        window["control_count"] = len(controls)
        normalized_windows.append(window)
        if total_controls >= MAX_CONTROLS:
            break
    return {
        "window_count": len(normalized_windows),
        "control_count": total_controls,
        "windows": normalized_windows,
        "truncated": truncated,
    }


def _iter_control_mappings(raw_controls: list[Any], *, backend: str) -> Iterable[Mapping[str, Any]]:
    stack = list(reversed(raw_controls))
    while stack:
        raw = stack.pop()
        if not isinstance(raw, Mapping):
            raise RuntimeProviderParseError("provider control entries must be objects", backend=backend)
        yield raw
        children = raw.get("children")
        if children is None:
            continue
        if not isinstance(children, list):
            raise RuntimeProviderParseError("provider control children must be a list", backend=backend)
        stack.extend(reversed(children))


def _normalize_element(raw: Mapping[str, Any]) -> Dict[str, Any]:
    control_type = _optional_text(raw.get("control_type") or raw.get("type"))
    if control_type and control_type.startswith("ControlType."):
        control_type = control_type.split(".", 1)[1]
    return {
        "automation_id": _optional_text(raw.get("automation_id") or raw.get("identifier")),
        "control_type": control_type,
        "name": _optional_text(raw.get("name") or raw.get("title")),
        "bounds": _normalize_bounds(raw.get("bounds") or raw.get("bounding_rectangle")),
        "enabled": _optional_bool(raw.get("enabled") if "enabled" in raw else raw.get("is_enabled")),
        "offscreen": _optional_bool(raw.get("offscreen") if "offscreen" in raw else raw.get("is_offscreen")),
        "class_name": _optional_text(raw.get("class_name") or raw.get("class")),
        "framework_id": _optional_text(raw.get("framework_id")),
        "native_window_handle": _optional_int(raw.get("native_window_handle") or raw.get("handle")),
        "process_id": _optional_int(raw.get("process_id")),
    }


def _normalize_ios_xml_element(element: ElementTree.Element) -> Dict[str, Any]:
    attributes = element.attrib
    control_type = _optional_text(attributes.get("type")) or _local_tag(element.tag)
    identifier = _optional_text(attributes.get("identifier") or attributes.get("uid"))
    name = _optional_text(attributes.get("name") or attributes.get("label") or attributes.get("value"))
    visible = _optional_bool(attributes.get("visible"))
    bounds_value: Mapping[str, Any] | str | None = {
        "left": attributes.get("x"),
        "top": attributes.get("y"),
        "width": attributes.get("width"),
        "height": attributes.get("height"),
    }
    if not any(value not in {None, ""} for value in bounds_value.values()):
        bounds_value = attributes.get("rect") or attributes.get("bounds")
    return {
        "automation_id": identifier,
        "control_type": control_type,
        "name": name,
        "bounds": _normalize_bounds(bounds_value),
        "enabled": _optional_bool(attributes.get("enabled")),
        "offscreen": (not visible) if visible is not None else None,
        "class_name": control_type,
        "framework_id": "XCUITest",
        "native_window_handle": None,
        "process_id": None,
    }


def _normalize_bounds(value: Any) -> Dict[str, int | float] | None:
    if isinstance(value, Mapping):
        left = _optional_number(value.get("left") if "left" in value else value.get("x"))
        top = _optional_number(value.get("top") if "top" in value else value.get("y"))
        width = _optional_number(value.get("width"))
        height = _optional_number(value.get("height"))
        right = _optional_number(value.get("right"))
        bottom = _optional_number(value.get("bottom"))
        if width is None and left is not None and right is not None:
            width = max(0, right - left)
        if height is None and top is not None and bottom is not None:
            height = max(0, bottom - top)
        if None in {left, top, width, height}:
            return None
        return {"left": left, "top": top, "width": max(0, width), "height": max(0, height)}
    numbers = [_optional_number(item) for item in re.findall(r"-?\d+(?:\.\d+)?", str(value or ""))]
    if len(numbers) != 4 or any(item is None for item in numbers):
        return None
    left, top, third, fourth = numbers
    assert left is not None and top is not None and third is not None and fourth is not None
    if str(value).strip().startswith("["):
        width = max(0, third - left)
        height = max(0, fourth - top)
    else:
        width = max(0, third)
        height = max(0, fourth)
    return {"left": left, "top": top, "width": width, "height": height}


def _android_bounds(value: Any) -> Dict[str, int | float] | None:
    numbers = [_optional_number(item) for item in re.findall(r"-?\d+", str(value or ""))]
    if len(numbers) != 4 or any(item is None for item in numbers):
        return None
    left, top, right, bottom = numbers
    assert left is not None and top is not None and right is not None and bottom is not None
    return {
        "left": left,
        "top": top,
        "width": max(0, right - left),
        "height": max(0, bottom - top),
    }


def _ios_element_kind(element: ElementTree.Element) -> str:
    element_type = str(element.attrib.get("type") or _local_tag(element.tag)).lower()
    if element_type.endswith("window") or element_type == "window":
        return "window"
    if element_type.endswith("application") or element_type == "application":
        return "application"
    return "control"


def _bounded_payload(payload: str | bytes, *, max_output_bytes: int, backend: str) -> str:
    if isinstance(payload, bytes):
        if len(payload) > max_output_bytes:
            raise RuntimeProviderParseError(
                f"provider output exceeded the {max_output_bytes}-byte parse limit",
                backend=backend,
            )
        return payload.decode("utf-8", errors="replace")
    if not isinstance(payload, str):
        raise RuntimeProviderParseError("provider output must be text or bytes", backend=backend)
    if len(payload) > max_output_bytes:
        raise RuntimeProviderParseError(
            f"provider output exceeded the {max_output_bytes}-byte parse limit",
            backend=backend,
        )
    if len(payload.encode("utf-8", errors="replace")) > max_output_bytes:
        raise RuntimeProviderParseError(
            f"provider output exceeded the {max_output_bytes}-byte parse limit",
            backend=backend,
        )
    if not payload.strip():
        raise RuntimeProviderParseError("provider output is empty", backend=backend)
    return payload


def _load_json_object(text: str, *, backend: str) -> Mapping[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        value = json.loads(text.lstrip("\ufeff"), parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise RuntimeProviderParseError(
            f"provider JSON parse failed: {_limit_text(str(exc), 500)}",
            backend=backend,
        ) from exc
    if not isinstance(value, Mapping):
        raise RuntimeProviderParseError("provider JSON root must be an object", backend=backend)
    return value


def _extract_xml(text: str, *, markers: Sequence[str], backend: str) -> str:
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise RuntimeProviderParseError("provider XML declarations and entities are not accepted", backend=backend)
    positions = [position for marker in markers if (position := text.find(marker)) >= 0]
    if not positions:
        raise RuntimeProviderParseError("provider output contains no recognized XML hierarchy", backend=backend)
    raw_xml = text[min(positions) :].strip()
    if not raw_xml:
        raise RuntimeProviderParseError("provider XML output is empty", backend=backend)
    return raw_xml


def _parse_xml(raw_xml: str, *, backend: str) -> ElementTree.Element:
    lowered = raw_xml.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise RuntimeProviderParseError("provider XML declarations and entities are not accepted", backend=backend)
    try:
        return ElementTree.fromstring(raw_xml)
    except ElementTree.ParseError as exc:
        raise RuntimeProviderParseError(
            f"provider XML parse failed: {_limit_text(str(exc), 500)}",
            backend=backend,
        ) from exc


def _provider_command(value: Sequence[str | os.PathLike[str]] | str) -> list[str]:
    if isinstance(value, str):
        command = shlex.split(value, posix=True)
    else:
        command = [os.fspath(item) for item in value]
    return _validate_command(command)


def _validate_command(command: Sequence[str | os.PathLike[str]]) -> list[str]:
    if isinstance(command, (str, bytes)):
        raise TypeError("command must be an argv sequence, not a shell string")
    argv = [os.fspath(item) for item in command]
    if not argv or not argv[0].strip():
        raise ValueError("command must contain an executable")
    if len(argv) > 128:
        raise ValueError("command contains too many arguments")
    if any("\x00" in item for item in argv):
        raise ValueError("command arguments cannot contain NUL bytes")
    if sum(len(item) for item in argv) > 128 * 1024:
        raise ValueError("command arguments exceed the size limit")
    return argv


def _resolve_executable(requested: str, executable_finder: ExecutableFinder) -> str | None:
    candidate = Path(requested).expanduser()
    if candidate.is_file():
        return str(candidate)
    return executable_finder(requested)


def _first_executable(names: Sequence[str], executable_finder: ExecutableFinder) -> str | None:
    for name in names:
        executable = executable_finder(name)
        if executable:
            return executable
    return None


def _decode_output(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    raise TypeError("command output must be text or bytes")


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.kill()
    except OSError:
        pass


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return _limit_text(text, MAX_TEXT_CHARS) if text else None


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    lowered = str(value).strip().lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return None


def _optional_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _optional_number(value: Any) -> int | float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    if number.is_integer():
        return int(number)
    return round(number, 3)


def _limit_text(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return f"{text[: max(0, limit - 3)]}..."


def _local_tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


_WINDOWS_UIA_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$targetPid = __PROCESS_ID__
$maxWindows = __MAX_WINDOWS__
$maxControls = __MAX_CONTROLS__
[void][System.Diagnostics.Process]::GetProcessById($targetPid)

function Convert-AutomationElement {
    param([System.Windows.Automation.AutomationElement]$Element)
    try {
        $current = $Element.Current
        $rect = $current.BoundingRectangle
        $controlType = $current.ControlType
        return [ordered]@{
            automation_id = [string]$current.AutomationId
            control_type = if ($null -ne $controlType) { [string]$controlType.ProgrammaticName } else { $null }
            name = [string]$current.Name
            bounds = [ordered]@{
                left = [double]$rect.Left
                top = [double]$rect.Top
                width = [double]$rect.Width
                height = [double]$rect.Height
            }
            enabled = [bool]$current.IsEnabled
            offscreen = [bool]$current.IsOffscreen
            class_name = [string]$current.ClassName
            framework_id = [string]$current.FrameworkId
            native_window_handle = [int]$current.NativeWindowHandle
            process_id = [int]$current.ProcessId
        }
    } catch {
        return $null
    }
}

$root = [System.Windows.Automation.AutomationElement]::RootElement
$pidCondition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::ProcessIdProperty,
    $targetPid
)
$topLevel = $root.FindAll([System.Windows.Automation.TreeScope]::Children, $pidCondition)
$windows = New-Object System.Collections.ArrayList
$controlCount = 0
$truncated = $false

foreach ($windowElement in $topLevel) {
    if ($windows.Count -ge $maxWindows) {
        $truncated = $true
        break
    }
    $windowInfo = Convert-AutomationElement -Element $windowElement
    if ($null -eq $windowInfo) {
        continue
    }
    $controls = New-Object System.Collections.ArrayList
    try {
        $descendants = $windowElement.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            [System.Windows.Automation.Condition]::TrueCondition
        )
        foreach ($child in $descendants) {
            if ($controlCount -ge $maxControls) {
                $truncated = $true
                break
            }
            $controlInfo = Convert-AutomationElement -Element $child
            if ($null -eq $controlInfo -or $controlInfo.process_id -ne $targetPid) {
                continue
            }
            [void]$controls.Add($controlInfo)
            $controlCount += 1
        }
    } catch {
        $windowInfo['descendant_error'] = [string]$_.Exception.Message
    }
    $windowInfo['title'] = $windowInfo.name
    $windowInfo['controls'] = @($controls.ToArray())
    $windowInfo['control_count'] = $controls.Count
    [void]$windows.Add($windowInfo)
    if ($controlCount -ge $maxControls) {
        break
    }
}

[ordered]@{
    schema_version = 1
    provider = 'System.Windows.Automation'
    process_id = $targetPid
    window_count = $windows.Count
    control_count = $controlCount
    truncated = $truncated
    windows = @($windows.ToArray())
} | ConvertTo-Json -Depth 7 -Compress
"""
