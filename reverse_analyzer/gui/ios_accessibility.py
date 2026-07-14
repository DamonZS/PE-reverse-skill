"""Bounded, read-only iOS accessibility inspection through Meta ``idb``.

The production adapter accepts one explicit target UDID, verifies that target
with ``idb describe``, and only dumps the hierarchy of an already-booted
simulator.  It never boots, installs, launches, focuses, taps, or otherwise
mutates the target.  Parser entry points remain platform independent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Mapping, Sequence
from xml.etree import ElementTree


IOS_ACCESSIBILITY_BACKEND = "ios-idb-accessibility"
IOS_ACCESSIBILITY_PROVIDER = "Meta idb"
IOS_ACCESSIBILITY_DEPENDENCY = "idb"
IOS_ACCESSIBILITY_TREE_SCHEMA = "reverse_analyzer.ios_accessibility_tree"
IOS_ACCESSIBILITY_TREE_SCHEMA_VERSION = "1.0"

_TREE_NODE_FIELDS = (
    "automation_id",
    "name",
    "control_type",
    "bounds",
    "enabled",
    "offscreen",
    "class_name",
    "framework_id",
    "process_id",
    "native_window_handle",
    "depth",
    "children",
)

DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_NODES = 5_000
DEFAULT_MAX_DEPTH = 32
DEFAULT_MAX_WINDOWS = 100
DEFAULT_MAX_TEXT_CHARS = 4_096

MAX_TIMEOUT_SECONDS = 120.0
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 128
MAX_WINDOWS = 1_000
MAX_TEXT_CHARS = 16_384
MAX_UDID_CHARS = 128
MAX_PATH_CHARS = 4_096
MAX_ARG_COUNT = 32
MAX_ARG_CHARS = 4_096
MAX_ALLOWED_ROOTS = 32

_IDB_BASENAMES = {"idb", "idb.exe"}
_TARGET_KINDS = {"simulator", "device"}
_UDID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,127}$")

ExecutableFinder = Callable[[str], str | None]
Clock = Callable[[], float]
Runner = Callable[..., Any]


class IOSAccessibilityError(RuntimeError):
    """Base class for bounded iOS accessibility failures."""


class IOSAccessibilityParseError(IOSAccessibilityError, ValueError):
    """Provider output is malformed or outside the accepted schema."""


class IOSCommandError(IOSAccessibilityError):
    """A local provider subprocess could not complete within its boundary."""


class IOSCommandTimeoutError(IOSCommandError, TimeoutError):
    """A local provider subprocess exceeded its deadline."""


class IOSCommandOutputLimitError(IOSCommandError):
    """A local provider subprocess exceeded its combined output budget."""


class IOSCommandLaunchError(IOSCommandError):
    """A local provider subprocess could not be started or reaped."""


class _DependencyUnavailable(IOSAccessibilityError):
    def __init__(self, code: str, reason: str, *, status: str = "unavailable") -> None:
        self.code = code
        self.reason = _limit_error(reason)
        self.status = status
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class IOSCommandOutput:
    """Decoded output and exact byte counts from one argv-only command."""

    returncode: int
    stdout: str
    stderr: str
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None


@dataclass(slots=True)
class _ProbeBudget:
    deadline: float
    max_output_bytes: int
    clock: Clock
    output_bytes: int = 0

    def remaining_seconds(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise IOSCommandTimeoutError("iOS accessibility probe exceeded its shared deadline")
        return remaining

    def remaining_output_bytes(self) -> int:
        remaining = self.max_output_bytes - self.output_bytes
        if remaining <= 0:
            raise IOSCommandOutputLimitError(
                "iOS accessibility probe exhausted its shared output budget"
            )
        return remaining


class SubprocessIOSAccessibilityRunner:
    """Run one local argv without a shell, stdin, cwd override, or unbounded pipes."""

    __slots__ = ()

    def __call__(
        self,
        command: Sequence[str | os.PathLike[str]],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> IOSCommandOutput:
        return self.run(
            command,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def run(
        self,
        command: Sequence[str | os.PathLike[str]],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> IOSCommandOutput:
        argv = _validate_argv(command)
        timeout = _positive_timeout(timeout_seconds, maximum=None)
        output_limit = _bounded_integer(
            max_output_bytes,
            "max_output_bytes",
            minimum=1,
            maximum=MAX_OUTPUT_BYTES,
        )

        creationflags = 0
        start_new_session = os.name != "nt"
        if os.name == "nt":
            creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            creationflags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv boundary; shell is disabled.
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
        except (OSError, ValueError) as exc:
            raise IOSCommandLaunchError(
                f"could not start iOS accessibility provider: {_limit_error(exc)}"
            ) from exc

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
                        remaining = max(0, output_limit - output_size)
                        if remaining:
                            sink.append(chunk[:remaining])
                        output_size += len(chunk)
                        exceeded = output_size > output_limit
                    if exceeded:
                        overflow.set()
                        _terminate_process(process)
                        return
            except (OSError, ValueError):
                return

        readers = [
            threading.Thread(
                target=drain,
                args=(process.stdout, stdout_chunks),
                name="reverse-analyzer-idb-stdout",
                daemon=True,
            ),
            threading.Thread(
                target=drain,
                args=(process.stderr, stderr_chunks),
                name="reverse-analyzer-idb-stderr",
                daemon=True,
            ),
        ]
        for reader in readers:
            reader.start()

        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process(process)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired as exc:
                raise IOSCommandLaunchError("timed-out iOS provider process could not be reaped") from exc
        except OSError as exc:
            _terminate_process(process)
            raise IOSCommandLaunchError(
                f"could not wait for iOS accessibility provider: {_limit_error(exc)}"
            ) from exc
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
            raise IOSCommandOutputLimitError(
                f"iOS accessibility provider output exceeded {output_limit} bytes"
            )
        if timed_out:
            raise IOSCommandTimeoutError(
                f"iOS accessibility provider exceeded {timeout:g} seconds"
            )

        stdout_raw = b"".join(stdout_chunks)
        stderr_raw = b"".join(stderr_chunks)
        return IOSCommandOutput(
            returncode=int(process.returncode or 0),
            stdout=stdout_raw.decode("utf-8", errors="replace"),
            stderr=stderr_raw.decode("utf-8", errors="replace"),
            stdout_bytes=len(stdout_raw),
            stderr_bytes=len(stderr_raw),
        )


@dataclass(frozen=True, slots=True)
class IOSAccessibilityAdapter:
    """Inspect one explicit, already-running iOS target through local ``idb``."""

    idb_path: str | os.PathLike[str] | None = None
    allowed_executable_roots: Sequence[str | os.PathLike[str]] | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES
    max_nodes: int = DEFAULT_MAX_NODES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_windows: int = DEFAULT_MAX_WINDOWS
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS
    runner: Runner | None = field(default=None, repr=False, compare=False)
    executable_finder: ExecutableFinder = field(
        default=shutil.which,
        repr=False,
        compare=False,
    )
    clock: Clock = field(default=time.monotonic, repr=False, compare=False)

    def __post_init__(self) -> None:
        _positive_timeout(self.timeout_seconds, maximum=MAX_TIMEOUT_SECONDS)
        _bounded_integer(
            self.max_output_bytes,
            "max_output_bytes",
            minimum=1,
            maximum=MAX_OUTPUT_BYTES,
        )
        _bounded_integer(self.max_nodes, "max_nodes", minimum=1, maximum=MAX_NODES)
        _bounded_integer(self.max_depth, "max_depth", minimum=0, maximum=MAX_DEPTH)
        _bounded_integer(self.max_windows, "max_windows", minimum=1, maximum=MAX_WINDOWS)
        _bounded_integer(
            self.max_text_chars,
            "max_text_chars",
            minimum=1,
            maximum=MAX_TEXT_CHARS,
        )
        if self.idb_path is not None and not isinstance(self.idb_path, (str, os.PathLike)):
            raise TypeError("idb_path must be a path-like value")
        if isinstance(self.allowed_executable_roots, (str, bytes, os.PathLike)):
            raise TypeError("allowed_executable_roots must be a sequence of path-like values")
        if self.allowed_executable_roots is not None:
            if not isinstance(self.allowed_executable_roots, Sequence):
                raise TypeError("allowed_executable_roots must be a sequence of path-like values")
            if len(self.allowed_executable_roots) > MAX_ALLOWED_ROOTS:
                raise ValueError(
                    f"allowed_executable_roots cannot contain more than {MAX_ALLOWED_ROOTS} entries"
                )
            for root in self.allowed_executable_roots:
                if not isinstance(root, (str, os.PathLike)):
                    raise TypeError("allowed_executable_roots entries must be path-like")
        if self.runner is not None and not (
            callable(self.runner) or callable(getattr(self.runner, "run", None))
        ):
            raise TypeError("runner must be callable or expose a callable run method")
        if not callable(self.executable_finder):
            raise TypeError("executable_finder must be callable")
        if not callable(self.clock):
            raise TypeError("clock must be callable")

    def probe(
        self,
        target_udid: str,
        *,
        target_kind: str = "simulator",
        platform_name: str | None = None,
    ) -> Dict[str, Any]:
        target, target_error = _normalize_target(target_udid, target_kind)
        result = _base_result(target, self)
        if target_error is not None:
            return _set_error(
                result,
                status="failed",
                code="target_invalid",
                reason=target_error,
                scope="target",
                provider_status="not_started",
            )

        host_platform = platform_name or sys.platform
        result["provenance"]["host_platform"] = host_platform
        if host_platform != "darwin":
            result["dependency"]["status"] = "not_checked"
            return _set_error(
                result,
                status="unavailable",
                code="platform_unavailable",
                reason="iOS accessibility probing through idb is only available on macOS",
                scope="platform",
                provider_status="unavailable",
            )

        started = self.clock()
        budget = _ProbeBudget(
            deadline=started + float(self.timeout_seconds),
            max_output_bytes=self.max_output_bytes,
            clock=self.clock,
        )
        command_runner = self.runner or SubprocessIOSAccessibilityRunner()
        production_runner = type(command_runner) is SubprocessIOSAccessibilityRunner
        result["provenance"].update(
            {
                "runner": type(command_runner).__name__,
                "production_runner": production_runner,
                "execution_assurance": (
                    "production" if production_runner else "simulation"
                ),
                "provider_process_executed": False,
            }
        )

        try:
            executable, executable_identity = _resolve_idb_executable(
                self.idb_path,
                executable_finder=self.executable_finder,
                allowed_roots=self.allowed_executable_roots,
            )
            budget.remaining_seconds()
        except _DependencyUnavailable as exc:
            result["dependency"]["status"] = exc.status
            return _finalize(
                _set_error(
                    result,
                    status="unavailable",
                    code=exc.code,
                    reason=exc.reason,
                    scope="dependency",
                    provider_status="unavailable",
                ),
                started,
                budget,
            )
        except IOSCommandTimeoutError as exc:
            return _finalize(
                _boundary_failure(result, exc),
                started,
                budget,
            )

        result["dependency"].update(
            {
                "status": "available",
                "path": executable,
                "identity": dict(executable_identity),
            }
        )
        result["provenance"]["executable"] = dict(executable_identity)

        describe_command = [
            executable,
            "describe",
            "--udid",
            target["udid"],
            "--json",
        ]
        try:
            describe = _invoke_runner(
                command_runner,
                describe_command,
                operation="describe-target",
                budget=budget,
                result=result,
                production_runner=production_runner,
            )
        except IOSCommandError as exc:
            return _finalize(_boundary_failure(result, exc), started, budget)
        if describe.returncode != 0:
            return _finalize(
                _command_failure(result, describe, operation="describe-target"),
                started,
                budget,
            )

        try:
            identity = parse_ios_target_identity(
                describe.stdout,
                max_output_bytes=self.max_output_bytes,
                max_text_chars=self.max_text_chars,
            )
        except IOSAccessibilityParseError as exc:
            return _finalize(
                _set_error(
                    result,
                    status="failed",
                    code="target_identity_invalid",
                    reason=str(exc),
                    scope="target",
                    provider_status="failed",
                    exc=exc,
                ),
                started,
                budget,
            )
        try:
            budget.remaining_seconds()
        except IOSCommandTimeoutError as exc:
            return _finalize(_boundary_failure(result, exc), started, budget)

        identity_error = _target_identity_error(target, identity)
        if identity_error is not None:
            if production_runner:
                _record_target_identity(result, identity, verified=False)
            return _finalize(
                _set_error(
                    result,
                    status="failed",
                    code="target_identity_mismatch",
                    reason=identity_error,
                    scope="target",
                    provider_status="failed",
                ),
                started,
                budget,
            )

        if production_runner:
            _record_target_identity(result, identity, verified=True)

        if identity["kind"] == "device":
            if not production_runner:
                _discard_untrusted_identity(result)
            return _finalize(
                _set_error(
                    result,
                    status="unavailable",
                    code="device_hierarchy_unsupported",
                    reason=(
                        "idb verified the requested physical device, but idb accessibility "
                        "hierarchy commands support booted simulators only"
                    ),
                    scope="provider",
                    provider_status="unsupported",
                ),
                started,
                budget,
            )

        if str(identity.get("state") or "").casefold() != "booted":
            if not production_runner:
                _discard_untrusted_identity(result)
            return _finalize(
                _set_error(
                    result,
                    status="unavailable",
                    code="target_not_booted",
                    reason="the verified simulator is not in the Booted state",
                    scope="target",
                    provider_status="available",
                ),
                started,
                budget,
            )

        hierarchy_command = [
            executable,
            "ui",
            "describe-all",
            "--udid",
            target["udid"],
            "--nested",
        ]
        try:
            hierarchy = _invoke_runner(
                command_runner,
                hierarchy_command,
                operation="dump-accessibility-hierarchy",
                budget=budget,
                result=result,
                production_runner=production_runner,
            )
        except IOSCommandError as exc:
            return _finalize(_boundary_failure(result, exc), started, budget)
        if hierarchy.returncode != 0:
            return _finalize(
                _command_failure(
                    result,
                    hierarchy,
                    operation="dump-accessibility-hierarchy",
                ),
                started,
                budget,
            )

        try:
            tree = parse_ios_accessibility_output(
                hierarchy.stdout,
                max_output_bytes=self.max_output_bytes,
                max_nodes=self.max_nodes,
                max_depth=self.max_depth,
                max_windows=self.max_windows,
                max_text_chars=self.max_text_chars,
            )
        except IOSAccessibilityParseError as exc:
            return _finalize(
                _set_error(
                    result,
                    status="failed",
                    code="hierarchy_parse_failed",
                    reason=str(exc),
                    scope="provider",
                    provider_status="failed",
                    exc=exc,
                ),
                started,
                budget,
            )
        try:
            budget.remaining_seconds()
        except IOSCommandTimeoutError as exc:
            return _finalize(_boundary_failure(result, exc), started, budget)

        if not production_runner:
            _discard_untrusted_identity(result)
            _clear_tree(result)
            return _finalize(
                _set_error(
                    result,
                    status="unavailable",
                    code="non_production_runner",
                    reason=(
                        "injected runner output was parsed for validation but cannot form "
                        "production iOS accessibility evidence"
                    ),
                    scope="provenance",
                    provider_status="unavailable",
                ),
                started,
                budget,
            )

        try:
            current_identity = _executable_identity(Path(executable))
        except _DependencyUnavailable as exc:
            return _finalize(
                _set_error(
                    result,
                    status="failed",
                    code="dependency_changed",
                    reason=exc.reason,
                    scope="dependency",
                    provider_status="failed",
                ),
                started,
                budget,
            )
        if not _same_file_identity(executable_identity, current_identity):
            return _finalize(
                _set_error(
                    result,
                    status="failed",
                    code="dependency_changed",
                    reason="idb executable identity changed while the probe was running",
                    scope="dependency",
                    provider_status="failed",
                ),
                started,
                budget,
            )
        try:
            budget.remaining_seconds()
        except IOSCommandTimeoutError as exc:
            _clear_tree(result)
            return _finalize(_boundary_failure(result, exc), started, budget)

        result.update(tree)
        result["coverage"]["truncated"] = bool(tree["truncated"])
        result["coverage"]["format"] = tree["format"]
        result["provider"]["status"] = "available"
        result["status"] = "partial" if tree["truncated"] else "ok"
        result["reason"] = (
            "idb returned a bounded live simulator accessibility hierarchy"
            if not tree["truncated"]
            else "idb returned a live simulator accessibility hierarchy truncated by configured limits"
        )
        result["provenance"]["production_evidence"] = True
        return _finalize(result, started, budget)


def probe_ios_accessibility(
    target_udid: str,
    *,
    target_kind: str = "simulator",
    idb_path: str | os.PathLike[str] | None = None,
    allowed_executable_roots: Sequence[str | os.PathLike[str]] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_windows: int = DEFAULT_MAX_WINDOWS,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
    runner: Runner | None = None,
    platform_name: str | None = None,
    executable_finder: ExecutableFinder = shutil.which,
) -> Dict[str, Any]:
    """Convenience wrapper around :class:`IOSAccessibilityAdapter`."""

    return IOSAccessibilityAdapter(
        idb_path=idb_path,
        allowed_executable_roots=allowed_executable_roots,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        max_nodes=max_nodes,
        max_depth=max_depth,
        max_windows=max_windows,
        max_text_chars=max_text_chars,
        runner=runner,
        executable_finder=executable_finder,
    ).probe(
        target_udid,
        target_kind=target_kind,
        platform_name=platform_name,
    )


def parse_ios_target_identity(
    payload: str | bytes,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> Dict[str, Any]:
    """Parse the strict identity fields emitted by ``idb describe --json``."""

    output_limit = _bounded_integer(
        max_output_bytes,
        "max_output_bytes",
        minimum=1,
        maximum=MAX_OUTPUT_BYTES,
    )
    text_limit = _bounded_integer(
        max_text_chars,
        "max_text_chars",
        minimum=1,
        maximum=MAX_TEXT_CHARS,
    )
    text = _bounded_payload(payload, output_limit)
    value = _load_json(text)
    identity_mapping = _find_identity_mapping(value)
    if identity_mapping is None:
        raise IOSAccessibilityParseError(
            "idb target description does not contain a target identity object"
        )
    index = _key_index(identity_mapping)
    udid = _limited_scalar(
        _indexed_get(index, "udid", "identifier", "target_udid"),
        text_limit,
        set(),
    )
    raw_kind = _limited_scalar(
        _indexed_get(index, "target_type", "type", "kind", "device_type"),
        text_limit,
        set(),
    )
    kind = _normalize_observed_kind(raw_kind)
    state = _limited_scalar(
        _indexed_get(index, "state", "target_state", "status"),
        text_limit,
        set(),
    )
    if not udid or not _UDID_PATTERN.fullmatch(udid):
        raise IOSAccessibilityParseError("idb target description contains no valid UDID")
    if kind is None:
        raise IOSAccessibilityParseError("idb target description contains no supported target type")
    if kind == "simulator" and not state:
        raise IOSAccessibilityParseError("idb simulator description contains no target state")
    return {
        "udid": udid,
        "kind": kind,
        "state": state,
        "name": _limited_scalar(_indexed_get(index, "name", "target_name"), text_limit, set()),
        "os_version": _limited_scalar(
            _indexed_get(index, "os_version", "osversion", "version"),
            text_limit,
            set(),
        ),
        "architecture": _limited_scalar(
            _indexed_get(index, "architecture", "arch"),
            text_limit,
            set(),
        ),
    }


def parse_ios_accessibility_output(
    payload: str | bytes,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_windows: int = DEFAULT_MAX_WINDOWS,
    max_text_chars: int = DEFAULT_MAX_TEXT_CHARS,
) -> Dict[str, Any]:
    """Normalize idb JSON or XCUITest/Appium XML into one bounded tree."""

    output_limit = _bounded_integer(
        max_output_bytes,
        "max_output_bytes",
        minimum=1,
        maximum=MAX_OUTPUT_BYTES,
    )
    node_limit = _bounded_integer(max_nodes, "max_nodes", minimum=1, maximum=MAX_NODES)
    depth_limit = _bounded_integer(max_depth, "max_depth", minimum=0, maximum=MAX_DEPTH)
    window_limit = _bounded_integer(
        max_windows,
        "max_windows",
        minimum=1,
        maximum=MAX_WINDOWS,
    )
    text_limit = _bounded_integer(
        max_text_chars,
        "max_text_chars",
        minimum=1,
        maximum=MAX_TEXT_CHARS,
    )
    text = _bounded_payload(payload, output_limit)
    stripped = text.lstrip("\ufeff\r\n\t ")

    if stripped.startswith("{") or stripped.startswith("["):
        value = _load_json(stripped)
        if isinstance(value, Mapping):
            wrapped = _mapping_value(value, "value")
            if isinstance(wrapped, str) and wrapped.lstrip().startswith("<"):
                return _parse_ios_xml(
                    wrapped,
                    max_nodes=node_limit,
                    max_depth=depth_limit,
                    max_windows=window_limit,
                    max_text_chars=text_limit,
                    max_output_bytes=output_limit,
                )
        return _parse_ios_json(
            value,
            max_nodes=node_limit,
            max_depth=depth_limit,
            max_windows=window_limit,
            max_text_chars=text_limit,
        )

    return _parse_ios_xml(
        stripped,
        max_nodes=node_limit,
        max_depth=depth_limit,
        max_windows=window_limit,
        max_text_chars=text_limit,
        max_output_bytes=output_limit,
    )


def _parse_ios_json(
    value: Any,
    *,
    max_nodes: int,
    max_depth: int,
    max_windows: int,
    max_text_chars: int,
) -> Dict[str, Any]:
    roots = _json_roots(value)
    if not roots:
        raise IOSAccessibilityParseError("iOS accessibility JSON contains an empty hierarchy")
    for root in roots:
        if not isinstance(root, Mapping):
            raise IOSAccessibilityParseError("iOS accessibility JSON nodes must be objects")

    truncation_reasons: set[str] = set()
    flat = len(roots) > 1 and all(not _mapping_children(root) for root in roots)
    if flat:
        root_index = next(
            (
                index
                for index, item in enumerate(roots)
                if _mapping_node_kind(item) in {"application", "window"}
            ),
            0,
        )
        grouped = dict(roots[root_index])
        grouped["children"] = [item for index, item in enumerate(roots) if index != root_index]
        roots = [grouped]

    if len(roots) > max_windows:
        roots = roots[:max_windows]
        truncation_reasons.add("max_windows")

    windows: list[Dict[str, Any]] = []
    stack: list[tuple[Mapping[str, Any], int, list[Dict[str, Any]]]] = [
        (root, 0, windows) for root in reversed(roots)
    ]
    node_count = 0
    while stack:
        if node_count >= max_nodes:
            truncation_reasons.add("max_nodes")
            break
        raw, depth, sink = stack.pop()
        node = _normalize_mapping_node(raw, depth, max_text_chars, truncation_reasons)
        sink.append(node)
        node_count += 1
        children = _mapping_children(raw)
        if children is None:
            continue
        if not isinstance(children, list):
            raise IOSAccessibilityParseError("iOS accessibility node children must be a list")
        if any(not isinstance(child, Mapping) for child in children):
            raise IOSAccessibilityParseError("iOS accessibility child nodes must be objects")
        if children and depth >= max_depth:
            truncation_reasons.add("max_depth")
            continue
        for child in reversed(children):
            stack.append((child, depth + 1, node["children"]))

    return _finish_tree(
        windows,
        node_count=node_count,
        truncation_reasons=truncation_reasons,
        output_format="idb-json",
    )


def _parse_ios_xml(
    payload: str | bytes,
    *,
    max_nodes: int,
    max_depth: int,
    max_windows: int,
    max_text_chars: int,
    max_output_bytes: int,
) -> Dict[str, Any]:
    text = _bounded_payload(payload, max_output_bytes)
    lowered = text.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise IOSAccessibilityParseError("XML DTD and entity declarations are not accepted")
    xml_start = _xml_start(text)
    if xml_start < 0:
        raise IOSAccessibilityParseError("provider output contains no recognized XML hierarchy")
    raw_xml = text[xml_start:].strip()
    try:
        root = ElementTree.fromstring(raw_xml)
    except ElementTree.ParseError as exc:
        raise IOSAccessibilityParseError(
            f"iOS accessibility XML parse failed: {_limit_error(exc)}"
        ) from exc

    truncation_reasons: set[str] = set()
    windows: list[ElementTree.Element] = []
    applications: list[ElementTree.Element] = []
    scan_count = 0
    stack: list[tuple[ElementTree.Element, int, bool, bool]] = [(root, 0, False, False)]
    while stack:
        element, depth, inside_window, inside_application = stack.pop()
        if scan_count >= max_nodes:
            truncation_reasons.add("max_nodes")
            break
        scan_count += 1
        kind = _xml_node_kind(element)
        now_inside_window = inside_window
        now_inside_application = inside_application
        if kind == "window" and not inside_window:
            if len(windows) < max_windows:
                windows.append(element)
            else:
                truncation_reasons.add("max_windows")
            now_inside_window = True
        elif kind == "application" and not inside_application:
            if len(applications) < max_windows:
                applications.append(element)
            else:
                truncation_reasons.add("max_windows")
            now_inside_application = True

        children = list(element)
        if children and depth >= max_depth + 2:
            truncation_reasons.add("max_depth")
            continue
        for child in reversed(children):
            stack.append((child, depth + 1, now_inside_window, now_inside_application))

    selected = windows or applications
    if not selected:
        raise IOSAccessibilityParseError(
            "iOS accessibility XML contains no application or window element"
        )

    normalized_windows: list[Dict[str, Any]] = []
    normalize_stack: list[tuple[ElementTree.Element, int, list[Dict[str, Any]]]] = [
        (element, 0, normalized_windows) for element in reversed(selected[:max_windows])
    ]
    node_count = 0
    while normalize_stack:
        if node_count >= max_nodes:
            truncation_reasons.add("max_nodes")
            break
        element, depth, sink = normalize_stack.pop()
        node = _normalize_xml_node(element, depth, max_text_chars, truncation_reasons)
        sink.append(node)
        node_count += 1
        children = list(element)
        if children and depth >= max_depth:
            truncation_reasons.add("max_depth")
            continue
        for child in reversed(children):
            normalize_stack.append((child, depth + 1, node["children"]))

    return _finish_tree(
        normalized_windows,
        node_count=node_count,
        truncation_reasons=truncation_reasons,
        output_format="xcuitest-xml",
    )


def _finish_tree(
    windows: list[Dict[str, Any]],
    *,
    node_count: int,
    truncation_reasons: set[str],
    output_format: str,
) -> Dict[str, Any]:
    if node_count <= 0 or not windows:
        raise IOSAccessibilityParseError("iOS accessibility hierarchy contains no readable nodes")
    control_count = max(0, node_count - len(windows))
    for window in windows:
        window["title"] = window.get("name")
        window["control_count"] = _descendant_count(window)
    reasons = sorted(truncation_reasons)
    return {
        "schema": _tree_schema(),
        "window_count": len(windows),
        "node_count": node_count,
        "control_count": control_count,
        "filtered_node_count": 0,
        "windows": windows,
        "truncated": bool(reasons),
        "truncation_reasons": reasons,
        "format": output_format,
    }


def _normalize_mapping_node(
    raw: Mapping[str, Any],
    depth: int,
    max_text_chars: int,
    truncation_reasons: set[str],
) -> Dict[str, Any]:
    index = _key_index(raw)
    control_type = _limited_scalar(
        _indexed_get(
            index,
            "control_type",
            "type",
            "element_type",
            "ax_role",
            "role",
            "class_name",
            "class",
        ),
        max_text_chars,
        truncation_reasons,
    )
    visible = _optional_bool(_indexed_get(index, "visible", "is_visible", "ax_visible"))
    offscreen = _optional_bool(_indexed_get(index, "offscreen", "is_offscreen"))
    if offscreen is None and visible is not None:
        offscreen = not visible
    return {
        "automation_id": _limited_scalar(
            _indexed_get(
                index,
                "automation_id",
                "identifier",
                "unique_id",
                "ax_unique_id",
                "uid",
            ),
            max_text_chars,
            truncation_reasons,
        ),
        "name": _limited_scalar(
            _indexed_get(index, "name", "label", "ax_label", "title", "ax_title", "value"),
            max_text_chars,
            truncation_reasons,
        ),
        "control_type": control_type,
        "bounds": _normalize_bounds(
            _indexed_get(
                index,
                "bounds",
                "frame",
                "rect",
                "bounding_rectangle",
                "ax_frame",
            )
        ),
        "enabled": _optional_bool(_indexed_get(index, "enabled", "is_enabled", "ax_enabled")),
        "offscreen": offscreen,
        "class_name": control_type,
        "framework_id": "idb/XCTest",
        "process_id": None,
        "native_window_handle": None,
        "depth": depth,
        "children": [],
    }


def _normalize_xml_node(
    element: ElementTree.Element,
    depth: int,
    max_text_chars: int,
    truncation_reasons: set[str],
) -> Dict[str, Any]:
    index = _key_index(element.attrib)
    control_type = _limited_scalar(
        _indexed_get(index, "type", "class", "role") or _local_tag(element.tag),
        max_text_chars,
        truncation_reasons,
    )
    visible = _optional_bool(_indexed_get(index, "visible", "is_visible"))
    offscreen = _optional_bool(_indexed_get(index, "offscreen", "is_offscreen"))
    if offscreen is None and visible is not None:
        offscreen = not visible
    bounds_value: Any = {
        "x": _indexed_get(index, "x"),
        "y": _indexed_get(index, "y"),
        "width": _indexed_get(index, "width"),
        "height": _indexed_get(index, "height"),
    }
    if not any(value not in {None, ""} for value in bounds_value.values()):
        bounds_value = _indexed_get(index, "rect", "bounds", "frame")
    return {
        "automation_id": _limited_scalar(
            _indexed_get(index, "identifier", "automation_id", "uid", "id"),
            max_text_chars,
            truncation_reasons,
        ),
        "name": _limited_scalar(
            _indexed_get(index, "name", "label", "value"),
            max_text_chars,
            truncation_reasons,
        ),
        "control_type": control_type,
        "bounds": _normalize_bounds(bounds_value),
        "enabled": _optional_bool(_indexed_get(index, "enabled", "is_enabled")),
        "offscreen": offscreen,
        "class_name": control_type,
        "framework_id": "XCUITest",
        "process_id": None,
        "native_window_handle": None,
        "depth": depth,
        "children": [],
    }


def _json_roots(value: Any) -> list[Mapping[str, Any]]:
    current = value
    if isinstance(current, Mapping):
        for key in (
            "windows",
            "accessibility_info",
            "accessibility",
            "elements",
            "nodes",
            "value",
        ):
            candidate = _mapping_value(current, key)
            if isinstance(candidate, (list, Mapping)):
                current = candidate
                break
        else:
            if not _looks_like_node(current):
                raise IOSAccessibilityParseError(
                    "iOS accessibility JSON contains no recognized hierarchy field"
                )
            current = [current]
    if isinstance(current, Mapping):
        return [current]
    if not isinstance(current, list):
        raise IOSAccessibilityParseError("iOS accessibility JSON hierarchy must be an object or list")
    return current


def _looks_like_node(value: Mapping[str, Any]) -> bool:
    index = _key_index(value)
    return any(
        key in index
        for key in (
            "children",
            "type",
            "controltype",
            "role",
            "axrole",
            "identifier",
            "label",
            "frame",
            "bounds",
        )
    )


def _mapping_children(value: Mapping[str, Any]) -> Any:
    index = _key_index(value)
    return _indexed_get(index, "children", "elements", "subviews")


def _mapping_node_kind(value: Mapping[str, Any]) -> str:
    index = _key_index(value)
    raw = _indexed_get(index, "control_type", "type", "element_type", "ax_role", "role")
    return _element_kind(raw)


def _xml_node_kind(element: ElementTree.Element) -> str:
    index = _key_index(element.attrib)
    raw = _indexed_get(index, "type", "class", "role") or _local_tag(element.tag)
    return _element_kind(raw)


def _element_kind(value: Any) -> str:
    normalized = re.sub(r"[^a-z]", "", str(value or "").casefold())
    if normalized.endswith("window") or normalized in {"window", "axwindow"}:
        return "window"
    if normalized.endswith("application") or normalized in {"application", "axapplication"}:
        return "application"
    return "control"


def _normalize_bounds(value: Any) -> Dict[str, int | float] | None:
    if isinstance(value, Mapping):
        index = _key_index(value)
        origin = _indexed_get(index, "origin")
        size = _indexed_get(index, "size")
        if isinstance(origin, Mapping) and isinstance(size, Mapping):
            origin_index = _key_index(origin)
            size_index = _key_index(size)
            left = _optional_number(_indexed_get(origin_index, "x", "left"))
            top = _optional_number(_indexed_get(origin_index, "y", "top"))
            width = _optional_number(_indexed_get(size_index, "width", "w"))
            height = _optional_number(_indexed_get(size_index, "height", "h"))
        else:
            left = _optional_number(_indexed_get(index, "left", "x"))
            top = _optional_number(_indexed_get(index, "top", "y"))
            width = _optional_number(_indexed_get(index, "width", "w"))
            height = _optional_number(_indexed_get(index, "height", "h"))
            right = _optional_number(_indexed_get(index, "right", "max_x"))
            bottom = _optional_number(_indexed_get(index, "bottom", "max_y"))
            if width is None and left is not None and right is not None:
                width = right - left
            if height is None and top is not None and bottom is not None:
                height = bottom - top
        if None in {left, top, width, height}:
            return None
        assert left is not None and top is not None and width is not None and height is not None
        return {
            "left": _clean_number(left),
            "top": _clean_number(top),
            "width": _clean_number(max(0.0, width)),
            "height": _clean_number(max(0.0, height)),
        }
    if isinstance(value, (list, tuple)) and len(value) == 4:
        numbers = [_optional_number(item) for item in value]
        if any(item is None for item in numbers):
            return None
        left, top, width, height = numbers
        assert left is not None and top is not None and width is not None and height is not None
        return {
            "left": _clean_number(left),
            "top": _clean_number(top),
            "width": _clean_number(max(0.0, width)),
            "height": _clean_number(max(0.0, height)),
        }
    raw = str(value or "").strip()
    numbers = [_optional_number(item) for item in re.findall(r"-?\d+(?:\.\d+)?", raw)]
    if len(numbers) != 4 or any(item is None for item in numbers):
        return None
    left, top, third, fourth = numbers
    assert left is not None and top is not None and third is not None and fourth is not None
    if raw.startswith("[") and "][" in raw.replace(" ", ""):
        width = third - left
        height = fourth - top
    else:
        width = third
        height = fourth
    return {
        "left": _clean_number(left),
        "top": _clean_number(top),
        "width": _clean_number(max(0.0, width)),
        "height": _clean_number(max(0.0, height)),
    }


def _invoke_runner(
    runner: Any,
    command: list[str],
    *,
    operation: str,
    budget: _ProbeBudget,
    result: Dict[str, Any],
    production_runner: bool,
) -> IOSCommandOutput:
    remaining_seconds = budget.remaining_seconds()
    remaining_bytes = budget.remaining_output_bytes()
    operation_record = {
        "operation": operation,
        "argv": list(command),
        "read_only": True,
        "shell": False,
        "status": "running",
    }
    result["provenance"]["operations"].append(operation_record)
    invoke = runner if callable(runner) else getattr(runner, "run")
    try:
        raw = invoke(
            list(command),
            timeout_seconds=remaining_seconds,
            max_output_bytes=remaining_bytes,
        )
        budget.remaining_seconds()
        output = _coerce_command_output(raw, trust_byte_counts=production_runner)
        output_bytes = _command_output_size(output, trust_byte_counts=production_runner)
        if output_bytes > remaining_bytes:
            raise IOSCommandOutputLimitError(
                "iOS accessibility provider exceeded the shared output budget"
            )
        budget.output_bytes += output_bytes
    except IOSCommandError:
        operation_record["status"] = "failed"
        raise
    except Exception as exc:  # noqa: BLE001 - injected runner failures are structured evidence.
        operation_record["status"] = "failed"
        raise IOSCommandLaunchError(
            f"iOS accessibility runner failed: {_limit_error(exc)}"
        ) from exc

    operation_record.update(
        {
            "status": "completed",
            "returncode": output.returncode,
            "stdout_bytes": output.stdout_bytes,
            "stderr_bytes": output.stderr_bytes,
        }
    )
    if production_runner:
        result["provenance"]["provider_process_executed"] = True
    return output


def _coerce_command_output(raw: Any, *, trust_byte_counts: bool) -> IOSCommandOutput:
    try:
        returncode = int(getattr(raw, "returncode"))
        stdout = _decode_text(getattr(raw, "stdout"))
        stderr = _decode_text(getattr(raw, "stderr"))
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise IOSCommandLaunchError(
            "iOS accessibility runner returned an invalid command result"
        ) from exc
    stdout_bytes = getattr(raw, "stdout_bytes", None) if trust_byte_counts else None
    stderr_bytes = getattr(raw, "stderr_bytes", None) if trust_byte_counts else None
    if not isinstance(stdout_bytes, int) or stdout_bytes < 0:
        stdout_bytes = len(stdout.encode("utf-8", errors="replace"))
    if not isinstance(stderr_bytes, int) or stderr_bytes < 0:
        stderr_bytes = len(stderr.encode("utf-8", errors="replace"))
    return IOSCommandOutput(returncode, stdout, stderr, stdout_bytes, stderr_bytes)


def _command_output_size(output: IOSCommandOutput, *, trust_byte_counts: bool) -> int:
    if trust_byte_counts and isinstance(output.stdout_bytes, int) and isinstance(output.stderr_bytes, int):
        return output.stdout_bytes + output.stderr_bytes
    return len(output.stdout.encode("utf-8", errors="replace")) + len(
        output.stderr.encode("utf-8", errors="replace")
    )


def _resolve_idb_executable(
    requested: str | os.PathLike[str] | None,
    *,
    executable_finder: ExecutableFinder,
    allowed_roots: Sequence[str | os.PathLike[str]] | None,
) -> tuple[str, Dict[str, Any]]:
    source = "argument"
    if requested is None:
        source = "PATH"
        try:
            requested = executable_finder(IOS_ACCESSIBILITY_DEPENDENCY)
        except Exception as exc:  # noqa: BLE001 - dependency discovery must degrade cleanly.
            raise _DependencyUnavailable(
                "dependency_detection_failed",
                f"idb dependency detection failed: {_limit_error(exc)}",
            ) from exc
        if not requested:
            raise _DependencyUnavailable(
                "dependency_missing",
                "idb was not found on PATH; install the fb-idb package and companion",
                status="missing",
            )
    try:
        raw_path = os.fspath(requested)
    except TypeError as exc:
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            "idb executable path must be path-like",
            status="invalid",
        ) from exc
    if not isinstance(raw_path, str) or not raw_path or "\x00" in raw_path:
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            "idb executable path is empty or contains a NUL byte",
            status="invalid",
        )
    if len(raw_path) > MAX_PATH_CHARS:
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            f"idb executable path exceeds {MAX_PATH_CHARS} characters",
            status="invalid",
        )
    path = Path(raw_path)
    if not path.is_absolute():
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            f"{source} idb executable path must be absolute",
            status="invalid",
        )
    if path.name.casefold() not in _IDB_BASENAMES:
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            "iOS accessibility executable basename must be idb or idb.exe",
            status="invalid",
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _DependencyUnavailable(
            "dependency_missing",
            f"idb executable does not resolve to an existing file: {_limit_error(exc)}",
            status="missing",
        ) from exc
    if len(str(resolved)) > MAX_PATH_CHARS:
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            f"resolved idb executable path exceeds {MAX_PATH_CHARS} characters",
            status="invalid",
        )
    if not resolved.is_file():
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            "idb executable path is not a regular file",
            status="invalid",
        )
    if not os.access(resolved, os.X_OK):
        raise _DependencyUnavailable(
            "dependency_not_executable",
            "idb executable path is not executable",
            status="invalid",
        )
    _enforce_allowed_roots(resolved, allowed_roots)
    identity = _executable_identity(resolved)
    identity["discovery"] = source
    identity["requested_path"] = str(path)
    return str(resolved), identity


def _enforce_allowed_roots(
    executable: Path,
    allowed_roots: Sequence[str | os.PathLike[str]] | None,
) -> None:
    if allowed_roots is None:
        return
    resolved_roots: list[Path] = []
    for raw_root in allowed_roots:
        try:
            root_text = os.fspath(raw_root)
        except TypeError as exc:
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                "allowed executable roots must be path-like",
                status="invalid",
            ) from exc
        if not isinstance(root_text, str) or not root_text or "\x00" in root_text:
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                "allowed executable roots cannot be empty or contain NUL bytes",
                status="invalid",
            )
        if len(root_text) > MAX_PATH_CHARS:
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                f"allowed executable root exceeds {MAX_PATH_CHARS} characters",
                status="invalid",
            )
        root = Path(root_text)
        if not root.is_absolute():
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                "allowed executable roots must be absolute",
                status="invalid",
            )
        try:
            resolved_root = root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                f"allowed executable root does not exist: {_limit_error(exc)}",
                status="invalid",
            ) from exc
        if len(str(resolved_root)) > MAX_PATH_CHARS:
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                f"resolved allowed executable root exceeds {MAX_PATH_CHARS} characters",
                status="invalid",
            )
        if not resolved_root.is_dir():
            raise _DependencyUnavailable(
                "dependency_path_invalid",
                "allowed executable root is not a directory",
                status="invalid",
            )
        resolved_roots.append(resolved_root)
    if not any(_is_relative_to(executable, root) for root in resolved_roots):
        raise _DependencyUnavailable(
            "dependency_path_outside_allowed_roots",
            "resolved idb executable is outside the allowed executable roots",
            status="invalid",
        )


def _executable_identity(path: Path) -> Dict[str, Any]:
    try:
        info = path.stat()
    except OSError as exc:
        raise _DependencyUnavailable(
            "dependency_missing",
            f"could not stat idb executable: {_limit_error(exc)}",
            status="missing",
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise _DependencyUnavailable(
            "dependency_path_invalid",
            "idb executable is no longer a regular file",
            status="invalid",
        )
    return {
        "path": str(path),
        "realpath": str(path.resolve()),
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "size": int(info.st_size),
        "mtime_ns": int(info.st_mtime_ns),
        "mode": int(info.st_mode),
    }


def _same_file_identity(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    fields = ("realpath", "device", "inode", "size", "mtime_ns", "mode")
    return all(before.get(field) == after.get(field) for field in fields)


def _find_identity_mapping(value: Any) -> Mapping[str, Any] | None:
    queue: list[tuple[Any, int]] = [(value, 0)]
    candidates: list[tuple[int, Mapping[str, Any]]] = []
    visited = 0
    while queue and visited < 64:
        current, depth = queue.pop(0)
        visited += 1
        if isinstance(current, Mapping):
            index = _key_index(current)
            score = 0
            if _indexed_get(index, "udid", "identifier", "target_udid") is not None:
                score += 4
            if _indexed_get(index, "target_type", "type", "kind", "device_type") is not None:
                score += 2
            if _indexed_get(index, "state", "target_state", "status") is not None:
                score += 1
            if score:
                candidates.append((score, current))
            if depth < 4:
                queue.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list) and depth < 4:
            queue.extend((item, depth + 1) for item in current[:64])
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _normalize_observed_kind(value: str | None) -> str | None:
    normalized = re.sub(r"[^a-z]", "", str(value or "").casefold())
    if "simulator" in normalized:
        return "simulator"
    if normalized in {"device", "physicaldevice", "iphone", "ipad"} or "physical" in normalized:
        return "device"
    return None


def _target_identity_error(target: Mapping[str, Any], identity: Mapping[str, Any]) -> str | None:
    expected_udid = str(target["udid"])
    actual_udid = str(identity["udid"])
    if expected_udid.casefold() != actual_udid.casefold():
        return f"idb resolved UDID {actual_udid}, not requested UDID {expected_udid}"
    if target["kind"] != identity["kind"]:
        return (
            f"idb resolved target kind {identity['kind']}, not requested kind {target['kind']}"
        )
    return None


def _record_target_identity(
    result: Dict[str, Any],
    identity: Mapping[str, Any],
    *,
    verified: bool,
) -> None:
    result["target"].update(identity)
    result["target"]["identity_verified"] = verified
    result["provenance"]["target_identity"] = dict(identity)


def _discard_untrusted_identity(result: Dict[str, Any]) -> None:
    requested_udid = result["target"]["requested_udid"]
    requested_kind = result["target"]["requested_kind"]
    result["target"] = {
        "udid": requested_udid,
        "kind": requested_kind,
        "requested_udid": requested_udid,
        "requested_kind": requested_kind,
        "identity_verified": False,
        "state": None,
        "name": None,
        "os_version": None,
        "architecture": None,
    }
    result["provenance"]["target_identity"] = None


def _base_result(target: Mapping[str, Any], adapter: IOSAccessibilityAdapter) -> Dict[str, Any]:
    limits = {
        "timeout_seconds": float(adapter.timeout_seconds),
        "max_output_bytes": adapter.max_output_bytes,
        "max_nodes": adapter.max_nodes,
        "max_depth": adapter.max_depth,
        "max_windows": adapter.max_windows,
        "max_text_chars": adapter.max_text_chars,
    }
    return {
        "schema": _tree_schema(),
        "status": "failed",
        "backend": IOS_ACCESSIBILITY_BACKEND,
        "reason": "iOS accessibility probe did not run",
        "provider": {
            "name": IOS_ACCESSIBILITY_PROVIDER,
            "api": "idb ui describe-all --nested",
            "transport": "local argv subprocess",
            "implementation": IOS_ACCESSIBILITY_DEPENDENCY,
            "status": "not_started",
        },
        "dependency": {
            "name": IOS_ACCESSIBILITY_DEPENDENCY,
            "required": True,
            "status": "not_checked",
            "install_command": "python3 -m pip install fb-idb",
        },
        "target": dict(target),
        "limits": limits,
        "coverage": {
            "scope": "explicit-udid-current-hierarchy",
            "hierarchy": "idb/XCTest accessibility hierarchy",
            "properties": [
                "automation_id",
                "name",
                "control_type",
                "bounds",
                "enabled",
                "offscreen",
            ],
            "limits": dict(limits),
            "truncated": False,
            "format": None,
            "limitations": [
                "Production hierarchy capture is available on macOS only.",
                "idb accessibility hierarchy capture currently supports booted simulators only.",
                "The adapter observes an existing target and performs no target lifecycle or UI action.",
                "Visibility depends on idb companion health and XCTest accessibility exposure.",
            ],
        },
        "provenance": {
            "provider": IOS_ACCESSIBILITY_PROVIDER,
            "adapter": IOS_ACCESSIBILITY_BACKEND,
            "dependency": IOS_ACCESSIBILITY_DEPENDENCY,
            "transport": "bounded local argv subprocess",
            "source": "live attached simulator accessibility hierarchy",
            "read_only": True,
            "target_executed": False,
            "target_mutated": False,
            "shell": False,
            "execution_assurance": "not_executed",
            "production_evidence": False,
            "target_identity": None,
            "operations": [],
            "budget": {**limits, "output_bytes_used": 0},
        },
        "window_count": 0,
        "node_count": 0,
        "control_count": 0,
        "filtered_node_count": 0,
        "windows": [],
        "truncated": False,
        "truncation_reasons": [],
        "errors": [],
        "error": None,
        "elapsed_seconds": 0.0,
    }


def _tree_schema() -> Dict[str, Any]:
    return {
        "name": IOS_ACCESSIBILITY_TREE_SCHEMA,
        "version": IOS_ACCESSIBILITY_TREE_SCHEMA_VERSION,
        "root": "windows",
        "node_fields": list(_TREE_NODE_FIELDS),
        "bounds_fields": ["left", "top", "width", "height"],
        "children": "nested",
    }


def _normalize_target(target_udid: Any, target_kind: Any) -> tuple[Dict[str, Any], str | None]:
    target = {
        "udid": None,
        "kind": None,
        "requested_udid": None,
        "requested_kind": None,
        "identity_verified": False,
        "state": None,
        "name": None,
        "os_version": None,
        "architecture": None,
    }
    if not isinstance(target_udid, str):
        return target, "target_udid must be a string"
    udid = target_udid.strip()
    if udid != target_udid or not udid:
        return target, "target_udid cannot be empty or contain surrounding whitespace"
    if len(udid) > MAX_UDID_CHARS or not _UDID_PATTERN.fullmatch(udid):
        return target, "target_udid must contain only ASCII letters, digits, and hyphens"
    if not isinstance(target_kind, str):
        return target, "target_kind must be simulator or device"
    kind = target_kind.strip().casefold()
    if kind not in _TARGET_KINDS:
        return target, "target_kind must be simulator or device"
    target.update(
        {
            "udid": udid,
            "kind": kind,
            "requested_udid": udid,
            "requested_kind": kind,
        }
    )
    return target, None


def _boundary_failure(result: Dict[str, Any], exc: IOSCommandError) -> Dict[str, Any]:
    if isinstance(exc, IOSCommandTimeoutError):
        code = "timeout"
        truncation = "timeout"
        provider_status = "timeout"
    elif isinstance(exc, IOSCommandOutputLimitError):
        code = "output_limit"
        truncation = "max_output_bytes"
        provider_status = "failed"
    else:
        code = "provider_execution_failed"
        truncation = None
        provider_status = "failed"
    failure = _set_error(
        result,
        status="failed",
        code=code,
        reason=str(exc),
        scope="provider",
        provider_status=provider_status,
        exc=exc,
    )
    if truncation:
        failure["truncated"] = True
        failure["truncation_reasons"] = [truncation]
        failure["coverage"]["truncated"] = True
    return failure


def _command_failure(
    result: Dict[str, Any],
    output: IOSCommandOutput,
    *,
    operation: str,
) -> Dict[str, Any]:
    detail = _limit_error(output.stderr or output.stdout or f"exit code {output.returncode}")
    return _set_error(
        result,
        status="failed",
        code="provider_command_failed",
        reason=f"idb {operation} failed with exit code {output.returncode}: {detail}",
        scope="provider",
        provider_status="failed",
    )


def _set_error(
    result: Dict[str, Any],
    *,
    status: str,
    code: str,
    reason: str,
    scope: str,
    provider_status: str,
    exc: BaseException | None = None,
) -> Dict[str, Any]:
    message = _limit_error(reason)
    error: Dict[str, Any] = {"code": code, "message": message, "scope": scope}
    if exc is not None:
        error["type"] = type(exc).__name__
    result["status"] = status
    result["reason"] = message
    result["provider"]["status"] = provider_status
    result["errors"] = [error]
    result["error"] = error
    if code == "non_production_runner":
        result["provenance"]["execution_assurance"] = "simulation"
    elif status == "unavailable":
        result["provenance"]["execution_assurance"] = "dependency_gated"
    elif status == "failed":
        result["provenance"]["execution_assurance"] = "failed"
    result["provenance"]["production_evidence"] = False
    return result


def _clear_tree(result: Dict[str, Any]) -> None:
    result.update(
        {
            "window_count": 0,
            "node_count": 0,
            "control_count": 0,
            "filtered_node_count": 0,
            "windows": [],
            "truncated": False,
            "truncation_reasons": [],
        }
    )
    result["coverage"]["truncated"] = False
    result["coverage"]["format"] = None


def _finalize(
    result: Dict[str, Any],
    started: float,
    budget: _ProbeBudget,
) -> Dict[str, Any]:
    elapsed = max(0.0, budget.clock() - started)
    result["elapsed_seconds"] = round(elapsed, 6)
    result["provenance"]["budget"]["output_bytes_used"] = budget.output_bytes
    return result


def _bounded_payload(payload: str | bytes, max_output_bytes: int) -> str:
    if isinstance(payload, bytes):
        if len(payload) > max_output_bytes:
            raise IOSAccessibilityParseError(
                f"provider output exceeded the {max_output_bytes}-byte parse limit"
            )
        text = payload.decode("utf-8", errors="replace")
    elif isinstance(payload, str):
        if len(payload.encode("utf-8", errors="replace")) > max_output_bytes:
            raise IOSAccessibilityParseError(
                f"provider output exceeded the {max_output_bytes}-byte parse limit"
            )
        text = payload
    else:
        raise IOSAccessibilityParseError("provider output must be text or bytes")
    if not text.strip():
        raise IOSAccessibilityParseError("provider output is empty")
    return text


def _load_json(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    try:
        return json.loads(text.lstrip("\ufeff"), parse_constant=reject_constant)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise IOSAccessibilityParseError(
            f"iOS accessibility JSON parse failed: {_limit_error(exc)}"
        ) from exc


def _xml_start(text: str) -> int:
    positions = [
        position
        for marker in (
            "<?xml",
            "<AppiumAUT",
            "<XCUIElementType",
            "<Application",
            "<Window",
        )
        if (position := text.find(marker)) >= 0
    ]
    return min(positions) if positions else -1


def _mapping_value(value: Mapping[str, Any], requested: str) -> Any:
    normalized = _normalize_key(requested)
    for key, item in value.items():
        if _normalize_key(key) == normalized:
            return item
    return None


def _key_index(value: Mapping[Any, Any]) -> Dict[str, Any]:
    return {_normalize_key(key): item for key, item in value.items()}


def _indexed_get(index: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        normalized = _normalize_key(key)
        if normalized in index:
            return index[normalized]
    return None


def _normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def _limited_scalar(
    value: Any,
    max_chars: int,
    truncation_reasons: set[str],
) -> str | None:
    if value is None or isinstance(value, (Mapping, list, tuple, set)):
        return None
    text = str(value).replace("\x00", "").strip()
    if not text:
        return None
    if len(text) > max_chars:
        truncation_reasons.add("max_text_chars")
        return text[:max_chars]
    return text


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    normalized = str(value or "").strip().casefold()
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    return None


def _optional_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _clean_number(value: float) -> int | float:
    return int(value) if value.is_integer() else value


def _descendant_count(node: Mapping[str, Any]) -> int:
    count = 0
    stack = list(node.get("children") or [])
    while stack:
        current = stack.pop()
        count += 1
        if isinstance(current, Mapping):
            stack.extend(current.get("children") or [])
    return count


def _decode_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    raise TypeError("command output must be text or bytes")


def _validate_argv(command: Sequence[str | os.PathLike[str]]) -> list[str]:
    if isinstance(command, (str, bytes, os.PathLike)) or not isinstance(command, Sequence):
        raise ValueError("command must be a non-empty argv sequence")
    if not command or len(command) > MAX_ARG_COUNT:
        raise ValueError(f"command must contain between 1 and {MAX_ARG_COUNT} arguments")
    argv: list[str] = []
    for item in command:
        try:
            value = os.fspath(item)
        except TypeError as exc:
            raise ValueError("command arguments must be path-like strings") from exc
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("command arguments cannot be empty or contain NUL bytes")
        if len(value) > MAX_ARG_CHARS:
            raise ValueError(f"command arguments cannot exceed {MAX_ARG_CHARS} characters")
        argv.append(value)
    if not Path(argv[0]).is_absolute():
        raise ValueError("command executable must be an absolute path")
    return argv


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except (OSError, ProcessLookupError):
            pass
    try:
        process.kill()
    except OSError:
        pass


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _local_tag(tag: Any) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _limit_error(value: Any, limit: int = 1_000) -> str:
    text = " ".join(str(value).replace("\x00", "").split())
    return text[:limit]


def _bounded_integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _positive_timeout(value: Any, *, maximum: float | None) -> float:
    if isinstance(value, bool):
        raise ValueError("timeout_seconds must be a positive finite number")
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("timeout_seconds must be a positive finite number") from exc
    if not math.isfinite(timeout) or timeout <= 0 or (maximum is not None and timeout > maximum):
        suffix = f" no greater than {maximum:g}" if maximum is not None else ""
        raise ValueError(f"timeout_seconds must be a positive finite number{suffix}")
    return timeout


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_NODES",
    "DEFAULT_MAX_OUTPUT_BYTES",
    "DEFAULT_MAX_TEXT_CHARS",
    "DEFAULT_MAX_WINDOWS",
    "DEFAULT_TIMEOUT_SECONDS",
    "IOS_ACCESSIBILITY_BACKEND",
    "IOS_ACCESSIBILITY_DEPENDENCY",
    "IOS_ACCESSIBILITY_PROVIDER",
    "IOSAccessibilityAdapter",
    "IOSAccessibilityError",
    "IOSAccessibilityParseError",
    "IOSCommandError",
    "IOSCommandLaunchError",
    "IOSCommandOutput",
    "IOSCommandOutputLimitError",
    "IOSCommandTimeoutError",
    "SubprocessIOSAccessibilityRunner",
    "parse_ios_accessibility_output",
    "parse_ios_target_identity",
    "probe_ios_accessibility",
]
