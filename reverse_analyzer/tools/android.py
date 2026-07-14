"""Bounded, static Android APK analysis helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import threading
import xml.etree.ElementTree as ET
import zipfile
import zlib
from typing import Any, Callable, Mapping, Sequence


_ANDROID_NS = "http://schemas.android.com/apk/res/android"
_NO_INDEX = 0xFFFFFFFF

_MAX_ZIP_ENTRIES = 10_000
_MAX_ZIP_NAME_LENGTH = 1_024
_MAX_DECLARED_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_DECLARED_ARCHIVE_BYTES = 768 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000
_MAX_TOTAL_READ_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_RESOURCE_XML_BYTES = 1 * 1024 * 1024
_MAX_DEX_BYTES = 16 * 1024 * 1024
_MAX_ELF_BYTES = 8 * 1024 * 1024

_MAX_DEX_FILES = 32
_MAX_NATIVE_LIBS = 128
_MAX_RESOURCE_XML_FILES = 64
_MAX_EXAMPLES = 40
_MAX_WARNINGS = 100

_MAX_AXML_CHUNKS = 10_000
_MAX_AXML_STRINGS = 8_192
_MAX_AXML_ELEMENTS = 4_096
_MAX_AXML_ATTRIBUTES = 64
_MAX_MANIFEST_COMPONENTS = 256

_MAX_DEX_STRING_IDS = 4_096
_MAX_DEX_CONTEXT_STRINGS = 8_192
_MAX_DEX_STRING_BYTES = 1_024
_MAX_DEX_EVIDENCE = 96

_MAX_ELF_SECTIONS = 512
_MAX_ELF_SYMBOLS = 8_192
_MAX_ELF_EXPORTS = 128
_MAX_JNI_EXPORTS = 96

_DEFAULT_JADX_TIMEOUT_SECONDS = 600.0
_DEFAULT_JADX_MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_DEFAULT_JADX_MAX_GENERATED_BYTES = 512 * 1024 * 1024
_DEFAULT_JADX_MAX_GENERATED_FILES = 20_000
_MAX_JADX_TIMEOUT_SECONDS = 3_600.0
_MAX_JADX_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_JADX_GENERATED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_JADX_GENERATED_FILES = 100_000
_MAX_JADX_LOG_CHARS = 8_192
_JADX_OUTPUT_DIRECTORY = "jadx"

_FRAMEWORK_NAMES = (
    "android_xml",
    "jetpack_compose",
    "flutter",
    "react_native",
    "unity",
    "webview_hybrid",
)
_FRAMEWORK_PRIORITY = {
    "flutter": 0,
    "unity": 1,
    "react_native": 2,
    "jetpack_compose": 3,
    "webview_hybrid": 4,
    "android_xml": 5,
}

_DEX_SECTION_SIZES = {
    "string_ids": 4,
    "type_ids": 4,
    "proto_ids": 12,
    "field_ids": 8,
    "method_ids": 8,
    "class_defs": 32,
}

_ANDROID_ATTRIBUTE_IDS = {
    0x01010000: "theme",
    0x01010001: "label",
    0x01010002: "icon",
    0x01010003: "name",
    0x01010010: "exported",
    0x0101020C: "minSdkVersion",
    0x0101021B: "versionCode",
    0x0101021C: "versionName",
    0x01010270: "targetSdkVersion",
    0x01010271: "maxSdkVersion",
}

_ELF_MACHINE_NAMES = {
    3: "Intel 80386",
    8: "MIPS",
    40: "ARM",
    62: "AMD x86-64",
    183: "AArch64",
    243: "RISC-V",
}
_ABI_MACHINES = {
    "armeabi": {40},
    "armeabi-v7a": {40},
    "arm64-v8a": {183},
    "x86": {3},
    "x86_64": {62},
    "mips": {8},
    "mips64": {8},
    "riscv64": {243},
}


JadxRunner = Callable[..., Any]
JadxExecutableFinder = Callable[[str], str | None]


@dataclass(frozen=True, slots=True)
class JadxCommandOutput:
    """Normalized output returned by the production or an injected JADX runner."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


class _JadxBoundaryError(RuntimeError):
    pass


class _JadxTimeoutError(_JadxBoundaryError):
    pass


class _JadxOutputLimitError(_JadxBoundaryError):
    pass


class _ReadBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def consume(self, amount: int) -> None:
        self.used = min(self.limit, self.used + max(0, amount))


def _run_bounded_jadx_command(
    command: Sequence[str | os.PathLike[str]],
    *,
    timeout_seconds: float = _DEFAULT_JADX_TIMEOUT_SECONDS,
    max_output_bytes: int = _DEFAULT_JADX_MAX_OUTPUT_BYTES,
) -> JadxCommandOutput:
    """Run JADX with argv-only execution and bounded combined output."""

    argv = [os.fspath(item) for item in command]
    if not argv or any(not item or "\x00" in item for item in argv):
        raise ValueError("JADX command contains an empty or invalid argument")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout_seconds must be a positive finite number")
    if not isinstance(max_output_bytes, int) or max_output_bytes <= 0:
        raise ValueError("max_output_bytes must be a positive integer")

    creationflags = 0
    if os.name == "nt":
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
    environment = dict(os.environ)
    for key in (
        "ALL_PROXY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "all_proxy",
        "http_proxy",
        "https_proxy",
    ):
        environment.pop(key, None)
    environment["NO_PROXY"] = "*"
    environment["no_proxy"] = "*"

    process = subprocess.Popen(  # noqa: S603 - executable is explicitly discovered and shell is disabled.
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        creationflags=creationflags,
        env=environment,
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
                    _terminate_jadx_process(process)
        except (OSError, ValueError):
            return

    readers = (
        threading.Thread(target=drain, args=(process.stdout, stdout_chunks), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_chunks), daemon=True),
    )
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_jadx_process(process)
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
        raise _JadxOutputLimitError(
            f"JADX command output exceeded {max_output_bytes} bytes"
        )
    if timed_out:
        raise _JadxTimeoutError(f"JADX command exceeded {timeout:g} seconds")
    return JadxCommandOutput(
        returncode=int(process.returncode or 0),
        stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace"),
        stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace"),
    )


def _terminate_jadx_process(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass


def _java_decompilation_request(
    evidence: Mapping[str, Any] | None,
    config: Mapping[str, Any] | None,
) -> tuple[bool, dict[str, Any], str | None]:
    requested = False
    options: dict[str, Any] = {}
    error: str | None = None

    for source_name, container in (("evidence", evidence), ("config", config)):
        if container is None:
            continue
        if not isinstance(container, Mapping):
            return True, {}, f"{source_name} must be a mapping"
        candidates: list[Any] = [
            container.get("java_decompilation"),
            container.get("jadx"),
        ]
        android_options = container.get("android")
        if isinstance(android_options, Mapping):
            candidates.extend(
                (
                    android_options.get("java_decompilation"),
                    android_options.get("jadx"),
                )
            )
        if container.get("request_java_decompilation") is True:
            requested = True
        for candidate in candidates:
            if candidate is None or candidate is False:
                continue
            if candidate is True:
                requested = True
                continue
            if not isinstance(candidate, Mapping):
                error = f"{source_name} java_decompilation configuration must be a mapping or boolean"
                requested = True
                continue
            enabled = candidate.get("enabled", False)
            if not isinstance(enabled, bool):
                error = f"{source_name} java_decompilation.enabled must be boolean"
                requested = True
                continue
            if not enabled:
                continue
            requested = True
            options.update({str(key): value for key, value in candidate.items() if key != "enabled"})
    return requested, options, error


def _unrequested_java_decompilation() -> dict[str, Any]:
    return _java_decompilation_payload(
        status="unavailable",
        requested=False,
        reason="JADX decompilation was not requested",
        dependency_state="not_requested",
    )


def _java_decompilation_payload(
    *,
    status: str,
    requested: bool,
    reason: str,
    dependency_state: str,
    executable_name: str | None = None,
    command: Sequence[str] = (),
    returncode: int | None = None,
    stdout: str = "",
    stderr: str = "",
    output: Mapping[str, Any] | None = None,
    target_sha256_before: str | None = None,
    target_sha256_after: str | None = None,
    warnings: Sequence[str] = (),
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "status": status,
        "requested": requested,
        "provider": "jadx",
        "reason": reason,
        "dependency": {
            "name": "jadx",
            "state": dependency_state,
            "executable": executable_name,
        },
        "command": list(command),
        "command_metadata": {
            "argv_only": True,
            "shell": False,
            "offline": True,
            "target_code_executed": False,
        },
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "output": dict(output or _empty_jadx_output()),
        "target": {
            "sha256_before": target_sha256_before,
            "sha256_after": target_sha256_after,
            "unchanged": bool(
                target_sha256_before
                and target_sha256_after
                and target_sha256_before == target_sha256_after
            ),
        },
        "capability_boundary": {
            "provider_kind": "external",
            "operation_kind": "offline_dex_java_kotlin_decompilation",
            "dependency_state": dependency_state,
            "required_tools": ["jadx"],
            "target_code_executed": False,
            "network_access": False,
            "content_recompiled": False,
        },
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
        "artifact": "android/java_decompilation.json",
    }


def _empty_jadx_output(relative_path: str = "android/jadx") -> dict[str, Any]:
    return {
        "path": relative_path,
        "file_count": 0,
        "source_file_count": 0,
        "java_file_count": 0,
        "kotlin_file_count": 0,
        "total_bytes": 0,
        "files": [],
    }


def android_java_decompile(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str],
    *,
    config: Mapping[str, Any] | None = None,
    runner: JadxRunner | None = None,
    executable_finder: JadxExecutableFinder | None = None,
) -> dict[str, Any]:
    """Run an explicitly requested offline JADX decompilation into ``android/jadx``."""

    sample = Path(path).expanduser().resolve(strict=False)
    output_root = Path(out_dir).expanduser().resolve(strict=False)
    android_root = (output_root / "android").resolve(strict=False)
    options = dict(config or {})
    finish = lambda payload: _persist_java_decompilation_summary(payload, output_root)

    if not sample.is_file() or sample.suffix.lower() != ".apk":
        return finish(
            _java_decompilation_payload(
                status="failed",
                requested=True,
                reason="JADX requires an existing APK input",
                dependency_state="not_checked",
            )
        )

    try:
        timeout_seconds = _bounded_jadx_float(
            options.get("timeout_seconds", _DEFAULT_JADX_TIMEOUT_SECONDS),
            "timeout_seconds",
            maximum=_MAX_JADX_TIMEOUT_SECONDS,
        )
        max_output_bytes = _bounded_jadx_int(
            options.get("max_output_bytes", _DEFAULT_JADX_MAX_OUTPUT_BYTES),
            "max_output_bytes",
            maximum=_MAX_JADX_OUTPUT_BYTES,
        )
        max_generated_bytes = _bounded_jadx_int(
            options.get("max_generated_bytes", _DEFAULT_JADX_MAX_GENERATED_BYTES),
            "max_generated_bytes",
            maximum=_MAX_JADX_GENERATED_BYTES,
        )
        max_generated_files = _bounded_jadx_int(
            options.get("max_generated_files", _DEFAULT_JADX_MAX_GENERATED_FILES),
            "max_generated_files",
            maximum=_MAX_JADX_GENERATED_FILES,
        )
        threads = _bounded_jadx_int(options.get("threads", 2), "threads", maximum=8)
        output_path, output_relative = _validated_jadx_output_path(
            android_root,
            output_root,
            options.get("output_dir", _JADX_OUTPUT_DIRECTORY),
        )
    except (TypeError, ValueError) as exc:
        return finish(
            _java_decompilation_payload(
                status="failed",
                requested=True,
                reason=f"invalid JADX configuration: {exc}",
                dependency_state="not_checked",
            )
        )

    finder = executable_finder or shutil.which
    try:
        executable, discovery_state = _discover_jadx_executable(
            options.get("executable"),
            finder,
        )
    except (OSError, TypeError, ValueError) as exc:
        return finish(
            _java_decompilation_payload(
                status="unavailable",
                requested=True,
                reason=f"JADX executable discovery failed: {type(exc).__name__}: {exc}",
                dependency_state="unavailable",
                output=_empty_jadx_output(output_relative),
            )
        )
    if executable is None:
        return finish(
            _java_decompilation_payload(
                status="unavailable",
                requested=True,
                reason=f"JADX executable was not found ({discovery_state})",
                dependency_state="unavailable",
                output=_empty_jadx_output(output_relative),
            )
        )

    executable_name = executable.name
    try:
        if output_path.is_symlink():
            raise ValueError("JADX output directory must not be a symbolic link")
        if output_path.exists() and not output_path.is_dir():
            raise ValueError("JADX output path exists and is not a directory")
        if output_path.exists() and any(output_path.iterdir()):
            raise ValueError("JADX output directory must be empty before execution")
        output_path.mkdir(parents=True, exist_ok=True)
        precondition_hash = _sha256_path(sample)
        actual_command, recorded_command = _build_jadx_command(
            executable,
            output_path,
            sample,
            threads=threads,
        )
    except (OSError, TypeError, ValueError) as exc:
        return finish(
            _java_decompilation_payload(
                status="failed",
                requested=True,
                reason=f"JADX precondition failed: {exc}",
                dependency_state="available",
                executable_name=executable_name,
                output=_empty_jadx_output(output_relative),
            )
        )

    command_runner = runner or _run_bounded_jadx_command
    command_output: JadxCommandOutput | None = None
    execution_error: str | None = None
    execution_status = "failed"
    try:
        raw_output = command_runner(
            actual_command,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )
        command_output = _normalize_jadx_command_output(raw_output, max_output_bytes)
    except (_JadxTimeoutError, subprocess.TimeoutExpired, TimeoutError):
        execution_error = f"JADX command timed out after {timeout_seconds:g} seconds"
    except _JadxOutputLimitError as exc:
        execution_error = str(exc)
    except FileNotFoundError:
        execution_error = "JADX executable became unavailable before execution"
        execution_status = "unavailable"
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        execution_error = f"JADX runner failed: {type(exc).__name__}: {exc}"

    try:
        inventory = _inventory_jadx_output(
            output_path,
            output_root,
            max_files=max_generated_files,
            max_bytes=max_generated_bytes,
        )
    except (OSError, ValueError, _JadxOutputLimitError) as exc:
        inventory = _empty_jadx_output(output_relative)
        execution_error = f"JADX output validation failed: {exc}"
        execution_status = "failed"

    try:
        postcondition_hash = _sha256_path(sample)
    except OSError as exc:
        postcondition_hash = None
        execution_error = f"unable to verify APK after JADX execution: {exc}"
        execution_status = "failed"

    stdout = ""
    stderr = ""
    returncode: int | None = None
    if command_output is not None:
        returncode = command_output.returncode
        stdout = _redact_jadx_text(
            command_output.stdout,
            sample,
            output_root,
            output_path,
            executable,
        )
        stderr = _redact_jadx_text(
            command_output.stderr,
            sample,
            output_root,
            output_path,
            executable,
        )
        if precondition_hash != postcondition_hash:
            execution_error = "JADX modified the input APK; result rejected"
        elif returncode != 0:
            execution_error = f"JADX exited with status {returncode}"
        elif execution_error is not None:
            pass
        elif inventory["source_file_count"] <= 0:
            execution_error = "JADX completed without producing Java or Kotlin source files"
        else:
            execution_status = "passed"

    reason = execution_error or (
        f"JADX produced {inventory['source_file_count']} source file(s)"
    )
    dependency_state = "available" if execution_status != "unavailable" else "unavailable"
    return finish(
        _java_decompilation_payload(
            status=execution_status,
            requested=True,
            reason=reason,
            dependency_state=dependency_state,
            executable_name=executable_name,
            command=recorded_command,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            output=inventory,
            target_sha256_before=precondition_hash,
            target_sha256_after=postcondition_hash,
            warnings=[f"executable discovery: {discovery_state}"],
        )
    )


def _bounded_jadx_float(value: Any, name: str, *, maximum: float) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be numeric")
    number = float(value)
    if not math.isfinite(number) or number <= 0 or number > maximum:
        raise ValueError(f"{name} must be greater than zero and at most {maximum:g}")
    return number


def _bounded_jadx_int(value: Any, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0 or value > maximum:
        raise ValueError(f"{name} must be greater than zero and at most {maximum}")
    return value


def _validated_jadx_output_path(
    android_root: Path,
    output_root: Path,
    configured: Any,
) -> tuple[Path, str]:
    if not isinstance(configured, (str, os.PathLike)):
        raise TypeError("output_dir must be a relative path")
    relative = Path(configured)
    if relative.is_absolute() or not relative.parts:
        raise ValueError("output_dir must be relative to the Android artifact directory")
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("output_dir contains a non-canonical path segment")
    output_path = (android_root / relative).resolve(strict=False)
    try:
        output_path.relative_to(android_root)
        output_relative = output_path.relative_to(output_root).as_posix()
    except ValueError as exc:
        raise ValueError("output_dir escapes the Android artifact directory") from exc
    if output_path == android_root:
        raise ValueError("output_dir must be below the Android artifact directory")
    return output_path, output_relative


def _discover_jadx_executable(
    configured: Any,
    finder: JadxExecutableFinder,
) -> tuple[Path | None, str]:
    if configured is not None:
        if not isinstance(configured, (str, os.PathLike)):
            return None, "invalid explicit executable"
        value = os.fspath(configured)
        if not value or "\x00" in value:
            return None, "invalid explicit executable"
        candidate = Path(value).expanduser()
        if candidate.is_absolute() or candidate.parent != Path("."):
            resolved = candidate.resolve(strict=False)
            return (resolved, "explicit path") if resolved.is_file() else (None, "explicit path missing")
        discovered = finder(value)
        if discovered:
            resolved = Path(discovered).resolve(strict=False)
            if resolved.is_file():
                return resolved, "explicit executable resolved through PATH"
        return None, "explicit executable missing"

    for name in ("jadx", "jadx.bat"):
        discovered = finder(name)
        if not discovered:
            continue
        resolved = Path(discovered).resolve(strict=False)
        if resolved.is_file():
            return resolved, f"PATH:{name}"
    return None, "PATH lookup failed"


def _build_jadx_command(
    executable: Path,
    output_path: Path,
    sample: Path,
    *,
    threads: int,
) -> tuple[list[str], list[str]]:
    logical = [
        str(executable),
        "-d",
        str(output_path),
        "--no-res",
        "-j",
        str(threads),
        str(sample),
    ]
    actual = list(logical)
    if os.name == "nt" and executable.suffix.lower() in {".bat", ".cmd"}:
        if any(re.search(r"[&|<>^%!\r\n]", item) for item in logical):
            raise ValueError("batch-backed JADX paths contain unsupported command metacharacters")
        command_processor = os.environ.get("COMSPEC") or shutil.which("cmd.exe")
        if not command_processor:
            raise ValueError("cmd.exe is required to execute jadx.bat")
        actual = [command_processor, "/d", "/c", subprocess.list2cmdline(logical)]
    recorded = [
        "jadx",
        "-d",
        "<ANDROID_JADX_DIR>",
        "--no-res",
        "-j",
        str(threads),
        "<APK>",
    ]
    return actual, recorded


def _normalize_jadx_command_output(raw: Any, max_output_bytes: int) -> JadxCommandOutput:
    if isinstance(raw, Mapping):
        returncode = raw.get("returncode")
        stdout = raw.get("stdout", "")
        stderr = raw.get("stderr", "")
    else:
        returncode = getattr(raw, "returncode", None)
        stdout = getattr(raw, "stdout", "")
        stderr = getattr(raw, "stderr", "")
    if isinstance(returncode, bool) or not isinstance(returncode, int):
        raise TypeError("JADX runner returned an invalid returncode")
    stdout_text = _decode_jadx_output(stdout)
    stderr_text = _decode_jadx_output(stderr)
    if len(stdout_text.encode("utf-8")) + len(stderr_text.encode("utf-8")) > max_output_bytes:
        raise _JadxOutputLimitError(
            f"JADX command output exceeded {max_output_bytes} bytes"
        )
    return JadxCommandOutput(returncode=returncode, stdout=stdout_text, stderr=stderr_text)


def _decode_jadx_output(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise TypeError("JADX runner stdout/stderr must be text or bytes")
    return value


def _inventory_jadx_output(
    output_path: Path,
    output_root: Path,
    *,
    max_files: int,
    max_bytes: int,
) -> dict[str, Any]:
    output_resolved = output_path.resolve(strict=True)
    root_resolved = output_root.resolve(strict=True)
    output_resolved.relative_to(root_resolved)
    if output_path.is_symlink():
        raise ValueError("JADX output directory is a symbolic link")

    entries: list[dict[str, Any]] = []
    total_bytes = 0
    java_count = 0
    kotlin_count = 0
    for current, dirnames, filenames in os.walk(output_resolved, followlinks=False):
        dirnames.sort()
        filenames.sort()
        current_path = Path(current)
        for dirname in list(dirnames):
            directory = current_path / dirname
            resolved = directory.resolve(strict=True)
            try:
                resolved.relative_to(output_resolved)
            except ValueError as exc:
                raise ValueError("JADX output contains a directory path escape") from exc
            if directory.is_symlink():
                raise ValueError("JADX output contains a symbolic-link directory")
        for filename in filenames:
            candidate = current_path / filename
            if candidate.is_symlink():
                raise ValueError("JADX output contains a symbolic-link file")
            resolved = candidate.resolve(strict=True)
            try:
                resolved.relative_to(output_resolved)
            except ValueError as exc:
                raise ValueError("JADX output contains a file path escape") from exc
            if not resolved.is_file():
                raise ValueError("JADX output contains a non-regular file")
            size = resolved.stat().st_size
            total_bytes += size
            if len(entries) + 1 > max_files:
                raise _JadxOutputLimitError(
                    f"JADX generated more than {max_files} files"
                )
            if total_bytes > max_bytes:
                raise _JadxOutputLimitError(
                    f"JADX generated more than {max_bytes} bytes"
                )
            suffix = resolved.suffix.casefold()
            java_count += int(suffix == ".java")
            kotlin_count += int(suffix == ".kt")
            entries.append(
                {
                    "path": resolved.relative_to(root_resolved).as_posix(),
                    "size": size,
                    "sha256": _sha256_path(resolved),
                    "language": "java" if suffix == ".java" else "kotlin" if suffix == ".kt" else None,
                }
            )
    entries.sort(key=lambda item: str(item["path"]))
    return {
        "path": output_resolved.relative_to(root_resolved).as_posix(),
        "file_count": len(entries),
        "source_file_count": java_count + kotlin_count,
        "java_file_count": java_count,
        "kotlin_file_count": kotlin_count,
        "total_bytes": total_bytes,
        "files": entries,
    }


def _redact_jadx_text(text: str, *paths: Path) -> str:
    result = text
    replacements: list[tuple[str, str]] = []
    labels = ("<APK>", "<OUTPUT_ROOT>", "<ANDROID_JADX_DIR>", "<JADX_EXECUTABLE>")
    for path, label in zip(paths, labels):
        value = str(path)
        replacements.extend(
            (
                (value, label),
                (value.replace("\\", "/"), label),
            )
        )
    for value, label in sorted(replacements, key=lambda item: len(item[0]), reverse=True):
        if value:
            result = result.replace(value, label)
    result = "".join(char for char in result if char in "\r\n\t" or ord(char) >= 32)
    if len(result) > _MAX_JADX_LOG_CHARS:
        return result[:_MAX_JADX_LOG_CHARS] + "...[truncated]"
    return result


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _persist_java_decompilation_summary(
    payload: dict[str, Any],
    output_root: Path,
) -> dict[str, Any]:
    try:
        _write_json(output_root / "android" / "java_decompilation.json", payload)
    except OSError as exc:
        payload.setdefault("warnings", []).append(
            f"unable to persist Java decompilation summary: {exc}"
        )
        if payload.get("status") == "passed":
            payload["status"] = "failed"
            payload["reason"] = "JADX completed but its summary artifact could not be persisted"
    return payload


def android_analyze(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
    *,
    evidence: Mapping[str, Any] | None = None,
    config: Mapping[str, Any] | None = None,
    jadx_runner: JadxRunner | None = None,
    jadx_executable_finder: JadxExecutableFinder | None = None,
) -> dict[str, Any]:
    """Analyze an APK and optionally run explicitly requested offline JADX."""

    sample = Path(path)
    if not sample.exists():
        return _finish_android_analysis(
            _unavailable_result(
                f"sample not found: {sample}",
                status="failed",
                package_type="apk" if sample.suffix.lower() == ".apk" else "unknown",
                framework_reason="APK sample is unavailable",
            ),
            sample,
            out_dir,
            evidence=evidence,
            config=config,
            jadx_runner=jadx_runner,
            jadx_executable_finder=jadx_executable_finder,
        )
    if sample.suffix.lower() != ".apk":
        result = _unavailable_result(
            "sample is not an APK",
            package_type="unknown",
            framework_reason="Input is not an APK",
        )
        result["reason"] = "sample is not an APK"
        return _finish_android_analysis(
            result,
            sample,
            out_dir,
            evidence=evidence,
            config=config,
            jadx_runner=jadx_runner,
            jadx_executable_finder=jadx_executable_finder,
        )

    try:
        with zipfile.ZipFile(sample) as archive:
            catalog = _catalog_archive(archive)
            infos: list[zipfile.ZipInfo] = catalog["infos"]
            archive_summary: dict[str, Any] = catalog["summary"]
            by_name = {info.filename: info for info in infos}
            names = [info.filename for info in infos]
            budget = _ReadBudget(_MAX_TOTAL_READ_BYTES)
            issues: list[str] = list(catalog["issues"])

            manifest_info = by_name.get("AndroidManifest.xml")
            manifest_bytes, manifest_truncated, manifest_error = _read_member_limited(
                archive,
                manifest_info,
                _MAX_MANIFEST_BYTES,
                budget,
            )
            manifest = _manifest_summary(
                manifest_bytes,
                present=manifest_info is not None,
                truncated=manifest_truncated,
                read_error=manifest_error,
            )
            if manifest_info is None:
                issues.append("AndroidManifest.xml is missing")
            elif manifest_error:
                issues.append(f"AndroidManifest.xml: {manifest_error}")
            elif manifest.get("status") != "ok":
                issues.append(
                    f"AndroidManifest.xml analysis status {manifest.get('status') or 'unavailable'}"
                )

            dex_infos = [info for info in infos if re.fullmatch(r"classes(?:\d+)?\.dex", info.filename)]
            dex_summary, dex_context, dex_issues = _dex_summary(archive, dex_infos, budget)
            issues.extend(dex_issues)

            native_infos = [
                info
                for info in infos
                if re.fullmatch(r"lib/[^/]+/[^/]+\.so", info.filename, flags=re.IGNORECASE)
            ]
            native, native_issues = _native_lib_summary(archive, native_infos, budget, dex_context)
            issues.extend(native_issues)

            resources, resource_issues = _resource_summary(archive, infos, budget)
            issues.extend(resource_issues)

            framework = _detect_framework(names, manifest, resources, dex_context, native)
            semantic_ir_fragment = _semantic_ir_fragment(
                manifest,
                resources,
                dex_summary,
                native,
                framework,
            )

            archive_summary["read_budget_bytes"] = budget.limit
            archive_summary["read_bytes"] = budget.used
            archive_summary["read_budget_exhausted"] = budget.remaining == 0
            if budget.remaining == 0:
                issues.append("APK read budget exhausted; remaining evidence was not read")

            status = "partial" if issues else "ok"
            result = _result_payload(
                status=status,
                archive=archive_summary,
                manifest=manifest,
                resources=resources,
                dex_summary=dex_summary,
                native=native,
                framework=framework,
                semantic_ir_fragment=semantic_ir_fragment,
                issues=issues,
            )
    except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error) as exc:
        result = _unavailable_result(str(exc))

    return _finish_android_analysis(
        result,
        sample,
        out_dir,
        evidence=evidence,
        config=config,
        jadx_runner=jadx_runner,
        jadx_executable_finder=jadx_executable_finder,
    )


def _finish_android_analysis(
    result: dict[str, Any],
    sample: Path,
    out_dir: str | os.PathLike[str] | None,
    *,
    evidence: Mapping[str, Any] | None,
    config: Mapping[str, Any] | None,
    jadx_runner: JadxRunner | None,
    jadx_executable_finder: JadxExecutableFinder | None,
) -> dict[str, Any]:
    requested, jadx_config, request_error = _java_decompilation_request(evidence, config)
    if not requested:
        java_decompilation = _unrequested_java_decompilation()
    elif request_error:
        java_decompilation = _java_decompilation_payload(
            status="failed",
            requested=True,
            reason=f"invalid JADX request: {request_error}",
            dependency_state="not_checked",
        )
    elif out_dir is None:
        java_decompilation = _java_decompilation_payload(
            status="failed",
            requested=True,
            reason="JADX requires an output directory for bounded artifacts",
            dependency_state="not_checked",
        )
    elif (
        not sample.is_file()
        or sample.suffix.lower() != ".apk"
        or str((result.get("archive") or {}).get("status")) == "unavailable"
    ):
        java_decompilation = _java_decompilation_payload(
            status="failed",
            requested=True,
            reason="JADX was not run because APK validation did not establish a readable input",
            dependency_state="not_checked",
        )
    else:
        java_decompilation = android_java_decompile(
            sample,
            out_dir,
            config=jadx_config,
            runner=jadx_runner,
            executable_finder=jadx_executable_finder,
        )

    result["java_decompilation"] = java_decompilation
    if requested and java_decompilation.get("status") != "passed":
        result.setdefault("warnings", []).append(
            f"Java/Kotlin decompilation {java_decompilation.get('status')}: "
            f"{java_decompilation.get('reason')}"
        )
        result["warnings"] = _dedupe_strings(result["warnings"], _MAX_WARNINGS)
        if result.get("status") == "ok":
            result["status"] = "partial"
    return _persist_artifacts(result, out_dir)


def _result_payload(
    *,
    status: str,
    archive: Mapping[str, Any],
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    dex_summary: Mapping[str, Any],
    native: Mapping[str, Any],
    framework: Mapping[str, Any],
    semantic_ir_fragment: Mapping[str, Any],
    issues: Sequence[str],
) -> dict[str, Any]:
    framework_name = str(framework.get("name") or "unknown")
    return {
        "status": status,
        "package_type": "apk",
        "archive": dict(archive),
        "framework": dict(framework),
        "manifest": dict(manifest),
        "resources": dict(resources),
        "dex_summary": dict(dex_summary),
        "native_libs": dict(native),
        "java_decompilation": _unrequested_java_decompilation(),
        "semantic_ir_fragment": dict(semantic_ir_fragment),
        "capability_boundary": _analysis_capability_boundary(),
        "strategy": {
            "name": f"{framework_name}_static_unpack",
            "key": f"android:{framework_name}_static_unpack",
            "reason": "Static package structure preserves Android resources, DEX, and native-library evidence.",
        },
        "warnings": _dedupe_strings(issues, _MAX_WARNINGS),
        "artifacts": [],
    }


def _analysis_capability_boundary() -> dict[str, Any]:
    return {
        "provider_kind": "builtin",
        "operation_kind": "bounded_zip_static_analysis",
        "dependency_state": "not_required",
        "required_tools": [],
        "content_recompiled": False,
        "byte_preserving": True,
        "signature_verification": "not_performed",
        "code_executed": False,
        "members_extracted": False,
    }


def _unavailable_result(
    error: str,
    *,
    status: str = "unavailable",
    package_type: str = "apk",
    framework_reason: str = "APK central directory could not be read",
) -> dict[str, Any]:
    manifest = _empty_manifest()
    resources = _empty_resources()
    dex_summary = _empty_dex_summary()
    native = _empty_native_summary()
    framework = _unknown_framework(framework_reason)
    semantic = _semantic_ir_fragment(manifest, resources, dex_summary, native, framework)
    result = _result_payload(
        status=status,
        archive={
            "status": "unavailable",
            "entry_count": 0,
            "safe_entry_count": 0,
            "unsafe_entry_count": 0,
            "unsafe_entries": [],
        },
        manifest=manifest,
        resources=resources,
        dex_summary=dex_summary,
        native=native,
        framework=framework,
        semantic_ir_fragment=semantic,
        issues=[error],
    )
    result["package_type"] = package_type
    result["error"] = error
    return result


def _persist_artifacts(result: dict[str, Any], out_dir: str | os.PathLike[str] | None) -> dict[str, Any]:
    if not out_dir:
        return result

    android_dir = Path(out_dir) / "android"
    payloads = {
        "android/manifest.json": result["manifest"],
        "android/resources.json": result["resources"],
        "android/dex_summary.json": result["dex_summary"],
        "android/native_libs.json": result["native_libs"],
        "android/framework.json": result["framework"],
        "android/java_decompilation.json": result["java_decompilation"],
        "android/semantic_ir_fragment.json": result["semantic_ir_fragment"],
    }
    artifacts: list[dict[str, Any]] = []
    try:
        android_dir.mkdir(parents=True, exist_ok=True)
        for name, payload in payloads.items():
            artifact_path = Path(out_dir) / Path(name)
            _write_json(artifact_path, payload)
            artifacts.append({"name": name, "path": str(artifact_path), "kind": "android-analysis"})
        output = result.get("java_decompilation", {}).get("output", {})
        for item in output.get("files", []):
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("path") or "")
            if not name:
                continue
            artifact_path = (Path(out_dir) / Path(name)).resolve(strict=False)
            try:
                artifact_path.relative_to(Path(out_dir).resolve(strict=False))
            except ValueError:
                raise OSError("JADX artifact path escapes the analysis output directory")
            if not artifact_path.is_file():
                raise OSError(f"JADX artifact is missing: {name}")
            artifacts.append(
                {"name": name, "path": str(artifact_path), "kind": "android-decompiled-source"}
            )
    except OSError as exc:
        result.setdefault("warnings", []).append(f"unable to persist Android artifacts: {exc}")
        if result.get("status") == "ok":
            result["status"] = "partial"
    result["artifacts"] = artifacts
    return result


def _catalog_archive(archive: zipfile.ZipFile) -> dict[str, Any]:
    all_infos = sorted(archive.infolist(), key=_zip_info_sort_key)
    inspected = all_infos[:_MAX_ZIP_ENTRIES]
    safe_infos: list[zipfile.ZipInfo] = []
    unsafe: list[dict[str, str]] = []
    duplicates: list[str] = []
    unsafe_count = 0
    duplicate_count = 0
    seen: set[str] = set()
    declared_bytes = 0

    for info in inspected:
        declared_bytes += max(0, info.file_size)
        issue = _zip_member_issue(info)
        if issue:
            unsafe_count += 1
            if len(unsafe) < _MAX_EXAMPLES:
                unsafe.append({"name": info.filename[:_MAX_ZIP_NAME_LENGTH], "reason": issue})
            continue
        if info.is_dir():
            continue
        if info.filename in seen:
            duplicate_count += 1
            if len(duplicates) < _MAX_EXAMPLES:
                duplicates.append(info.filename)
            continue
        seen.add(info.filename)
        safe_infos.append(info)

    entry_limit_hit = len(all_infos) > len(inspected)
    declared_limit_hit = declared_bytes > _MAX_DECLARED_ARCHIVE_BYTES
    issues: list[str] = []
    if unsafe_count:
        issues.append(f"ignored {unsafe_count} unsafe or over-limit ZIP member(s)")
    if duplicate_count:
        issues.append(f"ignored {duplicate_count} duplicate ZIP member name(s)")
    if entry_limit_hit:
        issues.append(f"ZIP entry limit {_MAX_ZIP_ENTRIES} reached")
    if declared_limit_hit:
        issues.append("declared APK uncompressed size exceeds analysis limit")

    return {
        "infos": safe_infos,
        "issues": issues,
        "summary": {
            "status": "partial" if issues else "ok",
            "entry_count": len(all_infos),
            "inspected_entry_count": len(inspected),
            "safe_entry_count": len(safe_infos),
            "unsafe_entry_count": unsafe_count,
            "unsafe_entries": unsafe,
            "duplicate_entry_count": duplicate_count,
            "duplicate_entries": duplicates,
            "entry_limit": _MAX_ZIP_ENTRIES,
            "entry_limit_hit": entry_limit_hit,
            "declared_uncompressed_bytes": declared_bytes,
            "declared_uncompressed_limit": _MAX_DECLARED_ARCHIVE_BYTES,
            "declared_size_limit_hit": declared_limit_hit,
            "members_extracted": 0,
        },
    }


def _zip_info_sort_key(info: zipfile.ZipInfo) -> tuple[Any, ...]:
    return (
        info.filename,
        int(info.CRC),
        int(info.file_size),
        int(info.compress_size),
        int(info.compress_type),
        int(info.flag_bits),
        int(info.external_attr),
    )


def _zip_member_issue(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    if not name or len(name) > _MAX_ZIP_NAME_LENGTH:
        return "empty or overlong member name"
    if "\x00" in name:
        return "NUL in member name"
    if "\\" in name:
        return "backslash in member name"
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        return "absolute member path"
    parts = name.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "non-canonical member path"
    unix_mode = (info.external_attr >> 16) & 0xFFFF
    if unix_mode and stat.S_ISLNK(unix_mode):
        return "symbolic-link member"
    if info.flag_bits & 0x1:
        return "encrypted member"
    if info.file_size > _MAX_DECLARED_MEMBER_BYTES:
        return "declared member size exceeds limit"
    if info.file_size > 1_048_576:
        if info.compress_size == 0 or info.file_size / max(1, info.compress_size) > _MAX_COMPRESSION_RATIO:
            return "suspicious compression ratio"
    return None


def _read_member_limited(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo | None,
    limit: int,
    budget: _ReadBudget,
) -> tuple[bytes, bool, str | None]:
    if info is None:
        return b"", False, None
    read_limit = min(max(0, limit), budget.remaining)
    if read_limit <= 0:
        return b"", True, "read budget exhausted"
    try:
        with archive.open(info, "r") as stream:
            data = stream.read(read_limit + 1)
    except (OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error) as exc:
        return b"", False, str(exc)
    truncated = len(data) > read_limit or info.file_size > read_limit
    data = data[:read_limit]
    budget.consume(len(data))
    return data, truncated, None


def _manifest_summary(
    manifest_bytes: bytes,
    *,
    present: bool | None = None,
    truncated: bool = False,
    read_error: str | None = None,
) -> dict[str, Any]:
    present = bool(manifest_bytes) if present is None else present
    if not present:
        return _empty_manifest()
    if read_error:
        result = _empty_manifest()
        result.update({"present": True, "status": "unavailable", "warnings": [read_error]})
        return result
    if not manifest_bytes:
        result = _empty_manifest()
        result.update({"present": True, "status": "unavailable", "warnings": ["manifest member is empty"]})
        return result

    text = _decode_xml_text(manifest_bytes)
    warnings: list[str] = []
    if text is not None and text.lstrip().startswith("<"):
        try:
            elements, xml_warnings = _text_xml_elements(text)
            result = _manifest_from_elements(elements, parser="text_xml", textual=True)
            warnings.extend(xml_warnings)
            if xml_warnings:
                result["status"] = "partial"
        except (ET.ParseError, ValueError) as exc:
            warnings.append(f"text XML parse failed: {exc}")
            result = _manifest_fallback(manifest_bytes, text=text, parser="text_fallback")
    elif len(manifest_bytes) >= 8 and _u16(manifest_bytes, 0, "<") == 0x0003:
        try:
            axml = _parse_binary_xml(manifest_bytes)
            if not axml["elements"]:
                raise ValueError("binary XML contains no start elements")
            result = _manifest_from_elements(axml["elements"], parser="binary_axml", textual=False)
            warnings.extend(axml["warnings"])
            if axml["status"] != "ok":
                result["status"] = "partial"
        except (IndexError, UnicodeError, ValueError, struct.error) as exc:
            warnings.append(f"binary AXML parse failed: {exc}")
            result = _manifest_fallback(manifest_bytes, parser="binary_fallback")
    else:
        result = _manifest_fallback(manifest_bytes, text=text, parser="binary_fallback")
        warnings.append("manifest encoding was not recognized as text XML or binary AXML")

    if truncated:
        warnings.append(f"manifest read was limited to {_MAX_MANIFEST_BYTES} bytes")
        result["status"] = "partial"
    if warnings:
        result["warnings"] = _dedupe_strings([*result.get("warnings", []), *warnings], _MAX_WARNINGS)
    return result


def _empty_manifest() -> dict[str, Any]:
    return {
        "present": False,
        "status": "unavailable",
        "parser": "none",
        "package": None,
        "version_code": None,
        "version_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "application": None,
        "permissions": [],
        "permission_count": 0,
        "permission_hint_count": 0,
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "component_counts": {"activities": 0, "services": 0, "receivers": 0, "providers": 0},
        "activity_hint_count": 0,
        "uses_features": [],
        "textual": False,
        "element_count": 0,
        "fallback_strings": [],
        "warnings": [],
    }


def _decode_xml_text(data: bytes) -> str | None:
    candidates: list[str] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append("utf-16")
    candidates.append("utf-8-sig")
    if data[:64].count(b"\x00") >= 8:
        candidates.extend(("utf-16le", "utf-16be"))
    for encoding in candidates:
        try:
            text = data.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        if text.lstrip().startswith("<"):
            return text
    return None


def _text_xml_elements(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    declaration_issue = _xml_declaration_issue(text)
    if declaration_issue:
        raise ValueError(declaration_issue)
    root = ET.fromstring(text)
    elements: list[dict[str, Any]] = []
    warnings: list[str] = []
    for index, element in enumerate(root.iter()):
        if index >= _MAX_AXML_ELEMENTS:
            warnings.append(f"text XML element limit {_MAX_AXML_ELEMENTS} reached")
            break
        attributes = list(element.attrib.items())
        if len(attributes) > _MAX_AXML_ATTRIBUTES:
            warnings.append(f"text XML attribute limit {_MAX_AXML_ATTRIBUTES} reached")
        elements.append(
            {
                "tag": _local_name(element.tag),
                "attributes": {
                    _normalized_xml_attr(key): value for key, value in attributes[:_MAX_AXML_ATTRIBUTES]
                },
            }
        )
    return elements, _dedupe_strings(warnings, _MAX_WARNINGS)


def _xml_declaration_issue(text: str) -> str | None:
    lowered = text.casefold()
    if "<!doctype" in lowered or "<!entity" in lowered:
        return "DTD/entity declarations are not accepted"
    return None


def _normalized_xml_attr(name: str) -> str:
    if name.startswith("{") and "}" in name:
        namespace, local = name[1:].split("}", 1)
        if namespace == _ANDROID_NS:
            return f"android:{local}"
        return local
    return name


def _manifest_from_elements(elements: Sequence[Mapping[str, Any]], *, parser: str, textual: bool) -> dict[str, Any]:
    result = _empty_manifest()
    result.update({"present": True, "status": "ok", "parser": parser, "textual": textual})
    component_keys = {
        "activity": "activities",
        "activity-alias": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }
    features: list[str] = []

    for element in elements[:_MAX_AXML_ELEMENTS]:
        tag = str(element.get("tag") or "")
        attrs = element.get("attributes") if isinstance(element.get("attributes"), Mapping) else {}
        if tag == "manifest":
            result["package"] = _attr(attrs, "package") or result["package"]
            result["version_code"] = _attr(attrs, "versionCode") or result["version_code"]
            result["version_name"] = _attr(attrs, "versionName") or result["version_name"]
        elif tag == "uses-sdk":
            result["min_sdk"] = _attr(attrs, "minSdkVersion") or result["min_sdk"]
            result["target_sdk"] = _attr(attrs, "targetSdkVersion") or result["target_sdk"]
        elif tag in {"uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"}:
            permission = _attr(attrs, "name")
            if permission and permission not in result["permissions"] and len(result["permissions"]) < _MAX_MANIFEST_COMPONENTS:
                result["permissions"].append(permission)
        elif tag == "uses-feature":
            feature = _attr(attrs, "name")
            if feature and feature not in features and len(features) < _MAX_MANIFEST_COMPONENTS:
                features.append(feature)
        elif tag == "application":
            result["application"] = _attr(attrs, "name") or result["application"]
        elif tag in component_keys:
            key = component_keys[tag]
            if len(result[key]) < _MAX_MANIFEST_COMPONENTS:
                component = {
                    "name": _attr(attrs, "name"),
                    "exported": _coerce_bool(_attr(attrs, "exported")),
                }
                if tag == "activity-alias":
                    component["component_type"] = "activity-alias"
                    component["target_activity"] = _attr(attrs, "targetActivity")
                result[key].append(component)

    result["permissions"] = _dedupe_strings(result["permissions"], _MAX_MANIFEST_COMPONENTS)
    result["permission_count"] = len(result["permissions"])
    result["permission_hint_count"] = result["permission_count"]
    result["activity_hint_count"] = len(result["activities"])
    result["component_counts"] = {
        "activities": len(result["activities"]),
        "services": len(result["services"]),
        "receivers": len(result["receivers"]),
        "providers": len(result["providers"]),
    }
    result["uses_features"] = features
    result["element_count"] = min(len(elements), _MAX_AXML_ELEMENTS)
    return result


def _manifest_fallback(data: bytes, *, text: str | None = None, parser: str) -> dict[str, Any]:
    strings = _extract_printable_strings(data, min_length=3, max_strings=512)
    searchable = text if text is not None else "\n".join(strings)
    package_match = re.search(r"\bpackage\s*=\s*['\"]([^'\"]+)", searchable)
    if package_match:
        package_name = package_match.group(1)
    else:
        package_name = next(
            (
                value
                for value in strings
                if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}", value)
                and not value.startswith(("android.permission.", "http."))
            ),
            None,
        )
    permissions = _dedupe_strings(
        re.findall(r"android\.permission\.[A-Z0-9_]+", searchable, flags=re.IGNORECASE),
        _MAX_MANIFEST_COMPONENTS,
    )
    activities = len(re.findall(r"<\s*activity(?:\s|>)", searchable, flags=re.IGNORECASE))
    result = _empty_manifest()
    result.update(
        {
            "present": True,
            "status": "partial",
            "parser": parser,
            "package": package_name,
            "permissions": permissions,
            "permission_count": len(permissions),
            "permission_hint_count": len(permissions),
            "activity_hint_count": activities,
            "component_counts": {"activities": activities, "services": 0, "receivers": 0, "providers": 0},
            "textual": text is not None,
            "fallback_strings": strings[:32],
            "warnings": ["manifest fields were recovered heuristically"],
        }
    )
    return result


def _parse_binary_xml(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or _u16(data, 0, "<") != 0x0003:
        raise ValueError("not an Android binary XML document")
    header_size = _u16(data, 2, "<")
    declared_size = _u32(data, 4, "<")
    if header_size < 8 or header_size > len(data):
        raise ValueError("invalid binary XML header size")
    limit = min(len(data), declared_size if declared_size >= header_size else len(data))
    warnings: list[str] = []
    if declared_size > len(data):
        warnings.append("binary XML is truncated")

    strings: list[str | None] = []
    resource_map: list[int] = []
    elements: list[dict[str, Any]] = []
    offset = header_size
    chunk_count = 0
    while offset + 8 <= limit and chunk_count < _MAX_AXML_CHUNKS:
        chunk_count += 1
        chunk_type = _u16(data, offset, "<")
        chunk_header_size = _u16(data, offset + 2, "<")
        chunk_size = _u32(data, offset + 4, "<")
        if chunk_header_size < 8 or chunk_size < chunk_header_size or offset + chunk_size > limit:
            warnings.append(f"invalid or truncated binary XML chunk at offset {offset}")
            break
        if chunk_type == 0x0001:
            strings, pool_warnings = _parse_axml_string_pool(data, offset, chunk_header_size, chunk_size)
            warnings.extend(pool_warnings)
        elif chunk_type == 0x0180:
            count = min((chunk_size - chunk_header_size) // 4, _MAX_AXML_STRINGS)
            resource_map = [_u32(data, offset + chunk_header_size + (index * 4), "<") for index in range(count)]
        elif chunk_type == 0x0102 and len(elements) < _MAX_AXML_ELEMENTS:
            try:
                element, element_warnings = _parse_axml_start_element(
                    data,
                    offset,
                    chunk_size,
                    strings,
                    resource_map,
                )
                elements.append(element)
                warnings.extend(element_warnings)
            except (IndexError, ValueError, struct.error) as exc:
                warnings.append(f"unable to parse start element at offset {offset}: {exc}")
        offset += chunk_size

    if chunk_count >= _MAX_AXML_CHUNKS and offset < limit:
        warnings.append(f"binary XML chunk limit {_MAX_AXML_CHUNKS} reached")
    return {
        "status": "partial" if warnings else "ok",
        "elements": elements,
        "root": elements[0]["tag"] if elements else None,
        "declared_string_count": len(strings),
        "chunk_count": chunk_count,
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
    }


def _parse_axml_string_pool(
    data: bytes,
    offset: int,
    header_size: int,
    chunk_size: int,
) -> tuple[list[str | None], list[str]]:
    if header_size < 28 or offset + header_size > len(data):
        raise ValueError("invalid string-pool header")
    string_count = _u32(data, offset + 8, "<")
    flags = _u32(data, offset + 16, "<")
    strings_start = _u32(data, offset + 20, "<")
    utf8 = bool(flags & 0x00000100)
    count = min(string_count, _MAX_AXML_STRINGS)
    warnings: list[str] = []
    if string_count > count:
        warnings.append(f"binary XML string limit {_MAX_AXML_STRINGS} reached")
    offsets_start = offset + header_size
    if offsets_start + (count * 4) > offset + chunk_size:
        raise ValueError("string-pool offsets exceed chunk")

    strings: list[str | None] = []
    chunk_end = min(len(data), offset + chunk_size)
    for index in range(count):
        relative = _u32(data, offsets_start + (index * 4), "<")
        string_offset = offset + strings_start + relative
        try:
            if utf8:
                value = _decode_axml_utf8(data, string_offset, chunk_end)
            else:
                value = _decode_axml_utf16(data, string_offset, chunk_end)
        except (UnicodeError, ValueError):
            value = None
        strings.append(value)
    return strings, warnings


def _decode_axml_utf8(data: bytes, offset: int, end: int) -> str:
    _, offset = _axml_length8(data, offset, end)
    byte_length, offset = _axml_length8(data, offset, end)
    if byte_length > _MAX_DEX_STRING_BYTES * 4 or offset + byte_length > end:
        raise ValueError("invalid UTF-8 string length")
    return data[offset : offset + byte_length].decode("utf-8", errors="replace")


def _decode_axml_utf16(data: bytes, offset: int, end: int) -> str:
    char_length, offset = _axml_length16(data, offset, end)
    byte_length = char_length * 2
    if byte_length > _MAX_DEX_STRING_BYTES * 4 or offset + byte_length > end:
        raise ValueError("invalid UTF-16 string length")
    return data[offset : offset + byte_length].decode("utf-16le", errors="replace")


def _axml_length8(data: bytes, offset: int, end: int) -> tuple[int, int]:
    if offset >= end:
        raise ValueError("truncated UTF-8 length")
    first = data[offset]
    offset += 1
    if first & 0x80:
        if offset >= end:
            raise ValueError("truncated UTF-8 length")
        return ((first & 0x7F) << 8) | data[offset], offset + 1
    return first, offset


def _axml_length16(data: bytes, offset: int, end: int) -> tuple[int, int]:
    if offset + 2 > end:
        raise ValueError("truncated UTF-16 length")
    first = _u16(data, offset, "<")
    offset += 2
    if first & 0x8000:
        if offset + 2 > end:
            raise ValueError("truncated UTF-16 length")
        return ((first & 0x7FFF) << 16) | _u16(data, offset, "<"), offset + 2
    return first, offset


def _parse_axml_start_element(
    data: bytes,
    offset: int,
    chunk_size: int,
    strings: Sequence[str | None],
    resource_map: Sequence[int],
) -> tuple[dict[str, Any], list[str]]:
    if chunk_size < 36:
        raise ValueError("start-element chunk is too small")
    name_index = _u32(data, offset + 20, "<")
    attribute_start = _u16(data, offset + 24, "<")
    attribute_size = _u16(data, offset + 26, "<")
    declared_count = _u16(data, offset + 28, "<")
    if attribute_size < 20:
        raise ValueError("invalid binary XML attribute size")
    count = min(declared_count, _MAX_AXML_ATTRIBUTES)
    warnings: list[str] = []
    if declared_count > count:
        warnings.append(f"attribute limit {_MAX_AXML_ATTRIBUTES} reached")
    attributes_offset = offset + 16 + attribute_start
    chunk_end = offset + chunk_size
    attributes: dict[str, Any] = {}
    for index in range(count):
        item = attributes_offset + (index * attribute_size)
        if item + 20 > chunk_end:
            warnings.append("attribute array is truncated")
            break
        namespace_index = _u32(data, item, "<")
        attribute_name_index = _u32(data, item + 4, "<")
        raw_value_index = _u32(data, item + 8, "<")
        data_type = data[item + 15]
        typed_data = _u32(data, item + 16, "<")
        attribute_name = _pool_string(strings, attribute_name_index)
        if not attribute_name and attribute_name_index < len(resource_map):
            attribute_name = _ANDROID_ATTRIBUTE_IDS.get(resource_map[attribute_name_index])
        if not attribute_name:
            attribute_name = f"attribute_{attribute_name_index}"
        namespace = _pool_string(strings, namespace_index)
        key = f"android:{attribute_name}" if namespace == _ANDROID_NS else attribute_name
        if raw_value_index != _NO_INDEX:
            value: Any = _pool_string(strings, raw_value_index)
        else:
            value = _typed_axml_value(data_type, typed_data, strings)
        attributes[key] = value
    return {"tag": _pool_string(strings, name_index) or f"element_{name_index}", "attributes": attributes}, warnings


def _typed_axml_value(data_type: int, data: int, strings: Sequence[str | None]) -> Any:
    if data_type == 0x03:
        return _pool_string(strings, data)
    if data_type == 0x12:
        return bool(data)
    if data_type == 0x10:
        return data
    if data_type == 0x11:
        return f"0x{data:08x}"
    if data_type in {0x01, 0x02}:
        return f"@0x{data:08x}"
    return data


def _pool_string(strings: Sequence[str | None], index: int) -> str | None:
    if index == _NO_INDEX or index >= len(strings):
        return None
    return strings[index]


def _dex_summary(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
    budget: _ReadBudget,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    files: list[dict[str, Any]] = []
    issues: list[str] = []
    context_values: list[dict[str, str]] = []
    totals = {name: 0 for name in _DEX_SECTION_SIZES}
    parsed_infos = list(infos[:_MAX_DEX_FILES])
    if len(infos) > len(parsed_infos):
        issues.append(f"DEX file limit {_MAX_DEX_FILES} reached")

    for info in parsed_infos:
        data, truncated, error = _read_member_limited(archive, info, _MAX_DEX_BYTES, budget)
        if error:
            files.append(_unavailable_dex_file(info, error))
            issues.append(f"{info.filename}: {error}")
            continue
        parsed, strings = _parse_dex(data, info.file_size, truncated)
        parsed["name"] = info.filename
        files.append(parsed)
        for key in totals:
            totals[key] += int(parsed.get("counts", {}).get(key, 0) or 0)
        for value in strings:
            if len(context_values) >= _MAX_DEX_CONTEXT_STRINGS:
                break
            context_values.append({"dex": info.filename, "value": value})
        if parsed["status"] != "ok":
            issues.append(f"{info.filename}: DEX parsing status {parsed['status']}")

    evidence = _dex_string_evidence(context_values)
    status_counts = Counter(str(item.get("status") or "unavailable") for item in files)
    summary: dict[str, Any] = {
        "status": "partial" if issues else ("ok" if infos else "unavailable"),
        "dex_count": len(infos),
        "parsed_count": len(files),
        "dex_files": [info.filename for info in infos[:_MAX_EXAMPLES]],
        "files": files,
        "totals": totals,
        "string_ids": totals["string_ids"],
        "type_ids": totals["type_ids"],
        "proto_ids": totals["proto_ids"],
        "field_ids": totals["field_ids"],
        "method_ids": totals["method_ids"],
        "class_defs": totals["class_defs"],
        "valid_count": status_counts.get("ok", 0),
        "partial_count": status_counts.get("partial", 0),
        "invalid_count": status_counts.get("unavailable", 0),
        "string_evidence": evidence,
        "limits": {
            "max_dex_files": _MAX_DEX_FILES,
            "max_bytes_per_dex": _MAX_DEX_BYTES,
            "max_string_ids_per_dex": _MAX_DEX_STRING_IDS,
            "max_string_evidence": _MAX_DEX_EVIDENCE,
        },
    }
    context = {
        "strings": context_values,
        "lower_strings": {item["value"].casefold() for item in context_values},
        "evidence": evidence,
    }
    return summary, context, issues


def _empty_dex_summary() -> dict[str, Any]:
    totals = {name: 0 for name in _DEX_SECTION_SIZES}
    return {
        "status": "unavailable",
        "dex_count": 0,
        "parsed_count": 0,
        "dex_files": [],
        "files": [],
        "totals": totals,
        "string_ids": 0,
        "type_ids": 0,
        "proto_ids": 0,
        "field_ids": 0,
        "method_ids": 0,
        "class_defs": 0,
        "valid_count": 0,
        "partial_count": 0,
        "invalid_count": 0,
        "string_evidence": [],
        "limits": {
            "max_dex_files": _MAX_DEX_FILES,
            "max_bytes_per_dex": _MAX_DEX_BYTES,
            "max_string_ids_per_dex": _MAX_DEX_STRING_IDS,
            "max_string_evidence": _MAX_DEX_EVIDENCE,
        },
    }


def _unavailable_dex_file(info: zipfile.ZipInfo, error: str) -> dict[str, Any]:
    return {
        "name": info.filename,
        "status": "unavailable",
        "version": None,
        "checksum": None,
        "checksum_valid": None,
        "file_size": None,
        "archive_file_size": info.file_size,
        "file_size_matches": None,
        "counts": {name: 0 for name in _DEX_SECTION_SIZES},
        "string_evidence": [],
        "warnings": [error],
    }


def _parse_dex(data: bytes, archive_size: int, truncated: bool) -> tuple[dict[str, Any], list[str]]:
    warnings: list[str] = []
    empty_counts = {name: 0 for name in _DEX_SECTION_SIZES}
    if len(data) < 112:
        return (
            {
                "status": "unavailable",
                "version": None,
                "magic_valid": False,
                "checksum": None,
                "checksum_valid": None,
                "file_size": None,
                "archive_file_size": archive_size,
                "file_size_matches": None,
                "counts": empty_counts,
                "string_evidence": [],
                "warnings": ["DEX header is truncated"],
            },
            [],
        )

    magic_match = re.fullmatch(rb"dex\n(\d{3})\x00", data[:8])
    if not magic_match:
        return (
            {
                "status": "unavailable",
                "version": None,
                "magic_valid": False,
                "checksum": f"0x{_u32(data, 8, '<'):08x}",
                "checksum_valid": None,
                "file_size": _u32(data, 32, "<"),
                "archive_file_size": archive_size,
                "file_size_matches": False,
                "counts": empty_counts,
                "string_evidence": [],
                "warnings": ["invalid DEX magic"],
            },
            [],
        )

    version = magic_match.group(1).decode("ascii")
    checksum = _u32(data, 8, "<")
    file_size = _u32(data, 32, "<")
    header_size = _u32(data, 36, "<")
    endian_tag = _u32(data, 40, "<")
    fields = (
        ("string_ids", 56, 60),
        ("type_ids", 64, 68),
        ("proto_ids", 72, 76),
        ("field_ids", 80, 84),
        ("method_ids", 88, 92),
        ("class_defs", 96, 100),
    )
    counts = {name: _u32(data, count_offset, "<") for name, count_offset, _ in fields}
    offsets = {name: _u32(data, offset_offset, "<") for name, _, offset_offset in fields}

    if header_size != 112:
        warnings.append(f"unexpected DEX header size {header_size}")
    if endian_tag != 0x12345678:
        warnings.append(f"unsupported DEX endian tag 0x{endian_tag:08x}")
    if file_size != archive_size:
        warnings.append(f"DEX header file_size {file_size} differs from ZIP size {archive_size}")
    if file_size < 112:
        warnings.append("DEX file_size is smaller than its header")
    for section_name, item_size in _DEX_SECTION_SIZES.items():
        count = counts[section_name]
        section_offset = offsets[section_name]
        if count == 0:
            continue
        if section_offset < 112 or section_offset + (count * item_size) > max(file_size, archive_size):
            warnings.append(f"{section_name} table lies outside declared DEX bounds")

    complete = not truncated and len(data) == archive_size
    checksum_valid: bool | None = None
    if complete and file_size == len(data):
        checksum_valid = (zlib.adler32(data[12:]) & 0xFFFFFFFF) == checksum
        if not checksum_valid:
            warnings.append("DEX Adler-32 checksum mismatch")
    else:
        warnings.append("DEX checksum was not verified because only a bounded prefix was read")

    strings, string_warnings = _parse_dex_strings(data, counts["string_ids"], offsets["string_ids"])
    warnings.extend(string_warnings)
    evidence_values = [item["value"] for item in _dex_string_evidence([{"dex": "", "value": value} for value in strings])]
    structurally_valid = header_size == 112 and endian_tag == 0x12345678 and file_size >= 112
    status = "ok" if structurally_valid and not warnings else ("partial" if structurally_valid else "unavailable")
    return (
        {
            "status": status,
            "version": version,
            "magic_valid": True,
            "checksum": f"0x{checksum:08x}",
            "checksum_valid": checksum_valid,
            "signature": data[12:32].hex(),
            "file_size": file_size,
            "archive_file_size": archive_size,
            "file_size_matches": file_size == archive_size,
            "header_size": header_size,
            "endian_tag": f"0x{endian_tag:08x}",
            "counts": counts,
            "offsets": offsets,
            "string_evidence": evidence_values[:_MAX_DEX_EVIDENCE],
            "strings_scanned": min(counts["string_ids"], _MAX_DEX_STRING_IDS),
            "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
        },
        strings,
    )


def _parse_dex_strings(data: bytes, count: int, table_offset: int) -> tuple[list[str], list[str]]:
    if count == 0:
        return [], []
    warnings: list[str] = []
    scan_count = min(count, _MAX_DEX_STRING_IDS)
    if count > scan_count:
        warnings.append(f"DEX string-id scan limit {_MAX_DEX_STRING_IDS} reached")
    if table_offset < 112 or table_offset + (scan_count * 4) > len(data):
        return [], ["DEX string-id table is outside the bytes read"]

    values: list[str] = []
    for index in range(scan_count):
        data_offset = _u32(data, table_offset + (index * 4), "<")
        if data_offset >= len(data):
            continue
        try:
            _, string_offset = _read_uleb128(data, data_offset)
        except ValueError:
            continue
        end = data.find(b"\x00", string_offset, min(len(data), string_offset + _MAX_DEX_STRING_BYTES + 1))
        if end < 0:
            continue
        raw = data[string_offset:end].replace(b"\xc0\x80", b"\x00")
        value = raw.decode("utf-8", errors="replace")
        if _useful_string(value):
            values.append(value)
    return _dedupe_strings(values, _MAX_DEX_STRING_IDS), warnings


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("ULEB128 is too large")


def _dex_string_evidence(values: Sequence[Mapping[str, str]]) -> list[dict[str, str]]:
    ranked: list[tuple[int, int, dict[str, str]]] = []
    for index, item in enumerate(values):
        value = str(item.get("value") or "")
        category, score = _classify_dex_string(value)
        if category is None:
            continue
        ranked.append(
            (
                -score,
                index,
                {"dex": str(item.get("dex") or ""), "value": value[:512], "category": category},
            )
        )
    ranked.sort(key=lambda item: (item[0], item[1]))
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for _, _, evidence in ranked:
        key = (evidence["dex"], evidence["value"])
        if key in seen:
            continue
        seen.add(key)
        result.append(evidence)
        if len(result) >= _MAX_DEX_EVIDENCE:
            break
    return result


def _classify_dex_string(value: str) -> tuple[str | None, int]:
    lowered = value.casefold()
    if re.match(r"^(?:https?|wss?)://", value):
        return "endpoint", 10
    if "loadlibrary" in lowered or "java/lang/system" in lowered or "system.loadlibrary" in lowered:
        return "native_loader", 9
    if re.fullmatch(r"L[A-Za-z0-9_$/.-]+;", value):
        return "class_descriptor", 8
    if any(
        token in lowered
        for token in (
            "androidx/compose",
            "io/flutter",
            "com/facebook/react",
            "com/unity3d/player",
            "android/webkit/webview",
        )
    ):
        return "framework", 8
    if re.fullmatch(r"lib[A-Za-z0-9_.+\-]+\.so", value, flags=re.IGNORECASE):
        return "native_library", 8
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.+\-]{2,80}", value):
        return "identifier", 2
    return None, 0


def _native_lib_summary(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
    budget: _ReadBudget,
    dex_context: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    entries: list[dict[str, Any]] = []
    issues: list[str] = []
    aggregated_jni: list[dict[str, str]] = []
    parsed_infos = list(infos[:_MAX_NATIVE_LIBS])
    if len(infos) > len(parsed_infos):
        issues.append(f"native-library limit {_MAX_NATIVE_LIBS} reached")

    for info in parsed_infos:
        parts = info.filename.split("/")
        abi = parts[1] if len(parts) >= 3 else "unknown"
        data, truncated, error = _read_member_limited(archive, info, _MAX_ELF_BYTES, budget)
        if error:
            elf = _empty_elf(error)
            issues.append(f"{info.filename}: {error}")
        else:
            elf = _analyze_elf(data, abi, info.file_size, truncated)
            if elf["status"] == "unavailable":
                issues.append(f"{info.filename}: not a readable ELF image")
            elif elf["status"] == "partial":
                detail = next(iter(elf.get("warnings", [])), "bounded ELF analysis")
                issues.append(f"{info.filename}: {detail}")
        entry = {
            "path": info.filename,
            "name": Path(info.filename).name,
            "library_name": _native_library_name(Path(info.filename).name),
            "abi": abi,
            "size": info.file_size,
            "elf": elf,
            "jni_exports": elf["jni_exports"],
            "string_evidence": elf["string_evidence"],
        }
        entries.append(entry)
        for symbol in elf["jni_exports"]:
            if len(aggregated_jni) < _MAX_JNI_EXPORTS:
                aggregated_jni.append({"library": info.filename, "symbol": symbol})

    links = _java_native_links(dex_context, entries)
    status = "partial" if issues else ("ok" if infos else "unavailable")
    return (
        {
            "status": status,
            "count": len(infos),
            "parsed_count": len(entries),
            "abis": sorted({entry["abi"] for entry in entries}),
            "libs": [info.filename for info in infos[:_MAX_EXAMPLES]],
            "entries": entries,
            "elf_count": sum(1 for entry in entries if entry["elf"].get("present")),
            "jni_export_count": len(aggregated_jni),
            "jni_exports": aggregated_jni,
            "java_native_links": links,
            "limits": {
                "max_native_libraries": _MAX_NATIVE_LIBS,
                "max_bytes_per_library": _MAX_ELF_BYTES,
                "max_elf_symbols": _MAX_ELF_SYMBOLS,
            },
        },
        issues,
    )


def _empty_native_summary() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "count": 0,
        "parsed_count": 0,
        "abis": [],
        "libs": [],
        "entries": [],
        "elf_count": 0,
        "jni_export_count": 0,
        "jni_exports": [],
        "java_native_links": [],
        "limits": {
            "max_native_libraries": _MAX_NATIVE_LIBS,
            "max_bytes_per_library": _MAX_ELF_BYTES,
            "max_elf_symbols": _MAX_ELF_SYMBOLS,
        },
    }


def _empty_elf(error: str) -> dict[str, Any]:
    return {
        "present": False,
        "status": "unavailable",
        "class": None,
        "endianness": None,
        "machine": None,
        "machine_name": None,
        "abi_consistent": None,
        "export_count": 0,
        "exports": [],
        "jni_exports": [],
        "string_evidence": [],
        "symbol_source": "none",
        "warnings": [error],
    }


def _analyze_elf(data: bytes, abi: str, archive_size: int, truncated: bool) -> dict[str, Any]:
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return _empty_elf("ELF magic/header is missing")
    elf_class_id = data[4]
    data_encoding = data[5]
    if elf_class_id not in {1, 2} or data_encoding not in {1, 2}:
        return _empty_elf("unsupported ELF class or byte order")
    endian = "<" if data_encoding == 1 else ">"
    endianness = "little" if data_encoding == 1 else "big"
    elf_class = "ELF32" if elf_class_id == 1 else "ELF64"
    min_header = 52 if elf_class_id == 1 else 64
    if len(data) < min_header:
        return _empty_elf("ELF header is truncated")

    machine = _u16(data, 18, endian)
    warnings: list[str] = []
    exports: list[str] = []
    jni_exports: list[str] = []
    dynsym_scanned = 0
    try:
        exports, dynsym_scanned, section_warnings = _elf_dynamic_symbols(data, elf_class_id, endian)
        warnings.extend(section_warnings)
    except (IndexError, ValueError, struct.error) as exc:
        warnings.append(f"ELF symbol parsing failed: {exc}")

    for symbol in exports:
        if symbol.startswith("Java_") or symbol in {"JNI_OnLoad", "JNI_OnUnload"}:
            jni_exports.append(symbol)
    string_jni = _scan_jni_symbols(data)
    for symbol in string_jni:
        if symbol not in jni_exports and len(jni_exports) < _MAX_JNI_EXPORTS:
            jni_exports.append(symbol)

    native_strings = _native_string_evidence(data)
    expected_machines = _ABI_MACHINES.get(abi.casefold())
    abi_consistent = machine in expected_machines if expected_machines else None
    if abi_consistent is False:
        warnings.append(f"ELF machine {_ELF_MACHINE_NAMES.get(machine, machine)} conflicts with ABI directory {abi}")
    if truncated or archive_size > len(data):
        warnings.append("ELF analysis used a bounded prefix")

    return {
        "present": True,
        "status": "partial" if warnings else "ok",
        "class": elf_class,
        "endianness": endianness,
        "machine": machine,
        "machine_name": _ELF_MACHINE_NAMES.get(machine, f"machine-{machine}"),
        "abi_consistent": abi_consistent,
        "archive_file_size": archive_size,
        "bytes_scanned": len(data),
        "export_count": len(exports),
        "exports": exports[:_MAX_ELF_EXPORTS],
        "symbols_scanned": dynsym_scanned,
        "jni_exports": jni_exports[:_MAX_JNI_EXPORTS],
        "string_evidence": native_strings,
        "symbol_source": (
            "dynsym+strings"
            if exports and string_jni
            else ("dynsym" if exports else ("strings" if string_jni else "none"))
        ),
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
    }


def _elf_dynamic_symbols(data: bytes, elf_class: int, endian: str) -> tuple[list[str], int, list[str]]:
    if elf_class == 1:
        section_offset = _u32(data, 32, endian)
        section_entry_size = _u16(data, 46, endian)
        section_count = _u16(data, 48, endian)
        min_section_size = 40
    else:
        section_offset = _u64(data, 40, endian)
        section_entry_size = _u16(data, 58, endian)
        section_count = _u16(data, 60, endian)
        min_section_size = 64
    if section_count == 0 or section_offset == 0:
        return [], 0, []
    warnings: list[str] = []
    count = min(section_count, _MAX_ELF_SECTIONS)
    if section_count > count:
        warnings.append(f"ELF section limit {_MAX_ELF_SECTIONS} reached")
    if section_entry_size < min_section_size or section_offset + (count * section_entry_size) > len(data):
        return [], 0, ["ELF section table lies outside bytes read"]

    sections: list[dict[str, int]] = []
    for index in range(count):
        item = section_offset + (index * section_entry_size)
        if elf_class == 1:
            sections.append(
                {
                    "type": _u32(data, item + 4, endian),
                    "offset": _u32(data, item + 16, endian),
                    "size": _u32(data, item + 20, endian),
                    "link": _u32(data, item + 24, endian),
                    "entry_size": _u32(data, item + 36, endian),
                }
            )
        else:
            sections.append(
                {
                    "type": _u32(data, item + 4, endian),
                    "offset": _u64(data, item + 24, endian),
                    "size": _u64(data, item + 32, endian),
                    "link": _u32(data, item + 40, endian),
                    "entry_size": _u64(data, item + 56, endian),
                }
            )

    exports: list[str] = []
    scanned = 0
    symbol_min_size = 16 if elf_class == 1 else 24
    for section in sections:
        if section["type"] != 11:
            continue
        link = section["link"]
        if link >= len(sections):
            warnings.append("ELF dynamic symbol table has an invalid string-table link")
            continue
        string_section = sections[link]
        symbol_offset = section["offset"]
        symbol_size = section["size"]
        entry_size = section["entry_size"] or symbol_min_size
        string_offset = string_section["offset"]
        string_size = string_section["size"]
        if (
            entry_size < symbol_min_size
            or symbol_offset + symbol_size > len(data)
            or string_offset + string_size > len(data)
        ):
            warnings.append("ELF dynamic symbol/string table lies outside bytes read")
            continue
        symbol_count = min(symbol_size // entry_size, _MAX_ELF_SYMBOLS - scanned)
        if symbol_size // entry_size > symbol_count:
            warnings.append(f"ELF symbol limit {_MAX_ELF_SYMBOLS} reached")
        for index in range(symbol_count):
            item = symbol_offset + (index * entry_size)
            name_offset = _u32(data, item, endian)
            if elf_class == 1:
                info = data[item + 12]
                section_index = _u16(data, item + 14, endian)
            else:
                info = data[item + 4]
                section_index = _u16(data, item + 6, endian)
            scanned += 1
            if name_offset >= string_size or section_index == 0 or (info >> 4) not in {1, 2}:
                continue
            name = _read_c_string(data, string_offset + name_offset, string_offset + string_size, 512)
            if name and name not in exports and len(exports) < _MAX_ELF_EXPORTS:
                exports.append(name)
        if scanned >= _MAX_ELF_SYMBOLS:
            break
    return exports, scanned, warnings


def _scan_jni_symbols(data: bytes) -> list[str]:
    pattern = re.compile(rb"(?:Java_[A-Za-z0-9_]{3,240}|JNI_On(?:Load|Unload))")
    result: list[str] = []
    for match in pattern.finditer(data):
        value = match.group(0).decode("ascii", errors="ignore")
        if value not in result:
            result.append(value)
        if len(result) >= _MAX_JNI_EXPORTS:
            break
    return result


def _native_string_evidence(data: bytes) -> list[str]:
    strings = _extract_printable_strings(data, min_length=5, max_strings=1_024)
    selected: list[str] = []
    for value in strings:
        if (
            value.startswith(("Java_", "JNI_On"))
            or re.fullmatch(r"lib[A-Za-z0-9_.+\-]+\.so", value, flags=re.IGNORECASE)
            or re.fullmatch(r"L[A-Za-z0-9_$/.-]+;", value)
            or re.fullmatch(r"(?:com|org|net)/[A-Za-z0-9_$/.-]+", value)
        ):
            selected.append(value)
        if len(selected) >= _MAX_EXAMPLES:
            break
    return _dedupe_strings(selected, _MAX_EXAMPLES)


def _java_native_links(dex_context: Mapping[str, Any], entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    dex_values = dex_context.get("strings") if isinstance(dex_context.get("strings"), list) else []
    loader_dexes = {
        str(item.get("dex") or "")
        for item in dex_values
        if "loadlibrary" in str(item.get("value") or "").casefold()
        or "java/lang/system" in str(item.get("value") or "").casefold()
    }
    by_lower: dict[str, set[str]] = {}
    for item in dex_values:
        value = str(item.get("value") or "")
        by_lower.setdefault(value.casefold(), set()).add(str(item.get("dex") or ""))

    links: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for entry in entries:
        library = str(entry.get("path") or "")
        bare_name = str(entry.get("library_name") or "")
        library_dexes = set(by_lower.get(bare_name.casefold(), set()))
        library_dexes.update(by_lower.get(f"lib{bare_name}.so".casefold(), set()))
        for dex_name in sorted(loader_dexes & library_dexes):
            link = {
                "kind": "loads_native_library",
                "dex": dex_name,
                "library": library,
                "java_class": None,
                "native_symbol": None,
                "confidence": 0.95,
                "evidence": ["DEX references System.loadLibrary/loadLibrary", f"DEX string matches {bare_name}"],
            }
            _append_link(links, seen, link)

        for symbol in entry.get("jni_exports", []):
            if not str(symbol).startswith("Java_"):
                continue
            decoded = _decode_jni_symbol(str(symbol))
            java_class = decoded.get("class")
            class_dexes: set[str] = set()
            if java_class:
                descriptor = f"L{java_class.replace('.', '/')};".casefold()
                class_dexes.update(by_lower.get(descriptor, set()))
                class_dexes.update(by_lower.get(java_class.replace(".", "/").casefold(), set()))
                class_dexes.update(by_lower.get(java_class.casefold(), set()))
            target_dexes = class_dexes or {""}
            for dex_name in sorted(target_dexes):
                link = {
                    "kind": "jni_binding",
                    "dex": dex_name or None,
                    "library": library,
                    "java_class": java_class,
                    "java_method": decoded.get("method"),
                    "native_symbol": str(symbol),
                    "confidence": 1.0 if class_dexes else 0.75,
                    "evidence": [
                        "JNI export name encodes a Java binding",
                        "matching DEX class descriptor" if class_dexes else "Java class inferred from JNI export",
                    ],
                }
                _append_link(links, seen, link)
    return links[:_MAX_EXAMPLES * 2]


def _append_link(
    links: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    link: Mapping[str, Any],
) -> None:
    key = (
        str(link.get("kind") or ""),
        str(link.get("dex") or ""),
        str(link.get("library") or ""),
        str(link.get("native_symbol") or ""),
    )
    if key not in seen:
        seen.add(key)
        links.append(dict(link))


def _decode_jni_symbol(symbol: str) -> dict[str, str | None]:
    if not symbol.startswith("Java_"):
        return {"class": None, "method": symbol}
    encoded = symbol[5:].split("__", 1)[0]
    if "_" not in encoded:
        return {"class": _decode_jni_component(encoded), "method": None}
    class_part, method_part = encoded.rsplit("_", 1)
    return {"class": _decode_jni_component(class_part), "method": _decode_jni_component(method_part, slash=False)}


def _decode_jni_component(value: str, *, slash: bool = True) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "_":
            output.append(value[index])
            index += 1
            continue
        if index + 1 < len(value) and value[index + 1] in "123":
            output.append({"1": "_", "2": ";", "3": "["}[value[index + 1]])
            index += 2
            continue
        output.append("." if slash else "_")
        index += 1
    return "".join(output)


def _native_library_name(filename: str) -> str:
    name = filename
    if name.casefold().startswith("lib"):
        name = name[3:]
    if name.casefold().endswith(".so"):
        name = name[:-3]
    return name


def _resource_summary(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
    budget: _ReadBudget,
) -> tuple[dict[str, Any], list[str]]:
    names = [info.filename for info in infos]
    layouts = [info for info in infos if re.fullmatch(r"res/layout(?:-[^/]+)?/[^/]+\.xml", info.filename)]
    drawables = [info for info in infos if re.fullmatch(r"res/drawable(?:-[^/]+)?/[^/]+", info.filename)]
    values = [name for name in names if re.fullmatch(r"res/values(?:-[^/]+)?/[^/]+\.xml", name)]
    assets = [name for name in names if name.startswith("assets/")]
    category_counts: Counter[str] = Counter()
    for name in names:
        category = _resource_path_category(name)
        if category:
            category_counts[category] += 1

    issues: list[str] = []
    layout_entries: list[dict[str, Any]] = []
    drawable_entries: list[dict[str, Any]] = []
    xml_read_count = 0
    xml_limit_hit = False
    for info in layouts[:_MAX_EXAMPLES]:
        classification = {
            "path": info.filename,
            "status": "unavailable",
            "encoding": "unread",
            "root": None,
            "category": "unknown",
            "warnings": [],
        }
        if xml_read_count < _MAX_RESOURCE_XML_FILES:
            data, truncated, error = _read_member_limited(archive, info, _MAX_RESOURCE_XML_BYTES, budget)
            xml_read_count += 1
            classification.update(_classify_resource_xml(data, kind="layout"))
            if truncated:
                classification["truncated"] = True
                issues.append(f"{info.filename}: XML read was limited to {_MAX_RESOURCE_XML_BYTES} bytes")
            if error:
                classification["error"] = error
                issues.append(f"{info.filename}: {error}")
            elif classification.get("status") != "ok":
                detail = next(iter(classification.get("warnings", [])), "resource XML could not be parsed")
                issues.append(f"{info.filename}: {detail}")
        else:
            xml_limit_hit = True
            classification["warnings"] = [f"resource XML parse limit {_MAX_RESOURCE_XML_FILES} reached"]
        layout_entries.append(classification)

    for info in drawables[:_MAX_EXAMPLES]:
        drawable_type = _drawable_file_type(info.filename)
        classification = {
            "path": info.filename,
            "status": "not_applicable",
            "encoding": "file",
            "root": None,
            "category": drawable_type,
            "warnings": [],
        }
        if info.filename.casefold().endswith(".xml"):
            if xml_read_count < _MAX_RESOURCE_XML_FILES:
                data, truncated, error = _read_member_limited(archive, info, _MAX_RESOURCE_XML_BYTES, budget)
                xml_read_count += 1
                classification.update(_classify_resource_xml(data, kind="drawable"))
                if truncated:
                    classification["truncated"] = True
                    issues.append(f"{info.filename}: XML read was limited to {_MAX_RESOURCE_XML_BYTES} bytes")
                if error:
                    classification["error"] = error
                    issues.append(f"{info.filename}: {error}")
                elif classification.get("status") != "ok":
                    detail = next(iter(classification.get("warnings", [])), "resource XML could not be parsed")
                    issues.append(f"{info.filename}: {detail}")
            else:
                xml_limit_hit = True
                classification.update(
                    {
                        "status": "unavailable",
                        "encoding": "unread",
                        "warnings": [f"resource XML parse limit {_MAX_RESOURCE_XML_FILES} reached"],
                    }
                )
        drawable_entries.append(classification)

    if xml_limit_hit:
        issues.append(f"resource XML parse limit {_MAX_RESOURCE_XML_FILES} reached")

    layout_types = Counter(str(item["category"]) for item in layout_entries)
    drawable_types = Counter(_drawable_file_type(info.filename) for info in drawables)
    for item in drawable_entries:
        if item["path"].casefold().endswith(".xml"):
            drawable_types[str(item["category"])] += 1
            drawable_types["xml"] -= 1
    drawable_types = Counter({key: value for key, value in drawable_types.items() if value > 0})

    return (
        {
            "status": "partial" if issues else "ok",
            "resource_arsc_present": "resources.arsc" in names,
            "resource_arsc_size": next((info.file_size for info in infos if info.filename == "resources.arsc"), None),
            "layout_count": len(layouts),
            "drawable_count": len(drawables),
            "values_count": len(values),
            "asset_count": len(assets),
            "layout_examples": [info.filename for info in layouts[:_MAX_EXAMPLES]],
            "drawable_examples": [info.filename for info in drawables[:_MAX_EXAMPLES]],
            "layouts": layout_entries,
            "drawables": drawable_entries,
            "layout_types": dict(sorted(layout_types.items())),
            "drawable_types": dict(sorted(drawable_types.items())),
            "categories": dict(sorted(category_counts.items())),
            "web_asset_count": category_counts.get("web_assets", 0),
            "limits": {
                "max_examples": _MAX_EXAMPLES,
                "max_xml_files_parsed": _MAX_RESOURCE_XML_FILES,
                "max_bytes_per_xml": _MAX_RESOURCE_XML_BYTES,
            },
        },
        issues,
    )


def _empty_resources() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "resource_arsc_present": False,
        "resource_arsc_size": None,
        "layout_count": 0,
        "drawable_count": 0,
        "values_count": 0,
        "asset_count": 0,
        "layout_examples": [],
        "drawable_examples": [],
        "layouts": [],
        "drawables": [],
        "layout_types": {},
        "drawable_types": {},
        "categories": {},
        "web_asset_count": 0,
        "limits": {
            "max_examples": _MAX_EXAMPLES,
            "max_xml_files_parsed": _MAX_RESOURCE_XML_FILES,
            "max_bytes_per_xml": _MAX_RESOURCE_XML_BYTES,
        },
    }


def _resource_path_category(name: str) -> str | None:
    lowered = name.casefold()
    if lowered.startswith("assets/"):
        if lowered.endswith((".html", ".htm", ".js", ".css", ".wasm")) or "/www/" in lowered:
            return "web_assets"
        return "assets"
    match = re.match(r"^res/([^/]+)/", lowered)
    if not match:
        return None
    directory = match.group(1).split("-", 1)[0]
    if directory in {
        "layout",
        "drawable",
        "mipmap",
        "values",
        "menu",
        "navigation",
        "xml",
        "raw",
        "font",
        "anim",
        "animator",
        "color",
        "transition",
    }:
        return directory
    return "other_res"


def _classify_resource_xml(data: bytes, *, kind: str) -> dict[str, Any]:
    if not data:
        return {
            "status": "unavailable",
            "encoding": "unavailable",
            "root": None,
            "category": "unknown",
            "warnings": ["resource XML member is empty"],
        }
    warnings: list[str] = []
    text = _decode_xml_text(data)
    if text is not None:
        declaration_issue = _xml_declaration_issue(text)
        if declaration_issue:
            warnings.append(declaration_issue)
            match = re.search(r"<\s*(?![!?])([A-Za-z_][\w.$:-]*)", text)
            root = match.group(1) if match else None
            encoding = "text_fallback"
        else:
            try:
                root = _local_name(ET.fromstring(text).tag)
                encoding = "text_xml"
            except (ET.ParseError, ValueError) as exc:
                warnings.append(f"text XML parse failed: {exc}")
                match = re.search(r"<\s*(?![!?])([A-Za-z_][\w.$:-]*)", text)
                root = match.group(1) if match else None
                encoding = "text_fallback"
        status = "ok" if encoding == "text_xml" else "partial"
    elif len(data) >= 8 and _u16(data, 0, "<") == 0x0003:
        try:
            parsed = _parse_binary_xml(data)
            root = parsed.get("root")
            encoding = "binary_axml" if root else "binary_fallback"
            warnings.extend(parsed.get("warnings", []))
            status = str(parsed.get("status") or "partial") if root else "partial"
        except (IndexError, ValueError, struct.error) as exc:
            root = None
            encoding = "binary_fallback"
            status = "partial"
            warnings.append(f"binary AXML parse failed: {exc}")
    else:
        root = None
        encoding = "unknown"
        status = "partial"
        warnings.append("resource XML encoding was not recognized")
    category = _layout_root_category(root) if kind == "layout" else _drawable_root_category(root)
    return {
        "status": status,
        "encoding": encoding,
        "root": root,
        "category": category,
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
    }


def _layout_root_category(root: Any) -> str:
    if not root:
        return "unknown"
    lowered = str(root).rsplit(".", 1)[-1].casefold()
    if lowered in {
        "linearlayout",
        "relativelayout",
        "framelayout",
        "constraintlayout",
        "coordinatorlayout",
        "drawerlayout",
        "gridlayout",
        "tablelayout",
        "scrollview",
        "nestedscrollview",
        "viewgroup",
    }:
        return "container"
    if lowered in {"merge", "include", "viewstub"}:
        return "composition"
    if lowered == "layout":
        return "data_binding"
    if lowered in {"composeview", "abstractcomposeview"}:
        return "compose_host"
    if "." in str(root):
        return "custom_view"
    return "widget"


def _drawable_root_category(root: Any) -> str:
    if not root:
        return "xml"
    lowered = str(root).casefold()
    if lowered in {
        "vector",
        "animated-vector",
        "shape",
        "selector",
        "layer-list",
        "ripple",
        "inset",
        "bitmap",
        "clip",
        "scale",
        "rotate",
        "animation-list",
    }:
        return lowered.replace("-", "_")
    return "xml_other"


def _drawable_file_type(name: str) -> str:
    lowered = name.casefold()
    if lowered.endswith(".9.png"):
        return "nine_patch"
    if lowered.endswith(".xml"):
        return "xml"
    if lowered.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif")):
        return "raster"
    return "other"


def _detect_framework(
    names: Sequence[str],
    manifest: Mapping[str, Any] | bytes = b"",
    resources: Mapping[str, Any] | None = None,
    dex_context: Mapping[str, Any] | None = None,
    native: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Score competing Android UI/runtime frameworks from independent signals."""

    # Keep the old private-call shape useful for callers that supplied raw manifest bytes.
    if isinstance(manifest, (bytes, bytearray)):
        manifest = _manifest_summary(bytes(manifest))
    resources = resources or _empty_resources()
    dex_context = dex_context or {"strings": [], "lower_strings": set()}
    native = native or _empty_native_summary()
    lowered_names = [name.casefold() for name in names]
    joined_names = "\n".join(lowered_names)
    dex_strings = dex_context.get("lower_strings")
    if not isinstance(dex_strings, set):
        dex_strings = {str(item.get("value") or "").casefold() for item in dex_context.get("strings", [])}
    joined_dex = "\n".join(sorted(dex_strings))
    native_paths = "\n".join(str(name).casefold() for name in native.get("libs", []))

    scores = {name: 0.0 for name in _FRAMEWORK_NAMES}
    evidence = {name: [] for name in _FRAMEWORK_NAMES}

    def add(name: str, score: float, reason: str) -> None:
        scores[name] += score
        if reason not in evidence[name]:
            evidence[name].append(reason)

    layout_count = int(resources.get("layout_count", 0) or 0)
    if layout_count:
        add("android_xml", min(7.0, 3.0 + (layout_count * 0.5)), f"{layout_count} res/layout XML file(s)")
    if manifest.get("textual"):
        add("android_xml", 0.5, "text AndroidManifest.xml")
    if "androidx/appcompat" in joined_dex or "appcompatactivity" in joined_dex:
        add("android_xml", 2.0, "AndroidX AppCompat classes")

    compose_tokens = [token for token in ("androidx/compose", "@landroidx/compose", "composable", "composeview") if token in joined_dex]
    if compose_tokens:
        add("jetpack_compose", 5.0 + min(3.0, len(compose_tokens)), f"DEX Compose signatures: {', '.join(compose_tokens)}")
    if any(item.get("category") == "compose_host" for item in resources.get("layouts", [])):
        add("jetpack_compose", 2.5, "ComposeView XML host")

    if "libflutter.so" in native_paths or "libflutter.so" in joined_names:
        add("flutter", 8.0, "libflutter.so")
    if any("flutter_assets" in name for name in lowered_names):
        add("flutter", 7.0, "Flutter asset bundle")
    if "io/flutter" in joined_dex:
        add("flutter", 3.0, "Flutter Java embedding classes")
    if "libapp.so" in native_paths and scores["flutter"]:
        add("flutter", 2.0, "Flutter AOT libapp.so")

    if any(name.endswith("index.android.bundle") for name in lowered_names):
        add("react_native", 9.0, "index.android.bundle")
    if any(token in native_paths for token in ("libreactnativejni.so", "libhermes.so", "libjsi.so")):
        add("react_native", 5.0, "React Native/Hermes native runtime")
    if "com/facebook/react" in joined_dex or "reactnative" in joined_dex:
        add("react_native", 4.0, "React Native Java classes")

    if "libunity.so" in native_paths or "libunity.so" in joined_names:
        add("unity", 8.0, "libunity.so")
    if "libil2cpp.so" in native_paths or "libil2cpp.so" in joined_names:
        add("unity", 4.0, "libil2cpp.so")
    if any("assets/bin/data" in name or name.endswith("globalgamemanagers") for name in lowered_names):
        add("unity", 7.0, "Unity data/globalgamemanagers assets")
    if "com/unity3d/player" in joined_dex or any(
        "unityplayeractivity" in str(item).casefold() for item in manifest.get("activities", [])
    ):
        add("unity", 3.0, "UnityPlayerActivity/classes")

    if "android/webkit/webview" in joined_dex or "webview" in joined_dex:
        add("webview_hybrid", 6.0, "android.webkit.WebView DEX reference")
    web_asset_count = int(resources.get("web_asset_count", 0) or 0)
    if web_asset_count:
        add("webview_hybrid", min(5.0, 1.5 + (web_asset_count * 0.25)), f"{web_asset_count} packaged web asset(s)")
    if any(token in joined_names for token in ("cordova.js", "capacitor.config", "www/index.html")):
        add("webview_hybrid", 4.0, "Cordova/Capacitor web bundle")

    positive = [(name, score) for name, score in scores.items() if score > 0]
    if not positive:
        return _unknown_framework("No bounded static framework signal")
    ranked = sorted(positive, key=lambda item: (-item[1], _FRAMEWORK_PRIORITY[item[0]]))
    total = sum(score for _, score in ranked)
    best_name, best_score = ranked[0]
    second_name, second_score = ranked[1] if len(ranked) > 1 else (None, 0.0)
    conflict_score = second_score / best_score if best_score else 0.0
    strong_candidates = [name for name, score in ranked if score >= 3.0 and score >= best_score * 0.5]
    conflicted = len(strong_candidates) > 1 and conflict_score >= 0.6
    candidates = [
        {
            "name": name,
            "score": round(scores[name], 3),
            "confidence": round(scores[name] / total, 3) if total else 0.0,
            "evidence": evidence[name],
        }
        for name in sorted(_FRAMEWORK_NAMES, key=lambda item: (-scores[item], _FRAMEWORK_PRIORITY[item]))
    ]
    conflicts = []
    if conflicted and second_name:
        conflicts.append(
            {
                "primary": best_name,
                "secondary": second_name,
                "score": round(conflict_score, 3),
                "reason": "independent static signals strongly support both candidates",
            }
        )
    return {
        "name": best_name,
        "confidence": round(best_score / total, 3),
        "score": round(best_score, 3),
        "evidence": evidence[best_name],
        "candidates": candidates,
        "conflict": {
            "is_conflicted": conflicted,
            "score": round(conflict_score, 3),
            "runner_up": second_name,
            "strong_candidates": strong_candidates,
        },
        "conflicts": conflicts,
        "scoring": "bounded-static-evidence-v1",
    }


def _unknown_framework(reason: str) -> dict[str, Any]:
    return {
        "name": "unknown",
        "confidence": 0.0,
        "score": 0.0,
        "evidence": [reason],
        "candidates": [
            {"name": name, "score": 0.0, "confidence": 0.0, "evidence": []} for name in _FRAMEWORK_NAMES
        ],
        "conflict": {"is_conflicted": False, "score": 0.0, "runner_up": None, "strong_candidates": []},
        "conflicts": [],
        "scoring": "bounded-static-evidence-v1",
    }


def _semantic_ir_fragment(
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    dex_summary: Mapping[str, Any],
    native: Mapping[str, Any],
    framework: Mapping[str, Any],
) -> dict[str, Any]:
    entities_by_id: dict[str, dict[str, Any]] = {}
    relations_by_id: dict[str, dict[str, Any]] = {}

    def add_entity(
        entity_id: str,
        *,
        kind: str,
        name: str,
        confidence: float,
        sources: Sequence[str],
        attributes: Mapping[str, Any],
    ) -> str:
        normalized_sources = sorted({str(item) for item in sources if item})
        entity = {
            "id": entity_id,
            "kind": kind,
            "name": name,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "sources": normalized_sources,
            "attributes": dict(attributes),
        }
        existing = entities_by_id.get(entity_id)
        if existing is None:
            entities_by_id[entity_id] = entity
        else:
            existing["confidence"] = max(existing["confidence"], entity["confidence"])
            existing["sources"] = sorted(set(existing["sources"]).union(normalized_sources))
        return entity_id

    def add_relation(
        relation_type: str,
        source_id: str,
        target_id: str,
        *,
        confidence: float,
        sources: Sequence[str],
        attributes: Mapping[str, Any] | None = None,
        identity: Any = None,
    ) -> None:
        if source_id not in entities_by_id or target_id not in entities_by_id:
            return
        identity_payload = json.dumps(
            [relation_type, source_id, target_id, identity],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        relation_id = "android:relation:" + hashlib.sha256(
            identity_payload.encode("utf-8")
        ).hexdigest()[:16]
        relation = {
            "id": relation_id,
            "type": relation_type,
            "source": source_id,
            "target": target_id,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "sources": sorted({str(item) for item in sources if item}),
        }
        if attributes:
            relation["attributes"] = dict(attributes)
        relations_by_id[relation_id] = relation

    package_name = str(manifest.get("package") or "unknown")
    package_id = f"android:package:{package_name}"
    manifest_status = str(manifest.get("status") or "unavailable")
    if manifest.get("present") or package_name != "unknown":
        add_entity(
            package_id,
            kind="android_package",
            name=package_name,
            confidence=1.0 if manifest_status == "ok" else 0.65,
            sources=["android.manifest"],
            attributes={
                "min_sdk": manifest.get("min_sdk"),
                "target_sdk": manifest.get("target_sdk"),
                "manifest_status": manifest_status,
            },
        )

    framework_name = str(framework.get("name") or "unknown")
    framework_id = f"android:framework:{framework_name}"
    if framework_name != "unknown":
        add_entity(
            framework_id,
            kind="android_framework",
            name=framework_name,
            confidence=float(framework.get("confidence") or 0.0),
            sources=["android.framework_fingerprint"],
            attributes={
                "score": framework.get("score"),
                "evidence": list(framework.get("evidence") or []),
            },
        )
        add_relation(
            "uses_framework",
            package_id,
            framework_id,
            confidence=float(framework.get("confidence") or 0.0),
            sources=["android.framework_fingerprint"],
        )

    resource_id = "android:resources"
    resource_status = str(resources.get("status") or "unavailable")
    if resource_status != "unavailable":
        add_entity(
            resource_id,
            kind="android_resources",
            name="resources",
            confidence=0.95 if resource_status == "ok" else 0.65,
            sources=["android.resources"],
            attributes={
                "status": resource_status,
                "layouts": resources.get("layout_count", 0),
                "drawables": resources.get("drawable_count", 0),
                "assets": resources.get("asset_count", 0),
            },
        )
        add_relation(
            "contains",
            package_id,
            resource_id,
            confidence=0.95,
            sources=["android.resources"],
        )

    dex_ids: dict[str, str] = {}
    dex_files = sorted(
        (item for item in dex_summary.get("files", []) if isinstance(item, Mapping)),
        key=lambda item: str(item.get("name") or ""),
    )[:_MAX_DEX_FILES]
    for item in dex_files:
        name = str(item.get("name") or "unknown.dex")
        entity_id = f"android:dex:{name}"
        dex_ids[name] = entity_id
        dex_status = str(item.get("status") or "unavailable")
        add_entity(
            entity_id,
            kind="dex_file",
            name=name,
            confidence=0.95 if dex_status == "ok" else 0.4,
            sources=["android.dex_header"],
            attributes={
                "version": item.get("version"),
                "counts": item.get("counts", {}),
                "status": dex_status,
            },
        )
        add_relation(
            "contains",
            package_id,
            entity_id,
            confidence=0.95,
            sources=["android.dex_header"],
        )

    native_ids: dict[str, str] = {}
    native_entries = sorted(
        (item for item in native.get("entries", []) if isinstance(item, Mapping)),
        key=lambda item: str(item.get("path") or ""),
    )[:_MAX_NATIVE_LIBS]
    for item in native_entries:
        path = str(item.get("path") or "unknown.so")
        entity_id = f"android:native:{path}"
        native_ids[path] = entity_id
        elf = item.get("elf") if isinstance(item.get("elf"), Mapping) else {}
        elf_status = str(elf.get("status") or "unavailable")
        add_entity(
            entity_id,
            kind="native_library",
            name=str(item.get("name") or path),
            confidence=0.95 if elf_status == "ok" else 0.55,
            sources=["android.native_libs"],
            attributes={
                "abi": item.get("abi"),
                "elf_class": elf.get("class"),
                "machine": elf.get("machine_name"),
                "status": elf_status,
                "jni_export_count": len(item.get("jni_exports", [])),
            },
        )
        add_relation(
            "contains",
            package_id,
            entity_id,
            confidence=0.95,
            sources=["android.native_libs"],
        )

    java_ids: dict[str, str] = {}
    native_links = sorted(
        (
            link
            for link in native.get("java_native_links", [])
            if isinstance(link, Mapping)
        ),
        key=lambda link: (
            str(link.get("library") or ""),
            str(link.get("java_class") or ""),
            str(link.get("dex") or ""),
            str(link.get("kind") or ""),
            str(link.get("native_symbol") or ""),
        ),
    )[: _MAX_EXAMPLES * 2]
    for link in native_links:
        library_id = native_ids.get(str(link.get("library") or ""))
        if not library_id:
            continue
        java_class = link.get("java_class")
        if java_class:
            java_class = str(java_class)
            java_id = java_ids.setdefault(java_class, f"android:java:{java_class}")
            add_entity(
                java_id,
                kind="java_class",
                name=java_class,
                confidence=float(link.get("confidence") or 0.7),
                sources=["android.dex_strings", "android.native_symbols"],
                attributes={},
            )
            source_id = java_id
        else:
            source_id = dex_ids.get(str(link.get("dex") or ""), package_id)
        add_relation(
            str(link.get("kind") or "native_association"),
            source_id,
            library_id,
            confidence=float(link.get("confidence") or 0.7),
            sources=["android.java_native_links"],
            attributes={
                "evidence": list(link.get("evidence") or []),
                "native_symbol": link.get("native_symbol"),
            },
            identity=link.get("native_symbol"),
        )

    component_types = (
        ("activities", "android_activity"),
        ("services", "android_service"),
        ("receivers", "android_receiver"),
        ("providers", "android_provider"),
    )
    component_count = 0
    for key, kind in component_types:
        components = sorted(
            (
                component
                for component in manifest.get(key, [])
                if isinstance(component, Mapping)
            ),
            key=lambda component: str(component.get("name") or ""),
        )
        for component in components:
            if component_count >= _MAX_MANIFEST_COMPONENTS:
                break
            name = str(component.get("name") or f"unknown-{component_count}")
            entity_id = f"android:component:{kind}:{name}"
            add_entity(
                entity_id,
                kind=kind,
                name=name,
                confidence=1.0 if manifest_status == "ok" else 0.65,
                sources=["android.manifest"],
                attributes={"exported": component.get("exported")},
            )
            add_relation(
                "declares",
                package_id,
                entity_id,
                confidence=1.0 if manifest_status == "ok" else 0.65,
                sources=["android.manifest"],
            )
            component_count += 1

    entities = sorted(entities_by_id.values(), key=lambda item: str(item["id"]))
    relations = sorted(relations_by_id.values(), key=lambda item: str(item["id"]))
    entity_ids = [str(item["id"]) for item in entities]
    capabilities: list[dict[str, Any]] = []
    if entity_ids:
        capabilities.append(
            {
                "id": "capability:android_static_structure:"
                + hashlib.sha256("\n".join(entity_ids).encode("utf-8")).hexdigest()[:16],
                "name": "android_static_structure",
                "category": "android_static_structure",
                "confidence": 1.0 if manifest_status == "ok" else 0.65,
                "entity_ids": entity_ids,
                "evidence_count": sum(max(1, len(item["sources"])) for item in entities),
            }
        )
    if native.get("jni_export_count"):
        jni_entity_ids = sorted(
            entity_id
            for entity_id in entity_ids
            if entity_id.startswith(("android:native:", "android:java:"))
        )
        capabilities.append(
            {
                "id": "capability:jni_bridge:"
                + hashlib.sha256("\n".join(jni_entity_ids).encode("utf-8")).hexdigest()[:16],
                "name": "jni_bridge",
                "category": "jni_bridge",
                "confidence": 0.95,
                "entity_ids": jni_entity_ids,
                "evidence_count": int(native.get("jni_export_count") or 0),
            }
        )
    capabilities.sort(key=lambda item: str(item["id"]))
    section_statuses = {
        "manifest": str(manifest.get("status") or "unavailable"),
        "resources": str(resources.get("status") or "unavailable"),
        "dex": str(dex_summary.get("status") or "unavailable"),
        "native": str(native.get("status") or "unavailable"),
    }
    if section_statuses["manifest"] == "unavailable" and section_statuses["resources"] == "unavailable":
        fragment_status = "unavailable"
    elif section_statuses["manifest"] != "ok" or section_statuses["resources"] != "ok":
        fragment_status = "partial"
    elif "partial" in section_statuses.values():
        fragment_status = "partial"
    else:
        fragment_status = "ok"
    return {
        "schema_version": 1,
        "source": "android_analyze",
        "status": fragment_status,
        "entities": entities,
        "relations": relations,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "capability_count": len(capabilities),
        },
        "artifacts": [],
        "limits": {
            "max_components": _MAX_MANIFEST_COMPONENTS,
            "max_dex_files": _MAX_DEX_FILES,
            "max_native_libraries": _MAX_NATIVE_LIBS,
        },
    }


def _extract_printable_strings(data: bytes, *, min_length: int, max_strings: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,512}" % min_length)
    for match in ascii_pattern.finditer(data):
        value = match.group(0).decode("ascii", errors="ignore")
        if value not in seen:
            seen.add(value)
            result.append(value)
        if len(result) >= max_strings:
            return result
    if len(data) >= min_length * 2:
        text = data.decode("utf-16le", errors="ignore")
        unicode_pattern = re.compile(rf"[\x20-\x7e]{{{min_length},512}}")
        for match in unicode_pattern.finditer(text):
            value = match.group(0)
            if value not in seen:
                seen.add(value)
                result.append(value)
            if len(result) >= max_strings:
                break
    return result


def _useful_string(value: str) -> bool:
    if not value or len(value) > 512:
        return False
    printable = sum(1 for char in value if char.isprintable())
    return printable >= max(1, int(len(value) * 0.8))


def _attr(attributes: Mapping[str, Any], name: str) -> Any:
    for key in (f"android:{name}", name):
        value = attributes.get(key)
        if value is not None and value != "":
            return value
    return None


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        if value.casefold() == "true":
            return True
        if value.casefold() == "false":
            return False
    return None


def _local_name(name: Any) -> str:
    value = str(name)
    if "}" in value:
        value = value.rsplit("}", 1)[-1]
    return value


def _read_c_string(data: bytes, offset: int, end: int, max_length: int) -> str | None:
    if offset < 0 or offset >= min(end, len(data)):
        return None
    terminator = data.find(b"\x00", offset, min(end, len(data), offset + max_length + 1))
    if terminator < 0:
        return None
    return data[offset:terminator].decode("utf-8", errors="replace")


def _u16(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str) -> int:
    return struct.unpack_from(f"{endian}Q", data, offset)[0]


def _dedupe_strings(values: Sequence[Any], limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
