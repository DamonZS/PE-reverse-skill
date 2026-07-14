"""Local build and behavior validation for reconstructed source projects.

The validator executes only explicit argv lists from a caller-supplied spec.
It records what was actually observed for that spec; a passing result is never
promoted into a claim that reconstructed source is behaviorally equivalent to
the original binary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Collection, Mapping, Sequence


RUNTIME_VALIDATION_SCHEMA_VERSION = 1
DEFAULT_RUNTIME_VALIDATION_PATH = "source/runtime_validation.json"
DEFAULT_TOOL_ALLOWLIST = frozenset(
    {
        "python",
        "node",
        "cmake",
        "ctest",
        "ninja",
        "make",
        "nmake",
        "msbuild",
        "dotnet",
        "csc",
        "mcs",
        "cc",
        "c++",
        "gcc",
        "g++",
        "clang",
        "clang++",
        "cl",
        "javac",
        "java",
        "gradle",
        "kotlinc",
        "kotlinc-jvm",
    }
)

_VALIDATOR_VERSION = "1.0"
_DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_TIMEOUT_SECONDS = 300.0
_DEFAULT_STREAM_LIMIT = 64 * 1024
_MAX_STREAM_LIMIT = 4 * 1024 * 1024
_MAX_SPEC_BYTES = 2 * 1024 * 1024
_MAX_JSON_BYTES = 4 * 1024 * 1024
_MAX_HASHED_FILE_BYTES = 512 * 1024 * 1024
_DEFAULT_MAX_PROJECT_BYTES = 1024 * 1024 * 1024
_DEFAULT_MAX_PROJECT_FILES = 20_000
_MAX_STEPS = 16
_MAX_ARGV_ITEMS = 512
_MAX_ARGUMENT_BYTES = 32 * 1024
_IO_CHUNK_BYTES = 64 * 1024
_FORBIDDEN_SHELLS = frozenset(
    {
        "bash",
        "cmd",
        "command",
        "csh",
        "dash",
        "fish",
        "ksh",
        "powershell",
        "pwsh",
        "sh",
        "tcsh",
        "wsl",
        "zsh",
    }
)
_SHELL_FILE_SUFFIXES = frozenset({".bat", ".cmd", ".ps1"})
_HEX_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_PYTHON_TOOL = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
_ATTACHED_PATH_OPTIONS = ("--cwd=", "--output=", "--out=", "-I", "-L", "-o")

ToolResolver = Callable[[str], str | os.PathLike[str] | None]


class _SpecError(ValueError):
    pass


class _BoundaryError(ValueError):
    pass


@dataclass(frozen=True)
class _TextExpectation:
    stream: str
    operator: str
    expected: str


@dataclass(frozen=True)
class _OutputExpectation:
    path: str
    sha256: str


@dataclass(frozen=True)
class _JsonAssertion:
    source: str
    path: Any
    operator: str
    expected: Any


@dataclass(frozen=True)
class _Step:
    name: str
    kind: str
    tool: str
    tool_key: str
    argv: tuple[str, ...]
    cwd: str
    cwd_path: Path
    timeout_seconds: float
    stdout_limit: int
    stderr_limit: int
    expected_exit_codes: tuple[int, ...] | None
    text_expectations: tuple[_TextExpectation, ...]
    output_expectations: tuple[_OutputExpectation, ...]
    json_assertions: tuple[_JsonAssertion, ...]


@dataclass(frozen=True)
class _ResolvedTool:
    key: str
    requested: str
    executable: Path
    provenance: dict[str, Any]


@dataclass(frozen=True)
class _ProcessObservation:
    started: bool
    timed_out: bool
    exit_code: int | None
    termination_exit_code: int | None
    duration_ms: int
    stdout: dict[str, Any]
    stderr: dict[str, Any]
    error: str | None = None


class _BoundedCapture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.content = bytearray()
        self.total_bytes = 0
        self.digest = hashlib.sha256()
        self.error: str | None = None

    def consume(self, pipe: Any) -> None:
        try:
            while True:
                chunk = pipe.read(_IO_CHUNK_BYTES)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    chunk = bytes(chunk)
                self.total_bytes += len(chunk)
                self.digest.update(chunk)
                remaining = self.limit - len(self.content)
                if remaining > 0:
                    self.content.extend(chunk[:remaining])
        except (OSError, ValueError) as error:
            self.error = f"{type(error).__name__}: {error}"
        finally:
            try:
                pipe.close()
            except (OSError, ValueError):
                pass

    def record(self) -> dict[str, Any]:
        decoded = bytes(self.content).decode("utf-8", errors="replace")
        text = decoded.replace("\r\n", "\n").replace("\r", "\n")
        return {
            "text": text,
            "sha256": self.digest.hexdigest(),
            "captured_bytes": len(self.content),
            "total_bytes": self.total_bytes,
            "limit_bytes": self.limit,
            "truncated": self.total_bytes > len(self.content),
        }


def validate_source_runtime(
    project_dir: str | os.PathLike[str],
    validation_spec: Mapping[str, Any],
    *,
    allowed_tools: Collection[str] | None = None,
    tool_resolver: ToolResolver | None = None,
    default_timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    default_stdout_limit: int = _DEFAULT_STREAM_LIMIT,
    default_stderr_limit: int = _DEFAULT_STREAM_LIMIT,
    max_project_files: int = _DEFAULT_MAX_PROJECT_FILES,
    max_project_bytes: int = _DEFAULT_MAX_PROJECT_BYTES,
) -> dict[str, Any]:
    """Execute an explicit local validation spec below ``project_dir``.

    A spec may contain a ``steps`` list or named ``build`` and ``behavior``
    steps. Every step requires an ``argv`` list. Expected values can be placed
    directly on a step (for example ``expected_stdout``) or under ``expect``.
    Output and JSON file paths are always interpreted relative to the project
    root, while ``cwd`` is a constrained project-relative directory.
    """

    root = _project_root(project_dir)
    project_file_limit = _bounded_integer(
        max_project_files,
        name="max_project_files",
        minimum=1,
        maximum=1_000_000,
    )
    project_byte_limit = _bounded_integer(
        max_project_bytes,
        name="max_project_bytes",
        minimum=1,
        maximum=16 * 1024 * 1024 * 1024,
    )
    try:
        before = _snapshot_project(root, project_file_limit, project_byte_limit)
    except (OSError, RuntimeError, _BoundaryError) as error:
        return _validation_result(
            status="failed",
            spec_sha256=None,
            planned_step_count=0,
            before=None,
            after=None,
            steps=(),
            tools=(),
            diagnostics=(f"project snapshot failed before execution: {error}",),
        )

    try:
        spec_sha256 = _spec_sha256(validation_spec)
        defaults = (
            _bounded_number(
                default_timeout,
                name="default_timeout",
                minimum_exclusive=0.0,
                maximum=_MAX_TIMEOUT_SECONDS,
            ),
            _bounded_integer(
                default_stdout_limit,
                name="default_stdout_limit",
                minimum=1,
                maximum=_MAX_STREAM_LIMIT,
            ),
            _bounded_integer(
                default_stderr_limit,
                name="default_stderr_limit",
                minimum=1,
                maximum=_MAX_STREAM_LIMIT,
            ),
        )
        effective_allowlist = _effective_allowlist(allowed_tools, validation_spec)
        steps = _parse_spec(root, validation_spec, defaults)
    except (TypeError, ValueError, _SpecError, _BoundaryError) as error:
        after, snapshot_error = _try_snapshot(root, project_file_limit, project_byte_limit)
        diagnostics = [f"invalid validation spec: {error}"]
        if snapshot_error:
            diagnostics.append(snapshot_error)
        return _validation_result(
            status="failed",
            spec_sha256=locals().get("spec_sha256"),
            planned_step_count=0,
            before=before,
            after=after,
            steps=(),
            tools=(),
            diagnostics=diagnostics,
        )

    resolver = tool_resolver or _default_tool_resolver
    resolved_tools: dict[tuple[str, str], _ResolvedTool] = {}
    tool_records: list[dict[str, Any]] = []
    unavailable_diagnostics: list[str] = []
    for step in steps:
        identity = (step.tool_key, step.argv[0])
        if identity in resolved_tools:
            continue
        resolved, record, diagnostic = _resolve_tool(step, effective_allowlist, resolver)
        tool_records.append(record)
        if resolved is None:
            unavailable_diagnostics.append(diagnostic or f"tool is unavailable: {step.tool}")
        else:
            resolved_tools[identity] = resolved

    if unavailable_diagnostics:
        after, snapshot_error = _try_snapshot(root, project_file_limit, project_byte_limit)
        if snapshot_error:
            unavailable_diagnostics.append(snapshot_error)
        return _validation_result(
            status="unavailable",
            spec_sha256=spec_sha256,
            planned_step_count=len(steps),
            before=before,
            after=after,
            steps=(),
            tools=tool_records,
            diagnostics=unavailable_diagnostics,
        )

    step_results: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    status = "passed"
    environment = _validation_environment()
    for step in steps:
        resolved = resolved_tools[(step.tool_key, step.argv[0])]
        observation = _run_process(step, resolved.executable, environment)
        step_result = _evaluate_step(root, step, resolved, observation)
        step_results.append(step_result)
        diagnostics.extend(step_result["diagnostics"])
        if step_result["status"] != "passed":
            status = step_result["status"]
            break

    after, snapshot_error = _try_snapshot(root, project_file_limit, project_byte_limit)
    if snapshot_error:
        status = "failed"
        diagnostics.append(snapshot_error)
    return _validation_result(
        status=status,
        spec_sha256=spec_sha256,
        planned_step_count=len(steps),
        before=before,
        after=after,
        steps=step_results,
        tools=tool_records,
        diagnostics=diagnostics,
    )


def _project_root(value: str | os.PathLike[str]) -> Path:
    path = Path(value).expanduser()
    if _is_link_or_reparse(path):
        raise ValueError("source project path must not be a symbolic link or reparse point")
    if not path.is_dir():
        raise NotADirectoryError(str(path))
    return path.resolve(strict=True)


def _spec_sha256(spec: Mapping[str, Any]) -> str:
    if not isinstance(spec, Mapping):
        raise TypeError("validation_spec must be a mapping")
    try:
        serialized = json.dumps(
            spec,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _SpecError("validation_spec must contain only finite JSON values") from error
    if len(serialized) > _MAX_SPEC_BYTES:
        raise _SpecError(f"validation_spec exceeds {_MAX_SPEC_BYTES} bytes")
    return hashlib.sha256(serialized).hexdigest()


def _effective_allowlist(
    provided: Collection[str] | None,
    spec: Mapping[str, Any],
) -> frozenset[str]:
    source = DEFAULT_TOOL_ALLOWLIST if provided is None else provided
    if isinstance(source, (str, bytes)):
        raise ValueError("allowed_tools must be a collection of tool names")
    normalized: set[str] = set()
    for value in source:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("allowed_tools must contain non-empty strings")
        key = _tool_key(value)
        if key in _FORBIDDEN_SHELLS:
            raise ValueError(f"shell tools cannot be allowlisted: {value}")
        normalized.add(key)

    narrowed = spec.get("allowed_tools")
    if narrowed is None:
        return frozenset(normalized)
    if not isinstance(narrowed, list) or not all(
        isinstance(item, str) and item.strip() for item in narrowed
    ):
        raise _SpecError("allowed_tools in validation_spec must be a list of tool names")
    requested = {_tool_key(item) for item in narrowed}
    if requested.intersection(_FORBIDDEN_SHELLS):
        raise _SpecError("validation_spec cannot allowlist a shell")
    return frozenset(normalized.intersection(requested))


def _parse_spec(
    root: Path,
    spec: Mapping[str, Any],
    defaults: tuple[float, int, int],
) -> tuple[_Step, ...]:
    if not isinstance(spec, Mapping):
        raise TypeError("validation_spec must be a mapping")
    top_timeout = _bounded_number(
        spec.get("timeout_seconds", defaults[0]),
        name="timeout_seconds",
        minimum_exclusive=0.0,
        maximum=_MAX_TIMEOUT_SECONDS,
    )
    common_limit = spec.get("output_limit")
    top_stdout = _bounded_integer(
        spec.get("stdout_limit", common_limit if common_limit is not None else defaults[1]),
        name="stdout_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )
    top_stderr = _bounded_integer(
        spec.get("stderr_limit", common_limit if common_limit is not None else defaults[2]),
        name="stderr_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )

    raw_steps: list[tuple[str, str, Mapping[str, Any]]] = []
    if "steps" in spec:
        value = spec.get("steps")
        if not isinstance(value, list):
            raise _SpecError("steps must be a list")
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                raise _SpecError(f"steps[{index}] must be an object")
            kind = str(item.get("kind") or "behavior").strip().casefold()
            if kind == "run":
                kind = "behavior"
            if kind not in {"build", "behavior"}:
                raise _SpecError(f"steps[{index}].kind must be build or behavior")
            raw_steps.append((kind, f"{kind}-{index + 1}", item))
    elif "argv" in spec:
        raw_steps.append(("behavior", "behavior", spec))
    else:
        for phase in ("build", "behavior", "run"):
            value = spec.get(phase)
            if value is None:
                continue
            kind = "behavior" if phase == "run" else phase
            items = value if isinstance(value, list) else [value]
            for index, item in enumerate(items):
                if not isinstance(item, Mapping):
                    raise _SpecError(f"{phase} validation step must be an object")
                default_name = kind if len(items) == 1 else f"{kind}-{index + 1}"
                raw_steps.append((kind, default_name, item))

    if not raw_steps:
        raise _SpecError("validation_spec must declare at least one argv step")
    if len(raw_steps) > _MAX_STEPS:
        raise _SpecError(f"validation_spec exceeds the step limit of {_MAX_STEPS}")

    parsed: list[_Step] = []
    names: set[str] = set()
    for index, (kind, default_name, raw) in enumerate(raw_steps):
        step = _parse_step(
            root,
            raw,
            kind=kind,
            default_name=default_name,
            default_timeout=top_timeout,
            default_stdout_limit=top_stdout,
            default_stderr_limit=top_stderr,
            location=f"steps[{index}]",
        )
        if step.name in names:
            raise _SpecError(f"duplicate validation step name: {step.name}")
        names.add(step.name)
        parsed.append(step)
    return tuple(parsed)


def _parse_step(
    root: Path,
    raw: Mapping[str, Any],
    *,
    kind: str,
    default_name: str,
    default_timeout: float,
    default_stdout_limit: int,
    default_stderr_limit: int,
    location: str,
) -> _Step:
    name = raw.get("name", default_name)
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise _SpecError(f"{location}.name must be a non-empty string of at most 80 characters")
    name = name.strip()
    if any(ord(character) < 32 for character in name):
        raise _SpecError(f"{location}.name contains a control character")

    argv_value = raw.get("argv")
    if not isinstance(argv_value, list) or not argv_value:
        raise _SpecError(f"{location}.argv must be a non-empty list")
    if len(argv_value) > _MAX_ARGV_ITEMS or not all(isinstance(item, str) for item in argv_value):
        raise _SpecError(f"{location}.argv must contain at most {_MAX_ARGV_ITEMS} strings")
    argv = tuple(argv_value)
    try:
        argument_size = sum(len(item.encode("utf-8")) for item in argv)
    except UnicodeEncodeError as error:
        raise _SpecError(f"{location}.argv must contain valid Unicode strings") from error
    if argument_size > _MAX_ARGUMENT_BYTES:
        raise _SpecError(f"{location}.argv exceeds {_MAX_ARGUMENT_BYTES} encoded bytes")
    for item in argv:
        if not item or any(ord(character) < 32 for character in item):
            raise _SpecError(f"{location}.argv contains an empty value or control character")

    tool = raw.get("tool", argv[0])
    if not isinstance(tool, str) or not tool.strip():
        raise _SpecError(f"{location}.tool must be a non-empty string")
    tool_key = _tool_key(tool)
    argv_tool_key = _tool_key(argv[0])
    if tool_key != argv_tool_key:
        raise _SpecError(f"{location}.tool does not identify argv[0]")
    if tool_key in _FORBIDDEN_SHELLS or _tool_suffix(tool) in _SHELL_FILE_SUFFIXES:
        raise _SpecError(f"{location} requests a forbidden shell tool")

    cwd, cwd_path = _constrained_directory(root, raw.get("cwd", "."), location=location)
    _validate_argv_boundaries(root, cwd_path, argv[1:], location=location)
    common_limit = raw.get("output_limit")
    timeout = _bounded_number(
        raw.get("timeout_seconds", default_timeout),
        name=f"{location}.timeout_seconds",
        minimum_exclusive=0.0,
        maximum=_MAX_TIMEOUT_SECONDS,
    )
    stdout_limit = _bounded_integer(
        raw.get(
            "stdout_limit",
            common_limit if common_limit is not None else default_stdout_limit,
        ),
        name=f"{location}.stdout_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )
    stderr_limit = _bounded_integer(
        raw.get(
            "stderr_limit",
            common_limit if common_limit is not None else default_stderr_limit,
        ),
        name=f"{location}.stderr_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )
    expectation = _expectation_mapping(raw, location)
    exit_codes = _expected_exit_codes(expectation, location)
    text_expectations = _text_expectations(expectation, location)
    output_expectations = _output_expectations(root, expectation, location)
    json_assertions = _json_assertions(root, expectation, location)
    return _Step(
        name=name,
        kind=kind,
        tool=tool,
        tool_key=tool_key,
        argv=argv,
        cwd=cwd,
        cwd_path=cwd_path,
        timeout_seconds=timeout,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        expected_exit_codes=exit_codes,
        text_expectations=text_expectations,
        output_expectations=output_expectations,
        json_assertions=json_assertions,
    )


def _expectation_mapping(raw: Mapping[str, Any], location: str) -> dict[str, Any]:
    nested = raw.get("expect", raw.get("expected", {}))
    if nested is None:
        nested = {}
    if not isinstance(nested, Mapping):
        raise _SpecError(f"{location}.expect must be an object")
    result = dict(nested)
    aliases = {
        "expected_exit_code": "exit_code",
        "expected_stdout": "stdout",
        "expected_stderr": "stderr",
        "expected_stdout_contains": "stdout_contains",
        "expected_stderr_contains": "stderr_contains",
        "expected_output_files": "output_files",
        "json_assertions": "json_assertions",
        "expected_json": "json",
    }
    for source, target in aliases.items():
        if source in raw:
            result[target] = raw[source]
    return result


def _expected_exit_codes(
    expectation: Mapping[str, Any], location: str
) -> tuple[int, ...] | None:
    value = expectation.get("exit_code", 0)
    if value is None:
        return None
    values = value if isinstance(value, list) else [value]
    if not values:
        raise _SpecError(f"{location}.expect.exit_code cannot be an empty list")
    result: list[int] = []
    for item in values:
        if not isinstance(item, int) or isinstance(item, bool):
            raise _SpecError(f"{location}.expect.exit_code must contain integers")
        result.append(item)
    return tuple(dict.fromkeys(result))


def _text_expectations(
    expectation: Mapping[str, Any], location: str
) -> tuple[_TextExpectation, ...]:
    result: list[_TextExpectation] = []
    for stream in ("stdout", "stderr"):
        if stream in expectation:
            value = expectation[stream]
            if isinstance(value, str):
                result.append(_TextExpectation(stream, "equals", _normalized_text(value)))
            elif isinstance(value, Mapping):
                if "equals" in value:
                    expected = value.get("equals")
                    if not isinstance(expected, str):
                        raise _SpecError(f"{location}.expect.{stream}.equals must be a string")
                    result.append(_TextExpectation(stream, "equals", _normalized_text(expected)))
                if "contains" in value:
                    result.extend(
                        _contains_expectations(stream, value.get("contains"), location)
                    )
                if not {"equals", "contains"}.intersection(value):
                    raise _SpecError(
                        f"{location}.expect.{stream} must declare equals or contains"
                    )
            else:
                raise _SpecError(f"{location}.expect.{stream} must be a string or object")
        contains_key = f"{stream}_contains"
        if contains_key in expectation:
            result.extend(
                _contains_expectations(stream, expectation[contains_key], location)
            )
    return tuple(result)


def _contains_expectations(
    stream: str, value: Any, location: str
) -> list[_TextExpectation]:
    values = value if isinstance(value, list) else [value]
    if not values or not all(isinstance(item, str) for item in values):
        raise _SpecError(f"{location}.expect.{stream}_contains must contain strings")
    return [_TextExpectation(stream, "contains", _normalized_text(item)) for item in values]


def _output_expectations(
    root: Path, expectation: Mapping[str, Any], location: str
) -> tuple[_OutputExpectation, ...]:
    value = expectation.get("output_files", expectation.get("files", []))
    if value is None:
        return ()
    raw_items: list[tuple[Any, Any]] = []
    if isinstance(value, Mapping):
        raw_items.extend(value.items())
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if not isinstance(item, Mapping):
                raise _SpecError(f"{location}.expect.output_files[{index}] must be an object")
            raw_items.append((item.get("path"), item.get("sha256")))
    else:
        raise _SpecError(f"{location}.expect.output_files must be an object or list")

    result: list[_OutputExpectation] = []
    seen: set[str] = set()
    for path_value, digest_value in raw_items:
        path = _constrained_file_name(root, path_value, location=location)
        if not isinstance(digest_value, str) or not _HEX_SHA256.fullmatch(digest_value):
            raise _SpecError(f"expected output SHA-256 must be 64 hexadecimal characters: {path}")
        if path in seen:
            raise _SpecError(f"duplicate expected output path: {path}")
        seen.add(path)
        result.append(_OutputExpectation(path, digest_value.casefold()))
    return tuple(result)


def _json_assertions(
    root: Path, expectation: Mapping[str, Any], location: str
) -> tuple[_JsonAssertion, ...]:
    value = expectation.get("json_assertions", expectation.get("json"))
    if value is None:
        return ()
    if isinstance(value, Mapping) and not _looks_like_json_assertion(value):
        value = [{"source": "stdout", "path": "", "equals": dict(value)}]
    elif isinstance(value, Mapping):
        value = [value]
    if not isinstance(value, list):
        raise _SpecError(f"{location}.expect.json_assertions must be a list or object")

    result: list[_JsonAssertion] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise _SpecError(f"{location}.expect.json_assertions[{index}] must be an object")
        source_value = item.get("file", item.get("source", "stdout"))
        if not isinstance(source_value, str) or not source_value.strip():
            raise _SpecError(f"JSON assertion {index} has an invalid source")
        source = source_value.strip()
        if source not in {"stdout", "stderr"}:
            source = _constrained_file_name(root, source, location=location)
        path = item.get("path", "")
        _validate_json_path(path, location, index)
        operators = [name for name in ("equals", "exists", "contains", "type") if name in item]
        if not operators:
            raise _SpecError(f"JSON assertion {index} must declare an assertion operator")
        for operator in operators:
            expected = item[operator]
            if operator == "exists" and not isinstance(expected, bool):
                raise _SpecError(f"JSON assertion {index} exists value must be boolean")
            if operator == "type" and expected not in {
                "array",
                "boolean",
                "integer",
                "null",
                "number",
                "object",
                "string",
            }:
                raise _SpecError(f"JSON assertion {index} has an unsupported type")
            result.append(_JsonAssertion(source, path, operator, expected))
    return tuple(result)


def _looks_like_json_assertion(value: Mapping[str, Any]) -> bool:
    return bool(
        {"source", "file", "path", "equals", "exists", "contains", "type"}.intersection(
            value
        )
    )


def _validate_json_path(path: Any, location: str, index: int) -> None:
    if isinstance(path, str):
        if any(ord(character) < 32 for character in path):
            raise _SpecError(f"JSON assertion {index} path contains a control character")
        return
    if isinstance(path, list) and all(
        isinstance(item, (str, int)) and not isinstance(item, bool) for item in path
    ):
        return
    raise _SpecError(f"{location} JSON assertion {index} path must be a string or list")


def _tool_key(value: str) -> str:
    text = value.strip().replace("\\", "/")
    base = PureWindowsPath(text).name.casefold()
    for suffix in (".exe", ".com", ".bat", ".cmd", ".ps1"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if _PYTHON_TOOL.fullmatch(base) or base in {"py", "pythonw"}:
        return "python"
    return base


def _tool_suffix(value: str) -> str:
    return PureWindowsPath(value.strip()).suffix.casefold()


def _resolve_tool(
    step: _Step,
    allowlist: frozenset[str],
    resolver: ToolResolver,
) -> tuple[_ResolvedTool | None, dict[str, Any], str | None]:
    base_record: dict[str, Any] = {
        "tool": step.tool_key,
        "requested": step.argv[0],
        "allowlisted": step.tool_key in allowlist,
        "available": False,
        "resolved_path": None,
        "sha256": None,
        "size_bytes": None,
    }
    if step.tool_key in _FORBIDDEN_SHELLS:
        return None, base_record, f"shell execution is forbidden: {step.tool}"
    if step.tool_key not in allowlist:
        return None, base_record, f"tool is not in the runtime validation allowlist: {step.tool}"
    try:
        candidate = resolver(step.argv[0])
    except (OSError, TypeError, ValueError) as error:
        return None, base_record, f"tool discovery failed for {step.tool}: {type(error).__name__}"
    if candidate is None:
        return None, base_record, f"allowlisted tool was not found: {step.tool}"
    try:
        candidate_text = os.fspath(candidate)
    except TypeError:
        return None, base_record, f"tool resolver returned an invalid path for {step.tool}"
    if not candidate_text or any(ord(character) < 32 for character in candidate_text):
        return None, base_record, f"tool resolver returned an invalid path for {step.tool}"
    discovered = Path(candidate_text).expanduser()
    if not discovered.is_absolute():
        located = shutil.which(candidate_text)
        if located is None:
            return None, base_record, f"resolved tool path was not discoverable: {step.tool}"
        discovered = Path(located)
    try:
        executable = discovered.resolve(strict=True)
    except OSError:
        return None, base_record, f"resolved tool path does not exist: {step.tool}"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return None, base_record, f"resolved tool is not executable: {step.tool}"
    if _tool_suffix(str(executable)) in _SHELL_FILE_SUFFIXES:
        return None, base_record, f"resolved tool would require a shell: {step.tool}"
    if _tool_key(executable.name) != step.tool_key:
        return None, base_record, f"resolved executable identity does not match {step.tool}"

    fingerprint = _fingerprint_file(executable)
    record = {
        **base_record,
        "available": True,
        "resolved_path": str(executable),
        "sha256": fingerprint.get("sha256"),
        "size_bytes": fingerprint.get("size_bytes"),
    }
    return (
        _ResolvedTool(step.tool_key, step.argv[0], executable, record),
        record,
        None,
    )


def _default_tool_resolver(value: str) -> str | None:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path) if path.is_file() else None
    if _tool_key(value) == "python" and sys.executable:
        executable = Path(sys.executable)
        if executable.is_file():
            return str(executable)
    return shutil.which(value)


def _constrained_directory(root: Path, value: Any, *, location: str) -> tuple[str, Path]:
    if value in (None, "", "."):
        return ".", root
    normalized = _normalize_relative_path(value)
    if normalized is None:
        raise _BoundaryError(f"{location}.cwd must stay below the source project")
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    _assert_no_symlink_components(root, candidate)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError(f"{location}.cwd must resolve below the source project") from error
    if not resolved.is_dir():
        raise _BoundaryError(f"{location}.cwd is not a directory")
    return normalized, resolved


def _constrained_file_name(root: Path, value: Any, *, location: str) -> str:
    normalized = _normalize_relative_path(value)
    if normalized is None:
        raise _BoundaryError(f"{location} file path must stay below the source project")
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    _assert_no_symlink_components(root, candidate)
    try:
        candidate.resolve(strict=False).relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError(f"{location} file path escapes the source project") from error
    return normalized


def _normalize_relative_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if not text or text.startswith("/") or any(ord(character) < 32 for character in text):
        return None
    pure = PurePosixPath(text)
    if pure.is_absolute() or not pure.parts:
        return None
    if any(part in {"", ".", ".."} or ":" in part for part in pure.parts):
        return None
    return PurePosixPath(*pure.parts).as_posix()


def _assert_no_symlink_components(root: Path, target: Path) -> None:
    try:
        relative = target.relative_to(root)
    except ValueError as error:
        raise _BoundaryError("path escapes the source project") from error
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if _is_link_or_reparse(cursor):
            raise _BoundaryError(
                f"project path traverses a symbolic link or reparse point: {relative.as_posix()}"
            )


def _is_link_or_reparse(path: Path) -> bool:
    """Return whether ``path`` redirects traversal through a filesystem link."""

    try:
        metadata = path.lstat()
    except (FileNotFoundError, OSError):
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _validate_argv_boundaries(
    root: Path,
    cwd: Path,
    arguments: Sequence[str],
    *,
    location: str,
) -> None:
    for argument in arguments:
        for candidate in _argument_path_candidates(argument):
            text = candidate.strip().strip('"\'')
            if not text:
                continue
            normalized = text.replace("\\", "/")
            if ".." in PurePosixPath(normalized).parts:
                raise _BoundaryError(f"{location}.argv contains a parent-directory traversal")
            if normalized.startswith("~"):
                raise _BoundaryError(f"{location}.argv contains an unbounded home path")
            windows = PureWindowsPath(text)
            host_path = Path(text)
            if windows.is_absolute() or host_path.is_absolute():
                try:
                    host_path.expanduser().resolve(strict=False).relative_to(root)
                except (OSError, ValueError) as error:
                    raise _BoundaryError(
                        f"{location}.argv contains an absolute path outside the source project"
                    ) from error
            elif _looks_path_like(text):
                joined = cwd / Path(text.replace("\\", os.sep))
                try:
                    joined.resolve(strict=False).relative_to(root)
                except (OSError, ValueError) as error:
                    raise _BoundaryError(f"{location}.argv path escapes the source project") from error


def _argument_path_candidates(argument: str) -> tuple[str, ...]:
    if argument.startswith("/") and not argument.startswith("//"):
        remainder = argument[1:]
        if "/" not in remainder and "\\" not in remainder and ":" not in remainder:
            return ()
    if argument.startswith("--") and "=" not in argument:
        return ()
    if argument in {"-c", "-m", "-e", "--"}:
        return ()
    candidates = [argument]
    if "=" in argument:
        candidates.append(argument.split("=", 1)[1])
    if argument.startswith("@"):
        candidates.append(argument[1:])
    for prefix in _ATTACHED_PATH_OPTIONS:
        if argument.startswith(prefix) and len(argument) > len(prefix):
            candidates.append(argument[len(prefix) :])
    return tuple(dict.fromkeys(candidates))


def _looks_path_like(value: str) -> bool:
    return (
        "/" in value
        or "\\" in value
        or value.startswith(".")
        or value.startswith("@")
    )


def _run_process(
    step: _Step,
    executable: Path,
    environment: Mapping[str, str],
) -> _ProcessObservation:
    stdout_capture = _BoundedCapture(step.stdout_limit)
    stderr_capture = _BoundedCapture(step.stderr_limit)
    command = [str(executable), *step.argv[1:]]
    options: dict[str, Any] = {
        "cwd": str(step.cwd_path),
        "env": dict(environment),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        options["start_new_session"] = True

    started_at = time.monotonic()
    try:
        process = subprocess.Popen(command, **options)
    except (OSError, subprocess.SubprocessError) as error:
        duration = max(0, round((time.monotonic() - started_at) * 1000))
        return _ProcessObservation(
            started=False,
            timed_out=False,
            exit_code=None,
            termination_exit_code=None,
            duration_ms=duration,
            stdout=stdout_capture.record(),
            stderr=stderr_capture.record(),
            error=f"{type(error).__name__}: {error}",
        )

    assert process.stdout is not None
    assert process.stderr is not None
    stdout_thread = threading.Thread(
        target=stdout_capture.consume,
        args=(process.stdout,),
        name=f"runtime-validation-{step.name}-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=stderr_capture.consume,
        args=(process.stderr,),
        name=f"runtime-validation-{step.name}-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=step.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
    finally:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_process(process)
            process.wait()

    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    reader_errors = [
        value
        for value in (stdout_capture.error, stderr_capture.error)
        if value is not None
    ]
    if stdout_thread.is_alive() or stderr_thread.is_alive():
        reader_errors.append("output reader did not terminate")
    duration = max(0, round((time.monotonic() - started_at) * 1000))
    return _ProcessObservation(
        started=True,
        timed_out=timed_out,
        exit_code=None if timed_out else process.returncode,
        termination_exit_code=process.returncode if timed_out else None,
        duration_ms=duration,
        stdout=stdout_capture.record(),
        stderr=stderr_capture.record(),
        error="; ".join(reader_errors) if reader_errors else None,
    )


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
            if taskkill.is_file():
                subprocess.run(
                    [str(taskkill), "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=5,
                    check=False,
                )
            if process.poll() is None:
                process.kill()
    except (OSError, ProcessLookupError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def _evaluate_step(
    root: Path,
    step: _Step,
    tool: _ResolvedTool,
    observation: _ProcessObservation,
) -> dict[str, Any]:
    diagnostics: list[str] = []
    assertions: list[dict[str, Any]] = []
    outputs: list[dict[str, Any]] = []

    if not observation.started:
        diagnostics.append(f"{step.name}: tool could not be started: {observation.error}")
        return _step_result(
            step,
            tool,
            observation,
            status="unavailable",
            assertions=assertions,
            outputs=outputs,
            diagnostics=diagnostics,
        )
    if observation.timed_out:
        diagnostics.append(
            f"{step.name}: validation timed out after {_format_seconds(step.timeout_seconds)} seconds"
        )
    if observation.error:
        diagnostics.append(f"{step.name}: output capture failed: {observation.error}")

    if step.expected_exit_codes is not None:
        passed = (
            not observation.timed_out
            and observation.exit_code in step.expected_exit_codes
        )
        assertions.append(
            {
                "kind": "exit_code",
                "operator": "in",
                "expected": list(step.expected_exit_codes),
                "actual": observation.exit_code,
                "passed": passed,
            }
        )
        if not passed:
            diagnostics.append(
                f"{step.name}: exit code assertion failed; expected "
                f"{list(step.expected_exit_codes)}, observed {observation.exit_code}"
            )

    streams = {"stdout": observation.stdout, "stderr": observation.stderr}
    for expected in step.text_expectations:
        stream = streams[expected.stream]
        actual = str(stream["text"])
        if expected.operator == "equals":
            passed = not stream["truncated"] and actual == expected.expected
        else:
            passed = expected.expected in actual
        assertions.append(
            {
                "kind": expected.stream,
                "operator": expected.operator,
                "expected": expected.expected,
                "passed": passed,
            }
        )
        if not passed:
            suffix = " (captured output was truncated)" if stream["truncated"] else ""
            diagnostics.append(
                f"{step.name}: {expected.stream} {expected.operator} assertion failed{suffix}"
            )

    for expected in step.output_expectations:
        try:
            record = _project_file_record(root, expected.path, _MAX_HASHED_FILE_BYTES)
            actual_hash = record["sha256"]
            passed = actual_hash == expected.sha256
            output = {
                **record,
                "expected_sha256": expected.sha256,
                "matched": passed,
            }
        except (OSError, RuntimeError, _BoundaryError) as error:
            actual_hash = None
            passed = False
            output = {
                "path": expected.path,
                "sha256": None,
                "size_bytes": None,
                "expected_sha256": expected.sha256,
                "matched": False,
                "error": str(error),
            }
        outputs.append(output)
        assertions.append(
            {
                "kind": "output_file_sha256",
                "path": expected.path,
                "operator": "equals",
                "expected": expected.sha256,
                "actual": actual_hash,
                "passed": passed,
            }
        )
        if not passed:
            diagnostics.append(f"{step.name}: output file SHA-256 assertion failed: {expected.path}")

    json_cache: dict[str, tuple[bool, Any, str | None]] = {}
    for expected in step.json_assertions:
        if expected.source not in json_cache:
            json_cache[expected.source] = _load_json_source(root, expected.source, observation)
        loaded, document, load_error = json_cache[expected.source]
        found = False
        actual: Any = None
        if loaded:
            found, actual = _json_value(document, expected.path)
        passed = _json_assertion_passes(expected, found, actual) if loaded else False
        assertion = {
            "kind": "json",
            "source": expected.source,
            "path": expected.path,
            "operator": expected.operator,
            "expected": expected.expected,
            "found": found,
            "passed": passed,
        }
        if found:
            assertion["actual"] = actual
        if load_error:
            assertion["error"] = load_error
        assertions.append(assertion)
        if not passed:
            diagnostic = load_error or (
                f"JSON {expected.operator} assertion failed at {_display_json_path(expected.path)}"
            )
            diagnostics.append(f"{step.name}: {expected.source}: {diagnostic}")

    failed = (
        observation.timed_out
        or observation.error is not None
        or any(not item["passed"] for item in assertions)
    )
    return _step_result(
        step,
        tool,
        observation,
        status="failed" if failed else "passed",
        assertions=assertions,
        outputs=outputs,
        diagnostics=diagnostics,
    )


def _step_result(
    step: _Step,
    tool: _ResolvedTool,
    observation: _ProcessObservation,
    *,
    status: str,
    assertions: Sequence[Mapping[str, Any]],
    outputs: Sequence[Mapping[str, Any]],
    diagnostics: Sequence[str],
) -> dict[str, Any]:
    return {
        "name": step.name,
        "kind": step.kind,
        "status": status,
        "tool": tool.key,
        "argv": list(step.argv),
        "cwd": step.cwd,
        "shell": False,
        "timeout_seconds": step.timeout_seconds,
        "timed_out": observation.timed_out,
        "duration_ms": observation.duration_ms,
        "exit_code": observation.exit_code,
        "termination_exit_code": observation.termination_exit_code,
        "stdout": observation.stdout,
        "stderr": observation.stderr,
        "stdout_text": observation.stdout["text"],
        "stderr_text": observation.stderr["text"],
        "assertions": [dict(item) for item in assertions],
        "outputs": [dict(item) for item in outputs],
        "diagnostics": list(diagnostics),
    }


def _load_json_source(
    root: Path,
    source: str,
    observation: _ProcessObservation,
) -> tuple[bool, Any, str | None]:
    if source in {"stdout", "stderr"}:
        stream = observation.stdout if source == "stdout" else observation.stderr
        if stream["truncated"]:
            return False, None, f"{source} exceeded its capture limit"
        text = stream["text"]
    else:
        try:
            path = _project_file_path(root, source)
            size = path.stat().st_size
            if size > _MAX_JSON_BYTES:
                return False, None, f"JSON result exceeds {_MAX_JSON_BYTES} bytes"
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, _BoundaryError) as error:
            return False, None, f"JSON result could not be read: {type(error).__name__}: {error}"
    try:
        return True, json.loads(text, parse_constant=_reject_json_constant), None
    except (json.JSONDecodeError, ValueError) as error:
        message = error.msg if isinstance(error, json.JSONDecodeError) else str(error)
        return False, None, f"JSON result could not be parsed: {message}"


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _json_value(document: Any, path: Any) -> tuple[bool, Any]:
    if path in ("", "$", []):
        return True, document
    if isinstance(path, list):
        parts: list[Any] = list(path)
    elif isinstance(path, str) and path.startswith("/"):
        parts = [item.replace("~1", "/").replace("~0", "~") for item in path[1:].split("/")]
    elif isinstance(path, str):
        text = path[2:] if path.startswith("$.") else path
        parts = text.split(".") if text else []
    else:
        return False, None
    current = document
    for part in parts:
        if isinstance(current, list):
            try:
                index = part if isinstance(part, int) else int(part)
            except (TypeError, ValueError):
                return False, None
            if isinstance(index, bool) or index < 0 or index >= len(current):
                return False, None
            current = current[index]
        elif isinstance(current, Mapping):
            key = str(part)
            if key not in current:
                return False, None
            current = current[key]
        else:
            return False, None
    return True, current


def _json_assertion_passes(
    assertion: _JsonAssertion,
    found: bool,
    actual: Any,
) -> bool:
    if assertion.operator == "exists":
        return found is assertion.expected
    if not found:
        return False
    if assertion.operator == "equals":
        return _json_equal(actual, assertion.expected)
    if assertion.operator == "contains":
        if isinstance(actual, Mapping):
            return isinstance(assertion.expected, str) and assertion.expected in actual
        if isinstance(actual, list):
            return any(_json_equal(item, assertion.expected) for item in actual)
        if isinstance(actual, str) and isinstance(assertion.expected, str):
            return assertion.expected in actual
        return False
    if assertion.operator == "type":
        return _json_type(actual) == assertion.expected
    return False


def _json_equal(actual: Any, expected: Any) -> bool:
    """Compare JSON values without Python's ``True == 1`` coercion."""

    if actual is None or expected is None:
        return actual is expected
    if isinstance(actual, bool) or isinstance(expected, bool):
        return isinstance(actual, bool) and isinstance(expected, bool) and actual is expected
    if isinstance(actual, (int, float)) or isinstance(expected, (int, float)):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, str) or isinstance(expected, str):
        return isinstance(actual, str) and isinstance(expected, str) and actual == expected
    if isinstance(actual, list) or isinstance(expected, list):
        return (
            isinstance(actual, list)
            and isinstance(expected, list)
            and len(actual) == len(expected)
            and all(_json_equal(left, right) for left, right in zip(actual, expected))
        )
    if isinstance(actual, Mapping) or isinstance(expected, Mapping):
        return (
            isinstance(actual, Mapping)
            and isinstance(expected, Mapping)
            and set(actual) == set(expected)
            and all(_json_equal(actual[key], expected[key]) for key in actual)
        )
    return False


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    return "unknown"


def _display_json_path(path: Any) -> str:
    if path in ("", "$", []):
        return "$"
    return str(path)


def _snapshot_project(root: Path, max_files: int, max_bytes: int) -> dict[str, Any]:
    if _is_link_or_reparse(root) or not root.is_dir():
        raise _BoundaryError("source project root changed or disappeared")
    digest = hashlib.sha256()
    file_count = 0
    total_bytes = 0
    for current_root, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current / name
            if _is_link_or_reparse(candidate):
                raise _BoundaryError(
                    f"linked or reparse-point directory is outside the runtime validation boundary: "
                    f"{candidate.relative_to(root).as_posix()}"
                )
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(filenames):
            path = current / name
            relative = path.relative_to(root).as_posix()
            if _is_link_or_reparse(path):
                raise _BoundaryError(
                    f"linked or reparse-point file is outside the runtime validation boundary: {relative}"
                )
            try:
                before = path.stat()
            except OSError as error:
                raise RuntimeError(f"project file could not be inspected: {relative}") from error
            if not stat.S_ISREG(before.st_mode):
                raise _BoundaryError(f"project path is not a regular file: {relative}")
            file_count += 1
            total_bytes += before.st_size
            if file_count > max_files:
                raise RuntimeError(f"project exceeds the file limit of {max_files}")
            if total_bytes > max_bytes:
                raise RuntimeError(f"project exceeds the byte limit of {max_bytes}")
            file_digest = _hash_file_stable(path, before, max_bytes)
            digest.update(relative.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(str(before.st_size).encode("ascii"))
            digest.update(b"\x00")
            digest.update(bytes.fromhex(file_digest))
            digest.update(b"\x00")
    return {
        "sha256": digest.hexdigest(),
        "file_count": file_count,
        "total_bytes": total_bytes,
    }


def _try_snapshot(
    root: Path, max_files: int, max_bytes: int
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        return _snapshot_project(root, max_files, max_bytes), None
    except (OSError, RuntimeError, _BoundaryError) as error:
        return None, f"project snapshot failed after execution: {error}"


def _hash_file_stable(path: Path, before: os.stat_result, max_bytes: int) -> str:
    if before.st_size > max_bytes:
        raise RuntimeError(f"file exceeds the hash limit: {path.name}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_IO_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError(f"file exceeds the hash limit: {path.name}")
            digest.update(chunk)
    after = path.stat()
    before_identity = (before.st_size, before.st_mtime_ns, getattr(before, "st_ino", None))
    after_identity = (after.st_size, after.st_mtime_ns, getattr(after, "st_ino", None))
    if before_identity != after_identity or total != after.st_size:
        raise RuntimeError(f"file changed while it was hashed: {path.name}")
    return digest.hexdigest()


def _project_file_path(root: Path, relative_path: str) -> Path:
    normalized = _normalize_relative_path(relative_path)
    if normalized is None:
        raise _BoundaryError("project file path is invalid")
    path = root.joinpath(*PurePosixPath(normalized).parts)
    _assert_no_symlink_components(root, path)
    if _is_link_or_reparse(path) or not path.is_file():
        raise FileNotFoundError(normalized)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError(f"project file escapes the source project: {normalized}") from error
    if not resolved.is_file():
        raise _BoundaryError(f"project path is not a regular file: {normalized}")
    return resolved


def _project_file_record(root: Path, relative_path: str, max_bytes: int) -> dict[str, Any]:
    path = _project_file_path(root, relative_path)
    before = path.stat()
    if before.st_size > max_bytes:
        raise RuntimeError(f"output file exceeds the hash limit of {max_bytes} bytes")
    return {
        "path": relative_path,
        "sha256": _hash_file_stable(path, before, max_bytes),
        "size_bytes": before.st_size,
    }


def _fingerprint_file(path: Path) -> dict[str, Any]:
    try:
        before = path.stat()
        if before.st_size > _MAX_HASHED_FILE_BYTES:
            return {"sha256": None, "size_bytes": before.st_size}
        return {
            "sha256": _hash_file_stable(path, before, _MAX_HASHED_FILE_BYTES),
            "size_bytes": before.st_size,
        }
    except (OSError, RuntimeError):
        return {"sha256": None, "size_bytes": None}


def _validation_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "NODE_OPTIONS",
        "PYTHONHOME",
        "PYTHONPATH",
        "RUBYOPT",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "CI": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def _validation_result(
    *,
    status: str,
    spec_sha256: str | None,
    planned_step_count: int,
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any] | None,
    steps: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]],
    diagnostics: Sequence[str],
) -> dict[str, Any]:
    step_items = [dict(item) for item in steps]
    assertion_items = [
        assertion
        for step in step_items
        for assertion in step.get("assertions", [])
        if isinstance(assertion, Mapping)
    ]
    passed_assertions = sum(1 for item in assertion_items if item.get("passed") is True)
    failed_assertions = sum(1 for item in assertion_items if item.get("passed") is not True)
    confidence = _confidence(status, step_items, assertion_items)
    project = {
        "before": dict(before) if before is not None else None,
        "after": dict(after) if after is not None else None,
        "sha256_before": before.get("sha256") if before is not None else None,
        "sha256_after": after.get("sha256") if after is not None else None,
        "changed": (
            before.get("sha256") != after.get("sha256")
            if before is not None and after is not None
            else None
        ),
    }
    summary = {
        "planned_step_count": planned_step_count,
        "executed_step_count": len(step_items),
        "passed_step_count": sum(1 for item in step_items if item.get("status") == "passed"),
        "failed_step_count": sum(1 for item in step_items if item.get("status") == "failed"),
        "unavailable_step_count": sum(
            1 for item in step_items if item.get("status") == "unavailable"
        ),
        "assertion_count": len(assertion_items),
        "passed_assertion_count": passed_assertions,
        "failed_assertion_count": failed_assertions,
    }
    provenance = {
        "validator": {
            "name": "reverse_analyzer.source.runtime_validation",
            "version": _VALIDATOR_VERSION,
            "local_execution": True,
            "shell": False,
        },
        "validation_spec": {
            "sha256": spec_sha256,
            "planned_step_count": planned_step_count,
        },
        "project": project,
        "tools": [dict(item) for item in tools],
    }
    evidence = {
        "schema_version": RUNTIME_VALIDATION_SCHEMA_VERSION,
        "status": status,
        "confidence": confidence,
        "behavior_equivalent": False,
        "summary": summary,
        "project": project,
        "steps": step_items,
        "provenance": provenance,
    }
    evidence_sha256 = hashlib.sha256(
        json.dumps(
            evidence,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    artifact = {
        "name": DEFAULT_RUNTIME_VALIDATION_PATH,
        "kind": "source_runtime_validation",
        "role": "validation_evidence",
        "media_type": "application/json",
        "status": status,
        "confidence": confidence["score"],
        "behavior_equivalent": False,
        "evidence_sha256": evidence_sha256,
    }
    return {
        "schema_version": RUNTIME_VALIDATION_SCHEMA_VERSION,
        "status": status,
        "confidence": confidence,
        "behavior_equivalent": False,
        "diagnostics": [str(item) for item in diagnostics if str(item)],
        "summary": summary,
        "project": project,
        "steps": step_items,
        "provenance": provenance,
        "artifact": artifact,
    }


def _confidence(
    status: str,
    steps: Sequence[Mapping[str, Any]],
    assertions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    basis = ["confidence applies only to the declared local validation spec"]
    if status != "passed":
        basis.append(f"runtime validation status is {status}")
        return {"score": 0.0, "level": "none", "basis": basis}
    kinds = {str(item.get("kind")) for item in steps}
    assertion_kinds = {str(item.get("kind")) for item in assertions}
    score = 0.45
    if "build" in kinds:
        score += 0.1
        basis.append("an explicit build step passed")
    if "behavior" in kinds:
        score += 0.15
        basis.append("an explicit behavior step passed")
    strong_kinds = assertion_kinds.intersection(
        {"stdout", "stderr", "output_file_sha256", "json"}
    )
    score += min(0.2, 0.05 * len(strong_kinds))
    if strong_kinds:
        basis.append("declared output or structured-result assertions passed")
    score = round(min(score, 0.9), 3)
    level = "high" if score >= 0.8 else "medium" if score >= 0.55 else "low"
    basis.append("passing does not establish whole-program behavioral equivalence")
    return {"score": score, "level": level, "basis": basis}


def _bounded_number(
    value: Any,
    *,
    name: str,
    minimum_exclusive: float,
    maximum: float,
) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a finite number") from error
    if not minimum_exclusive < number <= maximum or number != number:
        raise ValueError(f"{name} must be greater than {minimum_exclusive:g} and at most {maximum:g}")
    return number


def _bounded_integer(
    value: Any,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _normalized_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _format_seconds(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:g}"


# Compatibility aliases keep direct integrations independent from naming style.
validate_runtime_project = validate_source_runtime
validate_runtime_behavior = validate_source_runtime
run_runtime_validation = validate_source_runtime

__all__ = [
    "DEFAULT_RUNTIME_VALIDATION_PATH",
    "DEFAULT_TOOL_ALLOWLIST",
    "RUNTIME_VALIDATION_SCHEMA_VERSION",
    "run_runtime_validation",
    "validate_runtime_behavior",
    "validate_runtime_project",
    "validate_source_runtime",
]
