"""Bounded local differential validation for reconstructed source behavior.

The validator runs one explicit argv command for an original target and one
for its reconstruction.  It does not invoke a shell and it treats every path
declared by the validation spec as relative to the corresponding target root.
Behavioral equivalence is reported only when both real subprocesses complete
and every declared observation matches.
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


BEHAVIOR_VALIDATION_SCHEMA_VERSION = 1
DEFAULT_BEHAVIOR_VALIDATION_PATH = "source/behavior_validation.json"
DEFAULT_BEHAVIOR_TOOL_ALLOWLIST = frozenset(
    {
        "python",
        "node",
        "java",
        "dotnet",
        "ruby",
        "perl",
    }
)

_VALIDATOR_VERSION = "1.0"
_DEFAULT_TIMEOUT_SECONDS = 10.0
_MAX_TIMEOUT_SECONDS = 300.0
_DEFAULT_STREAM_LIMIT = 64 * 1024
_MAX_STREAM_LIMIT = 4 * 1024 * 1024
_DEFAULT_MAX_OUTPUT_BYTES = 256 * 1024 * 1024
_MAX_OUTPUT_BYTES = 1024 * 1024 * 1024
_MAX_SPEC_BYTES = 2 * 1024 * 1024
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_TARGET_BYTES = 512 * 1024 * 1024
_MAX_OUTPUTS = 128
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
_SHELL_SUFFIXES = frozenset({".bat", ".cmd", ".ps1", ".sh"})
_PYTHON_TOOL = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
_ATTACHED_PATH_OPTIONS = ("--cwd=", "--output=", "--out=", "-I", "-L", "-o")
_NON_REAL_FLAGS = frozenset(
    {
        "fake",
        "is_fake",
        "mock",
        "mocked",
        "is_mock",
        "placeholder",
        "is_placeholder",
        "stub",
        "stub_only",
        "test_double",
    }
)
_NON_REAL_COUNTS = frozenset({"fake_count", "mock_count", "placeholder_count", "stub_count"})
_CLASSIFICATION_KEYS = frozenset(
    {
        "backend",
        "execution",
        "execution_mode",
        "implementation",
        "kind",
        "mode",
        "provider",
        "runner",
        "source_type",
        "status",
    }
)
_NON_REAL_VALUES = frozenset({"fake", "mock", "mocked", "placeholder", "stub", "test_double"})

ToolResolver = Callable[[str], str | os.PathLike[str] | None]


class _SpecError(ValueError):
    pass


class _BoundaryError(ValueError):
    pass


@dataclass(frozen=True)
class _CommandSpec:
    role: str
    argv: tuple[str, ...]
    cwd: str
    cwd_path: Path
    timeout_seconds: float
    stdout_limit: int
    stderr_limit: int
    target_path: str | None


@dataclass(frozen=True)
class _OutputSpec:
    name: str
    kind: str
    original_path: str
    reconstructed_path: str
    json_path: Any


@dataclass(frozen=True)
class _ResolvedCommand:
    executable: Path
    source: str
    dependency: dict[str, Any]


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


class _NormalizedCapture:
    """Drain a byte stream while hashing normalized newlines and keeping a prefix."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.content = bytearray()
        self.raw_bytes = 0
        self.normalized_bytes = 0
        self.digest = hashlib.sha256()
        self.pending_cr = False
        self.error: str | None = None

    def consume(self, pipe: Any) -> None:
        try:
            while True:
                chunk = pipe.read(_IO_CHUNK_BYTES)
                if not chunk:
                    break
                if not isinstance(chunk, bytes):
                    chunk = bytes(chunk)
                self.raw_bytes += len(chunk)
                self._consume_chunk(chunk)
            if self.pending_cr:
                self._record_normalized(b"\n")
                self.pending_cr = False
        except (OSError, ValueError) as error:
            self.error = f"{type(error).__name__}: {error}"
        finally:
            try:
                pipe.close()
            except (OSError, ValueError):
                pass

    def _consume_chunk(self, chunk: bytes) -> None:
        if self.pending_cr:
            chunk = b"\r" + chunk
            self.pending_cr = False
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
            self.pending_cr = True
        normalized = chunk.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        self._record_normalized(normalized)

    def _record_normalized(self, content: bytes) -> None:
        self.normalized_bytes += len(content)
        self.digest.update(content)
        remaining = self.limit - len(self.content)
        if remaining > 0:
            self.content.extend(content[:remaining])

    def record(self) -> dict[str, Any]:
        content = bytes(self.content)
        digest = self.digest.hexdigest()
        return {
            "text": content.decode("utf-8", errors="replace"),
            "sha256": digest,
            "normalized_sha256": digest,
            "captured_bytes": len(content),
            "total_bytes": self.raw_bytes,
            "normalized_bytes": self.normalized_bytes,
            "limit_bytes": self.limit,
            "truncated": self.normalized_bytes > len(content),
            "normalization": "crlf_and_cr_to_lf",
        }


def validate_source_behavior(
    original_dir: str | os.PathLike[str],
    reconstructed_dir: str | os.PathLike[str],
    validation_spec: Mapping[str, Any],
    *,
    allowed_tools: Collection[str] | None = None,
    tool_resolver: ToolResolver | None = None,
    default_timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    default_stdout_limit: int = _DEFAULT_STREAM_LIMIT,
    default_stderr_limit: int = _DEFAULT_STREAM_LIMIT,
    max_output_file_bytes: int = _DEFAULT_MAX_OUTPUT_BYTES,
) -> dict[str, Any]:
    """Run and compare explicit original and reconstructed argv specifications.

    ``validation_spec`` contains ``original`` and ``reconstructed`` command
    mappings.  Each command requires an ``argv`` list and may declare ``cwd``,
    ``timeout_seconds``, stream limits, and a project-relative ``target``.
    Optional ``outputs`` entries compare either a file SHA-256 or a strict JSON
    value.  A shared ``path`` may be used for both roots, or separate
    ``original_path`` and ``reconstructed_path`` values may be supplied.
    """

    spec_sha256: str | None = None
    roots: dict[str, Path] = {}
    commands: dict[str, _CommandSpec] = {}
    outputs: tuple[_OutputSpec, ...] = ()
    dependencies: dict[str, dict[str, Any]] = {}
    target_identity: dict[str, Any] = {}
    command_payload: dict[str, Any] = {}

    try:
        spec_sha256 = _spec_sha256(validation_spec)
        roots = {
            "original": _target_root(original_dir, "original_dir"),
            "reconstructed": _target_root(reconstructed_dir, "reconstructed_dir"),
        }
        _require_disjoint_roots(roots["original"], roots["reconstructed"])
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
        output_byte_limit = _bounded_integer(
            max_output_file_bytes,
            name="max_output_file_bytes",
            minimum=1,
            maximum=_MAX_OUTPUT_BYTES,
        )
        commands = _parse_commands(roots, validation_spec, defaults)
        outputs = _parse_outputs(roots, validation_spec)
        non_real_reasons = _non_real_reasons(validation_spec)
        allowlist = _effective_allowlist(allowed_tools)
    except (OSError, TypeError, ValueError, _SpecError, _BoundaryError) as error:
        diagnostic = f"invalid behavior validation spec: {error}"
        return _validation_result(
            status="failed",
            behavior_equivalent=False,
            spec_sha256=spec_sha256,
            diagnostics=(diagnostic,),
            target_identity=target_identity,
            commands=command_payload,
            runs={},
            comparisons=(),
            dependencies=dependencies,
        )

    command_payload = {
        role: _planned_command_record(command)
        for role, command in commands.items()
    }
    declared_identity = {
        role: _declared_target_identity(validation_spec, role)
        for role in ("original", "reconstructed")
    }

    if non_real_reasons:
        return _validation_result(
            status="failed",
            behavior_equivalent=False,
            spec_sha256=spec_sha256,
            diagnostics=tuple(non_real_reasons),
            target_identity={
                role: {"declared": declared_identity[role], "verified": False}
                for role in ("original", "reconstructed")
            },
            commands=command_payload,
            runs={},
            comparisons=(),
            dependencies=dependencies,
        )

    resolver = tool_resolver or _default_tool_resolver
    resolved_commands: dict[str, _ResolvedCommand] = {}
    unavailable_diagnostics: list[str] = []
    for role in ("original", "reconstructed"):
        resolved, dependency, diagnostic = _resolve_command(
            roots[role], commands[role], allowlist, resolver
        )
        dependencies[role] = dependency
        if resolved is None:
            unavailable_diagnostics.append(
                diagnostic or f"{role} command dependency is unavailable"
            )
        else:
            resolved_commands[role] = resolved
            command_payload[role] = _resolved_command_record(commands[role], resolved)

    if unavailable_diagnostics:
        return _validation_result(
            status="unavailable",
            behavior_equivalent=False,
            spec_sha256=spec_sha256,
            diagnostics=unavailable_diagnostics,
            target_identity={
                role: {"declared": declared_identity[role], "verified": False}
                for role in ("original", "reconstructed")
            },
            commands=command_payload,
            runs={},
            comparisons=(),
            dependencies=dependencies,
        )

    identity_diagnostics: list[str] = []
    for role in ("original", "reconstructed"):
        try:
            identity = _build_target_identity(
                roots[role],
                commands[role],
                resolved_commands[role],
                declared_identity[role],
            )
            target_identity[role] = identity
            expected_sha256 = declared_identity[role].get("sha256")
            if expected_sha256 is not None:
                if not _is_sha256(expected_sha256):
                    raise _SpecError(f"{role} target identity SHA-256 is invalid")
                if identity.get("sha256") != expected_sha256.casefold():
                    identity_diagnostics.append(
                        f"{role} target identity SHA-256 does not match the declared target"
                    )
        except (OSError, RuntimeError, _SpecError, _BoundaryError) as error:
            target_identity[role] = {
                "declared": declared_identity[role],
                "verified": False,
                "error": str(error),
            }
            identity_diagnostics.append(f"{role} target identity failed: {error}")

    if identity_diagnostics:
        return _validation_result(
            status="failed",
            behavior_equivalent=False,
            spec_sha256=spec_sha256,
            diagnostics=identity_diagnostics,
            target_identity=target_identity,
            commands=command_payload,
            runs={},
            comparisons=(),
            dependencies=dependencies,
        )

    before_outputs: dict[str, dict[str, dict[str, Any]]] = {
        "original": {},
        "reconstructed": {},
    }
    try:
        for role in ("original", "reconstructed"):
            root = roots[role]
            for output in outputs:
                relative_path = _output_path(output, role)
                before_outputs[role][output.name] = _snapshot_output(root, relative_path)
    except (OSError, RuntimeError, _BoundaryError) as error:
        return _validation_result(
            status="failed",
            behavior_equivalent=False,
            spec_sha256=spec_sha256,
            diagnostics=(f"declared output could not be inspected before execution: {error}",),
            target_identity=target_identity,
            commands=command_payload,
            runs={},
            comparisons=(),
            dependencies=dependencies,
        )

    environment = _validation_environment()
    process_observations: dict[str, _ProcessObservation] = {}
    run_payload: dict[str, dict[str, Any]] = {}
    diagnostics: list[str] = []
    for role in ("original", "reconstructed"):
        observation = _run_process(
            commands[role], resolved_commands[role].executable, environment
        )
        process_observations[role] = observation
        output_records: list[dict[str, Any]] = []
        for output in outputs:
            relative_path = _output_path(output, role)
            try:
                record = _observe_output(
                    roots[role],
                    output,
                    role,
                    before_outputs[role][output.name],
                    output_byte_limit,
                )
            except (OSError, RuntimeError, ValueError, _BoundaryError) as error:
                record = {
                    "name": output.name,
                    "kind": output.kind,
                    "path": relative_path,
                    "available": False,
                    "produced": False,
                    "error": f"{type(error).__name__}: {error}",
                }
            output_records.append(record)
        run = _run_record(
            commands[role], resolved_commands[role], observation, output_records
        )
        run_payload[role] = run
        if not observation.started:
            diagnostics.append(f"{role} command could not be started: {observation.error}")
        if observation.timed_out:
            diagnostics.append(
                f"{role} command timed out after "
                f"{_format_seconds(commands[role].timeout_seconds)} seconds"
            )
        if observation.error:
            diagnostics.append(f"{role} output capture failed: {observation.error}")

    for role in ("original", "reconstructed"):
        identity = target_identity[role]
        try:
            after = _refresh_target_identity(roots[role], identity)
            identity["after"] = after
            identity["unchanged"] = _target_unchanged(identity, after)
            if identity["unchanged"] is not True:
                diagnostics.append(f"{role} target changed during behavior validation")
        except (OSError, RuntimeError, _BoundaryError) as error:
            identity["after"] = None
            identity["unchanged"] = False
            diagnostics.append(f"{role} target could not be re-identified: {error}")

    comparisons = _compare_observations(run_payload, outputs)
    for comparison in comparisons:
        if comparison.get("matched") is not True:
            diagnostics.append(f"behavior observation differs: {comparison['name']}")

    runs_completed = all(
        process_observations[role].started
        and not process_observations[role].timed_out
        and process_observations[role].error is None
        for role in ("original", "reconstructed")
    )
    targets_unchanged = all(
        target_identity[role].get("unchanged") is True
        for role in ("original", "reconstructed")
    )
    all_matched = bool(comparisons) and all(
        item.get("matched") is True for item in comparisons
    )
    behavior_equivalent = runs_completed and targets_unchanged and all_matched
    if behavior_equivalent:
        status = "passed"
    elif any(not item.started for item in process_observations.values()):
        status = "unavailable"
    else:
        status = "failed"

    return _validation_result(
        status=status,
        behavior_equivalent=behavior_equivalent,
        spec_sha256=spec_sha256,
        diagnostics=diagnostics,
        target_identity=target_identity,
        commands=command_payload,
        runs=run_payload,
        comparisons=comparisons,
        dependencies=dependencies,
    )


def _target_root(value: str | os.PathLike[str], name: str) -> Path:
    path = Path(value).expanduser()
    if _is_link_or_reparse(path):
        raise _BoundaryError(f"{name} must not be a symbolic link or reparse point")
    try:
        root = path.resolve(strict=True)
    except OSError as error:
        raise _BoundaryError(f"{name} does not exist") from error
    if not root.is_dir():
        raise _BoundaryError(f"{name} must identify a directory")
    return root


def _require_disjoint_roots(original: Path, reconstructed: Path) -> None:
    if _is_below(original, reconstructed) or _is_below(reconstructed, original):
        raise _BoundaryError("original and reconstructed roots must be disjoint")


def _is_below(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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
        raise _SpecError("validation_spec must contain finite JSON values") from error
    if len(serialized) > _MAX_SPEC_BYTES:
        raise _SpecError(f"validation_spec exceeds {_MAX_SPEC_BYTES} bytes")
    return hashlib.sha256(serialized).hexdigest()


def _parse_commands(
    roots: Mapping[str, Path],
    spec: Mapping[str, Any],
    defaults: tuple[float, int, int],
) -> dict[str, _CommandSpec]:
    container = spec.get("commands", spec)
    if not isinstance(container, Mapping):
        raise _SpecError("commands must be a mapping")
    commands: dict[str, _CommandSpec] = {}
    for role in ("original", "reconstructed"):
        if role not in container:
            raise _SpecError(f"{role} command is required")
        commands[role] = _parse_command(
            roots[role], role, container[role], defaults
        )
    return commands


def _parse_command(
    root: Path,
    role: str,
    raw: Any,
    defaults: tuple[float, int, int],
) -> _CommandSpec:
    if isinstance(raw, list):
        command: Mapping[str, Any] = {"argv": raw}
    elif isinstance(raw, Mapping):
        command = raw
    else:
        raise _SpecError(f"{role} command must be a mapping")

    argv_value = command.get("argv", command.get("command"))
    if isinstance(argv_value, Mapping):
        argv_value = argv_value.get("argv")
    if not isinstance(argv_value, list) or not argv_value:
        raise _SpecError(f"{role}.argv must be a non-empty list")
    if len(argv_value) > _MAX_ARGV_ITEMS:
        raise _SpecError(f"{role}.argv exceeds {_MAX_ARGV_ITEMS} items")
    argv: list[str] = []
    for index, value in enumerate(argv_value):
        if not isinstance(value, str) or not value:
            raise _SpecError(f"{role}.argv[{index}] must be a non-empty string")
        encoded = value.encode("utf-8")
        if len(encoded) > _MAX_ARGUMENT_BYTES:
            raise _SpecError(
                f"{role}.argv[{index}] exceeds {_MAX_ARGUMENT_BYTES} bytes"
            )
        if any(ord(character) < 32 for character in value):
            raise _SpecError(f"{role}.argv[{index}] contains a control character")
        argv.append(value)

    cwd, cwd_path = _constrained_directory(
        root, command.get("cwd", "."), location=role
    )
    timeout = _bounded_number(
        command.get("timeout_seconds", command.get("timeout", defaults[0])),
        name=f"{role}.timeout_seconds",
        minimum_exclusive=0.0,
        maximum=_MAX_TIMEOUT_SECONDS,
    )
    stdout_limit = _bounded_integer(
        command.get("stdout_limit", defaults[1]),
        name=f"{role}.stdout_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )
    stderr_limit = _bounded_integer(
        command.get("stderr_limit", defaults[2]),
        name=f"{role}.stderr_limit",
        minimum=1,
        maximum=_MAX_STREAM_LIMIT,
    )
    target_value = command.get("target", command.get("target_path"))
    target_path = None
    if target_value is not None:
        target_path = _constrained_file_name(root, target_value, location=f"{role}.target")
    _validate_argv_boundaries(root, cwd_path, argv[1:], location=role)
    return _CommandSpec(
        role=role,
        argv=tuple(argv),
        cwd=cwd,
        cwd_path=cwd_path,
        timeout_seconds=timeout,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
        target_path=target_path,
    )


def _parse_outputs(
    roots: Mapping[str, Path], spec: Mapping[str, Any]
) -> tuple[_OutputSpec, ...]:
    raw_outputs: Any = spec.get("outputs", [])
    observations = spec.get("observations")
    if isinstance(observations, Mapping) and "outputs" in observations:
        if raw_outputs not in (None, [], ()):
            raise _SpecError("outputs may be declared only once")
        raw_outputs = observations["outputs"]
    if raw_outputs is None:
        raw_outputs = []
    if isinstance(raw_outputs, Mapping):
        expanded: list[dict[str, Any]] = []
        for name, value in raw_outputs.items():
            if isinstance(value, str):
                expanded.append({"name": str(name), "path": value, "kind": "sha256"})
            elif isinstance(value, Mapping):
                expanded.append({"name": str(name), **dict(value)})
            else:
                raise _SpecError("mapped output declarations must be paths or mappings")
        raw_outputs = expanded
    if not isinstance(raw_outputs, list):
        raise _SpecError("outputs must be a list or mapping")
    if len(raw_outputs) > _MAX_OUTPUTS:
        raise _SpecError(f"outputs exceeds {_MAX_OUTPUTS} declarations")

    outputs: list[_OutputSpec] = []
    names: set[str] = set()
    for index, raw in enumerate(raw_outputs):
        if not isinstance(raw, Mapping):
            raise _SpecError(f"outputs[{index}] must be a mapping")
        name_value = raw.get("name", f"output_{index + 1}")
        if not isinstance(name_value, str) or not name_value.strip():
            raise _SpecError(f"outputs[{index}].name must be a non-empty string")
        name = name_value.strip()
        if len(name.encode("utf-8")) > 256 or any(ord(character) < 32 for character in name):
            raise _SpecError(f"outputs[{index}].name is invalid")
        if name in names:
            raise _SpecError(f"duplicate output name: {name}")
        names.add(name)

        kind_value = raw.get("kind", raw.get("compare", "sha256"))
        if not isinstance(kind_value, str):
            raise _SpecError(f"outputs[{index}].kind must be a string")
        kind = kind_value.strip().casefold().replace("-", "_")
        if kind in {"file", "file_sha256", "hash"}:
            kind = "sha256"
        if kind in {"json_value", "json_equals"}:
            kind = "json"
        if kind not in {"sha256", "json"}:
            raise _SpecError(f"outputs[{index}].kind must be sha256 or json")

        paths = raw.get("paths")
        path_value = raw.get("path")
        original_value = raw.get("original_path", path_value)
        reconstructed_value = raw.get("reconstructed_path", path_value)
        if isinstance(paths, Mapping):
            original_value = paths.get("original", original_value)
            reconstructed_value = paths.get("reconstructed", reconstructed_value)
        original_path = _constrained_file_name(
            roots["original"], original_value, location=f"outputs[{index}].original"
        )
        reconstructed_path = _constrained_file_name(
            roots["reconstructed"],
            reconstructed_value,
            location=f"outputs[{index}].reconstructed",
        )
        json_path = raw.get("json_path", raw.get("value_path", "$"))
        if kind == "json":
            _validate_json_path(json_path, index)
        outputs.append(
            _OutputSpec(
                name=name,
                kind=kind,
                original_path=original_path,
                reconstructed_path=reconstructed_path,
                json_path=json_path,
            )
        )
    return tuple(outputs)


def _validate_json_path(path: Any, index: int) -> None:
    if isinstance(path, str):
        if any(ord(character) < 32 for character in path):
            raise _SpecError(f"outputs[{index}].json_path contains a control character")
        return
    if isinstance(path, list) and all(
        isinstance(item, (str, int)) and not isinstance(item, bool) for item in path
    ):
        return
    raise _SpecError(f"outputs[{index}].json_path must be a string or list")


def _effective_allowlist(allowed_tools: Collection[str] | None) -> frozenset[str]:
    if allowed_tools is None:
        return DEFAULT_BEHAVIOR_TOOL_ALLOWLIST
    if isinstance(allowed_tools, (str, bytes)):
        raise _SpecError("allowed_tools must be a collection of tool names")
    normalized: set[str] = set()
    for value in allowed_tools:
        if not isinstance(value, str) or not value.strip():
            raise _SpecError("allowed_tools entries must be non-empty strings")
        key = _tool_key(value)
        if not key or key in _FORBIDDEN_SHELLS:
            raise _SpecError(f"shell tools cannot be allowlisted: {value}")
        normalized.add(key)
    return frozenset(normalized)


def _resolve_command(
    root: Path,
    command: _CommandSpec,
    allowlist: frozenset[str],
    resolver: ToolResolver,
) -> tuple[_ResolvedCommand | None, dict[str, Any], str | None]:
    requested = command.argv[0]
    tool_key = _tool_key(requested)
    base_record: dict[str, Any] = {
        "requested": requested,
        "tool": tool_key,
        "available": False,
        "allowlisted": tool_key in allowlist,
        "source": None,
        "resolved_path": None,
        "sha256": None,
        "size_bytes": None,
    }
    if tool_key in _FORBIDDEN_SHELLS or _tool_suffix(requested) in _SHELL_SUFFIXES:
        return None, base_record, f"{command.role} shell execution is forbidden: {requested}"

    local_candidate = _local_executable_candidate(root, command.cwd_path, requested)
    if local_candidate is not None:
        try:
            executable = _resolve_local_executable(root, local_candidate)
        except (OSError, _BoundaryError) as error:
            return None, base_record, f"{command.role} local executable is unavailable: {error}"
        source = "target_root"
    else:
        if tool_key not in allowlist:
            return (
                None,
                base_record,
                f"{command.role} tool is not in the behavior validation allowlist: {requested}",
            )
        try:
            candidate = resolver(requested)
        except (OSError, TypeError, ValueError) as error:
            return (
                None,
                base_record,
                f"{command.role} tool discovery failed: {type(error).__name__}",
            )
        if candidate is None:
            return None, base_record, f"{command.role} allowlisted tool was not found: {requested}"
        try:
            candidate_text = os.fspath(candidate)
        except TypeError:
            return None, base_record, f"{command.role} tool resolver returned an invalid path"
        if not candidate_text or any(ord(character) < 32 for character in candidate_text):
            return None, base_record, f"{command.role} tool resolver returned an invalid path"
        discovered = Path(candidate_text).expanduser()
        if not discovered.is_absolute():
            located = shutil.which(candidate_text)
            if located is None:
                return None, base_record, f"{command.role} resolved tool was not discoverable"
            discovered = Path(located)
        try:
            executable = discovered.resolve(strict=True)
        except OSError:
            return None, base_record, f"{command.role} resolved tool does not exist"
        source = "allowlisted_dependency"

    if not executable.is_file() or not os.access(executable, os.X_OK):
        return None, base_record, f"{command.role} resolved tool is not executable: {requested}"
    if _tool_key(executable.name) in _FORBIDDEN_SHELLS or _tool_suffix(str(executable)) in _SHELL_SUFFIXES:
        return None, base_record, f"{command.role} resolved tool would invoke a shell"
    if source == "allowlisted_dependency" and _tool_key(executable.name) != tool_key:
        return None, base_record, f"{command.role} resolved executable identity does not match {requested}"

    fingerprint = _fingerprint_file(executable, _MAX_TARGET_BYTES, required=False)
    dependency = {
        **base_record,
        "available": True,
        "source": source,
        "resolved_path": str(executable),
        "sha256": fingerprint.get("sha256"),
        "size_bytes": fingerprint.get("size_bytes"),
    }
    return _ResolvedCommand(executable, source, dependency), dependency, None


def _local_executable_candidate(root: Path, cwd: Path, requested: str) -> Path | None:
    requested_path = Path(requested).expanduser()
    windows_path = PureWindowsPath(requested)
    if requested_path.is_absolute() or windows_path.is_absolute():
        try:
            candidate = requested_path.resolve(strict=False)
            candidate.relative_to(root)
        except (OSError, ValueError):
            return None
        return candidate
    if _looks_path_like(requested):
        return cwd / Path(requested.replace("\\", os.sep))
    candidate = cwd / requested
    return candidate if candidate.is_file() else None


def _resolve_local_executable(root: Path, candidate: Path) -> Path:
    _assert_no_symlink_components(root, candidate)
    if _is_link_or_reparse(candidate):
        raise _BoundaryError("local executable must not be a link or reparse point")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError("local executable must resolve below its target root") from error
    return resolved


def _default_tool_resolver(value: str) -> str | None:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path) if path.is_file() else None
    if _tool_key(value) == "python" and sys.executable:
        executable = Path(sys.executable)
        if executable.is_file():
            return str(executable)
    return shutil.which(value)


def _tool_key(value: str) -> str:
    text = value.strip().replace("\\", "/")
    base = PureWindowsPath(text).name.casefold()
    for suffix in (".exe", ".com", ".bat", ".cmd", ".ps1", ".sh"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if _PYTHON_TOOL.fullmatch(base) or base in {"py", "pythonw"}:
        return "python"
    return base


def _tool_suffix(value: str) -> str:
    return PureWindowsPath(value.strip()).suffix.casefold()


def _constrained_directory(root: Path, value: Any, *, location: str) -> tuple[str, Path]:
    if value in (None, "", "."):
        return ".", root
    normalized = _normalize_relative_path(value)
    if normalized is None:
        raise _BoundaryError(f"{location}.cwd must stay below its target root")
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    _assert_no_symlink_components(root, candidate)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError(f"{location}.cwd must resolve below its target root") from error
    if not resolved.is_dir():
        raise _BoundaryError(f"{location}.cwd is not a directory")
    return normalized, resolved


def _constrained_file_name(root: Path, value: Any, *, location: str) -> str:
    normalized = _normalize_relative_path(value)
    if normalized is None:
        raise _BoundaryError(f"{location} path must stay below its target root")
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    _assert_no_symlink_components(root, candidate)
    try:
        candidate.resolve(strict=False).relative_to(root)
    except (OSError, ValueError) as error:
        raise _BoundaryError(f"{location} path escapes its target root") from error
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
        raise _BoundaryError("path escapes its target root") from error
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if _is_link_or_reparse(cursor):
            raise _BoundaryError(
                f"path traverses a symbolic link or reparse point: {relative.as_posix()}"
            )


def _is_link_or_reparse(path: Path) -> bool:
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
    skip_inline_value = False
    for argument in arguments:
        if skip_inline_value:
            skip_inline_value = False
            continue
        if argument in {"-c", "-e"}:
            skip_inline_value = True
            continue
        if argument == "-m":
            skip_inline_value = True
            continue
        for candidate in _argument_path_candidates(argument):
            text = candidate.strip().strip("\"'")
            if not text:
                continue
            normalized = text.replace("\\", "/")
            if ".." in PurePosixPath(normalized).parts:
                raise _BoundaryError(f"{location}.argv contains parent-directory traversal")
            if normalized.startswith("~"):
                raise _BoundaryError(f"{location}.argv contains an unbounded home path")
            windows = PureWindowsPath(text)
            host_path = Path(text)
            if windows.is_absolute() or host_path.is_absolute():
                try:
                    host_path.expanduser().resolve(strict=False).relative_to(root)
                except (OSError, ValueError) as error:
                    raise _BoundaryError(
                        f"{location}.argv contains an absolute path outside its target root"
                    ) from error
            elif _looks_path_like(text):
                joined = cwd / Path(text.replace("\\", os.sep))
                try:
                    joined.resolve(strict=False).relative_to(root)
                except (OSError, ValueError) as error:
                    raise _BoundaryError(f"{location}.argv path escapes its target root") from error


def _argument_path_candidates(argument: str) -> tuple[str, ...]:
    if argument.startswith("/") and not argument.startswith("//"):
        remainder = argument[1:]
        if "/" not in remainder and "\\" not in remainder and ":" not in remainder:
            return ()
    if argument.startswith("--") and "=" not in argument:
        return ()
    if argument == "--":
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
    return "/" in value or "\\" in value or value.startswith((".", "@"))


def _declared_target_identity(spec: Mapping[str, Any], role: str) -> dict[str, Any]:
    raw = spec.get("target_identity", spec.get("target"))
    if raw is None:
        return {}
    if isinstance(raw, str):
        return {"id": raw}
    if not isinstance(raw, Mapping):
        raise _SpecError("target_identity must be a string or mapping")
    common = {
        str(key): value
        for key, value in raw.items()
        if key not in {"original", "reconstructed", "original_path", "reconstructed_path"}
    }
    side = raw.get(role)
    if side is not None:
        if isinstance(side, str):
            common["path"] = side
        elif isinstance(side, Mapping):
            common.update({str(key): value for key, value in side.items()})
        else:
            raise _SpecError(f"target_identity.{role} must be a string or mapping")
    side_path = raw.get(f"{role}_path")
    if side_path is not None:
        common["path"] = side_path
    return common


def _non_real_reasons(spec: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []

    def inspect(value: Any, location: str) -> None:
        if isinstance(value, Mapping):
            for key_value, item in value.items():
                key = str(key_value).strip().casefold()
                item_location = f"{location}.{key}" if location else key
                if key in _NON_REAL_FLAGS and item is True:
                    reasons.append(
                        f"non-real execution evidence is not eligible: {item_location}=true"
                    )
                elif key in _NON_REAL_COUNTS and isinstance(item, int) and item > 0:
                    reasons.append(
                        f"non-real execution evidence is not eligible: {item_location}={item}"
                    )
                elif key == "real_execution" and item is False:
                    reasons.append(
                        f"non-real execution evidence is not eligible: {item_location}=false"
                    )
                elif key in _CLASSIFICATION_KEYS and isinstance(item, str):
                    if item.strip().casefold() in _NON_REAL_VALUES:
                        reasons.append(
                            f"non-real execution evidence is not eligible: {item_location}={item}"
                        )
                inspect(item, item_location)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, f"{location}[{index}]")

    inspect(spec, "validation_spec")
    return list(dict.fromkeys(reasons))


def _build_target_identity(
    root: Path,
    command: _CommandSpec,
    resolved: _ResolvedCommand,
    declared: Mapping[str, Any],
) -> dict[str, Any]:
    relative_path = command.target_path
    declared_path = declared.get("path")
    if relative_path is None and declared_path is not None:
        relative_path = _constrained_file_name(
            root, declared_path, location=f"target_identity.{command.role}"
        )
    if relative_path is None:
        relative_path = _infer_target_path(root, command, resolved)

    command_sha256 = _command_sha256(command, resolved)
    root_metadata = root.stat()
    identity: dict[str, Any] = {
        "role": command.role,
        "declared": dict(declared),
        "root": str(root),
        "root_file_id": getattr(root_metadata, "st_ino", None),
        "command_sha256": command_sha256,
        "verified": True,
    }
    if relative_path is None:
        identity.update(
            {
                "kind": "command",
                "path": None,
                "sha256": command_sha256,
                "size_bytes": None,
            }
        )
        return identity

    target = _project_file_path(root, relative_path)
    fingerprint = _fingerprint_file(target, _MAX_TARGET_BYTES, required=True)
    identity.update(
        {
            "kind": "file",
            "path": relative_path,
            "sha256": fingerprint["sha256"],
            "size_bytes": fingerprint["size_bytes"],
            "mtime_ns": fingerprint["mtime_ns"],
            "file_id": fingerprint["file_id"],
        }
    )
    return identity


def _infer_target_path(
    root: Path, command: _CommandSpec, resolved: _ResolvedCommand
) -> str | None:
    if resolved.source == "target_root":
        return resolved.executable.relative_to(root).as_posix()
    skip_inline_value = False
    for argument in command.argv[1:]:
        if skip_inline_value:
            skip_inline_value = False
            continue
        if argument in {"-c", "-e", "-m"}:
            skip_inline_value = True
            continue
        for value in _argument_path_candidates(argument):
            text = value.strip().strip("\"'")
            if not text or text.startswith("-"):
                continue
            candidate = Path(text).expanduser()
            if not candidate.is_absolute():
                candidate = command.cwd_path / Path(text.replace("\\", os.sep))
            try:
                resolved_path = candidate.resolve(strict=True)
                relative = resolved_path.relative_to(root).as_posix()
            except (OSError, ValueError):
                continue
            if resolved_path.is_file() and not _is_link_or_reparse(candidate):
                return relative
    return None


def _command_sha256(command: _CommandSpec, resolved: _ResolvedCommand) -> str:
    payload = {
        "argv": list(command.argv),
        "cwd": command.cwd,
        "executable_sha256": resolved.dependency.get("sha256"),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _refresh_target_identity(root: Path, identity: Mapping[str, Any]) -> dict[str, Any]:
    if identity.get("kind") != "file":
        return {
            "kind": identity.get("kind"),
            "path": identity.get("path"),
            "sha256": identity.get("sha256"),
            "size_bytes": identity.get("size_bytes"),
        }
    path = identity.get("path")
    if not isinstance(path, str):
        raise _BoundaryError("target identity path is missing")
    target = _project_file_path(root, path)
    fingerprint = _fingerprint_file(target, _MAX_TARGET_BYTES, required=True)
    return {
        "kind": "file",
        "path": path,
        "sha256": fingerprint["sha256"],
        "size_bytes": fingerprint["size_bytes"],
        "mtime_ns": fingerprint["mtime_ns"],
        "file_id": fingerprint["file_id"],
    }


def _target_unchanged(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
    return (
        before.get("kind") == after.get("kind")
        and before.get("path") == after.get("path")
        and before.get("sha256") == after.get("sha256")
        and before.get("size_bytes") == after.get("size_bytes")
    )


def _snapshot_output(root: Path, relative_path: str) -> dict[str, Any]:
    candidate = root.joinpath(*PurePosixPath(relative_path).parts)
    _assert_no_symlink_components(root, candidate)
    if not candidate.exists():
        return {"exists": False}
    if _is_link_or_reparse(candidate):
        raise _BoundaryError(f"declared output is a link or reparse point: {relative_path}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise _BoundaryError(f"declared output escapes its target root: {relative_path}") from error
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise _BoundaryError(f"declared output is not a regular file: {relative_path}")
    return {
        "exists": True,
        "size_bytes": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "file_id": getattr(metadata, "st_ino", None),
    }


def _observe_output(
    root: Path,
    output: _OutputSpec,
    role: str,
    before: Mapping[str, Any],
    max_bytes: int,
) -> dict[str, Any]:
    relative_path = _output_path(output, role)
    path = _project_file_path(root, relative_path)
    fingerprint = _fingerprint_file(path, max_bytes, required=True)
    after_identity = {
        "exists": True,
        "size_bytes": fingerprint["size_bytes"],
        "mtime_ns": fingerprint["mtime_ns"],
        "file_id": fingerprint["file_id"],
    }
    produced = before.get("exists") is not True or any(
        before.get(key) != after_identity.get(key)
        for key in ("size_bytes", "mtime_ns", "file_id")
    )
    record: dict[str, Any] = {
        "name": output.name,
        "kind": output.kind,
        "path": relative_path,
        "available": True,
        "produced": produced,
        "before": dict(before),
        "sha256": fingerprint["sha256"],
        "size_bytes": fingerprint["size_bytes"],
    }
    if output.kind == "json":
        if fingerprint["size_bytes"] > _MAX_JSON_BYTES:
            raise RuntimeError(f"JSON output exceeds {_MAX_JSON_BYTES} bytes")
        try:
            document = json.loads(
                path.read_text(encoding="utf-8-sig"),
                parse_constant=_reject_json_constant,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"JSON output could not be parsed: {error}") from error
        found, value = _json_value(document, output.json_path)
        record.update(
            {
                "json_path": output.json_path,
                "found": found,
                "value": value if found else None,
                "value_sha256": _json_value_sha256(value) if found else None,
            }
        )
    return record


def _output_path(output: _OutputSpec, role: str) -> str:
    return output.original_path if role == "original" else output.reconstructed_path


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
        raise _BoundaryError(f"project file escapes its target root: {normalized}") from error
    if not resolved.is_file():
        raise _BoundaryError(f"project path is not a regular file: {normalized}")
    return resolved


def _fingerprint_file(path: Path, max_bytes: int, *, required: bool) -> dict[str, Any]:
    try:
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise _BoundaryError(f"path is not a regular file: {path.name}")
        if before.st_size > max_bytes:
            if required:
                raise RuntimeError(f"file exceeds the hash limit of {max_bytes} bytes")
            return {
                "sha256": None,
                "size_bytes": before.st_size,
                "mtime_ns": before.st_mtime_ns,
                "file_id": getattr(before, "st_ino", None),
            }
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_IO_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError(f"file exceeds the hash limit of {max_bytes} bytes")
                digest.update(chunk)
        after = path.stat()
        before_identity = (
            before.st_size,
            before.st_mtime_ns,
            getattr(before, "st_ino", None),
        )
        after_identity = (
            after.st_size,
            after.st_mtime_ns,
            getattr(after, "st_ino", None),
        )
        if before_identity != after_identity or total != after.st_size:
            raise RuntimeError(f"file changed while it was hashed: {path.name}")
        return {
            "sha256": digest.hexdigest(),
            "size_bytes": after.st_size,
            "mtime_ns": after.st_mtime_ns,
            "file_id": getattr(after, "st_ino", None),
        }
    except (OSError, RuntimeError, _BoundaryError):
        if required:
            raise
        return {"sha256": None, "size_bytes": None, "mtime_ns": None, "file_id": None}


def _run_process(
    command: _CommandSpec,
    executable: Path,
    environment: Mapping[str, str],
) -> _ProcessObservation:
    stdout_capture = _NormalizedCapture(command.stdout_limit)
    stderr_capture = _NormalizedCapture(command.stderr_limit)
    argv = [str(executable), *command.argv[1:]]
    options: dict[str, Any] = {
        "cwd": str(command.cwd_path),
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
        process = subprocess.Popen(argv, **options)
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
        name=f"behavior-validation-{command.role}-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=stderr_capture.consume,
        args=(process.stderr,),
        name=f"behavior-validation-{command.role}-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=command.timeout_seconds)
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
        error
        for error in (stdout_capture.error, stderr_capture.error)
        if error is not None
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
                    timeout=1,
                    check=False,
                )
            if process.poll() is None:
                process.kill()
    except (OSError, ProcessLookupError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def _run_record(
    command: _CommandSpec,
    resolved: _ResolvedCommand,
    observation: _ProcessObservation,
    outputs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not observation.started:
        status = "unavailable"
    elif observation.timed_out or observation.error is not None:
        status = "failed"
    else:
        status = "completed"
    return {
        "role": command.role,
        "status": status,
        "argv": list(command.argv),
        "resolved_argv": [str(resolved.executable), *command.argv[1:]],
        "cwd": command.cwd,
        "cwd_path": str(command.cwd_path),
        "shell": False,
        "timeout_seconds": command.timeout_seconds,
        "timed_out": observation.timed_out,
        "duration_ms": observation.duration_ms,
        "exit_code": observation.exit_code,
        "termination_exit_code": observation.termination_exit_code,
        "stdout": observation.stdout,
        "stderr": observation.stderr,
        "stdout_text": observation.stdout["text"],
        "stderr_text": observation.stderr["text"],
        "outputs": [dict(item) for item in outputs],
        "error": observation.error,
    }


def _compare_observations(
    runs: Mapping[str, Mapping[str, Any]], outputs: Sequence[_OutputSpec]
) -> list[dict[str, Any]]:
    original = runs["original"]
    reconstructed = runs["reconstructed"]
    process_valid = (
        original.get("status") == "completed"
        and reconstructed.get("status") == "completed"
    )
    comparisons: list[dict[str, Any]] = [
        {
            "name": "exit_code",
            "kind": "exit_code",
            "original": original.get("exit_code"),
            "reconstructed": reconstructed.get("exit_code"),
            "matched": process_valid
            and original.get("exit_code") == reconstructed.get("exit_code"),
        }
    ]
    for stream_name in ("stdout", "stderr"):
        original_stream = original.get(stream_name, {})
        reconstructed_stream = reconstructed.get(stream_name, {})
        original_hash = original_stream.get("normalized_sha256")
        reconstructed_hash = reconstructed_stream.get("normalized_sha256")
        comparisons.append(
            {
                "name": stream_name,
                "kind": "normalized_stream_sha256",
                "normalization": "crlf_and_cr_to_lf",
                "original": original_hash,
                "reconstructed": reconstructed_hash,
                "original_truncated": original_stream.get("truncated"),
                "reconstructed_truncated": reconstructed_stream.get("truncated"),
                "matched": process_valid
                and isinstance(original_hash, str)
                and original_hash == reconstructed_hash,
            }
        )

    original_outputs = {
        item.get("name"): item
        for item in original.get("outputs", [])
        if isinstance(item, Mapping)
    }
    reconstructed_outputs = {
        item.get("name"): item
        for item in reconstructed.get("outputs", [])
        if isinstance(item, Mapping)
    }
    for output in outputs:
        left = original_outputs.get(output.name, {})
        right = reconstructed_outputs.get(output.name, {})
        available = (
            left.get("available") is True
            and right.get("available") is True
            and left.get("produced") is True
            and right.get("produced") is True
        )
        if output.kind == "sha256":
            left_value = left.get("sha256")
            right_value = right.get("sha256")
            matched = available and isinstance(left_value, str) and left_value == right_value
            comparison = {
                "name": output.name,
                "kind": "output_file_sha256",
                "original": dict(left),
                "reconstructed": dict(right),
                "matched": matched,
            }
        else:
            found = left.get("found") is True and right.get("found") is True
            matched = available and found and _json_equal(left.get("value"), right.get("value"))
            comparison = {
                "name": output.name,
                "kind": "output_json_value",
                "json_path": output.json_path,
                "original": dict(left),
                "reconstructed": dict(right),
                "matched": matched,
            }
        comparisons.append(comparison)
    return comparisons


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


def _json_equal(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return left is right
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) or isinstance(right, (int, float)):
        return type(left) is type(right) and left == right
    if isinstance(left, str) or isinstance(right, str):
        return isinstance(left, str) and isinstance(right, str) and left == right
    if isinstance(left, list) or isinstance(right, list):
        return (
            isinstance(left, list)
            and isinstance(right, list)
            and len(left) == len(right)
            and all(_json_equal(a, b) for a, b in zip(left, right))
        )
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        return (
            isinstance(left, Mapping)
            and isinstance(right, Mapping)
            and set(left) == set(right)
            and all(_json_equal(left[key], right[key]) for key in left)
        )
    return False


def _json_value_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _planned_command_record(command: _CommandSpec) -> dict[str, Any]:
    return {
        "argv": list(command.argv),
        "resolved_argv": None,
        "cwd": command.cwd,
        "cwd_path": str(command.cwd_path),
        "shell": False,
        "timeout_seconds": command.timeout_seconds,
        "stdout_limit": command.stdout_limit,
        "stderr_limit": command.stderr_limit,
    }


def _resolved_command_record(
    command: _CommandSpec, resolved: _ResolvedCommand
) -> dict[str, Any]:
    return {
        **_planned_command_record(command),
        "resolved_argv": [str(resolved.executable), *command.argv[1:]],
        "executable": dict(resolved.dependency),
    }


def _validation_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in ("NODE_OPTIONS", "PYTHONHOME", "PYTHONPATH", "RUBYOPT"):
        environment.pop(key, None)
    environment.update(
        {
            "CI": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def _validation_result(
    *,
    status: str,
    behavior_equivalent: bool,
    spec_sha256: str | None,
    diagnostics: Sequence[str],
    target_identity: Mapping[str, Any],
    commands: Mapping[str, Any],
    runs: Mapping[str, Any],
    comparisons: Sequence[Mapping[str, Any]],
    dependencies: Mapping[str, Any],
) -> dict[str, Any]:
    comparison_items = [dict(item) for item in comparisons]
    run_items = {str(key): dict(value) for key, value in runs.items()}
    target_items = {str(key): dict(value) for key, value in target_identity.items()}
    command_items = {str(key): dict(value) for key, value in commands.items()}
    dependency_items = {str(key): dict(value) for key, value in dependencies.items()}
    diagnostic_items = [str(item) for item in diagnostics if str(item)]
    summary = {
        "planned_command_count": len(command_items),
        "executed_command_count": sum(
            1 for item in run_items.values() if item.get("status") != "unavailable"
        ),
        "completed_command_count": sum(
            1 for item in run_items.values() if item.get("status") == "completed"
        ),
        "comparison_count": len(comparison_items),
        "matched_comparison_count": sum(
            1 for item in comparison_items if item.get("matched") is True
        ),
        "mismatched_comparison_count": sum(
            1 for item in comparison_items if item.get("matched") is not True
        ),
    }
    provenance = {
        "validator": {
            "name": "reverse_analyzer.source.behavior_validation",
            "version": _VALIDATOR_VERSION,
            "local_execution": True,
            "real_subprocess": True,
            "runner_injected": False,
            "shell": False,
        },
        "validation_spec": {
            "sha256": spec_sha256,
            "original_and_reconstructed_required": True,
        },
        "target_identity": target_items,
        "commands": command_items,
        "dependencies": dependency_items,
    }
    payload = {
        "schema_version": BEHAVIOR_VALIDATION_SCHEMA_VERSION,
        "status": status,
        "behavior_equivalent": behavior_equivalent is True,
        "diagnostics": diagnostic_items,
        "summary": summary,
        "target_identity": target_items,
        "commands": command_items,
        "runs": run_items,
        "comparisons": comparison_items,
        "provenance": provenance,
    }
    evidence_sha256 = hashlib.sha256(_canonical_json(payload)).hexdigest()
    artifact_payload = dict(payload)
    artifact = {
        "name": DEFAULT_BEHAVIOR_VALIDATION_PATH,
        "kind": "source_behavior_validation",
        "role": "behavioral_equivalence_evidence",
        "media_type": "application/json",
        "status": status,
        "behavior_equivalent": behavior_equivalent is True,
        "evidence_sha256": evidence_sha256,
        "payload": artifact_payload,
    }
    return {
        **payload,
        "artifact_payload": artifact_payload,
        "artifact": artifact,
    }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def _bounded_number(
    value: Any,
    *,
    name: str,
    minimum_exclusive: float,
    maximum: float,
) -> float:
    if isinstance(value, bool):
        raise _SpecError(f"{name} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise _SpecError(f"{name} must be a finite number") from error
    if not minimum_exclusive < number <= maximum or number != number:
        raise _SpecError(
            f"{name} must be greater than {minimum_exclusive:g} and at most {maximum:g}"
        )
    return number


def _bounded_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise _SpecError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise _SpecError(f"{name} must be between {minimum} and {maximum}")
    return value


def _format_seconds(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:g}"


# Compatibility aliases make the standalone module easy to consume directly.
validate_behavior_equivalence = validate_source_behavior
validate_source_behavior_equivalence = validate_source_behavior
run_behavior_validation = validate_source_behavior

__all__ = [
    "BEHAVIOR_VALIDATION_SCHEMA_VERSION",
    "DEFAULT_BEHAVIOR_TOOL_ALLOWLIST",
    "DEFAULT_BEHAVIOR_VALIDATION_PATH",
    "run_behavior_validation",
    "validate_behavior_equivalence",
    "validate_source_behavior",
    "validate_source_behavior_equivalence",
]
