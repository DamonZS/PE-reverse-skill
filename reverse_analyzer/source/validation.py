"""Bounded, deterministic validation for generated source skeletons.

Validation checks whether a generated project parses or builds with a locally
available toolchain.  It never executes the generated program and never claims
that a successful skeleton is behaviorally equivalent to the input binary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence


VALIDATION_SCHEMA_VERSION = 1
DEFAULT_VALIDATION_PATH = "source/validation.json"

_VALIDATOR_VERSION = "1.0"
_DEFAULT_TIMEOUT_SECONDS = 20.0
_MAX_TIMEOUT_SECONDS = 120.0
_DEFAULT_OUTPUT_LIMIT = 16 * 1024
_MAX_OUTPUT_LIMIT = 1024 * 1024
_MAX_METADATA_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_FILES = 512
_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".gradle",
        ".idea",
        ".vs",
        "__pycache__",
        "bin",
        "build",
        "dist",
        "node_modules",
        "obj",
    }
)
_STACK_ALIASES = {
    "c": "c",
    "cmake-c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "cmake-cpp": "cpp",
    "csharp": "csharp",
    "c#": "csharp",
    "dotnet": "csharp",
    "dotnet-console": "csharp",
    "electron": "electron",
    "electron-js": "electron",
    "javascript": "electron",
    "android-java": "android-java",
    "java": "android-java",
    "android-kotlin": "android-kotlin",
    "kotlin": "android-kotlin",
    "unity": "unity-csharp",
    "unity-csharp": "unity-csharp",
    "python": "pyinstaller-python",
    "pyinstaller": "pyinstaller-python",
    "pyinstaller-python": "pyinstaller-python",
}
_SOURCE_SUFFIXES = {
    "c": frozenset({".c", ".h"}),
    "cpp": frozenset({".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}),
    "csharp": frozenset({".cs"}),
    "electron": frozenset({".cjs", ".js", ".mjs"}),
    "android-java": frozenset({".java"}),
    "android-kotlin": frozenset({".kt", ".kts"}),
    "unity-csharp": frozenset({".cs"}),
    "pyinstaller-python": frozenset({".py"}),
}
_PYTHON_CHECK_SCRIPT = (
    "import pathlib,sys\n"
    "for source in (item for item in sys.argv[1:] if item != '--'):\n"
    "    compile(pathlib.Path(source).read_bytes(), source, 'exec', dont_inherit=True)\n"
)
_JAVASCRIPT_CHECK_SCRIPT = (
    "const fs=require('fs'),vm=require('vm');"
    "for(const source of process.argv.slice(1)){"
    "new vm.Script(fs.readFileSync(source,'utf8'),{filename:source});}"
)

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ToolResolver = Callable[[str], str | None]


@dataclass(frozen=True)
class _SourceFile:
    path: Path
    relative_path: str


@dataclass(frozen=True)
class _ValidationPlan:
    level: str
    toolchain: str | None
    actual_command: tuple[str, ...]
    report_command: tuple[str, ...]
    validated_files: tuple[str, ...]
    diagnostic: str | None = None


def validate_source_project(
    project_dir: str | os.PathLike[str],
    *,
    project_metadata: Mapping[str, Any] | None = None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    runner: CommandRunner | None = None,
    tool_resolver: ToolResolver | None = None,
) -> dict[str, Any]:
    """Validate one generated project without restoring or installing dependencies.

    The returned mapping has a stable, JSON-serializable schema.  Tool lookup
    and process execution are injectable so callers can reproduce validation
    decisions in fixtures without depending on the host machine.
    """

    root = _project_root(project_dir)
    timeout_seconds = _bounded_timeout(timeout)
    diagnostic_limit = _bounded_output_limit(output_limit)
    metadata, source_metadata, metadata_origin, diagnostics = _load_metadata(
        root, project_metadata
    )
    stack = _select_stack(root, metadata, source_metadata)
    unsafe_metadata = _metadata_path_diagnostics(metadata)
    diagnostics.extend(unsafe_metadata)
    source_files, discovery_diagnostics, discovery_incomplete = _discover_sources(root, stack)
    diagnostics.extend(discovery_diagnostics)
    placeholder_count = _placeholder_count(root, metadata, source_metadata, source_files)

    if stack is None:
        return _validation_result(
            status="unavailable",
            level="syntax",
            toolchain=None,
            command=(),
            exit_code=None,
            diagnostics=[*diagnostics, "project stack could not be determined"],
            validated_files=(),
            placeholder_count=placeholder_count,
            provenance=_build_provenance(None, metadata_origin, ()),
        )
    if not source_files:
        return _validation_result(
            status="failed",
            level=_default_level(stack),
            toolchain=None,
            command=(),
            exit_code=None,
            diagnostics=[*diagnostics, f"no {stack} source files were found"],
            validated_files=(),
            placeholder_count=placeholder_count,
            provenance=_build_provenance(stack, metadata_origin, ()),
        )

    resolver = tool_resolver or _default_tool_resolver
    with tempfile.TemporaryDirectory(prefix="reverse-analyzer-validation-") as temporary:
        temporary_dir = Path(temporary)
        plan = _build_plan(root, stack, source_files, resolver, temporary_dir)
        if not plan.actual_command:
            plan_diagnostics = [*diagnostics]
            if plan.diagnostic:
                plan_diagnostics.append(plan.diagnostic)
            return _validation_result(
                status="unavailable",
                level=plan.level,
                toolchain=plan.toolchain,
                command=plan.report_command,
                exit_code=None,
                diagnostics=plan_diagnostics,
                validated_files=(),
                placeholder_count=placeholder_count,
                provenance=_build_provenance(stack, metadata_origin, ()),
            )

        input_records = _input_records(root, plan.validated_files)
        provenance = _build_provenance(stack, metadata_origin, input_records)
        command_runner = runner or subprocess.run
        environment = _validation_environment(temporary_dir)
        exit_code: int | None = None
        status = "failed"
        try:
            completed = command_runner(
                list(plan.actual_command),
                cwd=str(root),
                env=environment,
                timeout=timeout_seconds,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                shell=False,
            )
            raw_exit_code = getattr(completed, "returncode", None)
            if isinstance(raw_exit_code, int) and not isinstance(raw_exit_code, bool):
                exit_code = raw_exit_code
            output = _process_output(
                getattr(completed, "stdout", ""),
                getattr(completed, "stderr", ""),
                root,
                diagnostic_limit,
                temporary_dir,
            )
            if output:
                diagnostics.append(output)
            if exit_code == 0 and not unsafe_metadata and not discovery_incomplete:
                status = "passed"
            elif exit_code is None:
                diagnostics.append("validation runner returned no integer exit code")
        except subprocess.TimeoutExpired as error:
            output = _process_output(
                error.stdout,
                error.stderr,
                root,
                diagnostic_limit,
                temporary_dir,
            )
            if output:
                diagnostics.append(output)
            diagnostics.append(f"validation timed out after {_format_seconds(timeout_seconds)} seconds")
        except (OSError, subprocess.SubprocessError) as error:
            diagnostics.append(
                _normalize_diagnostic(str(error), root, diagnostic_limit, temporary_dir)
            )

        if _input_records(root, plan.validated_files) != input_records:
            status = "failed"
            diagnostics.append("validation inputs changed while the toolchain was running")

        return _validation_result(
            status=status,
            level=plan.level,
            toolchain=plan.toolchain,
            command=plan.report_command,
            exit_code=exit_code,
            diagnostics=diagnostics,
            validated_files=plan.validated_files,
            placeholder_count=placeholder_count,
            provenance=provenance,
        )


def write_source_validation(
    project_dir: str | os.PathLike[str],
    validation: Mapping[str, Any] | None = None,
    *,
    relative_path: str = DEFAULT_VALIDATION_PATH,
    **validation_options: Any,
) -> Path:
    """Write a canonical validation report below ``project_dir`` and return its path."""

    root = _project_root(project_dir)
    if validation is not None and validation_options:
        raise TypeError("validation options are only accepted when validation is omitted")
    result = (
        validate_source_project(root, **validation_options)
        if validation is None
        else _canonical_validation(root, validation)
    )
    target = _safe_output_path(root, relative_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_symlink_path(root, target)
    if target.exists() and not target.is_file():
        raise IsADirectoryError(str(target))

    serialized = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=target.parent,
            prefix=".validation-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(serialized)
        os.replace(temporary_name, target)
        temporary_name = None
    finally:
        if temporary_name:
            temporary_path = Path(temporary_name)
            if temporary_path.is_file() and not temporary_path.is_symlink():
                temporary_path.unlink()
    return target


def validate_and_write_source_project(
    project_dir: str | os.PathLike[str],
    *,
    relative_path: str = DEFAULT_VALIDATION_PATH,
    **validation_options: Any,
) -> dict[str, Any]:
    """Validate a generated project, persist the result, and return the result."""

    result = validate_source_project(project_dir, **validation_options)
    write_source_validation(project_dir, result, relative_path=relative_path)
    return result


def _project_root(value: str | os.PathLike[str]) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink():
        raise ValueError("source project path must not be a symbolic link")
    if not path.is_dir():
        raise NotADirectoryError(str(path))
    return path.resolve(strict=True)


def _bounded_timeout(value: float) -> float:
    if isinstance(value, bool):
        raise ValueError("timeout must be a positive number")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("timeout must be a positive number") from error
    if not 0 < number <= _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 0 and {_MAX_TIMEOUT_SECONDS:g} seconds")
    return number


def _bounded_output_limit(value: int) -> int:
    if isinstance(value, bool):
        raise ValueError("output_limit must be a positive integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("output_limit must be a positive integer") from error
    if not 0 < number <= _MAX_OUTPUT_LIMIT:
        raise ValueError(f"output_limit must be between 1 and {_MAX_OUTPUT_LIMIT}")
    return number


def _load_metadata(
    root: Path, provided: Mapping[str, Any] | None
) -> tuple[dict[str, Any], dict[str, Any], str | None, list[str]]:
    diagnostics: list[str] = []
    project_path = root / "analysis" / "project.json"
    source_path = root / "analysis" / "source_reconstruction.json"
    project = _read_json_mapping(root, project_path, diagnostics)
    source = _read_json_mapping(root, source_path, diagnostics)
    origin: str | None = "analysis/project.json" if project else None

    if provided is not None:
        if not isinstance(provided, Mapping):
            raise TypeError("project_metadata must be a mapping")
        nested_project = provided.get("project")
        if isinstance(nested_project, Mapping):
            project.update(dict(nested_project))
        else:
            project.update(dict(provided))
        nested_analysis = provided.get("analysis")
        if isinstance(nested_analysis, Mapping):
            source.update(dict(nested_analysis))
        origin = "provided"
    return project, source, origin, diagnostics


def _read_json_mapping(root: Path, path: Path, diagnostics: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {}
    relative = path.relative_to(root).as_posix()
    if path.is_symlink() or not path.is_file():
        diagnostics.append(f"metadata path is not a regular file: {relative}")
        return {}
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        if resolved.stat().st_size > _MAX_METADATA_BYTES:
            diagnostics.append(f"metadata file exceeds {_MAX_METADATA_BYTES} bytes: {relative}")
            return {}
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        diagnostics.append(f"metadata file could not be read: {relative}: {type(error).__name__}")
        return {}
    if not isinstance(value, Mapping):
        diagnostics.append(f"metadata root is not an object: {relative}")
        return {}
    return dict(value)


def _select_stack(root: Path, project: Mapping[str, Any], source: Mapping[str, Any]) -> str | None:
    candidates = (
        project.get("stack"),
        project.get("output_stack"),
        project.get("language"),
        source.get("selected_stack"),
        source.get("output_stack"),
        source.get("language"),
    )
    for candidate in candidates:
        normalized = _STACK_ALIASES.get(str(candidate or "").strip().casefold())
        if normalized:
            return normalized

    if (root / "app" / "build.gradle").is_file() or (root / "app" / "build.gradle.kts").is_file():
        if _has_suffix(root, {".kt", ".kts"}):
            return "android-kotlin"
        return "android-java"
    if (root / "Packages" / "manifest.json").is_file() or (root / "Assets").is_dir():
        return "unity-csharp"
    if (root / "package.json").is_file() and _has_suffix(root, {".js", ".cjs", ".mjs"}):
        return "electron"
    if _safe_top_level_files(root, {".csproj"}):
        return "csharp"
    if (root / "CMakeLists.txt").is_file():
        return "cpp" if _has_suffix(root, {".cc", ".cpp", ".cxx"}) else "c"
    if (root / "pyproject.toml").is_file() or _has_suffix(root, {".py"}):
        return "pyinstaller-python"
    return None


def _has_suffix(root: Path, suffixes: set[str]) -> bool:
    for current_root, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_names[:] = sorted(
            name for name in directory_names if name.casefold() not in _IGNORED_DIRECTORIES
        )
        if any(Path(name).suffix.casefold() in suffixes for name in filenames):
            return True
    return False


def _metadata_path_diagnostics(metadata: Mapping[str, Any]) -> list[str]:
    diagnostics: list[str] = []
    values: list[Any] = []
    for key in ("entrypoints", "build_files", "analysis_files"):
        candidate = metadata.get(key)
        if isinstance(candidate, list):
            values.extend(candidate[:_MAX_SOURCE_FILES])
    records = metadata.get("files")
    if isinstance(records, list):
        values.extend(item.get("path") for item in records[:_MAX_SOURCE_FILES] if isinstance(item, Mapping))
    for value in values:
        if isinstance(value, str) and _normalize_relative_path(value) is None:
            diagnostics.append(f"unsafe metadata path was ignored: {value!r}")
            if len(diagnostics) >= 20:
                diagnostics.append("additional unsafe metadata paths were omitted")
                break
    return diagnostics


def _discover_sources(
    root: Path, stack: str | None
) -> tuple[list[_SourceFile], list[str], bool]:
    suffixes = _SOURCE_SUFFIXES.get(stack or "", frozenset())
    if not suffixes:
        return [], [], False
    files: list[_SourceFile] = []
    diagnostics: list[str] = []
    incomplete = False
    for current_root, directory_names, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        kept_directories = []
        for name in sorted(directory_names):
            if name.casefold() in _IGNORED_DIRECTORIES:
                continue
            candidate = current / name
            if candidate.is_symlink():
                diagnostics.append(f"symbolic-link directory was skipped: {_relative_display(root, candidate)}")
                incomplete = True
                continue
            kept_directories.append(name)
        directory_names[:] = kept_directories
        for filename in sorted(filenames):
            path = current / filename
            if path.suffix.casefold() not in suffixes:
                continue
            relative = _relative_display(root, path)
            if _normalize_relative_path(relative) is None:
                diagnostics.append(f"unsafe source path was skipped: {relative!r}")
                incomplete = True
                continue
            if path.is_symlink():
                diagnostics.append(f"symbolic-link source was skipped: {relative}")
                incomplete = True
                continue
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                size = resolved.stat().st_size
            except (OSError, ValueError):
                diagnostics.append(f"source path could not be constrained: {relative}")
                incomplete = True
                continue
            if size > _MAX_SOURCE_BYTES:
                diagnostics.append(f"source file exceeds {_MAX_SOURCE_BYTES} bytes: {relative}")
                incomplete = True
                continue
            if len(files) >= _MAX_SOURCE_FILES:
                diagnostics.append(f"source file limit of {_MAX_SOURCE_FILES} was reached")
                incomplete = True
                return files, diagnostics, incomplete
            files.append(_SourceFile(resolved, relative))
    files.sort(key=lambda item: item.relative_path)
    return files, diagnostics, incomplete


def _placeholder_count(
    root: Path,
    project: Mapping[str, Any],
    source: Mapping[str, Any],
    files: Sequence[_SourceFile],
) -> int:
    explicit = project.get("placeholder_count")
    if isinstance(explicit, int) and not isinstance(explicit, bool) and explicit >= 0:
        return explicit
    records = project.get("files")
    if isinstance(records, list):
        paths = {
            normalized
            for item in records[:_MAX_SOURCE_FILES]
            if isinstance(item, Mapping) and item.get("placeholder") is True
            for normalized in [_normalize_relative_path(item.get("path"))]
            if normalized is not None and _is_regular_file_inside(root, normalized)
        }
        if paths:
            return len(paths)

    count = 0
    markers = (b"TODO", b"placeholder=true", b"NotImplemented", b"NotImplementedError")
    for item in files:
        try:
            content = item.path.read_bytes()
        except OSError:
            continue
        if any(marker in content for marker in markers):
            count += 1
    if count:
        return count
    notes = source.get("placeholders")
    return len(notes) if isinstance(notes, list) else 0


def _build_plan(
    root: Path,
    stack: str,
    files: Sequence[_SourceFile],
    resolver: ToolResolver,
    temporary_dir: Path,
) -> _ValidationPlan:
    relative_files = tuple(item.relative_path for item in files)
    command_files = tuple(_command_path(item.relative_path) for item in files)
    if stack == "pyinstaller-python":
        return _script_plan(
            "syntax",
            resolver,
            ("python",),
            ("-I", "-c", _PYTHON_CHECK_SCRIPT, "--", *command_files),
            relative_files,
            "Python interpreter was not found",
        )
    if stack == "electron":
        return _script_plan(
            "syntax",
            resolver,
            ("node",),
            ("--no-warnings", "-e", _JAVASCRIPT_CHECK_SCRIPT, "--", *command_files),
            relative_files,
            "Node.js was not found",
        )
    if stack in {"c", "cpp"}:
        return _native_plan(stack, resolver, files)
    if stack in {"csharp", "unity-csharp"}:
        return _csharp_plan(root, resolver, relative_files, command_files, temporary_dir)
    if stack in {"android-java", "android-kotlin"}:
        return _android_plan(root, stack, resolver, relative_files, command_files, temporary_dir)
    return _ValidationPlan(
        _default_level(stack),
        None,
        (),
        (),
        (),
        f"no validator is registered for stack {stack}",
    )


def _script_plan(
    level: str,
    resolver: ToolResolver,
    candidates: Sequence[str],
    arguments: Sequence[str],
    files: Sequence[str],
    unavailable: str,
) -> _ValidationPlan:
    resolved = _resolve_tool(resolver, candidates)
    if resolved is None:
        return _ValidationPlan(level, None, (), (), (), unavailable)
    toolchain, executable = resolved
    return _ValidationPlan(
        level,
        toolchain,
        (executable, *arguments),
        (toolchain, *arguments),
        tuple(files),
    )


def _native_plan(
    stack: str, resolver: ToolResolver, files: Sequence[_SourceFile]
) -> _ValidationPlan:
    source_suffixes = {".c"} if stack == "c" else {".cc", ".cpp", ".cxx"}
    translation_units = tuple(
        _command_path(item.relative_path)
        for item in files
        if item.path.suffix.casefold() in source_suffixes
    )
    if not translation_units:
        return _ValidationPlan("syntax", None, (), (), (), "no C/C++ translation units were found")
    candidates = ("cc", "gcc", "clang", "cl") if stack == "c" else ("c++", "g++", "clang++", "cl")
    resolved = _resolve_tool(resolver, candidates)
    if resolved is None:
        cmake = _resolve_tool(resolver, ("cmake",))
        diagnostic = "C/C++ compiler was not found"
        if cmake is not None:
            diagnostic += "; CMake alone cannot safely validate source without a compiler"
        return _ValidationPlan("syntax", None, (), (), (), diagnostic)
    toolchain, executable = resolved
    if toolchain == "cl":
        language_flag = "/TC" if stack == "c" else "/TP"
        arguments = ("/nologo", "/Zs", language_flag, "/I./include", *translation_units)
    else:
        standard = "-std=c11" if stack == "c" else "-std=c++17"
        arguments = (standard, "-fsyntax-only", "-I./include", "--", *translation_units)
    return _ValidationPlan(
        "syntax",
        toolchain,
        (executable, *arguments),
        (toolchain, *arguments),
        tuple(item.relative_path for item in files),
    )


def _csharp_plan(
    root: Path,
    resolver: ToolResolver,
    relative_files: Sequence[str],
    command_files: Sequence[str],
    temporary_dir: Path,
) -> _ValidationPlan:
    project_files = _safe_top_level_files(root, {".csproj"})
    dotnet = _resolve_tool(resolver, ("dotnet",))
    if dotnet is not None and project_files:
        toolchain, executable = dotnet
        project_file = _command_path(project_files[0])
        actual_temp = temporary_dir.as_posix()
        actual_arguments = (
            "build",
            project_file,
            "--no-restore",
            "--nologo",
            "--verbosity",
            "quiet",
            f"-p:BaseIntermediateOutputPath={actual_temp}/obj/",
            f"-p:OutputPath={actual_temp}/out/",
            "-p:UseSharedCompilation=false",
            "-p:NuGetAudit=false",
        )
        report_arguments = tuple(
            item.replace(actual_temp, "<validation-temp>") for item in actual_arguments
        )
        return _ValidationPlan(
            "build",
            toolchain,
            (executable, *actual_arguments),
            (toolchain, *report_arguments),
            tuple(relative_files),
        )

    compiler = _resolve_tool(resolver, ("csc", "mcs"))
    if compiler is not None:
        toolchain, executable = compiler
        output = temporary_dir / "validation.dll"
        if toolchain == "csc":
            actual_arguments = ("/nologo", "/target:library", f"/out:{output}", *command_files)
            report_arguments = (
                "/nologo",
                "/target:library",
                "/out:<validation-temp>/validation.dll",
                *command_files,
            )
        else:
            actual_arguments = ("-target:library", f"-out:{output}", *command_files)
            report_arguments = (
                "-target:library",
                "-out:<validation-temp>/validation.dll",
                *command_files,
            )
        return _ValidationPlan(
            "build",
            toolchain,
            (executable, *actual_arguments),
            (toolchain, *report_arguments),
            tuple(relative_files),
        )

    diagnostic = "dotnet or a C# compiler was not found"
    if dotnet is not None and not project_files:
        diagnostic = "dotnet was found, but no constrained .csproj file was available"
    return _ValidationPlan("build", None, (), (), (), diagnostic)


def _android_plan(
    root: Path,
    stack: str,
    resolver: ToolResolver,
    relative_files: Sequence[str],
    command_files: Sequence[str],
    temporary_dir: Path,
) -> _ValidationPlan:
    gradle = _resolve_tool(resolver, ("gradle",))
    has_gradle_project = any(
        (root / name).is_file() and not (root / name).is_symlink()
        for name in ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")
    )
    if gradle is not None and has_gradle_project:
        toolchain, executable = gradle
        task = ":app:compileDebugKotlin" if stack == "android-kotlin" else ":app:compileDebugJavaWithJavac"
        arguments = ("--offline", "--no-daemon", "--console=plain", "--warning-mode=none", task)
        return _ValidationPlan(
            "build",
            toolchain,
            (executable, *arguments),
            (toolchain, *arguments),
            tuple(relative_files),
        )

    if stack == "android-java":
        compiler = _resolve_tool(resolver, ("javac",))
        if compiler is not None:
            toolchain, executable = compiler
            output = temporary_dir / "classes"
            output.mkdir(parents=True, exist_ok=True)
            actual_arguments = ("-proc:none", "-d", str(output), *command_files)
            report_arguments = ("-proc:none", "-d", "<validation-temp>/classes", *command_files)
            return _ValidationPlan(
                "build",
                toolchain,
                (executable, *actual_arguments),
                (toolchain, *report_arguments),
                tuple(relative_files),
            )
        return _ValidationPlan("build", None, (), (), (), "Gradle or javac was not found")

    compiler = _resolve_tool(resolver, ("kotlinc", "kotlinc-jvm"))
    if compiler is not None:
        toolchain, executable = compiler
        output = temporary_dir / "validation.jar"
        actual_arguments = (*command_files, "-d", str(output))
        report_arguments = (*command_files, "-d", "<validation-temp>/validation.jar")
        return _ValidationPlan(
            "build",
            toolchain,
            (executable, *actual_arguments),
            (toolchain, *report_arguments),
            tuple(relative_files),
        )
    return _ValidationPlan("build", None, (), (), (), "Gradle or kotlinc was not found")


def _resolve_tool(resolver: ToolResolver, candidates: Sequence[str]) -> tuple[str, str] | None:
    for candidate in candidates:
        try:
            resolved = resolver(candidate)
        except (OSError, TypeError, ValueError):
            continue
        if resolved is None:
            continue
        executable = os.fspath(resolved)
        if not executable or any(ord(character) < 32 for character in executable):
            continue
        return candidate, executable
    return None


def _default_tool_resolver(name: str) -> str | None:
    if name == "python" and sys.executable and Path(sys.executable).is_file():
        return sys.executable
    return shutil.which(name)


def _safe_top_level_files(root: Path, suffixes: set[str]) -> list[str]:
    result = []
    try:
        candidates = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError:
        return result
    for path in candidates:
        if path.suffix.casefold() not in suffixes or path.is_symlink() or not path.is_file():
            continue
        normalized = _normalize_relative_path(path.name)
        if normalized is not None:
            result.append(normalized)
    return result


def _command_path(relative_path: str) -> str:
    return f"./{relative_path}"


def _default_level(stack: str) -> str:
    return "syntax" if stack in {"c", "cpp", "electron", "pyinstaller-python"} else "build"


def _validation_environment(temporary_dir: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "GRADLE_OPTS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "NODE_OPTIONS",
        "PYTHONHOME",
        "PYTHONPATH",
        "_JAVA_OPTIONS",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "ALL_PROXY": "http://127.0.0.1:9",
            "CI": "1",
            "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
            "DOTNET_NOLOGO": "1",
            "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1",
            "GRADLE_USER_HOME": str(temporary_dir / "gradle-home"),
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "NUGET_XMLDOC_MODE": "skip",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "all_proxy": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "no_proxy": "",
        }
    )
    return environment


def _input_records(root: Path, relative_paths: Sequence[str]) -> tuple[dict[str, Any], ...]:
    records = []
    for relative_path in relative_paths:
        normalized = _normalize_relative_path(relative_path)
        if normalized is None:
            continue
        path = root.joinpath(*PurePosixPath(normalized).parts)
        if not _is_regular_file_inside(root, normalized):
            continue
        try:
            content = path.read_bytes()
        except OSError:
            continue
        records.append(
            {
                "path": normalized,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    return tuple(records)


def _build_provenance(
    stack: str | None,
    metadata_origin: str | None,
    inputs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "validator": {
            "name": "reverse_analyzer.source.validation",
            "version": _VALIDATOR_VERSION,
            "deterministic": True,
        },
        "stack": stack,
        "project_metadata": metadata_origin,
        "inputs": [dict(item) for item in inputs],
    }


def _process_output(
    stdout: Any,
    stderr: Any,
    root: Path,
    limit: int,
    temporary_dir: Path | None = None,
) -> str | None:
    sections = []
    stdout_text = _output_text(stdout).strip()
    stderr_text = _output_text(stderr).strip()
    if stdout_text:
        sections.append(f"stdout:\n{stdout_text}")
    if stderr_text:
        sections.append(f"stderr:\n{stderr_text}")
    if not sections:
        return None
    return _normalize_diagnostic("\n".join(sections), root, limit, temporary_dir)


def _output_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _normalize_diagnostic(
    value: str,
    root: Path,
    limit: int,
    temporary_dir: Path | None = None,
) -> str:
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    replacements = [(root, ".")]
    if temporary_dir is not None:
        replacements.append((temporary_dir, "<validation-temp>"))
    path_replacements = {
        candidate: replacement
        for path, replacement in replacements
        for candidate in {str(path), path.as_posix(), str(path).replace("\\", "/")}
        if candidate
    }
    for path_value in sorted(path_replacements, key=len, reverse=True):
        text = text.replace(path_value, path_replacements[path_value])
    marker = "\n...[truncated]"
    if len(text) > limit:
        if limit <= len(marker):
            return marker[-limit:]
        return text[: limit - len(marker)] + marker
    return text


def _format_seconds(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:g}"


def _validation_result(
    *,
    status: str,
    level: str,
    toolchain: str | None,
    command: Sequence[str],
    exit_code: int | None,
    diagnostics: Sequence[str],
    validated_files: Sequence[str],
    placeholder_count: int,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "status": status,
        "level": level,
        "toolchain": toolchain,
        "command": list(command),
        "exit_code": exit_code,
        "diagnostics": [str(item) for item in diagnostics if str(item)],
        "validated_files": list(validated_files),
        "placeholder_count": max(0, int(placeholder_count)),
        "behavior_equivalent": False,
        "provenance": dict(provenance),
    }


def _canonical_validation(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("validation must be a mapping")
    required = {
        "status",
        "level",
        "toolchain",
        "command",
        "exit_code",
        "diagnostics",
        "validated_files",
        "placeholder_count",
        "behavior_equivalent",
        "provenance",
    }
    missing = sorted(required.difference(value))
    if missing:
        raise ValueError(f"validation is missing required fields: {', '.join(missing)}")
    status = value.get("status")
    level = value.get("level")
    if status not in {"passed", "failed", "unavailable"}:
        raise ValueError("validation status must be passed, failed, or unavailable")
    if level not in {"syntax", "build"}:
        raise ValueError("validation level must be syntax or build")
    command = value.get("command")
    diagnostics = value.get("diagnostics")
    validated_files = value.get("validated_files")
    provenance = value.get("provenance")
    if not isinstance(command, (list, tuple)) or not all(isinstance(item, str) for item in command):
        raise ValueError("validation command must be a list of strings")
    if not isinstance(diagnostics, (list, tuple)) or not all(
        isinstance(item, str) for item in diagnostics
    ):
        raise ValueError("validation diagnostics must be a list of strings")
    if not isinstance(validated_files, (list, tuple)):
        raise ValueError("validated_files must be a list")
    normalized_files = []
    for item in validated_files:
        normalized = _normalize_relative_path(item)
        if normalized is None or not _is_regular_file_inside(root, normalized):
            raise ValueError(f"validated file is outside the source project: {item!r}")
        normalized_files.append(normalized)
    placeholder_count = value.get("placeholder_count")
    if (
        not isinstance(placeholder_count, int)
        or isinstance(placeholder_count, bool)
        or placeholder_count < 0
    ):
        raise ValueError("placeholder_count must be a non-negative integer")
    exit_code = value.get("exit_code")
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        raise ValueError("exit_code must be an integer or null")
    toolchain = value.get("toolchain")
    if toolchain is not None and not isinstance(toolchain, str):
        raise ValueError("toolchain must be a string or null")
    if not isinstance(provenance, Mapping):
        raise ValueError("provenance must be an object")
    canonical = _validation_result(
        status=status,
        level=level,
        toolchain=toolchain,
        command=command,
        exit_code=exit_code,
        diagnostics=diagnostics,
        validated_files=tuple(dict.fromkeys(normalized_files)),
        placeholder_count=placeholder_count,
        provenance=provenance,
    )
    json.dumps(canonical, sort_keys=True, allow_nan=False)
    return canonical


def _safe_output_path(root: Path, relative_path: str) -> Path:
    normalized = _normalize_relative_path(relative_path)
    if normalized is None:
        raise ValueError("validation output path must stay below the source project")
    target = root.joinpath(*PurePosixPath(normalized).parts)
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError as error:
        raise ValueError("validation output path escapes the source project") from error
    return target


def _assert_no_symlink_path(root: Path, target: Path) -> None:
    cursor = target
    while cursor != root:
        if cursor.exists() and cursor.is_symlink():
            raise ValueError("validation output path traverses a symbolic link")
        cursor = cursor.parent


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


def _is_regular_file_inside(root: Path, relative_path: str) -> bool:
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    if path.is_symlink() or not path.is_file():
        return False
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return False
    return True


def _relative_display(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


# Compatibility names for callers that describe projects as generated sources.
validate_generated_source = validate_source_project
validate_generated_project = validate_source_project
write_validation_report = write_source_validation

__all__ = [
    "DEFAULT_VALIDATION_PATH",
    "VALIDATION_SCHEMA_VERSION",
    "validate_and_write_source_project",
    "validate_generated_project",
    "validate_generated_source",
    "validate_source_project",
    "write_source_validation",
    "write_validation_report",
]
