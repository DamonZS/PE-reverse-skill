"""Isolated, evidence-producing builds for reconstructed mixed projects."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any


BUILD_RESULT_SCHEMA_VERSION = 1
DEFAULT_BUILD_RESULT_PATH = Path("docs/build-result.json")
DEFAULT_BUILD_LOG_DIRECTORY = Path("docs/build-logs")
DEFAULT_BUILD_DIRECTORY = Path(".reconstruction-build")
CONFIGURE_TIMEOUT_SECONDS = 120.0
BUILD_TIMEOUT_SECONDS = 600.0
_SANDBOX_ENVIRONMENT_KEYS = (
    "REVERSE_ANALYZER_SANDBOX",
    "REVERSE_ANALYZER_BUILD_SANDBOX",
)
_TRUTHY = {"1", "true", "yes", "on"}


def build_project(
    project_dir: str | os.PathLike[str],
    readiness: Mapping[str, Any] | None,
    model_state: Mapping[str, Any] | None,
    runner: Callable[..., Any] | None = None,
    *,
    _environment: Mapping[str, str] | None = None,
    _container_marker: Path = Path("/.dockerenv"),
) -> dict[str, Any]:
    """Configure and build a reconstructed project, preserving auditable evidence.

    A real subprocess is allowed only inside a detected container/sandbox. An
    injected runner is treated as a test fixture and never invokes production
    commands by itself.
    """

    root = Path(project_dir).resolve()
    result_path = root / DEFAULT_BUILD_RESULT_PATH
    log_directory = root / DEFAULT_BUILD_LOG_DIRECTORY
    build_directory = root / DEFAULT_BUILD_DIRECTORY
    environment = dict(os.environ if _environment is None else _environment)
    injected_runner = runner is not None
    isolated = injected_runner or _isolated_environment(environment, _container_marker)

    result: dict[str, Any] = {
        "schema_version": BUILD_RESULT_SCHEMA_VERSION,
        "status": "dependency-gated",
        "build_passed": False,
        "failed_stage": None,
        "error": None,
        "started_at": _utc_now(),
        "finished_at": None,
        "duration_ms": 0,
        "project_dir": str(root),
        "build_dir": DEFAULT_BUILD_DIRECTORY.as_posix(),
        "isolated": isolated,
        "isolation": {
            "detected": isolated,
            "mode": "injected-runner" if injected_runner else ("container" if isolated else "host"),
            "network": str(environment.get("REVERSE_ANALYZER_WORKER_NETWORK") or "unknown"),
        },
        "blocking_reasons": [],
        "stages": [],
        "artifacts": [],
        "artifact_count": 0,
    }
    started = time.monotonic()

    if not bool((readiness or {}).get("build_ready")):
        result["blocking_reasons"].append("readiness_not_build_ready")
    if (model_state or {}).get("status") != "executed":
        result["blocking_reasons"].append("model_reconstruction_not_executed")
    if not isolated:
        result["blocking_reasons"].append("isolated_build_environment_required")
    if result["blocking_reasons"]:
        result["error"] = "; ".join(result["blocking_reasons"])
        return _finish_and_write(result, result_path, started)

    command_runner = runner or subprocess.run
    commands: list[tuple[str, list[str], float]] = [
        (
            "configure",
            ["cmake", "-S", str(root), "-B", str(build_directory)],
            CONFIGURE_TIMEOUT_SECONDS,
        ),
        (
            "build",
            ["cmake", "--build", str(build_directory)],
            BUILD_TIMEOUT_SECONDS,
        ),
    ]
    android_output = build_directory / "android"
    for descriptor in sorted(root.glob("targets/**/apktool.yml")):
        target_root = descriptor.parent
        target_id = target_root.relative_to(root / "targets").parts[0]
        android_output.mkdir(parents=True, exist_ok=True)
        commands.append((
            f"apktool-{target_id}",
            ["apktool", "build", str(target_root), "--output", str(android_output / f"{target_id}.apk")],
            BUILD_TIMEOUT_SECONDS,
        ))
    result["status"] = "running"
    for stage_name, command, timeout_seconds in commands:
        stage, should_continue = _run_stage(
            stage_name,
            command,
            timeout_seconds,
            root,
            log_directory,
            environment,
            command_runner,
        )
        result["stages"].append(stage)
        if not should_continue:
            result["status"] = stage["status"]
            result["failed_stage"] = stage_name
            result["error"] = stage.get("error") or f'{stage_name} exited with code {stage.get("return_code")}'
            break
    else:
        result["status"] = "passed"
        result["build_passed"] = True

    result["artifacts"] = _artifact_records(root, build_directory)
    result["artifact_count"] = len(result["artifacts"])
    return _finish_and_write(result, result_path, started)


def _run_stage(
    name: str,
    command: list[str],
    timeout_seconds: float,
    root: Path,
    log_directory: Path,
    environment: Mapping[str, str],
    runner: Callable[..., Any],
) -> tuple[dict[str, Any], bool]:
    started = time.monotonic()
    stdout: str | bytes | None = ""
    stderr: str | bytes | None = ""
    return_code: int | None = None
    status = "error"
    error: str | None = None
    try:
        completed = runner(
            command,
            cwd=str(root),
            env=dict(environment),
            timeout=timeout_seconds,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            shell=False,
        )
        stdout = getattr(completed, "stdout", "")
        stderr = getattr(completed, "stderr", "")
        candidate = getattr(completed, "returncode", None)
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            return_code = candidate
        if return_code == 0:
            status = "passed"
        else:
            status = "failed"
            if return_code is None:
                error = "build runner returned no integer return code"
    except subprocess.TimeoutExpired as exception:
        status = "timed_out"
        stdout = exception.stdout
        stderr = exception.stderr
        error = f"stage timed out after {timeout_seconds:g} seconds"
    except Exception as exception:  # Runner failures must remain evidence, not escape the worker.
        status = "error"
        error = f"{type(exception).__name__}: {exception}"

    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    log_path = log_directory / f"{name}.log"
    _write_stage_log(log_path, command, timeout_seconds, stdout, stderr, error)
    stage = {
        "name": name,
        "status": status,
        "command": command,
        "timeout_seconds": timeout_seconds,
        "return_code": return_code,
        "duration_ms": duration_ms,
        "log": log_path.relative_to(root).as_posix(),
        "error": error,
    }
    return stage, status == "passed"


def _write_stage_log(
    path: Path,
    command: list[str],
    timeout_seconds: float,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    error: str | None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sections = [
        f"command: {json.dumps(command, ensure_ascii=False)}",
        f"timeout_seconds: {timeout_seconds:g}",
        "",
        "[stdout]",
        _output_text(stdout),
        "",
        "[stderr]",
        _output_text(stderr),
    ]
    if error:
        sections.extend(("", "[error]", error))
    path.write_text("\n".join(sections) + "\n", encoding="utf-8")


def _artifact_records(root: Path, build_directory: Path) -> list[dict[str, Any]]:
    if not build_directory.is_dir():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(build_directory.rglob("*"), key=lambda item: item.as_posix().lower()):
        if path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        records.append(
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
    return records


def _isolated_environment(environment: Mapping[str, str], container_marker: Path) -> bool:
    if container_marker.is_file():
        return True
    return any(str(environment.get(key, "")).strip().lower() in _TRUTHY for key in _SANDBOX_ENVIRONMENT_KEYS)


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _finish_and_write(result: dict[str, Any], path: Path, started: float) -> dict[str, Any]:
    result["finished_at"] = _utc_now()
    result["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "BUILD_RESULT_SCHEMA_VERSION",
    "DEFAULT_BUILD_RESULT_PATH",
    "build_project",
]
