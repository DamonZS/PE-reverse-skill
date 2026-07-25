"""Bounded build-diagnostic feedback loop for reconstructed projects."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Any


BUILD_REPAIR_SCHEMA_VERSION = 1
DEFAULT_BUILD_REPAIR_PATH = Path("docs/build-repair-loop.json")
DEFAULT_BUILD_REPAIR_DIRECTORY = Path("docs/build-repair")
DEFAULT_MAX_ITERATIONS = 5
MAX_ITERATIONS = 20
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_DIAGNOSTIC_BYTES_PER_ITERATION = 64 * 1024
MAX_ARCHIVED_BUILD_LOG_BYTES = 256 * 1024


def run_build_repair_loop(
    project_dir: str | os.PathLike[str],
    initial_build_result: Mapping[str, Any],
    build_callback: Callable[[Path], Mapping[str, Any]],
    repair_callback: Callable[..., Mapping[str, Any]],
    *,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    max_diagnostic_bytes: int = MAX_DIAGNOSTIC_BYTES,
) -> dict[str, Any]:
    """Repair build failures and rebuild until success or a hard bound is met.

    ``repair_callback`` receives keyword arguments ``project_dir``,
    ``iteration``, ``diagnostics`` and ``build_result``. It must return a
    mapping containing ``applied_changes`` (or ``changes``); the mapping may
    also contain provider/model usage. ``build_callback`` receives the project
    root and must return the next evidence-bearing build result.
    """

    root = Path(project_dir).resolve()
    result_path = root / DEFAULT_BUILD_REPAIR_PATH
    evidence_directory = root / DEFAULT_BUILD_REPAIR_DIRECTORY
    started = time.monotonic()
    bounded_iterations = _bounded_iterations(max_iterations)
    bounded_diagnostic_bytes = _bounded_diagnostic_budget(max_diagnostic_bytes)
    current_build = _plain_mapping(initial_build_result)
    result: dict[str, Any] = {
        "schema_version": BUILD_REPAIR_SCHEMA_VERSION,
        "status": "dependency-gated",
        "passed": False,
        "started_at": _utc_now(),
        "finished_at": None,
        "duration_ms": 0,
        "project_dir": str(root),
        "max_iterations": bounded_iterations,
        "max_diagnostic_bytes": bounded_diagnostic_bytes,
        "iterations_completed": 0,
        "diagnostic_bytes_consumed": 0,
        "archived_build_log_bytes": 0,
        "blocking_reasons": [],
        "iterations": [],
        "final_build_result": current_build,
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }

    if _build_passed(current_build):
        result["status"] = "passed"
        result["passed"] = True
        return _finish_and_write(result, result_path, started)
    if bounded_iterations == 0:
        result["status"] = "exhausted"
        result["blocking_reasons"].append("repair_iteration_budget_exhausted")
        return _finish_and_write(result, result_path, started)

    for iteration in range(1, bounded_iterations + 1):
        remaining_bytes = bounded_diagnostic_bytes - result["diagnostic_bytes_consumed"]
        if remaining_bytes <= 0:
            result["status"] = "exhausted"
            result["blocking_reasons"].append("diagnostic_byte_budget_exhausted")
            break
        diagnostics = collect_build_diagnostics(
            root,
            current_build,
            min(MAX_DIAGNOSTIC_BYTES_PER_ITERATION, remaining_bytes),
        )
        if not diagnostics:
            result["status"] = "dependency-gated"
            result["blocking_reasons"].append("usable_build_diagnostics_required")
            break

        diagnostic_bytes = len(diagnostics.encode("utf-8"))
        result["diagnostic_bytes_consumed"] += diagnostic_bytes
        iteration_directory = evidence_directory / f"iteration-{iteration:02d}"
        iteration_directory.mkdir(parents=True, exist_ok=True)
        diagnostics_path = iteration_directory / "diagnostics.log"
        diagnostics_path.write_text(diagnostics, encoding="utf-8")
        before_path = iteration_directory / "build-before.json"
        _write_json(before_path, current_build)
        logs_before, archived_bytes = _snapshot_stage_logs(
            root,
            current_build,
            iteration_directory / "logs-before",
            MAX_ARCHIVED_BUILD_LOG_BYTES - result["archived_build_log_bytes"],
        )
        result["archived_build_log_bytes"] += archived_bytes
        record: dict[str, Any] = {
            "iteration": iteration,
            "status": "repairing",
            "diagnostic_bytes": diagnostic_bytes,
            "diagnostics": diagnostics_path.relative_to(root).as_posix(),
            "build_before": before_path.relative_to(root).as_posix(),
            "logs_before": logs_before,
            "repair": None,
            "build_after": None,
            "logs_after": [],
            "error": None,
        }
        result["iterations"].append(record)
        try:
            repair_response = repair_callback(
                project_dir=root,
                iteration=iteration,
                diagnostics=diagnostics,
                build_result=current_build,
            )
            repair = _normalize_repair_response(repair_response)
            repair_path = iteration_directory / "repair.json"
            _write_json(repair_path, repair)
            record["repair"] = repair_path.relative_to(root).as_posix()
            _merge_usage(result["usage"], repair["usage"])
            if not repair["applied_changes"]:
                record["status"] = "dependency-gated"
                result["status"] = "dependency-gated"
                result["blocking_reasons"].append("repair_produced_no_applied_changes")
                break
        except Exception as exception:  # Preserve provider/tool failure as evidence.
            record["status"] = "error"
            record["error"] = f"{type(exception).__name__}: {exception}"
            result["status"] = "exhausted"
            result["blocking_reasons"].append("repair_callback_failed")
            break

        try:
            next_build = _plain_mapping(build_callback(root))
        except Exception as exception:  # Build orchestration failures are not success.
            record["status"] = "error"
            record["error"] = f"{type(exception).__name__}: {exception}"
            result["status"] = "exhausted"
            result["blocking_reasons"].append("build_callback_failed")
            break
        after_path = iteration_directory / "build-after.json"
        _write_json(after_path, next_build)
        record["build_after"] = after_path.relative_to(root).as_posix()
        logs_after, archived_bytes = _snapshot_stage_logs(
            root,
            next_build,
            iteration_directory / "logs-after",
            MAX_ARCHIVED_BUILD_LOG_BYTES - result["archived_build_log_bytes"],
        )
        result["archived_build_log_bytes"] += archived_bytes
        record["logs_after"] = logs_after
        record["status"] = "passed" if _build_passed(next_build) else "failed"
        current_build = next_build
        result["final_build_result"] = current_build
        result["iterations_completed"] = iteration
        if _build_passed(current_build):
            result["status"] = "passed"
            result["passed"] = True
            break
    else:
        result["status"] = "exhausted"
        result["blocking_reasons"].append("repair_iteration_budget_exhausted")

    return _finish_and_write(result, result_path, started)


def collect_build_diagnostics(root: Path, build_result: Mapping[str, Any], byte_limit: int) -> str:
    pieces: list[str] = []
    failed_stage = build_result.get("failed_stage")
    if failed_stage:
        pieces.append(f"failed_stage: {failed_stage}")
    for stage in _mapping_sequence(build_result.get("stages")):
        if stage.get("status") == "passed":
            continue
        pieces.append(f"stage: {stage.get('name', 'unknown')} ({stage.get('status', 'unknown')})")
        if stage.get("error"):
            pieces.append(str(stage["error"]))
        log = stage.get("log")
        if isinstance(log, str):
            log_path = _safe_project_file(root, log)
            if log_path is not None:
                pieces.append(log_path.read_text(encoding="utf-8", errors="replace"))
    for key in ("diagnostics", "stderr", "error"):
        value = build_result.get(key)
        if isinstance(value, str) and value.strip():
            pieces.append(value)
    text = "\n\n".join(piece.strip() for piece in pieces if piece.strip()).strip()
    if not text:
        return ""
    encoded = text.encode("utf-8")
    if len(encoded) <= byte_limit:
        return text + "\n"
    marker = b"\n[diagnostics truncated]\n"
    keep = max(0, byte_limit - len(marker))
    return (encoded[:keep] + marker).decode("utf-8", errors="ignore")


def _safe_project_file(root: Path, relative_path: str) -> Path | None:
    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _snapshot_stage_logs(
    root: Path,
    build_result: Mapping[str, Any],
    destination: Path,
    byte_budget: int,
) -> tuple[list[str], int]:
    records: list[str] = []
    consumed = 0
    for index, stage in enumerate(_mapping_sequence(build_result.get("stages")), start=1):
        if consumed >= max(0, byte_budget):
            break
        source_value = stage.get("log")
        if not isinstance(source_value, str):
            continue
        source = _safe_project_file(root, source_value)
        if source is None:
            continue
        remaining = min(MAX_DIAGNOSTIC_BYTES_PER_ITERATION, byte_budget - consumed)
        content = source.read_bytes()[:remaining]
        name = f"{index:02d}-{_safe_filename(str(stage.get('name', 'stage')))}.log"
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        consumed += len(content)
        records.append(target.relative_to(root).as_posix())
    return records, consumed


def _safe_filename(value: str) -> str:
    safe = "".join(character if character.isalnum() or character in "-_" else "-" for character in value)
    return safe.strip("-") or "stage"


def _normalize_repair_response(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("repair callback must return a mapping")
    changes = value.get("applied_changes", value.get("changes", []))
    if not isinstance(changes, Sequence) or isinstance(changes, (str, bytes)):
        raise TypeError("applied_changes must be a sequence")
    usage = value.get("usage", {})
    if not isinstance(usage, Mapping):
        usage = {}
    return {
        "applied_changes": [_json_value(change) for change in changes],
        "provider": _json_value(value.get("provider")),
        "model": _json_value(value.get("model")),
        "usage": _normalized_usage(usage),
        "raw_response_artifact": _json_value(value.get("raw_response_artifact")),
    }


def _normalized_usage(value: Mapping[str, Any]) -> dict[str, int]:
    input_tokens = _nonnegative_int(value.get("input_tokens", value.get("prompt_tokens", 0)))
    output_tokens = _nonnegative_int(value.get("output_tokens", value.get("completion_tokens", 0)))
    total_tokens = _nonnegative_int(value.get("total_tokens", input_tokens + output_tokens))
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "total_tokens": total_tokens}


def _merge_usage(total: dict[str, int], addition: Mapping[str, int]) -> None:
    for key in ("input_tokens", "output_tokens", "total_tokens"):
        total[key] += int(addition.get(key, 0))


def _build_passed(value: Mapping[str, Any]) -> bool:
    return value.get("status") == "passed" and value.get("build_passed") is True


def _bounded_iterations(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("max_iterations must be an integer")
    return min(MAX_ITERATIONS, max(0, value))


def _bounded_diagnostic_budget(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("max_diagnostic_bytes must be an integer")
    return min(MAX_DIAGNOSTIC_BYTES, max(0, value))


def _plain_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("build result must be a mapping")
    return _json_value(dict(value))


def _mapping_sequence(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _nonnegative_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _finish_and_write(result: dict[str, Any], path: Path, started: float) -> dict[str, Any]:
    result["finished_at"] = _utc_now()
    result["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
    _write_json(path, result)
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = [
    "BUILD_REPAIR_SCHEMA_VERSION",
    "DEFAULT_BUILD_REPAIR_PATH",
    "DEFAULT_MAX_ITERATIONS",
    "MAX_DIAGNOSTIC_BYTES",
    "MAX_ARCHIVED_BUILD_LOG_BYTES",
    "MAX_ITERATIONS",
    "run_build_repair_loop",
]
