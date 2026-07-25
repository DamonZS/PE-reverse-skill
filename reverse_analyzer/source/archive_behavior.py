"""Archive-level behavior validation with isolation and evidence gates."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
from typing import Any

from .behavior_validation import validate_source_behavior


ARCHIVE_BEHAVIOR_SCHEMA_VERSION = 1
DEFAULT_ARCHIVE_BEHAVIOR_PATH = Path("docs/behavior-validation.json")
_SANDBOX_ENVIRONMENT_KEYS = (
    "REVERSE_ANALYZER_SANDBOX",
    "REVERSE_ANALYZER_BEHAVIOR_SANDBOX",
)
_TRUTHY = {"1", "true", "yes", "on"}


def validate_archive_behavior(
    original_dir: str | os.PathLike[str],
    reconstructed_dir: str | os.PathLike[str],
    spec: Mapping[str, Any] | str | os.PathLike[str] | None = None,
    *,
    isolated: bool | None = None,
) -> dict[str, Any]:
    """Validate an archive reconstruction and persist auditable evidence.

    A string or path specification is resolved strictly beneath the original
    archive root. Execution is dependency-gated unless isolation is explicit
    or detected from the worker environment.
    """

    original = Path(original_dir).resolve()
    reconstructed = Path(reconstructed_dir).resolve()
    result_path = reconstructed / DEFAULT_ARCHIVE_BEHAVIOR_PATH
    isolation_detected = _isolated_environment() if isolated is None else isolated is True

    if spec is None:
        return _write_result(
            result_path,
            _gated_result(
                status="dependency-gated",
                reason="behavior_validation_spec_required",
                isolated=isolation_detected,
                spec_source=None,
            ),
        )

    try:
        validation_spec, spec_source = _load_spec(original, spec)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        reason = (
            "behavior_validation_spec_path_escape"
            if isinstance(error, _SpecPathEscape)
            else "behavior_validation_spec_invalid"
        )
        result = _gated_result(
            status="failed",
            reason=reason,
            isolated=isolation_detected,
            spec_source=None,
        )
        result["diagnostics"] = [f"invalid archive behavior spec: {error}"]
        return _write_result(result_path, result)

    if not isolation_detected:
        return _write_result(
            result_path,
            _gated_result(
                status="dependency-gated",
                reason="isolated_behavior_environment_required",
                isolated=False,
                spec_source=spec_source,
            ),
        )

    result = dict(validate_source_behavior(original, reconstructed, validation_spec))
    result["schema_version"] = ARCHIVE_BEHAVIOR_SCHEMA_VERSION
    result["archive_validation"] = {
        "isolated": True,
        "network": os.environ.get("REVERSE_ANALYZER_WORKER_NETWORK", "unknown"),
        "spec_source": spec_source,
        "artifact": DEFAULT_ARCHIVE_BEHAVIOR_PATH.as_posix(),
    }
    result["blocking_reasons"] = _blocking_reasons(result)

    validator = result.get("provenance", {}).get("validator", {})
    strict_pass = (
        result.get("status") == "passed"
        and result.get("behavior_equivalent") is True
        and validator.get("real_subprocess") is True
        and validator.get("runner_injected") is False
        and validator.get("shell") is False
    )
    if not strict_pass:
        result["behavior_equivalent"] = False
        if result.get("status") == "passed":
            result["status"] = "failed"
            result["blocking_reasons"].append("real_subprocess_provenance_required")
            diagnostics = list(result.get("diagnostics") or [])
            diagnostics.append("archive behavior validation lacks strict real subprocess provenance")
            result["diagnostics"] = diagnostics
        artifact = result.get("artifact")
        if isinstance(artifact, dict):
            artifact["behavior_equivalent"] = False

    return _write_result(result_path, result)


def _blocking_reasons(result: Mapping[str, Any]) -> list[str]:
    existing = [str(item) for item in result.get("blocking_reasons") or [] if str(item)]
    if existing:
        return existing
    if result.get("status") == "passed" and result.get("behavior_equivalent") is True:
        return []
    summary = result.get("summary") if isinstance(result.get("summary"), Mapping) else {}
    if int(summary.get("mismatched_comparison_count") or 0) > 0:
        return ["behavior_comparison_mismatch"]
    if result.get("status") == "unavailable":
        return ["behavior_validation_dependency_unavailable"]
    return ["behavior_validation_failed"]


class _SpecPathEscape(ValueError):
    pass


def _load_spec(
    original: Path,
    spec: Mapping[str, Any] | str | os.PathLike[str],
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    if isinstance(spec, Mapping):
        return spec, {"kind": "inline"}
    if not isinstance(spec, (str, os.PathLike)):
        raise TypeError("spec must be a mapping or an original-root-relative JSON path")

    relative = Path(spec)
    if relative.is_absolute():
        raise _SpecPathEscape("spec path must be relative to original_dir")
    candidate = original / relative
    try:
        candidate.resolve(strict=False).relative_to(original)
    except ValueError as error:
        raise _SpecPathEscape("spec path escapes original_dir") from error
    resolved = candidate.resolve(strict=True)
    if candidate.is_symlink() or not resolved.is_file():
        raise ValueError("spec path must identify a regular JSON file")
    if resolved.suffix.casefold() != ".json":
        raise ValueError("spec path must use the .json extension")

    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise TypeError("behavior validation JSON root must be an object")
    return payload, {"kind": "original_relative_json", "path": resolved.relative_to(original).as_posix()}


def _isolated_environment() -> bool:
    if Path("/.dockerenv").is_file():
        return True
    return any(
        os.environ.get(key, "").strip().casefold() in _TRUTHY
        for key in _SANDBOX_ENVIRONMENT_KEYS
    )


def _gated_result(
    *,
    status: str,
    reason: str,
    isolated: bool,
    spec_source: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "schema_version": ARCHIVE_BEHAVIOR_SCHEMA_VERSION,
        "status": status,
        "behavior_equivalent": False,
        "blocking_reasons": [reason],
        "diagnostics": [reason],
        "summary": {
            "executed_command_count": 0,
            "comparison_count": 0,
            "mismatched_comparison_count": 0,
        },
        "provenance": {
            "validator": {
                "real_subprocess": False,
                "runner_injected": False,
                "shell": False,
            }
        },
        "archive_validation": {
            "isolated": isolated,
            "network": os.environ.get("REVERSE_ANALYZER_WORKER_NETWORK", "unknown"),
            "spec_source": spec_source,
            "artifact": DEFAULT_ARCHIVE_BEHAVIOR_PATH.as_posix(),
        },
    }


def _write_result(path: Path, result: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


__all__ = [
    "ARCHIVE_BEHAVIOR_SCHEMA_VERSION",
    "DEFAULT_ARCHIVE_BEHAVIOR_PATH",
    "validate_archive_behavior",
]
