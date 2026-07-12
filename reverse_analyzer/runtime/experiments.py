"""File-backed control plane for dynamic analysis experiments.

This module only records experiment intent and results. It never starts a
sample or invokes an external process.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from reverse_analyzer.core.models import utc_now


SCHEMA_VERSION = 1
_EXPERIMENT_ID = re.compile(r"[0-9a-f]{32}")
_TRANSITIONS = {
    "queued": {"queued", "planned", "cancelled"},
    "planned": {"planned", "running", "cancelled"},
    "running": {"running", "completed", "failed", "cancelled"},
    "completed": {"completed"},
    "failed": {"failed"},
    "cancelled": {"cancelled"},
}
_OPTION_FLAGS = {
    "dynamic": "--dynamic",
    "memory_analysis": "--memory-analysis",
    "gui": "--gui",
    "gui_runtime": "--gui-runtime",
    "gui_visual": "--gui-visual",
    "reconstruct": "--reconstruct",
    "reconstruct_gui": "--reconstruct-gui",
}
_OPTION_VALUES = {
    "dynamic_backend": "--dynamic-backend",
    "dynamic_profile": "--dynamic-profile",
    "dynamic_duration": "--dynamic-duration",
    "memory_plan": "--memory-plan",
    "gui_target": "--gui-target",
    "gui_interaction_trace": "--gui-interaction-trace",
}


def _json_value(value: Any) -> Any:
    """Convert Path-bearing mappings and sequences into JSON-compatible data."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return [_json_value(item) for item in sorted(value, key=str)]
    return value


class ExperimentStore:
    """Persist experiment jobs under ``workspace/experiments``."""

    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace)
        self.experiments_dir = self.workspace / "experiments"
        self.experiments_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, experiment_id: str) -> Path:
        self._validate_experiment_id(experiment_id)
        return self.experiments_dir / f"{experiment_id}.json"

    def create(
        self,
        sample: str | Path,
        *,
        options: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now()
        experiment = {
            "schema": SCHEMA_VERSION,
            "schema_version": SCHEMA_VERSION,
            "id": uuid4().hex,
            "sample": str(sample),
            "status": "queued",
            "created_at": timestamp,
            "updated_at": timestamp,
            "options": _json_value(dict(options or {})),
            "metadata": _json_value(dict(metadata or {})),
            "history": [{"timestamp": timestamp, "status": "queued", "detail": "created"}],
            "artifacts": [],
            "summary": None,
        }
        self._save(experiment)
        return experiment

    def get(self, experiment_id: str) -> dict[str, Any]:
        self._validate_experiment_id(experiment_id)
        return self._read(self.path_for(experiment_id), expected_id=experiment_id)

    def list(self, limit: int | None = None) -> list[dict[str, Any]]:
        if limit is not None and limit < 0:
            raise ValueError("limit must be non-negative")
        if not self.experiments_dir.exists():
            return []
        paths = sorted(self.experiments_dir.glob("*.json"), key=lambda path: path.name)
        records = [self._read(path, expected_id=path.stem) for path in paths]
        records.sort(
            key=lambda record: (record["updated_at"], record["created_at"], record["id"]),
            reverse=True,
        )
        return records if limit is None else records[:limit]

    def set_status(
        self, experiment_id: str, status: str, *, detail: Any = None
    ) -> dict[str, Any]:
        experiment = self.get(experiment_id)
        self._validate_transition(experiment["status"], status)
        timestamp = utc_now()
        experiment["status"] = status
        experiment["updated_at"] = timestamp
        experiment["history"].append(
            {"timestamp": timestamp, "status": status, "detail": _json_value(detail)}
        )
        self._save(experiment)
        return experiment

    def record_result(
        self,
        experiment_id: str,
        *,
        status: str,
        artifacts: Any = None,
        summary: Any = None,
        error: Any = None,
    ) -> dict[str, Any]:
        experiment = self.get(experiment_id)
        self._validate_transition(experiment["status"], status)
        timestamp = utc_now()
        experiment["status"] = status
        experiment["updated_at"] = timestamp
        if artifacts is not None:
            experiment["artifacts"] = _json_value(artifacts)
        if summary is not None:
            experiment["summary"] = _json_value(summary)
        detail = error if error is not None else "result_recorded"
        experiment["history"].append(
            {"timestamp": timestamp, "status": status, "detail": _json_value(detail)}
        )
        if error is not None:
            experiment["error"] = _json_value(error)
        self._save(experiment)
        return experiment

    def build_analysis_command(
        self, experiment_id: str, *, python_executable: str | Path | None = None
    ) -> list[str]:
        experiment = self.get(experiment_id)
        options = experiment.get("options") or {}
        output_dir = self.experiments_dir / experiment_id / "analysis"
        command = [
            str(python_executable or sys.executable),
            "-m",
            "reverse_analyzer",
            "analyze",
            str(experiment["sample"]),
            "--out",
            str(output_dir),
        ]
        for name, flag in _OPTION_FLAGS.items():
            if options.get(name):
                command.append(flag)
        for name, flag in _OPTION_VALUES.items():
            if name in options and options[name] is not None:
                command.extend((flag, str(options[name])))
        return command

    @staticmethod
    def _validate_transition(current: str, requested: str) -> None:
        if not isinstance(requested, str) or requested not in _TRANSITIONS:
            raise ValueError(f"invalid experiment status: {requested!r}")
        if requested not in _TRANSITIONS.get(current, set()):
            raise ValueError(f"invalid experiment status transition: {current} -> {requested}")

    @staticmethod
    def _validate_experiment_id(experiment_id: str) -> None:
        if not isinstance(experiment_id, str) or _EXPERIMENT_ID.fullmatch(experiment_id) is None:
            raise ValueError("experiment_id must be a generated 32-character lowercase hexadecimal ID")

    @classmethod
    def _read(cls, path: Path, *, expected_id: str | None = None) -> dict[str, Any]:
        try:
            with path.open("r", encoding="utf-8") as handle:
                record = json.load(handle)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid experiment record in {path}: invalid JSON") from error
        return cls._validate_record(record, expected_id=expected_id)

    @classmethod
    def _validate_record(
        cls, record: Any, *, expected_id: str | None = None
    ) -> dict[str, Any]:
        if not isinstance(record, Mapping):
            raise ValueError("invalid experiment record: expected a JSON object")

        normalized = dict(record)
        has_schema = "schema" in normalized
        has_schema_version = "schema_version" in normalized
        if not has_schema and not has_schema_version:
            raise ValueError("invalid experiment record: missing schema version")
        if has_schema and normalized["schema"] != SCHEMA_VERSION:
            raise ValueError("invalid experiment record: unsupported schema")
        if has_schema_version and normalized["schema_version"] != SCHEMA_VERSION:
            raise ValueError("invalid experiment record: unsupported schema_version")

        required_fields = (
            "id",
            "sample",
            "status",
            "created_at",
            "updated_at",
            "options",
            "metadata",
            "history",
            "artifacts",
            "summary",
        )
        missing = [field for field in required_fields if field not in normalized]
        if missing:
            raise ValueError(f"invalid experiment record: missing {', '.join(missing)}")

        experiment_id = normalized["id"]
        cls._validate_experiment_id(experiment_id)
        if expected_id is not None and experiment_id != expected_id:
            raise ValueError("invalid experiment record: id does not match its file name")
        if not isinstance(normalized["sample"], str):
            raise ValueError("invalid experiment record: sample must be a string")
        if not isinstance(normalized["status"], str) or normalized["status"] not in _TRANSITIONS:
            raise ValueError("invalid experiment record: invalid status")
        if not isinstance(normalized["created_at"], str) or not isinstance(normalized["updated_at"], str):
            raise ValueError("invalid experiment record: timestamps must be strings")
        if not isinstance(normalized["options"], Mapping):
            raise ValueError("invalid experiment record: options must be an object")
        if not isinstance(normalized["metadata"], Mapping):
            raise ValueError("invalid experiment record: metadata must be an object")
        if not isinstance(normalized["history"], list):
            raise ValueError("invalid experiment record: history must be a list")
        if not isinstance(normalized["artifacts"], list):
            raise ValueError("invalid experiment record: artifacts must be a list")
        return normalized

    def _save(self, experiment: Mapping[str, Any]) -> None:
        self.experiments_dir.mkdir(parents=True, exist_ok=True)
        normalized = self._validate_record(_json_value(dict(experiment)))
        path = self.path_for(normalized["id"])
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(normalized, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)


__all__ = ["ExperimentStore"]
