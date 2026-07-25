"""Persistent event log used by the Web console.

The log is intentionally file-backed and append-only so the Web UI can recover
task history after a server restart without needing an external broker.
"""

from __future__ import annotations

from pathlib import Path
import json
import re
from typing import Any, Iterable, Mapping

from reverse_analyzer.core.models import utc_now


_EXPERIMENT_ID = re.compile(r"[0-9a-f]{32}")
_MAX_MESSAGE = 4096


class WebEventLog:
    """Append and read bounded per-experiment Web events."""

    def __init__(self, workspace: str | Path, *, retained_events: int = 500) -> None:
        self.workspace = Path(workspace)
        self.root = self.workspace / ".reverse_analyzer" / "web" / "events"
        self.retained_events = max(1, retained_events)
        self.root.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        experiment_id: str,
        event_type: str,
        *,
        status: str | None = None,
        message: str = "",
        data: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        events = self.list_events(experiment_id)
        sequence = int(events[-1]["sequence"]) + 1 if events else 1
        record = {
            "sequence": sequence,
            "timestamp": utc_now(),
            "experiment_id": experiment_id,
            "type": str(event_type or "event"),
            "status": status,
            "message": str(message or "")[:_MAX_MESSAGE],
            "data": _json_value(dict(data or {})),
        }
        path = self.path_for(experiment_id)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            handle.write("\n")
        self._trim(path)
        return record

    def list_events(
        self,
        experiment_id: str,
        *,
        after: int | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        path = self.path_for(experiment_id)
        if not path.exists():
            return []
        records: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                sequence = int(payload.get("sequence") or 0)
                if after is not None and sequence <= after:
                    continue
                records.append(dict(payload))
        if limit is None:
            return records
        return records[-max(0, limit) :]

    def as_sse(self, events: Iterable[Mapping[str, Any]]) -> bytes:
        chunks: list[str] = []
        for event in events:
            event_name = str(event.get("type") or "message").replace("\n", " ")
            data = json.dumps(dict(event), ensure_ascii=False, sort_keys=True)
            chunks.append(f"id: {event.get('sequence', '')}\nevent: {event_name}\ndata: {data}\n\n")
        return "".join(chunks).encode("utf-8")

    def path_for(self, experiment_id: str) -> Path:
        self._validate_experiment_id(experiment_id)
        return self.root / f"{experiment_id}.jsonl"

    def _trim(self, path: Path) -> None:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        if len(lines) <= self.retained_events:
            return
        path.write_text("\n".join(lines[-self.retained_events :]) + "\n", encoding="utf-8")

    @staticmethod
    def _validate_experiment_id(experiment_id: str) -> None:
        if not isinstance(experiment_id, str) or _EXPERIMENT_ID.fullmatch(experiment_id) is None:
            raise ValueError("experiment_id must be a generated 32-character lowercase hexadecimal ID")


def _json_value(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return [_json_value(item) for item in sorted(value, key=str)]
    return value


__all__ = ["WebEventLog"]
