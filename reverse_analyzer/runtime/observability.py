"""JSONL trace logging for reverse analyzer runtime steps."""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

from reverse_analyzer.core.models import utc_now


TRACE_FIELDS = ("timestamp", "session_id", "task", "subtask", "tool", "status", "message", "data")


class TraceLogger:
    """Append-only structured JSONL logger used for observability."""

    def __init__(self, trace_path: str | Path):
        self.trace_path = Path(trace_path)
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()

    def log(
        self,
        *,
        session_id: str,
        task: Optional[str] = None,
        subtask: Optional[str] = None,
        tool: Optional[str] = None,
        status: str = "running",
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record = {
            "timestamp": utc_now(),
            "session_id": session_id,
            "task": task,
            "subtask": subtask,
            "tool": tool,
            "status": status,
            "message": message,
            "data": dict(data or {}),
        }
        with self._lock:
            with self.trace_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        return record

    def read_records(self) -> list[Dict[str, Any]]:
        if not self.trace_path.exists():
            return []
        records: list[Dict[str, Any]] = []
        with self.trace_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
