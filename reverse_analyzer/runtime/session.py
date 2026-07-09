"""Persistence layer for ReverseSession records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from uuid import uuid4

from reverse_analyzer.core import ReverseSession
from reverse_analyzer.core.models import utc_now
from .observability import TraceLogger


class SessionStore:
    """File-backed store for sessions, events, tool calls, and artifacts."""

    def __init__(self, root: str | Path = ".reverse_analyzer", trace_logger: Optional[TraceLogger] = None):
        self.root = Path(root)
        self.sessions_dir = self.root / "sessions"
        self.artifacts_dir = self.root / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.trace_logger = trace_logger or TraceLogger(self.root / "trace.jsonl")

    def create_session(
        self,
        target: Optional[str] = None,
        *,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ReverseSession:
        session = ReverseSession(session_id=session_id or uuid4().hex, target=target, metadata=dict(metadata or {}))
        self.save(session)
        self.record_event(session, "session_created", data={"target": target})
        return session

    def path_for(self, session_id: str) -> Path:
        return self.sessions_dir / f"{session_id}.json"

    def save(self, session: ReverseSession) -> Path:
        session.updated_at = utc_now()
        path = self.path_for(session.session_id)
        temp = path.with_suffix(".json.tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(session.to_dict(), handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        temp.replace(path)
        return path

    def load(self, session_id: str) -> ReverseSession:
        path = self.path_for(session_id)
        with path.open("r", encoding="utf-8") as handle:
            return ReverseSession.from_dict(json.load(handle))

    def list_sessions(self) -> list[str]:
        return sorted(path.stem for path in self.sessions_dir.glob("*.json"))

    def record_event(
        self,
        session: ReverseSession | str,
        event_type: str,
        *,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        task: Optional[str] = None,
        subtask: Optional[str] = None,
        status: str = "succeeded",
    ) -> Dict[str, Any]:
        loaded = self._ensure_session(session)
        record = {
            "timestamp": utc_now(),
            "type": event_type,
            "message": message,
            "task": task,
            "subtask": subtask,
            "status": status,
            "data": dict(data or {}),
        }
        loaded.events.append(record)
        self.save(loaded)
        self._copy_back(session, loaded)
        self.trace_logger.log(
            session_id=loaded.session_id,
            task=task,
            subtask=subtask,
            status=status,
            message=message or event_type,
            data=record["data"],
        )
        return record

    def record_tool_call(
        self,
        session: ReverseSession | str,
        tool: str,
        *,
        task: Optional[str] = None,
        subtask: Optional[str] = None,
        status: str = "succeeded",
        input: Optional[Dict[str, Any]] = None,
        output: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        message: str = "",
    ) -> Dict[str, Any]:
        loaded = self._ensure_session(session)
        record = {
            "timestamp": utc_now(),
            "tool": tool,
            "task": task,
            "subtask": subtask,
            "status": status,
            "input": dict(input or {}),
            "output": dict(output or {}),
            "error": error,
            "message": message,
        }
        loaded.tool_calls.append(record)
        self.save(loaded)
        self._copy_back(session, loaded)
        self.trace_logger.log(
            session_id=loaded.session_id,
            task=task,
            subtask=subtask,
            tool=tool,
            status=status,
            message=message or error or tool,
            data={"input": record["input"], "output": record["output"], "error": error},
        )
        return record

    def record_artifact(
        self,
        session: ReverseSession | str,
        name: str,
        *,
        path: Optional[str | Path] = None,
        kind: str = "file",
        data: Optional[Dict[str, Any]] = None,
        task: Optional[str] = None,
        subtask: Optional[str] = None,
    ) -> Dict[str, Any]:
        loaded = self._ensure_session(session)
        record = {
            "timestamp": utc_now(),
            "name": name,
            "kind": kind,
            "path": str(path) if path is not None else None,
            "task": task,
            "subtask": subtask,
            "data": dict(data or {}),
        }
        loaded.artifacts.append(record)
        self.save(loaded)
        self._copy_back(session, loaded)
        self.trace_logger.log(
            session_id=loaded.session_id,
            task=task,
            subtask=subtask,
            status="succeeded",
            message=f"artifact:{name}",
            data=record,
        )
        return record

    def _ensure_session(self, session: ReverseSession | str) -> ReverseSession:
        return session if isinstance(session, ReverseSession) else self.load(session)

    @staticmethod
    def _copy_back(original: ReverseSession | str, loaded: ReverseSession) -> None:
        if isinstance(original, ReverseSession):
            original.events = loaded.events
            original.tool_calls = loaded.tool_calls
            original.artifacts = loaded.artifacts
            original.updated_at = loaded.updated_at
