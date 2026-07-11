"""Serializable flow/task/subtask models for resumable reverse analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid4


TERMINAL_STATUSES = {"succeeded", "failed", "skipped"}


class Status(str, Enum):
    """Lifecycle states shared by sessions, flows, tasks, and subtasks."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _status(value: Status | str) -> Status:
    if isinstance(value, Status):
        return value
    return Status(value)


def _metadata(value: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return dict(value or {})


@dataclass
class Subtask:
    """Smallest resumable unit in an analysis task."""

    name: str
    description: str = ""
    status: Status = Status.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def set_status(
        self,
        status: Status | str,
        *,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.status = _status(status)
        if result is not None:
            self.result = result
        if error is not None:
            self.error = error
        self.updated_at = utc_now()

    def start(self) -> None:
        self.set_status(Status.RUNNING)

    def succeed(self, result: Optional[Dict[str, Any]] = None) -> None:
        self.set_status(Status.SUCCEEDED, result=result)

    def fail(self, error: str) -> None:
        self.set_status(Status.FAILED, error=error)

    def skip(self, reason: str = "") -> None:
        self.set_status(Status.SKIPPED, error=reason or None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "metadata": self.metadata,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Subtask":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            status=_status(data.get("status", Status.PENDING)),
            metadata=_metadata(data.get("metadata")),
            result=data.get("result"),
            error=data.get("error"),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
        )


@dataclass
class Task:
    """A resumable analysis task containing ordered subtasks."""

    name: str
    description: str = ""
    subtasks: List[Subtask] = field(default_factory=list)
    status: Status = Status.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def add_subtask(self, subtask: Subtask | str, description: str = "", **metadata: Any) -> Subtask:
        item = subtask if isinstance(subtask, Subtask) else Subtask(str(subtask), description, metadata=metadata)
        self.subtasks.append(item)
        self.updated_at = utc_now()
        return item

    def set_status(
        self,
        status: Status | str,
        *,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.status = _status(status)
        if result is not None:
            self.result = result
        if error is not None:
            self.error = error
        self.updated_at = utc_now()

    def start(self) -> None:
        self.set_status(Status.RUNNING)

    def succeed(self, result: Optional[Dict[str, Any]] = None) -> None:
        self.set_status(Status.SUCCEEDED, result=result)

    def fail(self, error: str) -> None:
        self.set_status(Status.FAILED, error=error)

    def skip(self, reason: str = "") -> None:
        self.set_status(Status.SKIPPED, error=reason or None)
        for subtask in self.subtasks:
            if subtask.status == Status.PENDING:
                subtask.skip(reason)

    def next_subtask(self) -> Optional[Subtask]:
        for subtask in self.subtasks:
            if subtask.status in (Status.PENDING, Status.RUNNING):
                return subtask
        return None

    def refresh_status_from_subtasks(self) -> Status:
        if not self.subtasks:
            return self.status
        statuses = {subtask.status.value for subtask in self.subtasks}
        if "failed" in statuses:
            self.set_status(Status.FAILED)
        elif "running" in statuses:
            self.set_status(Status.RUNNING)
        elif "pending" in statuses:
            self.set_status(Status.RUNNING if len(statuses) > 1 else Status.PENDING)
        elif statuses <= TERMINAL_STATUSES:
            if statuses == {"skipped"}:
                self.set_status(Status.SKIPPED)
            else:
                self.set_status(Status.SUCCEEDED)
        return self.status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "metadata": self.metadata,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "subtasks": [subtask.to_dict() for subtask in self.subtasks],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            subtasks=[Subtask.from_dict(item) for item in data.get("subtasks", [])],
            status=_status(data.get("status", Status.PENDING)),
            metadata=_metadata(data.get("metadata")),
            result=data.get("result"),
            error=data.get("error"),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
        )


@dataclass
class Flow:
    """Ordered chain of tasks for an analysis workflow."""

    name: str
    description: str = ""
    tasks: List[Task] = field(default_factory=list)
    status: Status = Status.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def add_task(self, task: Task | str, description: str = "", **metadata: Any) -> Task:
        item = task if isinstance(task, Task) else Task(str(task), description, metadata=metadata)
        self.tasks.append(item)
        self.updated_at = utc_now()
        return item

    def set_status(self, status: Status | str) -> None:
        self.status = _status(status)
        self.updated_at = utc_now()

    def start(self) -> None:
        self.set_status(Status.RUNNING)

    def next_task(self) -> Optional[Task]:
        for task in self.tasks:
            if task.status in (Status.PENDING, Status.RUNNING):
                return task
        return None

    def refresh_status_from_tasks(self) -> Status:
        if not self.tasks:
            return self.status
        for task in self.tasks:
            task.refresh_status_from_subtasks()
        statuses = {task.status.value for task in self.tasks}
        if "failed" in statuses:
            self.set_status(Status.FAILED)
        elif "running" in statuses:
            self.set_status(Status.RUNNING)
        elif "pending" in statuses:
            self.set_status(Status.RUNNING if len(statuses) > 1 else Status.PENDING)
        elif statuses <= TERMINAL_STATUSES:
            if statuses == {"skipped"}:
                self.set_status(Status.SKIPPED)
            else:
                self.set_status(Status.SUCCEEDED)
        return self.status

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tasks": [task.to_dict() for task in self.tasks],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Flow":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            tasks=[Task.from_dict(item) for item in data.get("tasks", [])],
            status=_status(data.get("status", Status.PENDING)),
            metadata=_metadata(data.get("metadata")),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
        )


@dataclass
class ReverseSession:
    """Top-level resumable reverse-analysis session."""

    session_id: str = field(default_factory=lambda: uuid4().hex)
    target: Optional[str] = None
    flows: List[Flow] = field(default_factory=list)
    status: Status = Status.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def add_flow(self, flow: Flow | str, description: str = "", **metadata: Any) -> Flow:
        item = flow if isinstance(flow, Flow) else Flow(str(flow), description, metadata=metadata)
        self.flows.append(item)
        self.updated_at = utc_now()
        return item

    def set_status(self, status: Status | str) -> None:
        self.status = _status(status)
        self.updated_at = utc_now()

    def start(self) -> None:
        self.set_status(Status.RUNNING)

    def refresh_status_from_flows(self) -> Status:
        if not self.flows:
            return self.status
        for flow in self.flows:
            flow.refresh_status_from_tasks()
        statuses = {flow.status.value for flow in self.flows}
        if "failed" in statuses:
            self.set_status(Status.FAILED)
        elif "running" in statuses:
            self.set_status(Status.RUNNING)
        elif "pending" in statuses:
            self.set_status(Status.RUNNING if len(statuses) > 1 else Status.PENDING)
        elif statuses <= TERMINAL_STATUSES:
            if statuses == {"skipped"}:
                self.set_status(Status.SKIPPED)
            else:
                self.set_status(Status.SUCCEEDED)
        return self.status

    def next_task(self) -> Optional[Task]:
        for flow in self.flows:
            task = flow.next_task()
            if task is not None:
                return task
        return None

    def iter_tasks(self) -> Iterable[Task]:
        for flow in self.flows:
            yield from flow.tasks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "status": self.status.value,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "flows": [flow.to_dict() for flow in self.flows],
            "events": self.events,
            "tool_calls": self.tool_calls,
            "artifacts": self.artifacts,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReverseSession":
        return cls(
            session_id=data.get("session_id") or uuid4().hex,
            target=data.get("target"),
            flows=[Flow.from_dict(item) for item in data.get("flows", [])],
            status=_status(data.get("status", Status.PENDING)),
            metadata=_metadata(data.get("metadata")),
            events=list(data.get("events", [])),
            tool_calls=list(data.get("tool_calls", [])),
            artifacts=list(data.get("artifacts", [])),
            created_at=data.get("created_at", utc_now()),
            updated_at=data.get("updated_at", utc_now()),
        )
