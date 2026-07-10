"""Persistence layer for ReverseSession records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional
from uuid import uuid4

from reverse_analyzer.core import Flow, ReverseSession, Subtask, Task
from reverse_analyzer.core.models import Status, utc_now
from .observability import TraceLogger

RECONSTRUCTION_FLOW_NAME = "source-reconstruction"


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
        flow: Optional[str] = None,
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
            "flow": flow,
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
            flow=flow,
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
        flow: Optional[str] = None,
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
            "flow": flow,
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
            flow=flow,
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
        flow: Optional[str] = None,
        task: Optional[str] = None,
        subtask: Optional[str] = None,
    ) -> Dict[str, Any]:
        loaded = self._ensure_session(session)
        record = {
            "timestamp": utc_now(),
            "name": name,
            "kind": kind,
            "path": str(path) if path is not None else None,
            "flow": flow,
            "task": task,
            "subtask": subtask,
            "data": dict(data or {}),
        }
        loaded.artifacts.append(record)
        self.save(loaded)
        self._copy_back(session, loaded)
        self.trace_logger.log(
            session_id=loaded.session_id,
            flow=flow,
            task=task,
            subtask=subtask,
            status="succeeded",
            message=f"artifact:{name}",
            data=record,
        )
        return record

    def register_reconstruction_plan(
        self,
        session: ReverseSession | str,
        plan: Mapping[str, Any],
        *,
        project_dir: Optional[str | Path] = None,
        source_tool: str = "reconstruct_project",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Flow]:
        loaded = self._ensure_session(session)
        if not isinstance(plan, Mapping):
            return None

        existing = _find_flow(loaded, RECONSTRUCTION_FLOW_NAME)
        flow = _build_reconstruction_flow(
            plan,
            existing_flow=existing,
            project_dir=project_dir,
            source_tool=source_tool,
            metadata=metadata,
        )
        if flow is None:
            return None

        if existing is None:
            loaded.flows.append(flow)
        else:
            index = loaded.flows.index(existing)
            loaded.flows[index] = flow

        loaded.metadata["reconstruction"] = _reconstruction_flow_summary(flow)
        loaded.refresh_status_from_flows()
        self.save(loaded)
        self._copy_back(session, loaded)

        summary = _reconstruction_flow_summary(flow)
        summary["project_dir"] = str(project_dir) if project_dir is not None else None
        summary["source_tool"] = source_tool
        self.record_event(
            session,
            "reconstruction_plan_registered",
            message="reconstruction_plan_registered",
            flow=flow.name,
            status=flow.status.value,
            data=summary,
        )
        for task in flow.tasks:
            self.record_event(
                session,
                "reconstruction_task_registered",
                message="reconstruction_task_registered",
                flow=flow.name,
                task=task.name,
                status=task.status.value,
                data={
                    "module": task.metadata.get("module"),
                    "priority_score": task.metadata.get("priority_score"),
                    "subtask_count": len(task.subtasks),
                },
            )
            for subtask in task.subtasks:
                self.record_event(
                    session,
                    "reconstruction_subtask_registered",
                    message="reconstruction_subtask_registered",
                    flow=flow.name,
                    task=task.name,
                    subtask=subtask.name,
                    status=subtask.status.value,
                    data={
                        "module": subtask.metadata.get("module"),
                        "kind": subtask.metadata.get("kind"),
                        "function": subtask.metadata.get("function"),
                        "priority_score": subtask.metadata.get("priority_score"),
                    },
                )
        return flow

    def _ensure_session(self, session: ReverseSession | str) -> ReverseSession:
        return session if isinstance(session, ReverseSession) else self.load(session)

    @staticmethod
    def _copy_back(original: ReverseSession | str, loaded: ReverseSession) -> None:
        if isinstance(original, ReverseSession):
            original.target = loaded.target
            original.flows = loaded.flows
            original.status = loaded.status
            original.metadata = loaded.metadata
            original.events = loaded.events
            original.tool_calls = loaded.tool_calls
            original.artifacts = loaded.artifacts
            original.created_at = loaded.created_at
            original.updated_at = loaded.updated_at


def _find_flow(session: ReverseSession, name: str) -> Optional[Flow]:
    for flow in session.flows:
        if flow.name == name:
            return flow
    return None


def _build_reconstruction_flow(
    plan: Mapping[str, Any],
    *,
    existing_flow: Optional[Flow] = None,
    project_dir: Optional[str | Path] = None,
    source_tool: str = "reconstruct_project",
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Flow]:
    tasks_payload = plan.get("tasks")
    if not isinstance(tasks_payload, list):
        return None

    flow_metadata = dict(existing_flow.metadata if existing_flow is not None else {})
    flow_metadata.update(
        {
            "plan_status": plan.get("status") or flow_metadata.get("plan_status") or Status.PENDING.value,
            "project_dir": str(project_dir) if project_dir is not None else flow_metadata.get("project_dir"),
            "source_tool": source_tool,
        }
    )
    flow_metadata.update(dict(metadata or {}))
    flow = Flow(
        RECONSTRUCTION_FLOW_NAME,
        "Resumable source reconstruction work queue",
        status=_coerce_status((plan.get("status") or flow_metadata.get("plan_status") or Status.PENDING.value)),
        metadata=flow_metadata,
        created_at=str(plan.get("created_at") or getattr(existing_flow, "created_at", utc_now())),
        updated_at=str(plan.get("updated_at") or utc_now()),
    )

    task_snapshots = {task.name: task for task in existing_flow.tasks} if existing_flow is not None else {}
    for task_payload in tasks_payload:
        if not isinstance(task_payload, Mapping) or not task_payload.get("name"):
            continue
        existing_task = task_snapshots.get(str(task_payload["name"]))
        task = Task(
            name=str(task_payload["name"]),
            description=str(task_payload.get("description") or ""),
            status=_preserve_status(task_payload.get("status"), existing_task.status if existing_task else None),
            metadata=_merge_metadata(existing_task.metadata if existing_task else {}, task_payload.get("metadata")),
            result=getattr(existing_task, "result", None),
            error=getattr(existing_task, "error", None),
            created_at=str(task_payload.get("created_at") or getattr(existing_task, "created_at", utc_now())),
            updated_at=str(task_payload.get("updated_at") or getattr(existing_task, "updated_at", utc_now())),
        )

        subtask_snapshots = {subtask.name: subtask for subtask in existing_task.subtasks} if existing_task is not None else {}
        for subtask_payload in task_payload.get("subtasks") or []:
            if not isinstance(subtask_payload, Mapping) or not subtask_payload.get("name"):
                continue
            existing_subtask = subtask_snapshots.get(str(subtask_payload["name"]))
            task.subtasks.append(
                Subtask(
                    name=str(subtask_payload["name"]),
                    description=str(subtask_payload.get("description") or ""),
                    status=_preserve_status(subtask_payload.get("status"), existing_subtask.status if existing_subtask else None),
                    metadata=_merge_metadata(existing_subtask.metadata if existing_subtask else {}, subtask_payload.get("metadata")),
                    result=getattr(existing_subtask, "result", None),
                    error=getattr(existing_subtask, "error", None),
                    created_at=str(subtask_payload.get("created_at") or getattr(existing_subtask, "created_at", utc_now())),
                    updated_at=str(subtask_payload.get("updated_at") or getattr(existing_subtask, "updated_at", utc_now())),
                )
            )
        task.refresh_status_from_subtasks()
        flow.tasks.append(task)

    flow.refresh_status_from_tasks()
    flow.metadata.update(_reconstruction_flow_summary(flow))
    return flow


def _reconstruction_flow_summary(flow: Flow) -> Dict[str, Any]:
    completed_tasks = sum(1 for task in flow.tasks if task.status == Status.SUCCEEDED)
    subtask_count = sum(len(task.subtasks) for task in flow.tasks)
    completed_subtasks = sum(1 for task in flow.tasks for subtask in task.subtasks if subtask.status == Status.SUCCEEDED)
    next_task = flow.next_task()
    next_subtask = next_task.next_subtask() if next_task is not None else None
    return {
        "flow_name": flow.name,
        "flow_status": flow.status.value,
        "task_count": len(flow.tasks),
        "completed_task_count": completed_tasks,
        "pending_task_count": max(0, len(flow.tasks) - completed_tasks),
        "subtask_count": subtask_count,
        "completed_subtask_count": completed_subtasks,
        "next_task": next_task.name if next_task is not None else None,
        "next_subtask": next_subtask.name if next_subtask is not None else None,
    }


def _merge_metadata(existing: Any, incoming: Any) -> Dict[str, Any]:
    merged = dict(existing or {})
    if isinstance(incoming, Mapping):
        merged.update(dict(incoming))
    return merged


def _coerce_status(value: Any) -> Status:
    if isinstance(value, Status):
        return value
    try:
        return Status(str(value or Status.PENDING.value))
    except ValueError:
        return Status.PENDING


def _preserve_status(planned_status: Any, existing_status: Optional[Status]) -> Status:
    if existing_status in {Status.SUCCEEDED, Status.FAILED, Status.SKIPPED, Status.RUNNING}:
        return existing_status
    return _coerce_status(planned_status)
