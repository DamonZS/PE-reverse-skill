"""Bounded local job runner for Web-created experiments."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any

from reverse_analyzer.storage import create_experiment_store
from reverse_analyzer.web_events import WebEventLog


CONFIRMATION_PHRASE = "EXECUTE_LOCAL_ANALYSIS"


@dataclass
class _RunningJob:
    experiment_id: str
    process: subprocess.Popen[str]
    started_at: float
    cancel_requested: threading.Event = field(default_factory=threading.Event)


class WebJobManager:
    """Execute existing deterministic experiment commands under explicit consent."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        event_log: WebEventLog | None = None,
        python_executable: str | Path | None = None,
        timeout_seconds: int = 3600,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        self.store = create_experiment_store(self.workspace)
        self.event_log = event_log or WebEventLog(self.workspace)
        self.python_executable = str(python_executable or sys.executable)
        self.timeout_seconds = max(1, int(timeout_seconds))
        self._running: dict[str, _RunningJob] = {}
        self._lock = threading.Lock()

    def recover_stale_running(self) -> list[dict[str, Any]]:
        recovered: list[dict[str, Any]] = []
        for record in self.store.list():
            if record.get("status") != "running":
                continue
            updated = self.store.record_result(
                record["id"],
                status="failed",
                error="server restarted while this Web job was marked running",
            )
            self.event_log.append(
                record["id"],
                "recovered",
                status="failed",
                message="服务重启后恢复到失败状态",
            )
            recovered.append(updated)
        return recovered

    def execute(self, experiment_id: str, *, confirmation: str | bool | None = None) -> dict[str, Any]:
        if confirmation not in (True, CONFIRMATION_PHRASE):
            raise PermissionError(f"execution requires confirmation={CONFIRMATION_PHRASE!r}")
        record = self.store.get(experiment_id)
        if record["status"] not in {"queued", "planned"}:
            raise ValueError("only queued or planned experiments can be executed")
        with self._lock:
            if experiment_id in self._running:
                raise ValueError("experiment is already running")
            if record["status"] == "queued":
                record = self.store.set_status(experiment_id, "planned", detail="web execution confirmed")
                self.event_log.append(experiment_id, "planned", status="planned", message="已确认执行，进入计划状态")
            command = self.store.build_analysis_command(experiment_id, python_executable=self.python_executable)
            record = self.store.set_status(experiment_id, "running", detail={"command": command, "source": "web"})
            process = subprocess.Popen(
                command,
                cwd=str(self.workspace),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            job = _RunningJob(experiment_id=experiment_id, process=process, started_at=time.monotonic())
            self._running[experiment_id] = job
            self.event_log.append(
                experiment_id,
                "started",
                status="running",
                message="本地分析进程已启动",
                data={"command": command, "pid": process.pid},
            )
            thread = threading.Thread(target=self._monitor, args=(job,), daemon=True)
            thread.start()
            return {"experiment": record, "pid": process.pid, "running": True}

    def cancel(self, experiment_id: str) -> dict[str, Any]:
        record = self.store.get(experiment_id)
        with self._lock:
            job = self._running.get(experiment_id)
            if job is not None:
                job.cancel_requested.set()
                job.process.terminate()
                self.event_log.append(experiment_id, "cancel_requested", status="running", message="已请求取消")
                return {"experiment": record, "cancel_requested": True}
        if record["status"] in {"queued", "planned"}:
            updated = self.store.set_status(experiment_id, "cancelled", detail="cancelled before execution")
            self.event_log.append(experiment_id, "cancelled", status="cancelled", message="任务已在执行前取消")
            return {"experiment": updated, "cancel_requested": False}
        raise ValueError("only queued, planned, or running experiments can be cancelled")

    def retry(self, experiment_id: str) -> dict[str, Any]:
        record = self.store.get(experiment_id)
        if record["status"] not in {"failed", "cancelled"}:
            raise ValueError("only failed or cancelled experiments can be retried")
        new_record = self.store.create(
            record["sample"],
            options=record.get("options") or {},
            metadata={**dict(record.get("metadata") or {}), "retry_of": experiment_id, "source": "web-console"},
        )
        self.event_log.append(
            new_record["id"],
            "retry_created",
            status="queued",
            message="已从失败或取消任务创建重试计划",
            data={"retry_of": experiment_id},
        )
        return {"experiment": new_record, "retry_of": experiment_id}

    def is_running(self, experiment_id: str) -> bool:
        with self._lock:
            return experiment_id in self._running

    def _monitor(self, job: _RunningJob) -> None:
        output_tail: list[str] = []
        timed_out = False
        assert job.process.stdout is not None
        try:
            while True:
                if time.monotonic() - job.started_at > self.timeout_seconds:
                    timed_out = True
                    job.cancel_requested.set()
                    job.process.terminate()
                    self.event_log.append(
                        job.experiment_id,
                        "timeout",
                        status="running",
                        message=f"超过 {self.timeout_seconds} 秒限制，已终止",
                    )
                    break
                line = job.process.stdout.readline()
                if line:
                    clean = line.rstrip()
                    output_tail.append(clean)
                    output_tail = output_tail[-200:]
                    self.event_log.append(job.experiment_id, "output", status="running", message=clean)
                    continue
                if job.process.poll() is not None:
                    break
                time.sleep(0.1)
            return_code = job.process.wait(timeout=5)
        except Exception as exc:  # pragma: no cover - defensive process cleanup
            return_code = -1
            output_tail.append(str(exc))
            self.event_log.append(job.experiment_id, "error", status="failed", message=str(exc))
        finally:
            try:
                job.process.stdout.close()
            except Exception:
                pass
            with self._lock:
                self._running.pop(job.experiment_id, None)

        if job.cancel_requested.is_set() and not timed_out:
            updated = self.store.record_result(
                job.experiment_id,
                status="cancelled",
                summary={"return_code": return_code, "stdout_tail": output_tail[-25:]},
            )
            self.event_log.append(job.experiment_id, "cancelled", status="cancelled", message="任务已取消")
            return
        if return_code == 0:
            artifacts = self._collect_artifacts(job.experiment_id)
            self.store.record_result(
                job.experiment_id,
                status="completed",
                artifacts=artifacts,
                summary={"return_code": return_code, "stdout_tail": output_tail[-25:]},
            )
            self.event_log.append(
                job.experiment_id,
                "completed",
                status="completed",
                message="分析任务已完成",
                data={"artifact_count": len(artifacts)},
            )
            return
        self.store.record_result(
            job.experiment_id,
            status="failed",
            summary={"return_code": return_code, "stdout_tail": output_tail[-25:]},
            error="analysis process timed out" if timed_out else f"analysis process exited with {return_code}",
        )
        self.event_log.append(
            job.experiment_id,
            "failed",
            status="failed",
            message="分析任务失败",
            data={"return_code": return_code, "timed_out": timed_out},
        )

    def _collect_artifacts(self, experiment_id: str) -> list[dict[str, Any]]:
        output_dir = self.workspace / "experiments" / experiment_id / "analysis"
        if not output_dir.is_dir():
            return []
        artifacts: list[dict[str, Any]] = []
        for path in sorted(output_dir.rglob("*")):
            if not path.is_file() or len(artifacts) >= 200:
                continue
            try:
                relative = path.resolve().relative_to(self.workspace).as_posix()
            except ValueError:
                continue
            artifacts.append({"path": relative, "name": path.name, "size": path.stat().st_size})
        return artifacts


__all__ = ["CONFIRMATION_PHRASE", "WebJobManager"]
