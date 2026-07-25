"""Bounded Docker/Podman worker with an explicit execution boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess
from typing import Any, Sequence


SANDBOX_CONFIRMATION_PHRASE = "EXECUTE_ISOLATED_WORKER"
_MAX_OUTPUT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SandboxLimits:
    cpus: float = 1.0
    memory_mb: int = 1024
    pids: int = 256
    timeout_seconds: int = 300
    network: bool = False

    def validate(self) -> None:
        if self.cpus <= 0 or self.cpus > 32:
            raise ValueError("cpus must be greater than 0 and at most 32")
        if self.memory_mb < 128 or self.memory_mb > 131072:
            raise ValueError("memory_mb must be between 128 and 131072")
        if self.pids < 16 or self.pids > 4096:
            raise ValueError("pids must be between 16 and 4096")
        if self.timeout_seconds < 1 or self.timeout_seconds > 86400:
            raise ValueError("timeout_seconds must be between 1 and 86400")


def detect_container_runtimes(*, probe: bool = True) -> dict[str, Any]:
    runtimes = []
    for name in ("docker", "podman"):
        executable = shutil.which(name)
        item: dict[str, Any] = {
            "name": name,
            "available": bool(executable),
            "path": executable,
            "verified": False,
            "version": None,
        }
        if executable and probe:
            try:
                completed = subprocess.run(
                    [executable, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                item["verified"] = completed.returncode == 0
                item["version"] = _bounded_text(completed.stdout or completed.stderr, 4096).strip()
            except (OSError, subprocess.TimeoutExpired) as exc:
                item["error"] = f"{type(exc).__name__}: {exc}"
        runtimes.append(item)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "probe": probe,
        "available": any(item["available"] for item in runtimes),
        "verified": any(item["verified"] for item in runtimes),
        "runtimes": runtimes,
        "execution_boundary": "runtime discovery only; no container or target is started",
    }


class SandboxWorker:
    def __init__(
        self,
        *,
        runtime: str,
        image: str,
        workspace: str | Path,
        limits: SandboxLimits | None = None,
    ):
        if runtime not in {"docker", "podman"}:
            raise ValueError("runtime must be docker or podman")
        if not str(image).strip():
            raise ValueError("image is required")
        self.runtime = runtime
        self.image = str(image).strip()
        self.workspace = Path(workspace).resolve()
        self.limits = limits or SandboxLimits()
        self.limits.validate()

    def plan(self, command: Sequence[str]) -> dict[str, Any]:
        if not command or any(not isinstance(part, str) or not part for part in command):
            raise ValueError("command must contain non-empty string arguments")
        if not self.workspace.is_dir():
            raise ValueError("workspace must be an existing directory")
        executable = shutil.which(self.runtime)
        argv = [
            executable or self.runtime,
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.limits.pids),
            "--cpus",
            str(self.limits.cpus),
            "--memory",
            f"{self.limits.memory_mb}m",
            "--network",
            "bridge" if self.limits.network else "none",
            "--mount",
            f"type=bind,src={self.workspace},dst=/workspace,readonly",
            "--workdir",
            "/workspace",
            self.image,
            *command,
        ]
        return {
            "runtime": self.runtime,
            "runtime_path": executable,
            "runtime_available": bool(executable),
            "image": self.image,
            "workspace": str(self.workspace),
            "command": list(command),
            "argv": argv,
            "limits": asdict(self.limits),
            "dry_run": True,
            "executed": False,
            "execution_boundary": (
                "plan only; execution requires execute=True and the exact confirmation phrase"
            ),
        }

    def run(
        self,
        command: Sequence[str],
        *,
        execute: bool = False,
        confirmation: str | None = None,
    ) -> dict[str, Any]:
        plan = self.plan(command)
        if not execute:
            return plan
        if confirmation != SANDBOX_CONFIRMATION_PHRASE:
            raise PermissionError(
                f"isolated execution requires confirmation={SANDBOX_CONFIRMATION_PHRASE}"
            )
        if not plan["runtime_available"]:
            raise RuntimeError(f"{self.runtime} runtime is not available")
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            completed = subprocess.run(
                plan["argv"],
                capture_output=True,
                timeout=self.limits.timeout_seconds,
                check=False,
            )
            return {
                **plan,
                "dry_run": False,
                "executed": True,
                "status": "ok" if completed.returncode == 0 else "failed",
                "returncode": completed.returncode,
                "stdout": _bounded_bytes(completed.stdout),
                "stderr": _bounded_bytes(completed.stderr),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }
        except subprocess.TimeoutExpired as exc:
            return {
                **plan,
                "dry_run": False,
                "executed": True,
                "status": "timed_out",
                "returncode": None,
                "stdout": _bounded_bytes(exc.stdout),
                "stderr": _bounded_bytes(exc.stderr),
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
            }


def _bounded_bytes(value: bytes | str | None) -> str:
    if value is None:
        return ""
    data = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    truncated = len(data) > _MAX_OUTPUT_BYTES
    text = data[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
    return text + ("\n[output truncated]" if truncated else "")


def _bounded_text(value: str, limit: int) -> str:
    return value[:limit] + ("\n[output truncated]" if len(value) > limit else "")
