"""Container-backed isolated worker runtime."""

from .worker import (
    SANDBOX_CONFIRMATION_PHRASE,
    SandboxLimits,
    SandboxWorker,
    detect_container_runtimes,
)

def detect_runtime() -> dict:
    """Compatibility summary used by environment and Web APIs."""
    report = detect_container_runtimes(probe=False)
    runtime = next((item for item in report["runtimes"] if item["available"]), None)
    return {"status": "available" if runtime else "dependency-gated", "runtime": runtime["name"] if runtime else None, "path": runtime["path"] if runtime else None, "reason": None if runtime else "docker or podman is not installed"}

__all__ = [
    "SANDBOX_CONFIRMATION_PHRASE",
    "SandboxLimits",
    "SandboxWorker",
    "detect_container_runtimes",
    "detect_runtime",
]
