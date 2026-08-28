"""Registry dispatching cross-platform instruction deployment.

The registry is the single entry point for operating on any of the supported
platforms.  It exposes the uniform verbs --- ``list_platforms``,
``adapter_for``, plus ``deploy`` / ``inspect`` / ``restore`` -- each of which
routes to the matching concrete ``PlatformAdapter``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .adapter import ALL_PLATFORMS, InstructionDeployError, PLATFORM_CLAUDE, PLATFORM_CODEX, PLATFORM_CURSOR, PLATFORM_WORKBUDDY
from .platforms import (
    ClaudeAdapter,
    CodexAdapter,
    CursorAdapter,
    WorkBuddyAdapter,
)

_ADAPTERS: dict[str, Any] = {
    PLATFORM_CODEX: CodexAdapter(),
    PLATFORM_CLAUDE: ClaudeAdapter(),
    PLATFORM_CURSOR: CursorAdapter(),
    PLATFORM_WORKBUDDY: WorkBuddyAdapter(),
}

_CANONICAL_NAMES: dict[str, str] = {
    PLATFORM_CODEX: PLATFORM_CODEX,
    "codex-cli": PLATFORM_CODEX,
    PLATFORM_CLAUDE: PLATFORM_CLAUDE,
    "claude-code": PLATFORM_CLAUDE,
    "claude-desktop": PLATFORM_CLAUDE,
    PLATFORM_CURSOR: PLATFORM_CURSOR,
    "trea": PLATFORM_CURSOR,  # Trea is an alias for Cursor (per user decision)
    PLATFORM_WORKBUDDY: PLATFORM_WORKBUDDY,
    "workbuddy-skill": PLATFORM_WORKBUDDY,
}


def list_platforms() -> tuple[str, ...]:
    return ALL_PLATFORMS


def platform_aliases() -> Mapping[str, str]:
    return dict(_CANONICAL_NAMES)


def canonical_platform(name: str) -> str:
    key = (name or "").strip().casefold()
    canonical = _CANONICAL_NAMES.get(key)
    if canonical is None:
        raise ValueError(
            f"unknown platform {name!r}; available platforms: {', '.join(ALL_PLATFORMS)}"
        )
    return canonical


def adapter_for(name: str):
    canonical = canonical_platform(name)
    return _ADAPTERS[canonical]


def deploy(
    platform: str,
    target: str | None = None,
    *,
    allowed: bool = False,
    force: bool = False,
    dry_run: bool = False,
) -> Mapping[str, Any]:
    adapter = adapter_for(platform)
    return adapter.deploy(Path(target) if target else None, allowed=allowed, force=force, dry_run=dry_run)


def deploy_all(
    *,
    allowed: bool = False,
    force: bool = False,
    dry_run: bool = False,
) -> Mapping[str, Any]:
    """Deploy (or, when ``dry_run``, preview) the instruction bundle to every
    supported platform via its default target, in canonical order.

    Each platform is handled independently.  A ``allowed``/``force`` failure on
    one platform does not abort the rest; any error is captured per platform
    and reported in the per-platform result map.
    """
    results: dict[str, Any] = {}
    for name in ALL_PLATFORMS:
        adapter = adapter_for(name)
        try:
            results[name] = adapter.deploy(
                None, allowed=allowed, force=force, dry_run=dry_run
            )
        except InstructionDeployError as exc:
            results[name] = {
                "platform": name,
                "status": "error",
                "error": str(exc),
            }
    return {"results": results}


def inspect(platform: str, target: str | None = None) -> Mapping[str, Any]:
    adapter = adapter_for(platform)
    return adapter.inspect(Path(target) if target else None)


def inspect_all() -> Mapping[str, Any]:
    """Read-only scan of every supported platform via its default target."""
    results: dict[str, Any] = {}
    for name in ALL_PLATFORMS:
        adapter = adapter_for(name)
        try:
            results[name] = adapter.inspect(None)
        except InstructionDeployError as exc:
            results[name] = {"platform": name, "status": "error", "error": str(exc)}
    return {"results": results}


def restore(platform: str, target: str | None = None) -> Mapping[str, Any]:
    adapter = adapter_for(platform)
    return adapter.restore(Path(target) if target else None)


def restore_all() -> Mapping[str, Any]:
    """Restore every supported platform via its default target."""
    results: dict[str, Any] = {}
    for name in ALL_PLATFORMS:
        adapter = adapter_for(name)
        try:
            results[name] = adapter.restore(None)
        except InstructionDeployError as exc:
            results[name] = {
                "platform": name,
                "status": "error",
                "error": str(exc),
            }
    return {"results": results}


__all__ = [
    "adapter_for",
    "canonical_platform",
    "deploy",
    "deploy_all",
    "inspect",
    "inspect_all",
    "list_platforms",
    "platform_aliases",
    "restore",
    "restore_all",
]
