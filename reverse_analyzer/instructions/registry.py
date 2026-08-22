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

from .adapter import ALL_PLATFORMS, PLATFORM_CLAUDE, PLATFORM_CODEX, PLATFORM_CURSOR, PLATFORM_WORKBUDDY
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


def inspect(platform: str, target: str | None = None) -> Mapping[str, Any]:
    adapter = adapter_for(platform)
    return adapter.inspect(Path(target) if target else None)


def restore(platform: str, target: str | None = None) -> Mapping[str, Any]:
    adapter = adapter_for(platform)
    return adapter.restore(Path(target) if target else None)


__all__ = [
    "adapter_for",
    "canonical_platform",
    "deploy",
    "inspect",
    "list_platforms",
    "platform_aliases",
    "restore",
]
