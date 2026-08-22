"""Concrete platform adapters for cross-platform instruction deployment."""

from __future__ import annotations

from .codex import CodexAdapter, codex_default_target
from .claude import ClaudeAdapter, claude_default_target
from .cursor import CursorAdapter, cursor_default_target
from .workbuddy import WorkBuddyAdapter, workbuddy_default_target

__all__ = [
    "ClaudeAdapter",
    "CodexAdapter",
    "CursorAdapter",
    "WorkBuddyAdapter",
    "claude_default_target",
    "codex_default_target",
    "cursor_default_target",
    "workbuddy_default_target",
]
