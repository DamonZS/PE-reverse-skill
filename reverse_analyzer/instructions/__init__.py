"""Cross-platform instruction / identity deployment.

A platform-agnostic facility for deploying the branded topology instruction
bundle (激活词 拓扑 / AC) into any supported coding-agent's configuration.

The bundle content is platform-independent; only the *injection transport*
differs per platform:

* ``codex``      -- ``config.toml`` ``model_instructions_file``
* ``claude``     -- ``~/.claude/settings.json`` ``UserPromptSubmit`` hook
* ``cursor``     -- ``.cursor/rules/*.mdc`` ``alwaysApply`` rule
* ``workbuddy``  -- a triggerable ``topo-ac-unrestricted`` skill

Each adapter exposes the uniform ``PlatformAdapter`` interface (deploy /
inspect / restore / describe), and the registry dispatches requests to the
right concrete adapter.  Every write requires ``allowed=True`` (or ``force``)
and is atomic, confined to the target root, and reversible.
"""

from __future__ import annotations

from .adapter import (
    ALL_PLATFORMS,
    DeployPlan,
    EvidenceEntry,
    IDENTITY_SKILL,
    IDENTITY_WORD,
    INSTRUCTION_PROFILE,
    InstructionDeployError,
    Operation,
    PLATFORM_CLAUDE,
    PLATFORM_CODEX,
    PLATFORM_CURSOR,
    PLATFORM_WORKBUDDY,
    PlatformAdapter,
)
from .registry import (
    adapter_for,
    canonical_platform,
    deploy,
    inspect,
    list_platforms,
    platform_aliases,
    restore,
)

__all__ = [
    "ALL_PLATFORMS",
    "DeployPlan",
    "EvidenceEntry",
    "IDENTITY_SKILL",
    "IDENTITY_WORD",
    "INSTRUCTION_PROFILE",
    "InstructionDeployError",
    "Operation",
    "PLATFORM_CLAUDE",
    "PLATFORM_CODEX",
    "PLATFORM_CURSOR",
    "PLATFORM_WORKBUDDY",
    "PlatformAdapter",
    "adapter_for",
    "canonical_platform",
    "deploy",
    "inspect",
    "list_platforms",
    "platform_aliases",
    "restore",
]
