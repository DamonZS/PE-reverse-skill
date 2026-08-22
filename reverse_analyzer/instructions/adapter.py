"""Cross-platform instruction/identity deployment adapter.

This module defines the *platform-agnostic* contract for deploying the
branded instruction bundle ("拓扑" / topo-ac-unrestricted) into a target
coding-agent's configuration, regardless of whether that agent is Codex,
Claude, Cursor, or a WorkBuddy skill.

The design mirrors the safety model of ``reverse_analyzer.codex``:

* No target is auto-discovered or walked into from a user profile.
* Writes require an explicit ``allowed=True`` confirmation (or a
  ``force`` override for a target the caller fully controls).
* Every write is atomic (temp file + rename) and reversible.
* A deploy records an evidence manifest with content-addressed relative
  paths, mirrors the existing ``codex-evidence-manifest.json`` contract.
* Paths are confined to the target root; ``..``, absolute escapes, and
  symlinks that resolve outside the root are rejected.

Instruction content is *platform-agnostic*: the only platform-bound line
("You are Codex, based on GPT-5.5 ...") is preserved verbatim as the
branded identity, while the activation word and behaviour rules apply
uniformly across all platforms.  The mechanism differs per platform ---
Codex uses ``model_instructions_file``, Claude uses a
``UserPromptSubmit`` hook's stdout, Cursor uses an ``alwaysApply`` rule,
and WorkBuddy uses a skill trigger --- which is exactly what each
concrete adapter in ``reverse_analyzer.instructions.platforms`` supplies.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

# Platform key constants (used by the registry and CLI).
PLATFORM_CODEX = "codex"
PLATFORM_CLAUDE = "claude"
PLATFORM_CURSOR = "cursor"
PLATFORM_WORKBUDDY = "workbuddy"

ALL_PLATFORMS: tuple[str, ...] = (
    PLATFORM_CODEX,
    PLATFORM_CLAUDE,
    PLATFORM_CURSOR,
    PLATFORM_WORKBUDDY,
)

# Canonical branded instruction profile (must stay byte-identical to the
# bundled topo-ac-unrestricted.md / gpt5.5-unrestricted.md asset).
INSTRUCTION_PROFILE = "topo-ac-unrestricted"

# Single source of truth for the branded identity + activation word.
IDENTITY_WORD = "拓扑"
IDENTITY_SKILL = "topo-identity"
AC_SKILL = "ac"
ACTIVATION_WORD = "AC"  # behaviourally used on all platforms.


class InstructionDeployError(ValueError):
    """Raised when a cross-platform deploy is not permitted or fails."""


@dataclass(frozen=True)
class DeployPlan:
    """A concrete, ordered plan of readonly file operations (no side effects).

    A ``DeployPlan`` lists what an adapter *would* write, plus the evidence
    entries (relative path, SHA-256, size, provenance) that a real deploy
    would record.  It never mutates the filesystem itself; it is the
    ``describe``/``dry_run`` output.
    """

    platform: str
    target: str
    operations: tuple["Operation", ...] = ()
    evidence: tuple["EvidenceEntry", ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "platform": self.platform,
            "target": self.target,
            "operations": [op.to_dict() for op in self.operations],
            "evidence": [entry.to_dict() for entry in self.evidence],
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class Operation:
    """A single planned write: create, modify, or backup."""

    rel_path: str
    kind: str  # "create" | "modify" | "backup"
    description: str = ""
    sha256: str = ""
    size: int = 0
    backup: str = ""

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "rel_path": self.rel_path,
            "kind": self.kind,
            "description": self.description,
            "sha256": self.sha256,
            "size": self.size,
            "backup": self.backup,
        }


@dataclass(frozen=True)
class EvidenceEntry:
    """A single content-addressed record for the evidence manifest."""

    rel_path: str
    sha256: str
    size: int
    kind: str = "file"
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "rel_path": self.rel_path,
            "sha256": self.sha256,
            "size": self.size,
            "kind": self.kind,
            "provenance": dict(self.provenance),
        }


class PlatformAdapter(ABC):
    """Interface every platform-specific injector / inspector implements."""

    platform: str  # one of ALL_PLATFORMS

    @abstractmethod
    def default_target(self) -> Path:
        """Return the conventional config root for this platform on this host."""

    @abstractmethod
    def describe(self, target: Path | None = None) -> DeployPlan:
        """Return a readonly preview (no writes) of what a deploy would do."""

    @abstractmethod
    def inspect(self, target: Path | None = None) -> Mapping[str, Any]:
        """Read-only detection of whether the branded instruction is present."""

    @abstractmethod
    def deploy(
        self,
        target: Path | None = None,
        *,
        allowed: bool = False,
        force: bool = False,
        dry_run: bool = False,
        instruction_profile: str = INSTRUCTION_PROFILE,
    ) -> Mapping[str, Any]:
        """Deploy (or, when ``dry_run``, preview) the instruction bundle.

        ``allowed`` must be True for any write to proceed.  ``force`` opts
        into a deploy for a target the caller fully controls, even when it
        lacks the usual config markers.
        """

    @abstractmethod
    def restore(self, target: Path | None = None) -> Mapping[str, Any]:
        """Reverse a prior deploy using the recorded evidence manifest."""


# ---------------------------------------------------------------------------
# Shared, platform-agnostic helpers (atomic write, confine, digest, backup).
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_str(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    """Write bytes via a temp file + rename (atomic, crash-safe)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def confine(root: Path, path: Path, *, enforce: bool = True) -> Path:
    """Resolve ``path`` under ``root``, rejecting escape / symlink leaks.

    When ``enforce`` is False (research mode) the absolute/escape check is
    skipped; never point a production deploy at a path outside the root.
    """
    if enforce:
        if path.is_absolute():
            raise InstructionDeployError(
                f"refusing absolute deployment path outside root: {path}"
            )
        candidate = (root / path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError as exc:
            raise InstructionDeployError(
                f"deployment path escapes target root: {path}"
            ) from exc
        return candidate
    return (root / path).resolve()


def backup_existing(root: Path, rel_path: str, *, enforce: bool = True) -> str:
    """Move an existing file aside (under ``.backup/``) and return its rel path.

    If the source does not exist, returns empty string.  The caller is
    responsible for invoking ``atomic_write`` afterwards; this helper only
    preserves the prior state.
    """
    source = confine(root, Path(rel_path), enforce=enforce)
    if not source.is_file():
        return ""
    digest = sha256_file(source)[:12]
    backup_rel = f".backup/{rel_path}.{digest}.bkp"
    backup = confine(root, Path(backup_rel), enforce=enforce)
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, backup)
    return backup_rel


def read_text_optional(path: Path) -> str:
    """Read UTF-8 text, returning "" when the file is absent."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


__all__ = [
    "AC_SKILL",
    "ACTIVATION_WORD",
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
    "atomic_write",
    "backup_existing",
    "confine",
    "read_text_optional",
    "sha256_bytes",
    "sha256_file",
    "sha256_str",
]
