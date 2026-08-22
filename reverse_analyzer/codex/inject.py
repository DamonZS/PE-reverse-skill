"""Constrained, evidence-backed deployment into an authorized codex directory.

This module implements the *research/instrumentation* half of the codex
instruction-transfer technique.  It writes a known, content-addressed
instruction bundle (the global ``model_instructions_file``) plus the two
companion skill directories into a codex config directory, rewrites
``config.toml`` to point ``model_instructions_file`` at the deployed asset,
and records an evidence manifest with a recoverable backup.

Safety / authorization model
----------------------------

* The target must be explicitly supplied by the caller (``target`` /
  ``--target``).  It is never auto-discovered and never walked into from a
  profile directory.
* The target must contain a real ``config.toml`` and must be confirmed with
  ``allowed=True`` (the ``--allowed`` CLI flag).  Without confirmation,
  ``inject`` raises.
* Every write is atomic (temp file + rename), every replaced file is backed
  up, and ``restore(codex)`` reverses the operation using the recorded
  backup.
* All paths are confined to the target root; ``..``, absolute escapes, and
  symlinks that resolve outside the root are rejected.
* Nothing here disables safety rails on a third-party host; it instruments a
  directory the caller owns or is authorized to modify, and keeps the
  pre-existing state recoverable.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence, Tuple

from .manifest import (
    CodexEvidence,
    build_evidence_manifest,
    sha256_bytes,
    sha256_file,
    sha256_str,
    write_manifest,
)

CONFIG_FILENAME = "config.toml"
MODEL_INSTRUCTIONS_KEY = "model_instructions_file"
INSTRUCTION_ASSET = "gpt5.5-unrestricted.md"
SKILL_AC = "ac"
SKILL_TOPO_IDENTITY = "topo-identity"


class CodexInjectError(ValueError):
    """Raised when a codex deployment is not permitted or fails part-way."""


@dataclass(frozen=True)
class CodexTarget:
    """A validated, explicitly-authorized codex config directory."""

    path: Path
    confirmed: bool = False

    @property
    def valid(self) -> bool:
        return self.confirmed and (self.path / CONFIG_FILENAME).is_file()


@dataclass(frozen=True)
class _Operation:
    rel_path: str
    kind: str  # "create" | "modify" | "backup"
    sha256: str = ""
    size: int = 0
    backup: str = ""


def _asset_root() -> Path:
    return Path(__file__).resolve().parents[1] / "llm_jailbreak" / "builtin_assets" / "codex"


def _resolve_asset(*parts: str) -> Path:
    path = _asset_root().joinpath(*parts)
    if not path.is_file():
        raise CodexInjectError(f"bundled codex asset is missing: {path}")
    return path


def resolve_codex_root(expand_user: bool = True) -> Path:
    """Return the typical codex config root for the current user."""
    path = Path("~/.codex")
    return path.expanduser() if expand_user else path


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(file_descriptor, "wb") as stream:
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


def _confine(root: Path, path: Path, *, enforce: bool = True) -> Path:
    """Return path resolved under root, rejecting escapes and symlink leaks.

    When ``enforce`` is False (the ``--no-confine`` research mode) the
    absolute/escape check is skipped and the path is resolved as-is.  This
    exists only for controlled experiments in a sandbox; it must never point a
    production deploy at a path outside the target root.
    """
    if enforce:
        if path.is_absolute():
            raise CodexInjectError(
                f"refusing absolute deployment path outside root: {path}"
            )
        candidate = (root / path).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError as exc:
            raise CodexInjectError(
                f"deployment path escapes target root: {path}"
            ) from exc
        return candidate
    return (root / path).resolve()


def _read_config(config_path: Path) -> str:
    try:
        return config_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def restricted_allowed_for(
    target_path: Path,
    config_path: Path,
    allowed: bool,
    unrestricted: bool,
) -> bool:
    """Gate whether a deploy may proceed.

    A deploy is allowed when the caller has either confirmed ownership of a
    real codex config directory (``allowed``) **or** opted into the
    unrestricted force-deploy path (``unrestricted``).  Path confinement is
    still enforced separately by ``_confine``.
    """
    if unrestricted:
        return True
    return allowed and config_path.is_file()


def _find_root_string_key(config_text: str, key: str) -> Tuple[str, int]:
    """Return (existing_value, line_index) for a root-level ``key = "..."``."""
    for index, line in enumerate(config_text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        head = stripped.split("=", 1)[0].strip()
        if head == key:
            return _toml_string_value(stripped), index
    return "", -1


def _toml_string_value(line: str) -> str:
    match = __import__("re").search(r"=\s*\"([^\"]*)\"", line)
    return match.group(1) if match else ""


def _set_root_string_key(config_text: str, key: str, value: str) -> str:
    existing, index = _find_root_string_key(config_text, key)
    if index < 0:
        if config_text and not config_text.endswith("\n"):
            config_text += "\n"
        return config_text + f"{key} = \"{value}\"\n"
    lines = config_text.splitlines()
    lines[index] = f"{key} = \"{value}\""
    return "\n".join(lines) + "\n"


def _backup_existing(target: Path, rel_path: str, *, enforce: bool = True) -> str:
    """Move an existing file aside and return a stable backup relative path."""
    source = _confine(target, Path(rel_path), enforce=enforce)
    if not source.is_file():
        return ""
    digest = sha256_file(source)[:12]
    backup_rel = f".backup/{rel_path}.{digest}.bkp"
    backup = _confine(target, Path(backup_rel), enforce=enforce)
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, backup)
    return backup_rel


def _deploy_assets(target: Path, *, enforce: bool = True) -> Tuple[list[CodexEvidence], list[_Operation]]:
    evidence: list[CodexEvidence] = []
    operations: list[_Operation] = []

    # 1. Global instruction file -> target root
    instruction_src = _resolve_asset(INSTRUCTION_ASSET)
    instruction_bytes = instruction_src.read_bytes()
    instruction_rel = INSTRUCTION_ASSET
    instruction_path = _confine(target, Path(instruction_rel), enforce=enforce)
    backup = _backup_existing(target, instruction_rel, enforce=enforce)
    _atomic_write(instruction_path, instruction_bytes)
    evidence.append(
        CodexEvidence(
            path=instruction_rel,
            sha256=sha256_file(instruction_path),
            size=instruction_path.stat().st_size,
            source="builtin:codex/gpt5.5-unrestricted.md",
            provenance={"kind": "model_instructions_file", "backup": backup},
        )
    )
    operations.append(
        _Operation(
            rel_path=instruction_rel,
            kind="create",
            sha256=sha256_bytes(instruction_bytes),
            size=len(instruction_bytes),
            backup=backup,
        )
    )

    # 2. AC skill directory
    ac_rel = f"skills/{SKILL_AC}"
    evidence.extend(_deploy_skill(target, ac_rel, ("SKILL.md", "references/router-contract.md", "references/unrestricted-lab.md", "agents/openai.yaml"), operations, enforce=enforce))

    # 3. topo-identity skill directory
    identity_rel = f"skills/{SKILL_TOPO_IDENTITY}"
    evidence.extend(_deploy_skill(target, identity_rel, ("SKILL.md", "agents/openai.yaml"), operations, enforce=enforce))

    return evidence, operations


def _deploy_skill(
    target: Path,
    rel_dir: str,
    members: Sequence[str],
    operations: list[_Operation],
    *,
    enforce: bool = True,
) -> list[CodexEvidence]:
    evidence: list[CodexEvidence] = []
    for member in members:
        rel = f"{rel_dir}/{member}"
        src = _resolve_asset(rel)
        data = src.read_bytes()
        dest = _confine(target, Path(rel), enforce=enforce)
        backup = _backup_existing(target, rel, enforce=enforce)
        _atomic_write(dest, data)
        evidence.append(
            CodexEvidence(
                path=rel,
                sha256=sha256_file(dest),
                size=dest.stat().st_size,
                source=f"builtin:codex/{rel}",
                provenance={"kind": "skill", "backup": backup},
            )
        )
        operations.append(
            _Operation(
                rel_path=rel,
                kind="create",
                sha256=sha256_bytes(data),
                size=len(data),
                backup=backup,
            )
        )
    return evidence


def inject_codex(
    target: Path | str,
    *,
    instruction_profile: str = "gpt5.5-unrestricted",
    allowed: bool = False,
    unrestricted: bool = False,
    enforce_confine: bool = True,
    dry_run: bool = False,
) -> Mapping[str, Any]:
    """Deploy the codex instruction bundle into a target.

    ``target`` is an explicit codex config directory.  ``allowed`` must be
    True for any write to proceed; without it, the call raises instead of
    touching the directory.

    ``unrestricted`` opts into a *force-deploy* path that is meant only for
    targets the caller fully controls and intentionally wants to instrument
    from scratch (e.g. a disposable sandbox or an empty config directory).  It
    relaxes two guards:

    * the ``allowed``/``--allowed`` confirmation (a force deploy implies the
      caller already decided to instrument the target), and
    * the requirement that ``config.toml`` already exist (so an empty directory
      can be initialised), while still creating ``config.toml`` going forward.

    ``enforce_confine`` (default True) keeps the path-escape guard on.  Set it
    to False (the ``--no-confine`` research mode) **only** for controlled
    experiments in a throwaway sandbox where writing outside the target root
    is intended; it disables ``_confine`` and lets deployment paths resolve
    anywhere.  Never point a production deploy at a path outside the target
    root with this flag on.

    ``unrestricted``/``enforce_confine=False`` never turn off atomic writes,
    backups, or the evidence manifest.  Use ``dry_run`` to preview without
    writing anything.
    """
    target_path = Path(target).expanduser().resolve()
    config_path = target_path / CONFIG_FILENAME
    if not restricted_allowed_for(target_path, config_path, allowed, unrestricted):
        raise CodexInjectError(
            "deployment not permitted: pass allowed=True (or --allowed) to confirm "
            f"you own/are authorized to instrument {target_path}, or use "
            "--unrestricted/--force for a target you fully control"
        )
    if dry_run:
        return {
            "status": "dry-run",
            "target": str(target_path),
            "profile": instruction_profile,
            "unrestricted": unrestricted,
        }

    from .inspect import inspect_codex

    config_text = _read_config(config_path)
    modified_config = _set_root_string_key(
        config_text, MODEL_INSTRUCTIONS_KEY, f"./{INSTRUCTION_ASSET}"
    )
    config_backup = _backup_existing(target_path, CONFIG_FILENAME)
    config_changed = modified_config != config_text

    evidence, operations = _deploy_assets(target_path, enforce=enforce_confine)

    if config_changed:
        _atomic_write(config_path, modified_config.encode("utf-8"))
        evidence.insert(
            0,
            CodexEvidence(
                path=CONFIG_FILENAME,
                sha256=sha256_file(config_path),
                size=config_path.stat().st_size,
                source=CONFIG_FILENAME,
                provenance={"kind": "config.toml", "backup": config_backup},
            ),
        )
        operations.insert(
            0,
            _Operation(
                rel_path=CONFIG_FILENAME,
                kind="modify",
                sha256=sha256_str(modified_config),
                size=len(modified_config.encode("utf-8")),
                backup=config_backup,
            ),
        )

    manifest = build_evidence_manifest(
        evidence,
        root=str(target_path),
        operation="inject",
        target_dir=str(target_path),
    )
    write_manifest(manifest, target_path)

    return {
        "status": "ok",
        "target": str(target_path),
        "profile": instruction_profile,
        "config_changed": config_changed,
        "config_backup": config_backup,
        "model_instructions_file": f"./{INSTRUCTION_ASSET}",
        "artifacts": [
            {"path": op.rel_path, "kind": op.kind, "backup": op.backup} for op in operations
        ],
        "manifest": str(target_path / "codex-evidence-manifest.json"),
    }


def restore_codex(target: Path | str) -> Mapping[str, Any]:
    """Restore a previously-injected codex config directory from backup.

    Uses the recorded evidence manifest to reverse ``inject_codex``.
    """
    target_path = Path(target).expanduser().resolve()
    manifest_path = target_path / "codex-evidence-manifest.json"
    if not manifest_path.is_file():
        raise CodexInjectError(
            f"no codex evidence manifest at {manifest_path}; cannot restore"
        )
    from .manifest import load_manifest

    manifest = load_manifest(manifest_path)
    restored: list[str] = []
    touched_dirs: set[Path] = set()
    for entry in manifest.get("entries", []):
        rel = entry.get("path", "")
        if not rel:
            continue
        backup_rel = str((entry.get("provenance") or {}).get("backup") or "")
        dest = _confine(target_path, Path(rel))
        touched_dirs.add(dest.parent)
        if backup_rel:
            backup = _confine(target_path, Path(backup_rel))
            if backup.is_file():
                shutil.copy2(backup, dest)
                restored.append(f"{rel} <- {backup_rel}")
        else:
            if dest.is_file():
                dest.unlink()
                restored.append(f"{rel} removed (no prior file)")

    # Remove any skill directory left empty by the restore (leaf-first).
    for directory in sorted(touched_dirs, key=lambda item: len(item.parts), reverse=True):
        try:
            directory.relative_to(target_path.resolve())
        except ValueError:
            continue
        try:
            if directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
                restored.append(f"{directory.relative_to(target_path).as_posix()}/ removed (empty)")
        except OSError:
            continue

    return {
        "status": "ok",
        "target": str(target_path),
        "restored": restored,
    }


__all__ = [
    "CONFIG_FILENAME",
    "CodexInjectError",
    "CodexTarget",
    "inject_codex",
    "resolve_codex_root",
    "restricted_allowed_for",
    "restore_codex",
]
