"""Evidence-aware Codex configuration auditing and constrained deployment.

This subpackage implements the *defensive and research* half of the
"Codex instruction-transfer" technique: it can detect whether a local codex
config directory has been re-pointed at a third-party global instruction file
(``model_instructions_file``) and whether unexpected skills / activation
words have been planted, then (under an explicit, scoped target and a
confirmation flag) deploy a known, content-addressed instruction bundle into
an authorized codex directory with full backup and rollback.

Safety model
------------

* Read/inspect (``inspect``) is always allowed and never modifies anything.
* Deploy/restore (``inject`` / ``restore``) only ever touches the exact
  directory passed via ``--target`` (or ``--target-dir``).  That directory
  must contain a real ``config.toml`` and must have been explicitly
  confirmed with ``--allowed``.  No target is auto-discovered or walked into
  from the user profile.
* All file writes are atomic (temp file + rename), are recorded in an
  evidence manifest (relative paths + SHA-256), and every step is reversible
  via the recorded backup.
* Paths are resolved and confined to the target root; any path escaping the
  root (``..``, absolute, symlink) is rejected.

This is a research- and defense-oriented facility.  It does not silently
disable safety rails on arbitrary (third-party) hosts; it operates on a
directory the caller owns or is explicitly authorized to instrument, and it
keeps the original state recoverable.
"""

from __future__ import annotations

from .inspect import CodexInspection, CodexInspectionError, inspect_codex
from .inject import (
    CodexInjectError,
    CodexTarget,
    inject_codex,
    resolve_codex_root,
    restore_codex,
)
from .manifest import CodexEvidence, build_evidence_manifest

__all__ = [
    "CodexEvidence",
    "CodexInspection",
    "CodexInspectionError",
    "CodexInjectError",
    "CodexTarget",
    "build_evidence_manifest",
    "inject_codex",
    "inspect_codex",
    "resolve_codex_root",
    "restore_codex",
]
