"""Evidence manifest for Codex instrumentation.

Every mutation performed on a codex config directory is recorded as a
content-addressed artifact (relative path, size, SHA-256, and a provenance
note).  This mirrors the repository-wide evidence-manifest contract so that
later verification can confirm exactly what changed and can be compared
against a clean baseline.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from reverse_analyzer._version import __version__

MANIFEST_NAME = "codex-evidence-manifest.json"
SCHEMA_VERSION = 1


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_str(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CodexEvidence:
    """A single recorded artifact in a codex evidence manifest."""

    path: str
    sha256: str
    size: int
    kind: str = "file"
    source: str = ""
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "kind": self.kind,
            "source": self.source,
            "provenance": dict(self.provenance),
        }


def build_evidence_manifest(
    entries: Sequence[CodexEvidence],
    *,
    root: str = "",
    operation: str = "inspect",
    target_dir: str = "",
) -> Mapping[str, Any]:
    """Build the standard evidence manifest dictionary for a codex operation."""
    return {
        "schema_version": SCHEMA_VERSION,
        "product": "reverse-analyzer",
        "product_version": __version__,
        "operation": operation,
        "root": root,
        "target_dir": target_dir,
        "algorithm": "sha256",
        "entries": [entry.to_dict() for entry in entries],
    }


def write_manifest(manifest: Mapping[str, Any], directory: Path) -> Path:
    """Write (atomically) and return the manifest path."""
    target = directory / MANIFEST_NAME
    payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    _atomic_write(target, payload.encode("utf-8"))
    return target


def load_manifest(path: Path) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported manifest schema_version: {payload.get('schema_version')}")
    if payload.get("product") != "reverse-analyzer":
        raise ValueError("manifest product is unsupported")
    return payload


def _atomic_write(path: Path, data: bytes) -> None:
    """Write bytes to path via a temp file + rename (atomic, crash-safe)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)


__all__ = [
    "MANIFEST_NAME",
    "SCHEMA_VERSION",
    "CodexEvidence",
    "build_evidence_manifest",
    "load_manifest",
    "sha256_bytes",
    "sha256_file",
    "sha256_str",
    "write_manifest",
]
