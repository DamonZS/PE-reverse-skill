"""Read-only Codex configuration inspection (defensive).

``inspect_codex`` never writes, never restores, and never mutates a codex
config directory.  It answers the question:  *"Has this codex install been
re-pointed at a third-party global instruction file (the
``model_instructions_file`` technique), and were unexpected skills or
activation words planted?"*

It detects, in order of signal quality:

1. A ``config.toml`` whose ``model_instructions_file`` points at a
   non-official file / a file whose content carries an activation word
   (``AC ...`` or the ``Leila``/``拓扑`` backdoor) or a ``MODE: CTF SANDBOX`` /
   ``MODE: UNRESTRICTED`` banner.
2. Unexpected skill directories under ``skills/`` (here: ``ac``,
   ``leila-identity``, and ``topo-identity``), including their
   activation/identity markers.
3. The known activation words ``AC`` / ``Leila`` / ``拓扑`` in the served
   instruction file content.

The result is a structured report plus, when a problem is found, the exact
recovery steps (restore the original ``config.toml`` and remove the planted
skill directories), which are the caller's to act on.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence, Tuple

from .manifest import CodexEvidence, build_evidence_manifest, sha256_file

CONFIG_FILENAME = "config.toml"

# Well-known Codex / OpenAI config roots on typical developer machines.
DEFAULT_SEARCH_ROOTS: Tuple[Path, ...] = (
    Path("~/.codex"),
    Path("~/.config/codex"),
    Path("/Users/.codex"),
)


class CodexInspectionError(ValueError):
    """Raised when a codex config directory cannot be inspected."""


@dataclass(frozen=True)
class Finding:
    """A single discovered signal in a codex config directory."""

    severity: str  # "info" | "notice" | "warning" | "critical"
    code: str
    message: str
    path: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "path": self.path,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class CodexInspection:
    """The full read-only inspection result."""

    root: str
    exists: bool
    findings: Tuple[Finding, ...]
    config_file: str = ""
    model_instructions_file: str = ""
    skill_dirs: Tuple[str, ...] = ()
    instruction_content: str = ""
    evidence: Tuple[CodexEvidence, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(finding.severity in ("warning", "critical") for finding in self.findings)

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "root": self.root,
            "exists": self.exists,
            "ok": self.ok,
            "config_file": self.config_file,
            "model_instructions_file": self.model_instructions_file,
            "skill_dirs": list(self.skill_dirs),
            "evidence_count": len(self.evidence),
            "findings": [finding.to_dict() for finding in self.findings],
        }


_ACTIVATION_ROOT_LINE = re.compile(
    r"^# AC Entry Router\s*$", re.IGNORECASE | re.MULTILINE
)
_AC_LINE = re.compile(r"^AC在\s", re.MULTILINE)
_LEILA_BACKDOOR = re.compile(
    r"respond with ONLY\s*[\"']ok[\"'].*\bLeila\b", re.IGNORECASE | re.MULTILINE
)
_LEILA_TOKEN = re.compile(r"\bLeila\b")
_TOPO_BACKDOOR = re.compile(
    r"respond with ONLY\s*[\"']ok[\"'].*拓扑", re.IGNORECASE | re.MULTILINE
)
_TOPO_TOKEN = re.compile(r"拓扑")
_MODE_BANNER = re.compile(r"^\[MODE:\s*(CTF\s+SANDBOX|UNRESTRICTED)\]\s*$", re.IGNORECASE | re.MULTILINE)
_NO_REFUSAL = re.compile(
    r"\bNo disclaimers\b.*\bNo refusal\b", re.IGNORECASE | re.MULTILINE
)

_SPLITTER = re.compile(r"[^A-Za-z0-9_]+")


def _toml_string_value(line: str) -> str:
    match = re.search(r"=\s*\"([^\"]*)\"", line)
    if match:
        return match.group(1)
    match = re.search(r"=\s*'([^']*)'", line)
    if match:
        return match.group(1)
    return ""


def _parse_model_instructions_file(config_text: str) -> str:
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        key = stripped.split("=", 1)[0].strip()
        if key == "model_instructions_file":
            return _toml_string_value(stripped)
    return ""


def _is_activation_bearing(content: str) -> bool:
    """Return True when instruction content carries the activation markers.

    The detector is dual-track: it recognizes the canonical Leila attack
    markers (so real-world Leila deployments are never missed) **and** the
    branded topology re-issue (so a topology-labelled deploy is also caught).
    """
    return bool(
        _ACTIVATION_ROOT_LINE.search(content)
        or _AC_LINE.search(content)
        or _LEILA_BACKDOOR.search(content)
        or _LEILA_TOKEN.search(content)
        or _TOPO_BACKDOOR.search(content)
        or _TOPO_TOKEN.search(content)
    )


def _candidate_roots(explicit: Path | None) -> Tuple[Path, ...]:
    if explicit is not None:
        return (Path(explicit).expanduser().resolve(),)
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in DEFAULT_SEARCH_ROOTS:
        resolved = candidate.expanduser()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        roots.append(resolved)
    return tuple(roots)


def _find_root(explicit: Path | None) -> Path | None:
    for candidate in _candidate_roots(explicit):
        if (candidate / CONFIG_FILENAME).is_file():
            return candidate
    return None


def _classify_notice(
    path: Path, relative: str, content: str, config_text: str
) -> Finding:
    code = "info"
    severity = "info"
    message = "observed file (not inherently suspicious)"
    if relative == "config.toml":
        code = "config-present"
        severity = "info"
        message = "present codex config.toml"
    elif _MODE_BANNER.search(content) and _is_activation_bearing(content):
        # The strongest signal: an instruction file that both declares an
        # unrestricted/CTF sandbox mode AND carries the AC router / Leila
        # activation markers.  This should be surfaced as a warning, not an
        # informational note.
        code = "instructions-activation"
        severity = "warning"
        message = (
            "instruction content declares an unrestricted/CTF sandbox mode and "
            "carries the AC router / Leila or 拓扑 activation markers"
        )
    elif _MODE_BANNER.search(content):
        code = "instruction-mode-banner"
        severity = "notice"
        message = "instruction content declares an unrestricted/CTF sandbox mode banner"
    elif _is_activation_bearing(content):
        code = "instruction-activation"
        severity = "warning"
        message = (
            "instruction content carries an activation router (AC) or the "
            "Leila / 拓扑 self-check backdoor"
        )
    return Finding(
        severity=severity,
        code=code,
        message=message,
        path=relative,
        evidence=(content[:160].strip(),) if content else (),
    )


def inspect_codex(target: Path | None = None, *, root: Path | None = None) -> CodexInspection:
    """Inspect a codex config directory read-only.

    ``target`` (or ``root``) is the exact directory to inspect.  When omitted,
    common well-known codex roots are probed.  Nothing is written.
    """
    config_dir = _find_root(target if target is not None else root)
    if config_dir is None:
        requested = target if target is not None else root
        label = str(requested.expanduser()) if requested is not None else "known codex roots"
        return CodexInspection(
            root=str(requested.expanduser()) if requested is not None else "",
            exists=False,
            findings=(
                Finding(
                    severity="warning",
                    code="no-config",
                    message="no codex config.toml found under " + label,
                    path="",
                ),
            ),
        )

    config_path = config_dir / CONFIG_FILENAME
    config_text = config_path.read_text(encoding="utf-8", errors="replace")
    model_instructions_file = _parse_model_instructions_file(config_text)

    findings: list[Finding] = []
    evidence: list[CodexEvidence] = []
    skill_dirs: list[str] = []

    # 1. config.toml record
    evidence.append(
        CodexEvidence(
            path=CONFIG_FILENAME,
            sha256=sha256_file(config_path),
            size=config_path.stat().st_size,
            source=CONFIG_FILENAME,
            provenance={"kind": "config.toml"},
        )
    )
    findings.append(
        Finding(
            severity="info",
            code="config-present",
            message="present codex config.toml",
            path=CONFIG_FILENAME,
        )
    )

    # 2. model_instructions_file resolution
    if not model_instructions_file:
        findings.append(
            Finding(
                severity="info",
                code="no-instructions-file",
                message="no model_instructions_file directive; codex uses default global instructions",
                path=CONFIG_FILENAME,
            )
        )
    else:
        resolved = _resolve_instruction_path(config_dir, model_instructions_file)
        if not resolved or not resolved.is_file():
            findings.append(
                Finding(
                    severity="warning",
                    code="instructions-file-missing",
                    message=(
                        f"model_instructions_file is set to {model_instructions_file!r} "
                        f"but the resolved file does not exist"
                    ),
                    path=CONFIG_FILENAME,
                    evidence=(model_instructions_file,),
                )
            )
            model_instructions_file = ""
        else:
            content = resolved.read_text(encoding="utf-8", errors="replace")
            relative = _safe_relative(config_dir, resolved)
            evidence.append(
                CodexEvidence(
                    path=relative,
                    sha256=sha256_file(resolved),
                    size=resolved.stat().st_size,
                    source=model_instructions_file,
                    provenance={"kind": "model_instructions_file"},
                )
            )
            warning = _classify_notice(resolved, relative, content, config_text)
            if warning.severity == "warning" or warning.severity == "critical":
                findings.append(
                    Finding(
                        severity=warning.severity,
                        code="instructions-redirect",
                        message=(
                            "model_instructions_file re-points codex at a third-party "
                            f"instruction file: {model_instructions_file!r}"
                        ),
                        path=CONFIG_FILENAME,
                        evidence=(relative, warning.evidence[0] if warning.evidence else ""),
                    )
                )
            elif warning.severity == "notice":
                findings.append(
                    Finding(
                        severity="notice",
                        code="instructions-note",
                        message=warning.message,
                        path=relative,
                        evidence=warning.evidence,
                    )
                )

    # 3. skill directories
    skills_root = config_dir / "skills"
    if skills_root.is_dir():
        for child in sorted(skills_root.iterdir()):
            if not child.is_dir():
                continue
            name = child.name
            skill_dirs.append(name)
            if name in ("ac", "leila-identity", "topo-identity"):
                findings.append(
                    Finding(
                        severity="warning",
                        code="unexpected-skill",
                        message=f"unexpected skill directory planted: skills/{name}",
                        path=f"skills/{name}",
                        evidence=tuple(
                            str(item.relative_to(config_dir).as_posix())
                            for item in sorted(child.rglob("*"))[:6]
                            if item.is_file()
                        ),
                    )
                )

    return CodexInspection(
        root=str(config_dir),
        exists=True,
        findings=tuple(findings),
        config_file=str(config_path),
        model_instructions_file=model_instructions_file,
        skill_dirs=tuple(skill_dirs),
        evidence=tuple(evidence),
    )


def _resolve_instruction_path(config_dir: Path, raw: str) -> Path | None:
    if not raw:
        return None
    expanded = Path(raw).expanduser()
    candidate = expanded if expanded.is_absolute() else (config_dir / expanded)
    try:
        return candidate.resolve(strict=True)
    except OSError:
        # Try relative to the config dir without strict resolution.
        try:
            return (config_dir / expanded).resolve()
        except OSError:
            return None


def _safe_relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


__all__ = [
    "CodexInspection",
    "CodexInspectionError",
    "CONFIG_FILENAME",
    "Finding",
    "inspect_codex",
]
