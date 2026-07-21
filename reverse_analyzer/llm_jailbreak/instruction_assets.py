from __future__ import annotations

import hashlib
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Tuple


_MERGE_SEPARATOR = "\n\n"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PACKAGED_ASSET_ROOT = Path(__file__).resolve().parent / "builtin_assets"


@dataclass(frozen=True)
class _BuiltinAssetSource:
    name: str
    path: Path


@dataclass(frozen=True)
class _BuiltinProfile:
    assets: Tuple[_BuiltinAssetSource, ...]
    max_source_bytes: int


_CTF_SANDBOX_ASSET = _BuiltinAssetSource(
    "ctf-sandbox",
    Path("scripts/codex-instruct-examples/ctf-sandbox.md"),
)
_GPT_UNRESTRICTED_ASSET = _BuiltinAssetSource(
    "gpt5.5-unrestricted",
    Path("scripts/codex-instruct-examples/gpt5.5-unrestricted.md"),
)
_REVERSE_SKILLS_LLM_SECURITY_ASSETS = (
    _BuiltinAssetSource(
        "reverse-skills-llm-security",
        Path("reverse-skills/skills/llm-security/SKILL.md"),
    ),
    _BuiltinAssetSource(
        "reverse-skills-llm-security-owasp-top10",
        Path("reverse-skills/skills/llm-security/references/owasp-llm-top10.md"),
    ),
    _BuiltinAssetSource(
        "reverse-skills-llm-security-prompt-injection",
        Path(
            "reverse-skills/skills/llm-security/references/"
            "prompt-injection-methodology.md"
        ),
    ),
    _BuiltinAssetSource(
        "reverse-skills-llm-security-agent-testing",
        Path(
            "reverse-skills/skills/llm-security/references/"
            "agent-security-testing.md"
        ),
    ),
    _BuiltinAssetSource(
        "reverse-skills-llm-security-agent-obedience",
        Path(
            "reverse-skills/skills/llm-security/references/"
            "agent-obedience-engineering.md"
        ),
    ),
)
_CTF_UNIFIED_REVERSE_SKILLS_ASSETS = (
    _BuiltinAssetSource(
        "ctf-sandbox-orchestrator",
        Path(
            "reverse-skills/CTF-Sandbox-Orchestrator/"
            "ctf-sandbox-orchestrator/SKILL.md"
        ),
    ),
    _BuiltinAssetSource(
        "competition-prompt-injection",
        Path(
            "reverse-skills/CTF-Sandbox-Orchestrator/"
            "competition-prompt-injection/SKILL.md"
        ),
    ),
    _BuiltinAssetSource(
        "competition-prompt-injection-reference",
        Path(
            "reverse-skills/CTF-Sandbox-Orchestrator/"
            "competition-prompt-injection/references/prompt-injection.md"
        ),
    ),
)
_BUILTIN_PROFILES = {
    "ctf-sandbox": _BuiltinProfile((_CTF_SANDBOX_ASSET,), 8 * 1024),
    "gpt5.5-unrestricted": _BuiltinProfile((_GPT_UNRESTRICTED_ASSET,), 4 * 1024),
    "reverse-skills-llm-security": _BuiltinProfile(
        _REVERSE_SKILLS_LLM_SECURITY_ASSETS,
        32 * 1024,
    ),
    "codex-unified": _BuiltinProfile(
        (_GPT_UNRESTRICTED_ASSET,) + _REVERSE_SKILLS_LLM_SECURITY_ASSETS,
        32 * 1024,
    ),
    "ctf-unified": _BuiltinProfile(
        (_CTF_SANDBOX_ASSET,) + _CTF_UNIFIED_REVERSE_SKILLS_ASSETS,
        24 * 1024,
    ),
}
_PROFILE_ALIASES = {
    "ctf": "ctf-sandbox",
    "sandbox": "ctf-sandbox",
    "ctfsandbox": "ctf-sandbox",
    "gpt55": "gpt5.5-unrestricted",
    "unrestricted": "gpt5.5-unrestricted",
    "gpt55unrestricted": "gpt5.5-unrestricted",
    "llmsecurity": "reverse-skills-llm-security",
    "reversellmsecurity": "reverse-skills-llm-security",
    "reversesecurity": "reverse-skills-llm-security",
    "reverseskills": "reverse-skills-llm-security",
    "codex": "codex-unified",
    "codexall": "codex-unified",
    "ctfall": "ctf-unified",
    "unifiedctf": "ctf-unified",
}


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _normalize_markdown(content: str) -> str:
    return content.replace("\r\n", "\n").replace("\r", "\n").strip()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, os.PathLike):
        return os.fspath(value)
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return [_json_safe(item) for item in sorted(value, key=repr)]
    return str(value)


@dataclass(frozen=True)
class InstructionAsset:
    name: str
    content: str
    source: str
    provenance: Mapping[str, Any] = field(default_factory=dict)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("instruction asset name must be a non-empty string")
        if not isinstance(self.content, str):
            raise TypeError("instruction asset content must be a string")
        if not isinstance(self.source, (str, os.PathLike)) or not os.fspath(
            self.source
        ).strip():
            raise ValueError("instruction asset source must be a non-empty path")
        if not isinstance(self.provenance, Mapping):
            raise TypeError("instruction asset provenance must be a mapping")

        content = _normalize_markdown(self.content)
        if not content:
            raise ValueError(f"instruction asset {self.name!r} is empty")

        object.__setattr__(self, "name", self.name.strip())
        object.__setattr__(self, "content", content)
        object.__setattr__(self, "source", os.fspath(self.source))
        object.__setattr__(self, "provenance", _json_safe(self.provenance))
        object.__setattr__(self, "sha256", _sha256(content))

    @property
    def digest(self) -> str:
        return self.sha256

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "sha256": self.sha256,
            "content": self.content,
            "provenance": _json_safe(self.provenance),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InstructionAsset":
        if not isinstance(value, Mapping):
            raise TypeError("instruction asset snapshot must be a mapping")
        asset = cls(
            name=value.get("name", ""),
            content=value.get("content", ""),
            source=value.get("source", ""),
            provenance=value.get("provenance", {}),
        )
        expected = str(value.get("sha256") or "").strip().casefold()
        if expected and expected != asset.sha256:
            raise ValueError(
                f"instruction asset {asset.name!r} snapshot digest does not match"
            )
        return asset


@dataclass(frozen=True)
class InstructionBundle:
    assets: Tuple[InstructionAsset, ...] = ()
    content: str = field(init=False)
    digest: str = field(init=False)
    provenance: Mapping[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        assets = tuple(self.assets)
        if any(not isinstance(item, InstructionAsset) for item in assets):
            raise TypeError("instruction bundle assets must be InstructionAsset instances")

        content = _MERGE_SEPARATOR.join(item.content for item in assets)
        provenance = {
            "algorithm": "sha256",
            "merge_separator": _MERGE_SEPARATOR,
            "sources": [item.source for item in assets],
            "asset_sha256": [item.sha256 for item in assets],
        }
        object.__setattr__(self, "assets", assets)
        object.__setattr__(self, "content", content)
        object.__setattr__(self, "digest", _sha256(content))
        object.__setattr__(self, "provenance", provenance)

    @property
    def sha256(self) -> str:
        return self.digest

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "digest": self.digest,
            "assets": [item.to_dict() for item in self.assets],
            "provenance": _json_safe(self.provenance),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "InstructionBundle":
        if not isinstance(value, Mapping):
            raise TypeError("instruction bundle snapshot must be a mapping")
        raw_assets = value.get("assets", [])
        if not isinstance(raw_assets, Sequence) or isinstance(
            raw_assets, (str, bytes, bytearray)
        ):
            raise TypeError("instruction bundle snapshot assets must be an array")
        bundle = cls(tuple(InstructionAsset.from_dict(item) for item in raw_assets))
        expected_content = value.get("content")
        if expected_content is not None and expected_content != bundle.content:
            raise ValueError("instruction bundle snapshot content does not match its assets")
        expected_digest = str(value.get("digest") or "").strip().casefold()
        if expected_digest and expected_digest != bundle.digest:
            raise ValueError("instruction bundle snapshot digest does not match")
        return bundle


def _profile_key(profile: str) -> str:
    value = profile.strip().casefold()
    for suffix in (".markdown", ".md"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break
    return re.sub(r"[^a-z0-9]+", "", value)


def resolve_instruction_profile(profile: str) -> str:
    if not isinstance(profile, str):
        raise TypeError("instruction profile must be a string")
    if not profile.strip():
        return ""

    key = _profile_key(profile)
    canonical_by_key = {
        _profile_key(name): name for name in _BUILTIN_PROFILES
    }
    canonical = canonical_by_key.get(key) or _PROFILE_ALIASES.get(key)
    if canonical is None:
        available = ", ".join(list_instruction_profiles())
        raise ValueError(
            f"unknown instruction profile {profile!r}; available profiles: {available}"
        )
    return canonical


def list_instruction_profiles() -> Tuple[str, ...]:
    return tuple(_BUILTIN_PROFILES)


def _read_asset(
    path: Path,
    *,
    name: str,
    source: str,
    provenance: Mapping[str, Any],
) -> InstructionAsset:
    if not path.exists():
        raise FileNotFoundError(f"instruction Markdown file does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"instruction Markdown path is not a file: {path}")
    try:
        content = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"instruction Markdown file must be UTF-8: {path}") from exc
    return InstructionAsset(
        name=name,
        content=content,
        source=source,
        provenance=provenance,
    )


def _builtin_asset_path(relative_path: Path) -> Path:
    repository_path = _REPOSITORY_ROOT / relative_path
    if repository_path.is_file():
        return repository_path
    return _PACKAGED_ASSET_ROOT / relative_path


def _validate_builtin_profile_sources(
    profile: str,
    definition: _BuiltinProfile,
) -> None:
    missing = []
    not_files = []
    source_bytes = 0
    for asset in definition.assets:
        path = _builtin_asset_path(asset.path)
        if not path.exists():
            missing.append(asset.path.as_posix())
            continue
        if not path.is_file():
            not_files.append(asset.path.as_posix())
            continue
        source_bytes += path.stat().st_size

    if missing:
        raise FileNotFoundError(
            f"instruction profile {profile!r} is incomplete; missing required "
            f"Markdown files: {', '.join(missing)}"
        )
    if not_files:
        raise ValueError(
            f"instruction profile {profile!r} has required Markdown paths that "
            f"are not files: {', '.join(not_files)}"
        )
    if source_bytes > definition.max_source_bytes:
        raise ValueError(
            f"instruction profile {profile!r} exceeds its "
            f"{definition.max_source_bytes}-byte source size limit: "
            f"{source_bytes} bytes"
        )


def _load_builtin_profile(profile: str) -> Tuple[InstructionAsset, ...]:
    definition = _BUILTIN_PROFILES[profile]
    _validate_builtin_profile_sources(profile, definition)

    assets = []
    asset_count = len(definition.assets)
    for index, asset_source in enumerate(definition.assets):
        source = asset_source.path.as_posix()
        try:
            asset = _read_asset(
                _builtin_asset_path(asset_source.path),
                name=asset_source.name,
                source=source,
                provenance={
                    "kind": "builtin-profile",
                    "profile": profile,
                    "source": source,
                    "profile_asset_index": index,
                    "profile_asset_count": asset_count,
                },
            )
        except FileNotFoundError as exc:
            raise FileNotFoundError(
                f"instruction profile {profile!r} is missing required "
                f"Markdown file: {source}"
            ) from exc
        assets.append(asset)
    return tuple(assets)


def _load_custom_file(value: str | os.PathLike[str]) -> InstructionAsset:
    raw_path = os.fspath(value)
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError("instruction file path must be a non-empty string")

    path = Path(raw_path).expanduser().resolve()
    if path.suffix.casefold() not in {".md", ".markdown"}:
        raise ValueError(f"instruction file must be Markdown (.md or .markdown): {path}")
    loaded = _read_asset(
        path,
        name=path.name,
        source=path.name,
        provenance={"kind": "custom-markdown"},
    )
    source = _portable_custom_source(path, loaded.sha256)
    return InstructionAsset(
        name=loaded.name,
        content=loaded.content,
        source=source,
        provenance={
            "kind": "custom-markdown",
            "source": source,
            "content_addressed": True,
        },
    )


def _portable_custom_source(path: Path, digest: str) -> str:
    """Return a stable audit reference without persisting a host absolute path."""

    try:
        return path.relative_to(_REPOSITORY_ROOT).as_posix()
    except ValueError:
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", path.name).strip(".-")
        return f"external/{safe_name or 'instruction.md'}@sha256-{digest[:16]}"


def load_instruction_bundle(
    profile: str = "",
    files: Sequence[str | os.PathLike[str]] = (),
) -> InstructionBundle:
    canonical_profile = resolve_instruction_profile(profile)
    if isinstance(files, (str, bytes, os.PathLike)) or not isinstance(files, Sequence):
        raise TypeError("instruction files must be an ordered sequence of paths")

    assets = []
    if canonical_profile:
        assets.extend(_load_builtin_profile(canonical_profile))
    for index, value in enumerate(files):
        if not isinstance(value, (str, os.PathLike)):
            raise TypeError(f"instruction files[{index}] must be a path string")
        assets.append(_load_custom_file(value))
    return InstructionBundle(tuple(assets))


__all__ = [
    "InstructionAsset",
    "InstructionBundle",
    "list_instruction_profiles",
    "load_instruction_bundle",
    "resolve_instruction_profile",
]
