"""YARA scanning helpers with optional yara-python dependency.

This module keeps the dependency optional: when ``yara-python`` is unavailable,
callers receive a normalized ``ToolResult`` with ``status='unavailable'``
instead of an import failure.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Sequence

from .executor import ToolResult

DEFAULT_RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "yara"
RULE_SUFFIXES = {".yar", ".yara"}
MAX_STRING_ITEMS = 20
MAX_STRING_PREVIEW = 64


def yara_scan(path: str | Path, rules_path: str | Path | None = None) -> ToolResult | Dict[str, Any]:
    target = _require_file(path)
    try:
        import yara  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool="yara_scan",
            status="unavailable",
            error=f"optional dependency yara-python unavailable: {exc}",
            data={
                "path": str(target),
                "rules_path": str(_resolve_rules_path(rules_path)),
                "rule_files": [],
                "matches": [],
                "match_count": 0,
            },
        )

    resolved_rules_path = _resolve_rules_path(rules_path)
    rule_files = _collect_rule_files(resolved_rules_path)
    if not rule_files:
        raise FileNotFoundError(f"no YARA rule files found under: {resolved_rules_path}")

    namespaces = {_namespace_for_rule(rule_file, resolved_rules_path): str(rule_file) for rule_file in rule_files}
    compiled = yara.compile(filepaths=namespaces)
    raw_matches = compiled.match(str(target))
    matches = [_normalize_match(match) for match in raw_matches]
    return {
        "path": str(target),
        "rules_path": str(resolved_rules_path),
        "rule_files": [str(rule_file) for rule_file in rule_files],
        "match_count": len(matches),
        "matches": matches,
    }


def _resolve_rules_path(rules_path: str | Path | None) -> Path:
    return Path(rules_path) if rules_path is not None else DEFAULT_RULES_DIR


def _collect_rule_files(rules_path: str | Path) -> List[Path]:
    root = Path(rules_path)
    if root.is_file():
        return [root.resolve()] if root.suffix.lower() in RULE_SUFFIXES else []
    if not root.exists():
        raise FileNotFoundError(str(root))
    return sorted(
        rule_file.resolve()
        for rule_file in root.rglob("*")
        if rule_file.is_file() and rule_file.suffix.lower() in RULE_SUFFIXES
    )


def _namespace_for_rule(rule_file: Path, base_path: Path) -> str:
    if base_path.is_file():
        return rule_file.stem
    relative = rule_file.resolve().relative_to(base_path.resolve())
    return ".".join(relative.with_suffix("").parts)


def _normalize_match(match: Any) -> Dict[str, Any]:
    return {
        "rule": str(getattr(match, "rule", match)),
        "namespace": str(getattr(match, "namespace", "default")),
        "tags": [str(tag) for tag in (getattr(match, "tags", []) or [])],
        "meta": dict(getattr(match, "meta", {}) or {}),
        "strings": _summarize_strings(getattr(match, "strings", []) or []),
    }


def _summarize_strings(raw_strings: Sequence[Any]) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []
    total = 0
    for entry in raw_strings:
        normalized = _normalize_string_entry(entry)
        total += len(normalized)
        for item in normalized:
            if len(items) < MAX_STRING_ITEMS:
                items.append(item)
    return {"count": total, "truncated": total > MAX_STRING_ITEMS, "items": items}


def _normalize_string_entry(entry: Any) -> List[Dict[str, Any]]:
    if hasattr(entry, "identifier"):
        identifier = str(getattr(entry, "identifier", ""))
        instances = list(getattr(entry, "instances", []) or [])
        if not instances:
            return [{"identifier": identifier, "offset": None, "length": None, "preview": None}]
        return [_normalize_string_instance(identifier, instance) for instance in instances]

    if isinstance(entry, (tuple, list)) and len(entry) >= 3:
        offset, identifier, data = entry[0], entry[1], entry[2]
        return [
            {
                "identifier": str(identifier),
                "offset": _safe_int(offset),
                "length": len(data) if isinstance(data, (bytes, bytearray)) else None,
                "preview": _preview_bytes(data),
            }
        ]

    return [{"identifier": repr(entry), "offset": None, "length": None, "preview": None}]


def _normalize_string_instance(identifier: str, instance: Any) -> Dict[str, Any]:
    data = getattr(instance, "matched_data", None)
    if data is None:
        data = getattr(instance, "data", None)
    offset = getattr(instance, "offset", None)
    if offset is None:
        offset = getattr(instance, "matched_offset", None)
    return {
        "identifier": identifier,
        "offset": _safe_int(offset),
        "length": len(data) if isinstance(data, (bytes, bytearray)) else None,
        "preview": _preview_bytes(data),
    }


def _preview_bytes(data: Any) -> str | None:
    if not isinstance(data, (bytes, bytearray)):
        return None
    sample = bytes(data[:MAX_STRING_PREVIEW])
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return sample.hex()
    if all(32 <= ord(ch) <= 126 for ch in text):
        return text
    return sample.hex()


def _safe_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except Exception:  # noqa: BLE001
        return None


def _require_file(path: str | Path) -> Path:
    resolved = Path(path)
    if not resolved.is_file():
        raise FileNotFoundError(str(resolved))
    return resolved.resolve()


__all__ = ["DEFAULT_RULES_DIR", "yara_scan"]
