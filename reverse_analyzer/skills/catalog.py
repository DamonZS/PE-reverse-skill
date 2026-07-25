"""Dependency-free discovery for checked-in ``SKILL.md`` assets.

Skill documents remain instructions, not executable code.  The catalog makes
their route and runtime boundary explicit so a CLI/user never mistakes a
document-only skill for a registered capability provider.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Any, Iterable


_ROUTES = (
    ("android", ("android", "apk", "mobile")),
    ("ios", ("ios", "ipa")),
    ("protocol", ("protocol", "pcap", "websocket", "graphql", "api")),
    ("source", ("reverse", "binary", "ida", "radare", "malware", "firmware")),
    ("memory", ("windows", "kernel", "dma", "hook", "debug", "edr")),
    ("patch", ("patch", "diff")),
    ("jailbreak", ("llm", "prompt", "agent")),
    ("capability", ("pentest", "attack", "pwn", "supply", "cloud", "oauth", "jwt", "ssrf")),
)


@dataclass(frozen=True)
class SkillRecord:
    id: str
    path: str
    name: str
    description: str
    triggers: tuple[str, ...]
    routes: tuple[str, ...]
    metadata_status: str
    execution_boundary: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["triggers"] = list(self.triggers)
        data["routes"] = list(self.routes)
        return data


class SkillCatalog:
    def __init__(self, root: str | Path):
        self.root = Path(root)

    def discover(self) -> list[SkillRecord]:
        if not self.root.is_dir():
            return []
        return sorted((self._read(path) for path in self.root.rglob("SKILL.md")), key=lambda item: item.id)

    def get(self, skill_id: str) -> SkillRecord | None:
        normalized = str(skill_id).strip().lower()
        for record in self.discover():
            if normalized in {record.id.lower(), record.name.lower()}:
                return record
        return None

    def audit(self) -> dict[str, Any]:
        records = self.discover()
        routes = {route: 0 for route, _ in _ROUTES}
        for record in records:
            for route in record.routes:
                routes[route] = routes.get(route, 0) + 1
        return {
            "skill_count": len(records),
            "metadata_complete_count": sum(item.metadata_status == "complete" for item in records),
            "metadata_inferred_count": sum(item.metadata_status == "inferred" for item in records),
            "routable_count": sum(bool(item.routes) for item in records),
            "route_counts": routes,
            "execution_boundary": "Skills are discoverable instruction assets; a route identifies a platform command, not an automatic authorization to execute it.",
        }

    def _read(self, path: Path) -> SkillRecord:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        relative = path.relative_to(self.root).as_posix()
        metadata, body = _front_matter(text)
        fallback = path.parent.name if path.parent != self.root else "root"
        name = str(metadata.get("name") or fallback).strip()
        description = str(metadata.get("description") or _first_heading(body) or "").strip()
        triggers = _as_strings(metadata.get("triggers"))
        vocabulary = " ".join((relative, name, description, *triggers)).lower()
        routes = tuple(route for route, keywords in _ROUTES if any(word in vocabulary for word in keywords)) or ("capability",)
        return SkillRecord(
            id=relative[:-len("/SKILL.md")] if relative.endswith("/SKILL.md") else relative,
            path=str(path),
            name=name,
            description=description,
            triggers=triggers,
            routes=routes,
            metadata_status="complete" if metadata else "inferred",
            execution_boundary="instruction_asset",
        )


def _front_matter(text: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    try:
        end = next(index for index, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration:
        return {}, text
    metadata: dict[str, Any] = {}
    current_list: str | None = None
    for line in lines[1:end]:
        if re.match(r"^\s*-\s+", line) and current_list:
            metadata.setdefault(current_list, []).append(line.split("-", 1)[1].strip().strip('"'))
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.groups()
        current_list = key if not value else None
        metadata[key] = value.strip().strip('"') if value else []
    return metadata, "\n".join(lines[end + 1:])


def _as_strings(value: Any) -> tuple[str, ...]:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return (str(value).strip(),) if str(value or "").strip() else ()


def _first_heading(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return ""
