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

from .runtime import SkillRouter, SkillRoutingError, routing_summary


_ROUTES = (
    ("pe", ("pe file", "pe analysis", "pe structure", "pe reasoning", "windows pe")),
    ("android", ("android", "apk", "mobile")),
    ("ios", ("ios", "ipa")),
    ("protocol", ("protocol", "pcap", "websocket", "graphql", "api")),
    ("source", ("reverse", "binary", "source", "ida", "radare", "malware", "firmware")),
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
    scripts: tuple[str, ...]
    references: tuple[str, ...]
    metadata_status: str
    execution_boundary: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["triggers"] = list(self.triggers)
        data["routes"] = list(self.routes)
        data["scripts"] = list(self.scripts)
        data["references"] = list(self.references)
        return data


class SkillCatalog:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._route_scripts: dict[str, tuple[str, ...]] = {}
        self._suite_root: Path | None = None
        try:
            router = SkillRouter(self.root)
            self._route_scripts = {rule.skill_id: rule.scripts for rule in router.rules}
            self._suite_root = router.suite_root
        except SkillRoutingError:
            pass

    def discover(self) -> list[SkillRecord]:
        if not self.root.is_dir():
            return []
        return sorted((self._read(path) for path in self.root.rglob("SKILL.md")), key=lambda item: item.id)

    def get(self, skill_id: str) -> SkillRecord | None:
        normalized = str(skill_id).strip().lower()
        for record in self.discover():
            aliases = {record.id.lower(), record.name.lower(), record.id.rsplit("/", 1)[-1].lower()}
            canonical = self._canonical_route_id(Path(record.path))
            if canonical:
                aliases.add(canonical.lower())
            if normalized in aliases:
                return record
        return None

    def route(
        self,
        query: str,
        *,
        target: str | Path | None = None,
        endpoint: str | None = None,
        interface: str | None = None,
        package: str | None = None,
        limit: int = 3,
    ) -> dict[str, Any]:
        """Return a non-executing plan from the checked-in route contract."""

        decision = SkillRouter(self.root).route(
            query,
            target=target,
            endpoint=endpoint,
            interface=interface,
            package=package,
            limit=limit,
        )
        decision["primary"] = self._attach_record(decision["primary"])
        decision["secondary"] = [self._attach_record(item) for item in decision["secondary"]]
        decision["master_skill"] = self._attach_skill_reference(decision["master_skill"])
        workflow = dict(decision["workflow"])
        workflow["master"] = self._attach_skill_reference(workflow["master"])
        workflow["stages"] = [self._attach_skill_reference(item) for item in workflow["stages"]]
        workflow["subskills"] = [self._attach_skill_reference(item) for item in workflow["subskills"]]
        decision["workflow"] = workflow
        return decision

    def audit(self) -> dict[str, Any]:
        records = self.discover()
        routes = {route: 0 for route, _ in _ROUTES}
        for record in records:
            for route in record.routes:
                routes[route] = routes.get(route, 0) + 1
        try:
            runtime = routing_summary(self.root)
        except SkillRoutingError as exc:
            runtime = {"status": "unavailable", "reason": str(exc)}
        return {
            "skill_count": len(records),
            "metadata_complete_count": sum(item.metadata_status == "complete" for item in records),
            "metadata_inferred_count": sum(item.metadata_status == "inferred" for item in records),
            "routable_count": sum(bool(item.routes) for item in records),
            "script_backed_count": sum(bool(item.scripts) for item in records),
            "reference_backed_count": sum(bool(item.references) for item in records),
            "route_counts": routes,
            "skill_runtime": runtime,
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
        scripts, references = _resources(path, self.root)
        declared = self._declared_scripts(path)
        scripts = tuple(sorted(set(scripts) | set(declared)))
        return SkillRecord(
            id=relative[:-len("/SKILL.md")] if relative.endswith("/SKILL.md") else relative,
            path=str(path),
            name=name,
            description=description,
            triggers=triggers,
            routes=routes,
            scripts=scripts,
            references=references,
            metadata_status="complete" if metadata else "inferred",
            execution_boundary="instruction_asset_with_local_helpers" if scripts else "instruction_asset",
        )

    def _attach_record(self, candidate: Any) -> dict[str, Any]:
        enriched = dict(candidate)
        record = self.get(str(enriched.get("skill_id") or ""))
        enriched["skill"] = record.to_dict() if record else None
        return enriched

    def _attach_skill_reference(self, candidate: Any) -> dict[str, Any]:
        enriched = dict(candidate)
        path_value = str(enriched.get("path") or "").strip()
        record: SkillRecord | None = None
        if self._suite_root is not None and path_value:
            path = (self._suite_root / path_value).resolve()
            try:
                path.relative_to(self._suite_root.resolve())
            except ValueError:
                path = Path()
            if path.is_file():
                record = self._read(path)
        if record is None:
            record = self.get(str(enriched.get("skill_id") or ""))
        enriched["skill"] = record.to_dict() if record else None
        return enriched

    def _declared_scripts(self, path: Path) -> tuple[str, ...]:
        if self._suite_root is None:
            return ()
        route_id = self._canonical_route_id(path)
        declared = self._route_scripts.get(route_id or "", ())
        paths: list[str] = []
        for script in declared:
            try:
                paths.append((self._suite_root / script).relative_to(self.root).as_posix())
            except ValueError:
                continue
        return tuple(paths)

    def _canonical_route_id(self, skill_path: Path) -> str | None:
        if self._suite_root is None:
            return None
        try:
            return skill_path.parent.relative_to(self._suite_root).as_posix()
        except ValueError:
            return None


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


def _resources(path: Path, root: Path) -> tuple[tuple[str, ...], tuple[str, ...]]:
    def collect(directory: str) -> tuple[str, ...]:
        resource_root = path.parent / directory
        if not resource_root.is_dir():
            return ()
        return tuple(sorted(item.relative_to(root).as_posix() for item in resource_root.rglob("*") if item.is_file()))

    return collect("scripts"), collect("references")
