"""Configuration-driven routing for the checked-in PE skill suite."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


class SkillRoutingError(ValueError):
    """Raised when the local skill routing contract is missing or invalid."""


@dataclass(frozen=True)
class RouteRule:
    """One deterministic route declared by ``config/routing.json``."""

    skill_id: str
    title: str
    phase: str
    priority: int
    keywords: tuple[str, ...]
    extensions: tuple[str, ...]
    input_kinds: tuple[str, ...]
    interfaces: tuple[str, ...]
    packages: tuple[str, ...]
    url_keywords: tuple[str, ...]
    workflow: tuple[str, ...]
    subskills: tuple[str, ...]
    capability_candidates: tuple[str, ...]
    tools: tuple[str, ...]
    scripts: tuple[str, ...]
    requires_authorization: bool
    risk_level: str
    execution_boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_id": self.skill_id,
            "title": self.title,
            "phase": self.phase,
            "priority": self.priority,
            "keywords": list(self.keywords),
            "extensions": list(self.extensions),
            "input_kinds": list(self.input_kinds),
            "interfaces": list(self.interfaces),
            "packages": list(self.packages),
            "url_keywords": list(self.url_keywords),
            "workflow": list(self.workflow),
            "subskills": list(self.subskills),
            "capability_candidates": list(self.capability_candidates),
            "tools": list(self.tools),
            "scripts": list(self.scripts),
            "requires_authorization": self.requires_authorization,
            "risk_level": self.risk_level,
            "execution_boundary": self.execution_boundary,
        }


@dataclass(frozen=True)
class ToolRecord:
    """A declared local helper indexed by ``tool-manifest.json``."""

    id: str
    entrypoint: str
    mode: str
    summary: str
    skill_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entrypoint": self.entrypoint,
            "mode": self.mode,
            "summary": self.summary,
            "skill_ids": list(self.skill_ids),
            "execution_boundary": "manifest_only",
        }


@dataclass(frozen=True)
class RouteInput:
    """Structured descriptors used for deterministic, non-executing routing."""

    query: str
    target: str | None
    endpoint: str | None
    interface: str | None
    package: str | None
    kinds: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "target": self.target,
            "endpoint": self.endpoint,
            "interface": self.interface,
            "package": self.package,
            "kinds": list(self.kinds),
        }


class SkillRouter:
    """Load and score the small, local-first PE skill suite."""

    def __init__(self, root: str | Path, *, config_path: str | Path | None = None):
        self.root = Path(root)
        self.config_path = Path(config_path) if config_path is not None else _routing_path(self.root)
        self.suite_root = self.config_path.parents[1]
        self._payload = _read_payload(self.config_path)
        self._rules = _parse_rules(self._payload)
        self._fallback = _fallback_rule(self._payload, self._rules)
        self._master_skill = _parse_master_skill(self._payload)
        self._tools = _parse_tools(_tool_manifest_path(self.config_path))
        _validate_assets(self.suite_root, self._rules, self._tools, self._master_skill)

    @property
    def rules(self) -> tuple[RouteRule, ...]:
        return self._rules

    @property
    def policy(self) -> dict[str, Any]:
        value = self._payload.get("policy")
        return dict(value) if isinstance(value, Mapping) else {}

    def rule(self, skill_id: str) -> RouteRule:
        """Resolve one configured skill ID without applying keyword scoring."""

        normalized = str(skill_id or "").strip().casefold()
        for rule in self._rules:
            if rule.skill_id.casefold() == normalized:
                return rule
        raise SkillRoutingError(f"unknown skill ID: {skill_id}")

    def route_by_id(
        self,
        skill_id: str,
        *,
        target: str | Path | None = None,
        endpoint: str | None = None,
        interface: str | None = None,
        package: str | None = None,
    ) -> dict[str, Any]:
        """Plan one configured skill without keyword scoring or execution authority."""

        request = _route_input("", target=target, endpoint=endpoint, interface=interface, package=package)
        rule = self.rule(skill_id)
        primary = self._candidate(
            rule,
            score=rule.priority,
            matched_keywords=[],
            target_extension_match=False,
            selection="explicit_skill_id",
        )
        return self._plan(request=request, primary=primary, secondary=[], ranked_count=1)

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
        request = _route_input(query, target=target, endpoint=endpoint, interface=interface, package=package)
        normalized_query = _normalize(request.query)
        if not normalized_query and not any((request.target, request.endpoint, request.interface, request.package)):
            raise SkillRoutingError("provide a request or a local target path")
        if limit < 1:
            raise SkillRoutingError("limit must be at least 1")

        suffix = Path(request.target).suffix.casefold() if request.target else ""
        endpoint_text = _normalize(request.endpoint or "")
        ranked: list[dict[str, Any]] = []
        for rule in self._rules:
            matched_keywords = tuple(keyword for keyword in rule.keywords if _matches_keyword(keyword, normalized_query))
            extension_match = bool(suffix and suffix in rule.extensions)
            matched_kinds = tuple(kind for kind in rule.input_kinds if kind in request.kinds)
            matched_interfaces = tuple(value for value in rule.interfaces if value == request.interface)
            matched_packages = tuple(value for value in rule.packages if value == request.package)
            matched_url_keywords = tuple(
                keyword for keyword in rule.url_keywords if _matches_keyword(keyword, endpoint_text)
            )
            # A local-file descriptor only says that a file was supplied.  It
            # must not outweigh actual format or intent evidence, especially
            # for controlled protection-review routes.  An endpoint descriptor
            # is the one standalone descriptor that identifies its workflow.
            endpoint_descriptor_match = "url-descriptor" in matched_kinds
            controlled_signal = any((matched_keywords, matched_interfaces, matched_packages, matched_url_keywords))
            if rule.risk_level == "controlled" and not controlled_signal:
                continue
            if not any(
                (
                    matched_keywords,
                    extension_match,
                    endpoint_descriptor_match,
                    matched_interfaces,
                    matched_packages,
                    matched_url_keywords,
                )
            ):
                continue
            score = (
                rule.priority
                + len(matched_keywords) * 100
                + (50 if extension_match else 0)
                + (40 if endpoint_descriptor_match else 0)
                + len(matched_interfaces) * 70
                + len(matched_packages) * 70
                + len(matched_url_keywords) * 40
            )
            ranked.append(
                self._candidate(
                    rule,
                    score=score,
                    matched_keywords=list(matched_keywords),
                    target_extension_match=extension_match,
                    matched_input_kinds=list(matched_kinds),
                    matched_interfaces=list(matched_interfaces),
                    matched_packages=list(matched_packages),
                    matched_url_keywords=list(matched_url_keywords),
                )
            )

        if not ranked:
            ranked.append(
                self._candidate(
                    self._fallback,
                    score=self._fallback.priority,
                    matched_keywords=[],
                    target_extension_match=False,
                    fallback=True,
                )
            )

        ranked.sort(key=lambda item: (-int(item["score"]), str(item["skill_id"])))
        selected = ranked[:limit]
        primary = selected[0]
        return self._plan(request=request, primary=primary, secondary=selected[1:], ranked_count=len(ranked))

    def _candidate(self, rule: RouteRule, **matches: Any) -> dict[str, Any]:
        return {
            **matches,
            "tool_details": [self._tools[tool_id].to_dict() for tool_id in rule.tools],
            **rule.to_dict(),
        }

    def _plan(
        self,
        *,
        request: RouteInput,
        primary: Mapping[str, Any],
        secondary: list[dict[str, Any]],
        ranked_count: int,
    ) -> dict[str, Any]:
        return {
            "status": "planned",
            "input": request.to_dict(),
            "query": request.query,
            "target": request.target,
            "master_skill": dict(self._master_skill),
            "workflow": {
                "master": dict(self._master_skill),
                "stages": [_skill_reference(skill_id) for skill_id in primary.get("workflow", ())],
                "subskills": [_skill_reference(skill_id) for skill_id in primary.get("subskills", ())],
                "tools": list(primary.get("tool_details", ())),
            },
            "primary": primary,
            "secondary": secondary,
            "ranked_count": ranked_count,
            "next_actions": _next_actions(
                primary,
                has_local_target=bool(request.target),
            ),
        }


def routing_summary(root: str | Path) -> dict[str, Any]:
    """Return a compact validation-friendly view of the configured suite."""

    router = SkillRouter(root)
    return {
        "status": "ready",
        "config_path": str(router.config_path),
        "rule_count": len(router.rules),
        "fallback_skill_id": router._fallback.skill_id,
        "skill_ids": [rule.skill_id for rule in router.rules],
        "master_skill": dict(router._master_skill),
        "tool_count": len(router._tools),
        "controlled_route_count": sum(rule.risk_level == "controlled" for rule in router.rules),
    }


def _routing_path(root: Path) -> Path:
    candidates = (
        root / "skills" / "config" / "routing.json",
        root / "config" / "routing.json",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    expected = candidates[0] if (root / "skills").is_dir() else candidates[1]
    raise SkillRoutingError(f"routing configuration not found: {expected}")


def _read_payload(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise SkillRoutingError(f"could not read routing configuration: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SkillRoutingError(f"invalid routing JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise SkillRoutingError("routing configuration must be a JSON object")
    if value.get("version") != 1:
        raise SkillRoutingError("routing configuration version must be 1")
    return value


def _parse_rules(payload: Mapping[str, Any]) -> tuple[RouteRule, ...]:
    items = payload.get("routes")
    if not isinstance(items, list) or not items:
        raise SkillRoutingError("routing configuration must include a non-empty routes array")
    rules: list[RouteRule] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise SkillRoutingError(f"route {index} must be an object")
        skill_id = _required_text(item, "skill_id", index)
        if skill_id in seen:
            raise SkillRoutingError(f"duplicate skill_id in routing configuration: {skill_id}")
        seen.add(skill_id)
        priority = item.get("priority")
        if not isinstance(priority, int):
            raise SkillRoutingError(f"route {skill_id} priority must be an integer")
        authorization = item.get("requires_authorization", False)
        if not isinstance(authorization, bool):
            raise SkillRoutingError(f"route {skill_id} requires_authorization must be a boolean")
        risk_level = str(item.get("risk_level") or "standard").strip().casefold()
        if risk_level not in {"standard", "controlled"}:
            raise SkillRoutingError(f"route {skill_id} risk_level must be standard or controlled")
        rules.append(
            RouteRule(
                skill_id=skill_id,
                title=_required_text(item, "title", index),
                phase=_required_text(item, "phase", index),
                priority=priority,
                keywords=_string_list(item.get("keywords"), f"route {skill_id} keywords", allow_empty=False),
                extensions=tuple(value.casefold() for value in _string_list(item.get("extensions"), f"route {skill_id} extensions")),
                input_kinds=tuple(value.casefold() for value in _string_list(item.get("input_kinds"), f"route {skill_id} input_kinds")),
                interfaces=tuple(_normalize_token(value) for value in _string_list(item.get("interfaces"), f"route {skill_id} interfaces")),
                packages=tuple(_normalize_token(value) for value in _string_list(item.get("packages"), f"route {skill_id} packages")),
                url_keywords=tuple(value.casefold() for value in _string_list(item.get("url_keywords"), f"route {skill_id} url_keywords")),
                workflow=_string_list(item.get("workflow") or [skill_id], f"route {skill_id} workflow", allow_empty=False),
                subskills=_string_list(item.get("subskills"), f"route {skill_id} subskills"),
                capability_candidates=_string_list(item.get("capability_candidates"), f"route {skill_id} capability_candidates"),
                tools=_string_list(item.get("tools"), f"route {skill_id} tools"),
                scripts=_string_list(item.get("scripts"), f"route {skill_id} scripts"),
                requires_authorization=authorization,
                risk_level=risk_level,
                execution_boundary=str(item.get("execution_boundary") or "plan_only").strip(),
            )
        )
    return tuple(rules)


def _fallback_rule(payload: Mapping[str, Any], rules: Iterable[RouteRule]) -> RouteRule:
    fallback_id = str(payload.get("fallback_skill_id") or "").strip()
    matches = [rule for rule in rules if rule.skill_id == fallback_id]
    if len(matches) != 1:
        raise SkillRoutingError("fallback_skill_id must name exactly one configured route")
    return matches[0]


def _tool_manifest_path(config_path: Path) -> Path:
    return config_path.parent / "tool-manifest.json"


def _parse_tools(path: Path) -> dict[str, ToolRecord]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise SkillRoutingError(f"could not read tool manifest: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SkillRoutingError(f"invalid tool manifest JSON: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise SkillRoutingError("tool manifest must be a JSON object")
    items = payload.get("tools")
    if not isinstance(items, list):
        raise SkillRoutingError("tool manifest must include a tools array")
    records: dict[str, ToolRecord] = {}
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise SkillRoutingError(f"tool manifest entry {index} must be an object")
        tool_id = str(item.get("id") or "").strip()
        if not tool_id:
            raise SkillRoutingError(f"tool manifest entry {index} id must be non-empty")
        if tool_id in records:
            raise SkillRoutingError(f"duplicate tool manifest id: {tool_id}")
        entrypoint = str(item.get("entrypoint") or "").strip()
        mode = str(item.get("mode") or "").strip()
        summary = str(item.get("summary") or "").strip()
        skill_ids = _string_list(item.get("skill_ids"), f"tool {tool_id} skill_ids", allow_empty=False)
        if not entrypoint or not mode or not summary:
            raise SkillRoutingError(f"tool {tool_id} requires entrypoint, mode, and summary")
        records[tool_id] = ToolRecord(
            id=tool_id,
            entrypoint=entrypoint,
            mode=mode,
            summary=summary,
            skill_ids=skill_ids,
        )
    return records


def _parse_master_skill(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw = payload.get("master_skill")
    if raw is None:
        return {"id": "master", "path": None, "title": "Master skill", "execution_boundary": "plan_only"}
    if not isinstance(raw, Mapping):
        raise SkillRoutingError("master_skill must be an object")
    path = str(raw.get("path") or "").strip()
    if not path:
        raise SkillRoutingError("master_skill.path must be a non-empty string")
    return {
        "id": str(raw.get("id") or "master").strip(),
        "path": path,
        "title": str(raw.get("title") or "Master skill").strip(),
        "execution_boundary": str(raw.get("execution_boundary") or "plan_only").strip(),
    }


def _safe_suite_asset(suite_root: Path, relative: str, label: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise SkillRoutingError(f"{label} must stay inside the skill suite: {relative}")
    candidate = (suite_root / path).resolve()
    try:
        candidate.relative_to(suite_root.resolve())
    except ValueError as exc:
        raise SkillRoutingError(f"{label} must stay inside the skill suite: {relative}") from exc
    return candidate


def _validate_assets(
    suite_root: Path,
    rules: Iterable[RouteRule],
    tools: Mapping[str, ToolRecord],
    master_skill: Mapping[str, Any],
) -> None:
    master_path = master_skill.get("path")
    if master_path:
        resolved_master = _safe_suite_asset(suite_root, str(master_path), "master_skill.path")
        if not resolved_master.is_file():
            raise SkillRoutingError(f"master skill file is missing: {resolved_master}")
    for rule in rules:
        skill_file = _safe_suite_asset(suite_root, f"{rule.skill_id}/SKILL.md", f"route {rule.skill_id} skill")
        if not skill_file.is_file():
            raise SkillRoutingError(f"route {rule.skill_id} references a missing skill: {skill_file}")
        for skill_id in (*rule.workflow, *rule.subskills):
            workflow_file = _safe_suite_asset(suite_root, f"{skill_id}/SKILL.md", f"route {rule.skill_id} workflow")
            if not workflow_file.is_file():
                raise SkillRoutingError(f"route {rule.skill_id} references a missing workflow skill: {workflow_file}")
        for script in rule.scripts:
            script_path = _safe_suite_asset(suite_root, script, f"route {rule.skill_id} script")
            if not script_path.is_file():
                raise SkillRoutingError(f"route {rule.skill_id} references a missing script: {script_path}")
        for tool_id in rule.tools:
            tool = tools.get(tool_id)
            if tool is None:
                raise SkillRoutingError(f"route {rule.skill_id} references an unknown tool: {tool_id}")
            if rule.skill_id not in tool.skill_ids:
                raise SkillRoutingError(f"tool {tool_id} is not declared for route {rule.skill_id}")
            entrypoint = _safe_suite_asset(suite_root, tool.entrypoint, f"tool {tool_id} entrypoint")
            if not entrypoint.is_file():
                raise SkillRoutingError(f"tool {tool_id} references a missing entrypoint: {entrypoint}")


def _required_text(item: Mapping[str, Any], key: str, index: int) -> str:
    value = str(item.get(key) or "").strip()
    if not value:
        raise SkillRoutingError(f"route {index} {key} must be a non-empty string")
    return value


def _string_list(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if value is None:
        values: tuple[str, ...] = ()
    elif isinstance(value, list):
        values = tuple(str(item).strip() for item in value if str(item).strip())
    else:
        raise SkillRoutingError(f"{label} must be an array")
    if not allow_empty and not values:
        raise SkillRoutingError(f"{label} must contain at least one entry")
    return values


def _normalize(value: str) -> str:
    return re.sub(r"[\s_-]+", " ", str(value or "").casefold()).strip()


def _normalize_token(value: str) -> str:
    return re.sub(r"[\s_]+", "-", str(value or "").casefold()).strip("-")


def _route_input(
    query: str,
    *,
    target: str | Path | None,
    endpoint: str | None,
    interface: str | None,
    package: str | None,
) -> RouteInput:
    target_text = _local_target_text(target) or None
    endpoint_text = _endpoint_descriptor(endpoint)
    interface_text = _normalize_token(interface) or None
    package_text = _normalize_token(package) or None
    kinds: list[str] = []
    if target_text:
        kinds.append("local-file")
    if endpoint_text:
        kinds.append("url-descriptor")
    if interface_text:
        kinds.append("interface-descriptor")
    if package_text:
        kinds.append("package-descriptor")
    return RouteInput(
        query=str(query or ""),
        target=target_text,
        endpoint=endpoint_text,
        interface=interface_text,
        package=package_text,
        kinds=tuple(kinds),
    )


def _endpoint_descriptor(endpoint: str | None) -> str | None:
    endpoint_text = str(endpoint or "").strip()
    if not endpoint_text:
        return None
    parsed = urlsplit(endpoint_text)
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        raise SkillRoutingError("endpoint must be an absolute HTTP or HTTPS URL descriptor")
    return endpoint_text


def _local_target_text(target: str | Path | None) -> str:
    target_text = str(target or "").strip()
    if _looks_like_uri(target_text):
        raise SkillRoutingError("target must be a local path, not a URI")
    return target_text


def _looks_like_uri(value: str) -> bool:
    return bool(re.match(r"^[a-z][a-z0-9+.-]*://", value, flags=re.IGNORECASE))


def _matches_keyword(keyword: str, query: str) -> bool:
    """Match ASCII terms as words while retaining Chinese phrase matching."""

    if re.fullmatch(r"[a-z0-9.+-]+", keyword):
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", query))
    return keyword in query


def _skill_reference(skill_id: str) -> dict[str, str]:
    return {"skill_id": skill_id, "path": f"{skill_id}/SKILL.md"}


def _next_actions(
    primary: Mapping[str, Any], *, has_local_target: bool
) -> list[str]:
    actions = [
        "Read the master SKILL.md before opening the selected workflow stages.",
        "Create or select a local case workspace before producing artifacts.",
        "Check the declared tools with the tool-index script.",
    ]
    return actions
