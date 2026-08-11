#!/usr/bin/env python3
"""Validate the local intelligent reverse-router suite without executing targets."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping


DEFAULT_ROOT = Path(__file__).resolve().parent.parent
ROUTE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}(?:/[a-z0-9][a-z0-9-]{0,62})*$")
TOOL_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}$")
RISK_LEVELS = {"standard", "controlled"}
BASE_POLICY = {
    "scope": "local-offline",
    "network": "forbidden",
    "target_execution": "forbidden",
    "auto_install": False,
}


def load_json(path: Path, label: str, issues: list[str]) -> dict[str, Any] | None:
    """Load an object-shaped JSON file and accumulate validation errors."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        issues.append(f"cannot read {label}: {error}")
        return None
    except json.JSONDecodeError as error:
        issues.append(f"invalid {label} JSON: {error}")
        return None
    if not isinstance(value, dict):
        issues.append(f"{label} must contain a JSON object")
        return None
    return value


def is_nonempty_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def is_string_array(value: Any, *, nonempty: bool = False) -> bool:
    return isinstance(value, list) and (not nonempty or bool(value)) and all(
        is_nonempty_text(item) for item in value
    )


def inside_root(root: Path, relative_path: str) -> Path | None:
    """Resolve a configured path only when it remains inside the skills root."""

    candidate = (root / relative_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def validate_skill_document(path: Path, issues: list[str]) -> None:
    """Accept current and legacy SKILL.md metadata while requiring usable content."""

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        issues.append(f"cannot read skill document {path}: {error}")
        return
    if not lines:
        issues.append(f"{path}: skill document must not be empty")
        return

    if lines[0] == "---":
        try:
            closing_index = lines.index("---", 1)
        except ValueError:
            issues.append(f"{path}: missing closing frontmatter delimiter")
            return
        metadata: dict[str, str] = {}
        for line in lines[1:closing_index]:
            if not line or line[:1].isspace() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key, value = key.strip(), value.strip()
            if key in {"name", "description"} and value:
                metadata[key] = value
        missing = [key for key in ("name", "description") if not metadata.get(key)]
        if missing:
            issues.append(f"{path}: frontmatter must provide non-empty {', '.join(missing)}")
        return

    has_heading = any(line.startswith("# ") and line[2:].strip() for line in lines)
    has_body = any(line.strip() and not line.startswith("#") for line in lines)
    if not has_heading or not has_body:
        issues.append(f"{path}: legacy skill document must contain a title and description")


def validate_skill_reference(root: Path, skill_id: str, label: str, issues: list[str]) -> None:
    """Validate a skill ID and its checked-in SKILL.md document."""

    if not ROUTE_ID_RE.fullmatch(skill_id):
        issues.append(f"{label} has an invalid skill ID: {skill_id!r}")
        return
    skill_path = inside_root(root, f"{skill_id}/SKILL.md")
    if skill_path is None or not skill_path.is_file():
        issues.append(f"{label} skill file is missing: {skill_id}/SKILL.md")
        return
    validate_skill_document(skill_path, issues)


def validate_policy(policy: Any, label: str, issues: list[str]) -> Mapping[str, Any] | None:
    """Validate the non-executing policy shared by routing and tool metadata."""

    if not isinstance(policy, Mapping):
        issues.append(f"{label} must be an object")
        return None
    for key, expected in BASE_POLICY.items():
        if policy.get(key) != expected:
            issues.append(f"{label}.{key} must be {expected!r}")
    return policy


def validate_master_skill(root: Path, routing: Mapping[str, Any], issues: list[str]) -> None:
    """Ensure the AI-visible entry point is a local, documented master skill."""

    master = routing.get("master_skill")
    if not isinstance(master, Mapping):
        issues.append("routing.master_skill must be an object")
        return
    for field in ("id", "path", "title", "execution_boundary"):
        if not is_nonempty_text(master.get(field)):
            issues.append(f"routing.master_skill.{field} must be a non-empty string")
    path = master.get("path")
    if not isinstance(path, str) or not path.strip():
        return
    master_path = inside_root(root, path)
    if master_path is None or not master_path.is_file():
        issues.append(f"routing.master_skill.path references missing local file: {path!r}")
        return
    validate_skill_document(master_path, issues)


def validate_routing(root: Path, routing: Mapping[str, Any], issues: list[str]) -> list[dict[str, Any]]:
    """Validate descriptors, workflows, subskills, and local route assets."""

    if routing.get("version") != 1:
        issues.append("routing.version must be 1")
    suite = routing.get("suite")
    if not isinstance(suite, Mapping):
        issues.append("routing.suite must be an object")
    else:
        for field in ("title", "description"):
            if not is_nonempty_text(suite.get(field)):
                issues.append(f"routing.suite.{field} must be a non-empty string")
    validate_master_skill(root, routing, issues)
    policy = validate_policy(routing.get("policy"), "routing.policy", issues)

    routes = routing.get("routes")
    if not isinstance(routes, list) or not routes:
        issues.append("routing.routes must be a non-empty list")
        return []

    valid_routes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    has_controlled_route = False
    for index, route in enumerate(routes):
        prefix = f"routing.routes[{index}]"
        if not isinstance(route, dict):
            issues.append(f"{prefix} must be an object")
            continue
        skill_id = route.get("skill_id")
        if not isinstance(skill_id, str) or not ROUTE_ID_RE.fullmatch(skill_id):
            issues.append(f"{prefix}.skill_id is invalid")
            continue
        if skill_id in seen_ids:
            issues.append(f"{prefix}.skill_id is duplicated: {skill_id}")
            continue
        seen_ids.add(skill_id)
        valid_routes.append(route)

        for field in ("title", "phase", "execution_boundary"):
            if not is_nonempty_text(route.get(field)):
                issues.append(f"{prefix}.{field} must be a non-empty string")
        if type(route.get("priority")) is not int:
            issues.append(f"{prefix}.priority must be an integer")
        if not is_string_array(route.get("keywords"), nonempty=True):
            issues.append(f"{prefix}.keywords must be a non-empty string array")
        for field in ("extensions", "interfaces", "packages", "url_keywords", "subskills", "capability_candidates", "tools", "scripts"):
            if not is_string_array(route.get(field)):
                issues.append(f"{prefix}.{field} must be a string array")
        for field in ("input_kinds", "workflow"):
            if not is_string_array(route.get(field), nonempty=True):
                issues.append(f"{prefix}.{field} must be a non-empty string array")
        if type(route.get("requires_authorization")) is not bool:
            issues.append(f"{prefix}.requires_authorization must be a boolean")
        risk_level = route.get("risk_level")
        if not isinstance(risk_level, str) or risk_level not in RISK_LEVELS:
            issues.append(f"{prefix}.risk_level must be one of {sorted(RISK_LEVELS)!r}")
        elif risk_level == "controlled":
            has_controlled_route = True
            if route.get("requires_authorization") is not True:
                issues.append(f"{prefix} controlled routes must require authorization")

        validate_skill_reference(root, skill_id, prefix, issues)
        for field in ("workflow", "subskills"):
            values = route.get(field)
            if not is_string_array(values):
                continue
            for referenced_id in values:
                validate_skill_reference(root, referenced_id, f"{prefix}.{field}", issues)
        scripts = route.get("scripts")
        if is_string_array(scripts):
            for script in scripts:
                script_path = inside_root(root, script)
                if script_path is None or not script_path.is_file():
                    issues.append(f"{prefix}.scripts references missing local file: {script!r}")

    fallback_id = routing.get("fallback_skill_id")
    if not isinstance(fallback_id, str) or fallback_id not in seen_ids:
        issues.append("routing.fallback_skill_id must name a configured route")
    if has_controlled_route and (policy is None or policy.get("controlled_capabilities") != "authorization_required"):
        issues.append("routing.policy.controlled_capabilities must be 'authorization_required' when controlled routes exist")
    return valid_routes


def validate_manifest(
    root: Path, manifest: Mapping[str, Any], route_ids: tuple[str, ...], issues: list[str]
) -> dict[str, dict[str, Any]]:
    """Validate tool declarations and return the usable records by ID."""

    if manifest.get("format") != "pe-skill-tool-manifest/v1":
        issues.append("tool manifest format must be pe-skill-tool-manifest/v1")
    if manifest.get("version") != 1:
        issues.append("tool manifest version must be 1")
    validate_policy(manifest.get("policy"), "tool manifest policy", issues)
    manifest_skill_ids = manifest.get("skill_ids")
    if not is_string_array(manifest_skill_ids, nonempty=True):
        issues.append("tool manifest skill_ids must be a non-empty string array")
    elif tuple(manifest_skill_ids) != route_ids:
        issues.append("tool manifest skill_ids must match routing route IDs in order")

    tools = manifest.get("tools")
    if not isinstance(tools, list) or not tools:
        issues.append("tool manifest tools must be a non-empty list")
        return {}

    known_routes = set(route_ids)
    records: dict[str, dict[str, Any]] = {}
    for index, tool in enumerate(tools):
        prefix = f"tool manifest tools[{index}]"
        if not isinstance(tool, dict):
            issues.append(f"{prefix} must be an object")
            continue
        tool_id = tool.get("id")
        if not isinstance(tool_id, str) or not TOOL_ID_RE.fullmatch(tool_id):
            issues.append(f"{prefix}.id is invalid")
            continue
        if tool_id in records:
            issues.append(f"{prefix}.id is duplicated: {tool_id}")
            continue
        records[tool_id] = tool
        for field in ("mode", "summary", "entrypoint"):
            if not is_nonempty_text(tool.get(field)):
                issues.append(f"{prefix}.{field} must be a non-empty string")
        entrypoint = tool.get("entrypoint")
        if isinstance(entrypoint, str) and entrypoint.strip():
            script_path = inside_root(root, entrypoint)
            if script_path is None or not script_path.is_file():
                issues.append(f"{prefix}.entrypoint references missing local file: {entrypoint!r}")
        skill_ids = tool.get("skill_ids")
        if not is_string_array(skill_ids, nonempty=True):
            issues.append(f"{prefix}.skill_ids must be a non-empty string array")
        elif not set(skill_ids).issubset(known_routes):
            issues.append(f"{prefix}.skill_ids contains an ID absent from routing")
    return records


def validate_route_tool_links(routes: list[dict[str, Any]], tools: Mapping[str, Mapping[str, Any]], issues: list[str]) -> None:
    """Ensure every route exposes only helpers explicitly granted in the manifest."""

    for index, route in enumerate(routes):
        skill_id = str(route.get("skill_id", ""))
        route_tools = route.get("tools")
        if not is_string_array(route_tools):
            continue
        for tool_id in route_tools:
            tool = tools.get(tool_id)
            if tool is None:
                issues.append(f"routing.routes[{index}].tools references unknown tool: {tool_id!r}")
                continue
            declared_for = tool.get("skill_ids")
            if not isinstance(declared_for, list) or skill_id not in declared_for:
                issues.append(f"tool {tool_id!r} is not declared for route {skill_id!r}")


def _table_cell(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ").strip()


def render_index(routing: Mapping[str, Any], routes: list[dict[str, Any]]) -> str:
    """Render the same generated master-first navigation as the refresh script."""

    suite = routing.get("suite") if isinstance(routing.get("suite"), Mapping) else {}
    master = routing.get("master_skill") if isinstance(routing.get("master_skill"), Mapping) else {}
    title = _table_cell(suite.get("title") if isinstance(suite, Mapping) else "") or "Intelligent Reverse Task Router"
    master_title = _table_cell(master.get("title") if isinstance(master, Mapping) else "") or "Master skill"
    master_path = _table_cell(master.get("path") if isinstance(master, Mapping) else "") or "SKILL.md"
    lines = [
        "<!-- Generated by scripts/refresh-skill-index.py. Do not edit by hand. -->",
        "",
        f"# {title}",
        "",
        f"Start with [{master_title}]({master_path}), then follow the selected workflow and its indexed subskills/tools.",
        "",
        "| Workflow | Phase | Risk | Authorization | Indexed tools | Purpose |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for route in routes:
        skill_id = _table_cell(route.get("skill_id"))
        workflow_title = _table_cell(route.get("title"))
        phase = _table_cell(route.get("phase"))
        risk_level = _table_cell(route.get("risk_level")) or "standard"
        authorization = "required" if route.get("requires_authorization") else "not required"
        tools = _table_cell(", ".join(str(tool) for tool in route.get("tools", []) if str(tool))) or "-"
        boundary = _table_cell(route.get("execution_boundary"))
        lines.append(
            f"| [{workflow_title}]({skill_id}/SKILL.md) | {phase} | {risk_level} | {authorization} | {tools} | {boundary} |"
        )
    lines.append("")
    return "\n".join(lines)


def validate_index(
    root: Path,
    routing: Mapping[str, Any],
    routes: list[dict[str, Any]],
    strict: bool,
    issues: list[str],
    warnings: list[str],
) -> None:
    """Report a stale generated index without modifying it."""

    index_path = root / "INDEX.md"
    expected = render_index(routing, routes)
    try:
        current = index_path.read_text(encoding="utf-8")
    except OSError:
        message = "generated INDEX.md is missing"
    else:
        message = "generated INDEX.md is stale" if current != expected else ""
    if message:
        (issues if strict else warnings).append(message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate local intelligent reverse-router metadata; no targets are read or executed."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=DEFAULT_ROOT,
        help="Skills root containing config and packages (default: %(default)s).",
    )
    parser.add_argument(
        "--strict-index",
        action="store_true",
        help="Fail when the generated navigation index is missing or stale.",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: %(default)s).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.expanduser().resolve()
    issues: list[str] = []
    warnings: list[str] = []
    routing = load_json(root / "config" / "routing.json", "routing config", issues)
    routes: list[dict[str, Any]] = []
    if routing is not None:
        routes = validate_routing(root, routing, issues)
    manifest = load_json(root / "config" / "tool-manifest.json", "tool manifest", issues)
    if manifest is not None:
        route_ids = tuple(str(route.get("skill_id", "")) for route in routes)
        tools = validate_manifest(root, manifest, route_ids, issues)
        validate_route_tool_links(routes, tools, issues)
    if routing is not None and routes:
        validate_index(root, routing, routes, args.strict_index, issues, warnings)

    result = {"ok": not issues, "issues": issues, "warnings": warnings, "root": str(root)}
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("PASS" if result["ok"] else "FAIL")
        for issue in issues:
            print(f"issue: {issue}")
        for warning in warnings:
            print(f"warning: {warning}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
