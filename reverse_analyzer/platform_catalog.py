"""Read-only inventory of platform skills, tools, providers, and scripts."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping

from .providers import build_default_registry
from .skills import SkillCatalog
from .tools import register_builtin_tools


def build_platform_catalog(workspace: str | Path) -> dict[str, Any]:
    """Return a JSON-compatible platform inventory without executing catalog items."""

    root = Path(workspace).resolve()
    skills_root = Path(os.environ.get("REVERSE_ANALYZER_SKILLS_DIR", root / "reverse-skills")).resolve()
    skill_catalog = SkillCatalog(skills_root)
    skills = [
        record.to_dict()
        for record in skill_catalog.discover()
    ]
    routing = skill_catalog.audit()["skill_runtime"]
    tools = _builtin_tools()
    providers = _default_providers()
    scripts = _scripts(root / "scripts", root)
    github_tools = _github_tools(root / "config" / "github-tools.lock.json")
    extensions = _external_extensions(skills_root, root)
    discovered_total = len(skills) + len(tools) + len(providers) + len(scripts) + len(github_tools) + len(extensions)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(root),
        "execution_boundary": (
            "read-only catalog; listing an item does not authorize or execute tools, "
            "providers, scripts, installers, or external downloads"
        ),
        "summary": {
            "skill_total": len(skills),
            "tool_total": len(tools),
            "provider_total": len(providers),
            "capability_total": len({item["capability"] for item in providers}),
            "script_total": len(scripts),
            "github_tool_total": len(github_tools),
            "extension_total": len(extensions),
        },
        "integration": {
            "discovered_total": discovered_total,
            "cataloged_total": discovered_total,
            "catalog_coverage_percent": 100.0 if discovered_total else 0.0,
            "meaning": "All discovered repository assets are represented in this catalog; this is separate from dependency readiness and live acceptance.",
        },
        "skills": skills,
        "routing": routing,
        "tools": tools,
        "providers": providers,
        "scripts": scripts,
        "github_tools": github_tools,
        "extensions": extensions,
    }


def _display_path(path: Path, workspace_root: Path) -> str:
    try:
        return path.relative_to(workspace_root).as_posix()
    except ValueError:
        return path.as_posix()


def _external_extensions(skills_root: Path, workspace_root: Path) -> list[dict[str, Any]]:
    """Inventory absorbed external integrations without claiming they are live."""

    records: list[dict[str, Any]] = []
    extension_roots = {
        "ctf-sandbox-orchestrator": skills_root / "CTF-Sandbox-Orchestrator",
        "burp-mcp-full": skills_root / "burp-mcp-full",
        "kali-toolchain": skills_root / "kali",
        "examples": skills_root / "examples",
    }
    for extension_id, directory in extension_roots.items():
        if not directory.is_dir():
            continue
        files = [path for path in directory.rglob("*") if path.is_file()]
        skill_count = sum(path.name == "SKILL.md" for path in files)
        records.append(
            {
                "id": extension_id,
                "name": extension_id.replace("-", " ").title(),
                "kind": "extension",
                "path": _display_path(directory, workspace_root),
                "file_count": len(files),
                "skill_count": skill_count,
                "registered": True,
                "callable": False,
                "dependency_ready": False,
                "accepted": True,
                "status": "absorbed_inventory",
                "execution_boundary": "inventory_only",
                "missing_dependencies": ["external runtime acceptance"] if extension_id != "examples" else [],
            }
        )
    return records


def _builtin_tools() -> list[dict[str, Any]]:
    executor = register_builtin_tools()
    return [
        {
            "id": name,
            "callable": getattr(tool, "__qualname__", getattr(tool, "__name__", name)),
            "module": getattr(tool, "__module__", None),
            "execution_boundary": "registered_only",
        }
        for name, tool in sorted(executor.tools.items())
    ]


def _default_providers() -> list[dict[str, Any]]:
    registry = build_default_registry()
    records: list[dict[str, Any]] = []
    for capability in registry.list_capabilities():
        for provider_name in registry.list_providers(capability):
            provider = registry.resolve(capability, preferred=provider_name)
            records.append(
                {
                    "id": f"{capability}:{provider_name}",
                    "capability": capability,
                    "provider": provider_name,
                    "priority": getattr(provider, "priority", None),
                    "implementation": (
                        f"{type(provider).__module__}.{type(provider).__qualname__}"
                    ),
                    "execution_boundary": "registered_only",
                }
            )
    return records


def _scripts(directory: Path, root: Path) -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    supported = {".py", ".ps1", ".sh", ".bat", ".cmd"}
    records = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in supported:
            continue
        records.append(
            {
                "id": path.relative_to(directory).as_posix(),
                "path": path.relative_to(root).as_posix(),
                "kind": path.suffix.lower().lstrip("."),
                "classification": _script_classification(path),
                "size": path.stat().st_size,
                "execution_boundary": "file_inventory_only",
            }
        )
    return records


def _script_classification(path: Path) -> str:
    name = path.name.lower()
    if name.startswith(("build_", "install_")):
        return "build_or_install"
    if name.startswith(("smoke_", "verify_")):
        return "verification"
    if any(token in name for token in ("attack", "inject", "dump", "unpack", "patch")):
        return "controlled_execution"
    if name.endswith(("_analyze.py", "_extract.py", "_decompile.py")):
        return "offline_analysis"
    return "cli_or_helper"


def _github_tools(manifest_path: Path) -> list[dict[str, Any]]:
    if not manifest_path.is_file():
        return []
    payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    tools = payload.get("tools") if isinstance(payload, Mapping) else None
    if not isinstance(tools, list):
        return []
    records = []
    for item in tools:
        if not isinstance(item, Mapping):
            continue
        records.append(
            {
                "id": str(item.get("id") or ""),
                "version": item.get("version"),
                "platforms": list(item.get("platforms") or []),
                "environment": list(item.get("environment") or []),
                "provider_modules": list(item.get("provider_modules") or []),
                "source": item.get("source"),
                "download": item.get("download"),
                "license": item.get("license"),
                "execution_boundary": "manifest_only",
            }
        )
    return sorted(records, key=lambda item: item["id"])
