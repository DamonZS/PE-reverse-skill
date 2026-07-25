"""P1/P11 machine-readable integration audit.

The audit distinguishes registry reachability from dependency readiness.  Tool
smokes deliberately pass an invalid sentinel keyword so dispatch is exercised
without authorizing a real target operation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from reverse_analyzer.platform_catalog import build_platform_catalog
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.skills import SkillCatalog
from reverse_analyzer.tools import register_builtin_tools


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit(root: Path) -> dict[str, Any]:
    root = root.resolve()
    catalog = build_platform_catalog(root)
    executor = register_builtin_tools()
    skills = SkillCatalog(root / "reverse-skills")
    registry = build_default_registry()
    checks: list[dict[str, Any]] = []
    blocking: list[str] = []

    for item in catalog["skills"]:
        loaded = skills.get(str(item["id"]))
        checks.append({
            "kind": "skill",
            "id": item["id"],
            "discoverable": True,
            "invocation_smoke": "loaded" if loaded else "failed",
            "execution_boundary": "instruction_asset",
        })
        if loaded is None:
            blocking.append(f"skill_load_failed:{item['id']}")

    for item in catalog["tools"]:
        result = executor.execute(str(item["id"]), _p11_smoke_dispatch=True)
        reached = result.status == "failed" and result.error is not None
        checks.append({
            "kind": "tool",
            "id": item["id"],
            "discoverable": str(item["id"]) in executor.tools,
            "invocation_smoke": "dispatch_rejected_invalid_sentinel" if reached else result.status,
            "real_target_invoked": False,
            "error_type": (result.error or "").split(":", 1)[0] or None,
        })
        if not reached:
            blocking.append(f"tool_dispatch_smoke_unexpected:{item['id']}")

    for item in catalog["providers"]:
        capability = str(item["capability"])
        provider = str(item["provider"])
        try:
            resolved = registry.resolve(capability, preferred=provider)
            implementation = f"{type(resolved).__module__}.{type(resolved).__qualname__}"
            ok = implementation == item["implementation"]
        except Exception as error:  # registry boundary must remain evidence
            implementation = None
            ok = False
            blocking.append(f"provider_resolve_failed:{capability}:{provider}:{type(error).__name__}")
        checks.append({
            "kind": "provider",
            "id": item["id"],
            "discoverable": True,
            "invocation_smoke": "resolved" if ok else "failed",
            "implementation": implementation,
            "network_call": False,
        })

    for item in catalog["scripts"]:
        path = root / str(item["path"])
        valid = path.is_file() and path.resolve().is_relative_to(root)
        checks.append({
            "kind": "script",
            "id": item["id"],
            "discoverable": valid,
            "invocation_smoke": "content_loaded" if valid else "failed",
            "sha256": _sha256(path) if valid else None,
            "real_execution": False,
            "classification": item["classification"],
        })
        if not valid:
            blocking.append(f"script_load_failed:{item['id']}")

    for item in catalog["github_tools"]:
        complete = bool(item.get("source") and item.get("license") and item.get("version"))
        checks.append({
            "kind": "github_tool",
            "id": item["id"],
            "discoverable": True,
            "invocation_smoke": "manifest_loaded",
            "dependency_ready": None,
            "source_locked": complete,
        })
        if not complete:
            blocking.append(f"github_tool_lock_incomplete:{item['id']}")

    return {
        "schema_version": 1,
        "status": "passed" if not blocking else "dependency-gated",
        "catalog": catalog,
        "checks": checks,
        "summary": {
            "check_count": len(checks),
            "discoverable_count": sum(item["discoverable"] is True for item in checks),
            "smoke_passed_count": sum(item["invocation_smoke"] not in {"failed"} for item in checks),
            "real_target_invocation_count": 0,
            "blocking_count": len(blocking),
        },
        "blocking_reasons": blocking,
        "truthfulness": (
            "Discovery and non-target dispatch/load smokes do not prove external dependency "
            "readiness or live target acceptance."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = audit(Path(args.workspace))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "output": str(output), "checks": result["summary"]["check_count"]}))
    return 0 if result["status"] == "passed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
