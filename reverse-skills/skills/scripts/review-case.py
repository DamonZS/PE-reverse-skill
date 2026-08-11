#!/usr/bin/env python3
"""Review a local case record without reading or running an analysis target."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SKILLS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROUTING = SKILLS_ROOT / "config" / "routing.json"
REQUIRED_POLICY = {
    "local_only": True,
    "network": "forbidden",
    "target_execution": "forbidden",
    "auto_install": False,
}
VALID_STATUSES = {"pending", "in-progress", "complete", "blocked"}


def load_json(path: Path, label: str) -> dict[str, Any]:
    """Load an object-shaped JSON document with a useful error message."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"cannot read {label}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return value


def route_ids(routing_path: Path) -> set[str]:
    """Read valid stage IDs from the same routing source used by the workbench."""
    routing = load_json(routing_path, "routing config")
    routes = routing.get("routes")
    if not isinstance(routes, list):
        raise ValueError("routing config must contain a routes list")
    ids = {route.get("skill_id") for route in routes if isinstance(route, dict)}
    if not ids or not all(isinstance(value, str) for value in ids):
        raise ValueError("routing config has no valid skill IDs")
    return ids


def review(case_dir: Path, valid_skill_ids: set[str]) -> dict[str, Any]:
    """Return findings only; this function never mutates the case directory."""
    issues: list[str] = []
    warnings: list[str] = []
    case_path = case_dir / "case.json"
    if not case_dir.is_dir():
        return {"case_dir": str(case_dir), "issues": ["case directory is missing"], "warnings": []}
    if not case_path.is_file():
        return {"case_dir": str(case_dir), "issues": ["case.json is missing"], "warnings": []}

    try:
        record = load_json(case_path, "case record")
    except ValueError as error:
        return {"case_dir": str(case_dir), "issues": [str(error)], "warnings": []}

    if record.get("schema_version") != 1:
        issues.append("schema_version must be 1")
    if not isinstance(record.get("case_id"), str) or not record["case_id"].strip():
        issues.append("case_id must be a non-empty string")

    policy = record.get("policy")
    if not isinstance(policy, dict):
        issues.append("policy must be an object")
    else:
        for key, expected in REQUIRED_POLICY.items():
            if policy.get(key) != expected:
                issues.append(f"policy.{key} must be {expected!r}")

    stages = record.get("stages")
    if not isinstance(stages, list) or not stages:
        issues.append("stages must be a non-empty list")
    else:
        seen_stages: set[str] = set()
        for index, stage in enumerate(stages):
            if not isinstance(stage, dict):
                issues.append(f"stages[{index}] must be an object")
                continue
            skill_id = stage.get("skill_id")
            if skill_id not in valid_skill_ids:
                issues.append(f"stages[{index}].skill_id is not in routing config")
            elif skill_id in seen_stages:
                issues.append(f"stages[{index}].skill_id is duplicated: {skill_id}")
            else:
                seen_stages.add(skill_id)
            if stage.get("status") not in VALID_STATUSES:
                issues.append(f"stages[{index}].status is invalid")
        missing = sorted(valid_skill_ids - seen_stages)
        if missing:
            warnings.append("case has no stage record for: " + ", ".join(missing))

    evidence = record.get("evidence")
    if not isinstance(evidence, list):
        issues.append("evidence must be a list")
    elif not evidence:
        warnings.append("case has no evidence entries yet")

    for required_dir in ("evidence", "reports"):
        if not (case_dir / required_dir).is_dir():
            issues.append(f"{required_dir}/ directory is missing")
    if not (case_dir / "notes.md").is_file():
        issues.append("notes.md is missing")

    return {"case_dir": str(case_dir), "issues": issues, "warnings": warnings}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review a local PE case record without executing a target or using a network."
    )
    parser.add_argument("--case-dir", type=Path, required=True, help="Case directory to inspect.")
    parser.add_argument(
        "--routing",
        type=Path,
        default=DEFAULT_ROUTING,
        help="Local routing JSON used to validate stage IDs (default: %(default)s).",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="Output format (default: %(default)s).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings, such as missing evidence, as a failing result.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        valid_skill_ids = route_ids(args.routing)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    result = review(args.case_dir.expanduser().resolve(), valid_skill_ids)
    result["ok"] = not result["issues"] and (not args.strict or not result["warnings"])
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        status = "PASS" if result["ok"] else "FAIL"
        print(f"{status}: {result['case_dir']}")
        for issue in result["issues"]:
            print(f"issue: {issue}")
        for warning in result["warnings"]:
            print(f"warning: {warning}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
