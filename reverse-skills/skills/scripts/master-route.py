#!/usr/bin/env python3
"""Route an AI or operator request through the checked-in PE skill contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


SKILLS_ROOT = Path(__file__).resolve().parent.parent
REPOSITORY_ROOT = SKILLS_ROOT.parents[1]
DEFAULT_CONFIG = SKILLS_ROOT / "config" / "routing.json"

if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from reverse_analyzer.skills.runtime import SkillRouter, SkillRoutingError  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Route a reverse-analysis request."
    )
    selector = parser.add_mutually_exclusive_group()
    selector.add_argument("--intent", help="Plain-language request to route.")
    selector.add_argument("--skill-id", help="Explicit skill ID from config/routing.json.")
    parser.add_argument("--target", help="Optional local target path used for suffix routing.")
    parser.add_argument("--endpoint", "--url", dest="endpoint", help="Optional HTTP(S) endpoint descriptor.")
    parser.add_argument("--interface", help="Optional interface kind such as rest, graphql, or websocket.")
    parser.add_argument("--package", help="Optional package ecosystem such as android, dotnet, or npm.")
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Local routing JSON path (default: %(default)s).",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format (default: %(default)s).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        router = SkillRouter(SKILLS_ROOT.parent, config_path=args.config)
        decision = (
            router.route_by_id(
                args.skill_id,
                target=args.target,
                endpoint=args.endpoint,
                interface=args.interface,
                package=args.package,
            )
            if args.skill_id
            else router.route(
                args.intent or "",
                target=args.target,
                endpoint=args.endpoint,
                interface=args.interface,
                package=args.package,
                limit=3,
            )
        )
        primary = decision["primary"]
        result = {
            "status": decision["status"],
            "skill_id": primary["skill_id"],
            "skill_path": f"{primary['skill_id']}/SKILL.md",
            "title": primary["title"],
            "phase": primary["phase"],
            "tools": primary["tools"],
            "scripts": primary["scripts"],
            "route": decision,
        }
    except SkillRoutingError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"skill: {result['skill_id']}")
        print(f"path: {result['skill_path']}")
        print(f"phase: {result['phase']}")
        print(f"tools: {', '.join(result['tools'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
