"""CLI entrypoints for cross-platform instruction deployment.

``reverse-instruct`` is the console entry point for the cross-platform
instruction / identity deployment framework.  It wraps the registry and
exposes ``list``, ``inspect``, ``deploy``, ``describe``, and ``restore`` for
any supported platform, honoring the same safety model as the codex CLI:
writes require ``--allowed`` (or ``--force``) and are confined, atomic, and
reversible.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .adapter import InstructionDeployError
from .registry import (
    adapter_for,
    deploy,
    inspect,
    list_platforms,
    platform_aliases,
    restore,
)


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse-instruct",
        description=(
            "Deploy or inspect the branded topology instruction bundle across "
            "supported coding-agent platforms (codex / claude / cursor / workbuddy)."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    list_cmd = commands.add_parser("list", help="list available platforms and aliases")

    describe = commands.add_parser(
        "describe",
        help="show a readonly plan (no writes) of what a deploy would do",
    )
    describe.add_argument("--platform", required=True)
    describe.add_argument("--target", type=Path, default=None)

    inspect_cmd = commands.add_parser(
        "inspect",
        help="read-only scan for branded instruction presence on a platform",
    )
    inspect_cmd.add_argument("--platform", required=True)
    inspect_cmd.add_argument("--target", type=Path, default=None)

    deploy_cmd = commands.add_parser(
        "deploy",
        help="deploy the branded instruction bundle to a platform target",
    )
    deploy_cmd.add_argument("--platform", required=True)
    deploy_cmd.add_argument("--target", type=Path, default=None)
    deploy_cmd.add_argument("--allowed", action="store_true", default=False)
    deploy_cmd.add_argument(
        "--force",
        action="store_true",
        default=False,
        dest="force",
        help="unrestricted/force-deploy: skip --allowed and allow initialising a "
        "target you fully control",
    )
    deploy_cmd.add_argument("--dry-run", action="store_true")

    restore_cmd = commands.add_parser(
        "restore", help="restore a prior deploy from a recorded evidence manifest"
    )
    restore_cmd.add_argument("--platform", required=True)
    restore_cmd.add_argument("--target", type=Path, default=None)

    return parser


def _list_command() -> int:
    _print_json(
        {
            "platforms": list(list_platforms()),
            "aliases": dict(platform_aliases()),
        }
    )
    return 0


def _describe_command(args: argparse.Namespace) -> int:
    try:
        adapter = adapter_for(args.platform)
        plan = adapter.describe(args.target)
    except (InstructionDeployError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_json(plan.to_dict())
    return 0


def _inspect_command(args: argparse.Namespace) -> int:
    try:
        result = inspect(args.platform, str(args.target) if args.target else None)
    except (InstructionDeployError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_json(result)
    return 0


def _deploy_command(args: argparse.Namespace) -> int:
    try:
        result = deploy(
            args.platform,
            str(args.target) if args.target else None,
            allowed=args.allowed,
            force=args.force,
            dry_run=args.dry_run,
        )
    except (InstructionDeployError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_json(result)
    return 0


def _restore_command(args: argparse.Namespace) -> int:
    try:
        result = restore(args.platform, str(args.target) if args.target else None)
    except (InstructionDeployError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_json(result)
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            return _list_command()
        if args.command == "describe":
            return _describe_command(args)
        if args.command == "inspect":
            return _inspect_command(args)
        if args.command == "deploy":
            return _deploy_command(args)
        if args.command == "restore":
            return _restore_command(args)
    except InstructionDeployError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
