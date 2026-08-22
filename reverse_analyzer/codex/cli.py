"""Command-line entrypoints for codex inspection and constrained deployment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .inspect import inspect_codex
from .inject import CodexInjectError, inject_codex, restore_codex


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse-codex",
        description=(
            "Inspect and (under an explicit, authorized, confirmed target) "
            "instrument a local Codex config directory."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser(
        "inspect",
        help="read-only scan for instruction-file redirect, planted skills, activation words",
    )
    inspect.add_argument("--target", type=Path, default=None, help="exact .codex directory")
    inspect.add_argument("--json", action="store_true", dest="json_output")

    inject = commands.add_parser(
        "inject",
        help="deploy the instruction bundle into an explicit authorized codex directory",
    )
    inject.add_argument("--target", type=Path, required=True)
    inject.add_argument("--allowed", action="store_true", default=False)
    inject.add_argument(
        "--force",
        action="store_true",
        default=False,
        dest="unrestricted",
        help=(
            "unrestricted/force-deploy: skip the --allowed confirmation and allow "
            "initialising a codex directory that has no config.toml yet (for a target "
            "you fully control)"
        ),
    )
    inject.add_argument("--instruction-profile", default="gpt5.5-unrestricted")
    inject.add_argument("--dry-run", action="store_true")
    inject.add_argument("--json", action="store_true", dest="json_output")

    restore = commands.add_parser("restore", help="restore a prior inject from backup manifest")
    restore.add_argument("--target", type=Path, required=True)
    restore.add_argument("--json", action="store_true", dest="json_output")

    return parser


def _inspect_command(args: argparse.Namespace) -> int:
    result = inspect_codex(args.target)
    if args.json_output:
        _print_json(result.to_dict())
    else:
        print(f"root={result.root or '(none)'} exists={result.exists} ok={result.ok}")
        for finding in result.findings:
            print(f"  [{finding.severity:9}] {finding.code}: {finding.message}")
        if result.model_instructions_file:
            print(f"  model_instructions_file={result.model_instructions_file}")
        if result.skill_dirs:
            print(f"  skills={', '.join(result.skill_dirs)}")
    return 0


def _inject_command(args: argparse.Namespace) -> int:
    try:
        result = inject_codex(
            args.target,
            instruction_profile=args.instruction_profile,
            allowed=args.allowed,
            unrestricted=getattr(args, "unrestricted", False),
            dry_run=args.dry_run,
        )
    except CodexInjectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_output:
        _print_json(result)
    else:
        print(f"status={result['status']} target={result['target']}")
        if result["status"] == "ok":
            print(f"  model_instructions_file={result['model_instructions_file']}")
            for artifact in result.get("artifacts", []):
                print(f"  {artifact['kind']:6} {artifact['path']} backup={artifact.get('backup') or '-'}")
    # dry-run and ok are both successful (the former previews without writing).
    return 0 if result["status"] in ("ok", "dry-run") else 1


def _restore_command(args: argparse.Namespace) -> int:
    try:
        result = restore_codex(args.target)
    except CodexInjectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.json_output:
        _print_json(result)
    else:
        print(f"status={result['status']} target={result['target']} restored={len(result['restored'])}")
        for line in result["restored"]:
            print(f"  {line}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            return _inspect_command(args)
        if args.command == "inject":
            return _inject_command(args)
        if args.command == "restore":
            return _restore_command(args)
    except CodexInjectError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
