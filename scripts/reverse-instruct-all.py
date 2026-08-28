#!/usr/bin/env python3
"""One-shot deployer for the branded topology instruction across all local
platforms (Codex / Claude / Cursor / WorkBuddy).

This is the "一键部署到本地全部平台" entry.  It wraps the
``reverse_analyzer.instructions`` batch verbs (``deploy_all`` / ``restore_all``)
so you can instrument every installed coding-agent in a single command, with the
same safety model: writes require ``--allowed`` (or ``--force``); ``--dry-run``
is a zero-side-effect preview.

The default verb (no subcommand) is *deploy*: run ``--dry-run`` to preview,
``--allowed`` to act, or ``--force`` to override.  ``inspect`` and ``restore``
are explicit subcommands.

Usage:
  python scripts/reverse-instruct-all.py --dry-run     # preview every platform
  python scripts/reverse-instruct-all.py --allowed     # deploy to every platform
  python scripts/reverse-instruct-all.py --force       # force-deploy every platform
  python scripts/reverse-instruct-all.py inspect       # read-only scan
  python scripts/reverse-instruct-all.py restore       # restore every platform
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reverse_analyzer.instructions import (  # noqa: E402
    deploy_all,
    inspect_all,
    restore_all,
)


def _print(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverse-instruct-all",
        description=(
            "Deploy the branded topology instruction bundle to every supported "
            "local platform (codex / claude / cursor / workbuddy) in one shot."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s --dry-run          preview every platform, no writes\n"
            "  %(prog)s --allowed          deploy to every platform (confirm authorization)\n"
            "  %(prog)s --force            force-deploy every platform you control\n"
            "  %(prog)s inspect            read-only scan of every platform\n"
            "  %(prog)s restore            restore every platform from recorded evidence\n"
        ),
    )

    # The default verb is deploy; ``--dry-run`` etc. can be passed either at the
    # top level (preferred, "真正一键") or after the explicit ``deploy`` verb.
    parser.add_argument("--allowed", action="store_true", default=False)
    parser.add_argument("--force", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true")

    sub = parser.add_subparsers(dest="verb")
    sub.add_parser("deploy", help="(default) deploy to every platform").set_defaults(
        action="deploy"
    )
    sub.add_parser("inspect", help="read-only scan every platform").set_defaults(
        action="inspect"
    )
    sub.add_parser("restore", help="restore every platform").set_defaults(
        action="restore"
    )
    sub.add_parser("list", help="list supported platforms").set_defaults(action="list")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    action = getattr(args, "action", "deploy")

    if action == "deploy":
        payload = deploy_all(
            allowed=args.allowed,
            force=args.force,
            dry_run=args.dry_run,
        )
        _print(payload)

        results = payload.get("results", {})
        ok = sum(1 for v in results.values() if v.get("status") != "error")
        err = sum(1 for v in results.values() if v.get("status") == "error")
        total = len(results)
        mode = "preview (dry-run)" if args.dry_run else "deploy"
        print(
            f"\n[reverse-instruct-all] {mode}: {ok}/{total} platform(s) ok, "
            f"{err} error(s)."
        )
        return 1 if err else 0

    if action == "inspect":
        _print(inspect_all())
        return 0

    if action == "restore":
        _print(restore_all())
        return 0

    if action == "list":
        from reverse_analyzer.instructions import list_platforms

        print("\n".join(list_platforms()))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
