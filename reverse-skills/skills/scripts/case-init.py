#!/usr/bin/env python3
"""Create an empty, local PE analysis case without ingesting a target."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}$")
STAGE_IDS = [
    "pe-triage",
    "pe-static-analysis",
    "pe-deep-analysis",
    "source-reconstruction",
    "case-review",
]


def normalize_case_id(value: str) -> str:
    """Produce a portable case ID from a user-provided directory name."""
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not CASE_ID_RE.fullmatch(normalized):
        raise ValueError(
            "case ID must contain 1-63 lowercase letters, digits, or hyphens"
        )
    return normalized


def make_case_record(case_id: str) -> dict[str, Any]:
    """Return the schema consumed by review-case.py."""
    created_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return {
        "schema_version": 1,
        "case_id": case_id,
        "created_utc": created_utc,
        "policy": {
            "local_only": True,
            "network": "forbidden",
            "target_execution": "forbidden",
            "auto_install": False,
        },
        "stages": [{"skill_id": stage_id, "status": "pending"} for stage_id in STAGE_IDS],
        "evidence": [],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create an empty, local-only PE analysis case; no target is read or run."
    )
    parser.add_argument(
        "--case-dir",
        type=Path,
        required=True,
        help="New or empty directory for the case record.",
    )
    parser.add_argument(
        "--case-id",
        help="Optional lowercase case ID; defaults to a normalized directory name.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned files without writing them.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    case_dir = args.case_dir.expanduser().resolve()
    try:
        case_id = normalize_case_id(args.case_id or case_dir.name)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if case_dir.exists() and not case_dir.is_dir():
        print("error: --case-dir must be a directory path", file=sys.stderr)
        return 2
    if case_dir.exists() and any(case_dir.iterdir()):
        print("error: refusing to add files to a non-empty case directory", file=sys.stderr)
        return 2

    planned = [
        case_dir / "case.json",
        case_dir / "notes.md",
        case_dir / "evidence",
        case_dir / "reports",
    ]
    if args.dry_run:
        print(json.dumps({"case_id": case_id, "planned": [str(path) for path in planned]}, indent=2))
        return 0

    try:
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "evidence").mkdir(exist_ok=True)
        (case_dir / "reports").mkdir(exist_ok=True)
        (case_dir / "case.json").write_text(
            json.dumps(make_case_record(case_id), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (case_dir / "notes.md").write_text(
            "# Analysis Notes\n\nRecord local, static evidence and its confidence here.\n",
            encoding="utf-8",
        )
    except OSError as error:
        print(f"error: cannot initialize case: {error}", file=sys.stderr)
        return 2

    print(json.dumps({"case_id": case_id, "case_dir": str(case_dir), "created": True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
