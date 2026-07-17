#!/usr/bin/env python3
"""Deploy Codex model instructions to one or more Codex installations.

Usage:
  python scripts/codex-instruct.py
  python scripts/codex-instruct.py --file reverse-skills/.../SKILL.md
  python scripts/codex-instruct.py --name ctf-rules
  python scripts/codex-instruct.py --dry-run
"""

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from reverse_analyzer.llm_jailbreak.instruction_assets import (  # noqa: E402
    list_instruction_profiles,
    load_instruction_bundle,
)


DEFAULT_INSTRUCTION_PROFILE = "ctf-sandbox"


def find_codex_dirs():
    """Find Codex homes that contain a config.toml file."""
    # Windows
    if os.name == "nt":
        userprofile = os.environ.get("USERPROFILE", "")
        localappdata = os.environ.get("LOCALAPPDATA", "")
        home = Path.home()

        search_roots = [
            Path(userprofile) if userprofile else None,
            home,
            Path(localappdata) / "OpenAI" / "Codex" if localappdata else None,
        ]
        # Also inspect user directories on common Windows drives.
        for drive in ["C:", "D:", "E:"]:
            dp = Path(drive)
            if dp.exists():
                for d in dp.iterdir():
                    if d.is_dir() and d.name.lower() == "users":
                        search_roots.append(d)
    else:
        home = Path.home()
        search_roots = [home, Path("/home"), Path("/root")]

    found = set()
    for root in search_roots:
        if root is None or not root.exists():
            continue
        try:
            # Look directly below each root and one user directory deeper.
            for depth in [1, 2]:
                pattern = "*/" * (depth - 1) + ".codex" if depth > 1 else ".codex"
                for p in root.glob(pattern):
                    if p.is_dir():
                        config = p / "config.toml"
                        if config.exists():
                            found.add(str(p.resolve()))
        except PermissionError:
            continue

    # CODEX_HOME may point to an installation outside the common locations.
    codex_home = os.environ.get("CODEX_HOME", "")
    if codex_home:
        p = Path(codex_home)
        if p.is_dir() and (p / "config.toml").exists():
            found.add(str(p.resolve()))

    return sorted(found)


def backup_config(config_path: Path) -> Path:
    """Create a timestamped backup of config.toml."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = config_path.with_suffix(f".toml.bak_{ts}")
    shutil.copy2(config_path, backup)
    return backup


def ensure_model_instructions(config_path: Path, md_filename: str) -> bool:
    """Point config.toml at md_filename and report whether it changed."""
    content = config_path.read_text(encoding="utf-8")
    target_line = f'model_instructions_file = "./{md_filename}"'

    # Update an existing setting in place.
    if "model_instructions_file" in content:
        lines = content.splitlines()
        new_lines = []
        modified = False
        for line in lines:
            if line.strip().startswith("model_instructions_file"):
                new_line = target_line
                if line.strip() != target_line:
                    modified = True
                new_lines.append(new_line)
            else:
                new_lines.append(line)
        if modified:
            config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            return True
        return False

    # Insert the setting after the model when possible.
    lines = content.splitlines()
    insert_after = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("model ") and "=" in stripped:
            insert_after = i
            break

    if insert_after >= 0:
        lines.insert(insert_after + 1, target_line)
    else:
        # A config without a model setting remains valid with an appended value.
        lines.append(target_line)

    config_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


def deploy(args):
    """Load and deploy an instruction bundle."""
    # 1. Load the requested Markdown content through the shared asset API.
    profile = "" if args.file else (args.profile or DEFAULT_INSTRUCTION_PROFILE)
    files = (args.file,) if args.file else ()
    try:
        md_content = load_instruction_bundle(profile=profile, files=files).content
    except FileNotFoundError:
        print(f"[error] File not found: {args.file}")
        sys.exit(1)
    except (OSError, TypeError, ValueError) as exc:
        print(f"[error] Could not load instruction file: {exc}")
        sys.exit(1)

    md_filename = f"{args.name}.md"

    # 2. Locate Codex installations.
    codex_dirs = find_codex_dirs()
    if not codex_dirs:
        print("[!] No Codex installation found (.codex/config.toml)")
        print(
            "    Specify one manually: python scripts/codex-instruct.py "
            "--codex-dir C:\\Users\\xxx\\.codex"
        )
        sys.exit(1)

    print(f"[+] Found {len(codex_dirs)} Codex installation(s):")
    for d in codex_dirs:
        print(f"    {d}")

    if args.dry_run:
        print("\n[DRY RUN] Preview only; no files will be changed.")
        for d in codex_dirs:
            md_dest = Path(d) / md_filename
            print(f"\n  Target: {d}")
            print(f"    -> Write Markdown: {md_dest}")
            print(f"    -> Config: model_instructions_file = \"./{md_filename}\"")
        return

    # 3. Deploy to every Codex installation.
    for d in codex_dirs:
        codex_root = Path(d)
        config_path = codex_root / "config.toml"
        md_dest = codex_root / md_filename

        print(f"\n-- Deploying to: {codex_root} --")

        # 3a. Back up the configuration.
        backup = backup_config(config_path)
        print(f"  [backup] config.toml -> {backup.name}")

        # 3b. Write the instruction file as UTF-8.
        md_dest.write_text(md_content, encoding="utf-8")
        print(f"  [write] {md_dest}")

        # 3c. Update config.toml when needed.
        changed = ensure_model_instructions(config_path, md_filename)
        if changed:
            print(f"  [config] Set model_instructions_file = \"./{md_filename}\"")
        else:
            print(
                "  [config] model_instructions_file already has the requested "
                "value; skipped"
            )

    print(f"\n[done] Deployed to {len(codex_dirs)} Codex installation(s).")


def main():
    parser = argparse.ArgumentParser(
        description="Deploy a Markdown instruction bundle to Codex installations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Use the built-in CTF sandbox instructions
  %(prog)s --list-profiles         List repository-backed instruction profiles
  %(prog)s --profile codex-unified Deploy a named repository instruction bundle
  %(prog)s --name my-rules         Write the bundle as my-rules.md
  %(prog)s --file ./my_prompt.md   Use an external Markdown file
  %(prog)s --file reverse-skills/skills/reverse-engineering/SKILL.md
                                   Use a repository reverse-skill asset
  %(prog)s --dry-run               Preview without changing files
  %(prog)s --codex-dir D:\\.codex  Use a specific Codex directory
        """,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--file",
        "-f",
        help=(
            "Markdown file path, including reverse-skills assets "
            "(default: built-in CTF sandbox instructions)"
        ),
    )
    source.add_argument(
        "--profile",
        help=(
            "repository-backed instruction profile "
            f"(default: {DEFAULT_INSTRUCTION_PROFILE})"
        ),
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="list repository-backed instruction profiles and exit",
    )
    parser.add_argument(
        "--name",
        "-n",
        default="gpt5.5-unrestricted",
        help="Markdown filename without .md (default: gpt5.5-unrestricted)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="preview without changing files",
    )
    parser.add_argument(
        "--codex-dir",
        help="use a specific .codex directory instead of scanning",
    )
    args = parser.parse_args()

    if args.list_profiles:
        for profile in list_instruction_profiles():
            print(profile)
        return

    if args.codex_dir:
        # Manual mode overrides automatic discovery.
        codex_root = Path(args.codex_dir)
        config_path = codex_root / "config.toml"
        if not config_path.exists():
            print(f"[error] config.toml not found in specified directory: {codex_root}")
            sys.exit(1)
        global find_codex_dirs
        find_codex_dirs = lambda: [str(codex_root.resolve())]  # noqa

    deploy(args)


if __name__ == "__main__":
    main()
