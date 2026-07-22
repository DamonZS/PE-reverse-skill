from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from reverse_analyzer._version import __version__


MANIFEST_NAME = "release-manifest.json"
SCHEMA_VERSION = 1
REQUIRED_SUFFIXES = (".whl",)
REQUIRED_FILES = (
    "CHANGELOG.md",
    "RELEASE_NOTES.md",
    "jailbreak-campaign.schema.json",
    "jailbreak-campaign.example.json",
    "reverse_jailbreak_release.md",
    "smoke_release.py",
)
_SECRET_PATTERNS = (
    re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _release_files(root: Path) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (
                path
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink() and path.name != MANIFEST_NAME
            ),
            key=lambda item: item.relative_to(root).as_posix(),
        )
    )


def _symlink_paths(root: Path) -> tuple[str, ...]:
    """Return symlinks in a release without following their targets."""
    return tuple(
        sorted(
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_symlink()
        )
    )


def _required_errors(relative_paths: set[str]) -> list[str]:
    errors = [
        f"missing required release file: {name}"
        for name in REQUIRED_FILES
        if name not in relative_paths
    ]
    wheels = sorted(path for path in relative_paths if path.endswith(REQUIRED_SUFFIXES))
    if not wheels:
        errors.append("missing wheel artifact")
    elif len(wheels) != 1:
        errors.append("release must contain exactly one wheel artifact")
    else:
        expected_prefix = f"reverse_analyzer-{__version__.replace('-', '_')}-"
        if not wheels[0].startswith(expected_prefix):
            errors.append(
                f"wheel version does not match product version {__version__}: {wheels[0]}"
            )
    return errors


def _secret_errors(files: Sequence[Path], root: Path) -> list[str]:
    """Reject obvious credential material from portable release files."""

    errors: list[str] = []
    for path in files:
        try:
            matched = False
            tail = b""
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    window = tail + chunk
                    if any(pattern.search(window) for pattern in _SECRET_PATTERNS):
                        matched = True
                        break
                    tail = window[-256:]
        except OSError:
            continue
        if matched:
            errors.append(
                "release contains credential-like material: "
                f"{path.relative_to(root).as_posix()}"
            )
    return errors


def write_release_manifest(directory: str | Path) -> Mapping[str, Any]:
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise OSError(f"release directory does not exist: {root}")
    files = _release_files(root)
    relative_paths = {path.relative_to(root).as_posix() for path in files}
    errors = _required_errors(relative_paths)
    symlinks = _symlink_paths(root)
    errors.extend(f"release must not contain symlink: {path}" for path in symlinks)
    errors.extend(_secret_errors(files, root))
    if errors:
        raise ValueError("; ".join(errors))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "product": "reverse-jailbreak",
        "product_version": __version__,
        "files": [
            {
                "path": path.relative_to(root).as_posix(),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
            for path in files
        ],
    }
    (root / MANIFEST_NAME).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def verify_release_manifest(directory: str | Path) -> Mapping[str, Any]:
    root = Path(directory).expanduser().resolve()
    manifest_path = root / MANIFEST_NAME
    errors: list[str] = []
    symlinks = _symlink_paths(root) if root.is_dir() else ()
    errors.extend(f"release must not contain symlink: {path}" for path in symlinks)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"status": "failed", "ok": False, "errors": [str(exc)], "files": []}
    if not isinstance(payload, Mapping):
        return {
            "status": "failed",
            "ok": False,
            "errors": ["release manifest root must be an object"],
            "files": [],
        }
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append("release manifest schema_version is unsupported")
    if payload.get("product") != "reverse-jailbreak":
        errors.append("release manifest product is unsupported")
    if payload.get("product_version") != __version__:
        errors.append(
            f"release manifest product_version must be {__version__}"
        )
    entries = payload.get("files")
    if not isinstance(entries, list):
        entries = []
        errors.append("release manifest files must be an array")
    observed: set[str] = set()
    verified: list[Mapping[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            errors.append(f"files[{index}] must be an object")
            continue
        relative = str(entry.get("path") or "")
        candidate = (root / relative).resolve()
        try:
            normalized = candidate.relative_to(root).as_posix()
        except ValueError:
            errors.append(f"files[{index}] escapes release directory")
            continue
        if not relative or normalized != relative or relative in observed:
            errors.append(f"files[{index}] has an invalid or duplicate path")
            continue
        observed.add(relative)
        if not candidate.is_file():
            errors.append(f"missing release file: {relative}")
            continue
        actual_size = candidate.stat().st_size
        actual_sha256 = _sha256(candidate)
        if entry.get("size") != actual_size:
            errors.append(f"size mismatch: {relative}")
        if str(entry.get("sha256") or "").casefold() != actual_sha256:
            errors.append(f"sha256 mismatch: {relative}")
        verified.append(
            {"path": relative, "size": actual_size, "sha256": actual_sha256}
        )
    actual = {
        path.relative_to(root).as_posix() for path in _release_files(root)
    }
    errors.extend(_required_errors(actual))
    errors.extend(_secret_errors(_release_files(root), root))
    for relative in sorted(actual - observed):
        errors.append(f"untracked release file: {relative}")
    for relative in sorted(observed - actual):
        if not any(error.endswith(relative) for error in errors):
            errors.append(f"missing release file: {relative}")
    return {
        "status": "ok" if not errors else "failed",
        "ok": not errors,
        "errors": errors,
        "files": verified,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or verify a portable release manifest")
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "build":
            payload = write_release_manifest(args.directory)
            result = {"status": "ok", "ok": True, **payload}
        else:
            result = dict(verify_release_manifest(args.directory))
    except (OSError, ValueError) as exc:
        result = {"status": "failed", "ok": False, "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 4


if __name__ == "__main__":
    raise SystemExit(main())
