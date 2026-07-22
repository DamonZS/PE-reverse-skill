from __future__ import annotations

import argparse
import hashlib
import json
import re
import uuid
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Mapping, Sequence
from zipfile import BadZipFile, ZipFile

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
    "sbom.cdx.json",
    "smoke_release.py",
)
_SECRET_PATTERNS = (
    re.compile(rb"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b", re.IGNORECASE),
)


def _wheel_metadata(root: Path) -> Mapping[str, Any]:
    wheels = sorted(root.glob("*.whl"))
    if len(wheels) != 1:
        raise ValueError("release must contain exactly one wheel artifact")
    try:
        with ZipFile(wheels[0]) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if name.endswith(".dist-info/METADATA")
            ]
            if len(candidates) != 1:
                raise ValueError("wheel must contain exactly one dist-info/METADATA")
            message = BytesParser().parsebytes(archive.read(candidates[0]))
    except (BadZipFile, KeyError, OSError) as exc:
        raise ValueError(f"invalid wheel metadata: {exc}") from exc
    name = str(message.get("Name") or "").strip()
    version = str(message.get("Version") or "").strip()
    requires_python = str(message.get("Requires-Python") or "").strip()
    if name.replace("_", "-").casefold() != "reverse-analyzer":
        raise ValueError(f"unexpected wheel project name: {name or '<missing>'}")
    if version != __version__:
        raise ValueError(
            f"wheel metadata version does not match product version {__version__}: "
            f"{version or '<missing>'}"
        )
    if not requires_python:
        raise ValueError("wheel metadata has no Requires-Python")
    return {
        "name": name,
        "version": version,
        "requires_python": requires_python,
        "requirements": tuple(message.get_all("Requires-Dist") or ()),
    }


def _normalized_requirements(metadata: Mapping[str, Any]) -> list[str]:
    return sorted(
        {str(requirement).strip() for requirement in metadata["requirements"]},
        key=str.casefold,
    )


def write_release_sbom(directory: str | Path) -> Mapping[str, Any]:
    """Write a deterministic CycloneDX inventory for the portable package."""

    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        raise OSError(f"release directory does not exist: {root}")
    metadata = _wheel_metadata(root)
    requirements = _normalized_requirements(metadata)
    dependencies = [
        {
            "type": "library",
            "bom-ref": f"pkg:pypi/{match.group(1).replace('_', '-').lower()}",
            "name": match.group(1).replace("_", "-").lower(),
            "purl": f"pkg:pypi/{match.group(1).replace('_', '-').lower()}",
            "properties": [
                {"name": "python.requirement", "value": requirement}
            ],
        }
        for requirement in requirements
        if (match := re.match(r"^([A-Za-z0-9_.-]+)", requirement)) is not None
    ]
    root_ref = f"pkg:pypi/reverse-analyzer@{__version__}"
    payload: Mapping[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.UUID(hashlib.sha256(root_ref.encode()).hexdigest()[:32])}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "reverse-jailbreak",
                "version": __version__,
                "purl": root_ref,
            },
            "properties": [
                {"name": "python.requires", "value": metadata["requires_python"]}
            ],
        },
        "components": dependencies,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [item["bom-ref"] for item in dependencies]}
        ],
    }
    (root / "sbom.cdx.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


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


def _sbom_errors(root: Path) -> list[str]:
    path = root / "sbom.cdx.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"invalid release SBOM: {exc}"]
    if not isinstance(payload, Mapping):
        return ["release SBOM root must be an object"]
    errors: list[str] = []
    try:
        wheel_metadata = _wheel_metadata(root)
    except ValueError as exc:
        return [str(exc)]
    if payload.get("bomFormat") != "CycloneDX" or payload.get("specVersion") != "1.5":
        errors.append("release SBOM must use CycloneDX 1.5")
    component = payload.get("metadata", {}).get("component", {}) if isinstance(payload.get("metadata"), Mapping) else {}
    if not isinstance(component, Mapping) or component.get("version") != wheel_metadata["version"]:
        errors.append(f"release SBOM component version must be {__version__}")
    properties = payload.get("metadata", {}).get("properties", []) if isinstance(payload.get("metadata"), Mapping) else []
    python_requires = {
        item.get("value")
        for item in properties
        if isinstance(item, Mapping) and item.get("name") == "python.requires"
    } if isinstance(properties, list) else set()
    if python_requires != {wheel_metadata["requires_python"]}:
        errors.append("release SBOM Python requirement does not match wheel metadata")
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        errors.append("release SBOM must list direct dependencies")
    elif any(
        not isinstance(item, Mapping)
        or not str(item.get("name") or "")
        or not str(item.get("purl") or "").startswith("pkg:pypi/")
        or not isinstance(item.get("properties"), list)
        for item in components
    ):
        errors.append("release SBOM contains an invalid dependency component")
    else:
        sbom_requirements = {
            prop.get("value")
            for item in components
            for prop in item["properties"]
            if isinstance(prop, Mapping)
            and prop.get("name") == "python.requirement"
        }
        if sbom_requirements != set(_normalized_requirements(wheel_metadata)):
            errors.append("release SBOM dependencies do not match wheel metadata")
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
    errors.extend(_sbom_errors(root))
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
    errors.extend(_sbom_errors(root))
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
    parser.add_argument("action", choices=("build", "sbom", "verify"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "build":
            payload = write_release_manifest(args.directory)
            result = {"status": "ok", "ok": True, **payload}
        elif args.action == "sbom":
            payload = write_release_sbom(args.directory)
            result = {"status": "ok", "ok": True, "sbom": payload}
        else:
            result = dict(verify_release_manifest(args.directory))
    except (OSError, ValueError) as exc:
        result = {"status": "failed", "ok": False, "errors": [str(exc)]}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 4


if __name__ == "__main__":
    raise SystemExit(main())
