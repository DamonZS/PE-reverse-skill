"""Evidence-backed project structure and dependency readiness manifests.

This module is deliberately conservative: an existing build descriptor is
evidence of structure, while dependency locking requires a reproducible
artifact identity (a digest or content-addressed local source).
"""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

try:  # Python 3.11+; the package itself still supports Python 3.10.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    tomllib = None  # type: ignore[assignment]


SCHEMA_VERSION = 1
SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".cs", ".java", ".kt", ".kts", ".go", ".rs", ".swift",
    ".m", ".mm", ".py", ".js", ".jsx", ".ts", ".tsx", ".vue",
}
DESCRIPTOR_NAMES = {
    "cmakelists.txt": "cmake",
    "meson.build": "meson",
    "makefile": "make",
    "pyproject.toml": "python",
    "setup.py": "python",
    "package.json": "node",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "apktool.yml": "apktool",
    "pom.xml": "maven",
    "cargo.toml": "cargo",
    "go.mod": "go",
}
IGNORED_PARTS = {".git", ".build", "build", "dist", "node_modules", "__pycache__", "cmakefiles"}


def build_project_manifests(
    project_dir: Path | str,
    target_results: Iterable[Mapping[str, Any]],
    *,
    write: bool = True,
) -> dict[str, Any]:
    """Inspect a composite project and optionally write all P4 artifacts."""
    root = Path(project_dir).resolve()
    if not root.is_dir():
        raise ValueError(f"composite project does not exist: {root}")

    targets = [_inspect_target(root, result) for result in target_results]
    dependencies = _collect_dependencies(root, targets)
    structure_blockers: list[dict[str, Any]] = []
    for target in targets:
        if not target["source_files"]:
            structure_blockers.append(_blocker("missing_source", target["id"], "target has no recognized source files"))
        if not target["build_descriptors"]:
            structure_blockers.append(_blocker("missing_build_descriptor", target["id"], "target has no recognized build descriptor"))
    dependency_blockers = [
        _blocker("dependency_not_locked", item.get("target_id"), item["reason"], dependency=item["id"])
        for item in dependencies if not item["locked"]
    ]
    structure_complete = bool(targets) and not structure_blockers
    dependencies_locked = not dependency_blockers

    project_manifest = {
        "schema_version": SCHEMA_VERSION,
        "project_root": root.name,
        "target_count": len(targets),
        "structure_complete": structure_complete,
        "targets": targets,
        "blockers": structure_blockers,
    }
    dependency_manifest = {
        "schema_version": SCHEMA_VERSION,
        "dependencies_locked": dependencies_locked,
        "dependency_count": len(dependencies),
        "dependencies": dependencies,
        "blockers": dependency_blockers,
    }
    all_blockers = [*structure_blockers, *dependency_blockers]
    readiness = {
        "schema_version": SCHEMA_VERSION,
        "structure_complete": structure_complete,
        "dependencies_locked": dependencies_locked,
        "build_ready": structure_complete and dependencies_locked,
        "blockers": all_blockers,
        "blocking_reasons": [f'{item["code"]}:{item.get("target_id") or "project"}' for item in all_blockers],
        "target_count": len(targets),
        "dependency_count": len(dependencies),
        "evidence": {
            "project_manifest": "docs/project-manifest.json",
            "dependency_lock": "docs/dependencies.lock.json",
        },
    }
    result = {
        "project_manifest": project_manifest,
        "dependency_lock": dependency_manifest,
        "build_readiness": readiness,
        "artifacts": {
            "project_manifest": "docs/project-manifest.json",
            "dependency_lock": "docs/dependencies.lock.json",
            "build_readiness": "docs/build-readiness.json",
        },
    }
    if write:
        docs = root / "docs"
        docs.mkdir(parents=True, exist_ok=True)
        _write_json(docs / "project-manifest.json", project_manifest)
        _write_json(docs / "dependencies.lock.json", dependency_manifest)
        _write_json(docs / "build-readiness.json", readiness)
    return result


def _inspect_target(root: Path, result: Mapping[str, Any]) -> dict[str, Any]:
    target_id = str(result.get("id") or "").strip()
    if not target_id:
        raise ValueError("target result is missing id")
    raw_path = str(result.get("composite_path") or f"targets/{target_id}")
    relative = PurePosixPath(raw_path.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"target path escapes project: {raw_path}")
    target_root = (root / Path(*relative.parts)).resolve()
    if not target_root.is_relative_to(root):
        raise ValueError(f"target path escapes project: {raw_path}")

    files = list(_project_files(target_root)) if target_root.is_dir() else []
    sources = [path for path in files if path.suffix.casefold() in SOURCE_SUFFIXES]
    descriptors = [path for path in files if path.name.casefold() in DESCRIPTOR_NAMES]
    return {
        "id": target_id,
        "kind": str(result.get("kind") or "unknown"),
        "path": _relative(root, target_root),
        "exists": target_root.is_dir(),
        "source_files": [_file_evidence(root, path) for path in sources],
        "build_descriptors": [
            {**_file_evidence(root, path), "build_system": DESCRIPTOR_NAMES[path.name.casefold()]}
            for path in descriptors
        ],
    }


def _collect_dependencies(root: Path, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for target in targets:
        target_root = root / Path(target["path"])
        descriptor_paths = {
            root / Path(item["path"]): item["build_system"]
            for item in target["build_descriptors"]
        }
        if target_root.is_dir():
            descriptor_paths.update({path: "python-requirements" for path in _project_files(target_root) if path.name.casefold() == "requirements.txt"})
        for path, system in descriptor_paths.items():
            if system == "cmake":
                collected.extend(_cmake_dependencies(root, target["id"], target_root, path))
            elif path.name == "requirements.txt":
                collected.extend(_requirements_dependencies(root, target["id"], path))
            elif path.name == "pyproject.toml":
                collected.extend(_pyproject_dependencies(root, target["id"], path))
            elif path.name == "package.json":
                collected.extend(_node_dependencies(root, target["id"], path))
            elif system == "gradle":
                collected.extend(_gradle_dependencies(root, target["id"], path))
            elif system == "maven":
                collected.extend(_maven_dependencies(root, target["id"], path))
            elif system == "cargo":
                collected.extend(_cargo_dependencies(root, target["id"], path))
            elif system == "go":
                collected.extend(_go_dependencies(root, target["id"], path))
            elif system == "apktool":
                continue
            elif system != "python-requirements":
                collected.append(_dependency(
                    target["id"], system, f"<unverified-{path.name}>", None, path, False,
                    f"dependency discovery for {path.name} is not implemented", root=root,
                ))
    return _deduplicate(collected)


def _cmake_dependencies(root: Path, target_id: str, target_root: Path, path: Path) -> list[dict[str, Any]]:
    text = _cmake_without_comments(path.read_text(encoding="utf-8", errors="replace"))
    local_targets = set(re.findall(r"(?i)\b(?:add_library|add_executable)\s*\(\s*([^\s\)]+)", text))
    dependencies: list[dict[str, Any]] = []
    packages: dict[str, tuple[str | None, bool]] = {}
    for match in re.finditer(r"(?is)\bfind_package\s*\((.*?)\)", text):
        tokens = re.findall(r'"[^"]*"|[^\s]+', match.group(1))
        if not tokens:
            continue
        name = tokens[0].strip('"')
        version = next((token.strip('"') for token in tokens[1:] if re.fullmatch(r"\d+(?:\.\d+)*(?:[-+][\w.-]+)?", token.strip('"'))), None)
        packages[name.casefold()] = (version, any(token.casefold() == "exact" for token in tokens))
        reason = "CMake package has no exact version and verified artifact digest"
        dependencies.append(_dependency(target_id, "cmake", name, version, path, False, reason, root=root))
    for match in re.finditer(r"(?is)\btarget_link_libraries\s*\((.*?)\)", text):
        tokens = re.findall(r'"[^"]*"|[^\s]+', match.group(1))
        for token in tokens[1:]:
            name = token.strip('"')
            if not name or name.casefold() in {"private", "public", "interface", "debug", "optimized", "general"} or name.startswith("$"):
                continue
            if name in local_targets:
                digest = _tree_sha256(target_root)
                dependencies.append(_dependency(target_id, "cmake", name, None, path, True, "local target content is hashed", root=root, source="local", integrity=f"sha256:{digest}"))
            elif "::" not in name and (target_root / name).exists():
                local = (target_root / name).resolve()
                dependencies.append(_dependency(target_id, "cmake", name, None, path, True, "local dependency content is hashed", root=root, source="local", integrity=f"sha256:{_path_sha256(local)}"))
            elif not any(name.casefold().startswith(package) for package in packages):
                dependencies.append(_dependency(target_id, "cmake", name, None, path, False, "linked library is not a declared, content-locked local target", root=root))
    return dependencies


def _requirements_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    logical = path.read_text(encoding="utf-8", errors="replace").replace("\\\n", " ").splitlines()
    result: list[dict[str, Any]] = []
    for line in logical:
        value = line.strip()
        if not value or value.startswith("#") or value.startswith(("-r", "--requirement")):
            continue
        hashes = re.findall(r"--hash=(sha(?:256|384|512):[0-9a-fA-F]+)", value)
        spec = value.split(" --hash=", 1)[0].strip()
        if spec.startswith(("./", "../", "file:")):
            local = _resolve_local(path.parent, spec.removeprefix("file:"))
            locked = local is not None
            result.append(_dependency(target_id, "python", spec, None, path, locked, "local dependency content is hashed" if locked else "local dependency path is missing", root=root, source="local", integrity=f"sha256:{_path_sha256(local)}" if local else None))
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?==([^\s;]+)", spec)
        name, version = (match.group(1), match.group(2)) if match else (spec, None)
        locked = bool(match and hashes)
        result.append(_dependency(target_id, "python", name, version, path, locked, "exact version and distribution hash recorded" if locked else "Python requirement needs == version and --hash", root=root, integrity=hashes[0] if hashes else None))
    return result


def _pyproject_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    if tomllib is None:
        return [_dependency(target_id, "python", "<unparsed-pyproject>", None, path, False, "Python 3.10 runtime needs tomli to parse pyproject.toml", root=root)]
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        return [_dependency(target_id, "python", "<invalid-pyproject>", None, path, False, f"pyproject.toml cannot be parsed: {exc}", root=root)]
    raw = payload.get("project", {}).get("dependencies", [])
    build_requires = payload.get("build-system", {}).get("requires", [])
    raw = [*(raw if isinstance(raw, list) else []), *(build_requires if isinstance(build_requires, list) else [])]
    lock_entries = _python_lock_entries(path.parent)
    result = []
    for spec in raw:
        value = str(spec)
        match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([^\s;]+)$", value)
        name = match.group(1) if match else (re.match(r"^([A-Za-z0-9_.-]+)", value).group(1) if re.match(r"^([A-Za-z0-9_.-]+)", value) else value)
        locked = lock_entries.get(name.casefold())
        result.append(_dependency(
            target_id,
            "python",
            name,
            locked[0] if locked else (match.group(2) if match else None),
            locked[2] if locked else path,
            bool(locked),
            "Python lock records exact version and distribution hash" if locked else "pyproject dependency lacks an exact distribution hash lock",
            root=root,
            integrity=locked[1] if locked else None,
        ))
    return result


def _python_lock_entries(directory: Path) -> dict[str, tuple[str, str, Path]]:
    if tomllib is None:
        return {}
    for name in ("uv.lock", "poetry.lock"):
        lock_path = directory / name
        if not lock_path.is_file():
            continue
        try:
            payload = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            continue
        entries: dict[str, tuple[str, str, Path]] = {}
        packages = payload.get("package", [])
        for package in packages if isinstance(packages, list) else []:
            if not isinstance(package, dict):
                continue
            package_name = str(package.get("name") or "")
            version = str(package.get("version") or "")
            hashes: list[str] = []
            for file in package.get("files", []) if isinstance(package.get("files"), list) else []:
                if isinstance(file, dict) and file.get("hash"):
                    hashes.append(str(file["hash"]))
            for wheel in package.get("wheels", []) if isinstance(package.get("wheels"), list) else []:
                if isinstance(wheel, dict) and wheel.get("hash"):
                    hashes.append(str(wheel["hash"]))
            source = package.get("sdist")
            if isinstance(source, dict) and source.get("hash"):
                hashes.append(str(source["hash"]))
            if package_name and version and hashes:
                entries[package_name.casefold()] = (version, hashes[0], lock_path)
        return entries
    return {}


def _node_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    try:
        package = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return [_dependency(target_id, "node", "<invalid-package-json>", None, path, False, f"package.json cannot be parsed: {exc}", root=root)]
    declared: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = package.get(section, {})
        if isinstance(values, dict):
            declared.update({str(name): str(version) for name, version in values.items()})
    lock_path = path.with_name("package-lock.json")
    lock = _read_json(lock_path) if lock_path.is_file() else None
    packages = lock.get("packages", {}) if isinstance(lock, dict) else {}
    result = []
    for name, requested in declared.items():
        if requested.startswith(("file:", "link:")):
            local = _resolve_local(path.parent, requested.split(":", 1)[1])
            result.append(_dependency(target_id, "node", name, requested, path, local is not None, "local dependency content is hashed" if local else "local dependency path is missing", root=root, source="local", integrity=f"sha256:{_path_sha256(local)}" if local else None))
            continue
        entry = packages.get(f"node_modules/{name}", {}) if isinstance(packages, dict) else {}
        version = str(entry.get("version") or "") if isinstance(entry, dict) else ""
        integrity = str(entry.get("integrity") or "") if isinstance(entry, dict) else ""
        locked = bool(version and integrity)
        result.append(_dependency(target_id, "node", name, version or requested, lock_path if lock_path.is_file() else path, locked, "package-lock version and integrity recorded" if locked else "Node dependency needs package-lock version and integrity", root=root, integrity=integrity or None))
    return result


def _gradle_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    verification = next(iter(path.parent.glob("**/verification-metadata.xml")), None)
    verification_text = verification.read_text(encoding="utf-8", errors="replace") if verification else ""
    result = []
    pattern = r"(?m)^\s*(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]"
    for group, name, version in re.findall(pattern, text):
        has_hash = bool(verification and re.search(rf'group="{re.escape(group)}"[\s\S]*?name="{re.escape(name)}"[\s\S]*?<sha(?:256|512)\s+value="[0-9a-fA-F]+"', verification_text))
        result.append(_dependency(target_id, "gradle", f"{group}:{name}", version, verification or path, has_hash and not any(marker in version for marker in ("+", "latest", "SNAPSHOT")), "Gradle verification metadata records artifact digest" if has_hash else "Gradle dependency needs fixed version and verification metadata hash", root=root))
    return result


def _maven_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        return [_dependency(target_id, "maven", "<invalid-pom>", None, path, False, f"pom.xml cannot be parsed: {exc}", root=root)]
    result = []
    for element in tree.getroot().iter():
        if element.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        fields = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip() for child in element}
        name = f'{fields.get("groupId", "?")}:{fields.get("artifactId", "?")}'
        result.append(_dependency(target_id, "maven", name, fields.get("version"), path, False, "Maven descriptor does not provide an artifact checksum lock", root=root))
    return result


def _cargo_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    lock_path = path.with_name("Cargo.lock")
    if tomllib is None or not lock_path.is_file():
        lock_packages: dict[str, tuple[str, str]] = {}
    else:
        try:
            lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError):
            lock = {}
        lock_packages = {
            str(item.get("name")): (str(item.get("version")), str(item.get("checksum")))
            for item in lock.get("package", []) if isinstance(item, dict) and item.get("name") and item.get("version") and item.get("checksum")
        }
    try:
        manifest = tomllib.loads(path.read_text(encoding="utf-8")) if tomllib is not None else {}
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        manifest = {}
    result = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        values = manifest.get(section, {})
        for name, requested in values.items() if isinstance(values, dict) else []:
            if isinstance(requested, dict) and requested.get("path"):
                local = _resolve_local(path.parent, str(requested["path"]))
                result.append(_dependency(target_id, "cargo", str(name), None, path, local is not None, "local dependency content is hashed" if local else "local dependency path is missing", root=root, source="local", integrity=f"sha256:{_path_sha256(local)}" if local else None))
                continue
            locked = lock_packages.get(str(name))
            result.append(_dependency(target_id, "cargo", str(name), locked[0] if locked else str(requested), lock_path if locked else path, bool(locked), "Cargo.lock records version and checksum" if locked else "Cargo dependency needs Cargo.lock checksum", root=root, integrity=f"sha256:{locked[1]}" if locked else None))
    return result


def _go_dependencies(root: Path, target_id: str, path: Path) -> list[dict[str, Any]]:
    sums: dict[tuple[str, str], str] = {}
    sum_path = path.with_name("go.sum")
    if sum_path.is_file():
        for line in sum_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) == 3 and not parts[1].endswith("/go.mod"):
                sums[(parts[0], parts[1])] = parts[2]
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.findall(r"(?ms)^require\s*\((.*?)^\)", text)
    lines = [*re.findall(r"(?m)^require\s+([^\s]+)\s+([^\s]+)", text)]
    for block in blocks:
        lines.extend(re.findall(r"(?m)^\s*([^\s/][^\s]*)\s+([^\s]+)", block))
    result = []
    for name, version in lines:
        integrity = sums.get((name, version))
        result.append(_dependency(target_id, "go", name, version, sum_path if integrity else path, bool(integrity), "go.sum records module content hash" if integrity else "Go module dependency needs matching go.sum content hash", root=root, integrity=integrity))
    return result


def _dependency(target_id: str, ecosystem: str, name: str, version: str | None, evidence: Path, locked: bool, reason: str, *, root: Path, source: str = "external", integrity: str | None = None) -> dict[str, Any]:
    identifier = f"{ecosystem}:{name}"
    return {
        "id": identifier,
        "target_id": target_id,
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
        "source": source,
        "integrity": integrity,
        "locked": locked,
        "reason": reason,
        "evidence": [_relative(root, evidence)],
    }


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str | None, str | None]] = set()
    for item in items:
        key = (item["target_id"], item["id"], item["version"], item["integrity"])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return sorted(result, key=lambda item: (item["target_id"], item["id"], item["version"] or ""))


def _project_files(root: Path) -> Iterable[Path]:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not any(part.casefold() in IGNORED_PARTS for part in path.relative_to(root).parts):
            yield path


def _file_evidence(root: Path, path: Path) -> dict[str, Any]:
    return {"path": _relative(root, path), "size": path.stat().st_size, "sha256": _file_sha256(path)}


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in _project_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_file_sha256(path)))
    return digest.hexdigest()


def _path_sha256(path: Path) -> str:
    return _tree_sha256(path) if path.is_dir() else _file_sha256(path)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_local(parent: Path, value: str) -> Path | None:
    candidate = (parent / value).resolve()
    return candidate if candidate.exists() else None


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return str(path.resolve())


def _blocker(code: str, target_id: str | None, message: str, **extra: Any) -> dict[str, Any]:
    return {"code": code, "target_id": target_id, "message": message, **extra}


def _cmake_without_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
