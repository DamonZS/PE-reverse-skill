"""Transactional iOS IPA unpack, resign, and verification provider."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import threading
import zipfile
import zlib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, Optional, Protocol

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities.models import (
    CapabilityArtifact,
    CapabilityArtifactBundle,
    CapabilityExecutionResult,
    CapabilityPlan,
    CapabilityRequest,
    CapabilityRollbackResult,
    CapabilityValidation,
)


__all__ = [
    "IOSRebuildProvider",
    "IosRebuildProvider",
    "IosRebuildRunner",
    "LocalIosRebuildBackend",
    "SubprocessIosRebuildRunner",
]


_SCHEMA_VERSION = "1.0"
_SUPPORTED_ACTIONS = {"unpack", "resign", "verify"}
_MAX_ZIP_ENTRIES = 10_000
_MAX_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 768 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000
_RATIO_FLOOR_BYTES = 1024 * 1024
_MAX_PLIST_BYTES = 4 * 1024 * 1024
_IO_CHUNK = 1024 * 1024
_DEFAULT_OUTPUT_LIMIT = 256 * 1024
_MACHO_MAGICS = {
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}
_SECRET_KEY_RE = re.compile(r"(?:password|passphrase|secret|token)", re.I)


class IosRebuildRunner(Protocol):
    """External command runner used by the macOS signing path."""

    def which(self, command: str) -> Optional[str]: ...

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
    ) -> Any: ...


class SubprocessIosRebuildRunner:
    """Bounded production subprocess adapter; commands never use a shell."""

    production = True

    def __init__(self, *, max_output_bytes: int = _DEFAULT_OUTPUT_LIMIT) -> None:
        self.max_output_bytes = max(1024, int(max_output_bytes))

    def which(self, command: str) -> Optional[str]:
        return shutil.which(command)

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        max_output_bytes: Optional[int] = None,
    ) -> dict[str, Any]:
        argv = [str(item) for item in command]
        limit = max(1024, int(max_output_bytes or self.max_output_bytes))
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        buffers = [bytearray(), bytearray()]
        state = {"bytes": 0, "exceeded": False}
        lock = threading.Lock()

        def drain(stream: Any, index: int) -> None:
            while True:
                chunk = stream.read(16 * 1024)
                if not chunk:
                    break
                with lock:
                    room = max(0, limit - state["bytes"])
                    if room:
                        buffers[index].extend(chunk[:room])
                    state["bytes"] += len(chunk)
                    if state["bytes"] > limit and not state["exceeded"]:
                        state["exceeded"] = True
                        try:
                            process.kill()
                        except OSError:
                            pass

        threads = [
            threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, 1), daemon=True),
        ]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=1.0)
        return {
            "returncode": process.returncode,
            "stdout": bytes(buffers[0]).decode("utf-8", errors="replace"),
            "stderr": bytes(buffers[1]).decode("utf-8", errors="replace"),
            "timed_out": timed_out,
            "output_limit_exceeded": bool(state["exceeded"]),
            "output_limit_bytes": limit,
        }


def _is_production_runner(runner: Any, platform_name: str) -> bool:
    return type(runner) is SubprocessIosRebuildRunner and platform_name == "darwin"


class LocalIosRebuildBackend:
    """Bounded local filesystem and IPA implementation."""

    def snapshot(self, path: str | Path) -> dict[str, Any]:
        resolved = _path(path)
        result: dict[str, Any] = {
            "path": str(resolved),
            "exists": resolved.exists(),
            "is_file": resolved.is_file(),
            "is_dir": resolved.is_dir(),
            "is_symlink": resolved.is_symlink(),
        }
        try:
            if resolved.is_file():
                result.update(size=resolved.stat().st_size, sha256=_sha256_file(resolved))
            elif resolved.is_dir():
                digest, count, size = _sha256_tree(resolved)
                result.update(sha256=digest, entry_count=count, size=size)
        except (OSError, ValueError) as exc:
            result["error"] = str(exc)
        return result

    def inspect_ipa(self, path: str | Path) -> dict[str, Any]:
        resolved = _path(path)
        result = {
            **self.snapshot(resolved),
            "kind": "ipa",
            "is_zip": False,
            "zip_integrity": False,
            "payload_present": False,
            "app_count": 0,
            "app_path": None,
            "info_plist_present": False,
            "info_plist_valid": False,
            "bundle_identifier": None,
            "executable": None,
            "macho_present": False,
            "macho_path": None,
            "signature_present": False,
            "static_valid": False,
            "unsafe_entries": [],
            "duplicate_entries": [],
        }
        if not resolved.is_file():
            return result
        try:
            result["is_zip"] = zipfile.is_zipfile(resolved)
            if not result["is_zip"]:
                return result
            with zipfile.ZipFile(resolved) as archive:
                infos, catalog = _validate_zip_catalog(archive.infolist())
                result.update(catalog)
                verified_bytes = _verify_archive_streams(archive, infos)
                result["verified_uncompressed_bytes"] = verified_bytes
                result["zip_integrity"] = True
                names = {info.filename: info for info in infos if not info.is_dir()}
                structure = _ipa_structure(names.keys())
                result.update(structure)
                app_path = structure.get("app_path")
                if app_path:
                    plist_name = f"{app_path}/Info.plist"
                    plist_info = names.get(plist_name)
                    result["info_plist_present"] = plist_info is not None
                    if plist_info is not None:
                        payload = _read_zip_member(archive, plist_info, _MAX_PLIST_BYTES)
                        plist = _parse_info_plist(payload)
                        result.update(plist)
                        executable = plist.get("executable")
                        if executable:
                            macho_name = f"{app_path}/{executable}"
                            macho_info = names.get(macho_name)
                            if macho_info is not None:
                                with archive.open(macho_info) as stream:
                                    result["macho_present"] = stream.read(4) in _MACHO_MAGICS
                                result["macho_path"] = macho_name
                    result["signature_present"] = (
                        f"{app_path}/_CodeSignature/CodeResources" in names
                    )
                result["static_valid"] = _static_checks_ok(result)
        except (
            OSError,
            EOFError,
            RuntimeError,
            ValueError,
            plistlib.InvalidFileException,
            zipfile.BadZipFile,
            zipfile.LargeZipFile,
            zlib.error,
        ) as exc:
            result["error"] = str(exc)
        return result

    def inspect_directory(self, path: str | Path) -> dict[str, Any]:
        root = _path(path)
        result = {
            **self.snapshot(root),
            "kind": "unpacked_ipa",
            "zip_integrity": None,
            "payload_present": False,
            "app_count": 0,
            "app_path": None,
            "info_plist_present": False,
            "info_plist_valid": False,
            "bundle_identifier": None,
            "executable": None,
            "macho_present": False,
            "macho_path": None,
            "signature_present": False,
            "static_valid": False,
        }
        if not root.is_dir():
            return result
        try:
            entries = _walk_tree(root)
            names = {relative for relative, _item, is_dir, _mode, _size in entries if not is_dir}
            result.update(_ipa_structure(names))
            app_path = result.get("app_path")
            if app_path:
                plist_rel = f"{app_path}/Info.plist"
                plist_path = root.joinpath(*PurePosixPath(plist_rel).parts)
                result["info_plist_present"] = plist_rel in names
                if result["info_plist_present"]:
                    if plist_path.stat().st_size > _MAX_PLIST_BYTES:
                        raise ValueError("Info.plist exceeds bounded parser limit")
                    result.update(_parse_info_plist(plist_path.read_bytes()))
                    executable = result.get("executable")
                    if executable:
                        macho_rel = f"{app_path}/{executable}"
                        macho = root.joinpath(*PurePosixPath(macho_rel).parts)
                        if macho_rel in names:
                            with macho.open("rb") as handle:
                                result["macho_present"] = handle.read(4) in _MACHO_MAGICS
                            result["macho_path"] = macho_rel
                result["signature_present"] = (
                    f"{app_path}/_CodeSignature/CodeResources" in names
                )
            result["static_valid"] = _static_checks_ok(result)
        except (OSError, ValueError, plistlib.InvalidFileException) as exc:
            result["error"] = str(exc)
        return result

    def extract_ipa(self, source: str | Path, destination: str | Path) -> None:
        source_path = _path(source)
        destination_path = _path(destination)
        if destination_path.exists():
            raise FileExistsError(f"temporary extraction path exists: {destination_path}")
        destination_path.mkdir(parents=True)
        try:
            with zipfile.ZipFile(source_path) as archive:
                infos, _catalog = _validate_zip_catalog(archive.infolist())
                extracted = 0
                for info in infos:
                    relative = PurePosixPath(info.filename.rstrip("/"))
                    output = destination_path.joinpath(*relative.parts)
                    if not _is_relative_to(output.resolve(), destination_path):
                        raise ValueError(f"unsafe IPA member path: {info.filename}")
                    if info.is_dir():
                        output.mkdir(parents=True, exist_ok=True)
                        continue
                    output.parent.mkdir(parents=True, exist_ok=True)
                    member = 0
                    with archive.open(info) as reader, output.open("xb") as writer:
                        while True:
                            chunk = reader.read(_IO_CHUNK)
                            if not chunk:
                                break
                            member += len(chunk)
                            extracted += len(chunk)
                            if member > _MAX_MEMBER_BYTES or extracted > _MAX_ARCHIVE_BYTES:
                                raise ValueError("IPA extraction exceeded bounded size limits")
                            writer.write(chunk)
                    if member != int(info.file_size):
                        raise ValueError(f"IPA member size mismatch: {info.filename}")
                    mode = (int(info.external_attr) >> 16) & 0o777
                    if mode:
                        output.chmod(mode)
        except Exception:
            shutil.rmtree(destination_path, ignore_errors=True)
            raise

    def copy_tree(self, source: str | Path, destination: str | Path) -> None:
        source_path = _path(source)
        destination_path = _path(destination)
        if destination_path.exists():
            raise FileExistsError(f"tree copy destination exists: {destination_path}")
        entries = _walk_tree(source_path)
        destination_path.mkdir(parents=True)
        try:
            for relative, item, is_dir, mode, _size in entries:
                output = destination_path.joinpath(*PurePosixPath(relative).parts)
                if is_dir:
                    output.mkdir(parents=True, exist_ok=True)
                else:
                    output.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(item, output, follow_symlinks=False)
                try:
                    output.chmod(mode & 0o777)
                except OSError:
                    pass
        except Exception:
            shutil.rmtree(destination_path, ignore_errors=True)
            raise

    def repack_ipa(self, source: str | Path, destination: str | Path) -> None:
        source_path = _path(source)
        destination_path = _path(destination)
        if destination_path.exists():
            raise FileExistsError(f"temporary IPA output exists: {destination_path}")
        inspection = self.inspect_directory(source_path)
        if not inspection.get("static_valid"):
            raise ValueError("unpacked IPA tree failed Payload/Info.plist/Mach-O checks")
        entries = _walk_tree(source_path)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(
                destination_path,
                "x",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=9,
                allowZip64=True,
            ) as archive:
                for relative, item, is_dir, mode, _size in entries:
                    name = relative + ("/" if is_dir else "")
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.flag_bits |= 0x800
                    if is_dir:
                        info.compress_type = zipfile.ZIP_STORED
                        info.external_attr = (stat.S_IFDIR | 0o755) << 16
                        archive.writestr(info, b"")
                    else:
                        permissions = 0o755 if mode & 0o111 else 0o644
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = (stat.S_IFREG | permissions) << 16
                        with item.open("rb") as reader, archive.open(info, "w") as writer:
                            while True:
                                chunk = reader.read(_IO_CHUNK)
                                if not chunk:
                                    break
                                writer.write(chunk)
        except Exception:
            destination_path.unlink(missing_ok=True)
            raise

    def write_json(self, path: str | Path, payload: Mapping[str, Any]) -> None:
        destination = _path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.tmp")
        temporary.write_text(
            json.dumps(_json_value(payload), ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, destination)


def _path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_IO_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _walk_tree(root: Path) -> list[tuple[str, Path, bool, int, int]]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("IPA tree root must be a real directory")
    result: list[tuple[str, Path, bool, int, int]] = []
    total_size = 0

    def visit(directory: Path, prefix: PurePosixPath) -> None:
        nonlocal total_size
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name)
        for child in children:
            relative = (prefix / child.name).as_posix()
            metadata = child.stat(follow_symlinks=False)
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise ValueError(f"symbolic links are not allowed in IPA trees: {relative}")
            if stat.S_ISDIR(mode):
                result.append((relative, Path(child.path), True, mode, 0))
                if len(result) > _MAX_ZIP_ENTRIES:
                    raise ValueError("IPA tree entry count exceeds limit")
                visit(Path(child.path), prefix / child.name)
            elif stat.S_ISREG(mode):
                total_size += metadata.st_size
                if metadata.st_size > _MAX_MEMBER_BYTES or total_size > _MAX_ARCHIVE_BYTES:
                    raise ValueError("IPA tree size exceeds bounded limits")
                result.append((relative, Path(child.path), False, mode, metadata.st_size))
                if len(result) > _MAX_ZIP_ENTRIES:
                    raise ValueError("IPA tree entry count exceeds limit")
            else:
                raise ValueError(f"special files are not allowed in IPA trees: {relative}")

    visit(root, PurePosixPath())
    return sorted(result, key=lambda item: item[0])


def _sha256_tree(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    entries = _walk_tree(root)
    total_size = 0
    for relative, item, is_dir, mode, size in entries:
        digest.update(("D" if is_dir else "F").encode("ascii"))
        digest.update(relative.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(str(mode & 0o777).encode("ascii"))
        digest.update(b"\0")
        if not is_dir:
            total_size += size
            digest.update(_sha256_file(item).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest(), len(entries), total_size


def _zip_member_issue(info: zipfile.ZipInfo) -> Optional[str]:
    name = info.filename
    if not name or "\x00" in name or "\\" in name:
        return "invalid member name"
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        return "absolute member path"
    parts = name.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "non-canonical member path"
    mode = (int(info.external_attr) >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if file_type == stat.S_IFLNK:
        return "symbolic-link member"
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        return "special-file member"
    if int(info.flag_bits) & 0x1:
        return "encrypted member"
    if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
        return "unsupported compression method"
    if info.file_size < 0 or info.compress_size < 0 or info.file_size > _MAX_MEMBER_BYTES:
        return "declared member size exceeds limit"
    if info.file_size >= _RATIO_FLOOR_BYTES:
        ratio = info.file_size / max(1, info.compress_size)
        if info.compress_size == 0 or ratio > _MAX_COMPRESSION_RATIO:
            return "suspicious compression ratio"
    return None


def _validate_zip_catalog(
    infos: Sequence[zipfile.ZipInfo],
) -> tuple[list[zipfile.ZipInfo], dict[str, Any]]:
    if len(infos) > _MAX_ZIP_ENTRIES:
        raise ValueError("IPA ZIP entry count exceeds limit")
    declared = sum(max(0, int(info.file_size)) for info in infos)
    if declared > _MAX_ARCHIVE_BYTES:
        raise ValueError("IPA declared uncompressed size exceeds limit")
    seen: dict[str, str] = {}
    unsafe: list[dict[str, str]] = []
    duplicates: list[str] = []
    for info in infos:
        issue = _zip_member_issue(info)
        if issue:
            unsafe.append({"name": info.filename, "reason": issue})
        key = info.filename.rstrip("/").casefold()
        if key in seen:
            duplicates.append(info.filename)
        else:
            seen[key] = info.filename
    if unsafe:
        raise ValueError(f"unsafe IPA ZIP entry: {unsafe[0]['name']}: {unsafe[0]['reason']}")
    if duplicates:
        raise ValueError(f"duplicate or case-colliding IPA ZIP entry: {duplicates[0]}")
    return list(infos), {
        "entry_count": len(infos),
        "declared_uncompressed_bytes": declared,
        "unsafe_entries": unsafe,
        "duplicate_entries": duplicates,
        "limits": {
            "max_entries": _MAX_ZIP_ENTRIES,
            "max_member_bytes": _MAX_MEMBER_BYTES,
            "max_uncompressed_bytes": _MAX_ARCHIVE_BYTES,
            "max_compression_ratio": _MAX_COMPRESSION_RATIO,
        },
    }


def _verify_archive_streams(
    archive: zipfile.ZipFile, infos: Sequence[zipfile.ZipInfo]
) -> int:
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        member = 0
        with archive.open(info) as handle:
            while True:
                chunk = handle.read(_IO_CHUNK)
                if not chunk:
                    break
                member += len(chunk)
                total += len(chunk)
                if member > _MAX_MEMBER_BYTES or total > _MAX_ARCHIVE_BYTES:
                    raise ValueError("IPA ZIP expanded data exceeds bounded limits")
        if member != int(info.file_size):
            raise ValueError(f"IPA ZIP member size mismatch: {info.filename}")
    return total


def _read_zip_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int
) -> bytes:
    if info.file_size > limit:
        raise ValueError("Info.plist exceeds bounded parser limit")
    with archive.open(info) as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise ValueError("Info.plist exceeds bounded parser limit")
    return payload


def _ipa_structure(names: Sequence[str]) -> dict[str, Any]:
    app_roots = sorted(
        {
            match.group(1)
            for name in names
            if (match := re.match(r"^(Payload/[^/]+\.app)(?:/|$)", name))
        }
    )
    return {
        "payload_present": any(name == "Payload" or name.startswith("Payload/") for name in names),
        "app_count": len(app_roots),
        "app_path": app_roots[0] if len(app_roots) == 1 else None,
    }


def _parse_info_plist(payload: bytes) -> dict[str, Any]:
    value = plistlib.loads(payload)
    if not isinstance(value, Mapping):
        raise ValueError("Info.plist root must be a mapping")
    executable = value.get("CFBundleExecutable")
    if not isinstance(executable, str) or not executable or "/" in executable or "\\" in executable:
        raise ValueError("Info.plist CFBundleExecutable is missing or unsafe")
    bundle_identifier = value.get("CFBundleIdentifier")
    return {
        "info_plist_valid": True,
        "bundle_identifier": str(bundle_identifier) if bundle_identifier else None,
        "executable": executable,
    }


def _static_checks_ok(value: Mapping[str, Any]) -> bool:
    return bool(
        value.get("payload_present")
        and int(value.get("app_count") or 0) == 1
        and value.get("info_plist_present")
        and value.get("info_plist_valid")
        and value.get("macho_present")
        and (value.get("zip_integrity") is not False)
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _normalize_action(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


def _safe_segment(value: Any) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "session")).strip(".-")
    return cleaned[:80] or "session"


def _first(mapping: Mapping[str, Any], names: Sequence[str]) -> Any:
    for name in names:
        value = mapping.get(name)
        if value not in (None, ""):
            return value
    return None


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _bounded_number(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return min(high, max(low, number))


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "<redacted>"
                if _SECRET_KEY_RE.search(str(key))
                and not str(key).casefold().endswith("_configured")
                else _sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return _json_value(value)


def _same_hash(left: Any, right: Any) -> bool:
    return bool(left and right and str(left).casefold() == str(right).casefold())


def _valid_sha256(value: Any) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(value or "")))


def _same_snapshot(expected: Any, actual: Any) -> bool:
    if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
        return False
    if bool(expected.get("exists")) != bool(actual.get("exists")):
        return False
    if not expected.get("exists"):
        return True
    return (
        bool(expected.get("is_file")) == bool(actual.get("is_file"))
        and bool(expected.get("is_dir")) == bool(actual.get("is_dir"))
        and _same_hash(expected.get("sha256"), actual.get("sha256"))
    )


def _paths_equal(left: str | Path, right: str | Path) -> bool:
    return os.path.normcase(str(_path(left))) == os.path.normcase(str(_path(right)))


def _path_contains(parent: str | Path, child: str | Path) -> bool:
    return _is_relative_to(_path(child), _path(parent))


def _writable_parent(path: Path) -> bool:
    current = path.parent
    while not current.exists() and current != current.parent:
        current = current.parent
    return current.is_dir() and os.access(current, os.W_OK)


def _add_check(
    checks: list[dict[str, Any]],
    errors: list[str],
    name: str,
    ok: bool,
    error: str,
    **details: Any,
) -> None:
    checks.append({"name": name, "status": "ok" if ok else "failed", **_sanitize(details)})
    if not ok:
        errors.append(error)


def _non_execution_rollback(reason: str) -> dict[str, Any]:
    return {
        "supported": False,
        "mode": "none",
        "completed": False,
        "reason": reason,
    }


def _boundary(action: str, *, verify_signature: bool) -> dict[str, Any]:
    if action == "resign":
        return {
            "provider_kind": "external_toolchain",
            "operation_kind": "macos_codesign_resign_repack",
            "dependency_state": "required",
            "required_platform": "darwin",
            "required_tools": ["xcrun", "codesign", "security"],
            "byte_preserving": False,
            "content_recompiled": False,
            "signature_verification": "codesign",
            "input_modified": False,
        }
    if action == "verify" and verify_signature:
        return {
            "provider_kind": "hybrid",
            "operation_kind": "static_ipa_and_codesign_verify",
            "dependency_state": "required",
            "required_platform": "darwin",
            "required_tools": ["xcrun", "codesign"],
            "byte_preserving": True,
            "content_recompiled": False,
            "signature_verification": "codesign",
            "input_modified": False,
        }
    return {
        "provider_kind": "builtin",
        "operation_kind": "bounded_zip_extract" if action == "unpack" else "bounded_static_verify",
        "dependency_state": "not_required",
        "required_tools": [],
        "byte_preserving": action == "verify",
        "content_recompiled": False,
        "signature_verification": "not_requested" if action == "verify" else "not_performed",
        "input_modified": False,
    }


def _redact_command(
    command: Sequence[str], secrets: Sequence[str] = ()
) -> list[str]:
    secret_values = {str(item) for item in secrets if item not in (None, "")}
    result: list[str] = []
    hide_next = False
    unlock = any(str(item) == "unlock-keychain" for item in command)
    sensitive_options = {"--password", "--passphrase", "--token", "--secret"}
    for item in command:
        text = str(item)
        if hide_next or text in secret_values:
            result.append("<redacted>")
            hide_next = False
            continue
        option, separator, value = text.partition("=")
        if separator and (option.casefold() in sensitive_options or value in secret_values):
            result.append(f"{option}=<redacted>")
            continue
        result.append(text)
        hide_next = text.casefold() in sensitive_options or (unlock and text == "-p")
    return result


def _bounded_text(value: Any, limit: int) -> tuple[str, bool]:
    encoded = str(value or "").encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return encoded.decode("utf-8", errors="replace"), False
    return encoded[:limit].decode("utf-8", errors="replace"), True


def _command_result(value: Any, output_limit: int) -> dict[str, Any]:
    if value is None:
        raw: Mapping[str, Any] = {"returncode": 1, "stderr": "runner returned no result"}
    elif isinstance(value, Mapping):
        raw = value
    else:
        raw = {
            "returncode": getattr(value, "returncode", 1),
            "stdout": getattr(value, "stdout", ""),
            "stderr": getattr(value, "stderr", ""),
        }
    try:
        returncode = int(raw.get("returncode", raw.get("code", 1)))
    except (TypeError, ValueError):
        returncode = 1
    stdout, stdout_truncated = _bounded_text(raw.get("stdout"), output_limit)
    stderr, stderr_truncated = _bounded_text(raw.get("stderr") or raw.get("error"), output_limit)
    timed_out = bool(raw.get("timed_out"))
    output_exceeded = bool(raw.get("output_limit_exceeded"))
    return {
        "ok": returncode == 0 and not timed_out and not output_exceeded,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "timed_out": timed_out,
        "output_limit_exceeded": output_exceeded,
        "output_limit_bytes": output_limit,
    }


def _invoke_runner(
    runner: Any,
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    output_limit: int,
) -> Any:
    callable_runner = getattr(runner, "run", None)
    if not callable(callable_runner) and callable(runner):
        callable_runner = runner
    if not callable(callable_runner):
        raise TypeError("iOS rebuild runner must be callable or expose run()")
    argv = [str(item) for item in command]
    try:
        signature = inspect.signature(callable_runner)
    except (TypeError, ValueError):
        kwargs = {
            "cwd": str(cwd),
            "timeout": timeout,
            "max_output_bytes": output_limit,
        }
    else:
        accepts_kwargs = any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in signature.parameters.values()
        )
        candidates = {
            "cwd": str(cwd),
            "timeout": timeout,
            "max_output_bytes": output_limit,
        }
        kwargs = {
            name: value
            for name, value in candidates.items()
            if accepts_kwargs or name in signature.parameters
        }
    return callable_runner(argv, **kwargs)


def _run_recorded(
    records: list[dict[str, Any]],
    runner: Any,
    command: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    output_limit: int,
    step: str,
    secrets: Sequence[str] = (),
    target: Optional[str] = None,
) -> dict[str, Any]:
    try:
        raw = _invoke_runner(
            runner,
            command,
            cwd=cwd,
            timeout=timeout,
            output_limit=output_limit,
        )
        normalized = _command_result(raw, output_limit)
    except Exception as exc:
        normalized = {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc) or exc.__class__.__name__,
            "timed_out": isinstance(exc, subprocess.TimeoutExpired),
            "output_limit_exceeded": False,
            "output_limit_bytes": output_limit,
        }
    for secret in secrets:
        if secret:
            normalized["stdout"] = str(normalized.get("stdout") or "").replace(secret, "<redacted>")
            normalized["stderr"] = str(normalized.get("stderr") or "").replace(secret, "<redacted>")
    record = {
        "step": step,
        "command": _redact_command(command, secrets),
        "target": target,
        **normalized,
    }
    records.append(_sanitize(record))
    if not normalized.get("ok"):
        message = normalized.get("stderr") or normalized.get("stdout") or "command failed"
        raise RuntimeError(f"{step} failed: {message}")
    return records[-1]


class IosRebuildProvider:
    """Safe IPA copy reconstruction with dependency-gated macOS resigning."""

    capability_name = "ios_rebuild"
    provider_name = "local_ios_rebuild"
    priority = 10
    supported_actions = ("unpack", "resign", "verify")
    parameter_contract = {
        "common": ("artifact_dir", "timeout", "output_limit_bytes"),
        "unpack": ("unpack_dir", "output_dir"),
        "resign": (
            "out_path",
            "output_path",
            "identity",
            "entitlements",
            "provisioning_profile",
            "keychain",
            "keychain_password",
        ),
        "verify": ("verify_signature",),
    }

    def __init__(
        self,
        runner: Optional[IosRebuildRunner] = None,
        backend: Optional[LocalIosRebuildBackend] = None,
        *,
        platform_name: Optional[str] = None,
        timeout: float = 180.0,
        output_limit_bytes: int = _DEFAULT_OUTPUT_LIMIT,
    ) -> None:
        self.runner: Any = runner or SubprocessIosRebuildRunner(
            max_output_bytes=output_limit_bytes
        )
        self.backend = backend or LocalIosRebuildBackend()
        self.platform_name = (platform_name or sys.platform).lower()
        self.timeout = _bounded_number(timeout, 180.0, 1.0, 3600.0)
        self.output_limit_bytes = max(1024, min(int(output_limit_bytes), 4 * 1024 * 1024))
        self._secrets: dict[str, dict[str, str]] = {}

    def supports(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> bool:
        del context
        return (
            request.capability == self.capability_name
            and _normalize_action(request.action) in _SUPPORTED_ACTIONS
        )

    def plan(
        self,
        request: CapabilityRequest,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityPlan:
        backend = self._select_backend(context)
        action = _normalize_action(request.action)
        if action not in _SUPPORTED_ACTIONS:
            raise ValueError(f"unsupported ios_rebuild action: {request.action}")
        if not request.target.path:
            raise ValueError("ios_rebuild requires a target IPA or unpacked directory")
        source = _path(request.target.path)
        source_snapshot = backend.snapshot(source)
        source_kind = "directory" if source_snapshot.get("is_dir") else "ipa"
        session_id = request.session_id or "ios-rebuild-session"
        session_segment = _safe_segment(session_id)

        artifact_value = _first(request.params, ("artifact_dir",))
        if artifact_value in (None, "") and context:
            artifact_value = context.get("artifact_dir") or context.get("out_dir")
        artifact_dir = (
            _path(artifact_value)
            if artifact_value not in (None, "")
            else source.parent / ".ios-rebuild" / session_segment
        )
        if action == "unpack":
            destination_value = _first(
                request.params, ("unpack_dir", "output_dir", "out_path", "output_path")
            )
            destination = (
                _path(destination_value)
                if destination_value not in (None, "")
                else source.with_name(f"{source.stem}-unpacked")
            )
        elif action == "resign":
            destination_value = _first(request.params, ("out_path", "output_path"))
            default_name = f"{source.stem if source.is_file() else source.name}-resigned.ipa"
            destination = (
                _path(destination_value)
                if destination_value not in (None, "")
                else source.parent / default_name
            )
        else:
            destination = source

        work_dir = artifact_dir / "work"
        package_dir = work_dir / "package"
        temporary_unpack = (
            destination.with_name(f".{destination.name}.{session_segment}.tmp")
            if action == "unpack"
            else work_dir / "unpacked"
        )
        temporary_output = (
            destination.with_name(f".{destination.name}.{session_segment}.tmp")
            if action == "resign"
            else artifact_dir / "unused.tmp"
        )
        backup = destination.with_name(
            f".{destination.name}.{session_segment}.rollback"
        )
        verify_path = artifact_dir / f"{action}_verify.json"
        audit_path = artifact_dir / f"{action}_audit.json"
        destination_snapshot = backend.snapshot(destination)
        verify_signature = _coerce_bool(
            request.params.get("verify_signature"),
            default=action == "verify" and self.platform_name == "darwin",
        )
        tools = {
            name: str(_first(request.params, (name, f"{name}_path")) or name)
            for name in ("xcrun", "codesign", "security")
        }
        timeout = _bounded_number(request.params.get("timeout"), self.timeout, 1.0, 3600.0)
        output_limit = int(
            _bounded_number(
                request.params.get("output_limit_bytes"),
                float(self.output_limit_bytes),
                1024.0,
                4.0 * 1024 * 1024,
            )
        )
        identity = request.params.get("identity")
        entitlements = _first(request.params, ("entitlements", "entitlements_path"))
        profile = _first(
            request.params,
            ("provisioning_profile", "mobileprovision", "profile_path"),
        )
        keychain = _first(request.params, ("keychain", "keychain_path"))
        password = _first(
            request.params,
            ("keychain_password", "keychain_pass", "password"),
        )
        if password not in (None, ""):
            self._secrets[session_id] = {"keychain_password": str(password)}
        boundary = _boundary(action, verify_signature=verify_signature)
        parameters = {
            "schema_version": _SCHEMA_VERSION,
            "action": action,
            "source_path": str(source),
            "source_kind": source_kind,
            "artifact_dir": str(artifact_dir),
            "work_dir": str(work_dir),
            "package_dir": str(package_dir),
            "temporary_unpack": str(temporary_unpack),
            "temporary_output": str(temporary_output),
            "backup_path": str(backup),
            "verify_path": str(verify_path),
            "audit_path": str(audit_path),
            "timeout": timeout,
            "output_limit_bytes": output_limit,
            "platform": self.platform_name,
            "tools": tools,
            "verify_signature": verify_signature,
            "identity": str(identity) if identity not in (None, "") else None,
            "entitlements": str(_path(entitlements)) if entitlements not in (None, "") else None,
            "provisioning_profile": str(_path(profile)) if profile not in (None, "") else None,
            "keychain": str(_path(keychain)) if keychain not in (None, "") else None,
            "keychain_password_configured": password not in (None, ""),
            "capability_boundary": boundary,
        }
        if action == "unpack":
            parameters["unpack_dir"] = str(destination)
        elif action == "resign":
            parameters["out_path"] = str(destination)

        before = {
            "schema_version": _SCHEMA_VERSION,
            "source": source_snapshot,
            "source_sha256": source_snapshot.get("sha256"),
            "destination": destination_snapshot,
        }
        if action in {"unpack", "resign"}:
            destination_existed = bool(destination_snapshot.get("exists"))
            rollback_plan = {
                "supported": True,
                "mode": (
                    "restore_directory"
                    if action == "unpack" and destination_existed
                    else "delete_directory"
                    if action == "unpack"
                    else "restore_file"
                    if destination_existed
                    else "delete_file"
                ),
                "output_path": str(destination),
                "output_existed": destination_existed,
                "prior_output_sha256": destination_snapshot.get("sha256"),
                "backup_path": str(backup) if destination_existed else None,
                "completed": False,
            }
        else:
            rollback_plan = _non_execution_rollback("verify is read-only")
        steps = [
            {"step": "validate_target_identity", "status": "planned"},
            {"step": "static_payload_plist_macho_verify", "status": "planned"},
        ]
        if action == "unpack":
            steps.extend(
                [
                    {"step": "bounded_zip_extract", "status": "planned"},
                    {"step": "transactional_directory_commit", "status": "planned"},
                ]
            )
        elif action == "resign":
            steps.extend(
                [
                    {"step": "copy_to_isolated_work_tree", "status": "planned"},
                    {"step": "codesign_nested_frameworks_dylibs_appex", "status": "planned"},
                    {"step": "codesign_main_app", "status": "planned"},
                    {"step": "codesign_verify", "status": "planned"},
                    {"step": "deterministic_ipa_repack", "status": "planned"},
                    {"step": "transactional_file_commit", "status": "planned"},
                ]
            )
        elif verify_signature:
            steps.append({"step": "codesign_verify_copy", "status": "planned"})
        provenance = {
            **_sanitize(request.provenance),
            "audit_schema_version": _SCHEMA_VERSION,
            "provider": self.provider_name,
            "action": action,
            "source_path": str(source),
            "source_kind": source_kind,
            "planned_source_sha256": source_snapshot.get("sha256"),
            "declared_source_sha256": request.target.sha256,
            "destination_path": str(destination) if action != "verify" else None,
            "toolchain": tools if boundary["required_tools"] else {"python": "zipfile"},
            "capability_boundary": boundary,
        }
        return CapabilityPlan(
            capability=self.capability_name,
            provider=self.provider_name,
            session_id=session_id,
            target=request.target,
            action=action,
            parameters=_sanitize(parameters),
            steps=steps,
            precondition_hash=source_snapshot.get("sha256"),
            before_snapshot=before,
            rollback_plan=_sanitize(rollback_plan),
            provenance=provenance,
        )

    def validate(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityValidation:
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        action = _normalize_action(plan.action)
        checks: list[dict[str, Any]] = []
        errors: list[str] = []
        warnings: list[str] = []
        _add_check(
            checks,
            errors,
            "capability_contract",
            plan.capability == self.capability_name,
            f"plan capability must be {self.capability_name}",
            actual=plan.capability,
        )
        _add_check(
            checks,
            errors,
            "provider_contract",
            plan.provider == self.provider_name,
            f"plan provider must be {self.provider_name}",
            actual=plan.provider,
        )
        _add_check(
            checks,
            errors,
            "session_contract",
            isinstance(plan.session_id, str) and 0 < len(plan.session_id) <= 256,
            "plan session_id must contain 1-256 characters",
        )
        _add_check(
            checks,
            errors,
            "ios_rebuild_action",
            action in _SUPPORTED_ACTIONS
            and _normalize_action(plan.parameters.get("action")) == action,
            "plan action is unsupported or inconsistent with its parameters",
            action=action,
            parameter_action=plan.parameters.get("action"),
        )
        _add_check(
            checks,
            errors,
            "schema_contract",
            plan.parameters.get("schema_version") == _SCHEMA_VERSION
            and plan.before_snapshot.get("schema_version") == _SCHEMA_VERSION,
            "plan schema version is missing or inconsistent",
        )
        _add_check(
            checks,
            errors,
            "platform_contract",
            str(plan.parameters.get("platform") or "").lower() == self.platform_name,
            "plan host platform differs from the executing provider",
            planned=plan.parameters.get("platform"),
            actual=self.platform_name,
        )
        source = _path(plan.parameters.get("source_path") or plan.target.path or "")
        source_snapshot = backend.snapshot(source)
        target_path = _path(plan.target.path or "")
        _add_check(
            checks,
            errors,
            "target_path_identity",
            bool(plan.target.path) and _paths_equal(source, target_path),
            "planned source path no longer matches target identity",
            expected=str(target_path),
            actual=str(source),
        )
        _add_check(
            checks,
            errors,
            "target_precondition_hash",
            _valid_sha256(plan.precondition_hash)
            and _same_hash(source_snapshot.get("sha256"), plan.precondition_hash),
            "target changed after planning or has no valid SHA-256 precondition",
            expected=plan.precondition_hash,
            actual=source_snapshot.get("sha256"),
        )
        declared = plan.provenance.get("declared_source_sha256") or plan.target.sha256
        if declared:
            _add_check(
                checks,
                errors,
                "declared_target_hash",
                _valid_sha256(declared) and _same_hash(declared, source_snapshot.get("sha256")),
                "declared target SHA-256 does not match source",
                expected=declared,
                actual=source_snapshot.get("sha256"),
            )
        source_kind = str(plan.parameters.get("source_kind") or "ipa")
        inspection = (
            backend.inspect_directory(source)
            if source_kind == "directory"
            else backend.inspect_ipa(source)
        )
        source_type_ok = bool(
            source_snapshot.get("is_file") if source_kind == "ipa" else source_snapshot.get("is_dir")
        )
        if action == "unpack":
            source_type_ok = source_kind == "ipa" and bool(source_snapshot.get("is_file"))
        _add_check(
            checks,
            errors,
            "source_type",
            source_type_ok,
            "target type is not supported for this iOS rebuild action",
            source_kind=source_kind,
        )
        _add_check(
            checks,
            errors,
            "payload_info_plist_macho",
            bool(inspection.get("static_valid")),
            "target failed Payload, Info.plist, Mach-O, or bounded archive validation",
            inspection=inspection,
        )

        artifact_paths = [
            _path(plan.parameters.get("verify_path") or ""),
            _path(plan.parameters.get("audit_path") or ""),
        ]
        _add_check(
            checks,
            errors,
            "audit_path_isolation",
            all(not _paths_equal(path, source) for path in artifact_paths),
            "audit artifacts must not overwrite the input",
        )
        _add_check(
            checks,
            errors,
            "audit_parent_writable",
            all(_writable_parent(path) for path in artifact_paths),
            "audit artifact parent is not writable",
        )

        if action in {"unpack", "resign"}:
            key = "unpack_dir" if action == "unpack" else "out_path"
            destination = _path(plan.parameters.get(key) or "")
            current = backend.snapshot(destination)
            isolated = not _paths_equal(source, destination)
            if source_kind == "directory":
                isolated = isolated and not _path_contains(source, destination)
            _add_check(
                checks,
                errors,
                "output_path_isolation",
                isolated,
                "output must not overwrite or be inside the input",
                source=str(source),
                output=str(destination),
            )
            output_type_ok = (
                not current.get("is_file")
                if action == "unpack"
                else destination.suffix.casefold() == ".ipa" and not current.get("is_dir")
            )
            _add_check(
                checks,
                errors,
                "output_type",
                output_type_ok,
                "output type is incompatible with the requested action",
                output=str(destination),
            )
            _add_check(
                checks,
                errors,
                "output_precondition",
                _same_snapshot(plan.before_snapshot.get("destination"), current),
                "output changed after planning",
                expected=plan.before_snapshot.get("destination"),
                actual=current,
            )
            _add_check(
                checks,
                errors,
                "output_parent_writable",
                _writable_parent(destination),
                "output parent is not writable",
            )
            for parameter, label in (
                ("backup_path", "rollback backup"),
                ("work_dir", "work directory"),
                ("temporary_output" if action == "resign" else "temporary_unpack", "temporary output"),
            ):
                candidate = _path(plan.parameters.get(parameter) or "")
                _add_check(
                    checks,
                    errors,
                    f"{parameter}_available",
                    not backend.snapshot(candidate).get("exists"),
                    f"{label} already exists",
                    path=str(candidate),
                )

        if action == "resign":
            _add_check(
                checks,
                errors,
                "signing_identity",
                bool(str(plan.parameters.get("identity") or "").strip()),
                "resign requires a codesigning identity",
            )
            for parameter, label in (
                ("entitlements", "entitlements plist"),
                ("provisioning_profile", "provisioning profile"),
                ("keychain", "keychain"),
            ):
                value = plan.parameters.get(parameter)
                if value:
                    _add_check(
                        checks,
                        errors,
                        f"{parameter}_file",
                        _path(value).is_file(),
                        f"configured {label} does not exist",
                        path=str(value),
                    )

        verify_signature = _coerce_bool(
            plan.parameters.get("verify_signature"), default=False
        )
        expected_boundary = _boundary(action, verify_signature=verify_signature)
        _add_check(
            checks,
            errors,
            "capability_boundary_contract",
            plan.parameters.get("capability_boundary") == expected_boundary
            and plan.provenance.get("capability_boundary") == expected_boundary,
            "planned capability boundary is missing or inconsistent",
        )
        required_tools = list(expected_boundary["required_tools"])
        tools: dict[str, dict[str, Any]] = {}
        for name in ("xcrun", "codesign", "security"):
            required = name in required_tools
            details = self._resolve_tool(plan, runner, name)
            tools[name] = details
            checks.append(
                {
                    "name": f"{name}_available",
                    "status": "ok" if details["available"] else "unavailable",
                    "required": required,
                    **details,
                }
            )
            if required and not details["available"]:
                warnings.append(str(details.get("reason") or f"{name} unavailable"))
        dependencies_available = all(tools[name]["available"] for name in required_tools)
        boundary = dict(expected_boundary)
        if required_tools:
            boundary["dependency_state"] = "available" if dependencies_available else "unavailable"
        if not required_tools:
            assurance = "offline_verified"
        elif not dependencies_available:
            assurance = "dependency_gated"
        elif _is_production_runner(runner, self.platform_name) and all(
            tools[name].get("production_tool") for name in required_tools
        ):
            assurance = "production"
        else:
            assurance = "orchestration_only"
        boundary["execution_assurance"] = assurance
        boundary["production_evidence"] = assurance in {"offline_verified", "production"}
        checks.append({"name": "capability_boundary", "status": "ok", **boundary})
        return CapabilityValidation(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            ok=not errors,
            checks=checks,
            warnings=list(dict.fromkeys(warnings)),
            errors=list(dict.fromkeys(errors)),
        )

    def execute(
        self,
        plan: CapabilityPlan,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityExecutionResult:
        backend = self._select_backend(context)
        runner = self._select_runner(context)
        validation = self.validate(plan, context=context)
        action = _normalize_action(plan.action)
        source = _path(plan.parameters.get("source_path") or plan.target.path or "")
        source_kind = str(plan.parameters.get("source_kind") or "ipa")
        destination = source
        if action == "unpack":
            destination = _path(plan.parameters.get("unpack_dir") or "")
        elif action == "resign":
            destination = _path(plan.parameters.get("out_path") or "")
        before = {
            **dict(plan.before_snapshot or {}),
            "execution_source": backend.snapshot(source),
            "execution_destination": backend.snapshot(destination),
            "validation": validation.to_dict(),
        }
        commands: list[dict[str, Any]] = []
        verification: dict[str, Any] = {}
        rollback_plan = dict(plan.rollback_plan or {})
        created_work = False
        committed = False

        unavailable = [
            check
            for check in validation.checks
            if check.get("required") and check.get("status") == "unavailable"
        ]
        if unavailable:
            reason = "; ".join(
                str(check.get("reason") or f"{check.get('tool')} unavailable")
                for check in unavailable
            )
            self._secrets.pop(plan.session_id, None)
            return self._execution_result(
                plan,
                validation=validation,
                status="unavailable",
                before=before,
                after={
                    "source": backend.snapshot(source),
                    "destination": backend.snapshot(destination),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback(reason),
                verification={"status": "unavailable", "reason": reason},
                commands=commands,
                runner=runner,
                backend=backend,
                error=reason,
            )
        if not validation.ok:
            reason = "; ".join(validation.errors) or "iOS rebuild validation failed"
            self._secrets.pop(plan.session_id, None)
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                before=before,
                after={
                    "source": backend.snapshot(source),
                    "destination": backend.snapshot(destination),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback(reason),
                verification={"status": "failed", "reason": reason},
                commands=commands,
                runner=runner,
                backend=backend,
                error=reason,
            )

        try:
            if action == "verify":
                verification, created_work = self._verify_target(
                    plan,
                    source=source,
                    source_kind=source_kind,
                    runner=runner,
                    backend=backend,
                    commands=commands,
                )
                current_source = backend.snapshot(source)
                if not _same_hash(current_source.get("sha256"), plan.precondition_hash):
                    raise RuntimeError("source changed during verification")
                return self._execution_result(
                    plan,
                    validation=validation,
                    status="ok",
                    before=before,
                    after={
                        "source": current_source,
                        "verification": verification,
                        "side_effects": False,
                    },
                    rollback_plan=_non_execution_rollback("verify is read-only"),
                    verification=verification,
                    commands=commands,
                    runner=runner,
                    backend=backend,
                )

            staged = _path(
                plan.parameters.get("temporary_unpack")
                if action == "unpack"
                else plan.parameters.get("temporary_output")
                or ""
            )
            if action == "unpack":
                backend.extract_ipa(source, staged)
                staged_inspection = backend.inspect_directory(staged)
                if not staged_inspection.get("static_valid"):
                    raise RuntimeError("extracted IPA failed static verification")
                verification = {
                    "status": "ok",
                    "mode": "static",
                    "inspection": staged_inspection,
                }
            else:
                verification, created_work = self._resign_to_staged_ipa(
                    plan,
                    source=source,
                    source_kind=source_kind,
                    staged=staged,
                    runner=runner,
                    backend=backend,
                    commands=commands,
                )

            current_source = backend.snapshot(source)
            if not _same_hash(current_source.get("sha256"), plan.precondition_hash):
                raise RuntimeError("source changed during iOS rebuild")
            current_destination = backend.snapshot(destination)
            if not _same_snapshot(
                plan.before_snapshot.get("destination"), current_destination
            ):
                raise RuntimeError("output changed during iOS rebuild")

            backup = _path(plan.parameters.get("backup_path") or "")
            if current_destination.get("exists"):
                backup.parent.mkdir(parents=True, exist_ok=True)
                os.replace(destination, backup)
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(staged, destination)
                committed = True
            except Exception:
                if current_destination.get("exists") and backup.exists():
                    os.replace(backup, destination)
                raise

            final_inspection = (
                backend.inspect_directory(destination)
                if action == "unpack"
                else backend.inspect_ipa(destination)
            )
            if not final_inspection.get("static_valid"):
                raise RuntimeError("committed iOS output failed final static verification")
            output_snapshot = backend.snapshot(destination)
            rollback_plan.update(
                {
                    "output_sha256": output_snapshot.get("sha256"),
                    "completed": False,
                }
            )
            return self._execution_result(
                plan,
                validation=validation,
                status="ok",
                before=before,
                after={
                    "source": current_source,
                    "destination": final_inspection,
                    "output_sha256": output_snapshot.get("sha256"),
                    "verification": verification,
                    "side_effects": True,
                },
                rollback_plan=rollback_plan,
                verification=verification,
                commands=commands,
                runner=runner,
                backend=backend,
                output=destination,
            )
        except Exception as exc:
            reason = str(exc) or exc.__class__.__name__
            if committed:
                self._restore_failed_commit(plan, destination, backend)
            return self._execution_result(
                plan,
                validation=validation,
                status="failed",
                before=before,
                after={
                    "source": backend.snapshot(source),
                    "destination": backend.snapshot(destination),
                    "side_effects": False,
                },
                rollback_plan=_non_execution_rollback(reason),
                verification=verification or {"status": "failed", "reason": reason},
                commands=commands,
                runner=runner,
                backend=backend,
                error=reason,
            )
        finally:
            self._secrets.pop(plan.session_id, None)
            temporary = plan.parameters.get("temporary_unpack")
            if action == "resign":
                temporary = plan.parameters.get("temporary_output")
            if temporary:
                _remove_path(Path(str(temporary)))
            if created_work:
                _remove_path(Path(str(plan.parameters.get("work_dir") or "")))

    def rollback(
        self,
        result: CapabilityExecutionResult,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityRollbackResult:
        backend = self._select_backend(context)
        plan = dict(result.rollback_plan or {})
        if not plan.get("supported") or not result.after_snapshot.get("side_effects"):
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=True,
                restored=False,
                details={"status": "not_required", "reason": "no reversible output"},
            )
        output = _path(plan.get("output_path") or "")
        mode = str(plan.get("mode") or "")
        if plan.get("completed"):
            current = backend.snapshot(output)
            if mode in {"delete_file", "delete_directory"}:
                restored = not current.get("exists")
            elif mode in {"restore_file", "restore_directory"}:
                restored = bool(current.get("exists")) and _same_hash(
                    current.get("sha256"), plan.get("prior_output_sha256")
                )
            else:
                restored = False
            details = {
                "status": "already_completed" if restored else "failed",
                "mode": mode,
                "output_path": str(output),
                "restored_sha256": current.get("sha256"),
            }
            if not restored:
                details["error"] = "output no longer matches the completed rollback state"
            self._record_rollback_state(result, details, backend)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=restored,
                restored=restored,
                details=_sanitize(details),
            )

        expected = plan.get("output_sha256")
        current = backend.snapshot(output)
        if not current.get("exists") or not _same_hash(current.get("sha256"), expected):
            details = {
                "status": "failed",
                "output_path": str(output),
                "expected_output_sha256": expected,
                "actual_output_sha256": current.get("sha256"),
                "error": "output changed after execution; refusing rollback",
            }
            self._record_rollback_state(result, details, backend)
            return CapabilityRollbackResult(
                capability=result.capability,
                provider=result.provider,
                session_id=result.session_id,
                ok=False,
                restored=False,
                details=details,
            )

        restored = False
        details: dict[str, Any] = {
            "status": "failed",
            "mode": mode,
            "output_path": str(output),
        }
        try:
            if mode in {"delete_file", "delete_directory"}:
                _remove_path(output)
                restored = not output.exists()
            elif mode in {"restore_file", "restore_directory"}:
                backup = _path(plan.get("backup_path") or "")
                backup_snapshot = backend.snapshot(backup)
                if not backup_snapshot.get("exists") or not _same_hash(
                    backup_snapshot.get("sha256"), plan.get("prior_output_sha256")
                ):
                    raise RuntimeError("rollback backup is missing or has changed")
                _remove_path(output)
                os.replace(backup, output)
                restored_snapshot = backend.snapshot(output)
                restored = _same_hash(
                    restored_snapshot.get("sha256"), plan.get("prior_output_sha256")
                )
                details["restored_sha256"] = restored_snapshot.get("sha256")
            else:
                raise RuntimeError(f"unsupported iOS rollback mode: {mode}")
            details["status"] = "ok" if restored else "failed"
            if not restored:
                details["error"] = "rollback did not restore the prior output state"
        except Exception as exc:
            details["error"] = str(exc) or exc.__class__.__name__
        result.rollback_plan.update(
            {
                "completed": restored,
                "status": "completed" if restored else "failed",
            }
        )
        self._record_rollback_state(result, details, backend)
        return CapabilityRollbackResult(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            ok=restored,
            restored=restored,
            details=_sanitize(details),
        )

    def collect_artifacts(
        self,
        result: CapabilityExecutionResult,
        out_dir: str,
        context: Optional[dict[str, Any]] = None,
    ) -> CapabilityArtifactBundle:
        backend = self._select_backend(context)
        root_path = _path(out_dir)
        root_path.mkdir(parents=True, exist_ok=True)
        root = str(root_path)
        artifacts = list(result.artifacts or [])
        existing_entries = {
            str(entry.get("path")): dict(entry)
            for entry in result.evidence_manifest_entries or []
        }
        entries: list[dict[str, Any]] = []
        for artifact in artifacts:
            snapshot = backend.snapshot(artifact.path)
            expected_hash = artifact.metadata.get("sha256")
            verified = bool(snapshot.get("exists")) and (
                not expected_hash or _same_hash(expected_hash, snapshot.get("sha256"))
            )
            artifact.metadata.update(
                {
                    "collection_root": root,
                    "materialized": bool(snapshot.get("exists")),
                    "verified": verified,
                    "integrity_status": "verified" if verified else "failed",
                    "collected_snapshot": snapshot,
                }
            )
            entry = existing_entries.get(artifact.path) or _artifact_manifest_entry(
                artifact, status=result.status
            )
            entry.update(
                {
                    "materialized": bool(snapshot.get("exists")),
                    "verified": verified,
                    "integrity_status": "verified" if verified else "failed",
                    "actual_sha256": snapshot.get("sha256"),
                    "actual_size": snapshot.get("size"),
                }
            )
            entries.append(entry)
        result.artifacts = artifacts
        result.evidence_manifest_entries = entries
        result.report_section["artifacts_verified"] = all(
            artifact.metadata.get("verified") for artifact in artifacts
        )
        result.report_section["evidence_manifest_entries"] = entries
        return CapabilityArtifactBundle(
            capability=result.capability,
            provider=result.provider,
            session_id=result.session_id,
            artifacts=artifacts,
            manifest_entries=entries,
        )

    def _verify_target(
        self,
        plan: CapabilityPlan,
        *,
        source: Path,
        source_kind: str,
        runner: Any,
        backend: LocalIosRebuildBackend,
        commands: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        inspection = (
            backend.inspect_directory(source)
            if source_kind == "directory"
            else backend.inspect_ipa(source)
        )
        if not inspection.get("static_valid"):
            raise RuntimeError("target failed static IPA verification")
        if not _coerce_bool(plan.parameters.get("verify_signature"), default=False):
            return {"status": "ok", "mode": "static", "inspection": inspection}, False

        created_work = False
        verification_root = source
        if source_kind == "ipa":
            verification_root = _path(plan.parameters.get("temporary_unpack") or "")
            backend.extract_ipa(source, verification_root)
            created_work = True
        directory_inspection = backend.inspect_directory(verification_root)
        app = verification_root.joinpath(
            *PurePosixPath(str(directory_inspection["app_path"])).parts
        )
        self._run_tool_discovery(plan, runner, commands, verification_root)
        codesign = self._resolve_tool(plan, runner, "codesign")["path"]
        _run_recorded(
            commands,
            runner,
            [codesign, "--verify", "--deep", "--strict", "--verbose=2", str(app)],
            cwd=verification_root,
            timeout=float(plan.parameters["timeout"]),
            output_limit=int(plan.parameters["output_limit_bytes"]),
            step="codesign_verify",
            target=str(app),
        )
        return {
            "status": "ok",
            "mode": "static_and_codesign",
            "inspection": inspection,
            "execution_assurance": (
                "production"
                if _is_production_runner(runner, self.platform_name)
                else "orchestration_only"
            ),
        }, created_work

    def _resign_to_staged_ipa(
        self,
        plan: CapabilityPlan,
        *,
        source: Path,
        source_kind: str,
        staged: Path,
        runner: Any,
        backend: LocalIosRebuildBackend,
        commands: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        package = _path(plan.parameters.get("package_dir") or "")
        if source_kind == "directory":
            backend.copy_tree(source, package)
        else:
            backend.extract_ipa(source, package)
        inspection = backend.inspect_directory(package)
        if not inspection.get("static_valid"):
            raise RuntimeError("isolated IPA working copy failed static verification")
        app = package.joinpath(*PurePosixPath(str(inspection["app_path"])).parts)
        profile = plan.parameters.get("provisioning_profile")
        if profile:
            shutil.copyfile(_path(profile), app / "embedded.mobileprovision")

        self._run_tool_discovery(plan, runner, commands, package)
        timeout = float(plan.parameters["timeout"])
        output_limit = int(plan.parameters["output_limit_bytes"])
        tools = {
            name: self._resolve_tool(plan, runner, name)["path"]
            for name in ("codesign", "security")
        }
        secrets = self._secrets.get(plan.session_id, {})
        password = secrets.get("keychain_password")
        keychain = plan.parameters.get("keychain")
        if password:
            if not keychain:
                raise RuntimeError("keychain_password requires a keychain path")
            _run_recorded(
                commands,
                runner,
                [tools["security"], "unlock-keychain", "-p", password, str(keychain)],
                cwd=package,
                timeout=timeout,
                output_limit=output_limit,
                step="security_unlock_keychain",
                secrets=[password],
            )
        identity_command = [
            tools["security"],
            "find-identity",
            "-v",
            "-p",
            "codesigning",
        ]
        if keychain:
            identity_command.append(str(keychain))
        _run_recorded(
            commands,
            runner,
            identity_command,
            cwd=package,
            timeout=timeout,
            output_limit=output_limit,
            step="security_find_identity",
        )

        identity = str(plan.parameters.get("identity") or "")
        common = [tools["codesign"], "--force", "--sign", identity, "--timestamp=none"]
        if keychain:
            common.extend(["--keychain", str(keychain)])
        for target in _nested_signing_targets(app):
            _run_recorded(
                commands,
                runner,
                [*common, str(target)],
                cwd=package,
                timeout=timeout,
                output_limit=output_limit,
                step="codesign_nested",
                target=str(target),
            )
        main_command = list(common)
        entitlements = plan.parameters.get("entitlements")
        if entitlements:
            main_command.extend(["--entitlements", str(entitlements)])
        main_command.append(str(app))
        _run_recorded(
            commands,
            runner,
            main_command,
            cwd=package,
            timeout=timeout,
            output_limit=output_limit,
            step="codesign_main_app",
            target=str(app),
        )
        _run_recorded(
            commands,
            runner,
            [tools["codesign"], "--verify", "--deep", "--strict", "--verbose=2", str(app)],
            cwd=package,
            timeout=timeout,
            output_limit=output_limit,
            step="codesign_verify",
            target=str(app),
        )
        if _is_production_runner(runner, self.platform_name):
            signed = backend.inspect_directory(package)
            if not signed.get("signature_present"):
                raise RuntimeError("codesign completed without producing a main app signature")
        backend.repack_ipa(package, staged)
        repacked = backend.inspect_ipa(staged)
        if not repacked.get("static_valid"):
            raise RuntimeError("resigned IPA failed deterministic repack verification")
        assurance = (
            "production"
            if _is_production_runner(runner, self.platform_name)
            else "orchestration_only"
        )
        return {
            "status": "ok",
            "mode": "codesign_and_static",
            "inspection": repacked,
            "execution_assurance": assurance,
            "production_parity": assurance == "production",
            "signing_order": [record.get("target") for record in commands if record.get("target")],
        }, True

    def _run_tool_discovery(
        self,
        plan: CapabilityPlan,
        runner: Any,
        commands: list[dict[str, Any]],
        cwd: Path,
    ) -> None:
        xcrun = self._resolve_tool(plan, runner, "xcrun")["path"]
        _run_recorded(
            commands,
            runner,
            [xcrun, "--find", "codesign"],
            cwd=cwd,
            timeout=float(plan.parameters["timeout"]),
            output_limit=int(plan.parameters["output_limit_bytes"]),
            step="xcrun_find_codesign",
        )

    def _execution_result(
        self,
        plan: CapabilityPlan,
        *,
        validation: CapabilityValidation,
        status: str,
        before: Mapping[str, Any],
        after: Mapping[str, Any],
        rollback_plan: Mapping[str, Any],
        verification: Mapping[str, Any],
        commands: Sequence[Mapping[str, Any]],
        runner: Any,
        backend: LocalIosRebuildBackend,
        output: Optional[Path] = None,
        error: Optional[str] = None,
    ) -> CapabilityExecutionResult:
        verify_path = _path(plan.parameters.get("verify_path") or "")
        audit_path = _path(plan.parameters.get("audit_path") or "")
        verify_payload = {
            "schema_version": _SCHEMA_VERSION,
            "session_id": plan.session_id,
            "capability": plan.capability,
            "action": plan.action,
            "status": status,
            "verification": _sanitize(verification),
            "commands": _sanitize(commands),
            "error": error,
        }
        backend.write_json(verify_path, verify_payload)
        artifacts: list[CapabilityArtifact] = []
        if output is not None and output.exists():
            artifacts.append(
                CapabilityArtifact(
                    path=str(output),
                    kind="ipa" if output.is_file() else "directory",
                    description="iOS rebuild output",
                    metadata=backend.snapshot(output),
                )
            )
        artifacts.extend(
            [
                CapabilityArtifact(
                    path=str(verify_path),
                    kind="json",
                    description="iOS rebuild verification evidence",
                    metadata=backend.snapshot(verify_path),
                ),
                CapabilityArtifact(
                    path=str(audit_path),
                    kind="json",
                    description="iOS rebuild capability audit",
                ),
            ]
        )
        boundary = next(
            (dict(item) for item in validation.checks if item.get("name") == "capability_boundary"),
            {},
        )
        required_tools = list(boundary.get("required_tools") or [])
        boundary_assurance = str(boundary.get("execution_assurance") or "")
        if status == "unavailable":
            execution_assurance = "dependency_gated"
        elif status != "ok":
            execution_assurance = "failed"
        elif not required_tools:
            execution_assurance = "offline_verified"
        elif boundary_assurance == "production" and _is_production_runner(
            runner, self.platform_name
        ):
            execution_assurance = "production"
        else:
            execution_assurance = "orchestration_only"
        production_evidence = status == "ok" and execution_assurance in {
            "offline_verified",
            "production",
        }
        production_parity = production_evidence
        provenance = {
            **_sanitize(plan.provenance),
            "precondition_hash": plan.precondition_hash,
            "artifact_dir": plan.parameters.get("artifact_dir"),
            "verify_path": str(verify_path),
            "audit_path": str(audit_path),
            "capability_boundary": boundary,
            "command_audit": _sanitize(commands),
            "execution_assurance": execution_assurance,
            "production_evidence": production_evidence,
            "production_parity": production_parity,
            "error": error,
        }
        result = CapabilityExecutionResult(
            capability=plan.capability,
            provider=plan.provider,
            session_id=plan.session_id,
            status=status,
            action=plan.action,
            target=plan.target,
            before_snapshot=_sanitize(before),
            after_snapshot=_sanitize(after),
            rollback_plan=_sanitize(rollback_plan),
            artifacts=artifacts,
            evidence_manifest_entries=[
                _artifact_manifest_entry(artifact, status=status)
                for artifact in artifacts
                if artifact.path != str(audit_path)
            ],
            report_section={
                "title": "iOS rebuild",
                "capability": plan.capability,
                "provider": plan.provider,
                "status": status,
                "action": plan.action,
                "verification": _sanitize(verification),
                "execution_assurance": execution_assurance,
                "production_evidence": production_evidence,
                "production_parity": production_parity,
                "error": error,
            },
            dashboard_trace=[
                {
                    "kind": "ios_rebuild_validation",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "action": plan.action,
                    "phase": "validate",
                    "status": "ok" if validation.ok else "failed",
                },
                {
                    "kind": "ios_rebuild_execution",
                    "capability": plan.capability,
                    "provider": plan.provider,
                    "action": plan.action,
                    "phase": "execute",
                    "status": status,
                    "execution_assurance": execution_assurance,
                    "production_evidence": production_evidence,
                },
            ],
            provenance=provenance,
        )
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        backend.write_json(audit_path, record.to_dict())
        artifacts[-1].metadata.update(backend.snapshot(audit_path))
        result.evidence_manifest_entries = [
            _artifact_manifest_entry(artifact, status=status) for artifact in artifacts
        ]
        return result

    def _restore_failed_commit(
        self,
        plan: CapabilityPlan,
        destination: Path,
        backend: LocalIosRebuildBackend,
    ) -> None:
        backup = _path(plan.parameters.get("backup_path") or "")
        _remove_path(destination)
        if plan.before_snapshot.get("destination", {}).get("exists") and backup.exists():
            os.replace(backup, destination)

    def _record_rollback_state(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        backend: LocalIosRebuildBackend,
    ) -> None:
        sanitized = _sanitize(details)
        result.report_section["rollback_plan"] = _sanitize(result.rollback_plan)
        result.report_section.setdefault("rollback_history", []).append(sanitized)
        result.provenance["rollback_status"] = sanitized.get("status")
        result.dashboard_trace.append(
            {
                "kind": "ios_rebuild_rollback",
                "capability": result.capability,
                "provider": result.provider,
                "action": result.action,
                "phase": "rollback",
                "status": sanitized.get("status"),
            }
        )
        self._write_rollback_audit(result, sanitized, backend)

    def _write_rollback_audit(
        self,
        result: CapabilityExecutionResult,
        details: Mapping[str, Any],
        backend: LocalIosRebuildBackend,
    ) -> None:
        artifact_dir = result.provenance.get("artifact_dir")
        if not artifact_dir:
            return
        path = _path(artifact_dir) / f"{_safe_segment(result.action)}_rollback.json"
        backend.write_json(
            path,
            {
                "schema_version": _SCHEMA_VERSION,
                "session_id": result.session_id,
                "capability": result.capability,
                "details": _sanitize(details),
            },
        )
        artifact = CapabilityArtifact(
            path=str(path),
            kind="json",
            description="iOS rebuild rollback audit",
            metadata=backend.snapshot(path),
        )
        existing_artifact = next(
            (item for item in result.artifacts if item.path == artifact.path),
            None,
        )
        if existing_artifact is None:
            result.artifacts.append(artifact)
        else:
            existing_artifact.metadata = artifact.metadata
            artifact = existing_artifact
        entry = _artifact_manifest_entry(
            artifact, status=str(details.get("status") or "unknown")
        )
        for index, existing in enumerate(result.evidence_manifest_entries):
            if existing.get("path") == artifact.path:
                result.evidence_manifest_entries[index] = entry
                break
        else:
            result.evidence_manifest_entries.append(entry)

    def _resolve_tool(
        self,
        plan: CapabilityPlan,
        runner: Any,
        name: str,
    ) -> dict[str, Any]:
        configured_tools = plan.parameters.get("tools")
        configured = (
            str(configured_tools.get(name) or name)
            if isinstance(configured_tools, Mapping)
            else name
        )
        if self.platform_name != "darwin":
            return {
                "tool": name,
                "configured": configured,
                "path": configured,
                "available": False,
                "production_tool": False,
                "reason": f"{name} production execution requires macOS (darwin)",
            }
        resolver = getattr(runner, "which", None)
        try:
            resolved = resolver(configured) if callable(resolver) else None
        except Exception as exc:
            resolved = None
            reason = str(exc) or f"{name} discovery failed"
        else:
            reason = None if resolved else f"{name} executable was not found"
        production_tool = False
        if resolved and _is_production_runner(runner, self.platform_name):
            try:
                production_tool = Path(str(resolved)).resolve(strict=True) == Path(
                    f"/usr/bin/{name}"
                ).resolve(strict=True)
            except OSError:
                production_tool = False
            if not production_tool:
                resolved = None
                reason = f"{name} must resolve to the trusted macOS system executable /usr/bin/{name}"
        return {
            "tool": name,
            "configured": configured,
            "path": str(resolved or configured),
            "available": bool(resolved),
            "production_tool": production_tool,
            "reason": reason,
        }

    def _select_backend(
        self, context: Optional[dict[str, Any]]
    ) -> LocalIosRebuildBackend:
        if context:
            candidate = context.get("ios_rebuild_backend") or context.get("backend")
            if candidate is not None:
                return candidate
        return self.backend

    def _select_runner(self, context: Optional[dict[str, Any]]) -> Any:
        if context:
            candidate = context.get("ios_rebuild_runner") or context.get("runner")
            if candidate is not None:
                return candidate
        return self.runner


def _remove_path(path: Path) -> None:
    if not str(path):
        return
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path, ignore_errors=True)


def _nested_signing_targets(app: Path) -> list[Path]:
    frameworks = sorted(
        (item for item in app.rglob("*.framework") if item.is_dir() and not item.is_symlink()),
        key=lambda item: (-len(item.parts), item.as_posix().casefold()),
    )
    dylibs = sorted(
        (item for item in app.rglob("*.dylib") if item.is_file() and not item.is_symlink()),
        key=lambda item: item.as_posix().casefold(),
    )
    extensions = sorted(
        (item for item in app.rglob("*.appex") if item.is_dir() and not item.is_symlink()),
        key=lambda item: (-len(item.parts), item.as_posix().casefold()),
    )
    return [*frameworks, *dylibs, *extensions]


def _artifact_manifest_entry(
    artifact: CapabilityArtifact, *, status: str
) -> dict[str, Any]:
    return {
        "path": artifact.path,
        "kind": artifact.kind,
        "description": artifact.description,
        "sha256": artifact.metadata.get("sha256"),
        "size": artifact.metadata.get("size"),
        "status": status,
        "provider": IosRebuildProvider.provider_name,
    }


IOSRebuildProvider = IosRebuildProvider
