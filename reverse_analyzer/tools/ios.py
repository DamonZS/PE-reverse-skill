"""Bounded, evidence-first static analysis for iOS IPA archives."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import datetime as _datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import zipfile
import zlib
from typing import Any
from xml.parsers.expat import ExpatError


__all__ = ["ios_analyze", "ipa_analyze"]


_MAX_ZIP_ENTRIES = 10_000
_MAX_ZIP_NAME_LENGTH = 1_024
_MAX_DECLARED_MEMBER_BYTES = 128 * 1024 * 1024
_MAX_DECLARED_ARCHIVE_BYTES = 768 * 1024 * 1024
_MAX_COMPRESSION_RATIO = 1_000
_ZIP_RATIO_MIN_BYTES = 1 * 1024 * 1024
_MAX_TOTAL_READ_BYTES = 64 * 1024 * 1024
_MAX_PLIST_BYTES = 4 * 1024 * 1024
_MAX_MACHO_PREFIX_BYTES = 16 * 1024 * 1024

_MAX_PLIST_OBJECTS = 50_000
_MAX_PLIST_DEPTH = 64
_MAX_PLIST_KEYS = 512
_MAX_NATIVE_BINARIES = 128
_MAX_UNKNOWN_BINARY_CANDIDATES = 16
_MAX_FAT_ARCHITECTURES = 32
_MAX_LOAD_COMMANDS = 4_096
_MAX_LOAD_COMMAND_BYTES = 8 * 1024 * 1024
_MAX_EXAMPLES = 80
_MAX_WARNINGS = 100
_MAX_SEMANTIC_ENTITIES = 512

_FRAMEWORK_NAMES = (
    "uikit_storyboard",
    "swiftui",
    "flutter",
    "react_native",
    "unity",
    "webview_hybrid",
)
_FRAMEWORK_PRIORITY = {
    "flutter": 0,
    "unity": 1,
    "react_native": 2,
    "swiftui": 3,
    "webview_hybrid": 4,
    "uikit_storyboard": 5,
}

_THIN_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", 32),
    b"\xcf\xfa\xed\xfe": ("<", 64),
    b"\xfe\xed\xfa\xce": (">", 32),
    b"\xfe\xed\xfa\xcf": (">", 64),
}
_FAT_MAGICS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_CPU_NAMES = {
    7: "i386",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}
_ARCHITECTURE_ORDER = {
    "arm64": 0,
    "arm64e": 1,
    "arm64_32": 2,
    "armv7": 3,
    "armv7s": 4,
    "arm": 5,
    "x86_64": 6,
    "i386": 7,
}
_FILE_TYPE_NAMES = {
    1: "object",
    2: "execute",
    3: "fixed-vm-library",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    9: "dylib-stub",
    10: "dsym",
    11: "kext-bundle",
    12: "fileset",
}
_DYLIB_LOAD_COMMANDS = {0xC, 0x18, 0x1F, 0x20, 0x23}


class _ReadBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def consume(self, amount: int) -> None:
        self.used = min(self.limit, self.used + max(0, amount))


def ios_analyze(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Analyze an IPA without extracting members or executing application code."""

    sample = Path(path)
    try:
        exists = sample.is_file()
    except OSError as exc:
        return _persist_artifacts(_unavailable_result(str(exc)), out_dir)
    if not exists:
        package_type = "ipa" if sample.suffix.casefold() == ".ipa" else "unknown"
        return _persist_artifacts(
            _unavailable_result(f"sample not found or not a file: {sample}", package_type=package_type),
            out_dir,
        )
    if sample.suffix.casefold() != ".ipa":
        return _persist_artifacts(
            _unavailable_result("sample is not an IPA", package_type="unknown"),
            out_dir,
        )

    try:
        with zipfile.ZipFile(sample) as archive:
            catalog = _catalog_archive(archive)
            infos: list[zipfile.ZipInfo] = catalog["infos"]
            archive_summary: dict[str, Any] = catalog["summary"]
            issues: list[str] = list(catalog["issues"])
            budget = _ReadBudget(_MAX_TOTAL_READ_BYTES)

            bundle_path, info_plist, bundle_issues = _select_main_bundle(infos)
            issues.extend(bundle_issues)
            manifest_data, manifest_truncated, manifest_error = _read_member_limited(
                archive,
                info_plist,
                _MAX_PLIST_BYTES,
                budget,
            )
            manifest = _manifest_summary(
                manifest_data,
                bundle_path=bundle_path,
                path=info_plist.filename if info_plist is not None else None,
                present=info_plist is not None,
                truncated=manifest_truncated,
                read_error=manifest_error,
            )
            if info_plist is None:
                issues.append("main application Info.plist is missing")
            elif manifest_error:
                issues.append(f"{info_plist.filename}: {manifest_error}")
            elif manifest.get("status") != "ok":
                issues.append(
                    "Info.plist analysis status "
                    f"{manifest.get('status') or 'unavailable'}"
                )

            resources = _resource_summary(infos, bundle_path)
            native, native_issues = _native_binary_summary(
                archive,
                infos,
                manifest,
                resources,
                budget,
            )
            issues.extend(native_issues)
            framework = _detect_framework(manifest, resources, native)
            if framework["name"] == "unknown":
                issues.append("no bounded static iOS UI/runtime framework evidence")
            elif framework["conflict"]["is_conflicted"]:
                issues.append("conflicting iOS UI/runtime framework evidence")

            archive_summary["read_budget_bytes"] = budget.limit
            archive_summary["read_bytes"] = budget.used
            archive_summary["read_budget_exhausted"] = budget.remaining == 0
            if budget.remaining == 0:
                issues.append("IPA read budget exhausted; remaining evidence was not read")
            if issues:
                archive_summary["status"] = "partial"

            semantic_ir_fragment = _semantic_ir_fragment(
                manifest,
                resources,
                native,
                framework,
            )
            if info_plist is None or bundle_path is None:
                status = "failed"
            else:
                status = "partial" if issues else "ok"
            result = _result_payload(
                status=status,
                archive=archive_summary,
                manifest=manifest,
                resources=resources,
                native=native,
                framework=framework,
                semantic_ir_fragment=semantic_ir_fragment,
                issues=issues,
            )
    except (
        OSError,
        EOFError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        zlib.error,
    ) as exc:
        result = _unavailable_result(str(exc))

    return _persist_artifacts(result, out_dir)


def ipa_analyze(
    path: str | os.PathLike[str],
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Compatibility spelling for callers that name the package format."""

    return ios_analyze(path, out_dir)


def _result_payload(
    *,
    status: str,
    archive: Mapping[str, Any],
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    native: Mapping[str, Any],
    framework: Mapping[str, Any],
    semantic_ir_fragment: Mapping[str, Any],
    issues: Sequence[str],
) -> dict[str, Any]:
    framework_name = str(framework.get("name") or "unknown")
    encrypted = native.get("encrypted") is True
    decompilation_reason = (
        "Mach-O code may be encrypted; only bounded header evidence was inspected."
        if encrypted
        else "This analyzer inventories IPA structure and Mach-O headers; it does not decompile code."
    )
    return {
        "status": status,
        "package_type": "ipa",
        "archive": dict(archive),
        "manifest": dict(manifest),
        "resources": dict(resources),
        "native_binaries": dict(native),
        "framework": dict(framework),
        "semantic_ir_fragment": dict(semantic_ir_fragment),
        "decompilation": {
            "status": "unavailable",
            "attempted": False,
            "succeeded": False,
            "reason": decompilation_reason,
            "artifacts": [],
        },
        "capability_boundary": _analysis_capability_boundary(),
        "strategy": {
            "name": f"{framework_name}_bounded_static_inventory",
            "key": f"ios:{framework_name}_bounded_static_inventory",
            "reason": "Static IPA structure preserves plist, resource, and Mach-O header evidence.",
        },
        "warnings": _dedupe_strings(issues, _MAX_WARNINGS),
        "artifacts": [],
    }


def _analysis_capability_boundary() -> dict[str, Any]:
    return {
        "provider_kind": "builtin",
        "operation_kind": "bounded_zip_static_analysis",
        "dependency_state": "not_required",
        "required_tools": [],
        "content_decompiled": False,
        "content_recompiled": False,
        "byte_preserving": True,
        "signature_verification": "not_performed",
        "code_executed": False,
        "members_extracted": False,
    }


def _unavailable_result(error: str, *, package_type: str = "ipa") -> dict[str, Any]:
    manifest = _empty_manifest()
    resources = _empty_resources()
    native = _empty_native_summary()
    framework = _unknown_framework("IPA structure could not be established")
    semantic = _semantic_ir_fragment(manifest, resources, native, framework)
    result = _result_payload(
        status="failed",
        archive=_empty_archive_summary(),
        manifest=manifest,
        resources=resources,
        native=native,
        framework=framework,
        semantic_ir_fragment=semantic,
        issues=[error],
    )
    result["package_type"] = package_type
    result["error"] = error
    return result


def _persist_artifacts(
    result: dict[str, Any],
    out_dir: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    if out_dir is None:
        return result
    payloads = {
        "ios/manifest.json": result["manifest"],
        "ios/resources.json": result["resources"],
        "ios/native_binaries.json": result["native_binaries"],
        "ios/framework.json": result["framework"],
        "ios/semantic_ir_fragment.json": result["semantic_ir_fragment"],
    }
    artifacts: list[dict[str, Any]] = []
    try:
        root = Path(out_dir)
        (root / "ios").mkdir(parents=True, exist_ok=True)
        for name, payload in payloads.items():
            artifact_path = root / Path(name)
            _write_json(artifact_path, payload)
            artifacts.append({"name": name, "path": str(artifact_path), "kind": "ios-analysis"})
    except OSError as exc:
        result.setdefault("warnings", []).append(f"unable to persist iOS artifacts: {exc}")
        result["warnings"] = _dedupe_strings(result["warnings"], _MAX_WARNINGS)
        if result.get("status") == "ok":
            result["status"] = "partial"
    result["artifacts"] = artifacts
    return result


def _empty_archive_summary() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "entry_count": 0,
        "inspected_entry_count": 0,
        "safe_entry_count": 0,
        "unsafe_entry_count": 0,
        "unsafe_entries": [],
        "duplicate_entry_count": 0,
        "duplicate_entries": [],
        "entry_limit": _MAX_ZIP_ENTRIES,
        "entry_limit_hit": False,
        "declared_uncompressed_bytes": 0,
        "declared_uncompressed_limit": _MAX_DECLARED_ARCHIVE_BYTES,
        "declared_size_limit_hit": False,
        "read_budget_bytes": _MAX_TOTAL_READ_BYTES,
        "read_bytes": 0,
        "read_budget_exhausted": False,
        "members_extracted": 0,
    }


def _catalog_archive(archive: zipfile.ZipFile) -> dict[str, Any]:
    all_infos = archive.infolist()
    inspected = sorted(all_infos, key=_zip_info_sort_key)[:_MAX_ZIP_ENTRIES]
    safe_infos: list[zipfile.ZipInfo] = []
    unsafe: list[dict[str, str]] = []
    duplicates: list[str] = []
    seen: set[str] = set()
    unsafe_count = 0
    duplicate_count = 0
    declared_bytes = 0
    for info in all_infos:
        declared_bytes += max(0, int(info.file_size))

    for info in inspected:
        issue = _zip_member_issue(info)
        if issue:
            unsafe_count += 1
            if len(unsafe) < _MAX_EXAMPLES:
                unsafe.append({"name": info.filename[:_MAX_ZIP_NAME_LENGTH], "reason": issue})
            continue
        if info.is_dir():
            continue
        if info.filename in seen:
            duplicate_count += 1
            if len(duplicates) < _MAX_EXAMPLES:
                duplicates.append(info.filename)
            continue
        seen.add(info.filename)
        safe_infos.append(info)

    entry_limit_hit = len(all_infos) > len(inspected)
    declared_limit_hit = declared_bytes > _MAX_DECLARED_ARCHIVE_BYTES
    issues: list[str] = []
    if unsafe_count:
        issues.append(f"ignored {unsafe_count} unsafe or over-limit ZIP member(s)")
    if duplicate_count:
        issues.append(f"ignored {duplicate_count} duplicate ZIP member name(s)")
    if entry_limit_hit:
        issues.append(f"ZIP entry limit {_MAX_ZIP_ENTRIES} reached")
    if declared_limit_hit:
        issues.append("declared IPA uncompressed size exceeds analysis limit")

    summary = _empty_archive_summary()
    summary.update(
        {
            "status": "partial" if issues else "ok",
            "entry_count": len(all_infos),
            "inspected_entry_count": len(inspected),
            "safe_entry_count": len(safe_infos),
            "unsafe_entry_count": unsafe_count,
            "unsafe_entries": unsafe,
            "duplicate_entry_count": duplicate_count,
            "duplicate_entries": duplicates,
            "entry_limit_hit": entry_limit_hit,
            "declared_uncompressed_bytes": declared_bytes,
            "declared_size_limit_hit": declared_limit_hit,
        }
    )
    return {"infos": safe_infos, "issues": issues, "summary": summary}


def _zip_info_sort_key(info: zipfile.ZipInfo) -> tuple[Any, ...]:
    return (
        info.filename,
        int(info.CRC),
        int(info.file_size),
        int(info.compress_size),
        int(info.compress_type),
        int(info.flag_bits),
        int(info.header_offset),
    )


def _zip_member_issue(info: zipfile.ZipInfo) -> str | None:
    name = info.filename
    if not name or len(name) > _MAX_ZIP_NAME_LENGTH:
        return "empty or overlong member name"
    if "\x00" in name:
        return "NUL in member name"
    if "\\" in name:
        return "backslash in member name"
    if name.startswith(("/", "//")) or re.match(r"^[A-Za-z]:", name):
        return "absolute member path"
    parts = name.rstrip("/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return "non-canonical member path"
    unix_mode = (int(info.external_attr) >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFLNK:
        return "symbolic-link member"
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        return "special-file member"
    if int(info.flag_bits) & 0x1:
        return "encrypted member"
    if info.file_size < 0 or info.compress_size < 0:
        return "negative member size"
    if info.file_size > _MAX_DECLARED_MEMBER_BYTES:
        return "declared member size exceeds limit"
    if info.file_size >= _ZIP_RATIO_MIN_BYTES:
        ratio = info.file_size / max(1, info.compress_size)
        if info.compress_size == 0 or ratio > _MAX_COMPRESSION_RATIO:
            return "suspicious compression ratio"
    return None


def _read_member_limited(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo | None,
    limit: int,
    budget: _ReadBudget,
) -> tuple[bytes, bool, str | None]:
    if info is None:
        return b"", False, None
    read_limit = min(max(0, limit), budget.remaining)
    if read_limit <= 0:
        return b"", True, "read budget exhausted"
    try:
        with archive.open(info, "r") as stream:
            data = stream.read(read_limit + 1)
    except (
        OSError,
        EOFError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        zipfile.BadZipFile,
        zlib.error,
    ) as exc:
        return b"", False, str(exc)
    truncated = len(data) > read_limit or info.file_size > read_limit
    data = data[:read_limit]
    budget.consume(len(data))
    return data, truncated, None


def _select_main_bundle(
    infos: Sequence[zipfile.ZipInfo],
) -> tuple[str | None, zipfile.ZipInfo | None, list[str]]:
    info_candidates: list[tuple[str, zipfile.ZipInfo]] = []
    app_roots: set[str] = set()
    for info in infos:
        match = re.match(r"^(Payload/[^/]+\.app)(?:/|$)", info.filename)
        if not match:
            continue
        app_root = match.group(1)
        app_roots.add(app_root)
        if info.filename == f"{app_root}/Info.plist":
            info_candidates.append((app_root, info))
    info_candidates.sort(key=lambda item: (item[0], _zip_info_sort_key(item[1])))
    issues: list[str] = []
    if info_candidates:
        if len(info_candidates) > 1:
            issues.append(
                f"multiple top-level application bundles found; selected {info_candidates[0][0]}"
            )
        return info_candidates[0][0], info_candidates[0][1], issues
    if app_roots:
        selected = sorted(app_roots)[0]
        if len(app_roots) > 1:
            issues.append(f"multiple application bundles lack readable Info.plist; selected {selected}")
        return selected, None, issues
    return None, None, ["Payload/<name>.app structure is missing"]


def _manifest_summary(
    data: bytes,
    *,
    bundle_path: str | None,
    path: str | None,
    present: bool,
    truncated: bool,
    read_error: str | None,
) -> dict[str, Any]:
    result = _empty_manifest(bundle_path=bundle_path, path=path)
    result["present"] = present
    if not present:
        return result
    if read_error:
        result["warnings"] = [read_error]
        return result
    if not data:
        result["warnings"] = ["Info.plist member is empty"]
        return result
    if truncated:
        result["warnings"] = [f"Info.plist read was limited to {_MAX_PLIST_BYTES} bytes"]
        return result

    parser = "binary_plist" if data.startswith(b"bplist00") else "xml_plist"
    try:
        _preflight_plist(data, parser)
        payload = plistlib.loads(data)
        if not isinstance(payload, Mapping):
            raise ValueError("Info.plist root is not a dictionary")
        structure_issue = _plist_structure_issue(payload)
        if structure_issue:
            raise ValueError(structure_issue)
    except (
        plistlib.InvalidFileException,
        ExpatError,
        IndexError,
        OverflowError,
        RecursionError,
        UnicodeError,
        ValueError,
        struct.error,
    ) as exc:
        result["parser"] = parser
        result["warnings"] = [f"Info.plist parse failed: {exc}"]
        return result

    url_schemes: list[str] = []
    for item in _as_sequence(payload.get("CFBundleURLTypes")):
        if not isinstance(item, Mapping):
            continue
        url_schemes.extend(_string_list(item.get("CFBundleURLSchemes")))
    storyboard_names = _storyboard_names(payload)
    keys = sorted(str(key) for key in payload.keys())
    warnings: list[str] = []
    if len(keys) > _MAX_PLIST_KEYS:
        warnings.append(f"Info.plist key inventory limited to {_MAX_PLIST_KEYS}")

    result.update(
        {
            "status": "ok",
            "parser": parser,
            "bundle_identifier": _string(payload.get("CFBundleIdentifier")),
            "bundle_name": _string(payload.get("CFBundleName")),
            "display_name": _string(payload.get("CFBundleDisplayName")),
            "executable": _string(payload.get("CFBundleExecutable")),
            "package_type": _string(payload.get("CFBundlePackageType")),
            "version": _string(payload.get("CFBundleVersion")),
            "short_version": _string(payload.get("CFBundleShortVersionString")),
            "minimum_os_version": _string(
                payload.get("MinimumOSVersion") or payload.get("LSMinimumSystemVersion")
            ),
            "supported_platforms": _string_list(payload.get("CFBundleSupportedPlatforms")),
            "device_families": _scalar_list(payload.get("UIDeviceFamily")),
            "url_schemes": _dedupe_strings(url_schemes, _MAX_EXAMPLES),
            "query_schemes": _string_list(payload.get("LSApplicationQueriesSchemes")),
            "background_modes": _string_list(payload.get("UIBackgroundModes")),
            "required_device_capabilities": _json_safe(
                payload.get("UIRequiredDeviceCapabilities")
            ),
            "app_transport_security": _json_safe(payload.get("NSAppTransportSecurity")),
            "storyboard_names": storyboard_names,
            "main_storyboard": _string(payload.get("UIMainStoryboardFile")),
            "launch_storyboard": _string(payload.get("UILaunchStoryboardName")),
            "principal_class": _string(payload.get("NSPrincipalClass")),
            "uses_non_exempt_encryption": _optional_bool(
                payload.get("ITSAppUsesNonExemptEncryption")
            ),
            "usage_descriptions": {
                str(key): str(value)
                for key, value in sorted(payload.items(), key=lambda item: str(item[0]))
                if str(key).endswith("UsageDescription") and isinstance(value, str)
            },
            "key_count": len(keys),
            "keys": keys[:_MAX_PLIST_KEYS],
            "warnings": warnings,
        }
    )
    missing = []
    if not result["bundle_identifier"]:
        missing.append("CFBundleIdentifier")
    if not result["executable"]:
        missing.append("CFBundleExecutable")
    if missing:
        result["status"] = "partial"
        result["warnings"].append(f"missing required application key(s): {', '.join(missing)}")
    return result


def _empty_manifest(
    *,
    bundle_path: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    return {
        "present": False,
        "status": "unavailable",
        "parser": "none",
        "path": path,
        "bundle_path": bundle_path,
        "bundle_identifier": None,
        "bundle_name": None,
        "display_name": None,
        "executable": None,
        "package_type": None,
        "version": None,
        "short_version": None,
        "minimum_os_version": None,
        "supported_platforms": [],
        "device_families": [],
        "url_schemes": [],
        "query_schemes": [],
        "background_modes": [],
        "required_device_capabilities": None,
        "app_transport_security": None,
        "storyboard_names": [],
        "main_storyboard": None,
        "launch_storyboard": None,
        "principal_class": None,
        "uses_non_exempt_encryption": None,
        "usage_descriptions": {},
        "key_count": 0,
        "keys": [],
        "warnings": [],
    }


def _preflight_plist(data: bytes, parser: str) -> None:
    if parser == "binary_plist":
        if len(data) < 40:
            raise ValueError("binary plist is shorter than its trailer")
        offset_size, reference_size, object_count, top_object, offset_table = struct.unpack_from(
            ">6xBBQQQ", data, len(data) - 32
        )
        if offset_size not in {1, 2, 4, 8} or reference_size not in {1, 2, 4, 8}:
            raise ValueError("binary plist uses invalid integer widths")
        if object_count > _MAX_PLIST_OBJECTS:
            raise ValueError(f"binary plist object limit {_MAX_PLIST_OBJECTS} exceeded")
        if object_count == 0 or top_object >= object_count or offset_table >= len(data) - 32:
            raise ValueError("binary plist trailer is inconsistent")
        return
    lowered = data.lower()
    if b"<!entity" in lowered:
        raise ValueError("XML entity declarations are not accepted")
    tag_count = len(re.findall(rb"<(?:dict|array|key|string|data|date|integer|real|true|false)\b", lowered))
    if tag_count > _MAX_PLIST_OBJECTS:
        raise ValueError(f"XML plist object limit {_MAX_PLIST_OBJECTS} exceeded")


def _plist_structure_issue(payload: Mapping[str, Any]) -> str | None:
    stack: list[tuple[Any, int]] = [(payload, 1)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > _MAX_PLIST_OBJECTS:
            return f"plist object limit {_MAX_PLIST_OBJECTS} exceeded"
        if depth > _MAX_PLIST_DEPTH:
            return f"plist nesting limit {_MAX_PLIST_DEPTH} exceeded"
        if isinstance(value, Mapping):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, (list, tuple)):
            stack.extend((item, depth + 1) for item in value)
    return None


def _storyboard_names(payload: Mapping[str, Any]) -> list[str]:
    key_names = {
        "UIMainStoryboardFile",
        "UIMainStoryboardFile~ipad",
        "UILaunchStoryboardName",
        "UISceneStoryboardFile",
    }
    found: list[str] = []
    stack: list[Any] = [payload]
    visited = 0
    while stack and visited < _MAX_PLIST_OBJECTS:
        value = stack.pop()
        visited += 1
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key) in key_names and isinstance(item, str):
                    found.append(item)
                if isinstance(item, (Mapping, list, tuple)):
                    stack.append(item)
        elif isinstance(value, (list, tuple)):
            stack.extend(item for item in value if isinstance(item, (Mapping, list, tuple)))
    return _dedupe_strings(found, _MAX_EXAMPLES)


def _resource_summary(
    infos: Sequence[zipfile.ZipInfo],
    bundle_path: str | None,
) -> dict[str, Any]:
    if not bundle_path:
        return _empty_resources()
    prefix = f"{bundle_path}/"
    names = sorted(info.filename for info in infos if info.filename.startswith(prefix))
    if not names:
        result = _empty_resources()
        result["bundle_path"] = bundle_path
        return result

    storyboards: set[str] = set()
    xibs: set[str] = set()
    asset_catalogs: set[str] = set()
    assets: set[str] = set()
    frameworks: set[str] = set()
    dylibs: set[str] = set()
    bundles: set[str] = set()
    localizations: set[str] = set()
    web_assets: set[str] = set()
    swift_runtime_dylibs: set[str] = set()
    resource_extensions = {
        ".car",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".heic",
        ".pdf",
        ".json",
        ".strings",
        ".stringsdict",
        ".ttf",
        ".otf",
        ".wav",
        ".mp3",
        ".m4a",
        ".html",
        ".htm",
        ".js",
        ".css",
        ".wasm",
    }
    for name in names:
        lowered = name.casefold()
        parts = name.split("/")
        lowered_parts = [part.casefold() for part in parts]
        for index, part in enumerate(lowered_parts):
            original_root = "/".join(parts[: index + 1])
            if part.endswith(".storyboardc"):
                storyboards.add(original_root)
            elif part.endswith(".xcassets"):
                asset_catalogs.add(original_root)
            elif part.endswith(".framework"):
                frameworks.add(original_root)
            elif part.endswith(".bundle"):
                bundles.add(original_root)
            elif part.endswith(".lproj"):
                localizations.add(original_root)
        if lowered.endswith(".storyboard"):
            storyboards.add(name)
        if lowered.endswith(".xib"):
            xibs.add(name)
        if lowered.endswith(".car"):
            asset_catalogs.add(name)
        if lowered.endswith(".dylib"):
            dylibs.add(name)
            if Path(name).name.casefold().startswith("libswift"):
                swift_runtime_dylibs.add(name)
        suffix = Path(name).suffix.casefold()
        relative_parts = lowered[len(prefix) :].split("/")
        asset_directory = any(
            part in {"assets", "flutter_assets", "www", "web", "public"}
            for part in relative_parts[:-1]
        )
        in_bundle = any(part.endswith(".bundle") for part in relative_parts[:-1])
        if suffix in resource_extensions or asset_directory or in_bundle:
            assets.add(name)
        if suffix in {".html", ".htm", ".js", ".css", ".wasm"} or any(
            part in {"www", "web", "public"} for part in relative_parts[:-1]
        ):
            web_assets.add(name)

    return {
        "status": "ok",
        "bundle_path": bundle_path,
        "file_count": len(names),
        "storyboard_count": len(storyboards),
        "storyboards": sorted(storyboards)[:_MAX_EXAMPLES],
        "xib_count": len(xibs),
        "xibs": sorted(xibs)[:_MAX_EXAMPLES],
        "asset_catalog_count": len(asset_catalogs),
        "asset_catalogs": sorted(asset_catalogs)[:_MAX_EXAMPLES],
        "asset_count": len(assets),
        "assets": sorted(assets)[:_MAX_EXAMPLES],
        "framework_count": len(frameworks),
        "frameworks": sorted(frameworks)[:_MAX_EXAMPLES],
        "dylib_count": len(dylibs),
        "dylibs": sorted(dylibs)[:_MAX_EXAMPLES],
        "bundle_count": len(bundles),
        "bundles": sorted(bundles)[:_MAX_EXAMPLES],
        "localization_count": len(localizations),
        "localizations": sorted(localizations)[:_MAX_EXAMPLES],
        "web_asset_count": len(web_assets),
        "web_assets": sorted(web_assets)[:_MAX_EXAMPLES],
        "swift_runtime_dylibs": sorted(swift_runtime_dylibs)[:_MAX_EXAMPLES],
        "limits": {
            "max_examples": _MAX_EXAMPLES,
            "max_zip_entries": _MAX_ZIP_ENTRIES,
        },
    }


def _empty_resources() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "bundle_path": None,
        "file_count": 0,
        "storyboard_count": 0,
        "storyboards": [],
        "xib_count": 0,
        "xibs": [],
        "asset_catalog_count": 0,
        "asset_catalogs": [],
        "asset_count": 0,
        "assets": [],
        "framework_count": 0,
        "frameworks": [],
        "dylib_count": 0,
        "dylibs": [],
        "bundle_count": 0,
        "bundles": [],
        "localization_count": 0,
        "localizations": [],
        "web_asset_count": 0,
        "web_assets": [],
        "swift_runtime_dylibs": [],
        "limits": {"max_examples": _MAX_EXAMPLES, "max_zip_entries": _MAX_ZIP_ENTRIES},
    }


def _native_binary_summary(
    archive: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    budget: _ReadBudget,
) -> tuple[dict[str, Any], list[str]]:
    bundle_path = _string(manifest.get("bundle_path")) or _string(resources.get("bundle_path"))
    if not bundle_path:
        return _empty_native_summary(), ["application bundle path is unavailable"]

    by_name = {info.filename: info for info in infos}
    candidates: dict[str, str] = {}
    executable = _string(manifest.get("executable"))
    expected_main = f"{bundle_path}/{executable}" if executable else None
    if expected_main:
        candidates[expected_main] = "main_executable"

    for framework_path in resources.get("frameworks", []):
        if not isinstance(framework_path, str):
            continue
        framework_name = Path(framework_path).name
        if not framework_name.casefold().endswith(".framework"):
            continue
        binary_name = framework_name[: -len(".framework")]
        candidates.setdefault(f"{framework_path}/{binary_name}", "framework")
    for dylib_path in resources.get("dylibs", []):
        if isinstance(dylib_path, str):
            candidates.setdefault(dylib_path, "dylib")

    prefix = f"{bundle_path}/"
    unknown_count = 0
    known_resource_suffixes = {
        ".plist",
        ".car",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".json",
        ".strings",
        ".storyboard",
        ".xib",
        ".mobileprovision",
    }
    for info in sorted(infos, key=_zip_info_sort_key):
        if unknown_count >= _MAX_UNKNOWN_BINARY_CANDIDATES:
            break
        if not info.filename.startswith(prefix) or info.filename in candidates:
            continue
        relative = info.filename[len(prefix) :]
        if "/" in relative or not relative:
            continue
        if Path(relative).suffix.casefold() in known_resource_suffixes:
            continue
        if info.file_size < 4:
            continue
        candidates[info.filename] = "app_candidate"
        unknown_count += 1

    role_order = {"main_executable": 0, "framework": 1, "dylib": 2, "app_candidate": 3}
    ordered_candidates = sorted(
        candidates.items(), key=lambda item: (role_order.get(item[1], 9), item[0])
    )
    candidate_limit_hit = len(ordered_candidates) > _MAX_NATIVE_BINARIES
    ordered_candidates = ordered_candidates[:_MAX_NATIVE_BINARIES]
    entries: list[dict[str, Any]] = []
    issues: list[str] = []
    discovered_main: str | None = expected_main

    if not executable:
        issues.append("CFBundleExecutable is missing; direct bundle files were probed")
    if candidate_limit_hit:
        issues.append(f"native binary limit {_MAX_NATIVE_BINARIES} reached")

    for candidate_path, role in ordered_candidates:
        info = by_name.get(candidate_path)
        if info is None:
            if role != "app_candidate":
                entry = _empty_macho("expected binary member is missing")
                entry.update(
                    {
                        "path": candidate_path,
                        "role": role,
                        "size": None,
                        "compressed_size": None,
                    }
                )
                entries.append(entry)
                issues.append(f"{candidate_path}: expected binary member is missing")
            continue
        data, truncated, read_error = _read_member_limited(
            archive,
            info,
            _MAX_MACHO_PREFIX_BYTES,
            budget,
        )
        if read_error:
            macho = _empty_macho(read_error)
        else:
            macho = _parse_macho(data, declared_size=info.file_size, truncated=truncated)
        if role == "app_candidate" and macho.get("format") == "unknown":
            continue
        if role == "app_candidate" and discovered_main is None:
            discovered_main = candidate_path
        entry = dict(macho)
        entry.update(
            {
                "path": candidate_path,
                "role": "main_executable" if candidate_path == discovered_main else role,
                "size": int(info.file_size),
                "compressed_size": int(info.compress_size),
            }
        )
        entries.append(entry)
        if entry.get("status") != "ok":
            detail = "; ".join(str(item) for item in entry.get("warnings", [])[:2])
            issues.append(
                f"{candidate_path}: Mach-O analysis status {entry.get('status') or 'unavailable'}"
                + (f" ({detail})" if detail else "")
            )

    entries.sort(key=lambda item: (role_order.get(str(item.get("role")), 9), str(item["path"])))
    parsed = [entry for entry in entries if entry.get("format") in {"mach-o", "fat-mach-o"}]
    architectures = _sort_architectures(
        architecture
        for entry in parsed
        for architecture in entry.get("architectures", [])
    )
    encryption_states = [entry.get("encrypted") for entry in parsed]
    if any(state is True for state in encryption_states):
        encrypted: bool | None = True
    elif encryption_states and all(state is False for state in encryption_states):
        encrypted = False
    else:
        encrypted = None
    encrypted_count = sum(1 for state in encryption_states if state is True)
    encryption_evidence_count = sum(
        len(entry.get("encryption_info", [])) for entry in parsed
    )
    if encrypted_count:
        issues.append(f"{encrypted_count} Mach-O binary member(s) report non-zero cryptid")
    if not entries:
        status = "unavailable"
    elif not parsed:
        status = "partial"
    elif any(entry.get("status") != "ok" for entry in entries):
        status = "partial"
    elif expected_main is None or not any(
        entry.get("path") == expected_main and entry.get("status") == "ok" for entry in entries
    ):
        status = "partial"
    else:
        status = "ok"

    return (
        {
            "status": status,
            "count": len(entries),
            "parsed_count": len(parsed),
            "main_executable": discovered_main,
            "architectures": architectures,
            "encrypted": encrypted,
            "encrypted_binary_count": encrypted_count,
            "encryption_evidence_count": encryption_evidence_count,
            "entries": entries,
            "warnings": _dedupe_strings(issues, _MAX_WARNINGS),
            "limits": {
                "max_native_binaries": _MAX_NATIVE_BINARIES,
                "max_bytes_per_binary": _MAX_MACHO_PREFIX_BYTES,
                "max_load_commands": _MAX_LOAD_COMMANDS,
                "max_fat_architectures": _MAX_FAT_ARCHITECTURES,
                "candidate_limit_hit": candidate_limit_hit,
            },
        },
        issues,
    )


def _empty_native_summary() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "count": 0,
        "parsed_count": 0,
        "main_executable": None,
        "architectures": [],
        "encrypted": None,
        "encrypted_binary_count": 0,
        "encryption_evidence_count": 0,
        "entries": [],
        "warnings": [],
        "limits": {
            "max_native_binaries": _MAX_NATIVE_BINARIES,
            "max_bytes_per_binary": _MAX_MACHO_PREFIX_BYTES,
            "max_load_commands": _MAX_LOAD_COMMANDS,
            "max_fat_architectures": _MAX_FAT_ARCHITECTURES,
            "candidate_limit_hit": False,
        },
    }


def _empty_macho(error: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "format": "unknown",
        "bits": None,
        "endianness": None,
        "file_type": None,
        "architectures": [],
        "slices": [],
        "encrypted": None,
        "encryption_info": [],
        "linked_dylibs": [],
        "string_evidence": [],
        "header_bytes_read": 0,
        "content_read_limited": False,
        "warnings": [error],
    }


def _parse_macho(data: bytes, *, declared_size: int, truncated: bool) -> dict[str, Any]:
    if len(data) < 4:
        return _empty_macho("Mach-O member is shorter than a magic value")
    magic = data[:4]
    if magic in _THIN_MAGICS:
        slice_payload = _parse_thin_slice(data, 0, declared_size)
        result = {
            "status": slice_payload["status"],
            "format": "mach-o",
            "bits": slice_payload["bits"],
            "endianness": slice_payload["endianness"],
            "file_type": slice_payload["file_type"],
            "architectures": [slice_payload["architecture"]]
            if slice_payload.get("architecture")
            else [],
            "slices": [slice_payload],
            "encrypted": slice_payload["encrypted"],
            "encryption_info": list(slice_payload["encryption_info"]),
            "linked_dylibs": list(slice_payload["linked_dylibs"]),
            "string_evidence": list(slice_payload["string_evidence"]),
            "header_bytes_read": len(data),
            "content_read_limited": truncated,
            "warnings": list(slice_payload["warnings"]),
        }
        return result
    if magic in _FAT_MAGICS:
        return _parse_fat_macho(data, declared_size=declared_size, truncated=truncated)
    return _empty_macho(f"unrecognized Mach-O magic {magic.hex()}")


def _parse_thin_slice(data: bytes, base: int, declared_slice_size: int) -> dict[str, Any]:
    if base < 0 or declared_slice_size < 4 or base + 4 > len(data):
        return _empty_slice("Mach-O slice header is unavailable")
    magic = data[base : base + 4]
    magic_info = _THIN_MAGICS.get(magic)
    if magic_info is None:
        return _empty_slice(f"slice has unrecognized Mach-O magic {magic.hex()}")
    endian, bits = magic_info
    header_size = 32 if bits == 64 else 28
    if base + header_size > len(data) or declared_slice_size < header_size:
        return _empty_slice("Mach-O header is truncated", bits=bits, endian=endian)
    try:
        _, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            f"{endian}7I", data, base
        )
    except struct.error as exc:
        return _empty_slice(f"unable to unpack Mach-O header: {exc}", bits=bits, endian=endian)

    architecture = _architecture_name(cputype, cpusubtype)
    warnings: list[str] = []
    parse_command_count = ncmds
    if ncmds > _MAX_LOAD_COMMANDS:
        warnings.append(f"load command limit {_MAX_LOAD_COMMANDS} exceeded")
        parse_command_count = _MAX_LOAD_COMMANDS
    bounded_command_bytes = sizeofcmds
    if sizeofcmds > _MAX_LOAD_COMMAND_BYTES:
        warnings.append(f"load command bytes limit {_MAX_LOAD_COMMAND_BYTES} exceeded")
        bounded_command_bytes = _MAX_LOAD_COMMAND_BYTES
    declared_commands_end = base + header_size + sizeofcmds
    slice_end = base + declared_slice_size
    if declared_commands_end > slice_end:
        warnings.append("load commands extend beyond the declared Mach-O slice")
    available_commands_end = min(
        len(data),
        slice_end,
        base + header_size + bounded_command_bytes,
        declared_commands_end,
    )
    if declared_commands_end > len(data):
        warnings.append("load command bytes are outside the bounded binary prefix")

    encryption_info: list[dict[str, Any]] = []
    linked_dylibs: list[str] = []
    command_offset = base + header_size
    parsed_commands = 0
    for _ in range(parse_command_count):
        if command_offset + 8 > available_commands_end:
            warnings.append("load command table is truncated")
            break
        try:
            command, command_size = struct.unpack_from(f"{endian}II", data, command_offset)
        except struct.error:
            warnings.append("load command header is truncated")
            break
        if command_size < 8:
            warnings.append("load command has invalid size smaller than 8")
            break
        command_end = command_offset + command_size
        if command_end > available_commands_end:
            warnings.append("load command extends beyond the bounded command table")
            break
        base_command = command & 0x7FFFFFFF
        if base_command in {0x21, 0x2C}:
            if command_size < 20:
                warnings.append("LC_ENCRYPTION_INFO command is truncated")
            else:
                cryptoff, cryptsize, cryptid = struct.unpack_from(
                    f"{endian}III", data, command_offset + 8
                )
                encryption_info.append(
                    {
                        "command": "LC_ENCRYPTION_INFO_64" if base_command == 0x2C else "LC_ENCRYPTION_INFO",
                        "command_offset": command_offset - base,
                        "cryptoff": cryptoff,
                        "cryptsize": cryptsize,
                        "cryptid": cryptid,
                        "encrypted": cryptid != 0,
                    }
                )
        if base_command in _DYLIB_LOAD_COMMANDS:
            dylib_name = _parse_dylib_command(data, command_offset, command_size, endian)
            if dylib_name:
                linked_dylibs.append(dylib_name)
            else:
                warnings.append("dylib load command has no valid bounded name")
        parsed_commands += 1
        command_offset = command_end

    if parsed_commands != ncmds:
        warnings.append(f"parsed {parsed_commands} of {ncmds} declared load command(s)")
    if not encryption_info:
        encrypted: bool | None = None
        warnings.append("LC_ENCRYPTION_INFO evidence is absent")
    elif any(item["encrypted"] for item in encryption_info):
        encrypted = True
        warnings.append("Mach-O encryption command reports non-zero cryptid")
    elif all(not item["encrypted"] for item in encryption_info):
        encrypted = False
    else:
        encrypted = None
        warnings.append("Mach-O encryption commands are inconsistent")

    available_slice_end = min(len(data), slice_end)
    string_evidence = _recognized_binary_strings(data[base:available_slice_end])
    status = "partial" if warnings else "ok"
    return {
        "status": status,
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "cpu_type": cputype,
        "cpu_subtype": cpusubtype,
        "architecture": architecture,
        "file_type": _FILE_TYPE_NAMES.get(filetype, f"unknown-{filetype}"),
        "file_type_value": filetype,
        "load_command_count": ncmds,
        "load_command_bytes": sizeofcmds,
        "flags": flags,
        "encrypted": encrypted,
        "encryption_info": encryption_info,
        "linked_dylibs": _dedupe_strings(linked_dylibs, _MAX_EXAMPLES),
        "string_evidence": string_evidence,
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
    }


def _empty_slice(
    error: str,
    *,
    bits: int | None = None,
    endian: str | None = None,
) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "bits": bits,
        "endianness": None if endian is None else ("little" if endian == "<" else "big"),
        "cpu_type": None,
        "cpu_subtype": None,
        "architecture": None,
        "file_type": None,
        "file_type_value": None,
        "load_command_count": 0,
        "load_command_bytes": 0,
        "flags": None,
        "encrypted": None,
        "encryption_info": [],
        "linked_dylibs": [],
        "string_evidence": [],
        "warnings": [error],
    }


def _parse_fat_macho(
    data: bytes,
    *,
    declared_size: int,
    truncated: bool,
) -> dict[str, Any]:
    endian, uses_64_bit_records = _FAT_MAGICS[data[:4]]
    if len(data) < 8:
        return _empty_macho("fat Mach-O header is truncated")
    nfat_arch = struct.unpack_from(f"{endian}I", data, 4)[0]
    if nfat_arch == 0:
        return _empty_macho("fat Mach-O declares no architectures")
    record_size = 32 if uses_64_bit_records else 20
    parse_count = min(nfat_arch, _MAX_FAT_ARCHITECTURES)
    table_end = 8 + (record_size * parse_count)
    if table_end > len(data):
        return _empty_macho("fat Mach-O architecture table is truncated")

    warnings: list[str] = []
    if nfat_arch > _MAX_FAT_ARCHITECTURES:
        warnings.append(f"fat architecture limit {_MAX_FAT_ARCHITECTURES} exceeded")
    records: list[dict[str, Any]] = []
    for index in range(parse_count):
        offset = 8 + (index * record_size)
        if uses_64_bit_records:
            cputype, cpusubtype, slice_offset, slice_size, align, reserved = struct.unpack_from(
                f"{endian}IIQQII", data, offset
            )
        else:
            cputype, cpusubtype, slice_offset, slice_size, align = struct.unpack_from(
                f"{endian}IIIII", data, offset
            )
            reserved = 0
        records.append(
            {
                "cpu_type": cputype,
                "cpu_subtype": cpusubtype,
                "architecture": _architecture_name(cputype, cpusubtype),
                "offset": slice_offset,
                "size": slice_size,
                "align": align,
                "reserved": reserved,
            }
        )

    intervals: list[tuple[int, int]] = []
    slices: list[dict[str, Any]] = []
    full_table_end = 8 + (record_size * nfat_arch)
    for record in records:
        slice_offset = int(record["offset"])
        slice_size = int(record["size"])
        record_warnings: list[str] = []
        if slice_size < 4:
            record_warnings.append("fat slice is smaller than a Mach-O magic value")
        if slice_offset < full_table_end:
            record_warnings.append("fat slice overlaps the architecture table")
        if slice_offset > declared_size or slice_size > declared_size - min(slice_offset, declared_size):
            record_warnings.append("fat slice extends beyond the declared member size")
        if int(record["align"]) > 31:
            record_warnings.append("fat slice alignment exponent is unreasonable")
        if record_warnings:
            slice_payload = _empty_slice("; ".join(record_warnings))
        elif slice_offset + 4 > len(data):
            slice_payload = _empty_slice("fat slice header is outside the bounded binary prefix")
        else:
            slice_payload = _parse_thin_slice(data, slice_offset, slice_size)
            if (
                slice_payload.get("architecture")
                and slice_payload["architecture"] != record["architecture"]
            ):
                slice_payload["status"] = "partial"
                slice_payload["warnings"] = _dedupe_strings(
                    [
                        *slice_payload.get("warnings", []),
                        "fat table architecture does not match the embedded Mach-O header",
                    ],
                    _MAX_WARNINGS,
                )
        slice_payload.update(
            {
                "declared_architecture": record["architecture"],
                "offset": slice_offset,
                "size": slice_size,
                "align": int(record["align"]),
            }
        )
        slices.append(slice_payload)
        if not record_warnings:
            intervals.append((slice_offset, slice_offset + slice_size))

    sorted_intervals = sorted(intervals)
    if any(current[0] < previous[1] for previous, current in zip(sorted_intervals, sorted_intervals[1:])):
        warnings.append("fat Mach-O slices overlap")
    if any(item.get("status") != "ok" for item in slices):
        warnings.append("one or more fat Mach-O slices lack complete header evidence")

    architectures = _sort_architectures(record["architecture"] for record in records)
    encryption_states = [item.get("encrypted") for item in slices]
    if any(state is True for state in encryption_states):
        encrypted: bool | None = True
    elif (
        len(slices) == nfat_arch
        and encryption_states
        and all(state is False for state in encryption_states)
    ):
        encrypted = False
    else:
        encrypted = None
    encryption_info = []
    for item in slices:
        for evidence in item.get("encryption_info", []):
            enriched = dict(evidence)
            enriched["architecture"] = item.get("architecture") or item.get(
                "declared_architecture"
            )
            enriched["slice_offset"] = item.get("offset")
            encryption_info.append(enriched)
    linked_dylibs = _dedupe_strings(
        (
            dylib
            for item in slices
            for dylib in item.get("linked_dylibs", [])
        ),
        _MAX_EXAMPLES,
    )
    string_evidence = _dedupe_strings(
        (
            signal
            for item in slices
            for signal in item.get("string_evidence", [])
        ),
        _MAX_EXAMPLES,
    )
    return {
        "status": "partial" if warnings else "ok",
        "format": "fat-mach-o",
        "bits": None,
        "endianness": "little" if endian == "<" else "big",
        "file_type": None,
        "architectures": architectures,
        "slices": slices,
        "encrypted": encrypted,
        "encryption_info": encryption_info,
        "linked_dylibs": linked_dylibs,
        "string_evidence": string_evidence,
        "header_bytes_read": len(data),
        "content_read_limited": truncated,
        "warnings": _dedupe_strings(warnings, _MAX_WARNINGS),
    }


def _parse_dylib_command(
    data: bytes,
    command_offset: int,
    command_size: int,
    endian: str,
) -> str | None:
    if command_size < 24:
        return None
    name_offset = struct.unpack_from(f"{endian}I", data, command_offset + 8)[0]
    if name_offset < 24 or name_offset >= command_size:
        return None
    start = command_offset + name_offset
    end = command_offset + command_size
    terminator = data.find(b"\x00", start, end)
    if terminator < 0:
        terminator = end
    raw = data[start:terminator]
    if not raw or len(raw) > _MAX_ZIP_NAME_LENGTH:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def _architecture_name(cputype: int, cpusubtype: int) -> str:
    subtype = cpusubtype & 0x00FFFFFF
    if cputype == 12:
        if subtype == 9:
            return "armv7"
        if subtype == 11:
            return "armv7s"
    if cputype == 0x0100000C and subtype == 2:
        return "arm64e"
    return _CPU_NAMES.get(cputype, f"cpu-0x{cputype:08x}")


def _sort_architectures(values: Sequence[str] | Any) -> list[str]:
    unique = {str(value) for value in values if value}
    return sorted(unique, key=lambda value: (_ARCHITECTURE_ORDER.get(value, 100), value))


def _recognized_binary_strings(data: bytes) -> list[str]:
    lowered = data.lower()
    tokens = (
        (b"swiftui", "SwiftUI"),
        (b"uikit", "UIKit"),
        (b"wkwebview", "WKWebView"),
        (b"webkit", "WebKit"),
        (b"rctrootview", "RCTRootView"),
        (b"reactnative", "ReactNative"),
        (b"facebook::react", "facebook::react"),
        (b"flutterviewcontroller", "FlutterViewController"),
        (b"flutterengine", "FlutterEngine"),
        (b"unityframework", "UnityFramework"),
        (b"unityplayer", "UnityPlayer"),
    )
    return [label for token, label in tokens if token in lowered]


def _detect_framework(
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    native: Mapping[str, Any],
) -> dict[str, Any]:
    scores = {name: 0.0 for name in _FRAMEWORK_NAMES}
    evidence: dict[str, list[str]] = {name: [] for name in _FRAMEWORK_NAMES}

    def add(name: str, score: float, reason: str) -> None:
        scores[name] += score
        if reason not in evidence[name]:
            evidence[name].append(reason)

    framework_paths = [
        str(path) for path in resources.get("frameworks", []) if isinstance(path, str)
    ]
    asset_paths = [str(path) for path in resources.get("assets", []) if isinstance(path, str)]
    all_resource_paths = "\n".join(
        str(path).casefold()
        for key in ("assets", "frameworks", "dylibs", "bundles", "web_assets")
        for path in resources.get(key, [])
        if isinstance(path, str)
    )
    linked_dylibs = [
        str(dylib)
        for entry in native.get("entries", [])
        if isinstance(entry, Mapping)
        for dylib in entry.get("linked_dylibs", [])
        if isinstance(dylib, str)
    ]
    string_signals = [
        str(signal)
        for entry in native.get("entries", [])
        if isinstance(entry, Mapping)
        for signal in entry.get("string_evidence", [])
        if isinstance(signal, str)
    ]
    native_text = "\n".join(
        [
            *(str(entry.get("path") or "") for entry in native.get("entries", []) if isinstance(entry, Mapping)),
            *linked_dylibs,
            *string_signals,
        ]
    ).casefold()

    storyboard_count = int(resources.get("storyboard_count") or 0)
    xib_count = int(resources.get("xib_count") or 0)
    storyboard_names = [
        str(name) for name in manifest.get("storyboard_names", []) if isinstance(name, str)
    ]
    if storyboard_count:
        add(
            "uikit_storyboard",
            min(10.0, 6.0 + (storyboard_count * 0.5)),
            f"{storyboard_count} storyboard resource(s)",
        )
    if storyboard_names:
        add(
            "uikit_storyboard",
            4.0,
            "Info.plist storyboard declarations: " + ", ".join(storyboard_names[:4]),
        )
    if xib_count:
        add(
            "uikit_storyboard",
            min(4.0, 1.5 + (xib_count * 0.25)),
            f"{xib_count} XIB resource(s)",
        )
    if scores["uikit_storyboard"] and "uikit.framework/uikit" in native_text:
        add("uikit_storyboard", 1.5, "Mach-O links UIKit.framework")

    if "swiftui.framework/swiftui" in native_text:
        add("swiftui", 8.0, "Mach-O links SwiftUI.framework")
    elif "swiftui" in string_signals:
        add("swiftui", 6.0, "Mach-O SwiftUI string evidence")

    lowered_frameworks = [path.casefold() for path in framework_paths]
    if any(path.endswith("/flutter.framework") for path in lowered_frameworks):
        add("flutter", 8.0, "bundled Flutter.framework")
    if "flutter_assets" in all_resource_paths:
        add("flutter", 7.0, "Flutter asset bundle")
    if "flutterviewcontroller" in native_text or "flutterengine" in native_text:
        add("flutter", 4.0, "Mach-O Flutter runtime strings")
    if scores["flutter"] and any(path.endswith("/app.framework") for path in lowered_frameworks):
        add("flutter", 2.0, "bundled Flutter App.framework")

    if any(
        path.casefold().endswith(("/main.jsbundle", "/index.ios.bundle"))
        for path in asset_paths
    ) or any(token in all_resource_paths for token in ("main.jsbundle", "index.ios.bundle")):
        add("react_native", 9.0, "packaged React Native JavaScript bundle")
    if any(
        path.endswith(("/react.framework", "/hermes.framework", "/react-core.framework"))
        for path in lowered_frameworks
    ):
        add("react_native", 6.0, "bundled React Native/Hermes framework")
    if any(token in native_text for token in ("rctrootview", "facebook::react", "reactnative")):
        add("react_native", 6.0, "Mach-O React Native runtime strings")

    if any(path.endswith("/unityframework.framework") for path in lowered_frameworks):
        add("unity", 8.0, "bundled UnityFramework.framework")
    if any(
        token in all_resource_paths
        for token in ("globalgamemanagers", "global-metadata.dat", "/data/managed/")
    ):
        add("unity", 7.0, "Unity data or metadata assets")
    if "unityframework" in native_text or "unityplayer" in native_text:
        add("unity", 4.0, "Mach-O Unity runtime strings")

    if "webkit.framework/webkit" in native_text or "wkwebview" in native_text:
        add("webview_hybrid", 7.0, "Mach-O WebKit/WKWebView evidence")
    web_asset_count = int(resources.get("web_asset_count") or 0)
    if web_asset_count:
        add(
            "webview_hybrid",
            min(6.0, 2.0 + (web_asset_count * 0.5)),
            f"{web_asset_count} packaged web asset(s)",
        )
    if any(token in all_resource_paths for token in ("cordova.js", "capacitor.config")):
        add("webview_hybrid", 4.0, "Cordova/Capacitor bundle paths")

    positive = [(name, score) for name, score in scores.items() if score > 0]
    if not positive:
        return _unknown_framework("No bounded static framework signal")
    ranked = sorted(
        positive,
        key=lambda item: (-item[1], _FRAMEWORK_PRIORITY[item[0]], item[0]),
    )
    total = sum(score for _, score in ranked)
    best_name, best_score = ranked[0]
    second_name, second_score = ranked[1] if len(ranked) > 1 else (None, 0.0)
    conflict_score = second_score / best_score if best_score else 0.0
    strong_candidates = [
        name for name, score in ranked if score >= 3.0 and score >= best_score * 0.5
    ]
    conflicted = len(strong_candidates) > 1 and conflict_score >= 0.6
    candidates = [
        {
            "name": name,
            "score": round(scores[name], 3),
            "confidence": round(scores[name] / total, 3) if total else 0.0,
            "evidence": evidence[name],
        }
        for name in sorted(
            _FRAMEWORK_NAMES,
            key=lambda name: (-scores[name], _FRAMEWORK_PRIORITY[name], name),
        )
    ]
    conflicts = []
    if conflicted and second_name:
        conflicts.append(
            {
                "primary": best_name,
                "secondary": second_name,
                "score": round(conflict_score, 3),
                "reason": "independent static signals strongly support both candidates",
            }
        )
    return {
        "status": "partial" if conflicted else "ok",
        "name": best_name,
        "confidence": round(best_score / total, 3),
        "score": round(best_score, 3),
        "evidence": evidence[best_name],
        "candidates": candidates,
        "conflict": {
            "is_conflicted": conflicted,
            "score": round(conflict_score, 3),
            "runner_up": second_name,
            "strong_candidates": strong_candidates,
        },
        "conflicts": conflicts,
        "scoring": "bounded-static-evidence-v1",
    }


def _unknown_framework(reason: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "name": "unknown",
        "confidence": 0.0,
        "score": 0.0,
        "evidence": [reason],
        "candidates": [
            {"name": name, "score": 0.0, "confidence": 0.0, "evidence": []}
            for name in sorted(_FRAMEWORK_NAMES, key=lambda name: _FRAMEWORK_PRIORITY[name])
        ],
        "conflict": {
            "is_conflicted": False,
            "score": 0.0,
            "runner_up": None,
            "strong_candidates": [],
        },
        "conflicts": [],
        "scoring": "bounded-static-evidence-v1",
    }


def _semantic_ir_fragment(
    manifest: Mapping[str, Any],
    resources: Mapping[str, Any],
    native: Mapping[str, Any],
    framework: Mapping[str, Any],
) -> dict[str, Any]:
    entities_by_id: dict[str, dict[str, Any]] = {}
    relations_by_id: dict[str, dict[str, Any]] = {}

    def add_entity(
        entity_id: str,
        *,
        kind: str,
        name: str,
        confidence: float,
        sources: Sequence[str],
        attributes: Mapping[str, Any],
    ) -> str:
        if entity_id not in entities_by_id and len(entities_by_id) >= _MAX_SEMANTIC_ENTITIES:
            return entity_id
        normalized_sources = sorted({str(source) for source in sources if source})
        payload = {
            "id": entity_id,
            "kind": kind,
            "name": name,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "sources": normalized_sources,
            "attributes": dict(attributes),
        }
        existing = entities_by_id.get(entity_id)
        if existing is None:
            entities_by_id[entity_id] = payload
        else:
            existing["confidence"] = max(existing["confidence"], payload["confidence"])
            existing["sources"] = sorted(set(existing["sources"]).union(normalized_sources))
        return entity_id

    def add_relation(
        relation_type: str,
        source_id: str,
        target_id: str,
        *,
        confidence: float,
        sources: Sequence[str],
        attributes: Mapping[str, Any] | None = None,
        identity: Any = None,
    ) -> None:
        if source_id not in entities_by_id or target_id not in entities_by_id:
            return
        identity_payload = json.dumps(
            [relation_type, source_id, target_id, identity],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        relation_id = "ios:relation:" + hashlib.sha256(
            identity_payload.encode("utf-8")
        ).hexdigest()[:16]
        relation = {
            "id": relation_id,
            "type": relation_type,
            "source": source_id,
            "target": target_id,
            "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
            "sources": sorted({str(source) for source in sources if source}),
        }
        if attributes:
            relation["attributes"] = dict(attributes)
        relations_by_id[relation_id] = relation

    bundle_identifier = _string(manifest.get("bundle_identifier"))
    bundle_path = _string(manifest.get("bundle_path")) or "unknown.app"
    app_name = bundle_identifier or bundle_path
    app_id = f"ios:application:{app_name}"
    manifest_status = str(manifest.get("status") or "unavailable")
    if manifest.get("present") or resources.get("status") != "unavailable":
        add_entity(
            app_id,
            kind="ios_application",
            name=app_name,
            confidence=1.0 if manifest_status == "ok" else 0.6,
            sources=["ios.info_plist"],
            attributes={
                "bundle_path": bundle_path,
                "version": manifest.get("version"),
                "short_version": manifest.get("short_version"),
                "minimum_os_version": manifest.get("minimum_os_version"),
                "manifest_status": manifest_status,
            },
        )

    framework_name = str(framework.get("name") or "unknown")
    if framework_name != "unknown":
        framework_id = f"ios:ui_framework:{framework_name}"
        add_entity(
            framework_id,
            kind="ios_ui_framework",
            name=framework_name,
            confidence=float(framework.get("confidence") or 0.0),
            sources=["ios.framework_fingerprint"],
            attributes={
                "score": framework.get("score"),
                "evidence": list(framework.get("evidence") or []),
                "conflicted": bool((framework.get("conflict") or {}).get("is_conflicted")),
            },
        )
        add_relation(
            "uses_framework",
            app_id,
            framework_id,
            confidence=float(framework.get("confidence") or 0.0),
            sources=["ios.framework_fingerprint"],
        )

    if resources.get("status") != "unavailable":
        resource_id = "ios:resources"
        add_entity(
            resource_id,
            kind="ios_resources",
            name="resources",
            confidence=0.95,
            sources=["ios.archive_inventory"],
            attributes={
                "storyboards": resources.get("storyboard_count", 0),
                "xibs": resources.get("xib_count", 0),
                "asset_catalogs": resources.get("asset_catalog_count", 0),
                "frameworks": resources.get("framework_count", 0),
                "dylibs": resources.get("dylib_count", 0),
            },
        )
        add_relation(
            "contains",
            app_id,
            resource_id,
            confidence=0.95,
            sources=["ios.archive_inventory"],
        )

    for key, kind in (("storyboards", "ios_storyboard"), ("xibs", "ios_xib")):
        for path in resources.get(key, [])[:_MAX_EXAMPLES]:
            if not isinstance(path, str):
                continue
            entity_id = f"ios:resource:{path}"
            add_entity(
                entity_id,
                kind=kind,
                name=Path(path).name,
                confidence=0.95,
                sources=["ios.archive_inventory"],
                attributes={"path": path},
            )
            add_relation(
                "contains",
                app_id,
                entity_id,
                confidence=0.95,
                sources=["ios.archive_inventory"],
            )

    bundled_framework_ids: dict[str, str] = {}
    for path in resources.get("frameworks", [])[:_MAX_EXAMPLES]:
        if not isinstance(path, str):
            continue
        entity_id = f"ios:bundled_framework:{path}"
        bundled_framework_ids[path] = entity_id
        add_entity(
            entity_id,
            kind="ios_bundled_framework",
            name=Path(path).name,
            confidence=0.95,
            sources=["ios.archive_inventory"],
            attributes={"path": path},
        )
        add_relation(
            "bundles",
            app_id,
            entity_id,
            confidence=0.95,
            sources=["ios.archive_inventory"],
        )

    native_entity_ids: list[str] = []
    for entry in native.get("entries", [])[:_MAX_NATIVE_BINARIES]:
        if not isinstance(entry, Mapping):
            continue
        path = str(entry.get("path") or "unknown")
        entity_id = f"ios:native:{path}"
        native_entity_ids.append(entity_id)
        entry_status = str(entry.get("status") or "unavailable")
        add_entity(
            entity_id,
            kind="mach_o_binary",
            name=Path(path).name,
            confidence=0.95 if entry_status == "ok" else 0.5,
            sources=["ios.macho_header"],
            attributes={
                "path": path,
                "role": entry.get("role"),
                "status": entry_status,
                "format": entry.get("format"),
                "architectures": list(entry.get("architectures") or []),
                "encrypted": entry.get("encrypted"),
                "encryption_evidence_count": len(entry.get("encryption_info") or []),
            },
        )
        add_relation(
            "contains",
            app_id,
            entity_id,
            confidence=0.95 if entry_status == "ok" else 0.5,
            sources=["ios.macho_header"],
        )
        for framework_path, framework_id in bundled_framework_ids.items():
            if path.startswith(f"{framework_path}/"):
                add_relation(
                    "has_binary",
                    framework_id,
                    entity_id,
                    confidence=0.95,
                    sources=["ios.archive_inventory", "ios.macho_header"],
                )

    entities = sorted(entities_by_id.values(), key=lambda item: str(item["id"]))
    relations = sorted(relations_by_id.values(), key=lambda item: str(item["id"]))
    entity_ids = [str(entity["id"]) for entity in entities]
    capabilities: list[dict[str, Any]] = []
    if entity_ids:
        capabilities.append(
            {
                "id": "capability:ios_static_structure:"
                + hashlib.sha256("\n".join(entity_ids).encode("utf-8")).hexdigest()[:16],
                "name": "ios_static_structure",
                "category": "ios_static_structure",
                "confidence": 1.0 if manifest_status == "ok" else 0.6,
                "entity_ids": entity_ids,
                "evidence_count": sum(max(1, len(entity["sources"])) for entity in entities),
            }
        )

    section_statuses = {
        "manifest": manifest_status,
        "resources": str(resources.get("status") or "unavailable"),
        "native_binaries": str(native.get("status") or "unavailable"),
        "framework": str(framework.get("status") or "unavailable"),
    }
    if not entities:
        status = "unavailable"
    elif all(value == "ok" for value in section_statuses.values()):
        status = "ok"
    else:
        status = "partial"
    return {
        "schema_version": 1,
        "source": "ios_analyze",
        "status": status,
        "entities": entities,
        "relations": relations,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "capability_count": len(capabilities),
            "native_binary_count": len(native_entity_ids),
            "section_statuses": section_statuses,
        },
        "artifacts": [],
        "limits": {
            "max_entities": _MAX_SEMANTIC_ENTITIES,
            "max_native_binaries": _MAX_NATIVE_BINARIES,
            "max_resource_examples": _MAX_EXAMPLES,
        },
    }


def _as_sequence(value: Any) -> Sequence[Any]:
    if isinstance(value, (list, tuple)):
        return value
    return ()


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _string_list(value: Any) -> list[str]:
    return _dedupe_strings(
        (item for item in _as_sequence(value) if isinstance(item, str)),
        _MAX_EXAMPLES,
    )


def _scalar_list(value: Any) -> list[Any]:
    return [
        item
        for item in _as_sequence(value)[:_MAX_EXAMPLES]
        if item is None or isinstance(item, (bool, int, float, str))
    ]


def _optional_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_PLIST_DEPTH:
        return None
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") else None
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value[:256].hex(), "truncated": len(value) > 256}
    if isinstance(value, (_datetime.date, _datetime.datetime)):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item, depth=depth + 1)
            for key, item in list(sorted(value.items(), key=lambda pair: str(pair[0])))[:_MAX_PLIST_KEYS]
        }
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, depth=depth + 1) for item in value[:_MAX_EXAMPLES]]
    return str(value)


def _dedupe_strings(values: Any, limit: int) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value)
        if not text or text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
