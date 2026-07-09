"""Deep PE parsing helpers built on top of pefile."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from .executor import ToolResult

SUSPICIOUS_SECTION_NAMES = {"upx0", "upx1", "aspack", ".aspack", ".adata", ".packed", "petite"}


def pe_deep_scan(path: str | Path) -> ToolResult | Dict[str, Any]:
    """Return structured deep PE metadata using pefile when available."""

    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(str(target))

    try:
        import pefile  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool="pe_deep_scan",
            status="unavailable",
            error=f"optional dependency pefile unavailable: {exc}",
            data={"path": str(target)},
        )

    try:
        pe = pefile.PE(str(target), fast_load=False)
    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            tool="pe_deep_scan",
            status="failed",
            error=f"unable to parse PE: {exc}",
            data={"path": str(target)},
        )

    _parse_common_directories(pe, pefile)
    imports = _extract_imports(pe)
    exports = _extract_exports(pe)
    resources = _extract_resources(pe)
    tls_callbacks = _extract_tls_callbacks(pe)
    overlay = _extract_overlay(pe)
    rich_header = _extract_rich_header(pe)
    entrypoint = _entrypoint_details(pe)
    section_anomalies = _section_anomalies(pe, entrypoint["section"])
    iat_anomalies = _iat_anomalies(imports)
    shell_assessment = _shell_assessment(
        entrypoint=entrypoint,
        section_anomalies=section_anomalies,
        overlay=overlay,
        tls_callbacks=tls_callbacks,
        iat_anomalies=iat_anomalies,
    )

    return {
        "path": str(target),
        "imports": imports,
        "exports": exports,
        "resources": resources,
        "tls_callbacks": tls_callbacks,
        "overlay": overlay,
        "rich_header": rich_header,
        "entrypoint": entrypoint,
        "section_anomalies": section_anomalies,
        "iat_anomalies": iat_anomalies,
        "shell_score": shell_assessment["score"],
        "shell_verdict": shell_assessment["verdict"],
        "shell_indicators": shell_assessment["indicators"],
    }


def _parse_common_directories(pe: Any, pefile: Any) -> None:
    try:
        directory_map = getattr(pefile, "DIRECTORY_ENTRY", {})
        wanted = [
            directory_map.get("IMAGE_DIRECTORY_ENTRY_IMPORT"),
            directory_map.get("IMAGE_DIRECTORY_ENTRY_EXPORT"),
            directory_map.get("IMAGE_DIRECTORY_ENTRY_RESOURCE"),
            directory_map.get("IMAGE_DIRECTORY_ENTRY_TLS"),
        ]
        pe.parse_data_directories(directories=[item for item in wanted if item is not None])
    except Exception:
        return


def _extract_imports(pe: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll_raw = getattr(entry, "dll", "")
        dll = dll_raw.decode("utf-8", errors="replace") if isinstance(dll_raw, bytes) else str(dll_raw)
        functions = []
        for imp in getattr(entry, "imports", []) or []:
            name_raw = getattr(imp, "name", None)
            functions.append(
                {
                    "name": name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else name_raw,
                    "ordinal": _safe_int(getattr(imp, "ordinal", None)),
                    "address": _safe_int(getattr(imp, "address", None)),
                    "hint": _safe_int(getattr(imp, "hint", None)),
                    "bound": bool(getattr(imp, "bound", False)),
                }
            )
        items.append({"dll": dll, "function_count": len(functions), "functions": functions})
    return items


def _extract_exports(pe: Any) -> Dict[str, Any]:
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    symbols = []
    if directory is not None:
        for symbol in getattr(directory, "symbols", []) or []:
            name_raw = getattr(symbol, "name", None)
            symbols.append(
                {
                    "name": name_raw.decode("utf-8", errors="replace") if isinstance(name_raw, bytes) else name_raw,
                    "ordinal": _safe_int(getattr(symbol, "ordinal", None)),
                    "address": _safe_int(getattr(symbol, "address", None)),
                    "forwarder": _decode_maybe_bytes(getattr(symbol, "forwarder", None)),
                }
            )
    return {"count": len(symbols), "symbols": symbols}


def _extract_resources(pe: Any) -> Dict[str, Any]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return {"count": 0, "types": [], "entries": []}

    entries = []
    for type_entry in getattr(root, "entries", []) or []:
        type_id = _safe_int(getattr(type_entry.struct, "Id", None)) if hasattr(type_entry, "struct") else None
        type_name = _decode_maybe_bytes(getattr(type_entry, "name", None)) or _resource_type_name(type_id)
        type_children = getattr(getattr(type_entry, "directory", None), "entries", []) or []
        names = []
        languages = set()
        for name_entry in type_children:
            names.append(_decode_maybe_bytes(getattr(name_entry, "name", None)) or _safe_int(getattr(name_entry.struct, "Id", None)))
            for lang_entry in getattr(getattr(name_entry, "directory", None), "entries", []) or []:
                lang_id = _safe_int(getattr(lang_entry.struct, "Id", None)) if hasattr(lang_entry, "struct") else None
                if lang_id is not None:
                    languages.add(lang_id)
        entries.append(
            {
                "type": type_name,
                "type_id": type_id,
                "name_count": len(type_children),
                "names": names,
                "languages": sorted(languages),
            }
        )
    return {"count": len(entries), "types": [entry["type"] for entry in entries], "entries": entries}


def _extract_tls_callbacks(pe: Any) -> Dict[str, Any]:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    callbacks = []

    if tls is None:
        return {"count": 0, "callbacks": callbacks}

    callback_values = getattr(tls, "callbacks", None)
    if callback_values:
        callbacks = [_safe_int(item) for item in callback_values if _safe_int(item) is not None]
    else:
        callback_field = getattr(getattr(tls, "struct", None), "AddressOfCallBacks", None)
        callback_value = _safe_int(callback_field)
        if callback_value:
            callbacks = [callback_value]

    return {"count": len(callbacks), "callbacks": callbacks}


def _extract_overlay(pe: Any) -> Dict[str, Any]:
    offset = None
    size = 0
    has_overlay = False
    try:
        overlay = pe.get_overlay() or b""
        offset = _safe_int(pe.get_overlay_data_start_offset())
        size = len(overlay)
        has_overlay = size > 0
    except Exception:
        overlay = b""
    return {"present": has_overlay, "offset": offset, "size": size}


def _extract_rich_header(pe: Any) -> Dict[str, Any]:
    rich = None
    try:
        rich = pe.parse_rich_header()
    except Exception:
        rich = getattr(pe, "RICH_HEADER", None)

    if not rich:
        return {"present": False, "key": None, "entry_count": 0}

    values = rich.get("values", []) if isinstance(rich, dict) else []
    return {
        "present": True,
        "key": _safe_int(rich.get("key")) if isinstance(rich, dict) else None,
        "entry_count": len(values),
    }


def _entrypoint_details(pe: Any) -> Dict[str, Any]:
    ep_rva = _safe_int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", None)) or 0
    section_name = None
    section_rva = None
    section_exec = None

    section = None
    try:
        section = pe.get_section_by_rva(ep_rva)
    except Exception:
        section = None

    if section is None:
        for candidate in getattr(pe, "sections", []) or []:
            start = _safe_int(getattr(candidate, "VirtualAddress", None)) or 0
            size = _safe_int(getattr(candidate, "Misc_VirtualSize", None)) or _safe_int(getattr(candidate, "SizeOfRawData", None)) or 0
            if start <= ep_rva < start + max(size, 1):
                section = candidate
                break

    if section is not None:
        section_name = _section_name(section)
        section_rva = _safe_int(getattr(section, "VirtualAddress", None))
        section_exec = bool(getattr(section, "IMAGE_SCN_MEM_EXECUTE", False))

    anomaly = None if section_name else "entrypoint_section_not_found"
    return {
        "rva": ep_rva,
        "section": section_name,
        "section_rva": section_rva,
        "section_executable": section_exec,
        "anomaly": anomaly,
    }


def _section_anomalies(pe: Any, entrypoint_section: str | None) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    for section in getattr(pe, "sections", []) or []:
        name = _section_name(section)
        entropy = _safe_float(_call_if_present(section, "get_entropy"))
        raw_size = _safe_int(getattr(section, "SizeOfRawData", None)) or 0
        virtual_size = _safe_int(getattr(section, "Misc_VirtualSize", None)) or 0
        executable = bool(getattr(section, "IMAGE_SCN_MEM_EXECUTE", False))
        writable = bool(getattr(section, "IMAGE_SCN_MEM_WRITE", False))

        reasons = []
        if name.lower() in SUSPICIOUS_SECTION_NAMES or name.lower().startswith("upx"):
            reasons.append("suspicious_name")
        if entropy is not None and entropy >= 7.2:
            reasons.append("high_entropy")
        if executable and writable:
            reasons.append("writable_and_executable")
        if raw_size == 0 and virtual_size > 0:
            reasons.append("virtual_only_section")
        if raw_size > 0 and virtual_size > 0 and raw_size > virtual_size * 2:
            reasons.append("raw_size_exceeds_virtual_size")
        if entrypoint_section and name == entrypoint_section and not executable:
            reasons.append("entrypoint_in_nonexecutable_section")

        if reasons:
            anomalies.append(
                {
                    "section": name,
                    "entropy": entropy,
                    "raw_size": raw_size,
                    "virtual_size": virtual_size,
                    "reasons": reasons,
                }
            )
    return anomalies


def _iat_anomalies(imports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    anomalies: List[Dict[str, Any]] = []
    seen_dlls = set()
    for entry in imports:
        dll = str(entry.get("dll") or "")
        folded = dll.lower()
        if folded in seen_dlls:
            anomalies.append({"dll": dll, "type": "duplicate_dll"})
        else:
            seen_dlls.add(folded)

        if not entry.get("functions"):
            anomalies.append({"dll": dll, "type": "empty_import_descriptor"})
            continue

        for function in entry["functions"]:
            if function.get("name") is None and function.get("ordinal") is None:
                anomalies.append({"dll": dll, "type": "unnamed_import_without_ordinal", "address": function.get("address")})
            if function.get("address") in (None, 0):
                anomalies.append(
                    {
                        "dll": dll,
                        "type": "null_iat_address",
                        "symbol": function.get("name"),
                        "ordinal": function.get("ordinal"),
                    }
                )
    return anomalies


def _shell_assessment(
    *,
    entrypoint: Dict[str, Any],
    section_anomalies: List[Dict[str, Any]],
    overlay: Dict[str, Any],
    tls_callbacks: Dict[str, Any],
    iat_anomalies: List[Dict[str, Any]],
) -> Dict[str, Any]:
    score = 0
    indicators: List[Dict[str, Any]] = []
    weights = {
        "suspicious_name": 15,
        "high_entropy": 15,
        "writable_and_executable": 15,
        "virtual_only_section": 10,
        "raw_size_exceeds_virtual_size": 10,
        "entrypoint_in_nonexecutable_section": 20,
    }

    for anomaly in section_anomalies:
        section = anomaly.get("section")
        for reason in anomaly.get("reasons") or []:
            weight = weights.get(str(reason), 5)
            score += weight
            indicators.append(
                {
                    "kind": "section",
                    "section": section,
                    "reason": reason,
                    "weight": weight,
                }
            )

    if overlay.get("present"):
        weight = 10
        score += weight
        indicators.append(
            {
                "kind": "overlay",
                "reason": "overlay_present",
                "size": overlay.get("size"),
                "weight": weight,
            }
        )

    callback_count = int(tls_callbacks.get("count") or 0)
    if callback_count:
        weight = min(20, 5 * callback_count)
        score += weight
        indicators.append(
            {
                "kind": "tls",
                "reason": "tls_callbacks_present",
                "count": callback_count,
                "weight": weight,
            }
        )

    if iat_anomalies:
        weight = min(15, 5 * len(iat_anomalies))
        score += weight
        indicators.append(
            {
                "kind": "iat",
                "reason": "iat_anomalies_present",
                "count": len(iat_anomalies),
                "weight": weight,
            }
        )

    entry_section = str(entrypoint.get("section") or "")
    if entry_section.lower() in SUSPICIOUS_SECTION_NAMES or entry_section.lower().startswith("upx"):
        weight = 20
        score += weight
        indicators.append(
            {
                "kind": "entrypoint",
                "reason": "entrypoint_in_suspicious_section",
                "section": entry_section,
                "weight": weight,
            }
        )

    score = min(100, score)
    if score >= 70:
        verdict = "likely_packed"
    elif score >= 40:
        verdict = "suspicious"
    else:
        verdict = "low"

    return {"score": score, "verdict": verdict, "indicators": indicators}


def _resource_type_name(type_id: int | None) -> str | None:
    names = {
        1: "CURSOR",
        2: "BITMAP",
        3: "ICON",
        4: "MENU",
        5: "DIALOG",
        6: "STRING",
        10: "RCDATA",
        14: "GROUP_ICON",
        16: "VERSION",
        24: "MANIFEST",
    }
    return names.get(type_id)


def _section_name(section: Any) -> str:
    value = getattr(section, "Name", b"")
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode("utf-8", errors="replace")
    return str(value)


def _decode_maybe_bytes(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _safe_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


def _call_if_present(obj: Any, name: str) -> Any:
    value = getattr(obj, name, None)
    if callable(value):
        try:
            return value()
        except Exception:
            return None
    return value
