"""Bounded, read-only import of external debugger sessions and minidumps."""

from __future__ import annotations

import json
from pathlib import Path
import re
import struct
from typing import Any, Mapping, Sequence


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 10000


def debugger_session_import(path: str | Path, *, source: str = "auto", out: str | Path | None = None) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(str(target))
    size = target.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise ValueError(f"debugger input exceeds {MAX_INPUT_BYTES} bytes")
    raw = target.read_bytes()
    provider = _detect_source(target, raw, source)
    if provider == "minidump":
        normalized = _parse_minidump(raw)
    elif provider == "windbg":
        normalized = _parse_windbg(raw.decode("utf-8", errors="replace"))
    else:
        payload = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(payload, Mapping):
            raise ValueError("debugger JSON root must be an object")
        normalized = _parse_debugger_json(payload, provider)
    result = {
        "status": "ok",
        "schema_version": 1,
        "source": provider,
        "input": {"path": str(target), "size": size},
        **normalized,
        "analysis_scope": "offline_import",
    }
    if out is not None:
        destination = Path(out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result["artifact"] = str(destination)
    return result


def _detect_source(path: Path, raw: bytes, requested: str) -> str:
    choice = str(requested or "auto").strip().lower()
    if choice not in {"auto", "x64dbg", "windbg", "ida", "minidump"}:
        raise ValueError("source must be one of: auto, x64dbg, windbg, ida, minidump")
    if choice != "auto":
        return choice
    if raw.startswith(b"MDMP") or path.suffix.lower() in {".dmp", ".mdmp"}:
        return "minidump"
    if path.suffix.lower() in {".log", ".txt"}:
        return "windbg"
    lowered = raw[:4096].lower()
    if b"x64dbg" in lowered or b'"breakpoints"' in lowered:
        return "x64dbg"
    return "ida" if b'"functions"' in lowered or b'"segments"' in lowered else "x64dbg"


def _parse_debugger_json(payload: Mapping[str, Any], provider: str) -> dict[str, Any]:
    modules = _records(payload, ("modules", "module_list", "segments"))
    breakpoints = _records(payload, ("breakpoints", "bps", "bookmarks"))
    exceptions = _records(payload, ("exceptions", "crashes", "exception_records"))
    threads = _records(payload, ("threads", "thread_list"))
    registers = _mapping(payload, ("registers", "regs", "context"))
    functions = _records(payload, ("functions", "funcs"))
    comments = _records(payload, ("comments", "labels", "notes"))
    return {
        "modules": modules,
        "breakpoints": breakpoints,
        "exceptions": exceptions,
        "threads": threads,
        "registers": registers,
        "functions": functions,
        "comments": comments,
        "summary": {
            "provider": provider,
            "module_count": len(modules),
            "breakpoint_count": len(breakpoints),
            "exception_count": len(exceptions),
            "thread_count": len(threads),
            "function_count": len(functions),
        },
    }


def _parse_windbg(text: str) -> dict[str, Any]:
    modules = []
    exceptions = []
    registers: dict[str, str] = {}
    for line in text.splitlines()[:MAX_RECORDS]:
        module = re.match(r"^\s*([0-9a-fA-F`]{8,})\s+([0-9a-fA-F`]{8,})\s+(\S+)", line)
        if module:
            modules.append({"base": module.group(1), "end": module.group(2), "name": module.group(3)})
        exception = re.search(r"(?:ExceptionCode|exception code)[:=\s]+(0x)?([0-9a-fA-F]{8})", line, re.I)
        if exception:
            exceptions.append({"code": "0x" + exception.group(2).lower(), "line": line.strip()})
        for name, value in re.findall(r"\b([re]?(?:ax|bx|cx|dx|si|di|sp|bp|ip)|r(?:8|9|1[0-5]))=([0-9a-fA-F`]+)", line, re.I):
            registers[name.lower()] = value.replace("`", "")
    return {
        "modules": modules[:MAX_RECORDS],
        "breakpoints": [],
        "exceptions": exceptions[:MAX_RECORDS],
        "threads": [],
        "registers": registers,
        "functions": [],
        "comments": [],
        "summary": {"provider": "windbg", "module_count": len(modules), "exception_count": len(exceptions), "register_count": len(registers)},
    }


def _parse_minidump(raw: bytes) -> dict[str, Any]:
    if len(raw) < 32 or raw[:4] != b"MDMP":
        raise ValueError("input is not a valid minidump header")
    _signature, version, stream_count, directory_rva = struct.unpack_from("<IIII", raw, 0)
    if stream_count > MAX_RECORDS:
        raise ValueError("minidump stream count exceeds safety limit")
    streams = []
    for index in range(stream_count):
        offset = directory_rva + index * 12
        if offset + 12 > len(raw):
            raise ValueError("minidump stream directory is truncated")
        stream_type, data_size, rva = struct.unpack_from("<III", raw, offset)
        streams.append({"index": index, "type": stream_type, "data_size": data_size, "rva": rva, "in_bounds": rva + data_size <= len(raw)})
    return {
        "modules": [], "breakpoints": [], "exceptions": [], "threads": [], "registers": {}, "functions": [], "comments": [],
        "dump": {"version": version, "stream_count": stream_count, "directory_rva": directory_rva, "streams": streams},
        "summary": {"provider": "minidump", "stream_count": stream_count, "in_bounds_stream_count": sum(item["in_bounds"] for item in streams)},
    }


def _records(payload: Mapping[str, Any], names: Sequence[str]) -> list[Any]:
    for name in names:
        value = payload.get(name)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [dict(item) if isinstance(item, Mapping) else item for item in value[:MAX_RECORDS]]
        if isinstance(value, Mapping):
            return [{"name": str(key), "value": item} for key, item in list(value.items())[:MAX_RECORDS]]
    return []


def _mapping(payload: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
    for name in names:
        value = payload.get(name)
        if isinstance(value, Mapping):
            return {str(key): item for key, item in list(value.items())[:MAX_RECORDS]}
    return {}
