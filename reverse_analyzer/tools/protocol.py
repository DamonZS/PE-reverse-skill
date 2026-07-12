"""Passive protocol evidence inference from existing analysis data."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s'\"]+")
_HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?\b")
_PIPE_RE = re.compile(r"(?i)\\\\\.\\pipe\\[\w.-]+")


def protocol_analyze(
    *,
    path: str | os.PathLike[str] | None = None,
    strings: Mapping[str, Any] | Iterable[str] | None = None,
    dynamic_analysis: Mapping[str, Any] | None = None,
    behavior_graph: Mapping[str, Any] | None = None,
    semantic_ir: Mapping[str, Any] | None = None,
    gui_analysis: Mapping[str, Any] | None = None,
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    texts = _collect_texts(path, strings, dynamic_analysis, behavior_graph, semantic_ir, gui_analysis)
    if not texts:
        return {"status": "unavailable", "protocols": [], "flows": [], "field_stats": {}, "inference": {}, "reason": "no protocol evidence available"}

    urls = sorted({match for text in texts for match in _URL_RE.findall(text)})
    hosts = sorted({match for text in texts for match in _HOST_RE.findall(text)})
    pipes = sorted({match for text in texts for match in _PIPE_RE.findall(text)})
    lower = "\n".join(texts).lower()

    protocols: list[dict[str, Any]] = []

    def add(name: str, confidence: float, evidence: list[str]) -> None:
        protocols.append({"name": name, "confidence": round(confidence, 3), "evidence": evidence})

    if urls or any(token in lower for token in ("http", "https", "winhttp", "wininet", "user-agent", "content-type", "accept:")):
        add("http", 0.92 if urls else 0.62, ([f"url:{item}" for item in urls[:5]] or ["HTTP tokens in strings/dynamic evidence"]))
    if any(url.lower().startswith(("ws://", "wss://")) for url in urls) or "websocket" in lower:
        add("websocket", 0.88, ([f"url:{item}" for item in urls if item.lower().startswith(("ws://", "wss://"))][:5] or ["WebSocket tokens present"]))
    if any(token in lower for token in ("tcp", "connect", "socket", "ws2_32")):
        add("tcp", 0.58, ["TCP/socket API indicators"])
    if any(token in lower for token in ("udp", "sendto", "recvfrom", "datagram")):
        add("udp", 0.55, ["UDP/datagram API indicators"])
    if pipes:
        add("named_pipe", 0.8, [f"pipe:{item}" for item in pipes[:5]])

    formats: list[str] = []
    if any(token in lower for token in ('{"', "json", "application/json")):
        formats.append("json")
    if any(token in lower for token in ("protobuf", ".proto", "parsefromstring", "serializetostring", "protobuffer")):
        formats.append("protobuf-like")
    if "msgpack" in lower:
        formats.append("msgpack")
    if "gzip" in lower:
        formats.append("gzip")
    if "zlib" in lower or "deflate" in lower:
        formats.append("zlib")
    if "base64" in lower:
        formats.append("base64")

    flows = [{"endpoint": item, "kind": "url"} for item in urls[:20]]
    flows.extend({"endpoint": item, "kind": "host"} for item in hosts[:20] if item not in urls)
    flows.extend({"endpoint": item, "kind": "named_pipe"} for item in pipes[:20])

    field_stats = {
        "string_count": len(texts),
        "url_count": len(urls),
        "host_count": len(hosts),
        "named_pipe_count": len(pipes),
        "format_count": len(formats),
        "protocol_count": len(protocols),
    }
    inference = {
        "primary_protocol": protocols[0]["name"] if protocols else None,
        "message_formats": formats,
        "probable_flow_count": len(flows),
        "confidence": max((item["confidence"] for item in protocols), default=0.0),
        "strategy": {
            "name": "protocol_strings_dynamic_fusion",
            "key": "protocol:protocol_strings_dynamic_fusion",
            "reason": "Static strings plus dynamic/network hints provide low-friction passive protocol evidence.",
        },
    }
    result: dict[str, Any] = {
        "status": "ok",
        "protocols": protocols,
        "flows": flows,
        "field_stats": field_stats,
        "inference": inference,
        "artifacts": [],
    }
    if out_dir:
        protocol_dir = Path(out_dir) / "protocol"
        protocol_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "protocol/flows.json": protocol_dir / "flows.json",
            "protocol/field_stats.json": protocol_dir / "field_stats.json",
            "protocol/inference.json": protocol_dir / "inference.json",
        }
        _write_json(files["protocol/flows.json"], flows)
        _write_json(files["protocol/field_stats.json"], field_stats)
        _write_json(files["protocol/inference.json"], inference)
        result["artifacts"] = [{"name": name, "path": str(path_obj), "kind": "protocol-analysis"} for name, path_obj in files.items()]
    return result


def _collect_texts(
    path: str | os.PathLike[str] | None,
    strings: Mapping[str, Any] | Iterable[str] | None,
    dynamic_analysis: Mapping[str, Any] | None,
    behavior_graph: Mapping[str, Any] | None,
    semantic_ir: Mapping[str, Any] | None,
    gui_analysis: Mapping[str, Any] | None,
) -> list[str]:
    values: list[str] = []
    if path:
        try:
            data = Path(path).read_bytes()[:1024 * 1024]
            values.extend(match.group(0).decode("ascii", errors="ignore") for match in re.finditer(rb"[\x20-\x7e]{4,}", data))
        except OSError:
            pass
    if isinstance(strings, Mapping):
        values.extend(str(item) for item in (strings.get("strings") or []))
    elif isinstance(strings, Iterable) and not isinstance(strings, (str, bytes)):
        values.extend(str(item) for item in strings)
    for mapping in (dynamic_analysis, behavior_graph, semantic_ir, gui_analysis):
        values.extend(_mapping_strings(mapping))
    seen: set[str] = set()
    result: list[str] = []
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result[:4000]


def _mapping_strings(mapping: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(mapping, Mapping):
        return []
    results: list[str] = []
    stack: list[Any] = [mapping]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, value in current.items():
                if isinstance(key, str):
                    results.append(key)
                stack.append(value)
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            results.append(current)
    return results


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
