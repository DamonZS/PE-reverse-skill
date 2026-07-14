"""Bounded passive protocol capture import and message-shape inference.

The public helpers deliberately avoid live capture and network access.  They
consume existing evidence or bounded local files and return JSON-serializable
dictionaries so :class:`~reverse_analyzer.tools.executor.ToolExecutor` can
wrap them in the repository's normal ``ToolResult`` envelope.
"""

from __future__ import annotations

import base64
import binascii
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import struct
from typing import Any
from urllib.parse import urlsplit
import zlib


SCHEMA_VERSION = 1
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PACKETS = 4096
DEFAULT_MAX_MESSAGES = 1024
DEFAULT_MAX_MESSAGE_BYTES = 256 * 1024

_HARD_MAX_BYTES = 64 * 1024 * 1024
_HARD_MAX_PACKETS = 100_000
_HARD_MAX_MESSAGES = 10_000
_HARD_MAX_MESSAGE_BYTES = 1024 * 1024
_MAX_WARNINGS = 64
_MAX_TEXTS = 4000
_MAX_MAPPING_NODES = 12_000
_MAX_TEXT_PREVIEW = 8192

_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://[^\s'\"]+")
_HOST_RE = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?\b")
_PIPE_RE = re.compile(
    r"(?i)(?:\\\\[.?]\\pipe\\|\\Device\\NamedPipe\\|pipe://)[^\s'\"<>]+"
)
_LOOPBACK_RE = re.compile(
    r"(?i)(?<![\w.])(?:localhost|127(?:\.\d{1,3}){3}|::1|\[::1\])(?::\d{1,5})?"
)
_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}")
_HTTP_REQUEST_LINE_RE = re.compile(
    rb"^(?P<method>GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH)\s+"
    rb"(?P<target>\S+)\s+HTTP/(?P<version>\d(?:\.\d)?)$",
    re.IGNORECASE,
)
_HTTP_RESPONSE_LINE_RE = re.compile(
    rb"^HTTP/(?P<version>\d(?:\.\d)?)\s+(?P<status>\d{3})(?:\s+(?P<reason>.*))?$",
    re.IGNORECASE,
)

_APPLICATION_PROTOCOL_ALIASES = {
    "http": "http",
    "https": "http",
    "http1": "http",
    "http/1.0": "http",
    "http/1.1": "http",
    "ws": "websocket",
    "wss": "websocket",
    "websocket": "websocket",
    "web-socket": "websocket",
}
_TRANSPORT_ALIASES = {
    "6": "tcp",
    "17": "udp",
    "tcp": "tcp",
    "udp": "udp",
    "raw": "raw",
    "bytes": "raw",
    "binary": "raw",
    "pipe": "named_pipe",
    "named-pipe": "named_pipe",
    "named_pipe": "named_pipe",
    "namedpipe": "named_pipe",
    "ipc": "named_pipe",
    "loopback": "loopback",
    "local": "loopback",
}

_PCAP_MAGICS: dict[bytes, tuple[str, float]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_KNOWN_MAGICS: tuple[tuple[bytes, str], ...] = (
    (b"\x1f\x8b\x08", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
)


def protocol_capture(
    path: Any = None,
    *,
    data: Any = None,
    capture: Any = None,
    source_format: str | None = None,
    format: str | None = None,
    input_format: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Import a bounded passive capture and normalize TCP/UDP flows.

    ``path`` accepts PCAP, PCAPNG, JSON, JSONL, and raw files.  ``data`` can be
    bytes, text, a mapping, or an iterable of message/packet records.  The
    ``capture`` keyword is retained as a data alias.  Format aliases are
    accepted through ``source_format``, ``format``, and ``input_format`` for
    callers that already use one of those spellings.
    """

    limits = _effective_limits(max_bytes, max_packets, max_messages, max_message_bytes)
    warnings: list[str] = []
    source: dict[str, Any] = {
        "kind": "memory" if data is not None or isinstance(path, (bytes, bytearray, memoryview)) else "file",
        "format": None,
        "path": None,
        "bytes_read": 0,
        "size": None,
        "truncated": False,
    }
    requested_format = _normalize_format(source_format or format or input_format)

    if data is None and capture is not None:
        data = capture
    if data is None and isinstance(path, Mapping):
        data = path
        path = None
    elif data is None and isinstance(path, Iterable) and not isinstance(
        path, (str, bytes, bytearray, memoryview, os.PathLike)
    ):
        data = path
        path = None
    if data is not None:
        source["kind"] = "memory"

    if data is None and isinstance(path, (bytes, bytearray, memoryview)):
        data = bytes(path)
        path = None

    structured: Any = None
    raw = b""
    if data is not None:
        if isinstance(data, Mapping) or (
            isinstance(data, Iterable) and not isinstance(data, (str, bytes, bytearray, memoryview))
        ):
            structured = data
            source["format"] = requested_format or "json"
        else:
            if isinstance(data, str):
                encoded = data.encode("utf-8", errors="replace")
            elif isinstance(data, (bytes, bytearray, memoryview)):
                encoded = bytes(data)
            else:
                encoded = str(data).encode("utf-8", errors="replace")
            raw, truncated = _bounded_bytes(encoded, limits["max_bytes"])
            source.update(
                {
                    "bytes_read": len(raw),
                    "size": len(encoded),
                    "truncated": truncated,
                }
            )
            if truncated:
                _warn(warnings, f"input truncated at max_bytes={limits['max_bytes']}")
    elif path is None or not str(path).strip():
        return _capture_unavailable("no capture source provided", limits, source, out_dir)
    else:
        sample = Path(path)
        source["path"] = str(sample)
        try:
            if not sample.is_file():
                return _capture_unavailable(f"capture not found: {sample}", limits, source, out_dir)
            try:
                source["size"] = sample.stat().st_size
            except OSError:
                source["size"] = None
            raw, truncated = _read_bounded(sample, limits["max_bytes"])
            source["bytes_read"] = len(raw)
            source["truncated"] = truncated
            if truncated:
                _warn(warnings, f"capture truncated at max_bytes={limits['max_bytes']}")
        except OSError as exc:
            return _capture_unavailable(f"capture unavailable: {exc}", limits, source, out_dir)

    detected_format = requested_format or source.get("format") or _detect_format(raw, Path(path).suffix if path else "")
    source["format"] = detected_format

    flows: list[dict[str, Any]] = []
    messages: list[dict[str, Any]] = []
    packet_count = 0
    link_types: list[int] = []
    limit_hit = bool(source["truncated"])

    try:
        if structured is not None:
            flows, messages, stats = _capture_structured(
                structured,
                max_packets=limits["max_packets"],
                max_messages=limits["max_messages"],
                max_message_bytes=limits["max_message_bytes"],
                warnings=warnings,
            )
            packet_count = stats["packet_count"]
            limit_hit = limit_hit or stats["limit_hit"]
        elif detected_format == "pcap":
            parsed = _parse_pcap(raw, limits["max_packets"], limits["max_message_bytes"], warnings)
            flows, messages, stats = _normalize_packets(
                parsed["records"], limits["max_messages"], limits["max_message_bytes"], warnings
            )
            packet_count = parsed["packet_count"]
            link_types = parsed["link_types"]
            limit_hit = limit_hit or parsed["limit_hit"] or stats["limit_hit"]
        elif detected_format == "pcapng":
            parsed = _parse_pcapng(raw, limits["max_packets"], limits["max_message_bytes"], warnings)
            flows, messages, stats = _normalize_packets(
                parsed["records"], limits["max_messages"], limits["max_message_bytes"], warnings
            )
            packet_count = parsed["packet_count"]
            link_types = parsed["link_types"]
            limit_hit = limit_hit or parsed["limit_hit"] or stats["limit_hit"]
        elif detected_format == "json":
            try:
                value = json.loads(raw.decode("utf-8-sig"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                _warn(warnings, f"invalid JSON capture: {exc}")
                value = None
            if value is not None:
                flows, messages, stats = _capture_structured(
                    value,
                    max_packets=limits["max_packets"],
                    max_messages=limits["max_messages"],
                    max_message_bytes=limits["max_message_bytes"],
                    warnings=warnings,
                )
                packet_count = stats["packet_count"]
                limit_hit = limit_hit or stats["limit_hit"]
        elif detected_format == "jsonl":
            records, jsonl_truncated = _parse_jsonl(raw, limits["max_packets"], limits["max_messages"], warnings)
            flows, messages, stats = _capture_structured(
                {"records": records},
                max_packets=limits["max_packets"],
                max_messages=limits["max_messages"],
                max_message_bytes=limits["max_message_bytes"],
                warnings=warnings,
            )
            packet_count = stats["packet_count"]
            limit_hit = limit_hit or jsonl_truncated or stats["limit_hit"]
        elif detected_format == "raw":
            flows, messages, stats = _normalize_imported_messages(
                [raw], [], limits["max_messages"], limits["max_message_bytes"], warnings
            )
            packet_count = 1 if raw else 0
            limit_hit = limit_hit or stats["limit_hit"]
        else:
            _warn(warnings, f"unsupported capture format: {detected_format or 'unknown'}")
    except (ValueError, TypeError, struct.error) as exc:
        _warn(warnings, f"capture parse failed: {type(exc).__name__}: {exc}")

    _annotate_captured_messages(messages)
    _apply_message_protocols_to_flows(flows, messages)
    request_response_pairs = _correlate_request_responses(messages)
    capture_field_profile = _build_field_statistics(messages)
    transport_counts = Counter(str(flow.get("transport") or "unknown") for flow in flows)
    captured_payload_bytes = sum(int(message.get("captured_size") or 0) for message in messages)
    payload_bytes = sum(int(message.get("payload_size") or 0) for message in messages)
    field_stats = {
        "packet_count": packet_count,
        "flow_count": len(flows),
        "message_count": len(messages),
        "tcp_flow_count": transport_counts.get("tcp", 0),
        "udp_flow_count": transport_counts.get("udp", 0),
        "raw_flow_count": transport_counts.get("raw", 0),
        "named_pipe_flow_count": transport_counts.get("named_pipe", 0),
        "loopback_flow_count": sum(flow.get("scope") == "loopback" for flow in flows),
        "request_response_pair_count": len(request_response_pairs),
        "payload_bytes": payload_bytes,
        "captured_payload_bytes": captured_payload_bytes,
        **capture_field_profile,
    }
    source["packet_count"] = packet_count
    source["link_types"] = sorted(set(link_types))
    source["limit_hit"] = limit_hit
    if limit_hit:
        source["truncated"] = True

    if messages:
        status = "partial" if warnings or limit_hit else "ok"
        reason = None
    elif warnings or source["truncated"]:
        status = "partial"
        reason = "capture contained no supported protocol or IPC payload messages"
    else:
        status = "unavailable"
        reason = "capture contained no supported protocol or IPC payload messages"

    result: dict[str, Any] = {
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "limits": limits,
        "flows": flows,
        "messages": messages,
        "field_stats": field_stats,
        "field_statistics": field_stats["fields"],
        "request_response_pairs": request_response_pairs,
        "warnings": warnings,
        "dependencies": {"pcap_parser": "builtin"},
        "artifacts": [],
    }
    if reason:
        result["reason"] = reason
    _persist_result_artifacts(
        result,
        out_dir,
        [("protocol/capture.json", "capture.json", "protocol-capture", _artifact_payload(result))],
    )
    return result


def protocol_infer(
    capture: Any = None,
    *,
    data: Any = None,
    messages: Iterable[Any] | None = None,
    path: str | os.PathLike[str] | None = None,
    source_format: str | None = None,
    format: str | None = None,
    input_format: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Infer framing, encodings, and Protobuf wire shapes from messages."""

    limits = _effective_limits(max_bytes, max_packets, max_messages, max_message_bytes)
    warnings: list[str] = []
    dependencies: dict[str, str] = {"msgpack": "not-needed"}
    if capture is None and data is not None:
        capture = data
    source_format = source_format or format or input_format

    capture_result: dict[str, Any]
    if messages is not None:
        flows, normalized, stats = _normalize_imported_messages(
            messages, [], limits["max_messages"], limits["max_message_bytes"], warnings
        )
        capture_result = {
            "status": "partial" if stats["limit_hit"] else ("ok" if normalized else "unavailable"),
            "flows": flows,
            "messages": normalized,
            "source": {"kind": "memory", "format": source_format or "messages"},
            "warnings": [],
        }
    elif path is not None:
        capture_result = protocol_capture(
            path,
            source_format=source_format,
            max_bytes=limits["max_bytes"],
            max_packets=limits["max_packets"],
            max_messages=limits["max_messages"],
            max_message_bytes=limits["max_message_bytes"],
        )
    elif isinstance(capture, Mapping) and isinstance(capture.get("messages"), list):
        source_messages = capture.get("messages") or []
        flows, normalized, stats = _normalize_imported_messages(
            source_messages,
            capture.get("flows") if isinstance(capture.get("flows"), list) else [],
            limits["max_messages"],
            limits["max_message_bytes"],
            warnings,
        )
        capture_result = {
            "status": str(capture.get("status") or ("ok" if normalized else "unavailable")),
            "flows": flows,
            "messages": normalized,
            "source": dict(capture.get("source") or {}) if isinstance(capture.get("source"), Mapping) else {},
            "warnings": list(capture.get("warnings") or []) if isinstance(capture.get("warnings"), list) else [],
        }
        if stats["limit_hit"]:
            capture_result["status"] = "partial"
    elif capture is not None:
        capture_result = protocol_capture(
            data=capture,
            source_format=source_format,
            max_bytes=limits["max_bytes"],
            max_packets=limits["max_packets"],
            max_messages=limits["max_messages"],
            max_message_bytes=limits["max_message_bytes"],
        )
    else:
        capture_result = {
            "status": "unavailable",
            "flows": [],
            "messages": [],
            "source": {},
            "warnings": [],
        }

    for warning in capture_result.get("warnings") or []:
        _warn(warnings, str(warning))
    source_messages = list(capture_result.get("messages") or [])[: limits["max_messages"]]
    flows = list(capture_result.get("flows") or [])[: limits["max_messages"]]

    inferred_messages: list[dict[str, Any]] = []
    framing_observations: list[dict[str, Any]] = []
    format_counts: Counter[str] = Counter()
    entropy_values: list[float] = []
    protobuf_shapes: dict[str, dict[str, Any]] = {}
    logical_limit_hit = False

    for source_message in source_messages:
        payload = _message_payload(source_message, limits["max_message_bytes"])
        source_entropy = _entropy_summary(payload)
        entropy_values.append(float(source_entropy["value"]))
        frame_result = _frame_message(payload, limits["max_messages"] - len(inferred_messages))
        if frame_result["candidate"]:
            candidate = dict(frame_result["candidate"])
            candidate["source_message_id"] = str(source_message.get("id") or "")
            framing_observations.append(candidate)
        frames = frame_result["frames"]
        if frame_result["limit_hit"]:
            logical_limit_hit = True
            _warn(warnings, f"logical messages truncated at max_messages={limits['max_messages']}")
        for frame_index, frame in enumerate(frames, start=1):
            if len(inferred_messages) >= limits["max_messages"]:
                logical_limit_hit = True
                break
            frame_bytes, frame_truncated = _bounded_bytes(frame, limits["max_message_bytes"])
            entropy = _entropy_summary(frame_bytes)
            framing = dict(frame_result["candidate"] or {"type": "unframed", "confidence": 0.5})
            framing["frame_index"] = frame_index
            framing["frame_count"] = len(frames)
            application = _analyze_application_message(frame_bytes, source_message, framing)
            analysis_payload = application.pop("_analysis_payload", frame_bytes)
            format_result = _analyze_formats(analysis_payload, limits["max_message_bytes"])
            for warning in format_result["warnings"]:
                _warn(warnings, warning)
            if format_result["msgpack_dependency"]:
                dependencies["msgpack"] = format_result["msgpack_dependency"]
            format_names = [str(item["name"]) for item in format_result["formats"]]
            protobuf = _infer_protobuf_shape(analysis_payload)
            if protobuf is not None:
                if "protobuf" not in format_names:
                    format_names.append("protobuf")
                    format_result["formats"].append(
                        {
                            "name": "protobuf",
                            "confidence": protobuf["confidence"],
                            "layer": 0,
                            "evidence": "valid Protobuf wire-field sequence",
                        }
                    )
                shape = protobuf_shapes.setdefault(
                    str(protobuf["signature"]),
                    {
                        "signature": protobuf["signature"],
                        "message_count": 0,
                        "confidence": protobuf["confidence"],
                        "fields": protobuf["fields"],
                        "wire_type_counts": dict(protobuf["wire_type_counts"]),
                    },
                )
                shape["message_count"] += 1
                shape["confidence"] = max(float(shape["confidence"]), float(protobuf["confidence"]))

            for name in set(format_names):
                format_counts[name] += 1
            source_id = str(source_message.get("id") or f"message-{len(inferred_messages) + 1:06d}")
            message_id = source_id if len(frames) == 1 else f"{source_id}.frame-{frame_index:04d}"
            item = {
                "id": message_id,
                "source_message_id": source_id,
                "flow_id": source_message.get("flow_id"),
                "transport": str(source_message.get("transport") or "raw"),
                "direction": str(source_message.get("direction") or "unknown"),
                "kind": "logical_message",
                "timestamp_start": source_message.get("timestamp_start"),
                "timestamp_end": source_message.get("timestamp_end"),
                **_payload_fields(frame_bytes, len(frame), frame_truncated),
                "framing": framing,
                "entropy": entropy,
                "formats": format_names,
                "format_details": format_result["formats"],
                "decoded": format_result["decoded"],
                "protobuf": protobuf,
                **application,
            }
            inferred_messages.append(item)
        if len(inferred_messages) >= limits["max_messages"] and source_message is not source_messages[-1]:
            logical_limit_hit = True
            break

    _apply_message_protocols_to_flows(flows, inferred_messages)
    request_response_pairs = _correlate_request_responses(inferred_messages)
    field_profile = _build_field_statistics(inferred_messages)
    framing = _summarize_framing(framing_observations, entropy_values)
    protocols = _infer_capture_protocols(flows, inferred_messages)
    formats = sorted(format_counts, key=lambda name: (-format_counts[name], name))
    shapes = sorted(protobuf_shapes.values(), key=lambda item: str(item["signature"]))
    primary_protocol = protocols[0]["name"] if protocols else None
    confidence = max((float(item["confidence"]) for item in protocols), default=0.0)
    field_stats = {
        "flow_count": len(flows),
        "source_message_count": len(source_messages),
        "message_count": len(inferred_messages),
        "format_count": len(formats),
        "protobuf_message_count": sum(int(item["message_count"]) for item in shapes),
        "captured_payload_bytes": sum(int(item.get("captured_size") or 0) for item in inferred_messages),
        "format_counts": dict(sorted(format_counts.items())),
        "request_count": sum(item.get("message_type") == "request" for item in inferred_messages),
        "response_count": sum(item.get("message_type") == "response" for item in inferred_messages),
        "request_response_pair_count": len(request_response_pairs),
        **field_profile,
    }
    semantic_ir_fragment = _build_semantic_ir_fragment(
        flows,
        inferred_messages,
        protocols,
        formats,
        shapes,
        request_response_pairs,
    )
    inference = {
        "primary_protocol": primary_protocol,
        "message_formats": formats,
        "probable_flow_count": len(flows),
        "confidence": round(confidence, 3),
        "framing": framing,
        "protobuf_shapes": shapes,
        "request_response_pair_count": len(request_response_pairs),
        "field_count": int(field_profile["field_count"]),
        "strategy": {
            "name": "bounded_protocol_capture_inference",
            "key": "protocol:bounded_protocol_capture_inference",
            "reason": "Bounded passive flow normalization plus deterministic message framing and format inference.",
        },
    }

    source_status = str(capture_result.get("status") or "unavailable")
    unavailable_dependency = any(value == "unavailable" for value in dependencies.values())
    if inferred_messages:
        status = "partial" if source_status == "partial" or warnings or logical_limit_hit or unavailable_dependency else "ok"
        reason = None
    else:
        status = "partial" if source_status == "partial" or warnings else "unavailable"
        reason = "no messages available for protocol inference"

    result: dict[str, Any] = {
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "source": capture_result.get("source") or {},
        "limits": limits,
        "protocols": protocols,
        "flows": flows,
        "messages": inferred_messages,
        "framing": framing,
        "message_formats": formats,
        "protobuf_shapes": shapes,
        "field_stats": field_stats,
        "field_statistics": field_stats["fields"],
        "request_response_pairs": request_response_pairs,
        "inference": inference,
        "semantic_ir_fragment": semantic_ir_fragment,
        "dependencies": dependencies,
        "warnings": warnings,
        "artifacts": [],
    }
    if reason:
        result["reason"] = reason
    inference_artifact = {
        key: value
        for key, value in result.items()
        if key not in {"messages", "semantic_ir_fragment", "artifacts"}
    }
    _persist_result_artifacts(
        result,
        out_dir,
        [
            (
                "protocol/messages.json",
                "messages.json",
                "protocol-messages",
                {
                    "schema_version": SCHEMA_VERSION,
                    "messages": inferred_messages,
                    "request_response_pairs": request_response_pairs,
                    "field_stats": field_stats,
                },
            ),
            ("protocol/inference.json", "inference.json", "protocol-analysis", inference_artifact),
            (
                "protocol/semantic_ir_fragment.json",
                "semantic_ir_fragment.json",
                "semantic-ir",
                semantic_ir_fragment,
            ),
        ],
    )
    return result


def protocol_summarize(
    analysis: Mapping[str, Any] | None = None,
    *,
    capture: Any = None,
    data: Any = None,
    inference: Mapping[str, Any] | None = None,
    messages: Iterable[Any] | None = None,
    path: str | os.PathLike[str] | None = None,
    source_format: str | None = None,
    format: str | None = None,
    input_format: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    out_dir: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Produce a compact, stable summary from capture or inference output."""

    if capture is None and data is not None:
        capture = data
    source_format = source_format or format or input_format
    candidate = inference or analysis
    if candidate is not None and not _looks_like_inference(candidate):
        candidate = protocol_infer(
            candidate,
            max_bytes=max_bytes,
            max_packets=max_packets,
            max_messages=max_messages,
            max_message_bytes=max_message_bytes,
        )
    elif candidate is None:
        candidate = protocol_infer(
            capture,
            messages=messages,
            path=path,
            source_format=source_format,
            max_bytes=max_bytes,
            max_packets=max_packets,
            max_messages=max_messages,
            max_message_bytes=max_message_bytes,
        )

    payload = dict(candidate or {})
    flows = [dict(item) for item in payload.get("flows") or [] if isinstance(item, Mapping)]
    source_messages = [dict(item) for item in payload.get("messages") or [] if isinstance(item, Mapping)]
    protocols = [dict(item) for item in payload.get("protocols") or [] if isinstance(item, Mapping)]
    formats = [str(item) for item in payload.get("message_formats") or []]
    shapes = [dict(item) for item in payload.get("protobuf_shapes") or [] if isinstance(item, Mapping)]
    request_response_pairs = [
        dict(item)
        for item in payload.get("request_response_pairs") or []
        if isinstance(item, Mapping)
    ]
    field_stats = dict(payload.get("field_stats") or {}) if isinstance(payload.get("field_stats"), Mapping) else {}

    transport_counts = Counter(str(item.get("transport") or "unknown") for item in flows)
    framing_counts = Counter(
        str((item.get("framing") or {}).get("type") or "unframed")
        for item in source_messages
        if isinstance(item.get("framing"), Mapping)
    )
    message_summaries = [
        {
            "id": item.get("id"),
            "flow_id": item.get("flow_id"),
            "transport": item.get("transport"),
            "application_protocol": item.get("application_protocol"),
            "direction": item.get("direction"),
            "message_type": item.get("message_type"),
            "exchange_id": item.get("exchange_id"),
            "paired_message_id": item.get("paired_message_id"),
            "payload_size": item.get("payload_size"),
            "captured_size": item.get("captured_size"),
            "formats": list(item.get("formats") or []),
            "framing": dict(item.get("framing") or {}) if isinstance(item.get("framing"), Mapping) else {},
            "protobuf_signature": (item.get("protobuf") or {}).get("signature")
            if isinstance(item.get("protobuf"), Mapping)
            else None,
        }
        for item in source_messages[: _effective_limit(max_messages, DEFAULT_MAX_MESSAGES, _HARD_MAX_MESSAGES)]
    ]
    summary = {
        "flow_count": len(flows),
        "message_count": len(source_messages),
        "protocol_count": len(protocols),
        "format_count": len(formats),
        "protobuf_shape_count": len(shapes),
        "field_count": int(field_stats.get("field_count") or 0),
        "request_response_pair_count": len(request_response_pairs),
        "transport_counts": dict(sorted(transport_counts.items())),
        "framing_counts": dict(sorted(framing_counts.items())),
        "message_formats": formats,
        "primary_protocol": (payload.get("inference") or {}).get("primary_protocol")
        if isinstance(payload.get("inference"), Mapping)
        else (protocols[0].get("name") if protocols else None),
    }
    semantic_ir_fragment = payload.get("semantic_ir_fragment")
    if not isinstance(semantic_ir_fragment, Mapping):
        semantic_ir_fragment = _build_semantic_ir_fragment(
            flows,
            source_messages,
            protocols,
            formats,
            shapes,
            request_response_pairs,
        )
    status = str(payload.get("status") or ("ok" if source_messages else "unavailable"))
    result: dict[str, Any] = {
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "summary": summary,
        "protocols": protocols,
        "flows": flows,
        "messages": message_summaries,
        "message_shapes": shapes,
        "field_stats": field_stats,
        "request_response_pairs": request_response_pairs,
        "semantic_ir_fragment": dict(semantic_ir_fragment),
        "warnings": list(payload.get("warnings") or []),
        "artifacts": [],
    }
    _persist_result_artifacts(
        result,
        out_dir,
        [("protocol/summary.json", "summary.json", "protocol-summary", _artifact_payload(result))],
    )
    return result


def protocol_analyze(
    *,
    path: str | os.PathLike[str] | None = None,
    strings: Mapping[str, Any] | Iterable[str] | None = None,
    dynamic_analysis: Mapping[str, Any] | None = None,
    behavior_graph: Mapping[str, Any] | None = None,
    semantic_ir: Mapping[str, Any] | None = None,
    gui_analysis: Mapping[str, Any] | None = None,
    out_dir: str | os.PathLike[str] | None = None,
    capture: Any = None,
    data: Any = None,
    capture_path: str | os.PathLike[str] | None = None,
    messages: Iterable[Any] | None = None,
    source_format: str | None = None,
    format: str | None = None,
    input_format: str | None = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_messages: int = DEFAULT_MAX_MESSAGES,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> dict[str, Any]:
    """Fuse legacy string evidence with optional passive capture inference.

    The original keyword-only parameters and the legacy ``protocols``,
    ``flows``, ``field_stats``, and ``inference`` fields remain intact.
    """

    if capture is None and data is not None:
        capture = data
    source_format = source_format or format or input_format
    texts = _collect_texts(path, strings, dynamic_analysis, behavior_graph, semantic_ir, gui_analysis)
    static = _infer_static_evidence(texts)

    capture_inference: dict[str, Any] | None = None
    inferred_capture_path = capture_path
    if inferred_capture_path is None and path is not None and _looks_like_capture_path(Path(path)):
        inferred_capture_path = path
    if capture is not None or messages is not None or inferred_capture_path is not None:
        if isinstance(capture, Mapping) and _looks_like_inference(capture):
            capture_inference = dict(capture)
        else:
            capture_inference = protocol_infer(
                capture,
                messages=messages,
                path=inferred_capture_path,
                source_format=source_format,
                max_bytes=max_bytes,
                max_packets=max_packets,
                max_messages=max_messages,
                max_message_bytes=max_message_bytes,
            )

    capture_messages = list((capture_inference or {}).get("messages") or [])
    request_response_pairs = list((capture_inference or {}).get("request_response_pairs") or [])
    if not texts and not capture_messages:
        reason = "no protocol evidence available"
        if capture_inference and capture_inference.get("reason"):
            reason = str(capture_inference["reason"])
        return {
            "status": "unavailable",
            "protocols": [],
            "flows": [],
            "field_stats": {},
            "inference": {},
            "messages": [],
            "request_response_pairs": [],
            "field_statistics": [],
            "semantic_ir_fragment": _build_semantic_ir_fragment([], [], [], [], []),
            "artifacts": [],
            "reason": reason,
        }

    protocols = _merge_protocols(static["protocols"], (capture_inference or {}).get("protocols") or [])
    flows = _merge_flows(static["flows"], (capture_inference or {}).get("flows") or [])
    formats = _ordered_unique(
        [*static["formats"], *[str(item) for item in (capture_inference or {}).get("message_formats") or []]]
    )
    capture_stats = (capture_inference or {}).get("field_stats") or {}
    field_stats = dict(static["field_stats"])
    field_stats.update(
        {
            "protocol_count": len(protocols),
            "format_count": len(formats),
            "capture_flow_count": int(capture_stats.get("flow_count") or 0),
            "message_count": len(capture_messages),
            "protobuf_message_count": int(capture_stats.get("protobuf_message_count") or 0),
            "request_response_pair_count": len(request_response_pairs),
            "field_count": int(capture_stats.get("field_count") or 0),
            "messages_with_fields": int(capture_stats.get("messages_with_fields") or 0),
            "fields": list(capture_stats.get("fields") or []),
        }
    )
    primary_protocol = protocols[0]["name"] if protocols else None
    confidence = max((float(item.get("confidence") or 0.0) for item in protocols), default=0.0)
    inference = {
        "primary_protocol": primary_protocol,
        "message_formats": formats,
        "probable_flow_count": len(flows),
        "confidence": round(confidence, 3),
        "request_response_pair_count": len(request_response_pairs),
        "field_count": int(capture_stats.get("field_count") or 0),
        "strategy": {
            "name": "protocol_strings_dynamic_fusion"
            if not capture_messages
            else "protocol_strings_capture_fusion",
            "key": "protocol:protocol_strings_dynamic_fusion"
            if not capture_messages
            else "protocol:protocol_strings_capture_fusion",
            "reason": "Static strings plus dynamic/network hints provide low-friction passive protocol evidence."
            if not capture_messages
            else "Static and dynamic hints are fused with bounded passive capture message inference.",
        },
    }
    if capture_inference:
        inference["framing"] = capture_inference.get("framing") or {}
        inference["protobuf_shapes"] = capture_inference.get("protobuf_shapes") or []

    semantic_fragment = (capture_inference or {}).get("semantic_ir_fragment")
    if not isinstance(semantic_fragment, Mapping):
        semantic_fragment = _build_semantic_ir_fragment(
            flows,
            capture_messages,
            protocols,
            formats,
            [],
            request_response_pairs,
        )
    status = "partial" if capture_inference and capture_inference.get("status") == "partial" else "ok"
    result: dict[str, Any] = {
        "status": status,
        "protocols": protocols,
        "flows": flows,
        "field_stats": field_stats,
        "inference": inference,
        "messages": capture_messages,
        "field_statistics": field_stats.get("fields") or [],
        "request_response_pairs": request_response_pairs,
        "semantic_ir_fragment": dict(semantic_fragment),
        "warnings": list((capture_inference or {}).get("warnings") or []),
        "artifacts": [],
    }
    if out_dir:
        specs: list[tuple[str, str, str, Any]] = [
            ("protocol/flows.json", "flows.json", "protocol-analysis", flows),
            ("protocol/field_stats.json", "field_stats.json", "protocol-analysis", field_stats),
            ("protocol/inference.json", "inference.json", "protocol-analysis", inference),
        ]
        if capture_messages:
            specs.extend(
                [
                    (
                        "protocol/messages.json",
                        "messages.json",
                        "protocol-messages",
                        {
                            "schema_version": SCHEMA_VERSION,
                            "messages": capture_messages,
                            "request_response_pairs": request_response_pairs,
                            "field_stats": field_stats,
                        },
                    ),
                    (
                        "protocol/semantic_ir_fragment.json",
                        "semantic_ir_fragment.json",
                        "semantic-ir",
                        semantic_fragment,
                    ),
                ]
            )
        _persist_result_artifacts(result, out_dir, specs)
    return result


def _effective_limits(max_bytes: Any, max_packets: Any, max_messages: Any, max_message_bytes: Any) -> dict[str, int]:
    return {
        "max_bytes": _effective_limit(max_bytes, DEFAULT_MAX_BYTES, _HARD_MAX_BYTES),
        "max_packets": _effective_limit(max_packets, DEFAULT_MAX_PACKETS, _HARD_MAX_PACKETS),
        "max_messages": _effective_limit(max_messages, DEFAULT_MAX_MESSAGES, _HARD_MAX_MESSAGES),
        "max_message_bytes": _effective_limit(
            max_message_bytes, DEFAULT_MAX_MESSAGE_BYTES, _HARD_MAX_MESSAGE_BYTES
        ),
    }


def _effective_limit(value: Any, default: int, hard_max: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        parsed = default
    return max(1, min(parsed, hard_max))


def _bounded_bytes(data: bytes, limit: int) -> tuple[bytes, bool]:
    if len(data) <= limit:
        return data, False
    return data[:limit], True


def _read_bounded(path: Path, limit: int) -> tuple[bytes, bool]:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    return _bounded_bytes(data, limit)


def _normalize_format(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower().replace("_", "-")
    aliases = {
        "cap": "pcap",
        "libpcap": "pcap",
        "pcap-ng": "pcapng",
        "ndjson": "jsonl",
        "json-lines": "jsonl",
        "binary": "raw",
        "bytes": "raw",
        "bin": "raw",
    }
    return aliases.get(normalized, normalized)


def _detect_format(data: bytes, suffix: str = "") -> str:
    if data[:4] in _PCAP_MAGICS:
        return "pcap"
    if data.startswith(_PCAPNG_MAGIC):
        return "pcapng"
    suffix_format = _normalize_format(suffix.lower().lstrip("."))
    if suffix_format in {"pcap", "pcapng", "json", "jsonl", "raw"}:
        return str(suffix_format)
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped.startswith((b"[", b"{")):
        try:
            json.loads(data.decode("utf-8-sig"))
            return "json"
        except (UnicodeDecodeError, json.JSONDecodeError):
            if len([line for line in data.splitlines() if line.strip()]) > 1:
                return "jsonl"
    return "raw"


def _looks_like_capture_path(path: Path) -> bool:
    if path.suffix.lower() in {".pcap", ".cap", ".pcapng", ".json", ".jsonl", ".ndjson", ".raw"}:
        return True
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
        return magic in _PCAP_MAGICS or magic == _PCAPNG_MAGIC
    except OSError:
        return False


def _capture_unavailable(
    reason: str,
    limits: Mapping[str, int],
    source: Mapping[str, Any],
    out_dir: str | os.PathLike[str] | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "unavailable",
        "schema_version": SCHEMA_VERSION,
        "source": dict(source),
        "limits": dict(limits),
        "flows": [],
        "messages": [],
        "field_stats": {
            "packet_count": 0,
            "flow_count": 0,
            "message_count": 0,
            "tcp_flow_count": 0,
            "udp_flow_count": 0,
            "raw_flow_count": 0,
            "named_pipe_flow_count": 0,
            "loopback_flow_count": 0,
            "request_response_pair_count": 0,
            "payload_bytes": 0,
            "captured_payload_bytes": 0,
            "field_count": 0,
            "messages_with_fields": 0,
            "fields": [],
        },
        "field_statistics": [],
        "request_response_pairs": [],
        "warnings": [],
        "dependencies": {"pcap_parser": "builtin"},
        "artifacts": [],
        "reason": reason,
        "error": reason,
    }
    _persist_result_artifacts(
        result,
        out_dir,
        [("protocol/capture.json", "capture.json", "protocol-capture", _artifact_payload(result))],
    )
    return result


def _parse_pcap(
    data: bytes,
    max_packets: int,
    max_message_bytes: int,
    warnings: list[str],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    if len(data) < 24 or data[:4] not in _PCAP_MAGICS:
        _warn(warnings, "invalid or truncated PCAP global header")
        return {"records": records, "packet_count": 0, "link_types": [], "limit_hit": False}
    endian, timestamp_scale = _PCAP_MAGICS[data[:4]]
    _, major, _, _, _, snaplen, linktype = struct.unpack_from(f"{endian}IHHIIII", data, 0)
    if major not in {2}:
        _warn(warnings, f"unexpected PCAP version: {major}")
    if snaplen <= 0:
        _warn(warnings, "PCAP snaplen is zero")
    offset = 24
    packet_count = 0
    limit_hit = False
    while offset < len(data):
        if packet_count >= max_packets:
            limit_hit = True
            _warn(warnings, f"packet import truncated at max_packets={max_packets}")
            break
        if len(data) - offset < 16:
            _warn(warnings, "truncated PCAP packet header")
            break
        ts_sec, ts_fraction, captured_length, original_length = struct.unpack_from(f"{endian}IIII", data, offset)
        offset += 16
        if captured_length > len(data) - offset:
            _warn(warnings, "truncated PCAP packet payload")
            break
        packet_count += 1
        copy_length = min(captured_length, max_message_bytes + 512)
        packet = data[offset : offset + copy_length]
        timestamp = round(float(ts_sec) + float(ts_fraction) / timestamp_scale, 9)
        record = _decode_link_packet(packet, int(linktype), timestamp, packet_count, warnings)
        if record is not None:
            record["captured_packet_size"] = int(captured_length)
            record["original_packet_size"] = int(original_length)
            records.append(record)
        offset += captured_length
    return {
        "records": records,
        "packet_count": packet_count,
        "link_types": [int(linktype)],
        "limit_hit": limit_hit,
    }


def _parse_pcapng(
    data: bytes,
    max_packets: int,
    max_message_bytes: int,
    warnings: list[str],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    link_types: set[int] = set()
    offset = 0
    endian: str | None = None
    packet_count = 0
    limit_hit = False
    while offset < len(data):
        if len(data) - offset < 12:
            _warn(warnings, "truncated PCAPNG block header")
            break
        raw_type = data[offset : offset + 4]
        if raw_type == _PCAPNG_MAGIC:
            if len(data) - offset < 16:
                _warn(warnings, "truncated PCAPNG section header")
                break
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                _warn(warnings, "invalid PCAPNG byte-order magic")
                break
            block_type = 0x0A0D0D0A
            interfaces = []
        elif endian is None:
            _warn(warnings, "PCAPNG does not start with a section header")
            break
        else:
            block_type = struct.unpack_from(f"{endian}I", data, offset)[0]
        assert endian is not None
        block_length = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
        if block_length < 12 or block_length % 4 or block_length > len(data) - offset:
            _warn(warnings, "invalid or truncated PCAPNG block length")
            break
        trailer = struct.unpack_from(f"{endian}I", data, offset + block_length - 4)[0]
        if trailer != block_length:
            _warn(warnings, "PCAPNG block length trailer mismatch")
            break
        body_start = offset + 8
        body_end = offset + block_length - 4
        body = data[body_start:body_end]

        if block_type == 1:
            if len(body) < 8:
                _warn(warnings, "truncated PCAPNG interface description")
            else:
                linktype = struct.unpack_from(f"{endian}H", body, 0)[0]
                timestamp_resolution = 1e-6
                option_offset = 8
                while option_offset + 4 <= len(body):
                    option_code, option_length = struct.unpack_from(f"{endian}HH", body, option_offset)
                    option_offset += 4
                    if option_code == 0:
                        break
                    if option_length > len(body) - option_offset:
                        break
                    option_value = body[option_offset : option_offset + option_length]
                    if option_code == 9 and option_value:
                        resolution = option_value[0]
                        timestamp_resolution = 2.0 ** -(resolution & 0x7F) if resolution & 0x80 else 10.0 ** -resolution
                    option_offset += (option_length + 3) & ~3
                interfaces.append({"linktype": int(linktype), "timestamp_resolution": timestamp_resolution})
                link_types.add(int(linktype))
        elif block_type in {2, 6}:
            if packet_count >= max_packets:
                limit_hit = True
                _warn(warnings, f"packet import truncated at max_packets={max_packets}")
                break
            if block_type == 6 and len(body) >= 20:
                interface_id, ts_high, ts_low, captured_length, original_length = struct.unpack_from(
                    f"{endian}IIIII", body, 0
                )
                packet_offset = 20
            elif block_type == 2 and len(body) >= 20:
                interface_id, _drops = struct.unpack_from(f"{endian}HH", body, 0)
                ts_high, ts_low, captured_length, original_length = struct.unpack_from(f"{endian}IIII", body, 4)
                packet_offset = 20
            else:
                _warn(warnings, "truncated PCAPNG packet block")
                offset += block_length
                continue
            if interface_id >= len(interfaces):
                _warn(warnings, f"PCAPNG packet references unknown interface {interface_id}")
                offset += block_length
                continue
            if captured_length > len(body) - packet_offset:
                _warn(warnings, "truncated PCAPNG packet payload")
                offset += block_length
                continue
            packet_count += 1
            interface = interfaces[interface_id]
            raw_timestamp = (int(ts_high) << 32) | int(ts_low)
            timestamp = round(raw_timestamp * float(interface["timestamp_resolution"]), 9)
            packet = body[packet_offset : packet_offset + min(captured_length, max_message_bytes + 512)]
            record = _decode_link_packet(
                packet, int(interface["linktype"]), timestamp, packet_count, warnings
            )
            if record is not None:
                record["captured_packet_size"] = int(captured_length)
                record["original_packet_size"] = int(original_length)
                records.append(record)
        elif block_type == 3:
            if packet_count >= max_packets:
                limit_hit = True
                _warn(warnings, f"packet import truncated at max_packets={max_packets}")
                break
            if len(body) < 4 or not interfaces:
                _warn(warnings, "invalid PCAPNG simple packet block")
            else:
                original_length = struct.unpack_from(f"{endian}I", body, 0)[0]
                captured_length = min(original_length, len(body) - 4)
                packet_count += 1
                packet = body[4 : 4 + min(captured_length, max_message_bytes + 512)]
                record = _decode_link_packet(
                    packet, int(interfaces[0]["linktype"]), None, packet_count, warnings
                )
                if record is not None:
                    record["captured_packet_size"] = int(captured_length)
                    record["original_packet_size"] = int(original_length)
                    records.append(record)
        offset += block_length
    if not interfaces and not records:
        _warn(warnings, "PCAPNG contained no usable interfaces or packets")
    return {
        "records": records,
        "packet_count": packet_count,
        "link_types": sorted(link_types),
        "limit_hit": limit_hit,
    }


def _decode_link_packet(
    packet: bytes,
    linktype: int,
    timestamp: float | None,
    packet_index: int,
    warnings: list[str],
) -> dict[str, Any] | None:
    ip_packet = packet
    if linktype == 1:  # Ethernet
        if len(packet) < 14:
            _warn(warnings, "truncated Ethernet frame")
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(packet) < offset + 4:
                _warn(warnings, "truncated VLAN header")
                return None
            ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4
        if ethertype not in {0x0800, 0x86DD}:
            return None
        ip_packet = packet[offset:]
    elif linktype == 113:  # Linux cooked v1
        if len(packet) < 16:
            _warn(warnings, "truncated Linux cooked frame")
            return None
        protocol = struct.unpack_from("!H", packet, 14)[0]
        if protocol not in {0x0800, 0x86DD}:
            return None
        ip_packet = packet[16:]
    elif linktype == 276:  # Linux cooked v2
        if len(packet) < 20:
            _warn(warnings, "truncated Linux cooked v2 frame")
            return None
        protocol = struct.unpack_from("!H", packet, 0)[0]
        if protocol not in {0x0800, 0x86DD}:
            return None
        ip_packet = packet[20:]
    elif linktype == 0:  # BSD loopback/null
        if len(packet) < 4:
            return None
        family_le = struct.unpack_from("<I", packet, 0)[0]
        family_be = struct.unpack_from(">I", packet, 0)[0]
        if family_le not in {2, 24, 28, 30} and family_be not in {2, 24, 28, 30}:
            return None
        ip_packet = packet[4:]
    elif linktype in {101, 228, 229}:  # Raw IP, explicit IPv4, explicit IPv6
        ip_packet = packet
    else:
        _warn(warnings, f"unsupported PCAP link type {linktype}")
        return None
    return _decode_ip_packet(ip_packet, timestamp, packet_index, warnings)


def _decode_ip_packet(
    packet: bytes,
    timestamp: float | None,
    packet_index: int,
    warnings: list[str],
) -> dict[str, Any] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            _warn(warnings, "truncated IPv4 header")
            return None
        header_length = (packet[0] & 0x0F) * 4
        if header_length < 20 or header_length > len(packet):
            _warn(warnings, "invalid IPv4 header length")
            return None
        total_length = struct.unpack_from("!H", packet, 2)[0]
        end = min(len(packet), total_length if total_length >= header_length else len(packet))
        fragment = struct.unpack_from("!H", packet, 6)[0]
        if fragment & 0x1FFF:
            _warn(warnings, "non-initial IPv4 fragment skipped")
            return None
        protocol = packet[9]
        src = str(ipaddress.ip_address(packet[12:16]))
        dst = str(ipaddress.ip_address(packet[16:20]))
        transport = packet[header_length:end]
    elif version == 6:
        if len(packet) < 40:
            _warn(warnings, "truncated IPv6 header")
            return None
        payload_length = struct.unpack_from("!H", packet, 4)[0]
        protocol = packet[6]
        src = str(ipaddress.ip_address(packet[8:24]))
        dst = str(ipaddress.ip_address(packet[24:40]))
        end = min(len(packet), 40 + payload_length)
        cursor = 40
        extension_count = 0
        while protocol in {0, 43, 44, 51, 60} and extension_count < 8:
            if protocol == 44:
                if cursor + 8 > end:
                    return None
                fragment = struct.unpack_from("!H", packet, cursor + 2)[0]
                if fragment & 0xFFF8:
                    _warn(warnings, "non-initial IPv6 fragment skipped")
                    return None
                protocol = packet[cursor]
                cursor += 8
            elif protocol == 51:
                if cursor + 2 > end:
                    return None
                next_protocol = packet[cursor]
                length = (packet[cursor + 1] + 2) * 4
                if length < 8 or cursor + length > end:
                    return None
                protocol = next_protocol
                cursor += length
            else:
                if cursor + 2 > end:
                    return None
                next_protocol = packet[cursor]
                length = (packet[cursor + 1] + 1) * 8
                if cursor + length > end:
                    return None
                protocol = next_protocol
                cursor += length
            extension_count += 1
        transport = packet[cursor:end]
    else:
        return None

    if protocol == 6:
        if len(transport) < 20:
            return None
        src_port, dst_port, sequence = struct.unpack_from("!HHI", transport, 0)
        header_length = (transport[12] >> 4) * 4
        if header_length < 20 or header_length > len(transport):
            return None
        return {
            "transport": "tcp",
            "src": src,
            "dst": dst,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "sequence": int(sequence),
            "flags": int(transport[13]),
            "timestamp": timestamp,
            "packet_index": packet_index,
            "payload": transport[header_length:],
        }
    if protocol == 17:
        if len(transport) < 8:
            return None
        src_port, dst_port, udp_length = struct.unpack_from("!HHH", transport, 0)
        end = min(len(transport), udp_length if udp_length >= 8 else len(transport))
        return {
            "transport": "udp",
            "src": src,
            "dst": dst,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "sequence": None,
            "timestamp": timestamp,
            "packet_index": packet_index,
            "payload": transport[8:end],
        }
    return None


def _capture_structured(
    value: Any,
    *,
    max_packets: int,
    max_messages: int,
    max_message_bytes: int,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    flow_hints: list[Any] = []
    mode = "auto"
    records: Any = value
    if isinstance(value, Mapping):
        if isinstance(value.get("flows"), list):
            flow_hints = value.get("flows") or []
        if "messages" in value:
            records = value.get("messages") or []
            mode = "messages"
        elif "packets" in value:
            records = value.get("packets") or []
            mode = "packets"
        elif "records" in value:
            records = value.get("records") or []
            mode = "auto"
        else:
            records = [value]
    if isinstance(records, (str, bytes, bytearray, memoryview)) or not isinstance(records, Iterable):
        records = [records]

    bounded_records: list[Any] = []
    record_limit = max(max_packets, max_messages)
    limit_hit = False
    for item in records:
        if len(bounded_records) >= record_limit:
            limit_hit = True
            _warn(warnings, f"structured import truncated at {record_limit} records")
            break
        bounded_records.append(item)

    packet_like = mode == "packets" or (
        mode == "auto" and any(isinstance(item, Mapping) and _is_packet_record(item) for item in bounded_records)
    )
    if packet_like:
        packets: list[dict[str, Any]] = []
        for index, item in enumerate(bounded_records, start=1):
            if len(packets) >= max_packets:
                limit_hit = True
                _warn(warnings, f"packet import truncated at max_packets={max_packets}")
                break
            if not isinstance(item, Mapping):
                _warn(warnings, f"structured packet record {index} is not an object")
                continue
            packet = _packet_from_mapping(item, index, max_message_bytes, warnings)
            if packet is not None:
                packets.append(packet)
        flows, messages, stats = _normalize_packets(packets, max_messages, max_message_bytes, warnings)
        stats["packet_count"] = len(packets)
        stats["limit_hit"] = bool(stats["limit_hit"] or limit_hit)
        return flows, messages, stats

    flows, messages, stats = _normalize_imported_messages(
        bounded_records, flow_hints, max_messages, max_message_bytes, warnings
    )
    stats["packet_count"] = len(bounded_records)
    stats["limit_hit"] = bool(stats["limit_hit"] or limit_hit)
    return flows, messages, stats


def _parse_jsonl(
    data: bytes,
    max_packets: int,
    max_messages: int,
    warnings: list[str],
) -> tuple[list[Any], bool]:
    records: list[Any] = []
    limit = max(max_packets, max_messages)
    limit_hit = False
    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line.strip():
            continue
        if len(records) >= limit:
            limit_hit = True
            _warn(warnings, f"JSONL import truncated at {limit} records")
            break
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _warn(warnings, f"invalid JSONL record at line {line_number}: {exc}")
            continue
        if isinstance(value, list):
            for item in value:
                if len(records) >= limit:
                    limit_hit = True
                    break
                records.append(item)
        else:
            records.append(value)
    return records, limit_hit


def _is_packet_record(record: Mapping[str, Any]) -> bool:
    transport = record.get("transport") or record.get("protocol") or record.get("proto")
    has_endpoints = any(
        key in record
        for key in ("src", "source", "src_ip", "source_ip", "dst", "destination", "dst_ip", "destination_ip")
    )
    return has_endpoints and str(transport or "").lower() in {"tcp", "udp", "6", "17"}


def _packet_from_mapping(
    record: Mapping[str, Any],
    packet_index: int,
    max_message_bytes: int,
    warnings: list[str],
) -> dict[str, Any] | None:
    transport_value = record.get("transport") or record.get("protocol") or record.get("proto") or ""
    transport_text = str(transport_value).lower()
    transport = "tcp" if transport_text in {"tcp", "6"} else "udp" if transport_text in {"udp", "17"} else ""
    if not transport:
        return None
    src, src_port = _record_endpoint(record, "src")
    dst, dst_port = _record_endpoint(record, "dst")
    if not src or not dst:
        _warn(warnings, f"packet record {packet_index} is missing source/destination")
        return None
    payload, original_size, truncated = _record_payload(record, max_message_bytes)
    sequence = _safe_int(record.get("sequence", record.get("seq")))
    timestamp = _safe_float(record.get("timestamp", record.get("time", record.get("ts"))))
    return {
        "transport": transport,
        "src": src,
        "dst": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "sequence": sequence,
        "timestamp": timestamp,
        "packet_index": packet_index,
        "payload": payload,
        "payload_size": original_size,
        "payload_truncated": truncated,
    }


def _record_endpoint(record: Mapping[str, Any], side: str) -> tuple[str, int | None]:
    if side == "src":
        keys = ("src", "source", "src_ip", "source_ip", "source_address")
        port_keys = ("src_port", "source_port", "sport")
    else:
        keys = ("dst", "destination", "dst_ip", "destination_ip", "destination_address")
        port_keys = ("dst_port", "destination_port", "dport")
    value: Any = None
    for key in keys:
        if key in record:
            value = record.get(key)
            break
    port: int | None = None
    if isinstance(value, Mapping):
        port = _safe_port(value.get("port"))
        value = value.get("ip") or value.get("address") or value.get("host") or value.get("name")
    for key in port_keys:
        if key in record:
            port = _safe_port(record.get(key))
            break
    return str(value or "").strip(), port


def _normalize_protocol_context(record: Mapping[str, Any]) -> dict[str, Any]:
    transport_value = (
        record.get("transport")
        or record.get("layer4")
        or record.get("network_protocol")
        or ""
    )
    protocol_value = (
        record.get("application_protocol")
        or record.get("app_protocol")
        or record.get("scheme")
        or record.get("protocol")
        or record.get("proto")
        or ""
    )
    transport_token = _protocol_token(transport_value)
    protocol_token = _protocol_token(protocol_value)
    application_protocol = _APPLICATION_PROTOCOL_ALIASES.get(protocol_token)
    if application_protocol is None:
        application_protocol = _APPLICATION_PROTOCOL_ALIASES.get(transport_token)

    transport = _TRANSPORT_ALIASES.get(transport_token)
    if transport is None:
        transport = _TRANSPORT_ALIASES.get(protocol_token)
    if transport is None and application_protocol:
        transport = "tcp"
    if transport is None:
        transport = "raw"

    endpoint_value = record.get("url") or record.get("uri") or record.get("endpoint")
    endpoint = str(endpoint_value).strip() if isinstance(endpoint_value, (str, os.PathLike)) else ""
    pipe_path = str(record.get("pipe") or record.get("pipe_name") or "").strip()
    if not pipe_path and endpoint and _looks_like_pipe(endpoint):
        pipe_path = endpoint
    if pipe_path:
        transport = "named_pipe"
        endpoint = pipe_path

    parsed_url = _parse_url(endpoint)
    if parsed_url["application_protocol"]:
        application_protocol = parsed_url["application_protocol"]
        if transport == "raw":
            transport = "tcp"

    existing_http = record.get("http")
    existing_websocket = record.get("websocket") or record.get("ws")
    if isinstance(existing_http, Mapping) and not application_protocol:
        application_protocol = "http"
        if transport == "raw":
            transport = "tcp"
    if isinstance(existing_websocket, Mapping):
        application_protocol = "websocket"
        if transport == "raw":
            transport = "tcp"

    src, _ = _record_endpoint(record, "src")
    dst, _ = _record_endpoint(record, "dst")
    host = str(parsed_url["host"] or dst or "").strip()
    explicit_scope = str(record.get("scope") or "").strip().lower().replace("-", "_")
    if transport == "named_pipe":
        scope = "local"
    elif transport == "loopback" or any(_is_loopback_host(item) for item in (host, src, dst)):
        scope = "loopback"
    elif explicit_scope in {"loopback", "local", "remote", "network"}:
        scope = explicit_scope
    else:
        scope = "unknown"

    secure = bool(parsed_url["secure"] or protocol_token in {"https", "wss"})
    return {
        "transport": transport,
        "application_protocol": application_protocol,
        "scope": scope,
        "secure": secure,
        "endpoint": endpoint or pipe_path or None,
        "host": host or None,
        "port": parsed_url["port"],
    }


def _protocol_token(value: Any) -> str:
    token = str(value or "").strip().lower().replace("_", "-").replace(" ", "-")
    if token.startswith("http/") and token not in _APPLICATION_PROTOCOL_ALIASES:
        return "http"
    return token


def _parse_url(value: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "application_protocol": None,
        "host": None,
        "port": None,
        "secure": False,
    }
    if not value or "://" not in value:
        return result
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return result
    scheme = parsed.scheme.lower()
    result.update(
        {
            "application_protocol": _APPLICATION_PROTOCOL_ALIASES.get(scheme),
            "host": parsed.hostname,
            "port": port,
            "secure": scheme in {"https", "wss"},
        }
    )
    return result


def _looks_like_pipe(value: str) -> bool:
    lower = value.lower()
    return bool(
        _PIPE_RE.search(value)
        or lower.startswith("pipe://")
        or "\\pipe\\" in lower
        or "\\namedpipe\\" in lower
    )


def _is_loopback_host(value: Any) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        text = text.rsplit(":", 1)[0]
    if text == "localhost" or text.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False


def _endpoint_scope(*endpoints: tuple[str, int | None]) -> str:
    return "loopback" if any(_is_loopback_host(endpoint[0]) for endpoint in endpoints) else "network"


def _normalize_direction(value: Any) -> str:
    direction = str(value or "unknown").strip().lower().replace("-", "_")
    aliases = {
        "a2b": "a_to_b",
        "client_to_server": "a_to_b",
        "outbound": "a_to_b",
        "send": "a_to_b",
        "request": "a_to_b",
        "b2a": "b_to_a",
        "server_to_client": "b_to_a",
        "inbound": "b_to_a",
        "receive": "b_to_a",
        "recv": "b_to_a",
        "response": "b_to_a",
    }
    normalized = aliases.get(direction, direction)
    return normalized if normalized in {"a_to_b", "b_to_a"} else "unknown"


def _structured_message_semantics(
    record: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    message_type = _normalize_message_type(
        record.get("message_type") or record.get("role") or record.get("type")
    )
    existing_http = record.get("http") if isinstance(record.get("http"), Mapping) else {}
    method = record.get("method") or existing_http.get("method")
    status_code = _safe_int(
        record.get("status_code", record.get("status", existing_http.get("status_code")))
    )
    if method:
        message_type = "request"
    elif status_code is not None:
        message_type = "response"

    headers_value = record.get("headers") or existing_http.get("headers")
    headers = _normalize_headers(headers_value)
    request_id = _first_identifier(
        record.get("request_id"),
        existing_http.get("request_id"),
        headers.get("x-request-id"),
    )
    response_to = _first_identifier(record.get("response_to"), record.get("in_reply_to"))
    correlation_id = _first_identifier(
        record.get("correlation_id"),
        existing_http.get("correlation_id"),
        headers.get("x-correlation-id"),
        headers.get("traceparent"),
        request_id,
    )
    application_protocol = context.get("application_protocol")
    if application_protocol:
        result["application_protocol"] = application_protocol
    if message_type:
        result["message_type"] = message_type
    if request_id:
        result["request_id"] = request_id
    if response_to:
        result["response_to"] = response_to
    if correlation_id:
        result["correlation_id"] = correlation_id

    if application_protocol == "http" or method or status_code is not None or existing_http:
        http: dict[str, Any] = {
            "method": str(method).upper()[:32] if method else None,
            "target": str(
                record.get("target")
                or record.get("path")
                or existing_http.get("target")
                or ""
            )[:2048]
            or None,
            "url": str(record.get("url") or existing_http.get("url") or "")[:4096] or None,
            "status_code": status_code,
            "version": str(record.get("http_version") or existing_http.get("version") or "")[:32]
            or None,
            "headers": headers,
        }
        result["http"] = http
    existing_websocket = record.get("websocket") or record.get("ws")
    if isinstance(existing_websocket, Mapping):
        bounded_websocket, _ = _bounded_json_value(existing_websocket, 4096)
        result["websocket"] = bounded_websocket
    return result


def _normalize_message_type(value: Any) -> str | None:
    token = str(value or "").strip().lower().replace("-", "_")
    if token in {"request", "req", "query", "command", "call"}:
        return "request"
    if token in {"response", "resp", "reply", "result", "answer"}:
        return "response"
    if token in {"event", "notification", "message", "push", "control"}:
        return "event"
    return None


def _normalize_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for index, (key, item) in enumerate(value.items()):
        if index >= 128:
            break
        result[str(key).strip().lower()[:256]] = str(item)[:4096]
    return result


def _first_identifier(*values: Any) -> str | None:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()[:512]
    return None


def _record_payload(record: Mapping[str, Any], max_message_bytes: int) -> tuple[bytes, int, bool]:
    encoding = str(record.get("encoding") or record.get("payload_encoding") or "").lower()
    field = ""
    value: Any = None
    for candidate in (
        "payload_hex",
        "data_hex",
        "payload_base64",
        "data_base64",
        "payload",
        "data",
        "body",
        "raw",
        "bytes",
        "text",
    ):
        if candidate in record:
            field = candidate
            value = record.get(candidate)
            break
    if isinstance(value, Mapping):
        nested = value
        nested_record = {
            "encoding": nested.get("encoding") or encoding,
            "payload_hex": nested.get("hex"),
            "payload_base64": nested.get("base64"),
            "payload": nested.get("data") if nested.get("data") is not None else nested.get("text"),
        }
        nested_record = {key: item for key, item in nested_record.items() if item is not None}
        if nested_record:
            return _record_payload(nested_record, max_message_bytes)
    if value is None:
        return b"", 0, False
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        bounded, truncated = _bounded_bytes(raw, max_message_bytes)
        return bounded, len(raw), truncated
    if isinstance(value, str):
        if field.endswith("_hex") or encoding == "hex":
            compact = re.sub(r"\s+", "", value)
            original_size = len(compact) // 2
            compact = compact[: max_message_bytes * 2]
            try:
                decoded = bytes.fromhex(compact)
            except ValueError:
                decoded = b""
            return decoded, original_size, original_size > len(decoded)
        if field.endswith("_base64") or encoding in {"base64", "b64"}:
            compact = value.strip()[: ((max_message_bytes + 2) // 3) * 4 + 4]
            try:
                decoded = base64.b64decode(compact, validate=True)
            except (ValueError, binascii.Error):
                decoded = b""
            bounded, truncated = _bounded_bytes(decoded, max_message_bytes)
            estimated_size = max(len(bounded), (len(value.strip().rstrip("=")) * 3) // 4)
            return bounded, estimated_size, truncated or len(compact) < len(value.strip())
        prefix = value[: max_message_bytes + 1].encode("utf-8", errors="replace")
        bounded, truncated = _bounded_bytes(prefix, max_message_bytes)
        return bounded, max(len(value), len(prefix)), truncated or len(value) > max_message_bytes
    if isinstance(value, list) and all(isinstance(item, int) for item in value[: max_message_bytes + 1]):
        original_size = len(value)
        raw = bytes(int(item) & 0xFF for item in value[:max_message_bytes])
        return raw, original_size, original_size > len(raw)
    bounded_value, value_truncated = _bounded_json_value(value, max_message_bytes)
    encoded = json.dumps(bounded_value, ensure_ascii=False, separators=(",", ":"), default=repr).encode(
        "utf-8", errors="replace"
    )
    bounded, truncated = _bounded_bytes(encoded, max_message_bytes)
    return bounded, len(encoded), truncated or value_truncated


def _bounded_json_value(value: Any, budget: int, depth: int = 0) -> tuple[Any, bool]:
    if depth >= 8:
        return repr(value)[:256], True
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if isinstance(value, str):
        limit = max(32, min(len(value), budget))
        return value[:limit], len(value) > limit
    if isinstance(value, (bytes, bytearray, memoryview)):
        limit = max(16, budget // 2)
        raw = bytes(value)[:limit]
        return {"encoding": "hex", "data": raw.hex()}, len(value) > len(raw)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        truncated = False
        item_limit = max(1, min(256, budget // 16))
        for index, (key, item) in enumerate(value.items()):
            if index >= item_limit:
                truncated = True
                break
            child, child_truncated = _bounded_json_value(item, max(16, budget // item_limit), depth + 1)
            result[str(key)[:256]] = child
            truncated = truncated or child_truncated
        return result, truncated
    if isinstance(value, Iterable):
        result_list: list[Any] = []
        truncated = False
        item_limit = max(1, min(256, budget // 8))
        for index, item in enumerate(value):
            if index >= item_limit:
                truncated = True
                break
            child, child_truncated = _bounded_json_value(item, max(16, budget // item_limit), depth + 1)
            result_list.append(child)
            truncated = truncated or child_truncated
        return result_list, truncated
    return repr(value)[: min(512, budget)], True


def _normalize_packets(
    records: Iterable[Mapping[str, Any]],
    max_messages: int,
    max_message_bytes: int,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for record in records:
        payload = record.get("payload")
        if not isinstance(payload, (bytes, bytearray, memoryview)) or not payload:
            continue
        transport = str(record.get("transport") or "unknown").lower()
        src = (str(record.get("src") or ""), _safe_port(record.get("src_port")))
        dst = (str(record.get("dst") or ""), _safe_port(record.get("dst_port")))
        endpoint_a, endpoint_b = sorted((src, dst), key=_endpoint_sort_key)
        direction = "a_to_b" if src == endpoint_a else "b_to_a"
        key = (transport, endpoint_a, endpoint_b)
        flow = grouped.setdefault(
            key,
            {
                "transport": transport,
                "endpoint_a": endpoint_a,
                "endpoint_b": endpoint_b,
                "segments": {"a_to_b": [], "b_to_a": []},
                "packet_count": 0,
                "payload_bytes": 0,
            },
        )
        segment = dict(record)
        segment["payload"] = bytes(payload)
        segment["direction"] = direction
        flow["segments"][direction].append(segment)
        flow["packet_count"] += 1
        flow["payload_bytes"] += int(record.get("payload_size") or len(payload))

    flow_rows: list[dict[str, Any]] = []
    pending_messages: list[dict[str, Any]] = []
    limit_hit = False
    for key in sorted(grouped, key=lambda item: (str(item[0]), _endpoint_sort_key(item[1]), _endpoint_sort_key(item[2]))):
        grouped_flow = grouped[key]
        transport = grouped_flow["transport"]
        endpoint_a = grouped_flow["endpoint_a"]
        endpoint_b = grouped_flow["endpoint_b"]
        flow_id = _flow_id(transport, endpoint_a, endpoint_b)
        scope = _endpoint_scope(endpoint_a, endpoint_b)
        flow_row = {
            "id": flow_id,
            "flow_id": flow_id,
            "kind": "network_flow",
            "transport": transport,
            "application_protocol": None,
            "scope": scope,
            "endpoint_a": _endpoint_dict(endpoint_a),
            "endpoint_b": _endpoint_dict(endpoint_b),
            "packet_count": grouped_flow["packet_count"],
            "payload_bytes": grouped_flow["payload_bytes"],
            "message_ids": [],
            "directions": {},
        }
        flow_rows.append(flow_row)
        for direction in ("a_to_b", "b_to_a"):
            segments = grouped_flow["segments"][direction]
            if not segments:
                continue
            if transport == "tcp":
                reassembled = _reassemble_tcp(segments, max_message_bytes)
                if reassembled["truncated"]:
                    limit_hit = True
                pending_messages.append(
                    {
                        "flow_id": flow_id,
                        "transport": transport,
                        "application_protocol": None,
                        "scope": scope,
                        "direction": direction,
                        "kind": "tcp_stream",
                        "payload": reassembled["payload"],
                        "payload_size": reassembled["payload_size"],
                        "payload_truncated": reassembled["truncated"],
                        "timestamp_start": reassembled["timestamp_start"],
                        "timestamp_end": reassembled["timestamp_end"],
                        "sequence_start": reassembled["sequence_start"],
                        "packet_index": reassembled["packet_index"],
                        "metadata": {
                            "segment_count": len(segments),
                            "reassembly_gap_count": reassembled["gap_count"],
                            "overlap_bytes": reassembled["overlap_bytes"],
                        },
                    }
                )
                flow_row["directions"][direction] = {
                    "packet_count": len(segments),
                    "payload_bytes": reassembled["payload_size"],
                    "reassembly_gap_count": reassembled["gap_count"],
                }
            else:
                ordered = sorted(segments, key=lambda item: int(item.get("packet_index") or 0))
                flow_row["directions"][direction] = {
                    "packet_count": len(ordered),
                    "payload_bytes": sum(int(item.get("payload_size") or len(item["payload"])) for item in ordered),
                }
                for segment in ordered:
                    payload, truncated = _bounded_bytes(bytes(segment["payload"]), max_message_bytes)
                    pending_messages.append(
                        {
                            "flow_id": flow_id,
                            "transport": transport,
                            "application_protocol": None,
                            "scope": scope,
                            "direction": direction,
                            "kind": "udp_datagram" if transport == "udp" else "transport_message",
                            "payload": payload,
                            "payload_size": int(segment.get("payload_size") or len(segment["payload"])),
                            "payload_truncated": bool(segment.get("payload_truncated") or truncated),
                            "timestamp_start": segment.get("timestamp"),
                            "timestamp_end": segment.get("timestamp"),
                            "sequence_start": segment.get("sequence"),
                            "packet_index": int(segment.get("packet_index") or 0),
                            "metadata": {"segment_count": 1},
                        }
                    )

    pending_messages.sort(
        key=lambda item: (
            math.inf if item.get("timestamp_start") is None else float(item["timestamp_start"]),
            int(item.get("packet_index") or 0),
            str(item["flow_id"]),
            str(item["direction"]),
        )
    )
    if len(pending_messages) > max_messages:
        pending_messages = pending_messages[:max_messages]
        limit_hit = True
        _warn(warnings, f"message import truncated at max_messages={max_messages}")
    flow_lookup = {str(item["flow_id"]): item for item in flow_rows}
    messages: list[dict[str, Any]] = []
    for index, pending in enumerate(pending_messages, start=1):
        message_id = f"message-{index:06d}"
        payload = bytes(pending.pop("payload"))
        payload_size = int(pending.pop("payload_size"))
        truncated = bool(pending.pop("payload_truncated"))
        item = {
            "id": message_id,
            **pending,
            **_payload_fields(payload, payload_size, truncated),
        }
        messages.append(item)
        flow_lookup[str(item["flow_id"])]["message_ids"].append(message_id)
    return flow_rows, messages, {"packet_count": sum(item["packet_count"] for item in flow_rows), "limit_hit": limit_hit}


def _normalize_imported_messages(
    records: Iterable[Any],
    flow_hints: Iterable[Any],
    max_messages: int,
    max_message_bytes: int,
    warnings: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    hints = {
        str(item.get("flow_id") or item.get("id")): dict(item)
        for item in flow_hints
        if isinstance(item, Mapping) and (item.get("flow_id") or item.get("id"))
    }
    flows: dict[str, dict[str, Any]] = {}
    messages: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    limit_hit = False
    for record_index, record in enumerate(records, start=1):
        if len(messages) >= max_messages:
            limit_hit = True
            _warn(warnings, f"message import truncated at max_messages={max_messages}")
            break
        mapping = record if isinstance(record, Mapping) else {"payload": record}
        context = _normalize_protocol_context(mapping)
        payload, payload_size, truncated = _record_payload(mapping, max_message_bytes)
        if truncated:
            limit_hit = True
        transport = str(context["transport"])
        src, src_port = _record_endpoint(mapping, "src")
        dst, dst_port = _record_endpoint(mapping, "dst")
        if not dst and context.get("host"):
            dst = str(context["host"])
            dst_port = _safe_port(context.get("port"))
        explicit_flow_id = str(mapping.get("flow_id") or "").strip()
        direction = _normalize_direction(mapping.get("direction"))
        endpoint_a: tuple[str, int | None] | None = None
        endpoint_b: tuple[str, int | None] | None = None
        if src and dst:
            source_endpoint = (src, src_port)
            destination_endpoint = (dst, dst_port)
            endpoint_a, endpoint_b = sorted((source_endpoint, destination_endpoint), key=_endpoint_sort_key)
            if direction == "unknown":
                direction = "a_to_b" if source_endpoint == endpoint_a else "b_to_a"
        if explicit_flow_id:
            flow_id = explicit_flow_id[:512]
        elif endpoint_a is not None and endpoint_b is not None:
            flow_id = _flow_id(transport, endpoint_a, endpoint_b)
        elif context.get("endpoint"):
            flow_id = f"{transport}:{str(context['endpoint'])[:448]}"
        else:
            flow_id = f"{transport}:imported"
        flow = flows.get(flow_id)
        if flow is None:
            hint = hints.get(flow_id, {})
            hint_context = _normalize_protocol_context(hint)
            application_protocol = context.get("application_protocol") or hint_context.get(
                "application_protocol"
            )
            scope = context.get("scope") or hint_context.get("scope")
            if scope == "unknown" and endpoint_a is not None and endpoint_b is not None:
                scope = _endpoint_scope(endpoint_a, endpoint_b)
            if not scope:
                scope = "unknown"
            flow_kind = "ipc_flow" if transport == "named_pipe" else "network_flow"
            if transport == "raw":
                flow_kind = "raw_flow"
            flow = {
                "id": flow_id,
                "flow_id": flow_id,
                "kind": str(hint.get("kind") or flow_kind),
                "transport": transport,
                "application_protocol": application_protocol,
                "application_protocols": [application_protocol] if application_protocol else [],
                "scope": scope,
                "endpoint_a": _endpoint_dict(endpoint_a) if endpoint_a else hint.get("endpoint_a"),
                "endpoint_b": _endpoint_dict(endpoint_b) if endpoint_b else hint.get("endpoint_b"),
                "endpoint": context.get("endpoint") or hint.get("endpoint"),
                "packet_count": 0,
                "payload_bytes": 0,
                "message_ids": [],
                "directions": {},
            }
            flows[flow_id] = flow
        elif context.get("application_protocol"):
            protocols = flow.setdefault("application_protocols", [])
            if context["application_protocol"] not in protocols:
                protocols.append(context["application_protocol"])
            if not flow.get("application_protocol"):
                flow["application_protocol"] = context["application_protocol"]
        if flow.get("scope") in {None, "", "unknown"} and context.get("scope") not in {
            None,
            "",
            "unknown",
        }:
            flow["scope"] = context["scope"]
        proposed_id = str(mapping.get("id") or mapping.get("message_id") or f"message-{record_index:06d}")[:512]
        message_id = proposed_id
        duplicate_index = 2
        while message_id in seen_ids:
            message_id = f"{proposed_id}-{duplicate_index}"
            duplicate_index += 1
        seen_ids.add(message_id)
        timestamp_start = mapping.get("timestamp_start", mapping.get("timestamp", mapping.get("time")))
        timestamp_end = mapping.get("timestamp_end", timestamp_start)
        metadata = mapping.get("metadata") if isinstance(mapping.get("metadata"), Mapping) else {}
        semantic = _structured_message_semantics(mapping, context)
        combined_metadata = dict(metadata)
        for key in ("url", "method", "status_code", "request_id", "response_to", "correlation_id"):
            if semantic.get(key) is not None:
                combined_metadata.setdefault(key, semantic[key])
        bounded_metadata, _ = _bounded_json_value(combined_metadata, 8192)
        message = {
            "id": message_id,
            "flow_id": flow_id,
            "transport": transport,
            "application_protocol": context.get("application_protocol"),
            "scope": flow.get("scope") or context.get("scope") or "unknown",
            "direction": direction,
            "kind": str(
                mapping.get("kind")
                or (
                    "udp_datagram"
                    if transport == "udp"
                    else "pipe_message"
                    if transport == "named_pipe"
                    else "imported_message"
                )
            ),
            "timestamp_start": _safe_float(timestamp_start),
            "timestamp_end": _safe_float(timestamp_end),
            "sequence_start": _safe_int(mapping.get("sequence_start", mapping.get("sequence", mapping.get("seq")))),
            "metadata": bounded_metadata,
            **_payload_fields(payload, payload_size, truncated),
            **semantic,
        }
        messages.append(message)
        flow["packet_count"] += 1
        flow["payload_bytes"] += payload_size
        flow["message_ids"].append(message_id)
        direction_stats = flow["directions"].setdefault(direction, {"packet_count": 0, "payload_bytes": 0})
        direction_stats["packet_count"] += 1
        direction_stats["payload_bytes"] += payload_size
    flow_rows = sorted(flows.values(), key=lambda item: str(item["flow_id"]))
    return flow_rows, messages, {"packet_count": len(messages), "limit_hit": limit_hit}


def _reassemble_tcp(segments: list[Mapping[str, Any]], max_message_bytes: int) -> dict[str, Any]:
    with_sequences = all(_safe_int(item.get("sequence")) is not None for item in segments)
    ordered = sorted(
        segments,
        key=lambda item: (
            _safe_int(item.get("sequence")) if with_sequences else int(item.get("packet_index") or 0),
            int(item.get("packet_index") or 0),
        ),
    )
    output = bytearray()
    payload_size = 0
    expected_sequence: int | None = None
    gap_count = 0
    overlap_bytes = 0
    truncated = False
    for segment in ordered:
        payload = bytes(segment.get("payload") or b"")
        original_size = int(segment.get("payload_size") or len(payload))
        if segment.get("payload_truncated"):
            truncated = True
        if with_sequences:
            sequence = int(segment["sequence"])
            if expected_sequence is None:
                expected_sequence = sequence
            if sequence > expected_sequence:
                gap_count += 1
            elif sequence < expected_sequence:
                overlap = min(len(payload), expected_sequence - sequence)
                overlap_bytes += overlap
                payload = payload[overlap:]
                original_size = max(0, original_size - overlap)
                sequence += overlap
            expected_sequence = max(expected_sequence, sequence + original_size)
        payload_size += original_size
        remaining = max_message_bytes - len(output)
        if remaining > 0:
            output.extend(payload[:remaining])
        if len(payload) > remaining:
            truncated = True
    timestamps = [float(item["timestamp"]) for item in ordered if item.get("timestamp") is not None]
    sequences = [_safe_int(item.get("sequence")) for item in ordered]
    sequence_values = [item for item in sequences if item is not None]
    return {
        "payload": bytes(output),
        "payload_size": payload_size,
        "truncated": truncated or payload_size > len(output),
        "timestamp_start": min(timestamps) if timestamps else None,
        "timestamp_end": max(timestamps) if timestamps else None,
        "sequence_start": min(sequence_values) if sequence_values else None,
        "packet_index": min(int(item.get("packet_index") or 0) for item in ordered),
        "gap_count": gap_count,
        "overlap_bytes": overlap_bytes,
    }


def _endpoint_sort_key(endpoint: tuple[str, int | None]) -> tuple[str, int]:
    return endpoint[0], -1 if endpoint[1] is None else endpoint[1]


def _endpoint_dict(endpoint: tuple[str, int | None] | None) -> dict[str, Any] | None:
    if endpoint is None:
        return None
    return {"address": endpoint[0], "port": endpoint[1]}


def _endpoint_label(endpoint: tuple[str, int | None]) -> str:
    address, port = endpoint
    address_text = f"[{address}]" if ":" in address else address
    return f"{address_text}:{port}" if port is not None else address_text


def _flow_id(
    transport: str,
    endpoint_a: tuple[str, int | None],
    endpoint_b: tuple[str, int | None],
) -> str:
    return f"{transport}:{_endpoint_label(endpoint_a)}<>{_endpoint_label(endpoint_b)}"


def _payload_fields(payload: bytes, payload_size: int, truncated: bool) -> dict[str, Any]:
    text = _payload_text(payload)
    payload_object: dict[str, Any] = {
        "encoding": "hex",
        "hex": payload.hex(),
        "size": int(payload_size),
        "captured_size": len(payload),
        "truncated": bool(truncated),
    }
    if text is not None:
        payload_object["text"] = text
    return {
        "payload": payload_object,
        "payload_hex": payload.hex(),
        "payload_text": text,
        "payload_size": int(payload_size),
        "captured_size": len(payload),
        "payload_truncated": bool(truncated),
    }


def _message_payload(message: Mapping[str, Any], max_message_bytes: int) -> bytes:
    payload, _, _ = _record_payload(message, max_message_bytes)
    return payload


def _payload_text(payload: bytes) -> str | None:
    if not payload:
        return ""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(character.isprintable() or character in "\r\n\t" for character in text)
    if printable / max(1, len(text)) < 0.85:
        return None
    return text[:_MAX_TEXT_PREVIEW]


def _annotate_captured_messages(messages: Iterable[dict[str, Any]]) -> None:
    for message in messages:
        payload = _message_payload(message, _HARD_MAX_MESSAGE_BYTES)
        application = _analyze_application_message(payload, message, {})
        application.pop("_analysis_payload", None)
        message.update(application)


def _apply_message_protocols_to_flows(
    flows: Iterable[dict[str, Any]],
    messages: Iterable[Mapping[str, Any]],
) -> None:
    """Propagate message-level application protocol evidence to its flow."""

    flow_index = {
        str(flow.get("flow_id") or flow.get("id") or ""): flow
        for flow in flows
        if flow.get("flow_id") or flow.get("id")
    }
    for message in messages:
        flow = flow_index.get(str(message.get("flow_id") or ""))
        protocol = str(message.get("application_protocol") or "").strip().lower()
        if flow is None or not protocol:
            continue
        protocols = flow.setdefault("application_protocols", [])
        if not isinstance(protocols, list):
            protocols = list(protocols) if isinstance(protocols, Iterable) else []
            flow["application_protocols"] = protocols
        if protocol not in protocols:
            protocols.append(protocol)
        if not flow.get("application_protocol"):
            flow["application_protocol"] = protocol
    for flow in flow_index.values():
        protocols = flow.get("application_protocols")
        if isinstance(protocols, list):
            flow["application_protocols"] = sorted(
                {str(item).strip().lower() for item in protocols if str(item).strip()}
            )


def _correlate_request_responses(
    messages: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Pair bounded request/response observations without guessing across flows."""

    ordered = list(messages)
    requests = [item for item in ordered if item.get("message_type") == "request"]
    responses = [item for item in ordered if item.get("message_type") == "response"]
    request_by_token: dict[str, dict[str, Any]] = {}
    for request in requests:
        for value in (
            request.get("id"),
            request.get("request_id"),
            request.get("correlation_id"),
        ):
            token = str(value or "").strip()
            if token:
                request_by_token.setdefault(token, request)

    used_requests: set[str] = set()
    pairs: list[dict[str, Any]] = []
    for response in responses:
        request: dict[str, Any] | None = None
        reason = ""
        confidence = 0.0
        for value, candidate_reason, candidate_confidence in (
            (response.get("response_to"), "explicit_response_to", 1.0),
            (response.get("request_id"), "request_id", 0.98),
            (response.get("correlation_id"), "correlation_id", 0.95),
        ):
            token = str(value or "").strip()
            candidate = request_by_token.get(token) if token else None
            candidate_id = str((candidate or {}).get("id") or "")
            if candidate is not None and candidate_id not in used_requests:
                request = candidate
                reason = candidate_reason
                confidence = candidate_confidence
                break

        if request is None:
            response_index = ordered.index(response)
            response_flow = str(response.get("flow_id") or "")
            response_direction = str(response.get("direction") or "unknown")
            for candidate in reversed(ordered[:response_index]):
                candidate_id = str(candidate.get("id") or "")
                if (
                    candidate.get("message_type") == "request"
                    and candidate_id not in used_requests
                    and str(candidate.get("flow_id") or "") == response_flow
                    and (
                        response_direction == "unknown"
                        or str(candidate.get("direction") or "unknown") == "unknown"
                        or str(candidate.get("direction")) != response_direction
                    )
                ):
                    request = candidate
                    reason = "flow_order"
                    confidence = 0.75
                    break

        if request is None:
            continue
        request_id = str(request.get("id") or "")
        response_id = str(response.get("id") or "")
        if not request_id or not response_id:
            continue
        exchange_id = f"exchange:{_digest(request_id + '|' + response_id)}"
        request["paired_message_id"] = response_id
        response["paired_message_id"] = request_id
        request["exchange_id"] = exchange_id
        response["exchange_id"] = exchange_id
        used_requests.add(request_id)
        pairs.append(
            {
                "id": exchange_id,
                "exchange_id": exchange_id,
                "flow_id": request.get("flow_id") or response.get("flow_id"),
                "request_message_id": request_id,
                "response_message_id": response_id,
                "confidence": confidence,
                "reason": reason,
            }
        )
    return pairs


def _build_field_statistics(messages: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate bounded structural field observations across messages."""

    aggregates: dict[str, dict[str, Any]] = {}
    messages_with_fields = 0

    def observe(path: str, value: Any, message_id: str, source: str) -> None:
        if not path or len(aggregates) >= 4096 and path not in aggregates:
            return
        value_type = (
            "null"
            if value is None
            else "bool"
            if isinstance(value, bool)
            else "integer"
            if isinstance(value, int)
            else "number"
            if isinstance(value, float)
            else "bytes"
            if isinstance(value, (bytes, bytearray, memoryview))
            else "array"
            if isinstance(value, list)
            else "object"
            if isinstance(value, Mapping)
            else "string"
        )
        if isinstance(value, (str, bytes, bytearray, memoryview, list, tuple, Mapping)):
            length = len(value)
        else:
            length = None
        item = aggregates.setdefault(
            path,
            {
                "path": path,
                "sources": set(),
                "message_ids": set(),
                "type_counts": Counter(),
                "lengths": [],
                "sample_values": [],
                "occurrence_count": 0,
            },
        )
        item["sources"].add(source)
        item["message_ids"].add(message_id)
        item["type_counts"][value_type] += 1
        item["occurrence_count"] += 1
        if length is not None:
            item["lengths"].append(int(length))
        if len(item["sample_values"]) < 4 and not isinstance(value, (Mapping, list, tuple)):
            sample = value.hex()[:128] if isinstance(value, (bytes, bytearray, memoryview)) else value
            if sample not in item["sample_values"]:
                item["sample_values"].append(sample)

    def walk(value: Any, prefix: str, message_id: str, source: str, depth: int = 0) -> None:
        if depth > 5:
            return
        if isinstance(value, Mapping):
            for index, key in enumerate(sorted(value, key=lambda item: str(item))):
                if index >= 256:
                    break
                path = f"{prefix}.{key}" if prefix else str(key)
                child = value[key]
                observe(path, child, message_id, source)
                walk(child, path, message_id, source, depth + 1)
        elif isinstance(value, list):
            for child in value[:64]:
                path = f"{prefix}[]"
                observe(path, child, message_id, source)
                walk(child, path, message_id, source, depth + 1)

    for message in messages:
        message_id = str(message.get("id") or "")
        before = len(aggregates)
        for decoded in message.get("decoded") or []:
            if isinstance(decoded, Mapping) and "value" in decoded:
                source = str(decoded.get("format") or "decoded")
                walk(decoded.get("value"), source, message_id, source)
        http = message.get("http")
        if isinstance(http, Mapping):
            walk(http, "http", message_id, "http")
        protobuf = message.get("protobuf")
        if isinstance(protobuf, Mapping):
            for field in protobuf.get("fields") or []:
                if not isinstance(field, Mapping):
                    continue
                number = field.get("field_number", field.get("number"))
                observe(f"protobuf.field_{number}", field, message_id, "protobuf")
        if len(aggregates) > before:
            messages_with_fields += 1

    fields: list[dict[str, Any]] = []
    for path in sorted(aggregates):
        item = aggregates[path]
        lengths = item["lengths"]
        field = {
            "path": path,
            "sources": sorted(item["sources"]),
            "message_count": len(item["message_ids"]),
            "occurrence_count": int(item["occurrence_count"]),
            "type_counts": dict(sorted(item["type_counts"].items())),
            "sample_values": item["sample_values"],
        }
        if lengths:
            field["length"] = {
                "minimum": min(lengths),
                "maximum": max(lengths),
                "average": round(sum(lengths) / len(lengths), 3),
            }
        fields.append(field)
    return {
        "field_count": len(fields),
        "messages_with_fields": messages_with_fields,
        "fields": fields,
    }


def _analyze_application_message(
    payload: bytes,
    source_message: Mapping[str, Any],
    framing: Mapping[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in (
        "application_protocol",
        "scope",
        "message_type",
        "request_id",
        "response_to",
        "correlation_id",
    ):
        value = source_message.get(key)
        if value is not None and value != "":
            result[key] = value
    if isinstance(source_message.get("http"), Mapping):
        result["http"] = dict(source_message["http"])
    if isinstance(source_message.get("websocket"), Mapping):
        result["websocket"] = dict(source_message["websocket"])

    http = _parse_http_message(payload)
    if http is not None:
        parsed_http = dict(http.pop("http"))
        existing_http = result.get("http") if isinstance(result.get("http"), Mapping) else {}
        merged_http = dict(existing_http)
        for key, value in parsed_http.items():
            if value is not None and value != "" and value != {}:
                merged_http[key] = value
        result["http"] = merged_http
        result.update(http)
        return result

    websocket_hint = result.get("application_protocol") == "websocket" or framing.get("type") == "websocket_frame"
    websocket = _parse_websocket_frame(payload) if websocket_hint or _strong_websocket_prefix(payload) else None
    if websocket is not None:
        result["application_protocol"] = "websocket"
        result.setdefault("message_type", "event")
        result["websocket"] = {key: value for key, value in websocket.items() if key != "payload"}
        result["_analysis_payload"] = websocket["payload"]
    else:
        result["_analysis_payload"] = payload
    return result


def _parse_http_message(payload: bytes) -> dict[str, Any] | None:
    separator = b"\r\n\r\n"
    header_end = payload.find(separator)
    if header_end < 0:
        separator = b"\n\n"
        header_end = payload.find(separator)
    if header_end < 0:
        return None
    header_bytes = payload[:header_end]
    line_end = header_bytes.find(b"\n")
    start_line = (header_bytes if line_end < 0 else header_bytes[:line_end]).rstrip(b"\r")
    request_match = _HTTP_REQUEST_LINE_RE.fullmatch(start_line.strip())
    response_match = _HTTP_RESPONSE_LINE_RE.fullmatch(start_line.strip())
    if request_match is None and response_match is None:
        return None

    headers = _parse_http_headers(header_bytes)
    body = payload[header_end + len(separator) :]
    if "chunked" in headers.get("transfer-encoding", "").lower():
        decoded_chunked = _decode_chunked_body(body, _HARD_MAX_MESSAGE_BYTES)
        if decoded_chunked is not None:
            body = decoded_chunked
    application_protocol = (
        "websocket"
        if headers.get("upgrade", "").lower() == "websocket"
        or any(key.startswith("sec-websocket-") for key in headers)
        else "http"
    )
    http: dict[str, Any] = {
        "method": None,
        "target": None,
        "status_code": None,
        "reason": None,
        "version": None,
        "headers": headers,
        "content_type": headers.get("content-type"),
        "content_encoding": headers.get("content-encoding"),
        "body_size": len(body),
    }
    if request_match is not None:
        http.update(
            {
                "method": request_match.group("method").decode("ascii").upper(),
                "target": request_match.group("target").decode("latin-1", errors="replace")[:2048],
                "version": request_match.group("version").decode("ascii"),
            }
        )
        message_type = "request"
    else:
        assert response_match is not None
        reason = response_match.group("reason") or b""
        http.update(
            {
                "status_code": int(response_match.group("status")),
                "reason": reason.decode("latin-1", errors="replace")[:512] or None,
                "version": response_match.group("version").decode("ascii"),
            }
        )
        message_type = "response"
    request_id = _first_identifier(headers.get("x-request-id"))
    correlation_id = _first_identifier(
        headers.get("x-correlation-id"),
        headers.get("traceparent"),
        request_id,
    )
    result: dict[str, Any] = {
        "application_protocol": application_protocol,
        "message_type": message_type,
        "http": http,
        "_analysis_payload": body,
    }
    if request_id:
        result["request_id"] = request_id
    if correlation_id:
        result["correlation_id"] = correlation_id
    return result


def _parse_http_headers(header_bytes: bytes) -> dict[str, str]:
    try:
        lines = header_bytes.decode("latin-1").replace("\r\n", "\n").split("\n")
    except UnicodeDecodeError:
        return {}
    headers: dict[str, str] = {}
    for line in lines[1:129]:
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()[:256]
        normalized_value = value.strip()[:4096]
        if normalized_key in headers:
            headers[normalized_key] = f"{headers[normalized_key]}, {normalized_value}"[:4096]
        else:
            headers[normalized_key] = normalized_value
    return headers


def _decode_chunked_body(payload: bytes, max_output: int) -> bytes | None:
    output = bytearray()
    cursor = 0
    while cursor < len(payload):
        line_end = payload.find(b"\r\n", cursor)
        delimiter_size = 2
        if line_end < 0:
            line_end = payload.find(b"\n", cursor)
            delimiter_size = 1
        if line_end < 0:
            return None
        try:
            size = int(payload[cursor:line_end].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return None
        cursor = line_end + delimiter_size
        if size == 0:
            return bytes(output)
        if cursor + size > len(payload):
            return None
        remaining = max_output - len(output)
        if remaining > 0:
            output.extend(payload[cursor : cursor + min(size, remaining)])
        cursor += size
        if payload[cursor : cursor + 2] == b"\r\n":
            cursor += 2
        elif payload[cursor : cursor + 1] == b"\n":
            cursor += 1
        else:
            return None
    return None


def _strong_websocket_prefix(payload: bytes) -> bool:
    return len(payload) >= 2 and payload[0] in {0x81, 0x82, 0x88, 0x89, 0x8A}


def _parse_websocket_frame(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 2 or payload[0] & 0x70:
        return None
    opcode = payload[0] & 0x0F
    if opcode not in {0, 1, 2, 8, 9, 10}:
        return None
    masked = bool(payload[1] & 0x80)
    length = payload[1] & 0x7F
    cursor = 2
    if length == 126:
        if len(payload) < cursor + 2:
            return None
        length = int.from_bytes(payload[cursor : cursor + 2], "big")
        cursor += 2
    elif length == 127:
        if len(payload) < cursor + 8:
            return None
        length = int.from_bytes(payload[cursor : cursor + 8], "big")
        cursor += 8
    mask = b""
    if masked:
        if len(payload) < cursor + 4:
            return None
        mask = payload[cursor : cursor + 4]
        cursor += 4
    if length > _HARD_MAX_MESSAGE_BYTES or cursor + length != len(payload):
        return None
    body = payload[cursor : cursor + length]
    if masked:
        body = bytes(byte ^ mask[index % 4] for index, byte in enumerate(body))
    opcode_names = {
        0: "continuation",
        1: "text",
        2: "binary",
        8: "close",
        9: "ping",
        10: "pong",
    }
    return {
        "fin": bool(payload[0] & 0x80),
        "opcode": opcode,
        "opcode_name": opcode_names[opcode],
        "masked": masked,
        "payload_size": len(body),
        "payload": body,
    }


def _split_websocket_frames(payload: bytes, max_frames: int) -> dict[str, Any] | None:
    frames: list[bytes] = []
    cursor = 0
    while cursor < len(payload) and len(frames) < max_frames:
        if len(payload) - cursor < 2 or payload[cursor] & 0x70:
            return None
        length = payload[cursor + 1] & 0x7F
        header_size = 2
        if length == 126:
            if len(payload) - cursor < 4:
                return None
            length = int.from_bytes(payload[cursor + 2 : cursor + 4], "big")
            header_size = 4
        elif length == 127:
            if len(payload) - cursor < 10:
                return None
            length = int.from_bytes(payload[cursor + 2 : cursor + 10], "big")
            header_size = 10
        if payload[cursor + 1] & 0x80:
            header_size += 4
        end = cursor + header_size + length
        if end > len(payload):
            return None
        frame = payload[cursor:end]
        if _parse_websocket_frame(frame) is None:
            return None
        frames.append(frame)
        cursor = end
    if not frames or cursor != len(payload) or not _strong_websocket_prefix(frames[0]):
        return None
    return {
        "frames": frames,
        "candidate": {
            "type": "websocket_frame",
            "frame_count": len(frames),
            "confidence": 0.98,
        },
        "limit_hit": cursor < len(payload),
    }


def _frame_message(payload: bytes, max_frames: int) -> dict[str, Any]:
    if not payload:
        return {"frames": [b""], "candidate": None, "limit_hit": False}
    http_candidate = _split_http_messages(payload, max_frames)
    if http_candidate is not None:
        return http_candidate
    websocket_candidate = _split_websocket_frames(payload, max_frames)
    if websocket_candidate is not None:
        return websocket_candidate
    length_candidate = _split_length_prefixed(payload, max_frames)
    if length_candidate is not None:
        return length_candidate
    delimiter_candidate = _split_delimited(payload, max_frames)
    if delimiter_candidate is not None:
        return delimiter_candidate
    magic_candidate = _split_magic(payload, max_frames)
    if magic_candidate is not None:
        return magic_candidate
    known = _detect_magic(payload)
    candidate = (
        {
            "type": "magic",
            "name": known["name"],
            "magic_hex": known["magic_hex"],
            "confidence": known["confidence"],
            "frame_count": 1,
        }
        if known
        else None
    )
    return {"frames": [payload], "candidate": candidate, "limit_hit": False}


def _split_http_messages(payload: bytes, max_frames: int) -> dict[str, Any] | None:
    first_line_end = payload.find(b"\n")
    if first_line_end < 0 or not _http_start_line(payload[:first_line_end].rstrip(b"\r")):
        return None

    frames: list[bytes] = []
    cursor = 0
    incomplete = False
    while cursor < len(payload):
        line_end = payload.find(b"\n", cursor)
        if line_end < 0 or not _http_start_line(payload[cursor:line_end].rstrip(b"\r")):
            incomplete = True
            if frames:
                frames[-1] += payload[cursor:]
            else:
                frames.append(payload[cursor:])
            break
        separator = b"\r\n\r\n"
        header_end = payload.find(separator, cursor)
        if header_end < 0:
            separator = b"\n\n"
            header_end = payload.find(separator, cursor)
        if header_end < 0:
            incomplete = True
            frames.append(payload[cursor:])
            break

        body_start = header_end + len(separator)
        header_bytes = payload[cursor:header_end]
        headers = _parse_http_headers(header_bytes)
        content_length = _safe_int(headers.get("content-length"))
        if content_length is not None and content_length >= 0:
            message_end = min(len(payload), body_start + content_length)
            incomplete = incomplete or message_end < body_start + content_length
        elif "chunked" in str(headers.get("transfer-encoding") or "").lower():
            chunked_end = _chunked_http_end(payload, body_start)
            message_end = chunked_end if chunked_end is not None else len(payload)
            incomplete = incomplete or chunked_end is None
        else:
            next_start = _find_next_http_start(payload, body_start)
            start_line = payload[cursor:line_end].rstrip(b"\r")
            is_request = _HTTP_REQUEST_LINE_RE.fullmatch(start_line) is not None
            if next_start is not None:
                message_end = next_start
            elif is_request:
                message_end = body_start
            else:
                message_end = len(payload)
        frames.append(payload[cursor:message_end])
        cursor = message_end
        if len(frames) >= max_frames:
            return {
                "frames": frames,
                "candidate": {
                    "type": "http_message",
                    "frame_count": len(frames),
                    "confidence": 0.99,
                },
                "limit_hit": cursor < len(payload),
            }
    return {
        "frames": frames or [payload],
        "candidate": {
            "type": "http_message",
            "frame_count": len(frames) or 1,
            "confidence": 0.99 if not incomplete else 0.82,
            "incomplete": incomplete,
        },
        "limit_hit": False,
    }


def _http_start_line(line: bytes) -> bool:
    return bool(
        _HTTP_REQUEST_LINE_RE.fullmatch(line.strip())
        or _HTTP_RESPONSE_LINE_RE.fullmatch(line.strip())
    )


def _find_next_http_start(payload: bytes, start: int) -> int | None:
    candidates: list[int] = []
    markers = (b"HTTP/", b"GET ", b"HEAD ", b"POST ", b"PUT ", b"DELETE ", b"CONNECT ", b"OPTIONS ", b"TRACE ", b"PATCH ")
    for marker in markers:
        cursor = start
        while cursor < len(payload):
            position = payload.find(marker, cursor)
            if position < 0:
                break
            if position == start or payload[max(0, position - 2) : position] in {b"\n", b"\r\n"}:
                line_end = payload.find(b"\n", position)
                if line_end >= 0 and _http_start_line(payload[position:line_end].rstrip(b"\r")):
                    candidates.append(position)
                    break
            cursor = position + 1
    return min(candidates) if candidates else None


def _chunked_http_end(payload: bytes, start: int) -> int | None:
    cursor = start
    while cursor < len(payload):
        line_end = payload.find(b"\r\n", cursor)
        delimiter_size = 2
        if line_end < 0:
            line_end = payload.find(b"\n", cursor)
            delimiter_size = 1
        if line_end < 0:
            return None
        size_text = payload[cursor:line_end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return None
        cursor = line_end + delimiter_size
        if size == 0:
            trailer_end = payload.find(b"\r\n\r\n", cursor)
            if trailer_end >= 0:
                return trailer_end + 4
            line_end = payload.find(b"\r\n", cursor)
            return line_end + 2 if line_end >= 0 else cursor
        if cursor + size > len(payload):
            return None
        cursor += size
        if payload[cursor : cursor + 2] == b"\r\n":
            cursor += 2
        elif payload[cursor : cursor + 1] == b"\n":
            cursor += 1
        else:
            return None
    return None


def _split_length_prefixed(payload: bytes, max_frames: int) -> dict[str, Any] | None:
    candidates: list[dict[str, Any]] = []
    for width in (4, 2, 1):
        for endian in ("big", "little") if width > 1 else ("big",):
            cursor = 0
            frames: list[bytes] = []
            valid = True
            limit_hit = False
            while cursor < len(payload):
                if cursor + width > len(payload):
                    valid = False
                    break
                declared = int.from_bytes(payload[cursor : cursor + width], endian)
                cursor += width
                if declared <= 0 or declared > len(payload) - cursor:
                    valid = False
                    break
                if len(frames) >= max_frames:
                    limit_hit = True
                    break
                frames.append(payload[cursor : cursor + declared])
                cursor += declared
            if valid and frames and (cursor == len(payload) or limit_hit):
                confidence = 0.98 if len(frames) > 1 else (0.88 if width >= 2 else 0.7)
                candidates.append(
                    {
                        "frames": frames,
                        "candidate": {
                            "type": "length_prefix",
                            "byte_width": width,
                            "endianness": endian,
                            "frame_count": len(frames),
                            "confidence": confidence,
                        },
                        "limit_hit": limit_hit,
                    }
                )
    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            -len(item["frames"]),
            -float(item["candidate"]["confidence"]),
            -int(item["candidate"]["byte_width"]),
            str(item["candidate"]["endianness"]),
        )
    )
    return candidates[0]


def _split_delimited(payload: bytes, max_frames: int) -> dict[str, Any] | None:
    delimiters = (
        (b"\r\n\r\n", "CRLF-CRLF"),
        (b"\r\n", "CRLF"),
        (b"\n", "LF"),
        (b"\x00", "NUL"),
        (b"|", "pipe"),
    )
    for delimiter, name in delimiters:
        if payload.count(delimiter) < 2 and not (payload.endswith(delimiter) and payload.count(delimiter) >= 1):
            continue
        parts = [part for part in payload.split(delimiter) if part]
        if len(parts) < 2:
            continue
        limit_hit = len(parts) > max_frames
        frames = parts[:max_frames]
        confidence = min(0.97, 0.72 + 0.06 * len(frames))
        return {
            "frames": frames,
            "candidate": {
                "type": "delimiter",
                "name": name,
                "delimiter_hex": delimiter.hex(),
                "frame_count": len(frames),
                "confidence": round(confidence, 3),
            },
            "limit_hit": limit_hit,
        }
    return None


def _split_magic(payload: bytes, max_frames: int) -> dict[str, Any] | None:
    for width in (4, 3, 2):
        if len(payload) < width * 2:
            continue
        magic = payload[:width]
        if all(32 <= byte <= 126 for byte in magic) and magic.isalnum():
            continue
        positions: list[int] = []
        cursor = 0
        while cursor < len(payload):
            position = payload.find(magic, cursor)
            if position < 0:
                break
            positions.append(position)
            cursor = position + width
        if len(positions) < 2 or positions[0] != 0:
            continue
        frames = [
            payload[position : positions[index + 1] if index + 1 < len(positions) else len(payload)]
            for index, position in enumerate(positions)
        ]
        limit_hit = len(frames) > max_frames
        frames = frames[:max_frames]
        return {
            "frames": frames,
            "candidate": {
                "type": "magic",
                "name": "repeating-prefix",
                "magic_hex": magic.hex(),
                "frame_count": len(frames),
                "confidence": min(0.96, round(0.76 + 0.05 * len(frames), 3)),
            },
            "limit_hit": limit_hit,
        }
    return None


def _detect_magic(payload: bytes) -> dict[str, Any] | None:
    for magic, name in _KNOWN_MAGICS:
        if payload.startswith(magic):
            return {"name": name, "magic_hex": magic.hex(), "confidence": 0.98}
    if _is_zlib(payload):
        return {"name": "zlib", "magic_hex": payload[:2].hex(), "confidence": 0.95}
    if len(payload) >= 5 and payload[0] in {0x14, 0x15, 0x16, 0x17} and payload[1] == 0x03:
        return {"name": "tls-record", "magic_hex": payload[:3].hex(), "confidence": 0.9}
    return None


def _analyze_formats(payload: bytes, max_output: int) -> dict[str, Any]:
    formats: list[dict[str, Any]] = []
    decoded: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen_formats: set[tuple[str, int]] = set()
    seen_payloads: set[str] = set()
    msgpack_dependency: str | None = None

    def add_format(name: str, confidence: float, layer: int, evidence: str, parent: str | None = None) -> None:
        key = (name, layer)
        if key in seen_formats:
            return
        seen_formats.add(key)
        item: dict[str, Any] = {
            "name": name,
            "confidence": round(confidence, 3),
            "layer": layer,
            "evidence": evidence,
        }
        if parent:
            item["parent"] = parent
        formats.append(item)

    def inspect(current: bytes, layer: int, parent: str | None) -> None:
        nonlocal msgpack_dependency
        if layer > 3 or not current:
            return
        digest = hashlib.sha256(current).hexdigest()
        if digest in seen_payloads:
            return
        seen_payloads.add(digest)
        stripped = current.strip()
        text: str | None
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text and text[:1] in {"{", "[", '"'}:
            try:
                value = json.loads(text)
            except json.JSONDecodeError:
                pass
            else:
                add_format("json", 1.0, layer, "valid UTF-8 JSON", parent)
                bounded_value, truncated = _bounded_json_value(value, max_output)
                decoded.append(
                    {
                        "format": "json",
                        "layer": layer,
                        "value": bounded_value,
                        "truncated": truncated,
                    }
                )

        if current.startswith(b"\x1f\x8b\x08"):
            unpacked, truncated, error = _bounded_decompress(current, max_output, 16 + zlib.MAX_WBITS)
            if error is None:
                add_format("gzip", 0.99, layer, "valid gzip stream", parent)
                decoded.append(_decoded_bytes("gzip", layer, unpacked, truncated))
                if truncated:
                    warnings.append(f"gzip output truncated at max_message_bytes={max_output}")
                inspect(unpacked, layer + 1, "gzip")
            else:
                warnings.append(f"gzip stream could not be decoded: {error}")
        elif _is_zlib(current):
            unpacked, truncated, error = _bounded_decompress(current, max_output, zlib.MAX_WBITS)
            if error is None:
                add_format("zlib", 0.97, layer, "valid zlib stream", parent)
                decoded.append(_decoded_bytes("zlib", layer, unpacked, truncated))
                if truncated:
                    warnings.append(f"zlib output truncated at max_message_bytes={max_output}")
                inspect(unpacked, layer + 1, "zlib")
            else:
                warnings.append(f"zlib stream could not be decoded: {error}")

        base64_value = _try_base64(current)
        if base64_value is not None:
            add_format("base64", 0.92, layer, "strict base64 alphabet and padding", parent)
            unpacked, truncated = _bounded_bytes(base64_value, max_output)
            decoded.append(_decoded_bytes("base64", layer, unpacked, truncated))
            if truncated:
                warnings.append(f"base64 output truncated at max_message_bytes={max_output}")
            inspect(unpacked, layer + 1, "base64")

        msgpack_result = _try_msgpack(current, max_output)
        if msgpack_result["candidate"]:
            msgpack_dependency = str(msgpack_result["dependency"])
            add_format(
                "msgpack",
                float(msgpack_result["confidence"]),
                layer,
                str(msgpack_result["evidence"]),
                parent,
            )
            if "value" in msgpack_result:
                decoded.append(
                    {
                        "format": "msgpack",
                        "layer": layer,
                        "value": msgpack_result["value"],
                        "truncated": bool(msgpack_result.get("truncated")),
                    }
                )
            if msgpack_result.get("warning"):
                warnings.append(str(msgpack_result["warning"]))

    inspect(payload, 0, None)
    formats.sort(key=lambda item: (int(item["layer"]), str(item["name"])))
    return {
        "formats": formats,
        "decoded": decoded,
        "warnings": warnings,
        "msgpack_dependency": msgpack_dependency,
    }


def _is_zlib(payload: bytes) -> bool:
    return len(payload) >= 2 and payload[0] & 0x0F == 8 and ((payload[0] << 8) | payload[1]) % 31 == 0


def _bounded_decompress(payload: bytes, max_output: int, window_bits: int) -> tuple[bytes, bool, str | None]:
    try:
        decoder = zlib.decompressobj(window_bits)
        output = decoder.decompress(payload, max_output + 1)
        truncated = len(output) > max_output or bool(decoder.unconsumed_tail)
        output = output[:max_output]
        if not truncated and decoder.eof:
            remaining = max_output - len(output)
            if remaining > 0:
                tail = decoder.flush(remaining + 1)
                if len(tail) > remaining:
                    truncated = True
                output += tail[:remaining]
        elif not decoder.eof:
            truncated = True
        return output, truncated, None
    except zlib.error as exc:
        return b"", False, str(exc)


def _try_base64(payload: bytes) -> bytes | None:
    stripped = b"".join(payload.split())
    if len(stripped) < 8 or len(stripped) % 4 or _BASE64_RE.fullmatch(stripped) is None:
        return None
    if b"=" not in stripped and len(stripped) < 16:
        return None
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded:
        return None
    if b"=" not in stripped and _payload_text(decoded) is None and _detect_magic(decoded) is None:
        return None
    return decoded


def _try_msgpack(payload: bytes, budget: int) -> dict[str, Any]:
    if not _looks_like_msgpack(payload):
        return {"candidate": False, "dependency": "not-needed"}
    try:
        import msgpack  # type: ignore[import-not-found]
    except (ImportError, ModuleNotFoundError):
        return {
            "candidate": True,
            "dependency": "unavailable",
            "confidence": 0.68,
            "evidence": "MessagePack container marker",
            "warning": "msgpack dependency unavailable; shape recognized without decoding",
        }
    try:
        value = msgpack.unpackb(payload, raw=False, strict_map_key=False)
    except Exception:
        return {"candidate": False, "dependency": "available"}
    bounded, truncated = _bounded_json_value(value, budget)
    return {
        "candidate": True,
        "dependency": "available",
        "confidence": 0.99,
        "evidence": "successfully decoded MessagePack value",
        "value": bounded,
        "truncated": truncated,
    }


def _looks_like_msgpack(payload: bytes) -> bool:
    if not payload:
        return False
    marker = payload[0]
    return (
        0x80 <= marker <= 0x8F
        or 0x90 <= marker <= 0x9F
        or 0xA0 <= marker <= 0xBF
        or marker in {0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}
    )


def _decoded_bytes(name: str, layer: int, payload: bytes, truncated: bool) -> dict[str, Any]:
    return {
        "format": name,
        "layer": layer,
        "size": len(payload),
        "preview_hex": payload[:128].hex(),
        "preview_text": _payload_text(payload[:_MAX_TEXT_PREVIEW]),
        "truncated": truncated,
    }


def _infer_protobuf_shape(payload: bytes, depth: int = 0) -> dict[str, Any] | None:
    if not payload or len(payload) > _HARD_MAX_MESSAGE_BYTES:
        return None
    cursor = 0
    observations: list[dict[str, Any]] = []
    while cursor < len(payload):
        key_result = _read_varint(payload, cursor)
        if key_result is None:
            return None
        key, cursor = key_result
        field_number = key >> 3
        wire_type = key & 0x07
        if field_number <= 0 or field_number > 536_870_911 or wire_type not in {0, 1, 2, 5}:
            return None
        observation: dict[str, Any] = {"field_number": field_number, "wire_type": wire_type}
        if wire_type == 0:
            value_result = _read_varint(payload, cursor)
            if value_result is None:
                return None
            value, cursor = value_result
            observation["value"] = value
        elif wire_type == 1:
            if cursor + 8 > len(payload):
                return None
            observation["value_hex"] = payload[cursor : cursor + 8].hex()
            cursor += 8
        elif wire_type == 2:
            length_result = _read_varint(payload, cursor)
            if length_result is None:
                return None
            length, cursor = length_result
            if length > len(payload) - cursor:
                return None
            value = payload[cursor : cursor + length]
            cursor += length
            observation["length"] = length
            text = _payload_text(value)
            if text is not None and text:
                observation["value_shape"] = "utf8"
                observation["sample_text"] = text[:128]
            elif depth < 1:
                nested = _infer_protobuf_shape(value, depth + 1)
                if nested is not None:
                    observation["value_shape"] = "embedded_message"
                    observation["nested_signature"] = nested["signature"]
                else:
                    observation["value_shape"] = "bytes"
            else:
                observation["value_shape"] = "bytes"
            observation["sample_hex"] = value[:32].hex()
        else:
            if cursor + 4 > len(payload):
                return None
            observation["value_hex"] = payload[cursor : cursor + 4].hex()
            cursor += 4
        observations.append(observation)
        if len(observations) > 4096:
            return None
    if not observations:
        return None

    wire_names = {0: "varint", 1: "fixed64", 2: "length_delimited", 5: "fixed32"}
    grouped: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for item in observations:
        grouped[(int(item["field_number"]), int(item["wire_type"]))].append(item)
    fields: list[dict[str, Any]] = []
    wire_type_counts: Counter[str] = Counter()
    for (field_number, wire_type), values in sorted(grouped.items()):
        wire_name = wire_names[wire_type]
        wire_type_counts[str(wire_type)] += len(values)
        field: dict[str, Any] = {
            "number": field_number,
            "field_number": field_number,
            "wire_type": wire_type,
            "wire_name": wire_name,
            "occurrences": len(values),
        }
        shapes = sorted({str(item.get("value_shape")) for item in values if item.get("value_shape")})
        if shapes:
            field["value_shapes"] = shapes
        samples = [item.get("value") for item in values if "value" in item][:4]
        if samples:
            field["sample_values"] = samples
        sample_texts = [str(item["sample_text"]) for item in values if item.get("sample_text")][:4]
        if sample_texts:
            field["sample_texts"] = sample_texts
        nested = sorted({str(item["nested_signature"]) for item in values if item.get("nested_signature")})
        if nested:
            field["nested_signatures"] = nested
        fields.append(field)
    signature = ",".join(f"{item['number']}:{item['wire_name']}" for item in fields)
    confidence = min(0.98, 0.67 + 0.04 * len(observations) + 0.03 * len(fields))
    return {
        "status": "inferred",
        "confidence": round(confidence, 3),
        "field_count": len(fields),
        "occurrence_count": len(observations),
        "fields": fields,
        "wire_type_counts": dict(sorted(wire_type_counts.items())),
        "signature": signature,
    }


def _read_varint(payload: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for index in range(10):
        position = offset + index
        if position >= len(payload):
            return None
        byte = payload[position]
        if index == 9 and byte > 1:
            return None
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, position + 1
    return None


def _entropy_summary(payload: bytes) -> dict[str, Any]:
    if not payload:
        return {"value": 0.0, "classification": "empty", "sample_size": 0}
    counts = Counter(payload)
    total = len(payload)
    value = -sum((count / total) * math.log2(count / total) for count in counts.values())
    text = _payload_text(payload)
    if text is not None and value < 6.5:
        classification = "textual"
    elif value >= 7.5:
        classification = "high"
    elif value >= 5.0:
        classification = "medium"
    else:
        classification = "low"
    return {"value": round(value, 4), "classification": classification, "sample_size": total}


def _summarize_framing(observations: list[dict[str, Any]], entropy_values: list[float]) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for observation in observations:
        key_payload = {key: value for key, value in observation.items() if key not in {"source_message_id", "frame_count"}}
        key = json.dumps(key_payload, sort_keys=True, separators=(",", ":"), default=repr)
        item = grouped.setdefault(key, {**key_payload, "message_count": 0, "frame_count": 0})
        item["message_count"] += 1
        item["frame_count"] += int(observation.get("frame_count") or 1)
    candidates = sorted(
        grouped.values(),
        key=lambda item: (-int(item["message_count"]), -float(item.get("confidence") or 0.0), str(item["type"])),
    )
    mean_entropy = sum(entropy_values) / len(entropy_values) if entropy_values else 0.0
    maximum_entropy = max(entropy_values) if entropy_values else 0.0
    entropy_class = (
        "high"
        if mean_entropy >= 7.5
        else "medium"
        if mean_entropy >= 4.5 or maximum_entropy >= 7.5
        else "low"
    )
    entropy_candidate = {
        "type": "entropy",
        "mean": round(mean_entropy, 4),
        "minimum": round(min(entropy_values), 4) if entropy_values else 0.0,
        "maximum": round(maximum_entropy, 4),
        "classification": entropy_class if entropy_values else "empty",
        "message_count": len(entropy_values),
    }
    return {
        "primary": candidates[0] if candidates else None,
        "candidates": [*candidates, entropy_candidate],
        "entropy": entropy_candidate,
    }


def _infer_capture_protocols(
    flows: list[dict[str, Any]], messages: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}

    def add(name: str, confidence: float, item: str) -> None:
        protocol = evidence.setdefault(name, {"name": name, "confidence": 0.0, "evidence": []})
        protocol["confidence"] = max(float(protocol["confidence"]), confidence)
        if item not in protocol["evidence"] and len(protocol["evidence"]) < 12:
            protocol["evidence"].append(item)

    transport_counts = Counter(str(flow.get("transport") or "unknown") for flow in flows)
    for transport in ("tcp", "udp"):
        if transport_counts[transport]:
            add(transport, 0.99, f"{transport_counts[transport]} normalized {transport.upper()} flow(s)")
    for flow in flows:
        ports = {
            _safe_port((flow.get("endpoint_a") or {}).get("port")) if isinstance(flow.get("endpoint_a"), Mapping) else None,
            _safe_port((flow.get("endpoint_b") or {}).get("port")) if isinstance(flow.get("endpoint_b"), Mapping) else None,
        }
        if 53 in ports:
            add("dns", 0.85, f"DNS port in {flow.get('flow_id') or flow.get('id')}")
        if 80 in ports or 8080 in ports:
            add("http", 0.75, f"HTTP-associated port in {flow.get('flow_id') or flow.get('id')}")
        if 443 in ports:
            add("tls", 0.75, f"TLS-associated port in {flow.get('flow_id') or flow.get('id')}")
    for message in messages:
        payload = _message_payload(message, _HARD_MAX_MESSAGE_BYTES)
        upper = payload[:32].upper()
        if upper.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"PATCH ", b"HEAD ", b"OPTIONS ", b"HTTP/")):
            add("http", 0.98, f"HTTP start line in {message.get('id')}")
        text = _payload_text(payload[:4096]) or ""
        if "upgrade: websocket" in text.lower() or "sec-websocket-" in text.lower():
            add("websocket", 0.97, f"WebSocket headers in {message.get('id')}")
        if len(payload) >= 5 and payload[0] in {0x14, 0x15, 0x16, 0x17} and payload[1] == 0x03:
            add("tls", 0.95, f"TLS record header in {message.get('id')}")
    return sorted(evidence.values(), key=lambda item: (-float(item["confidence"]), str(item["name"])))


def _build_semantic_ir_fragment(
    flows: Iterable[Mapping[str, Any]],
    messages: Iterable[Mapping[str, Any]],
    protocols: Iterable[Mapping[str, Any]],
    formats: Iterable[str],
    protobuf_shapes: Iterable[Mapping[str, Any]],
    request_response_pairs: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    flows = list(flows)
    messages = list(messages)
    protocols = list(protocols)
    formats = list(formats)
    protobuf_shapes = list(protobuf_shapes)
    request_response_pairs = list(request_response_pairs)
    entities: list[dict[str, Any]] = []
    relations: list[dict[str, Any]] = []
    flow_entity_ids: dict[str, str] = {}
    message_shape_ids: dict[str, str] = {}
    message_entity_ids: dict[str, str] = {}

    for flow in flows:
        flow_id = str(flow.get("flow_id") or flow.get("id") or flow.get("endpoint") or "")
        if not flow_id:
            continue
        entity_id = f"protocol-flow:{_digest(flow_id)}"
        flow_entity_ids[flow_id] = entity_id
        entities.append(
            {
                "id": entity_id,
                "kind": "dynamic_event",
                "name": flow_id,
                "confidence": 1.0,
                "sources": ["protocol_capture"],
                "attributes": {
                    "domain": "network",
                    "transport": flow.get("transport"),
                    "endpoint_a": flow.get("endpoint_a"),
                    "endpoint_b": flow.get("endpoint_b"),
                    "endpoint": flow.get("endpoint"),
                    "message_count": len(flow.get("message_ids") or []),
                },
            }
        )

    shape_members: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for message in messages:
        protobuf = message.get("protobuf") if isinstance(message.get("protobuf"), Mapping) else {}
        signature = str(protobuf.get("signature") or "")
        format_names = sorted(str(item) for item in message.get("formats") or [])
        framing_type = (
            str((message.get("framing") or {}).get("type") or "unframed")
            if isinstance(message.get("framing"), Mapping)
            else "unframed"
        )
        shape_key = json.dumps(
            {"formats": format_names, "framing": framing_type, "protobuf": signature},
            sort_keys=True,
            separators=(",", ":"),
        )
        shape_members[shape_key].append(message)
    for shape_key in sorted(shape_members):
        members = shape_members[shape_key]
        descriptor = json.loads(shape_key)
        entity_id = f"protocol-message-shape:{_digest(shape_key)}"
        message_shape_ids[shape_key] = entity_id
        for member in members:
            message_id = str(member.get("id") or "")
            if message_id:
                message_entity_ids[message_id] = entity_id
        entities.append(
            {
                "id": entity_id,
                "kind": "resource",
                "name": "protocol message shape",
                "confidence": 0.9 if descriptor["formats"] or descriptor["protobuf"] else 0.6,
                "sources": ["protocol_infer"],
                "attributes": {
                    "domain": "network",
                    "formats": descriptor["formats"],
                    "framing": descriptor["framing"],
                    "protobuf_signature": descriptor["protobuf"] or None,
                    "message_count": len(members),
                    "message_ids": [str(item.get("id")) for item in members[:64]],
                },
            }
        )
        flow_ids = sorted({str(item.get("flow_id") or "") for item in members if item.get("flow_id")})
        for flow_id in flow_ids:
            source_id = flow_entity_ids.get(flow_id)
            if not source_id:
                continue
            relation_id = f"protocol-relation:{_digest(source_id + '|' + entity_id)}"
            relations.append(
                {
                    "id": relation_id,
                    "type": "carries",
                    "source": source_id,
                    "target": entity_id,
                    "confidence": 0.95,
                    "sources": ["protocol_infer"],
                }
            )

    for pair in request_response_pairs:
        request_shape_id = message_entity_ids.get(str(pair.get("request_message_id") or ""))
        response_shape_id = message_entity_ids.get(str(pair.get("response_message_id") or ""))
        if not request_shape_id or not response_shape_id:
            continue
        pair_id = str(pair.get("exchange_id") or pair.get("id") or "")
        relations.append(
            {
                "id": f"protocol-exchange:{_digest(pair_id or request_shape_id + '|' + response_shape_id)}",
                "type": "request_response",
                "source": request_shape_id,
                "target": response_shape_id,
                "confidence": float(pair.get("confidence") or 0.75),
                "sources": ["protocol_infer"],
                "attributes": {"exchange_id": pair_id or None},
            }
        )

    protocol_names = sorted({str(item.get("name")) for item in protocols if item.get("name")})
    format_names = sorted(set(str(item) for item in formats))
    entity_ids = sorted(str(item["id"]) for item in entities)
    capabilities = []
    if entity_ids or protocol_names or format_names:
        confidence = max(
            (float(item.get("confidence") or 0.0) for item in protocols),
            default=0.6 if entity_ids else 0.0,
        )
        capabilities.append(
            {
                "id": f"capability:network:{_digest(entity_ids + protocol_names + format_names)}",
                "name": "network_protocol",
                "category": "network",
                "confidence": round(confidence, 3),
                "entity_ids": entity_ids,
                "evidence_count": max(len(entity_ids), len(protocol_names) + len(format_names)),
                "attributes": {
                    "protocols": protocol_names,
                    "message_formats": format_names,
                    "protobuf_shape_count": len(protobuf_shapes),
                    "request_response_pair_count": len(request_response_pairs),
                },
            }
        )
    entities.sort(key=lambda item: str(item["id"]))
    relations.sort(key=lambda item: str(item["id"]))
    return {
        "status": "ok" if entities or relations or capabilities else "unavailable",
        "schema_version": SCHEMA_VERSION,
        "source": "protocol",
        "entities": entities,
        "relations": relations,
        "capabilities": capabilities,
        "summary": {
            "entity_count": len(entities),
            "relation_count": len(relations),
            "capability_count": len(capabilities),
            "flow_count": len(flow_entity_ids),
            "message_shape_count": len(message_shape_ids),
            "request_response_pair_count": len(request_response_pairs),
        },
    }


def _infer_static_evidence(texts: list[str]) -> dict[str, Any]:
    urls = sorted({match for text in texts for match in _URL_RE.findall(text)})
    hosts = sorted({match for text in texts for match in _HOST_RE.findall(text)})
    pipes = sorted({match for text in texts for match in _PIPE_RE.findall(text)})
    lower = "\n".join(texts).lower()
    protocols: list[dict[str, Any]] = []

    def add(name: str, confidence: float, evidence: list[str]) -> None:
        protocols.append({"name": name, "confidence": round(confidence, 3), "evidence": evidence})

    if urls or any(token in lower for token in ("http", "https", "winhttp", "wininet", "user-agent", "content-type", "accept:")):
        add("http", 0.92 if urls else 0.62, [f"url:{item}" for item in urls[:5]] or ["HTTP tokens in strings/dynamic evidence"])
    if any(url.lower().startswith(("ws://", "wss://")) for url in urls) or "websocket" in lower:
        add(
            "websocket",
            0.88,
            [f"url:{item}" for item in urls if item.lower().startswith(("ws://", "wss://"))][:5]
            or ["WebSocket tokens present"],
        )
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
    return {
        "protocols": protocols,
        "formats": formats,
        "flows": flows,
        "field_stats": {
            "string_count": len(texts),
            "url_count": len(urls),
            "host_count": len(hosts),
            "named_pipe_count": len(pipes),
            "format_count": len(formats),
            "protocol_count": len(protocols),
        },
    }


def _merge_protocols(*groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for group in groups:
        for item in group:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            if name not in merged:
                merged[name] = {"name": name, "confidence": 0.0, "evidence": []}
                order.append(name)
            target = merged[name]
            target["confidence"] = max(float(target["confidence"]), float(item.get("confidence") or 0.0))
            for evidence in item.get("evidence") or []:
                evidence_text = str(evidence)
                if evidence_text not in target["evidence"] and len(target["evidence"]) < 20:
                    target["evidence"].append(evidence_text)
    return [merged[name] for name in order]


def _merge_flows(*groups: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            key = str(item.get("flow_id") or item.get("id") or item.get("endpoint") or json.dumps(item, sort_keys=True, default=repr))
            if key in seen:
                continue
            seen.add(key)
            result.append(dict(item))
    return result


def _ordered_unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _looks_like_inference(value: Mapping[str, Any]) -> bool:
    return "message_formats" in value or "protobuf_shapes" in value or "semantic_ir_fragment" in value


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
            data, _ = _read_bounded(Path(path), 1024 * 1024)
            values.extend(
                match.group(0).decode("ascii", errors="ignore")
                for match in re.finditer(rb"[\x20-\x7e]{4,}", data)
            )
        except OSError:
            pass
    if isinstance(strings, Mapping):
        source = strings.get("strings") or []
        if isinstance(source, Iterable) and not isinstance(source, (str, bytes, bytearray)):
            for index, item in enumerate(source):
                if index >= _MAX_TEXTS:
                    break
                values.append(str(item))
    elif isinstance(strings, Iterable) and not isinstance(strings, (str, bytes, bytearray)):
        for index, item in enumerate(strings):
            if index >= _MAX_TEXTS:
                break
            values.append(str(item))
    for mapping in (dynamic_analysis, behavior_graph, semantic_ir, gui_analysis):
        if len(values) >= _MAX_TEXTS:
            break
        values.extend(_mapping_strings(mapping, _MAX_TEXTS - len(values)))
    seen: set[str] = set()
    result: list[str] = []
    for item in values:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
            if len(result) >= _MAX_TEXTS:
                break
    return result


def _mapping_strings(mapping: Mapping[str, Any] | None, limit: int = _MAX_TEXTS) -> list[str]:
    if not isinstance(mapping, Mapping) or limit <= 0:
        return []
    results: list[str] = []
    stack: list[Any] = [mapping]
    visited = 0
    while stack and len(results) < limit and visited < _MAX_MAPPING_NODES:
        current = stack.pop()
        visited += 1
        if isinstance(current, Mapping):
            for key, value in current.items():
                if isinstance(key, str) and len(results) < limit:
                    results.append(key)
                if len(stack) < _MAX_MAPPING_NODES:
                    stack.append(value)
        elif isinstance(current, list):
            remaining = _MAX_MAPPING_NODES - len(stack)
            if remaining > 0:
                stack.extend(current[:remaining])
        elif isinstance(current, str):
            results.append(current)
    return results[:limit]


def _persist_result_artifacts(
    result: dict[str, Any],
    out_dir: str | os.PathLike[str] | None,
    specs: Iterable[tuple[str, str, str, Any]],
) -> None:
    if out_dir is None or not str(out_dir).strip():
        return
    protocol_dir = Path(out_dir) / "protocol"
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []
    for artifact_name, filename, kind, payload in specs:
        path = protocol_dir / filename
        try:
            _write_json(path, payload)
        except (OSError, TypeError, ValueError) as exc:
            errors.append(f"could not write {artifact_name}: {exc}")
            continue
        artifacts.append({"name": artifact_name, "path": str(path), "kind": kind})
    result["artifacts"] = artifacts
    if errors:
        warnings = result.setdefault("warnings", [])
        for error in errors:
            _warn(warnings, error)
        if result.get("status") == "ok":
            result["status"] = "partial"


def _artifact_payload(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key != "artifacts"}


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, default=_json_default) + "\n",
        encoding="utf-8",
    )


def _json_default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, set):
        return sorted(value, key=repr)
    return repr(value)


def _warn(warnings: list[str], message: str) -> None:
    if message not in warnings and len(warnings) < _MAX_WARNINGS:
        warnings.append(message)


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _safe_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def _safe_port(value: Any) -> int | None:
    parsed = _safe_int(value)
    if parsed is None or not 0 <= parsed <= 65535:
        return None
    return parsed


def _digest(value: Any) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]
