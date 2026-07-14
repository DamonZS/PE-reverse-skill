import base64
import builtins
import gzip
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import zlib

from reverse_analyzer.tools.executor import ToolExecutor, ToolResult
from reverse_analyzer.tools.protocol import (
    protocol_analyze,
    protocol_capture,
    protocol_infer,
    protocol_summarize,
)


def _ethernet_ipv4_tcp(
    payload: bytes,
    *,
    src: bytes = b"\x0a\x00\x00\x01",
    dst: bytes = b"\x0a\x00\x00\x02",
    src_port: int = 41000,
    dst_port: int = 8080,
    sequence: int = 1000,
) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        sequence,
        0,
        (5 << 12) | 0x18,
        65535,
        0,
        0,
    )
    total_length = 20 + len(tcp) + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
    return ethernet + ipv4 + tcp + payload


def _ethernet_ipv4_udp(
    payload: bytes,
    *,
    src: bytes = b"\x0a\x00\x00\x01",
    dst: bytes = b"\x0a\x00\x00\x02",
    src_port: int = 53000,
    dst_port: int = 53,
) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    total_length = 20 + len(udp) + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        2,
        0x4000,
        64,
        17,
        0,
        src,
        dst,
    )
    return ethernet + ipv4 + udp + payload


def _write_pcap(path: Path, packets: list[bytes]) -> None:
    payload = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets, start=1):
        payload.extend(struct.pack("<IIII", index, index * 1000, len(packet), len(packet)))
        payload.extend(packet)
    path.write_bytes(bytes(payload))


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((-len(body)) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + padding
        + struct.pack("<I", total_length)
    )


def _write_pcapng(path: Path, packets: list[bytes]) -> None:
    section = _pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1),
    )
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    enhanced = []
    for index, packet in enumerate(packets, start=1):
        enhanced.append(
            _pcapng_block(
                6,
                struct.pack("<IIIII", 0, 0, index * 1000, len(packet), len(packet))
                + packet,
            )
        )
    path.write_bytes(section + interface + b"".join(enhanced))


class ProtocolAnalysisTests(unittest.TestCase):
    def test_protocol_analyze_keeps_legacy_schema_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "analysis"

            result = protocol_analyze(
                strings=[
                    "https://api.example.test/v1/events",
                    "WinHttpConnect application/json base64",
                ],
                dynamic_analysis={"apis": ["connect", "send"]},
                out_dir=out_dir,
            )

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["inference"]["primary_protocol"], "http")
            self.assertIn("json", result["inference"]["message_formats"])
            self.assertEqual(result["messages"], [])
            self.assertIsInstance(result["semantic_ir_fragment"]["entities"], list)
            self.assertEqual(
                {item["name"] for item in result["artifacts"]},
                {
                    "protocol/flows.json",
                    "protocol/field_stats.json",
                    "protocol/inference.json",
                },
            )
            for artifact in result["artifacts"]:
                self.assertEqual(set(artifact), {"name", "path", "kind"})
                self.assertTrue(Path(artifact["path"]).is_file())

    def test_pcap_tcp_reassembly_length_framing_and_protobuf_shape(self) -> None:
        json_message = json.dumps({"operation": "ping", "id": 7}).encode("utf-8")
        protobuf_message = b"\x08\x96\x01\x12\x03abc\x1d\x01\x00\x00\x00"
        stream = (
            struct.pack(">I", len(json_message))
            + json_message
            + struct.pack(">I", len(protobuf_message))
            + protobuf_message
        )
        split_at = 11
        with tempfile.TemporaryDirectory() as tmp:
            capture_path = Path(tmp) / "sample.pcap"
            _write_pcap(
                capture_path,
                [
                    _ethernet_ipv4_tcp(stream[:split_at], sequence=9000),
                    _ethernet_ipv4_tcp(stream[split_at:], sequence=9000 + split_at),
                ],
            )

            captured = protocol_capture(capture_path)
            inferred = protocol_infer(captured)

        self.assertEqual(captured["status"], "ok")
        self.assertEqual(captured["source"]["format"], "pcap")
        self.assertEqual(captured["field_stats"]["packet_count"], 2)
        self.assertEqual(len(captured["flows"]), 1)
        self.assertEqual(captured["flows"][0]["transport"], "tcp")
        self.assertEqual(len(captured["messages"]), 1)
        self.assertEqual(bytes.fromhex(captured["messages"][0]["payload_hex"]), stream)
        self.assertEqual(captured["messages"][0]["metadata"]["segment_count"], 2)

        self.assertEqual(inferred["status"], "ok")
        self.assertEqual(len(inferred["messages"]), 2)
        self.assertEqual(inferred["framing"]["primary"]["type"], "length_prefix")
        self.assertEqual(inferred["framing"]["primary"]["byte_width"], 4)
        self.assertIn("json", inferred["message_formats"])
        self.assertIn("protobuf", inferred["message_formats"])
        shape = inferred["protobuf_shapes"][0]
        self.assertEqual(shape["signature"], "1:varint,2:length_delimited,3:fixed32")
        self.assertEqual(
            [(field["field_number"], field["wire_type"]) for field in shape["fields"]],
            [(1, 0), (2, 2), (3, 5)],
        )
        self.assertEqual(
            inferred["semantic_ir_fragment"]["summary"]["flow_count"],
            1,
        )
        self.assertGreaterEqual(
            inferred["semantic_ir_fragment"]["summary"]["message_shape_count"],
            2,
        )

    def test_pcapng_udp_packets_share_normalized_bidirectional_flow(self) -> None:
        first = _ethernet_ipv4_udp(b'{"query":"example.test"}')
        second = _ethernet_ipv4_udp(
            b'{"answer":"10.0.0.9"}',
            src=b"\x0a\x00\x00\x02",
            dst=b"\x0a\x00\x00\x01",
            src_port=53,
            dst_port=53000,
        )
        with tempfile.TemporaryDirectory() as tmp:
            capture_path = Path(tmp) / "sample.pcapng"
            _write_pcapng(capture_path, [first, second])

            captured = protocol_capture(capture_path)
            inferred = protocol_infer(captured)

        self.assertEqual(captured["status"], "ok")
        self.assertEqual(captured["source"]["format"], "pcapng")
        self.assertEqual(captured["source"]["link_types"], [1])
        self.assertEqual(len(captured["flows"]), 1)
        self.assertEqual(captured["flows"][0]["transport"], "udp")
        self.assertEqual(
            {item["direction"] for item in captured["messages"]},
            {"a_to_b", "b_to_a"},
        )
        self.assertEqual(inferred["message_formats"], ["json"])
        self.assertEqual(inferred["protocols"][0]["name"], "udp")
        self.assertIn("dns", {item["name"] for item in inferred["protocols"]})

    def test_json_jsonl_and_raw_imports_enforce_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "messages.json"
            json_path.write_text(
                json.dumps(
                    {
                        "messages": [
                            {
                                "flow_id": "udp:fixture",
                                "transport": "udp",
                                "direction": "a_to_b",
                                "payload_base64": base64.b64encode(b'{"ok":true}').decode("ascii"),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            jsonl_path = root / "messages.jsonl"
            jsonl_path.write_text(
                "\n".join(
                    json.dumps({"payload": f"message-{index}"})
                    for index in range(4)
                )
                + "\n",
                encoding="utf-8",
            )
            raw_path = root / "payload.raw"
            raw_path.write_bytes(bytes(range(64)))

            json_result = protocol_capture(json_path)
            jsonl_result = protocol_capture(jsonl_path, max_messages=2)
            raw_result = protocol_capture(raw_path, max_bytes=8)

        self.assertEqual(json_result["status"], "ok")
        self.assertEqual(json_result["source"]["format"], "json")
        self.assertEqual(json_result["messages"][0]["payload_text"], '{"ok":true}')

        self.assertEqual(jsonl_result["status"], "partial")
        self.assertEqual(jsonl_result["source"]["format"], "jsonl")
        self.assertEqual(len(jsonl_result["messages"]), 2)
        self.assertTrue(jsonl_result["source"]["limit_hit"])

        self.assertEqual(raw_result["status"], "partial")
        self.assertEqual(raw_result["source"]["format"], "raw")
        self.assertTrue(raw_result["source"]["truncated"])
        self.assertEqual(raw_result["source"]["bytes_read"], 8)
        self.assertEqual(raw_result["messages"][0]["captured_size"], 8)

    def test_nested_encodings_and_missing_msgpack_dependency_are_partial(self) -> None:
        nested_gzip = base64.b64encode(gzip.compress(b'{"codec":"gzip"}'))
        nested_zlib = zlib.compress(b'{"codec":"zlib"}')
        msgpack_map = b"\x82\xa2id\x07\xa4name\xa3bob"
        original_import = builtins.__import__

        def without_msgpack(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "msgpack":
                raise ModuleNotFoundError("msgpack disabled by test")
            return original_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=without_msgpack):
            result = protocol_infer(messages=[nested_gzip, nested_zlib, msgpack_map])

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["dependencies"]["msgpack"], "unavailable")
        self.assertTrue(
            {"base64", "gzip", "zlib", "json", "msgpack"}
            <= set(result["message_formats"])
        )
        msgpack_message = next(item for item in result["messages"] if "msgpack" in item["formats"])
        self.assertEqual(msgpack_message["format_details"][0]["name"], "msgpack")
        self.assertTrue(any("dependency unavailable" in warning for warning in result["warnings"]))

    def test_delimiter_magic_and_entropy_framing_are_reported(self) -> None:
        delimiter = b"alpha\nbeta\ngamma\n"
        magic = b"\xaa\x55first\xaa\x55second"
        high_entropy = bytes(range(256)) * 4

        result = protocol_infer(messages=[delimiter, magic, high_entropy])

        candidate_types = {item["type"] for item in result["framing"]["candidates"]}
        self.assertIn("delimiter", candidate_types)
        self.assertIn("magic", candidate_types)
        self.assertIn("entropy", candidate_types)
        self.assertEqual(result["framing"]["entropy"]["classification"], "medium")
        entropy_messages = [item for item in result["messages"] if item["entropy"]["value"] >= 7.5]
        self.assertTrue(entropy_messages)

    def test_artifacts_summary_and_toolresult_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "analysis"
            capture_result = protocol_capture(
                data=b'{"event":"ready"}',
                source_format="raw",
                out_dir=out_dir,
            )
            infer_result = protocol_infer(capture_result, out_dir=out_dir)
            summary = protocol_summarize(infer_result, out_dir=out_dir)

            executor = ToolExecutor()
            executor.register("protocol_capture", protocol_capture)
            wrapped = executor.execute(
                "protocol_capture",
                data=b"bounded fixture",
                source_format="raw",
            )

            self.assertEqual(
                {item["name"] for item in infer_result["artifacts"]},
                {
                    "protocol/messages.json",
                    "protocol/inference.json",
                    "protocol/semantic_ir_fragment.json",
                },
            )
            self.assertEqual(summary["summary"]["message_count"], 1)
            self.assertEqual(summary["summary"]["message_formats"], ["json"])
            self.assertEqual(summary["artifacts"][0]["name"], "protocol/summary.json")
            for result in (capture_result, infer_result, summary):
                for artifact in result["artifacts"]:
                    artifact_path = Path(artifact["path"])
                    self.assertTrue(artifact_path.is_file())
                    json.loads(artifact_path.read_text(encoding="utf-8"))

        self.assertIsInstance(wrapped, ToolResult)
        self.assertEqual(wrapped.status, "ok")
        self.assertEqual(wrapped.data["status"], "ok")

    def test_missing_capture_is_gracefully_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.pcap"

            captured = protocol_capture(missing)
            inferred = protocol_infer(captured)
            analyzed = protocol_analyze(path=missing)

        self.assertEqual(captured["status"], "unavailable")
        self.assertEqual(captured["messages"], [])
        self.assertIn("not found", captured["reason"])
        self.assertEqual(inferred["status"], "unavailable")
        self.assertEqual(inferred["messages"], [])
        self.assertEqual(analyzed["status"], "unavailable")
        self.assertEqual(analyzed["protocols"], [])


if __name__ == "__main__":
    unittest.main()
