from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.protocol_runtime import ProtocolRuntimeProvider


def _ethernet_ipv4_tcp(
    payload: bytes,
    *,
    sequence: int,
    src: bytes = b"\x0a\x00\x00\x01",
    dst: bytes = b"\x0a\x00\x00\x02",
    src_port: int = 41000,
    dst_port: int = 8080,
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
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        src,
        dst,
    )
    return ethernet + ipv4 + tcp + payload


def _ethernet_ipv4_udp(payload: bytes) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(payload), 0)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp) + len(payload),
        2,
        0x4000,
        64,
        17,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    return ethernet + ipv4 + udp + payload


def _write_pcap(path: Path, packets: list[bytes]) -> None:
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets, start=1):
        data.extend(struct.pack("<IIII", index, index * 1000, len(packet), len(packet)))
        data.extend(packet)
    path.write_bytes(bytes(data))


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
    section = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = _pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    enhanced = [
        _pcapng_block(
            6,
            struct.pack("<IIIII", 0, 0, index * 1000, len(packet), len(packet))
            + packet,
        )
        for index, packet in enumerate(packets, start=1)
    ]
    path.write_bytes(section + interface + b"".join(enhanced))


class _TcpEcho:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        data = connection.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        break
                    self.received.append(data)
                    connection.sendall(data)


class _UdpEcho:
    def __init__(self) -> None:
        self.value = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.value.bind(("127.0.0.1", 0))
        self.value.settimeout(0.1)
        self.port = int(self.value.getsockname()[1])
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self.value.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.value.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.received.append(data)
            self.value.sendto(data, peer)


class ProtocolRuntimeCaptureReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.provider = ProtocolRuntimeProvider()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _limits(self, **overrides: Any) -> dict[str, Any]:
        limits: dict[str, Any] = {
            "duration_ms": 1_000,
            "socket_timeout_ms": 250,
            "max_bytes": 64 * 1024,
            "max_frames": 32,
            "max_connections": 4,
            "max_packets": 32,
            "max_messages": 32,
            "max_message_bytes": 8 * 1024,
            "max_stream_bytes": 8 * 1024,
            "max_correlation_messages": 32,
            "max_request_response_pairs": 8,
        }
        limits.update(overrides)
        return limits

    def _import(
        self,
        path: Path,
        **parameters: Any,
    ) -> tuple[Any, Any]:
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="passive_capture_import",
            target=TargetIdentity(kind="capture", path=str(path)),
            params={"capture_source": str(path), **self._limits(), **parameters},
            session_id=f"import-{path.stem}",
            provenance={"test_case": self.id()},
        )
        plan = self.provider.plan(request)
        validation = self.provider.validate(plan)
        self.assertTrue(validation.ok, validation.errors)
        return plan, self.provider.execute(plan)

    def _collect(self, result: Any, name: str) -> Path:
        output = self.root / name
        bundle = self.provider.collect_artifacts(result, str(output))
        return output / bundle.artifacts[0].path

    def _offline_plan(
        self,
        artifact: Path,
        payload: bytes,
        *,
        transport: str = "tcp",
        offline_fixture: Any = None,
    ) -> Any:
        fixture = offline_fixture or {
            "enabled": True,
            "expected_frame_count": 1,
            "expected_payload_sha256": hashlib.sha256(payload).hexdigest(),
        }
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="controlled_replay",
            target=TargetIdentity(kind="artifact", path=str(artifact)),
            params={
                "capture_artifact": str(artifact),
                "replay_target_mode": "offline_fixture",
                "offline_fixture": fixture,
                "transport": transport,
                "frame_direction": "client_to_server",
                **self._limits(),
            },
            session_id=f"offline-{artifact.stem}",
        )
        return self.provider.plan(request)

    def test_bounded_imports_cover_pcap_pcapng_jsonl_and_raw(self) -> None:
        pcap = self.root / "out-of-order.pcap"
        _write_pcap(
            pcap,
            [
                _ethernet_ipv4_tcp(b"-world", sequence=1005),
                _ethernet_ipv4_tcp(b"hello", sequence=1000),
            ],
        )
        _, pcap_result = self._import(pcap)
        self.assertEqual(pcap_result.status, "ok")
        self.assertEqual(pcap_result.after_snapshot["source_format"], "pcap")
        self.assertEqual(
            bytes.fromhex(pcap_result.after_snapshot["messages"][0]["payload_hex"]),
            b"hello-world",
        )
        self.assertEqual(pcap_result.after_snapshot["integrity"]["reassembly_gap_count"], 0)

        pcapng = self.root / "udp.pcapng"
        _write_pcapng(pcapng, [_ethernet_ipv4_udp(b'{"query":"local"}')])
        _, pcapng_result = self._import(pcapng)
        self.assertEqual(pcapng_result.status, "ok")
        self.assertEqual(pcapng_result.after_snapshot["source_format"], "pcapng")
        self.assertEqual(pcapng_result.after_snapshot["messages"][0]["transport"], "udp")

        jsonl = self.root / "messages.jsonl"
        jsonl.write_text(
            "\n".join(json.dumps({"payload": f"message-{index}"}) for index in range(3))
            + "\n",
            encoding="utf-8",
        )
        _, jsonl_result = self._import(jsonl, max_messages=2)
        self.assertEqual(jsonl_result.status, "partial")
        self.assertEqual(jsonl_result.after_snapshot["message_count"], 2)
        self.assertIn("capture_or_stream_budget", jsonl_result.after_snapshot["limit_reached"])

        raw = self.root / "payload.raw"
        raw.write_bytes(bytes(range(64)))
        _, raw_result = self._import(raw, max_bytes=8)
        self.assertEqual(raw_result.status, "partial")
        self.assertEqual(raw_result.after_snapshot["source_format"], "raw")
        self.assertTrue(raw_result.after_snapshot["truncated"])
        self.assertEqual(raw_result.after_snapshot["messages"][0]["captured_size"], 8)

        for result in (pcap_result, pcapng_result, jsonl_result, raw_result):
            self.assertTrue(result.after_snapshot["real_capture_success"])
            self.assertFalse(result.after_snapshot["network_transmit"])
            self.assertEqual(result.after_snapshot["session"]["state"], "closed")

    def test_budget_pair_limit_gap_and_corrupt_capture_boundaries(self) -> None:
        pairs = self.root / "pairs.json"
        pairs.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "id": "request-1",
                            "flow_id": "tcp:pairs",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "role": "request",
                            "payload": "one",
                        },
                        {
                            "id": "response-1",
                            "flow_id": "tcp:pairs",
                            "transport": "tcp",
                            "direction": "b_to_a",
                            "role": "response",
                            "response_to": "request-1",
                            "payload": "ONE",
                        },
                        {
                            "id": "request-2",
                            "flow_id": "tcp:pairs",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "role": "request",
                            "payload": "two",
                        },
                        {
                            "id": "response-2",
                            "flow_id": "tcp:pairs",
                            "transport": "tcp",
                            "direction": "b_to_a",
                            "role": "response",
                            "response_to": "request-2",
                            "payload": "TWO",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        _, pair_result = self._import(pairs, max_request_response_pairs=1)
        self.assertEqual(pair_result.status, "partial")
        self.assertEqual(pair_result.after_snapshot["request_response_pair_count"], 1)
        self.assertIn(
            "max_request_response_pairs",
            pair_result.after_snapshot["budget"]["limit_reached"],
        )
        self.assertEqual(pair_result.report_section["errors"], [])

        stream = self.root / "stream.raw"
        stream.write_bytes(b"0123456789abcdef")
        _, stream_result = self._import(
            stream,
            max_message_bytes=4,
            max_stream_bytes=4,
        )
        self.assertEqual(stream_result.status, "partial")
        self.assertEqual(
            stream_result.after_snapshot["integrity"]["truncated_message_count"],
            1,
        )

        gap = self.root / "gap.pcap"
        _write_pcap(
            gap,
            [
                _ethernet_ipv4_tcp(b"abc", sequence=1000),
                _ethernet_ipv4_tcp(b"xyz", sequence=1010),
            ],
        )
        _, gap_result = self._import(gap)
        self.assertEqual(gap_result.status, "partial")
        self.assertEqual(gap_result.after_snapshot["integrity"]["reassembly_gap_count"], 1)
        self.assertTrue(gap_result.after_snapshot["integrity"]["damaged"])

        corrupt = self.root / "corrupt.pcap"
        corrupt.write_bytes(
            struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, 128, 128)
            + b"short"
        )
        _, corrupt_result = self._import(corrupt)
        self.assertEqual(corrupt_result.status, "unavailable")
        self.assertFalse(corrupt_result.after_snapshot["real_capture_success"])
        self.assertTrue(corrupt_result.report_section["warnings"])

    def test_source_and_offline_fixture_drift_fail_closed(self) -> None:
        source = self.root / "drift.raw"
        source.write_bytes(b"before")
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="passive_capture_import",
            target=TargetIdentity(kind="capture", path=str(source)),
            params={"capture_source": str(source), **self._limits()},
            session_id="source-drift",
        )
        plan = self.provider.plan(request)
        source.write_bytes(b"after!")
        validation = self.provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertIn("changed after planning", " ".join(validation.errors))
        result = self.provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.after_snapshot["real_capture_success"])

        stable = self.root / "stable.raw"
        stable.write_bytes(b"fixture-payload")
        _, stable_result = self._import(stable)
        artifact = self._collect(stable_result, "fixture-drift-source")
        fixture_file = self.root / "fixture.json"
        fixture_file.write_text("{}", encoding="utf-8")
        fixture_plan = self._offline_plan(
            artifact,
            b"fixture-payload",
            transport="raw",
            offline_fixture=str(fixture_file),
        )
        fixture_file.write_text('{"changed":true}', encoding="utf-8")
        fixture_validation = self.provider.validate(fixture_plan)
        self.assertFalse(fixture_validation.ok)
        self.assertIn("offline fixture", " ".join(fixture_validation.errors))

    def test_dependency_gate_and_non_real_adapter_never_report_real_success(self) -> None:
        unavailable_probe = {
            "status": "dependency-gated",
            "requested": "auto",
            "real_adapter": False,
            "reason": "passive capture dependency unavailable: test fixture",
        }
        adapter_request = CapabilityRequest(
            capability="protocol_runtime",
            action="passive_capture",
            target=TargetIdentity(kind="interface", display_name="loopback"),
            params={
                "capture_mode": "adapter",
                "capture_interface": "lo",
                **self._limits(duration_ms=10),
            },
            session_id="dependency-gated",
        )
        with patch(
            "reverse_analyzer.providers.protocol_runtime._probe_passive_capture_adapter",
            return_value=unavailable_probe,
        ):
            gated_plan = self.provider.plan(adapter_request)
            gated_validation = self.provider.validate(gated_plan)
            self.assertFalse(gated_validation.ok)
            gated = self.provider.execute(gated_plan)
        self.assertEqual(gated.status, "dependency-gated")
        self.assertEqual(gated.after_snapshot["dependency_state"], "dependency-gated")
        self.assertFalse(gated.after_snapshot["real_capture_success"])

        available_probe = {
            "status": "available",
            "requested": "auto",
            "adapter": "tcpdump",
            "executable": {"path": "fixture-tcpdump", "size": 1, "mtime_ns": 1},
            "dependency_kind": "local_executable",
            "real_adapter": True,
        }
        fake_message = {
            "id": "message-1",
            "flow_id": "raw:mock",
            "transport": "raw",
            "direction": "a_to_b",
            "payload_hex": "6d6f636b",
            "payload_size": 4,
            "captured_size": 4,
        }
        mock_outcome = {
            "status": "captured",
            "capture_result": {
                "status": "ok",
                "messages": [fake_message],
                "flows": [{"flow_id": "raw:mock", "transport": "raw"}],
                "request_response_pairs": [],
                "source": {"format": "raw", "bytes_read": 4},
            },
            "source": {"path": "mock-capture", "is_file": True, "size": 4},
            "errors": [],
            "execution": {
                "started": True,
                "real_adapter": False,
                "mock_provider": True,
            },
        }
        with (
            patch(
                "reverse_analyzer.providers.protocol_runtime._probe_passive_capture_adapter",
                return_value=available_probe,
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime._run_passive_capture_adapter",
                return_value=mock_outcome,
            ),
        ):
            mock_plan = self.provider.plan(adapter_request)
            mock_result = self.provider.execute(mock_plan)
        self.assertEqual(mock_result.status, "unavailable")
        self.assertFalse(mock_result.after_snapshot["real_capture_success"])
        self.assertEqual(mock_result.after_snapshot["outcome_class"], "unavailable")

        empty_outcome = {
            "status": "captured",
            "capture_result": {
                "status": "unavailable",
                "messages": [],
                "flows": [],
                "request_response_pairs": [],
                "warnings": ["adapter produced no packets"],
            },
            "source": {"path": "empty-capture", "is_file": True, "size": 0},
            "errors": [],
            "execution": {
                "started": True,
                "real_adapter": True,
                "mock_provider": False,
            },
        }
        with (
            patch(
                "reverse_analyzer.providers.protocol_runtime._probe_passive_capture_adapter",
                return_value=available_probe,
            ),
            patch(
                "reverse_analyzer.providers.protocol_runtime._run_passive_capture_adapter",
                return_value=empty_outcome,
            ),
        ):
            empty_plan = self.provider.plan(adapter_request)
            empty_result = self.provider.execute(empty_plan)
        self.assertEqual(empty_result.status, "unavailable")
        self.assertFalse(empty_result.after_snapshot["real_capture_success"])

    def test_audit_artifact_and_offline_fixture_replay_are_complete(self) -> None:
        payload = b'{"operation":"status"}'
        source = self.root / "audit.json"
        source.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "id": "request-1",
                            "flow_id": "tcp:audit",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "role": "request",
                            "payload_base64": base64.b64encode(payload).decode("ascii"),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        plan, result = self._import(source)
        self.assertEqual(plan.before_snapshot["session"]["state"], "planned")
        self.assertEqual(result.after_snapshot["session"]["state"], "closed")
        self.assertTrue(result.provenance["real_provider"])
        self.assertFalse(result.provenance["mock_provider"])
        self.assertFalse(result.provenance["network_transmit"])
        self.assertEqual(result.report_section["capture_summary"]["message_count"], 1)
        self.assertEqual(result.dashboard_trace[0]["outcome_class"], "real")
        self.assertIn(
            "passive-capture-source",
            {item.get("role") for item in result.evidence_manifest_entries},
        )

        rollback = self.provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertEqual(rollback.details["mode"], "close_passive_import_session")
        artifact = self._collect(result, "audit-output")
        materialized = json.loads(artifact.read_text("utf-8"))
        self.assertEqual(len(materialized["messages"]), 1)
        self.assertNotIn("messages", materialized["after_snapshot"])
        self.assertNotIn("messages", materialized["report_section"]["after_snapshot"])
        self.assertEqual(materialized["provenance"]["capture_source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertTrue(result.evidence_manifest_entries[0]["materialized"])

        offline_plan = self._offline_plan(artifact, payload)
        offline_validation = self.provider.validate(offline_plan)
        self.assertTrue(offline_validation.ok, offline_validation.errors)
        with patch(
            "reverse_analyzer.providers.protocol_runtime.socket.socket",
            side_effect=AssertionError("offline replay attempted network access"),
        ):
            offline = self.provider.execute(offline_plan)
        self.assertEqual(offline.status, "ok")
        self.assertFalse(offline.after_snapshot["network_transmit"])
        self.assertEqual(offline.after_snapshot["processed_source_frame_count"], 1)
        self.assertEqual(offline.after_snapshot["sent_bytes"], 0)
        self.assertEqual(offline.provenance["network_transmit_scope"], "none")

    def test_replay_rejects_truncated_gap_and_damaged_imports(self) -> None:
        truncated = self.root / "truncated.raw"
        truncated.write_bytes(b"0123456789")
        _, truncated_result = self._import(
            truncated,
            max_message_bytes=4,
            max_stream_bytes=4,
        )

        gap = self.root / "replay-gap.pcap"
        _write_pcap(
            gap,
            [
                _ethernet_ipv4_tcp(b"left", sequence=500),
                _ethernet_ipv4_tcp(b"right", sequence=520),
            ],
        )
        _, gap_result = self._import(gap)

        damaged = self.root / "damaged.json"
        damaged.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "flow_id": "tcp:damaged",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "payload": "damaged",
                            "metadata": {"malformed": True},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        _, damaged_result = self._import(damaged)

        cases = (
            ("truncated", truncated_result, b"0123", "raw", "truncated evidence"),
            ("gap", gap_result, b"leftright", "tcp", "reassembly gap"),
            ("damaged", damaged_result, b"damaged", "tcp", "damaged or malformed"),
        )
        for name, import_result, expected_payload, transport, expected_error in cases:
            with self.subTest(name=name):
                artifact = self._collect(import_result, f"replay-reject-{name}")
                offline_plan = self._offline_plan(
                    artifact,
                    expected_payload,
                    transport=transport,
                )
                validation = self.provider.validate(offline_plan)
                self.assertFalse(validation.ok)
                self.assertIn(expected_error, " ".join(validation.errors))

    def test_imported_messages_replay_only_to_real_loopback_tcp_and_udp(self) -> None:
        tcp_payload = b"tcp-loopback"
        tcp_source = self.root / "tcp-replay.json"
        tcp_source.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "flow_id": "tcp:fixture",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "payload_base64": base64.b64encode(tcp_payload).decode("ascii"),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        _, tcp_import = self._import(tcp_source)
        tcp_artifact = self._collect(tcp_import, "tcp-import")
        tcp_echo = _TcpEcho()
        try:
            tcp_request = CapabilityRequest(
                capability="protocol_runtime",
                action="replay",
                target=TargetIdentity(kind="artifact", path=str(tcp_artifact)),
                params={
                    "capture_artifact": str(tcp_artifact),
                    "destination_host": "127.0.0.1",
                    "destination_port": tcp_echo.port,
                    "frame_direction": "client_to_server",
                    "verify_echo": True,
                    **self._limits(),
                },
                session_id="tcp-import-replay",
            )
            tcp_plan = self.provider.plan(tcp_request)
            self.assertTrue(self.provider.validate(tcp_plan).ok)
            tcp_result = self.provider.execute(tcp_plan)
        finally:
            tcp_echo.close()
        self.assertEqual(tcp_result.status, "ok", tcp_result.report_section["errors"])
        self.assertEqual(b"".join(tcp_echo.received), tcp_payload)
        self.assertEqual(tcp_result.provenance["network_transmit_scope"], "explicit_loopback_ip_only")

        udp_payload = b"udp-loopback"
        udp_source = self.root / "udp-replay.json"
        udp_source.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "flow_id": "udp:fixture",
                            "transport": "udp",
                            "direction": "a_to_b",
                            "payload_base64": base64.b64encode(udp_payload).decode("ascii"),
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        _, udp_import = self._import(udp_source)
        udp_artifact = self._collect(udp_import, "udp-import")
        udp_echo = _UdpEcho()
        try:
            udp_request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_udp_replay",
                target=TargetIdentity(kind="artifact", path=str(udp_artifact)),
                params={
                    "capture_artifact": str(udp_artifact),
                    "destination_host": "127.0.0.1",
                    "destination_port": udp_echo.port,
                    "frame_direction": "client_to_server",
                    "verify_echo": True,
                    **self._limits(),
                },
                session_id="udp-import-replay",
            )
            udp_plan = self.provider.plan(udp_request)
            self.assertTrue(self.provider.validate(udp_plan).ok)
            udp_result = self.provider.execute(udp_plan)
        finally:
            udp_echo.close()
        self.assertEqual(udp_result.status, "ok", udp_result.report_section["errors"])
        self.assertEqual(udp_echo.received, [udp_payload])

    def test_remote_replay_is_rejected_before_any_socket_is_created(self) -> None:
        source = self.root / "remote.json"
        source.write_text(
            json.dumps(
                {
                    "messages": [
                        {
                            "flow_id": "tcp:remote",
                            "transport": "tcp",
                            "direction": "a_to_b",
                            "payload": "never-send",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        _, imported = self._import(source)
        artifact = self._collect(imported, "remote-source")
        for allow_remote in (False, True):
            with self.subTest(allow_remote=allow_remote):
                request = CapabilityRequest(
                    capability="protocol_runtime",
                    action="controlled_replay",
                    target=TargetIdentity(kind="artifact", path=str(artifact)),
                    params={
                        "capture_artifact": str(artifact),
                        "destination_host": "192.0.2.10",
                        "destination_port": 443,
                        "allow_remote": allow_remote,
                        **self._limits(),
                    },
                    session_id=f"remote-{allow_remote}",
                )
                plan = self.provider.plan(request)
                validation = self.provider.validate(plan)
                self.assertFalse(validation.ok)
                with patch(
                    "reverse_analyzer.providers.protocol_runtime.socket.socket",
                    side_effect=AssertionError("remote replay created a socket"),
                ):
                    result = self.provider.execute(plan)
                self.assertEqual(result.status, "failed")
                self.assertFalse(result.provenance["network_transmit"])


if __name__ == "__main__":
    unittest.main()
