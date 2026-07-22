from __future__ import annotations

import json
import hashlib
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, RequestReceived, StreamEnded
    _H2_AVAILABLE = True
except ImportError:  # pragma: no cover - dependency-gated environments
    H2Configuration = H2Connection = DataReceived = RequestReceived = StreamEnded = None
    _H2_AVAILABLE = False

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.protocol_runtime import ProtocolRuntimeProvider


class Http2FixtureServer:
    def __init__(self, response_body: bytes) -> None:
        self.response_body = response_body
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
        self.requests: list[dict[str, Any]] = []
        self.errors: list[str] = []
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
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with connection:
                    connection.settimeout(0.2)
                    h2 = H2Connection(
                        config=H2Configuration(
                            client_side=False,
                            header_encoding="utf-8",
                        )
                    )
                    h2.initiate_connection()
                    connection.sendall(h2.data_to_send())
                    streams: dict[int, dict[str, Any]] = {}
                    while not self._stop.is_set():
                        try:
                            data = connection.recv(65535)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        for event in h2.receive_data(data):
                            if isinstance(event, RequestReceived):
                                streams[event.stream_id] = {
                                    "stream_id": event.stream_id,
                                    "headers": [[str(k), str(v)] for k, v in event.headers],
                                    "body": bytearray(),
                                }
                            elif isinstance(event, DataReceived):
                                streams[event.stream_id]["body"].extend(event.data)
                                h2.acknowledge_received_data(
                                    event.flow_controlled_length,
                                    event.stream_id,
                                )
                            elif isinstance(event, StreamEnded):
                                request = streams[event.stream_id]
                                request["body"] = bytes(request["body"])
                                self.requests.append(request)
                                h2.send_headers(
                                    event.stream_id,
                                    [
                                        (":status", "200"),
                                        ("content-type", "application/octet-stream"),
                                        ("content-length", str(len(self.response_body))),
                                    ],
                                )
                                h2.send_data(
                                    event.stream_id,
                                    self.response_body,
                                    end_stream=True,
                                )
                        outbound = h2.data_to_send()
                        if outbound:
                            connection.sendall(outbound)
                    return
        except Exception as exc:  # pragma: no cover - reported by assertions
            self.errors.append(str(exc) or exc.__class__.__name__)


@unittest.skipUnless(_H2_AVAILABLE, "hyper-h2 is not installed")
class ProtocolRuntimeHttp2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = ProtocolRuntimeProvider()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _limits() -> dict[str, int]:
        return {
            "duration_ms": 2_000,
            "socket_timeout_ms": 250,
            "max_bytes": 64 * 1024,
            "max_frames": 64,
            "max_connections": 2,
            "max_messages": 16,
            "max_stream_bytes": 16 * 1024,
        }

    def test_real_http2_capture_materialize_and_replay(self) -> None:
        body = b"request-body"
        response = b"bounded-http2-response"
        source_server = Http2FixtureServer(response)
        try:
            capture_request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_http2_capture",
                target=TargetIdentity(
                    kind="http2-fixture",
                    display_name=f"h2c://127.0.0.1:{source_server.port}",
                ),
                params={
                    "listen_host": "127.0.0.1",
                    "listen_port": 0,
                    "upstream_host": "127.0.0.1",
                    "upstream_port": source_server.port,
                    "http2_request": {
                        "method": "POST",
                        "path": "/capture",
                        "headers": [["x-fixture", "p6-http2"]],
                        "body": body,
                    },
                    **self._limits(),
                },
                session_id="http2-capture",
                provenance={"test_case": self.id()},
            )
            capture_plan = self.provider.plan(capture_request)
            capture_validation = self.provider.validate(capture_plan)
            self.assertTrue(capture_validation.ok, capture_validation.errors)
            capture = self.provider.execute(capture_plan)
        finally:
            source_server.close()

        self.assertEqual(capture.status, "ok", capture.report_section["errors"])
        self.assertEqual(len(source_server.requests), 1)
        self.assertEqual(source_server.requests[0]["body"], body)
        after = capture.after_snapshot
        self.assertTrue(after["live_verified"])
        self.assertTrue(after["real_socket_evidence"])
        self.assertEqual(after["application_protocol"], "http/2")
        self.assertEqual(after["protocol_adapter"], "hyper-h2")
        self.assertEqual(after["stream_id"], 1)
        self.assertEqual(after["response"]["body_base64"], "Ym91bmRlZC1odHRwMi1yZXNwb25zZQ==")
        self.assertIn("HEADERS", {item["type"] for item in after["client_frames"]})
        self.assertIn("DATA", {item["type"] for item in after["server_frames"]})
        self.assertIn("ResponseReceived", {item["event"] for item in after["events"]})
        self.assertEqual(len(after["client_wire"]["sha256"]), 64)
        self.assertEqual(len(after["server_wire"]["sha256"]), 64)
        self.assertTrue(self.provider.rollback(capture).ok)

        bundle = self.provider.collect_artifacts(capture, str(self.root / "capture"))
        artifact = self.root / "capture" / bundle.artifacts[0].path
        stored = json.loads(artifact.read_text(encoding="utf-8"))
        self.assertEqual(stored["after_snapshot"]["stream_id"], 1)

        replay_server = Http2FixtureServer(response)
        try:
            replay_request = CapabilityRequest(
                capability="protocol_runtime",
                action="http2_fixture_replay",
                target=TargetIdentity(kind="artifact", path=str(artifact)),
                params={
                    "capture_artifact": str(artifact),
                    "destination_host": "127.0.0.1",
                    "destination_port": replay_server.port,
                    **self._limits(),
                },
                session_id="http2-replay",
                provenance={"test_case": self.id()},
            )
            replay_plan = self.provider.plan(replay_request)
            replay_validation = self.provider.validate(replay_plan)
            self.assertTrue(replay_validation.ok, replay_validation.errors)
            replay = self.provider.execute(replay_plan)
        finally:
            replay_server.close()

        self.assertEqual(replay.status, "ok", replay.report_section["errors"])
        self.assertEqual(len(replay_server.requests), 1)
        self.assertEqual(replay_server.requests[0]["body"], body)
        self.assertTrue(replay.after_snapshot["response_verified"])
        self.assertTrue(replay.after_snapshot["replay_verified"])
        self.assertTrue(replay.after_snapshot["live_verified"])
        self.assertTrue(replay.after_snapshot["real_socket_evidence"])
        self.assertTrue(self.provider.rollback(replay).ok)

    def test_http2_capture_rejects_remote_endpoint_before_socket(self) -> None:
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="loopback_http2_capture",
            target=TargetIdentity(display_name="remote-http2"),
            params={
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "upstream_host": "192.0.2.10",
                "upstream_port": 443,
                "allow_remote": True,
                **self._limits(),
            },
            session_id="remote-http2",
        )
        plan = self.provider.plan(request)
        validation = self.provider.validate(plan)
        self.assertFalse(validation.ok)
        with patch(
            "reverse_analyzer.providers.protocol_runtime.socket.socket",
            side_effect=AssertionError("remote HTTP/2 validation opened a socket"),
        ):
            result = self.provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.provenance["network_transmit"])

    def test_http2_replay_rejects_tampered_wire_evidence_before_socket(self) -> None:
        server = Http2FixtureServer(b"tamper-response")
        try:
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_http2_capture",
                target=TargetIdentity(display_name="h2c-tamper-source"),
                params={
                    "upstream_host": "127.0.0.1",
                    "upstream_port": server.port,
                    **self._limits(),
                },
                session_id="http2-tamper-source",
            )
            capture = self.provider.execute(self.provider.plan(request))
        finally:
            server.close()
        self.assertEqual(capture.status, "ok")
        bundle = self.provider.collect_artifacts(capture, str(self.root / "tamper"))
        artifact = self.root / "tamper" / bundle.artifacts[0].path
        payload = json.loads(artifact.read_text(encoding="utf-8"))
        payload["after_snapshot"]["server_wire"]["sha256"] = "0" * 64
        artifact.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        replay_request = CapabilityRequest(
            capability="protocol_runtime",
            action="http2_fixture_replay",
            target=TargetIdentity(
                kind="artifact",
                path=str(artifact),
                sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            ),
            params={
                "capture_artifact": str(artifact),
                "destination_host": "127.0.0.1",
                "destination_port": 1,
                **self._limits(),
            },
            session_id="http2-tamper-replay",
        )
        plan = self.provider.plan(replay_request)
        validation = self.provider.validate(plan)
        self.assertFalse(validation.ok)
        self.assertIn("server wire hash is invalid", " ".join(validation.errors))
        with patch(
            "reverse_analyzer.providers.protocol_runtime.socket.socket",
            side_effect=AssertionError("tampered HTTP/2 source opened a socket"),
        ):
            result = self.provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.provenance["network_transmit"])


if __name__ == "__main__":
    unittest.main()
