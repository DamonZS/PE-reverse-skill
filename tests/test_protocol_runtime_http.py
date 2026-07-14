from __future__ import annotations

import base64
import hashlib
import json
import queue
import socket
import ssl
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.protocol_runtime import ProtocolRuntimeProvider
from tests.test_protocol_runtime_tls import _CA_CERT, _SERVER_CERT, _SERVER_KEY


class HttpFixtureServer:
    def __init__(
        self,
        responses: bytes | list[bytes],
        *,
        host: str = "127.0.0.1",
        tls_context: ssl.SSLContext | None = None,
        response_chunks: list[int] | None = None,
    ) -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.listener.bind((host, 0))
        self.listener.listen(8)
        self.listener.settimeout(0.1)
        self.host = host
        self.port = int(self.listener.getsockname()[1])
        self.responses = responses if isinstance(responses, list) else [responses]
        self.tls_context = tls_context
        self.response_chunks = list(response_chunks or [])
        self.received: list[bytes] = []
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
        response_index = 0
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            connection: socket.socket = raw
            try:
                if self.tls_context is not None:
                    connection = self.tls_context.wrap_socket(raw, server_side=True)
                with connection:
                    connection.settimeout(0.5)
                    request = self._read_request(connection)
                    self.received.append(request)
                    response = self.responses[min(response_index, len(self.responses) - 1)]
                    response_index += 1
                    self._send_response(connection, response)
            except (OSError, ssl.SSLError, ValueError) as exc:
                self.errors.append(str(exc) or exc.__class__.__name__)
                try:
                    raw.close()
                except OSError:
                    pass

    @staticmethod
    def _read_request(connection: socket.socket) -> bytes:
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = connection.recv(4096)
            if not chunk:
                return bytes(request)
            request.extend(chunk)
            if len(request) > 256 * 1024:
                raise ValueError("test request exceeded fixture bound")
        marker = request.index(b"\r\n\r\n") + 4
        header_lines = bytes(request[: marker - 4]).split(b"\r\n")[1:]
        content_length = 0
        for line in header_lines:
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
        expected = marker + content_length
        while len(request) < expected:
            chunk = connection.recv(expected - len(request))
            if not chunk:
                break
            request.extend(chunk)
        return bytes(request)

    def _send_response(self, connection: socket.socket, response: bytes) -> None:
        cursor = 0
        for size in self.response_chunks:
            if cursor >= len(response):
                break
            end = min(len(response), cursor + size)
            connection.sendall(response[cursor:end])
            cursor = end
            time.sleep(0.005)
        if cursor < len(response):
            connection.sendall(response[cursor:])


class ProtocolRuntimeHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.provider = ProtocolRuntimeProvider()
        self.ca_file = self.root / "test-ca.pem"
        self.cert_file = self.root / "server.pem"
        self.key_file = self.root / "server-key.pem"
        self.ca_file.write_text(_CA_CERT, encoding="ascii")
        self.cert_file.write_text(_SERVER_CERT, encoding="ascii")
        self.key_file.write_text(_SERVER_KEY, encoding="ascii")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def _limits(**overrides: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "duration_ms": 2_000,
            "socket_timeout_ms": 500,
            "max_bytes": 64 * 1024,
            "max_frames": 32,
            "max_connections": 1,
            "max_messages": 32,
            "max_message_bytes": 32 * 1024,
            "max_stream_bytes": 32 * 1024,
            "max_correlation_messages": 32,
            "max_request_response_pairs": 8,
            "max_http_header_bytes": 8 * 1024,
            "max_http_headers": 32,
        }
        values.update(overrides)
        return values

    def _server_tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_file), str(self.key_file))
        return context

    def _tls_params(self) -> dict[str, Any]:
        return {
            "tls": {
                "enabled": True,
                "verify": True,
                "server_hostname": "localhost",
                "ca_file": str(self.ca_file),
            }
        }

    def _capture(
        self,
        request_wire: bytes,
        response_wire: bytes,
        *,
        host: str = "127.0.0.1",
        tls: bool = False,
        limits: dict[str, Any] | None = None,
        response_chunks: list[int] | None = None,
        session_id: str = "http-capture",
    ) -> tuple[Any, Any, list[bytes]]:
        server = HttpFixtureServer(
            response_wire,
            host=host,
            tls_context=self._server_tls_context() if tls else None,
            response_chunks=response_chunks,
        )
        try:
            params = {
                "listen_host": host,
                "listen_port": 0,
                "upstream_host": host,
                "upstream_port": server.port,
                **self._limits(),
            }
            params.update(limits or {})
            if tls:
                params.update(self._tls_params())
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_http_capture",
                target=TargetIdentity(
                    kind="http-endpoint",
                    display_name=f"http://{host}:{server.port}",
                ),
                params=params,
                session_id=session_id,
                provenance={"test_case": self.id()},
            )
            plan = self.provider.plan(request)
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            ready: queue.Queue[dict[str, Any]] = queue.Queue()
            outcome: dict[str, Any] = {}

            def run() -> None:
                outcome["result"] = self.provider.execute(
                    plan,
                    context={"protocol_runtime_ready": ready.put},
                )

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            endpoint = ready.get(timeout=2)
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as client:
                client.settimeout(1)
                client.connect((str(endpoint["host"]), int(endpoint["port"])))
                client.sendall(request_wire)
                received = bytearray()
                while len(received) < len(response_wire):
                    chunk = client.recv(len(response_wire) - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                self.assertEqual(bytes(received), response_wire)
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive(), "HTTP capture exceeded its duration bound")
            return plan, outcome["result"], list(server.received)
        finally:
            server.close()

    def _materialize(self, result: Any, name: str) -> Path:
        bundle = self.provider.collect_artifacts(result, str(self.root / name))
        path = self.root / name / bundle.artifacts[0].path
        self.assertTrue(path.is_file())
        return path

    def _replay_request(
        self,
        artifact: Path,
        server: HttpFixtureServer,
        *,
        http_fixture: Any = None,
        tls: bool = False,
        limits: dict[str, Any] | None = None,
        allow_remote: bool = False,
        destination_host: str | None = None,
    ) -> CapabilityRequest:
        params: dict[str, Any] = {
            "capture_artifact": str(artifact),
            "destination_host": destination_host or server.host,
            "destination_port": server.port,
            "allow_remote": allow_remote,
            **self._limits(),
        }
        params.update(limits or {})
        if http_fixture is not None:
            params["http_fixture"] = http_fixture
        if tls:
            params.update(self._tls_params())
        return CapabilityRequest(
            capability="protocol_runtime",
            action="http_fixture_replay",
            target=TargetIdentity(
                kind="protocol-capture",
                path=str(artifact),
                sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
            ),
            params=params,
            session_id="http-replay",
            provenance={"test_case": self.id()},
        )

    def test_real_ipv4_http_request_response_capture_has_framing_and_hashes(self) -> None:
        request_wire = (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 5\r\n"
            b"X-Test: one\r\n\r\n"
            b"hello"
        )
        response_wire = (
            b"HTTP/1.1 201 Created\r\n"
            b"Content-Length: 5\r\n"
            b"Connection: close\r\n\r\n"
            b"world"
        )
        _, result, received = self._capture(request_wire, response_wire)

        self.assertEqual(result.status, "ok", result.report_section["errors"])
        self.assertEqual(received, [request_wire])
        after = result.after_snapshot
        self.assertTrue(after["real_socket_evidence"])
        self.assertTrue(after["real_capture_success"])
        self.assertEqual(after["application_protocol"], "http/1.1")
        self.assertEqual(after["request_response_pair_count"], 1)
        self.assertEqual(after["integrity"]["gap_count"], 0)
        self.assertFalse(after["integrity"]["fail_closed"])
        messages = {item["kind"]: item for item in after["messages"]}
        request = messages["http_request"]
        response = messages["http_response"]
        self.assertEqual(request["framing"]["type"], "content_length")
        self.assertEqual(response["framing"]["type"], "content_length")
        self.assertEqual(request["body_sha256"], hashlib.sha256(b"hello").hexdigest())
        self.assertEqual(response["body_sha256"], hashlib.sha256(b"world").hexdigest())
        request_headers = (
            b"Host: localhost\r\nContent-Length: 5\r\nX-Test: one"
        )
        self.assertEqual(
            request["headers_sha256"], hashlib.sha256(request_headers).hexdigest()
        )
        self.assertEqual(request["wire_sha256"], hashlib.sha256(request_wire).hexdigest())
        pair = after["request_response_pairs"][0]
        self.assertEqual(pair["request_header_sha256"], request["headers_sha256"])
        self.assertEqual(pair["response_body_sha256"], response["body_sha256"])
        for connection_key in ("client_socket_identity", "upstream_socket_identity"):
            identity = after["connections"][0][connection_key]
            self.assertTrue(identity["real_socket"])
            self.assertFalse(identity["synthetic"])
            self.assertTrue(identity["local"]["loopback"])
            self.assertTrue(identity["peer"]["loopback"])
            self.assertEqual(identity["local"]["ip_version"], 4)

    def test_real_ipv6_http_capture(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 sockets are unavailable")
        try:
            probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            probe.bind(("::1", 0))
            probe.close()
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is unavailable: {exc}")
        request_wire = b"GET /v6 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        response_wire = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
        _, result, _ = self._capture(
            request_wire,
            response_wire,
            host="::1",
            session_id="http-ipv6",
        )

        self.assertEqual(result.status, "ok", result.report_section["errors"])
        self.assertEqual(result.after_snapshot["listen_endpoint_identity"]["ip_version"], 6)
        connection = result.after_snapshot["connections"][0]
        self.assertEqual(connection["client_socket_identity"]["local"]["ip_version"], 6)
        self.assertEqual(connection["upstream_socket_identity"]["peer"]["ip_version"], 6)

    def test_chunked_response_records_decoded_body_trailers_and_wire_hashes(self) -> None:
        request_wire = b"GET /chunked HTTP/1.1\r\nHost: localhost\r\n\r\n"
        response_wire = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Trailer: X-Checksum\r\n"
            b"Connection: close\r\n\r\n"
            b"5\r\nhello\r\n"
            b"6\r\n world\r\n"
            b"0\r\nX-Checksum: done\r\n\r\n"
        )
        _, result, _ = self._capture(
            request_wire,
            response_wire,
            response_chunks=[7, 3, 11, 2, 5],
            session_id="http-chunked",
        )

        self.assertEqual(result.status, "ok", result.report_section["errors"])
        response = next(
            item for item in result.after_snapshot["messages"]
            if item["kind"] == "http_response"
        )
        self.assertEqual(response["framing"]["type"], "chunked")
        self.assertEqual(response["body_length"], 11)
        self.assertEqual(
            response["body_sha256"], hashlib.sha256(b"hello world").hexdigest()
        )
        self.assertEqual(response["trailers"][0]["name_lower"], "x-checksum")
        self.assertEqual(response["wire_sha256"], hashlib.sha256(response_wire).hexdigest())
        self.assertNotEqual(response["body_wire_sha256"], response["body_sha256"])

    def test_verified_tls_http_capture_and_replay_bind_certificate_identity(self) -> None:
        request_wire = b"GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        response_wire = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntls"
        )
        _, capture_result, _ = self._capture(
            request_wire,
            response_wire,
            tls=True,
            session_id="http-tls-capture",
        )
        self.assertEqual(
            capture_result.status, "ok", capture_result.report_section["errors"]
        )
        tls_evidence = capture_result.after_snapshot["connections"][0]["tls"]
        self.assertTrue(tls_evidence["verify"])
        self.assertTrue(tls_evidence["peer_certificate"]["hostname_verified"])
        self.assertTrue(tls_evidence["peer_certificate"]["subject"])
        self.assertTrue(tls_evidence["peer_certificate"]["issuer"])
        self.assertTrue(tls_evidence["peer_certificate"]["subject_alt_names"])
        self.assertEqual(len(tls_evidence["peer_certificate_sha256"]), 64)
        self.assertTrue(tls_evidence["endpoint_identity"]["certificate_verified"])

        artifact = self._materialize(capture_result, "tls-http-capture")
        server = HttpFixtureServer(
            response_wire,
            tls_context=self._server_tls_context(),
        )
        try:
            replay_plan = self.provider.plan(
                self._replay_request(artifact, server, tls=True)
            )
            validation = self.provider.validate(replay_plan)
            self.assertTrue(validation.ok, validation.errors)
            replay_result = self.provider.execute(replay_plan)
        finally:
            server.close()
        self.assertEqual(replay_result.status, "ok", replay_result.report_section["errors"])
        self.assertTrue(replay_result.after_snapshot["fixture_verified"])
        replay_tls = replay_result.after_snapshot["connections"][0]["tls"]
        self.assertEqual(
            replay_tls["peer_certificate_sha256"],
            tls_evidence["peer_certificate_sha256"],
        )
        self.assertTrue(replay_tls["endpoint_identity"]["certificate_verified"])

    def test_controlled_fixture_file_replays_exact_request_and_response(self) -> None:
        request_wire = b"GET /fixture HTTP/1.1\r\nHost: localhost\r\n\r\n"
        response_wire = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nfixture"
        )
        _, capture_result, _ = self._capture(request_wire, response_wire)
        artifact = self._materialize(capture_result, "http-fixture-source")
        server = HttpFixtureServer(response_wire)
        fixture_path = self.root / "controlled-http-fixture.json"
        fixture_path.write_text(
            json.dumps(
                {
                    "expected_transaction_count": 1,
                    "expected_status_codes": [200],
                    "expected_request_wire_sha256": [
                        hashlib.sha256(request_wire).hexdigest()
                    ],
                    "expected_response_wire_sha256": [
                        hashlib.sha256(response_wire).hexdigest()
                    ],
                    "expected_response_body_sha256": [
                        hashlib.sha256(b"fixture").hexdigest()
                    ],
                    "endpoint": {"host": "127.0.0.1", "port": server.port},
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        try:
            plan = self.provider.plan(
                self._replay_request(
                    artifact,
                    server,
                    http_fixture=str(fixture_path),
                )
            )
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = self.provider.execute(plan)
        finally:
            server.close()

        self.assertEqual(result.status, "ok", result.report_section["errors"])
        self.assertEqual(server.received, [request_wire])
        self.assertTrue(result.after_snapshot["fixture_verified"])
        self.assertTrue(result.after_snapshot["real_socket_evidence"])
        self.assertEqual(
            result.after_snapshot["request_response_pairs"][0][
                "actual_response_wire_sha256"
            ],
            hashlib.sha256(response_wire).hexdigest(),
        )
        fixture_entries = [
            item for item in result.evidence_manifest_entries
            if item.get("role") == "controlled-http-fixture"
        ]
        self.assertEqual(len(fixture_entries), 1)
        self.assertEqual(
            fixture_entries[0]["sha256"], hashlib.sha256(fixture_path.read_bytes()).hexdigest()
        )

    def test_response_mismatch_is_fail_closed(self) -> None:
        request_wire = b"GET /mismatch HTTP/1.1\r\nHost: localhost\r\n\r\n"
        captured_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood"
        )
        mismatched_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nbad"
        )
        _, capture_result, _ = self._capture(request_wire, captured_response)
        artifact = self._materialize(capture_result, "mismatch-source")
        server = HttpFixtureServer(mismatched_response)
        try:
            plan = self.provider.plan(self._replay_request(artifact, server))
            self.assertTrue(self.provider.validate(plan).ok)
            result = self.provider.execute(plan)
        finally:
            server.close()

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.after_snapshot["fixture_verified"])
        self.assertTrue(result.after_snapshot["network_transmit"])
        self.assertIn("did not match", " ".join(result.report_section["errors"]))

    def test_source_budget_gap_and_tamper_fail_before_socket_creation(self) -> None:
        request_wire = b"GET /integrity HTTP/1.1\r\nHost: localhost\r\n\r\n"
        response_wire = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        )
        _, capture_result, _ = self._capture(request_wire, response_wire)
        artifact = self._materialize(capture_result, "integrity-source")
        original = json.loads(artifact.read_text("utf-8"))
        unused_server = HttpFixtureServer(response_wire)
        try:
            mutations: list[tuple[str, Any, dict[str, Any]]] = []
            tampered = json.loads(json.dumps(original))
            tampered["messages"][1]["body_sha256"] = "0" * 64
            mutations.append(("tamper", tampered, {}))
            gap = json.loads(json.dumps(original))
            gap["after_snapshot"]["integrity"]["gap_count"] = 1
            mutations.append(("gap", gap, {}))
            truncated = json.loads(json.dumps(original))
            truncated["after_snapshot"]["integrity"]["truncated"] = True
            mutations.append(("truncated", truncated, {}))
            mutations.append(("budget", original, {"max_frames": 1}))

            for name, payload, limit_overrides in mutations:
                with self.subTest(name=name):
                    source = self.root / f"{name}.json"
                    source.write_text(
                        json.dumps(payload, sort_keys=True), encoding="utf-8"
                    )
                    plan = self.provider.plan(
                        self._replay_request(
                            source,
                            unused_server,
                            limits=limit_overrides,
                        )
                    )
                    validation = self.provider.validate(plan)
                    self.assertFalse(validation.ok)
                    with patch(
                        "reverse_analyzer.providers.protocol_runtime._connect_loopback",
                        side_effect=AssertionError("invalid source opened a socket"),
                    ):
                        result = self.provider.execute(plan)
                    self.assertEqual(result.status, "failed")
                    self.assertFalse(result.provenance["network_transmit"])
                    self.assertEqual(result.after_snapshot["frame_count"], 0)
        finally:
            unused_server.close()

    def test_truncated_and_malformed_http_capture_never_succeeds(self) -> None:
        request_wire = b"GET /broken HTTP/1.1\r\nHost: localhost\r\n\r\n"
        cases = {
            "truncated": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc",
                "truncated",
            ),
            "te_and_cl": (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                b"Content-Length: 1\r\nConnection: close\r\n\r\n0\r\n\r\n",
                "both Transfer-Encoding and Content-Length",
            ),
            "conflicting_cl": (
                b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"
                b"Content-Length: 2\r\nConnection: close\r\n\r\nab",
                "Content-Length values conflict",
            ),
        }
        for name, (response_wire, expected_error) in cases.items():
            with self.subTest(name=name):
                _, result, _ = self._capture(
                    request_wire,
                    response_wire,
                    session_id=f"http-{name}",
                )
                self.assertEqual(result.status, "partial")
                self.assertFalse(result.after_snapshot["real_capture_success"])
                self.assertTrue(result.after_snapshot["integrity"]["fail_closed"])
                self.assertIn(expected_error, " ".join(result.report_section["errors"]))

    def test_remote_and_hostname_http_endpoints_are_rejected_without_sockets(self) -> None:
        base = {
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "upstream_port": 443,
            **self._limits(duration_ms=50, socket_timeout_ms=25),
        }
        for host, allow_remote in (
            ("192.0.2.10", False),
            ("192.0.2.10", True),
            ("localhost", False),
        ):
            with self.subTest(host=host, allow_remote=allow_remote):
                plan = self.provider.plan(
                    CapabilityRequest(
                        capability="protocol_runtime",
                        action="http_capture",
                        target=TargetIdentity(kind="endpoint", display_name=host),
                        params={
                            **base,
                            "upstream_host": host,
                            "allow_remote": allow_remote,
                        },
                        session_id="remote-http-denied",
                    )
                )
                self.assertFalse(self.provider.validate(plan).ok)
                with patch(
                    "reverse_analyzer.providers.protocol_runtime._new_socket",
                    side_effect=AssertionError("denied HTTP endpoint created a socket"),
                ):
                    result = self.provider.execute(plan)
                self.assertEqual(result.status, "failed")
                self.assertFalse(result.provenance["network_transmit"])

    def test_synthetic_capture_runner_cannot_report_production_success(self) -> None:
        request_wire = b"GET /fake HTTP/1.1\r\nHost: localhost\r\n\r\n"
        response_wire = b"HTTP/1.1 204 No Content\r\n\r\n"

        def frame(sequence: int, direction: str, payload: bytes) -> dict[str, Any]:
            digest = hashlib.sha256(payload).hexdigest()
            return {
                "sequence": sequence,
                "connection_id": "connection-1",
                "transport": "tcp",
                "direction": direction,
                "length": len(payload),
                "sha256": digest,
                "payload_base64": base64.b64encode(payload).decode("ascii"),
            }

        fake_outcome = {
            "status": "ok",
            "errors": [],
            "after_snapshot": {
                "session_state": "closed",
                "transport": "tcp",
                "frame_count": 2,
                "frames": [
                    frame(1, "client_to_server", request_wire),
                    frame(2, "server_to_client", response_wire),
                ],
                "connection_count": 1,
                "connections": [
                    {
                        "connection_id": "connection-1",
                        "status": "closed",
                        "client_socket_identity": {
                            "real_socket": False,
                            "synthetic": True,
                        },
                        "upstream_socket_identity": {
                            "real_socket": False,
                            "synthetic": True,
                        },
                    }
                ],
                "forwarded_bytes": len(request_wire) + len(response_wire),
            },
        }
        plan = self.provider.plan(
            CapabilityRequest(
                capability="protocol_runtime",
                action="http_capture",
                target=TargetIdentity(kind="fixture", display_name="synthetic"),
                params={
                    "listen_host": "127.0.0.1",
                    "listen_port": 0,
                    "upstream_host": "127.0.0.1",
                    "upstream_port": 9,
                    **self._limits(),
                },
                session_id="synthetic-http-capture",
            )
        )
        self.assertTrue(self.provider.validate(plan).ok)
        with patch.object(self.provider, "_execute_capture", return_value=fake_outcome):
            result = self.provider.execute(plan)

        self.assertEqual(result.status, "partial")
        self.assertFalse(result.after_snapshot["real_socket_evidence"])
        self.assertFalse(result.after_snapshot["real_capture_success"])

    def test_connect_replay_is_explicitly_partial_not_success(self) -> None:
        request_wire = (
            b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n"
        )
        response_wire = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        _, capture_result, _ = self._capture(
            request_wire,
            response_wire,
            session_id="http-connect-capture",
        )
        self.assertEqual(capture_result.status, "ok")
        self.assertFalse(
            capture_result.after_snapshot["request_response_pairs"][0][
                "replay_supported"
            ]
        )
        artifact = self._materialize(capture_result, "connect-source")
        server = HttpFixtureServer(response_wire)
        try:
            plan = self.provider.plan(self._replay_request(artifact, server))
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = self.provider.execute(plan)
        finally:
            server.close()

        self.assertEqual(result.status, "partial")
        self.assertFalse(result.after_snapshot["network_transmit"])
        self.assertEqual(result.after_snapshot["generalized_replay"], "partial")
        self.assertIn(
            "CONNECT tunnel replay is not generalized",
            result.after_snapshot["generalized_replay_limitations"],
        )
        self.assertFalse(result.after_snapshot["fixture_verified"])


if __name__ == "__main__":
    unittest.main()
