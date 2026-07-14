from __future__ import annotations

import base64
import hashlib
import json
import queue
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import validate_capability_audit_record
from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import build_default_registry
from reverse_analyzer.providers.protocol_runtime import (
    ProtocolRuntimeMockProvider,
    ProtocolRuntimeProvider,
)


class LoopbackEchoFixture:
    def __init__(self, host: str = "127.0.0.1") -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
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
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        data = connection.recv(16 * 1024)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        self.errors.append(str(exc))
                        break
                    if not data:
                        break
                    self.received.append(data)
                    try:
                        connection.sendall(data)
                    except OSError as exc:
                        self.errors.append(str(exc))
                        break


class LoopbackUdpEchoFixture:
    def __init__(self, host: str = "127.0.0.1") -> None:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        self.socket.bind((host, 0))
        self.socket.settimeout(0.1)
        self.port = int(self.socket.getsockname()[1])
        self.received: list[bytes] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self.socket.close()
        except OSError:
            pass
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self.socket.recvfrom(65_535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.received.append(data)
            try:
                self.socket.sendto(data, peer)
            except OSError as exc:
                self.errors.append(str(exc))
                break


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = connection.recv(length - len(payload))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _unused_loopback_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


def _unused_udp_loopback_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()
    return port


class ProtocolRuntimeProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.provider = ProtocolRuntimeProvider()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _capture_request(
        self,
        upstream_port: int,
        *,
        session_id: str = "capture-session",
        params: dict[str, Any] | None = None,
    ) -> CapabilityRequest:
        values: dict[str, Any] = {
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "upstream_host": "127.0.0.1",
            "upstream_port": upstream_port,
            "duration_ms": 3_000,
            "socket_timeout_ms": 500,
            "max_bytes": 4_096,
            "max_frames": 16,
            "max_connections": 1,
        }
        values.update(params or {})
        return CapabilityRequest(
            capability="protocol_runtime",
            action="loopback_tcp_proxy_capture",
            target=TargetIdentity(
                kind="loopback-endpoint",
                display_name=f"127.0.0.1:{upstream_port}",
            ),
            params=values,
            session_id=session_id,
            provenance={"test_case": self.id()},
        )

    def _execute_capture(
        self,
        request: CapabilityRequest,
        payload: bytes,
        expected_response: bytes,
    ) -> tuple[Any, Any, Any]:
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
        with socket.create_connection(
            (str(endpoint["host"]), int(endpoint["port"])),
            timeout=1,
        ) as client:
            client.settimeout(1)
            client.sendall(payload)
            self.assertEqual(_recv_exact(client, len(expected_response)), expected_response)
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive(), "capture provider did not respect duration bounds")
        return plan, validation, outcome["result"]

    def _materialize_capture(self) -> tuple[Path, Any, Any, Any]:
        echo = LoopbackEchoFixture()
        try:
            plan, validation, result = self._execute_capture(
                self._capture_request(
                    echo.port,
                    params={
                        "mutation": {
                            "direction": "client_to_server",
                            "find_hex": b"ping".hex(),
                            "replace_hex": b"pong".hex(),
                            "max_replacements": 1,
                        }
                    },
                ),
                b"ping",
                b"pong",
            )
            self.assertEqual(result.status, "ok")
            self.assertEqual(b"".join(echo.received), b"pong")
            rollback = self.provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertFalse(rollback.restored)
            bundle = self.provider.collect_artifacts(result, str(self.root / "capture"))
            artifact_path = self.root / "capture" / bundle.artifacts[0].path
            self.assertTrue(artifact_path.is_file())
            return artifact_path, plan, validation, result
        finally:
            echo.close()

    def _materialize_udp_capture(self) -> tuple[Path, Any, Any, Any]:
        echo = LoopbackUdpEchoFixture()
        try:
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_udp_proxy_capture",
                target=TargetIdentity(
                    kind="loopback-endpoint",
                    display_name=f"udp://127.0.0.1:{echo.port}",
                ),
                params={
                    "listen_host": "127.0.0.1",
                    "listen_port": 0,
                    "upstream_host": "127.0.0.1",
                    "upstream_port": echo.port,
                    "duration_ms": 250,
                    "socket_timeout_ms": 200,
                    "max_bytes": 4_096,
                    "max_frames": 8,
                    "max_connections": 1,
                    "mutation": {
                        "direction": "client_to_server",
                        "find_hex": b"ping".hex(),
                        "replace_hex": b"pong".hex(),
                        "max_replacements": 1,
                    },
                },
                session_id="udp-capture-session",
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
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                client.sendto(b"ping", (str(endpoint["host"]), int(endpoint["port"])))
                response, _ = client.recvfrom(1_024)
                self.assertEqual(response, b"pong")
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), "UDP capture did not respect duration bounds")
            result = outcome["result"]
            self.assertEqual(result.status, "ok", result.report_section.get("errors"))
            self.assertEqual(b"".join(echo.received), b"pong")
            bundle = self.provider.collect_artifacts(result, str(self.root / "udp-capture"))
            artifact_path = self.root / "udp-capture" / bundle.artifacts[0].path
            self.assertTrue(artifact_path.is_file())
            return artifact_path, plan, validation, result
        finally:
            echo.close()

    def test_real_loopback_capture_mutation_audit_and_artifact(self) -> None:
        artifact_path, plan, validation, result = self._materialize_capture()

        frames = result.after_snapshot["frames"]
        self.assertEqual([item["direction"] for item in frames], [
            "client_to_server",
            "server_to_client",
        ])
        outbound = frames[0]
        self.assertEqual(outbound["connection_id"], "connection-1")
        self.assertEqual(outbound["length"], 4)
        self.assertEqual(outbound["sha256"], hashlib.sha256(b"pong").hexdigest())
        self.assertEqual(base64.b64decode(outbound["payload_base64"]), b"pong")
        self.assertTrue(outbound["mutation"]["applied"])
        self.assertEqual(
            base64.b64decode(outbound["observed_payload_base64"]),
            b"ping",
        )
        self.assertEqual(
            base64.b64decode(outbound["payload_base64"]),
            b"pong",
        )
        self.assertEqual(outbound["mutation"]["before"]["length"], 4)
        self.assertEqual(outbound["mutation"]["after"]["length"], 4)
        payload = json.loads(artifact_path.read_text("utf-8"))
        self.assertEqual(payload["action"], "loopback_tcp_proxy_capture")
        self.assertEqual(len(payload["frames"]), 2)
        self.assertTrue(result.evidence_manifest_entries[0]["materialized"])
        self.assertEqual(
            result.evidence_manifest_entries[0]["sha256"],
            hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
        )

        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_real_ipv6_loopback_tcp_capture(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 sockets are unavailable")
        try:
            echo = LoopbackEchoFixture("::1")
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is unavailable: {exc}")
        try:
            request = self._capture_request(
                echo.port,
                session_id="ipv6-capture-session",
                params={"listen_host": "::1", "upstream_host": "::1"},
            )
            plan, validation, result = self._execute_capture(request, b"ipv6", b"ipv6")

            self.assertTrue(validation.ok, validation.errors)
            self.assertEqual(result.status, "ok", result.report_section.get("errors"))
            self.assertEqual(plan.parameters["listen_endpoint"]["host"], "::1")
            self.assertEqual(plan.parameters["upstream_endpoint"]["host"], "::1")
            self.assertEqual(b"".join(echo.received), b"ipv6")
        finally:
            echo.close()

    def test_real_ipv6_loopback_udp_capture(self) -> None:
        if not socket.has_ipv6:
            self.skipTest("IPv6 sockets are unavailable")
        try:
            echo = LoopbackUdpEchoFixture("::1")
        except OSError as exc:
            self.skipTest(f"IPv6 loopback is unavailable: {exc}")
        try:
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_udp_proxy_capture",
                target=TargetIdentity(
                    kind="loopback-endpoint",
                    display_name=f"udp://[::1]:{echo.port}",
                ),
                params={
                    "listen_host": "::1",
                    "listen_port": 0,
                    "upstream_host": "::1",
                    "upstream_port": echo.port,
                    "duration_ms": 250,
                    "socket_timeout_ms": 200,
                    "max_bytes": 4_096,
                    "max_frames": 8,
                    "max_connections": 1,
                },
                session_id="ipv6-udp-capture-session",
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
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                client.sendto(b"ipv6-udp", (str(endpoint["host"]), int(endpoint["port"])))
                response, _ = client.recvfrom(1_024)
                self.assertEqual(response, b"ipv6-udp")
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), "IPv6 UDP capture exceeded its duration bound")
            result = outcome["result"]
            self.assertEqual(result.status, "ok", result.report_section.get("errors"))
            self.assertEqual(b"".join(echo.received), b"ipv6-udp")
        finally:
            echo.close()

    def test_real_loopback_udp_capture_mutation_audit_and_artifact(self) -> None:
        artifact_path, plan, validation, result = self._materialize_udp_capture()

        frames = result.after_snapshot["frames"]
        self.assertEqual([item["direction"] for item in frames], [
            "client_to_server",
            "server_to_client",
        ])
        self.assertEqual({item["transport"] for item in frames}, {"udp"})
        self.assertEqual(base64.b64decode(frames[0]["observed_payload_base64"]), b"ping")
        self.assertEqual(base64.b64decode(frames[0]["payload_base64"]), b"pong")
        self.assertTrue(frames[0]["mutation"]["applied"])
        payload = json.loads(artifact_path.read_text("utf-8"))
        self.assertEqual(payload["action"], "loopback_udp_proxy_capture")
        self.assertEqual(payload["report_section"]["frame_summary"]["transport"], "udp")

        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result,
        )
        contract = validate_capability_audit_record(record)
        self.assertTrue(contract.ok, contract.errors)

    def test_replay_reads_capture_artifact_and_uses_real_loopback_echo(self) -> None:
        artifact_path, _, _, _ = self._materialize_capture()
        artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        echo = LoopbackEchoFixture()
        try:
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="replay",
                target=TargetIdentity(
                    kind="protocol-capture",
                    path=str(artifact_path),
                    sha256=artifact_hash,
                ),
                params={
                    "capture_artifact": str(artifact_path),
                    "destination_host": "127.0.0.1",
                    "destination_port": echo.port,
                    "frame_direction": "client_to_server",
                    "verify_echo": True,
                    "duration_ms": 2_000,
                    "socket_timeout_ms": 500,
                    "max_bytes": 4_096,
                    "max_frames": 16,
                    "max_connections": 1,
                },
                session_id="replay-session",
                provenance={"test_case": self.id()},
            )
            plan = self.provider.plan(request)
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = self.provider.execute(plan)

            self.assertEqual(result.status, "ok", result.report_section.get("errors"))
            self.assertEqual(result.after_snapshot["sent_bytes"], 4)
            self.assertEqual(result.after_snapshot["received_bytes"], 4)
            self.assertEqual(b"".join(echo.received), b"pong")
            self.assertTrue(result.after_snapshot["connections"][0]["echo_verified"])
            socket_identity = result.after_snapshot["connections"][0]["socket_identity"]
            self.assertTrue(socket_identity["real_socket"])
            self.assertTrue(socket_identity["local"]["loopback"])
            self.assertTrue(socket_identity["peer"]["loopback"])
            self.assertEqual(socket_identity["peer"]["host"], "127.0.0.1")
            self.assertEqual(socket_identity["peer"]["port"], echo.port)
            self.assertTrue(result.after_snapshot["real_socket_evidence"])
            self.assertEqual(
                {item["direction"] for item in result.after_snapshot["frames"]},
                {"client_to_server", "server_to_client"},
            )
            source_entries = [
                item
                for item in result.evidence_manifest_entries
                if item.get("role") == "replay-source"
            ]
            self.assertEqual(source_entries[0]["sha256"], artifact_hash)
            rollback = self.provider.rollback(result)
            self.assertTrue(rollback.ok)
            bundle = self.provider.collect_artifacts(result, str(self.root / "replay"))
            self.assertTrue((self.root / "replay" / bundle.artifacts[0].path).is_file())

            record = CapabilityAuditBuilder().build_record(
                plan=plan,
                validation=validation,
                result=result,
            )
            contract = validate_capability_audit_record(record)
            self.assertTrue(contract.ok, contract.errors)
        finally:
            echo.close()

    def test_udp_replay_uses_capture_artifact_and_real_datagram_echo(self) -> None:
        artifact_path, _, _, _ = self._materialize_udp_capture()
        artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        echo = LoopbackUdpEchoFixture()
        try:
            request = CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_udp_replay",
                target=TargetIdentity(
                    kind="protocol-capture",
                    path=str(artifact_path),
                    sha256=artifact_hash,
                ),
                params={
                    "capture_artifact": str(artifact_path),
                    "destination_host": "127.0.0.1",
                    "destination_port": echo.port,
                    "frame_direction": "client_to_server",
                    "verify_echo": True,
                    "duration_ms": 2_000,
                    "socket_timeout_ms": 500,
                    "max_bytes": 4_096,
                    "max_frames": 8,
                    "max_connections": 1,
                },
                session_id="udp-replay-session",
                provenance={"test_case": self.id()},
            )
            plan = self.provider.plan(request)
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)
            result = self.provider.execute(plan)

            self.assertEqual(result.status, "ok", result.report_section.get("errors"))
            self.assertEqual(result.after_snapshot["transport"], "udp")
            self.assertEqual(result.after_snapshot["sent_bytes"], 4)
            self.assertEqual(result.after_snapshot["received_bytes"], 4)
            self.assertEqual(b"".join(echo.received), b"pong")
            self.assertTrue(result.after_snapshot["connections"][0]["echo_verified"])
            self.assertEqual(
                {item["transport"] for item in result.after_snapshot["frames"]},
                {"udp"},
            )
            bundle = self.provider.collect_artifacts(result, str(self.root / "udp-replay"))
            self.assertTrue((self.root / "udp-replay" / bundle.artifacts[0].path).is_file())

            record = CapabilityAuditBuilder().build_record(
                plan=plan,
                validation=validation,
                result=result,
            )
            contract = validate_capability_audit_record(record)
            self.assertTrue(contract.ok, contract.errors)
        finally:
            echo.close()

    def test_non_loopback_and_hostname_endpoints_fail_closed(self) -> None:
        request = self._capture_request(
            12345,
            params={
                "listen_host": "localhost",
                "upstream_host": "8.8.8.8",
            },
        )
        plan = self.provider.plan(request)
        validation = self.provider.validate(plan)

        self.assertFalse(validation.ok)
        self.assertIn("IP literal", " ".join(validation.errors))
        self.assertIn("127.0.0.0/8", " ".join(validation.errors))
        result = self.provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["status"], "failed")
        self.assertEqual(result.dashboard_trace[-1]["status"], "failed")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertEqual(result.after_snapshot["session_state"], "closed")

    def test_replay_artifact_precondition_detects_tampering(self) -> None:
        artifact_path, _, _, _ = self._materialize_capture()
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="replay",
            target=TargetIdentity(kind="artifact", path=str(artifact_path)),
            params={
                "capture_artifact": str(artifact_path),
                "destination_host": "127.0.0.1",
                "destination_port": _unused_loopback_port(),
                "max_bytes": 4_096,
                "max_frames": 16,
            },
            session_id="tamper-session",
        )
        plan = self.provider.plan(request)
        artifact_path.write_bytes(artifact_path.read_bytes() + b" ")
        validation = self.provider.validate(plan)

        self.assertFalse(validation.ok)
        self.assertIn("changed after planning", " ".join(validation.errors))
        result = self.provider.execute(plan)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.after_snapshot["frame_count"], 0)

    def test_unreachable_loopback_replay_reports_failed(self) -> None:
        artifact_path, _, _, _ = self._materialize_capture()
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="replay",
            target=TargetIdentity(kind="artifact", path=str(artifact_path)),
            params={
                "capture_artifact": str(artifact_path),
                "destination_host": "127.0.0.1",
                "destination_port": _unused_loopback_port(),
                "duration_ms": 500,
                "socket_timeout_ms": 100,
                "max_bytes": 4_096,
                "max_frames": 16,
            },
            session_id="failed-replay-session",
        )
        plan = self.provider.plan(request)
        self.assertTrue(self.provider.validate(plan).ok)
        result = self.provider.execute(plan)

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.report_section["status"], "failed")
        self.assertEqual(result.dashboard_trace[-1]["status"], "failed")
        self.assertEqual(result.after_snapshot["session_state"], "closed")
        self.assertFalse(result.after_snapshot["side_effects"])
        self.assertTrue(result.report_section["errors"])
        bundle = self.provider.collect_artifacts(result, str(self.root / "failed"))
        artifact_path = self.root / "failed" / bundle.artifacts[0].path
        self.assertTrue(artifact_path.is_file())
        artifact = json.loads(artifact_path.read_text("utf-8"))
        self.assertEqual(artifact["status"], "failed")
        self.assertEqual(artifact["report_section"]["status"], "failed")

    def test_registry_prefers_production_provider_before_mock(self) -> None:
        registry = build_default_registry()
        providers = registry.list_providers("protocol_runtime")

        self.assertEqual(
            providers,
            ["local_loopback_protocol_runtime", "mock_protocol_runtime"],
        )
        self.assertIsInstance(registry.resolve("protocol_runtime"), ProtocolRuntimeProvider)
        self.assertIsInstance(
            registry.resolve("protocol_runtime", preferred="mock_protocol_runtime"),
            ProtocolRuntimeMockProvider,
        )


if __name__ == "__main__":
    unittest.main()
