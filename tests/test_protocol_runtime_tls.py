from __future__ import annotations

import hashlib
import json
import os
import queue
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.protocol_runtime import ProtocolRuntimeProvider


_CA_CERT = """-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgICA+kwDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYUHJv
dG9jb2wgUnVudGltZSBUZXN0IENBMB4XDTI1MDEwMTAwMDAwMFoXDTQ1MDEwMTAw
MDAwMFowIzEhMB8GA1UEAwwYUHJvdG9jb2wgUnVudGltZSBUZXN0IENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneVtqofv3REwODdpiiywMsvSpU5J
EVn1qo6nMcW6nCbELb/6ityDGXiZ1rqKcTs30dFgxn7EZAGdzDDOswZ/YLeIEzal
B/qVcrEORzb83j6i7nPq7yiCg4aEmcqq/NpLgGFRYKp9PI2kGMdgtc7yiqyoVjim
HdrBVT3Kg7PgffJE9ez/6qa4PtvFFRd1u3zcFZq+3763LkEWdKcltFChi8jQ3Nd9
E1yvnSbu2xrLUN8yxwA5OFJOBSAaCSpRWWmAd5hFT0ACMHqNjBmeTgzlaE2eeTjp
/+H27NmtK+SEWBbPoxkJ/TyTn1ex6gN6G4//F0JMkqqIMQv0MOnLw9sL9QIDAQAB
o2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4E
FgQUL3r/l/cB6jFUXUXIn3JrNmwvF/swHwYDVR0jBBgwFoAUL3r/l/cB6jFUXUXI
n3JrNmwvF/swDQYJKoZIhvcNAQELBQADggEBAInXiajuAatRKfQFT8yBOIWltY2W
OQsHR5oxX2K6KQz1B0zMoVP34cKvTb2II8AuTs5NN4aqoAlEfP4uuUPxEQ/WFAHc
G0lWvnzHE6MNKE1+EyvY3YgJHvgDQdBDixit5NekvbjI0Fbht7cZRBkyuQgwjsGB
3Wi+F+kx7lptfsM/HomvFu9ib3IT1qzDGnhhC0AcHirGncY1sSwePufr0zi/y2WK
kMMcrMWUEY/5LMf5YoY/LEYAhv27N78w8gH77fwrwGIOvIkbmIEE3u+Wa+82wh8S
kktvdZjzR/jBqfoM9ScXX3HdQby+tw4Jkj/32wfCLk3X1JAb8hG9uQ0LiX0=
-----END CERTIFICATE-----
"""

_SERVER_CERT = """-----BEGIN CERTIFICATE-----
MIIDWDCCAkCgAwIBAgICA+owDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYUHJv
dG9jb2wgUnVudGltZSBUZXN0IENBMB4XDTI1MDEwMTAwMDAwMFoXDTQ1MDEwMTAw
MDAwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAjX6memVaql8bnIBNB+EeztxFwZjK8Vt3Wn8zsBvoQ9Vtbp3d
WEd4iIySFQzFBVPWtDYhOGo+Q164jZPKMofQDePETmS9RKu1CKsbMEFQl5u3G/SV
O4iHLuJLM9ily2EWx/vAt/m7G3xMo8VGn0lvbXF/ikFo5fxhAXyzIZRbs2HAMkku
zlbs8JMPXUhM2sqD+gU8sIWnyl6e+uR/EqzyNFVHp4KS2iBX3R5Vwjb71lWV8SEK
kOj6Vy+ibThuFPz52Wp4etXofSvqjPKSNEOfzj6KRifwvu6qNSlgawdENMWesXIB
lANZG6kRhOOUA2BntOaC1JPhmQs27pFRRBQMNwIDAQABo4GkMIGhMAwGA1UdEwEB
/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCwGA1Ud
EQQlMCOCCWxvY2FsaG9zdIcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATAdBgNVHQ4E
FgQUFbcWgNS8FEKxBkpVqg1i71DTTNMwHwYDVR0jBBgwFoAUL3r/l/cB6jFUXUXI
n3JrNmwvF/swDQYJKoZIhvcNAQELBQADggEBAFAC5UGuwjVzgcyC0R8oawznauNb
o+q4yj1wNNPKHwfD1pU0LydVaJpMpaj+xddSbVHlHm4zpsksNxsS7C8uJfT77pNO
Q+0PxO82Xuw8LdzCpbsJVe/xT7iaam+vXiDVZMcee+N+IPL0imtX+HYNHZhp9qCN
nCTkhG77/z73iWgp3vagrbGzCeR0rTGa2Fol3YLkladWB/hJ7Zk9ys2lWZ8UT0oG
lazddgjiAxhsKXYMBhJAXNEc+n+E/6SqJout8OHQkdXfNqzAOR/+id1W6KjYzeDG
dNvg6MQJRlcngkfJjKrNyEa1LNLore2/82YLic8Nm3Yg4DXid7oTJGiSDVI=
-----END CERTIFICATE-----
"""

_SERVER_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCNfqZ6ZVqqXxuc
gE0H4R7O3EXBmMrxW3dafzOwG+hD1W1und1YR3iIjJIVDMUFU9a0NiE4aj5DXriN
k8oyh9AN48ROZL1Eq7UIqxswQVCXm7cb9JU7iIcu4ksz2KXLYRbH+8C3+bsbfEyj
xUafSW9tcX+KQWjl/GEBfLMhlFuzYcAySS7OVuzwkw9dSEzayoP6BTywhafKXp76
5H8SrPI0VUengpLaIFfdHlXCNvvWVZXxIQqQ6PpXL6JtOG4U/PnZanh61eh9K+qM
8pI0Q5/OPopGJ/C+7qo1KWBrB0Q0xZ6xcgGUA1kbqRGE45QDYGe05oLUk+GZCzbu
kVFEFAw3AgMBAAECggEACJPl+cONNIjhfqJUiSa/nGDEJdFidDFMUgMmGgYHFZ2p
rawKUCC9EOIctQP6KbGEcZZaezYNoj3qyEJuXpPXLBBjxTDcPH6AUg81bb536Uj6
V8qDBYHoWBJF5tW6b1Lqc6MycrTEAA2QA9mgx2VHSQY5aiM+/bpIEzQBFAcPbBdo
2ZNz2pKigHUriR8ACwMMhijS5lsr86gFty1buUGrkC6O+zSeKEXZkeKsCklpxMkg
bNd+awnQkpkSEq0GFyhPqUo/RWHwCaF5QIxUGZiiYGWV0cb4PhMe1dxTTSI6RuCp
9wVgnZm9SfLDInkJNztTbBx2bnOQm+YgG8nZv0ZBcQKBgQDIE9MjtJzhXD3yRo9T
V/8gfW38j5/S9qHrS4WoFT4S3bBgUVGql+EZRp+PJS2A88ezZ/ftl4xlEIgHVT6d
zM+c8rDk31nL7ji7gdORZ0e5aiWoUruGsHWpadHVOkqYemK5WjyZUAWt+m5qfuWg
mtGofTxN8woLVGmsznhXQqehXwKBgQC1Cwv0rO3Ymv2MBubG/j7zSsKchEB4sjuM
4eH4plsqvKMGR9kPHr4xAlf9pL1xdvRjJmMWfwyUeedJ7AZkunV6LjBsQvARPuOI
m0oA/7YeYgmpe4YO4NRQLerEYQd0DKxtIBg93msmivarEVJQ82FHNiA3ZkZOJtCT
mlVRTo1MKQKBgQCFDRn1vqAtBah0OxQI+pXAx2ii8ef45OZckMZ7NlUnOqGWC73h
UkrxAhQNn02ZWYRN/C/VolhMxSeQqNGRIqhV2NZl/Vm70dmMaBOHuETsOnh8bTgj
o6k7VhGiWLdOmuSYGjf+REbioY1X6LdPjGUsRMwbkin1ytbTgiJo9PyAxQKBgBJQ
qcb4757oHxpZYGNlOS0XtRRsdLFBJrEb8OZcvgBW0Q9DmXvkGk2O9SPd1KRz6klV
itStybIDmxhpXkQ2cMgJgDCTnQHBoPci7punQt9T/7I7otZCfHgYDRYM0to0pgTs
KEeqBqEBke7Ac9lopcC0gxHXsOkbGCK2jEcLcVPxAoGBAIhUvxEVww2KqgxJNjRj
IKdUg/ucB+FtDwk/JY579FkBDLOE90PgOO6oWG8w7VZph9htqCSVoSCB1QZtghgS
/a1u1v3ApBguonRz1Mo/tsXWeopvOUjGvoBMbcfU4IuXBqLJT8bf9zHHEYdRfozp
1QiUf+0m7ko9Xms2u9Hjbvee
-----END PRIVATE KEY-----
"""


class TlsEchoFixture:
    def __init__(self, cert_file: Path, key_file: Path) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert_file), str(key_file))
        self._context = context
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = int(self.listener.getsockname()[1])
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self.listener.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                connection = self._context.wrap_socket(raw, server_side=True)
            except (OSError, ssl.SSLError):
                raw.close()
                continue
            with connection:
                connection.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        data = connection.recv(16 * 1024)
                    except socket.timeout:
                        continue
                    except (OSError, ssl.SSLError):
                        break
                    if not data:
                        break
                    self.received.append(data)
                    try:
                        connection.sendall(data)
                    except (OSError, ssl.SSLError):
                        break


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    received = bytearray()
    while len(received) < length:
        chunk = connection.recv(length - len(received))
        if not chunk:
            break
        received.extend(chunk)
    return bytes(received)


class ProtocolRuntimeTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ca_file = self.root / "test-ca.pem"
        self.cert_file = self.root / "server.pem"
        self.key_file = self.root / "server-key.pem"
        self.ca_file.write_text(_CA_CERT, encoding="ascii")
        self.cert_file.write_text(_SERVER_CERT, encoding="ascii")
        self.key_file.write_text(_SERVER_KEY, encoding="ascii")
        self.provider = ProtocolRuntimeProvider()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def _capture_tls(
        self,
        server: TlsEchoFixture,
        *,
        session_id: str = "tls-capture-session",
        artifact_root: Path | None = None,
    ) -> tuple[Path, Any]:
        request = CapabilityRequest(
            capability="protocol_runtime",
            action="loopback_tcp_proxy_capture",
            target=TargetIdentity(
                kind="tls-endpoint",
                display_name=f"tls://localhost:{server.port}",
            ),
            params={
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "upstream_host": "127.0.0.1",
                "upstream_port": server.port,
                "duration_ms": 1_000,
                "socket_timeout_ms": 500,
                "max_bytes": 4_096,
                "max_frames": 8,
                "max_connections": 1,
                "tls": {
                    "enabled": True,
                    "verify": True,
                    "server_hostname": "localhost",
                    "ca_file": str(self.ca_file),
                    "client_key_password": "must-not-be-recorded",
                },
            },
            session_id=session_id,
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
        with socket.create_connection((str(endpoint["host"]), int(endpoint["port"]))) as client:
            client.settimeout(1)
            client.sendall(b"tls-ping")
            self.assertEqual(_recv_exact(client, 8), b"tls-ping")
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        result = outcome["result"]
        self.assertEqual(result.status, "ok", result.report_section.get("errors"))
        tls_evidence = result.after_snapshot["connections"][0]["tls"]
        self.assertTrue(tls_evidence["handshake"]["completed"])
        self.assertTrue(tls_evidence["negotiated_version"].startswith("TLSv1."))
        self.assertEqual(len(tls_evidence["peer_certificate_sha256"]), 64)
        visibility = result.after_snapshot["traffic_visibility"]
        self.assertEqual(
            visibility["application_bytes"],
            "visible_at_provider_managed_tls_endpoint",
        )
        self.assertFalse(visibility["wire_tls_records_captured"])
        self.assertEqual(
            visibility["decryption"]["scope"],
            "provider_terminated_connection_only",
        )
        self.assertFalse(
            visibility["decryption"]["unmanaged_or_external_sessions_supported"]
        )
        self.assertFalse(
            visibility["decryption"]["private_or_session_keys_recorded"]
        )

        collection_root = artifact_root or (self.root / "capture")
        bundle = self.provider.collect_artifacts(result, str(collection_root))
        artifact_path = collection_root / bundle.artifacts[0].path
        artifact_text = artifact_path.read_text("utf-8")
        self.assertNotIn(str(self.ca_file), artifact_text)
        self.assertNotIn("must-not-be-recorded", artifact_text)
        artifact = json.loads(artifact_text)
        tls_parameters = artifact["report_section"]["parameters"]["tls"]
        self.assertTrue(tls_parameters["ca_file_configured"])
        self.assertNotIn("ca_file", tls_parameters)
        return artifact_path, result

    @unittest.skipUnless(
        os.environ.get("RUN_PROTOCOL_RUNTIME_LIVE") == "1",
        "set RUN_PROTOCOL_RUNTIME_LIVE=1 to retain bounded live protocol evidence",
    )
    def test_acceptance_runner_retains_live_protocol_artifacts(self) -> None:
        configured = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or ""
        ).strip()
        if not configured:
            self.skipTest("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR is required")

        root = Path(configured).expanduser().resolve()
        session_id = str(
            os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_SESSION_ID")
            or "p6-protocol-runtime-loopback"
        )
        server = TlsEchoFixture(self.cert_file, self.key_file)
        try:
            artifact_path, capture_result = self._capture_tls(
                server,
                session_id="capture",
                artifact_root=root,
            )
            replay_request = self._session_replay_request(
                artifact_path,
                port=server.port,
                session_id="replay",
            )
            replay_plan = self.provider.plan(replay_request)
            replay_validation = self.provider.validate(replay_plan)
            self.assertTrue(replay_validation.ok, replay_validation.errors)
            replay_result = self.provider.execute(replay_plan)
            self.assertEqual(replay_result.status, "ok", replay_result.report_section)
            self.provider.collect_artifacts(replay_result, str(root))

            capture_rollback = self.provider.rollback(capture_result)
            replay_rollback = self.provider.rollback(replay_result)
            self.assertTrue(capture_rollback.ok)
            self.assertTrue(replay_rollback.ok)

            evidence = root / "protocol-runtime"
            evidence.mkdir(parents=True, exist_ok=True)
            executable = Path(sys.executable).resolve()
            target_identity = {
                "kind": "controlled_loopback_tls_fixture",
                "path": str(executable),
                "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                "host": "127.0.0.1",
                "transport": "tcp+tls",
                "application_protocol": "opaque_echo",
                "acceptance_session_id": session_id,
            }
            (evidence / "target-identity.json").write_text(
                json.dumps(target_identity, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            (evidence / "rollback.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "verified": bool(capture_rollback.ok and replay_rollback.ok),
                        "target_mutated": False,
                        "capture": capture_rollback.to_dict(),
                        "replay": replay_rollback.to_dict(),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            (evidence / "execution-proof.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "provider": replay_result.provider,
                        "evidence_class": "live_host_proof",
                        "executed_tests": 1,
                        "skipped_tests": 0,
                        "live_operations": 2,
                        "actions": [capture_result.action, replay_result.action],
                        "real_socket_evidence": bool(
                            capture_result.after_snapshot.get("real_socket_evidence")
                            and replay_result.after_snapshot.get("real_socket_evidence")
                        ),
                        "tls_verify": True,
                        "certificate_pin_matched": bool(
                            replay_result.after_snapshot["connections"][0][
                                "tls_identity_binding"
                            ]["certificate_pin_matched"]
                        ),
                        "source_order_preserved": bool(
                            replay_result.after_snapshot.get("source_order_preserved")
                        ),
                        "synthetic": False,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        finally:
            server.close()

    def _session_replay_request(
        self,
        artifact_path: Path,
        *,
        port: int,
        session_id: str,
        server_hostname: str = "localhost",
    ) -> CapabilityRequest:
        artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        return CapabilityRequest(
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
                "destination_port": port,
                "replay_mode": "session",
                "timing_scale": 0,
                "verify_echo": True,
                "duration_ms": 2_000,
                "socket_timeout_ms": 500,
                "max_bytes": 4_096,
                "max_frames": 8,
                "max_connections": 1,
                "tls_enabled": True,
                "tls_verify": True,
                "tls_server_hostname": server_hostname,
                "tls_ca_file": str(self.ca_file),
            },
            session_id=session_id,
        )

    def test_real_tls_capture_and_ordered_session_replay(self) -> None:
        server = TlsEchoFixture(self.cert_file, self.key_file)
        try:
            artifact_path, capture_result = self._capture_tls(server)
            replay_request = self._session_replay_request(
                artifact_path,
                port=server.port,
                session_id="tls-session-replay",
            )
            replay_plan = self.provider.plan(replay_request)
            replay_validation = self.provider.validate(replay_plan)
            self.assertTrue(replay_validation.ok, replay_validation.errors)
            replay_result = self.provider.execute(replay_plan)

            self.assertEqual(
                replay_result.status,
                "ok",
                replay_result.report_section.get("errors"),
            )
            after = replay_result.after_snapshot
            self.assertEqual(after["replay_mode"], "session")
            self.assertTrue(after["source_order_preserved"])
            self.assertEqual(after["processed_source_frame_count"], len(capture_result.after_snapshot["frames"]))
            self.assertEqual(
                [frame["direction"] for frame in after["frames"]],
                ["client_to_server", "server_to_client"],
            )
            self.assertEqual(after["sent_bytes"], 8)
            self.assertEqual(after["received_bytes"], 8)
            self.assertIn("negotiated_version", after["connections"][0]["tls"])
            socket_identity = after["connections"][0]["socket_identity"]
            self.assertTrue(socket_identity["real_socket"])
            self.assertTrue(socket_identity["local"]["loopback"])
            self.assertEqual(socket_identity["peer"]["port"], server.port)
            binding = after["connections"][0]["tls_identity_binding"]
            self.assertTrue(binding["certificate_pin_required"])
            self.assertTrue(binding["certificate_pin_matched"])
            self.assertTrue(binding["identity_check_completed"])
            self.assertEqual(
                binding["application_data_release"],
                "allowed_after_identity_check",
            )
            self.assertTrue(after["real_socket_evidence"])
            self.assertEqual(
                replay_result.provenance["traffic_visibility"]["decryption"]["scope"],
                "provider_terminated_connection_only",
            )
        finally:
            server.close()

    def test_tls_replay_certificate_pin_mismatch_blocks_application_bytes(self) -> None:
        server = TlsEchoFixture(self.cert_file, self.key_file)
        try:
            artifact_path, _ = self._capture_tls(server)
            payload = json.loads(artifact_path.read_text("utf-8"))
            replacement_hash = "0" * 64
            for container in (
                payload["after_snapshot"],
                payload["report_section"]["after_snapshot"],
            ):
                tls = container["connections"][0]["tls"]
                self.assertNotEqual(tls["peer_certificate_sha256"], replacement_hash)
                tls["peer_certificate_sha256"] = replacement_hash
                tls["peer_certificate"]["sha256"] = replacement_hash
                tls["endpoint_identity"]["certificate_sha256"] = replacement_hash
            mismatched_artifact = self.root / "different-source-certificate.json"
            mismatched_artifact.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            received_before_replay = list(server.received)
            request = self._session_replay_request(
                mismatched_artifact,
                port=server.port,
                session_id="tls-certificate-pin-mismatch",
            )
            plan = self.provider.plan(request)
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)

            result = self.provider.execute(plan)

            self.assertEqual(result.status, "failed")
            self.assertEqual(result.after_snapshot["sent_bytes"], 0)
            self.assertFalse(result.after_snapshot["side_effects"])
            binding = result.after_snapshot["connections"][0][
                "tls_identity_binding"
            ]
            self.assertTrue(binding["certificate_pin_required"])
            self.assertFalse(binding["certificate_pin_matched"])
            self.assertFalse(binding["identity_check_completed"])
            self.assertEqual(binding["application_data_release"], "blocked")
            self.assertIn(
                "does not match the source capture",
                " ".join(result.report_section["errors"]),
            )
            self.assertEqual(server.received, received_before_replay)
        finally:
            server.close()

    def test_tls_hostname_failure_occurs_before_application_replay(self) -> None:
        server = TlsEchoFixture(self.cert_file, self.key_file)
        try:
            artifact_path, _ = self._capture_tls(server)
            received_before_replay = list(server.received)
            request = self._session_replay_request(
                artifact_path,
                port=server.port,
                session_id="tls-hostname-mismatch",
                server_hostname="wrong-hostname.invalid",
            )
            plan = self.provider.plan(request)
            validation = self.provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)

            result = self.provider.execute(plan)

            self.assertEqual(result.status, "failed")
            self.assertEqual(result.after_snapshot["sent_bytes"], 0)
            self.assertFalse(result.after_snapshot["side_effects"])
            self.assertIn(
                "certificate verify failed",
                " ".join(result.report_section["errors"]).lower(),
            )
            self.assertEqual(server.received, received_before_replay)
        finally:
            server.close()

    def test_remote_endpoint_is_default_deny_and_audited_when_opted_in(self) -> None:
        base_params = {
            "listen_host": "127.0.0.1",
            "listen_port": 0,
            "upstream_host": "192.0.2.10",
            "upstream_port": 443,
            "duration_ms": 50,
            "socket_timeout_ms": 25,
            "max_bytes": 1_024,
            "max_frames": 4,
            "max_connections": 1,
        }
        denied = self.provider.plan(
            CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_tcp_proxy_capture",
                target=TargetIdentity(kind="endpoint", display_name="remote-denied"),
                params=base_params,
                session_id="remote-denied",
            )
        )
        denied_validation = self.provider.validate(denied)
        self.assertFalse(denied_validation.ok)
        self.assertIn("allow_remote=true", " ".join(denied_validation.errors))

        allowed = self.provider.plan(
            CapabilityRequest(
                capability="protocol_runtime",
                action="loopback_tcp_proxy_capture",
                target=TargetIdentity(kind="endpoint", display_name="remote-opt-in"),
                params={**base_params, "allow_remote": True},
                session_id="remote-opt-in",
            )
        )
        self.assertTrue(self.provider.validate(allowed).ok)
        self.assertTrue(allowed.provenance["remote_access_opt_in"])
        self.assertEqual(allowed.provenance["target_endpoint"]["host"], "192.0.2.10")
        result = self.provider.execute(allowed)
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.report_section["parameters"]["allow_remote"])
        self.assertEqual(
            result.dashboard_trace[0]["network_boundary"],
            "explicit_ip_remote_opt_in",
        )


if __name__ == "__main__":
    unittest.main()
