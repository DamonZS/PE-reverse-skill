from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core.capabilities.models import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers.dma_memory import (
    DMAMemoryProvider,
    LeechCorePythonAdapter,
    MemProcFSVFSAdapter,
    OfflinePhysicalMemoryAdapter,
    UnavailableDMAMemoryAdapter,
)


_PAGE_SIZE = 0x1000
_PID = 4242
_DTB = 0x1000
_VIRTUAL_ADDRESS = 0x00400FF0
_PAYLOAD = b"offline-page-table-snapshot-proof"


def _write_entry(image: bytearray, table: int, index: int, value: int) -> None:
    struct.pack_into("<Q", image, table + index * 8, value)


def _build_physical_fixture(path: Path) -> dict[str, int | str]:
    image = bytearray(0xB000)
    pml4 = _DTB
    pdpt = 0x2000
    pd = 0x3000
    pt = 0x4000
    first_data_page = 0x8000
    second_data_page = 0x9000
    present_rw_user = 0x7

    _write_entry(image, pml4, (_VIRTUAL_ADDRESS >> 39) & 0x1FF, pdpt | present_rw_user)
    _write_entry(image, pdpt, (_VIRTUAL_ADDRESS >> 30) & 0x1FF, pd | present_rw_user)
    _write_entry(image, pd, (_VIRTUAL_ADDRESS >> 21) & 0x1FF, pt | present_rw_user)
    first_pt_index = (_VIRTUAL_ADDRESS >> 12) & 0x1FF
    _write_entry(image, pt, first_pt_index, first_data_page | present_rw_user)
    _write_entry(image, pt, first_pt_index + 1, second_data_page | present_rw_user)

    split = _PAGE_SIZE - (_VIRTUAL_ADDRESS & (_PAGE_SIZE - 1))
    image[first_data_page + (_VIRTUAL_ADDRESS & 0xFFF) : first_data_page + 0x1000] = _PAYLOAD[:split]
    image[second_data_page : second_data_page + len(_PAYLOAD) - split] = _PAYLOAD[split:]
    path.write_bytes(image)
    return {
        "pid": _PID,
        "dtb": _DTB,
        "name": "fixture.exe",
        "image_path": r"C:\\fixtures\\fixture.exe",
        "identity_verified": True,
    }


def _target() -> TargetIdentity:
    return TargetIdentity(
        kind="process",
        pid=_PID,
        display_name="fixture.exe",
        metadata={
            "pid": _PID,
            "process_name": "fixture.exe",
            "dtb": hex(_DTB),
        },
    )


def _request(action: str, **params: object) -> CapabilityRequest:
    return CapabilityRequest(
        capability="dma_memory",
        action=action,
        target=_target(),
        params=dict(params),
        session_id=f"dma-{action}-fixture",
        provenance={"fixture": "offline-x64-four-level-page-table"},
    )


def _virtual_allowlist(start: int, size: int) -> dict[str, list[list[int]]]:
    return {"virtual": [[start, start + size]]}


class DMAMemoryProviderTests(unittest.TestCase):
    def _offline_provider(
        self,
        root: Path,
        *,
        max_read_bytes: int = 256,
    ) -> tuple[DMAMemoryProvider, OfflinePhysicalMemoryAdapter]:
        image = root / "physical-memory.raw"
        process = _build_physical_fixture(image)
        adapter = OfflinePhysicalMemoryAdapter(
            image,
            targets={_PID: process},
            allowed_root=root,
        )
        return (
            DMAMemoryProvider(adapter=adapter, max_read_bytes=max_read_bytes),
            adapter,
        )

    def test_offline_page_tables_translate_virtual_address_with_walk_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider, adapter = self._offline_provider(Path(tmp))
            request = _request(
                "translate",
                pid=_PID,
                dtb=hex(_DTB),
                address=hex(_VIRTUAL_ADDRESS),
                allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, 1),
            )

            plan = provider.plan(request)
            self.assertEqual(adapter.open_count, 0, "planning must not open a memory source")
            validation = provider.validate(plan)
            self.assertTrue(validation.ok, validation.errors)

            result = provider.execute(plan)
            self.assertEqual(result.status, "ok")
            translation = result.after_snapshot["translations"][0]
            self.assertEqual(translation["virtual_address"], _VIRTUAL_ADDRESS)
            self.assertEqual(translation["physical_address"], 0x8FF0)
            self.assertEqual(translation["page_size"], _PAGE_SIZE)
            self.assertEqual([item["level"] for item in translation["walk"]], ["pml4", "pdpt", "pd", "pt"])
            self.assertTrue(all(item["present"] for item in translation["walk"]))
            self.assertFalse(result.provenance["hardware_acquisition_completed"])
            self.assertEqual(result.provenance["acquisition_mode"], "offline_image")

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertFalse(rollback.restored)
            self.assertEqual(rollback.details["status"], "resources_released")
            self.assertEqual(adapter.close_count, 1)

    def test_snapshot_crosses_page_boundary_and_materializes_hashed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider, _ = self._offline_provider(root)
            request = _request(
                "snapshot",
                pid=_PID,
                dtb=_DTB,
                ranges=[
                    {
                        "address_space": "virtual",
                        "address": hex(_VIRTUAL_ADDRESS),
                        "size": len(_PAYLOAD),
                        "label": "cross-page",
                    }
                ],
                allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, len(_PAYLOAD)),
                artifact_name="fixture-snapshot.bin",
            )

            plan = provider.plan(request)
            self.assertTrue(provider.validate(plan).ok)
            result = provider.execute(plan)
            self.assertEqual(result.status, "ok")
            segment = result.after_snapshot["segments"][0]
            self.assertEqual(segment["size"], len(_PAYLOAD))
            self.assertEqual(segment["sha256"], hashlib.sha256(_PAYLOAD).hexdigest())
            self.assertEqual(
                [item["physical_address"] for item in segment["translations"]],
                [0x8FF0, 0x9000],
            )

            out_dir = root / "evidence"
            bundle = provider.collect_artifacts(result, str(out_dir))
            snapshot = next(item for item in bundle.artifacts if item.kind == "memory-snapshot")
            snapshot_path = out_dir / snapshot.path
            self.assertEqual(snapshot_path.read_bytes(), _PAYLOAD)
            self.assertEqual(snapshot.metadata["sha256"], hashlib.sha256(_PAYLOAD).hexdigest())
            self.assertEqual(snapshot.metadata["size"], len(_PAYLOAD))

            evidence = next(item for item in bundle.artifacts if item.kind == "dma-memory-evidence")
            manifest = next(item for item in bundle.artifacts if item.kind == "evidence-manifest")
            evidence_payload = json.loads((out_dir / evidence.path).read_text(encoding="utf-8"))
            manifest_payload = json.loads((out_dir / manifest.path).read_text(encoding="utf-8"))
            self.assertEqual(evidence_payload["target"]["pid"], _PID)
            self.assertFalse(evidence_payload["provenance"]["hardware_acquisition_completed"])
            self.assertTrue(any(item["path"] == snapshot.path for item in manifest_payload["entries"]))
            self.assertTrue(all(item.get("sha256") for item in bundle.manifest_entries))

            rollback = provider.rollback(result)
            self.assertTrue(rollback.ok)
            self.assertTrue(rollback.details["buffers_zeroed"])
            self.assertTrue(snapshot_path.is_file(), "rollback must preserve collected evidence")

    def test_validation_enforces_allowlist_max_bytes_target_identity_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider, _ = self._offline_provider(Path(tmp), max_read_bytes=len(_PAYLOAD))
            outside = provider.plan(
                _request(
                    "read",
                    pid=_PID,
                    dtb=_DTB,
                    address=_VIRTUAL_ADDRESS,
                    size=len(_PAYLOAD),
                    allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, len(_PAYLOAD) - 1),
                )
            )
            self.assertFalse(provider.validate(outside).ok)

            too_large = provider.plan(
                _request(
                    "read",
                    pid=_PID,
                    dtb=_DTB,
                    address=_VIRTUAL_ADDRESS,
                    size=len(_PAYLOAD) + 1,
                    allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, len(_PAYLOAD) + 1),
                )
            )
            self.assertFalse(provider.validate(too_large).ok)

            wrong_pid = provider.plan(
                _request(
                    "read",
                    pid=_PID + 1,
                    dtb=_DTB,
                    address=_VIRTUAL_ADDRESS,
                    size=1,
                    allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, 1),
                )
            )
            self.assertFalse(provider.validate(wrong_pid).ok)

            traversal = provider.plan(
                _request(
                    "snapshot",
                    pid=_PID,
                    dtb=_DTB,
                    ranges=[{"address": _VIRTUAL_ADDRESS, "size": 1}],
                    allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, 1),
                    artifact_name="../escape.bin",
                )
            )
            validation = provider.validate(traversal)
            self.assertFalse(validation.ok)
            self.assertTrue(any("artifact_name" in error for error in validation.errors))

            wrong_architecture = provider.plan(
                _request(
                    "translate",
                    pid=_PID,
                    dtb=_DTB,
                    address=_VIRTUAL_ADDRESS,
                    allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, 1),
                    architecture="arm64",
                )
            )
            self.assertFalse(provider.validate(wrong_architecture).ok)

            self.assertFalse(provider.supports(_request("write", pid=_PID, address=1, size=1)))

    def test_unavailable_dependency_is_gated_without_mock_success(self) -> None:
        provider = DMAMemoryProvider(adapter=UnavailableDMAMemoryAdapter("dependency missing"))
        plan = provider.plan(
            _request(
                "translate",
                pid=_PID,
                dtb=_DTB,
                address=_VIRTUAL_ADDRESS,
                allowlist=_virtual_allowlist(_VIRTUAL_ADDRESS, 1),
            )
        )
        validation = provider.validate(plan)
        self.assertFalse(validation.ok)
        dependency_check = next(item for item in validation.checks if item["name"] == "dependency")
        self.assertEqual(dependency_check["status"], "dependency-gated")

        result = provider.execute(plan)
        self.assertEqual(result.status, "dependency-gated")
        self.assertFalse(result.provenance["hardware_acquisition_completed"])
        self.assertIn("dependency missing", result.report_section["errors"][0])
        with tempfile.TemporaryDirectory() as tmp:
            bundle = provider.collect_artifacts(result, tmp)
            evidence = next(item for item in bundle.artifacts if item.kind == "dma-memory-evidence")
            manifest = next(item for item in bundle.artifacts if item.kind == "evidence-manifest")
            evidence_payload = json.loads((Path(tmp) / evidence.path).read_text(encoding="utf-8"))
            manifest_payload = json.loads((Path(tmp) / manifest.path).read_text(encoding="utf-8"))
            self.assertEqual(evidence_payload["status"], "dependency-gated")
            self.assertEqual(manifest_payload["entries"][0]["path"], evidence.path)

        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertEqual(rollback.details["status"], "already_released")

    def test_memprocfs_vfs_adapter_parses_read_only_target_modules_and_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process_dir = root / "pid" / str(_PID)
            map_dir = process_dir / "map"
            memory_dir = root / "sys" / "memory"
            map_dir.mkdir(parents=True)
            memory_dir.mkdir(parents=True)
            (process_dir / "win-dtb.txt").write_text("DTB: 0x1000\n", encoding="utf-8")
            (process_dir / "name.txt").write_text("fixture.exe\n", encoding="utf-8")
            (map_dir / "module.txt").write_text(
                "Base Size Name Path\n"
                "0000000000400000 0000000000010000 fixture.exe C:\\fixtures\\fixture.exe\n",
                encoding="utf-8",
            )
            fixture_path = memory_dir / "physmem.raw"
            _build_physical_fixture(fixture_path)

            adapter = MemProcFSVFSAdapter(root)
            adapter.open()
            target = adapter.resolve_target(_PID, dtb=_DTB, expected_name="fixture.exe")
            self.assertEqual(target["pid"], _PID)
            self.assertEqual(target["dtb"], _DTB)
            self.assertTrue(target["identity_verified"])
            self.assertEqual(adapter.read_physical(0x8FF0, 4), _PAYLOAD[:4])
            modules = adapter.list_modules(_PID)
            self.assertEqual(modules[0]["name"], "fixture.exe")
            self.assertTrue(str(modules[0]["source_path"]).startswith(str(root.resolve())))
            adapter.close()

    def test_leechcore_api_fake_only_proves_read_adapter_boundary(self) -> None:
        calls: list[tuple[object, ...]] = []

        class FakeHandle:
            def __init__(self, device: str) -> None:
                calls.append(("init", device))

            def read(self, address: int, size: int) -> bytes:
                calls.append(("read", address, size))
                return bytes(range(size))

            def close(self) -> None:
                calls.append(("close",))

        class FakeModule:
            LeechCore = FakeHandle

        adapter = LeechCorePythonAdapter(
            device="fpga",
            module=FakeModule,
            test_double=True,
        )
        adapter.open()
        self.assertEqual(adapter.read_physical(0x1000, 4), b"\x00\x01\x02\x03")
        target = adapter.resolve_target(_PID, dtb=_DTB, expected_name="fixture.exe")
        self.assertEqual(target["dtb"], _DTB)
        self.assertFalse(target["identity_verified"])
        self.assertFalse(adapter.hardware_backed)
        self.assertFalse(adapter.describe()["hardware_acquisition_completed"])
        self.assertFalse(hasattr(adapter, "write_physical"))
        adapter.close()
        self.assertEqual(calls, [("init", "fpga"), ("read", 0x1000, 4), ("close",)])


if __name__ == "__main__":
    unittest.main()
