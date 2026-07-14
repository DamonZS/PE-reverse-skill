from pathlib import Path
import struct
import tempfile
import unittest

from reverse_analyzer.tools.engine import engine_analyze
from tests.test_engine_analysis import (
    _dotnet_metadata_root,
    _global_metadata,
    _managed_pe,
    _write_unity_mono_sample,
)


def _write_il2cpp_sample(root: Path, metadata: bytes) -> Path:
    sample = root / "Il2CppGame.exe"
    sample.write_bytes(b"MZ\x00UnityPlayer.dll\x00")
    (root / "GameAssembly.dll").write_bytes(b"MZ\x00il2cpp_init\x00")
    metadata_path = root / "Il2CppGame_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    metadata_path.parent.mkdir(parents=True)
    metadata_path.write_bytes(metadata)
    return sample


def _unityfs_bundle(payload: bytes = b"bundle-data") -> bytes:
    prefix = b"UnityFS\x00" + struct.pack(">I", 6)
    prefix += b"2021.3.0f1\x00" + b"2021.3.0f1\x00"
    declared_size = len(prefix) + 20 + len(payload)
    return prefix + struct.pack(">QIII", declared_size, 1, 1, 0x80) + payload


class UnityEngineAnalysisTests(unittest.TestCase):
    def test_bsjb_string_without_pe_cli_directory_is_not_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "MonoCandidate.exe"
            sample.write_bytes(b"MZ\x00mono-2.0-bdwgc.dll\x00")
            managed = root / "MonoCandidate_Data" / "Managed"
            managed.mkdir(parents=True)
            (managed / "Assembly-CSharp.dll").write_bytes(
                b"MZ\x00not-a-pe\x00BSJB\x00PlayerController\x00MonoBehaviour\x00"
            )

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unity-mono")
        self.assertEqual(result["status"], "partial")
        assembly = result["metadata"]["managed_assembly_files"][0]
        self.assertEqual(assembly["status"], "unavailable")
        self.assertFalse(assembly["cli_header_present"])
        self.assertFalse(assembly["dotnet_metadata_present"])
        self.assertFalse(assembly["dotnet_metadata_signature_present"])
        self.assertEqual(result["symbols"]["symbol_records"], [])

    def test_pe32_plus_cli_metadata_is_parsed_from_declared_rva(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "Mono64.exe"
            sample.write_bytes(b"MZ\x00mono-2.0-bdwgc.dll\x00")
            managed = root / "Mono64_Data" / "Managed"
            managed.mkdir(parents=True)
            metadata = _dotnet_metadata_root(
                "Assembly-CSharp",
                "PlayerController",
                "MonoBehaviour",
            )
            (managed / "Assembly-CSharp.dll").write_bytes(
                _managed_pe(metadata, pe_plus=True)
            )

            result = engine_analyze(sample)

        assembly = result["metadata"]["managed_assembly_files"][0]
        self.assertEqual(result["status"], "ok")
        self.assertEqual(assembly["status"], "ok")
        self.assertEqual(assembly["pe"]["pe_format"], "pe32+")
        self.assertEqual(assembly["pe"]["machine"], "0x8664")
        self.assertEqual(assembly["assembly_name"], "Assembly-CSharp")

    def test_mono_semantic_ir_preserves_declaring_type_and_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_unity_mono_sample(Path(tmp))
            result = engine_analyze(sample)

        records = result["symbols"]["symbol_records"]
        player = next(item for item in records if item["name"] == "Game.PlayerController")
        update = next(item for item in records if item["kind"] == "method" and item["name"] == "Update")
        health = next(item for item in records if item["kind"] == "field" and item["name"] == "health")
        self.assertEqual(player["provenance"]["parser"], "ecma-335-tables")
        self.assertEqual(update["declaring_type"], "Game.PlayerController")
        self.assertEqual(health["declaring_type"], "Game.PlayerController")
        self.assertEqual(update["token"], "0x06000001")

        fragment = result["semantic_ir_fragment"]
        class_entity = next(item for item in fragment["entities"] if item["name"] == "Game.PlayerController")
        method_entity = next(
            item for item in fragment["entities"]
            if item["kind"] == "function" and item["name"] == "Update"
        )
        self.assertTrue(
            any(
                relation["type"] == "declares"
                and relation["source"] == class_entity["id"]
                and relation["target"] == method_entity["id"]
                for relation in fragment["relations"]
            )
        )

    def test_il2cpp_structured_symbols_and_semantic_ir_are_linked(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_il2cpp_sample(Path(tmp), _global_metadata(version=29))
            result = engine_analyze(sample)

        parsed = result["metadata"]["global_metadata"]
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["method_definition_record_size"], 32)
        update = next(
            item for item in result["symbols"]["symbol_records"]
            if item["kind"] == "method" and item["name"] == "Update"
        )
        self.assertEqual(update["declaring_type"], "Game.PlayerController")
        self.assertEqual(update["provenance"]["parser"], "il2cpp-global-metadata-v1")

        fragment = result["semantic_ir_fragment"]
        player = next(item for item in fragment["entities"] if item["name"] == "Game.PlayerController")
        method = next(
            item for item in fragment["entities"]
            if item["kind"] == "function" and item["name"] == "Update"
        )
        self.assertTrue(
            any(
                relation["source"] == player["id"] and relation["target"] == method["id"]
                for relation in fragment["relations"]
            )
        )

    def test_corrupt_il2cpp_type_rows_do_not_become_recovered_classes(self):
        metadata = bytearray(_global_metadata(version=29))
        type_offset, type_size = struct.unpack_from("<II", metadata, 8 + (19 * 8))
        for offset in range(type_offset, type_offset + type_size, 104):
            struct.pack_into("<i", metadata, offset, len(metadata) + 4096)

        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_il2cpp_sample(Path(tmp), bytes(metadata))
            result = engine_analyze(sample)

        parsed = result["metadata"]["global_metadata"]
        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(parsed["type_definition_count"], 0)
        self.assertTrue(
            any("invalid name index" in error for error in parsed["definition_errors"])
        )
        self.assertEqual(result["symbols"]["type_symbols"], [])
        self.assertEqual(result["symbols"]["recovered_symbols"], [])

    def test_unityfs_requires_a_complete_structural_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_unity_mono_sample(root)
            asset = root / "MonoGame_Data" / "resources.assets"
            asset.write_bytes(_unityfs_bundle())
            valid = engine_analyze(sample)

            asset.write_bytes(b"UnityFS\x00MainMenu\x00")
            invalid = engine_analyze(sample)

        valid_record = next(
            item for item in valid["assets"]["package_files"]
            if item["name"] == "resources.assets"
        )
        invalid_record = next(
            item for item in invalid["assets"]["package_files"]
            if item["name"] == "resources.assets"
        )
        self.assertTrue(valid_record["format_validated"])
        self.assertEqual(valid_record["magic"], "UnityFS")
        self.assertFalse(invalid_record["format_validated"])
        self.assertFalse(invalid["assets"]["resources_assets_present"])


if __name__ == "__main__":
    unittest.main()
