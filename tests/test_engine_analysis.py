import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile

from reverse_analyzer.tools.engine import engine_analyze


def _align(value: int, alignment: int = 4) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _string_heap(values: list[str]) -> tuple[bytes, dict[str, int]]:
    data = bytearray(b"\x00")
    offsets: dict[str, int] = {"": 0}
    for value in values:
        if value in offsets:
            continue
        offsets[value] = len(data)
        data.extend(value.encode("utf-8") + b"\x00")
    return bytes(data), offsets


def _dotnet_tables(assembly_name: str, symbols: tuple[str, ...]) -> tuple[bytes, bytes]:
    rich = "PlayerController" in symbols
    values = [f"{assembly_name}.dll", assembly_name, "<Module>"]
    if rich:
        values.extend(
            [
                "MonoBehaviour",
                "ScriptableObject",
                "UnityEngine",
                "PlayerController",
                "GameConfig",
                "MainMenuCanvas",
                "Game",
                "health",
                "menuState",
                "Update",
                "Load",
                "Show",
            ]
        )
    strings, index = _string_heap(values)

    rows: dict[int, bytes] = {}
    rows[0] = struct.pack("<HHHHH", 0, index[f"{assembly_name}.dll"], 0, 0, 0)
    if rich:
        rows[1] = b"".join(
            [
                struct.pack("<HHH", 0, index["MonoBehaviour"], index["UnityEngine"]),
                struct.pack("<HHH", 0, index["ScriptableObject"], index["UnityEngine"]),
            ]
        )
        rows[2] = b"".join(
            [
                struct.pack("<IHHHHH", 0, index["<Module>"], 0, 0, 1, 1),
                struct.pack(
                    "<IHHHHH",
                    1,
                    index["PlayerController"],
                    index["Game"],
                    (1 << 2) | 1,
                    1,
                    1,
                ),
                struct.pack(
                    "<IHHHHH",
                    1,
                    index["GameConfig"],
                    index["Game"],
                    (2 << 2) | 1,
                    2,
                    2,
                ),
                struct.pack(
                    "<IHHHHH",
                    1,
                    index["MainMenuCanvas"],
                    index["Game"],
                    (1 << 2) | 1,
                    3,
                    3,
                ),
            ]
        )
        rows[4] = b"".join(
            [
                struct.pack("<HHH", 0, index["health"], 0),
                struct.pack("<HHH", 0, index["menuState"], 0),
            ]
        )
        rows[6] = b"".join(
            [
                struct.pack("<IHHHHH", 0x2100, 0, 0, index["Update"], 0, 1),
                struct.pack("<IHHHHH", 0x2120, 0, 0, index["Load"], 0, 1),
                struct.pack("<IHHHHH", 0x2140, 0, 0, index["Show"], 0, 1),
            ]
        )
    else:
        rows[2] = struct.pack("<IHHHHH", 0, index["<Module>"], 0, 0, 1, 1)

    rows[32] = struct.pack(
        "<IHHHHIHHH",
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        index[assembly_name],
        0,
    )
    row_sizes = {0: 10, 1: 6, 2: 14, 4: 6, 6: 14, 32: 22}
    row_counts = {table: len(payload) // row_sizes[table] for table, payload in rows.items()}
    valid_mask = sum(1 << table for table in rows)
    tables = struct.pack("<IBBBBQQ", 0, 2, 0, 0, 1, valid_mask, 0)
    tables += b"".join(struct.pack("<I", row_counts[table]) for table in sorted(rows))
    tables += b"".join(rows[table] for table in sorted(rows))
    return tables, strings


def _dotnet_metadata_root(assembly_name: str, *symbols: str) -> bytes:
    version = b"v4.0.30319\x00"
    tables, strings = _dotnet_tables(assembly_name, symbols)
    root = struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version
    root = root.ljust(_align(len(root)), b"\x00") + struct.pack("<HH", 0, 2)
    record_sizes = (_align(8 + len(b"#~\x00")), _align(8 + len(b"#Strings\x00")))
    tables_offset = _align(len(root) + sum(record_sizes))
    strings_offset = _align(tables_offset + len(tables))

    def stream_record(offset: int, size: int, name: bytes) -> bytes:
        record = struct.pack("<II", offset, size) + name + b"\x00"
        return record.ljust(_align(len(record)), b"\x00")

    root += stream_record(tables_offset, len(tables), b"#~")
    root += stream_record(strings_offset, len(strings), b"#Strings")
    root = root.ljust(tables_offset, b"\x00") + tables
    return root.ljust(strings_offset, b"\x00") + strings


def _managed_pe(metadata: bytes, *, pe_plus: bool = False) -> bytes:
    pe_offset = 0x80
    optional_size = 0xF0 if pe_plus else 0xE0
    section_rva = 0x2000
    raw_offset = 0x200
    cli_offset = raw_offset
    metadata_offset = raw_offset + 0x80
    raw_size = _align(0x80 + len(metadata), 0x200)

    dos = bytearray(pe_offset)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)
    coff = struct.pack(
        "<HHIIIHH",
        0x8664 if pe_plus else 0x14C,
        1,
        0,
        0,
        0,
        optional_size,
        0x2102,
    )
    optional = bytearray(optional_size)
    struct.pack_into("<H", optional, 0, 0x20B if pe_plus else 0x10B)
    struct.pack_into("<I", optional, 32, 0x1000)
    struct.pack_into("<I", optional, 36, 0x200)
    struct.pack_into("<I", optional, 56, 0x3000)
    struct.pack_into("<I", optional, 60, raw_offset)
    directory_count_offset = 108 if pe_plus else 92
    directory_offset = 112 if pe_plus else 96
    struct.pack_into("<I", optional, directory_count_offset, 16)
    struct.pack_into("<II", optional, directory_offset + (14 * 8), section_rva, 72)
    section = bytearray(40)
    section[:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", section, 8, raw_size, section_rva, raw_size, raw_offset)
    struct.pack_into("<I", section, 36, 0x60000020)

    image = bytearray(raw_offset + raw_size)
    image[:pe_offset] = dos
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    cursor = pe_offset + 4
    image[cursor : cursor + len(coff)] = coff
    cursor += len(coff)
    image[cursor : cursor + len(optional)] = optional
    cursor += len(optional)
    image[cursor : cursor + len(section)] = section
    cli = struct.pack(
        "<IHHIIII",
        72,
        2,
        5,
        section_rva + 0x80,
        len(metadata),
        1,
        0,
    )
    image[cli_offset : cli_offset + len(cli)] = cli
    image[metadata_offset : metadata_offset + len(metadata)] = metadata
    return bytes(image)


def _write_unity_mono_sample(root: Path) -> Path:
    sample = root / "MonoGame.exe"
    sample.write_bytes(b"MZ\x00UnityPlayer.dll\x00mono-2.0-bdwgc.dll\x00")

    data_dir = root / "MonoGame_Data"
    managed_dir = data_dir / "Managed"
    managed_dir.mkdir(parents=True)
    (managed_dir / "Assembly-CSharp.dll").write_bytes(
        _managed_pe(
            _dotnet_metadata_root(
            "Assembly-CSharp",
            "PlayerController",
            "MonoBehaviour",
            "GameConfig",
            "ScriptableObject",
            "MainMenuCanvas",
            "UnityEngine.UI.Button",
            )
        )
    )
    (managed_dir / "UnityEngine.CoreModule.dll").write_bytes(
        _managed_pe(_dotnet_metadata_root("UnityEngine.CoreModule", "UnityEngine"))
    )
    (data_dir / "resources.assets").write_bytes(
        _unity_serialized_asset(b"MainMenu\x00Canvas\x00RectTransform\x00")
    )
    return sample


def _unity_serialized_asset(payload: bytes) -> bytes:
    metadata = b"\x00" * 16
    data_offset = 20 + len(metadata)
    file_size = data_offset + len(payload)
    header = struct.pack(">IIII", len(metadata), file_size, 17, data_offset) + b"\x00\x00\x00\x00"
    return header + metadata + payload


def _global_metadata(version: int = 29, *, valid_magic: bool = True) -> bytes:
    string_values = [
        "Assembly-CSharp",
        "PlayerController",
        "InventoryConfig",
        "MonoBehaviour",
        "ScriptableObject",
        "HUDCanvas",
        "UnityEngine",
        "Game",
        "Update",
        "Load",
        "health",
        "itemCount",
    ]
    strings, index = _string_heap(string_values)
    methods = b"".join(
        [
            struct.pack("<iiiiiIHHHH", index["Update"], 0, -1, -1, -1, 0x06000001, 0, 0, 0, 0),
            struct.pack("<iiiiiIHHHH", index["Load"], 1, -1, -1, -1, 0x06000002, 0, 0, 0, 0),
        ]
    )
    fields = b"".join(
        [
            struct.pack("<iiI", index["health"], -1, 0x04000001),
            struct.pack("<iiI", index["itemCount"], -1, 0x04000002),
        ]
    )

    def type_definition(
        name: str,
        namespace: str,
        row_id: int,
        field_start: int,
        method_start: int,
        field_count: int,
        method_count: int,
    ) -> bytes:
        prefixes = [index[name], index[namespace], -1, -1, -1, -1, -1, -1, 0, -1, -1]
        ranges = [field_start, method_start, -1, -1, -1, -1, -1, -1]
        counts = [method_count, 0, field_count, 0, 0, 0, 0, 0]
        return struct.pack(
            "<11iI8i8HII",
            *prefixes,
            1,
            *ranges,
            *counts,
            0,
            0x02000001 + row_id,
        )

    types = b"".join(
        [
            type_definition("PlayerController", "Game", 0, 0, 0, 1, 1),
            type_definition("InventoryConfig", "Game", 1, 1, 1, 1, 1),
            type_definition("MonoBehaviour", "UnityEngine", 2, 2, 2, 0, 0),
            type_definition("ScriptableObject", "UnityEngine", 3, 2, 2, 0, 0),
        ]
    )
    header_size = 8 + (20 * 8)
    payload = bytearray()

    def add_table(data: bytes) -> tuple[int, int]:
        while (header_size + len(payload)) % 4:
            payload.append(0)
        offset = header_size + len(payload)
        payload.extend(data)
        return offset, len(data)

    pairs = [(header_size, 0) for _ in range(20)]
    pairs[2] = add_table(strings)
    pairs[5] = add_table(methods)
    pairs[11] = add_table(fields)
    pairs[19] = add_table(types)
    magic = 0xFAB11BAF if valid_magic else 0xDEADBEEF
    header = struct.pack("<II", magic, version)
    header += b"".join(struct.pack("<II", offset, size) for offset, size in pairs)
    return header + payload


def _unreal_package(*strings: str) -> bytes:
    summary = struct.pack("<Iiiii", 0x9E2A83C1, -7, 864, 522, 0)
    return summary + b"\x00".join(value.encode("ascii") for value in strings) + b"\x00"


def _unreal_pak(index_data: bytes, *, version: int = 8) -> bytes:
    footer = struct.pack("<IIQQ", 0x5A6F12E1, version, 0, len(index_data))
    footer += hashlib.sha1(index_data).digest()
    return index_data + footer


class EngineAnalysisTests(unittest.TestCase):
    def test_unity_mono_inventories_managed_assemblies_and_script_clues(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_unity_mono_sample(Path(tmp))

            result = engine_analyze(sample)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["engine"], "unity-mono")
        self.assertIn("Assembly-CSharp.dll", result["metadata"]["managed_assemblies"])
        self.assertEqual(result["metadata"]["managed_assembly_count"], 2)
        assembly = next(
            item
            for item in result["metadata"]["managed_assembly_files"]
            if item["name"] == "Assembly-CSharp.dll"
        )
        self.assertTrue(assembly["dotnet_metadata_present"])
        self.assertEqual(assembly["status"], "ok")
        self.assertEqual(assembly["runtime_version"], "v4.0.30319")
        self.assertEqual({item["name"] for item in assembly["metadata_streams"]}, {"#~", "#Strings"})
        self.assertIn("Game.PlayerController", result["symbols"]["mono_behaviour_symbols"])
        self.assertIn("Game.GameConfig", result["symbols"]["scriptable_object_symbols"])
        self.assertIn("Game.MainMenuCanvas", result["symbols"]["ui_symbols"])
        self.assertIn("Update", result["symbols"]["method_symbols"])
        self.assertIn("health", result["symbols"]["field_symbols"])
        self.assertTrue(result["assets"]["resources_assets_present"])

    def test_unity_il2cpp_parses_global_metadata_header_and_table_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "Il2CppGame.exe"
            sample.write_bytes(b"MZ\x00UnityPlayer.dll\x00")
            (root / "GameAssembly.dll").write_bytes(b"MZ\x00il2cpp_init\x00")
            metadata_path = root / "Il2CppGame_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
            metadata_path.parent.mkdir(parents=True)
            metadata_path.write_bytes(_global_metadata())

            result = engine_analyze(sample)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertTrue(result["metadata"]["global_metadata_present"])
        self.assertTrue(result["metadata"]["gameassembly_present"])
        parsed = result["metadata"]["global_metadata"]
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["magic"], "0xfab11baf")
        self.assertEqual(parsed["version"], 29)
        self.assertEqual(parsed["header_size"], 168)
        strings_table = next(item for item in parsed["tables"] if item["name"] == "strings")
        self.assertEqual(strings_table["offset"], 168)
        self.assertTrue(strings_table["in_bounds"])
        self.assertEqual(parsed["type_definition_count"], 4)
        self.assertEqual(parsed["method_definition_count"], 2)
        self.assertEqual(parsed["field_definition_count"], 2)
        self.assertEqual(parsed["method_definition_record_size"], 32)
        self.assertIn("UnityEngine.MonoBehaviour", result["symbols"]["type_symbols"])
        self.assertIn("Update", result["symbols"]["method_symbols"])
        self.assertIn("health", result["symbols"]["field_symbols"])
        self.assertEqual(result["native_mapping"]["status"], "partial")
        self.assertEqual(result["native_mapping"]["mapped_method_count"], 0)
        self.assertEqual(result["native_mapping"]["mappings"], [])
        self.assertTrue(result["native_mapping"]["errors"])

    def test_corrupt_il2cpp_metadata_is_partial_instead_of_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "BrokenGame.exe"
            sample.write_bytes(b"MZ\x00GameAssembly.dll\x00")
            metadata_path = root / "BrokenGame_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
            metadata_path.parent.mkdir(parents=True)
            metadata_path.write_bytes(_global_metadata(valid_magic=False))

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["metadata"]["global_metadata"]["status"], "partial")
        self.assertIn("magic", result["metadata"]["global_metadata"]["error"].lower())

    def test_empty_il2cpp_header_is_not_reported_as_successfully_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "HeaderOnly.exe"
            sample.write_bytes(b"MZ\x00GameAssembly.dll\x00")
            metadata_path = root / "HeaderOnly_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
            metadata_path.parent.mkdir(parents=True)
            metadata_path.write_bytes(
                struct.pack("<II", 0xFAB11BAF, 29) + struct.pack("<II", 8, 0)
            )

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertEqual(result["status"], "partial")
        parsed = result["metadata"]["global_metadata"]
        self.assertEqual(parsed["status"], "partial")
        self.assertEqual(parsed["table_count"], 0)
        self.assertIn("header", parsed["error"].lower())

    def test_malformed_managed_metadata_never_reports_a_successful_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "MalformedMono.exe"
            sample.write_bytes(b"MZ\x00mono-2.0-bdwgc.dll\x00")
            managed_dir = root / "MalformedMono_Data" / "Managed"
            managed_dir.mkdir(parents=True)
            (managed_dir / "Assembly-CSharp.dll").write_bytes(
                _managed_pe(b"BSJB" + (b"\x00" * 20))
            )

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unity-mono")
        self.assertEqual(result["status"], "partial")
        assembly = result["metadata"]["managed_assembly_files"][0]
        self.assertEqual(assembly["status"], "partial")
        self.assertFalse(assembly["dotnet_metadata_present"])
        self.assertTrue(assembly["dotnet_metadata_signature_present"])
        self.assertEqual(assembly["metadata"]["status"], "partial")

    def test_il2cpp_metadata_inside_apk_is_parsed_without_extracting(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "game.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                    _global_metadata(version=27),
                )
                archive.writestr("lib/arm64-v8a/libil2cpp.so", b"ELF\x00il2cpp_init\x00")
                archive.writestr("assets/bin/Data/resources.assets", b"UnityFS\x00HUDCanvas\x00")

            result = engine_analyze(apk)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["platform"], "android-apk")
        self.assertEqual(result["engine"], "unity-il2cpp")
        self.assertEqual(result["metadata"]["global_metadata"]["version"], 27)
        self.assertIn(
            "!assets/bin/Data/Managed/Metadata/global-metadata.dat",
            result["metadata"]["global_metadata"]["path"],
        )

    def test_unreal_extracts_asset_package_and_reflection_name_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "UnrealGame.exe"
            sample.write_bytes(
                b"MZ\x00UnrealEngine\x00UObject\x00UClass\x00UFunction\x00ProcessEvent\x00"
                b"/Script/Engine.Actor\x00BlueprintGeneratedClass\x00"
            )
            content = root / "UnrealGame" / "Content"
            (content / "Paks").mkdir(parents=True)
            (content / "UI").mkdir()
            (content / "Maps").mkdir()
            (content / "Paks" / "UnrealGame-Windows.pak").write_bytes(
                _unreal_pak(b"/Game/UI/WBP_MainMenu.WBP_MainMenu_C\x00WidgetBlueprint\x00")
            )
            (content / "UI" / "WBP_MainMenu.uasset").write_bytes(
                _unreal_package("/Game/UI/WBP_MainMenu", "UWidget", "StaticClass")
            )
            (content / "Maps" / "Lobby.umap").write_bytes(
                _unreal_package("/Game/Maps/Lobby", "PersistentLevel", "AActor")
            )

            result = engine_analyze(sample)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["engine"], "unreal")
        self.assertEqual(result["assets"]["pak_count"], 1)
        self.assertEqual(result["assets"]["uasset_count"], 1)
        self.assertEqual(result["assets"]["umap_count"], 1)
        self.assertIn("WBP_MainMenu", result["assets"]["unreal_asset_names"])
        self.assertTrue(
            any(name.startswith("/Game/UI/WBP_MainMenu") for name in result["assets"]["unreal_package_names"])
        )
        self.assertTrue(
            {"UObject", "UClass", "UFunction", "ProcessEvent"}
            <= set(result["symbols"]["unreal_reflection_names"])
        )

    def test_ordinary_sample_remains_unknown_with_compatible_empty_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "ordinary.bin"
            sample.write_bytes(b"MZ\x00CreateFileW\x00ordinary application\x00")

            result = engine_analyze(sample)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["engine"], "unknown")
        self.assertEqual(result["metadata"]["status"], "unavailable")
        self.assertEqual(result["assets"]["status"], "unavailable")
        self.assertEqual(result["symbols"]["status"], "unavailable")
        self.assertEqual(result["semantic_ir_fragment"]["status"], "unavailable")
        self.assertEqual(result["metadata"]["managed_assembly_count"], 0)
        self.assertFalse(result["metadata"]["global_metadata_present"])
        global_metadata = result["metadata"]["global_metadata"]
        self.assertEqual(global_metadata["type_definition_record_count"], 0)
        self.assertEqual(global_metadata["method_definition_record_count"], 0)
        self.assertEqual(global_metadata["field_definition_record_count"], 0)
        self.assertIsNone(global_metadata["method_definition_record_size"])
        self.assertEqual(result["assets"]["pak_count"], 0)
        self.assertEqual(result["symbols"]["recovered_symbol_count"], 0)
        self.assertEqual(result["semantic_ir_fragment"]["summary"]["entity_count"], 0)
        json.dumps(result, ensure_ascii=False, sort_keys=True)

    def test_missing_sample_is_gracefully_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.exe"

            result = engine_analyze(missing)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["engine"], "unknown")
        self.assertEqual(result["artifacts"], [])
        self.assertIn("not found", result["error"])

    def test_artifact_directory_failure_is_partial_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_unity_mono_sample(root)
            occupied = root / "occupied"
            occupied.write_bytes(b"not a directory")

            result = engine_analyze(sample, occupied)

        self.assertEqual(result["engine"], "unity-mono")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["artifacts"], [])
        self.assertTrue(
            any(item["component"] == "artifacts" for item in result["diagnostics"])
        )

    def test_artifacts_have_stable_schema_and_semantic_ir_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_unity_mono_sample(root)
            out_dir = root / "analysis"

            result = engine_analyze(sample, out_dir)

            expected_names = {
                "engine/fingerprint.json",
                "engine/metadata.json",
                "engine/assets.json",
                "engine/symbols.json",
                "engine/native_mapping.json",
                "engine/sdk_skeleton.json",
                "engine/semantic_ir_fragment.json",
            }
            self.assertEqual({item["name"] for item in result["artifacts"]}, expected_names)
            for artifact in result["artifacts"]:
                self.assertEqual(set(artifact), {"name", "path", "kind"})
                artifact_path = Path(artifact["path"])
                self.assertTrue(artifact_path.is_file())
                payload = json.loads(artifact_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], 1)

            fragment = json.loads(
                (out_dir / "engine" / "semantic_ir_fragment.json").read_text(encoding="utf-8")
            )
            self.assertEqual(fragment["engine"], "unity-mono")
            self.assertIsInstance(fragment["entities"], list)
            self.assertIsInstance(fragment["relations"], list)
            self.assertEqual(fragment["summary"]["entity_count"], len(fragment["entities"]))


if __name__ == "__main__":
    unittest.main()
