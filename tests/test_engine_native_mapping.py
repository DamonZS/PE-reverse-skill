from pathlib import Path
import json
import struct
import tempfile
import unittest

from reverse_analyzer.tools.engine import engine_analyze


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _string_heap(values: list[str]) -> tuple[bytes, dict[str, int]]:
    data = bytearray(b"\x00")
    offsets = {"": 0}
    for value in values:
        offsets[value] = len(data)
        data.extend(value.encode("utf-8") + b"\x00")
    return bytes(data), offsets


def _global_metadata_with_image() -> bytes:
    strings, index = _string_heap(
        ["Assembly-CSharp.dll", "PlayerController", "Game", "Update", "Start"]
    )
    methods = b"".join(
        [
            struct.pack(
                "<iiiiiIHHHH",
                index["Update"],
                0,
                -1,
                -1,
                -1,
                0x06000001,
                0,
                0,
                0,
                0,
            ),
            struct.pack(
                "<iiiiiIHHHH",
                index["Start"],
                0,
                -1,
                -1,
                -1,
                0x06000002,
                0,
                0,
                0,
                0,
            ),
        ]
    )
    type_definition = struct.pack(
        "<11iI8i8HII",
        index["PlayerController"],
        index["Game"],
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        0,
        -1,
        -1,
        1,
        -1,
        0,
        -1,
        -1,
        -1,
        -1,
        -1,
        -1,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x02000001,
    )
    image_definition = struct.pack(
        "<iiiIiIiIiI",
        index["Assembly-CSharp.dll"],
        0,
        0,
        1,
        -1,
        0,
        -1,
        0x20000001,
        -1,
        0,
    )
    header_size = 8 + (22 * 8)
    payload = bytearray()

    def add_table(data: bytes) -> tuple[int, int]:
        while (header_size + len(payload)) % 4:
            payload.append(0)
        offset = header_size + len(payload)
        payload.extend(data)
        return offset, len(data)

    pairs = [(header_size, 0) for _ in range(22)]
    pairs[2] = add_table(strings)
    pairs[5] = add_table(methods)
    pairs[19] = add_table(type_definition)
    pairs[21] = add_table(image_definition)
    header = struct.pack("<II", 0xFAB11BAF, 29)
    header += b"".join(struct.pack("<II", offset, size) for offset, size in pairs)
    return header + payload


def _gameassembly_pe(
    *,
    pe_plus: bool,
    machine: int | None = None,
    pointer_table_out_of_bounds: bool = False,
) -> bytes:
    pe_offset = 0x80
    optional_size = 0xF0 if pe_plus else 0xE0
    image_base = 0x180000000 if pe_plus else 0x00400000
    machine = machine if machine is not None else (0x8664 if pe_plus else 0x14C)
    pointer_size = 8 if pe_plus else 4
    raw_header_size = 0x400
    sections = [
        (b".text", 0x1000, 0x400, 0x200, 0x60000020),
        (b".rdata", 0x2000, 0x600, 0x200, 0x40000040),
        (b".data", 0x3000, 0x800, 0x400, 0xC0000040),
    ]
    image = bytearray(0xC00)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, pe_offset)
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    coff_offset = pe_offset + 4
    struct.pack_into(
        "<HHIIIHH",
        image,
        coff_offset,
        machine,
        len(sections),
        0,
        0,
        0,
        optional_size,
        0x2022,
    )
    optional_offset = coff_offset + 20
    struct.pack_into("<H", image, optional_offset, 0x20B if pe_plus else 0x10B)
    if pe_plus:
        struct.pack_into("<Q", image, optional_offset + 24, image_base)
    else:
        struct.pack_into("<I", image, optional_offset + 28, image_base)
    struct.pack_into("<I", image, optional_offset + 32, 0x1000)
    struct.pack_into("<I", image, optional_offset + 36, 0x200)
    struct.pack_into("<I", image, optional_offset + 56, 0x4000)
    struct.pack_into("<I", image, optional_offset + 60, raw_header_size)
    directory_count_offset = optional_offset + (108 if pe_plus else 92)
    struct.pack_into("<I", image, directory_count_offset, 16)
    section_offset = optional_offset + optional_size
    for index, (name, rva, raw_offset, raw_size, characteristics) in enumerate(sections):
        offset = section_offset + index * 40
        image[offset : offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIII", image, offset + 8, raw_size, rva, raw_size, raw_offset)
        struct.pack_into("<I", image, offset + 36, characteristics)

    image[0x420:0x424] = b"\x55\x48\x89\xe5" if pe_plus else b"\x55\x8b\xec\x90"
    image[0x440:0x444] = b"\x90\x90\xc3\x00"
    image[0x620:0x634] = b"Assembly-CSharp.dll\x00"
    name_va = image_base + 0x2020
    pointer_table_va = image_base + (0x5000 if pointer_table_out_of_bounds else 0x3100)
    if pointer_size == 8:
        struct.pack_into("<QI4xQ", image, 0x820, name_va, 2, pointer_table_va)
        struct.pack_into("<QQ", image, 0x900, image_base + 0x1020, image_base + 0x1040)
    else:
        struct.pack_into("<III", image, 0x820, name_va, 2, pointer_table_va)
        struct.pack_into("<II", image, 0x900, image_base + 0x1020, image_base + 0x1040)
    return bytes(image)


def _write_sample(root: Path, gameassembly: bytes) -> Path:
    sample = root / "NativeMap.exe"
    sample.write_bytes(b"MZ\x00UnityPlayer.dll\x00")
    (root / "GameAssembly.dll").write_bytes(gameassembly)
    metadata = root / "NativeMap_Data" / "il2cpp_data" / "Metadata" / "global-metadata.dat"
    metadata.parent.mkdir(parents=True)
    metadata.write_bytes(_global_metadata_with_image())
    return sample


class EngineNativeMappingTests(unittest.TestCase):
    def test_maps_method_tokens_through_validated_pe_codegen_module(self):
        for pe_plus, expected_arch in ((False, "i386"), (True, "amd64")):
            with self.subTest(architecture=expected_arch), tempfile.TemporaryDirectory() as tmp:
                sample = _write_sample(Path(tmp), _gameassembly_pe(pe_plus=pe_plus))
                result = engine_analyze(sample)

            mapping = result["native_mapping"]
            self.assertEqual(result["status"], "ok")
            self.assertEqual(mapping["status"], "ok")
            self.assertEqual(mapping["pe"]["architecture"], expected_arch)
            self.assertEqual(mapping["eligible_method_count"], 2)
            self.assertEqual(mapping["mapped_method_count"], 2)
            self.assertEqual(
                {item["native_rva"] for item in mapping["mappings"]},
                {0x1020, 0x1040},
            )
            self.assertTrue(all(item["confidence"] == 0.98 for item in mapping["mappings"]))
            update = next(
                item
                for item in result["symbols"]["symbol_records"]
                if item.get("kind") == "method" and item.get("name") == "Update"
            )
            self.assertEqual(update["native_rva"], 0x1020)
            self.assertEqual(update["image_name"], "Assembly-CSharp.dll")
            ir_method = next(
                item
                for item in result["semantic_ir_fragment"]["entities"]
                if item.get("kind") == "function" and item.get("name") == "Update"
            )
            self.assertEqual(ir_method["attributes"]["native_rva"], 0x1020)
            self.assertTrue(
                any(evidence.get("kind") == "il2cpp-native-method-pointer" for evidence in ir_method["evidence"])
            )

    def test_out_of_bounds_pointer_table_is_partial_and_never_fabricates_rvas(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_sample(
                Path(tmp),
                _gameassembly_pe(pe_plus=True, pointer_table_out_of_bounds=True),
            )
            result = engine_analyze(sample)

        mapping = result["native_mapping"]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(mapping["status"], "partial")
        self.assertEqual(mapping["mapped_method_count"], 0)
        self.assertEqual(mapping["mappings"], [])
        self.assertTrue(any("outside the PE image" in error for error in mapping["errors"]))

    def test_machine_optional_header_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = _write_sample(
                Path(tmp),
                _gameassembly_pe(pe_plus=True, machine=0xAA64),
            )
            result = engine_analyze(sample)

        mapping = result["native_mapping"]
        self.assertEqual(mapping["status"], "partial")
        self.assertEqual(mapping["pe"]["machine"], "0xaa64")
        self.assertEqual(mapping["mapped_method_count"], 0)
        self.assertTrue(any("inconsistent" in error for error in mapping["errors"]))

    def test_native_mapping_artifact_matches_semantic_ir_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_sample(root, _gameassembly_pe(pe_plus=True))
            out_dir = root / "out"
            result = engine_analyze(sample, out_dir=out_dir)
            artifact = json.loads(
                (out_dir / "engine" / "native_mapping.json").read_text(encoding="utf-8")
            )

        self.assertEqual(artifact["status"], "ok")
        self.assertEqual(artifact["mapped_method_count"], 2)
        self.assertEqual(
            result["semantic_ir_fragment"]["summary"]["native_mapped_method_count"],
            2,
        )
        self.assertIn(
            "engine/native_mapping.json",
            {item["name"] for item in result["artifacts"]},
        )


if __name__ == "__main__":
    unittest.main()
