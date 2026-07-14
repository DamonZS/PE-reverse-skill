from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from reverse_analyzer.tools.engine import engine_analyze
from tests.test_engine_analysis import _unreal_package, _unreal_pak


def _write_unreal_sample(root: Path) -> Path:
    sample = root / "UnrealGame.exe"
    sample.write_bytes(
        b"MZ\x00UnrealEngine\x00UObject\x00UClass\x00UFunction\x00ProcessEvent\x00"
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
    return sample


class UnrealEngineAnalysisTests(unittest.TestCase):
    def test_chromium_pak_is_not_treated_as_an_unreal_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "ElectronApp.exe"
            sample.write_bytes(b"MZ\x00Chromium\x00Electron\x00")
            (root / "chrome_100_percent.pak").write_bytes(
                b"Chromium resource pack\x00/Game/Fake\x00UObject\x00ProcessEvent\x00"
            )

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unknown")
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["assets"]["pak_candidate_count"], 1)
        self.assertEqual(result["assets"]["pak_count"], 0)
        record = next(
            item for item in result["assets"]["package_files"]
            if item["name"] == "chrome_100_percent.pak"
        )
        self.assertFalse(record["format_validated"])
        self.assertIn("footer magic", record["validation_error"])
        self.assertEqual(result["symbols"]["unreal_package_names"], [])

    def test_unreal_strings_without_a_structural_anchor_remain_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "StringOnly.exe"
            sample.write_bytes(
                b"MZ\x00UnrealEngine\x00UObject\x00UClass\x00UFunction\x00ProcessEvent\x00"
                b"/Game/UI/WBP_StringOnly.WBP_StringOnly_C\x00WidgetBlueprint\x00"
            )

            result = engine_analyze(sample)

        self.assertEqual(result["engine"], "unknown")
        self.assertEqual(result["confidence"], 0.0)
        unreal_candidate = next(
            item for item in result["candidates"] if item["engine"] == "unreal"
        )
        self.assertGreater(unreal_candidate["score"], 6.0)

    def test_truncated_pak_footer_magic_is_not_enough_to_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "ordinary.exe"
            sample.write_bytes(b"MZ\x00ordinary\x00")
            (root / "truncated.pak").write_bytes(
                b"index" + struct.pack("<II", 0x5A6F12E1, 8)
            )

            result = engine_analyze(sample)

        record = next(
            item for item in result["assets"]["package_files"]
            if item["name"] == "truncated.pak"
        )
        self.assertEqual(result["engine"], "unknown")
        self.assertFalse(record["format_validated"])
        self.assertEqual(record["status"], "partial")

    def test_pak_index_hash_mismatch_invalidates_the_package(self):
        pak = bytearray(_unreal_pak(b"/Game/UI/WBP_MainMenu\x00"))
        pak[0] ^= 0x01
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "ordinary.exe"
            sample.write_bytes(b"MZ\x00ordinary\x00")
            (root / "hash-mismatch.pak").write_bytes(pak)

            result = engine_analyze(sample)

        record = next(
            item for item in result["assets"]["package_files"]
            if item["name"] == "hash-mismatch.pak"
        )
        self.assertEqual(result["engine"], "unknown")
        self.assertFalse(record["format_validated"])
        self.assertFalse(record["index_hash_validated"])

    def test_magic_only_uasset_and_implausible_summary_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "ordinary.exe"
            sample.write_bytes(b"MZ\x00ordinary\x00")
            (root / "magic-only.uasset").write_bytes(struct.pack("<I", 0x9E2A83C1))
            (root / "bad-summary.umap").write_bytes(
                struct.pack("<Iiiii", 0x9E2A83C1, 100, -1, -1, -1)
            )

            result = engine_analyze(sample)

        records = {item["name"]: item for item in result["assets"]["package_files"]}
        self.assertEqual(result["engine"], "unknown")
        self.assertFalse(records["magic-only.uasset"]["format_validated"])
        self.assertFalse(records["bad-summary.umap"]["format_validated"])
        self.assertEqual(result["assets"]["validated_package_count"], 0)

    def test_valid_unreal_assets_emit_verified_inventory_symbols_and_ir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = _write_unreal_sample(root)
            out_dir = root / "out"
            result = engine_analyze(sample, out_dir=out_dir)
            header = out_dir / "engine" / "unreal_sdk_skeleton.hpp"
            header_exists = header.is_file()
            compiler = next(
                (path for name in ("clang++", "g++", "c++") if (path := shutil.which(name))),
                None,
            )
            compile_result = (
                subprocess.run(
                    [compiler, "-std=c++17", "-fsyntax-only", str(header)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if compiler and header_exists
                else None
            )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["engine"], "unreal")
        self.assertEqual(result["assets"]["validated_package_count"], 3)
        pak = next(
            item for item in result["assets"]["package_files"]
            if item["kind"] == "unreal-pak"
        )
        self.assertTrue(pak["format_validated"])
        self.assertTrue(pak["index_hash_validated"])
        self.assertEqual(pak["index_offset"], 0)
        self.assertGreater(pak["index_size"], 0)
        self.assertIn("/Game/UI/WBP_MainMenu", result["symbols"]["unreal_package_names"])
        self.assertTrue(
            {"UObject", "UClass", "UFunction", "ProcessEvent"}
            <= set(result["symbols"]["unreal_reflection_names"])
        )

        fragment = result["semantic_ir_fragment"]
        package_entity = next(
            item for item in fragment["entities"]
            if item["name"] == "/Game/UI/WBP_MainMenu"
        )
        self.assertEqual(package_entity["kind"], "resource")
        self.assertEqual(
            package_entity["attributes"]["resource_kind"],
            "engine-package",
        )
        self.assertTrue(
            any(
                relation["type"] == "declares"
                and relation["target"] == package_entity["id"]
                for relation in fragment["relations"]
            )
        )

        skeleton = result["sdk_skeleton"]
        self.assertEqual(skeleton["status"], "ok")
        self.assertFalse(skeleton["runtime_uobject_enumeration"])
        self.assertFalse(skeleton["sdk_dump_complete"])
        self.assertGreater(skeleton["declaration_count"], 0)
        self.assertIn("struct UObject;", skeleton["source"])
        self.assertNotIn("struct ProcessEvent;", skeleton["source"])
        self.assertTrue(skeleton["provenance"]["validated_package_files"])
        self.assertTrue(
            all(
                item["path"] and item["kind"].startswith("unreal-")
                for item in skeleton["provenance"]["validated_package_files"]
            )
        )
        self.assertFalse(skeleton["provenance"]["runtime_uobject_enumeration"])
        self.assertTrue(header_exists)
        if compile_result is not None:
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)


if __name__ == "__main__":
    unittest.main()
