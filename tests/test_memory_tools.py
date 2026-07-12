import json
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.memory import (
    MAX_REGIONS,
    MAX_SAMPLE_BYTES,
    _enumerate_regions,
    memory_address_map,
    memory_diff,
    memory_snapshot,
)
from reverse_analyzer.tools.static_tools import register_builtin_tools


def _snapshot(regions, modules=None):
    return {
        "schema_version": 1,
        "kind": "memory_snapshot",
        "modules": modules or [{"name": "demo.exe", "path": "C:/demo.exe", "base_address": "0x1000", "size": 0x4000}],
        "regions": regions,
    }


class MemoryToolTests(TestCase):
    def test_snapshot_is_unavailable_off_windows_without_artifact(self):
        with tempfile.TemporaryDirectory() as td, patch("reverse_analyzer.tools.memory.os.name", "posix"):
            result = memory_snapshot(1234, td)
            self.assertIsInstance(result, ToolResult)
            self.assertEqual(result.status, "unavailable")
            self.assertIn("Windows", result.error)
            self.assertFalse(list(Path(td).iterdir()))
            json.dumps(result.to_dict(), sort_keys=True)

    def test_diff_classifies_added_removed_changed_and_writes_stable_json(self):
        before = _snapshot([
            {"base_address": "0x1000", "size": 4096, "state": "MEM_COMMIT", "protect": "PAGE_READONLY", "sample": {"sha256": "a", "size": 1, "hex": "aa"}},
            {"base_address": "0x3000", "size": 4096, "state": "MEM_COMMIT", "protect": "PAGE_READWRITE"},
        ])
        after = _snapshot([
            {"base_address": "0x1000", "size": 2048, "state": "MEM_COMMIT", "protect": "PAGE_READONLY", "sample": {"sha256": "b", "size": 1, "hex": "bb"}},
            {"base_address": "0x5000", "size": 8192, "state": "MEM_COMMIT", "protect": "PAGE_EXECUTE_READ"},
        ])
        with tempfile.TemporaryDirectory() as td:
            result = memory_diff(before, after, td)
            self.assertEqual(result.status, "ok")
            self.assertEqual(result.data["summary"], {"before_region_count": 2, "after_region_count": 2, "added_count": 1, "removed_count": 1, "changed_count": 1})
            self.assertEqual(result.data["added_regions"][0]["base_address"], "0x5000")
            self.assertEqual(result.data["removed_regions"][0]["base_address"], "0x3000")
            self.assertEqual(result.data["changed_regions"][0]["changed_fields"], ["sample", "size"])
            artifact = Path(result.metadata["artifacts"][0]["path"])
            self.assertEqual(result.data["artifacts"], result.metadata["artifacts"])
            self.assertTrue(artifact.is_file())
            self.assertEqual(json.loads(artifact.read_text(encoding="utf-8")), result.data)
            json.dumps(result.to_dict(), sort_keys=True)

    def test_diff_and_address_map_accept_unique_artifact_filenames(self):
        snapshot = _snapshot([])
        with tempfile.TemporaryDirectory() as td, patch("reverse_analyzer.tools.memory._pe_sections", return_value=([], "no PE fixture")):
            root = Path(td)
            first_diff = memory_diff(snapshot, snapshot, root, artifact_name="memory_diff_stage_1.json")
            second_diff = memory_diff(snapshot, snapshot, root, artifact_name="memory_diff_stage_2.json")
            first_map = memory_address_map("C:/demo.exe", snapshot, [], root, artifact_name="memory_address_map_stage_1.json")
            second_map = memory_address_map("C:/demo.exe", snapshot, [], root, artifact_name="memory_address_map_stage_2.json")

            artifact_names = {
                Path(result.metadata["artifacts"][0]["path"]).name
                for result in (first_diff, second_diff, first_map, second_map)
            }
            self.assertEqual(
                artifact_names,
                {
                    "memory_diff_stage_1.json",
                    "memory_diff_stage_2.json",
                    "memory_address_map_stage_1.json",
                    "memory_address_map_stage_2.json",
                },
            )
            self.assertTrue(all((root / name).is_file() for name in artifact_names))

    def test_region_enumeration_marks_byte_and_region_limits_as_truncated(self):
        class FakeKernel32:
            def __init__(self, region_count):
                self.region_count = region_count

            def GetSystemInfo(self, info_pointer):
                info = info_pointer._obj
                info.lpMinimumApplicationAddress = 0x1000
                info.lpMaximumApplicationAddress = 0x1000 + (self.region_count * 0x1000) - 1

            def VirtualQueryEx(self, _process, address, mbi_pointer, _size):
                base = int(address.value or 0)
                if base >= 0x1000 + (self.region_count * 0x1000):
                    return 0
                mbi = mbi_pointer._obj
                mbi.BaseAddress = base
                mbi.AllocationBase = base
                mbi.RegionSize = 0x1000
                mbi.State = 0x1000
                mbi.Protect = 0x04
                mbi.Type = 0x20000
                return 1

        with patch("reverse_analyzer.tools.memory._kernel32", return_value=FakeKernel32(2)), patch(
            "reverse_analyzer.tools.memory._read_memory", side_effect=lambda _process, _address, size: b"x" * size
        ):
            regions, sampled_bytes, truncated = _enumerate_regions(1, [], None, max_bytes=1024, max_regions=2)
        self.assertEqual(len(regions), 2)
        self.assertEqual(sampled_bytes, 1024)
        self.assertTrue(truncated)

        with patch("reverse_analyzer.tools.memory._kernel32", return_value=FakeKernel32(2)), patch(
            "reverse_analyzer.tools.memory._read_memory", side_effect=lambda _process, _address, size: b"x" * size
        ):
            regions, _sampled_bytes, truncated = _enumerate_regions(1, [], None, max_bytes=8192, max_regions=1)
        self.assertEqual(len(regions), 1)
        self.assertTrue(truncated)

    def test_snapshot_clamps_requested_capture_limits_and_reports_truncation(self):
        class FakeKernel32:
            def OpenProcess(self, *_args):
                return 1

            def CloseHandle(self, *_args):
                return True

        def write_artifact(_out_dir, _name, payload, _kind):
            return {**payload, "artifacts": []}, []

        with patch("reverse_analyzer.tools.memory.os.name", "nt"), patch(
            "reverse_analyzer.tools.memory._resolve_pid", return_value=42
        ), patch("reverse_analyzer.tools.memory._kernel32", return_value=FakeKernel32()), patch(
            "reverse_analyzer.tools.memory._enumerate_modules", return_value=[]
        ), patch("reverse_analyzer.tools.memory._enumerate_regions", return_value=([], 0, False)) as enumerate_regions, patch(
            "reverse_analyzer.tools.memory._write_artifact", side_effect=write_artifact
        ):
            result = memory_snapshot(42, "unused", max_bytes=MAX_SAMPLE_BYTES + 1, max_regions=MAX_REGIONS + 1)

        self.assertEqual(result.status, "ok")
        self.assertTrue(result.data["truncated"])
        self.assertEqual(result.data["summary"]["max_bytes"], MAX_SAMPLE_BYTES)
        self.assertEqual(result.data["summary"]["max_regions"], MAX_REGIONS)
        self.assertEqual(result.data["summary"]["requested_max_bytes"], MAX_SAMPLE_BYTES + 1)
        self.assertEqual(result.data["summary"]["requested_max_regions"], MAX_REGIONS + 1)
        self.assertEqual(enumerate_regions.call_args.args[-2:], (MAX_SAMPLE_BYTES, MAX_REGIONS))

    def test_diff_accepts_json_files_and_normalizes_invalid_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            before = root / "before.json"
            before.write_text(json.dumps(_snapshot([])), encoding="utf-8")
            result = memory_diff(before, {"regions": "not-a-list"}, root)
            self.assertEqual(result.status, "failed")
            self.assertIn("regions", result.error)
            json.dumps(result.to_dict(), sort_keys=True)

    def test_diff_accepts_utf8_bom_snapshot_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(json.dumps(_snapshot([])), encoding="utf-8-sig")
            after.write_text(json.dumps(_snapshot([])), encoding="utf-8-sig")
            result = memory_diff(before, after, root)
            self.assertEqual(result.status, "ok")

    def test_address_map_uses_module_rva_and_handles_bad_addresses(self):
        snapshot = _snapshot([], [{"name": "demo.exe", "path": "C:/demo.exe", "base_address": "0x140000000", "size": 0x3000}])
        with tempfile.TemporaryDirectory() as td, patch("reverse_analyzer.tools.memory._pe_sections", return_value=([], "no PE fixture")):
            result = memory_address_map("C:/demo.exe", snapshot, ["0x140001234", 0x140003000, "bogus"], td)
            self.assertEqual(result.status, "ok")
            first, outside, invalid = result.data["addresses"]
            self.assertEqual(first["rva"], "0x1234")
            self.assertEqual(first["module"]["name"], "demo.exe")
            self.assertIsNone(outside["module"])
            self.assertEqual(invalid["error"], "invalid address")
            self.assertFalse(result.data["pe_mapping"]["available"])
            self.assertEqual(result.data["artifacts"], result.metadata["artifacts"])
            self.assertTrue(Path(result.metadata["artifacts"][0]["path"]).is_file())
            json.dumps(result.to_dict(), sort_keys=True)

    def test_address_map_includes_section_and_file_offset_when_available(self):
        snapshot = _snapshot([], [{"name": "demo.exe", "path": "C:/demo.exe", "base_address": "0x400000", "size": 0x5000}])
        sections = [{"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x900, "raw_offset": 0x400, "raw_size": 0xA00}]
        with tempfile.TemporaryDirectory() as td, patch("reverse_analyzer.tools.memory._pe_sections", return_value=(sections, None)):
            result = memory_address_map("C:/demo.exe", snapshot, [0x401234], td)
            entry = result.data["addresses"][0]
            self.assertEqual(entry["section"], ".text")
            self.assertEqual(entry["file_offset"], 0x634)
            self.assertTrue(result.data["pe_mapping"]["available"])

    def test_address_map_does_not_attribute_same_basename_from_other_directory(self):
        snapshot = _snapshot([], [{"name": "demo.exe", "path": "C:/loaded/demo.exe", "base_address": "0x400000", "size": 0x5000}])
        sections = [{"name": ".text", "virtual_address": 0x1000, "virtual_size": 0x900, "raw_offset": 0x400, "raw_size": 0xA00}]
        with tempfile.TemporaryDirectory() as td, patch("reverse_analyzer.tools.memory._pe_sections", return_value=(sections, None)):
            result = memory_address_map("C:/analyzed/demo.exe", snapshot, [0x401234], td)
            entry = result.data["addresses"][0]
            self.assertEqual(entry["module"]["path"], "C:/loaded/demo.exe")
            self.assertEqual(entry["rva"], "0x1234")
            self.assertIsNone(entry["section"])
            self.assertIsNone(entry["file_offset"])

    def test_memory_tools_are_exported_and_registered_with_artifact_data(self):
        from reverse_analyzer.tools import memory_address_map as exported_address_map
        from reverse_analyzer.tools import memory_diff as exported_diff
        from reverse_analyzer.tools import memory_snapshot as exported_snapshot

        self.assertIs(exported_snapshot, memory_snapshot)
        self.assertIs(exported_diff, memory_diff)
        self.assertIs(exported_address_map, memory_address_map)
        executor = register_builtin_tools()
        self.assertTrue({"memory_snapshot", "memory_diff", "memory_address_map"}.issubset(executor.tools))
        with tempfile.TemporaryDirectory() as td:
            result = executor.execute("memory_diff", before=_snapshot([]), after=_snapshot([]), out_dir=td)
        self.assertEqual(result.status, "ok")
        self.assertEqual(result.data["artifacts"], result.metadata["artifacts"])
        self.assertEqual(result.data["artifacts"][0]["kind"], "memory_diff")
