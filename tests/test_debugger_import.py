import json
import struct
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.tools.debugger_import import debugger_session_import
from reverse_analyzer.tools.static_tools import register_builtin_tools


class DebuggerImportTests(unittest.TestCase):
    def test_normalizes_x64dbg_json_and_writes_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "x64dbg.json"
            source.write_text(json.dumps({"breakpoints": [{"address": "401000"}], "modules": [{"name": "sample.exe"}], "registers": {"rip": "401000"}}), encoding="utf-8")
            out = root / "diagnostics.json"
            result = debugger_session_import(source, out=out)
            self.assertEqual(result["source"], "x64dbg")
            self.assertEqual(result["summary"]["breakpoint_count"], 1)
            self.assertTrue(out.is_file())

    def test_parses_windbg_text_and_minidump_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "windbg.log"
            log.write_text("00000000`40000000 00000000`40100000 sample\nExceptionCode: c0000005\nrax=00000001 rip=00401000", encoding="utf-8")
            parsed = debugger_session_import(log)
            self.assertEqual(parsed["summary"]["exception_count"], 1)
            self.assertEqual(parsed["registers"]["rip"], "00401000")

            dump = root / "sample.dmp"
            header = struct.pack("<IIIIIIQ", 0x504D444D, 1, 1, 32, 0, 0, 0)
            directory = struct.pack("<III", 7, 4, 44)
            dump.write_bytes(header + directory + b"data")
            triage = debugger_session_import(dump)
            self.assertEqual(triage["dump"]["stream_count"], 1)
            self.assertTrue(triage["dump"]["streams"][0]["in_bounds"])

    def test_registry_contains_importer(self) -> None:
        self.assertIn("debugger_session_import", register_builtin_tools().tools)


if __name__ == "__main__":
    unittest.main()
