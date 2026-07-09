import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase, main
from unittest.mock import patch

from reverse_analyzer.tools import ToolExecutor, register_builtin_tools


class ToolExecutorTests(TestCase):
    def test_register_execute_and_exception_result(self):
        executor = ToolExecutor()
        executor.register("echo", lambda value: {"value": value})

        ok = executor.execute("echo", value="hello")
        self.assertEqual(ok.status, "ok")
        self.assertEqual(ok.data, {"value": "hello"})
        json.dumps(ok.to_dict())

        def boom():
            raise RuntimeError("bad")

        executor.register("boom", boom)
        failed = executor.execute("boom")
        self.assertEqual(failed.status, "failed")
        self.assertIn("RuntimeError", failed.error)
        self.assertEqual(len(executor.results), 2)

    def test_file_hash_and_strings(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.bin"
            sample.write_bytes(b"MZ\x00\x00hello-world\x00noise\x00LoadLibraryA\x00")
            executor = register_builtin_tools()

            info = executor.execute("file_info", path=sample)
            self.assertEqual(info.status, "ok")
            self.assertEqual(info.data["size"], sample.stat().st_size)

            hashes = executor.execute("hash", path=sample)
            self.assertEqual(hashes.status, "ok")
            self.assertEqual(len(hashes.data["hashes"]["sha256"]), 64)

            strings = executor.execute("strings_extract", path=sample)
            self.assertEqual(strings.status, "ok")
            self.assertIn("hello-world", strings.data["strings"])
            self.assertIn("LoadLibraryA", strings.data["strings"])

    def test_missing_optional_dependencies_are_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.bin"
            sample.write_bytes(b"not really a PE")
            executor = register_builtin_tools()

            with patch.dict(sys.modules, {"pefile": None}):
                pe = executor.execute("pe_header_scan", path=sample)
            self.assertEqual(pe.status, "unavailable")
            self.assertIn("pefile", pe.error)

            with patch.dict(sys.modules, {"yara": None}):
                yara = executor.execute("yara_scan_stub", path=sample)
            self.assertEqual(yara.status, "unavailable")
            self.assertIn("yara", yara.error.lower())

            external = executor.execute("external_command", command=["python", "--version"])
            self.assertEqual(external.status, "unavailable")

    def test_packer_detect_heuristic_on_strings_and_entropy(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "packed-ish.bin"
            sample.write_bytes(
                b"UPX0\x00UPX1\x00GetProcAddress\x00VirtualAlloc\x00"
                + bytes(range(256)) * 32
            )
            executor = register_builtin_tools()

            result = executor.execute("packer_detect", path=sample)
            self.assertEqual(result.status, "ok")
            self.assertIs(result.data["packed_likely"], True)
            indicator_types = {item["type"] for item in result.data["indicators"]}
            self.assertIn("import_or_string", indicator_types)
            self.assertIn("high_entropy", indicator_types)


if __name__ == "__main__":
    main()
