import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, main
from unittest.mock import patch

from reverse_analyzer.tools.executor import ToolResult
from reverse_analyzer.tools.pe_deep import pe_deep_scan


class PeDeepScanTests(TestCase):
    def test_missing_dependency_is_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "sample.bin"
            sample.write_bytes(b"MZ")

            with patch.dict(sys.modules, {"pefile": None}):
                result = pe_deep_scan(sample)

            self.assertIsInstance(result, ToolResult)
            self.assertEqual(result.status, "unavailable")
            self.assertIn("pefile", result.error)
            json.dumps(result.to_dict())

    def test_non_pe_is_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "not-pe.bin"
            sample.write_bytes(b"not a pe")
            fake_pefile = SimpleNamespace(PE=_raising_pe_factory("bad pe"), DIRECTORY_ENTRY={})

            with patch.dict(sys.modules, {"pefile": fake_pefile}):
                result = pe_deep_scan(sample)

            self.assertIsInstance(result, ToolResult)
            self.assertEqual(result.status, "failed")
            self.assertIn("unable to parse PE", result.error)
            json.dumps(result.to_dict())

    def test_fake_pefile_extracts_expected_structure_and_anomalies(self):
        with tempfile.TemporaryDirectory() as td:
            sample = Path(td) / "fake.exe"
            sample.write_bytes(b"MZ" + (b"\x00" * 128))
            fake_pe = _build_fake_pe()
            fake_pefile = SimpleNamespace(
                PE=lambda *_args, **_kwargs: fake_pe,
                DIRECTORY_ENTRY={
                    "IMAGE_DIRECTORY_ENTRY_IMPORT": 1,
                    "IMAGE_DIRECTORY_ENTRY_EXPORT": 2,
                    "IMAGE_DIRECTORY_ENTRY_RESOURCE": 3,
                    "IMAGE_DIRECTORY_ENTRY_TLS": 4,
                },
            )

            with patch.dict(sys.modules, {"pefile": fake_pefile}):
                result = pe_deep_scan(sample)

            self.assertIsInstance(result, dict)
            json.dumps(result)

            self.assertEqual(result["entrypoint"]["section"], "UPX0")
            self.assertIsNone(result["entrypoint"]["anomaly"])
            self.assertEqual(result["overlay"]["present"], True)
            self.assertEqual(result["overlay"]["size"], 12)
            self.assertEqual(result["rich_header"]["present"], True)
            self.assertEqual(result["resources"]["types"], ["ICON"])
            self.assertEqual(result["tls_callbacks"]["callbacks"], [0x401000, 0x401100])
            self.assertEqual(result["exports"]["count"], 1)
            self.assertEqual(result["imports"][0]["dll"], "KERNEL32.dll")
            self.assertGreaterEqual(result["shell_score"], 40)
            self.assertEqual(result["shell_verdict"], "likely_packed")

            reasons = {reason for item in result["section_anomalies"] for reason in item["reasons"]}
            self.assertIn("suspicious_name", reasons)
            self.assertIn("high_entropy", reasons)

            anomaly_types = {item["type"] for item in result["iat_anomalies"]}
            self.assertIn("null_iat_address", anomaly_types)
            self.assertIn("unnamed_import_without_ordinal", anomaly_types)


def _raising_pe_factory(message: str):
    def factory(*_args, **_kwargs):
        raise ValueError(message)

    return factory


def _build_fake_pe():
    class FakeSection:
        def __init__(self, name, va, vs, raw, entropy, executable=False, writable=False):
            self.Name = name
            self.VirtualAddress = va
            self.Misc_VirtualSize = vs
            self.SizeOfRawData = raw
            self.IMAGE_SCN_MEM_EXECUTE = executable
            self.IMAGE_SCN_MEM_WRITE = writable
            self._entropy = entropy

        def get_entropy(self):
            return self._entropy

    class FakePE:
        def __init__(self):
            self.OPTIONAL_HEADER = SimpleNamespace(AddressOfEntryPoint=0x1000)
            self.sections = [
                FakeSection(b"UPX0\x00\x00\x00\x00", 0x1000, 0x600, 0x600, 7.8, executable=True, writable=True),
                FakeSection(b".rdata\x00\x00", 0x2000, 0x300, 0x500, 4.2, executable=False, writable=False),
            ]
            self.DIRECTORY_ENTRY_IMPORT = [
                SimpleNamespace(
                    dll=b"KERNEL32.dll",
                    imports=[
                        SimpleNamespace(name=b"LoadLibraryA", ordinal=None, address=0x5000, hint=1, bound=False),
                        SimpleNamespace(name=None, ordinal=None, address=0, hint=None, bound=False),
                    ],
                )
            ]
            self.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(
                symbols=[SimpleNamespace(name=b"ExportedFunc", ordinal=1, address=0x1234, forwarder=None)]
            )
            self.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(
                entries=[
                    SimpleNamespace(
                        name=None,
                        struct=SimpleNamespace(Id=3),
                        directory=SimpleNamespace(
                            entries=[
                                SimpleNamespace(
                                    name=b"MAINICON",
                                    struct=SimpleNamespace(Id=1),
                                    directory=SimpleNamespace(entries=[SimpleNamespace(struct=SimpleNamespace(Id=1033))]),
                                )
                            ]
                        ),
                    )
                ]
            )
            self.DIRECTORY_ENTRY_TLS = SimpleNamespace(
                callbacks=[0x401000, 0x401100],
                struct=SimpleNamespace(AddressOfCallBacks=0x401000),
            )

        def parse_data_directories(self, directories=None):
            self.last_directories = directories

        def get_overlay(self):
            return b"OVERLAY-DATA"

        def get_overlay_data_start_offset(self):
            return 2048

        def parse_rich_header(self):
            return {"key": 0x12345678, "values": [1, 2, 3, 4]}

        def get_section_by_rva(self, rva):
            for section in self.sections:
                start = section.VirtualAddress
                end = start + section.Misc_VirtualSize
                if start <= rva < end:
                    return section
            return None

    return FakePE()


if __name__ == "__main__":
    main()
