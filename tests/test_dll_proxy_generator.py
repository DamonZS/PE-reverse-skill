import ctypes
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import pefile

from reverse_analyzer.patch.dll_proxy import (
    ArchitectureMismatchError,
    DllProxyGenerationError,
    DuplicateExportError,
    MalformedPEError,
    PathBoundaryError,
    generate_dll_proxy_project,
    parse_pe_exports,
)


EXPORT_RVA = 0x1000
SECTION_OFFSET = 0x200


def _minimal_export_dll(
    *,
    bits: int,
    machine: int | None = None,
    duplicate_name: bool = False,
    duplicate_ordinal: bool = False,
    malformed_address_table: bool = False,
    directory_count: int = 16,
    first_export_name: str = "Alpha",
) -> bytes:
    """Build a loader-shaped PE DLL with named, forwarded, and NONAME exports."""

    if bits not in {32, 64}:
        raise ValueError("bits must be 32 or 64")
    pe_offset = 0x80
    optional_size = 0xE0 if bits == 32 else 0xF0
    optional_offset = pe_offset + 24
    section_table = optional_offset + optional_size
    data = bytearray(0x800)

    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    observed_machine = machine if machine is not None else (0x014C if bits == 32 else 0x8664)
    characteristics = 0x2102 if bits == 32 else 0x2022
    struct.pack_into(
        "<HHIIIHH",
        data,
        pe_offset + 4,
        observed_machine,
        1,
        0,
        0,
        0,
        optional_size,
        characteristics,
    )

    struct.pack_into("<H", data, optional_offset, 0x10B if bits == 32 else 0x20B)
    data[optional_offset + 2] = 14
    struct.pack_into("<I", data, optional_offset + 8, 0x600)
    struct.pack_into("<I", data, optional_offset + 20, 0x1000)
    if bits == 32:
        struct.pack_into("<I", data, optional_offset + 24, 0x1000)
        struct.pack_into("<I", data, optional_offset + 28, 0x400000)
        struct.pack_into("<IIII", data, optional_offset + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        number_of_directories_offset = optional_offset + 92
        directory_offset = optional_offset + 96
    else:
        struct.pack_into("<Q", data, optional_offset + 24, 0x180000000)
        struct.pack_into(
            "<QQQQ",
            data,
            optional_offset + 72,
            0x100000,
            0x1000,
            0x100000,
            0x1000,
        )
        number_of_directories_offset = optional_offset + 108
        directory_offset = optional_offset + 112
    struct.pack_into("<II", data, optional_offset + 32, 0x1000, 0x200)
    struct.pack_into("<HH", data, optional_offset + 40, 6, 0)
    struct.pack_into("<HH", data, optional_offset + 48, 6, 0)
    struct.pack_into("<II", data, optional_offset + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional_offset + 68, 3)
    struct.pack_into("<I", data, number_of_directories_offset, directory_count)
    struct.pack_into("<II", data, directory_offset, EXPORT_RVA, 0x200)

    data[section_table : section_table + 8] = b".edata\x00\x00"
    struct.pack_into("<IIII", data, section_table + 8, 0x600, EXPORT_RVA, 0x600, SECTION_OFFSET)
    struct.pack_into("<I", data, section_table + 36, 0x40000040)

    export_offset = SECTION_OFFSET
    functions_rva = 0x1FFF if malformed_address_table else 0x1030
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        export_offset,
        0,
        0,
        0,
        0,
        0x1060,
        1,
        4,
        2,
        functions_rva,
        0x1040,
        0x1048,
    )
    struct.pack_into("<IIII", data, SECTION_OFFSET + 0x30, 0x1300, 0x1090, 0x1310, 0)
    second_name_rva = 0x1078 if not duplicate_name else 0x106C
    struct.pack_into("<II", data, SECTION_OFFSET + 0x40, 0x106C, second_name_rva)
    struct.pack_into(
        "<HH",
        data,
        SECTION_OFFSET + 0x48,
        0,
        0 if duplicate_ordinal else 1,
    )
    data[SECTION_OFFSET + 0x60 : SECTION_OFFSET + 0x6C] = b"fixture.dll\x00"
    encoded_first_name = first_export_name.encode("ascii")
    if not encoded_first_name or len(encoded_first_name) > 5:
        raise ValueError("first_export_name must contain 1-5 ASCII bytes")
    data[SECTION_OFFSET + 0x6C : SECTION_OFFSET + 0x72] = encoded_first_name.ljust(6, b"\x00")
    data[SECTION_OFFSET + 0x78 : SECTION_OFFSET + 0x82] = b"Forwarded\x00"
    data[SECTION_OFFSET + 0x90 : SECTION_OFFSET + 0x9F] = b"KERNEL32.Sleep\x00"
    data[SECTION_OFFSET + 0x300] = 0xC3
    data[SECTION_OFFSET + 0x310] = 0xC3
    return bytes(data)


def _write_source(root: Path, *, bits: int = 64, name: str = "fixture.dll", **kwargs: object) -> Path:
    source = root / "input" / name
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(_minimal_export_dll(bits=bits, **kwargs))
    return source


class DllProxyExportParserTests(unittest.TestCase):
    def test_parses_real_pe32_and_pe32_plus_export_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for bits, architecture, machine in ((32, "x86", 0x014C), (64, "x64", 0x8664)):
                with self.subTest(bits=bits):
                    source = root / f"fixture-{bits}.dll"
                    source.write_bytes(_minimal_export_dll(bits=bits))

                    parsed_by_dependency = pefile.PE(str(source), fast_load=False)
                    try:
                        self.assertEqual(parsed_by_dependency.FILE_HEADER.Machine, machine)
                        self.assertEqual(len(parsed_by_dependency.DIRECTORY_ENTRY_EXPORT.symbols), 3)
                    finally:
                        parsed_by_dependency.close()

                    table = parse_pe_exports(source)

                    self.assertEqual(table.bits, bits)
                    self.assertEqual(table.architecture, architecture)
                    self.assertEqual(table.machine, machine)
                    self.assertEqual(table.dll_name, "fixture.dll")
                    self.assertEqual(table.ordinal_base, 1)
                    self.assertEqual(table.hole_ordinals, (4,))
                    self.assertEqual(
                        [
                            (item.ordinal, item.name, item.forwarder, item.noname)
                            for item in table.exports
                        ],
                        [
                            (1, "Alpha", None, False),
                            (2, "Forwarded", "KERNEL32.Sleep", False),
                            (3, None, None, True),
                        ],
                    )

    def test_rejects_duplicate_names_and_duplicate_ordinal_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate_name = root / "duplicate-name.dll"
            duplicate_name.write_bytes(_minimal_export_dll(bits=64, duplicate_name=True))
            duplicate_ordinal = root / "duplicate-ordinal.dll"
            duplicate_ordinal.write_bytes(_minimal_export_dll(bits=64, duplicate_ordinal=True))

            with self.assertRaisesRegex(DuplicateExportError, "duplicate export name"):
                parse_pe_exports(duplicate_name)
            with self.assertRaisesRegex(DuplicateExportError, "ordinal"):
                parse_pe_exports(duplicate_ordinal)

    def test_rejects_malformed_tables_and_architecture_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            malformed = root / "malformed.dll"
            malformed.write_bytes(_minimal_export_dll(bits=64, malformed_address_table=True))
            ambiguous = root / "ambiguous.dll"
            ambiguous.write_bytes(_minimal_export_dll(bits=64, machine=0x014C))
            valid = root / "valid.dll"
            valid.write_bytes(_minimal_export_dll(bits=64))

            with self.assertRaisesRegex(MalformedPEError, "export address table"):
                parse_pe_exports(malformed)
            with self.assertRaisesRegex(ArchitectureMismatchError, r"PE32\+"):
                parse_pe_exports(ambiguous)
            with self.assertRaisesRegex(ArchitectureMismatchError, "expected x86"):
                parse_pe_exports(valid, expected_architecture="x86")

    def test_rejects_data_directory_count_beyond_optional_header(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            malformed = Path(tmp) / "directory-count.dll"
            malformed.write_bytes(_minimal_export_dll(bits=64, directory_count=17))

            with self.assertRaisesRegex(MalformedPEError, "data-directory capacity"):
                parse_pe_exports(malformed)


class DllProxyProjectGeneratorTests(unittest.TestCase):
    def test_generates_complete_confined_project_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copy_root = Path(tmp) / "copy"
            source = _write_source(copy_root)
            original = source.read_bytes()

            result = generate_dll_proxy_project(
                source,
                copy_dir=copy_root,
                project_dir="generated/fixture_proxy",
                expected_architecture="x64",
            )

            project = copy_root / "generated" / "fixture_proxy"
            self.assertEqual(result.project_dir, project.resolve())
            self.assertEqual(source.read_bytes(), original)
            expected_files = {
                "CMakeLists.txt",
                "proxy.c",
                "proxy.def",
                "backing/fixture_original.dll",
                "build_manifest.json",
                "risk_report.json",
                "rollback.json",
                "validation_report.json",
            }
            self.assertEqual(
                {path.relative_to(project).as_posix() for path in project.rglob("*") if path.is_file()},
                expected_files,
            )
            self.assertEqual((project / "backing" / "fixture_original.dll").read_bytes(), original)
            definition = (project / "proxy.def").read_text(encoding="ascii")
            self.assertIn('LIBRARY "fixture.dll"', definition)
            self.assertIn("Alpha=fixture_original.Alpha @1", definition)
            self.assertIn("Forwarded=fixture_original.Forwarded @2", definition)
            self.assertIn('__proxy_ordinal_3="fixture_original.#3" @3 NONAME', definition)

            validation = json.loads((project / "validation_report.json").read_text(encoding="utf-8"))
            self.assertEqual(validation["status"], "passed")
            self.assertEqual(validation["coverage"]["forwarded_exports"], 3)
            self.assertEqual(validation["coverage"]["total_exports"], 3)
            self.assertEqual(validation["coverage"]["coverage_percent"], 100.0)
            self.assertTrue(validation["preservation"]["names"])
            self.assertTrue(validation["preservation"]["ordinals"])
            self.assertTrue(validation["preservation"]["calling_boundaries"])

            rollback = json.loads((project / "rollback.json").read_text(encoding="utf-8"))
            self.assertTrue(rollback["reversible"])
            self.assertFalse(rollback["original_modified"])
            self.assertEqual(rollback["scope"], "copy_directory_only")
            self.assertTrue(rollback["generated_files"])
            risk = json.loads((project / "risk_report.json").read_text(encoding="utf-8"))
            self.assertIn(risk["overall_risk"], {"medium", "high"})
            self.assertTrue(any(item["id"] == "unsigned_proxy_binary" for item in risk["findings"]))

    def test_requires_input_and_output_to_remain_inside_copy_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy_root = root / "copy"
            outside_source = _write_source(root / "outside")
            inside_source = _write_source(copy_root)

            with self.assertRaisesRegex(PathBoundaryError, "source DLL"):
                generate_dll_proxy_project(outside_source, copy_dir=copy_root)
            with self.assertRaisesRegex(PathBoundaryError, "project directory"):
                generate_dll_proxy_project(
                    inside_source,
                    copy_dir=copy_root,
                    project_dir=root / "escaped-project",
                )
            self.assertFalse((root / "escaped-project").exists())

    def test_rejects_existing_or_invalid_projects_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copy_root = Path(tmp) / "copy"
            source = _write_source(copy_root)
            project = copy_root / "project"
            project.mkdir(parents=True)
            marker = project / "owner.txt"
            marker.write_text("do not replace", encoding="utf-8")

            with self.assertRaisesRegex(DllProxyGenerationError, "already exists"):
                generate_dll_proxy_project(source, copy_dir=copy_root, project_dir=project)
            self.assertEqual(marker.read_text(encoding="utf-8"), "do not replace")

            malformed = _write_source(copy_root, name="malformed.dll", malformed_address_table=True)
            malformed_project = copy_root / "malformed-project"
            with self.assertRaises(MalformedPEError):
                generate_dll_proxy_project(
                    malformed,
                    copy_dir=copy_root,
                    project_dir=malformed_project,
                )
            self.assertFalse(malformed_project.exists())

    def test_rejects_windows_device_proxy_names_without_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            copy_root = Path(tmp) / "copy"
            source = _write_source(copy_root)
            project = copy_root / "reserved-name-project"

            with self.assertRaisesRegex(DllProxyGenerationError, "reserved Windows device"):
                generate_dll_proxy_project(
                    source,
                    copy_dir=copy_root,
                    project_dir=project,
                    proxy_name="NUL.dll",
                )
            self.assertFalse(project.exists())

    def test_json_artifacts_are_stable_across_equivalent_copy_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            projects: list[Path] = []
            for name in ("one", "two"):
                copy_root = root / name / "copy"
                source = _write_source(copy_root)
                generate_dll_proxy_project(
                    source,
                    copy_dir=copy_root,
                    project_dir="generated/proxy",
                )
                projects.append(copy_root / "generated" / "proxy")

            json_names = (
                "build_manifest.json",
                "risk_report.json",
                "rollback.json",
                "validation_report.json",
            )
            for json_name in json_names:
                with self.subTest(artifact=json_name):
                    first = (projects[0] / json_name).read_bytes()
                    second = (projects[1] / json_name).read_bytes()
                    self.assertEqual(first, second)
                    self.assertTrue(first.endswith(b"\n"))
                    self.assertEqual(json.loads(first), json.loads(second))

    @unittest.skipUnless(
        shutil.which("cmake")
        and shutil.which("ninja")
        and shutil.which("x86_64-w64-mingw32-gcc"),
        "requires CMake, Ninja, and an x86_64 MinGW compiler",
    )
    def test_generated_x64_project_builds_and_preserves_export_surface(self) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if configured:
            acceptance_root = Path(configured).expanduser().resolve()
            with tempfile.TemporaryDirectory() as tmp:
                project = self._build_and_verify_generated_proxy(
                    Path(tmp) / "copy",
                    retain_toolchain_proof=True,
                )
                shutil.copytree(project, acceptance_root / "proxy")
            return
        with tempfile.TemporaryDirectory() as tmp:
            self._build_and_verify_generated_proxy(Path(tmp) / "copy", retain_toolchain_proof=False)

    @unittest.skipUnless(
        os.name == "nt"
        and os.environ.get("RUN_DLL_PROXY_LIVE") == "1"
        and shutil.which("cmake")
        and shutil.which("ninja")
        and shutil.which("x86_64-w64-mingw32-gcc"),
        "requires explicit Windows DLL proxy live acceptance and the MinGW toolchain",
    )
    def test_generated_x64_proxy_loads_resolves_and_unloads(self) -> None:
        configured = str(os.environ.get("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR") or "").strip()
        if not configured:
            self.skipTest("REVERSE_ANALYZER_ACCEPTANCE_RUN_DIR is required for retained live evidence")
        acceptance_root = Path(configured).expanduser().resolve()
        with tempfile.TemporaryDirectory() as tmp:
            generated_project = self._build_and_verify_generated_proxy(
                Path(tmp) / "copy",
                retain_toolchain_proof=True,
                loader_compatible_source=True,
            )
            project = acceptance_root / "proxy"
            shutil.copytree(generated_project, project)
        proxy = (project / "build" / "fixture.dll").resolve()
        backing = (project / "build" / "fixture_original.dll").resolve()

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        kernel32.LoadLibraryW.restype = ctypes.c_void_p
        kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        kernel32.GetProcAddress.restype = ctypes.c_void_p
        kernel32.FreeLibrary.argtypes = [ctypes.c_void_p]
        kernel32.FreeLibrary.restype = ctypes.c_int
        kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        kernel32.GetModuleHandleW.restype = ctypes.c_void_p

        handle = 0
        resolved: dict[str, int] = {}
        sleep_called = False
        unloaded = False
        previous_cwd = Path.cwd()
        try:
            with os.add_dll_directory(str(proxy.parent)):
                os.chdir(proxy.parent)
                handle = int(kernel32.LoadLibraryW(proxy.name) or 0)
                self.assertNotEqual(handle, 0, ctypes.WinError(ctypes.get_last_error()))
                try:
                    for export_name in (b"LoaderData", b"Forwarded"):
                        address = int(kernel32.GetProcAddress(handle, export_name) or 0)
                        self.assertNotEqual(
                            address,
                            0,
                            f"GetProcAddress failed for {export_name!r}: {ctypes.WinError(ctypes.get_last_error())}",
                        )
                        resolved[export_name.decode("ascii")] = address
                    ctypes.WINFUNCTYPE(None, ctypes.c_uint32)(resolved["Forwarded"])(0)
                    sleep_called = True
                finally:
                    unloaded = bool(kernel32.FreeLibrary(handle))
        finally:
            os.chdir(previous_cwd)

        proxy_absent = not bool(kernel32.GetModuleHandleW(proxy.name))
        backing_absent = not bool(kernel32.GetModuleHandleW(backing.name))
        self.assertTrue(unloaded, ctypes.WinError(ctypes.get_last_error()))
        self.assertTrue(proxy_absent)
        self.assertTrue(backing_absent)

        target_identity = {
            "path": str(proxy),
            "sha256": hashlib.sha256(proxy.read_bytes()).hexdigest(),
            "architecture": "x64",
            "backing_path": str(backing),
            "backing_sha256": hashlib.sha256(backing.read_bytes()).hexdigest(),
        }
        load_proof = {
            "schema_version": 1,
            "status": "ok",
            "provider": "windows_loader",
            "evidence_class": "live_host_proof",
            "proxy_handle_nonzero": handle != 0,
            "resolved_exports": sorted(resolved),
            "forwarded_sleep_called": sleep_called,
        }
        unload_proof = {
            "schema_version": 1,
            "status": "unloaded",
            "verified": True,
            "unloaded": unloaded,
            "proxy_module_absent": proxy_absent,
            "backing_module_absent": backing_absent,
        }
        execution_proof = {
            "schema_version": 1,
            "status": "ok",
            "provider": "windows_loader",
            "evidence_class": "live_host_proof",
            "executed_tests": 1,
            "skipped_tests": 0,
            "live_operations": 5,
            "actions": ["load_library", "resolve_exports", "call_forwarder", "free_library", "verify_unloaded"],
        }
        for name, payload in (
            ("target-identity.json", target_identity),
            ("load-proof.json", load_proof),
            ("unload-proof.json", unload_proof),
            ("execution-proof.json", execution_proof),
        ):
            (project / name).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def _build_and_verify_generated_proxy(
        self,
        copy_root: Path,
        *,
        retain_toolchain_proof: bool,
        loader_compatible_source: bool = False,
    ) -> Path:
        cmake = shutil.which("cmake") or "cmake"
        compiler = shutil.which("x86_64-w64-mingw32-gcc") or "x86_64-w64-mingw32-gcc"
        source_build_argv: list[str] | None = None
        source_build: subprocess.CompletedProcess[str] | None = None
        if loader_compatible_source:
            source_dir = copy_root / "source"
            source_dir.mkdir(parents=True, exist_ok=True)
            source_c = source_dir / "fixture.c"
            source_def = source_dir / "fixture.def"
            source = copy_root / "input" / "fixture.dll"
            source.parent.mkdir(parents=True, exist_ok=True)
            source_c.write_text(
                "#define WIN32_LEAN_AND_MEAN\n"
                "#include <windows.h>\n"
                "void LoaderData(void) {}\n"
                "void OrdinalOnly(void) {}\n"
                "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {\n"
                "    (void)instance; (void)reason; (void)reserved;\n"
                "    return TRUE;\n"
                "}\n",
                encoding="utf-8",
            )
            source_def.write_text(
                "LIBRARY fixture.dll\n"
                "EXPORTS\n"
                "    LoaderData @1\n"
                "    Forwarded=KERNEL32.Sleep @2\n"
                "    OrdinalOnly @3 NONAME\n",
                encoding="utf-8",
            )
            source_build_argv = [
                compiler,
                "-shared",
                "-o",
                str(source),
                str(source_c),
                str(source_def),
            ]
            source_build = subprocess.run(
                source_build_argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(source_build.returncode, 0, source_build.stdout + source_build.stderr)
        else:
            source = _write_source(copy_root, first_export_name="DATA")

        result = generate_dll_proxy_project(source, copy_dir=copy_root, project_dir="proxy")
        build_dir = result.project_dir / "build"
        configure_argv = [
            cmake,
            "-S",
            str(result.project_dir),
            "-B",
            str(build_dir),
            "-G",
            "Ninja",
            f"-DCMAKE_C_COMPILER={compiler}",
        ]
        configure = subprocess.run(
            configure_argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(configure.returncode, 0, configure.stdout + configure.stderr)
        build_argv = [cmake, "--build", str(build_dir)]
        build = subprocess.run(
            build_argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)

        proxy = build_dir / "fixture.dll"
        backing = build_dir / "fixture_original.dll"
        self.assertTrue(proxy.is_file(), list(build_dir.rglob("*.dll")))
        self.assertEqual(backing.read_bytes(), source.read_bytes())
        parsed = parse_pe_exports(proxy, expected_architecture="x64")
        observed_exports = [(item.ordinal, item.name, item.forwarder) for item in parsed.exports]
        first_export_name = "LoaderData" if loader_compatible_source else "DATA"
        expected_exports = [
            (1, first_export_name, f"fixture_original.{first_export_name}"),
            (2, "Forwarded", "fixture_original.Forwarded"),
            (3, None, "fixture_original.#3"),
        ]
        self.assertEqual(observed_exports, expected_exports)
        if retain_toolchain_proof:
            (result.project_dir / "toolchain-proof.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "passed",
                        "evidence_level": "toolchain",
                        "generator": "reverse_analyzer.patch.dll_proxy.generate_dll_proxy_project",
                        "mock": False,
                        "configure": {
                            "argv": configure_argv,
                            "exit_code": configure.returncode,
                        },
                        "build": {
                            "argv": build_argv,
                            "exit_code": build.returncode,
                        },
                        "source_build": (
                            {
                                "argv": source_build_argv,
                                "exit_code": source_build.returncode,
                            }
                            if source_build is not None
                            else None
                        ),
                        "tools": {
                            "cmake": str(Path(cmake).resolve()),
                            "ninja": str(Path(shutil.which("ninja") or "ninja").resolve()),
                            "compiler": str(Path(compiler).resolve()),
                        },
                        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                        "proxy_sha256": hashlib.sha256(proxy.read_bytes()).hexdigest(),
                        "backing_sha256": hashlib.sha256(backing.read_bytes()).hexdigest(),
                        "export_surface_verified": observed_exports == expected_exports,
                        "export_count": len(observed_exports),
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
        return result.project_dir


if __name__ == "__main__":
    unittest.main()
