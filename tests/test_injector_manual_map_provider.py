import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from reverse_analyzer.providers.injector import _manual_map_evidence_errors
from reverse_analyzer.providers.injector_manual_map import (
    IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_I386,
    Win32ManualMapper,
    bind_delay_imports,
    inspect_manual_map_image,
    map_image_bytes,
    parse_manual_map_bytes,
)


def _build_delay_import_pe(
    *,
    machine: int = IMAGE_FILE_MACHINE_AMD64,
    attributes: int = 1,
    bound_iat_rva: int = 0,
    unload_iat_rva: int = 0,
    load_config: bool = False,
    tls_callbacks: Optional[Sequence[int]] = None,
    tls_unterminated: bool = False,
    exception_table: bool = False,
    exception_directory_rva: int = 0x2180,
    exception_directory_size: int = 12,
    unwind_prolog_size: int = 0,
) -> bytes:
    """Build a local DLL with one named and one ordinal delay import."""

    pe32_plus = machine == IMAGE_FILE_MACHINE_AMD64
    optional_size = 0xF0 if pe32_plus else 0xE0
    directory_offset = 112 if pe32_plus else 96
    directory_count_offset = 108 if pe32_plus else 92
    image_base = 0x180000000 if pe32_plus else 0x10000000
    pe_offset = 0x80
    optional = pe_offset + 24
    payload = bytearray(0xA00)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, pe_offset)
    payload[pe_offset : pe_offset + 4] = b"PE\0\0"
    characteristics = 0x2002 | (0 if pe32_plus else 0x0100)
    struct.pack_into(
        "<HHIIIHH",
        payload,
        pe_offset + 4,
        machine,
        2,
        0,
        0,
        0,
        optional_size,
        characteristics,
    )
    struct.pack_into("<H", payload, optional, 0x20B if pe32_plus else 0x10B)
    struct.pack_into("<I", payload, optional + 16, 0x1000)
    struct.pack_into("<I", payload, optional + 20, 0x1000)
    if pe32_plus:
        struct.pack_into("<Q", payload, optional + 24, image_base)
    else:
        struct.pack_into("<I", payload, optional + 24, 0x2000)
        struct.pack_into("<I", payload, optional + 28, image_base)
    struct.pack_into("<I", payload, optional + 32, 0x1000)
    struct.pack_into("<I", payload, optional + 36, 0x200)
    struct.pack_into("<I", payload, optional + 56, 0x3000)
    struct.pack_into("<I", payload, optional + 60, 0x200)
    struct.pack_into("<H", payload, optional + 68, 3)
    struct.pack_into("<H", payload, optional + 70, 0x0100)
    struct.pack_into("<I", payload, optional + directory_count_offset, 16)
    delay_directory = optional + directory_offset + 13 * 8
    struct.pack_into("<II", payload, delay_directory, 0x2000, 0x40)
    if load_config:
        load_config_directory = optional + directory_offset + 10 * 8
        struct.pack_into("<II", payload, load_config_directory, 0x2180, 4)
    if tls_callbacks is not None:
        tls_directory = optional + directory_offset + 9 * 8
        struct.pack_into("<II", payload, tls_directory, 0x2140, 40)
    if exception_table:
        exception_directory = optional + directory_offset + 3 * 8
        struct.pack_into(
            "<II",
            payload,
            exception_directory,
            exception_directory_rva,
            exception_directory_size,
        )

    section = optional + optional_size
    payload[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<I", payload, section + 8, 0x100)
    struct.pack_into("<I", payload, section + 12, 0x1000)
    struct.pack_into("<I", payload, section + 16, 0x200)
    struct.pack_into("<I", payload, section + 20, 0x200)
    struct.pack_into("<I", payload, section + 36, 0x60000020)

    section += 40
    payload[section : section + 8] = b".didat\0\0"
    struct.pack_into("<I", payload, section + 8, 0x600)
    struct.pack_into("<I", payload, section + 12, 0x2000)
    struct.pack_into("<I", payload, section + 16, 0x600)
    struct.pack_into("<I", payload, section + 20, 0x400)
    struct.pack_into("<I", payload, section + 36, 0xC0000040)

    if pe32_plus:
        payload[0x200 : 0x206] = b"\xB8\x01\x00\x00\x00\xC3"
        pointer_format = "<Q"
        ordinal_flag = 1 << 63
    else:
        payload[0x200 : 0x208] = b"\xB8\x01\x00\x00\x00\xC2\x0C\x00"
        pointer_format = "<I"
        ordinal_flag = 1 << 31

    def didat_offset(rva: int) -> int:
        return 0x400 + rva - 0x2000

    struct.pack_into(
        "<8I",
        payload,
        didat_offset(0x2000),
        attributes,
        0x2080,
        0x20A0,
        0x20B0,
        0x20D0,
        bound_iat_rva,
        unload_iat_rva,
        0,
    )
    payload[didat_offset(0x2080) : didat_offset(0x2080) + 11] = b"USER32.dll\0"
    struct.pack_into(pointer_format, payload, didat_offset(0x20B0), image_base + 0x1050)
    struct.pack_into(pointer_format, payload, didat_offset(0x20B0) + struct.calcsize(pointer_format), image_base + 0x1060)
    struct.pack_into(pointer_format, payload, didat_offset(0x20D0), 0x2100)
    struct.pack_into(
        pointer_format,
        payload,
        didat_offset(0x20D0) + struct.calcsize(pointer_format),
        ordinal_flag | 7,
    )
    struct.pack_into("<H", payload, didat_offset(0x2100), 3)
    payload[didat_offset(0x2100) + 2 : didat_offset(0x2100) + 14] = b"MessageBeep\0"
    if tls_callbacks is not None:
        if not pe32_plus:
            # The parser must reject this directory before interpreting its x64 fields.
            struct.pack_into("<Q", payload, didat_offset(0x2140) + 24, image_base + 0x2200)
        else:
            callback_array_rva = 0x25F8 if tls_unterminated else 0x2200
            struct.pack_into(
                "<QQQQII",
                payload,
                didat_offset(0x2140),
                0,
                0,
                0,
                image_base + callback_array_rva,
                0,
                0,
            )
            callbacks = list(tls_callbacks)
            if tls_unterminated and not callbacks:
                callbacks = [0x1020]
            for index, callback_rva in enumerate(callbacks):
                struct.pack_into(
                    "<Q",
                    payload,
                    didat_offset(callback_array_rva) + index * 8,
                    image_base + callback_rva,
                )
            if not tls_unterminated:
                struct.pack_into(
                    "<Q",
                    payload,
                    didat_offset(callback_array_rva) + len(callbacks) * 8,
                    0,
                )
    if exception_table:
        struct.pack_into(
            "<III",
            payload,
            didat_offset(exception_directory_rva),
            0x1000,
            0x1006,
            0x21C0,
        )
        struct.pack_into(
            "<BBBB",
            payload,
            didat_offset(0x21C0),
            1,
            unwind_prolog_size,
            0,
            0,
        )
    return bytes(payload)


class _RecordingKernel32:
    def __init__(self, events: list[tuple[Any, ...]]) -> None:
        self.events = events

    def FlushInstructionCache(self, process: Any, address: Any, size: int) -> int:
        self.events.append(("flush_instruction_cache", size))
        return 1

    def CloseHandle(self, process: Any) -> int:
        self.events.append(("close_process",))
        return 1


class _RecordingHost:
    LOAD_LIBRARY = 0x70001000
    GET_PROC_ADDRESS = 0x70002000
    FREE_LIBRARY = 0x70003000
    RTL_ADD_FUNCTION_TABLE = 0x70004000
    RTL_DELETE_FUNCTION_TABLE = 0x70005000

    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []
        self._kernel32 = _RecordingKernel32(self.events)
        self.identity = {
            "pid": 4242,
            "creation_time_100ns": 133713371337,
            "image_path": "C:/targets/target.exe",
            "machine": IMAGE_FILE_MACHINE_AMD64,
            "injector_machine": IMAGE_FILE_MACHINE_AMD64,
        }
        self.modules: list[dict[str, Any]] = [
            {"name": "target.exe", "path": self.identity["image_path"]}
        ]

    def _open_process(self, pid: int) -> object:
        self.events.append(("open_process", pid))
        return object()

    def _process_identity(self, process: Any, pid: int) -> Mapping[str, Any]:
        self.events.append(("process_identity", pid))
        return dict(self.identity)

    def _remote_export_address(
        self,
        pid: int,
        *,
        module_name: str,
        export_name: str,
    ) -> tuple[int, Mapping[str, Any]]:
        self.events.append(("resolve_export", export_name))
        address = {
            "LoadLibraryW": self.LOAD_LIBRARY,
            "GetProcAddress": self.GET_PROC_ADDRESS,
            "FreeLibrary": self.FREE_LIBRARY,
            "RtlAddFunctionTable": self.RTL_ADD_FUNCTION_TABLE,
            "RtlDeleteFunctionTable": self.RTL_DELETE_FUNCTION_TABLE,
        }[export_name]
        return address, {"module_name": module_name, "export_name": export_name}

    def list_modules(self, pid: int) -> list[Mapping[str, Any]]:
        self.events.append(("list_modules", pid))
        return [dict(item) for item in self.modules]


class _RecordingWin32BoundaryMapper(Win32ManualMapper):
    """Run production orchestration while replacing only native Win32 calls."""

    MODULE_HANDLE = 0x71000000
    NAMED_ADDRESS = 0x72001000
    ORDINAL_ADDRESS = 0x72002000

    def __init__(
        self,
        host: _RecordingHost,
        *,
        fail_symbol: Optional[str] = None,
        add_function_table_result: int = 1,
        delete_function_table_result: int = 1,
        entrypoint_attach_result: bool = True,
        entrypoint_attach_completed: Any = True,
        incomplete_tls_attach_rva: Optional[int] = None,
        incomplete_tls_detach_rva: Optional[int] = None,
    ) -> None:
        super().__init__(host)
        self.fail_symbol = fail_symbol
        self.add_function_table_result = add_function_table_result
        self.delete_function_table_result = delete_function_table_result
        self.entrypoint_attach_result = entrypoint_attach_result
        self.entrypoint_attach_completed = entrypoint_attach_completed
        self.incomplete_tls_attach_rva = incomplete_tls_attach_rva
        self.incomplete_tls_detach_rva = incomplete_tls_detach_rva
        self.remote_image = b""
        self.remote_base = 0
        self.image_present = False

    @property
    def events(self) -> list[tuple[Any, ...]]:
        return self.host.events

    def _allocate_image(self, process: Any, image: Any) -> int:
        self.remote_base = image.image_base
        self.image_present = True
        self.events.append(("allocate_image", image.image_base, image.size_of_image))
        return image.image_base

    def _call_with_bytes_argument(
        self,
        process: Any,
        architecture: str,
        function: int,
        arguments: Sequence[Optional[int]],
        payload: bytes,
        timeout_ms: int,
    ) -> dict[str, Any]:
        if function == self.host.LOAD_LIBRARY:
            module_name = payload.decode("utf-16-le").rstrip("\0")
            self.events.append(("remote_LoadLibraryW", module_name))
            self.host.modules.append(
                {"name": module_name, "path": f"C:/Windows/System32/{module_name}"}
            )
            return {"completed": True, "result": self.MODULE_HANDLE, "thread_id": 11}
        if function == self.host.GET_PROC_ADDRESS:
            symbol_name = payload.rstrip(b"\0").decode("ascii")
            self.events.append(("remote_GetProcAddress", symbol_name))
            result = 0 if symbol_name == self.fail_symbol else self.NAMED_ADDRESS
            return {"completed": True, "result": result, "thread_id": 12}
        raise AssertionError(f"unexpected byte-argument function: {function:#x}")

    def _remote_call(
        self,
        process: Any,
        architecture: str,
        function: int,
        arguments: Sequence[int],
        timeout_ms: int,
    ) -> dict[str, Any]:
        if function == self.host.GET_PROC_ADDRESS:
            self.events.append(("remote_GetProcAddress", f"#{arguments[1]}"))
            return {"completed": True, "result": self.ORDINAL_ADDRESS, "thread_id": 13}
        if function == self.host.FREE_LIBRARY:
            self.events.append(("remote_FreeLibrary", int(arguments[0])))
            self.host.modules = [
                item
                for item in self.host.modules
                if str(item.get("name") or "").casefold() != "user32.dll"
            ]
            return {"completed": True, "result": 1, "thread_id": 14}
        if function == self.host.RTL_ADD_FUNCTION_TABLE:
            self.events.append(
                (
                    "RtlAddFunctionTable",
                    int(arguments[0]),
                    int(arguments[1]),
                    int(arguments[2]),
                )
            )
            return {
                "completed": True,
                "result": int(self.add_function_table_result),
                "thread_id": 16,
            }
        if function == self.host.RTL_DELETE_FUNCTION_TABLE:
            self.events.append(("RtlDeleteFunctionTable", int(arguments[0])))
            return {
                "completed": True,
                "result": int(self.delete_function_table_result),
                "thread_id": 17,
            }
        if len(arguments) == 3 and arguments[1] in (self.DLL_PROCESS_ATTACH, self.DLL_PROCESS_DETACH):
            reason = "attach" if arguments[1] == self.DLL_PROCESS_ATTACH else "detach"
            if function == self.remote_base + 0x1000:
                self.events.append((f"DllMain_{reason}", function))
                result = self.entrypoint_attach_result if reason == "attach" else True
                completed = (
                    self.entrypoint_attach_completed if reason == "attach" else True
                )
                return {"completed": completed, "result": int(result), "thread_id": 15}
            self.events.append((f"TLS_{reason}", function))
            if (
                reason == "attach"
                and self.incomplete_tls_attach_rva is not None
                and function == self.remote_base + self.incomplete_tls_attach_rva
            ):
                return {"completed": False, "result": 0, "thread_id": 18}
            if (
                reason == "detach"
                and self.incomplete_tls_detach_rva is not None
                and function == self.remote_base + self.incomplete_tls_detach_rva
            ):
                return {"completed": False, "result": 0, "thread_id": 18}
            return {"completed": True, "result": 0, "thread_id": 18}
        raise AssertionError(f"unexpected remote function: {function:#x}")

    def _write(self, process: Any, address: int, payload: bytes | bytearray, label: str) -> None:
        self.events.append(("write_remote_image", label, len(payload)))
        self.remote_image = bytes(payload)

    def _read(self, process: Any, address: int, size: int, label: str) -> bytes:
        self.events.append(("read_remote_image", label, size))
        return self.remote_image[:size]

    def _protect(self, process: Any, address: int, size: int, protection: int) -> int:
        self.events.append(("protect_remote_image", address, size, protection))
        return self.PAGE_READWRITE

    def _query_region(self, process: Any, address: int) -> dict[str, Any]:
        self.events.append(("query_image_region", address, self.image_present))
        if self.image_present:
            return {
                "base_address": address,
                "allocation_base": address,
                "region_size": len(self.remote_image),
                "state": self.MEM_COMMIT,
                "protect": self.PAGE_READONLY,
                "type": 0x20000,
            }
        return {
            "base_address": address,
            "allocation_base": 0,
            "region_size": 0,
            "state": self.MEM_FREE,
            "protect": 0,
            "type": 0,
        }

    def _release_image(self, process: Any, address: int) -> dict[str, Any]:
        self.events.append(("release_image", address))
        before = self._query_region(process, address)
        self.image_present = False
        after = self._query_region(process, address)
        return {
            "attempted": True,
            "released": True,
            "already_free": False,
            "release_verified": after["state"] == self.MEM_FREE,
            "before_region": before,
            "after_region": after,
        }


class ManualMapDelayImportTests(unittest.TestCase):
    @staticmethod
    def _event_index(events: Sequence[tuple[Any, ...]], name: str) -> int:
        return next(index for index, event in enumerate(events) if event[0] == name)

    def test_parses_and_binds_delay_imports_for_pe32_and_pe32_plus(self) -> None:
        for machine, pointer_format in (
            (IMAGE_FILE_MACHINE_I386, "<I"),
            (IMAGE_FILE_MACHINE_AMD64, "<Q"),
        ):
            with self.subTest(machine=machine):
                image = parse_manual_map_bytes(_build_delay_import_pe(machine=machine))
                self.assertEqual(image.delay_import_symbol_count, 2)
                self.assertEqual(image.to_audit_dict()["loader_semantics"], "partial")
                self.assertIn(
                    "load-config initialization and Control Flow Guard",
                    image.to_audit_dict()["loader_coverage"]["fail_closed"],
                )
                calls: list[tuple[Any, ...]] = []
                mapped = map_image_bytes(image)

                def load_module(module_name: str) -> int:
                    calls.append(("load", module_name))
                    return 0x71000000

                def resolve(
                    module_name: str,
                    symbol_name: Optional[str],
                    ordinal: Optional[int],
                ) -> int:
                    calls.append(("resolve", module_name, symbol_name, ordinal))
                    return 0x72001000 if symbol_name else 0x72002000

                evidence = bind_delay_imports(image, mapped, load_module, resolve)

                self.assertTrue(evidence["complete"])
                self.assertEqual(evidence["strategy"], "eager_target_context")
                self.assertEqual(
                    calls,
                    [
                        ("load", "USER32.dll"),
                        ("resolve", "USER32.dll", "MessageBeep", None),
                        ("resolve", "USER32.dll", None, 7),
                    ],
                )
                self.assertEqual(struct.unpack_from(pointer_format, mapped, 0x20A0)[0], 0x71000000)
                self.assertEqual(struct.unpack_from(pointer_format, mapped, 0x20B0)[0], 0x72001000)
                self.assertEqual(
                    struct.unpack_from(
                        pointer_format,
                        mapped,
                        0x20B0 + struct.calcsize(pointer_format),
                    )[0],
                    0x72002000,
                )

    def test_delay_subset_and_remaining_loader_features_fail_closed(self) -> None:
        cases = (
            (
                _build_delay_import_pe(attributes=0),
                "rva-based descriptor",
            ),
            (
                _build_delay_import_pe(bound_iat_rva=0x2140),
                "bound delay imports",
            ),
            (
                _build_delay_import_pe(unload_iat_rva=0x2160),
                "unloadable delay imports",
            ),
            (
                _build_delay_import_pe(load_config=True),
                "load-config initialization",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for index, (payload, expected) in enumerate(cases):
                with self.subTest(expected=expected):
                    path = Path(tmp) / f"unsupported-{index}.dll"
                    path.write_bytes(payload)
                    assessment = inspect_manual_map_image(str(path))
                    self.assertFalse(assessment["ok"])
                    self.assertEqual(assessment["loader_semantics"], "partial")
                    self.assertIn(expected, " ".join(assessment["errors"]).lower())

    def test_production_orchestration_binds_before_attach_and_rolls_back_in_reverse_order(self) -> None:
        payload = _build_delay_import_pe()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "delay.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(host)

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertTrue(operation["ok"], operation)
            self.assertTrue(operation["delay_imports"]["complete"])
            self.assertTrue(operation["delay_imports"]["readback_verified"])
            assessment = inspect_manual_map_image(str(path))
            self.assertEqual(
                _manual_map_evidence_errors(
                    operation,
                    assessment=assessment,
                    expected_sha256=hashlib.sha256(payload).hexdigest(),
                    expected_identity=host.identity,
                ),
                [],
            )
            event_names = [event[0] for event in host.events]
            self.assertLess(event_names.index("remote_LoadLibraryW"), event_names.index("write_remote_image"))
            self.assertLess(event_names.index("remote_GetProcAddress"), event_names.index("write_remote_image"))
            self.assertLess(event_names.index("write_remote_image"), event_names.index("protect_remote_image"))
            self.assertLess(event_names.index("protect_remote_image"), event_names.index("DllMain_attach"))
            self.assertEqual(
                [item["stage"] for item in operation["execution_trace"]],
                [
                    "validate_image_and_target_identity",
                    "allocate_remote_image",
                    "apply_base_relocations",
                    "bind_normal_imports",
                    "bind_delay_imports",
                    "write_and_verify_remote_image",
                    "apply_final_protections_and_flush",
                    "dll_process_attach",
                ],
            )

            rollback_start = len(host.events)
            rollback = mapper.rollback_image(
                4242,
                operation["rollback"],
                host.identity,
                2500,
            )
            rollback_events = host.events[rollback_start:]

            self.assertTrue(rollback["ok"], rollback)
            self.assertTrue(rollback["release_verified"])
            self.assertLess(
                self._event_index(rollback_events, "DllMain_detach"),
                self._event_index(rollback_events, "remote_FreeLibrary"),
            )
            self.assertLess(
                self._event_index(rollback_events, "remote_FreeLibrary"),
                self._event_index(rollback_events, "release_image"),
            )
            self.assertEqual(
                [item["stage"] for item in rollback["rollback_trace"]],
                [
                    "verify_target_identity",
                    "dll_process_detach",
                    "release_import_dependencies",
                    "release_and_verify_image",
                ],
            )

    def test_tls_callback_parser_enforces_order_limit_and_null_termination(self) -> None:
        image = parse_manual_map_bytes(
            _build_delay_import_pe(tls_callbacks=(0x1020, 0x1030))
        )
        self.assertEqual(image.tls_callback_count, 2)
        self.assertEqual(image.tls_directory.callback_rvas, (0x1020, 0x1030))
        self.assertTrue(image.to_audit_dict()["tls"]["array_null_terminated"])
        self.assertEqual(image.to_audit_dict()["tls"]["callback_limit"], 64)

        with self.assertRaisesRegex(ValueError, "64-callback limit"):
            parse_manual_map_bytes(
                _build_delay_import_pe(tls_callbacks=(0x1020,) * 65)
            )
        with self.assertRaisesRegex(ValueError, "not null-terminated"):
            parse_manual_map_bytes(
                _build_delay_import_pe(
                    tls_callbacks=(0x1020,),
                    tls_unterminated=True,
                )
            )

    def test_tls_callbacks_use_array_order_for_attach_and_detach(self) -> None:
        payload = _build_delay_import_pe(tls_callbacks=(0x1020, 0x1030))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tls.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(host)

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertTrue(operation["ok"], operation)
            self.assertTrue(operation["tls_callbacks"]["complete"])
            self.assertEqual(operation["tls_callbacks"]["attach_completed_count"], 2)
            self.assertEqual(
                [event for event in host.events if event[0] == "TLS_attach"],
                [
                    ("TLS_attach", operation["image_base"] + 0x1020),
                    ("TLS_attach", operation["image_base"] + 0x1030),
                ],
            )
            attach_events = [event[0] for event in host.events]
            self.assertLess(attach_events.index("TLS_attach"), attach_events.index("DllMain_attach"))

            rollback_start = len(host.events)
            rollback = mapper.rollback_image(
                4242,
                operation["rollback"],
                host.identity,
                2500,
            )
            rollback_events = host.events[rollback_start:]

            self.assertTrue(rollback["ok"], rollback)
            self.assertTrue(rollback["tls_callbacks_detached"])
            self.assertEqual(
                [event for event in rollback_events if event[0] == "TLS_detach"],
                [
                    ("TLS_detach", operation["image_base"] + 0x1020),
                    ("TLS_detach", operation["image_base"] + 0x1030),
                ],
            )
            rollback_names = [event[0] for event in rollback_events]
            self.assertLess(rollback_names.index("TLS_detach"), rollback_names.index("DllMain_detach"))
            self.assertLess(rollback_names.index("DllMain_detach"), rollback_names.index("remote_FreeLibrary"))

    def test_incomplete_tls_attach_compensates_completed_callbacks(self) -> None:
        payload = _build_delay_import_pe(tls_callbacks=(0x1020, 0x1030))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tls-attach-failure.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                incomplete_tls_attach_rva=0x1030,
            )

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertFalse(operation["side_effects"], operation)
            self.assertTrue(operation["cleanup"]["tls_callbacks_detached"])
            self.assertTrue(operation["cleanup"]["image_release_verified"])
            self.assertEqual(
                [event for event in host.events if event[0].startswith("TLS_")],
                [
                    ("TLS_attach", operation["image_base"] + 0x1020),
                    ("TLS_attach", operation["image_base"] + 0x1030),
                    ("TLS_detach", operation["image_base"] + 0x1020),
                ],
            )
            self.assertNotIn("DllMain_attach", [event[0] for event in host.events])

    def test_partial_tls_rollback_retries_only_the_remaining_callback(self) -> None:
        payload = _build_delay_import_pe(tls_callbacks=(0x1020, 0x1030))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tls-detach-retry.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                incomplete_tls_detach_rva=0x1030,
            )
            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )
            self.assertTrue(operation["ok"], operation)

            first_start = len(host.events)
            first = mapper.rollback_image(
                4242,
                operation["rollback"],
                host.identity,
                2500,
            )
            first_events = host.events[first_start:]

            self.assertFalse(first["ok"])
            self.assertEqual(
                first["error"]["operation"],
                "TLS callback(DLL_PROCESS_DETACH)",
            )
            self.assertEqual(
                [item["sequence"] for item in first["rollback"]["tls_callbacks"]],
                [2],
            )
            self.assertEqual(
                [event for event in first_events if event[0] == "TLS_detach"],
                [
                    ("TLS_detach", operation["image_base"] + 0x1020),
                    ("TLS_detach", operation["image_base"] + 0x1030),
                ],
            )
            self.assertNotIn("DllMain_detach", [event[0] for event in first_events])

            mapper.incomplete_tls_detach_rva = None
            retry_start = len(host.events)
            retry = mapper.rollback_image(
                4242,
                first["rollback"],
                host.identity,
                2500,
            )
            retry_events = host.events[retry_start:]

            self.assertTrue(retry["ok"], retry)
            self.assertEqual(
                [event for event in retry_events if event[0] == "TLS_detach"],
                [("TLS_detach", operation["image_base"] + 0x1030)],
            )
            self.assertIn("DllMain_detach", [event[0] for event in retry_events])

    def test_x64_exception_table_registers_before_execution_and_rollback_deletes_it(self) -> None:
        payload = _build_delay_import_pe(
            exception_table=True,
            tls_callbacks=(0x1020,),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unwind.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(host)

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertTrue(operation["ok"], operation)
            self.assertTrue(operation["exception_table"]["registered"])
            self.assertEqual(operation["exception_table"]["entry_count"], 1)
            self.assertEqual(operation["image"]["runtime_function_count"], 1)
            event_names = [event[0] for event in host.events]
            self.assertLess(event_names.index("RtlAddFunctionTable"), event_names.index("TLS_attach"))
            self.assertLess(event_names.index("TLS_attach"), event_names.index("DllMain_attach"))

            rollback_start = len(host.events)
            rollback = mapper.rollback_image(
                4242,
                operation["rollback"],
                host.identity,
                2500,
            )
            rollback_events = host.events[rollback_start:]

            self.assertTrue(rollback["ok"], rollback)
            self.assertTrue(rollback["function_table"]["deleted"])
            rollback_names = [event[0] for event in rollback_events]
            self.assertLess(
                rollback_names.index("TLS_detach"),
                rollback_names.index("DllMain_detach"),
            )
            self.assertLess(
                rollback_names.index("DllMain_detach"),
                rollback_names.index("RtlDeleteFunctionTable"),
            )
            self.assertLess(
                rollback_names.index("RtlDeleteFunctionTable"),
                rollback_names.index("remote_FreeLibrary"),
            )
            self.assertLess(
                rollback_names.index("RtlDeleteFunctionTable"),
                rollback_names.index("release_image"),
            )

    def test_function_table_registration_failure_compensates_dependencies_and_image(self) -> None:
        payload = _build_delay_import_pe(exception_table=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unwind-registration-failure.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                add_function_table_result=False,
            )

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertEqual(operation["error"]["operation"], "RtlAddFunctionTable")
            self.assertFalse(operation["side_effects"], operation)
            self.assertTrue(operation["cleanup"]["dependencies_released"])
            self.assertTrue(operation["cleanup"]["image_release_verified"])
            event_names = [event[0] for event in host.events]
            self.assertNotIn("DllMain_attach", event_names)
            self.assertNotIn("RtlDeleteFunctionTable", event_names)
            self.assertLess(event_names.index("RtlAddFunctionTable"), event_names.index("remote_FreeLibrary"))
            self.assertLess(event_names.index("remote_FreeLibrary"), event_names.index("release_image"))

    def test_function_table_boolean_uses_only_the_low_byte(self) -> None:
        payload = _build_delay_import_pe(exception_table=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unwind-registration-low-byte-false.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                add_function_table_result=0x100,
            )

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertEqual(operation["error"]["operation"], "RtlAddFunctionTable")
            self.assertEqual(operation["error"]["details"]["raw_result"], 0x100)
            self.assertEqual(operation["error"]["details"]["boolean_result"], 0)
            self.assertTrue(operation["cleanup"]["image_release_verified"])

    def test_incomplete_entrypoint_call_is_not_accepted_as_success(self) -> None:
        payload = _build_delay_import_pe(exception_table=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "entrypoint-incomplete.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                entrypoint_attach_result=True,
                entrypoint_attach_completed=False,
            )

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertEqual(
                operation["error"]["operation"],
                "DllMain(DLL_PROCESS_ATTACH)",
            )
            self.assertTrue(operation["cleanup"]["function_table"]["deleted"])
            self.assertTrue(operation["cleanup"]["image_release_verified"])

    def test_failure_after_registration_deletes_function_table_before_freeing_image(self) -> None:
        payload = _build_delay_import_pe(exception_table=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "post-registration-failure.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                entrypoint_attach_result=False,
            )

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertFalse(operation["side_effects"], operation)
            self.assertTrue(operation["cleanup"]["function_table"]["deleted"])
            event_names = [event[0] for event in host.events]
            self.assertLess(
                event_names.index("RtlAddFunctionTable"),
                event_names.index("DllMain_attach"),
            )
            self.assertLess(
                event_names.index("DllMain_attach"),
                event_names.index("RtlDeleteFunctionTable"),
            )
            self.assertLess(
                event_names.index("RtlDeleteFunctionTable"),
                event_names.index("release_image"),
            )

    def test_rollback_retains_image_when_function_table_deletion_fails(self) -> None:
        payload = _build_delay_import_pe(
            exception_table=True,
            tls_callbacks=(0x1020,),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unwind-delete-failure.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(
                host,
                delete_function_table_result=False,
            )
            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )
            self.assertTrue(operation["ok"], operation)

            rollback_start = len(host.events)
            rollback = mapper.rollback_image(
                4242,
                operation["rollback"],
                host.identity,
                2500,
            )
            rollback_events = host.events[rollback_start:]

            self.assertFalse(rollback["ok"])
            self.assertEqual(rollback["error"]["operation"], "RtlDeleteFunctionTable")
            self.assertFalse(rollback["mapping_released"])
            self.assertFalse(rollback["function_table"]["deleted"])
            self.assertEqual(rollback["rollback"]["tls_callbacks"], [])
            self.assertFalse(rollback["rollback"]["attach_succeeded"])
            self.assertTrue(rollback["rollback"]["function_table"]["registered"])
            rollback_names = [event[0] for event in rollback_events]
            self.assertIn("RtlDeleteFunctionTable", rollback_names)
            self.assertNotIn("remote_FreeLibrary", rollback_names)
            self.assertNotIn("release_image", rollback_names)
            self.assertEqual(
                [item["stage"] for item in rollback["rollback_trace"]][-2:],
                ["delete_x64_function_table", "rollback_failure"],
            )

            mapper.delete_function_table_result = 1
            retry_start = len(host.events)
            retry = mapper.rollback_image(
                4242,
                rollback["rollback"],
                host.identity,
                2500,
            )
            retry_events = host.events[retry_start:]
            retry_names = [event[0] for event in retry_events]

            self.assertTrue(retry["ok"], retry)
            self.assertNotIn("TLS_detach", retry_names)
            self.assertNotIn("DllMain_detach", retry_names)
            self.assertIn("RtlDeleteFunctionTable", retry_names)
            self.assertIn("remote_FreeLibrary", retry_names)
            self.assertIn("release_image", retry_names)

    def test_exception_directory_rejects_misalignment_size_and_oversized_prolog(self) -> None:
        malformed = (
            (
                {"exception_directory_rva": 0x2182},
                "exception directory RVA is not DWORD-aligned",
            ),
            (
                {"exception_directory_size": 13},
                "nonzero multiple of RUNTIME_FUNCTION",
            ),
            (
                {"unwind_prolog_size": 7},
                "UNWIND_INFO prolog exceeds its function range",
            ),
        )
        for options, message in malformed:
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, message):
                    parse_manual_map_bytes(
                        _build_delay_import_pe(exception_table=True, **options)
                    )

    def test_images_without_x64_loader_directories_remain_compatible(self) -> None:
        for machine in (IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64):
            with self.subTest(machine=machine):
                image = parse_manual_map_bytes(_build_delay_import_pe(machine=machine))
                self.assertIsNone(image.tls_directory)
                self.assertEqual(image.runtime_functions, ())
                self.assertEqual(image.to_audit_dict()["tls_callback_count"], 0)
                self.assertFalse(image.to_audit_dict()["exception_table"]["present"])

        with self.assertRaisesRegex(ValueError, "non-x64 exception directory"):
            parse_manual_map_bytes(
                _build_delay_import_pe(
                    machine=IMAGE_FILE_MACHINE_I386,
                    exception_table=True,
                )
            )

    def test_delay_resolution_failure_compensates_dependency_and_image_before_return(self) -> None:
        payload = _build_delay_import_pe()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "delay-failure.dll"
            path.write_bytes(payload)
            host = _RecordingHost()
            mapper = _RecordingWin32BoundaryMapper(host, fail_symbol="MessageBeep")

            operation = mapper.map_image(
                4242,
                str(path),
                hashlib.sha256(payload).hexdigest(),
                host.identity,
                2500,
            )

            self.assertFalse(operation["ok"])
            self.assertFalse(operation["side_effects"], operation)
            self.assertTrue(operation["cleanup"]["dependencies_released"])
            self.assertTrue(operation["cleanup"]["image_release_verified"])
            event_names = [event[0] for event in host.events]
            self.assertNotIn("write_remote_image", event_names)
            self.assertNotIn("DllMain_attach", event_names)
            self.assertLess(event_names.index("remote_LoadLibraryW"), event_names.index("remote_GetProcAddress"))
            self.assertLess(event_names.index("remote_GetProcAddress"), event_names.index("remote_FreeLibrary"))
            self.assertLess(event_names.index("remote_FreeLibrary"), event_names.index("release_image"))
            self.assertEqual(
                [item["stage"] for item in operation["execution_trace"][-3:]],
                [
                    "mapping_failure",
                    "compensate_dependencies",
                    "compensate_image_allocation",
                ],
            )


if __name__ == "__main__":
    unittest.main()
