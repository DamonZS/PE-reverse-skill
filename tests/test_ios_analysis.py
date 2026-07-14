import json
import plistlib
from pathlib import Path
import struct
import tempfile
from unittest import TestCase, main, mock
import zipfile

from reverse_analyzer.tools import ios as ios_module
from reverse_analyzer.tools.ios import ios_analyze


APP_ROOT = "Payload/Demo.app"
ARM64 = 0x0100000C
X86_64 = 0x01000007


class IosAnalysisTests(TestCase):
    def test_xml_plist_resources_thin_macho_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ipa = root / "storyboard.ipa"
            out_dir = root / "analysis"
            macho = _thin_macho(
                dylibs=("/System/Library/Frameworks/UIKit.framework/UIKit",),
            )
            members = _base_members(macho=macho)
            members.update(
                {
                    f"{APP_ROOT}/Base.lproj/Main.storyboardc/Info.plist": b"compiled",
                    f"{APP_ROOT}/Base.lproj/Legacy.xib": b"<xib />",
                    f"{APP_ROOT}/Assets.car": b"asset-catalog",
                    f"{APP_ROOT}/Frameworks/DemoKit.framework/DemoKit": macho,
                    f"{APP_ROOT}/Frameworks/libExtra.dylib": macho,
                }
            )
            _write_ipa(ipa, members)

            result = ios_analyze(ipa, out_dir)

            self.assertEqual(result["status"], "ok", result["warnings"])
            self.assertEqual(result["package_type"], "ipa")
            self.assertEqual(result["manifest"]["parser"], "xml_plist")
            self.assertEqual(result["manifest"]["bundle_identifier"], "com.example.demo")
            self.assertEqual(result["manifest"]["executable"], "Demo")
            self.assertEqual(result["resources"]["storyboard_count"], 1)
            self.assertEqual(result["resources"]["xib_count"], 1)
            self.assertEqual(result["resources"]["asset_catalog_count"], 1)
            self.assertEqual(result["resources"]["framework_count"], 1)
            self.assertEqual(result["resources"]["dylib_count"], 1)
            self.assertEqual(result["framework"]["name"], "uikit_storyboard")
            self.assertGreater(result["framework"]["confidence"], 0.5)

            native = result["native_binaries"]
            self.assertEqual(native["status"], "ok")
            self.assertEqual(native["count"], 3)
            self.assertEqual(native["architectures"], ["arm64"])
            self.assertFalse(native["encrypted"])
            self.assertTrue(all(item["encrypted"] is False for item in native["entries"]))

            self.assertFalse(result["decompilation"]["attempted"])
            self.assertFalse(result["decompilation"]["succeeded"])
            self.assertEqual(result["semantic_ir_fragment"]["status"], "ok")
            self.assertTrue(result["semantic_ir_fragment"]["entities"])

            self.assertEqual(
                {item["name"] for item in result["artifacts"]},
                {
                    "ios/manifest.json",
                    "ios/resources.json",
                    "ios/native_binaries.json",
                    "ios/framework.json",
                    "ios/semantic_ir_fragment.json",
                },
            )
            for artifact in result["artifacts"]:
                artifact_path = Path(artifact["path"])
                self.assertTrue(artifact_path.is_file())
                json.loads(artifact_path.read_text(encoding="utf-8"))

    def test_binary_plist_and_fat_macho_architectures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "swiftui-fat.ipa"
            arm64 = _thin_macho(
                cputype=ARM64,
                dylibs=("/System/Library/Frameworks/SwiftUI.framework/SwiftUI",),
            )
            x86_64 = _thin_macho(
                cputype=X86_64,
                dylibs=("/System/Library/Frameworks/SwiftUI.framework/SwiftUI",),
            )
            fat = _fat_macho((arm64, x86_64), (ARM64, X86_64))
            members = _base_members(
                macho=fat,
                plist_format=plistlib.FMT_BINARY,
                info_overrides={"UIMainStoryboardFile": None},
            )
            _write_ipa(ipa, members)

            result = ios_analyze(ipa)

            self.assertEqual(result["status"], "ok", result["warnings"])
            self.assertEqual(result["manifest"]["parser"], "binary_plist")
            self.assertEqual(result["framework"]["name"], "swiftui")
            main_binary = result["native_binaries"]["entries"][0]
            self.assertEqual(main_binary["format"], "fat-mach-o")
            self.assertEqual(main_binary["architectures"], ["arm64", "x86_64"])
            self.assertEqual(len(main_binary["slices"]), 2)
            self.assertFalse(main_binary["encrypted"])

    def test_flutter_react_native_unity_and_webview_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = (
                (
                    "flutter",
                    {
                        f"{APP_ROOT}/Frameworks/Flutter.framework/Flutter": _thin_macho(),
                        f"{APP_ROOT}/flutter_assets/AssetManifest.json": b"{}",
                    },
                ),
                (
                    "react_native",
                    {
                        f"{APP_ROOT}/main.jsbundle": b"__d(function() { RCTRootView; });",
                    },
                ),
                (
                    "unity",
                    {
                        f"{APP_ROOT}/Frameworks/UnityFramework.framework/UnityFramework": _thin_macho(),
                        f"{APP_ROOT}/Data/globalgamemanagers": b"unity",
                    },
                ),
                (
                    "webview_hybrid",
                    {
                        f"{APP_ROOT}/www/index.html": b"<html></html>",
                        f"{APP_ROOT}/www/app.js": b"window.webkit.messageHandlers.bridge;",
                    },
                ),
            )
            for expected, extra_members in cases:
                with self.subTest(framework=expected):
                    ipa = root / f"{expected}.ipa"
                    if expected == "webview_hybrid":
                        main_macho = _thin_macho(
                            dylibs=("/System/Library/Frameworks/WebKit.framework/WebKit",),
                        )
                    elif expected == "react_native":
                        main_macho = _thin_macho(strings=("RCTRootView",))
                    else:
                        main_macho = _thin_macho()
                    members = _base_members(
                        macho=main_macho,
                        info_overrides={"UIMainStoryboardFile": None},
                    )
                    members.update(extra_members)
                    _write_ipa(ipa, members)

                    framework = ios_analyze(ipa)["framework"]

                    self.assertEqual(framework["name"], expected, framework)
                    self.assertTrue(framework["evidence"])
                    self.assertGreater(framework["confidence"], 0.5)

    def test_framework_conflict_tie_has_deterministic_priority_and_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            extras = [
                (f"{APP_ROOT}/Frameworks/Flutter.framework/Flutter", _thin_macho()),
                (f"{APP_ROOT}/flutter_assets/AssetManifest.json", b"{}"),
                (f"{APP_ROOT}/Frameworks/UnityFramework.framework/UnityFramework", _thin_macho()),
                (f"{APP_ROOT}/Data/globalgamemanagers", b"unity"),
            ]
            results = []
            for index, ordered_extras in enumerate((extras, list(reversed(extras)))):
                ipa = root / f"conflict-{index}.ipa"
                base = list(
                    _base_members(
                        macho=_thin_macho(),
                        info_overrides={"UIMainStoryboardFile": None},
                    ).items()
                )
                _write_ipa(ipa, [*base, *ordered_extras])
                results.append(ios_analyze(ipa))

            first, second = results
            self.assertEqual(first["framework"], second["framework"])
            self.assertEqual(first["framework"]["name"], "flutter")
            self.assertTrue(first["framework"]["conflict"]["is_conflicted"])
            positive = [
                item["name"]
                for item in first["framework"]["candidates"]
                if item["score"] > 0
            ]
            self.assertEqual(positive[:2], ["flutter", "unity"])
            self.assertEqual(first["status"], "partial")

    def test_path_traversal_and_zip_bomb_members_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ipa = root / "unsafe.ipa"
            out_dir = root / "analysis"
            members = _base_members(macho=_thin_macho())
            members[f"{APP_ROOT}/Base.lproj/Main.storyboard"] = b"storyboard"
            members["../outside.txt"] = b"escape"
            members[f"{APP_ROOT}/assets/bomb.bin"] = b"\x00" * (8 * 1024 * 1024)
            _write_ipa(ipa, members)

            result = ios_analyze(ipa, out_dir)

            self.assertEqual(result["status"], "partial")
            archive = result["archive"]
            self.assertEqual(archive["unsafe_entry_count"], 2)
            reasons = {item["reason"] for item in archive["unsafe_entries"]}
            self.assertIn("non-canonical member path", reasons)
            self.assertIn("suspicious compression ratio", reasons)
            self.assertFalse((root / "outside.txt").exists())
            self.assertEqual(archive["members_extracted"], 0)

    def test_encrypted_zip_member_is_rejected_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "encrypted-member.ipa"
            secret_path = f"{APP_ROOT}/assets/secret.dat"
            members = _base_members(macho=_thin_macho())
            members[f"{APP_ROOT}/Base.lproj/Main.storyboard"] = b"storyboard"
            members[secret_path] = b"secret"
            _write_ipa(ipa, members)
            _mark_member_encrypted(ipa, secret_path)

            result = ios_analyze(ipa)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["archive"]["unsafe_entry_count"], 1)
            self.assertEqual(
                result["archive"]["unsafe_entries"][0]["reason"],
                "encrypted member",
            )

    def test_encrypted_macho_is_partial_and_never_claims_decompilation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "encrypted-binary.ipa"
            members = _base_members(macho=_thin_macho(cryptid=1))
            members[f"{APP_ROOT}/Base.lproj/Main.storyboard"] = b"storyboard"
            _write_ipa(ipa, members)

            result = ios_analyze(ipa)

            self.assertEqual(result["status"], "partial")
            self.assertTrue(result["native_binaries"]["encrypted"])
            entry = result["native_binaries"]["entries"][0]
            self.assertTrue(entry["encrypted"])
            self.assertEqual(entry["encryption_info"][0]["cryptid"], 1)
            self.assertEqual(result["semantic_ir_fragment"]["status"], "partial")
            self.assertEqual(result["decompilation"]["status"], "unavailable")
            self.assertFalse(result["decompilation"]["attempted"])
            self.assertFalse(result["decompilation"]["succeeded"])

    def test_corrupt_macho_and_plist_propagate_partial_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            corrupt_binary = root / "corrupt-binary.ipa"
            members = _base_members(macho=b"\xcf\xfa\xed\xfe\x0c")
            members[f"{APP_ROOT}/Base.lproj/Main.storyboard"] = b"storyboard"
            _write_ipa(corrupt_binary, members)

            binary_result = ios_analyze(corrupt_binary)

            self.assertEqual(binary_result["status"], "partial")
            self.assertEqual(binary_result["native_binaries"]["status"], "partial")
            self.assertEqual(
                binary_result["native_binaries"]["entries"][0]["status"],
                "unavailable",
            )
            self.assertNotEqual(binary_result["semantic_ir_fragment"]["status"], "ok")

            corrupt_plist = root / "corrupt-plist.ipa"
            _write_ipa(
                corrupt_plist,
                {
                    f"{APP_ROOT}/Info.plist": b"<plist><dict><key>CFBundleIdentifier</key>",
                    f"{APP_ROOT}/Demo": _thin_macho(),
                    f"{APP_ROOT}/Base.lproj/Main.storyboard": b"storyboard",
                },
            )

            plist_result = ios_analyze(corrupt_plist)

            self.assertIn(plist_result["status"], {"partial", "failed"})
            self.assertEqual(plist_result["manifest"]["status"], "unavailable")
            self.assertNotEqual(plist_result["semantic_ir_fragment"]["status"], "ok")

    def test_entry_and_member_limits_are_reported_without_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ipa = Path(tmp) / "limits.ipa"
            members = _base_members(
                macho=_thin_macho(strings=("SwiftUI",)),
                info_overrides={"UIMainStoryboardFile": None},
            )
            members[f"{APP_ROOT}/z-one.dat"] = b"1"
            members[f"{APP_ROOT}/z-two.dat"] = b"2"
            _write_ipa(ipa, members)

            with mock.patch.object(ios_module, "_MAX_ZIP_ENTRIES", 2):
                entry_limited = ios_analyze(ipa)

            self.assertEqual(entry_limited["status"], "partial")
            self.assertTrue(entry_limited["archive"]["entry_limit_hit"])
            self.assertEqual(entry_limited["archive"]["members_extracted"], 0)

            with mock.patch.object(ios_module, "_MAX_DECLARED_MEMBER_BYTES", 4):
                member_limited = ios_analyze(ipa)

            self.assertIn(member_limited["status"], {"partial", "failed"})
            self.assertGreater(member_limited["archive"]["unsafe_entry_count"], 0)

    def test_missing_non_ipa_and_bad_zip_keep_stable_failed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.ipa"
            non_ipa = root / "sample.exe"
            bad_zip = root / "bad.ipa"
            non_ipa.write_bytes(b"MZ")
            bad_zip.write_bytes(b"not-a-zip")

            for index, sample in enumerate((missing, non_ipa, bad_zip)):
                with self.subTest(sample=sample.name):
                    out_dir = root / f"analysis-{index}"
                    result = ios_analyze(sample, out_dir)

                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(result["manifest"]["status"], "unavailable")
                    self.assertEqual(result["resources"]["status"], "unavailable")
                    self.assertEqual(result["native_binaries"]["status"], "unavailable")
                    self.assertEqual(result["framework"]["name"], "unknown")
                    self.assertEqual(result["semantic_ir_fragment"]["status"], "unavailable")
                    self.assertFalse(result["decompilation"]["succeeded"])
                    self.assertEqual(len(result["artifacts"]), 5)
                    self.assertTrue(
                        all(Path(item["path"]).is_file() for item in result["artifacts"])
                    )


def _base_members(
    *,
    macho: bytes,
    plist_format: plistlib.PlistFormat = plistlib.FMT_XML,
    info_overrides: dict[str, object] | None = None,
) -> dict[str, bytes]:
    info: dict[str, object] = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleExecutable": "Demo",
        "CFBundleName": "Demo",
        "CFBundleDisplayName": "Demo App",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "42",
        "MinimumOSVersion": "15.0",
        "UIMainStoryboardFile": "Main",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo"]}],
    }
    for key, value in (info_overrides or {}).items():
        if value is None:
            info.pop(key, None)
        else:
            info[key] = value
    return {
        f"{APP_ROOT}/Info.plist": plistlib.dumps(info, fmt=plist_format, sort_keys=True),
        f"{APP_ROOT}/Demo": macho,
    }


def _write_ipa(
    path: Path,
    members: dict[str, bytes] | list[tuple[str, bytes]],
) -> None:
    entries = members.items() if isinstance(members, dict) else members
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)


def _thin_macho(
    *,
    cputype: int = ARM64,
    cryptid: int = 0,
    dylibs: tuple[str, ...] = (),
    strings: tuple[str, ...] = (),
) -> bytes:
    commands = [struct.pack("<IIIIII", 0x2C, 24, 0x1000, 0x2000, cryptid, 0)]
    for dylib in dylibs:
        encoded = dylib.encode("utf-8") + b"\x00"
        command_size = (24 + len(encoded) + 7) & ~7
        command = struct.pack("<IIIIII", 0xC, command_size, 24, 0, 0, 0)
        commands.append(command + encoded + (b"\x00" * (command_size - 24 - len(encoded))))
    load_commands = b"".join(commands)
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        cputype,
        0,
        2,
        len(commands),
        len(load_commands),
        0,
        0,
    )
    suffix = b"\x00".join(item.encode("utf-8") for item in strings)
    return header + load_commands + suffix


def _fat_macho(slices: tuple[bytes, ...], cpu_types: tuple[int, ...]) -> bytes:
    table_size = 8 + (20 * len(slices))
    cursor = (table_size + 0xFF) & ~0xFF
    records = []
    placements = []
    for cputype, macho in zip(cpu_types, slices):
        records.append(struct.pack(">IIIII", cputype, 0, cursor, len(macho), 8))
        placements.append((cursor, macho))
        cursor = (cursor + len(macho) + 0xFF) & ~0xFF
    output = bytearray(struct.pack(">II", 0xCAFEBABE, len(slices)) + b"".join(records))
    output.extend(b"\x00" * (cursor - len(output)))
    for offset, macho in placements:
        output[offset : offset + len(macho)] = macho
    return bytes(output)


def _mark_member_encrypted(path: Path, member_name: str) -> None:
    data = bytearray(path.read_bytes())
    encoded_name = member_name.encode("utf-8")
    cursor = 0
    while cursor < len(data) - 4:
        signature = bytes(data[cursor : cursor + 4])
        if signature == b"PK\x03\x04":
            name_length = struct.unpack_from("<H", data, cursor + 26)[0]
            extra_length = struct.unpack_from("<H", data, cursor + 28)[0]
            name = bytes(data[cursor + 30 : cursor + 30 + name_length])
            if name == encoded_name:
                flags = struct.unpack_from("<H", data, cursor + 6)[0]
                struct.pack_into("<H", data, cursor + 6, flags | 1)
            compressed_size = struct.unpack_from("<I", data, cursor + 18)[0]
            cursor += 30 + name_length + extra_length + compressed_size
            continue
        if signature == b"PK\x01\x02":
            name_length = struct.unpack_from("<H", data, cursor + 28)[0]
            extra_length = struct.unpack_from("<H", data, cursor + 30)[0]
            comment_length = struct.unpack_from("<H", data, cursor + 32)[0]
            name = bytes(data[cursor + 46 : cursor + 46 + name_length])
            if name == encoded_name:
                flags = struct.unpack_from("<H", data, cursor + 8)[0]
                struct.pack_into("<H", data, cursor + 8, flags | 1)
            cursor += 46 + name_length + extra_length + comment_length
            continue
        cursor += 1
    path.write_bytes(data)


if __name__ == "__main__":
    main()
