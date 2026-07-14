import hashlib
import json
import shutil
import stat
import struct
import tempfile
import unittest
import warnings
from pathlib import Path
from typing import Any, Mapping
import zipfile

from reverse_analyzer.tools.android_native_patch import (
    ApkPatchLimits,
    android_native_patch_apk,
    rollback_android_native_patch_apk,
    verify_android_native_patch_apk,
)


ARM_BASE = 0x1000
ARM_CODE_OFFSET = 0x100
ARM_CODE_VA = ARM_BASE + ARM_CODE_OFFSET
ARM_CODE = bytes.fromhex("00 f0 20 e3 00 f0 20 e3 00 f0 20 e3 00 f0 20 e3")
PATCHED_ARM_INSTRUCTION = bytes.fromhex("01 00 a0 e3")
TARGET_MEMBER = "lib/armeabi-v7a/libfixture.so"
AARCH64_BASE = 0x400000
AARCH64_CODE_OFFSET = 0x100
AARCH64_CODE_VA = AARCH64_BASE + AARCH64_CODE_OFFSET
AARCH64_CODE = bytes.fromhex("1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5")
AARCH64_PATCH = bytes.fromhex("c0 03 5f d6")
AARCH64_MEMBER = "lib/arm64-v8a/libfixture.so"


def _minimal_arm_elf32(*, machine: int = 40, relocation_va: int | None = None) -> bytes:
    section_table = 0x220
    data = bytearray(0x2A0)
    data[:16] = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIIIIIHHHHHH",
        data,
        16,
        3,
        machine,
        1,
        ARM_CODE_VA,
        52,
        section_table,
        0x05000000,
        52,
        32,
        1,
        40,
        3,
        0,
    )
    struct.pack_into(
        "<IIIIIIII",
        data,
        52,
        1,
        0,
        ARM_BASE,
        ARM_BASE,
        0x200,
        0x200,
        0x5,
        0x1000,
    )
    data[ARM_CODE_OFFSET : ARM_CODE_OFFSET + len(ARM_CODE)] = ARM_CODE
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 40,
        0,
        1,
        0x6,
        ARM_CODE_VA,
        ARM_CODE_OFFSET,
        0x40,
        0,
        0,
        4,
        0,
    )
    relocation_size = 8 if relocation_va is not None else 0
    struct.pack_into(
        "<IIIIIIIIII",
        data,
        section_table + 80,
        0,
        9,
        0,
        0,
        0x180,
        relocation_size,
        0,
        1,
        4,
        8,
    )
    if relocation_va is not None:
        struct.pack_into("<II", data, 0x180, relocation_va, (1 << 8) | 2)
    jni_names = b"JNI_OnLoad\x00Java_com_example_Native_ping\x00"
    data[0x1A0 : 0x1A0 + len(jni_names)] = jni_names
    return bytes(data)


def _minimal_aarch64_elf64(*, relocation_va: int | None = None) -> bytes:
    section_table = 0x240
    data = bytearray(0x310)
    data[:16] = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        data,
        16,
        3,
        183,
        1,
        AARCH64_CODE_VA,
        64,
        section_table,
        0,
        64,
        56,
        1,
        64,
        3,
        0,
    )
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        64,
        1,
        0x5,
        0,
        AARCH64_BASE,
        AARCH64_BASE,
        0x200,
        0x200,
        0x1000,
    )
    data[AARCH64_CODE_OFFSET : AARCH64_CODE_OFFSET + len(AARCH64_CODE)] = AARCH64_CODE
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table + 64,
        0,
        1,
        0x6,
        AARCH64_CODE_VA,
        AARCH64_CODE_OFFSET,
        0x40,
        0,
        0,
        4,
        0,
    )
    relocation_size = 24 if relocation_va is not None else 0
    struct.pack_into(
        "<IIQQQQIIQQ",
        data,
        section_table + 128,
        0,
        4,
        0,
        0,
        0x180,
        relocation_size,
        0,
        1,
        8,
        24,
    )
    if relocation_va is not None:
        struct.pack_into("<QQq", data, 0x180, relocation_va, (1 << 32) | 257, 0)
    jni_names = b"JNI_OnLoad\x00Java_com_example_Native_ping\x00"
    data[0x1A0 : 0x1A0 + len(jni_names)] = jni_names
    return bytes(data)


def _zip_info(
    name: str,
    *,
    compress_type: int = zipfile.ZIP_DEFLATED,
    mode: int = 0o100640,
    comment: bytes = b"entry-comment",
) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(2024, 2, 3, 4, 5, 6))
    info.compress_type = compress_type
    info.comment = comment
    info.extra = struct.pack("<HH2s", 0xCAFE, 2, b"ok")
    info.create_system = 3
    info.external_attr = mode << 16
    info.internal_attr = 1
    return info


def _write_apk(
    path: Path,
    *,
    elf: bytes | None = None,
    target_member: str = TARGET_MEMBER,
    extra_entries: list[tuple[zipfile.ZipInfo | str, bytes]] | None = None,
    include_signatures: bool = True,
) -> None:
    payload = elf if elf is not None else _minimal_arm_elf32(relocation_va=ARM_CODE_VA + 0x20)
    entries: list[tuple[zipfile.ZipInfo | str, bytes]] = [
        (_zip_info("AndroidManifest.xml", compress_type=zipfile.ZIP_STORED), b"manifest"),
        (_zip_info("assets/config.bin"), b"configuration-data"),
        (_zip_info(target_member), payload),
        (_zip_info("META-INF/NOTICE", comment=b"notice-comment"), b"notice"),
    ]
    entries.extend(extra_entries or [])
    if include_signatures:
        entries.extend(
            [
                (_zip_info("META-INF/MANIFEST.MF"), b"Signature-Version: 1.0\n"),
                (_zip_info("META-INF/CERT.SF"), b"signature-file"),
                (_zip_info("META-INF/CERT.RSA"), b"not-a-real-certificate"),
            ]
        )
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        archive.comment = b"apk-archive-comment"
        for info, data in entries:
            archive.writestr(info, data)


def _sha256(value: bytes | Path) -> str:
    payload = value.read_bytes() if isinstance(value, Path) else value
    return hashlib.sha256(payload).hexdigest()


def _replace_raw_zip_name(path: Path, old: str, new: str) -> None:
    old_bytes = old.encode("utf-8")
    new_bytes = new.encode("utf-8")
    if len(old_bytes) != len(new_bytes):
        raise AssertionError("raw ZIP name replacement must preserve byte length")
    payload = path.read_bytes()
    if payload.count(old_bytes) < 2:
        raise AssertionError("ZIP member name was not found in local and central headers")
    path.write_bytes(payload.replace(old_bytes, new_bytes))


def _add_apk_signing_block_fixture(path: Path) -> None:
    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        raise AssertionError("ZIP EOCD was not found")
    central_offset = struct.unpack_from("<I", payload, eocd_offset + 16)[0]
    block = struct.pack("<Q", 24) + struct.pack("<Q", 24) + b"APK Sig Block 42"
    payload[central_offset:central_offset] = block
    struct.pack_into("<I", payload, eocd_offset + len(block) + 16, central_offset + len(block))
    path.write_bytes(payload)


def _application_infos(path: Path) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(path, "r") as archive:
        return [
            info
            for info in archive.infolist()
            if info.filename
            not in {"META-INF/MANIFEST.MF", "META-INF/CERT.SF", "META-INF/CERT.RSA"}
        ]


def _metadata(info: zipfile.ZipInfo) -> tuple[Any, ...]:
    return (
        info.filename,
        info.compress_type,
        info.date_time,
        info.comment,
        info.extra,
        info.create_system,
        info.create_version,
        info.extract_version,
        info.internal_attr,
        info.external_attr,
    )


def _data(result: Any) -> Mapping[str, Any]:
    value = getattr(result, "data", None)
    return value if isinstance(value, Mapping) else {}


class AndroidNativePatchApkTests(unittest.TestCase):
    def _patch(
        self,
        root: Path,
        apk: Path,
        *,
        name: str = "patched",
        sign: bool = False,
        abi: str = "armeabi-v7a",
        library_path: str = "libfixture.so",
        limits: ApkPatchLimits | Mapping[str, Any] | None = None,
    ) -> Any:
        return android_native_patch_apk(
            apk,
            abi=abi,
            library_path=library_path,
            out_path=root / f"{name}.apk",
            artifact_dir=root / f"{name}-artifacts",
            file_offset=ARM_CODE_OFFSET,
            expected=ARM_CODE[:4],
            replacement=PATCHED_ARM_INSTRUCTION,
            instruction_mode="arm",
            sign=sign,
            signing={"keystore": root / "missing.jks"} if sign else None,
            apksigner=root / "missing-apksigner",
            apktool=root / "missing-apktool",
            limits=limits,
        )

    def test_patch_verify_and_rollback_preserve_evidence_and_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)
            _add_apk_signing_block_fixture(source)
            source_bytes = source.read_bytes()
            source_infos = _application_infos(source)
            with zipfile.ZipFile(source, "r") as archive:
                source_so = archive.read(TARGET_MEMBER)

            result = self._patch(root, source)

            self.assertEqual(result.status, "ok", result.to_dict())
            data = _data(result)
            output = Path(str(data["patched_apk_path"]))
            artifacts = root / "patched-artifacts"
            self.assertEqual(source.read_bytes(), source_bytes)
            self.assertEqual(data["source_sha256"], _sha256(source_bytes))
            self.assertTrue(data["original_apk_unchanged"])
            self.assertTrue(output.is_file())
            self.assertEqual(data["signing"]["status"], "dependency-gated")
            self.assertFalse(data["signing"]["signed"])
            self.assertFalse(data["signing"]["install_ready"])
            self.assertTrue(data["signing"]["before"]["material_present"])
            self.assertTrue(data["signing"]["before"]["apk_signing_block_present"])
            self.assertFalse(data["signing"]["after"]["material_present"])
            self.assertFalse(data["signing"]["after"]["apk_signing_block_present"])
            self.assertTrue(data["elf"]["invariants"]["machine_abi_preserved"])
            self.assertTrue(data["elf"]["invariants"]["jni_exports_preserved"])
            self.assertTrue(data["elf"]["invariants"]["relocations_preserved"])
            self.assertEqual(data["elf"]["before"]["relocation_count"], 1)
            self.assertEqual(
                data["elf"]["before"]["jni_exports"],
                ["JNI_OnLoad", "Java_com_example_Native_ping"],
            )

            for name in (
                "native-patch-plan.json",
                "native-patch-verify.json",
                "rollback.json",
                "unsigned-patched.apk",
                "elf-plan/plan.json",
                "elf-apply/rollback.json",
                "elf-rollback-proof/restored.so",
            ):
                self.assertTrue((artifacts / name).is_file(), name)

            plan = json.loads((artifacts / "native-patch-plan.json").read_text("utf-8"))
            elf_plan = json.loads((artifacts / "elf-plan/plan.json").read_text("utf-8"))
            self.assertEqual(plan["source"]["sha256"], _sha256(source_bytes))
            self.assertEqual(elf_plan["target_identity"]["sha256"], _sha256(source_so))
            self.assertEqual(elf_plan["operations"][0]["preimage"], ARM_CODE[:4].hex())

            with zipfile.ZipFile(output, "r") as archive:
                names = archive.namelist()
                patched_so = archive.read(TARGET_MEMBER)
                self.assertEqual(archive.comment, b"apk-archive-comment")
                self.assertNotIn("META-INF/MANIFEST.MF", names)
                self.assertNotIn("META-INF/CERT.SF", names)
                self.assertNotIn("META-INF/CERT.RSA", names)
                self.assertEqual(archive.read("assets/config.bin"), b"configuration-data")
                self.assertEqual(archive.read("META-INF/NOTICE"), b"notice")
            self.assertNotEqual(patched_so, source_so)
            self.assertEqual(
                patched_so[ARM_CODE_OFFSET : ARM_CODE_OFFSET + 4],
                PATCHED_ARM_INSTRUCTION,
            )
            self.assertEqual(
                [_metadata(info) for info in _application_infos(output)],
                [_metadata(info) for info in source_infos],
            )

            verify_dir = root / "independent-verify"
            verified = verify_android_native_patch_apk(
                output,
                plan=artifacts / "native-patch-plan.json",
                out_dir=verify_dir,
                apksigner=root / "missing-apksigner",
            )
            self.assertEqual(verified.status, "ok", verified.to_dict())
            self.assertTrue(_data(verified)["valid"])
            self.assertTrue((verify_dir / "native-patch-verify.json").is_file())

            exact_output = root / "exact-rollback.apk"
            exact = rollback_android_native_patch_apk(
                output,
                rollback=artifacts / "rollback.json",
                out_path=exact_output,
                artifact_dir=root / "exact-rollback-artifacts",
                apksigner=root / "missing-apksigner",
            )
            self.assertEqual(exact.status, "ok", exact.to_dict())
            self.assertEqual(_data(exact)["restoration_mode"], "exact-source-copy")
            self.assertEqual(exact_output.read_bytes(), source_bytes)
            self.assertTrue((root / "exact-rollback-artifacts/rollback-verify.json").is_file())

            source.unlink()
            logical_output = root / "logical-rollback.apk"
            logical = rollback_android_native_patch_apk(
                output,
                rollback=artifacts / "rollback.json",
                out_path=logical_output,
                artifact_dir=root / "logical-rollback-artifacts",
                apksigner=root / "missing-apksigner",
            )
            self.assertEqual(logical.status, "ok", logical.to_dict())
            self.assertEqual(_data(logical)["restoration_mode"], "logical-unsigned-repack")
            with zipfile.ZipFile(logical_output, "r") as archive:
                self.assertEqual(archive.read(TARGET_MEMBER), source_so)
                self.assertNotIn("META-INF/CERT.RSA", archive.namelist())

    def test_independent_verify_rejects_tampered_apk_and_malformed_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source, include_signatures=False)
            patched = self._patch(root, source)
            self.assertEqual(patched.status, "ok", patched.to_dict())
            output = Path(str(_data(patched)["patched_apk_path"]))
            plan_path = root / "patched-artifacts/native-patch-plan.json"
            tampered = root / "tampered.apk"
            shutil.copyfile(output, tampered)
            with zipfile.ZipFile(tampered, "a") as archive:
                archive.comment = b"tampered-comment"

            verified = verify_android_native_patch_apk(
                tampered,
                plan=plan_path,
                out_dir=root / "tampered-verify",
                apksigner=root / "missing-apksigner",
            )
            self.assertEqual(verified.status, "failed", verified.to_dict())
            self.assertFalse(_data(verified)["valid"])
            self.assertIn("SHA-256", str(verified.error))

            malformed = json.loads(plan_path.read_text("utf-8"))
            del malformed["target"]["abi"]
            malformed_result = verify_android_native_patch_apk(
                output,
                plan=malformed,
                out_dir=root / "malformed-verify",
                apksigner=root / "missing-apksigner",
            )
            self.assertEqual(malformed_result.status, "failed", malformed_result.to_dict())

    def test_requested_signing_without_apksigner_retains_unsigned_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.apk"
            _write_apk(source)

            result = self._patch(root, source, sign=True)

            self.assertEqual(result.status, "dependency-gated", result.to_dict())
            data = _data(result)
            self.assertTrue(data["valid"])
            self.assertEqual(data["signing"]["gate"], "apksigner")
            self.assertFalse(data["signing"]["signed"])
            self.assertFalse(data["signing"]["install_ready"])
            self.assertTrue(Path(str(data["patched_apk_path"])).is_file())
            self.assertTrue((root / "patched-artifacts/unsigned-patched.apk").is_file())
            self.assertNotIn("sign_command", data["signing"])

    def test_unsafe_archives_limits_abi_and_library_paths_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = _minimal_arm_elf32()
            cases: list[tuple[str, Path, Mapping[str, Any]]] = []

            traversal = root / "traversal.apk"
            _write_apk(traversal, extra_entries=[("../escape.txt", b"escape")])
            cases.append(("traversal", traversal, {}))

            backslash = root / "backslash.apk"
            _write_apk(backslash, extra_entries=[("assets/escape.txt", b"escape")])
            _replace_raw_zip_name(backslash, "assets/escape.txt", "assets\\escape.txt")
            cases.append(("backslash", backslash, {}))

            duplicate = root / "duplicate.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                _write_apk(
                    duplicate,
                    extra_entries=[("assets/config.bin", b"duplicate")],
                )
            cases.append(("duplicate", duplicate, {}))

            count = root / "count.apk"
            _write_apk(count, include_signatures=False)
            cases.append(("count", count, {"limits": {"max_entries": 3}}))

            member = root / "member.apk"
            _write_apk(member, include_signatures=False)
            cases.append(
                (
                    "member",
                    member,
                    {"limits": {"max_member_bytes": len(elf) - 1}},
                )
            )

            total = root / "total.apk"
            _write_apk(total, include_signatures=False)
            cases.append(
                (
                    "total",
                    total,
                    {
                        "limits": {
                            "max_member_bytes": len(elf) + 1,
                            "max_total_uncompressed_bytes": len(elf) + 5,
                        }
                    },
                )
            )

            ratio = root / "ratio.apk"
            _write_apk(
                ratio,
                include_signatures=False,
                extra_entries=[(_zip_info("assets/zeros.bin"), b"\x00" * 4096)],
            )
            cases.append(("ratio", ratio, {"limits": {"max_compression_ratio": 2}}))

            archive_size = root / "archive-size.apk"
            _write_apk(archive_size, include_signatures=False)
            cases.append(("archive-size", archive_size, {"limits": {"max_archive_bytes": 1}}))

            symlink = root / "symlink.apk"
            _write_apk(
                symlink,
                include_signatures=False,
                extra_entries=[
                    (
                        _zip_info(
                            "assets/link",
                            mode=stat.S_IFLNK | 0o777,
                        ),
                        b"../outside",
                    )
                ],
            )
            cases.append(("symlink", symlink, {}))

            mismatch = root / "mismatch.apk"
            _write_apk(
                mismatch,
                target_member="lib/arm64-v8a/libfixture.so",
                include_signatures=False,
            )
            cases.append(
                (
                    "mismatch",
                    mismatch,
                    {"abi": "arm64-v8a", "library_path": "libfixture.so"},
                )
            )

            for name, apk, overrides in cases:
                with self.subTest(name=name):
                    result = android_native_patch_apk(
                        apk,
                        abi=str(overrides.get("abi", "armeabi-v7a")),
                        library_path=str(overrides.get("library_path", "libfixture.so")),
                        out_path=root / f"{name}-output.apk",
                        artifact_dir=root / f"{name}-artifacts",
                        file_offset=ARM_CODE_OFFSET,
                        expected=ARM_CODE[:4],
                        replacement=PATCHED_ARM_INSTRUCTION,
                        instruction_mode="arm",
                        apksigner=root / "missing-apksigner",
                        limits=overrides.get("limits"),
                    )
                    self.assertEqual(result.status, "failed", result.to_dict())
                    self.assertFalse((root / f"{name}-output.apk").exists())
                    self.assertFalse((root / f"{name}-artifacts").exists())

            safe = root / "safe.apk"
            _write_apk(safe, include_signatures=False)
            for index, library_path in enumerate(
                ("../libfixture.so", "lib/armeabi-v7a/../libfixture.so", "lib\\fixture.so")
            ):
                with self.subTest(library_path=library_path):
                    result = self._patch(
                        root,
                        safe,
                        name=f"bad-path-{index}",
                        library_path=library_path,
                    )
                    self.assertEqual(result.status, "failed", result.to_dict())
                    self.assertFalse((root / f"bad-path-{index}.apk").exists())


if __name__ == "__main__":
    unittest.main()
