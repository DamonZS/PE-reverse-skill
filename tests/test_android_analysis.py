import json
from pathlib import Path
import struct
import tempfile
from unittest import TestCase, main, mock
import zipfile
import zlib

from reverse_analyzer.tools import android as android_module
from reverse_analyzer.tools.android import android_analyze


ANDROID_NS = "http://schemas.android.com/apk/res/android"


class AndroidAnalysisTests(TestCase):
    def test_missing_and_non_apk_inputs_keep_stable_schema_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = root / "missing.apk"
            non_apk = root / "sample.exe"
            non_apk.write_bytes(b"MZ")

            cases = (
                (missing, root / "missing-analysis", "failed", "apk"),
                (non_apk, root / "non-apk-analysis", "unavailable", "unknown"),
            )
            for sample, out_dir, expected_status, expected_type in cases:
                with self.subTest(sample=sample.name):
                    result = android_analyze(sample, out_dir)

                    self.assertEqual(result["status"], expected_status)
                    self.assertEqual(result["package_type"], expected_type)
                    self.assertEqual(result["framework"]["name"], "unknown")
                    self.assertEqual(result["manifest"]["status"], "unavailable")
                    self.assertEqual(result["resources"]["status"], "unavailable")
                    self.assertEqual(result["dex_summary"]["status"], "unavailable")
                    self.assertEqual(result["native_libs"]["status"], "unavailable")
                    self.assertEqual(result["semantic_ir_fragment"]["status"], "unavailable")
                    self.assertEqual(len(result["artifacts"]), 7)
                    self.assertTrue(
                        all(Path(item["path"]).is_file() for item in result["artifacts"])
                    )

    def test_text_manifest_resources_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "ordinary.apk"
            out_dir = root / "analysis"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.ordinary"),
                    "classes.dex": _build_dex(["Lcom/example/ordinary/MainActivity;", "hello"]),
                    "resources.arsc": b"arsc",
                    "res/layout/activity_main.xml": b'<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" />',
                    "res/drawable/icon.png": b"\x89PNG\r\n\x1a\n",
                    "res/drawable/panel.xml": b'<shape xmlns:android="http://schemas.android.com/apk/res/android" />',
                    "res/values/strings.xml": b"<resources><string name=\"app_name\">Ordinary</string></resources>",
                    "assets/readme.txt": b"asset",
                },
            )

            result = android_analyze(apk, out_dir)

            self.assertEqual(result["status"], "ok", result.get("warnings"))
            self.assertEqual(result["manifest"]["parser"], "text_xml")
            self.assertEqual(result["manifest"]["package"], "com.example.ordinary")
            self.assertEqual(result["manifest"]["min_sdk"], "23")
            self.assertEqual(result["manifest"]["target_sdk"], "35")
            self.assertEqual(result["manifest"]["permission_count"], 1)
            self.assertEqual(result["manifest"]["component_counts"]["activities"], 1)
            self.assertEqual(result["resources"]["layout_count"], 1)
            self.assertEqual(result["resources"]["drawable_count"], 2)
            self.assertEqual(result["resources"]["layout_types"]["container"], 1)
            self.assertEqual(result["resources"]["drawable_types"]["shape"], 1)
            self.assertEqual(result["framework"]["name"], "android_xml")

            artifact_names = {item["name"] for item in result["artifacts"]}
            self.assertEqual(
                artifact_names,
                {
                    "android/manifest.json",
                    "android/resources.json",
                    "android/dex_summary.json",
                    "android/native_libs.json",
                    "android/framework.json",
                    "android/java_decompilation.json",
                    "android/semantic_ir_fragment.json",
                },
            )
            for artifact in result["artifacts"]:
                artifact_path = Path(artifact["path"])
                self.assertTrue(artifact_path.is_file())
                json.loads(artifact_path.read_text(encoding="utf-8"))

    def test_binary_axml_manifest_is_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "binary-manifest.apk"
            _write_apk(apk, {"AndroidManifest.xml": _build_binary_axml()})

            result = android_analyze(apk)

            manifest = result["manifest"]
            self.assertEqual(manifest["status"], "ok", manifest["warnings"])
            self.assertEqual(manifest["parser"], "binary_axml")
            self.assertFalse(manifest["textual"])
            self.assertEqual(manifest["package"], "com.example.binary")
            self.assertEqual(manifest["min_sdk"], 24)
            self.assertEqual(manifest["target_sdk"], 35)
            self.assertEqual(manifest["permissions"], ["android.permission.INTERNET"])
            self.assertEqual(manifest["activities"][0]["name"], ".MainActivity")

    def test_malformed_text_manifest_uses_bounded_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "fallback.apk"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": (
                        b'<manifest package="com.example.fallback">'
                        b'<uses-permission android:name="android.permission.CAMERA">'
                        b"<activity"
                    )
                },
            )

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["manifest"]["parser"], "text_fallback")
            self.assertEqual(result["manifest"]["package"], "com.example.fallback")
            self.assertIn("android.permission.CAMERA", result["manifest"]["permissions"])

    def test_manifest_rejects_entity_declaration_beyond_initial_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "entity.apk"
            manifest = (
                (b" " * 5_000)
                + b'<!DOCTYPE manifest [<!ENTITY pkg "com.example.entity">]>'
                + b'<manifest package="&pkg;"><application /></manifest>'
            )
            _write_apk(apk, {"AndroidManifest.xml": manifest})

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["manifest"]["status"], "partial")
            self.assertEqual(result["manifest"]["parser"], "text_fallback")
            self.assertNotEqual(result["manifest"]["package"], "com.example.entity")
            self.assertTrue(
                any("DTD/entity" in warning for warning in result["manifest"]["warnings"]),
                result["manifest"]["warnings"],
            )

    def test_manifest_element_limit_is_reported_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "element-limit.apk"
            manifest = (
                b'<manifest package="com.example.limit"><application>'
                b'<activity name=".One"/><activity name=".Two"/>'
                b"</application></manifest>"
            )
            _write_apk(apk, {"AndroidManifest.xml": manifest})

            with mock.patch.object(android_module, "_MAX_AXML_ELEMENTS", 2):
                result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["manifest"]["status"], "partial")
            self.assertTrue(
                any("element limit 2" in warning for warning in result["manifest"]["warnings"]),
                result["manifest"]["warnings"],
            )

    def test_dex_header_counts_checksum_and_string_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "dex.apk"
            dex = _build_dex(
                [
                    "java/lang/System",
                    "loadLibrary",
                    "demo",
                    "Lcom/example/Bridge;",
                    "https://api.example.test/v1",
                ]
            )
            _write_apk(apk, {"AndroidManifest.xml": _text_manifest("com.example.dex"), "classes.dex": dex})

            result = android_analyze(apk)

            summary = result["dex_summary"]
            self.assertEqual(summary["dex_count"], 1)
            self.assertEqual(summary["string_ids"], 5)
            self.assertEqual(summary["type_ids"], 2)
            self.assertEqual(summary["proto_ids"], 1)
            self.assertEqual(summary["field_ids"], 1)
            self.assertEqual(summary["method_ids"], 2)
            self.assertEqual(summary["class_defs"], 1)
            dex_file = summary["files"][0]
            self.assertEqual(dex_file["version"], "035")
            self.assertTrue(dex_file["checksum_valid"])
            self.assertTrue(dex_file["file_size_matches"])
            evidence = {item["value"]: item["category"] for item in summary["string_evidence"]}
            self.assertEqual(evidence["loadLibrary"], "native_loader")
            self.assertEqual(evidence["Lcom/example/Bridge;"], "class_descriptor")
            self.assertEqual(evidence["https://api.example.test/v1"], "endpoint")

    def test_truncated_dex_is_contained_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "truncated-dex.apk"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.truncated"),
                    "classes.dex": b"dex\n035\x00",
                },
            )

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["dex_summary"]["status"], "partial")
            self.assertEqual(result["dex_summary"]["invalid_count"], 1)
            self.assertEqual(result["dex_summary"]["files"][0]["status"], "unavailable")

    def test_flutter_and_unity_signals_report_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "conflict.apk"
            elf = _minimal_elf64()
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.conflict"),
                    "lib/arm64-v8a/libflutter.so": elf,
                    "lib/arm64-v8a/libunity.so": elf,
                    "assets/flutter_assets/AssetManifest.json": b"{}",
                    "assets/bin/Data/globalgamemanagers": b"unity",
                },
            )

            framework = android_analyze(apk)["framework"]

            candidates = {item["name"]: item for item in framework["candidates"]}
            self.assertGreater(candidates["flutter"]["score"], 0)
            self.assertGreater(candidates["unity"]["score"], 0)
            self.assertTrue(framework["conflict"]["is_conflicted"])
            self.assertGreaterEqual(framework["conflict"]["score"], 0.9)
            self.assertEqual({framework["name"], framework["conflict"]["runner_up"]}, {"flutter", "unity"})

    def test_compose_react_native_and_webview_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = (
                (
                    "compose.apk",
                    {
                        "AndroidManifest.xml": _text_manifest("com.example.compose"),
                        "classes.dex": _build_dex(
                            ["androidx/compose/runtime/Composable", "ComposeView"]
                        ),
                    },
                    "jetpack_compose",
                ),
                (
                    "react-native.apk",
                    {
                        "AndroidManifest.xml": _text_manifest("com.example.reactnative"),
                        "classes.dex": _build_dex(["com/facebook/react/ReactActivity"]),
                        "assets/index.android.bundle": b"__d(function() {});",
                    },
                    "react_native",
                ),
                (
                    "webview.apk",
                    {
                        "AndroidManifest.xml": _text_manifest("com.example.webview"),
                        "classes.dex": _build_dex(["android/webkit/WebView"]),
                        "assets/www/index.html": b"<html><body>local app</body></html>",
                        "assets/www/app.js": b"console.log('ready');",
                    },
                    "webview_hybrid",
                ),
            )
            for name, members, expected in cases:
                with self.subTest(framework=expected):
                    apk = root / name
                    _write_apk(apk, members)

                    framework = android_analyze(apk)["framework"]

                    self.assertEqual(framework["name"], expected, framework)
                    self.assertGreater(framework["confidence"], 0.5)
                    self.assertTrue(framework["evidence"])

    def test_unity_activity_manifest_signal_is_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "unity-activity.apk"
            manifest = f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.unity">
  <application>
    <activity android:name="com.unity3d.player.UnityPlayerActivity" />
  </application>
</manifest>
""".encode("utf-8")
            _write_apk(apk, {"AndroidManifest.xml": manifest})

            framework = android_analyze(apk)["framework"]

            self.assertEqual(framework["name"], "unity")
            self.assertTrue(any("UnityPlayerActivity" in item for item in framework["evidence"]))

    def test_native_elf_jni_and_java_library_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "native.apk"
            dex = _build_dex(
                [
                    "java/lang/System",
                    "loadLibrary",
                    "demo",
                    "Lcom/example/Bridge;",
                ]
            )
            elf = _minimal_elf64(b"JNI_OnLoad\x00Java_com_example_Bridge_nativePing\x00libdependency.so\x00")
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.nativeapp"),
                    "classes.dex": dex,
                    "lib/arm64-v8a/libdemo.so": elf,
                },
            )

            native = android_analyze(apk)["native_libs"]

            self.assertEqual(native["count"], 1)
            self.assertEqual(native["abis"], ["arm64-v8a"])
            entry = native["entries"][0]
            self.assertTrue(entry["elf"]["present"])
            self.assertEqual(entry["elf"]["class"], "ELF64")
            self.assertEqual(entry["elf"]["machine_name"], "AArch64")
            self.assertTrue(entry["elf"]["abi_consistent"])
            self.assertIn("JNI_OnLoad", entry["jni_exports"])
            self.assertIn("Java_com_example_Bridge_nativePing", entry["jni_exports"])
            link_kinds = {item["kind"] for item in native["java_native_links"]}
            self.assertEqual(link_kinds, {"loads_native_library", "jni_binding"})
            jni_link = next(item for item in native["java_native_links"] if item["kind"] == "jni_binding")
            self.assertEqual(jni_link["java_class"], "com.example.Bridge")
            self.assertEqual(jni_link["dex"], "classes.dex")

    def test_partial_elf_analysis_propagates_to_native_and_result_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "abi-mismatch.apk"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.mismatch"),
                    "lib/x86_64/libdemo.so": _minimal_elf64(),
                },
            )

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["native_libs"]["status"], "partial")
            self.assertEqual(result["native_libs"]["entries"][0]["elf"]["status"], "partial")
            self.assertFalse(result["native_libs"]["entries"][0]["elf"]["abi_consistent"])

    def test_truncated_deflate_stream_fails_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "broken-deflate.apk"
            manifest = b'<manifest package="com.example.broken">' + (b" " * 5_000) + b"</manifest>"
            _write_apk(apk, {"AndroidManifest.xml": manifest})
            archive_bytes = bytearray(apk.read_bytes())
            name_length, extra_length = struct.unpack_from("<HH", archive_bytes, 26)
            compressed_data_offset = 30 + name_length + extra_length
            archive_bytes[compressed_data_offset + 2] ^= 0xFF
            apk.write_bytes(archive_bytes)

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["manifest"]["status"], "unavailable")
            self.assertTrue(
                any("decompress" in warning.casefold() for warning in result["warnings"]),
                result["warnings"],
            )

    def test_truncated_resource_xml_marks_resource_summary_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "truncated-resource.apk"
            layout = b"<LinearLayout" + (b" " * 256) + b"/>"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.resource"),
                    "res/layout/activity_main.xml": layout,
                },
            )

            with mock.patch.object(android_module, "_MAX_RESOURCE_XML_BYTES", 64):
                result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["resources"]["status"], "partial")
            self.assertTrue(result["resources"]["layouts"][0]["truncated"])
            self.assertTrue(
                any("activity_main.xml" in warning and "limited" in warning for warning in result["warnings"]),
                result["warnings"],
            )

    def test_zip_slip_member_is_never_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "zip-slip.apk"
            out_dir = root / "analysis"
            escaped = root / "escaped.txt"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.zipslip"),
                    "../escaped.txt": b"must not be extracted",
                },
            )

            result = android_analyze(apk, out_dir)

            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["archive"]["unsafe_entry_count"], 1)
            self.assertEqual(result["archive"]["members_extracted"], 0)
            self.assertFalse(escaped.exists())
            self.assertTrue((out_dir / "android" / "manifest.json").is_file())

    def test_apk_without_manifest_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "missing-manifest.apk"
            _write_apk(apk, {"assets/readme.txt": b"no manifest"})

            result = android_analyze(apk)

            self.assertEqual(result["status"], "partial")
            self.assertFalse(result["manifest"]["present"])
            self.assertEqual(result["manifest"]["status"], "unavailable")
            self.assertTrue(
                any("AndroidManifest.xml is missing" in warning for warning in result["warnings"]),
                result["warnings"],
            )

    def test_corrupt_apk_is_unavailable_and_still_emits_partial_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "corrupt.apk"
            out_dir = root / "analysis"
            apk.write_bytes(b"PK\x03\x04truncated")

            result = android_analyze(apk, out_dir)

            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["package_type"], "apk")
            self.assertEqual(result["manifest"]["status"], "unavailable")
            self.assertEqual(result["dex_summary"]["status"], "unavailable")
            self.assertEqual(result["native_libs"]["status"], "unavailable")
            self.assertEqual(result["semantic_ir_fragment"]["status"], "unavailable")
            self.assertEqual(len(result["artifacts"]), 7)
            self.assertTrue((out_dir / "android" / "semantic_ir_fragment.json").is_file())
            json.dumps(result)

    def test_artifact_payload_schemas_are_stable_for_unavailable_apk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            valid_apk = root / "valid.apk"
            corrupt_apk = root / "corrupt.apk"
            out_dir = root / "analysis"
            _write_apk(valid_apk, {"AndroidManifest.xml": _text_manifest("com.example.schema")})
            corrupt_apk.write_bytes(b"not a ZIP archive")

            valid = android_analyze(valid_apk)
            unavailable = android_analyze(corrupt_apk, out_dir)

            for section in (
                "manifest",
                "resources",
                "dex_summary",
                "native_libs",
                "framework",
                "java_decompilation",
                "semantic_ir_fragment",
            ):
                self.assertEqual(set(unavailable[section]), set(valid[section]), section)

            self.assertEqual(
                [artifact["name"] for artifact in unavailable["artifacts"]],
                [
                    "android/manifest.json",
                    "android/resources.json",
                    "android/dex_summary.json",
                    "android/native_libs.json",
                    "android/framework.json",
                    "android/java_decompilation.json",
                    "android/semantic_ir_fragment.json",
                ],
            )
            for artifact in unavailable["artifacts"]:
                self.assertEqual(set(artifact), {"name", "path", "kind"})
                self.assertEqual(artifact["kind"], "android-analysis")

    def test_semantic_ir_fragment_uses_complete_deterministic_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "semantic.apk"
            _write_apk(
                apk,
                {
                    "AndroidManifest.xml": _text_manifest("com.example.semantic"),
                    "classes.dex": _build_dex(
                        [
                            "java/lang/System",
                            "loadLibrary",
                            "demo",
                            "Lcom/example/Bridge;",
                        ]
                    ),
                    "res/layout/activity_main.xml": b"<LinearLayout />",
                    "lib/arm64-v8a/libdemo.so": _minimal_elf64(
                        b"Java_com_example_Bridge_nativePing\x00"
                    ),
                },
            )

            result = android_analyze(apk)
            fragment = result["semantic_ir_fragment"]

            self.assertEqual(fragment["schema_version"], 1)
            self.assertEqual(fragment["source"], "android_analyze")
            self.assertEqual(fragment["artifacts"], [])
            self.assertEqual(
                fragment["summary"],
                {
                    "entity_count": len(fragment["entities"]),
                    "relation_count": len(fragment["relations"]),
                    "capability_count": len(fragment["capabilities"]),
                },
            )
            self.assertEqual(
                [item["id"] for item in fragment["entities"]],
                sorted(item["id"] for item in fragment["entities"]),
            )
            self.assertEqual(
                [item["id"] for item in fragment["relations"]],
                sorted(item["id"] for item in fragment["relations"]),
            )
            entity_ids = {item["id"] for item in fragment["entities"]}
            for entity in fragment["entities"]:
                self.assertTrue(
                    {"id", "kind", "name", "confidence", "sources", "attributes"}
                    <= set(entity)
                )
                self.assertTrue(entity["sources"])
            for relation in fragment["relations"]:
                self.assertTrue(
                    {"id", "type", "source", "target", "confidence", "sources"}
                    <= set(relation)
                )
                self.assertIn(relation["source"], entity_ids)
                self.assertIn(relation["target"], entity_ids)
                self.assertTrue(relation["sources"])
            for capability in fragment["capabilities"]:
                self.assertTrue(
                    {
                        "id",
                        "name",
                        "category",
                        "confidence",
                        "entity_ids",
                        "evidence_count",
                    }
                    <= set(capability)
                )
                self.assertTrue(set(capability["entity_ids"]) <= entity_ids)

            boundary = result["capability_boundary"]
            self.assertEqual(boundary["provider_kind"], "builtin")
            self.assertEqual(boundary["operation_kind"], "bounded_zip_static_analysis")
            self.assertEqual(boundary["dependency_state"], "not_required")
            self.assertEqual(boundary["required_tools"], [])
            self.assertFalse(boundary["content_recompiled"])
            self.assertFalse(boundary["code_executed"])
            self.assertFalse(boundary["members_extracted"])

    def test_analysis_is_independent_of_zip_central_directory_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            members = [
                ("assets/www/index.html", b"<html />"),
                ("lib/arm64-v8a/liborder.so", _minimal_elf64()),
                ("res/layout/activity_main.xml", b"<LinearLayout />"),
                ("classes2.dex", _build_dex(["second", "android/webkit/WebView"])),
                ("AndroidManifest.xml", _text_manifest("com.example.order")),
                ("classes.dex", _build_dex(["first", "Lcom/example/Order;"])),
                ("res/drawable/icon.png", b"\x89PNG\r\n\x1a\n"),
            ]
            forward = root / "forward.apk"
            reverse = root / "reverse.apk"
            _write_apk(forward, dict(members))
            _write_apk(reverse, dict(reversed(members)))

            forward_result = android_analyze(forward)
            reverse_result = android_analyze(reverse)

            for section in (
                "archive",
                "manifest",
                "resources",
                "dex_summary",
                "native_libs",
                "framework",
                "semantic_ir_fragment",
            ):
                with self.subTest(section=section):
                    self.assertEqual(forward_result[section], reverse_result[section])


def _text_manifest(package: str) -> bytes:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="{package}" android:versionCode="7" android:versionName="1.2">
  <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:name=".App">
    <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>
""".encode("utf-8")


def _write_apk(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def _build_dex(strings: list[str]) -> bytes:
    header_size = 112
    counts = {
        "string_ids": len(strings),
        "type_ids": 2,
        "proto_ids": 1,
        "field_ids": 1,
        "method_ids": 2,
        "class_defs": 1,
    }
    item_sizes = {
        "string_ids": 4,
        "type_ids": 4,
        "proto_ids": 12,
        "field_ids": 8,
        "method_ids": 8,
        "class_defs": 32,
    }
    offsets: dict[str, int] = {}
    cursor = header_size
    for name in item_sizes:
        offsets[name] = cursor
        cursor += counts[name] * item_sizes[name]
    data_offset = cursor
    string_data = bytearray()
    string_offsets: list[int] = []
    for value in strings:
        encoded = value.encode("utf-8")
        string_offsets.append(data_offset + len(string_data))
        string_data.extend(_uleb128(len(value)))
        string_data.extend(encoded)
        string_data.append(0)
    file_size = data_offset + len(string_data)
    dex = bytearray(file_size)
    dex[:8] = b"dex\n035\x00"
    dex[12:32] = b"\x11" * 20
    struct.pack_into("<I", dex, 32, file_size)
    struct.pack_into("<I", dex, 36, header_size)
    struct.pack_into("<I", dex, 40, 0x12345678)
    struct.pack_into("<III", dex, 44, 0, 0, 0)
    header_fields = (
        (56, "string_ids"),
        (64, "type_ids"),
        (72, "proto_ids"),
        (80, "field_ids"),
        (88, "method_ids"),
        (96, "class_defs"),
    )
    for field_offset, name in header_fields:
        struct.pack_into("<II", dex, field_offset, counts[name], offsets[name])
    struct.pack_into("<II", dex, 104, len(string_data), data_offset)
    for index, value_offset in enumerate(string_offsets):
        struct.pack_into("<I", dex, offsets["string_ids"] + (index * 4), value_offset)
    dex[data_offset:] = string_data
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]) & 0xFFFFFFFF)
    return bytes(dex)


def _uleb128(value: int) -> bytes:
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def _minimal_elf64(strings: bytes = b"") -> bytes:
    elf = bytearray(64)
    elf[:16] = b"\x7fELF\x02\x01\x01" + (b"\x00" * 9)
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        elf,
        16,
        3,
        183,
        1,
        0,
        0,
        0,
        0,
        64,
        0,
        0,
        0,
        0,
        0,
    )
    return bytes(elf) + b"\x00" + strings


def _build_binary_axml() -> bytes:
    strings = [
        "manifest",
        "package",
        "com.example.binary",
        "versionCode",
        "7",
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
        "uses-permission",
        "name",
        "android.permission.INTERNET",
        ANDROID_NS,
        "application",
        "activity",
        ".MainActivity",
        "exported",
    ]
    indexes = {value: index for index, value in enumerate(strings)}
    string_pool = _axml_string_pool(strings)
    no_index = 0xFFFFFFFF
    android_ns = indexes[ANDROID_NS]
    chunks = [
        _axml_element(
            indexes["manifest"],
            [
                (no_index, indexes["package"], indexes["com.example.binary"], 0x03, indexes["com.example.binary"]),
                (android_ns, indexes["versionCode"], indexes["7"], 0x03, indexes["7"]),
            ],
        ),
        _axml_element(
            indexes["uses-sdk"],
            [
                (android_ns, indexes["minSdkVersion"], no_index, 0x10, 24),
                (android_ns, indexes["targetSdkVersion"], no_index, 0x10, 35),
            ],
        ),
        _axml_element(
            indexes["uses-permission"],
            [(android_ns, indexes["name"], indexes["android.permission.INTERNET"], 0x03, indexes["android.permission.INTERNET"])],
        ),
        _axml_element(indexes["application"], []),
        _axml_element(
            indexes["activity"],
            [
                (android_ns, indexes["name"], indexes[".MainActivity"], 0x03, indexes[".MainActivity"]),
                (android_ns, indexes["exported"], no_index, 0x12, 1),
            ],
        ),
    ]
    body = string_pool + b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


def _axml_string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    data = bytearray()
    for value in strings:
        encoded = value.encode("utf-8")
        offsets.append(len(data))
        data.extend(_axml_length8(len(value)))
        data.extend(_axml_length8(len(encoded)))
        data.extend(encoded)
        data.append(0)
    while len(data) % 4:
        data.append(0)
    header_size = 28
    strings_start = header_size + (len(strings) * 4)
    chunk_size = strings_start + len(data)
    header = struct.pack("<HHIIIIII", 0x0001, header_size, chunk_size, len(strings), 0, 0x100, strings_start, 0)
    return header + struct.pack(f"<{len(offsets)}I", *offsets) + bytes(data)


def _axml_length8(value: int) -> bytes:
    if value > 0x7F:
        return bytes((0x80 | (value >> 8), value & 0xFF))
    return bytes((value,))


def _axml_element(name_index: int, attributes: list[tuple[int, int, int, int, int]]) -> bytes:
    chunk_size = 36 + (20 * len(attributes))
    node = struct.pack("<HHIII", 0x0102, 16, chunk_size, 1, 0xFFFFFFFF)
    extension = struct.pack("<IIHHHHHH", 0xFFFFFFFF, name_index, 20, 20, len(attributes), 0, 0, 0)
    encoded_attributes = b"".join(
        struct.pack("<IIIHBBI", namespace, name, raw, 8, 0, data_type, typed_data)
        for namespace, name, raw, data_type, typed_data in attributes
    )
    return node + extension + encoded_attributes


if __name__ == "__main__":
    main()
