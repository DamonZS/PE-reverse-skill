from __future__ import annotations

import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

from reverse_analyzer.tools.android import JadxCommandOutput, android_analyze


ANDROID_NS = "http://schemas.android.com/apk/res/android"


class _RecordingJadxRunner:
    def __init__(self, *, returncode: int = 0, create_sources: bool = True) -> None:
        self.returncode = returncode
        self.create_sources = create_sources
        self.calls: list[dict[str, object]] = []

    def __call__(
        self,
        command: list[str],
        *,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> JadxCommandOutput:
        self.calls.append(
            {
                "command": list(command),
                "timeout_seconds": timeout_seconds,
                "max_output_bytes": max_output_bytes,
            }
        )
        output_dir = Path(command[command.index("-d") + 1])
        sample = Path(command[-1])
        executable = Path(command[0])
        if self.create_sources:
            source_dir = output_dir / "sources" / "com" / "example"
            source_dir.mkdir(parents=True, exist_ok=True)
            (source_dir / "MainActivity.java").write_text(
                "package com.example; public class MainActivity {}\n",
                encoding="utf-8",
            )
            (source_dir / "KotlinFacade.kt").write_text(
                "package com.example\nclass KotlinFacade\n",
                encoding="utf-8",
            )
        return JadxCommandOutput(
            returncode=self.returncode,
            stdout=f"input={sample} output={output_dir} executable={executable}",
            stderr="synthetic JADX warning" if self.returncode else "",
        )


class AndroidJadxTests(unittest.TestCase):
    def test_default_analysis_does_not_discover_or_run_jadx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            _write_apk(apk)

            def forbidden_finder(name: str) -> str | None:
                self.fail(f"unexpected executable discovery: {name}")

            result = android_analyze(
                apk,
                out_dir,
                jadx_executable_finder=forbidden_finder,
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "ok", result["warnings"])
            self.assertEqual(section["status"], "unavailable")
            self.assertFalse(section["requested"])
            self.assertEqual(section["dependency"]["state"], "not_requested")
            self.assertFalse((out_dir / "android" / "jadx").exists())
            self.assertTrue((out_dir / "android" / "java_decompilation.json").is_file())

    def test_explicit_config_runs_bounded_jadx_and_persists_sources(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            executable = root / "tools" / "jadx.exe"
            executable.parent.mkdir()
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            runner = _RecordingJadxRunner()
            discoveries: list[str] = []

            def finder(name: str) -> str | None:
                discoveries.append(name)
                return str(executable) if name == "jadx" else None

            result = android_analyze(
                apk,
                out_dir,
                config={
                    "java_decompilation": {
                        "enabled": True,
                        "timeout_seconds": 45,
                        "max_output_bytes": 2_048,
                        "threads": 1,
                    }
                },
                jadx_runner=runner,
                jadx_executable_finder=finder,
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "ok", result["warnings"])
            self.assertEqual(section["status"], "passed", section)
            self.assertTrue(section["requested"])
            self.assertEqual(discoveries, ["jadx"])
            self.assertEqual(len(runner.calls), 1)
            call = runner.calls[0]
            command = call["command"]
            self.assertIsInstance(command, list)
            self.assertEqual(command[0], str(executable.resolve()))
            self.assertEqual(command[command.index("-d") + 1], str((out_dir / "android" / "jadx").resolve()))
            self.assertIn("--no-res", command)
            self.assertEqual(command[command.index("-j") + 1], "1")
            self.assertEqual(command[-1], str(apk.resolve()))
            self.assertEqual(call["timeout_seconds"], 45.0)
            self.assertEqual(call["max_output_bytes"], 2_048)

            self.assertEqual(
                section["command"],
                ["jadx", "-d", "<ANDROID_JADX_DIR>", "--no-res", "-j", "1", "<APK>"],
            )
            self.assertNotIn(str(root), json.dumps(section))
            self.assertIn("<APK>", section["stdout"])
            self.assertIn("<ANDROID_JADX_DIR>", section["stdout"])
            self.assertTrue(section["target"]["unchanged"])
            self.assertEqual(section["output"]["source_file_count"], 2)
            self.assertEqual(section["output"]["java_file_count"], 1)
            self.assertEqual(section["output"]["kotlin_file_count"], 1)
            self.assertTrue(
                all(item["sha256"] for item in section["output"]["files"])
            )

            artifact_names = {item["name"] for item in result["artifacts"]}
            self.assertIn("android/java_decompilation.json", artifact_names)
            self.assertIn(
                "android/jadx/sources/com/example/MainActivity.java",
                artifact_names,
            )
            self.assertIn(
                "android/jadx/sources/com/example/KotlinFacade.kt",
                artifact_names,
            )
            persisted = json.loads(
                (out_dir / "android" / "java_decompilation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(persisted, section)

    def test_production_runner_probes_jadx_before_decompilation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            executable = root / "jadx.exe"
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            commands: list[list[str]] = []

            def bounded_runner(
                command: list[str],
                *,
                timeout_seconds: float,
                max_output_bytes: int,
            ) -> JadxCommandOutput:
                commands.append(list(command))
                if any("--version" in item for item in command):
                    self.assertLessEqual(timeout_seconds, 15.0)
                    self.assertEqual(max_output_bytes, 64 * 1024)
                    return JadxCommandOutput(0, "1.5.1\n", "")
                output_dir = Path(command[command.index("-d") + 1])
                source_dir = output_dir / "sources" / "com" / "example"
                source_dir.mkdir(parents=True)
                (source_dir / "Main.java").write_text("class Main {}\n", encoding="utf-8")
                return JadxCommandOutput(0, "complete", "")

            with patch(
                "reverse_analyzer.tools.android._run_bounded_jadx_command",
                side_effect=bounded_runner,
            ):
                result = android_analyze(
                    apk,
                    out_dir,
                    config={
                        "java_decompilation": {
                            "enabled": True,
                            "executable": str(executable),
                        }
                    },
                )

            section = result["java_decompilation"]
            self.assertEqual(section["status"], "passed", section)
            self.assertEqual(len(commands), 2)
            self.assertEqual(section["dependency"]["probe"]["status"], "passed")
            self.assertEqual(section["dependency"]["probe"]["version"], "1.5.1")
            self.assertEqual(section["dependency"]["probe"]["command"], ["jadx", "--version"])

    def test_failed_production_probe_stops_before_jadx_output_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            executable = root / "jadx.exe"
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            commands: list[list[str]] = []

            def failed_probe(
                command: list[str],
                *,
                timeout_seconds: float,
                max_output_bytes: int,
            ) -> JadxCommandOutput:
                commands.append(list(command))
                return JadxCommandOutput(1, "", "broken runtime")

            with patch(
                "reverse_analyzer.tools.android._run_bounded_jadx_command",
                side_effect=failed_probe,
            ):
                result = android_analyze(
                    apk,
                    out_dir,
                    config={
                        "java_decompilation": {
                            "enabled": True,
                            "executable": str(executable),
                        }
                    },
                )

            section = result["java_decompilation"]
            self.assertEqual(section["status"], "unavailable")
            self.assertEqual(section["dependency"]["state"], "unavailable")
            self.assertEqual(section["dependency"]["probe"]["status"], "failed")
            self.assertEqual(section["dependency"]["probe"]["version"], "broken runtime")
            self.assertEqual(len(commands), 1)
            self.assertFalse((out_dir / "android" / "jadx").exists())

    def test_evidence_flag_can_explicitly_request_jadx(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            executable = root / "jadx"
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            runner = _RecordingJadxRunner()

            result = android_analyze(
                apk,
                root / "out",
                evidence={"request_java_decompilation": True},
                jadx_runner=runner,
                jadx_executable_finder=lambda name: str(executable) if name == "jadx" else None,
            )

            self.assertEqual(result["java_decompilation"]["status"], "passed")
            self.assertEqual(len(runner.calls), 1)

    def test_missing_dependency_is_unavailable_and_not_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            _write_apk(apk)
            discoveries: list[str] = []

            def finder(name: str) -> str | None:
                discoveries.append(name)
                return None

            result = android_analyze(
                apk,
                out_dir,
                config={"java_decompilation": {"enabled": True}},
                jadx_runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
                jadx_executable_finder=finder,
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "unavailable")
            self.assertTrue(section["requested"])
            self.assertEqual(section["dependency"]["state"], "unavailable")
            self.assertEqual(discoveries, ["jadx", "jadx.bat"])
            self.assertFalse((out_dir / "android" / "jadx").exists())
            self.assertEqual(
                json.loads(
                    (out_dir / "android" / "java_decompilation.json").read_text(encoding="utf-8")
                )["status"],
                "unavailable",
            )

    def test_nonzero_exit_is_failed_even_when_partial_sources_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            executable = root / "jadx"
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            runner = _RecordingJadxRunner(returncode=3)

            result = android_analyze(
                apk,
                root / "out",
                config={"java_decompilation": {"enabled": True}},
                jadx_runner=runner,
                jadx_executable_finder=lambda _name: str(executable),
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "failed")
            self.assertEqual(section["returncode"], 3)
            self.assertEqual(section["output"]["source_file_count"], 2)
            self.assertIn("status 3", section["reason"])

    def test_zero_exit_without_java_or_kotlin_sources_is_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            executable = root / "jadx"
            executable.write_bytes(b"fixture")
            _write_apk(apk)

            result = android_analyze(
                apk,
                root / "out",
                config={"java_decompilation": {"enabled": True}},
                jadx_runner=_RecordingJadxRunner(create_sources=False),
                jadx_executable_finder=lambda _name: str(executable),
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "failed")
            self.assertEqual(section["returncode"], 0)
            self.assertEqual(section["output"]["source_file_count"], 0)
            self.assertIn("without producing Java or Kotlin", section["reason"])

    def test_generated_file_and_byte_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "jadx"
            executable.write_bytes(b"fixture")

            for name, limit, expected_reason in (
                ("file-limit", {"max_generated_files": 1}, "more than 1 files"),
                ("byte-limit", {"max_generated_bytes": 8}, "more than 8 bytes"),
            ):
                with self.subTest(case=name):
                    apk = root / f"{name}.apk"
                    _write_apk(apk)
                    result = android_analyze(
                        apk,
                        root / name,
                        config={"java_decompilation": {"enabled": True, **limit}},
                        jadx_runner=_RecordingJadxRunner(),
                        jadx_executable_finder=lambda _tool: str(executable),
                    )

                    section = result["java_decompilation"]
                    self.assertEqual(result["status"], "partial")
                    self.assertEqual(section["status"], "failed")
                    self.assertIn(expected_reason, section["reason"])

    def test_input_apk_mutation_is_rejected_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            executable = root / "jadx"
            executable.write_bytes(b"fixture")
            _write_apk(apk)
            delegate = _RecordingJadxRunner()

            def mutating_runner(command: list[str], **kwargs: object) -> JadxCommandOutput:
                output = delegate(command, **kwargs)
                with Path(command[-1]).open("ab") as stream:
                    stream.write(b"modified-by-test")
                return output

            result = android_analyze(
                apk,
                root / "out",
                config={"java_decompilation": {"enabled": True}},
                jadx_runner=mutating_runner,
                jadx_executable_finder=lambda _name: str(executable),
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "failed")
            self.assertFalse(section["target"]["unchanged"])
            self.assertNotEqual(
                section["target"]["sha256_before"],
                section["target"]["sha256_after"],
            )
            self.assertIn("modified the input APK", section["reason"])

    def test_explicit_missing_executable_is_gracefully_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            missing = root / "tools" / "missing-jadx"
            _write_apk(apk)

            result = android_analyze(
                apk,
                root / "out",
                config={
                    "java_decompilation": {
                        "enabled": True,
                        "executable": str(missing),
                    }
                },
                jadx_runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
                jadx_executable_finder=lambda _name: self.fail("finder must not execute"),
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "unavailable")
            self.assertEqual(section["dependency"]["state"], "unavailable")
            self.assertIn("explicit path missing", section["reason"])

    def test_executable_finder_error_is_gracefully_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            _write_apk(apk)

            def failing_finder(_name: str) -> str | None:
                raise OSError("PATH lookup failed")

            result = android_analyze(
                apk,
                root / "out",
                config={"java_decompilation": {"enabled": True}},
                jadx_runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
                jadx_executable_finder=failing_finder,
            )

            section = result["java_decompilation"]
            self.assertEqual(result["status"], "partial")
            self.assertEqual(section["status"], "unavailable")
            self.assertEqual(section["dependency"]["state"], "unavailable")
            self.assertIn("executable discovery failed", section["reason"])

    def test_timeout_and_captured_output_limit_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "jadx"
            executable.write_bytes(b"fixture")

            for name, runner, config, expected_reason in (
                (
                    "timeout",
                    lambda command, **_kwargs: (_ for _ in ()).throw(
                        subprocess.TimeoutExpired(command, 1)
                    ),
                    {"timeout_seconds": 1},
                    "timed out",
                ),
                (
                    "output-limit",
                    lambda _command, **_kwargs: JadxCommandOutput(
                        returncode=0,
                        stdout="x" * 65,
                    ),
                    {"max_output_bytes": 64},
                    "exceeded 64 bytes",
                ),
            ):
                with self.subTest(case=name):
                    apk = root / f"{name}.apk"
                    out_dir = root / name
                    _write_apk(apk)
                    result = android_analyze(
                        apk,
                        out_dir,
                        config={"java_decompilation": {"enabled": True, **config}},
                        jadx_runner=runner,
                        jadx_executable_finder=lambda _tool: str(executable),
                    )
                    section = result["java_decompilation"]
                    self.assertEqual(section["status"], "failed")
                    self.assertIn(expected_reason, section["reason"])

    def test_output_directory_escape_is_rejected_before_discovery_or_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / "sample.apk"
            out_dir = root / "out"
            escaped = out_dir / "escape"
            _write_apk(apk)

            result = android_analyze(
                apk,
                out_dir,
                config={
                    "java_decompilation": {
                        "enabled": True,
                        "output_dir": "../escape",
                    }
                },
                jadx_runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
                jadx_executable_finder=lambda _name: self.fail("finder must not execute"),
            )

            section = result["java_decompilation"]
            self.assertEqual(section["status"], "failed")
            self.assertIn("non-canonical", section["reason"])
            self.assertFalse(escaped.exists())
            self.assertTrue((out_dir / "android" / "java_decompilation.json").is_file())


def _write_apk(path: Path) -> None:
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="{ANDROID_NS}" package="com.example.jadx">
  <application android:label="Jadx"><activity android:name=".MainActivity" /></application>
</manifest>
""".encode("utf-8")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", _empty_valid_dex())
        archive.writestr("res/layout/activity_main.xml", b"<LinearLayout />")


def _empty_valid_dex() -> bytes:
    dex = bytearray(112)
    dex[:8] = b"dex\n035\x00"
    dex[12:32] = b"\x11" * 20
    struct.pack_into("<I", dex, 32, len(dex))
    struct.pack_into("<I", dex, 36, 112)
    struct.pack_into("<I", dex, 40, 0x12345678)
    struct.pack_into("<I", dex, 8, zlib.adler32(dex[12:]) & 0xFFFFFFFF)
    return bytes(dex)


if __name__ == "__main__":
    unittest.main()
