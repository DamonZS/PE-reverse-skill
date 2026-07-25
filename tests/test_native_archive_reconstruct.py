from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from reverse_analyzer.archive_reconstruct import _capability_commands, extract_archive
from reverse_analyzer.native_reconstruct import reconstruct_native


@unittest.skipUnless(shutil.which("cc") and shutil.which("readelf") and shutil.which("objdump"), "native compiler and binutils required")
class NativeArchiveReconstructionTests(unittest.TestCase):
    def test_compiled_elf_is_magic_detected_and_produces_real_evidence_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "fixture.c"
            binary = root / "misleading.exe"
            source.write_text('#include <stdio.h>\nint main(void){puts("native-p11-evidence");return 7;}\n', encoding="utf-8")
            completed = subprocess.run(["cc", str(source), "-o", str(binary)], capture_output=True, text=True, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            archive = root / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.write(binary, "program.exe")
            package = root / "package"
            inventory = extract_archive(archive, package)
            self.assertEqual(inventory[0]["kind"], "linux-native-executable")
            self.assertEqual(inventory[0]["detection"], "elf_magic")
            self.assertTrue(inventory[0]["analysis_target"])
            commands = _capability_commands(package / "program.exe", root / "analysis")
            self.assertEqual(commands[0]["capability"], "elf-binutils-source-reconstruction")

            result = reconstruct_native(package / "program.exe", root / "analysis")
            self.assertEqual(result["provider"], "local-binutils")
            self.assertTrue(result["provenance"]["real_subprocess"])
            self.assertFalse(result["provenance"]["runner_injected"])
            self.assertTrue((root / "analysis/source/CMakeLists.txt").is_file())
            self.assertIn("native-p11-evidence", (root / "analysis/source/main.c").read_text(encoding="utf-8"))
            artifact = json.loads((root / "analysis/native-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(artifact["target"]["magic"], "7f454c46")


if __name__ == "__main__":
    unittest.main()
