from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib.parse import urlparse


class GitHubToolManifestTests(unittest.TestCase):
    def test_manifest_references_existing_providers_and_official_sources(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "config" / "github-tools.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["policy"], "official-source-only")
        self.assertGreaterEqual(len(manifest["tools"]), 8)
        for entry in manifest["tools"]:
            self.assertTrue(entry["source"].startswith("https://github.com/"))
            self.assertEqual(urlparse(entry["source"]).hostname, "github.com")
            self.assertEqual(urlparse(entry["download"]).hostname, "github.com")
            self.assertTrue(entry["classification"])
            self.assertIn(entry["distribution"], {"release-archive", "source-release"})
            self.assertTrue(entry["provider_modules"])
            for module in entry["provider_modules"]:
                provider = (root / module).resolve()
                self.assertTrue(provider.is_relative_to(root.resolve()), module)
                self.assertEqual(provider.suffix, ".py")
                self.assertTrue(provider.is_file(), module)

    def test_manifest_does_not_claim_installed_or_verified(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifest = json.loads((root / "config" / "github-tools.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["installation_policy"], "manual-reviewed-only")
        for entry in manifest["tools"]:
            self.assertEqual(entry["version"], "operator-selected")
            self.assertTrue(entry["environment"])

    def test_script_validates_manifest_without_downloading_tools(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is not available")
        root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [shell, "-NoProfile", "-File", str(root / "scripts" / "install_github_tools.ps1"), "-ListOnly"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = completed.stdout.lower() + completed.stderr.lower()
        self.assertIn("classification", output)
        self.assertIn("operator-selected", output)

    def test_script_rejects_unknown_id_even_when_a_known_id_is_present(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is not available")
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [
                    shell,
                    "-NoProfile",
                    "-File",
                    str(root / "scripts" / "install_github_tools.ps1"),
                    "-Destination",
                    temporary,
                    "-Tool",
                    "ghidra,unknown-tool",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unknown", completed.stdout.lower() + completed.stderr.lower())

    def test_script_rejects_provider_path_outside_repository(self) -> None:
        shell = shutil.which("pwsh") or shutil.which("powershell")
        if shell is None:
            self.skipTest("PowerShell is not available")
        root = Path(__file__).resolve().parents[1]
        manifest = {
            "schema_version": 1,
            "policy": "official-source-only",
            "installation_policy": "manual-reviewed-only",
            "tools": [
                {
                    "id": "invalid",
                    "classification": "test",
                    "distribution": "source-release",
                    "provider_modules": ["../outside.py"],
                    "source": "https://github.com/example/example",
                    "download": "https://github.com/example/example/releases/latest",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            manifest_path = Path(temporary) / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            completed = subprocess.run(
                [
                    shell,
                    "-NoProfile",
                    "-File",
                    str(root / "scripts" / "install_github_tools.ps1"),
                    "-Manifest",
                    str(manifest_path),
                    "-ListOnly",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("provider module", completed.stdout.lower() + completed.stderr.lower())


if __name__ == "__main__":
    unittest.main()
