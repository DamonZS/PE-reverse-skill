import subprocess
import sys
import unittest


class PackageImportRegressionTests(unittest.TestCase):
    def test_patch_and_tools_packages_import_in_fresh_interpreters(self) -> None:
        snippets = (
            "import reverse_analyzer.patch; import reverse_analyzer.tools",
            "import reverse_analyzer.tools; import reverse_analyzer.patch",
            (
                "from reverse_analyzer.patch.dll_proxy "
                "import generate_dll_proxy_project"
            ),
            (
                "from reverse_analyzer.tools import AndroidNativePatchError, "
                "android_native_patch_apk"
            ),
            (
                "from reverse_analyzer.providers import EngineRuntimeProvider, "
                "ImGuiHostOrchestrator, parse_engine_runtime_dump"
            ),
        )
        for snippet in snippets:
            with self.subTest(snippet=snippet):
                completed = subprocess.run(
                    [sys.executable, "-c", snippet],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
