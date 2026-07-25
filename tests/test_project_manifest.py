import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.source.project_manifest import build_project_manifests


class ProjectManifestTests(unittest.TestCase):
    def test_apktool_project_is_a_locked_buildable_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            target = project / "targets" / "mobile" / "source" / "apktool"
            target.mkdir(parents=True)
            (target / "apktool.yml").write_text("version: 2.9.3\n", encoding="utf-8")
            (target / "AndroidManifest.xml").write_text("<manifest package=\"fixture\" />\n", encoding="utf-8")
            (target / "Main.java").write_text("class Main {}\n", encoding="utf-8")

            result = build_project_manifests(project, [{"id": "mobile", "kind": "android-package"}])

            self.assertTrue(result["project_manifest"]["structure_complete"])
            self.assertTrue(result["dependency_lock"]["dependencies_locked"])
            self.assertTrue(result["build_readiness"]["build_ready"])
            descriptor = result["project_manifest"]["targets"][0]["build_descriptors"][0]
            self.assertEqual(descriptor["build_system"], "apktool")

    def test_fully_locked_native_fixture_is_build_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "composite"
            target = project / "targets" / "app"
            vendor = target / "vendor" / "helper"
            vendor.mkdir(parents=True)
            (target / "main.c").write_text("int main(void) { return helper(); }\n", encoding="utf-8")
            (vendor / "helper.c").write_text("int helper(void) { return 0; }\n", encoding="utf-8")
            (target / "CMakeLists.txt").write_text(
                "add_library(helper STATIC vendor/helper/helper.c)\n"
                "add_executable(app main.c)\n"
                "target_link_libraries(app PRIVATE helper)\n",
                encoding="utf-8",
            )

            result = build_project_manifests(project, [{"id": "app", "kind": "windows-executable"}])

            self.assertTrue(result["project_manifest"]["structure_complete"])
            self.assertTrue(result["dependency_lock"]["dependencies_locked"])
            self.assertTrue(result["build_readiness"]["build_ready"])
            dependency = result["dependency_lock"]["dependencies"][0]
            self.assertEqual(dependency["source"], "local")
            self.assertTrue(dependency["integrity"].startswith("sha256:"))
            for name in ("project-manifest.json", "dependencies.lock.json", "build-readiness.json"):
                payload = json.loads((project / "docs" / name).read_text(encoding="utf-8"))
                self.assertEqual(payload["schema_version"], 1)

    def test_missing_structure_and_floating_dependency_are_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "composite"
            app = project / "targets" / "app"
            empty = project / "targets" / "empty"
            app.mkdir(parents=True)
            empty.mkdir(parents=True)
            (app / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (app / "CMakeLists.txt").write_text(
                "find_package(OpenSSL REQUIRED)\n"
                "add_executable(app main.c)\n"
                "target_link_libraries(app PRIVATE OpenSSL::SSL)\n",
                encoding="utf-8",
            )

            result = build_project_manifests(project, [{"id": "app"}, {"id": "empty"}])

            self.assertFalse(result["project_manifest"]["structure_complete"])
            self.assertFalse(result["dependency_lock"]["dependencies_locked"])
            self.assertFalse(result["build_readiness"]["build_ready"])
            codes = {item["code"] for item in result["build_readiness"]["blockers"]}
            self.assertEqual(codes, {"missing_source", "missing_build_descriptor", "dependency_not_locked"})
            openssl = next(item for item in result["dependency_lock"]["dependencies"] if item["name"] == "OpenSSL")
            self.assertIsNone(openssl["version"])
            self.assertFalse(openssl["locked"])

    def test_exact_python_version_without_hash_remains_unlocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "composite"
            target = project / "targets" / "service"
            target.mkdir(parents=True)
            (target / "main.py").write_text("print('ready')\n", encoding="utf-8")
            (target / "pyproject.toml").write_text(
                '[build-system]\nrequires = ["setuptools==70.0.0"]\nbuild-backend = "setuptools.build_meta"\n'
                '[project]\nname = "service"\nversion = "1.0.0"\ndependencies = ["requests==2.32.3"]\n',
                encoding="utf-8",
            )

            result = build_project_manifests(project, [{"id": "service"}])

            self.assertTrue(result["project_manifest"]["structure_complete"])
            self.assertFalse(result["dependency_lock"]["dependencies_locked"])
            self.assertEqual(result["dependency_lock"]["dependencies"][0]["version"], "2.32.3")

    def test_requirements_file_does_not_substitute_for_build_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "composite"
            target = project / "targets" / "script"
            target.mkdir(parents=True)
            (target / "main.py").write_text("print('ready')\n", encoding="utf-8")
            (target / "requirements.txt").write_text(
                "requests==2.32.3 --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )

            result = build_project_manifests(project, [{"id": "script"}])

            self.assertFalse(result["project_manifest"]["structure_complete"])
            self.assertTrue(result["dependency_lock"]["dependencies_locked"])
            self.assertEqual(result["dependency_lock"]["dependencies"][0]["version"], "2.32.3")

    def test_unsupported_descriptor_cannot_be_silently_locked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "composite"
            target = project / "targets" / "service"
            target.mkdir(parents=True)
            (target / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
            (target / "go.mod").write_text("module example/service\ngo 1.23\nrequire example.org/lib v1.2.3\n", encoding="utf-8")

            result = build_project_manifests(project, [{"id": "service"}])

            self.assertTrue(result["project_manifest"]["structure_complete"])
            self.assertFalse(result["dependency_lock"]["dependencies_locked"])
            self.assertEqual(result["dependency_lock"]["dependencies"][0]["name"], "example.org/lib")
            self.assertEqual(result["dependency_lock"]["dependencies"][0]["version"], "v1.2.3")
            readiness = result["build_readiness"]
            self.assertEqual(readiness["target_count"], 1)
            self.assertEqual(readiness["dependency_count"], 1)
            self.assertTrue(readiness["blocking_reasons"])


if __name__ == "__main__":
    unittest.main()
