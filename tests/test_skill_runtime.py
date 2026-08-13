import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.skills import SkillCatalog, SkillRouter, SkillRoutingError


ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = ROOT / "reverse-skills" / "skills"
SCRIPTS = SKILLS_ROOT / "scripts"


class SkillRuntimeTests(unittest.TestCase):
    def test_url_descriptor_routes_without_network_access(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        decision = router.route(
            "inspect the API interface",
            endpoint="https://api.example.test/v1/openapi.json",
            interface="rest",
            package="openapi",
        )
        self.assertEqual(decision["primary"]["skill_id"], "interface-analysis")
        self.assertEqual(decision["input"]["endpoint"], "https://api.example.test/v1/openapi.json")
        self.assertIn("url-descriptor", decision["input"]["kinds"])

    def test_package_and_protection_routes_include_workflow_and_gate(self) -> None:
        catalog = SkillCatalog(ROOT / "reverse-skills")
        package = catalog.route("unpack client", target="client.apk", package="android")
        self.assertEqual(package["primary"]["skill_id"], "apk-reverse")
        self.assertEqual(package["workflow"]["master"]["path"], "SKILL.md")
        self.assertTrue(package["workflow"]["stages"][0]["skill"])

        protection = catalog.route("review anti-cheat integrity", package="windows-game")
        self.assertEqual(protection["primary"]["skill_id"], "protection-review")
        self.assertIn("anti_tamper_lab", protection["primary"]["capability_candidates"])

    def test_plain_local_files_do_not_accidentally_select_controlled_routes(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        self.assertEqual(router.route("", target="client.apk")["primary"]["skill_id"], "apk-reverse")
        self.assertEqual(router.route("inspect binary", target="client.exe")["primary"]["skill_id"], "pe-static-analysis")
        self.assertEqual(router.route("inspect library", target="client.dll")["primary"]["skill_id"], "pe-static-analysis")

    def test_imported_reverse_skill_routes_match_expected_domains(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        self.assertEqual(
            router.route("inspect chrome extension manifest", target="plugin.crx")["primary"]["skill_id"],
            "browser-extension-reverse",
        )
        self.assertEqual(
            router.route("analyze protobuf traffic", target="capture.pcapng", interface="protocol")["primary"]["skill_id"],
            "protocol-reverse",
        )
        self.assertEqual(
            router.route("review a memory dump timeline", target="host.dmp", package="forensics")["primary"]["skill_id"],
            "digital-forensics",
        )
        self.assertEqual(
            router.route("open-source decompiler workflow with ghidra", target="sample.exe")["primary"]["skill_id"],
            "ghidra-reverse",
        )

    def test_cli_routes_endpoint_descriptors(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "reverse_analyzer",
                "skills",
                "route",
                "inspect endpoint",
                "--endpoint",
                "https://api.example.test/v1",
                "--interface",
                "rest",
                "--package",
                "openapi",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["primary"]["skill_id"], "interface-analysis")

    def test_catalog_exposes_declared_route_scripts(self) -> None:
        catalog = SkillCatalog(ROOT / "reverse-skills")
        triage = catalog.get("pe-triage")
        self.assertIsNotNone(triage)
        assert triage is not None
        self.assertIn("skills/scripts/case-init.py", triage.scripts)
        self.assertIn("skills/scripts/master-route.py", triage.scripts)

        audit = catalog.audit()
        self.assertEqual(audit["skill_runtime"]["status"], "ready")
        self.assertGreaterEqual(audit["script_backed_count"], 5)

    def test_cli_and_script_share_hyphenated_route_normalization(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        expected = router.route("data-flow", target="sample.exe")["primary"]["skill_id"]
        self.assertEqual(expected, "pe-deep-analysis")

        cli = subprocess.run(
            [
                sys.executable,
                "-m",
                "reverse_analyzer",
                "skills",
                "route",
                "data-flow",
                "--target",
                "sample.exe",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(json.loads(cli.stdout)["primary"]["skill_id"], expected)

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "master-route.py"),
                "--intent",
                "data-flow",
                "--target",
                "sample.exe",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["route"]["primary"]["skill_id"], expected)

    def test_explicit_skill_id_uses_the_router_plan(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        expected = router.route_by_id("pe-triage", target="sample.exe")

        completed = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS / "master-route.py"),
                "--skill-id",
                "pe-triage",
                "--target",
                "sample.exe",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["route"], expected)
        self.assertTrue(expected["next_actions"])

    def test_cli_route_rejects_remote_targets_and_invalid_limits(self) -> None:
        remote = subprocess.run(
            [
                sys.executable,
                "-m",
                "reverse_analyzer",
                "skills",
                "route",
                "inspect imports",
                "--target",
                "https://example.test/sample.exe",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(remote.returncode, 2)
        self.assertIn("local path", remote.stderr)

        invalid_limit = subprocess.run(
            [
                sys.executable,
                "-m",
                "reverse_analyzer",
                "skills",
                "route",
                "inspect imports",
                "--limit",
                "0",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(invalid_limit.returncode, 2)
        self.assertIn("at least 1", invalid_limit.stderr)

    def test_router_rejects_remote_uri_targets(self) -> None:
        router = SkillRouter(ROOT / "reverse-skills")
        with self.assertRaises(SkillRoutingError):
            router.route("inspect imports", target="https://example.test/sample.exe")
        with self.assertRaises(SkillRoutingError):
            router.route_by_id("pe-triage", target="https://example.test/sample.exe")

    def test_nested_route_ids_attach_catalog_records_and_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suite = root / "skills"
            (suite / "config").mkdir(parents=True)
            (suite / "nested" / "example" / "scripts").mkdir(parents=True)
            (suite / "scripts").mkdir()
            (suite / "nested" / "example" / "SKILL.md").write_text(
                "---\nname: example\ndescription: Nested example skill.\n---\n\n# Example\n",
                encoding="utf-8",
            )
            (suite / "scripts" / "helper.py").write_text("pass\n", encoding="utf-8")
            routing = {
                "version": 1,
                "fallback_skill_id": "nested/example",
                "routes": [
                    {
                        "skill_id": "nested/example",
                        "title": "Nested example",
                        "phase": "test",
                        "priority": 10,
                        "keywords": ["nested"],
                        "extensions": [],
                        "tools": [],
                        "scripts": ["scripts/helper.py"],
                        "requires_authorization": False,
                        "execution_boundary": "plan_only",
                    }
                ],
            }
            (suite / "config" / "routing.json").write_text(json.dumps(routing), encoding="utf-8")

            catalog = SkillCatalog(root)
            decision = catalog.route("nested")
            record = decision["primary"]["skill"]
            self.assertEqual(record["id"], "skills/nested/example")
            self.assertIn("skills/scripts/helper.py", record["scripts"])

            cli = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "reverse_analyzer",
                    "skills",
                    "--root",
                    str(root),
                    "route",
                    "nested",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(cli.returncode, 0, cli.stderr)
            self.assertEqual(json.loads(cli.stdout)["primary"]["skill_id"], "nested/example")

    def test_case_scripts_create_and_review_a_local_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            case_dir = Path(directory) / "demo-case"
            created = subprocess.run(
                [sys.executable, str(SCRIPTS / "case-init.py"), "--case-dir", str(case_dir)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertTrue((case_dir / "case.json").is_file())

            reviewed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "review-case.py"),
                    "--case-dir",
                    str(case_dir),
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
            payload = json.loads(reviewed.stdout)
            self.assertTrue(payload["ok"])
            self.assertIn("case has no evidence entries yet", payload["warnings"])

    def test_skill_suite_verifier_accepts_checked_in_assets(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPTS / "verify-skill-suite.py"), "--strict-index", "--format", "json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(completed.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
