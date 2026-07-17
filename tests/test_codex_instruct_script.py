import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.llm_jailbreak.instruction_assets import (
    list_instruction_profiles,
    load_instruction_bundle,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "codex-instruct.py"
REVERSE_SKILL_PATH = (
    REPOSITORY_ROOT
    / "reverse-skills"
    / "skills"
    / "reverse-engineering"
    / "SKILL.md"
)


class CodexInstructScriptTests(unittest.TestCase):
    def run_script(
        self,
        *arguments: object,
        cwd: Path,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "ascii"
        return subprocess.run(
            [sys.executable, str(SCRIPT_PATH), *(str(item) for item in arguments)],
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )

    @staticmethod
    def make_codex_dir(root: Path) -> Path:
        codex_dir = root / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text(
            'model = "gpt-5.5-codex"\nmodel_reasoning_effort = "high"\n',
            encoding="utf-8",
        )
        return codex_dir

    def test_script_does_not_embed_a_duplicate_builtin_prompt(self):
        source = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertNotIn("BUILTIN_MD", source)
        self.assertTrue(source.isascii(), repr(source))

    def test_help_output_is_ascii_and_documents_asset_compatible_file_option(self):
        result = self.run_script("--help", cwd=REPOSITORY_ROOT)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.isascii(), repr(result.stdout))
        self.assertIn(
            "Deploy a Markdown instruction bundle to Codex installations.",
            result.stdout,
        )
        self.assertIn(
            "--file reverse-skills/skills/reverse-engineering/SKILL.md",
            result.stdout,
        )
        self.assertIn("Use a repository reverse-skill asset", result.stdout)
        self.assertIn("--profile codex-unified", result.stdout)

    def test_list_profiles_uses_shared_instruction_registry_without_codex_home(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_script("--list-profiles", cwd=Path(directory))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            list(list_instruction_profiles()),
        )

    def test_named_profile_deploys_the_same_bundle_used_by_campaigns(self):
        expected = load_instruction_bundle("codex-unified")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)
            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--profile",
                "codex-unified",
                "--name",
                "codex-unified",
                cwd=root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (codex_dir / "codex-unified.md").read_text(encoding="utf-8"),
                expected.content,
            )

    def test_default_deploy_loads_ctf_profile_from_example_asset(self):
        expected = load_instruction_bundle("ctf-sandbox")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)
            original_config = (codex_dir / "config.toml").read_bytes()

            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--name",
                "ctf-rules",
                cwd=root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (codex_dir / "ctf-rules.md").read_text(encoding="utf-8"),
                expected.content,
            )
            self.assertEqual(
                expected.assets[0].source,
                "scripts/codex-instruct-examples/ctf-sandbox.md",
            )
            resolved_codex_dir = codex_dir.resolve()
            self.assertTrue(result.stdout.isascii(), repr(result.stdout))
            self.assertIn("[+] Found 1 Codex installation(s):", result.stdout)
            self.assertIn(
                f"-- Deploying to: {resolved_codex_dir} --",
                result.stdout,
            )
            self.assertIn(
                f"[write] {resolved_codex_dir / 'ctf-rules.md'}",
                result.stdout,
            )
            self.assertIn(
                '[config] Set model_instructions_file = "./ctf-rules.md"',
                result.stdout,
            )
            self.assertIn(
                "[done] Deployed to 1 Codex installation(s).",
                result.stdout,
            )
            config = (codex_dir / "config.toml").read_text(encoding="utf-8")
            self.assertIn(
                'model = "gpt-5.5-codex"\n'
                'model_instructions_file = "./ctf-rules.md"\n',
                config,
            )
            backups = list(codex_dir.glob("config.toml.bak_*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original_config)
            self.assertIn(
                f"[backup] config.toml -> {backups[0].name}",
                result.stdout,
            )

    def test_file_option_loads_a_real_reverse_skill_through_asset_api(self):
        expected = load_instruction_bundle(files=(REVERSE_SKILL_PATH,))
        relative_skill_path = REVERSE_SKILL_PATH.relative_to(REPOSITORY_ROOT)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)

            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--file",
                relative_skill_path,
                "--name",
                "reverse-engineering",
                cwd=REPOSITORY_ROOT,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (codex_dir / "reverse-engineering.md").read_text(encoding="utf-8"),
                expected.content,
            )
            self.assertEqual(
                expected.assets[0].source,
                relative_skill_path.as_posix(),
            )

    def test_existing_matching_config_keeps_legacy_skip_and_backup_behavior(self):
        expected = load_instruction_bundle("ctf-sandbox")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)
            config_path = codex_dir / "config.toml"
            original_config = (
                'model = "gpt-5.5-codex"\n'
                'model_instructions_file = "./existing-rules.md"\n'
                'model_reasoning_effort = "high"\n'
            ).encode()
            config_path.write_bytes(original_config)

            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--name",
                "existing-rules",
                cwd=root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(config_path.read_bytes(), original_config)
            self.assertEqual(
                (codex_dir / "existing-rules.md").read_text(encoding="utf-8"),
                expected.content,
            )
            backups = list(codex_dir.glob("config.toml.bak_*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original_config)
            self.assertIn(
                "[config] model_instructions_file already has the requested value; "
                "skipped",
                result.stdout,
            )

    def test_dry_run_preserves_files_and_uses_plain_console_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)
            original_config = (codex_dir / "config.toml").read_bytes()

            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--dry-run",
                cwd=root,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "[DRY RUN] Preview only; no files will be changed.",
                result.stdout,
            )
            self.assertIn(
                f"-> Write Markdown: {codex_dir.resolve() / 'gpt5.5-unrestricted.md'}",
                result.stdout,
            )
            self.assertIn(
                '-> Config: model_instructions_file = "./gpt5.5-unrestricted.md"',
                result.stdout,
            )
            self.assertNotIn("-- Deploying to:", result.stdout)
            self.assertTrue(result.stdout.isascii(), repr(result.stdout))
            self.assertEqual((codex_dir / "config.toml").read_bytes(), original_config)
            self.assertFalse((codex_dir / "gpt5.5-unrestricted.md").exists())
            self.assertEqual(list(codex_dir.glob("config.toml.bak_*")), [])

    def test_missing_custom_file_keeps_legacy_error_behavior(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            codex_dir = self.make_codex_dir(root)
            missing = root / "missing.md"

            result = self.run_script(
                "--codex-dir",
                codex_dir,
                "--file",
                missing,
                cwd=root,
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn(f"[error] File not found: {missing}", result.stdout)
            self.assertFalse((codex_dir / "gpt5.5-unrestricted.md").exists())
            self.assertEqual(list(codex_dir.glob("config.toml.bak_*")), [])


if __name__ == "__main__":
    unittest.main()
