"""Tests for the cross-platform instruction deployment framework.

Covers the shared safety model (allowed gate, dry-run read-only, uniform
platform surface) and each platform adapter's describe/plan behaviour.  All
tests are read-only: they never deploy to a real user config directory or
write outside a temporary sandbox.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.instructions import (
    ALL_PLATFORMS,
    INSTRUCTION_PROFILE,
    IDENTITY_WORD,
    PLATFORM_CLAUDE,
    PLATFORM_CODEX,
    PLATFORM_CURSOR,
    PLATFORM_WORKBUDDY,
    adapter_for,
    canonical_platform,
    deploy,
    deploy_all,
    inspect,
    list_platforms,
    platform_aliases,
    restore_all,
)
from reverse_analyzer.instructions.adapter import (
    InstructionDeployError,
    PlatformAdapter,
)
from reverse_analyzer.instructions.platforms import (
    ClaudeAdapter,
    CodexAdapter,
    CursorAdapter,
    WorkBuddyAdapter,
)


class RegistryTests(unittest.TestCase):
    def test_lists_all_platforms(self):
        self.assertEqual(
            list_platforms(),
            (PLATFORM_CODEX, PLATFORM_CLAUDE, PLATFORM_CURSOR, PLATFORM_WORKBUDDY),
        )

    def test_platform_aliases_include_trea_to_cursor(self):
        aliases = platform_aliases()
        self.assertEqual(aliases["trea"], PLATFORM_CURSOR)

    def test_canonical_platform_normalizes_case_and_aliases(self):
        for raw, expected in (
            ("CODEX", PLATFORM_CODEX),
            ("codex-cli", PLATFORM_CODEX),
            ("claude-desktop", PLATFORM_CLAUDE),
            ("TREA", PLATFORM_CURSOR),
            ("workbuddy-skill", PLATFORM_WORKBUDDY),
        ):
            self.assertEqual(canonical_platform(raw), expected)

    def test_unknown_platform_raises(self):
        with self.assertRaisesRegex(ValueError, "unknown platform"):
            canonical_platform("not-a-platform")

    def test_every_adapter_implements_platformadapter(self):
        for key in ALL_PLATFORMS:
            adapter = adapter_for(key)
            self.assertIsInstance(adapter, PlatformAdapter)
            self.assertEqual(adapter.platform, key)
            self.assertTrue(adapter.default_target().is_absolute() or adapter.default_target().is_relative_to(Path.home()))


class SharedSafetyModelTests(unittest.TestCase):
    """Tests that write-free describe/inspect work and deploy requires allowed."""

    def test_describe_is_read_only_and_returns_a_plan(self):
        for key in ALL_PLATFORMS:
            with self.subTest(platform=key):
                plan = adapter_for(key).describe()
                self.assertEqual(plan.platform, key)
                self.assertIsInstance(plan.operations, tuple)
                self.assertTrue(plan.target)

    def test_inspect_returns_structured_findings(self):
        for key in ALL_PLATFORMS:
            with self.subTest(platform=key):
                result = adapter_for(key).inspect()
                self.assertEqual(result["platform"], key)
                self.assertIn("findings", result)
                self.assertIn("exists", result)

    def test_deploy_requires_allowed_unless_force(self):
        for key in ALL_PLATFORMS:
            with self.subTest(platform=key):
                with self.assertRaises(InstructionDeployError):
                    deploy(key, allowed=False, force=False)

    def test_deploy_dry_run_returns_plan_without_force(self):
        # dry-run should not require allowed either (it writes nothing).
        for key in ALL_PLATFORMS:
            with self.subTest(platform=key):
                result = deploy(key, allowed=False, force=False, dry_run=True)
                self.assertEqual(result["status"], "dry-run")
                self.assertEqual(result["platform"], key)
                self.assertIn("plan", result)


class BatchDeployTests(unittest.TestCase):
    """deploy_all / restore_all cover every platform without touching the host."""

    def test_deploy_all_dry_run_previews_every_platform(self):
        # dry-run needs no allowed and writes nothing.
        result = deploy_all(allowed=False, force=False, dry_run=True)
        results = result["results"]
        self.assertEqual(set(results), set(ALL_PLATFORMS))
        for name in ALL_PLATFORMS:
            with self.subTest(platform=name):
                self.assertEqual(results[name]["status"], "dry-run")
                self.assertEqual(results[name]["platform"], name)
                self.assertIn("plan", results[name])

    def test_deploy_all_requires_allowed_unless_force(self):
        # Without allowed/force, every platform must refuse (status error), and
        # the batch must not abort on a single refusal.
        result = deploy_all(allowed=False, force=False, dry_run=False)
        for name in ALL_PLATFORMS:
            with self.subTest(platform=name):
                self.assertEqual(result["results"][name]["status"], "error")

    def test_restore_all_runs_on_every_platform(self):
        result = restore_all()
        self.assertEqual(set(result["results"]), set(ALL_PLATFORMS))
        for name in ALL_PLATFORMS:
            with self.subTest(platform=name):
                # restore may error (adapter not wired to a manifest) but must
                # not raise out of the batch; it is captured per platform.
                self.assertIn("status", result["results"][name])


class CodexAdapterTests(unittest.TestCase):
    def test_codex_describe_touches_instruction_and_skills(self):
        adapter = CodexAdapter()
        plan = adapter.describe()
        rels = {op.rel_path for op in plan.operations}
        self.assertIn("gpt5.5-unrestricted.md", rels)
        self.assertIn("skills/ac/SKILL.md", rels)
        self.assertIn("skills/topo-identity/SKILL.md", rels)


class ClaudeAdapterTests(unittest.TestCase):
    def test_claude_default_target_is_hidden_config(self):
        adapter = ClaudeAdapter()
        self.assertEqual(adapter.default_target().name, ".claude")

    def test_claude_plan_wires_userpromptsubmit_hook(self):
        adapter = ClaudeAdapter()
        plan = adapter.describe()
        rels = {op.rel_path for op in plan.operations}
        # Paths live at the target root; the hook script sits under hooks/.
        self.assertIn("settings.json", rels)
        self.assertIn("hooks/instruction-inject.sh", rels)
        self.assertIn("instruction.md", rels)

    def test_claude_deploy_would_write_hook_in_sandbox(self):
        adapter = ClaudeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Pre-create a valid settings.json.
            (root / "settings.json").write_text("{}", encoding="utf-8")
            result = adapter.deploy(
                root, allowed=True, force=False, dry_run=True
            )
            self.assertEqual(result["status"], "dry-run")

    def test_claude_hook_script_is_pure_bash_and_outputs_instruction(self):
        adapter = ClaudeAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.json").write_text("{}", encoding="utf-8")
            result = adapter.deploy(
                root, allowed=True, force=False, dry_run=False
            )
            self.assertEqual(result["status"], "ok")
            hook = root / "hooks" / "instruction-inject.sh"
            self.assertTrue(hook.is_file())
            content = hook.read_text(encoding="utf-8")
            # Pure bash: must not rely on an external python interpreter.
            self.assertNotIn("python", content)
            self.assertNotIn("<<'PY'", content)
            # The script cats instruction.md relative to its directory.
            self.assertIn('cat "$_INSTR"', content)
            # instruction.md must exist alongside.
            self.assertTrue((root / "instruction.md").is_file())
            # Executing the hook (via bash) yields the branded activation line.
            # On Windows the subprocess pipes carry UTF-8 bytes but text=True
            # decodes with the locale encoding (GBK/cp936), which crashes on
            # the Chinese activation word and leaves .stdout as None.  So we
            # decode explicitly as UTF-8 and only run when bash is available.
            import shutil
            import subprocess

            bash = shutil.which("bash")
            self.assertIsNotNone(bash, "bash is required to exercise the hook script")
            completed = subprocess.run(
                [bash, str(hook)],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
            output = completed.stdout
            self.assertEqual(completed.returncode, 0, output)
            # The hook's sole job is to re-emit instruction.md to stdout, so
            # the output must match the instruction file byte-for-byte.
            expected = (root / "instruction.md").read_text(encoding="utf-8")
            self.assertEqual(output.rstrip("\r\n"), expected)
            # It must also carry the branded activation-word contract.
            self.assertIn(IDENTITY_WORD, output)


class CursorAdapterTests(unittest.TestCase):
    def test_cursor_rule_is_always_apply(self):
        adapter = CursorAdapter()
        plan = adapter.describe()
        rule_op = next(
            op for op in plan.operations if op.rel_path.endswith("topo.ac.mdc")
        )
        self.assertIn("alwaysApply", rule_op.description)

    def test_cursor_project_target_places_rule_under_dot_cursor_rules(self):
        adapter = CursorAdapter()
        with tempfile.TemporaryDirectory() as directory:
            proj = Path(directory)
            rel = adapter._rule_rel(proj.resolve())
            self.assertEqual(rel, ".cursor/rules/topo.ac.mdc")


class WorkBuddyAdapterTests(unittest.TestCase):
    def test_workbuddy_default_target_is_skills_root(self):
        adapter = WorkBuddyAdapter()
        self.assertEqual(adapter.default_target().name, "skills")

    def test_workbuddy_skill_package_carries_activation_trigger(self):
        adapter = WorkBuddyAdapter()
        plan = adapter.describe()
        rels = {op.rel_path for op in plan.operations}
        self.assertIn("topo-ac-unrestricted/SKILL.md", rels)

    def test_identity_word_is_branded(self):
        self.assertEqual(IDENTITY_WORD, "拓扑")
        self.assertEqual(INSTRUCTION_PROFILE, "topo-ac-unrestricted")


if __name__ == "__main__":
    unittest.main()
