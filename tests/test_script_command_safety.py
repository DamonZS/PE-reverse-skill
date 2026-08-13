from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


SCRIPT_ROOT = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("reverse_scripts_common", SCRIPT_ROOT / "common.py")
assert SPEC and SPEC.loader
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)


class ScriptCommandSafetyTests(TestCase):
    def test_run_cmd_rejects_shell_command_strings(self) -> None:
        with self.assertRaises(TypeError):
            COMMON.run_cmd("tool --output user-controlled; touch escaped")

    def test_run_cmd_uses_argument_array_without_shell(self) -> None:
        command = [sys.executable, "-c", "print('ok')", "literal;not-a-command"]
        with patch.object(COMMON.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "ok\n"
            run.return_value.stderr = ""
            code, stdout, stderr = COMMON.run_cmd(command)
        self.assertEqual((code, stdout, stderr), (0, "ok\n", ""))
        args, kwargs = run.call_args
        self.assertEqual(args[0], command)
        self.assertIs(kwargs["shell"], False)

    def test_legacy_scripts_do_not_enable_shell_execution(self) -> None:
        for name in ("common.py", "reconstruct.py", "apk_analyze.py"):
            source = (SCRIPT_ROOT / name).read_text(encoding="utf-8")
            self.assertNotIn("shell=True", source, name)
