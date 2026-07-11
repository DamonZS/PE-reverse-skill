import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.cli import _build_reconstruction_analysis, _load_dynamic_hooks, _resolve_dynamic_profile
from reverse_analyzer.tools.frida import DEFAULT_HOOKS, frida_hook_profiles, frida_hooks_for_profile, _render_agent


class FridaDynamicHookTests(unittest.TestCase):
    def test_default_hooks_cover_dynamic_reverse_primitives(self):
        names = {item["name"] for item in DEFAULT_HOOKS}
        self.assertIn("connect", names)
        self.assertIn("send", names)
        self.assertIn("NtQueryInformationProcess", names)
        self.assertIn("VirtualAllocEx", names)

        create_file = next(item for item in DEFAULT_HOOKS if item["name"] == "CreateFileW")
        disposition = next(arg for arg in create_file["args"] if arg["name"] == "creation_disposition")
        self.assertEqual(disposition["index"], 4)

        reg_create = next(item for item in DEFAULT_HOOKS if item["name"] == "RegCreateKeyExW")
        subkey = next(arg for arg in reg_create["args"] if arg["name"] == "subkey")
        self.assertEqual(subkey["index"], 1)

    def test_render_agent_supports_explicit_indices_buffers_returns_and_module_snapshot(self):
        source = _render_agent([
            {
                "module": "ws2_32.dll",
                "name": "send",
                "category": "network",
                "capture_return": True,
                "args": [
                    {"index": 1, "name": "buffer", "type": "buffer", "size_index": 2},
                    {"index": 2, "name": "length", "type": "u32"},
                ],
            }
        ])
        self.assertIn("const argIndex", source)
        self.assertIn("safeReadBuffer", source)
        self.assertIn("safeReadSockaddr", source)
        self.assertIn("capture_return", source)
        self.assertIn("moduleSnapshot", source)
        self.assertIn("onLeave(retval)", source)

    def test_builtin_hook_profiles_select_expected_subsets(self):
        profiles = frida_hook_profiles()
        self.assertIn("behavior", profiles)
        self.assertIn("unpacking", profiles)
        self.assertGreater(profiles["behavior"]["hook_count"], profiles["quick"]["hook_count"])

        network_hooks = frida_hooks_for_profile("network")
        network_categories = {item["category"] for item in network_hooks}
        self.assertLess(len(network_hooks), len(DEFAULT_HOOKS))
        self.assertTrue(network_categories <= {"loader", "network"})
        self.assertIn("connect", {item["name"] for item in network_hooks})

        unpacking_categories = {item["category"] for item in frida_hooks_for_profile("unpacking")}
        self.assertIn("anti_debug", unpacking_categories)
        self.assertIn("memory", unpacking_categories)

    def test_load_dynamic_hook_file_accepts_list_or_hooks_object(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hooks.json"
            path.write_text(json.dumps({"hooks": [{"module": "kernel32.dll", "name": "Sleep"}]}), encoding="utf-8")
            hooks = _load_dynamic_hooks(path)
            self.assertEqual(hooks[0]["name"], "Sleep")

            path.write_text(json.dumps([{"module": "kernel32.dll", "name": "CreateFileW"}]), encoding="utf-8")
            hooks = _load_dynamic_hooks(path)
            self.assertEqual(hooks[0]["name"], "CreateFileW")


    def test_auto_dynamic_profile_uses_static_signals(self):
        self.assertEqual(_resolve_dynamic_profile("auto", []), "quick")
        self.assertEqual(_resolve_dynamic_profile("auto", [], "network"), "network")
        self.assertEqual(
            _resolve_dynamic_profile(
                "auto",
                [{"tool_name": "packer_detect", "result": {"tool": "packer_detect", "status": "ok", "data": {"packed_likely": True, "score": 75}}}],
                "network",
            ),
            "unpacking",
        )
        self.assertEqual(
            _resolve_dynamic_profile(
                "auto",
                [{"tool_name": "strings_extract", "result": {"tool": "strings_extract", "status": "ok", "data": {"strings": ["https://api.example.test/v1"]}}}],
            ),
            "network",
        )
        self.assertEqual(
            _resolve_dynamic_profile(
                "auto",
                [{"tool_name": "strings_extract", "result": {"tool": "strings_extract", "status": "ok", "data": {"strings": ["RegSetValueExW HKCU\\Software\\Run"]}}}],
            ),
            "persistence",
        )
        self.assertEqual(_resolve_dynamic_profile("network", []), "network")
    def test_build_reconstruction_analysis_includes_dynamic_evidence(self):
        analysis = _build_reconstruction_analysis(
            [
                {
                    "tool_name": "frida_trace",
                    "result": {
                        "tool": "frida_trace",
                        "status": "ok",
                        "data": {
                            "backend": "frida",
                            "event_count": 2,
                            "api_counts": {"WinHttpSendRequest": 2, "CreateRemoteThread": 1},
                            "category_counts": {"network": 2, "process": 1},
                        },
                    },
                },
                {
                    "tool_name": "procmon_trace",
                    "result": {
                        "tool": "procmon_trace",
                        "status": "ok",
                        "data": {
                            "backend": "procmon",
                            "event_count": 1,
                            "operation_counts": {"TCP Connect": 1},
                            "category_counts": {"network": 1},
                        },
                    },
                },
            ]
        )
        modules = {item["module"] for item in analysis["dynamic_evidence"]}
        self.assertIn("network", modules)
        self.assertIn("process", modules)
        self.assertEqual(analysis["summary"]["dynamic_event_count"], 3)
        self.assertEqual(analysis["summary"]["dynamic_backends"], ["frida", "procmon"])
if __name__ == "__main__":
    unittest.main()
