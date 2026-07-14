import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from reverse_analyzer.gui.vlm_provider import (
    GUI_VLM_CONFIG_ENV,
    GUI_VLM_PROVIDER_ENV,
    GUI_VLM_TIMEOUT_ENV,
    VLM_SCHEMA_VERSION,
    load_vlm_provider,
)
from reverse_analyzer.tools.gui import gui_visual_parse


def _image(root: Path, name: str = "screen.png") -> Path:
    path = root / name
    path.write_bytes(b"mock-image-payload")
    return path


def _response(*, text: str = "Save", status: str = "ok") -> dict[str, object]:
    return {
        "schema_version": VLM_SCHEMA_VERSION,
        "status": status,
        "text_regions": [{"text": text, "confidence": 0.98}],
        "widgets": [{"type": "button", "text": text, "bbox": {"x": 1, "y": 2, "width": 30, "height": 12}}],
        "provenance": {"provider": "mock", "model": "mock-vision", "request_id": "request-1"},
    }


class GuiVLMProviderTests(unittest.TestCase):
    def test_loader_imports_function_and_validates_request_without_reporting_secrets(self) -> None:
        module_name = "mock_gui_vlm_function"
        plugin = types.ModuleType(module_name)
        observed: dict[str, object] = {}
        secret = "mock-secret-value-123"

        def analyze(request: dict[str, object], *, config: dict[str, object]) -> dict[str, object]:
            observed["request"] = request
            observed["config"] = config
            response = _response(text=f"Save {config['api_key']}")
            response["provenance"] = {
                "provider": "mock",
                "model": f"mock-vision-{config['api_key']}",
                "api_key": config["api_key"],
            }
            return response

        plugin.analyze = analyze
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {module_name: plugin}):
            image = _image(Path(tmp))
            loaded = load_vlm_provider(
                {
                    "provider": f"{module_name}:analyze",
                    "options": {"model": "mock-vision"},
                    "secret_env": {"api_key": "MOCK_GUI_VLM_KEY"},
                    "timeout_seconds": 1,
                },
                environ={"MOCK_GUI_VLM_KEY": secret},
            )

            self.assertTrue(loaded.available)
            invocation = loaded.provider.invoke(image)  # type: ignore[union-attr]

        self.assertEqual(invocation.status, "ok")
        request = observed["request"]
        self.assertIsInstance(request, dict)
        self.assertEqual(request["schema_version"], VLM_SCHEMA_VERSION)  # type: ignore[index]
        self.assertEqual(request["task"], "gui_visual_parse")  # type: ignore[index]
        self.assertEqual(request["media_type"], "image/png")  # type: ignore[index]
        self.assertEqual(len(str(request["sha256"])), 64)  # type: ignore[index]
        self.assertEqual(observed["config"], {"model": "mock-vision", "api_key": secret})
        self.assertEqual(invocation.output["widgets"][0]["type"], "button")  # type: ignore[index]
        self.assertNotIn("api_key", invocation.provenance.get("response", {}))
        self.assertEqual(loaded.provenance["configuration"]["secret_count"], 1)
        serialized = json.dumps({"load": loaded.to_dict(), "invoke": invocation.to_dict(), "provider": repr(loaded.provider)})
        self.assertNotIn(secret, serialized)
        self.assertIn("<redacted>", serialized)

    def test_loader_supports_provider_classes_with_private_constructor_config(self) -> None:
        module_name = "mock_gui_vlm_class"
        plugin = types.ModuleType(module_name)
        observed: dict[str, object] = {}

        class Provider:
            name = "class-provider"

            def __init__(self, *, config: dict[str, object]) -> None:
                observed["config"] = config

            def analyze(self, request: dict[str, object]) -> dict[str, object]:
                observed["request"] = request
                return _response(text="Open")

        plugin.Provider = Provider
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {module_name: plugin}):
            loaded = load_vlm_provider(
                {
                    "provider": f"{module_name}:Provider",
                    "options": {"model": "class-model"},
                },
                environ={},
            )
            invocation = loaded.provider.invoke(_image(Path(tmp)))  # type: ignore[union-attr]

        self.assertTrue(loaded.available)
        self.assertEqual(loaded.provenance["provider"], "Provider")
        self.assertEqual(observed["config"], {"model": "class-model"})
        self.assertEqual(invocation.status, "ok")
        self.assertEqual(invocation.output["text_regions"][0]["text"], "Open")  # type: ignore[index]

    def test_loader_reports_missing_module_and_rejects_unsafe_import_syntax(self) -> None:
        missing = load_vlm_provider("definitely_missing_gui_vlm_plugin:analyze", environ={})
        invalid = load_vlm_provider("mock_gui_vlm_plugin:analyze()", environ={})

        self.assertEqual(missing.status, "unavailable")
        self.assertFalse(missing.available)
        self.assertEqual(missing.error.code, "provider_module_missing")  # type: ignore[union-attr]
        self.assertEqual(invalid.status, "failed")
        self.assertEqual(invalid.error.code, "provider_import_path_invalid")  # type: ignore[union-attr]

    def test_loader_timeout_and_output_schema_failure_are_explicit(self) -> None:
        module_name = "mock_gui_vlm_failures"
        plugin = types.ModuleType(module_name)

        def slow(_request: dict[str, object]) -> dict[str, object]:
            time.sleep(0.15)
            return _response()

        def invalid(_request: dict[str, object]) -> dict[str, object]:
            return {"status": "ok", "text_regions": "not-a-list", "widgets": []}

        plugin.slow = slow
        plugin.invalid = invalid
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {module_name: plugin}):
            image = _image(Path(tmp))
            slow_provider = load_vlm_provider(
                {"provider": f"{module_name}:slow", "timeout_seconds": 0.02},
                environ={},
            )
            started = time.monotonic()
            timed_out = slow_provider.provider.invoke(image)  # type: ignore[union-attr]
            elapsed = time.monotonic() - started

            invalid_provider = load_vlm_provider(f"{module_name}:invalid", environ={})
            invalid_output = invalid_provider.provider.invoke(image)  # type: ignore[union-attr]

        self.assertLess(elapsed, 0.12)
        self.assertEqual(timed_out.status, "failed")
        self.assertEqual(timed_out.error.code, "provider_timeout")  # type: ignore[union-attr]
        self.assertEqual(invalid_output.status, "failed")
        self.assertEqual(invalid_output.error.code, "provider_output_schema_invalid")  # type: ignore[union-attr]

    def test_constructor_failure_is_failed_and_redacts_secret(self) -> None:
        module_name = "mock_gui_vlm_constructor_failure"
        plugin = types.ModuleType(module_name)
        secret = "constructor-secret-456"

        class Provider:
            def __init__(self, *, config: dict[str, object]) -> None:
                raise RuntimeError(f"invalid api_key={config['api_key']}")

        plugin.Provider = Provider
        with mock.patch.dict(sys.modules, {module_name: plugin}):
            loaded = load_vlm_provider(
                {
                    "provider": f"{module_name}:Provider",
                    "secrets": {"api_key": secret},
                },
                environ={},
            )

        self.assertEqual(loaded.status, "failed")
        self.assertEqual(loaded.error.code, "provider_constructor_failed")  # type: ignore[union-attr]
        serialized = json.dumps(loaded.to_dict())
        self.assertNotIn(secret, serialized)
        self.assertIn("<redacted>", serialized)

    def test_constructor_dependency_missing_is_unavailable(self) -> None:
        module_name = "mock_gui_vlm_constructor_dependency"
        dependency_name = "definitely_missing_constructor_dependency"
        plugin = types.ModuleType(module_name)

        class Provider:
            def __init__(self) -> None:
                raise ModuleNotFoundError(
                    f"No module named '{dependency_name}'",
                    name=dependency_name,
                )

        plugin.Provider = Provider
        with mock.patch.dict(sys.modules, {module_name: plugin}):
            loaded = load_vlm_provider(f"{module_name}:Provider", environ={})

        self.assertEqual(loaded.status, "unavailable")
        self.assertFalse(loaded.available)
        self.assertEqual(loaded.error.code, "provider_dependency_missing")  # type: ignore[union-attr]

    def test_provider_reported_unavailable_remains_unavailable(self) -> None:
        module_name = "mock_gui_vlm_unavailable"
        plugin = types.ModuleType(module_name)

        def analyze(_request: dict[str, object]) -> dict[str, object]:
            return {
                "schema_version": VLM_SCHEMA_VERSION,
                "status": "unavailable",
                "reason": "model dependency is unavailable",
            }

        plugin.analyze = analyze
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {module_name: plugin}):
            loaded = load_vlm_provider(f"{module_name}:analyze", environ={})
            invocation = loaded.provider.invoke(_image(Path(tmp)))  # type: ignore[union-attr]

        self.assertEqual(invocation.status, "unavailable")
        self.assertFalse(invocation.succeeded)
        self.assertEqual(invocation.output["text_regions"], [])  # type: ignore[index]
        self.assertEqual(invocation.output["widgets"], [])  # type: ignore[index]
        self.assertEqual(invocation.error.code, "provider_reported_unavailable")  # type: ignore[union-attr]

    def test_invalid_injected_timeout_returns_failed_load_result(self) -> None:
        loaded = load_vlm_provider(lambda _path: _response(), timeout_seconds=0, environ={})

        self.assertEqual(loaded.status, "failed")
        self.assertFalse(loaded.available)
        self.assertEqual(loaded.error.code, "provider_config_schema_invalid")  # type: ignore[union-attr]

    def test_visual_parse_loads_mock_plugin_from_cli_environment_config(self) -> None:
        module_name = "mock_gui_vlm_visual_consumer"
        plugin = types.ModuleType(module_name)
        secret = "report-secret-789"
        observed: dict[str, object] = {}

        def analyze(request: dict[str, object], *, config: dict[str, object]) -> dict[str, object]:
            observed["request"] = request
            observed["secret"] = config["api_key"]
            response = _response(text=f"Launch {config['api_key']}")
            response["provenance"] = {
                "provider": "mock",
                "model": f"mock-vision-{config['api_key']}",
            }
            return response

        plugin.analyze = analyze
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, {module_name: plugin}):
            root = Path(tmp)
            screenshots = root / "screenshots"
            screenshots.mkdir()
            _image(screenshots)
            config_path = root / "vlm-provider.json"
            config_path.write_text(
                json.dumps(
                    {
                        "provider": f"{module_name}:analyze",
                        "name": "mock-production-vlm",
                        "options": {"model": "mock-vision"},
                        "secret_env": {"api_key": "MOCK_GUI_VLM_REPORT_KEY"},
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                GUI_VLM_CONFIG_ENV: str(config_path),
                GUI_VLM_PROVIDER_ENV: "",
                GUI_VLM_TIMEOUT_ENV: "1",
                "MOCK_GUI_VLM_REPORT_KEY": secret,
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                result = gui_visual_parse(screenshots, root / "out")

            report_path = root / "out" / "gui" / "visual_parse.json"
            report_text = report_path.read_text(encoding="utf-8")
            report = json.loads(report_text)

        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["components"]["vlm"]["status"], "ok")
        self.assertEqual(result["components"]["vlm"]["load_status"], "ok")
        self.assertEqual(result["vlm_provider"], "mock-production-vlm")
        self.assertEqual(result["detected_widget_count"], 1)
        self.assertEqual(result["widgets"][0]["source"], "mock-production-vlm")
        self.assertEqual(result["vlm_provenance"]["source"], "environment_config")
        self.assertEqual(observed["secret"], secret)
        self.assertNotIn(secret, report_text)
        self.assertNotIn("api_key", report_text)
        self.assertEqual(report["components"]["vlm"]["provenance"]["configuration"]["secret_count"], 1)

    def test_visual_parse_does_not_fake_success_when_plugin_cannot_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            screenshots = root / "screenshots"
            screenshots.mkdir()
            _image(screenshots)

            result = gui_visual_parse(
                screenshots,
                root / "out",
                vlm_provider="definitely_missing_gui_vlm_consumer:analyze",
            )

        component = result["components"]["vlm"]
        self.assertEqual(component["status"], "unavailable")
        self.assertEqual(component["load_status"], "unavailable")
        self.assertFalse(component["available"])
        self.assertEqual(component["succeeded_count"], 0)
        self.assertEqual(component["evidence_count"], 0)
        self.assertNotEqual(result["status"], "ok")

    def test_visual_parse_preserves_failed_load_status_without_screenshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = gui_visual_parse(
                None,
                root / "out",
                vlm_provider="mock_gui_vlm_invalid:analyze()",
            )
            report = json.loads((root / "out" / "gui" / "visual_parse.json").read_text(encoding="utf-8"))

        self.assertEqual(result.status, "unavailable")  # type: ignore[union-attr]
        component = result.data["components"]["vlm"]  # type: ignore[union-attr,index]
        self.assertEqual(component["status"], "failed")
        self.assertEqual(component["load_status"], "failed")
        self.assertEqual(component["error_details"][0]["code"], "provider_import_path_invalid")
        self.assertEqual(report["components"]["vlm"]["load_status"], "failed")


if __name__ == "__main__":
    unittest.main()
