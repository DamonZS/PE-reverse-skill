import json
import os
import tempfile
import unittest

from reverse_analyzer.core.audit import CapabilityAuditBuilder
from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.core.integration import (
    ensure_platform_sections,
    finalize_platform_core,
)
from reverse_analyzer.providers import build_default_registry


class PlatformCoreIntegrationTests(unittest.TestCase):
    def test_ensure_platform_sections(self):
        report_data = {}
        ensure_platform_sections(report_data)
        self.assertIn("engine_analysis", report_data)
        self.assertIn("android_analysis", report_data)
        self.assertIn("protocol_analysis", report_data)
        self.assertIn("gui_analysis", report_data)
        self.assertIn("source_reconstruction", report_data)
        self.assertIn("platform_core", report_data)

    def test_finalize_platform_core_writes_artifacts(self):
        registry = build_default_registry()
        provider = registry.resolve("memory_runtime", preferred="mock")
        request = CapabilityRequest(
            capability="memory_runtime",
            action="scan",
            target=TargetIdentity(kind="process", pid=1337, display_name="demo.exe"),
            session_id="plat-1",
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result_payload = provider.execute(plan)
        record = CapabilityAuditBuilder().build_record(
            plan=plan,
            validation=validation,
            result=result_payload,
        ).to_dict()

        report_data = {
            "sample_name": "demo.exe",
            "platform": "windows-pe",
            "gui_analysis": {
                "status": "ok",
                "framework": "wpf",
                "confidence": 0.91,
            },
            "protocol_analysis": {
                "status": "unavailable",
            },
            "capability_audit": {
                "records": [record],
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            result = finalize_platform_core(
                report_data,
                temp_dir,
                sample_path="C:/tmp/demo.exe",
                registry=registry,
            )

            semantic_ir_path = os.path.join(temp_dir, "semantic_ir.json")
            evidence_graph_path = os.path.join(temp_dir, "evidence_graph.json")

            self.assertEqual(result["status"], "ok")
            self.assertTrue(os.path.exists(semantic_ir_path))
            self.assertTrue(os.path.exists(evidence_graph_path))

            with open(semantic_ir_path, "r", encoding="utf-8") as handle:
                semantic_ir = json.load(handle)
            with open(evidence_graph_path, "r", encoding="utf-8") as handle:
                evidence_graph = json.load(handle)

            self.assertEqual(semantic_ir["sample"]["name"], "demo.exe")
            self.assertGreaterEqual(len(evidence_graph["nodes"]), 2)
            self.assertEqual(
                result["capability_registry"]["capabilities"]["memory_runtime"],
                ["windows_memory_runtime", "mock"],
            )
            self.assertEqual(result["capability_audit"]["record_count"], 1)
            self.assertEqual(result["capability_audit"]["summary"]["status_counts"]["mocked"], 1)
            self.assertTrue(any(node["node_type"] == "capability_audit" for node in evidence_graph["nodes"]))
            self.assertTrue(any(note["type"] == "capability_audit" for note in semantic_ir["notes"]))

    def test_finalize_platform_core_preserves_rich_semantic_ir(self):
        report_data = {
            "sample_name": "rich.exe",
            "semantic_ir": {
                "status": "ok",
                "schema_version": 1,
                "entities": [
                    {
                        "id": "entity:function:main",
                        "kind": "function",
                        "name": "main",
                    }
                ],
                "relations": [
                    {
                        "id": "relation:calls:main-api",
                        "type": "calls",
                        "source": "entity:function:main",
                        "target": "entity:api:create-file",
                    }
                ],
                "capabilities": [
                    {
                        "id": "capability:file",
                        "name": "file",
                    }
                ],
                "summary": {
                    "entity_count": 1,
                    "relation_count": 1,
                    "capability_count": 1,
                },
            },
            "engine_analysis": {"status": "ok", "engine": "unity"},
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            finalize_platform_core(report_data, temp_dir, sample_path="C:/tmp/rich.exe")

            with open(os.path.join(temp_dir, "semantic_ir.json"), "r", encoding="utf-8") as handle:
                semantic_ir = json.load(handle)

        self.assertEqual(semantic_ir["status"], "ok")
        self.assertEqual(semantic_ir["entities"], report_data["semantic_ir"]["entities"])
        self.assertEqual(semantic_ir["relations"], report_data["semantic_ir"]["relations"])
        self.assertEqual(semantic_ir["capabilities"], report_data["semantic_ir"]["capabilities"])
        self.assertEqual(semantic_ir["summary"]["entity_count"], 1)
        self.assertEqual(semantic_ir["summary"]["relation_count"], 1)
        self.assertEqual(semantic_ir["summary"]["capability_count"], 1)
        self.assertEqual(semantic_ir["summary"]["artifact_count"], 0)
        self.assertEqual(semantic_ir["summary"]["module_count"], 0)
        self.assertEqual(semantic_ir["summary"]["runtime_count"], 0)
        self.assertEqual(semantic_ir["summary"]["domain_statuses"], {"engine": "ok"})
        self.assertEqual(semantic_ir["engine"], report_data["engine_analysis"])

    def test_finalize_platform_core_derives_status_from_domain_evidence(self):
        report_data = {
            "sample_name": "gui.exe",
            "gui_analysis": {
                "status": "ok",
                "framework": "wpf",
                "confidence": 0.93,
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            result = finalize_platform_core(
                report_data,
                temp_dir,
                sample_path="C:/tmp/gui.exe",
            )

            with open(os.path.join(temp_dir, "semantic_ir.json"), "r", encoding="utf-8") as handle:
                semantic_ir = json.load(handle)

        self.assertEqual(semantic_ir["status"], "ok")
        self.assertEqual(semantic_ir["summary"]["domain_statuses"], {"gui": "ok"})
        self.assertEqual(result["semantic_ir"]["status"], "ok")
        self.assertEqual(result["semantic_ir"]["runtime_count"], 0)


if __name__ == "__main__":
    unittest.main()
