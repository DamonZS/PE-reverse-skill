import json
import os
import tempfile
import unittest

from reverse_analyzer.core.audit import AuditSessionRecord, CapabilityAuditBuilder, summarize_audit_records
from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.core.ir import EvidenceGraph, SemanticIR
from reverse_analyzer.providers import build_default_registry


class CapabilityCoreTests(unittest.TestCase):
    def test_default_registry_contains_core_capabilities(self):
        registry = build_default_registry()
        self.assertEqual(
            registry.list_capabilities(),
            [
                "android_rebuild",
                "hook_runtime",
                "injector",
                "memory_runtime",
                "patch_executor",
            ],
        )
        self.assertEqual(registry.list_providers("memory_runtime"), ["mock"])

    def test_mock_provider_plan_validate_execute_rollback(self):
        registry = build_default_registry()
        provider = registry.resolve("memory_runtime")
        request = CapabilityRequest(
            capability="memory_runtime",
            action="scan",
            target=TargetIdentity(kind="process", pid=1337, display_name="demo.exe"),
            provenance={"source": "unit-test"},
        )
        plan = provider.plan(request)
        self.assertEqual(plan.provider, "mock")
        validation = provider.validate(plan)
        self.assertTrue(validation.ok)
        result = provider.execute(plan)
        self.assertEqual(result.status, "mocked")
        rollback = provider.rollback(result)
        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)

    def test_capability_audit_builder_generates_full_record_and_summary(self):
        registry = build_default_registry()
        provider = registry.resolve("injector")
        request = CapabilityRequest(
            capability="injector",
            action="plan",
            target=TargetIdentity(kind="process", pid=2048, display_name="target.exe"),
            session_id="audit-1",
            provenance={"source": "unit-test"},
        )
        plan = provider.plan(request)
        validation = provider.validate(plan)
        result = provider.execute(plan)

        record = CapabilityAuditBuilder().build_record(plan=plan, validation=validation, result=result)
        payload = record.to_dict()
        summary = summarize_audit_records([payload])

        self.assertEqual(payload["session_id"], "audit-1")
        self.assertEqual(payload["capability"], "injector")
        self.assertEqual(payload["provider"], "mock")
        self.assertEqual(payload["target_identity"]["display_name"], "target.exe")
        self.assertEqual(payload["precondition_hash"], "mock-injector-plan")
        self.assertTrue(payload["rollback_plan"]["supported"])
        self.assertEqual(len(payload["events"]), 3)
        self.assertEqual(summary["record_count"], 1)
        self.assertEqual(summary["status_counts"]["mocked"], 1)
        self.assertEqual(summary["rollback_supported_count"], 1)
        self.assertEqual(summary["manifest_reference_count"], 1)
        self.assertEqual(summary["dashboard_trace_count"], 1)

    def test_semantic_ir_and_evidence_graph_write_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            ir_path = os.path.join(temp_dir, "semantic_ir.json")
            graph_path = os.path.join(temp_dir, "evidence_graph.json")

            ir = SemanticIR(sample={"name": "sample.exe"})
            ir.merge_fragment("protocol", {"status": "unavailable"})
            ir.write_json(ir_path)

            graph = EvidenceGraph()
            graph.add_node("sample:1", "sample", "sample.exe", sha256="abc")
            graph.add_node("module:1", "module", "kernel32.dll")
            graph.add_edge("sample:1", "module:1", "imports")
            graph.write_json(graph_path)

            with open(ir_path, "r", encoding="utf-8") as handle:
                ir_data = json.load(handle)
            with open(graph_path, "r", encoding="utf-8") as handle:
                graph_data = json.load(handle)

            self.assertEqual(ir_data["sample"]["name"], "sample.exe")
            self.assertEqual(graph_data["nodes"][0]["label"], "sample.exe")
            self.assertEqual(graph_data["edges"][0]["edge_type"], "imports")

    def test_audit_session_record_write_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            session_path = os.path.join(temp_dir, "session.json")
            session = AuditSessionRecord(
                session_id="sess-1",
                capability="patch_executor",
                provider="mock",
                target_identity=TargetIdentity(kind="sample", path="C:/tmp/sample.exe"),
                action="plan",
            )
            session.add_event("plan", "created mock plan", step="mock_plan")
            session.write_json(session_path)

            with open(session_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)

            self.assertEqual(data["session_id"], "sess-1")
            self.assertEqual(data["events"][0]["kind"], "plan")


if __name__ == "__main__":
    unittest.main()
