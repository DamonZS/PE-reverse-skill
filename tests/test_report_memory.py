import unittest
from types import SimpleNamespace

from reverse_analyzer.report import ReportBuilder


class ReportMemoryEvidenceTests(unittest.TestCase):
    def test_report_normalizes_runtime_memory_snapshot_diff_and_mapping(self) -> None:
        session = SimpleNamespace(session_id="memory-1", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "memory_snapshot",
                "result": {
                    "tool": "memory_snapshot",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "pid": 4242,
                        "modules": [{"path": "sample.exe"}, {"path": "kernel32.dll"}],
                        "regions": [{"base": "0x1000"}, {"base": "0x2000"}, {"base": "0x3000"}],
                        "sampled_bytes": 96,
                        "artifacts": [{"name": "snapshot.json", "path": "gui/snapshot.json"}],
                    },
                },
            },
            {
                "tool_name": "memory_diff",
                "result": {
                    "tool": "memory_diff",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "added_regions": [{"base": "0x4000"}],
                        "removed_regions": [],
                        "changed_regions": [{"base": "0x1000"}, {"base": "0x2000"}],
                    },
                },
            },
            {
                "tool_name": "memory_address_map",
                "result": {
                    "tool": "memory_address_map",
                    "status": "ok",
                    "data": {
                        "status": "ok",
                        "mappings": [{"address": "0x401000", "rva": "0x1000"}],
                        "unmapped": [{"address": "0x70000000"}],
                    },
                },
            },
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()

        memory = report["memory_analysis"]
        self.assertEqual(memory["status"], "ok")
        self.assertEqual(memory["snapshot"], {"status": "ok", "pid": 4242, "module_count": 2, "region_count": 3, "sampled_bytes": 96})
        self.assertEqual(memory["diff"], {"status": "ok", "added_region_count": 1, "removed_region_count": 0, "changed_region_count": 2})
        self.assertEqual(memory["address_map"], {"status": "ok", "mapped_count": 1, "unmapped_count": 1})
        self.assertIn("## Runtime Memory Evidence", markdown)
        self.assertIn("sampled_bytes=96", markdown)

    def test_report_preserves_unavailable_memory_stage(self) -> None:
        session = SimpleNamespace(session_id="memory-2", target="sample.exe", status="succeeded", artifacts=[])
        report = ReportBuilder(
            session,
            [{"tool_name": "memory_snapshot", "result": {"tool": "memory_snapshot", "status": "unavailable", "data": {"status": "unavailable"}}}],
        ).build()

        self.assertEqual(report["memory_analysis"]["status"], "unavailable")
        self.assertEqual(report["memory_analysis"]["snapshot"]["status"], "unavailable")
        self.assertEqual(report["memory_analysis"]["snapshot"]["region_count"], 0)

    def test_report_retains_every_multi_stage_diff_and_address_map(self) -> None:
        """A multi-stage plan must not collapse earlier evidence into the last trace."""

        session = SimpleNamespace(session_id="memory-3", target="sample.exe", status="succeeded", artifacts=[])
        tool_results = [
            {
                "tool_name": "memory_snapshot",
                "tool_args": {"attach_pid": 4242},
                "iteration": 7,
                "result": {
                    "tool": "memory_snapshot",
                    "status": "ok",
                    "data": {
                        "source": {"pid": 4242},
                        "modules": [{"name": "sample.exe"}],
                        "regions": [{"base_address": "0x1000"}],
                        "summary": {"sampled_bytes": 32},
                    },
                },
            },
            {
                "tool_name": "memory_diff",
                "tool_args": {"stage": 0, "artifact_name": "memory_diff_stage_1.json"},
                "iteration": 8,
                "result": {
                    "tool": "memory_diff",
                    "status": "ok",
                    "data": {
                        "added_regions": [{"base_address": "0x2000"}],
                        "removed_regions": [],
                        "changed_regions": [],
                        "artifacts": [{"name": "memory_diff_stage_1.json", "path": "memory_diff_stage_1.json"}],
                    },
                },
            },
            {
                "tool_name": "memory_diff",
                "tool_args": {"stage": 1, "artifact_name": "memory_diff_stage_2.json"},
                "iteration": 9,
                "result": {
                    "tool": "memory_diff",
                    "status": "ok",
                    "data": {
                        "added_regions": [],
                        "removed_regions": [{"base_address": "0x2000"}],
                        "changed_regions": [{"base_address": "0x1000"}, {"base_address": "0x3000"}],
                        "artifacts": [{"name": "memory_diff_stage_2.json", "path": "memory_diff_stage_2.json"}],
                    },
                },
            },
            {
                "tool_name": "memory_address_map",
                "tool_args": {"stage": 0, "artifact_name": "memory_address_map_stage_1.json"},
                "iteration": 10,
                "result": {
                    "tool": "memory_address_map",
                    "status": "ok",
                    "data": {"mappings": [{"address": "0x401000"}], "unmapped": []},
                },
            },
            {
                "tool_name": "memory_address_map",
                "tool_args": {"stage": 1, "artifact_name": "memory_address_map_stage_2.json"},
                "iteration": 11,
                "result": {
                    "tool": "memory_address_map",
                    "status": "ok",
                    "data": {
                        "mappings": [{"address": "0x402000"}, {"address": "0x403000"}],
                        "unmapped": [{"address": "0x70000000"}],
                    },
                },
            },
        ]

        builder = ReportBuilder(session, tool_results)
        report = builder.build()
        markdown = builder.to_markdown()
        memory = report["memory_analysis"]

        # Legacy compact fields remain deterministic and select the latest
        # trace for each kind, while the stage list preserves all evidence.
        self.assertEqual(memory["diff"]["added_region_count"], 0)
        self.assertEqual(memory["diff"]["removed_region_count"], 1)
        self.assertEqual(memory["diff"]["changed_region_count"], 2)
        self.assertEqual(memory["address_map"], {"status": "ok", "mapped_count": 2, "unmapped_count": 1})

        stages = memory["stages"]
        self.assertEqual([stage["kind"] for stage in stages], ["snapshot", "diff", "diff", "address_map", "address_map"])
        self.assertEqual([stage["stage_index"] for stage in stages], [1, 2, 3, 4, 5])
        self.assertEqual([stage["source_trace_index"] for stage in stages], [7, 8, 9, 10, 11])
        self.assertEqual([stage.get("plan_stage_index") for stage in stages[1:]], [1, 2, 1, 2])
        self.assertEqual(stages[1]["summary"]["added_region_count"], 1)
        self.assertEqual(stages[2]["summary"]["changed_region_count"], 2)
        self.assertEqual(stages[3]["summary"]["mapped_count"], 1)
        self.assertEqual(stages[4]["summary"]["unmapped_count"], 1)
        self.assertEqual(len(memory["artifacts"]), 2)

        self.assertIn("**Stage 2 / Diff (diff-1):** status=ok added=1", markdown)
        self.assertIn("**Stage 3 / Diff (diff-2):** status=ok added=0 removed=1 changed=2", markdown)
        self.assertIn("**Stage 4 / Address Mapping (address_map-1):** status=ok mapped=1 unmapped=0", markdown)
        self.assertIn("**Stage 5 / Address Mapping (address_map-2):** status=ok mapped=2 unmapped=1", markdown)


if __name__ == "__main__":
    unittest.main()
