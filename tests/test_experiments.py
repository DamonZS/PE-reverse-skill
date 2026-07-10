import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.runtime import ExperimentStore


class ExperimentStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.store = ExperimentStore(self.workspace)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_persists_json_and_serializes_paths(self):
        job = self.store.create(
            Path("samples/app.exe"),
            options={"gui_interaction_trace": Path("trace.json")},
            metadata={"source": Path("fixture")},
        )
        path = self.workspace / "experiments" / f"{job['id']}.json"
        self.assertTrue(path.is_file())
        loaded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(loaded["schema"], 1)
        self.assertEqual(loaded["schema_version"], 1)
        self.assertEqual(loaded["status"], "queued")
        self.assertEqual(loaded["options"]["gui_interaction_trace"], "trace.json")
        self.assertEqual(self.store.get(job["id"]), loaded)

    def test_get_supports_schema_and_schema_version_records(self):
        job = self.store.create("app.exe")
        path = self.workspace / "experiments" / f"{job['id']}.json"
        record = json.loads(path.read_text(encoding="utf-8"))

        record.pop("schema")
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(self.store.get(job["id"])["schema_version"], 1)

        record["schema"] = 1
        record.pop("schema_version")
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(self.store.get(job["id"])["schema"], 1)

    def test_list_orders_most_recent_records_with_stable_tie_breakers(self):
        jobs = [self.store.create(f"sample-{index}.exe") for index in range(3)]
        timestamps = (
            ("2026-01-03T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
            ("2026-01-04T00:00:00+00:00", "2026-01-02T00:00:00+00:00"),
            ("2026-01-04T00:00:00+00:00", "2026-01-02T00:00:00+00:00"),
        )
        expected = []
        for job, (updated_at, created_at) in zip(jobs, timestamps):
            path = self.workspace / "experiments" / f"{job['id']}.json"
            record = json.loads(path.read_text(encoding="utf-8"))
            record["updated_at"] = updated_at
            record["created_at"] = created_at
            path.write_text(json.dumps(record), encoding="utf-8")
            expected.append(record)

        expected.sort(
            key=lambda record: (record["updated_at"], record["created_at"], record["id"]),
            reverse=True,
        )
        self.assertEqual([record["id"] for record in self.store.list()], [record["id"] for record in expected])
        self.assertEqual([record["id"] for record in self.store.list(limit=2)], [record["id"] for record in expected[:2]])

    def test_status_transitions_and_history(self):
        job = self.store.create("app.exe")
        self.store.set_status(job["id"], "queued", detail="still queued")
        self.store.set_status(job["id"], "planned")
        self.store.set_status(job["id"], "running", detail={"worker": "local"})
        result = self.store.set_status(job["id"], "completed", detail="done")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["history"]), 5)
        with self.assertRaises(ValueError):
            self.store.set_status(job["id"], "running")

    def test_build_analysis_command_is_deterministic_and_does_not_execute(self):
        job = self.store.create(
            Path("app.exe"),
            options={
                "dynamic": True,
                "dynamic_backend": "procmon",
                "dynamic_profile": "network",
                "dynamic_duration": 3.5,
                "gui": True,
                "gui_runtime": True,
                "gui_visual": True,
                "reconstruct": True,
                "reconstruct_gui": True,
                "gui_target": "wpf",
                "gui_interaction_trace": Path("trace.json"),
            },
        )
        command = self.store.build_analysis_command(job["id"], python_executable=Path("python"))
        self.assertEqual(command[:7], ["python", "-m", "reverse_analyzer", "analyze", "app.exe", "--out", str(self.workspace / "experiments" / job["id"] / "analysis")])
        self.assertEqual(command[7:], ["--dynamic", "--gui", "--gui-runtime", "--gui-visual", "--reconstruct", "--reconstruct-gui", "--dynamic-backend", "procmon", "--dynamic-profile", "network", "--dynamic-duration", "3.5", "--gui-target", "wpf", "--gui-interaction-trace", "trace.json"])

    def test_record_result_persists_result_fields(self):
        job = self.store.create("app.exe")
        self.store.set_status(job["id"], "planned")
        self.store.set_status(job["id"], "running")
        result = self.store.record_result(
            job["id"],
            status="failed",
            artifacts=[Path("report.json")],
            summary={"events": 2},
            error="analysis unavailable",
        )
        self.assertEqual(result["artifacts"], ["report.json"])
        self.assertEqual(result["summary"], {"events": 2})
        self.assertEqual(result["error"], "analysis unavailable")
        self.assertEqual(result["history"][-1]["detail"], "analysis unavailable")

    def test_get_and_list_reject_invalid_or_damaged_records(self):
        job = self.store.create("app.exe")
        path = self.workspace / "experiments" / f"{job['id']}.json"
        path.write_text("{not valid JSON", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            self.store.get(job["id"])
        with self.assertRaises(ValueError):
            self.store.list()

        replacement = self.store.create("other.exe")
        replacement_path = self.workspace / "experiments" / f"{replacement['id']}.json"
        record = json.loads(replacement_path.read_text(encoding="utf-8"))
        record["status"] = "unknown"
        replacement_path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "invalid status"):
            self.store.get(replacement["id"])

    def test_rejects_path_traversal_and_non_generated_ids(self):
        invalid_ids = ("../outside", "A" * 32, "abc", "0" * 31)
        for experiment_id in invalid_ids:
            with self.subTest(experiment_id=experiment_id):
                with self.assertRaises(ValueError):
                    self.store.path_for(experiment_id)
                with self.assertRaises(ValueError):
                    self.store.get(experiment_id)

    def test_save_uses_unique_temporary_file_and_persists_complete_record(self):
        with patch("reverse_analyzer.runtime.experiments.os.replace", wraps=os.replace) as replace:
            with patch("reverse_analyzer.runtime.experiments.os.fsync", wraps=os.fsync) as fsync:
                job = self.store.create("app.exe")
                self.store.set_status(job["id"], "planned")

        temporary_paths = [Path(call.args[0]) for call in replace.call_args_list]
        final_paths = [Path(call.args[1]) for call in replace.call_args_list]
        self.assertEqual(len(temporary_paths), 2)
        self.assertEqual(len(set(temporary_paths)), 2)
        self.assertTrue(all(path.name != f"{job['id']}.json.tmp" for path in temporary_paths))
        self.assertEqual(final_paths, [self.store.path_for(job["id"])] * 2)
        self.assertEqual(fsync.call_count, 2)
        self.assertEqual(self.store.get(job["id"])["status"], "planned")


if __name__ == "__main__":
    unittest.main()
