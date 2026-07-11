import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.core import Flow, ReverseSession, Status, Subtask, Task
from reverse_analyzer.runtime import SessionStore, TraceLogger
from reverse_analyzer.knowledge import KnowledgeBase


class CoreModelTests(unittest.TestCase):
    def test_state_transitions_and_json_roundtrip(self):
        session = ReverseSession(session_id="s1", target="sample.exe")
        flow = session.add_flow("triage")
        task = flow.add_task("detect_packer")
        subtask = task.add_subtask("section_scan")

        session.start()
        flow.start()
        task.start()
        subtask.start()
        subtask.succeed({"packer": "UPX"})

        task.refresh_status_from_subtasks()
        flow.refresh_status_from_tasks()
        session.refresh_status_from_flows()

        self.assertEqual(subtask.status, Status.SUCCEEDED)
        self.assertEqual(task.status, Status.SUCCEEDED)
        self.assertEqual(flow.status, Status.SUCCEEDED)
        self.assertEqual(session.status, Status.SUCCEEDED)

        loaded = ReverseSession.from_dict(json.loads(json.dumps(session.to_dict())))
        self.assertEqual(loaded.session_id, "s1")
        self.assertEqual(loaded.flows[0].tasks[0].subtasks[0].result["packer"], "UPX")

    def test_failure_bubbles_up(self):
        task = Task("analyze", subtasks=[Subtask("a"), Subtask("b")])
        task.subtasks[0].succeed()
        task.subtasks[1].fail("boom")
        self.assertEqual(task.refresh_status_from_subtasks(), Status.FAILED)

    def test_pending_and_completed_mix_becomes_running(self):
        session = ReverseSession(session_id="s-mixed", target="sample.exe")
        flow = session.add_flow("flow")
        task_one = flow.add_task("done")
        task_one.add_subtask(Subtask("done-sub", status=Status.SUCCEEDED))
        task_two = flow.add_task("todo")
        task_two.add_subtask(Subtask("todo-sub", status=Status.PENDING))

        self.assertEqual(task_one.refresh_status_from_subtasks(), Status.SUCCEEDED)
        self.assertEqual(task_two.refresh_status_from_subtasks(), Status.PENDING)
        self.assertEqual(flow.refresh_status_from_tasks(), Status.RUNNING)
        self.assertEqual(session.refresh_status_from_flows(), Status.RUNNING)


class SessionStoreTests(unittest.TestCase):
    def test_create_save_load_and_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SessionStore(Path(tmp) / "runtime")
            session = store.create_session("a.exe", session_id="sess")
            session.add_flow(Flow("flow"))
            store.save(session)

            store.record_event(session, "step", message="started", task="t")
            store.record_tool_call(session, "pefile", task="t", status="succeeded", output={"ok": True})
            store.record_artifact(session, "report", path="report.json", data={"size": 1})

            loaded = store.load("sess")
            self.assertEqual(loaded.target, "a.exe")
            self.assertEqual(len(loaded.events), 2)  # session_created + step
            self.assertEqual(loaded.tool_calls[0]["tool"], "pefile")
            self.assertEqual(loaded.artifacts[0]["name"], "report")
            self.assertIn("sess", store.list_sessions())

    def test_trace_logger_writes_required_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = TraceLogger(Path(tmp) / "trace.jsonl")
            trace.log(
                session_id="s",
                flow="flow",
                task="task",
                subtask="sub",
                tool="tool",
                status="running",
                message="msg",
                data={"x": 1},
            )
            records = trace.read_records()
            self.assertEqual(len(records), 1)
            record = records[0]
            for field in ["timestamp", "session_id", "flow", "task", "subtask", "tool", "status", "message", "data"]:
                self.assertIn(field, record)
            self.assertEqual(record["data"]["x"], 1)

    def test_register_reconstruction_plan_persists_flow_and_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "runtime"
            store = SessionStore(root)
            session = store.create_session("sample.exe", session_id="sess-plan")
            base = session.add_flow(Flow("binary-analysis"))
            base.add_task(Task("identify", status=Status.SUCCEEDED))
            base.add_task(Task("analyze", status=Status.SUCCEEDED))
            base.add_task(Task("report", status=Status.SUCCEEDED))
            store.save(session)

            flow = store.register_reconstruction_plan(
                session,
                {
                    "status": "planned",
                    "tasks": [
                        {
                            "name": "reconstruct_loader",
                            "description": "Recover loader logic",
                            "metadata": {"module": "loader", "priority_score": 9.5},
                            "subtasks": [
                                {"name": "review_loader_xrefs", "metadata": {"module": "loader", "kind": "triage"}},
                                {"name": "recover_entry", "metadata": {"module": "loader", "kind": "function_recovery"}},
                            ],
                        }
                    ],
                },
                project_dir="out/reconstructed_sample",
            )

            self.assertIsNotNone(flow)
            self.assertEqual(flow.name, "source-reconstruction")
            self.assertEqual(flow.tasks[0].name, "reconstruct_loader")
            self.assertEqual(flow.tasks[0].subtasks[0].name, "review_loader_xrefs")
            self.assertEqual(session.status, Status.RUNNING)

            loaded = store.load("sess-plan")
            reconstruction_flow = next(item for item in loaded.flows if item.name == "source-reconstruction")
            self.assertEqual(reconstruction_flow.status, Status.PENDING)
            self.assertEqual(reconstruction_flow.tasks[0].status, Status.PENDING)
            self.assertEqual(loaded.metadata["reconstruction"]["next_task"], "reconstruct_loader")
            self.assertEqual(loaded.metadata["reconstruction"]["next_subtask"], "review_loader_xrefs")

            trace_records = store.trace_logger.read_records()
            messages = [record["message"] for record in trace_records]
            self.assertIn("reconstruction_plan_registered", messages)
            self.assertIn("reconstruction_task_registered", messages)
            self.assertIn("reconstruction_subtask_registered", messages)


class KnowledgeBaseTests(unittest.TestCase):
    def test_upsert_observation_and_similarity(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            kb.upsert_sample(
                "sha256:1",
                features={"packer": "UPX", "imports": ["LoadLibraryA", "VirtualAlloc"]},
                metadata={"path": "a.exe"},
            )
            kb.upsert_sample("sha256:2", features={"packer": "NSIS", "imports": ["CreateFileW"]})
            obs = kb.add_observation("sha256:1", "entry point jump detected")

            self.assertEqual(obs["message"], "entry point jump detected")
            matches = kb.find_similar_by_feature({"packer": "UPX", "imports": ["VirtualAlloc"]}, min_score=0.1)
            self.assertEqual(matches[0]["sample_id"], "sha256:1")
            self.assertGreater(matches[0]["score"], 0)

            detection = kb.load_detection_db()
            self.assertEqual(detection["samples"]["sha256:1"]["features"]["packer"], "UPX")


    def test_dynamic_profile_stats_and_recommendation(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(tmp)
            first = kb.record_dynamic_profile_result(
                "network",
                backend="frida",
                status="ok",
                event_count=20,
                return_event_count=5,
                planned_hook_count=8,
                category_counts={"network": 20},
                sample_id="sample-a",
            )
            second = kb.record_dynamic_profile_result(
                "quick",
                backend="frida",
                status="failed",
                event_count=0,
                planned_hook_count=6,
                sample_id="sample-b",
            )

            self.assertEqual(first["runs"], 1)
            self.assertEqual(second["failures"], 1)
            profiles = kb.load_dynamic_profiles()
            self.assertEqual(profiles["profiles"]["network"]["category_counts"]["network"], 20)
            self.assertEqual(profiles["profiles"]["network"]["samples"], ["sample-a"])
            recommendation = kb.recommend_dynamic_profile()
            self.assertEqual(recommendation["profile"], "network")
            self.assertGreater(recommendation["score"], 0)
if __name__ == "__main__":
    unittest.main()
