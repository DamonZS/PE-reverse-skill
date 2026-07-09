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
            for field in ["timestamp", "session_id", "task", "subtask", "tool", "status", "message", "data"]:
                self.assertIn(field, record)
            self.assertEqual(record["data"]["x"], 1)


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


if __name__ == "__main__":
    unittest.main()
