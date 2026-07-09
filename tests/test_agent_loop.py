import unittest

from reverse_analyzer.agent import AgentLoop
from reverse_analyzer.providers import ProviderMessage


class OneToolThenFinalProvider:
    def __init__(self):
        self.calls = 0

    def analyze(self, context):
        self.calls += 1
        if self.calls == 1:
            return ProviderMessage(content="run", tool_name="identify", tool_args={"target": "x.exe"})
        return ProviderMessage(content="done", final_answer="finished")


class RepeatingProvider:
    def analyze(self, context):
        return ProviderMessage(content="repeat", tool_name="same", tool_args={"a": 1})


class AgentLoopTests(unittest.TestCase):
    def test_agent_loop_executes_tool_and_stops_on_final_answer(self):
        calls = []

        def identify(target):
            calls.append(target)
            return {"verdict": "PE32"}

        loop = AgentLoop(OneToolThenFinalProvider(), {"identify": identify}, max_iterations=3)

        result = loop.run({"target": "x.exe"})

        self.assertEqual(calls, ["x.exe"])
        self.assertEqual(result.final_answer, "finished")
        self.assertEqual(result.stopped_reason, "final_answer")
        self.assertEqual(result.tool_results[0]["result"], {"verdict": "PE32"})

    def test_agent_loop_barriers_on_repeated_tool_request(self):
        loop = AgentLoop(RepeatingProvider(), {"same": lambda a: a}, max_iterations=5, repeat_limit=1)

        result = loop.run()

        self.assertEqual(result.stopped_reason, "repeated_tool")
        self.assertTrue(result.barrier)
        self.assertEqual(len(result.tool_results), 1)


if __name__ == "__main__":
    unittest.main()
