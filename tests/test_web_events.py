from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from reverse_analyzer.web_events import WebEventLog


class WebEventLogTests(unittest.TestCase):
    def test_append_lists_and_formats_sse(self) -> None:
        with TemporaryDirectory() as directory:
            log = WebEventLog(Path(directory), retained_events=3)

            first = log.append("0" * 32, "created", status="queued", message="已创建")
            second = log.append("0" * 32, "output", status="running", message="line")

            self.assertEqual(first["sequence"], 1)
            self.assertEqual(second["sequence"], 2)
            self.assertEqual([item["sequence"] for item in log.list_events("0" * 32, after=1)], [2])
            self.assertIn(b"event: output", log.as_sse([second]))

    def test_retains_bounded_tail(self) -> None:
        with TemporaryDirectory() as directory:
            log = WebEventLog(Path(directory), retained_events=2)
            for index in range(4):
                log.append("1" * 32, "output", message=str(index))

            self.assertEqual([item["message"] for item in log.list_events("1" * 32)], ["2", "3"])


if __name__ == "__main__":
    unittest.main()
