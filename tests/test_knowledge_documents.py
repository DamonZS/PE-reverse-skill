import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.knowledge import KnowledgeBase


ROOT = Path(__file__).resolve().parents[1]


class KnowledgeDocumentTests(unittest.TestCase):
    def test_typed_documents_are_filtered_and_ranked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            knowledge = KnowledgeBase(tmp)
            knowledge.add_document(
                "Use Frida hooks to capture runtime network APIs.",
                document_type="guide",
                title="Frida network tracing",
                scope="windows",
                tags=["frida", "network"],
            )
            knowledge.add_document(
                "Inspect imports before choosing a dynamic profile.",
                document_type="memory",
                scope="windows",
                tags=["static"],
            )

            matches = knowledge.search_documents(
                "frida network",
                document_type="guide",
                scope="windows",
                tags=["network"],
            )
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["document"]["title"], "Frida network tracing")
            self.assertGreater(matches[0]["score"], 0)
            self.assertLessEqual(matches[0]["score"], 1)

    def test_cli_add_and_search_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            add = subprocess.run(
                [
                    sys.executable, "-m", "reverse_analyzer", "knowledge", "add",
                    "--workspace", tmp, "--type", "code", "--title", "PE parser",
                    "--tag", "pe,parser", "--content", "Parse PE imports with pefile.",
                ],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(add.returncode, 0, add.stderr)
            self.assertEqual(json.loads(add.stdout)["type"], "code")

            search = subprocess.run(
                [
                    sys.executable, "-m", "reverse_analyzer", "knowledge", "search",
                    "PE parser", "--workspace", tmp, "--type", "code", "--tag", "pe",
                ],
                cwd=ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(search.returncode, 0, search.stderr)
            payload = json.loads(search.stdout)
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["matches"][0]["document"]["title"], "PE parser")


if __name__ == "__main__":
    unittest.main()
