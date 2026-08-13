import json
import subprocess
import sys
import unittest
from pathlib import Path

from reverse_analyzer.skills import SkillCatalog


ROOT = Path(__file__).resolve().parents[1]


class SkillCatalogTests(unittest.TestCase):
    def test_discovers_every_checked_in_skill_with_stable_identity(self) -> None:
        catalog = SkillCatalog(ROOT / "reverse-skills")
        records = catalog.discover()
        self.assertEqual(len(records), len(list((ROOT / "reverse-skills").rglob("SKILL.md"))))
        self.assertEqual(len({record.id for record in records}), len(records))
        self.assertTrue(catalog.get("skills/apk-reverse"))
        self.assertTrue(all(record.metadata_status == "complete" for record in records))

    def test_cli_lists_and_audits_skills(self) -> None:
        audit = subprocess.run([sys.executable, "-m", "reverse_analyzer", "skills", "audit"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(audit.returncode, 0, audit.stderr)
        payload = json.loads(audit.stdout)
        self.assertGreaterEqual(payload["skill_count"], 60)
        self.assertGreater(payload["routable_count"], 0)

        listed = subprocess.run([sys.executable, "-m", "reverse_analyzer", "skills", "list", "--route", "android"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertGreater(json.loads(listed.stdout)["count"], 0)


if __name__ == "__main__":
    unittest.main()
