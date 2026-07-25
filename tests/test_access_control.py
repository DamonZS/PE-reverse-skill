import unittest
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from reverse_analyzer.access_control import TokenRegistry, compare_token, has_permission, token_digest

class AccessControlTests(unittest.TestCase):
    def test_role_permissions_and_hashed_tokens(self):
        digest = token_digest("secret")
        self.assertTrue(compare_token("secret", digest))
        self.assertFalse(compare_token("wrong", digest))
        self.assertTrue(has_permission("analyst", "analysis.plan"))
        self.assertFalse(has_permission("viewer", "analysis.execute"))

    def test_registry_scopes_identity_to_workspace(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.json"
            path.write_text(json.dumps({"tokens": [{"subject": "alice", "role": "viewer", "workspace": "demo", "token_hash": token_digest("read-token")}]}), encoding="utf-8")
            identity = TokenRegistry(path).authenticate("read-token")
        self.assertIsNotNone(identity)
        assert identity is not None
        self.assertTrue(identity.allows("workspace.read", "demo"))
        self.assertFalse(identity.allows("analysis.execute", "demo"))
        self.assertFalse(identity.allows("workspace.read", "other"))

if __name__ == "__main__":
    unittest.main()
