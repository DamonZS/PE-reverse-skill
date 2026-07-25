from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from reverse_analyzer.web_auth import AuthService, LocalAuthStore, bearer_or_api_key


class WebAuthTests(unittest.TestCase):
    def test_token_is_hashed_and_authenticates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "auth.json"
            store = LocalAuthStore(path)
            store.create_user("u1", "analyst", "analyst", ["alpha"])
            token = store.issue_token("u1")
            self.assertNotIn(token, path.read_text(encoding="utf-8"))
            principal = store.authenticate(token)
            self.assertEqual(principal.username, "analyst")
            self.assertTrue(principal.permits("experiment.execute", "alpha"))

    def test_rbac_and_workspace_scope_are_both_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalAuthStore(Path(temporary) / "auth.json")
            store.create_user("u1", "reader", "viewer", ["alpha"])
            token = store.issue_token("u1")
            service = AuthService(store)
            service.authorize(token, "artifact.read", "alpha")
            with self.assertRaises(PermissionError):
                service.authorize(token, "experiment.execute", "alpha")
            with self.assertRaises(PermissionError):
                service.authorize(token, "artifact.read", "beta")

    def test_legacy_environment_token_remains_admin_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = AuthService(LocalAuthStore(Path(temporary) / "auth.json"), legacy_token="old-secret")
            principal = service.authorize("old-secret", "experiment.execute", "any-workspace")
            self.assertEqual(principal.authentication, "legacy-env-token")
            self.assertEqual(principal.role, "admin")

    def test_duplicate_users_and_unknown_roles_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalAuthStore(Path(temporary) / "auth.json")
            store.create_user("u1", "user", "viewer", ["alpha"])
            with self.assertRaises(ValueError):
                store.create_user("u2", "user", "admin", ["alpha"])
            with self.assertRaises(ValueError):
                store.create_user("u3", "other", "owner", ["alpha"])

    def test_bearer_header_precedes_api_key(self) -> None:
        self.assertEqual(bearer_or_api_key("Bearer first", "second"), "first")
        self.assertEqual(bearer_or_api_key(None, "second"), "second")


if __name__ == "__main__":
    unittest.main()
