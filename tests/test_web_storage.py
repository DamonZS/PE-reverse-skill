from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from reverse_analyzer.web_storage import LocalJsonStorage, StorageConfig, create_storage_backend


class WebStorageTests(unittest.TestCase):
    def test_local_records_are_isolated_by_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalJsonStorage(temporary)
            store.put("alpha", "jobs", "one", {"id": "one", "owner": "alpha"})
            store.put("beta", "jobs", "one", {"id": "one", "owner": "beta"})
            self.assertEqual(store.get("alpha", "jobs", "one")["owner"], "alpha")
            self.assertEqual(store.list("beta", "jobs"), [{"id": "one", "owner": "beta"}])

    def test_local_storage_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = LocalJsonStorage(temporary)
            for invalid in ("../other", "a/b", "", "."):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    store.put(invalid, "jobs", "one", {"id": "one"})

    def test_environment_defaults_to_local_backend(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {}, clear=True):
            config = StorageConfig.from_environment(temporary)
            self.assertEqual(config.backend, "local")
            self.assertIsInstance(create_storage_backend(config), LocalJsonStorage)

    def test_postgresql_requires_database_url_without_importing_driver(self) -> None:
        config = StorageConfig(backend="postgresql", local_root=Path("unused"), database_url=None)
        with self.assertRaisesRegex(ValueError, "DATABASE_URL"):
            create_storage_backend(config)


if __name__ == "__main__":
    unittest.main()
