import unittest

from reverse_analyzer.providers.engine_runtime import parse_engine_runtime_dump


def _dump(engine: str, runtime: dict) -> dict:
    return {
        "schema_version": "engine-runtime-dump-v1",
        "engine": engine,
        "collector": {"name": "frida", "status": "ok", "available": True},
        "runtime": runtime,
        "provenance": {"target": "controlled-fixture"},
    }


class EngineRuntimeDumpTests(unittest.TestCase):
    def test_mono_runtime_entities_and_parent_relations_are_normalized(self) -> None:
        result = parse_engine_runtime_dump(
            _dump(
                "mono",
                {
                    "domains": [{"id": "domain", "name": "Root", "address": "0x1000"}],
                    "assemblies": [
                        {"id": "assembly", "name": "Assembly-CSharp", "address": "0x2000", "parent": "domain"}
                    ],
                    "classes": [
                        {"id": "player", "name": "Game.Player", "address": "0x3000", "assembly": "assembly"}
                    ],
                    "methods": [
                        {"name": "Update", "address": "0x4000", "class": "player", "token": "0x06000001"}
                    ],
                },
            )
        )
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["engine"], "unity_mono")
        self.assertEqual(result["semantic_ir_fragment"]["summary"]["entity_count"], 4)
        self.assertEqual(result["semantic_ir_fragment"]["summary"]["relation_count"], 3)
        self.assertTrue(
            all(
                entity["attributes"]["address_kind"] == "runtime_va"
                for entity in result["semantic_ir_fragment"]["entities"]
            )
        )

    def test_il2cpp_requires_registration_evidence(self) -> None:
        complete = parse_engine_runtime_dump(
            _dump(
                "il2cpp",
                {
                    "code_registration": {"name": "CodeRegistration", "address": "0x140010000"},
                    "metadata_registration": {"name": "MetadataRegistration", "address": "0x140020000"},
                    "methods": [{"name": "Player.Update", "address": "0x140030000", "token": "0x06000001"}],
                },
            )
        )
        self.assertEqual(complete["status"], "ok", complete)
        self.assertEqual(complete["unity_il2cpp"]["entity_counts"]["il2cpp_method"], 1)

        partial = parse_engine_runtime_dump(
            _dump("il2cpp", {"methods": [{"name": "Update", "address": "0x5000"}]})
        )
        self.assertEqual(partial["status"], "partial")
        self.assertIn("code_registration", " ".join(partial["errors"]))

    def test_unreal_globals_objects_and_version_are_preserved(self) -> None:
        result = parse_engine_runtime_dump(
            _dump(
                "ue5",
                {
                    "version": "5.3",
                    "globals": {"GWorld": "0x7ff600001000", "GObjects": "0x7ff600002000"},
                    "objects": [{"id": "world", "name": "PersistentWorld", "address": "0x200000"}],
                    "functions": [{"name": "BeginPlay", "address": "0x210000", "owner": "world"}],
                },
            )
        )
        self.assertEqual(result["status"], "ok", result)
        self.assertEqual(result["unreal"]["engine_version"], "5.3")
        self.assertEqual(result["unreal"]["entity_counts"]["unreal_global"], 2)

    def test_test_double_collector_and_unproven_addresses_fail_closed(self) -> None:
        synthetic = _dump("mono", {"domains": [{"name": "Root", "address": 1}]})
        synthetic["collector"] = {"name": "synthetic-mono", "status": "ok"}
        rejected = parse_engine_runtime_dump(synthetic)
        self.assertEqual(rejected["status"], "unavailable")
        self.assertIn("test-double", rejected["errors"][0])

        unproven = parse_engine_runtime_dump(
            _dump("mono", {"methods": [{"name": "Update"}]})
        )
        self.assertEqual(unproven["status"], "unavailable")
        self.assertEqual(unproven["semantic_ir_fragment"]["summary"]["entity_count"], 0)

    def test_invalid_schema_is_unavailable(self) -> None:
        payload = _dump("mono", {"domains": [{"name": "Root", "address": 1}]})
        payload["schema_version"] = 99
        result = parse_engine_runtime_dump(payload)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("schema_version", result["errors"][0])


if __name__ == "__main__":
    unittest.main()
