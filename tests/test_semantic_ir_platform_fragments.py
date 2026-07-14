import copy
import json
import unittest

from reverse_analyzer.tools.semantic_ir import build_semantic_ir


def _analysis(fragment, *, status="ok"):
    return {"status": status, "semantic_ir_fragment": fragment}


class SemanticIrPlatformFragmentTests(unittest.TestCase):
    def test_conflicting_entities_choose_stronger_record_deterministically(self):
        weaker = {
            "id": "shared-entity",
            "kind": "platform_symbol",
            "name": "weaker-name",
            "confidence": 0.4,
            "sources": ["engine.symbols"],
            "attributes": {"owner": "engine", "engine_only": True},
        }
        stronger = {
            "id": "shared-entity",
            "kind": "platform_symbol",
            "name": "stronger-name",
            "confidence": 0.9,
            "sources": ["android.symbols"],
            "attributes": {"owner": "android", "android_only": True},
        }
        fragment = {
            "status": "ok",
            "entities": [weaker, stronger],
            "relations": [],
            "capabilities": [],
            "provenance": [{"provider": "fixture", "mode": "static"}],
        }

        forward = build_semantic_ir(engine_analysis=_analysis(fragment))
        reversed_fragment = copy.deepcopy(fragment)
        reversed_fragment["entities"].reverse()
        reverse = build_semantic_ir(engine_analysis=_analysis(reversed_fragment))

        self.assertEqual(forward, reverse)
        self.assertEqual(len(forward["entities"]), 1)
        entity = forward["entities"][0]
        self.assertEqual(entity["name"], "stronger-name")
        self.assertEqual(entity["confidence"], 0.9)
        self.assertEqual(entity["attributes"]["owner"], "android")
        self.assertTrue(entity["attributes"]["engine_only"])
        self.assertTrue(entity["attributes"]["android_only"])
        self.assertIn("engine.symbols", entity["sources"])
        self.assertIn("android.symbols", entity["sources"])

    def test_all_platform_fragments_are_fused_with_stable_deduplication(self):
        duplicate_entity = {
            "id": "shared-node",
            "kind": "platform_node",
            "name": "shared",
            "confidence": 0.8,
            "sources": ["fixture.entities"],
            "attributes": {"role": "shared"},
        }
        duplicate_relation = {
            "id": "duplicate-relation",
            "type": "aliases",
            "source": "shared-node",
            "target": "shared-node",
            "confidence": 0.7,
            "sources": ["fixture.relations"],
        }
        duplicate_capability = {
            "id": "capability:fixture",
            "name": "fixture-capability",
            "category": "fixture",
            "confidence": 0.75,
            "entity_ids": ["shared-node"],
            "evidence_count": 1,
            "provenance": {"provider": "fixture-capability"},
        }
        shared_fragment = {
            "status": "ok",
            "entities": [duplicate_entity, copy.deepcopy(duplicate_entity)],
            "relations": [duplicate_relation, copy.deepcopy(duplicate_relation)],
            "capabilities": [duplicate_capability, copy.deepcopy(duplicate_capability)],
            "provenance": [
                {"provider": "fixture", "mode": "static"},
                {"mode": "static", "provider": "fixture"},
            ],
        }
        ios_fragment = {
            "status": "partial",
            "source": "ios_analyze",
            "entities": [
                {
                    "id": "ios-node",
                    "kind": "ios_application",
                    "name": "Example.app",
                    "confidence": 0.6,
                    "sources": ["ios.info_plist"],
                    "attributes": {},
                }
            ],
            "relations": [],
            "capabilities": [],
        }
        protocol_fragment = {
            "status": "ok",
            "source": "protocol",
            "entities": [
                {
                    "id": "protocol-node",
                    "kind": "dynamic_event",
                    "name": "tcp-flow",
                    "confidence": 1.0,
                    "sources": ["protocol_capture"],
                    "attributes": {"domain": "network"},
                }
            ],
            "relations": [],
            "capabilities": [],
        }

        result = build_semantic_ir(
            engine_analysis=_analysis(shared_fragment),
            android_analysis=_analysis(copy.deepcopy(shared_fragment)),
            ios_analysis=_analysis(ios_fragment, status="partial"),
            protocol_analysis=_analysis(protocol_fragment),
        )

        self.assertEqual({item["name"] for item in result["entities"]}, {"shared", "Example.app", "tcp-flow"})
        self.assertEqual(len([item for item in result["relations"] if item["type"] == "aliases"]), 1)
        self.assertEqual(len([item for item in result["capabilities"] if item["name"] == "fixture-capability"]), 1)
        fixture_provenance = [item for item in result["provenance"] if item.get("provider") == "fixture"]
        self.assertEqual(fixture_provenance, [{"mode": "static", "provider": "fixture"}])
        json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False)

        reordered_fragments = [
            copy.deepcopy(shared_fragment),
            copy.deepcopy(shared_fragment),
            copy.deepcopy(ios_fragment),
            copy.deepcopy(protocol_fragment),
        ]
        for item in reordered_fragments:
            for key in ("entities", "relations", "capabilities", "provenance"):
                if isinstance(item.get(key), list):
                    item[key].reverse()
        reordered = build_semantic_ir(
            engine_analysis=_analysis(reordered_fragments[0]),
            android_analysis=_analysis(reordered_fragments[1]),
            ios_analysis=_analysis(reordered_fragments[2], status="partial"),
            protocol_analysis=_analysis(reordered_fragments[3]),
        )
        self.assertEqual(
            json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False),
            json.dumps(reordered, ensure_ascii=False, sort_keys=True, allow_nan=False),
        )

    def test_cross_fragment_relation_and_capability_resolve_after_entity_pass(self):
        engine_fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "engine-root",
                    "kind": "resource",
                    "name": "engine-root",
                }
            ],
            "relations": [
                {
                    "type": "loads",
                    "source": {"id": "engine-root", "name": "engine-root"},
                    "target": {"id": "ios-late-node", "name": "Example"},
                }
            ],
            "capabilities": [
                {
                    "name": "cross-platform-link",
                    "category": "linkage",
                    "entity_ids": ["engine-root", "ios-late-node"],
                }
            ],
        }
        ios_fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "ios-late-node",
                    "kind": "mach_o_binary",
                    "name": "Example",
                }
            ],
            "relations": [],
            "capabilities": [],
        }

        result = build_semantic_ir(
            engine_analysis=_analysis(engine_fragment),
            ios_analysis={"result": {"data": _analysis(ios_fragment)}},
        )

        relation = next(item for item in result["relations"] if item["type"] == "loads")
        self.assertEqual(relation["source"], "engine-root")
        self.assertEqual(relation["target"], "ios-late-node")
        self.assertNotIn("engine-root", relation["sources"])
        capability = next(item for item in result["capabilities"] if item["name"] == "cross-platform-link")
        self.assertEqual(capability["entity_ids"], ["engine-root", "ios-late-node"])

    def test_kind_conflict_is_preserved_and_raw_id_is_ambiguous(self):
        fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "colliding-id",
                    "kind": "android_package",
                    "name": "com.example",
                },
                {
                    "id": "colliding-id",
                    "kind": "mach_o_binary",
                    "name": "Example",
                },
            ],
            "relations": [
                {
                    "type": "ambiguous",
                    "source": "colliding-id",
                    "target": "colliding-id",
                }
            ],
            "capabilities": [
                {
                    "name": "ambiguous-reference",
                    "category": "fixture",
                    "entity_ids": ["colliding-id"],
                }
            ],
        }

        forward = build_semantic_ir(engine_analysis=_analysis(fragment))
        reversed_fragment = copy.deepcopy(fragment)
        reversed_fragment["entities"].reverse()
        reverse = build_semantic_ir(engine_analysis=_analysis(reversed_fragment))

        self.assertEqual(forward, reverse)
        self.assertEqual({item["name"] for item in forward["entities"]}, {"com.example", "Example"})
        self.assertEqual(forward["relations"], [])
        capability = next(item for item in forward["capabilities"] if item["name"] == "ambiguous-reference")
        self.assertEqual(capability["entity_ids"], [])

    def test_unavailable_analysis_or_fragment_is_suppressed(self):
        fake_fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "fake-node",
                    "kind": "platform_node",
                    "name": "must-not-appear",
                    "confidence": 1.0,
                    "sources": ["fake"],
                    "attributes": {},
                }
            ],
            "relations": [],
            "capabilities": [
                {
                    "id": "fake-capability",
                    "name": "must-not-appear",
                    "category": "fake",
                    "confidence": 1.0,
                }
            ],
            "provenance": [{"provider": "fake"}],
        }

        result = build_semantic_ir(
            engine_analysis=_analysis(fake_fragment, status="unavailable"),
            android_analysis=_analysis({**fake_fragment, "status": "unsupported"}),
            ios_analysis=_analysis(fake_fragment, status="not_available"),
            protocol_analysis=_analysis({**fake_fragment, "status": "skipped"}),
        )

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["entities"], [])
        self.assertEqual(result["relations"], [])
        self.assertEqual(result["capabilities"], [])
        self.assertNotIn("provenance", result)

    def test_dangling_relations_are_rejected_and_capability_references_are_filtered(self):
        fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "present",
                    "kind": "platform_node",
                    "name": "present",
                    "confidence": 0.8,
                    "sources": ["fixture"],
                    "attributes": {},
                }
            ],
            "relations": [
                {"id": "valid", "type": "self", "source": "present", "target": "present"},
                {"id": "missing-target", "type": "bad", "source": "present", "target": "missing"},
                {"id": "missing-source", "type": "bad", "source": "missing", "target": "present"},
            ],
            "capabilities": [
                {
                    "id": "capability:filtered",
                    "name": "filtered",
                    "category": "fixture",
                    "confidence": 0.8,
                    "entity_ids": ["missing", "present"],
                }
            ],
        }

        result = build_semantic_ir(engine_analysis=_analysis(fragment))

        entity_ids = {item["id"] for item in result["entities"]}
        self.assertEqual(len(result["relations"]), 1)
        self.assertTrue(all(item["source"] in entity_ids for item in result["relations"]))
        self.assertTrue(all(item["target"] in entity_ids for item in result["relations"]))
        capability = next(item for item in result["capabilities"] if item["name"] == "filtered")
        self.assertEqual(capability["entity_ids"], ["present"])

    def test_unavailable_records_are_suppressed(self):
        fragment = {
            "status": "ok",
            "entities": [
                {"id": "present", "kind": "resource", "name": "present"},
                {
                    "id": "hidden",
                    "kind": "resource",
                    "name": "hidden",
                    "available": False,
                    "provenance": {"provider": "hidden-entity"},
                },
            ],
            "relations": [
                {"type": "self", "source": "present", "target": "present"},
                {
                    "type": "hidden-record",
                    "source": "present",
                    "target": "present",
                    "status": "skipped",
                },
                {"type": "dangling", "source": "present", "target": "hidden"},
            ],
            "capabilities": [
                {
                    "name": "kept",
                    "category": "fixture",
                    "entity_ids": ["present", "hidden"],
                },
                {
                    "name": "hidden-capability",
                    "status": "not-run",
                    "provenance": {"provider": "hidden-capability"},
                },
            ],
            "provenance": [
                {"provider": "kept-provenance"},
                {"provider": "hidden-provenance", "status": "unsupported"},
            ],
        }

        result = build_semantic_ir(engine_analysis=_analysis(fragment))

        self.assertEqual(result["status"], "partial")
        self.assertEqual([item["name"] for item in result["entities"]], ["present"])
        self.assertEqual([item["type"] for item in result["relations"]], ["self"])
        self.assertNotIn("hidden-capability", {item["name"] for item in result["capabilities"]})
        kept = next(item for item in result["capabilities"] if item["name"] == "kept")
        self.assertEqual(kept["entity_ids"], ["present"])
        providers = {item.get("provider") for item in result["provenance"]}
        self.assertIn("kept-provenance", providers)
        self.assertNotIn("hidden-provenance", providers)

    def test_engine_capability_without_standard_fields_is_preserved(self):
        fragment = {
            "status": "partial",
            "entities": [],
            "relations": [],
            "capabilities": [
                {
                    "name": "il2cpp-native-mapping",
                    "status": "dependency-gated",
                    "confidence": 0.45,
                    "mapped_method_count": 3,
                    "eligible_method_count": 9,
                    "provenance": {"provider": "engine.native_mapping"},
                }
            ],
        }

        result = build_semantic_ir(engine_analysis=_analysis(fragment, status="partial"))

        capability = next(item for item in result["capabilities"] if item["name"] == "il2cpp-native-mapping")
        self.assertTrue(capability["id"].startswith("capability:il2cpp-native-mapping:"))
        self.assertEqual(capability["category"], "il2cpp-native-mapping")
        self.assertEqual(capability["status"], "dependency_gated")
        self.assertEqual(capability["attributes"]["mapped_method_count"], 3)
        self.assertEqual(capability["attributes"]["eligible_method_count"], 9)
        self.assertEqual(capability["provenance"], [{"provider": "engine.native_mapping"}])
        self.assertEqual(result["status"], "partial")

    def test_non_production_statuses_are_not_reported_as_done(self):
        fragment = {
            "status": "ok",
            "entities": [
                {
                    "id": "mock-node",
                    "kind": "platform_node",
                    "name": "mock-node",
                    "confidence": 0.5,
                    "sources": ["mock-provider"],
                    "attributes": {},
                }
            ],
            "relations": [],
            "capabilities": [],
        }

        for status in ("mock", "dependency-gated", "fake", "schema-only"):
            with self.subTest(status=status):
                status_fragment = copy.deepcopy(fragment)
                status_fragment["status"] = status
                result = build_semantic_ir(engine_analysis=_analysis(status_fragment, status=status))

                self.assertEqual(result["status"], "partial")
                self.assertEqual(len(result["entities"]), 1)

        empty = build_semantic_ir(
            engine_analysis=_analysis(
                {"status": "schema-only", "entities": [], "relations": [], "capabilities": []},
                status="schema-only",
            )
        )
        self.assertEqual(empty["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
