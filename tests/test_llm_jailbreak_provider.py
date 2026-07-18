import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.providers import LLMJailbreakProvider, build_default_registry


class LLMJailbreakProviderTests(unittest.TestCase):
    def _request(self, *, target=None, **parameter_overrides):
        params = {
            "campaign": {
                "id": "gpt-family-regression",
                "name": "GPT family jailbreak regression",
                "prompts": ["seed-one", "seed-two"],
            },
            "base_url": "https://models.example.test/v1/",
            "model": "gpt-5.2",
            "api_key_env": "LLM_JAILBREAK_TEST_KEY",
            "timeout": 12.5,
            "max_attempts": 9,
            "max_rounds": 3,
            "resume": False,
            "strategies": ["roleplay", "instruction_conflict"],
        }
        params.update(parameter_overrides)
        return CapabilityRequest(
            capability="llm_jailbreak",
            action="run",
            target=target
            or TargetIdentity(
                kind="llm_endpoint",
                display_name="GPT fixture",
                metadata={"environment": "unit-test"},
            ),
            params=params,
            session_id="llm-jailbreak-test",
            provenance={"source": "unit-test"},
        )

    def test_default_registry_registers_and_exports_real_provider(self):
        registry = build_default_registry()

        self.assertIn("llm_jailbreak", registry.list_capabilities())
        self.assertEqual(
            registry.list_providers("llm_jailbreak"),
            ["openai_compatible_jailbreak"],
        )
        self.assertIsInstance(registry.resolve("llm_jailbreak"), LLMJailbreakProvider)

    def test_full_lifecycle_uses_transport_factory_and_never_persists_api_key(self):
        api_key = "sk-unit-test-super-secret-key"
        factory_calls = []
        runner_calls = []
        transport_calls = []

        def fake_transport(payload):
            transport_calls.append(payload)
            return {"content": "fixture response"}

        def fake_transport_factory(**settings):
            factory_calls.append(settings)
            return fake_transport

        def fake_runner(**request):
            runner_calls.append(request)
            response = request["transport"]({"messages": [{"role": "user", "content": "seed"}]})
            return {
                "status": "completed",
                "strategy": "adaptive-tree",
                "success": True,
                "score": 0.94,
                "attempt_count": 2,
                "latency_ms": 123.4,
                "api_key": api_key,
                "authorization": f"Bearer {api_key}",
                "attempts": [
                    {
                        "attempt": 1,
                        "strategy": "roleplay",
                        "success": False,
                        "score": 0.2,
                        "latency_ms": 50,
                    },
                    {
                        "attempt": 2,
                        "strategy": "instruction_conflict",
                        "success": True,
                        "score": 0.94,
                        "latency_ms": 73.4,
                        "response": response["content"],
                        "debug": f"echo={api_key}",
                    },
                ],
            }

        provider = LLMJailbreakProvider(
            runner=fake_runner,
            transport_factory=fake_transport_factory,
        )
        with mock.patch.dict(os.environ, {"LLM_JAILBREAK_TEST_KEY": api_key}, clear=False):
            plan = provider.plan(self._request())
            validation = provider.validate(plan)
            result = provider.execute(plan)
            rollback = provider.rollback(result)
            with tempfile.TemporaryDirectory() as temp_dir:
                bundle = provider.collect_artifacts(result, temp_dir)
                artifact_text = "\n".join(
                    (Path(temp_dir) / artifact.path).read_text(encoding="utf-8")
                    for artifact in bundle.artifacts
                )
                self.assertNotIn(api_key, artifact_text)
                self.assertEqual(len(bundle.artifacts), 4)
                self.assertEqual(len(bundle.manifest_entries), 4)
                for artifact, entry in zip(bundle.artifacts, bundle.manifest_entries):
                    path = Path(temp_dir) / artifact.path
                    encoded = path.read_bytes()
                    self.assertTrue(path.is_file())
                    self.assertEqual(entry["sha256"], hashlib.sha256(encoded).hexdigest())
                    self.assertEqual(entry["size"], len(encoded))
                    self.assertTrue(entry["materialized"])

                result_json = json.loads(
                    (
                        Path(temp_dir)
                        / "llm_jailbreak"
                        / "llm-jailbreak-test"
                        / "result.json"
                    ).read_text(encoding="utf-8")
                )
                attempts_json = json.loads(
                    (
                        Path(temp_dir)
                        / "llm_jailbreak"
                        / "llm-jailbreak-test"
                        / "attempts.json"
                    ).read_text(encoding="utf-8")
                )
                rollback_json = json.loads(
                    (
                        Path(temp_dir)
                        / "llm_jailbreak"
                        / "llm-jailbreak-test"
                        / "rollback.json"
                    ).read_text(encoding="utf-8")
                )

        self.assertTrue(validation.ok)
        self.assertEqual(plan.target.metadata["campaign_id"], "gpt-family-regression")
        self.assertEqual(plan.parameters["base_url"], "https://models.example.test/v1")
        self.assertEqual(plan.parameters["model"], "gpt-5.2")
        self.assertEqual(plan.parameters["api_key_env"], "LLM_JAILBREAK_TEST_KEY")
        self.assertEqual(plan.parameters["timeout"], 12.5)
        self.assertEqual(plan.parameters["max_attempts"], 9)
        self.assertEqual(plan.parameters["max_rounds"], 3)
        self.assertEqual(plan.parameters["strategies"], ["roleplay", "instruction_conflict"])
        self.assertNotIn(api_key, json.dumps(plan.to_dict(), sort_keys=True))

        self.assertEqual(result.status, "ok")
        expected_report = {
            "strategy": "adaptive-tree",
            "success": True,
            "score": 0.94,
            "attempt_count": 2,
            "latency_ms": 123.4,
            "model": "gpt-5.2",
            "base_url": "https://models.example.test/v1",
            "campaign_id": "gpt-family-regression",
        }
        for key, value in expected_report.items():
            self.assertEqual(result.report_section[key], value)
        self.assertNotIn(api_key, json.dumps(result.to_dict(), sort_keys=True))
        self.assertTrue(rollback.ok)
        self.assertTrue(rollback.restored)
        self.assertEqual(rollback_json["status"], "completed")
        self.assertEqual(result_json["result"]["api_key"], "[REDACTED]")
        self.assertEqual(attempts_json["attempt_count"], 2)
        self.assertEqual(len(factory_calls), 1)
        self.assertEqual(factory_calls[0]["api_key_env"], "LLM_JAILBREAK_TEST_KEY")
        self.assertNotIn("api_key", factory_calls[0])
        self.assertEqual(len(runner_calls), 1)
        self.assertNotIn("api_key", runner_calls[0])
        self.assertIs(runner_calls[0]["transport"], fake_transport)
        self.assertEqual(len(transport_calls), 1)

    def test_campaign_path_is_loaded_and_tampered_plan_does_not_execute(self):
        calls = []

        def fake_runner(**request):
            calls.append(request)
            return {"status": "completed", "success": False, "attempts": []}

        provider = LLMJailbreakProvider(runner=fake_runner, transport=lambda payload: payload)
        with tempfile.TemporaryDirectory() as temp_dir:
            campaign_path = Path(temp_dir) / "campaign.json"
            campaign_path.write_text(
                json.dumps(
                    {
                        "campaign_id": "path-campaign",
                        "goals": ["goal-one"],
                        "strategies": ["multilingual"],
                    }
                ),
                encoding="utf-8",
            )
            request = self._request(campaign_path=str(campaign_path))
            request.params.pop("campaign")
            request.params.pop("strategies")
            request.params["resume"] = True
            plan = provider.plan(request)

        self.assertEqual(plan.parameters["campaign_metadata"]["source"], "path")
        self.assertEqual(plan.parameters["campaign_metadata"]["source_name"], "campaign.json")
        self.assertEqual(plan.parameters["campaign_metadata"]["campaign_id"], "path-campaign")
        self.assertEqual(plan.parameters["strategies"], ["multilingual"])
        self.assertTrue(plan.parameters["resume"])
        self.assertTrue(provider.validate(plan).ok)

        plan.parameters["model"] = "tampered-model"
        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        self.assertEqual(calls, [])

    def test_direct_transport_injection_is_forwarded_to_runner(self):
        transport = object()
        seen = []

        def fake_runner(**request):
            seen.append(request)
            return {"status": "completed", "attempts": []}

        provider = LLMJailbreakProvider(runner=fake_runner, transport=transport)
        plan = provider.plan(self._request())
        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertIs(provider.transport, transport)
        self.assertIs(seen[0]["transport"], transport)

    def test_core_result_latency_seconds_is_reported_in_milliseconds(self):
        def fake_runner(**request):
            return {
                "status": "completed",
                "success": False,
                "summary": {"latency_seconds": 1.25},
                "attempts": [
                    {
                        "attempt": 1,
                        "response": {"latency_seconds": 0.5},
                    }
                ],
            }

        provider = LLMJailbreakProvider(runner=fake_runner, transport=object())
        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(result.status, "ok")
        self.assertEqual(result.report_section["latency_ms"], 1250.0)

    def test_nested_attempt_score_is_reported_as_scalar(self):
        def fake_runner(**request):
            return {
                "status": "completed",
                "success": True,
                "attempts": [
                    {
                        "attempt": 1,
                        "success": True,
                        "score": {"score": 1.0, "success": True},
                    }
                ],
            }

        provider = LLMJailbreakProvider(runner=fake_runner, transport=object())
        result = provider.execute(provider.plan(self._request()))

        self.assertEqual(result.report_section["score"], 1.0)
        self.assertEqual(result.after_snapshot["score"], 1.0)
        self.assertEqual(result.dashboard_trace[0]["score"], 1.0)

    def test_explicit_runner_receives_every_parameter_and_session_engine_directory(self):
        seen = {}
        transport = object()

        def explicit_runner(
            campaign,
            campaign_path,
            campaign_id,
            base_url,
            model,
            api_key_env,
            timeout,
            max_attempts,
            max_rounds,
            resume,
            strategies,
            options,
            session_id,
            target_identity,
            out_dir,
            transport,
        ):
            seen.update(
                {
                    "campaign": campaign,
                    "campaign_path": campaign_path,
                    "campaign_id": campaign_id,
                    "base_url": base_url,
                    "model": model,
                    "api_key_env": api_key_env,
                    "timeout": timeout,
                    "max_attempts": max_attempts,
                    "max_rounds": max_rounds,
                    "resume": resume,
                    "strategies": strategies,
                    "options": options,
                    "session_id": session_id,
                    "target_identity": target_identity,
                    "out_dir": out_dir,
                    "transport": transport,
                }
            )
            engine_output = Path(out_dir)
            engine_output.mkdir(parents=True, exist_ok=True)
            (engine_output / "runner-marker.json").write_text(
                json.dumps({"session_id": session_id}),
                encoding="utf-8",
            )
            return {
                "status": "completed",
                "success": False,
                "score": 0.1,
                "attempt_count": 1,
                "attempts": [{"strategy": "roleplay", "success": False}],
            }

        provider = LLMJailbreakProvider(runner=explicit_runner, transport=transport)
        request = self._request(
            target=TargetIdentity(
                kind="model",
                display_name="Model target",
                metadata={"provider": "fixture"},
            ),
            resume=True,
            options={"temperature": 0.2, "max_tokens": 64},
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plan = provider.plan(request)
            result = provider.execute(plan, context={"out_dir": str(root)})
            expected_engine = (
                root.resolve()
                / "llm_jailbreak"
                / "llm-jailbreak-test"
                / "engine"
            )
            self.assertTrue((expected_engine / "runner-marker.json").is_file())

        self.assertEqual(plan.target.kind, "model")
        self.assertEqual(result.target.kind, "model")
        self.assertEqual(result.status, "ok")
        self.assertFalse(result.report_section["success"])
        self.assertEqual(seen["campaign"], plan.parameters["campaign"])
        self.assertIsNone(seen["campaign_path"])
        self.assertEqual(seen["campaign_id"], "gpt-family-regression")
        self.assertEqual(seen["base_url"], "https://models.example.test/v1")
        self.assertEqual(seen["model"], "gpt-5.2")
        self.assertEqual(seen["api_key_env"], "LLM_JAILBREAK_TEST_KEY")
        self.assertEqual(seen["timeout"], 12.5)
        self.assertEqual(seen["max_attempts"], 9)
        self.assertEqual(seen["max_rounds"], 3)
        self.assertTrue(seen["resume"])
        self.assertEqual(seen["strategies"], ["roleplay", "instruction_conflict"])
        self.assertEqual(seen["options"], {"temperature": 0.2, "max_tokens": 64})
        self.assertEqual(seen["session_id"], "llm-jailbreak-test")
        self.assertEqual(seen["target_identity"]["kind"], "model")
        self.assertEqual(Path(seen["out_dir"]), expected_engine)
        self.assertIs(seen["transport"], transport)

    def test_checkpoint_path_is_canonical_validated_and_forwarded(self):
        seen = {}

        def checkpoint_runner(checkpoint_path, out_dir):
            seen["checkpoint_path"] = checkpoint_path
            seen["out_dir"] = out_dir
            return {"status": "completed", "success": False, "attempts": []}

        provider = LLMJailbreakProvider(
            runner=checkpoint_runner,
            transport=object(),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            checkpoint = root / "state" / "campaign.checkpoint.json"
            plan = provider.plan(
                self._request(
                    checkpoint_path=str(checkpoint),
                    resume=True,
                )
            )
            validation = provider.validate(plan)
            result = provider.execute(plan, context={"out_dir": str(root)})

            self.assertTrue(validation.ok)
            self.assertEqual(
                Path(plan.parameters["checkpoint_path"]),
                checkpoint.resolve(),
            )
            self.assertEqual(Path(seen["checkpoint_path"]), checkpoint.resolve())
            self.assertEqual(
                Path(seen["out_dir"]),
                root.resolve()
                / "llm_jailbreak"
                / "llm-jailbreak-test"
                / "engine",
            )
            self.assertEqual(
                result.provenance["checkpoint"]["path"],
                str(checkpoint.resolve()),
            )
            self.assertTrue(result.provenance["checkpoint"]["resume_requested"])

            plan.parameters["checkpoint_path"] = str(root / "other.json")
            self.assertFalse(provider.validate(plan).ok)

    def test_collects_engine_artifacts_and_checkpoint_snapshot_without_secrets(self):
        api_key = "sk-engine-artifact-secret-value"

        def artifact_runner(**request):
            engine = Path(request["out_dir"])
            (engine / "prompts").mkdir(parents=True, exist_ok=True)
            (engine / "responses").mkdir(parents=True, exist_ok=True)
            json_files = {
                "campaign.json": {"id": request["campaign_id"]},
                "attempts.json": {"attempts": [{"id": "attempt-1"}]},
                "transcript.json": {"turns": [{"attempt_id": "attempt-1"}]},
                "result.json": {"status": "completed", "success": False},
                "instruction-assets.json": {
                    "digest": "c" * 64,
                    "assets": [{"artifact_path": "instructions/profile.md"}],
                },
                "manifest.json": {"artifact_count": 6, "artifacts": []},
            }
            for name, payload in json_files.items():
                (engine / name).write_text(json.dumps(payload), encoding="utf-8")
            (engine / "attempts.jsonl").write_text(
                json.dumps({"id": "attempt-1"}) + "\n",
                encoding="utf-8",
            )
            (engine / "prompts" / "attempt-1.txt").write_text(
                "active jailbreak prompt\n",
                encoding="utf-8",
            )
            (engine / "responses" / "attempt-1.txt").write_text(
                f"model echoed Bearer {api_key}\n",
                encoding="utf-8",
            )
            (engine / "instructions").mkdir(parents=True, exist_ok=True)
            (engine / "instructions" / "profile.md").write_text(
                "fixture instruction asset\n",
                encoding="utf-8",
            )
            checkpoint = Path(request["checkpoint_path"])
            checkpoint.parent.mkdir(parents=True, exist_ok=True)
            checkpoint.write_text(
                json.dumps(
                    {
                        "campaign_id": request["campaign_id"],
                        "completed": True,
                    }
                ),
                encoding="utf-8",
            )
            return {
                "status": "completed",
                "success": False,
                "attempt_count": 1,
                "attempts": [{"strategy": "roleplay", "success": False}],
            }

        provider = LLMJailbreakProvider(
            runner=artifact_runner,
            transport=object(),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            checkpoint = root / "stable" / "campaign.json"
            with mock.patch.dict(
                os.environ,
                {"LLM_JAILBREAK_TEST_KEY": api_key},
                clear=False,
            ):
                plan = provider.plan(
                    self._request(checkpoint_path=str(checkpoint))
                )
                result = provider.execute(plan, context={"out_dir": str(root)})
                bundle = provider.collect_artifacts(result, str(root))

            artifact_paths = {artifact.path for artifact in bundle.artifacts}
            engine_root = "llm_jailbreak/llm-jailbreak-test/engine"
            expected_engine_paths = {
                f"{engine_root}/campaign.json",
                f"{engine_root}/attempts.json",
                f"{engine_root}/attempts.jsonl",
                f"{engine_root}/transcript.json",
                f"{engine_root}/result.json",
                f"{engine_root}/instruction-assets.json",
                f"{engine_root}/instructions/profile.md",
                f"{engine_root}/manifest.json",
                f"{engine_root}/prompts/attempt-1.txt",
                f"{engine_root}/responses/attempt-1.txt",
                "llm_jailbreak/llm-jailbreak-test/checkpoint.json",
            }
            self.assertTrue(expected_engine_paths.issubset(artifact_paths))
            self.assertEqual(
                len(bundle.manifest_entries),
                len(bundle.artifacts),
            )
            entries = {entry["path"]: entry for entry in bundle.manifest_entries}
            self.assertEqual(
                entries[f"{engine_root}/instruction-assets.json"]["kind"],
                "llm-jailbreak-instruction-assets",
            )
            self.assertEqual(
                entries[f"{engine_root}/instructions/profile.md"]["kind"],
                "llm-jailbreak-instruction-asset",
            )
            for artifact in bundle.artifacts:
                path = root / artifact.path
                content = path.read_bytes()
                self.assertTrue(path.is_file(), artifact.path)
                self.assertEqual(
                    entries[artifact.path]["sha256"],
                    hashlib.sha256(content).hexdigest(),
                )
                self.assertEqual(entries[artifact.path]["size"], len(content))
                self.assertTrue(entries[artifact.path]["materialized"])

            leaked_paths = [
                path
                for path in root.rglob("*")
                if path.is_file() and api_key.encode("utf-8") in path.read_bytes()
            ]
            self.assertEqual(leaked_paths, [])
            self.assertEqual(
                json.loads(
                    (root / "llm_jailbreak/llm-jailbreak-test/checkpoint.json").read_text(
                        encoding="utf-8"
                    )
                )["completed"],
                True,
            )

    def test_default_provider_resolves_core_package_entrypoint_without_network(self):
        calls = []

        def core_run_campaign(**request):
            calls.append(request)
            return {"status": "completed", "success": False, "attempts": []}

        provider = LLMJailbreakProvider(transport=lambda payload: payload)
        fake_core = SimpleNamespace(run_campaign=core_run_campaign)
        with mock.patch(
            "reverse_analyzer.providers.llm_jailbreak.importlib.import_module",
            return_value=fake_core,
        ):
            plan = provider.plan(self._request())
            self.assertTrue(provider.validate(plan).ok)
            result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["campaign_id"], "gpt-family-regression")

    def test_inline_api_key_is_rejected_before_plan_is_created(self):
        provider = LLMJailbreakProvider(runner=lambda **request: {})
        request = self._request(api_key="must-not-be-serialized")

        with self.assertRaisesRegex(ValueError, "api_key_env"):
            provider.plan(request)


if __name__ == "__main__":
    unittest.main()
