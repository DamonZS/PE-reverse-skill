import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock, patch

from reverse_analyzer.core.capabilities import CapabilityRequest, TargetIdentity
from reverse_analyzer.llm_jailbreak import (
    list_instruction_profiles,
    load_instruction_bundle,
)
from reverse_analyzer.llm_jailbreak.cli import build_parser, main
from reverse_analyzer.llm_jailbreak.models import Campaign
from reverse_analyzer.providers.llm_jailbreak import LLMJailbreakProvider


def _cli_campaign():
    return Campaign(
        name="Advanced CLI fixture",
        objective="Exercise CLI product wiring without a remote endpoint.",
    )


class AdvancedStandaloneCliTests(unittest.TestCase):
    def _invoke(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_parser_accepts_repeated_and_comma_separated_attack_modes(self):
        args = build_parser().parse_args(
            [
                "run",
                "campaign.json",
                "--attack-mode",
                "pair,tap",
                "--attack-mode",
                "crescendo",
                "--semantic-judge",
                "model",
                "--judge-model",
                "judge-fixture",
                "--instruction-profile",
                "CTF_SANDBOX.md",
                "--instruction-file",
                "prompts/one.md",
                "--instruction-files",
                "prompts/two.markdown",
            ]
        )

        self.assertEqual(args.attack_modes, ["pair,tap", "crescendo"])
        self.assertEqual(args.semantic_judge, "model")
        self.assertEqual(args.judge_model, "judge-fixture")
        self.assertEqual(args.instruction_profile, "CTF_SANDBOX.md")
        self.assertEqual(
            args.instruction_files,
            ["prompts/one.md", "prompts/two.markdown"],
        )

    def test_profiles_command_discovers_repository_instruction_bundles(self):
        code, stdout, stderr = self._invoke(["profiles", "--json"])

        self.assertEqual(code, 0, stderr)
        self.assertEqual(
            json.loads(stdout),
            {"profiles": list(list_instruction_profiles())},
        )

    def test_run_normalizes_and_forwards_advanced_campaign_overrides(self):
        campaign = _cli_campaign()
        transport = object()
        result = SimpleNamespace(
            campaign_id="advanced-cli",
            status="exhausted",
            success=False,
            attempts=(),
            to_dict=lambda: {"campaign_id": "advanced-cli", "status": "exhausted"},
        )
        with (
            patch(
                "reverse_analyzer.llm_jailbreak.cli.load_campaign",
                return_value=campaign,
            ),
            patch(
                "reverse_analyzer.llm_jailbreak.cli."
                "OpenAICompatibleTransport.from_target",
                return_value=transport,
            ) as transport_factory,
            patch(
                "reverse_analyzer.llm_jailbreak.cli.run_campaign",
                return_value=result,
            ) as runner,
        ):
            code, _, stderr = self._invoke(
                [
                    "run",
                    "campaign.json",
                    "--attack-mode",
                    "PAIR,tap",
                    "--attack-mode",
                    "crescendo,pair",
                    "--semantic-judge",
                    "model",
                    "--judge-model",
                    " judge-fixture ",
                    "--instruction-profile",
                    "CTF_SANDBOX.md",
                    "--instruction-file",
                    " prompts/one.md ",
                    "--instruction-file",
                    "prompts/two.markdown",
                ]
            )

        self.assertEqual(code, 0, stderr)
        effective = runner.call_args.args[0]
        self.assertEqual(effective.attack_modes, ("pair", "tap", "crescendo"))
        self.assertEqual(effective.semantic_judge, "model")
        self.assertEqual(effective.judge_model, "judge-fixture")
        self.assertEqual(effective.instruction_profile, "ctf-sandbox")
        self.assertEqual(
            effective.instruction_files,
            ("prompts/one.md", "prompts/two.markdown"),
        )
        self.assertIs(runner.call_args.kwargs["transport"], transport)
        transport_factory.assert_called_once_with(effective.target)

    def test_run_without_advanced_flags_preserves_old_campaign_defaults(self):
        campaign = _cli_campaign()
        result = SimpleNamespace(
            campaign_id="legacy-cli",
            status="exhausted",
            success=False,
            attempts=(),
            to_dict=lambda: {},
        )
        with (
            patch(
                "reverse_analyzer.llm_jailbreak.cli.load_campaign",
                return_value=campaign,
            ),
            patch(
                "reverse_analyzer.llm_jailbreak.cli."
                "OpenAICompatibleTransport.from_target",
                return_value=object(),
            ),
            patch(
                "reverse_analyzer.llm_jailbreak.cli.run_campaign",
                return_value=result,
            ) as runner,
        ):
            code, _, stderr = self._invoke(["run", "legacy.json"])

        self.assertEqual(code, 0, stderr)
        self.assertIs(runner.call_args.args[0], campaign)

    def test_invalid_attack_mode_stops_before_transport_or_runner(self):
        transport_factory = Mock()
        runner = Mock()
        with (
            patch(
                "reverse_analyzer.llm_jailbreak.cli.load_campaign",
                return_value=_cli_campaign(),
            ),
            patch(
                "reverse_analyzer.llm_jailbreak.cli."
                "OpenAICompatibleTransport.from_target",
                transport_factory,
            ),
            patch("reverse_analyzer.llm_jailbreak.cli.run_campaign", runner),
        ):
            code, _, stderr = self._invoke(
                ["run", "campaign.json", "--attack-mode", "unknown"]
            )

        self.assertEqual(code, 2)
        self.assertIn("unsupported --attack-mode", stderr)
        transport_factory.assert_not_called()
        runner.assert_not_called()

    def test_model_judge_requires_judge_model_before_transport_is_built(self):
        transport_factory = Mock()
        runner = Mock()
        with (
            patch(
                "reverse_analyzer.llm_jailbreak.cli.load_campaign",
                return_value=_cli_campaign(),
            ),
            patch(
                "reverse_analyzer.llm_jailbreak.cli."
                "OpenAICompatibleTransport.from_target",
                transport_factory,
            ),
            patch("reverse_analyzer.llm_jailbreak.cli.run_campaign", runner),
        ):
            code, _, stderr = self._invoke(
                ["run", "campaign.json", "--semantic-judge", "model"]
            )

        self.assertEqual(code, 2)
        self.assertIn("--judge-model is required", stderr)
        transport_factory.assert_not_called()
        runner.assert_not_called()


class AdvancedProviderTests(unittest.TestCase):
    def setUp(self):
        self._instruction_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._instruction_tmp.cleanup)

    def _instruction_file(self, relative_path):
        path = Path(self._instruction_tmp.name) / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {path.stem}\n\nFixture instruction.\n", encoding="utf-8")
        return str(path)

    def _request(self, *, campaign=None, **overrides):
        params = {
            "campaign": campaign
            or {
                "id": "advanced-provider",
                "name": "Advanced provider fixture",
                "prompts": ["fixture"],
            },
            "base_url": "https://fixture.invalid/v1",
            "model": "target-fixture",
            "api_key_env": "ADVANCED_PROVIDER_TEST_KEY",
            "max_attempts": 4,
            "max_rounds": 2,
        }
        params.update(overrides)
        return CapabilityRequest(
            capability="llm_jailbreak",
            action="run",
            target=TargetIdentity(kind="model", display_name="Fixture model"),
            params=params,
            session_id="advanced-provider-test",
        )

    def test_advanced_settings_flow_through_plan_runner_and_audit_payloads(self):
        calls = []
        instruction_files = [
            self._instruction_file("prompts/one.md"),
            self._instruction_file("prompts/two.markdown"),
        ]
        instruction_source_refs = [
            asset.source
            for asset in load_instruction_bundle("ctf", instruction_files).assets
            if asset.provenance.get("kind") == "custom-markdown"
        ]

        def fake_runner(**kwargs):
            calls.append(kwargs)
            return {
                "status": "completed",
                "success": False,
                "attempts": [
                    {
                        "strategy": "roleplay",
                        "score": 0.25,
                        "metadata": {
                            "instruction_asset": {
                                "bundle_digest": "a" * 64,
                                "asset_count": 3,
                            }
                        },
                    }
                ],
            }

        provider = LLMJailbreakProvider(runner=fake_runner, transport=object())
        plan = provider.plan(
            self._request(
                attack_modes=["PAIR,tap", "crescendo", "pair"],
                semantic_judge="MODEL",
                judge_model="judge-fixture",
                instruction_profile="CTF_SANDBOX.md",
                instruction_files=[f" {instruction_files[0]} ", instruction_files[1]],
            )
        )

        self.assertEqual(plan.parameters["attack_modes"], ["pair", "tap", "crescendo"])
        self.assertEqual(plan.parameters["semantic_judge"], "model")
        self.assertEqual(plan.parameters["judge_model"], "judge-fixture")
        self.assertEqual(plan.parameters["instruction_profile"], "ctf-sandbox")
        self.assertEqual(
            plan.parameters["instruction_files"],
            instruction_files,
        )
        self.assertEqual(
            plan.parameters["campaign"]["instruction_profile"],
            "ctf-sandbox",
        )
        self.assertEqual(
            plan.parameters["campaign"]["instruction_files"],
            instruction_files,
        )
        execution = plan.before_snapshot["execution"]
        self.assertEqual(execution["attack_modes"], ["pair", "tap", "crescendo"])
        self.assertEqual(execution["semantic_judge"], "model")
        self.assertEqual(execution["judge_model"], "judge-fixture")
        self.assertEqual(execution["instruction_profile"], "ctf-sandbox")
        self.assertEqual(
            execution["instruction_files"],
            instruction_source_refs,
        )
        self.assertTrue(provider.validate(plan).ok)

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(calls[0]["attack_modes"], ["pair", "tap", "crescendo"])
        self.assertEqual(calls[0]["semantic_judge"], "model")
        self.assertEqual(calls[0]["judge_model"], "judge-fixture")
        self.assertEqual(calls[0]["instruction_profile"], "ctf-sandbox")
        self.assertEqual(
            calls[0]["instruction_files"],
            instruction_files,
        )
        self.assertEqual(
            calls[0]["campaign"]["instruction_profile"],
            "ctf-sandbox",
        )
        for summary in (
            result.report_section,
            result.after_snapshot,
            result.dashboard_trace[0],
        ):
            self.assertEqual(summary["attack_modes"], ["pair", "tap", "crescendo"])
            self.assertEqual(summary["semantic_judge"], "model")
            self.assertEqual(summary["judge_model"], "judge-fixture")
            self.assertEqual(summary["instruction_profile"], "ctf-sandbox")
            self.assertEqual(
                summary["instruction_files"],
                instruction_source_refs,
            )
            self.assertEqual(
                summary["instruction_bundle_digest"],
                plan.parameters["instruction_bundle_digest"],
            )
            self.assertEqual(
                summary["instruction_asset_count"],
                plan.parameters["instruction_asset_count"],
            )
            self.assertEqual(
                summary["instruction_bundle_provenance"],
                plan.parameters["instruction_bundle_provenance"],
            )

        with tempfile.TemporaryDirectory() as directory:
            provider.collect_artifacts(result, directory)
            root = Path(directory) / "llm_jailbreak" / "advanced-provider-test"
            campaign_payload = json.loads(
                (root / "campaign.json").read_text(encoding="utf-8")
            )
            result_payload = json.loads(
                (root / "result.json").read_text(encoding="utf-8")
            )

        self.assertEqual(
            campaign_payload["execution"]["attack_modes"],
            ["pair", "tap", "crescendo"],
        )
        self.assertEqual(campaign_payload["execution"]["semantic_judge"], "model")
        self.assertEqual(campaign_payload["execution"]["judge_model"], "judge-fixture")
        self.assertEqual(
            campaign_payload["execution"]["instruction_profile"],
            "ctf-sandbox",
        )
        self.assertEqual(
            campaign_payload["campaign"]["instruction_files"],
            instruction_source_refs,
        )
        self.assertEqual(result_payload["summary"]["semantic_judge"], "model")
        self.assertEqual(
            result_payload["summary"]["instruction_bundle_digest"],
            plan.parameters["instruction_bundle_digest"],
        )
        self.assertEqual(
            result_payload["summary"]["instruction_asset_count"],
            plan.parameters["instruction_asset_count"],
        )

    def test_campaign_values_are_used_and_explicit_params_take_precedence(self):
        campaign_instruction = self._instruction_file("campaign/one.md")
        request_instruction = self._instruction_file("request/one.markdown")
        campaign = {
            "id": "campaign-settings",
            "name": "Campaign settings",
            "attack_modes": ["pair", "evolution"],
            "semantic_judge": "heuristic",
            "judge_model": "campaign-judge",
            "instruction_profile": "ctf",
            "instruction_files": [campaign_instruction],
        }
        provider = LLMJailbreakProvider(runner=lambda **kwargs: {}, transport=object())

        inherited = provider.plan(self._request(campaign=campaign))
        overridden = provider.plan(
            self._request(
                campaign=campaign,
                attack_modes="tap,crescendo",
                semantic_judge="model",
                judge_model="request-judge",
                instruction_profile="unrestricted",
                instruction_files=[request_instruction],
            )
        )

        self.assertEqual(inherited.parameters["attack_modes"], ["pair", "evolution"])
        self.assertEqual(inherited.parameters["semantic_judge"], "heuristic")
        self.assertEqual(inherited.parameters["judge_model"], "campaign-judge")
        self.assertEqual(inherited.parameters["instruction_profile"], "ctf-sandbox")
        self.assertEqual(
            inherited.parameters["instruction_files"],
            [campaign_instruction],
        )
        self.assertEqual(overridden.parameters["attack_modes"], ["tap", "crescendo"])
        self.assertEqual(overridden.parameters["semantic_judge"], "model")
        self.assertEqual(overridden.parameters["judge_model"], "request-judge")
        self.assertEqual(
            overridden.parameters["instruction_profile"],
            "gpt5.5-unrestricted",
        )
        self.assertEqual(
            overridden.parameters["instruction_files"],
            [request_instruction],
        )
        self.assertEqual(
            overridden.parameters["campaign"]["instruction_profile"],
            "gpt5.5-unrestricted",
        )

    def test_legacy_config_gets_compatible_defaults_and_model_judge_fallback(self):
        calls = []
        provider = LLMJailbreakProvider(
            runner=lambda **kwargs: calls.append(kwargs) or {"status": "completed"},
            transport=object(),
        )

        legacy = provider.plan(self._request())
        model_judged = provider.plan(self._request(semantic_judge="model"))
        result = provider.execute(legacy)

        self.assertEqual(legacy.parameters["attack_modes"], ["builtin"])
        self.assertEqual(legacy.parameters["semantic_judge"], "disabled")
        self.assertEqual(legacy.parameters["judge_model"], "")
        self.assertNotIn("instruction_profile", legacy.parameters)
        self.assertNotIn("instruction_files", legacy.parameters)
        self.assertNotIn("instruction_profile", legacy.parameters["campaign"])
        self.assertNotIn("instruction_files", legacy.parameters["campaign"])
        self.assertEqual(model_judged.parameters["judge_model"], "target-fixture")
        self.assertEqual(result.status, "ok")
        self.assertEqual(calls[0]["attack_modes"], ["builtin"])
        self.assertEqual(calls[0]["semantic_judge"], "disabled")
        self.assertEqual(calls[0]["judge_model"], "")
        self.assertNotIn("instruction_profile", calls[0])
        self.assertNotIn("instruction_files", calls[0])

    def test_instruction_settings_reach_campaign_with_legacy_runner_signature(self):
        seen = {}
        instruction_file = self._instruction_file("prompts/custom.md")

        def legacy_runner(campaign):
            seen["campaign"] = Campaign.from_dict(campaign)
            return {"status": "completed", "attempts": []}

        campaign = {
            "id": "instruction-provider",
            "name": "Instruction provider fixture",
            "objective": "Verify provider campaign construction.",
        }
        provider = LLMJailbreakProvider(
            runner=legacy_runner,
            transport=object(),
        )
        plan = provider.plan(
            self._request(
                campaign=campaign,
                instruction_profile="ctf",
                instruction_files=[instruction_file],
            )
        )

        result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(seen["campaign"].instruction_profile, "ctf-sandbox")
        self.assertEqual(
            seen["campaign"].instruction_files,
            (instruction_file,),
        )

    def test_tampered_advanced_settings_fail_validation_without_running(self):
        runner = Mock(return_value={"status": "completed"})
        provider = LLMJailbreakProvider(runner=runner, transport=object())
        plan = provider.plan(self._request())
        plan.parameters["attack_modes"] = ["unsupported"]

        validation = provider.validate(plan)
        result = provider.execute(plan)

        self.assertFalse(validation.ok)
        self.assertEqual(result.status, "failed")
        runner.assert_not_called()

    def test_execution_uses_plan_fixed_bundle_snapshot_after_validation(self):
        instruction_file = self._instruction_file("prompts/session.md")
        original_content = Path(instruction_file).read_text(encoding="utf-8")
        calls = []

        def runner(**kwargs):
            calls.append(kwargs)
            return {"status": "completed", "attempts": []}

        provider = LLMJailbreakProvider(runner=runner, transport=object())
        plan = provider.plan(
            self._request(instruction_files=[instruction_file])
        )
        original_validate = provider.validate

        def validate_then_change(value, context=None):
            validation = original_validate(value, context)
            Path(instruction_file).write_text(
                "changed after validation",
                encoding="utf-8",
            )
            return validation

        with patch.object(provider, "validate", side_effect=validate_then_change):
            result = provider.execute(plan)

        self.assertEqual(result.status, "ok")
        self.assertEqual(len(calls), 1)
        snapshot = calls[0]["instruction_bundle"]
        self.assertEqual(snapshot["digest"], plan.parameters["instruction_bundle_digest"])
        self.assertEqual(snapshot["assets"][0]["content"], original_content.strip())
        self.assertNotIn(
            str(Path(instruction_file).parent),
            json.dumps(result.report_section, sort_keys=True),
        )


if __name__ == "__main__":
    unittest.main()
