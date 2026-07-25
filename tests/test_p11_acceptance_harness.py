from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class P11AcceptanceHarnessContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = (ROOT / "scripts" / "accept_p11.ps1").read_text(encoding="utf-8")
        cls.server = (ROOT / "cmd" / "reverse-analyzer-server" / "main.go").read_text(encoding="utf-8")

    def test_uses_fresh_context_ephemeral_dependencies_and_final_cleanup(self) -> None:
        for required in (
            "git -c core.quotepath=false ls-files",
            "docker build",
            "temporary PostgreSQL",
            "finally",
            "docker rm -f",
            "Remove-Item -LiteralPath $temp -Recurse -Force",
        ):
            self.assertIn(required, self.script)
        self.assertNotIn("source=$repo,destination=/workspace", self.script)

    def test_fixture_is_compiled_and_ground_truth_is_not_archived(self) -> None:
        self.assertIn("program.c", self.script)
        self.assertIn("--entrypoint cc", self.script)
        self.assertIn("ground_truth_in_archive = $false", self.script)
        archive_line = next(line for line in self.script.splitlines() if line.strip().startswith("Compress-Archive"))
        self.assertNotIn("program.c", archive_line)
        self.assertIn("behavior-validation.json", archive_line)

    def test_secrets_are_not_written_to_evidence(self) -> None:
        self.assertIn("secret_recorded = $false", self.script)
        self.assertIn("output_sha256", self.script)
        self.assertNotIn("OPENAI_API_KEY =", self.script)
        self.assertNotIn("api_key =", self.script.lower())

    def test_external_provider_is_the_only_model_path(self) -> None:
        self.assertIn('fallback_policy = "external_credentials_only"', self.script)
        self.assertIn('Add-Block "real_model_provider_not_ready"', self.script)
        for forbidden in ("ollama", "qwen2.5-coder", "local_model = [ordered]"):
            self.assertNotIn(forbidden, self.script.lower())

    def test_external_probe_validates_real_model_and_all_credential_slots(self) -> None:
        probe = self.script[self.script.index("$probeScript = @'") : self.script.index("$probe = Invoke-Captured")]
        self.assertIn("enumerate(keys,1)", probe)
        self.assertIn("/chat/completions", probe)
        self.assertIn('"type":"json_schema"', probe)
        self.assertIn('"strict":True', probe)
        self.assertIn('value!={"ok":True}', probe)
        self.assertIn('"key_slot":slot', probe)
        self.assertIn('"fallback_count":slot-1', probe)
        self.assertIn('"strict_json":True', probe)
        self.assertIn("-e OPENAI_MODEL=$ProviderModel", self.script)
        self.assertIn("$probeScript | docker run --rm -i", self.script)

    def test_safe_summaries_are_parsed_without_recording_raw_output(self) -> None:
        capture = self.script[self.script.index("function Invoke-Captured") : self.script.index("function Add-Block")]
        self.assertIn('SAFE_SUMMARY:', capture)
        self.assertIn('ConvertFrom-Json', capture)
        self.assertIn('summary_parse_failed', capture)
        self.assertIn("$probeScript = @'", self.script)
        self.assertIn('p11-unittest-runner.py', self.script)
        self.assertIn('destination=/tmp/p11-unittest-runner.py,readonly', self.script)
        self.assertIn('P11_SUMMARY_PATH=/summary/python-regression-summary.json', self.script)
        self.assertIn('$pythonRegression["safe_summary"]', self.script)
        self.assertIn('[Text.UTF8Encoding]::new($false)', self.script)
        self.assertNotIn('output = $output', capture)

    def test_python_regression_uses_tmp_paths_and_bounded_unittest_summary(self) -> None:
        regression = self.script[self.script.index('$unittestWrapper = @\'') : self.script.index('$goRegression = Invoke-Captured')]
        for assignment in (
            "REVERSE_ANALYZER_WORKSPACE=/tmp/workspace",
            "REVERSE_ANALYZER_KNOWLEDGE_DIR=/tmp/knowledge",
            "REVERSE_ANALYZER_SESSIONS_DIR=/tmp/sessions",
            "REVERSE_ANALYZER_REPORTS_DIR=/tmp/reports",
        ):
            self.assertIn(assignment, regression)
        for field in ("tests_run", "failures", "errors", "dependency_gated", "dependency_gated_test_ids", "skipped", "expected_failures", "unexpected_successes", "failing_test_ids"):
            self.assertIn(field, regression)
        self.assertIn('[:100]', regression)
        self.assertIn('successful=not blocking_failures and not blocking_errors', regression)
        self.assertIn('tests.test_acceptance_records.AcceptanceRecordTests.test_windows_uia_fixture_contract_retains_hash_backed_live_proof', regression)

    def test_production_worker_docker_run_forces_network_none(self) -> None:
        self.assertIn('network = "none"', self.server)
        worker_argv = (
            'argv := []string{"run", "--rm", "--read-only", "--cap-drop", "ALL", '
            '"--security-opt", "no-new-privileges", "--pids-limit", "256", "--cpus", "1", '
            '"--memory", "1024m", "--network", network, "--mount", workspaceMount'
        )
        self.assertIn(worker_argv, self.server)
        self.assertIn('worker_network_none = ($manifest.worker_network.declared -eq "none"', self.script)
        self.assertIn('$manifest.worker_network.egress_blocked -eq $true', self.script)
        self.assertIn('.worker_network -eq "none")', self.script)

    def test_hard_gates_remain_false_when_live_chain_is_not_proven(self) -> None:
        self.assertIn("production_archive_chain", self.script)
        self.assertIn("model_tokens_positive", self.script)
        self.assertIn("behavior_real", self.script)
        self.assertIn("worker_network_none", self.script)
        self.assertIn("trusted_complete_buildable_artifacts_not_proven", self.script)
        for gate in (
            "analysis_complete",
            "source_generated",
            "structure_complete",
            "dependencies_locked",
            "build_passed",
            "behavior_passed",
            "complete_buildable",
        ):
            self.assertRegex(self.script, rf"{gate} = \$false")


if __name__ == "__main__":
    unittest.main()
