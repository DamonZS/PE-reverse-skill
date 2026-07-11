import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverse_analyzer.cli import _local_runner_environment


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "reverse_analyzer", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CliExperimentDashboardTests(unittest.TestCase):
    def test_experiment_plan_dry_run_local_execution_and_dashboard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            sample = workspace / "fixture.exe"
            trace = workspace / "trace.json"
            sample.write_text("MZ PresentationFramework.dll InitializeComponent", encoding="utf-8")
            trace.write_text(json.dumps({"initial_state": "editing", "steps": []}), encoding="utf-8")

            created = run_cli(
                "experiment",
                "create",
                str(sample),
                "--workspace",
                str(workspace),
                "--dynamic",
                "--dynamic-backend",
                "procmon",
                "--dynamic-profile",
                "network",
                "--gui-runtime",
                "--reconstruct-gui",
                "--gui-interaction-trace",
                str(trace),
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            create_payload = json.loads(created.stdout)
            experiment_id = create_payload["experiment"]["id"]
            self.assertEqual(create_payload["experiment"]["status"], "queued")
            self.assertIn("--dynamic", create_payload["analysis_command"])
            self.assertIn("--gui", create_payload["analysis_command"])
            self.assertIn("--gui-interaction-trace", create_payload["analysis_command"])

            planned = run_cli("experiment", "plan", experiment_id, "--workspace", str(workspace))
            self.assertEqual(planned.returncode, 0, planned.stderr)
            self.assertEqual(json.loads(planned.stdout)["experiment"]["status"], "planned")

            shown = run_cli("experiment", "show", experiment_id, "--workspace", str(workspace))
            self.assertEqual(shown.returncode, 0, shown.stderr)
            show_payload = json.loads(shown.stdout)
            self.assertEqual(show_payload["experiment"]["id"], experiment_id)
            self.assertIn("--dynamic-profile", show_payload["analysis_command"])

            dry_run = run_cli("experiment", "run", experiment_id, "--workspace", str(workspace), "--dry-run")
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            self.assertFalse(json.loads(dry_run.stdout)["executed"])

            second = run_cli("experiment", "create", str(sample), "--workspace", str(workspace))
            self.assertEqual(second.returncode, 0, second.stderr)
            second_id = json.loads(second.stdout)["experiment"]["id"]
            executed = run_cli(
                "experiment",
                "run",
                second_id,
                "--workspace",
                str(workspace),
                "--execute-local",
                "--timeout",
                "30",
            )
            self.assertEqual(executed.returncode, 0, executed.stderr)
            executed_payload = json.loads(executed.stdout)
            self.assertTrue(executed_payload["executed"])
            self.assertEqual(executed_payload["experiment"]["status"], "completed")
            self.assertTrue((workspace / "experiments" / second_id / "analysis" / "report.json").is_file())

            listed = run_cli("experiment", "list", "--workspace", str(workspace), "--json")
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertEqual(json.loads(listed.stdout)["count"], 2)

            dashboard = run_cli("dashboard", "--workspace", str(workspace))
            self.assertEqual(dashboard.returncode, 0, dashboard.stderr)
            dashboard_payload = json.loads(dashboard.stdout)
            dashboard_dir = Path(dashboard_payload["dashboard_dir"])
            self.assertTrue((dashboard_dir / "index.html").is_file())
            self.assertIn("source_reconstruction", dashboard_payload)
            data = json.loads((dashboard_dir / "data.json").read_text(encoding="utf-8"))
            self.assertEqual(data["summary"]["experiment_total"], 2)
            self.assertGreaterEqual(data["summary"]["session_total"], 1)

    def test_experiment_and_dashboard_help_expose_all_operations(self) -> None:
        top_level_help = run_cli("--help")
        self.assertEqual(top_level_help.returncode, 0, top_level_help.stderr)
        self.assertIn("experiment", top_level_help.stdout)
        self.assertIn("dashboard", top_level_help.stdout)

        experiment_help = run_cli("experiment", "--help")
        self.assertEqual(experiment_help.returncode, 0, experiment_help.stderr)
        for command in ("create", "list", "show", "plan", "run"):
            self.assertIn(command, experiment_help.stdout)
            command_help = run_cli("experiment", command, "--help")
            self.assertEqual(command_help.returncode, 0, command_help.stderr)

        dashboard_help = run_cli("dashboard", "--help")
        self.assertEqual(dashboard_help.returncode, 0, dashboard_help.stderr)
        self.assertIn("--serve", dashboard_help.stdout)

    def test_invalid_experiment_show_and_timeout_are_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            sample = workspace / "fixture.exe"
            sample.write_text("MZ", encoding="utf-8")
            created = run_cli("experiment", "create", str(sample), "--workspace", str(workspace))
            self.assertEqual(created.returncode, 0, created.stderr)
            experiment_id = json.loads(created.stdout)["experiment"]["id"]

            invalid_show = run_cli("experiment", "show", "../not-an-experiment", "--workspace", str(workspace))
            self.assertEqual(invalid_show.returncode, 2)
            self.assertIn("Experiment not available", invalid_show.stderr)

            invalid_timeout = run_cli(
                "experiment",
                "run",
                experiment_id,
                "--workspace",
                str(workspace),
                "--execute-local",
                "--timeout",
                "-1",
            )
            self.assertEqual(invalid_timeout.returncode, 2)
            self.assertIn("timeout must be positive", invalid_timeout.stderr)

            shown = run_cli("experiment", "show", experiment_id, "--workspace", str(workspace))
            self.assertEqual(json.loads(shown.stdout)["experiment"]["status"], "queued")

    def test_local_runner_environment_isolated_from_parent_location_overrides(self) -> None:
        workspace = Path("C:/analysis/workspace")
        with patch.dict(
            os.environ,
            {
                "REVERSE_ANALYZER_KNOWLEDGE_DIR": "C:/parent/knowledge",
                "REVERSE_ANALYZER_SESSIONS_DIR": "C:/parent/sessions",
                "REVERSE_ANALYZER_REPORTS_DIR": "C:/parent/reports",
                "REVERSE_ANALYZER_WORKSPACE": "C:/parent/workspace",
            },
            clear=False,
        ):
            environment = _local_runner_environment(workspace)

        self.assertEqual(environment["REVERSE_ANALYZER_WORKSPACE"], str(workspace))
        self.assertNotIn("REVERSE_ANALYZER_KNOWLEDGE_DIR", environment)
        self.assertNotIn("REVERSE_ANALYZER_SESSIONS_DIR", environment)
        self.assertNotIn("REVERSE_ANALYZER_REPORTS_DIR", environment)


if __name__ == "__main__":
    unittest.main()
