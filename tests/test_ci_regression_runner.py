import unittest
from unittest import mock

from scripts import run_python_regression


class PythonRegressionRunnerTests(unittest.TestCase):
    def test_windows_uia_is_dependency_gated_on_every_non_windows_host(self):
        with mock.patch.object(run_python_regression.os, "name", "posix"):
            self.assertEqual(
                run_python_regression.dependency_gated_test_ids(),
                {run_python_regression.WINDOWS_UIA_TEST_ID},
            )

    def test_windows_host_runs_windows_uia_test_as_blocking(self):
        with mock.patch.object(run_python_regression.os, "name", "nt"):
            self.assertEqual(run_python_regression.dependency_gated_test_ids(), set())


if __name__ == "__main__":
    unittest.main()
