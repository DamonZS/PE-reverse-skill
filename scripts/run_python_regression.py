"""Run Python regression tests with explicit host dependency gates."""

from __future__ import annotations

import json
import os
import sys
import unittest


WINDOWS_UIA_TEST_ID = (
    "tests.test_acceptance_records.AcceptanceRecordTests."
    "test_windows_uia_fixture_contract_retains_hash_backed_live_proof"
)


def dependency_gated_test_ids() -> set[str]:
    if os.name == "nt":
        return set()
    return {WINDOWS_UIA_TEST_ID}


def test_id(record: tuple[unittest.TestCase, str]) -> str:
    case = record[0]
    try:
        return case.id()
    except Exception:
        return type(case).__name__


def main() -> int:
    suite = unittest.defaultTestLoader.discover("tests", top_level_dir=".")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    dependency_ids = dependency_gated_test_ids()

    gated_failures = [item for item in result.failures if test_id(item) in dependency_ids]
    gated_errors = [item for item in result.errors if test_id(item) in dependency_ids]
    blocking_failures = [item for item in result.failures if test_id(item) not in dependency_ids]
    blocking_errors = [item for item in result.errors if test_id(item) not in dependency_ids]
    successful = not blocking_failures and not blocking_errors and not result.unexpectedSuccesses

    summary = {
        "status": "passed" if successful else "failed",
        "tests_run": result.testsRun,
        "failures": len(blocking_failures),
        "errors": len(blocking_errors),
        "dependency_gated": len(gated_failures) + len(gated_errors),
        "dependency_gated_test_ids": [
            test_id(item) for item in gated_failures + gated_errors
        ],
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "failing_test_ids": [
            test_id(item) for item in blocking_failures + blocking_errors
        ][:100],
    }
    print("SAFE_SUMMARY:" + json.dumps(summary, separators=(",", ":"), sort_keys=True))
    return 0 if successful else 1


if __name__ == "__main__":
    sys.exit(main())
