"""Unit tests for check_durability_violation.py verification script."""

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
from pathlib import Path
from unittest import TestCase, main

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_durability_violation.py"

spec = importlib.util.spec_from_file_location("check_durability_violation", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestFileChecks(TestCase):
    def test_impl_file_exists(self):
        result = mod.check_file(mod.IMPL, "implementation")
        self.assertTrue(result["pass"], f"Implementation file missing: {result['detail']}")

    def test_spec_file_exists(self):
        result = mod.check_file(mod.SPEC, "spec contract")
        self.assertTrue(result["pass"], f"Spec file missing: {result['detail']}")

    def test_missing_file_fails(self):
        result = mod.check_file(Path("/nonexistent/file.rs"), "fake")
        self.assertFalse(result["pass"])

    def test_module_registered(self):
        result = mod.check_module_registered()
        self.assertTrue(result["pass"], f"Module not registered: {result['detail']}")


class TestContentChecks(TestCase):
    def test_required_types_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TYPES, "type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing type: {r['check']}")

    def test_required_methods_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_METHODS, "method")
        for r in results:
            self.assertTrue(r["pass"], f"Missing method: {r['check']}")

    def test_event_codes_found(self):
        results = mod.check_content(mod.IMPL, mod.EVENT_CODES, "event_code")
        for r in results:
            self.assertTrue(r["pass"], f"Missing event code: {r['check']}")

    def test_invariants_found(self):
        results = mod.check_content(mod.IMPL, mod.INVARIANTS, "invariant")
        for r in results:
            self.assertTrue(r["pass"], f"Missing invariant: {r['check']}")

    def test_causal_event_types_found(self):
        results = mod.check_content(mod.IMPL, mod.CAUSAL_EVENT_TYPES, "causal_event_type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing causal event type: {r['check']}")

    def test_halt_policies_found(self):
        results = mod.check_content(mod.IMPL, mod.HALT_POLICIES, "halt_policy")
        for r in results:
            self.assertTrue(r["pass"], f"Missing halt policy: {r['check']}")

    def test_error_types_found(self):
        results = mod.check_content(mod.IMPL, mod.ERROR_CODES, "error_type")
        for r in results:
            self.assertTrue(r["pass"], f"Missing error type: {r['check']}")

    def test_required_tests_found(self):
        results = mod.check_content(mod.IMPL, mod.REQUIRED_TESTS, "test")
        for r in results:
            self.assertTrue(r["pass"], f"Missing test: {r['check']}")


class TestTestCount(TestCase):
    def test_minimum_test_count(self):
        result = mod.check_test_count()
        self.assertTrue(result["pass"], f"Insufficient tests: {result['detail']}")

    def test_at_least_25_tests(self):
        result = mod.check_test_count()
        # Extract count from detail string
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 25)


class TestMissingFileContent(TestCase):
    def test_content_check_on_missing_file(self):
        results = mod.check_content(Path("/nonexistent"), ["foo"], "cat")
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["pass"])
        self.assertEqual(results[0]["detail"], "file missing")


class TestRunChecks(TestCase):
    def test_overall_pass(self):
        result = mod.run_checks()
        self.assertTrue(result["overall_pass"], f"Overall check failed: {result['summary']}")
        self.assertEqual(result["verdict"], "PASS")

    def test_bead_id(self):
        result = mod.run_checks()
        self.assertEqual(result["bead_id"], "bd-b9b6")

    def test_section(self):
        result = mod.run_checks()
        self.assertEqual(result["section"], "10.14")

    def test_test_count_in_result(self):
        result = mod.run_checks()
        self.assertGreaterEqual(result["test_count"], 25)

    def test_json_output_valid(self):
        result = mod.run_checks()
        # Ensure it's JSON-serializable
        json_str = json.dumps(result)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["bead_id"], "bd-b9b6")


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        ok, checks = mod.self_test()
        self.assertTrue(ok, "self_test should pass")

    def test_self_test_returns_checks(self):
        ok, checks = mod.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestCheckSummary(TestCase):
    def test_no_failing_checks(self):
        result = mod.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(len(failing), 0, f"Failing checks: {failing}")

    def test_summary_counts_match(self):
        result = mod.run_checks()
        s = result["summary"]
        self.assertEqual(s["passing"] + s["failing"], s["total"])
        self.assertEqual(s["failing"], 0)


if __name__ == "__main__":
    main()
