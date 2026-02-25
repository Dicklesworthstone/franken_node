#!/usr/bin/env python3
"""Unit tests for check_profile_tuning_harness.py verification script."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_profile_tuning_harness as checker


class TestCheckFileHelper(unittest.TestCase):
    def test_file_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertTrue(result["pass"])

    def test_file_missing(self):
        result = checker.check_file(Path("/nonexistent/file.rs"), "missing")
        self.assertFalse(result["pass"])

    def test_detail_on_exists(self):
        result = checker.check_file(checker.IMPL, "implementation")
        self.assertIn("exists:", result["detail"])

    def test_detail_on_missing(self):
        result = checker.check_file(Path("/nonexistent/file.rs"), "missing")
        self.assertIn("MISSING", result["detail"])


class TestCheckContentHelper(unittest.TestCase):
    def test_found(self):
        results = checker.check_content(checker.IMPL, ["pub struct BenchmarkResult"], "type")
        self.assertTrue(results[0]["pass"])

    def test_not_found(self):
        results = checker.check_content(checker.IMPL, ["NONEXISTENT_PATTERN_XYZ"], "type")
        self.assertFalse(results[0]["pass"])

    def test_missing_file(self):
        results = checker.check_content(Path("/nonexistent"), ["pattern"], "cat")
        self.assertFalse(results[0]["pass"])
        self.assertEqual(results[0]["detail"], "file missing")

    def test_multiple_patterns(self):
        results = checker.check_content(
            checker.IMPL,
            ["pub struct BenchmarkResult", "pub struct BaselineRow"],
            "type",
        )
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["pass"] for r in results))


class TestCheckModuleRegistered(unittest.TestCase):
    def test_registered(self):
        result = checker.check_module_registered()
        self.assertTrue(result["pass"])


class TestCheckTestCount(unittest.TestCase):
    def test_minimum_35(self):
        result = checker.check_test_count()
        self.assertTrue(result["pass"])
        count = int(result["detail"].split()[0])
        self.assertGreaterEqual(count, 35)

    def test_real_impl(self):
        result = checker.check_test_count()
        self.assertTrue(result["pass"])


class TestCheckSerdeDerive(unittest.TestCase):
    def test_serde(self):
        result = checker.check_serde_derives()
        self.assertTrue(result["pass"])


class TestCheckSignedBundle(unittest.TestCase):
    def test_bundle_checks(self):
        results = checker.check_signed_bundle()
        for r in results:
            self.assertTrue(r["pass"], f"Failed: {r['check']}: {r['detail']}")

    def test_bundle_has_version(self):
        results = checker.check_signed_bundle()
        version_check = [r for r in results if "version" in r["check"]]
        self.assertTrue(len(version_check) > 0)
        self.assertTrue(version_check[0]["pass"])

    def test_bundle_has_signature(self):
        results = checker.check_signed_bundle()
        sig_check = [r for r in results if "signature" in r["check"]]
        self.assertTrue(len(sig_check) > 0)
        self.assertTrue(sig_check[0]["pass"])

    def test_bundle_has_candidates(self):
        results = checker.check_signed_bundle()
        cand_check = [r for r in results if "candidates" in r["check"]]
        self.assertTrue(len(cand_check) > 0)
        self.assertTrue(cand_check[0]["pass"])


class TestCheckBaselineCsv(unittest.TestCase):
    def test_baseline_exists(self):
        result = checker.check_baseline_csv()
        self.assertTrue(result["pass"])


class TestRunChecks(unittest.TestCase):
    def test_full_run(self):
        result = checker.run_checks()
        self.assertIn("checks", result)
        self.assertIn("summary", result)

    def test_all_checks_pass(self):
        result = checker.run_checks()
        failing = [c for c in result["checks"] if not c["pass"]]
        self.assertEqual(
            len(failing), 0,
            f"Failing checks: {json.dumps(failing, indent=2)}",
        )

    def test_verdict_is_pass(self):
        result = checker.run_checks()
        self.assertEqual(result["verdict"], "PASS")

    def test_title_field(self):
        result = checker.run_checks()
        self.assertIn("Profile tuning harness", result["title"])

    def test_test_count_field(self):
        result = checker.run_checks()
        count = int(result["test_count"])
        self.assertGreaterEqual(count, 35)

    def test_check_count_reasonable(self):
        result = checker.run_checks()
        self.assertGreaterEqual(result["summary"]["total"], 80)


class TestSelfTest(unittest.TestCase):
    def test_self_test_passes(self):
        ok, checks = checker.self_test()
        self.assertTrue(ok)

    def test_self_test_returns_checks(self):
        ok, checks = checker.self_test()
        self.assertIsInstance(checks, list)
        self.assertGreater(len(checks), 0)


class TestRequiredConstants(unittest.TestCase):
    def test_types_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TYPES), 10)

    def test_methods_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_METHODS), 14)

    def test_event_codes_count(self):
        self.assertEqual(len(checker.EVENT_CODES), 6)

    def test_invariants_count(self):
        self.assertEqual(len(checker.INVARIANTS), 4)

    def test_required_tests_count(self):
        self.assertGreaterEqual(len(checker.REQUIRED_TESTS), 40)


class TestJsonOutput(unittest.TestCase):
    def test_json_serializable(self):
        result = checker.run_checks()
        json_str = json.dumps(result)
        self.assertIsInstance(json_str, str)

    def test_cli_json(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_profile_tuning_harness.py"), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["verdict"], "PASS")

    def test_cli_human(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_profile_tuning_harness.py")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PASS", proc.stdout)


if __name__ == "__main__":
    unittest.main()
