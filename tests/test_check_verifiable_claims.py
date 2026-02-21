#!/usr/bin/env python3
"""Unit tests for scripts/check_verifiable_claims.py"""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import check_verifiable_claims as checker


class TestSelfTest(unittest.TestCase):
    def test_self_test(self):
        checker.self_test()


class TestFilesExist(unittest.TestCase):
    def test_two_files(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        checks = [r for r in checker.RESULTS if r["name"].startswith("file_exists:")]
        self.assertEqual(len(checks), 2)

    def test_spec_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        spec_check = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
        self.assertTrue(spec_check["pass"])

    def test_policy_exists(self):
        checker.RESULTS.clear()
        checker.check_files_exist()
        policy_check = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
        self.assertTrue(policy_check["pass"])


class TestVerifiabilityDimensions(unittest.TestCase):
    def test_five_dimensions(self):
        checker.RESULTS.clear()
        checker.check_verifiability_dimensions()
        checks = [r for r in checker.RESULTS if r["name"].startswith("dimension:")]
        self.assertEqual(len(checks), 5)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_verifiability_dimensions()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestQuantitativeTargets(unittest.TestCase):
    def test_four_targets(self):
        checker.RESULTS.clear()
        checker.check_quantitative_targets()
        checks = [r for r in checker.RESULTS if r["name"].startswith("target:")]
        self.assertEqual(len(checks), 4)


class TestEventCodes(unittest.TestCase):
    def test_four_codes(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        checks = [r for r in checker.RESULTS if r["name"].startswith("event_code:")]
        self.assertEqual(len(checks), 4)

    def test_all_pass(self):
        checker.RESULTS.clear()
        checker.check_event_codes()
        for r in checker.RESULTS:
            self.assertTrue(r["pass"], r["name"])


class TestInvariants(unittest.TestCase):
    def test_four_invariants(self):
        checker.RESULTS.clear()
        checker.check_invariants()
        checks = [r for r in checker.RESULTS if r["name"].startswith("invariant:")]
        self.assertEqual(len(checks), 4)


class TestBundleFormat(unittest.TestCase):
    def test_four_keywords(self):
        checker.RESULTS.clear()
        checker.check_evidence_bundle_format()
        checks = [r for r in checker.RESULTS if r["name"].startswith("bundle:")]
        self.assertEqual(len(checks), 4)


class TestReproductionProtocol(unittest.TestCase):
    def test_five_keywords(self):
        checker.RESULTS.clear()
        checker.check_reproduction_protocol()
        checks = [r for r in checker.RESULTS if r["name"].startswith("reproduction:")]
        self.assertEqual(len(checks), 5)


class TestAdversarialResilience(unittest.TestCase):
    def test_four_perturbations(self):
        checker.RESULTS.clear()
        checker.check_adversarial_resilience()
        checks = [r for r in checker.RESULTS if r["name"].startswith("adversarial:")]
        self.assertEqual(len(checks), 4)


class TestCIIntegration(unittest.TestCase):
    def test_three_keywords(self):
        checker.RESULTS.clear()
        checker.check_ci_integration()
        checks = [r for r in checker.RESULTS if r["name"].startswith("ci:")]
        self.assertEqual(len(checks), 3)


class TestClaimCategories(unittest.TestCase):
    def test_five_categories(self):
        checker.RESULTS.clear()
        checker.check_claim_categories()
        checks = [r for r in checker.RESULTS if r["name"].startswith("category:")]
        self.assertEqual(len(checks), 5)


class TestAcceptanceCriteria(unittest.TestCase):
    def test_four_keywords(self):
        checker.RESULTS.clear()
        checker.check_spec_acceptance_criteria()
        checks = [r for r in checker.RESULTS if r["name"].startswith("acceptance:")]
        self.assertEqual(len(checks), 4)


class TestRunAll(unittest.TestCase):
    def test_returns_dict(self):
        result = checker.run_all()
        self.assertIsInstance(result, dict)

    def test_bead_id(self):
        result = checker.run_all()
        self.assertEqual(result["bead_id"], "bd-2a4l")

    def test_math(self):
        result = checker.run_all()
        self.assertEqual(result["total"], result["passed"] + result["failed"])

    def test_verdict_pass(self):
        result = checker.run_all()
        self.assertEqual(result["verdict"], "PASS")

    def test_check_count(self):
        result = checker.run_all()
        self.assertGreaterEqual(result["total"], 40)


class TestMissingFiles(unittest.TestCase):
    def test_spec_missing(self):
        with patch.object(checker, "SPEC_PATH", Path("/nonexistent/spec.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            spec_check = [r for r in checker.RESULTS if r["name"] == "file_exists:spec"][0]
            self.assertFalse(spec_check["pass"])

    def test_policy_missing(self):
        with patch.object(checker, "POLICY_PATH", Path("/nonexistent/policy.md")):
            checker.RESULTS.clear()
            checker.check_files_exist()
            policy_check = [r for r in checker.RESULTS if r["name"] == "file_exists:policy"][0]
            self.assertFalse(policy_check["pass"])


class TestJsonOutput(unittest.TestCase):
    def test_json_flag(self):
        result = subprocess.run(
            [sys.executable, "scripts/check_verifiable_claims.py", "--json"],
            capture_output=True, text=True, cwd=str(checker.ROOT),
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["bead_id"], "bd-2a4l")


class TestSafeRel(unittest.TestCase):
    def test_relative_path(self):
        p = checker.ROOT / "foo" / "bar.md"
        self.assertEqual(checker._safe_rel(p), "foo/bar.md")

    def test_nonrelative_path(self):
        p = Path("/nonexistent/foo.md")
        self.assertEqual(checker._safe_rel(p), "/nonexistent/foo.md")


if __name__ == "__main__":
    unittest.main()
