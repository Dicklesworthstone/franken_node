#!/usr/bin/env python3
"""Unit tests for the bd-sh3 policy approval workflow verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_policy_approval as checker  # noqa: E402


class TestSelfTest(TestCase):
    def test_self_test_passes(self):
        self.assertTrue(checker.self_test())


class TestFileChecks(TestCase):
    def test_spec_file_exists(self):
        result = checker.check_file_exists(checker.SPEC_PATH)
        self.assertTrue(result["exists"])
        self.assertGreater(result["size_bytes"], 0)

    def test_rust_impl_exists(self):
        result = checker.check_file_exists(checker.RUST_IMPL_PATH)
        self.assertTrue(result["exists"])
        self.assertGreater(result["size_bytes"], 0)

    def test_mod_rs_exists(self):
        result = checker.check_file_exists(checker.MOD_PATH)
        self.assertTrue(result["exists"])


class TestSpecInvariants(TestCase):
    def test_all_invariants_present(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_INVARIANTS)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_existing_unreadable_input_fails_closed(self):
        with TemporaryDirectory() as temp_dir:
            result = checker.check_content("spec", Path(temp_dir), ["INV-POL-MULTI-PARTY"])

        self.assertFalse(result["pass"])
        self.assertEqual(result["found"], [])
        self.assertEqual(result["missing"], ["INV-POL-MULTI-PARTY"])
        self.assertIn("unable to read", result["reason"])

    def test_eight_invariants(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_INVARIANTS)
        self.assertEqual(len(result["found"]), 8)


class TestRustSymbols(TestCase):
    def test_all_symbols_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_ten_symbols(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        self.assertEqual(len(result["found"]), 10)


class TestEventCodes(TestCase):
    def test_all_event_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_eight_event_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        self.assertEqual(len(result["found"]), 8)


class TestErrorCodes(TestCase):
    def test_all_error_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_seven_error_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        self.assertEqual(len(result["found"]), 7)


class TestEngineMethods(TestCase):
    def test_all_methods_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ENGINE_METHODS)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_nine_methods(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ENGINE_METHODS)
        self.assertEqual(len(result["found"]), 9)


class TestInlineTests(TestCase):
    def test_all_tests_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_twenty_tests(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        self.assertEqual(len(result["found"]), 20)


class TestStates(TestCase):
    def test_all_states_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_STATES)
        self.assertTrue(result["pass"], f"Missing: {result['missing']}")

    def test_six_states(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_STATES)
        self.assertEqual(len(result["found"]), 6)


class TestModRegistration(TestCase):
    def test_module_registered(self):
        result = checker.check_mod_registration()
        self.assertTrue(result["pass"])


class TestHashChain(TestCase):
    def test_hash_chain_pass(self):
        result = checker.check_hash_chain()
        self.assertTrue(result["pass"])

    def test_sha256_present(self):
        result = checker.check_hash_chain()
        self.assertTrue(result["sha256"])


class TestRoleSeparation(TestCase):
    def test_role_separation_pass(self):
        result = checker.check_role_separation()
        self.assertTrue(result["pass"])

    def test_sole_approver_check(self):
        result = checker.check_role_separation()
        self.assertTrue(result["sole_approver_check"])

    def test_non_proposer_counting(self):
        result = checker.check_role_separation()
        self.assertTrue(result["non_proposer_counting"])


class TestRollbackMechanism(TestCase):
    def test_rollback_pass(self):
        result = checker.check_rollback_mechanism()
        self.assertTrue(result["pass"])

    def test_inverse_diff(self):
        result = checker.check_rollback_mechanism()
        self.assertTrue(result["inverse_diff"])


class TestFullEvidence(TestCase):
    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        self.assertTrue(evidence["overall_pass"])

    def test_bead_id(self):
        evidence = checker.run_all_checks()
        self.assertEqual(evidence["bead_id"], "bd-sh3")

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        self.assertEqual(evidence["summary"]["total_checks"], 12)
        self.assertEqual(evidence["summary"]["passed"], 12)

    def test_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        roundtrip = json.JSONDecoder().decode(serialized)
        self.assertEqual(roundtrip["bead_id"], "bd-sh3")


if __name__ == "__main__":
    main()
