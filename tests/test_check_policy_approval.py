#!/usr/bin/env python3
"""Unit tests for the bd-sh3 policy approval workflow verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_policy_approval as checker


class TestSelfTest:
    def test_self_test_passes(self):
        assert checker.self_test() is True


class TestFileChecks:
    def test_spec_file_exists(self):
        result = checker.check_file_exists(checker.SPEC_PATH)
        assert result["exists"] is True
        assert result["size_bytes"] > 0

    def test_rust_impl_exists(self):
        result = checker.check_file_exists(checker.RUST_IMPL_PATH)
        assert result["exists"] is True
        assert result["size_bytes"] > 0

    def test_mod_rs_exists(self):
        result = checker.check_file_exists(checker.MOD_PATH)
        assert result["exists"] is True


class TestSpecInvariants:
    def test_all_invariants_present(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_INVARIANTS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_eight_invariants(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_INVARIANTS)
        assert len(result["found"]) == 8


class TestRustSymbols:
    def test_all_symbols_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_ten_symbols(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert len(result["found"]) == 10


class TestEventCodes:
    def test_all_event_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_eight_event_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert len(result["found"]) == 8


class TestErrorCodes:
    def test_all_error_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_seven_error_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        assert len(result["found"]) == 7


class TestEngineMethods:
    def test_all_methods_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ENGINE_METHODS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_nine_methods(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ENGINE_METHODS)
        assert len(result["found"]) == 9


class TestInlineTests:
    def test_all_tests_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_twenty_tests(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert len(result["found"]) == 20


class TestStates:
    def test_all_states_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_STATES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_six_states(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_STATES)
        assert len(result["found"]) == 6


class TestModRegistration:
    def test_module_registered(self):
        result = checker.check_mod_registration()
        assert result["pass"] is True


class TestHashChain:
    def test_hash_chain_pass(self):
        result = checker.check_hash_chain()
        assert result["pass"] is True

    def test_sha256_present(self):
        result = checker.check_hash_chain()
        assert result["sha256"] is True


class TestRoleSeparation:
    def test_role_separation_pass(self):
        result = checker.check_role_separation()
        assert result["pass"] is True

    def test_sole_approver_check(self):
        result = checker.check_role_separation()
        assert result["sole_approver_check"] is True

    def test_non_proposer_counting(self):
        result = checker.check_role_separation()
        assert result["non_proposer_counting"] is True


class TestRollbackMechanism:
    def test_rollback_pass(self):
        result = checker.check_rollback_mechanism()
        assert result["pass"] is True

    def test_inverse_diff(self):
        result = checker.check_rollback_mechanism()
        assert result["inverse_diff"] is True


class TestFullEvidence:
    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_bead_id(self):
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-sh3"

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 12
        assert evidence["summary"]["passed"] == 12

    def test_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-sh3"
