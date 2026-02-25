#!/usr/bin/env python3
"""Unit tests for the bd-1vm quarantine/recall workflow verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_quarantine_workflow as checker


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

    def test_fourteen_symbols(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert len(result["found"]) == 14


class TestEventCodes:
    def test_all_event_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_ten_event_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert len(result["found"]) == 10


class TestErrorCodes:
    def test_all_error_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_five_error_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ERROR_CODES)
        assert len(result["found"]) == 5


class TestRegistryMethods:
    def test_all_methods_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_REGISTRY_METHODS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_seventeen_methods(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_REGISTRY_METHODS)
        assert len(result["found"]) == 17


class TestInlineTests:
    def test_all_tests_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_twenty_tests(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert len(result["found"]) == 20


class TestQuarantineReasons:
    def test_all_reasons_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_QUARANTINE_REASONS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_seven_reasons(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_QUARANTINE_REASONS)
        assert len(result["found"]) == 7


class TestModRegistration:
    def test_module_registered(self):
        result = checker.check_mod_registration()
        assert result["pass"] is True


class TestStateMachine:
    def test_all_states_present(self):
        result = checker.check_state_machine()
        assert result["pass"] is True, f"Missing: {result.get('missing', [])}"

    def test_eight_states(self):
        result = checker.check_state_machine()
        assert result["total_states"] == 8


class TestHashChain:
    def test_hash_chain_pass(self):
        result = checker.check_hash_chain()
        assert result["pass"] is True

    def test_sha256_present(self):
        result = checker.check_hash_chain()
        assert result["sha256"] is True


class TestFastPath:
    def test_fast_path_pass(self):
        result = checker.check_fast_path()
        assert result["pass"] is True

    def test_critical_severity_check(self):
        result = checker.check_fast_path()
        assert result["critical_severity_check"] is True


class TestFullEvidence:
    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_bead_id(self):
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-1vm"

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 12
        assert evidence["summary"]["passed"] == 12

    def test_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-1vm"
