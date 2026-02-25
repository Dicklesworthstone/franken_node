#!/usr/bin/env python3
"""Unit tests for the bd-tyr2 evidence replay gate verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_evidence_replay_gate as checker


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


class TestSpecContent:
    def test_all_spec_content_present(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_SPEC_CONTENT)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_twelve_spec_items(self):
        result = checker.check_content("spec", checker.SPEC_PATH, checker.REQUIRED_SPEC_CONTENT)
        assert len(result["found"]) == 12


class TestRustSymbols:
    def test_all_symbols_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_eight_symbols(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert len(result["found"]) == 8


class TestEventCodes:
    def test_all_event_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_five_event_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert len(result["found"]) == 5


class TestDecisionTypes:
    def test_all_decision_types_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_DECISION_TYPES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_four_decision_types(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_DECISION_TYPES)
        assert len(result["found"]) == 4


class TestGateMethods:
    def test_all_methods_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_GATE_METHODS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_nine_methods(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_GATE_METHODS)
        assert len(result["found"]) == 9


class TestInlineTests:
    def test_all_tests_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_fourteen_tests(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert len(result["found"]) == 14


class TestModRegistration:
    def test_module_registered(self):
        result = checker.check_mod_registration()
        assert result["pass"] is True


class TestHashIntegrity:
    def test_hash_integrity_pass(self):
        result = checker.check_hash_integrity()
        assert result["pass"] is True

    def test_sha256_present(self):
        result = checker.check_hash_integrity()
        assert result["sha256"] is True


class TestVerdictTypes:
    def test_verdict_types_pass(self):
        result = checker.check_verdict_types()
        assert result["pass"] is True

    def test_diff_details_present(self):
        result = checker.check_verdict_types()
        assert result["diff_details"] is True


class TestFullEvidence:
    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_bead_id(self):
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-tyr2"

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 10
        assert evidence["summary"]["passed"] == 10

    def test_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-tyr2"
