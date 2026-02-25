#!/usr/bin/env python3
"""Unit tests for the bd-phf ecosystem telemetry verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path


SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_ecosystem_telemetry as checker


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

    def test_sixteen_symbols(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_RUST_SYMBOLS)
        assert len(result["found"]) == 16


class TestEventCodes:
    def test_all_event_codes_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_six_event_codes(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_EVENT_CODES)
        assert len(result["found"]) == 6


class TestTrustMetrics:
    def test_all_trust_metrics_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TRUST_METRICS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_five_trust_metrics(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TRUST_METRICS)
        assert len(result["found"]) == 5


class TestAdoptionMetrics:
    def test_all_adoption_metrics_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ADOPTION_METRICS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_five_adoption_metrics(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ADOPTION_METRICS)
        assert len(result["found"]) == 5


class TestAnomalyTypes:
    def test_all_anomaly_types_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ANOMALY_TYPES)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_five_anomaly_types(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_ANOMALY_TYPES)
        assert len(result["found"]) == 5


class TestPipelineMethods:
    def test_all_methods_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_PIPELINE_METHODS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_twelve_methods(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_PIPELINE_METHODS)
        assert len(result["found"]) == 12


class TestInlineTests:
    def test_all_tests_present(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert result["pass"] is True, f"Missing: {result['missing']}"

    def test_thirteen_tests(self):
        result = checker.check_content("rust", checker.RUST_IMPL_PATH, checker.REQUIRED_TESTS)
        assert len(result["found"]) == 13


class TestModRegistration:
    def test_module_registered(self):
        result = checker.check_mod_registration()
        assert result["pass"] is True


class TestPrivacyGovernance:
    def test_privacy_governance_checks_pass(self):
        result = checker.check_privacy_governance()
        assert result["pass"] is True

    def test_opt_in_default(self):
        result = checker.check_privacy_governance()
        assert result["opt_in_default"] is True

    def test_k_anonymity(self):
        result = checker.check_privacy_governance()
        assert result["k_anonymity"] is True


class TestAnomalyDetection:
    def test_anomaly_detection_pass(self):
        result = checker.check_anomaly_detection()
        assert result["pass"] is True

    def test_deviation_threshold(self):
        result = checker.check_anomaly_detection()
        assert result["deviation_threshold"] is True


class TestResourceBudget:
    def test_resource_budget_pass(self):
        result = checker.check_resource_budget()
        assert result["pass"] is True

    def test_eviction_logic(self):
        result = checker.check_resource_budget()
        assert result["eviction_logic"] is True


class TestFullEvidence:
    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_bead_id(self):
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-phf"

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 13
        assert evidence["summary"]["passed"] == 13

    def test_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-phf"
