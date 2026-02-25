#!/usr/bin/env python3
"""Unit tests for the bd-ml1 publisher reputation verification script."""

from __future__ import annotations

import json
import sys
from pathlib import Path


# Add scripts directory to path.
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_publisher_reputation as checker


class TestSelfTest:
    """Verify the self_test function works."""

    def test_self_test_passes(self):
        assert checker.self_test() is True


class TestFileChecks:
    """Verify file existence checks."""

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
    """Verify spec contains all required invariants."""

    def test_all_invariants_present(self):
        result = checker.check_spec_invariants()
        assert result["pass"] is True, f"Missing invariants: {result['missing']}"

    def test_no_missing_invariants(self):
        result = checker.check_spec_invariants()
        assert len(result["missing"]) == 0

    def test_all_eight_invariants_found(self):
        result = checker.check_spec_invariants()
        assert len(result["found"]) == 8


class TestRustSymbols:
    """Verify all required Rust symbols exist."""

    def test_all_symbols_present(self):
        result = checker.check_rust_symbols()
        assert result["pass"] is True, f"Missing symbols: {result['missing']}"

    def test_no_missing_symbols(self):
        result = checker.check_rust_symbols()
        assert len(result["missing"]) == 0

    def test_all_twelve_symbols_found(self):
        result = checker.check_rust_symbols()
        assert len(result["found"]) == 12


class TestEventCodes:
    """Verify all event codes are defined."""

    def test_all_event_codes_present(self):
        result = checker.check_event_codes()
        assert result["pass"] is True, f"Missing events: {result['missing']}"

    def test_eight_event_codes(self):
        result = checker.check_event_codes()
        assert len(result["found"]) == 8


class TestTiers:
    """Verify all reputation tiers are implemented."""

    def test_all_tiers_present(self):
        result = checker.check_tiers()
        assert result["pass"] is True, f"Missing tiers: {result['missing']}"

    def test_five_tiers(self):
        result = checker.check_tiers()
        assert len(result["found"]) == 5


class TestSignalKinds:
    """Verify all signal kinds are implemented."""

    def test_all_signal_kinds_present(self):
        result = checker.check_signal_kinds()
        assert result["pass"] is True, f"Missing kinds: {result['missing']}"

    def test_nine_signal_kinds(self):
        result = checker.check_signal_kinds()
        assert len(result["found"]) == 9


class TestRegistryMethods:
    """Verify all registry methods exist."""

    def test_all_methods_present(self):
        result = checker.check_registry_methods()
        assert result["pass"] is True, f"Missing methods: {result['missing']}"

    def test_thirteen_methods(self):
        result = checker.check_registry_methods()
        assert len(result["found"]) == 13


class TestInlineTests:
    """Verify all required inline tests exist."""

    def test_all_tests_present(self):
        result = checker.check_tests()
        assert result["pass"] is True, f"Missing tests: {result['missing']}"

    def test_eighteen_tests(self):
        result = checker.check_tests()
        assert len(result["found"]) == 18


class TestModRegistration:
    """Verify module is registered in mod.rs."""

    def test_module_registered(self):
        result = checker.check_mod_registration()
        assert result["pass"] is True
        assert result["registered"] is True


class TestDeterminism:
    """Verify deterministic scoring patterns."""

    def test_determinism_checks_pass(self):
        result = checker.check_determinism()
        assert result["pass"] is True
        assert result["deterministic_fn"] is True
        assert result["score_clamped"] is True
        assert result["ordered_collections"] is True


class TestHashChain:
    """Verify hash-chain audit trail implementation."""

    def test_hash_chain_checks_pass(self):
        result = checker.check_hash_chain()
        assert result["pass"] is True
        assert result["prev_hash_field"] is True
        assert result["entry_hash_field"] is True
        assert result["sha256_hashing"] is True
        assert result["integrity_verification"] is True


class TestFreezeSemantics:
    """Verify freeze/unfreeze semantics."""

    def test_freeze_checks_pass(self):
        result = checker.check_freeze_semantics()
        assert result["pass"] is True
        assert result["freeze_method"] is True
        assert result["unfreeze_method"] is True
        assert result["frozen_state_field"] is True
        assert result["suspended_tier"] is True
        assert result["frozen_signal_rejection"] is True


class TestFullEvidence:
    """Verify the full evidence generation pipeline."""

    def test_run_all_checks_returns_valid_evidence(self):
        evidence = checker.run_all_checks()
        assert evidence["bead_id"] == "bd-ml1"
        assert evidence["section"] == "10.4"
        assert "timestamp" in evidence
        assert "checks" in evidence
        assert "summary" in evidence

    def test_overall_pass(self):
        evidence = checker.run_all_checks()
        assert evidence["overall_pass"] is True

    def test_summary_counts(self):
        evidence = checker.run_all_checks()
        assert evidence["summary"]["total_checks"] == 12
        assert evidence["summary"]["passed"] == 12
        assert evidence["summary"]["failed"] == 0

    def test_evidence_is_json_serializable(self):
        evidence = checker.run_all_checks()
        serialized = json.dumps(evidence)
        assert len(serialized) > 0
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-ml1"
