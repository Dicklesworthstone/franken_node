#!/usr/bin/env python3
"""Unit tests for the bd-3q9 rollback bundles verification script.

Covers: file existence, content checks, spec/policy coverage, module registration,
test counts, serde derives, SHA-256 usage, idempotency, dry-run, deterministic
restore, health checks, event codes, invariants, error codes, self-test, and
full evidence structure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import check_rollback_bundles as checker


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


class TestSelfTest:
    def test_self_test_passes(self):
        assert checker.self_test() is True

    def test_self_test_report_shape(self):
        report = checker.run_all()
        assert "bead_id" in report
        assert "checks" in report
        assert "summary" in report


# ---------------------------------------------------------------------------
# File existence
# ---------------------------------------------------------------------------


class TestFileExistence:
    def test_spec_exists(self):
        assert checker.SPEC_PATH.is_file()

    def test_policy_exists(self):
        assert checker.POLICY_PATH.is_file()

    def test_rust_impl_exists(self):
        assert checker.RUST_IMPL.is_file()

    def test_mod_rs_exists(self):
        assert checker.MOD_RS.is_file()

    def test_file_exists_helper_pass(self):
        checker.RESULTS.clear()
        r = checker._file_exists(checker.SPEC_PATH, "spec")
        assert r["pass"] is True
        assert "exists" in r["detail"]

    def test_file_exists_helper_fail(self):
        checker.RESULTS.clear()
        r = checker._file_exists(Path("/does/not/exist"), "missing")
        assert r["pass"] is False
        assert "missing" in r["detail"]


# ---------------------------------------------------------------------------
# Module registration
# ---------------------------------------------------------------------------


class TestModuleRegistration:
    def test_module_registered(self):
        checker.RESULTS.clear()
        result = checker.check_module_registered()
        assert result["pass"] is True

    def test_mod_rs_contains_rollback_bundle(self):
        text = checker.MOD_RS.read_text(encoding="utf-8")
        assert "pub mod rollback_bundle;" in text


# ---------------------------------------------------------------------------
# Rust types
# ---------------------------------------------------------------------------


class TestRustTypes:
    def test_all_types_present(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_RUST_TYPES, "type")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing types: {[r['check'] for r in missing]}"

    def test_type_count(self):
        assert len(checker.REQUIRED_RUST_TYPES) == 14


# ---------------------------------------------------------------------------
# Rust methods
# ---------------------------------------------------------------------------


class TestRustMethods:
    def test_all_methods_present(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_RUST_METHODS, "method")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing methods: {[r['check'] for r in missing]}"

    def test_method_count(self):
        assert len(checker.REQUIRED_RUST_METHODS) == 23


# ---------------------------------------------------------------------------
# Event codes
# ---------------------------------------------------------------------------


class TestEventCodes:
    def test_all_event_codes_in_impl(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_EVENT_CODES, "ev")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_all_event_codes_in_spec(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.SPEC_PATH, checker.REQUIRED_EVENT_CODES, "ev")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_four_event_codes(self):
        assert len(checker.REQUIRED_EVENT_CODES) == 4

    def test_event_code_prefix(self):
        for ec in checker.REQUIRED_EVENT_CODES:
            assert ec.startswith("RRB-"), f"Event code {ec} does not start with RRB-"


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


class TestInvariants:
    def test_all_invariants_in_impl(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_INVARIANTS, "inv")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_all_invariants_in_spec(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.SPEC_PATH, checker.REQUIRED_INVARIANTS, "inv")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_four_invariants(self):
        assert len(checker.REQUIRED_INVARIANTS) == 4


# ---------------------------------------------------------------------------
# Error codes
# ---------------------------------------------------------------------------


class TestErrorCodes:
    def test_all_error_codes_in_impl(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_ERROR_CODES, "err")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_all_error_codes_in_spec(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.SPEC_PATH, checker.REQUIRED_ERROR_CODES, "err")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_four_error_codes(self):
        assert len(checker.REQUIRED_ERROR_CODES) == 4


# ---------------------------------------------------------------------------
# Rust tests
# ---------------------------------------------------------------------------


class TestRustTests:
    def test_all_test_names_present(self):
        checker.RESULTS.clear()
        results = checker._check_content(checker.RUST_IMPL, checker.REQUIRED_RUST_TESTS, "test")
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_at_least_60_tests(self):
        assert len(checker.REQUIRED_RUST_TESTS) >= 60

    def test_impl_test_count_at_least_40(self):
        checker.RESULTS.clear()
        result = checker.check_impl_test_count()
        assert result["pass"] is True


# ---------------------------------------------------------------------------
# Serde and SHA-256
# ---------------------------------------------------------------------------


class TestSerdeAndSha:
    def test_serde_derives_present(self):
        checker.RESULTS.clear()
        result = checker.check_serde_derives()
        assert result["pass"] is True

    def test_sha256_usage(self):
        checker.RESULTS.clear()
        result = checker.check_sha256_usage()
        assert result["pass"] is True


# ---------------------------------------------------------------------------
# Idempotency and dry-run
# ---------------------------------------------------------------------------


class TestIdempotencyAndDryRun:
    def test_idempotency_test_present(self):
        checker.RESULTS.clear()
        result = checker.check_idempotency_test()
        assert result["pass"] is True

    def test_dry_run_test_present(self):
        checker.RESULTS.clear()
        result = checker.check_dry_run_test()
        assert result["pass"] is True


# ---------------------------------------------------------------------------
# Deterministic restore
# ---------------------------------------------------------------------------


class TestDeterministicRestore:
    def test_deterministic_restore_logic(self):
        checker.RESULTS.clear()
        result = checker.check_deterministic_restore()
        assert result["pass"] is True


# ---------------------------------------------------------------------------
# Health check kinds
# ---------------------------------------------------------------------------


class TestHealthCheckKinds:
    def test_all_health_checks_present(self):
        checker.RESULTS.clear()
        results = checker.check_health_check_kinds()
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_four_health_checks(self):
        assert len(checker.REQUIRED_HEALTH_CHECKS) == 4


# ---------------------------------------------------------------------------
# Spec and policy sections
# ---------------------------------------------------------------------------


class TestSpecSections:
    def test_all_spec_sections_present(self):
        checker.RESULTS.clear()
        results = checker.check_spec_sections()
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_spec_section_count(self):
        assert len(checker.REQUIRED_SPEC_SECTIONS) == 7


class TestPolicySections:
    def test_all_policy_sections_present(self):
        checker.RESULTS.clear()
        results = checker.check_policy_sections()
        missing = [r for r in results if not r["pass"]]
        assert len(missing) == 0, f"Missing: {[r['check'] for r in missing]}"

    def test_policy_section_count(self):
        assert len(checker.REQUIRED_POLICY_SECTIONS) == 6


# ---------------------------------------------------------------------------
# Full evidence
# ---------------------------------------------------------------------------


class TestFullEvidence:
    def test_overall_pass(self):
        report = checker.run_all()
        assert report["overall_pass"] is True, (
            f"Failing checks: {[c for c in report['checks'] if not c['pass']]}"
        )

    def test_bead_id(self):
        report = checker.run_all()
        assert report["bead_id"] == "bd-3q9"

    def test_section(self):
        report = checker.run_all()
        assert report["section"] == "10.6"

    def test_verdict_pass(self):
        report = checker.run_all()
        assert report["verdict"] == "PASS"

    def test_summary_counts(self):
        report = checker.run_all()
        assert report["summary"]["total"] > 100
        assert report["summary"]["passing"] == report["summary"]["total"]
        assert report["summary"]["failing"] == 0

    def test_json_serializable(self):
        report = checker.run_all()
        serialized = json.dumps(report)
        roundtrip = json.loads(serialized)
        assert roundtrip["bead_id"] == "bd-3q9"

    def test_checks_list_type(self):
        report = checker.run_all()
        assert isinstance(report["checks"], list)

    def test_each_check_has_required_keys(self):
        report = checker.run_all()
        for c in report["checks"]:
            assert "check" in c
            assert "pass" in c
            assert "detail" in c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_safe_rel_inside_root(self):
        p = checker.ROOT / "foo" / "bar.rs"
        assert checker._safe_rel(p) == "foo/bar.rs"

    def test_safe_rel_outside_root(self):
        p = Path("/tmp/unrelated/file.txt")
        result = checker._safe_rel(p)
        assert result == "/tmp/unrelated/file.txt"

    def test_check_helper_pass(self):
        checker.RESULTS.clear()
        r = checker._check("test-check", True, "ok")
        assert r["pass"] is True
        assert r["detail"] == "ok"

    def test_check_helper_fail(self):
        checker.RESULTS.clear()
        r = checker._check("test-check", False, "bad")
        assert r["pass"] is False

    def test_check_helper_default_detail(self):
        checker.RESULTS.clear()
        r = checker._check("test-check", True)
        assert r["detail"] == "found"
        checker.RESULTS.clear()
        r = checker._check("test-check", False)
        assert r["detail"] == "NOT FOUND"

    def test_file_contains_helper_pass(self):
        checker.RESULTS.clear()
        r = checker._file_contains(checker.RUST_IMPL, "pub struct RollbackBundle", "test")
        assert r["pass"] is True

    def test_file_contains_helper_fail(self):
        checker.RESULTS.clear()
        r = checker._file_contains(checker.RUST_IMPL, "NONEXISTENT_PATTERN_12345", "test")
        assert r["pass"] is False

    def test_file_contains_missing_file(self):
        checker.RESULTS.clear()
        r = checker._file_contains(Path("/no/such/file.rs"), "anything", "test")
        assert r["pass"] is False
        assert "missing" in r["detail"]

    def test_check_content_missing_file(self):
        checker.RESULTS.clear()
        results = checker._check_content(Path("/no/such/file.rs"), ["pattern"], "cat")
        assert len(results) == 1
        assert results[0]["pass"] is False


# ---------------------------------------------------------------------------
# Edge cases / mock tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_impl_file(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/rollback_bundle.rs")):
            result = checker.check_impl_test_count()
        assert result["pass"] is False

    def test_missing_mod_rs(self):
        checker.RESULTS.clear()
        with patch.object(checker, "MOD_RS", Path("/no/such/mod.rs")):
            result = checker.check_module_registered()
        assert result["pass"] is False

    def test_missing_impl_serde(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            result = checker.check_serde_derives()
        assert result["pass"] is False

    def test_missing_impl_sha256(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            result = checker.check_sha256_usage()
        assert result["pass"] is False

    def test_missing_impl_idempotency(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            result = checker.check_idempotency_test()
        assert result["pass"] is False

    def test_missing_impl_dry_run(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            result = checker.check_dry_run_test()
        assert result["pass"] is False

    def test_missing_impl_deterministic(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            result = checker.check_deterministic_restore()
        assert result["pass"] is False

    def test_missing_impl_health_checks(self):
        checker.RESULTS.clear()
        with patch.object(checker, "RUST_IMPL", Path("/no/such/impl.rs")):
            results = checker.check_health_check_kinds()
        assert all(not r["pass"] for r in results)

    def test_missing_spec_sections(self):
        checker.RESULTS.clear()
        with patch.object(checker, "SPEC_PATH", Path("/no/such/spec.md")):
            results = checker.check_spec_sections()
        assert all(not r["pass"] for r in results)

    def test_missing_policy_sections(self):
        checker.RESULTS.clear()
        with patch.object(checker, "POLICY_PATH", Path("/no/such/policy.md")):
            results = checker.check_policy_sections()
        assert all(not r["pass"] for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
