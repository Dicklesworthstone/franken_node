"""Unit tests for check_high_assurance_promotion.py verification script."""

import importlib.util
import os

import pytest

# Load the verification script as a module
SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts",
    "check_high_assurance_promotion.py",
)
spec = importlib.util.spec_from_file_location("check_mod", SCRIPT)
check_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_mod)


class TestRunChecks:
    """Tests that run_checks() returns expected structure."""

    def test_returns_list(self):
        result = check_mod.run_checks()
        assert isinstance(result, list)

    def test_all_entries_have_required_keys(self):
        for entry in check_mod.run_checks():
            assert "check" in entry
            assert "pass" in entry
            assert "detail" in entry

    def test_pass_values_are_bool(self):
        for entry in check_mod.run_checks():
            assert isinstance(entry["pass"], bool)

    def test_minimum_check_count(self):
        result = check_mod.run_checks()
        assert len(result) >= 60, f"Expected >= 60 checks, got {len(result)}"

    def test_all_checks_pass(self):
        """Verify all checks pass against current codebase."""
        result = check_mod.run_checks()
        failing = [c for c in result if not c["pass"]]
        assert not failing, f"Failing checks: {failing}"


class TestFileChecks:
    """Tests for file existence checks."""

    def test_implementation_file_check(self):
        checks = check_mod.run_checks()
        impl_check = next(c for c in checks if c["check"] == "file: implementation")
        assert impl_check["pass"]

    def test_spec_file_check(self):
        checks = check_mod.run_checks()
        spec_check = next(c for c in checks if c["check"] == "file: spec contract")
        assert spec_check["pass"]

    def test_matrix_file_check(self):
        checks = check_mod.run_checks()
        matrix_check = next(c for c in checks if c["check"] == "file: promotion matrix artifact")
        assert matrix_check["pass"]


class TestTypeChecks:
    """Tests for type definitions in source."""

    TYPES = [
        "pub enum AssuranceMode",
        "pub enum ObjectClass",
        "pub enum ProofRequirement",
        "pub struct ProofBundle",
        "pub enum PromotionDenialReason",
        "pub struct PolicyAuthorization",
        "pub struct HighAssuranceGate",
        "pub struct PromotionMatrixEntry",
    ]

    @pytest.mark.parametrize("ty", TYPES)
    def test_type_found(self, ty):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"type: {ty}")
        assert check["pass"], f"Type not found: {ty}"


class TestEventCodes:
    """Tests for event code presence."""

    CODES = [
        "QUARANTINE_PROMOTION_APPROVED",
        "QUARANTINE_PROMOTION_DENIED",
        "ASSURANCE_MODE_CHANGED",
    ]

    @pytest.mark.parametrize("code", CODES)
    def test_event_code_found(self, code):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"event_code: {code}")
        assert check["pass"]


class TestInvariants:
    """Tests for invariant presence."""

    INVARIANTS = [
        "INV-HA-PROOF-REQUIRED",
        "INV-HA-FAIL-CLOSED",
        "INV-HA-MODE-POLICY",
    ]

    @pytest.mark.parametrize("inv", INVARIANTS)
    def test_invariant_found(self, inv):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == f"invariant: {inv}")
        assert check["pass"]


class TestUnitTestChecks:
    """Tests that unit test count is verified."""

    def test_unit_test_count_passes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "unit test count")
        assert check["pass"]
        assert "33" in check["detail"] or int(check["detail"].split()[0]) >= 25


class TestSelfTest:
    """Tests for the self_test() function."""

    def test_self_test_passes(self):
        assert check_mod.self_test()


class TestCheckHelper:
    """Tests for the _check helper."""

    def test_pass_true(self):
        result = check_mod._check("test", True, "ok")
        assert result == {"check": "test", "pass": True, "detail": "ok"}

    def test_pass_false(self):
        result = check_mod._check("test", False, "nope")
        assert result == {"check": "test", "pass": False, "detail": "nope"}

    def test_default_detail_pass(self):
        result = check_mod._check("test", True)
        assert result["detail"] == "found"

    def test_default_detail_fail(self):
        result = check_mod._check("test", False)
        assert result["detail"] == "NOT FOUND"


class TestPromotionMatrix:
    """Tests for promotion matrix artifact validation."""

    def test_matrix_covers_all_classes(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "matrix covers all classes")
        assert check["pass"]

    def test_matrix_has_four_entries(self):
        checks = check_mod.run_checks()
        check = next(c for c in checks if c["check"] == "matrix has 4 entries")
        assert check["pass"]
